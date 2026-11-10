(ns bitecho.shell.acme
  "RFC 8555 ACME v2 Issuance & Zero-Downtime Renewal Shell over `\"bitecho.org/infra\"` (Gap G7):
   - Single-authority generation-tagged lifecycle state via `bitecho.shell.infra/transition-shell` (Rule 4).
   - Uses pure `bitecho.core.protocol.acme` for Base64URL, RFC 7638 JWK thumbprints, RFC 8555
     key authorizations / DNS-01 digests, Flattened JWS serialization, PKCS#10 DER CSR assembly,
     and renewal/readiness/backoff predicates.
   - Publishes `\"acme/challenge/<token>\"` Pointer (`15 min` TTL, `:acme-key-auth` proof) + Blob into
     `subnet-runtime`, and **immediately publishes a `nil`-target tombstone Pointer in `finally`**
     once authorization validation completes (Gap G7).
   - Encrypts the issued private key with AES-256-GCM (`bitecho.shell.infra/encrypt-tls-key-pem`)
     before storing the `\"tls/current-cert\"` Blob, signing its Pointer with a semantic `:cert`
     leaf DER SHA-256 fingerprint proof (`F2`) so followers verify and hot-reload TLS automatically."
  (:require [bitecho.core.data :as data]
            [bitecho.core.protocol.acme :as acme-proto]
            [bitecho.fressian :as fressian]
            [bitecho.shell.http :as http-shell]
            [bitecho.shell.infra :as infra]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io File]
           [java.math BigInteger]
           [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpClient$Version HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file CopyOption Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]
           [java.security KeyFactory KeyPair KeyPairGenerator PrivateKey PublicKey Signature]
           [java.security.interfaces ECPublicKey]
           [java.security.spec X509EncodedKeySpec]
           [java.time Duration]
           [java.util Base64]
           [java.util.concurrent Executors ScheduledExecutorService TimeUnit]
           [java.util.concurrent.atomic AtomicBoolean AtomicLong]))

;; =============================================================================
;; 1. JVM EC P-256 Keypair, JWK, JWS Signing, & CSR Signing Bridges
;; =============================================================================

(defn generate-ec-keypair
  "Generates an ECDSA P-256 (`secp256r1`) `KeyPair`."
  ^KeyPair []
  (let [kpg (KeyPairGenerator/getInstance "EC")]
    (.initialize kpg 256)
    (.generateKeyPair kpg)))

(defn ec-public-key->jwk
  "Converts a JVM `^ECPublicKey` into a pure `bitecho.core.protocol.acme` JWK map."
  [^ECPublicKey pub-key]
  (let [w (.getW pub-key)
        bi->bytes (fn [^BigInteger bi] (.toByteArray bi))]
    (acme-proto/coords->jwk (bi->bytes (.getAffineX w))
                            (bi->bytes (.getAffineY w)))))

(defn sign-jws-es256
  "Signs an RFC 8555 Flattened JWS JSON string using `SHA256withECDSAinP1363Format`."
  [{:keys [^PrivateKey private-key ^ECPublicKey public-key kid nonce url payload]}]
  (let [jwk (when-not kid (ec-public-key->jwk public-key))
        jws-in (acme-proto/build-jws-signing-input {:kid kid :jwk jwk :nonce nonce :url url :payload payload})
        sig (Signature/getInstance "SHA256withECDSAinP1363Format")]
    (.initSign sig private-key)
    (.update sig ^bytes (:signing-bytes jws-in))
    (acme-proto/assemble-flattened-jws jws-in (.sign sig))))

(defn generate-csr-der
  "Builds and signs a DER-encoded PKCS#10 CSR for `domains` under `^KeyPair domain-kp`."
  ^bytes [^KeyPair domain-kp domains]
  (let [spki-der (.getEncoded (.getPublic domain-kp))
        csr-info (acme-proto/build-csr-info-der domains spki-der)
        sig (Signature/getInstance "SHA256withECDSA")]
    (.initSign sig (.getPrivate domain-kp))
    (.update sig ^bytes csr-info)
    (acme-proto/assemble-csr-der csr-info (.sign sig))))

(defn- encode-public-key-pem
  [^PublicKey pub]
  (let [enc (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII))]
    (str "-----BEGIN PUBLIC KEY-----\n"
         (.encodeToString enc (.getEncoded pub))
         "\n-----END PUBLIC KEY-----\n")))

(defn- parse-public-key-pem
  [^String pem-str]
  (let [cleaned (-> pem-str
                    (str/replace #"-----BEGIN [A-Z ]+-----" "")
                    (str/replace #"-----END [A-Z ]+-----" "")
                    (str/replace #"\s+" ""))]
    (.generatePublic (KeyFactory/getInstance "EC")
                     (X509EncodedKeySpec. (.decode (Base64/getDecoder) ^String cleaned)))))

(defn save-or-load-account-keypair!
  "Atomically persists or loads `<state-dir>/acme/account-{key,pub}.pem`."
  [state-dir]
  (let [acme-dir (io/file state-dir "acme")
        _ (.mkdirs acme-dir)
        priv-file (io/file acme-dir "account-key.pem")
        pub-file (io/file acme-dir "account-pub.pem")]
    (if (and (.exists priv-file) (.exists pub-file))
      (let [priv (http-shell/parse-private-key-pem (slurp priv-file))
            pub (parse-public-key-pem (slurp pub-file))]
        {:private-key priv :public-key pub :keypair (KeyPair. pub priv)})
      (let [kp (generate-ec-keypair)
            priv (.getPrivate kp)
            pub (.getPublic kp)
            tmp-priv (File/createTempFile "acc-priv-" ".tmp" acme-dir)
            tmp-pub (File/createTempFile "acc-pub-" ".tmp" acme-dir)]
        (spit tmp-priv (http-shell/encode-private-key-pem priv))
        (spit tmp-pub (encode-public-key-pem pub))
        (try
          (Files/setPosixFilePermissions (.toPath tmp-priv) (PosixFilePermissions/fromString "rw-------"))
          (catch UnsupportedOperationException _ nil))
        (Files/move (.toPath tmp-priv) (.toPath priv-file)
                    (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING]))
        (Files/move (.toPath tmp-pub) (.toPath pub-file)
                    (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING]))
        {:private-key priv :public-key pub :keypair kp}))))

;; =============================================================================
;; 2. ACME v2 HTTP Client & Issuance Orchestrator (with Gap G7 Tombstone)
;; =============================================================================

(defn create-http-client
  "Creates standard JDK 25 `HttpClient` for ACME directory/order requests."
  ([] (create-http-client 15))
  ([^long timeout-seconds]
   (-> (HttpClient/newBuilder)
       (.version HttpClient$Version/HTTP_1_1)
       (.followRedirects HttpClient$Redirect/NORMAL)
       (.connectTimeout (Duration/ofSeconds timeout-seconds))
       (.build))))

(defn- fetch-directory
  [^HttpClient client ^String directory-url]
  (let [req (-> (HttpRequest/newBuilder (URI/create directory-url))
                (.timeout (Duration/ofSeconds 15))
                (.GET)
                (.build))
        resp (.send client req (HttpResponse$BodyHandlers/ofString))]
    (if (<= 200 (.statusCode resp) 299)
      (json/read-str (.body resp))
      (throw (ex-info "Failed to fetch ACME directory" {:status (.statusCode resp) :url directory-url})))))

(defn- fetch-nonce
  [^HttpClient client ^String new-nonce-url]
  (let [req (-> (HttpRequest/newBuilder (URI/create new-nonce-url))
                (.timeout (Duration/ofSeconds 15))
                (.method "HEAD" (HttpRequest$BodyPublishers/noBody))
                (.build))
        resp (.send client req (HttpResponse$BodyHandlers/discarding))]
    (or (.orElse (.firstValue (.headers resp) "Replay-Nonce") nil)
        (throw (ex-info "No Replay-Nonce header in ACME response" {:url new-nonce-url})))))

(defn- acme-post!
  ([client-state url payload]
   (acme-post! client-state url payload 0))
  ([client-state url payload retry-count]
   (let [st @client-state
         ^HttpClient client (:http-client st)
         directory (:directory st)
         nonce (or (:nonce st) (fetch-nonce client (get directory "newNonce")))
         jws-body (sign-jws-es256 {:private-key (:account-priv st)
                                   :public-key (:account-pub st)
                                   :kid (:kid st)
                                   :nonce nonce
                                   :url url
                                   :payload payload})
         req (-> (HttpRequest/newBuilder (URI/create url))
                 (.timeout (Duration/ofSeconds 30))
                 (.header "Content-Type" "application/jose+json")
                 (.POST (HttpRequest$BodyPublishers/ofString jws-body))
                 (.build))
         resp (.send client req (HttpResponse$BodyHandlers/ofString))
         status (.statusCode resp)
         headers (.headers resp)
         new-nonce (.orElse (.firstValue headers "Replay-Nonce") nil)
         body (.body resp)
         json-data (try (when (and body (not (str/blank? body))) (json/read-str body)) (catch Exception _ nil))
         loc (.orElse (.firstValue headers "Location") nil)]
     (when new-nonce
       (swap! client-state assoc :nonce new-nonce))
     (if (and (= status 400)
              (< retry-count 1)
              (= (get json-data "type") "urn:ietf:params:acme:error:badNonce"))
       (do
         (swap! client-state assoc :nonce (or new-nonce (fetch-nonce client (get directory "newNonce"))))
         (acme-post! client-state url payload (inc retry-count)))
       {:status status :location loc :body body :json json-data :headers headers}))))

(defn- poll-until-status!
  [client-state url target-statuses failure-statuses timeout-ms interval-ms]
  (let [start-ms (System/currentTimeMillis)]
    (loop []
      (let [resp (acme-post! client-state url :post-as-get)
            cur (get-in resp [:json "status"])]
        (cond
          (contains? target-statuses cur) resp
          (contains? failure-statuses cur)
          (throw (ex-info (str "ACME resource failed with status " cur) {:url url :response resp}))
          (> (- (System/currentTimeMillis) start-ms) timeout-ms)
          (throw (ex-info "Timed out polling ACME resource" {:url url :last-status cur}))
          :else
          (do (Thread/sleep (long interval-ms))
              (recur)))))))

(defn- next-path-seq
  [subnet-runtime path]
  (let [inst @(:subnet-atom subnet-runtime)
        sid (:subnet-id inst)
        existing (get-in inst [:data :pointers [sid path]])]
    (inc (long (or (:pointer/seq existing) 0)))))

(defn- publish-challenge-tombstone!
  "Gap G7: Immediately tombstones `acme/challenge/<token>` (`:pointer/target nil`) upon authorization completion."
  [subnet-runtime token]
  (when subnet-runtime
    (let [inst @(:subnet-atom subnet-runtime)
          sid (:subnet-id inst)
          path (str "acme/challenge/" token)
          auth-pub (:default-sender subnet-runtime)
          auth-priv (:node-privkey subnet-runtime)
          le-term (get-in inst [:leader-election :term])
          seq-num (next-path-seq subnet-runtime path)]
      (when (and auth-pub auth-priv)
        (let [tomb (data/sign-pointer auth-priv
                                      (cond-> {:pointer/authority auth-pub
                                               :pointer/subnet sid
                                               :pointer/path path
                                               :pointer/seq seq-num
                                               :pointer/target nil
                                               :pointer/proof {:proof/type :self}}
                                        (some? le-term) (assoc :pointer/leader-term (long le-term))))]
          (infra/submit-event! subnet-runtime
                               {:type :publish-pointer
                                :sender auth-pub
                                :pointer tomb
                                :now-ms (System/currentTimeMillis)}))))))

(defn provision-certificate!
  "Executes full RFC 8555 issuance against `directory-url`, publishing `acme/challenge/<token>` Pointers
   (with immediate Gap G7 tombstoning) and AES-GCM encrypted `tls/current-cert` Blob + Pointer."
  ([config subnet-runtime tls-manager]
   (provision-certificate! config subnet-runtime tls-manager {}))
  ([config subnet-runtime tls-manager opts]
   (let [domains (or (:domains (:acme config))
                     (when-let [d (:domain config)] [d])
                     ["localhost"])
         state-dir (:state-dir config)
         acme-cfg (get config :acme {})
         directory-url (or (:directory-url opts)
                           (:directory-url acme-cfg)
                           "https://acme-v02.api.letsencrypt.org/directory")
         poll-interval-ms (long (or (:poll-interval-ms opts) 500))
         poll-timeout-ms (long (or (:poll-timeout-ms opts) 60000))
         acc (save-or-load-account-keypair! state-dir)
         account-pub (:public-key acc)
         thumbprint (acme-proto/jwk->thumbprint (ec-public-key->jwk account-pub))
         client (or (:http-client opts) (create-http-client))
         directory (fetch-directory client directory-url)
         initial-nonce (fetch-nonce client (get directory "newNonce"))
         client-state (atom {:http-client client
                             :account-priv (:private-key acc)
                             :account-pub account-pub
                             :kid nil
                             :nonce initial-nonce
                             :directory directory})
         acct-payload (cond-> {"termsOfServiceAgreed" true}
                        (:contact-email acme-cfg) (assoc "contact" [(:contact-email acme-cfg)]))
         acct-resp (acme-post! client-state (get directory "newAccount") acct-payload)
         account-url (or (:location acct-resp)
                         (throw (ex-info "newAccount missing Location header" {:resp acct-resp})))
         _ (swap! client-state assoc :kid account-url)
         order-resp (acme-post! client-state
                                (get directory "newOrder")
                                {"identifiers" (mapv (fn [d] {"type" "dns" "value" d}) domains)})
         order-url (or (:location order-resp)
                       (throw (ex-info "newOrder missing Location header" {:resp order-resp})))
         authz-urls (get-in order-resp [:json "authorizations"])
         finalize-url (get-in order-resp [:json "finalize"])]
     (when (empty? authz-urls)
       (throw (ex-info "newOrder returned empty authorizations" {:resp order-resp})))

     ;; Authorize each domain via HTTP-01 + Subnet Pointer replication + immediate Gap G7 tombstone
     (doseq [authz-url authz-urls]
       (let [authz-resp (acme-post! client-state authz-url :post-as-get)
             authz-data (:json authz-resp)]
         (when-not (= "valid" (get authz-data "status"))
           (let [http-chall (first (filter #(= "http-01" (get % "type")) (get authz-data "challenges")))]
             (when-not http-chall
               (throw (ex-info "No http-01 challenge in ACME authorization" {:authz authz-data})))
             (let [token (get http-chall "token")
                   chall-url (get http-chall "url")
                   key-auth (acme-proto/key-authorization-from-thumbprint token thumbprint)
                   dns-txt (acme-proto/dns-01-txt-from-key-auth key-auth)
                   now-ms (System/currentTimeMillis)
                   chall-path (str "acme/challenge/" token)
                   chall-blob (data/make-blob (fressian/encode-canonical {:token token
                                                                          :key-auth key-auth
                                                                          :dns-txt dns-txt})
                                              "application/fressian")]
               (when subnet-runtime
                 (let [pub-res (infra/publish-blob-and-pointer!
                                subnet-runtime
                                {:blob chall-blob
                                 :path chall-path
                                 :seq (next-path-seq subnet-runtime chall-path)
                                 :expires (+ now-ms 900000) ;; 15-minute TTL (Gap G7)
                                 :authority-pubkey (:default-sender subnet-runtime)
                                 :authority-privkey (:node-privkey subnet-runtime)
                                 :proof {:proof/type :acme-key-auth
                                         :token token
                                         :key-auth key-auth}
                                 :now-ms now-ms})]
                   (when-not (:applied? pub-res)
                     (throw (ex-info "Failed to publish ACME challenge Pointer" {:res pub-res})))))
               (try
                 (acme-post! client-state chall-url {})
                 (poll-until-status! client-state authz-url #{"valid"} #{"invalid"} poll-timeout-ms poll-interval-ms)
                 (finally
                   (publish-challenge-tombstone! subnet-runtime token))))))))

     ;; Finalize CSR, download PEM chain, update local TLS, and replicate AES-GCM encrypted bundle!
     (let [domain-kp (or (:domain-keypair opts) (generate-ec-keypair))
           csr-b64 (acme-proto/base64url-encode (generate-csr-der domain-kp domains))
           _ (acme-post! client-state finalize-url {"csr" csr-b64})
           final-order (poll-until-status! client-state order-url #{"valid"} #{"invalid"} poll-timeout-ms poll-interval-ms)
           cert-url (or (get-in final-order [:json "certificate"])
                        (throw (ex-info "Order valid but certificate URL missing" {:order final-order})))
           cert-pem (:body (acme-post! client-state cert-url :post-as-get))
           key-pem (http-shell/encode-private-key-pem (.getPrivate domain-kp))
           certs (http-shell/parse-cert-chain-pem cert-pem)]
       (when (empty? certs)
         (throw (ex-info "Downloaded ACME certificate chain is empty" {})))
       (let [expires-at (.getTime (.getNotAfter ^java.security.cert.X509Certificate (first certs)))
             leaf-der (acme-proto/extract-first-pem-cert-der cert-pem)
             leaf-fp (acme-proto/cert-der-sha256-hex leaf-der)]
         (when tls-manager
           (http-shell/update-tls-bundle! tls-manager cert-pem key-pem))
         (when subnet-runtime
           (let [tls-secret (or (:tls-secret opts)
                                (:tls-secret subnet-runtime)
                                (:node-privkey subnet-runtime))
                 enc-key (infra/encrypt-tls-key-pem tls-secret key-pem)
                 bundle-blob (data/make-blob (fressian/encode-canonical {:cert-pem cert-pem
                                                                         :encrypted-key enc-key
                                                                         :expires-at expires-at})
                                             "application/fressian")
                 pub-res (infra/publish-blob-and-pointer!
                          subnet-runtime
                          {:blob bundle-blob
                           :path "tls/current-cert"
                           :seq (next-path-seq subnet-runtime "tls/current-cert")
                           :authority-pubkey (:default-sender subnet-runtime)
                           :authority-privkey (:node-privkey subnet-runtime)
                           :proof {:proof/type :cert :fingerprint leaf-fp}
                           :now-ms (System/currentTimeMillis)})]
             (when-not (:applied? pub-res)
               (throw (ex-info "Failed to publish tls/current-cert Pointer" {:res pub-res})))))
         {:cert-pem cert-pem
          :key-pem key-pem
          :fingerprint leaf-fp
          :expires-at expires-at
          :certificates certs})))))

(defn start-acme-loop!
  "Starts background renewal loop triggered when `subnet-ready-for-acme?` and `needs-renewal?` hold."
  ([config subnet-runtime tls-manager]
   (start-acme-loop! config subnet-runtime tls-manager {}))
  ([config subnet-runtime tls-manager opts]
   (let [shell-atom (atom (infra/init-shell-state :acme-shell))
         _ (infra/apply-shell-event! shell-atom {:type :start})
         gen (:generation @shell-atom)
         running? (AtomicBoolean. true)
         executor (Executors/newSingleThreadScheduledExecutor)
         interval-ms (long (or (:check-interval-ms opts) (get-in config [:acme :check-interval-ms] 15000)))
         base-backoff-ms (long (or (:backoff-base-ms opts) 60000))
         failures (AtomicLong. 0)
         next-attempt (AtomicLong. 0)
         task (fn []
                (when (.get running?)
                  (let [now (System/currentTimeMillis)]
                    (when (>= now (.get next-attempt))
                      (let [le (when subnet-runtime (:leader-election @(:subnet-atom subnet-runtime)))
                            bundle (when tls-manager @(:bundle-atom tls-manager))]
                        (when (and (acme-proto/subnet-ready-for-acme? le)
                                   (acme-proto/needs-renewal? config bundle now))
                          (try
                            (provision-certificate! config subnet-runtime tls-manager opts)
                            (.set failures 0)
                            (.set next-attempt 0)
                            (catch Exception e
                              (let [f (.incrementAndGet failures)
                                    delay-ms (acme-proto/compute-backoff-ms base-backoff-ms f)]
                                (.set next-attempt (+ now delay-ms))
                                (infra/apply-shell-event! shell-atom
                                                          {:type :diagnose
                                                           :reason :acme-renewal-failed
                                                           :failures f
                                                           :detail (.getMessage e)}))))))))))]
     (.scheduleWithFixedDelay ^ScheduledExecutorService executor
                              ^Runnable task
                              0
                              interval-ms
                              TimeUnit/MILLISECONDS)
     (infra/apply-shell-event! shell-atom {:type :started :generation gen :resources {:exec executor}})
     {:shell-atom shell-atom
      :executor executor
      :running? running?
      :stop-fn (fn []
                 (infra/apply-shell-event! shell-atom
                                           {:type :stop}
                                           (fn [{:keys [exec]}]
                                             (.set running? false)
                                             (when exec
                                               (try (.shutdownNow ^ScheduledExecutorService exec) (catch Exception _ nil))))))})))

(defn stop-acme-loop!
  "Stops the ACME renewal scheduler cleanly."
  [acme-mgr]
  (when-let [stop-fn (:stop-fn acme-mgr)]
    (stop-fn))
  acme-mgr)
