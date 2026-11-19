(ns bitecho.d36-nodejs-infra-parity-test
  "Milestone D36 Remediation (`BIP-010 / BIP-011`): Full JVM Infra-Node Parity in Node.js (`dist/bitecho-full-node.cjs`).
   Strict TDD (AGENTS.md Rule 1):
   1. `prop-infra-shell-lifecycle-single-authority-and-stale-gen` (model-based `test.check` lifecycle & stale-gen callbacks)
   2. `prop-http-path-sanitization-and-connect-allowlist-fail-closed` (path traversal & CONNECT proxy allowlist)
   3. `prop-dns-smtp-and-artifact-pointer-parity` (authoritative DNS, SMTP relay-denial, artifact pointer normalization)
   4. `test-nodejs-infra-node-full-parity-e2e` (live `node dist/bitecho-full-node.cjs infra-node <config.edn>` E2E across HTTP, HTTPS, UDP DNS, Relay, Artifact, CONNECT, SMTP)
   5. `test-ops-run-node-preflight-and-cluster-script-parity` (Rule 6 ops script preflight verification)"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.infra :as core-infra]
            [bitecho.core.mesh :as core-mesh]
            [bitecho.core.protocol.dns :as dns-proto]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.core.protocol.smtp :as smtp-proto]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http-shell]
            [bitecho.shell.infra :as jvm-infra]
            [bitecho.shell.light-node :as light-node]
            [bitecho.streamlet.core :as streamlet]
            [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io BufferedReader BufferedWriter InputStreamReader OutputStreamWriter]
           [java.net DatagramPacket DatagramSocket InetAddress ServerSocket Socket URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.security SecureRandom]
           [java.security.cert X509Certificate]
           [java.time Duration]
           [java.util.concurrent TimeUnit]
           [javax.net.ssl SSLContext TrustManager X509TrustManager]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- kp->pk-hex [kp]
  (let [pub (or (:public-key kp) (:public kp))]
    (if (string? pub) pub (basalt/bytes->hex pub))))

(defn- kp->sk [kp]
  (or (:private-key kp) (:private kp)))

(defn- make-temp-dir [prefix]
  (.toFile (Files/createTempDirectory prefix (into-array FileAttribute []))))

(defn- delete-dir-recursively! [^java.io.File f]
  (when (and f (.exists f))
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-dir-recursively! c)))
    (.delete f)))

(defn- trust-all-http-client
  ^HttpClient []
  (let [tm (reify X509TrustManager
             (getAcceptedIssuers [_] (into-array X509Certificate []))
             (checkClientTrusted [_ _ _] nil)
             (checkServerTrusted [_ _ _] nil))
        ctx (doto (SSLContext/getInstance "TLS")
              (.init nil (into-array TrustManager [tm]) (SecureRandom.)))]
    (-> (HttpClient/newBuilder)
        (.sslContext ctx)
        (.connectTimeout (Duration/ofSeconds 5))
        (.build))))

(defn- node-bin-path []
  (let [local-node (io/file (System/getProperty "user.home") ".local/bin/node")]
    (if (and (.exists local-node) (.canExecute local-node))
      (.getAbsolutePath local-node)
      "node")))

;; =============================================================================
;; 1. Generative Properties (AGENTS.md Rule 1: >= 50 trials each)
;; =============================================================================

(defspec ^{:doc "Rule 4 & Rule 5: Single-authority pure shell lifecycle reducer enforces monotonic generations, ignores stale-generation callbacks with counted :ignored-stale + :diagnose, and never drops events silently."}
  prop-infra-shell-lifecycle-single-authority-and-stale-gen 50
  (prop/for-all
   [cmds (gen/vector
          (gen/elements [:start :started :stale-started :drop :diagnose :failed :stale-failed :stop])
          5 30)]
   (let [res (reduce
              (fn [{:keys [st max-gen expected-drops expected-stale ok?]} cmd]
                (let [cur-gen (:generation st)
                      ev (case cmd
                           :start {:type :start}
                           :started {:type :started :generation cur-gen :resources {:sock :mock}}
                           :stale-started {:type :started :generation (max 0 (dec cur-gen)) :resources {:sock :stale}}
                           :drop {:type :drop :reason :test-drop :detail "sim"}
                           :diagnose {:type :diagnose :reason :test-diag}
                           :failed {:type :failed :generation cur-gen :error :bind-failed}
                           :stale-failed {:type :failed :generation (max 0 (dec cur-gen)) :error :stale-err}
                           :stop {:type :stop})
                      stale? (and (contains? #{:stale-started :stale-failed} cmd)
                                  (pos? cur-gen))
                      [st' effs] (core-infra/transition-shell st ev)
                      gen-mono? (>= (:generation st') cur-gen)
                      stale-ok? (if stale?
                                  (and (= (:phase st') (:phase st))
                                       (= (:ignored-stale st') (inc expected-stale))
                                       (some #(= :stale-generation-callback (:reason %)) effs))
                                  true)
                      drop-ok? (if (= cmd :drop)
                                 (and (= (:dropped st') (inc expected-drops))
                                      (some #(= :diagnose (:effect %)) effs))
                                 true)]
                  {:st st'
                   :max-gen (max max-gen (:generation st'))
                   :expected-drops (if (= cmd :drop) (inc expected-drops) expected-drops)
                   :expected-stale (if stale? (inc expected-stale) expected-stale)
                   :ok? (and ok? gen-mono? stale-ok? drop-ok?)}))
              {:st (core-infra/init-shell-state :node-http)
               :max-gen 0
               :expected-drops 0
               :expected-stale 0
               :ok? true}
              cmds)]
     (true? (:ok? res)))))

(defspec ^{:doc "Fail-closed HTTP path sanitization blocks all traversal/dotfile/NUL vectors, and HTTP CONNECT resolution strictly enforces allowlisted connect-targets / connect-routes."}
  prop-http-path-sanitization-and-connect-allowlist-fail-closed 50
  (prop/for-all
   [bad-path (gen/elements ["/../etc/passwd"
                            "/%2e%2e/secret"
                            "/a/b/../../c"
                            "/.env"
                            "/web/.git/config"
                            "/foo\u0000bar"
                            "/%00index.html"])
    good-seg (gen/fmap #(str "page-" %) (gen/choose 1 9999))
    connect-mode (gen/elements [:exact-route :wildcard-ingress :disallowed-host :disallowed-port])]
   (let [bad-res (core-infra/sanitize-web-subpath bad-path)
         good-res (core-infra/sanitize-web-subpath (str "/docs/" good-seg ".md"))
         targets #{"node1.ingress.bitecho.org:443" "*.ingress.bitecho.org:443"}
         routes {"node1.ingress.bitecho.org:443" {:host "35.212.129.138" :port 5010}}
         ingress {:host "127.0.0.1" :port 5010}
         conn-req (case connect-mode
                    :exact-route {:host "node1.ingress.bitecho.org" :port 443}
                    :wildcard-ingress {:host (str good-seg ".ingress.bitecho.org") :port 443}
                    :disallowed-host {:host "evil.example.com" :port 443}
                    :disallowed-port {:host "node1.ingress.bitecho.org" :port 22})
         backend (core-infra/resolve-connect-backend conn-req targets routes ingress)]
     (and (nil? bad-res)
          (= (str "docs/" good-seg ".md") good-res)
          (case connect-mode
            :exact-route (= {:host "35.212.129.138" :port 5010} backend)
            :wildcard-ingress (= ingress backend)
            (:disallowed-host :disallowed-port) (nil? backend))))))

(defspec ^{:doc "Pure DNS resolution, SMTP open-relay rejection, and artifact pointer normalization/verification maintain exact parity across random seeds."}
  prop-dns-smtp-and-artifact-pointer-parity 50
  (prop/for-all
   [seed (gen/choose 1 100000)
    qtype (gen/elements [:A :NS :SOA])
    relay-attack? gen/boolean]
   (let [kp (crypto/generate-keypair (str "d36-parity-" seed))
         pk (kp->pk-hex kp)
         sk (kp->sk kp)
         ;; 1. DNS query resolution parity
         cfg {:domain "bitecho.org"
              :dns {:ttl-seconds 60
                    :ns-ttl-seconds 3600
                    :hostmaster "hostmaster.bitecho.org"
                    :subdomains #{"@" "www" "ingress"}
                    :delegated-ingress {"nexus.ingress" {:ns "ns1.nexus.ingress.bitecho.org" :ip4 "136.62.15.220" :ttl 60}}}
              :cluster {:nodes {:ns1 {:ip4 "35.212.172.159"}
                                :ns2 {:ip4 "35.209.253.119"}
                                :ns3 {:ip4 "35.211.30.106"}}}}
         q-pkt {:id (mod seed 65535)
                :qr? false
                :opcode 0
                :rd? false
                :questions [{:qname "bitecho.org" :qtype qtype :qclass :IN}]}
         q-bytes (dns-proto/encode-packet q-pkt)
         decoded-q (dns-proto/decode-packet q-bytes)
         resp (dns-proto/resolve-query cfg {:leader-election {:healthy-nodes #{:ns1 :ns2 :ns3}}} decoded-q 1700000000000)
         resp-bytes (dns-proto/encode-packet resp {:max-bytes 512})
         decoded-resp (dns-proto/decode-packet resp-bytes)
         ;; 2. SMTP session parity
         s0 (:state (smtp-proto/greeting (smtp-proto/init-session {:domain "bitecho.org" :allowed-recipients #{"@bitecho.org"}})))
         s1 (:state (smtp-proto/handle-smtp-line s0 "EHLO mail.example.com"))
         s2 (:state (smtp-proto/handle-smtp-line s1 "MAIL FROM:<alice@example.com>"))
         rcpt-res (smtp-proto/handle-smtp-line s2 (if relay-attack? "RCPT TO:<victim@evil.com>" "RCPT TO:<admin@bitecho.org>"))
         ;; 3. Artifact pointer normalization + verification parity
         blob (data/make-blob (.getBytes (str "payload-" seed) StandardCharsets/UTF_8) "text/plain")
         ptr (data/sign-pointer sk {:pointer/authority pk
                                    :pointer/subnet "bitecho.org/infra"
                                    :pointer/path (str "web/test-" seed ".txt")
                                    :pointer/seq 1
                                    :pointer/target (:blob/cid blob)
                                    :pointer/proof {:proof/type :self}})
         norm-ptr (core-infra/normalize-artifact-pointer
                   {"authority" (:pointer/authority ptr)
                    "subnet" (:pointer/subnet ptr)
                    "path" (:pointer/path ptr)
                    "seq" (:pointer/seq ptr)
                    "target" (:pointer/target ptr)
                    "proof" {"type" "self"}
                    "sig" (:pointer/sig ptr)})]
     (and (= :noerror (:rcode decoded-resp))
          (pos? (count (:answers decoded-resp)))
          (if relay-attack?
            (and (some #(str/starts-with? % "550") (:responses rcpt-res))
                 (some #(= :diagnose (:effect %)) (:effects rcpt-res)))
            (some #(str/starts-with? % "250") (:responses rcpt-res)))
          (true? (:ok? (data/verify-pointer norm-ptr)))))))

(defspec ^{:doc "Pure validator Fressian snapshot round-trip (strip -> encode -> decode -> restore), authenticated agent envelope unwrapping, and validator chain-state snapshot signing preserve 100% invariant parity."}
  prop-validator-fressian-snapshot-and-agent-envelope-parity 50
  (prop/for-all
   [seed (gen/choose 1 100000)
    epoch (gen/choose 1 500)
    balance (gen/choose 100 10000000)
    burn-amt (gen/choose 10 500)]
   (let [val-kp (crypto/generate-keypair (str "d36-val-" seed))
         val-pk (kp->pk-hex val-kp)
         val-sk (kp->sk val-kp)
         agent-kp (crypto/generate-keypair (str "d36-agent-" seed))
         agent-pk (kp->pk-hex agent-kp)
         agent-sk (kp->sk agent-kp)
         ident {:node-id :node1
                :pubkey-hex val-pk
                :privkey-hex (basalt/bytes->hex val-sk)
                :keypair {:public (:public val-kp) :private val-sk}}
         cfg {:node/id :node1
              :network :devnet
              :genesis-ledger {agent-pk {:balance balance :seq 3 :deps ["dep-1"]}}
              :cluster {:validators [val-pk]
                        :nodes {:node1 {:pubkey val-pk :ip "127.0.0.1" :port 5000}}}}
         st0 (-> (core-mesh/build-initial-node-state cfg ident)
                 (assoc :epoch epoch
                        :last-executed-finalized-epoch epoch
                        :notarized-blocks #{"b1" "b2"}
                        :finalized-blocks #{"b1"}
                        :blocks {"b1" (streamlet/map->Block {:epoch epoch :parent-hash "genesis" :txs [] :proposer val-pk :signature "sig"})}
                        :rng (crypto/make-random seed)))
         fressian-bytes (core-mesh/encode-snapshot-bytes st0)
         restored (core-mesh/decode-snapshot-bytes fressian-bytes)
         rebound (core-mesh/rebind-restored-state restored cfg ident)
         ;; Test wrap-agent-event -> Fressian wire -> unwrap-authenticated-agent-event
         raw-ev {:type :signaling-burn :sender agent-pk :burn burn-amt}
         wrapped (core-mesh/wrap-agent-event raw-ev agent-pk agent-sk)
         wire-ev (fressian/encode-wire wrapped)
         unwrapped (core-mesh/unwrap-authenticated-agent-event wire-ev)
         ;; Test build-validator-chain-state-snapshot -> verify-chain-state-snapshot-signature
         nonce (str "nonce-" seed)
         snap (core-mesh/build-validator-chain-state-snapshot rebound ident agent-pk nonce)]
     (and (= epoch (:epoch rebound))
          (= epoch (:last-executed-finalized-epoch rebound))
          (nil? (:node-private-key restored))
          (some? (:node-private-key rebound))
          (instance? bitecho.economy.account.AccountState (get-in rebound [:ledger agent-pk]))
          (instance? bitecho.streamlet.core.Block (get-in rebound [:blocks "b1"]))
          (set? (:notarized-blocks rebound))
          (set? (:finalized-blocks rebound))
          (= :signaling-burn (:type unwrapped))
          (= agent-pk (:sender unwrapped))
          (= burn-amt (:burn unwrapped))
          (map? snap)
          (= val-pk (:validator-pubkey snap))
          (= balance (:balance snap))
          (= epoch (:finalized-epoch snap))
          (true? (relay/verify-chain-state-snapshot-signature snap))))))

;; =============================================================================
;; 2. Live Node.js Infra-Node Full Parity E2E Test
;; =============================================================================

(deftest test-nodejs-infra-node-full-parity-e2e
  (testing "Live `node dist/bitecho-full-node.cjs infra-node <config.edn>` provides full JVM infra-node parity across HTTP/HTTPS/TLS-GCM/UDP-DNS/Artifact/Relay/CONNECT/SMTP"
    (let [bundle-file (io/file "dist/bitecho-full-node.cjs")]
      (is (.exists bundle-file) "dist/bitecho-full-node.cjs must exist (run ./scripts/build-full-node-bundle.sh)")
      (when (.exists bundle-file)
        (let [tmp-dir (make-temp-dir "d36-node-infra-e2e-")
              state-dir (io/file tmp-dir "state")
              public-dir (io/file tmp-dir "public")
              cfg-file (io/file tmp-dir "config.edn")
              tls-secret-file (io/file tmp-dir "tls-secret.key")
              ;; Generate a real 32-byte shared TLS secret + self-signed cert encrypted in Fressian tls/current-cert
              ;; to verify exact AES-256-GCM decryption parity between JVM and Node.js!
              tls-secret-hex "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
              _ (.mkdirs state-dir)
              _ (.mkdirs public-dir)
              _ (spit tls-secret-file (str tls-secret-hex "\n"))
              _ (spit (io/file public-dir "index.md") "# Bitecho Node.js Infra\n")
              _ (spit (io/file public-dir "SKILL.md") "# Skill Doc\n")
              ;; Create a mock echo TCP server for HTTP CONNECT tunnel test
              echo-server (ServerSocket. 0 10 (InetAddress/getByName "127.0.0.1"))
              echo-port (.getLocalPort echo-server)
              _ (doto (Thread.
                       ^Runnable
                       (fn []
                         (try
                           (while (not (.isClosed echo-server))
                             (let [s (.accept echo-server)]
                               (future
                                 (try
                                   (let [in (.getInputStream s)
                                         out (.getOutputStream s)
                                         buf (byte-array 1024)
                                         n (.read in buf)]
                                     (when (pos? n)
                                       (.write out buf 0 n)
                                       (.flush out)))
                                   (catch Exception _ nil)
                                   (finally (try (.close s) (catch Exception _ nil)))))))
                           (catch Exception _ nil))))
                  (.setDaemon true)
                  (.start))
              ;; Create a valid self-signed TLS bundle & encrypt key into subnet-pointers.fressian
              auth-kp (crypto/generate-keypair "e2e-node-infra-auth")
              auth-pk (kp->pk-hex auth-kp)
              auth-sk (kp->sk auth-kp)
              cert-bundle (http-shell/generate-self-signed-cert "bitecho.org" 30)
              cert-pem (http-shell/encode-cert-pem (:certificate cert-bundle))
              key-pem (http-shell/encode-private-key-pem (:private-key cert-bundle))
              enc-key (jvm-infra/encrypt-tls-key-pem (basalt/hex->bytes tls-secret-hex) key-pem)
              tls-blob (data/make-blob (fressian/encode-canonical {:cert-pem cert-pem :encrypted-key enc-key})
                                       "application/fressian")
              tls-cid (:blob/cid tls-blob)
              tls-blob-dir (io/file state-dir "blobs" (subs tls-cid 0 2))
              _ (.mkdirs tls-blob-dir)
              _ (Files/write (.toPath (io/file tls-blob-dir tls-cid)) ^bytes (:blob/bytes tls-blob) (into-array java.nio.file.OpenOption []))
              tls-ptr (data/sign-pointer auth-sk {:pointer/authority auth-pk
                                                  :pointer/subnet "bitecho.org/infra"
                                                  :pointer/path "tls/current-cert"
                                                  :pointer/seq 1
                                                  :pointer/target tls-cid
                                                  :pointer/proof {:proof/type :self}})
              policy (core-infra/default-infra-policy {:trust-anchors #{auth-pk} :threshold 1})
              snap-bytes (fressian/encode-canonical
                          {:subnet-id "bitecho.org/infra"
                           :policy policy
                           :pointers {["bitecho.org/infra" "tls/current-cert"] tls-ptr}})
              _ (Files/write (.toPath (io/file state-dir "subnet-pointers.fressian"))
                             ^bytes snap-bytes
                             (into-array java.nio.file.OpenOption []))
              ;; Write config.edn with ephemeral ports (0)
              cfg {:node/id :ns3
                   :domain "bitecho.org"
                   :state-dir (.getAbsolutePath state-dir)
                   :tls-secret-file (.getAbsolutePath tls-secret-file)
                   :dns {:enabled? true
                         :bind-ip "127.0.0.1"
                         :port 0
                         :ttl-seconds 60
                         :ns-ttl-seconds 3600
                         :hostmaster "hostmaster.bitecho.org"
                         :subdomains #{"@" "www" "ingress"}
                         :delegated-ingress {"nexus.ingress" {:ns "ns1.nexus.ingress.bitecho.org" :ip4 "136.62.15.220" :ttl 60}}}
                   :http {:enabled? true
                          :bind-ip "127.0.0.1"
                          :http-port 0
                          :https-port 0
                          :relay {:min-signaling-burn 0}
                          :content-root (.getAbsolutePath public-dir)
                          :connect-targets #{(str "127.0.0.1:" echo-port) "allowed.ingress.bitecho.org:443"}
                          :connect-routes {"allowed.ingress.bitecho.org:443" {:host "127.0.0.1" :port echo-port}}}
                   :smtp {:enabled? true
                          :bind-ip "127.0.0.1"
                          :port 0
                          :allowed-recipients #{"@bitecho.org"}}
                   :validator {:http {:enabled? true :host "127.0.0.1" :port 0}}
                   :cluster {:enabled? false
                             :nodes {:ns1 {:ip4 "35.212.172.159" :pubkey auth-pk}
                                     :ns2 {:ip4 "35.209.253.119" :pubkey auth-pk}
                                     :ns3 {:ip4 "35.211.30.106" :pubkey auth-pk}}}}
              _ (spit cfg-file (pr-str cfg))
              pb (ProcessBuilder. ^java.util.List [(node-bin-path)
                                                   (.getAbsolutePath bundle-file)
                                                   "infra-node"
                                                   (.getAbsolutePath cfg-file)])
              _ (.redirectErrorStream pb false)
              proc (.start pb)]
          (try
            (let [stdout-rdr (BufferedReader. (InputStreamReader. (.getInputStream proc) StandardCharsets/UTF_8))
                  ready-line (loop [attempts 0]
                               (when (< attempts 100)
                                 (if-let [l (.readLine stdout-rdr)]
                                   (if (str/includes? l "infra-node-ready")
                                     l
                                     (recur (inc attempts)))
                                   (do (Thread/sleep 50) (recur (inc attempts))))))
                  ready (when ready-line (json/read-str ready-line))
                  http-port (get ready "http_port")
                  https-port (get ready "https_port")
                  dns-port (get ready "dns_udp_port")
                  smtp-port (get ready "smtp_port")
                  diag-port (get ready "diag_port")
                  client (trust-all-http-client)]
              (is (some? ready) "Node.js infra-node must emit infra-node-ready JSON line")
              (is (pos? (long (or http-port 0))))
              (is (pos? (long (or https-port 0))))
              (is (pos? (long (or dns-port 0))))
              (is (pos? (long (or smtp-port 0))))

              ;; 1. /healthz and /statusz on HTTP & diag port
              (let [hz-resp (.send client
                                   (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/healthz")))
                                       (.GET) (.build))
                                   (HttpResponse$BodyHandlers/ofString))
                    hz (json/read-str (.body hz-resp))
                    stz-resp (.send client
                                    (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/statusz")))
                                        (.GET) (.build))
                                    (HttpResponse$BodyHandlers/ofString))
                    stz (json/read-str (.body stz-resp))]
                (is (= 200 (.statusCode hz-resp)))
                (is (true? (get hz "ok")))
                (is (= "nodejs" (get hz "runtime")))
                (is (= 200 (.statusCode stz-resp)))
                (is (true? (get stz "ok")))
                (is (= "nodejs" (get stz "runtime")))
                (is (contains? stz "role"))
                (is (contains? stz "egress_bytes"))
                (when (pos? (long (or diag-port 0)))
                  (let [d-resp (.send client
                                      (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" diag-port "/statusz")))
                                          (.GET) (.build))
                                      (HttpResponse$BodyHandlers/ofString))]
                    (is (= 200 (.statusCode d-resp))))))

              ;; 2. HTTPS :443 TLS (decrypted from AES-256-GCM Fressian blob!) serving / (index.md) and blocking traversal
              (let [root-resp (.send client
                                     (-> (HttpRequest/newBuilder (URI/create (str "https://127.0.0.1:" https-port "/")))
                                         (.GET) (.build))
                                     (HttpResponse$BodyHandlers/ofString))
                    ct (or (.orElse (.firstValue (.headers root-resp) "content-type") "") "")
                    trav-resp (.send client
                                     (-> (HttpRequest/newBuilder (URI/create (str "https://127.0.0.1:" https-port "/%2e%2e/etc/passwd")))
                                         (.GET) (.build))
                                     (HttpResponse$BodyHandlers/ofString))]
                (is (= 200 (.statusCode root-resp)))
                (is (= "text/markdown; charset=utf-8" (str/lower-case ct)))
                (is (str/includes? (.body root-resp) "Bitecho Node.js Infra"))
                (is (= 403 (.statusCode trav-resp))))

              ;; 3. Authoritative UDP DNS (:53) for A record & delegated ingress NS record
              (with-open [ds (DatagramSocket.)]
                (.setSoTimeout ds 3000)
                (let [addr (InetAddress/getByName "127.0.0.1")
                      q-a (dns-proto/encode-packet {:id 4242 :qr? false :opcode 0 :rd? false
                                                    :questions [{:qname "bitecho.org" :qtype :A :qclass :IN}]})
                      _ (.send ds (DatagramPacket. q-a (alength q-a) addr (int dns-port)))
                      rbuf (byte-array 512)
                      rpkt (DatagramPacket. rbuf (alength rbuf))
                      _ (.receive ds rpkt)
                      ans-a (dns-proto/decode-packet (java.util.Arrays/copyOf rbuf (.getLength rpkt)))
                      q-ns (dns-proto/encode-packet {:id 4243 :qr? false :opcode 0 :rd? false
                                                     :questions [{:qname "nexus.ingress.bitecho.org" :qtype :NS :qclass :IN}]})
                      _ (.send ds (DatagramPacket. q-ns (alength q-ns) addr (int dns-port)))
                      rpkt2 (DatagramPacket. rbuf (alength rbuf))
                      _ (.receive ds rpkt2)
                      ans-ns (dns-proto/decode-packet (java.util.Arrays/copyOf rbuf (.getLength rpkt2)))]
                  (is (= :noerror (:rcode ans-a)))
                  (is (pos? (count (:answers ans-a))))
                  (is (= :noerror (:rcode ans-ns)))
                  (is (or (pos? (count (:answers ans-ns)))
                          (pos? (count (:authority ans-ns)))))))

              ;; 4. Artifact API: POST /artifact/v1/blob + POST /artifact/v1/pointer -> GET /<path>, GET /artifact/v1/blob/<cid>, GET /artifact/v1/list
              (let [art-bytes (.getBytes "hello-from-nodejs-artifact\n" StandardCharsets/UTF_8)
                    art-blob (data/make-blob art-bytes "text/plain; charset=utf-8")
                    art-cid (:blob/cid art-blob)
                    blob-resp (.send client
                                     (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/artifact/v1/blob")))
                                         (.header "Content-Type" "text/plain; charset=utf-8")
                                         (.header "X-Bitecho-Blob-Cid" art-cid)
                                         (.header "X-Bitecho-Pubkey" auth-pk)
                                         (.POST (HttpRequest$BodyPublishers/ofByteArray art-bytes))
                                         (.build))
                                     (HttpResponse$BodyHandlers/ofString))
                    blob-json (json/read-str (.body blob-resp))
                    art-ptr (data/sign-pointer auth-sk {:pointer/authority auth-pk
                                                        :pointer/subnet "bitecho.org/infra"
                                                        :pointer/path "web/hello.txt"
                                                        :pointer/seq 1
                                                        :pointer/target art-cid
                                                        :pointer/proof {:proof/type :self}})
                    ptr-resp (.send client
                                    (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/artifact/v1/pointer")))
                                        (.header "Content-Type" "application/edn")
                                        (.POST (HttpRequest$BodyPublishers/ofString (pr-str art-ptr)))
                                        (.build))
                                    (HttpResponse$BodyHandlers/ofString))
                    ptr-json (json/read-str (.body ptr-resp))
                    list-resp (.send client
                                     (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/artifact/v1/list?prefix=web/")))
                                         (.GET) (.build))
                                     (HttpResponse$BodyHandlers/ofString))
                    list-json (json/read-str (.body list-resp))
                    get-blob-resp (.send client
                                         (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/artifact/v1/blob/" art-cid)))
                                             (.GET) (.build))
                                         (HttpResponse$BodyHandlers/ofString))
                    get-web-resp (.send client
                                        (-> (HttpRequest/newBuilder (URI/create (str "https://127.0.0.1:" https-port "/hello.txt")))
                                            (.GET) (.build))
                                        (HttpResponse$BodyHandlers/ofString))]
                (is (= 200 (.statusCode blob-resp)))
                (is (= art-cid (get blob-json "cid")))
                (is (.exists (io/file state-dir "blobs" (subs art-cid 0 2) art-cid)) "Blob must be persisted in blobs/<2>/<cid>")
                (is (= 200 (.statusCode ptr-resp)))
                (is (true? (get ptr-json "ok")))
                (is (= 200 (.statusCode list-resp)))
                (is (some #(= "web/hello.txt" (get % "path")) (get list-json "pointers")))
                (is (= 200 (.statusCode get-blob-resp)))
                (is (= "hello-from-nodejs-artifact\n" (.body get-blob-resp)))
                (is (= 200 (.statusCode get-web-resp)))
                (is (= "hello-from-nodejs-artifact\n" (.body get-web-resp))))

              ;; 5. Relay API: JVM light-node -> Node.js infra-node /relay/v1/send + /relay/v1/poll + /relay/v1/ack
              (let [relay-url (str "http://127.0.0.1:" http-port)
                    sender-kp (crypto/generate-keypair "e2e-relay-sender")
                    recip-kp (crypto/generate-keypair "e2e-relay-recip")
                    sender-id {:pubkey-hex (kp->pk-hex sender-kp) :privkey-bytes (kp->sk sender-kp)}
                    recip-id {:pubkey-hex (kp->pk-hex recip-kp) :privkey-bytes (kp->sk recip-kp)}
                    init-s (light-core/init-light-state sender-id {:subnet-id "test/node-parity"
                                                                   :economy-enabled? false
                                                                   :burn-floor 0
                                                                   :epoch 1})
                    off-res (light-core/handle-command init-s
                                                       {"cmd" "offer" "callee" (:pubkey-hex recip-id) "price" 0 "burn" 0}
                                                       (:privkey-bytes sender-id))
                    off-envs (:net-envelopes off-res)]
                (is (seq off-envs))
                (doseq [env off-envs]
                  (let [send-json (light-node/submit-relay-envelope! relay-url env)]
                    (is (true? (get send-json "ok")))))
                (let [poll-json (light-node/poll-relay-envelopes! relay-url (:pubkey-hex recip-id) (:privkey-bytes recip-id))
                      msgs (get poll-json "messages" [])
                      bcasts (get poll-json "broadcasts" [])]
                  (is (true? (get poll-json "ok")))
                  (is (pos? (+ (count msgs) (count bcasts))))
                  (when (seq msgs)
                    (let [seq-val (or (get (last msgs) "relay_seq") (get (last msgs) "relay-seq"))
                          ack-json (light-node/ack-relay-envelopes! relay-url (:pubkey-hex recip-id) (:privkey-bytes recip-id) seq-val)]
                      (is (true? (get ack-json "ok")))))))

              ;; 6. HTTP CONNECT tunneling (allowlisted succeeds, disallowed returns 403)
              (with-open [s (Socket. "127.0.0.1" (int https-port))]
                (.setSoTimeout s 3000)
                (let [out (.getOutputStream s)
                      in (BufferedReader. (InputStreamReader. (.getInputStream s) StandardCharsets/UTF_8))]
                  (.write out (.getBytes "CONNECT allowed.ingress.bitecho.org:443 HTTP/1.1\r\nHost: allowed.ingress.bitecho.org:443\r\n\r\n" StandardCharsets/UTF_8))
                  (.flush out)
                  (let [status-line (.readLine in)
                        _ (.readLine in)]
                    (is (str/includes? (or status-line "") "200 Connection Established"))
                    (.write out (.getBytes "PING-TUNNEL\n" StandardCharsets/UTF_8))
                    (.flush out)
                    (is (= "PING-TUNNEL" (.readLine in))))))
              (with-open [s (Socket. "127.0.0.1" (int https-port))]
                (.setSoTimeout s 3000)
                (let [out (.getOutputStream s)
                      in (BufferedReader. (InputStreamReader. (.getInputStream s) StandardCharsets/UTF_8))]
                  (.write out (.getBytes "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n" StandardCharsets/UTF_8))
                  (.flush out)
                  (let [status-line (.readLine in)]
                    (is (str/includes? (or status-line "") "403 Forbidden")))))

              ;; 7. SMTP ingress: accepts @bitecho.org and rejects open relay @evil.com
              (with-open [s (Socket. "127.0.0.1" (int smtp-port))]
                (.setSoTimeout s 3000)
                (let [in (BufferedReader. (InputStreamReader. (.getInputStream s) StandardCharsets/UTF_8))
                      out (BufferedWriter. (OutputStreamWriter. (.getOutputStream s) StandardCharsets/UTF_8))
                      send-cmd (fn [cmd]
                                 (.write out (str cmd "\r\n"))
                                 (.flush out)
                                 (.readLine in))
                      greet (.readLine in)
                      helo (send-cmd "HELO test.example.com")
                      mfrom (send-cmd "MAIL FROM:<alice@example.com>")
                      rcpt-bad (send-cmd "RCPT TO:<victim@evil.com>")
                      rcpt-ok (send-cmd "RCPT TO:<admin@bitecho.org>")
                      data-resp (send-cmd "DATA")
                      _ (.write out "Subject: NodeJS Infra E2E\r\n\r\nHello Bitecho!\r\n.\r\n")
                      _ (.flush out)
                      queued (.readLine in)
                      quit (send-cmd "QUIT")]
                  (is (str/starts-with? (or greet "") "220"))
                  (is (str/starts-with? (or helo "") "250"))
                  (is (str/starts-with? (or mfrom "") "250"))
                  (is (str/starts-with? (or rcpt-bad "") "550"))
                  (is (str/starts-with? (or rcpt-ok "") "250"))
                  (is (str/starts-with? (or data-resp "") "354"))
                  (is (str/starts-with? (or queued "") "250"))
                  (is (str/starts-with? (or quit "") "221")))))
            (finally
              (.destroy proc)
              (.waitFor proc 3 TimeUnit/SECONDS)
              (.destroyForcibly proc)
              (try (.close echo-server) (catch Exception _ nil))
              (delete-dir-recursively! tmp-dir))))))))

(deftest test-nodejs-validator-run-and-embedded-infra-validator-parity-e2e
  (testing "Live `node dist/bitecho-full-node.cjs run <config.edn>` and `infra-node` with embedded `:validator` provide full JVM validator & Fressian state continuity parity"
    (let [bundle-file (io/file "dist/bitecho-full-node.cjs")]
      (is (.exists bundle-file) "dist/bitecho-full-node.cjs must exist")
      (when (.exists bundle-file)
        (let [tmp-dir (make-temp-dir "d36-node-val-e2e-")
              state-dir (io/file tmp-dir "val-state")
              infra-state-dir (io/file tmp-dir "infra-state")
              cfg-file (io/file tmp-dir "val-config.edn")
              infra-cfg-file (io/file tmp-dir "infra-val-config.edn")
              val-kp (crypto/generate-keypair "e2e-val-node1")
              val-pk (kp->pk-hex val-kp)
              val-sk (kp->sk val-kp)
              agent-kp (crypto/generate-keypair "e2e-val-agent")
              agent-pk (kp->pk-hex agent-kp)
              _ (.mkdirs (io/file state-dir "identity"))
              _ (.mkdirs (io/file state-dir "state"))
              _ (.mkdirs (io/file infra-state-dir "identity"))
              ;; Pre-seed a JVM-written Fressian snapshot at <state-dir>/state/snapshot-node1.edn with epoch=42
              snap-file (io/file state-dir "state" "snapshot-node1.edn")
              ident-map {:pubkey-hex val-pk
                         :privkey-hex (basalt/bytes->hex val-sk)}
              _ (spit (io/file state-dir "identity" "node-identity.edn") (pr-str ident-map))
              _ (spit (io/file infra-state-dir "identity" "node-identity.edn") (pr-str ident-map))
              val-cfg {:node/id :node1
                       :network :devnet
                       :state-dir (.getAbsolutePath state-dir)
                       :genesis-ledger {agent-pk {:balance 777000 :seq 2 :deps ["tx-prev"]}}
                       :protocol {:tick-interval-ms 60000}
                       :http {:enabled? true :host "127.0.0.1" :port 0}
                       :transport :in-memory
                       :cluster {:listen-agents? false
                                 :validators [val-pk]
                                 :nodes {:node1 {:ip "127.0.0.1"
                                                 :port 5000
                                                 :pubkey val-pk}}}}
              init-st (-> (core-mesh/build-initial-node-state val-cfg {:node-id :node1
                                                                       :pubkey-hex val-pk
                                                                       :privkey-hex (basalt/bytes->hex val-sk)
                                                                       :keypair {:public (:public val-kp) :private val-sk}})
                          (assoc :epoch 42
                                 :last-executed-finalized-epoch 41
                                 :head-hash "block-42"
                                 :notarized-blocks #{"block-41" "block-42"}
                                 :finalized-blocks #{"block-41"}))
              _ (Files/write (.toPath snap-file)
                             ^bytes (core-mesh/encode-snapshot-bytes init-st)
                             (into-array java.nio.file.OpenOption []))
              _ (spit cfg-file (pr-str val-cfg))
              pb (ProcessBuilder. ^java.util.List [(node-bin-path)
                                                   (.getAbsolutePath bundle-file)
                                                   "run"
                                                   (.getAbsolutePath cfg-file)])
              proc (.start pb)
              ;; Also start infra-node with embedded :validator
              infra-cfg {:node/id :ns1
                         :domain "bitecho.org"
                         :state-dir (.getAbsolutePath infra-state-dir)
                         :dns {:enabled? false}
                         :smtp {:enabled? false}
                         :http {:enabled? true :bind-ip "127.0.0.1" :http-port 0 :https-port 0 :redirect-http-to-https? false}
                         :cluster {:enabled? false
                                   :nodes {:ns1 {:ip4 "127.0.0.1" :pubkey val-pk}}}
                         :validator {:node/id :ns1
                                     :network :devnet
                                     :state-dir (.getAbsolutePath infra-state-dir)
                                     :genesis-ledger {agent-pk {:balance 888000 :seq 5 :deps []}}
                                     :protocol {:tick-interval-ms 60000}
                                     :http {:enabled? true :host "127.0.0.1" :port 0}
                                     :transport :in-memory
                                     :cluster {:listen-agents? false
                                               :validators [val-pk]
                                               :nodes {:ns1 {:ip "127.0.0.1" :port 5000 :pubkey val-pk}}}}}
              _ (spit infra-cfg-file (pr-str infra-cfg))
              pb-infra (ProcessBuilder. ^java.util.List [(node-bin-path)
                                                         (.getAbsolutePath bundle-file)
                                                         "infra-node"
                                                         (.getAbsolutePath infra-cfg-file)])
              proc-infra (.start pb-infra)]
          (try
            (let [rdr (BufferedReader. (InputStreamReader. (.getInputStream proc) StandardCharsets/UTF_8))
                  started-line (loop [attempts 0]
                                 (when (< attempts 100)
                                   (if-let [l (.readLine rdr)]
                                     (if (str/includes? l "Bitecho node started:")
                                       l
                                       (recur (inc attempts)))
                                     (do (Thread/sleep 50) (recur (inc attempts))))))
                  http-port (when started-line
                              (some-> (re-find #"http=:(\d+)" started-line) second Long/parseLong))
                  rdr-infra (BufferedReader. (InputStreamReader. (.getInputStream proc-infra) StandardCharsets/UTF_8))
                  infra-ready-line (loop [attempts 0]
                                     (when (< attempts 100)
                                       (if-let [l (.readLine rdr-infra)]
                                         (if (str/includes? l "infra-node-ready")
                                           l
                                           (recur (inc attempts)))
                                         (do (Thread/sleep 50) (recur (inc attempts))))))
                  infra-ready (when infra-ready-line (json/read-str infra-ready-line))
                  infra-http-port (get infra-ready "http_port")
                  infra-diag-port (get infra-ready "diag_port")
                  client (trust-all-http-client)]
              (is (some? started-line) "Standalone validator must emit Bitecho node started line")
              (is (pos? (long (or http-port 0))))
              (is (pos? (long (or infra-http-port 0))))
              (is (pos? (long (or infra-diag-port 0))))

              ;; 1. Verify standalone validator /healthz, /statusz (loaded from JVM Fressian snapshot!), /connz, /burnsz, /accountz
              (let [hz (.send client
                              (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/healthz")))
                                  (.GET) (.build))
                              (HttpResponse$BodyHandlers/ofString))
                    stz (.send client
                               (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/statusz")))
                                   (.GET) (.build))
                               (HttpResponse$BodyHandlers/ofString))
                    parsed-stz (core-mesh/parse-statusz-line (.body stz))
                    cz (.send client
                              (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/connz")))
                                  (.GET) (.build))
                              (HttpResponse$BodyHandlers/ofString))
                    bz (.send client
                              (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/burnsz")))
                                  (.GET) (.build))
                              (HttpResponse$BodyHandlers/ofString))
                    az (.send client
                              (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/accountz?pubkey=" agent-pk "&nonce=test-n1")))
                                  (.GET) (.build))
                              (HttpResponse$BodyHandlers/ofString))
                    az-map (edn/read-string (.body az))]
                (is (= "ok\n" (.body hz)))
                (is (= "validator" (:role parsed-stz)))
                (is (= 42 (:epoch parsed-stz)) "Node.js validator must restore epoch=42 from JVM Fressian snapshot")
                (is (= 41 (:finalized_epoch parsed-stz)))
                (is (= "block-42" (:head parsed-stz)))
                (is (map? (edn/read-string (.body cz))))
                (is (map? (edn/read-string (.body bz))))
                (is (= 777000 (:spendable az-map)))
                (is (= 2 (get-in az-map [:account :seq])))
                (is (true? (relay/verify-chain-state-snapshot-signature (:snapshot az-map)))))

              ;; 2. Verify infra-node with embedded :validator returns signed snapshot on /relay/v1/chain-state AND validator /statusz on diag_port
              (let [cs-resp (.send client
                                   (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" infra-http-port "/relay/v1/chain-state?pubkey=" agent-pk "&nonce=relay-n2")))
                                       (.GET) (.build))
                                   (HttpResponse$BodyHandlers/ofString))
                    cs-json (json/read-str (.body cs-resp))
                    snaps (get cs-json "snapshots" [])
                    diag-stz (.send client
                                    (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" infra-diag-port "/statusz")))
                                        (.GET) (.build))
                                    (HttpResponse$BodyHandlers/ofString))
                    parsed-diag (core-mesh/parse-statusz-line (.body diag-stz))]
                (is (= 200 (.statusCode cs-resp)))
                (is (true? (get cs-json "ok")))
                (is (= 1 (count snaps)))
                (is (true? (relay/verify-chain-state-snapshot-signature (first snaps))))
                (is (= 888000 (get (first snaps) "balance")))
                (is (= "validator" (:role parsed-diag)))))
            (finally
              (.destroy proc)
              (.destroy proc-infra)
              (.waitFor proc 3 TimeUnit/SECONDS)
              (.waitFor proc-infra 3 TimeUnit/SECONDS)
              (.destroyForcibly proc)
              (.destroyForcibly proc-infra)
              (delete-dir-recursively! tmp-dir))))))))

;; =============================================================================
;; 3. Rule 6 Ops Script & Runtime Preflight Gate Verification
;; =============================================================================

(deftest test-ops-run-node-preflight-and-cluster-script-parity
  (testing "Rule 6: scripts/infra_cluster.sh, scripts/cluster.sh, scripts/run-infra-node.sh, and scripts/run-validator-node.sh implement fail-closed active-runtime.env + Node >= 22 preflight gate"
    (let [run-script (io/file "scripts/run-infra-node.sh")
          val-run-script (io/file "scripts/run-validator-node.sh")
          cluster-script (io/file "scripts/infra_cluster.sh")
          val-cluster-script (io/file "scripts/cluster.sh")]
      (is (.exists run-script) "scripts/run-infra-node.sh must exist")
      (is (.exists val-run-script) "scripts/run-validator-node.sh must exist")
      (when (.exists run-script)
        (let [content (slurp run-script)]
          (is (str/includes? content "active-runtime.env"))
          (is (str/includes? content "bitecho-full-node.cjs"))
          (is (str/includes? content "22"))))
      (when (.exists val-run-script)
        (let [content (slurp val-run-script)]
          (is (str/includes? content "active-runtime.env"))
          (is (str/includes? content "bitecho-full-node.cjs"))
          (is (str/includes? content "run"))
          (is (str/includes? content "22"))))
      (let [cluster-content (slurp cluster-script)
            val-cluster-content (slurp val-cluster-script)]
        (is (str/includes? cluster-content "run-node.sh"))
        (is (str/includes? cluster-content "active-runtime.env"))
        (is (str/includes? val-cluster-content "run-node.sh"))
        (is (str/includes? val-cluster-content "active-runtime.env"))))))
