(ns bitecho.shell.http
  "Unified Edge HTTP (`:80`) + Port `:443` Passthrough Multiplexer + mTLS HTTPS Shell (Gaps G6, G12, G17):
   - Single-authority generation-tagged lifecycle state via `bitecho.shell.infra/transition-shell` (Rule 4).
   - Port `:443` front-door multiplexer with bounded `<= 1024`-byte / `2s`-timeout initial peek:
     1. RFC 4571 DTLS (`0x16 0xFE`) -> `:ingress-target`
     2. RFC 4571 STUN (`0x00 0x01` + `0x2112A442`) -> `:ingress-target`
     3. TLS SNI `ingress.<domain>` / `*.ingress.<domain>` -> `:ingress-target`
     4. Allowlisted `HTTP CONNECT <host>:<port> HTTP/1.1` tunnel (failing closed with `403` + counted `:diagnose` otherwise)
     5. Internal JDK 25 Virtual-Thread `HttpsServer` configured with `SSLParameters.setWantClientAuth(true)` mTLS.
   - Serves immutable `Blob`s referenced by Subnet `Pointer`s (`\"web/<path>\"`) after enforcing the
     target Subnet's `:subnet/gate` (`check-gate-admission`, Gap G12), with `ETag: \"<cid>\"`, `304 Not Modified`,
     `206 Partial Content`, gzip compression, and zero-heap `FileChannel` streaming via `bitecho.shell.blob-fs` (Gap G6).
   - Hot-reloadable X.509 TLS manager integrated with `\"tls/current-cert\"` follower replication."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.acme :as acme-proto]
            [bitecho.core.protocol.dns :as dns-proto]
            [bitecho.core.subnet :as subnet]
            [bitecho.fressian :as fressian]
            [bitecho.shell.infra :as infra]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer HttpsConfigurator HttpsExchange HttpsParameters HttpsServer]
           [java.io ByteArrayInputStream ByteArrayOutputStream File InputStream OutputStream RandomAccessFile]
           [java.net InetSocketAddress ServerSocket Socket SocketException]
           [java.nio ByteBuffer]
           [java.nio.charset StandardCharsets]
           [java.nio.file CopyOption Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]
           [java.security KeyFactory KeyPair PrivateKey SecureRandom Signature]
           [java.security.cert CertificateFactory X509Certificate]
           [java.security.spec PKCS8EncodedKeySpec]
           [java.text SimpleDateFormat]
           [java.util Arrays Base64 Date]
           [java.util.concurrent Executors ExecutorService]
           [java.util.concurrent.atomic AtomicInteger]
           [java.util.zip GZIPOutputStream]
           [javax.net.ssl KeyManager SSLContext SSLEngine SSLPeerUnverifiedException TrustManager X509ExtendedKeyManager X509TrustManager]))

;; =============================================================================
;; 1. X.509 Certificate Generation, PEM Codec, & Dynamic mTLS SSLContext
;; =============================================================================

(def ^:private mime-encoder
  (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII)))

(defn generate-self-signed-cert
  "Generates a self-signed ECDSA (P-256) X.509 certificate and private key for `domain`."
  ([domain] (generate-self-signed-cert domain 30))
  ([domain validity-days]
   (let [c (sun.security.tools.keytool.CertAndKeyGen. "EC" "SHA256withECDSA")
         validity-secs (* (long (or validity-days 30)) 86400)]
     (.generate c 256)
     (let [x500 (sun.security.x509.X500Name. (str "CN=" domain))
           exts (sun.security.x509.CertificateExtensions.)
           gn (sun.security.x509.GeneralNames.)
           _ (when (and domain (not (str/starts-with? domain "*")))
               (try
                 (.add gn (sun.security.x509.GeneralName. (sun.security.x509.DNSName. domain)))
                 (catch Exception _ nil)))
           _ (.add gn (sun.security.x509.GeneralName. (sun.security.x509.DNSName. "localhost")))
           _ (.add gn (sun.security.x509.GeneralName. (sun.security.x509.IPAddressName. "127.0.0.1")))
           san-ext (sun.security.x509.SubjectAlternativeNameExtension. gn)
           _ (.setExtension exts (sun.security.x509.SubjectAlternativeNameExtension/NAME) san-ext)
           cert (.getSelfCertificate c x500 (Date.) validity-secs exts)
           priv-key (.getPrivateKey c)]
       {:certificate cert
        :certificates [cert]
        :private-key priv-key
        :expires-at (.getTime (.getNotAfter cert))
        :self-signed? true}))))

(defn generate-ed25519-client-cert
  "Generates a self-signed Ed25519 X.509 client certificate whose `SubjectPublicKeyInfo` is an exact
   44-byte (`88`-hex) Bitecho Ed25519 public key (UNIFICATION.md §6 Instance #5 mTLS + DAC)."
  ([common-name] (generate-ed25519-client-cert common-name 30))
  ([common-name validity-days]
   (let [c (sun.security.tools.keytool.CertAndKeyGen. "Ed25519" "Ed25519")
         validity-secs (* (long (or validity-days 30)) 86400)]
     (.generate c 255)
     (let [cert (.getSelfCertificate c (sun.security.x509.X500Name. (str "CN=" common-name)) validity-secs)
           priv-key (.getPrivateKey c)
           spki-hex (str/lower-case (basalt/bytes->hex (.getEncoded (.getPublicKey cert))))]
       {:certificate cert
        :certificates [cert]
        :private-key priv-key
        :pubkey-hex spki-hex
        :expires-at (.getTime (.getNotAfter cert))
        :self-signed? true}))))

(defn generate-cert-and-keypair
  "Generates an X.509 certificate and matching `^KeyPair` covering `domain` using `CertAndKeyGen`."
  ([domain] (generate-cert-and-keypair domain 90))
  ([domain validity-days]
   (let [bundle (generate-self-signed-cert domain validity-days)
         ^X509Certificate cert (:certificate bundle)
         ^PrivateKey priv (:private-key bundle)]
     (assoc bundle
            :keypair (KeyPair. (.getPublicKey cert) priv)
            :self-signed? false))))

(defn encode-cert-pem
  "Serializes an `X509Certificate` to PEM."
  [^X509Certificate cert]
  (str "-----BEGIN CERTIFICATE-----\n"
       (.encodeToString mime-encoder (.getEncoded cert))
       "\n-----END CERTIFICATE-----\n"))

(defn encode-private-key-pem
  "Serializes a PKCS#8 `PrivateKey` to PEM."
  [^PrivateKey k]
  (str "-----BEGIN PRIVATE KEY-----\n"
       (.encodeToString mime-encoder (.getEncoded k))
       "\n-----END PRIVATE KEY-----\n"))

(defn parse-cert-chain-pem
  "Parses one or more X.509 certificates from a PEM string."
  [pem-str]
  (when (and pem-str (not (str/blank? pem-str)))
    (let [cf (CertificateFactory/getInstance "X.509")
          in (ByteArrayInputStream. (.getBytes ^String pem-str StandardCharsets/US_ASCII))]
      (vec (.generateCertificates cf in)))))

(defn parse-private-key-pem
  "Parses a PKCS#8 `PrivateKey` from PEM (EC, Ed25519, or RSA)."
  [pem-str]
  (when (and pem-str (not (str/blank? pem-str)))
    (let [cleaned (-> pem-str
                      (str/replace #"-----BEGIN [A-Z0-9 ]+-----" "")
                      (str/replace #"-----END [A-Z0-9 ]+-----" "")
                      (str/replace #"\s+" ""))
          spec (PKCS8EncodedKeySpec. (.decode (Base64/getDecoder) ^String cleaned))]
      (or (try (.generatePrivate (KeyFactory/getInstance "EC") spec) (catch Exception _ nil))
          (try (.generatePrivate (KeyFactory/getInstance "Ed25519") spec) (catch Exception _ nil))
          (.generatePrivate (KeyFactory/getInstance "RSA") spec)))))

(defn- cert-covers-domain?
  [^X509Certificate cert ^String expected-domain]
  (let [expected (str/lower-case (str/trim expected-domain))
        sans (try
               (when-let [alt-names (.getSubjectAlternativeNames cert)]
                 (keep (fn [entry]
                         (when (= (first entry) 2)
                           (str/lower-case (str (second entry)))))
                       alt-names))
               (catch Exception _ nil))
        cn (try
             (let [dn (.getName (.getSubjectX500Principal cert))]
               (when-let [[_ cn-val] (re-find #"(?i)CN=([^,]+)" dn)]
                 (str/lower-case (str/trim cn-val))))
             (catch Exception _ nil))
        names (set (concat sans (when cn [cn])))]
    (boolean
     (or (contains? names expected)
         (some (fn [pattern]
                 (when (str/starts-with? pattern "*.")
                   (let [suffix (subs pattern 1)]
                     (and (> (count expected) (count suffix))
                          (str/ends-with? expected suffix)
                          (let [prefix (subs expected 0 (- (count expected) (count suffix)))]
                            (and (pos? (count prefix))
                                 (not (str/includes? prefix "."))))))))
               names)))))

(defn validate-tls-bundle!
  "Validates a TLS certificate chain and matching private key against `expected-domain`."
  [certs ^PrivateKey priv-key expected-domain]
  (when (or (empty? certs) (nil? priv-key))
    (throw (ex-info "Missing TLS certificates or private key" {})))
  (let [^X509Certificate leaf (first certs)
        now (System/currentTimeMillis)
        not-after (.getTime (.getNotAfter leaf))
        not-before (.getTime (.getNotBefore leaf))]
    (when (or (<= not-after now) (>= not-before (+ now 300000)))
      (throw (ex-info "Leaf certificate is expired or not yet valid" {:not-after not-after})))
    (let [pub-key (.getPublicKey leaf)
          alg (.getAlgorithm priv-key)
          sig-alg (cond
                    (= alg "RSA") "SHA256withRSA"
                    (= alg "EdDSA") "Ed25519"
                    :else "SHA256withECDSA")
          challenge (.getBytes "bitecho-tls-key-check" StandardCharsets/UTF_8)
          signer (Signature/getInstance sig-alg)
          verifier (Signature/getInstance sig-alg)]
      (.initSign signer priv-key)
      (.update signer challenge)
      (let [sig (.sign signer)]
        (.initVerify verifier pub-key)
        (.update verifier challenge)
        (when-not (.verify verifier sig)
          (throw (ex-info "Private key does not match leaf certificate" {})))))
    (when (and (string? expected-domain) (not (str/blank? expected-domain)) (not= expected-domain "localhost"))
      (when-not (cert-covers-domain? leaf expected-domain)
        (throw (ex-info (str "Certificate does not cover domain: " expected-domain) {:domain expected-domain}))))
    true))

(defn build-ssl-context
  "Builds a dynamic server `SSLContext` supporting hot certificate reload AND optional self-signed
   mTLS client certificates (`SSLParameters.setWantClientAuth(true)` verified at Subnet gate)."
  [bundle-atom]
  (let [km (proxy [X509ExtendedKeyManager] []
             (chooseEngineServerAlias [_ _ ^SSLEngine _] "node-key")
             (chooseServerAlias [_ _ ^Socket _] "node-key")
             (getCertificateChain [alias]
               (when (= alias "node-key")
                 (let [b (if (instance? clojure.lang.IDeref bundle-atom) @bundle-atom bundle-atom)]
                   (into-array X509Certificate (:certificates b)))))
             (getPrivateKey [alias]
               (when (= alias "node-key")
                 (let [b (if (instance? clojure.lang.IDeref bundle-atom) @bundle-atom bundle-atom)]
                   ^PrivateKey (:private-key b))))
             (getServerAliases [_ _] (into-array String ["node-key"]))
             (getClientAliases [_ _] (into-array String []))
             (chooseClientAlias [_ _ ^Socket _] nil)
             (chooseEngineClientAlias [_ _ ^SSLEngine _] nil))
        ;; Permissive X509TrustManager allows self-signed agent client certs to complete TLS CertificateVerify;
        ;; cryptographic pubkey authorization is enforced fail-closed in Subnet check-gate-admission!
        tm (reify X509TrustManager
             (getAcceptedIssuers [_] (into-array X509Certificate []))
             (checkClientTrusted [_ _ _] nil)
             (checkServerTrusted [_ _ _] nil))
        ssl-ctx (SSLContext/getInstance "TLS")]
    (.init ssl-ctx (into-array KeyManager [km]) (into-array TrustManager [tm]) (SecureRandom.))
    ssl-ctx))

(defn- save-tls-bundle!
  [state-dir cert-pem key-pem]
  (when state-dir
    (let [certs-dir (io/file state-dir "certs")
          _ (.mkdirs certs-dir)
          bundle-file (io/file certs-dir "bundle.edn")
          tmp (File/createTempFile "bundle-" ".tmp" certs-dir)]
      (spit tmp (pr-str {:cert-pem cert-pem :key-pem key-pem}))
      (try
        (Files/setPosixFilePermissions (.toPath tmp) (PosixFilePermissions/fromString "rw-------"))
        (catch UnsupportedOperationException _ nil))
      (try
        (Files/move (.toPath tmp) (.toPath bundle-file)
                    (into-array CopyOption [StandardCopyOption/ATOMIC_MOVE StandardCopyOption/REPLACE_EXISTING]))
        (catch Exception _
          (Files/move (.toPath tmp) (.toPath bundle-file)
                      (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING])))))))

(defn- load-tls-bundle
  [state-dir domain]
  (when state-dir
    (let [bundle-file (io/file state-dir "certs" "bundle.edn")]
      (when (.exists bundle-file)
        (try
          (let [{:keys [cert-pem key-pem]} (edn/read-string (slurp bundle-file))
                certs (parse-cert-chain-pem cert-pem)
                priv (parse-private-key-pem key-pem)]
            (validate-tls-bundle! certs priv domain)
            {:certificates certs
             :private-key priv
             :cert-pem cert-pem
             :key-pem key-pem
             :expires-at (.getTime (.getNotAfter ^X509Certificate (first certs)))
             :self-signed? false})
          (catch Exception _ nil))))))

(defn update-tls-bundle!
  "Validates, persists, and atomically hot-reloads `cert-pem` + `key-pem` into `tls-manager`."
  [tls-manager cert-pem key-pem]
  (let [certs (parse-cert-chain-pem cert-pem)
        priv-key (parse-private-key-pem key-pem)]
    (validate-tls-bundle! certs priv-key (:domain tls-manager))
    (save-tls-bundle! (:state-dir tls-manager) cert-pem key-pem)
    (let [new-bundle {:certificates certs
                      :private-key priv-key
                      :cert-pem cert-pem
                      :key-pem key-pem
                      :expires-at (.getTime (.getNotAfter ^X509Certificate (first certs)))
                      :self-signed? false}]
      (reset! (:bundle-atom tls-manager) new-bundle)
      (reset! (:ssl-context-atom tls-manager) (build-ssl-context (:bundle-atom tls-manager)))
      tls-manager)))

(defn init-tls-manager!
  "Initializes hot-reloadable TLS manager (with `:reload-fn` hook for `bitecho.shell.infra`)."
  [config]
  (let [state-dir (:state-dir config)
        domain (or (:domain config) "localhost")
        disk-bundle (load-tls-bundle state-dir domain)
        now (System/currentTimeMillis)
        bundle (if (and disk-bundle (> (:expires-at disk-bundle) now))
                 disk-bundle
                 (generate-self-signed-cert domain 30))
        bundle-atom (atom bundle)
        ssl-ctx-atom (atom (build-ssl-context bundle-atom))
        mgr-base {:ssl-context-atom ssl-ctx-atom
                  :bundle-atom bundle-atom
                  :state-dir state-dir
                  :domain domain}]
    (assoc mgr-base :reload-fn (fn [cert-pem key-pem]
                                 (update-tls-bundle! mgr-base cert-pem key-pem)))))

(defn make-https-configurator
  "Creates an `HttpsConfigurator` setting TLSv1.3/TLSv1.2 AND `SSLParameters.setWantClientAuth(true)` (Gap G17)."
  [ssl-context-atom]
  (proxy [HttpsConfigurator] [@ssl-context-atom]
    (getSSLContext [] @ssl-context-atom)
    (configure [^HttpsParameters params]
      (let [^SSLContext ctx @ssl-context-atom
            ssl-params (.getDefaultSSLParameters ctx)]
        (.setProtocols ssl-params (into-array String ["TLSv1.3" "TLSv1.2"]))
        (.setWantClientAuth ssl-params true)
        (.setSSLParameters params ssl-params)))))

;; =============================================================================
;; 2. Request / Response Helpers & Subnet Pointer -> Blob Content Serving
;; =============================================================================

(defn- extract-mtls-client-pubkey
  "Extracts lowercase hex-encoded SubjectPublicKeyInfo (`SPKI`) from peer TLS client certificate, if presented."
  [^HttpExchange exchange]
  (when (instance? HttpsExchange exchange)
    (try
      (when-let [sess (.getSSLSession ^HttpsExchange exchange)]
        (let [certs (.getPeerCertificates sess)]
          (when (and certs (pos? (alength certs)))
            (let [^X509Certificate leaf (aget certs 0)]
              (str/lower-case (basalt/bytes->hex (.getEncoded (.getPublicKey leaf))))))))
      (catch SSLPeerUnverifiedException _ nil)
      (catch Exception _ nil))))

(defn exchange->request
  "Converts `HttpExchange` into a clean request map (including `:request/mtls-pubkey` if mTLS client cert present)."
  ([^HttpExchange exchange]
   (exchange->request exchange nil))
  ([^HttpExchange exchange forwarded-ips-atom]
   (let [uri (.getRequestURI exchange)
         path (or (.getPath uri) "/")
         query (.getRawQuery uri)
         scheme (if (instance? HttpsExchange exchange) "https" "http")
         method (keyword (str/upper-case (.getRequestMethod exchange)))
         remote-addr (.getRemoteAddress exchange)
         forwarded-ip (when (and remote-addr forwarded-ips-atom)
                        (get @forwarded-ips-atom (.getPort remote-addr)))
         remote-ip (or forwarded-ip
                       (if remote-addr
                         (.getHostAddress (.getAddress remote-addr))
                         "127.0.0.1"))
         headers (into {}
                       (map (fn [[k v]]
                              [(keyword "header" (str/lower-case k)) (vec v)]))
                       (.getRequestHeaders exchange))
         host-hdr (first (get headers :header/host))
         host (if host-hdr (str/lower-case (first (str/split host-hdr #":"))) "localhost")
         dac-hdr (first (get headers :header/x-bitecho-dac))
         parsed-dac (when (and (string? dac-hdr) (not (str/blank? dac-hdr)))
                      (try
                        (let [d (fressian/decode-wire (acme-proto/base64url-decode (str/trim dac-hdr)))]
                          (when (map? d) d))
                        (catch Exception _ nil)))]
     {:request/method method
      :request/uri {:scheme scheme :host host :path path :query query}
      :request/headers headers
      :request/remote-ip remote-ip
      :request/mtls-pubkey (extract-mtls-client-pubkey exchange)
      :request/dac parsed-dac
      :request/exchange exchange})))

(defn send-response
  "Sends polymorphic HTTP response (`nil`, `byte[]`, `String`, `File`, or `{:file f :offset off :length len}` zero-heap slice)."
  [^HttpExchange exchange response]
  (let [status (int (or (:response/status response) 200))
        headers (or (:response/headers response) {})
        resp-headers (.getResponseHeaders exchange)]
    (doseq [[k v] headers]
      (when (and k v)
        (.set resp-headers (name k) (str v))))
    (let [body (:response/body response)]
      (cond
        (or (nil? body) (= status 304) (= status 204))
        (do (.sendResponseHeaders exchange status -1)
            (.close exchange))

        (bytes? body)
        (let [len (alength ^bytes body)]
          (.sendResponseHeaders exchange status len)
          (with-open [os (.getResponseBody exchange)]
            (.write os ^bytes body 0 len)
            (.flush os)))

        (string? body)
        (let [bs (.getBytes ^String body StandardCharsets/UTF_8)]
          (.sendResponseHeaders exchange status (alength bs))
          (with-open [os (.getResponseBody exchange)]
            (.write os bs 0 (alength bs))
            (.flush os)))

        (instance? File body)
        (let [len (.length ^File body)]
          (.sendResponseHeaders exchange status len)
          (with-open [raf (RandomAccessFile. ^File body "r")
                      os (.getResponseBody exchange)]
            (let [fc (.getChannel raf)
                  buf (ByteBuffer/allocate 65536)]
              (loop []
                (let [n (.read fc buf)]
                  (when (pos? n)
                    (.flip buf)
                    (.write os (.array buf) 0 n)
                    (.clear buf)
                    (recur))))
              (.flush os))))

        (and (map? body) (:file body))
        (let [^File file (:file body)
              offset (long (or (:offset body) 0))
              len (long (or (:length body) (- (.length file) offset)))]
          (.sendResponseHeaders exchange status len)
          (with-open [raf (RandomAccessFile. file "r")
                      os (.getResponseBody exchange)]
            (.seek raf offset)
            (let [fc (.getChannel raf)
                  buf (ByteBuffer/allocate 65536)]
              (loop [rem len]
                (when (pos? rem)
                  (.limit buf (int (min rem 65536)))
                  (let [n (.read fc buf)]
                    (when (pos? n)
                      (.flip buf)
                      (.write os (.array buf) 0 n)
                      (.clear buf)
                      (recur (- rem n))))))
              (.flush os))))

        :else
        (do (.sendResponseHeaders exchange status -1)
            (.close exchange))))))

(defn- compressible-content-type?
  [ct]
  (let [l (str/lower-case (or ct ""))]
    (or (str/starts-with? l "text/")
        (str/includes? l "json")
        (str/includes? l "xml")
        (str/includes? l "markdown")
        (str/includes? l "javascript"))))

(defn- gzip-bytes
  [^bytes bs]
  (let [baos (ByteArrayOutputStream.)]
    (with-open [gz (GZIPOutputStream. baos)]
      (.write gz bs 0 (alength bs)))
    (.toByteArray baos)))

(defn- parse-byte-range
  [range-header ^long total-size]
  (when (and range-header (str/starts-with? range-header "bytes="))
    (let [spec (subs range-header 6)]
      (cond
        (re-matches #"^(\d+)-(\d+)$" spec)
        (let [[_ s e] (re-matches #"^(\d+)-(\d+)$" spec)
              start (Long/parseLong s)
              end (Long/parseLong e)]
          (when (and (<= start end) (< start total-size))
            [start (min end (dec total-size))]))

        (re-matches #"^(\d+)-$" spec)
        (let [[_ s] (re-matches #"^(\d+)-$" spec)
              start (Long/parseLong s)]
          (when (< start total-size)
            [start (dec total-size)]))

        (re-matches #"^-(\d+)$" spec)
        (let [[_ suf] (re-matches #"^-(\d+)$" spec)
              slen (Long/parseLong suf)]
          (when (pos? slen)
            [(max 0 (- total-size slen)) (dec total-size)]))))))

(def default-extension-media-types
  "Complete set of default extension-derived MIME types returned by `content-type-for-file`."
  #{"application/gzip"
    "text/markdown; charset=utf-8"
    "application/javascript; charset=utf-8"
    "text/html; charset=utf-8"
    "text/css; charset=utf-8"
    "application/json; charset=utf-8"
    "application/xml; charset=utf-8"
    "text/plain; charset=utf-8"
    "application/x-shellscript; charset=utf-8"
    "application/java-archive"
    "application/octet-stream"})

(defn- content-type-for-file
  [name-str]
  (let [l (str/lower-case (or name-str ""))]
    (cond
      (or (str/ends-with? l ".tar.gz") (str/ends-with? l ".tgz")) "application/gzip"
      (str/ends-with? l ".md") "text/markdown; charset=utf-8"
      (or (str/ends-with? l ".js") (str/ends-with? l ".mjs")) "application/javascript; charset=utf-8"
      (or (str/ends-with? l ".html") (str/ends-with? l ".htm")) "text/html; charset=utf-8"
      (str/ends-with? l ".css") "text/css; charset=utf-8"
      (str/ends-with? l ".json") "application/json; charset=utf-8"
      (or (str/ends-with? l ".xml") (str/ends-with? l ".pom")) "application/xml; charset=utf-8"
      (or (str/ends-with? l ".clj") (str/ends-with? l ".cljc") (str/ends-with? l ".cljs")
          (str/ends-with? l ".edn") (str/ends-with? l ".txt") (str/ends-with? l ".sha1")
          (str/ends-with? l ".sha256") (str/ends-with? l ".sri") (= l "head")) "text/plain; charset=utf-8"
      (str/ends-with? l ".sh") "text/x-shellscript; charset=utf-8"
      (str/ends-with? l ".jar") "application/java-archive"
      :else "application/octet-stream")))

(defn- sha256-file-hex
  [^File f]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")
        buf (byte-array 65536)]
    (with-open [is (io/input-stream f)]
      (loop []
        (let [n (.read is buf)]
          (when (pos? n)
            (.update md buf 0 n)
            (recur)))))
    (str/lower-case (basalt/bytes->hex (.digest md)))))

(defn- resolve-safe-content-root
  "Safely resolves `req-path` under `content-root` (blocking `\\u0000`, `..`, dotfiles, and canonical
   symlink escapes). Used for zero-copy static/git-pack fallback during Phase C `ns1..ns3` cutover."
  [content-root req-path]
  (try
    (let [raw (or req-path "/")]
      (if (str/includes? raw "\u0000")
        {:ok? false :error :forbidden}
        (let [decoded (try (java.net.URLDecoder/decode raw StandardCharsets/UTF_8) (catch Exception _ nil))]
          (if (or (nil? decoded) (str/includes? decoded "\u0000"))
            {:ok? false :error :forbidden}
            (let [segs (remove str/blank? (str/split (first (str/split decoded #"\?")) #"[/\\]"))]
              (if (some #(or (= % "..") (and (str/starts-with? % ".") (not= % "."))) segs)
                {:ok? false :error :forbidden}
                (let [root-f (io/file content-root)]
                  (if-not (.exists root-f)
                    {:ok? false :error :not-found}
                    (let [root-p (.toRealPath (.toPath root-f) (into-array java.nio.file.LinkOption []))
                          cand-p (.normalize (.resolve root-p (str/join File/separator segs)))]
                      (if-not (.startsWith cand-p root-p)
                        {:ok? false :error :forbidden}
                        (let [cand-f (.toFile cand-p)]
                          (if-not (.exists cand-f)
                            {:ok? false :error :not-found}
                            (let [real-p (.toRealPath cand-p (into-array java.nio.file.LinkOption []))]
                              (if-not (.startsWith real-p root-p)
                                {:ok? false :error :forbidden}
                                (let [^File rf (.toFile real-p)
                                      target-f (cond
                                                 (not (.isDirectory rf)) rf
                                                 (.exists (io/file rf "index.html")) (io/file rf "index.html")
                                                 (.exists (io/file rf "index.md")) (io/file rf "index.md")
                                                 :else nil)]
                                  (if-not target-f
                                    {:ok? false :error :not-found}
                                    (let [cid (sha256-file-hex target-f)
                                          ct (content-type-for-file (.getName target-f))
                                          bs (when (<= (.length target-f) 2097152)
                                               (Files/readAllBytes (.toPath target-f)))]
                                      {:ok? true
                                       :file target-f
                                       :blob {:blob/cid cid
                                              :blob/media-type ct
                                              :blob/bytes bs}})))))))))))))))))
    (catch Exception _
      {:ok? false :error :not-found})))

(defn- sanitize-web-subpath
  [raw-path]
  (when-not (str/includes? (or raw-path "") "\u0000")
    (let [decoded (try (java.net.URLDecoder/decode (or raw-path "/") StandardCharsets/UTF_8)
                       (catch Exception _ nil))]
      (when (and decoded (not (str/includes? decoded "\u0000")))
        (let [segs (remove str/blank? (str/split decoded #"[/\\]"))]
          (when-not (some #(or (= % "..") (and (str/starts-with? % ".") (not= % "."))) segs)
            (str/join "/" segs)))))))

(defn- resolve-web-blob!
  [config rt req-path now-ms]
  (if-let [subpath (sanitize-web-subpath req-path)]
    (let [ptr-res (if (str/blank? subpath)
                    (let [r1 (infra/resolve-path-blob! rt "web/index.html" now-ms)]
                      (if (:ok? r1)
                        r1
                        (infra/resolve-path-blob! rt "web/index.md" now-ms)))
                    (let [r-direct (infra/resolve-path-blob! rt (str "web/" subpath) now-ms)]
                      (if (:ok? r-direct)
                        r-direct
                        (let [r-idx (infra/resolve-path-blob! rt (str "web/" subpath "/index.html") now-ms)]
                          (if (:ok? r-idx)
                            r-idx
                            (infra/resolve-path-blob! rt (str "web/" subpath "/index.md") now-ms))))))]
      (if (:ok? ptr-res)
        ptr-res
        (if-let [content-root (get-in config [:http :content-root])]
          (resolve-safe-content-root content-root req-path)
          ptr-res)))
    {:ok? false :error :forbidden}))

(defn- serve-subnet-request
  "Evaluates target Subnet `:subnet/gate` (Gap G12 & `F-B1`) and serves Pointer -> Blob with `ETag: \"<cid>\"`,
   `304`, `206`, gzip, and Tier-2 zero-heap `blob-fs` / `content-root` file streaming (Gap G6)."
  [config shell-atom rt req now-ms]
  (let [method (:request/method req)]
    (cond
      (= method :OPTIONS)
      {:response/status 204
       :response/headers {"Access-Control-Allow-Origin" "*"
                          "Access-Control-Allow-Methods" "GET, HEAD, OPTIONS"
                          "Access-Control-Allow-Headers" "Content-Type, Range, If-None-Match, X-Bitecho-DAC"}
       :response/body nil}

      (not (or (= method :GET) (= method :HEAD)))
      {:response/status 405
       :response/headers {"Allow" "GET, HEAD, OPTIONS"
                          "Content-Type" "text/plain; charset=utf-8"}
       :response/body "Method Not Allowed\n"}

      :else
      (let [inst @(:subnet-atom rt)
            policy (:policy inst)
            gate (:subnet/gate policy)
            admission (:gate/admission gate)
            ;; Public web subnets (:open or cluster-write :allowlist without :gate/private-read?) allow public GET/HEAD;
            ;; :mtls-cert, :dac, :min-stake, or :gate/private-read? subnets strictly enforce check-gate-admission!
            requires-read-auth? (or (contains? #{:mtls-cert :dac :min-stake} admission)
                                    (true? (:gate/private-read? gate)))
            adm (if-not requires-read-auth?
                  {:admitted? true}
                  (subnet/check-gate-admission policy inst
                                               (cond-> {:type :http-read
                                                        :mtls-client-pubkey (:request/mtls-pubkey req)
                                                        ;; Require TLS client-cert possession (:mtls-pubkey) as sender so X-Bitecho-DAC cannot be replayed as a bearer header!
                                                        :sender (:request/mtls-pubkey req)
                                                        :now-ms now-ms}
                                                 (:request/dac req) (assoc :dac (:request/dac req))
                                                 (some? (infra/current-runtime-epoch rt))
                                                 (assoc :epoch (infra/current-runtime-epoch rt)))))]
        (if-not (:admitted? adm)
          (do
            (infra/apply-shell-event! shell-atom {:type :drop :reason :http-subnet-gate-denied :detail (:error adm)})
            {:response/status 403
             :response/headers {"Content-Type" "text/plain; charset=utf-8"}
             :response/body "Forbidden: Subnet Gate Denied\n"})
          (let [resolved (resolve-web-blob! config rt (get-in req [:request/uri :path]) now-ms)]
            (case (:error resolved)
              :forbidden
              (do
                (infra/apply-shell-event! shell-atom {:type :drop :reason :http-forbidden-path})
                {:response/status 403
                 :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                 :response/body "Forbidden\n"})

              (:not-found :missing-blob)
              {:response/status 404
               :response/headers {"Content-Type" "text/plain; charset=utf-8"}
               :response/body "Not Found\n"}

              ;; Found!
              (let [blob (:blob resolved)
                    cid (:blob/cid blob)
                    raw-ct (:blob/media-type blob)
                    fallback-name (or (get-in resolved [:pointer :pointer/path])
                                      (when-let [^File df (:file resolved)] (.getName df))
                                      (get-in req [:request/uri :path]))
                    path-ct (content-type-for-file fallback-name)
                    ct (cond
                         (and (string? raw-ct)
                              (not (str/blank? raw-ct))
                              (not (contains? default-extension-media-types raw-ct)))
                         raw-ct

                         (not= path-ct "application/octet-stream")
                         path-ct

                         (and (string? raw-ct) (not (str/blank? raw-ct)))
                         raw-ct

                         :else
                         "application/octet-stream")
                    ^bytes raw-bs (:blob/bytes blob)
                    ^File disk-file (:file resolved)
                    total-size (long (if (and disk-file (.exists disk-file))
                                       (.length disk-file)
                                       (alength raw-bs)))
                    max-tier1 (long (get-in config [:http :cache-max-file-bytes] 2097152))
                    tier1? (or (<= total-size max-tier1) (nil? disk-file) (not (.exists disk-file)))
                    etag (str "\"" cid "\"")
                    inm (first (get (:request/headers req) :header/if-none-match))
                    range-hdr (first (get (:request/headers req) :header/range))]
                (cond
                  (and inm (= (str/trim inm) etag))
                  {:response/status 304
                   :response/headers {"ETag" etag
                                      "Cache-Control" "public, max-age=3600"}
                   :response/body nil}

                  range-hdr
                  (if-let [[start end] (parse-byte-range range-hdr total-size)]
                    (let [part-len (inc (- end start))
                          hdrs {"Content-Type" ct
                                "Content-Range" (str "bytes " start "-" end "/" total-size)
                                "Accept-Ranges" "bytes"
                                "Content-Length" (str part-len)
                                "ETag" etag
                                "X-Checksum-SHA256" cid}
                          body (cond
                                 (= method :HEAD) nil
                                 tier1? (Arrays/copyOfRange raw-bs (int start) (int (inc end)))
                                 :else {:file disk-file :offset start :length part-len})]
                      {:response/status 206 :response/headers hdrs :response/body body})
                    {:response/status 416
                     :response/headers {"Content-Range" (str "bytes */" total-size)}
                     :response/body nil})

                  :else
                  (let [ae (first (get (:request/headers req) :header/accept-encoding))
                        want-gz? (and tier1?
                                      ae
                                      (str/includes? (str/lower-case ae) "gzip")
                                      (compressible-content-type? ct))
                        gz-bs (when want-gz? (gzip-bytes raw-bs))]
                    (if (and gz-bs (< (alength gz-bs) total-size))
                      {:response/status 200
                       :response/headers {"Content-Type" ct
                                          "Content-Encoding" "gzip"
                                          "Vary" "Accept-Encoding"
                                          "ETag" etag
                                          "X-Checksum-SHA256" cid
                                          "Content-Length" (str (alength gz-bs))}
                       :response/body (if (= method :HEAD) nil gz-bs)}
                      {:response/status 200
                       :response/headers {"Content-Type" ct
                                          "Accept-Ranges" "bytes"
                                          "ETag" etag
                                          "X-Checksum-SHA256" cid
                                          "Content-Length" (str total-size)}
                       :response/body (cond
                                        (= method :HEAD) nil
                                        tier1? raw-bs
                                        :else {:file disk-file :offset 0 :length total-size})})))))))))))

;; =============================================================================
;; 3. Port `:80` Handler, Port `:443` Handler, & Bounded-Peek Multiplexer
;; =============================================================================

(defn- lookup-acme-http01-key-auth
  [subnet-runtime token now-ms]
  (when (and subnet-runtime (string? token) (not (str/blank? token)))
    (let [res (infra/resolve-path-blob! subnet-runtime (str "acme/challenge/" token) now-ms)]
      (when (:ok? res)
        (let [bs (get-in res [:blob :blob/bytes])
              mt (get-in res [:blob :blob/media-type])]
          (if (= mt "application/fressian")
            (let [d (try (fressian/decode-wire bs) (catch Exception _ nil))]
              (when (map? d) (:key-auth d)))
            (fressian/bytes->utf8 bs)))))))

(defn- make-port-80-handler
  [subnet-runtime https-port limiter-atom]
  (reify HttpHandler
    (handle [_ exchange]
      (let [req (exchange->request exchange)
            path (get-in req [:request/uri :path])
            method (:request/method req)
            now-ms (System/currentTimeMillis)]
        (cond
          (and (or (= method :GET) (= method :HEAD))
               (str/starts-with? path "/.well-known/acme-challenge/"))
          (let [token (subs path (count "/.well-known/acme-challenge/"))
                key-auth (lookup-acme-http01-key-auth subnet-runtime token now-ms)]
            (if key-auth
              (send-response exchange
                             {:response/status 200
                              :response/headers {"Content-Type" "application/octet-stream"}
                              :response/body (if (= method :HEAD) nil key-auth)})
              (send-response exchange
                             {:response/status 404
                              :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                              :response/body "Not Found\n"})))

          (and (or (= method :GET) (= method :HEAD)) (= path "/healthz"))
          (send-response exchange
                         {:response/status 200
                          :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                          :response/body (if (= method :HEAD) nil "ok\n")})

          (and (or (= method :GET) (= method :HEAD))
               (= path "/statusz")
               (#{"127.0.0.1" "::1" "0:0:0:0:0:0:0:1"} (:request/remote-ip req)))
          (let [st (when subnet-runtime (infra/runtime-status subnet-runtime))
                sdf (SimpleDateFormat. "yyyy-MM")
                month-key (.format sdf (Date. now-ms))
                egress (get-in @limiter-atom [:egress-by-month month-key] 0)
                body (format "role=%s leader=%s term=%s epoch=%s healthy=%d egress_bytes=%d\n"
                             (name (or (:role st) :standalone))
                             (str (or (:leader-id st) :none))
                             (str (or (:term st) 0))
                             (str (or (:epoch st) :none))
                             (count (or (:healthy-nodes st) #{}))
                             (long egress))]
            (send-response exchange
                           {:response/status 200
                            :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                            :response/body (if (= method :HEAD) nil body)}))

          :else
          (let [host (get-in req [:request/uri :host] "localhost")
                port-suffix (if (and https-port (not= https-port 443)) (str ":" https-port) "")
                query (get-in req [:request/uri :query])
                q-suffix (if (seq query) (str "?" query) "")
                loc (str "https://" host port-suffix path q-suffix)]
            (send-response exchange
                           {:response/status 308
                            :response/headers {"Location" loc "Connection" "close"}
                            :response/body nil})))))))

(defn- make-port-443-handler
  [config shell-atom default-runtime limiter-atom forwarded-ips-atom]
  (let [host-subnets (get-in config [:http :host-subnets] {})]
    (reify HttpHandler
      (handle [_ exchange]
        (let [req (exchange->request exchange forwarded-ips-atom)
              path (get-in req [:request/uri :path])
              method (:request/method req)
              host (get-in req [:request/uri :host])
              target-rt (or (get host-subnets host) default-runtime)
              remote-ip (:request/remote-ip req)
              subnet-key (dns-proto/ip->subnet-key remote-ip)
              now-ms (System/currentTimeMillis)]
          (if (and (or (= method :GET) (= method :HEAD)) (= path "/healthz"))
            (send-response exchange
                           {:response/status 200
                            :response/headers {"Content-Type" "text/plain; charset=utf-8"}
                            :response/body (if (= method :HEAD) nil "ok\n")})
            (let [res-box (atom nil)
                  _ (swap! limiter-atom
                           (fn [st]
                             (let [r (dns-proto/check-and-consume st subnet-key 1.0 now-ms)]
                               (reset! res-box r)
                               (:state r))))
                  rl-res @res-box]
              (if-not (:allowed? rl-res)
                (let [retry-s (max 1 (long (Math/ceil (/ (long (:retry-after-ms rl-res 1000)) 1000.0))))]
                  (infra/apply-shell-event! shell-atom {:type :drop :reason :https-rate-limited :detail subnet-key})
                  (send-response exchange
                                 {:response/status 429
                                  :response/headers {"Retry-After" (str retry-s)
                                                     "Content-Type" "text/plain; charset=utf-8"}
                                  :response/body "Too Many Requests\n"}))
                (let [resp (-> (serve-subnet-request config shell-atom target-rt req now-ms)
                               (update :response/headers assoc
                                       "Strict-Transport-Security" "max-age=31536000; includeSubDomains"))
                      body (:response/body resp)
                      body-len (cond
                                 (bytes? body) (alength ^bytes body)
                                 (string? body) (alength (.getBytes ^String body StandardCharsets/UTF_8))
                                 (map? body) (long (or (:length body) 0))
                                 (instance? File body) (.length ^File body)
                                 :else 0)]
                  (if (pos? body-len)
                    (let [month-key (.format (SimpleDateFormat. "yyyy-MM") (Date. now-ms))
                          eg-ok (atom true)
                          _ (swap! limiter-atom
                                   (fn [st]
                                     (let [r (dns-proto/record-egress st body-len month-key)]
                                       (reset! eg-ok (:allowed? r))
                                       (:state r))))]
                      (if-not @eg-ok
                        (do
                          (infra/apply-shell-event! shell-atom {:type :drop :reason :monthly-egress-exceeded})
                          (send-response exchange
                                         {:response/status 429
                                          :response/headers {"Retry-After" "3600"
                                                             "Content-Type" "text/plain; charset=utf-8"}
                                          :response/body "Monthly egress limit exceeded\n"}))
                        (send-response exchange resp)))
                    (send-response exchange resp)))))))))))

(defn- pipe-stream!
  [^InputStream in ^OutputStream out ^Socket dst-sock ^Socket other-sock cleanup-fn]
  (try
    (.transferTo in out)
    (.flush out)
    (try (.shutdownOutput dst-sock) (catch Exception _ nil))
    (catch Exception _
      (try (.close dst-sock) (catch Exception _ nil))
      (try (.close other-sock) (catch Exception _ nil)))
    (finally
      (cleanup-fn))))

(defn- peek-initial-bytes
  "Bounded initial peek (`<= 1024` bytes, `peek-timeout-ms` default `2000ms` — Gap G17)."
  [^Socket client-sock ^long peek-timeout-ms]
  (.setSoTimeout client-sock (int peek-timeout-ms))
  (let [in (.getInputStream client-sock)
        buf (byte-array 1024)
        n0 (.read in buf 0 1024)]
    (if (pos? n0)
      (let [tls-hdr? (and (>= n0 5)
                          (= (bit-and (aget buf 0) 0xff) 0x16)
                          (= (bit-and (aget buf 1) 0xff) 0x03))
            needed (if tls-hdr?
                     (min 1024 (+ 5 (bit-or (bit-shift-left (bit-and (aget buf 3) 0xff) 8)
                                            (bit-and (aget buf 4) 0xff))))
                     n0)]
        (loop [curr n0]
          (if (and (< curr needed) (.isConnected client-sock) (not (.isClosed client-sock)))
            (let [r (.read in buf curr (- needed curr))]
              (if (pos? r)
                (recur (+ curr r))
                [buf curr]))
            [buf curr])))
      [buf 0])))

(defn- find-header-end-idx
  "Finds the byte offset immediately after `\r\n\r\n` in `buf[0..len)`, or `nil`."
  [^bytes buf ^long len]
  (loop [i 0]
    (when (<= (+ i 4) len)
      (if (and (= (aget buf i) 13)
               (= (aget buf (+ i 1)) 10)
               (= (aget buf (+ i 2)) 13)
               (= (aget buf (+ i 3)) 10))
        (+ i 4)
        (recur (inc i))))))

(defn- splice-bidirectional!
  [^Socket client-sock ^Socket backend-sock ^ExecutorService vthread-executor extra-cleanup-fn]
  (let [client-in (.getInputStream client-sock)
        client-out (.getOutputStream client-sock)
        backend-in (.getInputStream backend-sock)
        backend-out (.getOutputStream backend-sock)
        rem-dirs (AtomicInteger. 2)
        cleanup (fn []
                  (when (zero? (.decrementAndGet rem-dirs))
                    (when extra-cleanup-fn (extra-cleanup-fn))
                    (try (.close client-sock) (catch Exception _ nil))
                    (try (.close backend-sock) (catch Exception _ nil))))]
    (.submit vthread-executor ^Runnable (fn [] (pipe-stream! client-in backend-out backend-sock client-sock cleanup)))
    (.submit vthread-executor ^Runnable (fn [] (pipe-stream! backend-in client-out client-sock backend-sock cleanup)))))

(defn- handle-passthrough-connection!
  "Classifies initial `<= 1024` peeked bytes on port `:443` and splices to `HTTP CONNECT` target,
   `:ingress-target`, or internal `HttpsServer`."
  [^Socket client-sock ctx]
  (let [{:keys [domain internal-https-port ingress-target connect-targets peek-timeout-ms
                forwarded-ips-atom shell-atom ^ExecutorService vthread-executor]} ctx]
    (try
      (let [[^bytes buf n] (peek-initial-bytes client-sock (long (or peek-timeout-ms 2000)))]
        (.setSoTimeout client-sock 0)
        (if-not (pos? n)
          (try (.close client-sock) (catch Exception _ nil))
          (if-let [conn-req (dns-proto/parse-http-connect-request buf n)]
            ;; 1. Explicit HTTP CONNECT tunnel (strictly allowlisted, never open proxy!)
            (let [target-key (str (:host conn-req) ":" (:port conn-req))
                  allowed? (contains? (set (map str/lower-case (or connect-targets #{})))
                                      (str/lower-case target-key))]
              (if-not allowed?
                (do
                  (infra/apply-shell-event! shell-atom {:type :drop :reason :http-connect-denied :detail target-key})
                  (with-open [out (.getOutputStream client-sock)]
                    (.write out (.getBytes "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n" StandardCharsets/UTF_8))
                    (.flush out))
                  (try (.close client-sock) (catch Exception _ nil)))
                (let [backend-sock (Socket. ^String (:host conn-req) (int (:port conn-req)))
                      client-out (.getOutputStream client-sock)
                      backend-out (.getOutputStream backend-sock)
                      hdr-end (or (find-header-end-idx buf n) n)]
                  (.setTcpNoDelay client-sock true)
                  (.setTcpNoDelay backend-sock true)
                  (.write client-out (.getBytes "HTTP/1.1 200 Connection Established\r\n\r\n" StandardCharsets/UTF_8))
                  (.flush client-out)
                  (when (< hdr-end n)
                    (.write backend-out buf (int hdr-end) (int (- n hdr-end)))
                    (.flush backend-out))
                  (splice-bidirectional! client-sock backend-sock vthread-executor nil))))

            ;; 2. Ingress stream (RFC 4571 DTLS/STUN or SNI *.ingress.<domain>) vs internal HttpsServer
            (let [ingress? (and (some? ingress-target) (dns-proto/ingress-stream? buf n domain))
                  target (if ingress?
                           ingress-target
                           {:host "127.0.0.1" :port internal-https-port})
                  backend-sock (Socket. ^String (:host target) (int (:port target)))
                  local-backend-port (.getLocalPort backend-sock)
                  client-ip (some-> (.getInetAddress client-sock) (.getHostAddress))]
              (.setTcpNoDelay client-sock true)
              (.setTcpNoDelay backend-sock true)
              (when (and (not ingress?) forwarded-ips-atom client-ip)
                (swap! forwarded-ips-atom assoc local-backend-port client-ip))
              (let [backend-out (.getOutputStream backend-sock)]
                (.write backend-out buf 0 n)
                (.flush backend-out))
              (splice-bidirectional! client-sock
                                     backend-sock
                                     vthread-executor
                                     (fn []
                                       (when (and (not ingress?) forwarded-ips-atom)
                                         (swap! forwarded-ips-atom dissoc local-backend-port))))))))
      (catch Exception e
        (infra/apply-shell-event! shell-atom {:type :drop :reason :passthrough-conn-error :detail (.getMessage e)})
        (try (.close client-sock) (catch Exception _ nil))))))

;; =============================================================================
;; 4. Server Lifecycle (`start-http-servers!` & `stop-http-servers!`)
;; =============================================================================

(defn start-http-servers!
  "Starts JDK 25 Virtual-Thread `HttpServer` (`:80`), internal `HttpsServer` (`setWantClientAuth(true)`),
   and front-door Port `:443` passthrough multiplexer backed by `subnet-runtime`."
  [config tls-manager subnet-runtime]
  (let [shell-atom (atom (infra/init-shell-state :http-shell))
        _ (infra/apply-shell-event! shell-atom {:type :start})
        gen (:generation @shell-atom)
        bind-ip (get-in config [:http :bind-ip] "0.0.0.0")
        http-port (int (get-in config [:http :http-port] 80))
        https-port (int (get-in config [:http :https-port] 443))
        domain (:domain config)
        vthread-executor (Executors/newVirtualThreadPerTaskExecutor)
        forwarded-ips-atom (atom {})
        limiter-atom (atom (dns-proto/init-limiter
                            {:capacity 100.0
                             :refill-per-sec 20.0
                             :monthly-egress-limit-bytes (get-in config [:http :monthly-egress-limit-bytes] 900000000)}))]
    (try
      (let [https-server (HttpsServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
            _ (.setHttpsConfigurator https-server (make-https-configurator (:ssl-context-atom tls-manager)))
            _ (.setExecutor https-server vthread-executor)
            _ (.createContext https-server "/" (make-port-443-handler config shell-atom subnet-runtime limiter-atom forwarded-ips-atom))
            _ (.start https-server)
            internal-https-port (.getPort (.getAddress https-server))
            passthrough-ctx {:domain domain
                             :internal-https-port internal-https-port
                             :ingress-target (get-in config [:http :ingress-target])
                             :connect-targets (get-in config [:http :connect-targets])
                             :peek-timeout-ms (get-in config [:http :peek-timeout-ms] 2000)
                             :forwarded-ips-atom forwarded-ips-atom
                             :shell-atom shell-atom
                             :vthread-executor vthread-executor}
            front-door-sock (doto (ServerSocket.)
                              (.setReuseAddress true)
                              (.bind (InetSocketAddress. ^String bind-ip https-port)))
            bound-https-port (.getLocalPort front-door-sock)
            _ (.submit vthread-executor
                       ^Runnable
                       (fn []
                         (while (not (.isClosed front-door-sock))
                           (try
                             (let [client (.accept front-door-sock)]
                               (.submit vthread-executor
                                        ^Runnable
                                        (fn [] (handle-passthrough-connection! client passthrough-ctx))))
                             (catch SocketException _ nil)
                             (catch Throwable t
                               (when-not (.isClosed front-door-sock)
                                 (infra/apply-shell-event! shell-atom {:type :diagnose :reason :https-accept-error :detail (.getMessage t)})))))))
            http-server (HttpServer/create (InetSocketAddress. ^String bind-ip http-port) 0)
            _ (.setExecutor http-server vthread-executor)
            _ (.createContext http-server "/" (make-port-80-handler subnet-runtime bound-https-port limiter-atom))
            _ (.start http-server)
            bound-http-port (.getPort (.getAddress http-server))
            close-resources! (fn [{:keys [front http https exec]}]
                               (when front (try (.close ^ServerSocket front) (catch Exception _ nil)))
                               (when http (try (.stop ^HttpServer http 0) (catch Exception _ nil)))
                               (when https (try (.stop ^HttpsServer https 0) (catch Exception _ nil)))
                               (when exec (try (.shutdownNow ^ExecutorService exec) (catch Exception _ nil))))
            resources {:front front-door-sock :http http-server :https https-server :exec vthread-executor}]
        (infra/apply-shell-event! shell-atom {:type :started :generation gen :resources resources})
        {:shell-atom shell-atom
         :http-server http-server
         :https-server https-server
         :front-door-sock front-door-sock
         :http-port bound-http-port
         :https-port bound-https-port
         :limiter-atom limiter-atom
         :stop-fn (fn []
                    (infra/apply-shell-event! shell-atom {:type :stop} close-resources!))})
      (catch Exception e
        (infra/apply-shell-event! shell-atom {:type :failed :generation gen :error :http-bind-failed :detail (.getMessage e)})
        (throw e)))))

(defn stop-http-servers!
  "Stops HTTP and HTTPS servers and transitions lifecycle state to `:stopped`."
  [servers]
  (when-let [stop-fn (:stop-fn servers)]
    (stop-fn))
  servers)

(defn http-status
  "Returns generation-tagged HTTP shell lifecycle & diagnostic counters."
  [servers]
  (infra/shell-status-summary @(:shell-atom servers)))
