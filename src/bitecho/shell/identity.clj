(ns bitecho.shell.identity
  "Node identity management, DTLS certificates, and persistent credentials.
   Maintains deterministic ICE credentials, DTLS certificates for WebRTC DataChannel,
   and Ed25519 node signing keypairs."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datachannel.dtls :as dtls])
  (:import [java.io ByteArrayInputStream File]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]
           [java.security KeyFactory MessageDigest PrivateKey]
           [java.security.cert CertificateFactory X509Certificate]
           [java.security.spec PKCS8EncodedKeySpec]
           [java.util Base64]))

;; ---------------------------------------------------------------------------
;; Fingerprints & Hashes
;; ---------------------------------------------------------------------------

(def ^:private mime-encoder
  (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII)))

(def ^:private fingerprint-pattern
  #"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")

(defn- sha256-hex
  "Returns the lowercase hex-encoded SHA-256 digest of input byte array."
  [^bytes bs]
  (let [md (MessageDigest/getInstance "SHA-256")
        digest (.digest md bs)]
    (apply str (map #(format "%02x" (bit-and % 0xFF)) digest))))

(defn normalize-fingerprint
  "Normalizes a SHA-256 DTLS fingerprint string to 32 uppercase colon-separated hex pairs.
   Strips optional case-insensitive 'SHA-256:' prefix and surrounding whitespace.
   Throws ex-info if input is nil, blank, or does not match the 32-byte hex pattern."
  [fp]
  (when (or (nil? fp) (str/blank? (str fp)))
    (throw (ex-info "Invalid fingerprint: cannot be nil or blank" {:fingerprint fp})))
  (let [trimmed (str/trim (str fp))
        stripped (if (str/starts-with? (str/lower-case trimmed) "sha-256:")
                   (str/trim (subs trimmed 8))
                   trimmed)
        upper (str/upper-case stripped)]
    (if (re-matches fingerprint-pattern upper)
      upper
      (throw (ex-info "Invalid fingerprint format" {:fingerprint fp :normalized upper})))))

(defn verify-peer-fingerprint?
  "Verifies actual DTLS peer fingerprint against expected fingerprint.
   Strictly fail-closed: returns false if either is nil, blank, or invalid."
  [expected actual]
  (if (or (nil? expected) (nil? actual)
          (str/blank? (str expected)) (str/blank? (str actual)))
    false
    (try
      (= (normalize-fingerprint expected) (normalize-fingerprint actual))
      (catch Exception _
        false))))

(defn deterministic-ice-creds
  "Derives deterministic ICE ufrag (8 chars) and pwd (24 chars) credentials
   from node-id and optional peer/cert fingerprint."
  ([node-id]
   (deterministic-ice-creds node-id nil))
  ([node-id fingerprint]
   (let [name-str (name (or node-id :node))
         seed-str (if (and (string? fingerprint) (not (str/blank? fingerprint)))
                    (str name-str "-" (normalize-fingerprint fingerprint))
                    name-str)
         ufrag (subs (sha256-hex (.getBytes (str "ufrag-" seed-str) StandardCharsets/UTF_8)) 0 8)
         pwd (subs (sha256-hex (.getBytes (str "pwd-" seed-str) StandardCharsets/UTF_8)) 0 24)]
     {:ufrag ufrag :pwd pwd})))

;; ---------------------------------------------------------------------------
;; PEM Serialization
;; ---------------------------------------------------------------------------

(defn encode-cert-pem
  "Serializes an X509Certificate to standard PEM format string."
  [^X509Certificate cert]
  (str "-----BEGIN CERTIFICATE-----\n"
       (.encodeToString mime-encoder (.getEncoded cert))
       "\n-----END CERTIFICATE-----\n"))

(defn encode-private-key-pem
  "Serializes a PKCS#8 PrivateKey to standard PEM format string."
  [^PrivateKey k]
  (str "-----BEGIN PRIVATE KEY-----\n"
       (.encodeToString mime-encoder (.getEncoded k))
       "\n-----END PRIVATE KEY-----\n"))

(defn parse-cert-pem
  "Parses an X.509 certificate from a PEM string.
   Returns the first X509Certificate found, or nil if none."
  [pem-str]
  (when (and pem-str (not (str/blank? pem-str)))
    (let [cf (CertificateFactory/getInstance "X.509")
          in (ByteArrayInputStream. (.getBytes ^String pem-str StandardCharsets/US_ASCII))]
      (first (vec (.generateCertificates cf in))))))

(defn parse-private-key-pem
  "Parses a PKCS#8 PrivateKey from a PEM string (EC with fallback to RSA)."
  [pem-str]
  (when (and pem-str (not (str/blank? pem-str)))
    (let [cleaned (-> pem-str
                      (str/replace #"-----BEGIN [A-Z ]+-----" "")
                      (str/replace #"-----END [A-Z ]+-----" "")
                      (str/replace #"\s+" ""))
          decoder (Base64/getDecoder)
          key-bytes (.decode decoder ^String cleaned)
          spec (PKCS8EncodedKeySpec. key-bytes)]
      (try
        (let [kf (KeyFactory/getInstance "EC")]
          (.generatePrivate kf spec))
        (catch Exception _
          (let [kf (KeyFactory/getInstance "RSA")]
            (.generatePrivate kf spec)))))))

;; ---------------------------------------------------------------------------
;; Identity Storage & Key Generation
;; ---------------------------------------------------------------------------

(defn generate-ed25519-keypair-map
  "Generates an Ed25519 keypair and returns map with hex-encoded :pubkey-hex and :privkey-hex."
  []
  (let [kp (crypto/generate-keypair)]
    {:pubkey-hex (basalt/bytes->hex (:public kp))
     :privkey-hex (basalt/bytes->hex (:private kp))}))

(defn- read-persisted-identity
  "Reads and validates an existing node-identity.edn file."
  [node-id identity-file]
  (let [edn-data (edn/read-string (slurp identity-file))]
    (when-not (and (map? edn-data)
                   (:pubkey-hex edn-data)
                   (:privkey-hex edn-data)
                   (:cert-pem edn-data)
                   (:key-pem edn-data)
                   (:fingerprint edn-data)
                   (:ice-creds edn-data))
      (throw (ex-info "Corrupt node-identity.edn file: missing required fields"
                      {:file (.getAbsolutePath identity-file)})))
    (let [cert (parse-cert-pem (:cert-pem edn-data))
          key (parse-private-key-pem (:key-pem edn-data))
          pub-bytes (basalt/hex->bytes (:pubkey-hex edn-data))
          priv-bytes (basalt/hex->bytes (:privkey-hex edn-data))]
      (when (or (nil? cert) (nil? key))
        (throw (ex-info "Corrupt node-identity.edn file: invalid certificate or key"
                        {:file (.getAbsolutePath identity-file)})))
      {:node-id node-id
       :pubkey-hex (:pubkey-hex edn-data)
       :privkey-hex (:privkey-hex edn-data)
       :keypair {:public pub-bytes :private priv-bytes}
       :fingerprint (:fingerprint edn-data)
       :ice-creds (:ice-creds edn-data)
       :cert-data {:cert cert :key key :fingerprint (:fingerprint edn-data)}})))

(defn- write-atomic-identity!
  "Writes node identity map to disk atomically using temporary file and atomic rename."
  [identity-dir identity-file identity-map]
  (let [tmp-file (File/createTempFile "identity" ".tmp" identity-dir)]
    (spit tmp-file (pr-str identity-map))
    (try
      (Files/setPosixFilePermissions (.toPath tmp-file) (PosixFilePermissions/fromString "rw-------"))
      (catch UnsupportedOperationException _ nil))
    (try
      (Files/move (.toPath tmp-file) (.toPath identity-file)
                  (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                        StandardCopyOption/REPLACE_EXISTING]))
      (catch Exception _
        (Files/move (.toPath tmp-file) (.toPath identity-file)
                    (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))))

(defn load-or-create-node-identity!
  "Loads or creates node identity containing Ed25519 keypair, DTLS certificate/key,
   deterministic ICE credentials, and SHA-256 fingerprint.
   Persists to <state-dir>/identity/node-identity.edn."
  [state-dir node-id]
  (let [identity-dir (io/file state-dir "identity")
        _ (.mkdirs identity-dir)
        identity-file (io/file identity-dir "node-identity.edn")]
    (if (.exists identity-file)
      (try
        (read-persisted-identity node-id identity-file)
        (catch clojure.lang.ExceptionInfo e (throw e))
        (catch Exception e
          (throw (ex-info "Corrupt node-identity.edn file"
                          {:file (.getAbsolutePath identity-file)}
                          e))))
      (let [cert-data (dtls/generate-cert)
            cert (:cert cert-data)
            key (:key cert-data)
            fp (normalize-fingerprint (:fingerprint cert-data))
            cert-pem (encode-cert-pem cert)
            key-pem (encode-private-key-pem key)
            ice-creds (deterministic-ice-creds node-id fp)
            kp (crypto/generate-keypair)
            pub-hex (basalt/bytes->hex (:public kp))
            priv-hex (basalt/bytes->hex (:private kp))
            data-to-save {:pubkey-hex pub-hex
                          :privkey-hex priv-hex
                          :cert-pem cert-pem
                          :key-pem key-pem
                          :fingerprint fp
                          :ice-creds ice-creds}]
        (write-atomic-identity! identity-dir identity-file data-to-save)
        {:node-id node-id
         :pubkey-hex pub-hex
         :privkey-hex priv-hex
         :keypair kp
         :fingerprint fp
         :ice-creds ice-creds
         :cert-data {:cert cert :key key :fingerprint fp}}))))
