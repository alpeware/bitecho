(ns bitecho.crypto.key-provider
  "Row 11 Phase 1 — Pluggable Pure Sans-IO `IKeyProvider` / `Signer` Protocol & Encrypted Keystore
   (`bitecho.keystore/v1`) shared across Browser, Node.js Light, JVM Light, and Full Node (Rules 2, 4, 5)."
  (:require [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [clojure.string :as str])
  #?(:clj (:import [javax.crypto SecretKeyFactory]
                   [javax.crypto.spec PBEKeySpec])))

(def ^:private ed25519-spki-prefix-hex "302a300506032b6570032100")
(def ^:private ed25519-pkcs8-prefix-hex "302e020100300506032b657004220420")

#?(:cljs
   (def ^:private node-crypto
     (when (exists? js/require)
       (try (js/require "node:crypto") (catch :default _ nil)))))

(def security-tiers
  "Ordered security tier keywords surfaced in startup logs and `security_flags.keystore_security_tier`."
  #{:webauthn-prf-non-extractable
    :webcrypto-non-extractable
    :encrypted-keystore-0600
    :legacy-file-0600
    :webauthn-locked
    :ephemeral-memory})

(def keystore-schema-version
  "Canonical encrypted keystore EDN schema version."
  "bitecho.keystore/v1")

(def min-kdf-iterations
  "Recommended minimum PBKDF2-HMAC-SHA256 iteration floor."
  200000)

;; =============================================================================
;; Pubkey & Seed Normalization (64-char Raw Ed25519 vs 88-char SPKI-DER Parity)
;; =============================================================================

(defn normalize-pubkey-hex
  "Normalizes an Ed25519 public key (64-char raw hex, 88-char X.509 SPKI DER hex,
   or 32/44-byte array) to canonical lowercase 64-char raw Ed25519 hex."
  [pk]
  (let [hex-str (cond
                  (nil? pk) nil
                  (string? pk) (str/lower-case (str/trim pk))
                  (fressian/bytes? pk) (str/lower-case (fressian/bytes->hex pk))
                  :else (str/lower-case (str/trim (str pk))))]
    (when (and (string? hex-str) (not (str/blank? hex-str)))
      (cond
        (and (= 88 (count hex-str))
             (str/starts-with? hex-str ed25519-spki-prefix-hex))
        (subs hex-str 24)

        :else
        hex-str))))

(defn pubkey-hex->spki-hex
  "Converts a 64-char raw Ed25519 hex pubkey (or already 88-char SPKI hex) into 88-char SPKI DER hex."
  [pk]
  (when-let [raw (normalize-pubkey-hex pk)]
    (if (= 64 (count raw))
      (str ed25519-spki-prefix-hex raw)
      raw)))

(defn extract-ed25519-seed
  "Extracts a 32-byte raw Ed25519 seed from a 32-byte seed, 48-byte PKCS#8 DER byte array,
   or 64/96-char hex string."
  [priv-or-seed]
  (let [bs (cond
             (nil? priv-or-seed) nil
             (string? priv-or-seed) (fressian/hex->bytes (str/trim priv-or-seed))
             (fressian/bytes? priv-or-seed) priv-or-seed
             :else nil)]
    (when bs
      (let [n (fressian/count-bytes bs)]
        (cond
          (= n 32) bs
          (= n 48)
          #?(:clj (let [out (byte-array 32)]
                    (System/arraycopy bs 16 out 0 32)
                    out)
             :cljs (let [out (js/Uint8Array. 32)]
                     (.set out (.subarray bs 16 48) 0)
                     out))
          :else nil)))))

(defn- seed->raw-pubkey-bytes
  [seed32]
  (let [kp (crypto/pure-ed25519-keypair seed32)
        pub-der (:public kp)]
    #?(:clj (let [out (byte-array 32)]
              (System/arraycopy pub-der 12 out 0 32)
              out)
       :cljs (let [out (js/Uint8Array. 32)]
               (.set out (.subarray pub-der 12 44) 0)
               out))))

(defn- seed->pkcs8-bytes
  [seed32]
  (fressian/concat-bytes (fressian/hex->bytes ed25519-pkcs8-prefix-hex) seed32))

;; =============================================================================
;; IKeyProvider Protocol
;; =============================================================================

(defprotocol IKeyProvider
  "Uniform pluggable identity, signing, ECDH, and domain-key derivation boundary
   shared across Browser, Node.js Light, JVM Light, and Full Node (Row 11 Phase 1).
   Private key material MUST NEVER be required by callers or serialized in state."
  (public-key [this]
    "Returns canonical lowercase 64-char hex Ed25519 public key string (or nil if locked/uninitialized).")
  (public-key-bytes [this]
    "Returns 32-byte Ed25519 public key (byte-array on CLJ, Uint8Array on CLJS).")
  (sign [this message-bytes]
    "Signs `message-bytes` with Ed25519. Returns 64-byte signature (or {:ok? false :error :hardware-unlock-required}
     when locked; Browser async WebCrypto adapter exposes `sign-async` returning a Promise resolving to the same contract).")
  (x25519-agree [this peer-x25519-pubkey-bytes]
    "Performs X25519 ECDH key agreement against `peer-x25519-pubkey-bytes`. Returns 32-byte shared secret.")
  (derive-domain-key [this domain-context]
    "Derives a deterministic 32-byte domain-separated symmetric key for `domain-context`
     (e.g. \"bitecho-e2ee-backup-v1\"). Never exposes raw Ed25519 private key bytes.")
  (security-tier [this]
    "Returns one of `security-tiers` keywords for startup echo and `bitecho.status/v1`."))

(defprotocol IAsyncKeyProvider
  "Optional async signing boundary for non-extractable Browser WebCrypto / WebAuthn PRF
   `CryptoKey` providers (BIP-022 Stage C §3.1, F6b). On CLJS returns a `js/Promise` resolving
   to a 64-byte `Uint8Array` signature (or `{:ok? false :error ...}` when locked); on CLJ
   returns the synchronous result directly."
  (sign-async [this message-bytes]
    "Asynchronously signs `message-bytes` with Ed25519 without exposing private key material."))

;; =============================================================================
;; PBKDF2-HMAC-SHA256 & Keystore Seal / Open (`bitecho.keystore/v1`)
;; =============================================================================

#?(:cljs
   (defn- pure-cljs-pbkdf2-sha256-32
     [passphrase-bytes salt-bytes iterations]
     (let [block1 (js/Uint8Array. #js [0 0 0 1])
           salt-block (fressian/concat-bytes salt-bytes block1)
           u1 (sealed/pure-hmac-sha256 passphrase-bytes salt-block)
           acc (js/Uint8Array. u1)]
       (loop [i 1
              prev u1]
         (if (< i iterations)
           (let [u-next (sealed/pure-hmac-sha256 passphrase-bytes prev)]
             (dotimes [j 32]
               (aset acc j (bit-xor (aget acc j) (aget u-next j))))
             (recur (inc i) u-next))
           acc)))))

(defn derive-passphrase-kek
  "Pure KDF deriving a 32-byte Key-Encryption-Key (KEK) from `passphrase` and `salt-bytes`
   using PBKDF2-HMAC-SHA256 (`iterations >= 200000`, configurable for fast test vectors)."
  ([passphrase salt-bytes]
   (derive-passphrase-kek passphrase salt-bytes {}))
  ([passphrase salt-bytes {:keys [iterations] :or {iterations min-kdf-iterations}}]
   (let [pw-str (str (or passphrase ""))
         iters (max 1 (long (or iterations min-kdf-iterations)))
         salt (if (string? salt-bytes) (fressian/hex->bytes salt-bytes) salt-bytes)]
     #?(:clj
        (let [skf (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
              spec (PBEKeySpec. (.toCharArray pw-str) ^bytes salt (int iters) 256)]
          (.getEncoded (.generateSecret skf spec)))
        :cljs
        (if node-crypto
          (let [pbkdf2-fn (or (aget node-crypto "pbkdf2Sync") (.-pbkdf2Sync node-crypto))
                buf (.call pbkdf2-fn node-crypto
                           (js/Buffer.from pw-str "utf8")
                           (js/Buffer.from salt)
                           iters
                           32
                           "sha256")]
            (crypto/compact-u8 buf))
          (pure-cljs-pbkdf2-sha256-32 (fressian/utf8->bytes pw-str) salt iters))))))

(defn seal-keystore-edn
  "Purely encrypts identity secret material (`{:ed25519-seed <hex> :pubkey <hex> :created-ms <long> :metadata <map>}`)
   using XSalsa20-Poly1305 under KEK derived from `passphrase` + `salt-bytes` + `nonce-bytes`.
   Returns pure EDN map `{:schema \"bitecho.keystore/v1\" :pubkey <hex> :kdf {...} :cipher \"xsalsa20-poly1305\"
   :nonce-hex <48-hex> :ciphertext-hex <hex>}`. Zero plaintext private-key bytes appear anywhere in the map."
  [{:keys [pubkey seed-bytes passphrase salt-bytes nonce-bytes iterations created-ms metadata]}]
  (let [seed (extract-ed25519-seed seed-bytes)
        _ (when-not seed
            (throw (ex-info "Invalid Ed25519 seed bytes for seal-keystore-edn" {})))
        derived-pub (str/lower-case (fressian/bytes->hex (seed->raw-pubkey-bytes seed)))
        norm-pub (or (normalize-pubkey-hex pubkey) derived-pub)
        salt (or salt-bytes (crypto/random-bytes 16))
        nonce (or nonce-bytes (crypto/random-bytes 24))
        iters (long (or iterations min-kdf-iterations))
        kek (derive-passphrase-kek passphrase salt {:iterations iters})
        inner-payload (cond-> {:ed25519-seed (str/lower-case (fressian/bytes->hex seed))
                               :pubkey norm-pub
                               :created-ms (long (or created-ms 0))}
                        (map? metadata) (assoc :metadata metadata))
        pt-bytes (fressian/encode-canonical inner-payload)
        boxed (crypto/secretbox kek nonce pt-bytes)]
    {:schema keystore-schema-version
     :pubkey norm-pub
     :kdf {:alg "pbkdf2-hmac-sha256"
           :iterations iters
           :salt-hex (str/lower-case (fressian/bytes->hex salt))}
     :cipher "xsalsa20-poly1305"
     :nonce-hex (str/lower-case (fressian/bytes->hex nonce))
     :ciphertext-hex (str/lower-case (fressian/bytes->hex boxed))}))

(defn open-keystore-edn
  "Purely decrypts and verifies a `bitecho.keystore/v1` EDN map with `passphrase`.
   Verifies decrypted seed reproduces `:pubkey`.
   Returns `{:ok? true :pubkey <hex> :seed-bytes <bytes> :metadata <map-or-nil> :security-tier :encrypted-keystore-0600}`
   or `{:ok? false :error <:invalid-keystore-format | :invalid-passphrase-or-corrupt | :pubkey-mismatch>}`."
  [keystore-map passphrase]
  (if-not (and (map? keystore-map)
               (= keystore-schema-version (:schema keystore-map))
               (= "xsalsa20-poly1305" (:cipher keystore-map))
               (string? (:pubkey keystore-map))
               (map? (:kdf keystore-map))
               (string? (get-in keystore-map [:kdf :salt-hex]))
               (pos? (long (or (get-in keystore-map [:kdf :iterations]) 0)))
               (string? (:nonce-hex keystore-map))
               (string? (:ciphertext-hex keystore-map)))
    {:ok? false :error :invalid-keystore-format}
    (try
      (let [salt (fressian/hex->bytes (get-in keystore-map [:kdf :salt-hex]))
            iters (long (get-in keystore-map [:kdf :iterations]))
            nonce (fressian/hex->bytes (:nonce-hex keystore-map))
            ct (fressian/hex->bytes (:ciphertext-hex keystore-map))
            kek (derive-passphrase-kek passphrase salt {:iterations iters})
            pt (crypto/secretbox-open kek nonce ct)]
        (if-not pt
          {:ok? false :error :invalid-passphrase-or-corrupt}
          (let [decoded (fressian/decode-canonical pt)
                seed (extract-ed25519-seed (:ed25519-seed decoded))
                expected-pub (normalize-pubkey-hex (:pubkey keystore-map))]
            (if-not seed
              {:ok? false :error :invalid-passphrase-or-corrupt}
              (let [derived-pub (str/lower-case (fressian/bytes->hex (seed->raw-pubkey-bytes seed)))]
                (if (not= derived-pub expected-pub)
                  {:ok? false :error :pubkey-mismatch}
                  (cond-> {:ok? true
                           :pubkey derived-pub
                           :seed-bytes seed
                           :created-ms (:created-ms decoded)
                           :security-tier :encrypted-keystore-0600}
                    (map? (:metadata decoded)) (assoc :metadata (:metadata decoded)))))))))
      (catch #?(:clj Exception :cljs :default) _
        {:ok? false :error :invalid-passphrase-or-corrupt}))))

;; =============================================================================
;; Pure In-Memory & Locked Providers
;; =============================================================================

(defn make-memory-key-provider
  "Pure `.cljc` `IKeyProvider` backed by an in-memory 32-byte Ed25519 seed (or 48-byte PKCS#8 DER).
   Used by decrypted `keystore.enc.edn`, legacy `node-identity.edn` adapter, and generative tests.
   `tier` defaults to `:ephemeral-memory`."
  ([seed-bytes]
   (make-memory-key-provider seed-bytes :ephemeral-memory))
  ([seed-bytes tier]
   (let [seed (extract-ed25519-seed seed-bytes)
         _ (when-not seed
             (throw (ex-info "make-memory-key-provider requires 32-byte Ed25519 seed or 48-byte PKCS#8 DER" {})))
         eff-tier (if (contains? security-tiers tier) tier :ephemeral-memory)
         pub-raw (seed->raw-pubkey-bytes seed)
         pub-hex (str/lower-case (fressian/bytes->hex pub-raw))
         pkcs8 (seed->pkcs8-bytes seed)
         x-kp (sealed/x25519-keypair-from-seed seed)]
     (reify
       IKeyProvider
       (public-key [_] pub-hex)
       (public-key-bytes [_] pub-raw)
       (sign [_ message-bytes]
         (crypto/sign pkcs8 message-bytes))
       (x25519-agree [_ peer-x25519-pubkey-bytes]
         (sealed/x25519-shared-secret (:private x-kp) peer-x25519-pubkey-bytes))
       (derive-domain-key [_ domain-context]
         (sealed/hkdf-sha256 (fressian/utf8->bytes "bitecho-key-provider-v1")
                             seed
                             (fressian/utf8->bytes (str (or domain-context "default")))
                             32))
       (security-tier [_] eff-tier)
       IAsyncKeyProvider
       (sign-async [_ message-bytes]
         #?(:clj (crypto/sign pkcs8 message-bytes)
            :cljs (js/Promise.resolve (crypto/sign pkcs8 message-bytes))))))))

(defn make-locked-key-provider
  "Pure `.cljc` `IKeyProvider` representing a locked hardware/WebAuthn identity: exposes
   `public-key` and `:webauthn-locked` tier, and fails closed with canonical `:hardware-unlock-required`
   on `sign`, `x25519-agree`, and `derive-domain-key`."
  [pubkey-hex]
  (let [norm-pub (normalize-pubkey-hex pubkey-hex)
        pub-raw (when (and (string? norm-pub) (= 64 (count norm-pub)))
                  (fressian/hex->bytes norm-pub))]
    (reify
      IKeyProvider
      (public-key [_] norm-pub)
      (public-key-bytes [_] pub-raw)
      (sign [_ _message-bytes]
        {:ok? false :error :hardware-unlock-required})
      (x25519-agree [_ _peer-x25519-pubkey-bytes]
        {:ok? false :error :hardware-unlock-required})
      (derive-domain-key [_ _domain-context]
        {:ok? false :error :hardware-unlock-required})
      (security-tier [_] :webauthn-locked)
      IAsyncKeyProvider
      (sign-async [_ _message-bytes]
        #?(:clj {:ok? false :error :hardware-unlock-required}
           :cljs (js/Promise.resolve {:ok? false :error :hardware-unlock-required}))))))
