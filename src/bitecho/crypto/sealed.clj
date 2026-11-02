(ns bitecho.crypto.sealed
  "Pure sealed-channel cryptographic primitives using JDK standard library only.
   Provides X25519 key agreement, HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 AEAD,
   deterministic nonce derivation, and gap-tolerant replay window."
  (:require [bitecho.basalt.core :as basalt]
            [clojure.string :as str])
  (:import [java.nio ByteBuffer]
           [java.security KeyFactory KeyPairGenerator]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [javax.crypto Cipher KeyAgreement Mac]
           [javax.crypto.spec IvParameterSpec SecretKeySpec]))

;; -----------------------------------------------------------------------------
;; X25519 Key Exchange
;; -----------------------------------------------------------------------------

(defn generate-x25519-keypair
  "Generates a new X25519 keypair using the JDK KeyPairGenerator.
   Returns a map with :public and :private encoded byte arrays."
  []
  (let [kpg (KeyPairGenerator/getInstance "X25519")
        kp (.generateKeyPair kpg)]
    {:public (.getEncoded (.getPublic kp))
     :private (.getEncoded (.getPrivate kp))}))

(defn x25519-shared-secret
  "Derives a 32-byte shared secret from local private key bytes and remote public key bytes."
  [^bytes priv-bytes ^bytes pub-bytes]
  (let [kf (KeyFactory/getInstance "X25519")
        priv-key (.generatePrivate kf (PKCS8EncodedKeySpec. priv-bytes))
        pub-key (.generatePublic kf (X509EncodedKeySpec. pub-bytes))
        ka (KeyAgreement/getInstance "X25519")]
    (.init ka priv-key)
    (.doPhase ka pub-key true)
    (.generateSecret ka)))

;; -----------------------------------------------------------------------------
;; HKDF-SHA256 (RFC 5869)
;; -----------------------------------------------------------------------------

(defn hkdf-extract
  "Extracts a pseudorandom key (PRK) from salt and input keying material (IKM) using HMAC-SHA256.
   If salt is nil or empty, a 32-byte array of zeros is used per RFC 5869 §2.2."
  [^bytes salt ^bytes ikm]
  (let [effective-salt (if (or (nil? salt) (zero? (alength salt)))
                         (byte-array 32)
                         salt)
        mac (Mac/getInstance "HmacSHA256")]
    (.init mac (SecretKeySpec. effective-salt "HmacSHA256"))
    (.doFinal mac ikm)))

(defn hkdf-expand
  "Expands a pseudorandom key (PRK) and info into output keying material (OKM) of desired length.
   Follows RFC 5869 §2.3 for HMAC-SHA256."
  [^bytes prk ^bytes info ^long length]
  (let [hash-len 32
        n (long (Math/ceil (/ (double length) hash-len)))
        _ (when (> n 255)
            (throw (IllegalArgumentException. "Requested length exceeds HKDF-SHA256 maximum (255 * 32 bytes)")))
        mac (Mac/getInstance "HmacSHA256")
        key-spec (SecretKeySpec. prk "HmacSHA256")
        out-buf (ByteBuffer/allocate length)
        safe-info (or info (byte-array 0))]
    (loop [i 1
           t (byte-array 0)]
      (if (<= i n)
        (do
          (.init mac key-spec)
          (when (pos? (alength ^bytes t))
            (.update mac ^bytes t))
          (when (pos? (alength ^bytes safe-info))
            (.update mac ^bytes safe-info))
          (.update mac (byte i))
          (let [t-next (.doFinal mac)
                to-copy (min hash-len (- length (.position out-buf)))]
            (.put out-buf t-next 0 to-copy)
            (recur (inc i) t-next)))
        (.array out-buf)))))

(defn hkdf-sha256
  "Combines hkdf-extract and hkdf-expand into a single RFC 5869 HKDF-SHA256 operation."
  [^bytes ikm ^bytes salt ^bytes info ^long length]
  (let [prk (hkdf-extract salt ikm)]
    (hkdf-expand prk info length)))

;; -----------------------------------------------------------------------------
;; Directional Channel Keys & Nonce Derivation
;; -----------------------------------------------------------------------------

(defn derive-channel-keys
  "Derives directional 32-byte :tx-key and :rx-key from shared-secret and session-id.
   For role :initiator:
     :tx-key = i2r key, :rx-key = r2i key
   For role :responder:
     :tx-key = r2i key, :rx-key = i2r key."
  [^bytes shared-secret ^String session-id role]
  (let [salt (.getBytes (or session-id "") "UTF-8")
        prk (hkdf-extract salt shared-secret)
        info-i2r (.getBytes "bitecho-sealed-v1-i2r" "UTF-8")
        info-r2i (.getBytes "bitecho-sealed-v1-r2i" "UTF-8")
        k-i2r (hkdf-expand prk info-i2r 32)
        k-r2i (hkdf-expand prk info-r2i 32)]
    (if (= role :initiator)
      {:tx-key k-i2r :rx-key k-r2i}
      {:tx-key k-r2i :rx-key k-i2r})))

(defn derive-session-keys
  "Derives directional channel keys for a rendezvous sealed-channel handoff.
   Accepts [my-priv peer-pub caller-pub callee-pub offer-hash role] or [my-priv peer-pub caller-pub callee-pub offer-hash].
   Uses X25519 Diffie-Hellman to derive the shared secret and derives directional keys
   bound to offer-hash salt."
  ([my-priv peer-pub caller-pub callee-pub offer-hash]
   (derive-session-keys my-priv peer-pub caller-pub callee-pub offer-hash :initiator))
  ([my-priv peer-pub _caller-pub _callee-pub offer-hash role]
   (let [priv-bytes (if (string? my-priv) (basalt/hex->bytes my-priv) my-priv)
         peer-bytes (if (string? peer-pub) (basalt/hex->bytes peer-pub) peer-pub)
         shared-secret (x25519-shared-secret priv-bytes peer-bytes)
         salt-str (str (or offer-hash ""))]
     (derive-channel-keys shared-secret salt-str role))))

(defn seq->nonce
  "Deterministically encodes a 64-bit sequence number into a 12-byte (96-bit) nonce:
   4 zero prefix bytes followed by 8-byte big-endian sequence number."
  ^bytes [^long seq-num]
  (let [bb (ByteBuffer/allocate 12)]
    (.putInt bb 0)
    (.putLong bb seq-num)
    (.array bb)))

;; -----------------------------------------------------------------------------
;; ChaCha20-Poly1305 AEAD
;; -----------------------------------------------------------------------------

(defn seal-message
  "Encrypts and authenticates plaintext using ChaCha20-Poly1305 AEAD.
   Returns a map with :seq, :nonce (12 bytes), and :ciphertext (including 16-byte Poly1305 tag)."
  [^bytes tx-key ^long seq-num ^bytes plaintext ^bytes aad]
  (let [nonce (seq->nonce seq-num)
        cipher (Cipher/getInstance "ChaCha20-Poly1305")
        key-spec (SecretKeySpec. tx-key "ChaCha20")
        iv-spec (IvParameterSpec. nonce)]
    (.init cipher Cipher/ENCRYPT_MODE key-spec iv-spec)
    (when (and aad (pos? (alength aad)))
      (.updateAAD cipher aad))
    (let [input (or plaintext (byte-array 0))
          ct (.doFinal cipher input)]
      {:seq seq-num
       :nonce nonce
       :ciphertext ct})))

(defn open-message
  "Decrypts and verifies ciphertext using ChaCha20-Poly1305 AEAD.
   Returns the decrypted plaintext byte array on success, or nil on failure/tampering."
  [^bytes rx-key ^long seq-num ^bytes ciphertext ^bytes aad]
  (try
    (let [nonce (seq->nonce seq-num)
          cipher (Cipher/getInstance "ChaCha20-Poly1305")
          key-spec (SecretKeySpec. rx-key "ChaCha20")
          iv-spec (IvParameterSpec. nonce)]
      (.init cipher Cipher/DECRYPT_MODE key-spec iv-spec)
      (when (and aad (pos? (alength aad)))
        (.updateAAD cipher aad))
      (.doFinal cipher ciphertext))
    (catch Exception _ nil)))

;; -----------------------------------------------------------------------------
;; Offer Hash Binding & DAC Integrity (SPEC §4)
;; -----------------------------------------------------------------------------

(defn- safe-long [v default-val]
  (cond
    (integer? v) (long v)
    (number? v) (long v)
    (string? v) (try (Long/parseLong (str/trim v)) (catch Exception _ default-val))
    :else default-val))

(defn offer-hash
  "Computes deterministic offer-hash binding session-id, caller, callee, ephemeral key, epoch, price, and home-node.
   When :dac is absent, uses canonical format bitecho-sealed-offer-v1|...
   When :dac is present, appends |<dac-id> to cryptographically bind the offer signature to the specific DAC."
  [offer-map]
  (let [sid (str (or (:session-id offer-map) (get offer-map "session_id") (get offer-map "session-id") ""))
        caller (str (or (:caller offer-map) (get offer-map "caller") ""))
        callee (str (or (:callee offer-map) (get offer-map "callee") ""))
        eph (str (or (:caller-ephemeral-pub offer-map) (get offer-map "caller_ephemeral_pub") (get offer-map "caller-ephemeral-pub") ""))
        epoch (safe-long (or (:epoch offer-map) (get offer-map "epoch")) 0)
        price (safe-long (or (:price offer-map) (get offer-map "price") (:burn offer-map) (get offer-map "burn")) 0)
        home-node (or (:home-node offer-map) (get offer-map "home_node") (get offer-map "home-node") "")
        hn-str (if (keyword? home-node) (name home-node) (str home-node))
        dac (or (:dac offer-map) (get offer-map "dac"))
        dac-id (when dac (or (:dac-id dac) (get dac "dac_id") (get dac "dac-id") (:dac_id dac)))
        base-str (str "bitecho-sealed-offer-v1|" sid "|" caller "|" callee "|" eph "|" epoch "|" price "|" hn-str)
        canonical-str (if (and dac (seq (str dac-id)))
                        (str base-str "|" dac-id)
                        base-str)
        md (java.security.MessageDigest/getInstance "SHA-256")
        digest (.digest md (.getBytes canonical-str "UTF-8"))
        sb (StringBuilder.)]
    (doseq [b digest]
      (.append sb (format "%02x" (Byte/toUnsignedInt b))))
    (.toString sb)))

;; -----------------------------------------------------------------------------
;; Gap-Tolerant Replay Window (SPEC §7)
;; -----------------------------------------------------------------------------

(defn init-replay-window
  "Initializes an anti-replay window state map with highest-seq 0, empty seen set, and window-size."
  ([] (init-replay-window 64))
  ([^long window-size]
   {:highest-seq 0
    :seen #{}
    :window-size window-size}))

(defn check-and-advance-replay-window
  "Evaluates seq-num against anti-replay window.
   Rejects non-positive sequence numbers (:invalid-seq),
   duplicates (:replayed-seq), and entries older than the sliding window (:stale-seq).
   Returns {:accepted? boolean :error keyword :window updated-window}."
  [window ^long seq-num]
  (let [window-size (:window-size window 64)
        highest (:highest-seq window 0)
        seen (:seen window #{})]
    (cond
      (<= seq-num 0)
      {:accepted? false :error :invalid-seq :window window}

      (> seq-num highest)
      (let [cutoff (- seq-num window-size)
            pruned (into #{} (filter #(>= % cutoff)) seen)
            updated-window (assoc window
                                  :highest-seq seq-num
                                  :seen (conj pruned seq-num))]
        {:accepted? true :window updated-window})

      (< (- highest seq-num) window-size)
      (if (contains? seen seq-num)
        {:accepted? false :error :replayed-seq :window window}
        (let [updated-window (update window :seen conj seq-num)]
          {:accepted? true :window updated-window}))

      :else
      {:accepted? false :error :stale-seq :window window})))
