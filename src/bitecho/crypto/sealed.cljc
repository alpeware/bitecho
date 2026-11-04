(ns bitecho.crypto.sealed
  "Pure sealed-channel cryptographic primitives using JDK standard library on JVM and node:crypto on Node.
   Provides X25519 key agreement, HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 AEAD,
   deterministic nonce derivation, and gap-tolerant replay window.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str])
  #?(:clj (:import [java.nio ByteBuffer]
                   [java.security KeyFactory KeyPairGenerator]
                   [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
                   [javax.crypto Cipher KeyAgreement Mac]
                   [javax.crypto.spec IvParameterSpec SecretKeySpec])))

;; -----------------------------------------------------------------------------
;; X25519 Key Exchange
;; -----------------------------------------------------------------------------

(defn generate-x25519-keypair
  "Generates a new X25519 keypair.
   Returns a map with :public and :private encoded byte arrays."
  []
  #?(:clj (let [kpg (KeyPairGenerator/getInstance "X25519")
                kp (.generateKeyPair kpg)]
            {:public (.getEncoded (.getPublic kp))
             :private (.getEncoded (.getPrivate kp))})
     :cljs (let [node-crypto (js/require "node:crypto")
                 kp (.generateKeyPairSync node-crypto "x25519"
                                          #js {:publicKeyEncoding #js {:type "spki" :format "der"}
                                               :privateKeyEncoding #js {:type "pkcs8" :format "der"}})]
             {:public (js/Uint8Array. (.-publicKey kp))
              :private (js/Uint8Array. (.-privateKey kp))})))

(defn x25519-shared-secret
  "Derives a 32-byte shared secret from local private key bytes and remote public key bytes."
  [priv-bytes pub-bytes]
  #?(:clj (let [kf (KeyFactory/getInstance "X25519")
                priv-key (.generatePrivate kf (PKCS8EncodedKeySpec. priv-bytes))
                pub-key (.generatePublic kf (X509EncodedKeySpec. pub-bytes))
                ka (KeyAgreement/getInstance "X25519")]
            (.init ka priv-key)
            (.doPhase ka pub-key true)
            (.generateSecret ka))
     :cljs (let [node-crypto (js/require "node:crypto")
                 priv-key (.createPrivateKey node-crypto #js {:key (js/Buffer.from priv-bytes) :format "der" :type "pkcs8"})
                 pub-key (.createPublicKey node-crypto #js {:key (js/Buffer.from pub-bytes) :format "der" :type "spki"})]
             (js/Uint8Array. (.diffieHellman node-crypto #js {:privateKey priv-key :publicKey pub-key})))))

;; -----------------------------------------------------------------------------
;; HKDF-SHA256 (RFC 5869)
;; -----------------------------------------------------------------------------

(defn hkdf-extract
  "Extracts a pseudorandom key (PRK) from salt and input keying material (IKM) using HMAC-SHA256.
   If salt is nil or empty, a 32-byte array of zeros is used per RFC 5869 §2.2."
  [salt ikm]
  #?(:clj (let [effective-salt (if (or (nil? salt) (zero? (alength ^bytes salt)))
                                 (byte-array 32)
                                 salt)
                mac (Mac/getInstance "HmacSHA256")]
            (.init mac (SecretKeySpec. effective-salt "HmacSHA256"))
            (.doFinal mac ikm))
     :cljs (let [node-crypto (js/require "node:crypto")
                 eff-salt (if (or (nil? salt) (zero? (fressian/count-bytes salt)))
                            (js/Uint8Array. 32)
                            salt)
                 hmac (.createHmac node-crypto "sha256" (js/Buffer.from eff-salt))]
             (.update hmac (js/Buffer.from ikm))
             (js/Uint8Array. (.digest hmac)))))

(defn hkdf-expand
  "Expands a pseudorandom key (PRK) and info into output keying material (OKM) of desired length.
   Follows RFC 5869 §2.3 for HMAC-SHA256."
  [prk info length]
  #?(:clj (let [hash-len 32
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
                (.array out-buf))))
     :cljs (let [node-crypto (js/require "node:crypto")
                 safe-info (or info (js/Uint8Array. 0))]
             (js/Uint8Array. (.hkdfSync node-crypto "sha256" (js/Buffer.from prk) (js/Buffer.from (js/Uint8Array. 32)) (js/Buffer.from safe-info) length)))))

(defn hkdf-sha256
  "Combines hkdf-extract and hkdf-expand into a single RFC 5869 HKDF-SHA256 operation."
  [ikm salt info length]
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
  [shared-secret session-id role]
  (let [salt (fressian/utf8->bytes (or session-id ""))
        prk (hkdf-extract salt shared-secret)
        info-i2r (fressian/utf8->bytes "bitecho-sealed-v1-i2r")
        info-r2i (fressian/utf8->bytes "bitecho-sealed-v1-r2i")
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
  [seq-num]
  #?(:clj (let [bb (ByteBuffer/allocate 12)]
            (.putInt bb 0)
            (.putLong bb (long seq-num))
            (.array bb))
     :cljs (let [buf (js/Uint8Array. 12)
                 dv (js/DataView. (.-buffer buf))]
             (.setBigUint64 dv 4 (js/BigInt (str seq-num)))
             buf)))

;; -----------------------------------------------------------------------------
;; ChaCha20-Poly1305 AEAD
;; -----------------------------------------------------------------------------

(defn seal-message
  "Encrypts and authenticates plaintext using ChaCha20-Poly1305 AEAD.
   Returns a map with :seq, :nonce (12 bytes), and :ciphertext (including 16-byte Poly1305 tag)."
  [tx-key seq-num plaintext aad]
  (let [nonce (seq->nonce seq-num)]
    #?(:clj (let [cipher (Cipher/getInstance "ChaCha20-Poly1305")
                  key-spec (SecretKeySpec. tx-key "ChaCha20")
                  iv-spec (IvParameterSpec. nonce)]
              (.init cipher Cipher/ENCRYPT_MODE key-spec iv-spec)
              (when (and aad (pos? (alength ^bytes aad)))
                (.updateAAD cipher ^bytes aad))
              (let [input (or plaintext (byte-array 0))
                    ct (.doFinal cipher input)]
                {:seq seq-num
                 :nonce nonce
                 :ciphertext ct}))
       :cljs (let [node-crypto (js/require "node:crypto")
                   cipher (.createCipheriv node-crypto "chacha20-poly1305" (js/Buffer.from tx-key) (js/Buffer.from nonce) #js {:authTagLength 16})]
               (when (and aad (pos? (fressian/count-bytes aad)))
                 (.setAAD cipher (js/Buffer.from aad)))
               (let [input (or plaintext (js/Uint8Array. 0))
                     part1 (.update cipher (js/Buffer.from input))
                     _part2 (.final cipher)
                     tag (.getAuthTag cipher)
                     total (js/Buffer.concat #js [part1 tag])]
                 {:seq seq-num
                  :nonce nonce
                  :ciphertext (js/Uint8Array. total)})))))

(defn open-message
  "Decrypts and verifies ciphertext using ChaCha20-Poly1305 AEAD.
   Returns the decrypted plaintext byte array on success, or nil on failure/tampering."
  [rx-key seq-num ciphertext aad]
  (try
    (let [nonce (seq->nonce seq-num)]
      #?(:clj (let [cipher (Cipher/getInstance "ChaCha20-Poly1305")
                    key-spec (SecretKeySpec. rx-key "ChaCha20")
                    iv-spec (IvParameterSpec. nonce)]
                (.init cipher Cipher/DECRYPT_MODE key-spec iv-spec)
                (when (and aad (pos? (alength ^bytes aad)))
                  (.updateAAD cipher ^bytes aad))
                (.doFinal cipher ^bytes ciphertext))
         :cljs (let [node-crypto (js/require "node:crypto")
                     ct-buf (js/Buffer.from ciphertext)
                     tag-len 16
                     payload-len (- (.-length ct-buf) tag-len)
                     payload (.subarray ct-buf 0 payload-len)
                     tag (.subarray ct-buf payload-len)
                     decipher (.createDecipheriv node-crypto "chacha20-poly1305" (js/Buffer.from rx-key) (js/Buffer.from nonce) #js {:authTagLength 16})]
                 (when (and aad (pos? (fressian/count-bytes aad)))
                   (.setAAD decipher (js/Buffer.from aad)))
                 (.setAuthTag decipher tag)
                 (let [part1 (.update decipher payload)
                       part2 (.final decipher)]
                   (js/Uint8Array. (js/Buffer.concat #js [part1 part2]))))))
    (catch #?(:clj Exception :cljs :default) _ nil)))

;; -----------------------------------------------------------------------------
;; Offer Hash Binding & DAC Integrity (SPEC §4)
;; -----------------------------------------------------------------------------

(defn- safe-long [v default-val]
  (cond
    (integer? v) (long v)
    (number? v) (long v)
    (string? v) (try
                  #?(:clj (Long/parseLong (str/trim v))
                     :cljs (let [n (js/parseInt (str/trim v) 10)]
                             (if (js/isNaN n) default-val n)))
                  (catch #?(:clj Exception :cljs :default) _ default-val))
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
                        base-str)]
    (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes canonical-str)))))

;; -----------------------------------------------------------------------------
;; Gap-Tolerant Replay Window (SPEC §7)
;; -----------------------------------------------------------------------------

(defn init-replay-window
  "Initializes an anti-replay window state map with highest-seq 0, empty seen set, and window-size."
  ([] (init-replay-window 64))
  ([window-size]
   {:highest-seq 0
    :seen #{}
    :window-size (long window-size)}))

(defn check-and-advance-replay-window
  "Evaluates seq-num against anti-replay window.
   Rejects non-positive sequence numbers (:invalid-seq),
   duplicates (:replayed-seq), and entries older than the sliding window (:stale-seq).
   Returns {:accepted? boolean :error keyword :window updated-window}."
  [window seq-num]
  (let [seq-val (long seq-num)
        window-size (:window-size window 64)
        highest (:highest-seq window 0)
        seen (:seen window #{})]
    (cond
      (<= seq-val 0)
      {:accepted? false :error :invalid-seq :window window}

      (> seq-val highest)
      (let [cutoff (- seq-val window-size)
            pruned (into #{} (filter #(>= % cutoff)) seen)
            updated-window (assoc window
                                  :highest-seq seq-val
                                  :seen (conj pruned seq-val))]
        {:accepted? true :window updated-window})

      (< (- highest seq-val) window-size)
      (if (contains? seen seq-val)
        {:accepted? false :error :replayed-seq :window window}
        (let [updated-window (update window :seen conj seq-val)]
          {:accepted? true :window updated-window}))

      :else
      {:accepted? false :error :stale-seq :window window})))
