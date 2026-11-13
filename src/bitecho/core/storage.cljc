(ns bitecho.core.storage
  "Universal Sans-IO Fractal E2EE Storage & Capability Service.
   Built 100% on Bitecho data primitives (`Blob` + `Pointer` + `Subnet`):
   - Domain-separated on-device symmetric key derivation from Ed25519 seed/private-key
   - Pure XSalsa20-Poly1305 payload encryption with anti-tamper authentication
   - Anti-rollback monotonic versioning enforced via Pointer sequence numbers
   - Zero plaintext leakage to Nexus / storage subnets
   - Fractal capability advertising for UOp kernels, GPU access, relay, and weights."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

;; =============================================================================
;; 1. Domain-Separated Key Derivation & Secretbox Payload Encryption
;; =============================================================================

(defn derive-storage-key
  "Computes a 32-byte symmetric key using crypto/sha256 over
   [\"bitecho-e2ee-storage-v1:\" || privkey-bytes || \":\" || context-str].
   Private keys never leave the host device."
  ([privkey-bytes-or-hex]
   (derive-storage-key privkey-bytes-or-hex "default"))
  ([privkey-bytes-or-hex context-str]
   (let [p-bytes (cond
                   (string? privkey-bytes-or-hex)
                   (if (and (= (count privkey-bytes-or-hex) 64)
                            (re-matches #"[0-9a-fA-F]{64}" privkey-bytes-or-hex))
                     (fressian/hex->bytes privkey-bytes-or-hex)
                     (fressian/utf8->bytes privkey-bytes-or-hex))
                   :else privkey-bytes-or-hex)
         prefix (fressian/utf8->bytes "bitecho-e2ee-storage-v1:")
         sep (fressian/utf8->bytes ":")
         ctx-bytes (fressian/utf8->bytes (str (or context-str "default")))
         p-len (fressian/count-bytes p-bytes)
         pref-len (fressian/count-bytes prefix)
         sep-len (fressian/count-bytes sep)
         ctx-len (fressian/count-bytes ctx-bytes)
         total-len (+ pref-len p-len sep-len ctx-len)
         combined #?(:clj (byte-array total-len) :cljs (js/Uint8Array. total-len))]
     #?(:clj
        (do
          (System/arraycopy prefix 0 combined 0 pref-len)
          (System/arraycopy p-bytes 0 combined pref-len p-len)
          (System/arraycopy sep 0 combined (+ pref-len p-len) sep-len)
          (System/arraycopy ctx-bytes 0 combined (+ pref-len p-len sep-len) ctx-len))
        :cljs
        (do
          (.set combined prefix 0)
          (.set combined p-bytes pref-len)
          (.set combined sep (+ pref-len p-len))
          (.set combined ctx-bytes (+ pref-len p-len sep-len))))
     (crypto/sha256 combined))))

(defn encrypt-storage-payload
  "Encrypts plaintext using XSalsa20-Poly1305 and prepends the 24-byte nonce
   to the ciphertext bytes ([24-byte nonce || 16-byte tag || ciphertext])."
  [key-32-bytes nonce-24-bytes plaintext-bytes]
  (let [nonce (or nonce-24-bytes (crypto/random-bytes 24))
        pt (if (string? plaintext-bytes) (fressian/utf8->bytes plaintext-bytes) plaintext-bytes)
        boxed (crypto/secretbox key-32-bytes nonce pt)
        n-len (fressian/count-bytes nonce)
        b-len (fressian/count-bytes boxed)
        total-len (+ n-len b-len)
        res #?(:clj (byte-array total-len) :cljs (js/Uint8Array. total-len))]
    #?(:clj
       (do
         (System/arraycopy nonce 0 res 0 n-len)
         (System/arraycopy boxed 0 res n-len b-len))
       :cljs
       (do
         (.set res nonce 0)
         (.set res boxed n-len)))
    res))

(defn decrypt-storage-payload
  "Extracts the 24-byte nonce and ciphertext, calls crypto/secretbox-open,
   and returns {:ok? true :plaintext ...} or {:ok? false :error :decryption-failed}."
  [key-32-bytes packed-ciphertext-bytes]
  (let [total-len (if packed-ciphertext-bytes (fressian/count-bytes packed-ciphertext-bytes) 0)]
    (if (< total-len 40)
      {:ok? false :error :decryption-failed}
      (let [nonce #?(:clj (byte-array 24) :cljs (js/Uint8Array. 24))
            ct-len (- total-len 24)
            boxed #?(:clj (byte-array ct-len) :cljs (js/Uint8Array. ct-len))]
        #?(:clj
           (do
             (System/arraycopy packed-ciphertext-bytes 0 nonce 0 24)
             (System/arraycopy packed-ciphertext-bytes 24 boxed 0 ct-len))
           :cljs
           (do
             (.set nonce (.subarray packed-ciphertext-bytes 0 24) 0)
             (.set boxed (.subarray packed-ciphertext-bytes 24 total-len) 0)))
        (if-let [pt (crypto/secretbox-open key-32-bytes nonce boxed)]
          {:ok? true :plaintext pt}
          {:ok? false :error :decryption-failed})))))

;; =============================================================================
;; 2. Browser / Light-Node E2EE State Backup & Restore over Blob + Pointer
;; =============================================================================

(defn pack-encrypted-state
  "Encodes and encrypts user state data on-device into a content-addressed Blob
   and monotonic authority-signed Pointer."
  [{:keys [privkey pubkey subnet-id slot seq leader-term nonce-bytes state-data context]}]
  (let [sub-id (str (or subnet-id "global"))
        slot-name (str (or slot "default"))
        ctx-str (str (or context slot-name "state"))
        seq-num (long (or seq 1))
        term-num (long (or leader-term 1))
        pubkey-str (str pubkey)
        path (str "storage/" pubkey-str "/" slot-name)
        data-bytes (if (fressian/bytes? state-data)
                     state-data
                     (fressian/encode-canonical state-data))
        sym-key (derive-storage-key privkey ctx-str)
        nonce (or nonce-bytes (crypto/random-bytes 24))
        encrypted-bytes (encrypt-storage-payload sym-key nonce data-bytes)
        blob (data/make-blob encrypted-bytes "application/x-bitecho-e2ee-fressian")
        ptr-template {:pointer/subnet sub-id
                      :pointer/path path
                      :pointer/authority pubkey-str
                      :pointer/seq seq-num
                      :pointer/leader-term term-num
                      :pointer/target (:blob/cid blob)
                      :pointer/proof {:proof/type :self}}
        pointer (data/sign-pointer privkey ptr-template)]
    {:ok? true
     :blob blob
     :pointer pointer
     :cid (:blob/cid blob)
     :path path
     :subnet-id sub-id
     :seq seq-num}))

(defn unpack-encrypted-state
  "Verifies Blob and Pointer, checks anti-rollback monotonicity, decrypts, and decodes state."
  [{:keys [privkey pubkey blob pointer min-expected-seq context]}]
  (cond
    (not (data/verify-blob blob))
    {:ok? false :error :invalid-blob-cid}

    (let [v-ptr (data/verify-pointer pointer)]
      (or (not (:ok? v-ptr))
          (not= (:pointer/authority pointer) (str pubkey))))
    {:ok? false :error :invalid-pointer-signature}

    (not= (:pointer/target pointer) (:blob/cid blob))
    {:ok? false :error :pointer-target-mismatch}

    (< (long (:pointer/seq pointer 0)) (long (or min-expected-seq 0)))
    {:ok? false :error :stale-pointer-rollback}

    :else
    (let [path (:pointer/path pointer)
          pubkey-str (str pubkey)
          slot (when (and path (str/starts-with? path (str "storage/" pubkey-str "/")))
                 (subs path (count (str "storage/" pubkey-str "/"))))
          ctx-str (str (or context slot "state"))
          sym-key (derive-storage-key privkey ctx-str)
          dec-res (decrypt-storage-payload sym-key (:blob/bytes blob))]
      (if-not (:ok? dec-res)
        dec-res
        (let [pt (:plaintext dec-res)
              decoded (try
                        (fressian/decode-canonical pt)
                        (catch #?(:clj Exception :cljs :default) _ pt))]
          {:ok? true
           :data decoded
           :seq (:pointer/seq pointer)
           :cid (:blob/cid blob)
           :path path})))))

;; =============================================================================
;; 3. Fractal Capability Descriptors on Blob + Pointer
;; =============================================================================

(def supported-capability-types
  "Set of supported network capability type identifiers."
  #{:storage/blob-pinning
    :compute/uop-kernel
    :compute/gpu-access
    :model/weights
    :network/turn-relay
    :network/gateway})

(defn pack-capability-descriptor
  "Creates a canonical capability descriptor Blob and signed Pointer."
  [{:keys [privkey pubkey subnet-id capability-id capability-type price-echo burn-floor metadata seq leader-term target-cid path]}]
  (let [sub-id (str (or subnet-id "global"))
        cap-id (str capability-id)
        pubkey-str (str pubkey)
        cap-path (or path
                     (if (and subnet-id (not= subnet-id "global"))
                       (str "subnet/" subnet-id "/capability/" pubkey-str "/" cap-id)
                       (str "capability/" pubkey-str "/" cap-id)))
        seq-num (long (or seq 1))
        term-num (long (or leader-term 1))
        cap-map {:capability/id cap-id
                 :capability/type capability-type
                 :capability/provider pubkey-str
                 :capability/subnet sub-id
                 :capability/price-echo (long (or price-echo 0))
                 :capability/burn-floor (long (or burn-floor 0))
                 :capability/target-cid target-cid
                 :capability/metadata (or metadata {})}
        blob (data/make-blob (fressian/encode-canonical cap-map) "application/x-bitecho-capability")
        ptr-template {:pointer/subnet sub-id
                      :pointer/path cap-path
                      :pointer/authority pubkey-str
                      :pointer/seq seq-num
                      :pointer/leader-term term-num
                      :pointer/target (:blob/cid blob)
                      :pointer/proof {:proof/type :self}}
        pointer (data/sign-pointer privkey ptr-template)]
    {:ok? true
     :blob blob
     :pointer pointer
     :cid (:blob/cid blob)
     :path cap-path
     :subnet-id sub-id
     :seq seq-num}))

(defn unpack-capability-descriptor
  "Verifies Blob and Pointer, checks anti-rollback, and decodes capability descriptor."
  [{:keys [blob pointer min-expected-seq]}]
  (cond
    (not (data/verify-blob blob))
    {:ok? false :error :invalid-blob-cid}

    (not (:ok? (data/verify-pointer pointer)))
    {:ok? false :error :invalid-pointer-signature}

    (not= (:pointer/target pointer) (:blob/cid blob))
    {:ok? false :error :pointer-target-mismatch}

    (< (long (:pointer/seq pointer 0)) (long (or min-expected-seq 0)))
    {:ok? false :error :stale-pointer-rollback}

    :else
    (let [decoded (fressian/decode-canonical (:blob/bytes blob))]
      {:ok? true
       :capability decoded
       :cid (:blob/cid blob)
       :seq (:pointer/seq pointer)})))
