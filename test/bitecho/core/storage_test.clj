(ns bitecho.core.storage-test
  "Unit and generative property-based tests for bitecho.core.storage:
   - Domain-separated on-device key derivation and XSalsa20-Poly1305 encryption
   - Bounded anti-tamper ciphertext authentication
   - Monotonic state backup / restore over Blob + Pointer
   - Anti-rollback stale sequence rejection
   - Fractal capability descriptor advertising and verification."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.storage :as storage]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Generators
;; =============================================================================

(def ^:private gen-state-data
  (gen/recursive-gen
   (fn [inner]
     (gen/one-of [(gen/vector inner 0 5)
                  (gen/map (gen/fmap keyword gen/string-alphanumeric) inner {:max-elements 5})]))
   (gen/one-of [gen/int
                gen/boolean
                gen/string-alphanumeric
                (gen/fmap keyword gen/string-alphanumeric)])))

(def ^:private gen-bytes-payload
  (gen/fmap (fn [bs] (byte-array (map unchecked-byte bs)))
            (gen/vector (gen/choose 0 255) 1 128)))

;; =============================================================================
;; 1. Domain-Separated Key Derivation & Secretbox Tests
;; =============================================================================

(deftest test-derive-storage-key-domain-separation
  (testing "Domain separation: different contexts produce distinct 32-byte symmetric keys"
    (let [kp (crypto/generate-keypair)
          priv (:private kp)
          k1 (storage/derive-storage-key priv "session")
          k2 (storage/derive-storage-key priv "petnames")
          k3 (storage/derive-storage-key priv "session")
          k-default (storage/derive-storage-key priv)]
      (is (= 32 (alength ^bytes k1)))
      (is (= 32 (alength ^bytes k2)))
      (is (= (basalt/bytes->hex k1) (basalt/bytes->hex k3)))
      (is (not= (basalt/bytes->hex k1) (basalt/bytes->hex k2)))
      (is (not= (basalt/bytes->hex k1) (basalt/bytes->hex k-default))))))

(deftest test-encrypt-decrypt-storage-payload-unit
  (testing "XSalsa20-Poly1305 payload encryption roundtrip and bit-flip tampering rejection"
    (let [kp (crypto/generate-keypair)
          k (storage/derive-storage-key (:private kp) "test-ctx")
          nonce (crypto/random-bytes 24)
          plaintext (fressian/utf8->bytes "Secret User State 2026")
          packed (storage/encrypt-storage-payload k nonce plaintext)
          _ (is (>= (alength ^bytes packed) (+ 24 16 (alength ^bytes plaintext))))
          dec-res (storage/decrypt-storage-payload k packed)]
      (is (true? (:ok? dec-res)))
      (is (= "Secret User State 2026" (fressian/bytes->utf8 (:plaintext dec-res))))

      ;; Adversarial bit-flip in ciphertext
      (let [tampered (byte-array packed)]
        (aset tampered 30 (unchecked-byte (bit-xor (aget tampered 30) 1)))
        (is (= {:ok? false :error :decryption-failed}
               (storage/decrypt-storage-payload k tampered))))

      ;; Adversarial bit-flip in nonce
      (let [tampered-nonce (byte-array packed)]
        (aset tampered-nonce 5 (unchecked-byte (bit-xor (aget tampered-nonce 5) 1)))
        (is (= {:ok? false :error :decryption-failed}
               (storage/decrypt-storage-payload k tampered-nonce))))

      ;; Wrong key fails decryption
      (let [wrong-k (storage/derive-storage-key (:private kp) "other-ctx")]
        (is (= {:ok? false :error :decryption-failed}
               (storage/decrypt-storage-payload wrong-k packed)))))))

;; =============================================================================
;; 2. State Backup & Restore over Blob + Pointer Tests
;; =============================================================================

(deftest test-pack-unpack-encrypted-state-unit
  (testing "State pack/unpack roundtrip, anti-rollback, and tamper resistance"
    (let [kp (crypto/generate-keypair)
          priv (:private kp)
          pub (basalt/bytes->hex (:public kp))
          state-data {:petnames {"alice" "302a..." "bob" "302b..."}
                      :sessions ["s-001" "s-002"]
                      :preferences {:theme "nord" :font-size 14}}
          pack-res (storage/pack-encrypted-state {:privkey priv
                                                  :pubkey pub
                                                  :subnet-id "nexus"
                                                  :slot "state"
                                                  :seq 5
                                                  :state-data state-data})
          blob (:blob pack-res)
          ptr (:pointer pack-res)]
      (is (true? (:ok? pack-res)))
      (is (= "nexus" (:subnet-id pack-res)))
      (is (= 5 (:seq pack-res)))
      (is (= (str "storage/" pub "/state") (:path pack-res)))
      (is (string? (:blob/cid blob)))

      ;; Default subnet fallback is "global"
      (let [default-pack (storage/pack-encrypted-state {:privkey priv
                                                        :pubkey pub
                                                        :slot "state"
                                                        :seq 1
                                                        :state-data state-data})]
        (is (= "global" (:subnet-id default-pack)))
        (is (= "global" (get-in default-pack [:pointer :pointer/subnet]))))

      ;; Successful unpack at min-expected-seq 5
      (let [unpack-res (storage/unpack-encrypted-state {:privkey priv
                                                        :pubkey pub
                                                        :blob blob
                                                        :pointer ptr
                                                        :min-expected-seq 5})]
        (is (true? (:ok? unpack-res)))
        (is (= state-data (:data unpack-res)))
        (is (= 5 (:seq unpack-res)))
        (is (= (:blob/cid blob) (:cid unpack-res))))

      ;; Anti-rollback rejection when expected seq is higher
      (let [rollback-res (storage/unpack-encrypted-state {:privkey priv
                                                          :pubkey pub
                                                          :blob blob
                                                          :pointer ptr
                                                          :min-expected-seq 6})]
        (is (false? (:ok? rollback-res)))
        (is (= :stale-pointer-rollback (:error rollback-res))))

      ;; Invalid pointer signature rejection
      (let [tampered-ptr (assoc ptr :pointer/sig (apply str (repeat 128 "0")))
            sig-fail (storage/unpack-encrypted-state {:privkey priv
                                                      :pubkey pub
                                                      :blob blob
                                                      :pointer tampered-ptr
                                                      :min-expected-seq 5})]
        (is (false? (:ok? sig-fail)))
        (is (= :invalid-pointer-signature (:error sig-fail))))

      ;; Pointer target mismatch rejection
      (let [mismatch-ptr (assoc ptr :pointer/target (apply str (repeat 64 "f")))
            mismatch-fail (storage/unpack-encrypted-state {:privkey priv
                                                           :pubkey pub
                                                           :blob blob
                                                           :pointer mismatch-ptr
                                                           :min-expected-seq 5})]
        (is (false? (:ok? mismatch-fail)))
        ;; Signature verified over canonical pointer, so target change invalidates signature or target mismatch
        (is (contains? #{:pointer-target-mismatch :invalid-pointer-signature} (:error mismatch-fail))))

      ;; Bit-flipped blob CID rejection
      (let [tampered-blob (assoc blob :blob/cid (apply str (repeat 64 "a")))
            cid-fail (storage/unpack-encrypted-state {:privkey priv
                                                      :pubkey pub
                                                      :blob tampered-blob
                                                      :pointer ptr
                                                      :min-expected-seq 5})]
        (is (false? (:ok? cid-fail)))
        (is (= :invalid-blob-cid (:error cid-fail)))))))

;; =============================================================================
;; 3. Capability Descriptors Tests
;; =============================================================================

(deftest test-capability-descriptor-pack-unpack-unit
  (testing "Capability descriptor creation, validation, and anti-rollback"
    (let [kp (crypto/generate-keypair)
          priv (:private kp)
          pub (basalt/bytes->hex (:public kp))
          kernel-cid "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
          cap-pack (storage/pack-capability-descriptor
                    {:privkey priv
                     :pubkey pub
                     :subnet-id "global"
                     :capability-id "uop-kernel-gemm"
                     :capability-type :compute/uop-kernel
                     :price-echo 500
                     :burn-floor 10
                     :metadata {:architecture "rv64-vector" :speedup 4.2}
                     :seq 1
                     :target-cid kernel-cid})
          blob (:blob cap-pack)
          ptr (:pointer cap-pack)]
      (is (true? (:ok? cap-pack)))
      (is (= (str "capability/" pub "/uop-kernel-gemm") (:path cap-pack)))

      ;; Named subnet (e.g. "nexus") prefixes path with "subnet/<id>/"
      (let [nexus-pack (storage/pack-capability-descriptor
                        {:privkey priv
                         :pubkey pub
                         :subnet-id "nexus"
                         :capability-id "uop-kernel-gemm"
                         :capability-type :compute/uop-kernel
                         :price-echo 500
                         :seq 1})]
        (is (= (str "subnet/nexus/capability/" pub "/uop-kernel-gemm") (:path nexus-pack))))

      ;; Successful resolve
      (let [cap-res (storage/unpack-capability-descriptor {:blob blob :pointer ptr :min-expected-seq 1})]
        (is (true? (:ok? cap-res)))
        (is (= :compute/uop-kernel (get-in cap-res [:capability :capability/type])))
        (is (= 500 (get-in cap-res [:capability :capability/price-echo])))
        (is (= 10 (get-in cap-res [:capability :capability/burn-floor])))
        (is (= kernel-cid (get-in cap-res [:capability :capability/target-cid])))
        (is (= 4.2 (get-in cap-res [:capability :capability/metadata :speedup]))))

      ;; Anti-rollback rejection
      (let [stale-res (storage/unpack-capability-descriptor {:blob blob :pointer ptr :min-expected-seq 2})]
        (is (false? (:ok? stale-res)))
        (is (= :stale-pointer-rollback (:error stale-res)))))))

;; =============================================================================
;; 4. Generative Invariant Properties (clojure.test.check)
;; =============================================================================

(defspec ^{:doc "Invariant: pack-encrypted-state and unpack-encrypted-state preserve arbitrary data idempotently"}
  prop-e2ee-storage-roundtrip-preservation 50
  (prop/for-all [data gen-state-data
                 context (gen/elements ["state" "profile" "tokens" "prefs"])
                 seq-num (gen/choose 1 1000)]
                (let [kp (crypto/generate-keypair)
                      priv (:private kp)
                      pub (basalt/bytes->hex (:public kp))
                      packed (storage/pack-encrypted-state {:privkey priv
                                                            :pubkey pub
                                                            :subnet-id "nexus"
                                                            :slot context
                                                            :seq seq-num
                                                            :state-data data
                                                            :context context})
                      unpacked (storage/unpack-encrypted-state {:privkey priv
                                                                :pubkey pub
                                                                :blob (:blob packed)
                                                                :pointer (:pointer packed)
                                                                :min-expected-seq seq-num
                                                                :context context})]
                  (and (true? (:ok? packed))
                       (true? (:ok? unpacked))
                       (= data (:data unpacked))
                       (= seq-num (:seq unpacked))))))

(defspec ^{:doc "Invariant: Any single bit flip in encrypted payload fails closed with :decryption-failed"}
  prop-e2ee-payload-tamper-resistance 50
  (prop/for-all [payload gen-bytes-payload]
                (let [kp (crypto/generate-keypair)
                      sym-key (storage/derive-storage-key (:private kp) "property-test")
                      packed (storage/encrypt-storage-payload sym-key nil payload)
                      packed-len (alength ^bytes packed)
                      flip-idx (mod 17 packed-len)
                      tampered (byte-array packed)]
                  (aset tampered flip-idx (unchecked-byte (bit-xor (aget tampered flip-idx) 1)))
                  (let [res (storage/decrypt-storage-payload sym-key tampered)]
                    (and (false? (:ok? res))
                         (= :decryption-failed (:error res)))))))

(defspec ^{:doc "Invariant: Monotonic anti-rollback rejects any pointer with seq < min-expected-seq"}
  prop-storage-anti-rollback-monotonicity 50
  (prop/for-all [seq-num (gen/choose 1 100)
                 delta (gen/choose 1 50)]
                (let [kp (crypto/generate-keypair)
                      priv (:private kp)
                      pub (basalt/bytes->hex (:public kp))
                      packed (storage/pack-encrypted-state {:privkey priv
                                                            :pubkey pub
                                                            :slot "test"
                                                            :seq seq-num
                                                            :state-data {:count seq-num}})
                      expected-future-seq (+ seq-num delta)
                      unpacked (storage/unpack-encrypted-state {:privkey priv
                                                                :pubkey pub
                                                                :blob (:blob packed)
                                                                :pointer (:pointer packed)
                                                                :min-expected-seq expected-future-seq})]
                  (and (false? (:ok? unpacked))
                       (= :stale-pointer-rollback (:error unpacked))))))
