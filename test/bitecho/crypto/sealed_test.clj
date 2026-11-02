(ns bitecho.crypto.sealed-test
  "Tests and generative invariants for pure sealed-channel crypto:
   X25519, HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 AEAD, and gap-tolerant replay window."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto.sealed :as sealed]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; -----------------------------------------------------------------------------
;; RFC 5869 HKDF-SHA256 Official Test Vectors
;; -----------------------------------------------------------------------------

(deftest rfc5869-test-case-1
  (testing "RFC 5869 Test Case 1 (SHA-256)"
    (let [ikm (basalt/hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
          salt (basalt/hex->bytes "000102030405060708090a0b0c")
          info (basalt/hex->bytes "f0f1f2f3f4f5f6f7f8f9")
          expected-prk "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
          expected-okm "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
          prk (sealed/hkdf-extract salt ikm)
          okm (sealed/hkdf-expand prk info 42)
          okm-full (sealed/hkdf-sha256 ikm salt info 42)]
      (is (= expected-prk (basalt/bytes->hex prk)))
      (is (= expected-okm (basalt/bytes->hex okm)))
      (is (= expected-okm (basalt/bytes->hex okm-full))))))

(deftest rfc5869-test-case-2
  (testing "RFC 5869 Test Case 2 (SHA-256, longer inputs and outputs)"
    (let [ikm (basalt/hex->bytes (str "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                                      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                                      "404142434445464748494a4b4c4d4e4f"))
          salt (basalt/hex->bytes (str "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                                       "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                                       "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
          info (basalt/hex->bytes (str "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                       "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                       "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
          expected-prk "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
          expected-okm (str "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                            "cc30c58179ec3e87c14c01d5c1f3434f1d87")
          prk (sealed/hkdf-extract salt ikm)
          okm (sealed/hkdf-expand prk info 82)
          okm-full (sealed/hkdf-sha256 ikm salt info 82)]
      (is (= expected-prk (basalt/bytes->hex prk)))
      (is (= expected-okm (basalt/bytes->hex okm)))
      (is (= expected-okm (basalt/bytes->hex okm-full))))))

(deftest rfc5869-test-case-3
  (testing "RFC 5869 Test Case 3 (SHA-256, zero-length salt and info)"
    (let [ikm (basalt/hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
          salt (byte-array 0)
          info (byte-array 0)
          expected-prk "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
          expected-okm "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
          prk (sealed/hkdf-extract salt ikm)
          okm (sealed/hkdf-expand prk info 42)
          okm-full (sealed/hkdf-sha256 ikm salt info 42)]
      (is (= expected-prk (basalt/bytes->hex prk)))
      (is (= expected-okm (basalt/bytes->hex okm)))
      (is (= expected-okm (basalt/bytes->hex okm-full))))))

;; -----------------------------------------------------------------------------
;; Generative Invariant Tests
;; -----------------------------------------------------------------------------

(def gen-bytes
  "Generates random byte arrays from 0 to 256 bytes."
  (gen/fmap (fn [byte-list] (byte-array (map byte byte-list)))
            (gen/vector (gen/choose -128 127) 0 256)))

(def gen-non-empty-bytes
  "Generates non-empty random byte arrays from 1 to 256 bytes."
  (gen/fmap (fn [byte-list] (byte-array (map byte byte-list)))
            (gen/vector (gen/choose -128 127) 1 256)))

(defspec ^{:doc "Property: X25519 key exchange is commutative and derives identical directional keys"}
  prop-x25519-commutative-and-directional-keys 50
  (prop/for-all [session-id (gen/fmap (partial apply str) (gen/vector gen/char-alphanumeric 8 32))]
                (let [kp-init (sealed/generate-x25519-keypair)
                      kp-resp (sealed/generate-x25519-keypair)
                      sec-init (sealed/x25519-shared-secret (:private kp-init) (:public kp-resp))
                      sec-resp (sealed/x25519-shared-secret (:private kp-resp) (:public kp-init))
                      init-keys (sealed/derive-channel-keys sec-init session-id :initiator)
                      resp-keys (sealed/derive-channel-keys sec-resp session-id :responder)]
                  (and (= (basalt/bytes->hex sec-init) (basalt/bytes->hex sec-resp))
                       (= (basalt/bytes->hex (:tx-key init-keys)) (basalt/bytes->hex (:rx-key resp-keys)))
                       (= (basalt/bytes->hex (:rx-key init-keys)) (basalt/bytes->hex (:tx-key resp-keys)))
                       (not= (basalt/bytes->hex (:tx-key init-keys)) (basalt/bytes->hex (:rx-key init-keys)))))))

(defspec ^{:doc "Property: Sealed channel round-trip encryption/decryption succeeds bidirectionally across random plaintexts, AADs, and sequences"}
  prop-sealed-channel-roundtrip 50
  (prop/for-all [plaintext gen-bytes
                 aad gen-bytes
                 seq-num (gen/choose 1 1000000)
                 session-id (gen/fmap (partial apply str) (gen/vector gen/char-alphanumeric 8 32))]
                (let [kp-init (sealed/generate-x25519-keypair)
                      kp-resp (sealed/generate-x25519-keypair)
                      sec-init (sealed/x25519-shared-secret (:private kp-init) (:public kp-resp))
                      sec-resp (sealed/x25519-shared-secret (:private kp-resp) (:public kp-init))
                      init-keys (sealed/derive-channel-keys sec-init session-id :initiator)
                      resp-keys (sealed/derive-channel-keys sec-resp session-id :responder)
                      ;; Initiator -> Responder
                      sealed-i2r (sealed/seal-message (:tx-key init-keys) seq-num plaintext aad)
                      decrypted-i2r (sealed/open-message (:rx-key resp-keys) seq-num (:ciphertext sealed-i2r) aad)
                      ;; Responder -> Initiator
                      sealed-r2i (sealed/seal-message (:tx-key resp-keys) seq-num plaintext aad)
                      decrypted-r2i (sealed/open-message (:rx-key init-keys) seq-num (:ciphertext sealed-r2i) aad)]
                  (and (java.util.Arrays/equals ^bytes plaintext ^bytes decrypted-i2r)
                       (java.util.Arrays/equals ^bytes plaintext ^bytes decrypted-r2i)
                       (= seq-num (:seq sealed-i2r))
                       (= 12 (alength ^bytes (:nonce sealed-i2r)))))))

(deftest test-derive-session-keys-symmetry
  (testing "derive-session-keys produces symmetric directional keys for initiator and responder"
    (let [kp-caller (sealed/generate-x25519-keypair)
          kp-callee (sealed/generate-x25519-keypair)
          caller-pub "caller-pub-1"
          callee-pub "callee-pub-2"
          offer-hash "offer-hash-abc-123"
          caller-keys (sealed/derive-session-keys (:private kp-caller) (:public kp-callee) caller-pub callee-pub offer-hash :initiator)
          callee-keys (sealed/derive-session-keys (:private kp-callee) (:public kp-caller) caller-pub callee-pub offer-hash :responder)]
      (is (= (basalt/bytes->hex (:tx-key caller-keys)) (basalt/bytes->hex (:rx-key callee-keys))))
      (is (= (basalt/bytes->hex (:rx-key caller-keys)) (basalt/bytes->hex (:tx-key callee-keys))))
      (is (not= (basalt/bytes->hex (:tx-key caller-keys)) (basalt/bytes->hex (:rx-key caller-keys)))))))

(defspec ^{:doc "Property: Sealed channel fail-closed on tampered ciphertext, tampered AAD, wrong sequence, or third-party key"}
  prop-sealed-channel-tamper-resistance 50
  (prop/for-all [plaintext gen-non-empty-bytes
                 aad gen-bytes
                 seq-num (gen/choose 1 1000000)
                 session-id (gen/fmap (partial apply str) (gen/vector gen/char-alphanumeric 8 32))]
                (let [kp-init (sealed/generate-x25519-keypair)
                      kp-resp (sealed/generate-x25519-keypair)
                      kp-third (sealed/generate-x25519-keypair)
                      sec-init (sealed/x25519-shared-secret (:private kp-init) (:public kp-resp))
                      sec-resp (sealed/x25519-shared-secret (:private kp-resp) (:public kp-init))
                      sec-third (sealed/x25519-shared-secret (:private kp-third) (:public kp-init))
                      init-keys (sealed/derive-channel-keys sec-init session-id :initiator)
                      resp-keys (sealed/derive-channel-keys sec-resp session-id :responder)
                      third-keys (sealed/derive-channel-keys sec-third session-id :responder)
                      sealed (sealed/seal-message (:tx-key init-keys) seq-num plaintext aad)
                      ct ^bytes (:ciphertext sealed)
                      tampered-ct (byte-array ct)
                      _ (aset tampered-ct 0 (byte (bit-xor 0x01 (aget tampered-ct 0))))
                      tampered-aad (byte-array (conj (vec aad) (byte 0x42)))
                      wrong-seq (inc seq-num)]
                  (and (nil? (sealed/open-message (:rx-key resp-keys) seq-num tampered-ct aad))
                       (nil? (sealed/open-message (:rx-key resp-keys) seq-num ct tampered-aad))
                       (nil? (sealed/open-message (:rx-key resp-keys) wrong-seq ct aad))
                       (nil? (sealed/open-message (:rx-key third-keys) seq-num ct aad))))))

(defspec ^{:doc "Property: Gap-tolerant replay window strictly enforces anti-replay, rejects out-of-window and stale sequence numbers"}
  prop-replay-window-invariants 50
  (prop/for-all [window-size (gen/choose 16 64)
                 advances (gen/vector (gen/choose 1 5) 5 20)]
                (let [;; Monotonic advances through increasing sequence numbers
                      monotonic-seqs (reductions + 0 advances)
                      seq-pairs (partition 2 1 monotonic-seqs)]
                  (every? (fn [[_ s-curr]]
                            (let [w-prev (sealed/init-replay-window window-size)
                                  res-first (sealed/check-and-advance-replay-window w-prev s-curr)
                                  w-next (:window res-first)
                                  ;; 1. Valid advance is accepted
                                  accepted? (:accepted? res-first)
                                  ;; 2. Replay of same seq is rejected
                                  res-dup (sealed/check-and-advance-replay-window w-next s-curr)
                                  dup-rejected? (and (false? (:accepted? res-dup))
                                                     (= :replayed-seq (:error res-dup)))
                                  ;; 3. Stale sequence older than window is rejected
                                  stale-seq (- s-curr window-size 5)
                                  res-stale (when (pos? stale-seq)
                                              (sealed/check-and-advance-replay-window w-next stale-seq))
                                  stale-rejected? (if (pos? stale-seq)
                                                    (and (false? (:accepted? res-stale))
                                                         (= :stale-seq (:error res-stale)))
                                                    true)
                                  ;; 4. Non-positive seq is rejected
                                  res-zero (sealed/check-and-advance-replay-window w-next 0)
                                  zero-rejected? (and (false? (:accepted? res-zero))
                                                      (= :invalid-seq (:error res-zero)))]
                              (and accepted? dup-rejected? stale-rejected? zero-rejected?)))
                          seq-pairs))))
