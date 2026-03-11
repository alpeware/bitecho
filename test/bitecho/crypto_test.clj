(ns bitecho.crypto-test
  "Tests for the bitecho.crypto namespace"
  (:require [bitecho.crypto :as crypto]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.util Arrays]))

(deftest sha256-test
  (testing "SHA-256 hashing is deterministic"
    (let [input (.getBytes "bitecho" "UTF-8")
          hash1 (crypto/sha256 input)
          hash2 (crypto/sha256 input)]
      (is (Arrays/equals ^bytes hash1 ^bytes hash2))))
  (testing "SHA-256 output is 32 bytes"
    (let [input (.getBytes "bitecho" "UTF-8")]
      (is (= 32 (count (crypto/sha256 input)))))))

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec ed25519-sign-verify-spec 100
  (prop/for-all [msg-bytes gen/bytes]
                (let [keypair (crypto/generate-keypair)
                      pubkey (:public keypair)
                      privkey (:private keypair)
                      sig (crypto/sign privkey msg-bytes)]
                  (crypto/verify pubkey msg-bytes sig))))

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec ed25519-verify-fails-on-corrupted-message 100
  (prop/for-all [msg-bytes gen/bytes
                 corruption-byte (gen/choose 1 255)]
                (if (zero? (count msg-bytes))
                  true ; skip empty messages for corruption
                  (let [keypair (crypto/generate-keypair)
                        pubkey (:public keypair)
                        privkey (:private keypair)
                        sig (crypto/sign privkey msg-bytes)
                        corrupted-msg (byte-array msg-bytes)]
                    ;; Corrupt the first byte
                    (aset-byte corrupted-msg 0 (unchecked-byte (+ (aget corrupted-msg 0) corruption-byte)))
                    (not (crypto/verify pubkey corrupted-msg sig))))))

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec ed25519-verify-fails-on-corrupted-signature 100
  (prop/for-all [msg-bytes gen/bytes
                 corruption-byte (gen/choose 1 255)]
                (let [keypair (crypto/generate-keypair)
                      pubkey (:public keypair)
                      privkey (:private keypair)
                      sig (crypto/sign privkey msg-bytes)
                      corrupted-sig (byte-array sig)]
                  ;; Corrupt the first byte of signature
                  (aset-byte corrupted-sig 0 (unchecked-byte (+ (aget corrupted-sig 0) corruption-byte)))
                  (not (crypto/verify pubkey msg-bytes corrupted-sig)))))
