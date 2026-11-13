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

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec prop-splitmix64-prng-determinism 50
  (prop/for-all [seed gen/large-integer]
                (let [rng1 (crypto/make-random seed)
                      rng2 (crypto/make-random seed)
                      ints1 (vec (repeatedly 20 #(crypto/next-int rng1)))
                      ints2 (vec (repeatedly 20 #(crypto/next-int rng2)))
                      bounds1 (vec (repeatedly 20 #(crypto/next-int rng1 1000)))
                      bounds2 (vec (repeatedly 20 #(crypto/next-int rng2 1000)))
                      doubles1 (vec (repeatedly 10 #(crypto/next-double rng1)))
                      doubles2 (vec (repeatedly 10 #(crypto/next-double rng2)))]
                  (and (= ints1 ints2)
                       (= bounds1 bounds2)
                       (= doubles1 doubles2)))))

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec prop-splitmix64-snapshot-restore 50
  (prop/for-all [seed gen/large-integer]
                (let [rng1 (crypto/make-random seed)
                      _ (dotimes [_ 15] (crypto/next-int rng1))
                      snapshot (crypto/random-state rng1)
                      rng-restored (crypto/make-random snapshot)
                      orig (vec (repeatedly 25 #(crypto/next-int rng1)))
                      restored (vec (repeatedly 25 #(crypto/next-int rng-restored)))]
                  (= orig restored))))

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec prop-splitmix64-fork-isolation 50
  (prop/for-all [seed gen/large-integer]
                (let [parent (crypto/make-random seed)
                      _ (dotimes [_ 5] (crypto/next-int parent))
                      child-a (crypto/fork-random parent "branch-a")
                      child-b (crypto/fork-random parent "branch-b")
                      child-a2 (crypto/fork-random parent "branch-a")
                      seq-a (vec (repeatedly 15 #(crypto/next-int child-a)))
                      seq-b (vec (repeatedly 15 #(crypto/next-int child-b)))
                      seq-a2 (vec (repeatedly 15 #(crypto/next-int child-a2)))]
                  (and (= seq-a seq-a2)
                       (not= seq-a seq-b)))))

(deftest test-splitmix64-golden-vector
  (testing "Exact golden vector parity across platforms"
    (let [rng (crypto/make-random 42)
          expected [803958421 -1301876477 319790930 239788948 608707570]
          actual (vec (repeatedly 5 #(crypto/next-int rng)))]
      (is (= expected actual)))))
