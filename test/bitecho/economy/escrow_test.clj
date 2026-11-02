(ns bitecho.economy.escrow-test
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.escrow :as escrow]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import (java.nio.charset StandardCharsets)))

(deftest test-valid-deliverable-hash
  (testing "valid-deliverable-hash? validates 64-char hex strings"
    (is (escrow/valid-deliverable-hash? (basalt/bytes->hex (crypto/sha256 (.getBytes "deliverable-1" StandardCharsets/UTF_8)))))
    (is (escrow/valid-deliverable-hash? "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
    (is (not (escrow/valid-deliverable-hash? "too-short")))
    (is (not (escrow/valid-deliverable-hash? nil)))
    (is (not (escrow/valid-deliverable-hash? 12345)))
    (is (not (escrow/valid-deliverable-hash? "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefxx")))))

(deftest test-compute-escrow-id-deterministic
  (testing "compute-escrow-id produces deterministic SHA-256 hex string"
    (let [payer "0011223344"
          receiver "5566778899"
          amount 1000
          d-hash (basalt/bytes->hex (crypto/sha256 (.getBytes "proof" StandardCharsets/UTF_8)))
          c-ep 1
          e-ep 10
          nonce "n-1"
          id1 (escrow/compute-escrow-id payer receiver amount d-hash c-ep e-ep nonce)
          id2 (escrow/compute-escrow-id {:payer payer
                                         :receiver receiver
                                         :amount amount
                                         :deliverable-hash d-hash
                                         :created-epoch c-ep
                                         :expires-epoch e-ep
                                         :nonce nonce})]
      (is (= 64 (count id1)))
      (is (= id1 id2)))))

(deftest test-preimage-verification
  (testing "verify-deliverable-preimage validates correct preimages and rejects corrupted ones"
    (let [secret "verified-secret-output-preimage"
          d-hash (basalt/bytes->hex (crypto/sha256 (.getBytes secret StandardCharsets/UTF_8)))]
      (is (escrow/verify-deliverable-preimage secret d-hash))
      (is (not (escrow/verify-deliverable-preimage "wrong-secret" d-hash)))
      (is (not (escrow/verify-deliverable-preimage "" d-hash)))
      (is (not (escrow/verify-deliverable-preimage nil d-hash))))))

(deftest test-escrow-release-signature
  (testing "Payer can sign outcome release and signature verifies"
    (let [kp (crypto/generate-keypair)
          payer-pub (basalt/bytes->hex (:public kp))
          payer-priv (:private kp)
          escrow-id "escrow-123"
          d-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          sig (escrow/sign-escrow-release payer-priv escrow-id d-hash)]
      (is (string? sig))
      (is (escrow/verify-escrow-release-sig payer-pub escrow-id d-hash sig))
      ;; Corrupted signature fails
      (is (not (escrow/verify-escrow-release-sig payer-pub escrow-id "different-hash" sig)))
      (is (not (escrow/verify-escrow-release-sig payer-pub "different-escrow" d-hash sig)))
      ;; Other key fails
      (let [other-kp (crypto/generate-keypair)
            other-pub (basalt/bytes->hex (:public other-kp))]
        (is (not (escrow/verify-escrow-release-sig other-pub escrow-id d-hash sig)))))))

(deftest test-escrow-settlement-take-calculation
  (testing "Protocol take is at least 1 unit burned for positive amounts"
    ;; Large amount with default 50 bps (0.5%): 10000 -> 50
    (is (= 50 (escrow/calculate-escrow-settlement-take 10000 50)))
    ;; Medium amount: 1000 -> 5
    (is (= 5 (escrow/calculate-escrow-settlement-take 1000 50)))
    ;; Small amount: 100 -> 50 bps gives 0, but minimum 1 unit burned
    (is (= 1 (escrow/calculate-escrow-settlement-take 100 50)))
    ;; Tiny amount: 1 -> minimum 1 unit burned
    (is (= 1 (escrow/calculate-escrow-settlement-take 1 50)))
    ;; Zero amount: 0
    (is (= 0 (escrow/calculate-escrow-settlement-take 0 50)))
    ;; Negative amount: 0
    (is (= 0 (escrow/calculate-escrow-settlement-take -50 50)))))

(defspec ^{:doc "Verifies that valid escrow release signatures verify cleanly and tampered hashes fail."}
  prop-escrow-release-signature-roundtrip
  50
  (prop/for-all [secret gen/string-alphanumeric
                 amount (gen/choose 1 100000)]
                (let [kp (crypto/generate-keypair)
                      pub (basalt/bytes->hex (:public kp))
                      priv (:private kp)
                      d-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (str secret) StandardCharsets/UTF_8)))
                      escrow-id (escrow/compute-escrow-id pub "receiver" amount d-hash 1 10 "nonce")
                      sig (escrow/sign-escrow-release priv escrow-id d-hash)]
                  (and (escrow/verify-deliverable-preimage (str secret) d-hash)
                       (escrow/verify-escrow-release-sig pub escrow-id d-hash sig)
                       (not (escrow/verify-escrow-release-sig pub escrow-id (str/reverse d-hash) sig))))))
