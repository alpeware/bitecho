(ns bitecho.economy.receipt-test
  (:require [bitecho.crypto :as crypto]
            [bitecho.economy.receipt :as receipt]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest generate-receipt-test
  (testing "Generates a valid Proof of Delivery receipt"
    (let [agent-kp (crypto/generate-keypair)
          agent-pub (:public agent-kp)
          agent-priv (:private agent-kp)
          node-pub (byte-array [1 2 3])
          payload-id "msg-123"
          receipt (receipt/create-receipt agent-pub agent-priv node-pub payload-id)]
      (is (= (vec agent-pub) (:agent receipt)))
      (is (= (vec node-pub) (:node receipt)))
      (is (= payload-id (:payload-id receipt)))
      (is (some? (:signature receipt)))

      ;; Verify the signature
      (let [unsigned-receipt (dissoc receipt :signature)
            payload-bytes (.getBytes (pr-str unsigned-receipt) "UTF-8")]
        (is (crypto/verify agent-pub payload-bytes (byte-array (:signature receipt))))))))

(defspec ^{:doc "Receipts must be deterministically verifiable"}
  receipt-verification-invariant 100
  (prop/for-all [payload-id gen/string-alphanumeric]
                (let [agent-kp (crypto/generate-keypair)
                      node-kp (crypto/generate-keypair)
                      receipt (receipt/create-receipt (:public agent-kp) (:private agent-kp) (:public node-kp) payload-id)
                      unsigned-receipt (dissoc receipt :signature)
                      payload-bytes (.getBytes (pr-str unsigned-receipt) "UTF-8")]
                  (crypto/verify (:public agent-kp) payload-bytes (byte-array (:signature receipt))))))
