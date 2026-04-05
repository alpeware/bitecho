(ns bitecho.economy.treasury-test
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.receipt :as receipt]
            [bitecho.economy.treasury :as treasury]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest test-process-finalized-blocks-empty
  (testing "Processing an empty list of blocks returns no transfers"
    (let [treasury-kp (crypto/generate-keypair)
          pubkey (:public treasury-kp)
          privkey (:private treasury-kp)
          result (treasury/process-finalized-blocks pubkey privkey 10 ["hash-prev"] [] 50)]
      (is (= 10 (:seq result)))
      (is (= ["hash-prev"] (:deps result)))
      (is (empty? (:commands result))))))

(deftest test-process-finalized-blocks-with-receipts
  (testing "Processing blocks containing PoD receipts generates valid payout transfers"
    (let [treasury-kp (crypto/generate-keypair)
          t-pubkey (:public treasury-kp)
          t-privkey (:private treasury-kp)

          agent-kp (crypto/generate-keypair)
          agent-pub (:public agent-kp)
          agent-priv (:private agent-kp)

          node-kp1 (crypto/generate-keypair)
          node-pub1 (:public node-kp1)

          node-kp2 (crypto/generate-keypair)
          node-pub2 (:public node-kp2)

          ;; Create some valid receipts
          receipt1 (receipt/create-receipt agent-pub agent-priv node-pub1 "payload-1")
          receipt2 (receipt/create-receipt agent-pub agent-priv node-pub2 "payload-2")

          ;; Create blocks with these receipts as payloads
          ;; We only care about the :payload field in treasury logic
          block1 {:epoch 1 :payload [receipt1]}
          block2 {:epoch 2 :payload [receipt2]}
          blocks [block1 block2]

          start-seq 100
          start-deps ["initial-hash"]
          payout-amount 50

          result (treasury/process-finalized-blocks t-pubkey t-privkey start-seq start-deps blocks payout-amount)

          commands (:commands result)]

      (is (= 102 (:seq result)))
      (is (= 2 (count commands)))
      (is (= 1 (count (:deps result))))

      ;; Verify first transfer
      (let [t1 (first commands)]
        (is (= t-pubkey (:sender t1)))
        (is (= (basalt/bytes->hex node-pub1) (:receiver t1)))
        (is (= 50 (:amount t1)))
        (is (= 101 (:seq t1)))
        (is (= ["initial-hash"] (:deps t1)))
        ;; verify signature
        (let [unsigned-t1 (into (sorted-map) (dissoc t1 :signature))
              payload-bytes (.getBytes (pr-str unsigned-t1) "UTF-8")]
          (is (crypto/verify t-pubkey payload-bytes (byte-array (:signature t1))))))

      ;; Verify second transfer
      (let [t1 (first commands)
            t2 (second commands)
            safe-t1 (assoc (into (sorted-map) t1) :signature (basalt/bytes->hex (byte-array (map byte (:signature t1)))))
            t1-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-t1) "UTF-8")))]
        (is (= t-pubkey (:sender t2)))
        (is (= (basalt/bytes->hex node-pub2) (:receiver t2)))
        (is (= 50 (:amount t2)))
        (is (= 102 (:seq t2)))
        (is (= [t1-hash] (:deps t2)))
        (is (= [t1-hash] (:deps result)))
        ;; verify signature
        (let [unsigned-t2 (into (sorted-map) (dissoc t2 :signature))
              payload-bytes (.getBytes (pr-str unsigned-t2) "UTF-8")]
          (is (crypto/verify t-pubkey payload-bytes (byte-array (:signature t2)))))))))

(defspec ^{:doc "Property: Generated treasury payouts are always valid Account transfers."}
  prop-treasury-payouts-valid 50
  (prop/for-all [num-receipts (gen/choose 0 10)
                 start-seq (gen/choose 1 1000)
                 payout-amount (gen/choose 1 100)]
                (let [treasury-kp (crypto/generate-keypair)
                      t-pubkey (:public treasury-kp)
                      t-privkey (:private treasury-kp)

                      agent-kp (crypto/generate-keypair)
                      agent-pub (:public agent-kp)
                      agent-priv (:private agent-kp)

                      node-kps (repeatedly num-receipts crypto/generate-keypair)
                      receipts (map-indexed (fn [i kp]
                                              (receipt/create-receipt agent-pub agent-priv (:public kp) (str "payload-" i)))
                                            node-kps)
                      ;; distribute receipts somewhat randomly into blocks
                      blocks (map (fn [rcpts] {:payload rcpts})
                                  (partition-all 3 receipts))

                      start-deps ["initial-hash"]

                      result (treasury/process-finalized-blocks t-pubkey t-privkey start-seq start-deps blocks payout-amount)

                      ;; Validate sequence increments correctly
                      expected-end-seq (+ start-seq num-receipts)]
                  (and (= expected-end-seq (:seq result))
                       (= num-receipts (count (:commands result)))
                       ;; Each generated command should be a valid account transfer if applied to a ledger
                       (let [initial-ledger {t-pubkey (account/map->AccountState {:balance 1000000 :seq start-seq :deps start-deps})}
                             final-ledger (reduce account/apply-transfer initial-ledger (:commands result))]
                         (= expected-end-seq (:seq (get final-ledger t-pubkey))))))))
