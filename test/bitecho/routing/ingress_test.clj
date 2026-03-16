(ns bitecho.routing.ingress-test
  "Tests for stake-weighted ingress logic."
  (:require [bitecho.economy.ledger :as ledger]
            [bitecho.routing.ingress :as ingress]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest ^{:doc "Tests admitting messages based on stake."} admit-message-test
  (testing "admits staked senders 100% of the time"
    (let [sender-hex "deadbeef"
          expected-hash (ledger/standard-puzzle-hash sender-hex)
          utxos {"u1" {:amount 10 :puzzle-hash expected-hash}}
          rng (java.util.Random. 42)]
      (is (true? (ingress/admit-message? rng sender-hex utxos)))))

  (testing "admits unstaked senders via 5% trickle lane"
    (let [sender-hex "cafebabe"
          utxos {}
          rng (java.util.Random. 42)
          ;; generate 10,000 requests
          requests (repeatedly 10000 #(ingress/admit-message? rng sender-hex utxos))
          admitted (count (filter true? requests))]
      ;; Expected ~500 admissions.
      (is (> admitted 400))
      (is (< admitted 600)))))

(defspec ^{:doc "Generative testing for ingress trickle rate (~5%)."} trickle-rate-property 50
  (prop/for-all [seed gen/int]
                (let [rng (java.util.Random. seed)
                      sender-hex "test-pubkey"
                      utxos {}
                      n 1000
                      results (repeatedly n #(ingress/admit-message? rng sender-hex utxos))
                      admitted (count (filter true? results))
                      ;; expected 50, let's allow 20 to 80 to account for statistical variance
                      ]
                  (and (>= admitted 20)
                       (<= admitted 80)))))
