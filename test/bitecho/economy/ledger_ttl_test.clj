(ns bitecho.economy.ledger-ttl-test
  (:require [bitecho.crypto :as crypto]
            [bitecho.economy.ledger :as ledger]
            [bitecho.lottery.core :as lottery]
            [clojure.test :refer [deftest is]]))

(deftest ^{:doc "Tests that old claimed tickets are pruned from the ledger based on TTL"} claimed-ticket-pruning-test
  (let [payload (.getBytes "hello")
        nonce 123
        keypair (crypto/generate-keypair)
        max-difficulty (apply str (repeat 64 "f"))
        ;; Generate ticket at epoch 0
        ticket (lottery/generate-ticket :fee payload nonce (:private keypair) (:public keypair) 0)
        genesis (ledger/init-ledger)
        claimer-pubkey (:public-key ticket)
        ;; Claim the ticket
        ledger-1 (ledger/claim-ticket genesis ticket max-difficulty claimer-pubkey 10 0)
        ticket-hash (first (keys (:claimed-tickets ledger-1)))]
    (is (contains? (:claimed-tickets ledger-1) ticket-hash))

    ;; Prune tickets at epoch 11 (assuming TTL is 10)
    (let [ledger-after-prune (ledger/prune-claimed-tickets ledger-1 11)]
      (is (not (contains? (:claimed-tickets ledger-after-prune) ticket-hash))))))
