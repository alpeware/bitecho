(ns bitecho.economy.ledger-test
  "Generative tests for the Echo Economy ledger."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.ledger :as ledger]
            [bitecho.lottery.core :as lottery]
            [clojure.test :refer [deftest is]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def gen-payload "Generator for payloads" gen/bytes)
(def gen-nonce "Generator for nonces" gen/large-integer)

(deftest ^{:doc "Genesis ledger should have empty balances and no claimed tickets"}
  genesis-ledger-initialization
  (let [genesis (ledger/init-ledger)]
    (is (map? genesis))
    (is (empty? (:balances genesis)))
    (is (empty? (:claimed-tickets genesis)))))

(defspec ^{:doc "Claiming a winning ticket credits the balance and marks ticket as claimed."}
  claim-winning-ticket
  100
  (prop/for-all [payload gen-payload
                 nonce gen-nonce]
                (let [keypair (crypto/generate-keypair)
                      ticket (lottery/generate-ticket payload nonce (:private keypair) (:public keypair))
          ;; Max difficulty ensures ticket always wins
                      max-difficulty (apply str (repeat 64 "f"))
                      genesis (ledger/init-ledger)
                      claimer-pubkey (:public-key ticket)
                      payout-amount 10
                      new-ledger (ledger/claim-ticket genesis ticket max-difficulty claimer-pubkey payout-amount)
                      ticket-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (str (:payload-hash ticket) (:nonce ticket) (:public-key ticket) (:signature ticket)) "UTF-8")))]
                  (and
       ;; Balance should increase by payout amount
                   (= payout-amount (get-in new-ledger [:balances claimer-pubkey]))
       ;; Ticket should be marked as claimed
                   (contains? (:claimed-tickets new-ledger) ticket-hash)))))

(defspec ^{:doc "Claiming a winning ticket twice ignores the second claim."}
  claim-winning-ticket-twice
  100
  (prop/for-all [payload gen-payload
                 nonce gen-nonce]
                (let [keypair (crypto/generate-keypair)
                      ticket (lottery/generate-ticket payload nonce (:private keypair) (:public keypair))
                      max-difficulty (apply str (repeat 64 "f"))
                      genesis (ledger/init-ledger)
                      claimer-pubkey (:public-key ticket)
                      payout-amount 10
                      ledger-once (ledger/claim-ticket genesis ticket max-difficulty claimer-pubkey payout-amount)
                      ledger-twice (ledger/claim-ticket ledger-once ticket max-difficulty claimer-pubkey payout-amount)]
      ;; Balances and state should remain unchanged on the second claim
                  (= ledger-once ledger-twice))))

(defspec ^{:doc "Claiming a losing ticket ignores the claim."}
  claim-losing-ticket
  100
  (prop/for-all [payload gen-payload
                 nonce gen-nonce]
                (let [keypair (crypto/generate-keypair)
                      ticket (lottery/generate-ticket payload nonce (:private keypair) (:public keypair))
          ;; Min difficulty ensures ticket always loses
                      min-difficulty (apply str (repeat 64 "0"))
                      genesis (ledger/init-ledger)
                      claimer-pubkey (:public-key ticket)
                      payout-amount 10
                      new-ledger (ledger/claim-ticket genesis ticket min-difficulty claimer-pubkey payout-amount)]
      ;; The ledger should be completely unchanged
                  (= genesis new-ledger))))
