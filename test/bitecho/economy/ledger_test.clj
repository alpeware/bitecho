(ns bitecho.economy.ledger-test
  "Generative tests for the Echo Economy ledger using the UTXO model."
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

(deftest ^{:doc "Genesis ledger should have empty utxos and no claimed tickets"}
  genesis-ledger-initialization
  (let [genesis (ledger/init-ledger)]
    (is (map? genesis))
    (is (empty? (:utxos genesis)))
    (is (empty? (:claimed-tickets genesis)))))

(defspec ^{:doc "Claiming a winning ticket creates a UTXO and marks ticket as claimed."}
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
                   ;; UTXO should exist with correct amount and owner
                   (= {:amount payout-amount :owner-pubkey claimer-pubkey}
                      (get-in new-ledger [:utxos ticket-hash]))
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
                  ;; UTXOs and state should remain unchanged on the second claim
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

(defn- create-signed-tx
  "Helper to create a signed transaction."
  [inputs outputs sender-keypair]
  (let [payload-str (pr-str {:inputs inputs :outputs outputs})
        payload (crypto/sha256 (.getBytes payload-str "UTF-8"))
        signature (crypto/sign (:private sender-keypair) payload)]
    {:inputs inputs
     :outputs outputs
     :sender-pubkey (basalt/bytes->hex (:public sender-keypair))
     :signature (basalt/bytes->hex signature)}))

(defspec ^{:doc "Processing a valid transaction consumes inputs and creates outputs."}
  process-valid-transaction
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      receiver-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      receiver-pubkey (basalt/bytes->hex (:public receiver-keypair))
                      ;; Create initial ledger with some UTXOs
                      utxo1-id "utxo1"
                      utxo2-id "utxo2"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :owner-pubkey sender-pubkey}
                                              utxo2-id {:amount 5 :owner-pubkey sender-pubkey}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id utxo2-id]
                      outputs [{:amount 12 :owner-pubkey receiver-pubkey}
                               {:amount 3 :owner-pubkey sender-pubkey}]
                      tx (create-signed-tx inputs outputs sender-keypair)
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  (and
                   ;; Inputs should be consumed
                   (not (contains? (:utxos new-ledger) utxo1-id))
                   (not (contains? (:utxos new-ledger) utxo2-id))
                   ;; Correct number of outputs created
                   (= 2 (count (:utxos new-ledger)))
                   ;; Outputs are what we expect
                   (= (set outputs) (set (vals (:utxos new-ledger))))))))

(defspec ^{:doc "Processing transaction fails if signature is invalid."}
  process-invalid-signature
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :owner-pubkey sender-pubkey}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id]
                      outputs [{:amount 10 :owner-pubkey sender-pubkey}]
                      ;; Create with wrong keypair
                      wrong-keypair (crypto/generate-keypair)
                      tx (assoc (create-signed-tx inputs outputs wrong-keypair)
                                :sender-pubkey sender-pubkey) ; keep sender pubkey but bad sig
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  ;; Ledger unchanged
                  (= initial-ledger new-ledger))))

(defspec ^{:doc "Processing transaction fails if inputs contain duplicates."}
  process-duplicate-inputs
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :owner-pubkey sender-pubkey}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id utxo1-id]
                      outputs [{:amount 20 :owner-pubkey sender-pubkey}]
                      tx (create-signed-tx inputs outputs sender-keypair)
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  ;; Ledger unchanged
                  (= initial-ledger new-ledger))))

(defspec ^{:doc "Processing transaction fails if any output has non-positive amount."}
  process-negative-outputs
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :owner-pubkey sender-pubkey}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id]
                      outputs [{:amount 100 :owner-pubkey sender-pubkey}
                               {:amount -90 :owner-pubkey sender-pubkey}]
                      tx (create-signed-tx inputs outputs sender-keypair)
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  ;; Ledger unchanged
                  (= initial-ledger new-ledger))))

(defspec ^{:doc "Processing transaction fails if input doesn't exist."}
  process-missing-input
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      utxo1-id "utxo1"
                      missing-id "missing"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :owner-pubkey sender-pubkey}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id missing-id]
                      outputs [{:amount 10 :owner-pubkey sender-pubkey}]
                      tx (create-signed-tx inputs outputs sender-keypair)
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  ;; Ledger unchanged
                  (= initial-ledger new-ledger))))

(defspec ^{:doc "Processing transaction fails if input belongs to someone else."}
  process-wrong-owner
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      owner-keypair (crypto/generate-keypair)
                      owner-pubkey (basalt/bytes->hex (:public owner-keypair))
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :owner-pubkey owner-pubkey}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id]
                      outputs [{:amount 10 :owner-pubkey owner-pubkey}]
                      tx (create-signed-tx inputs outputs sender-keypair)
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  ;; Ledger unchanged
                  (= initial-ledger new-ledger))))

(defspec ^{:doc "Processing transaction fails if inputs amount < outputs amount."}
  process-insufficient-funds
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :owner-pubkey sender-pubkey}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id]
                      outputs [{:amount 11 :owner-pubkey sender-pubkey}]
                      tx (create-signed-tx inputs outputs sender-keypair)
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  ;; Ledger unchanged
                  (= initial-ledger new-ledger))))
