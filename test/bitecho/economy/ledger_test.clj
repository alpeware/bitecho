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

(defn- expected-puzzle-hash
  "Helper to compute standard puzzle hash."
  [pubkey-hex]
  (basalt/bytes->hex (crypto/sha256 (.getBytes (str "(let [pub-bytes (bitecho.basalt.core/hex->bytes \"" pubkey-hex "\") "
                                                    "sig-bytes (bitecho.basalt.core/hex->bytes (:signature solution)) "
                                                    "tx-hash-bytes (bitecho.basalt.core/hex->bytes tx-hash)] "
                                                    "(bitecho.crypto/verify pub-bytes tx-hash-bytes sig-bytes))") "UTF-8"))))

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
                      ticket (lottery/generate-ticket :fee payload nonce (:private keypair) (:public keypair) 0)
                      ;; Max difficulty ensures ticket always wins
                      max-difficulty (apply str (repeat 64 "f"))
                      genesis (ledger/init-ledger)
                      claimer-pubkey (:public-key ticket)
                      payout-amount 10
                      new-ledger (ledger/claim-ticket genesis ticket max-difficulty claimer-pubkey payout-amount)
                      type-str (name (:ticket-type ticket))
                      ticket-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (str type-str (:payload-hash ticket) (:nonce ticket) (:epoch ticket) (:public-key ticket) (:signature ticket)) "UTF-8")))
                      expected-hash (expected-puzzle-hash claimer-pubkey)]
                  (and
                   ;; UTXO should exist with correct amount and puzzle-hash
                   (= {:amount payout-amount :puzzle-hash expected-hash}
                      (get-in new-ledger [:utxos ticket-hash]))
                   ;; Ticket should be marked as claimed
                   (contains? (:claimed-tickets new-ledger) ticket-hash)))))

(defspec ^{:doc "Claiming a winning ticket twice ignores the second claim."}
  claim-winning-ticket-twice
  100
  (prop/for-all [payload gen-payload
                 nonce gen-nonce]
                (let [keypair (crypto/generate-keypair)
                      ticket (lottery/generate-ticket :fee payload nonce (:private keypair) (:public keypair) 0)
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
                      ticket (lottery/generate-ticket :fee payload nonce (:private keypair) (:public keypair) 0)
                      ;; Min difficulty ensures ticket always loses
                      min-difficulty (apply str (repeat 64 "0"))
                      genesis (ledger/init-ledger)
                      claimer-pubkey (:public-key ticket)
                      payout-amount 10
                      new-ledger (ledger/claim-ticket genesis ticket min-difficulty claimer-pubkey payout-amount)]
                  ;; The ledger should be completely unchanged
                  (= genesis new-ledger))))

(defn- create-tx-with-puzzles
  "Helper to create a transaction with puzzles and solutions."
  [inputs outputs sender-pubkey-hex sender-privkey]
  (let [puzzle-str (str "(let [pub-bytes (bitecho.basalt.core/hex->bytes \"" sender-pubkey-hex "\") "
                        "sig-bytes (bitecho.basalt.core/hex->bytes (:signature solution)) "
                        "tx-hash-bytes (bitecho.basalt.core/hex->bytes tx-hash)] "
                        "(bitecho.crypto/verify pub-bytes tx-hash-bytes sig-bytes))")
        puzzles (repeat (count inputs) puzzle-str)
        ;; Create the transaction WITHOUT solutions to compute the auth hash
        tx-base {:inputs inputs
                 :outputs outputs
                 :puzzles puzzles}
        canonical-tx (into (sorted-map) tx-base)
        tx-hash-bytes (crypto/sha256 (.getBytes (pr-str canonical-tx) "UTF-8"))
        sig-bytes (crypto/sign sender-privkey tx-hash-bytes)
        sig-hex (basalt/bytes->hex sig-bytes)
        solutions (repeat (count inputs) {:signature sig-hex})]
    (assoc tx-base :solutions solutions)))

(defspec ^{:doc "Processing a valid transaction consumes inputs and creates outputs."}
  process-valid-transaction
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      receiver-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      receiver-pubkey (basalt/bytes->hex (:public receiver-keypair))
                      sender-puzzle-hash (expected-puzzle-hash sender-pubkey)
                      receiver-puzzle-hash (expected-puzzle-hash receiver-pubkey)
                      ;; Create initial ledger with some UTXOs
                      utxo1-id "utxo1"
                      utxo2-id "utxo2"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :puzzle-hash sender-puzzle-hash}
                                              utxo2-id {:amount 5 :puzzle-hash sender-puzzle-hash}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id utxo2-id]
                      outputs [{:amount 12 :puzzle-hash receiver-puzzle-hash}
                               {:amount 3 :puzzle-hash sender-puzzle-hash}]
                      tx (create-tx-with-puzzles inputs outputs sender-pubkey (:private sender-keypair))
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  (and
                   ;; Inputs should be consumed
                   (not (contains? (:utxos new-ledger) utxo1-id))
                   (not (contains? (:utxos new-ledger) utxo2-id))
                   ;; Correct number of outputs created
                   (= 2 (count (:utxos new-ledger)))
                   ;; Outputs are what we expect
                   (= (set outputs) (set (vals (:utxos new-ledger))))))))

(defspec ^{:doc "Processing transaction fails if puzzle hash does not match."}
  process-invalid-puzzle-hash
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      sender-puzzle-hash (expected-puzzle-hash sender-pubkey)
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :puzzle-hash sender-puzzle-hash}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id]
                      outputs [{:amount 10 :puzzle-hash sender-puzzle-hash}]
                      ;; Provide wrong puzzle
                      tx (assoc (create-tx-with-puzzles inputs outputs sender-pubkey (:private sender-keypair))
                                :puzzles ["(let [pub-bytes (bitecho.basalt.core/hex->bytes \"different\") sig-bytes (bitecho.basalt.core/hex->bytes (:signature solution)) tx-hash-bytes (bitecho.basalt.core/hex->bytes tx-hash)] (bitecho.crypto/verify pub-bytes tx-hash-bytes sig-bytes))"])
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  ;; Ledger unchanged
                  (= initial-ledger new-ledger))))

(defspec ^{:doc "Processing transaction fails if script evaluates to false."}
  process-script-evaluates-false
  100
  (prop/for-all [_payload gen-payload
                 _nonce gen-nonce]
                (let [sender-keypair (crypto/generate-keypair)
                      sender-pubkey (basalt/bytes->hex (:public sender-keypair))
                      sender-puzzle-hash (expected-puzzle-hash sender-pubkey)
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :puzzle-hash sender-puzzle-hash}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id]
                      outputs [{:amount 10 :puzzle-hash sender-puzzle-hash}]
                      ;; Wrong solution makes the standard puzzle script evaluate to false
                      tx (assoc (create-tx-with-puzzles inputs outputs sender-pubkey (:private sender-keypair))
                                :solutions [{:signature "wrong-sig"}])
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
                      sender-puzzle-hash (expected-puzzle-hash sender-pubkey)
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :puzzle-hash sender-puzzle-hash}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id utxo1-id]
                      outputs [{:amount 20 :puzzle-hash sender-puzzle-hash}]
                      tx (create-tx-with-puzzles inputs outputs sender-pubkey (:private sender-keypair))
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
                      sender-puzzle-hash (expected-puzzle-hash sender-pubkey)
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :puzzle-hash sender-puzzle-hash}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id]
                      outputs [{:amount 100 :puzzle-hash sender-puzzle-hash}
                               {:amount -90 :puzzle-hash sender-puzzle-hash}]
                      tx (create-tx-with-puzzles inputs outputs sender-pubkey (:private sender-keypair))
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
                      sender-puzzle-hash (expected-puzzle-hash sender-pubkey)
                      utxo1-id "utxo1"
                      missing-id "missing"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :puzzle-hash sender-puzzle-hash}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id missing-id]
                      outputs [{:amount 10 :puzzle-hash sender-puzzle-hash}]
                      ;; Since inputs array length is 2, need 2 puzzles/solutions
                      tx (create-tx-with-puzzles inputs outputs sender-pubkey (:private sender-keypair))
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
                      sender-puzzle-hash (expected-puzzle-hash sender-pubkey)
                      utxo1-id "utxo1"
                      initial-ledger {:utxos {utxo1-id {:amount 10 :puzzle-hash sender-puzzle-hash}}
                                      :claimed-tickets #{}}
                      inputs [utxo1-id]
                      outputs [{:amount 11 :puzzle-hash sender-puzzle-hash}]
                      tx (create-tx-with-puzzles inputs outputs sender-pubkey (:private sender-keypair))
                      new-ledger (ledger/process-transaction initial-ledger tx)]
                  ;; Ledger unchanged
                  (= initial-ledger new-ledger))))
