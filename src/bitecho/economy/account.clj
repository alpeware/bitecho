(ns bitecho.economy.account
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defrecord AccountState [balance seq deps])

(defrecord Transfer [sender receiver amount seq deps signature])

(defn validate-transfer
  "Validates a transfer against a current account state.
   Returns true if valid, false otherwise.
   Validation rules:
   1. The transfer's sequence number must be exactly 1 greater than the current state's sequence number.
   2. The transfer's causal dependencies must exactly match the current state's causal dependencies.
   3. The current state's balance must be >= the transfer's amount.
   4. The transfer's signature must be valid."
  [current-state transfer]
  (try
    (let [valid-seq? (= (:seq transfer) (inc (:seq current-state)))
          valid-deps? (= (:deps transfer) (:deps current-state))
          valid-balance? (>= (:balance current-state) (:amount transfer))

          unsigned-transfer (into {} (dissoc transfer :signature))
          payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
          valid-signature? (crypto/verify (:sender transfer) payload-bytes (:signature transfer))]
      (and valid-seq? valid-deps? valid-balance? valid-signature?))
    (catch Exception _
      false)))

(defn apply-transfer
  "Applies a transfer to the given ledger (a map of pubkeys to AccountState).
   Validates the transfer against the sender's current state.
   If valid, decrements the sender's balance, increments the sender's seq,
   updates the sender's deps to the transfer hash, and increments the receiver's balance.
   If invalid, returns the ledger unmodified."
  [ledger transfer]
  (let [sender (:sender transfer)
        receiver (:receiver transfer)
        sender-state (get ledger sender)
        amount (:amount transfer)]
    (if (and sender-state (validate-transfer sender-state transfer))
      (let [safe-transfer (assoc (into {} transfer) :signature (basalt/bytes->hex (:signature transfer)))
            transfer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8")))
            new-sender-state (map->AccountState
                              {:balance (- (:balance sender-state) amount)
                               :seq (:seq transfer)
                               :deps [transfer-hash]})
            ledger-after-send (assoc ledger sender new-sender-state)
            receiver-state (get ledger-after-send receiver (map->AccountState {:balance 0 :seq 0 :deps []}))
            new-receiver-state (assoc receiver-state :balance (+ (:balance receiver-state) amount))]
        (assoc ledger-after-send receiver new-receiver-state))
      ledger)))
