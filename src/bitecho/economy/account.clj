(ns bitecho.economy.account
  (:require [bitecho.crypto :as crypto]))

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
