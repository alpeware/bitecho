(ns bitecho.economy.account
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defrecord AccountState [balance seq deps])

(defrecord Transfer [sender receiver amount seq deps signature])

(defn create-transfer
  "Creates and signs a transfer, ensuring byte-level consistency with validate-transfer."
  [privkey unsigned-transfer]
  (let [payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-transfer)) "UTF-8")
        signature-bytes (crypto/sign privkey payload-bytes)]
    (map->Transfer (assoc unsigned-transfer :signature (vec signature-bytes)))))

(defn transfer-hash
  "Calculates the SHA-256 hash of a transfer, ensuring consistent signature stringification."
  [transfer]
  (let [safe-transfer (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex (byte-array (map byte (:signature transfer)))))]
    (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-transfer) "UTF-8")))))

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

          unsigned-transfer (into (sorted-map) (dissoc transfer :signature))
          payload-bytes (.getBytes (pr-str unsigned-transfer) "UTF-8")
          sig-bytes (if (coll? (:signature transfer))
                      (byte-array (map byte (:signature transfer)))
                      (:signature transfer))
          valid-signature? (crypto/verify (:sender transfer) payload-bytes sig-bytes)]

      (when-not valid-seq? (println "validate-transfer failed: invalid seq." "expected:" (inc (:seq current-state)) "got:" (:seq transfer)))
      (when-not valid-deps? (println "validate-transfer failed: invalid deps." "expected:" (:deps current-state) "got:" (:deps transfer)))
      (when-not valid-balance? (println "validate-transfer failed: invalid balance." "current:" (:balance current-state) "transfer amount:" (:amount transfer)))
      (when-not valid-signature? (println "validate-transfer failed: invalid signature."))

      (and valid-seq? valid-deps? valid-balance? valid-signature?))
    (catch Exception e
      (println "validate-transfer threw exception:" e)
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
      (let [transfer-hash (transfer-hash transfer)
            new-sender-state (map->AccountState
                              {:balance (- (:balance sender-state) amount)
                               :seq (:seq transfer)
                               :deps [transfer-hash]})
            ledger-after-send (assoc ledger sender new-sender-state)
            receiver-state (get ledger-after-send receiver (map->AccountState {:balance 0 :seq 0 :deps []}))
            new-receiver-state (assoc receiver-state :balance (+ (:balance receiver-state) amount))]
        (println "✅ apply-transfer executed successfully for seq:" (:seq transfer) "hash generated:" transfer-hash)
        (assoc ledger-after-send receiver new-receiver-state))
      (do
        (println "❌ apply-transfer rejected seq:" (:seq transfer))
        ledger))))
