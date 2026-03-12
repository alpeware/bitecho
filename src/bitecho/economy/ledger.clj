(ns bitecho.economy.ledger
  "Pure functions to define the Genesis state data structure and apply valid lottery
   ticket payouts to an agent's Echo balance."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.lottery.core :as lottery]))

(defn init-ledger
  "Initializes the ledger genesis state."
  []
  {:utxos {}
   :claimed-tickets #{}})

(defn- hash-ticket
  "Computes a hex hash of the full ticket contents for tracking claims."
  [ticket]
  (let [hash-hex (:payload-hash ticket)
        nonce-str (str (:nonce ticket))
        pub-key-hex (:public-key ticket)
        sig-hex (:signature ticket)
        input-str (str hash-hex nonce-str pub-key-hex sig-hex)]
    (basalt/bytes->hex (crypto/sha256 (.getBytes input-str "UTF-8")))))

(defn claim-ticket
  "Applies a valid lottery ticket payout to an agent by creating a new UTXO.
   If the ticket wins and hasn't been claimed before, creates the UTXO
   and marks the ticket as claimed. Otherwise, returns the ledger unchanged."
  [ledger ticket difficulty-hex claimer-pubkey payout-amount]
  (let [ticket-hash (hash-ticket ticket)]
    (if (and (lottery/winning-ticket? ticket difficulty-hex)
             (not (contains? (:claimed-tickets ledger) ticket-hash)))
      (-> ledger
          (assoc-in [:utxos ticket-hash] {:amount payout-amount :owner-pubkey claimer-pubkey})
          (update :claimed-tickets conj ticket-hash))
      ledger)))

(defn- hash-tx-data
  "Hashes the transaction inputs and outputs to create the payload for signature validation."
  [inputs outputs]
  (let [payload-str (pr-str {:inputs inputs :outputs outputs})]
    (crypto/sha256 (.getBytes payload-str "UTF-8"))))

(defn- valid-tx-signature?
  "Verifies the transaction signature."
  [tx]
  (let [payload (hash-tx-data (:inputs tx) (:outputs tx))
        pubkey-bytes (basalt/hex->bytes (:sender-pubkey tx))
        sig-bytes (basalt/hex->bytes (:signature tx))]
    (crypto/verify pubkey-bytes payload sig-bytes)))

(defn process-transaction
  "Processes a transaction by consuming UTXOs and creating new ones.
   Validates that inputs exist, are unique, belong to the sender,
   outputs are strictly positive, have sufficient funds,
   and the transaction is properly signed.
   Returns the updated ledger if valid, or unchanged ledger if invalid."
  [ledger tx]
  (let [{:keys [inputs outputs sender-pubkey]} tx
        utxos (:utxos ledger)
        input-utxos (map #(get utxos %) inputs)]
    (if (and (every? some? input-utxos)
             (= (count inputs) (count (set inputs)))
             (every? #(= sender-pubkey (:owner-pubkey %)) input-utxos)
             (every? #(pos? (:amount %)) outputs)
             (>= (reduce + (map :amount input-utxos))
                 (reduce + (map :amount outputs)))
             (valid-tx-signature? tx))
      (let [ledger-without-inputs (reduce (fn [l input-id] (update l :utxos dissoc input-id)) ledger inputs)
            new-outputs-with-ids (map-indexed (fn [idx output]
                                                [(basalt/bytes->hex (crypto/sha256 (.getBytes (str (:signature tx) idx) "UTF-8")))
                                                 output])
                                              outputs)]
        (reduce (fn [l [out-id out]] (assoc-in l [:utxos out-id] out)) ledger-without-inputs new-outputs-with-ids))
      ledger)))
