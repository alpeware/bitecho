(ns bitecho.routing.ingress
  "Pure logic to prioritize and admit incoming application-level messages based on
   the sender's Echo UTXO balance. Provides a 5% unstaked trickle lane."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.economy.ledger :as ledger]))

(defn admit-message?
  "Evaluates whether an incoming message from the given sender should be admitted.
   If the sender's balance is > 0, it is admitted (staked lane).
   If the balance is 0 (or no sender is provided), it is admitted with a 5% probability (trickle lane)."
  [^java.util.Random rng sender-pubkey utxos]
  (if-not sender-pubkey
    (< (.nextDouble rng) 0.05)
    (let [pubkey-hex (if (string? sender-pubkey) sender-pubkey (basalt/bytes->hex sender-pubkey))
          expected-hash (ledger/standard-puzzle-hash pubkey-hex)
          balance (reduce + (map :amount (filter #(= expected-hash (:puzzle-hash %)) (vals utxos))))]
      (if (pos? balance)
        true
        (< (.nextDouble rng) 0.05)))))
