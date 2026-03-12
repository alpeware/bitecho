(ns bitecho.economy.ledger
  "Pure functions to define the Genesis state data structure and apply valid lottery
   ticket payouts to an agent's Echo balance."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.lottery.core :as lottery]))

(defn init-ledger
  "Initializes the ledger genesis state."
  []
  {:balances {}
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
  "Applies a valid lottery ticket payout to an agent's Echo balance.
   If the ticket wins and hasn't been claimed before, updates the balance
   and marks the ticket as claimed. Otherwise, returns the ledger unchanged."
  [ledger ticket difficulty-hex claimer-pubkey payout-amount]
  (let [ticket-hash (hash-ticket ticket)]
    (if (and (lottery/winning-ticket? ticket difficulty-hex)
             (not (contains? (:claimed-tickets ledger) ticket-hash)))
      (-> ledger
          (update-in [:balances claimer-pubkey] (fnil + 0) payout-amount)
          (update :claimed-tickets conj ticket-hash))
      ledger)))
