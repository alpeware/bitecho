(ns bitecho.economy.burn)

(def routing-fee
  "The fixed amount of ECHO micro-fee burned per transfer."
  1)

(defn deduct-routing-fee
  "Deducts the routing fee from the sender's account state in the ledger,
   effectively burning it from the total supply.
   Returns the updated ledger, or the original ledger if the sender has insufficient funds."
  [ledger transfer]
  (let [sender (:sender transfer)
        sender-state (get ledger sender)]
    (if (and sender-state (>= (:balance sender-state) routing-fee))
      (let [new-balance (- (:balance sender-state) routing-fee)
            new-sender-state (assoc sender-state :balance new-balance)]
        (assoc ledger sender new-sender-state))
      ledger)))
