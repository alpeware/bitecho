(ns bitecho.economy.burn
  "Fee constants and pure burn accounting for Bitecho 42B-scale economy.")

(def min-signaling-burn
  "The minimum base fee burned per signaling/broadcast event (in base ECHO units)."
  100)

(def default-settlement-take-bps
  "Default settlement take in basis points (50 bps = 0.50%)."
  50)

(def min-settlement-take-bps
  "Minimum allowable settlement take in basis points (0 bps = 0.00%)."
  0)

(def max-settlement-take-bps
  "Maximum allowable settlement take in basis points (200 bps = 2.00%)."
  200)

(def routing-fee
  "Backward-compatible alias for min-signaling-burn."
  min-signaling-burn)

(defn- deduct-account-burn
  [account-state burn-amount]
  (when (and (map? account-state)
             (contains? account-state :balance)
             (number? burn-amount)
             (>= burn-amount min-signaling-burn))
    (let [bal (:balance account-state)]
      (when (and (number? bal) (>= bal burn-amount))
        (let [new-bal (- bal burn-amount)
              updated-acct (assoc account-state :balance new-bal)]
          {:account-state updated-acct
           :burn-amount burn-amount
           :balance new-bal})))))

(defn deduct-signaling-burn
  "Deducts signaling burn from an account state or from a sender within a ledger.
   Supports:
     (deduct-signaling-burn account-state)
     (deduct-signaling-burn account-state burn-amount)
     (deduct-signaling-burn ledger sender)
     (deduct-signaling-burn ledger sender burn-amount)
   Returns a map with :account-state, :burn-amount, :balance (and :ledger if called with ledger),
   or nil if burn < min-signaling-burn or balance < burn-amount or sender not found."
  ([target]
   (deduct-signaling-burn target min-signaling-burn))
  ([target arg]
   (if (or (number? arg) (contains? target :balance))
     (deduct-account-burn target arg)
     (deduct-signaling-burn target arg min-signaling-burn)))
  ([ledger sender burn-amount]
   (when (and (map? ledger) (some? sender))
     (when-let [sender-state (get ledger sender)]
       (when-let [res (deduct-account-burn sender-state burn-amount)]
         (assoc res :ledger (assoc ledger sender (:account-state res))))))))

(defn calculate-settlement-take
  "Calculates the integer settlement take in basis points (bps).
   Defaults to default-settlement-take-bps (50 bps).
   bps is clamped to [min-settlement-take-bps, max-settlement-take-bps] ([0, 200])."
  ([amount]
   (calculate-settlement-take amount default-settlement-take-bps))
  ([amount bps]
   (let [effective-bps (max min-settlement-take-bps
                            (min max-settlement-take-bps (or bps default-settlement-take-bps)))
         safe-amount (max 0 (or amount 0))]
     (quot (* safe-amount effective-bps) 10000))))

(defn deduct-routing-fee
  "Deducts the routing fee from the sender's account state in the ledger,
   effectively burning it from the total supply.
   Returns the updated ledger, or the original ledger if the sender has insufficient funds."
  [ledger transfer]
  (if-let [res (deduct-signaling-burn ledger (:sender transfer) routing-fee)]
    (:ledger res)
    ledger))
