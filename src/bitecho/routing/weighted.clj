(ns bitecho.routing.weighted
  "Pure logic to select a next-hop routing target by weighting the current Basalt view
   according to each peer's known Echo balance.")

(defn- peer-weight
  "Calculates the weight of a peer given its pubkey and the balances map.
   Defaults to 1 if the balance is 0 or unknown."
  [peer balances]
  (max 1 (get balances (:pubkey peer) 0)))

(defn select-next-hop
  "Selects a single peer from the Basalt view for routing, weighted proportionally
   to their Echo balance. Ensures deterministic pure behavior by using the provided
   rng and sorting the view before sampling."
  [^java.util.Random rng view balances]
  (when (seq view)
    (let [;; Sort the view deterministically by hash to ensure pure function behavior
          sorted-view (sort-by :hash view)
          ;; Calculate cumulative weights
          weights (map #(peer-weight % balances) sorted-view)
          total-weight (reduce + weights)
          ;; Sample a point between 0 (inclusive) and total-weight (exclusive)
          ;; since nextDouble returns [0.0, 1.0)
          target-point (* (.nextDouble rng) total-weight)]
      (loop [remaining-peers sorted-view
             remaining-weights weights
             current-sum 0.0]
        (let [p (first remaining-peers)
              w (first remaining-weights)
              new-sum (+ current-sum w)]
          (if (or (empty? (rest remaining-peers))
                  (< target-point new-sum))
            p
            (recur (rest remaining-peers) (rest remaining-weights) new-sum)))))))
