(ns bitecho.economy.treasury
  "Demand-gated minting (k = 0.5), 20/80 Streamlet-Mesh split, and Genesis Bootstrap custody."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]))

(def default-k-bps
  "Default demand-gated minting factor in basis points (5000 bps = 50.0% = 0.5x)."
  5000)

(def max-k-bps
  "Maximum demand-gated minting factor in basis points (capped at 5000 bps = 50.0%)."
  5000)

(def streamlet-share-pct
  "Percentage of demand-gated mint allocated to Streamlet validators/proposers (20%)."
  20)

(def mesh-share-pct
  "Percentage of demand-gated mint allocated to attested mesh routing nodes (80%)."
  80)

(defn calculate-trailing-revenue
  "Calculates average trailing burn revenue over N epochs:
     R_trailing = (quot (reduce + trailing-N-burns) N)
   Safely returns 0 when N <= 0, trailing-burns is empty, or input is nil."
  ([trailing-burns]
   (calculate-trailing-revenue trailing-burns (count trailing-burns)))
  ([trailing-burns n]
   (if (or (nil? n) (<= n 0) (empty? trailing-burns))
     0
     (let [safe-burns (map #(max 0 (or % 0)) trailing-burns)
           total-burn (reduce + 0 safe-burns)]
       (quot total-burn (long n))))))

(defn calculate-demand-gated-mint
  "Calculates the demand-gated mint M_t = (quot (* R_trailing k-bps) 10000).
   k-bps defaults to default-k-bps (5000) and is capped at max-k-bps (5000)."
  ([r-trailing]
   (calculate-demand-gated-mint r-trailing default-k-bps))
  ([r-trailing k-bps]
   (let [effective-k (min max-k-bps (max 0 (or k-bps default-k-bps)))
         safe-r (max 0 (or r-trailing 0))]
     (quot (* safe-r effective-k) 10000))))

(defn split-mint
  "Splits M_t into Streamlet (20%) and Mesh (80%) shares:
     M_streamlet = (quot (* M_t 20) 100)
     M_mesh = (- M_t M_streamlet)
   Conserves the exact total mint (M_streamlet + M_mesh == M_t) with zero loss."
  [mint-amount]
  (let [safe-m (max 0 (or mint-amount 0))
        m-streamlet (quot (* safe-m streamlet-share-pct) 100)
        m-mesh (- safe-m m-streamlet)]
    {:streamlet m-streamlet
     :mesh m-mesh}))

(defn distribute-shares
  "Distributes an integer total-amount across recipients.
   Recipients can be a map of {node-pubkey -> weight} or a collection of node-pubkeys.
   Returns a map of {node-pubkey -> allocated-amount}."
  [total-amount recipients]
  (let [safe-amt (max 0 (or total-amount 0))]
    (cond
      (or (zero? safe-amt) (empty? recipients))
      {}

      (map? recipients)
      (let [total-weight (reduce + 0.0 (vals recipients))]
        (if (<= total-weight 0.0)
          {}
          (into {}
                (keep (fn [[node weight]]
                        (let [w (max 0.0 (double (or weight 0.0)))
                              share (long (Math/floor (/ (* (double safe-amt) w) total-weight)))]
                          (when (pos? share)
                            [node share])))
                      recipients))))

      (coll? recipients)
      (let [n (count recipients)]
        (if (zero? n)
          {}
          (let [share (quot safe-amt n)]
            (if (pos? share)
              (into {} (map (fn [node] [node share]) recipients))
              {}))))

      :else {})))

(defn process-bootstrap-custody
  "Draws down the pre-allocated finite Genesis Bootstrap custody account balance
   to satisfy allocation transfers without creating new money or increasing M_t.
   Accepts a single custody-ctx map."
  [custody-ctx]
  (let [custody-pub (:custody-pubkey custody-ctx)
        custody-priv (:custody-privkey custody-ctx)
        balance (or (:custody-balance custody-ctx) 0)
        allocations (or (:allocations custody-ctx) [])
        start-seq (or (:start-seq custody-ctx) 0)
        start-deps (or (:start-deps custody-ctx) [])]
    (loop [rem-allocs allocations
           rem-balance balance
           seq-num start-seq
           deps start-deps
           commands []]
      (if (empty? rem-allocs)
        {:remaining-balance rem-balance
         :seq seq-num
         :deps deps
         :commands commands}
        (let [{:keys [receiver amount]} (first rem-allocs)
              req-amt (max 0 (or amount 0))
              drawn (min rem-balance req-amt)]
          (if (pos? drawn)
            (let [next-seq (inc seq-num)
                  receiver-hex (if (string? receiver) receiver (basalt/bytes->hex receiver))
                  unsigned-tx {:sender custody-pub
                               :receiver receiver-hex
                               :amount drawn
                               :seq next-seq
                               :deps deps}
                  payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-tx)) "UTF-8")
                  signature (crypto/sign custody-priv payload-bytes)
                  transfer (account/map->Transfer (assoc unsigned-tx :signature (vec signature)))
                  safe-tx (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex signature))
                  tx-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-tx) "UTF-8")))]
              (recur (rest rem-allocs)
                     (- rem-balance drawn)
                     next-seq
                     [tx-hash]
                     (conj commands transfer)))
            (recur (rest rem-allocs)
                   rem-balance
                   seq-num
                   deps
                   commands)))))))

(defn- build-mint-transfers
  "Helper to build and sign account transfers for demand-gated mint allocations."
  [treasury-pub treasury-priv shares start-seq start-deps]
  (loop [entries (seq shares)
         seq-num start-seq
         deps start-deps
         transfers []]
    (if-let [[node amt] (first entries)]
      (let [next-seq (inc seq-num)
            node-hex (if (string? node) node (basalt/bytes->hex node))
            unsigned-tx {:sender treasury-pub
                         :receiver node-hex
                         :amount amt
                         :seq next-seq
                         :deps deps}
            payload-bytes (.getBytes (pr-str (into (sorted-map) unsigned-tx)) "UTF-8")
            sig (crypto/sign treasury-priv payload-bytes)
            transfer (account/map->Transfer (assoc unsigned-tx :signature (vec sig)))
            safe-tx (assoc (into (sorted-map) transfer) :signature (basalt/bytes->hex sig))
            tx-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (pr-str safe-tx) "UTF-8")))]
        (recur (rest entries) next-seq [tx-hash] (conj transfers transfer)))
      {:seq seq-num :deps deps :commands transfers})))

(defn process-treasury-epoch
  "Processes an epoch's demand-gated treasury minting, 20/80 split, and Genesis custody drawdowns.
   Accepts a single treasury-ctx map."
  [treasury-ctx]
  (let [trailing-burns (or (:trailing-burns treasury-ctx) [])
        n (or (:n-epochs treasury-ctx) (count trailing-burns))
        r-trailing (calculate-trailing-revenue trailing-burns n)
        k-bps (or (:k-bps treasury-ctx) default-k-bps)
        m-t (calculate-demand-gated-mint r-trailing k-bps)
        split (split-mint m-t)
        m-streamlet (:streamlet split)
        m-mesh (:mesh split)
        streamlet-shares (distribute-shares m-streamlet (:validators treasury-ctx))
        mesh-shares (distribute-shares m-mesh (:mesh-nodes treasury-ctx))
        all-mint-shares (merge-with + streamlet-shares mesh-shares)
        t-pub (:treasury-pubkey treasury-ctx)
        t-priv (:treasury-privkey treasury-ctx)
        start-seq (or (:start-seq treasury-ctx) 0)
        start-deps (or (:start-deps treasury-ctx) [])
        mint-res (if (and t-pub t-priv (seq all-mint-shares))
                   (build-mint-transfers t-pub t-priv all-mint-shares start-seq start-deps)
                   {:seq start-seq :deps start-deps :commands []})
        custody-res (if (and (:custody-pubkey treasury-ctx)
                             (:custody-privkey treasury-ctx)
                             (seq (:custody-allocations treasury-ctx)))
                      (process-bootstrap-custody (assoc treasury-ctx
                                                        :allocations (:custody-allocations treasury-ctx)
                                                        :start-seq (:seq mint-res)
                                                        :start-deps (:deps mint-res)))
                      {:remaining-balance (:custody-balance treasury-ctx)
                       :seq (:seq mint-res)
                       :deps (:deps mint-res)
                       :commands []})]
    {:r-trailing r-trailing
     :epoch-mint m-t
     :m-streamlet m-streamlet
     :m-mesh m-mesh
     :seq (:seq custody-res)
     :deps (:deps custody-res)
     :mint-commands (:commands mint-res)
     :custody-commands (:commands custody-res)
     :commands (into (:commands mint-res) (:commands custody-res))
     :remaining-custody-balance (:remaining-balance custody-res)}))
