(ns bitecho.economy.treasury
  "Demand-gated minting (k = 0.5), 20/80 Streamlet-Mesh split, and Genesis Bootstrap custody.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [clojure.string :as string]))

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

(def default-bootstrap-sunset-epoch
  "Default 3-year hard sunset in 1-hour epochs (3 * 365 * 24 = 26,280)."
  26280)

(def hard-cap
  "Canonical v2.1 hard supply cap: 42,000,000,000 ECHO."
  42000000000)

(def genesis-custody-supply
  "Canonical v2.1 Genesis custody supply: 18,900,000,000 ECHO (45% pre-minted)."
  18900000000)

(def max-conditional-mint-supply
  "Canonical v2.1 maximum conditional mintable supply: 23,100,000,000 ECHO (55% conditional mint)."
  23100000000)

(def conditional-mint-cap
  "Canonical v2.1 maximum conditional mintable supply (23.1B)."
  max-conditional-mint-supply)

(defn calculate-trailing-revenue
  "Calculates average trailing burn revenue over N epochs:
     R_trailing = (quot (reduce + trailing-N-burns) N)
   When called with explicit N, dividing the sum by N naturally implements the
   zero-padding rule for initial windows (t <= N): epochs prior to genesis or
   missing epochs contribute 0 to the sum while the divisor remains the fixed window N.
   Safely returns 0 when N <= 0, trailing-burns is empty, or input is nil."
  ([trailing-burns]
   (calculate-trailing-revenue trailing-burns (count trailing-burns)))
  ([trailing-burns n]
   (if (or (nil? n) (<= n 0) (empty? trailing-burns))
     0
     (let [safe-burns (map #(max 0 (or % 0)) trailing-burns)
           total-burn (reduce + 0 safe-burns)]
       (quot total-burn (long n))))))

(defn extract-trailing-revenues
  "Extracts the trailing revenue sequence for the `n` epochs preceding `current-epoch`
   from `state`. For each epoch `ep` in the preceding window (`current-epoch - n` to `current-epoch - 1`),
   sums `(+ (get-in state [:epoch-burns ep] 0) (get-in state [:epoch-settlement-takes ep] 0))`.
   Terms with `ep < 0` (prior to genesis) or missing contribute `0` (zero-padding).
   Returns a vector of length `n`."
  ([state current-epoch]
   (extract-trailing-revenues state current-epoch (get-in state [:config :treasury-trailing-epochs] 168)))
  ([state current-epoch n]
   (let [safe-n (max 0 (or n 0))]
     (mapv (fn [j]
             (let [ep (- current-epoch j)]
               (if (neg? ep)
                 0
                 (+ (get-in state [:epoch-burns ep] 0)
                    (get-in state [:epoch-settlement-takes ep] 0)))))
           (range safe-n 0 -1)))))

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
                              share (long #?(:clj (Math/floor (/ (* (double safe-amt) w) total-weight))
                                             :cljs (js/Math.floor (/ (* (double safe-amt) w) total-weight))))]
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
   Fails closed: allocations exceeding remaining balance (or non-positive) are skipped
   without partial-filling. Accepts a single custody-ctx map."
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
           commands []
           skipped []]
      (if (empty? rem-allocs)
        {:remaining-balance rem-balance
         :seq seq-num
         :deps deps
         :commands commands
         :skipped-allocations skipped}
        (let [{:keys [receiver amount]} (first rem-allocs)
              req-amt (or amount 0)]
          (if (and (integer? req-amt) (pos? req-amt) (<= req-amt rem-balance))
            (let [next-seq (inc seq-num)
                  receiver-hex (if (string? receiver) receiver (basalt/bytes->hex receiver))
                  unsigned-tx {:sender custody-pub
                               :receiver receiver-hex
                               :amount req-amt
                               :seq next-seq
                               :deps deps}
                  signature (crypto/sign-canonical custody-priv unsigned-tx)
                  transfer (account/map->Transfer (assoc unsigned-tx :signature (vec signature)))
                  tx-hash (account/transfer-hash transfer)]
              (recur (rest rem-allocs)
                     (- rem-balance req-amt)
                     next-seq
                     [tx-hash]
                     (conj commands transfer)
                     skipped))
            (let [reason (if (and (integer? req-amt) (pos? req-amt))
                           :insufficient-custody-balance
                           :invalid-amount)]
              (recur (rest rem-allocs)
                     rem-balance
                     seq-num
                     deps
                     commands
                     (conj skipped {:receiver receiver
                                    :amount amount
                                    :reason reason})))))))))

(defn burn-unspent-bootstrap-custody
  "Burns any unspent balance in the Bootstrap custody account directly in the ledger
   at or after the bootstrap sunset epoch.
   Sets the custody account balance to 0 in :ledger without increasing :total-minted.
   Returns the updated ledger, or unchanged ledger if custody account is missing or zero."
  [ledger custody-pubkey]
  (if-let [pk (when custody-pubkey (if (string? custody-pubkey) custody-pubkey (basalt/bytes->hex custody-pubkey)))]
    (if-let [acct (get ledger pk)]
      (if (pos? (:balance acct))
        (assoc ledger pk (assoc acct :balance 0))
        ledger)
      ledger)
    ledger))

(defn- apply-custody-transfers-to-ledger
  "Applies executed custody drawdown transfers to the ledger without increasing :total-minted."
  [ledger commands]
  (reduce
   (fn [acc-ledger tx]
     (if (and (get acc-ledger (:sender tx))
              (account/validate-transfer (get acc-ledger (:sender tx)) tx))
       (let [l-with-rec (if (contains? acc-ledger (:receiver tx))
                          acc-ledger
                          (assoc acc-ledger (:receiver tx) (account/map->AccountState {:balance 0 :seq 0 :deps []})))]
         (account/apply-transfer l-with-rec tx))
       acc-ledger))
   ledger
   commands))

(defn- resolve-epoch-custody
  "Processes custody drawdown and sunset burns for the epoch."
  [treasury-ctx custody-pub effective-custody-bal sunset?]
  (let [ledger (:ledger treasury-ctx)
        start-seq (or (when (and ledger custody-pub) (get-in ledger [custody-pub :seq]))
                      (:start-seq treasury-ctx)
                      0)
        start-deps (or (when (and ledger custody-pub) (get-in ledger [custody-pub :deps]))
                       (:start-deps treasury-ctx)
                       [])
        custody-ctx (assoc treasury-ctx
                           :custody-pubkey custody-pub
                           :custody-balance effective-custody-bal
                           :allocations (if sunset? [] (:custody-allocations treasury-ctx))
                           :start-seq start-seq
                           :start-deps start-deps)
        custody-res (if (and custody-pub
                             (:custody-privkey custody-ctx)
                             (seq (:allocations custody-ctx)))
                      (process-bootstrap-custody custody-ctx)
                      {:remaining-balance effective-custody-bal
                       :seq start-seq
                       :deps start-deps
                       :commands []
                       :skipped-allocations []})
        updated-ledger (when ledger
                         (let [l (if sunset? (burn-unspent-bootstrap-custody ledger custody-pub) ledger)]
                           (apply-custody-transfers-to-ledger l (:commands custody-res))))]
    {:custody-res custody-res
     :updated-ledger (or updated-ledger ledger)}))

(defn process-treasury-epoch
  "Processes an epoch's demand-gated treasury minting, 20/80 split, and Genesis custody drawdowns.
   Caps mint by remaining conditional mint room under the 23.1B cap.
   Accounts for rounding dust explicitly (:actual-minted + :mint-dust == :epoch-mint).
   Reads custody balance from :ledger when provided, and executes any custody transfers
   or bootstrap sunset burns directly against :ledger without increasing :total-minted."
  [treasury-ctx]
  (let [trailing-burns (or (:trailing-burns treasury-ctx) [])
        n (or (:n-epochs treasury-ctx) (count trailing-burns))
        r-trailing (calculate-trailing-revenue trailing-burns n)
        k-bps (or (:k-bps treasury-ctx) default-k-bps)
        demand-gate (calculate-demand-gated-mint r-trailing k-bps)
        carry-dust (max 0 (or (:carry-dust treasury-ctx) (:mint-dust treasury-ctx) 0))
        total-minted (or (:total-minted treasury-ctx) 0)
        cap-room (max 0 (- max-conditional-mint-supply total-minted))
        m-t (min (+ demand-gate carry-dust) cap-room)
        split (split-mint m-t)
        m-streamlet (:streamlet split)
        m-mesh (:mesh split)
        streamlet-shares (distribute-shares m-streamlet (:validators treasury-ctx))
        mesh-shares (distribute-shares m-mesh (:mesh-nodes treasury-ctx))
        all-mint-shares (merge-with + streamlet-shares mesh-shares)
        streamlet-minted (reduce + 0 (vals streamlet-shares))
        mesh-minted (reduce + 0 (vals mesh-shares))
        streamlet-dust (if (seq streamlet-shares) (- m-streamlet streamlet-minted) 0)
        mesh-dust (if (seq mesh-shares) (- m-mesh mesh-minted) 0)
        unclaimed-mint (+ (if (seq streamlet-shares) 0 m-streamlet)
                          (if (seq mesh-shares) 0 m-mesh))
        actual-minted (+ streamlet-minted mesh-minted)
        mint-dust (+ streamlet-dust mesh-dust)
        c-pk-raw (:custody-pubkey treasury-ctx)
        custody-pub (when c-pk-raw (if (string? c-pk-raw) c-pk-raw (basalt/bytes->hex c-pk-raw)))
        ledger (:ledger treasury-ctx)
        custody-bal (if (and ledger custody-pub)
                      (get-in ledger [custody-pub :balance] 0)
                      (or (:custody-balance treasury-ctx) 0))
        epoch (:epoch treasury-ctx)
        sunset-epoch (:bootstrap-sunset-epoch treasury-ctx)
        sunset? (and (some? sunset-epoch) (some? epoch) (>= epoch sunset-epoch))
        effective-custody-bal (if sunset? 0 custody-bal)
        custody-state (resolve-epoch-custody treasury-ctx custody-pub effective-custody-bal sunset?)
        custody-res (:custody-res custody-state)]
    {:r-trailing r-trailing
     :epoch-mint m-t
     :m-t m-t
     :demand-gate demand-gate
     :actual-minted actual-minted
     :mint-dust mint-dust
     :unclaimed-mint unclaimed-mint
     :m-streamlet m-streamlet
     :m-mesh m-mesh
     :streamlet-shares streamlet-shares
     :mesh-shares mesh-shares
     :all-mint-shares all-mint-shares
     :seq (:seq custody-res)
     :deps (:deps custody-res)
     :custody-commands (:commands custody-res)
     :commands (:commands custody-res)
     :remaining-custody-balance (:remaining-balance custody-res)
     :skipped-allocations (or (:skipped-allocations custody-res) [])
     :ledger (:updated-ledger custody-state)}))

(def genesis-custody-shares
  "Standard 45% Genesis custody allocations (18.9B ECHO total)."
  {:bootstrap 4200000000
   :team 6300000000
   :partners 4200000000
   :ecosystem 4200000000})

(defn default-genesis-ledger
  "Builds the 45% Genesis custody ledger (18,900,000,000 ECHO total) from a map
   of custody pubkeys {:bootstrap pub1 :team pub2 :partners pub3 :ecosystem pub4}.
   Returns a map of {pubkey-hex -> AccountState} with :seq 0 and :deps []."
  [custody-pubkeys]
  (reduce-kv
   (fn [m role amount]
     (if-let [pk (get custody-pubkeys role)]
       (let [pk-hex (if (string? pk) pk (basalt/bytes->hex pk))]
         (assoc m pk-hex (account/map->AccountState {:balance amount :seq 0 :deps []})))
       m))
   {}
   genesis-custody-shares))

(defn sign-epoch-mint
  "Cryptographically signs an epoch mint context using the treasury private key.
   Supports 3-arity (epoch and allocations) and 4-arity (binding mint-dust)."
  ([treasury-priv epoch allocations]
   (let [sorted-allocs (into (sorted-map) allocations)
         priv-bytes (if (string? treasury-priv) (basalt/hex->bytes treasury-priv) treasury-priv)
         sig-bytes (crypto/sign-canonical priv-bytes [epoch sorted-allocs])]
     (basalt/bytes->hex sig-bytes)))
  ([treasury-priv epoch allocations mint-dust]
   (let [sorted-allocs (into (sorted-map) allocations)
         priv-bytes (if (string? treasury-priv) (basalt/hex->bytes treasury-priv) treasury-priv)
         sig-bytes (crypto/sign-canonical priv-bytes [epoch sorted-allocs mint-dust])]
     (basalt/bytes->hex sig-bytes))))

(defn- normalize-key-hex
  "Normalizes a public key representation (string, byte array, or seqable bytes) to a hex string."
  [k]
  (cond
    (string? k) k
    (fressian/bytes? k) (basalt/bytes->hex k)
    (and (seqable? k) (seq k)) (basalt/bytes->hex #?(:clj (byte-array (map byte k))
                                                     :cljs (js/Uint8Array. (clj->js k))))
    :else nil))

(defn- blank-key-or-sig?
  "Checks if a key or signature is nil or empty."
  [x]
  (cond
    (nil? x) true
    (string? x) (string/blank? x)
    (fressian/bytes? x) (zero? (fressian/count-bytes x))
    (seqable? x) (empty? x)
    :else false))

(defn verify-mint-signature
  "Cryptographically verifies the treasury signature on epoch mint allocations,
   optionally binding mint-dust into the signed payload.
   Supports N/N-1 rolling verification (v2 canonical Fressian with v1 pr-str fallback)."
  ([expected-pub sig epoch allocations]
   (try
     (let [pub-bytes (if (string? expected-pub) (basalt/hex->bytes expected-pub) expected-pub)
           sig-bytes (cond
                       (string? sig) (basalt/hex->bytes sig)
                       (fressian/bytes? sig) sig
                       :else #?(:clj (byte-array (map byte sig))
                                :cljs (js/Uint8Array. (clj->js sig))))
           sorted-allocs (into (sorted-map) allocations)]
       (boolean (crypto/verify-with-fallback pub-bytes [epoch sorted-allocs] sig-bytes)))
     (catch #?(:clj Exception :cljs :default) _
       false)))
  ([expected-pub sig epoch allocations mint-dust]
   (try
     (let [pub-bytes (if (string? expected-pub) (basalt/hex->bytes expected-pub) expected-pub)
           sig-bytes (cond
                       (string? sig) (basalt/hex->bytes sig)
                       (fressian/bytes? sig) sig
                       :else #?(:clj (byte-array (map byte sig))
                                :cljs (js/Uint8Array. (clj->js sig))))
           sorted-allocs (into (sorted-map) allocations)]
       (boolean (crypto/verify-with-fallback pub-bytes [epoch sorted-allocs mint-dust] sig-bytes)))
     (catch #?(:clj Exception :cljs :default) _
       false))))

(defn apply-epoch-mint
  "Applies an authorized, capped epoch demand-gated mint to state.
   Requires cryptographic verification against the authoritative treasury public key.
   Rejects in full (leaving :ledger, :total-minted, and :minted-epochs unchanged) if:
     - epoch is missing or already in :minted-epochs (double-mint rejected);
     - treasury pubkey or signature is missing, empty, mismatched, or invalid;
     - any allocation amount is not a non-negative integer;
     - mint-dust is present but negative or not an integer;
     - total requested mint exceeds epoch-gate (M_t);
     - total requested mint + dust + unclaimed exceeds epoch-gate (M_t);
     - total-minted + actual-minted exceeds max-conditional-mint-supply (23.1B).
   Increments :total-minted by the actual distributed sum (excluding rounding dust),
   credits receivers in :ledger, records epoch in :minted-epochs, and updates :mint-dust
   and :unclaimed-mint state accumulators."
  [state mint-ctx]
  (let [epoch (:epoch mint-ctx)
        minted-epochs (or (:minted-epochs state) #{})
        allocs-raw (or (:allocations mint-ctx) {})
        allocations (if (map? allocs-raw)
                      allocs-raw
                      (into {} (map (fn [item] [(:receiver item) (:amount item)]) allocs-raw)))
        state-pub (or (:treasury-pubkey state) (get-in state [:config :treasury-pubkey]))
        ctx-pub (:treasury-pubkey mint-ctx)
        sig (:signature mint-ctx)
        has-dust? (some? (:mint-dust mint-ctx))
        raw-dust (:mint-dust mint-ctx)]
    (cond
      ;; 1. Epoch must be present and not already minted
      (or (nil? epoch) (contains? minted-epochs epoch))
      state

      ;; 2. Signature and state pubkey must be non-nil and non-empty
      (or (blank-key-or-sig? state-pub) (blank-key-or-sig? sig))
      state

      ;; 3. State pubkey and mint-ctx pubkey must match if ctx-pub is present
      (and ctx-pub (not= (normalize-key-hex state-pub) (normalize-key-hex ctx-pub)))
      state

      ;; 4. Allocations must be non-negative integers
      (some (fn [[_ amt]] (or (not (integer? amt)) (neg? amt))) allocations)
      state

      ;; 4b. When mint-dust is provided, it must be a non-negative integer
      (and has-dust? (or (not (integer? raw-dust)) (neg? raw-dust)))
      state

      ;; 5. Cryptographic signature verification against allocations, binding mint-dust if present
      (not (if has-dust?
             (verify-mint-signature state-pub sig epoch allocations raw-dust)
             (verify-mint-signature state-pub sig epoch allocations)))
      state

      :else
      (let [actual-minted (reduce + 0 (vals allocations))
            epoch-gate (:epoch-gate mint-ctx)
            total-minted (or (:total-minted state) 0)
            unclaimed (if (and (integer? (:unclaimed-mint mint-ctx))
                               (not (neg? (:unclaimed-mint mint-ctx))))
                        (:unclaimed-mint mint-ctx)
                        0)
            dust (if has-dust?
                   raw-dust
                   (if epoch-gate (max 0 (- epoch-gate actual-minted unclaimed)) 0))]
        (cond
          ;; 6. Epoch demand gate check: actual-minted cannot exceed epoch-gate
          (and (some? epoch-gate) (> actual-minted epoch-gate))
          state

          ;; 6b. Total allocation + dust + unclaimed cannot exceed epoch-gate
          (and (some? epoch-gate) (> (+ actual-minted dust unclaimed) epoch-gate))
          state

          ;; 7. Hard supply cap check
          (> (+ total-minted actual-minted) max-conditional-mint-supply)
          state

          ;; Valid: credit allocations to ledger, persist mint-dust and unclaimed-mint
          :else
          (let [new-ledger (account/apply-mint (or (:ledger state) {}) allocations)]
            (-> state
                (assoc :ledger new-ledger)
                (assoc :total-minted (+ total-minted actual-minted))
                (update :minted-epochs (fnil conj #{}) epoch)
                (assoc :mint-dust dust)
                (assoc-in [:epoch-mint-dust epoch] dust)
                (update :unclaimed-mint (fnil + 0) unclaimed)
                (assoc-in [:epoch-unclaimed-mint epoch] unclaimed))))))))

(defn- parse-long-safe
  "Safely parses an integer/long from a string representation across JVM and CLJS."
  [v]
  (try
    #?(:clj (Long/parseLong (str v))
       :cljs (let [n (js/parseInt (str v) 10)]
               (if (js/isNaN n) nil n)))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(defn evaluate-treasury-sla
  "Pure function evaluating Treasury SLA conformance across cluster validator snapshots or state machine states.
   Accepts either a map of {node-id snapshot-or-state, ...} or a collection of snapshots/states.
   Options map opts supports {:k-bps 5000 :min-validators 3 :quorum-size 3}.
   Evaluates:
     :demand-gate-k-bps        (<= max-k-bps 5000, i.e. k <= 0.5)
     :demand-gate-compliant?
     :supply-cap-compliant?    (total-minted <= max-conditional-mint-supply and supply <= hard-cap)
     :redundant-infra?         (active-validators >= min-validators (default 3))
     :quorum-met?              (active-validators >= quorum-size)
     :finality-healthy?        (finalized-epoch-skew <= 2)
     :zero-failed-receipts?    (max-failed-receipts == 0)
     :mint-converged?          (when finalized-epoch-skew == 0, minted-skew == 0)
     :sla-healthy?             (conjunction of the above)."
  [snapshots-or-states & [opts]]
  (let [items (if (map? snapshots-or-states)
                (vals snapshots-or-states)
                (or snapshots-or-states []))
        item-stats
        (mapv (fn [item]
                (let [st (if (and (map? item) (contains? item :statusz))
                           (:statusz item)
                           item)
                      st-map (if (string? st)
                               (try
                                 (let [pairs (string/split (string/trim st) #"\s+")]
                                   (into {} (keep (fn [p]
                                                    (let [[k v] (string/split p #"=" 2)]
                                                      (when (and k v)
                                                        [(keyword k) (or (parse-long-safe v) v)])))
                                                  pairs)))
                                 (catch #?(:clj Exception :cljs :default) _ {}))
                               (or st {}))
                      fin-epoch (long (or (:fin-epoch item)
                                          (:finalized_epoch st-map)
                                          (:finalized-epoch st-map)
                                          (:last-executed-finalized-epoch item)
                                          (:last-executed-finalized-epoch st-map)
                                          (get-in item [:burnsz :anchor-epoch])
                                          0))
                      minted (long (or (:minted item)
                                       (:minted st-map)
                                       (:total-minted item)
                                       (:total-minted st-map)
                                       (get-in item [:treasury :ledger :minted-total])
                                       (get-in st-map [:treasury :ledger :minted-total])
                                       0))
                      supply (long (or (:supply item)
                                       (:supply st-map)
                                       (when-let [ledger (or (:ledger item) (:ledger st-map))]
                                         (reduce + 0 (map (fn [v] (if (map? v) (or (:balance v) 0) (or v 0))) (vals ledger))))
                                       0))
                      failed (long (or (:failed-rcpts item)
                                       (:failed_receipts st-map)
                                       (:failed-receipts-count item)
                                       (:failed-receipts-count st-map)
                                       (count (:failed-receipts item))
                                       0))
                      node-k (or (when-let [v (or (:k_bps st-map) (:k-bps st-map))]
                                   (parse-long-safe v))
                                 (when-let [v (:k-bps item)]
                                   (parse-long-safe v))
                                 (when-let [v (or (get-in item [:config :treasury-k-bps])
                                                  (get-in item [:config :k-bps]))]
                                   (parse-long-safe v)))]
                  {:fin-epoch fin-epoch
                   :minted minted
                   :supply supply
                   :failed failed
                   :k-bps node-k}))
              items)
        active-validators (count items)
        min-validators (long (or (:min-validators opts) 3))
        quorum-size (long (or (:quorum-size opts) (+ (quot (* 2 active-validators) 3) 1)))
        fin-epochs (mapv :fin-epoch item-stats)
        fin-epoch-skew (if (seq fin-epochs)
                         (- (apply max fin-epochs) (apply min fin-epochs))
                         0)
        minted-vals (mapv :minted item-stats)
        minted-skew (if (seq minted-vals)
                      (- (apply max minted-vals) (apply min minted-vals))
                      0)
        max-minted (if (seq minted-vals) (apply max minted-vals) 0)
        max-supply (if (seq item-stats) (apply max (map :supply item-stats)) 0)
        max-failed (if (seq item-stats) (apply max (map :failed item-stats)) 0)

        reported-k-vals (vec (keep :k-bps item-stats))
        telemetry-present? (boolean (seq reported-k-vals))
        k-bps-source (if telemetry-present? :telemetry :configured-default)
        k-bps (long (if telemetry-present?
                      (apply max reported-k-vals)
                      (or (:k-bps opts) default-k-bps)))
        demand-gate-compliant? (<= k-bps max-k-bps)
        supply-cap-compliant? (and (<= max-minted max-conditional-mint-supply)
                                   (or (zero? max-supply) (<= max-supply hard-cap)))
        redundant-infra? (>= active-validators min-validators)
        quorum-met? (>= active-validators quorum-size)
        finality-healthy? (<= fin-epoch-skew 2)
        zero-failed-receipts? (zero? max-failed)
        mint-converged? (if (zero? fin-epoch-skew) (zero? minted-skew) true)
        sla-healthy? (and demand-gate-compliant?
                          supply-cap-compliant?
                          redundant-infra?
                          quorum-met?
                          finality-healthy?
                          zero-failed-receipts?
                          mint-converged?)]
    {:demand-gate-k-bps k-bps
     :demand-gate-compliant? demand-gate-compliant?
     :k-bps-source k-bps-source
     :supply-cap-compliant? supply-cap-compliant?
     :redundant-infra? redundant-infra?
     :quorum-met? quorum-met?
     :finality-healthy? finality-healthy?
     :zero-failed-receipts? zero-failed-receipts?
     :mint-converged? mint-converged?
     :active-validators active-validators
     :finalized-epoch-skew fin-epoch-skew
     :minted-skew minted-skew
     :max-failed-receipts max-failed
     :total-minted max-minted
     :supply max-supply
     :sla-healthy? sla-healthy?}))
