(ns bitecho.stress.monte-carlo
  "Milestone D19: Sans-IO Monte Carlo Tokenomics Optimizer & Endogenous Cohort Simulator.
   Evaluates candidate policy vectors theta in Theta using:
   - Latin Hypercube Sampling (`sample-lhs-parameters`)
   - Decoupled Common Random Number streams (`crypto/fork-random`) per path and epoch (`A-CARB-D19-1`)
   - Exact integer Ornstein-Uhlenbeck + Hawkes jump-diffusion demand generation (`A-CARB-D19-2`)
   - Endogenous rational Validator/Mesh operator cohort entry/exit & fault reducer (`step-operator-cohort`)
   - 4-objective Pareto frontier (`pareto-frontier`) with [0, 1] normalized scoring (`A-CARB-D19-3`)
   - Cross-layer validation in Layer 3 (`harness/run-chaos-byzantine-e2e`) and Layer 5 experiment config generation."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.attestation :as attestation]
            [bitecho.economy.treasury :as treasury]
            [bitecho.fressian :as fressian]
            [bitecho.stress.harness :as harness]
            [bitecho.stress.tokenomics-sim :as tok-sim]))

;; =============================================================================
;; 1. Parameter Space (Theta) & Latin Hypercube Sampling (LHS)
;; =============================================================================

(def ratified-policy-theta
  "Canonical ratified Tokenomics v2.1 policy parameter vector."
  {:k-bps 5000
   :treasury-trailing-epochs 168
   :settlement-take-bps 50
   :streamlet-share-pct 20
   :min-node-stake 250000
   :max-stake-multiplier 4.0
   :min-signaling-burn 100
   :bootstrap-sunset-epoch 26280
   :bootstrap-drawdown-lambda 0.0001})

(def default-parameter-bounds
  "Sweep bounds for each dimension of the 9-parameter policy vector theta."
  {:k-bps {:min 1500 :max 5000 :type :long}
   :treasury-trailing-epochs {:min 24 :max 720 :type :long}
   :settlement-take-bps {:min 10 :max 200 :type :long}
   :streamlet-share-pct {:min 10 :max 40 :type :long}
   :min-node-stake {:min 50000 :max 1000000 :type :long}
   :max-stake-multiplier {:min 2.0 :max 8.0 :type :double}
   :min-signaling-burn {:min 10 :max 1000 :type :long}
   :bootstrap-sunset-epoch {:min 8760 :max 35040 :type :long}
   :bootstrap-drawdown-lambda {:min 0.00003 :max 0.0005 :type :double}})

(defn- deterministic-shuffle
  "Deterministically shuffles a vector `v` using `rng` (Fisher-Yates)."
  [rng v]
  (let [n (count v)]
    (loop [i (dec n)
           acc (vec v)]
      (if (<= i 0)
        acc
        (let [j (crypto/next-int rng (inc i))
              vi (nth acc i)
              vj (nth acc j)]
          (recur (dec i)
                 (-> acc (assoc i vj) (assoc j vi))))))))

(defn sample-lhs-parameters
  "Stratifies the 9-dimensional parameter space `bounds` across `num-samples` intervals
   using deterministic Latin Hypercube Sampling seeded by `seed`."
  ([num-samples]
   (sample-lhs-parameters num-samples 20261115 default-parameter-bounds))
  ([num-samples seed]
   (sample-lhs-parameters num-samples seed default-parameter-bounds))
  ([num-samples seed bounds]
   (let [k (max 1 (long num-samples))
         master-rng (crypto/make-random seed)
         dim-keys (vec (sort (keys bounds)))
         stratified-by-dim
         (into {}
               (map (fn [dim-key]
                      (let [{:keys [min max type]} (get bounds dim-key)
                            dim-rng (crypto/fork-random master-rng (str "lhs-" (name dim-key)))
                            perm (deterministic-shuffle dim-rng (vec (range k)))
                            vals-vec (mapv (fn [stratum-idx]
                                             (let [u (/ (+ (double stratum-idx) (crypto/next-double dim-rng))
                                                        (double k))
                                                   raw (+ (double min) (* u (- (double max) (double min))))]
                                               (if (= type :long)
                                                 (long (Math/round raw))
                                                 (double (/ (Math/round (* raw 100000.0)) 100000.0)))))
                                           perm)]
                        [dim-key vals-vec]))
                    dim-keys))]
     (mapv (fn [idx]
             (into {}
                   (map (fn [dim-key]
                          [dim-key (nth (get stratified-by-dim dim-key) idx)])
                        dim-keys)))
           (range k)))))

;; =============================================================================
;; 2. Decoupled Common Random Numbers & Integer Demand Generator (A-CARB-D19-1..2)
;; =============================================================================

(defn generate-epoch-demand
  "Pure integer Ornstein-Uhlenbeck + Hawkes jump-diffusion demand generator (`A-CARB-D19-1`, `A-CARB-D19-2`).
   Forks an isolated PRNG stream `(crypto/fork-random master-rng (str \"demand-\" path-id \"-\" epoch))`
   so endogenous operator state changes never alter the exogenous shock sequence.
   Returns `{:signaling-events :escrow-volume :signaling-burn :settlement-take :total-revenue :next-demand-state}`."
  [master-rng path-id epoch prev-demand-state theta]
  (let [rng (crypto/fork-random master-rng (str "demand-" path-id "-" epoch))
        prev-ou (long (or (:ou-level prev-demand-state) 500))
        prev-hawkes (long (or (:hawkes-intensity prev-demand-state) 0))
        ;; Mean-reverting Ornstein-Uhlenbeck step in integer basis units around 500
        shock (- (long (crypto/next-int rng 201)) 100)
        reversion (quot (- 500 prev-ou) 5)
        ou-level (max 50 (+ prev-ou reversion shock))
        ;; Hawkes self-exciting jump arrival (10% baseline jump probability)
        jump-roll (crypto/next-int rng 1000)
        jump? (< jump-roll (+ 100 (min 400 (quot prev-hawkes 2))))
        jump-mag (if jump? (+ 200 (long (crypto/next-int rng 800))) 0)
        hawkes-intensity (+ (quot (* prev-hawkes 7) 10) jump-mag)
        raw-events (+ ou-level (quot hawkes-intensity 4))
        ;; Price elasticity dampening for signaling burn floor (baseline = 100 ECH)
        min-burn (max 1 (long (or (:min-signaling-burn theta) 100)))
        sig-elasticity-num 1100
        sig-elasticity-den (+ 1000 min-burn)
        signaling-events (max 1 (quot (* raw-events sig-elasticity-num) sig-elasticity-den))
        signaling-burn (* signaling-events min-burn)
        ;; Escrow volume & disintermediation dampening for settlement take bps (baseline = 50 bps)
        take-bps (max 1 (long (or (:settlement-take-bps theta) 50)))
        take-elasticity-num 250
        take-elasticity-den (+ 200 take-bps)
        raw-escrow-vol (* (+ ou-level hawkes-intensity) 4000)
        escrow-volume (max 10000 (quot (* raw-escrow-vol take-elasticity-num) take-elasticity-den))
        settlement-take (max 1 (quot (* escrow-volume take-bps) 10000))
        total-revenue (+ signaling-burn settlement-take)]
    {:signaling-events signaling-events
     :escrow-volume escrow-volume
     :signaling-burn signaling-burn
     :settlement-take settlement-take
     :total-revenue total-revenue
     :next-demand-state {:ou-level ou-level
                         :hawkes-intensity hawkes-intensity}}))

;; =============================================================================
;; 3. Endogenous Operator Cohort Reducer (`step-operator-cohort`)
;; =============================================================================

(defn init-operator-cohort
  "Initializes 9 operators across 3 stake tiers (small = 1x S_min, medium = 2x S_min, whale = S_max * S_min)."
  [initial-mesh-nodes theta]
  (let [s-min (max 1 (long (or (:min-node-stake theta) 250000)))
        s-max (max 1.0 (double (or (:max-stake-multiplier theta) 4.0)))
        pks (vec (sort (keys initial-mesh-nodes)))]
    (into (sorted-map)
          (map-indexed
           (fn [idx pk]
             (let [tier (case (mod idx 3)
                          0 :small
                          1 :medium
                          :whale)
                   stake (case tier
                           :small s-min
                           :medium (* 2 s-min)
                           :whale (long (* s-max (double s-min))))
                   weight (attestation/calculate-node-weight 1.0 stake s-min s-max)]
               [pk {:pubkey pk
                    :tier tier
                    :stake stake
                    :active? true
                    :fault-strikes 0
                    :cumulative-rewards 0
                    :trailing-reward-ema 5000
                    :weight weight}]))
           pks))))

(defn step-operator-cohort
  "Pure rational operator entry/exit and Poisson fault cohort reducer (`A-CARB-D19-1`).
   Forks `(crypto/fork-random master-rng (str \"cohort-\" path-id \"-\" epoch))` so cohort transitions
   are completely decoupled from the demand stream."
  [master-rng path-id epoch cohort mesh-shares theta]
  (let [rng (crypto/fork-random master-rng (str "cohort-" path-id "-" epoch))
        s-min (max 1 (long (or (:min-node-stake theta) 250000)))
        s-max (max 1.0 (double (or (:max-stake-multiplier theta) 4.0)))
        ;; Simulated hourly server + capital lockup OpEx in ECH
        base-opex (+ 250 (quot s-min 2500))
        updated-cohort
        (into (sorted-map)
              (map (fn [[pk op]]
                     (let [reward (long (get mesh-shares pk 0))
                           new-cum (+ (long (:cumulative-rewards op 0)) reward)
                           new-ema (quot (+ (* 7 (long (:trailing-reward-ema op 0))) (* 3 reward)) 10)
                           fault-draw (crypto/next-int rng 1000)
                           new-strikes (if (< fault-draw 5)
                                         (inc (long (:fault-strikes op 0)))
                                         (long (:fault-strikes op 0)))
                           frozen? (>= new-strikes 3)
                           profitable? (>= new-ema (quot base-opex 2))
                           reenter-draw (crypto/next-int rng 100)
                           active? (cond
                                     frozen? false
                                     (:active? op) (or profitable? (>= reenter-draw 15))
                                     :else (and profitable? (< reenter-draw 40)))
                           participation (if active?
                                           (/ (+ 80.0 (double (crypto/next-int rng 21))) 100.0)
                                           0.0)
                           weight (if active?
                                    (attestation/calculate-node-weight participation (:stake op) s-min s-max)
                                    0.0)]
                       [pk (assoc op
                                  :active? active?
                                  :fault-strikes (if frozen? 0 new-strikes)
                                  :cumulative-rewards new-cum
                                  :trailing-reward-ema new-ema
                                  :weight weight)]))
                   cohort))
        active-mesh-nodes (into (sorted-map)
                                (keep (fn [[pk op]]
                                        (when (and (:active? op) (pos? (double (:weight op))))
                                          [pk (:weight op)])))
                                updated-cohort)]
    {:cohort updated-cohort
     :mesh-nodes (if (seq active-mesh-nodes)
                   active-mesh-nodes
                   ;; Ensure at least 1 fallback seed node remains routable even in extreme bear stress
                   (let [[first-pk _] (first updated-cohort)]
                     {first-pk 1.0}))
     :active-count (count active-mesh-nodes)}))

;; =============================================================================
;; 4. Trajectory Evaluation & Gini / CVaR Metrics
;; =============================================================================

(defn compute-gini-index
  "Computes the Gini coefficient in [0.0, 1.0] for a collection of non-negative reward numbers."
  [values]
  (let [xs (vec (sort (map #(max 0.0 (double %)) values)))
        n (count xs)
        total (reduce + 0.0 xs)]
    (if (or (<= n 1) (<= total 0.0))
      0.0
      (let [weighted-sum (reduce + 0.0
                                 (map-indexed (fn [idx x]
                                                (* (double (- (inc (* 2 (inc idx))) (inc n))) x))
                                              xs))]
        (min 1.0 (max 0.0 (/ weighted-sum (* (double n) total))))))))

(defn compute-cvar-5pct
  "Computes the 5th-percentile Conditional Value at Risk (average of worst 5% observations)."
  [samples]
  (if (empty? samples)
    0.0
    (let [sorted (vec (sort samples))
          k (max 1 (long (Math/ceil (* 0.05 (double (count sorted))))))]
      (/ (double (reduce + 0 (subvec sorted 0 k))) (double k)))))

(defn run-monte-carlo-trajectory
  "Runs a single seeded Monte Carlo trajectory for candidate parameter map `theta`.
   Options:
   - `:seed` (default `20261115`)
   - `:path-id` (default `0`)
   - `:epochs` (default `250`)
   - `:verify-signatures?` (default `false` for fast sweeps, `true` for cryptographic verification)"
  ([theta]
   (run-monte-carlo-trajectory theta nil))
  ([theta opts]
   (let [seed (long (or (:seed opts) 20261115))
         path-id (long (or (:path-id opts) 0))
         epochs (max 1 (long (or (:epochs opts) 250)))
         verify-sigs? (boolean (:verify-signatures? opts false))
         master-rng (crypto/make-random seed)
         {:keys [keys state]} (tok-sim/build-initial-tokenomics-state theta)
         recipient-hex (get-in keys [:recipient :hex])
         sunset-ep (long (or (:bootstrap-sunset-epoch theta) treasury/default-bootstrap-sunset-epoch))
         drawdown-lambda (double (or (:bootstrap-drawdown-lambda theta) 0.0001))
         init-cohort (init-operator-cohort (:mesh-nodes state) theta)]
     (loop [ep 1
            curr-st state
            demand-st {:ou-level 500 :hawkes-intensity 0}
            cohort init-cohort
            cum-burns 0
            cum-takes 0
            active-counts []
            demand-trace []
            cap-reached-ep nil
            conserved? true]
       (if (> ep epochs)
         (let [cvar-nodes (compute-cvar-5pct active-counts)
               rewards (mapv :cumulative-rewards (vals cohort))
               gini (compute-gini-index rewards)
               decentralization (- 1.0 gini)
               total-minted (long (:total-minted curr-st 0))
               total-burned (+ cum-burns cum-takes)
               deflation-eff (if (pos? total-minted)
                               (/ (double total-burned) (double total-minted))
                               (if (pos? total-burned) 2.0 1.0))
               ;; Longevity rewards sustained conditional mint headroom past sunset
               longevity-score (if (nil? cap-reached-ep)
                                 1.0
                                 (min 1.0 (/ (double cap-reached-ep) (double (max 1 sunset-ep)))))
               trace-digest (basalt/bytes->hex
                             (crypto/sha256 (fressian/utf8->bytes (pr-str demand-trace))))]
           {:theta theta
            :path-id path-id
            :seed seed
            :epochs epochs
            :demand-trace-digest trace-digest
            :metrics {:cvar-5pct-active-nodes cvar-nodes
                      :cap-reached-epoch cap-reached-ep
                      :cap-longevity-score longevity-score
                      :net-deflation-efficiency deflation-eff
                      :gini-index gini
                      :decentralization-score decentralization
                      :total-minted total-minted
                      :total-burned total-burned
                      :sunset-custody-burned (:sunset-custody-burned curr-st 0)
                      :supply-conserved? conserved?}})
         (let [demand (generate-epoch-demand master-rng path-id ep demand-st theta)
               sig-burn (:signaling-burn demand)
               take-amt (:settlement-take demand)
               custody-bal (long (get-in curr-st [:ledger (:custody-pubkey curr-st) :balance] 0))
               drawdown-amt (if (and (< ep sunset-ep) (zero? (mod ep 25)) (pos? custody-bal))
                              (min custody-bal (max 1 (long (* (double custody-bal) drawdown-lambda))))
                              0)
               allocs (when (pos? drawdown-amt)
                        [{:receiver recipient-hex :amount drawdown-amt}])
               step-res (tok-sim/step-tokenomics-epoch
                         curr-st ep sig-burn allocs
                         {:settlement-take-per-epoch take-amt
                          :verify-signatures? verify-sigs?})
               st-after (:state step-res)
               t-res (:treasury-res step-res)
               cohort-res (step-operator-cohort
                           master-rng path-id ep cohort (:mesh-shares t-res) theta)
               st-with-cohort (assoc st-after :mesh-nodes (:mesh-nodes cohort-res))
               ledger-sum (reduce + 0 (map :balance (vals (:ledger st-with-cohort))))
               expected-sum (- (+ treasury/genesis-custody-supply (:total-minted st-with-cohort))
                               (:sunset-custody-burned st-with-cohort))
               step-ok? (and (= ledger-sum expected-sum)
                             (<= (:total-minted st-with-cohort) treasury/max-conditional-mint-supply)
                             (<= ledger-sum treasury/hard-cap))
               newly-capped (if (and (nil? cap-reached-ep)
                                     (= treasury/max-conditional-mint-supply
                                        (+ (:total-minted st-with-cohort) (:mint-dust st-with-cohort))))
                              ep
                              cap-reached-ep)]
           (recur (inc ep)
                  st-with-cohort
                  (:next-demand-state demand)
                  (:cohort cohort-res)
                  (+ cum-burns sig-burn)
                  (+ cum-takes take-amt)
                  (conj active-counts (:active-count cohort-res))
                  (conj demand-trace [sig-burn take-amt])
                  newly-capped
                  (and conserved? step-ok?))))))))

;; =============================================================================
;; 5. Multi-Objective Pareto Frontier & Normalized Scoring (`A-CARB-D19-3`)
;; =============================================================================

(def objective-keys
  "Four competing objectives maximized on the Pareto frontier."
  [:cvar-5pct-active-nodes
   :cap-longevity-score
   :net-deflation-efficiency
   :decentralization-score])

(defn pareto-dominates?
  "Returns true iff metric map `m-a` is >= `m-b` on all 4 `objective-keys` and strictly > on at least one."
  [m-a m-b]
  (let [ge-all? (every? (fn [k]
                          (>= (double (get m-a k 0.0))
                              (double (get m-b k 0.0))))
                        objective-keys)
        gt-some? (some (fn [k]
                         (> (double (get m-a k 0.0))
                            (double (get m-b k 0.0))))
                       objective-keys)]
    (boolean (and ge-all? gt-some?))))

(defn pareto-frontier
  "Filters `candidates` (each containing `:metrics`) to the non-dominated Pareto frontier,
   normalizes each objective across the candidate set to `[0.0, 1.0]` (`A-CARB-D19-3`),
   and sorts the frontier in descending order of `:composite-score`."
  [candidates]
  (if (empty? candidates)
    []
    (let [bounds-by-obj
          (into {}
                (map (fn [k]
                       (let [vs (map #(double (get-in % [:metrics k] 0.0)) candidates)
                             mn (apply min vs)
                             mx (apply max vs)]
                         [k {:min mn :max mx :span (- mx mn)}]))
                     objective-keys))
          score-fn
          (fn [cand]
            (let [norm-scores
                  (map (fn [k]
                         (let [{:keys [min span]} (get bounds-by-obj k)
                               v (double (get-in cand [:metrics k] 0.0))]
                           (if (<= span 1.0e-12)
                             1.0
                             (/ (- v min) span))))
                       objective-keys)]
              (/ (reduce + 0.0 norm-scores) (double (count objective-keys)))))
          scored (mapv (fn [c] (assoc c :composite-score (score-fn c))) candidates)
          non-dominated
          (filterv (fn [cand]
                     (not-any? (fn [other]
                                 (pareto-dominates? (:metrics other) (:metrics cand)))
                               scored))
                   scored)]
      (vec (sort-by (fn [c] [(- (double (:composite-score c))) (str (:candidate-id c))])
                    non-dominated)))))

;; =============================================================================
;; 6. Parallel Sweep Orchestrator & Cross-Layer E2E Validation
;; =============================================================================

(defn run-monte-carlo-sweep
  "Samples `num-candidates` policy vectors via LHS (including `ratified-policy-theta` as candidate 0),
   evaluates each across `num-paths` Common Random Number paths in parallel, aggregates metrics,
   and computes the non-dominated Pareto frontier."
  ([]
   (run-monte-carlo-sweep nil))
  ([{:keys [num-candidates num-paths epochs seed]
     :or {num-candidates 8
          num-paths 3
          epochs 120
          seed 20261115}}]
   (let [lhs-samples (sample-lhs-parameters (max 1 (dec (long num-candidates))) seed)
         thetas (into [ratified-policy-theta] (take (dec (long num-candidates)) lhs-samples))
         results
         (vec
          (pmap
           (fn [[cand-idx theta]]
             (let [trajectories
                   (mapv (fn [pid]
                           (run-monte-carlo-trajectory
                            theta
                            {:seed seed
                             :path-id pid
                             :epochs epochs
                             :verify-signatures? false}))
                         (range (max 1 (long num-paths))))
                   ms (mapv :metrics trajectories)
                   avg-fn (fn [k]
                            (/ (reduce + 0.0 (map #(double (get % k 0.0)) ms))
                               (double (count ms))))]
               {:candidate-id (str "theta-" cand-idx)
                :candidate-index cand-idx
                :theta theta
                :metrics {:cvar-5pct-active-nodes (apply min (map :cvar-5pct-active-nodes ms))
                          :cap-longevity-score (avg-fn :cap-longevity-score)
                          :net-deflation-efficiency (avg-fn :net-deflation-efficiency)
                          :decentralization-score (avg-fn :decentralization-score)
                          :gini-index (avg-fn :gini-index)
                          :supply-conserved? (every? :supply-conserved? ms)}}))
           (map-indexed vector thetas)))
         frontier (pareto-frontier results)]
     {:seed seed
      :num-candidates (count results)
      :num-paths num-paths
      :epochs epochs
      :results results
      :pareto-frontier frontier
      :top-candidates (vec (take 3 frontier))})))

(defn validate-pareto-candidates-e2e!
  "Validates the top-k Pareto-optimal candidates from `sweep-res` inside Layer 3
   (`harness/run-chaos-byzantine-e2e`) and generates a Layer 5 `runner.clj` experiment
   configuration map parameterized with `theta*`."
  ([sweep-res]
   (validate-pareto-candidates-e2e! sweep-res {:top-k 1}))
  ([sweep-res {:keys [top-k] :or {top-k 1}}]
   (let [top-cands (take (max 1 (long top-k)) (:pareto-frontier sweep-res))
         validated
         (mapv (fn [cand]
                 (let [theta (:theta cand)
                       chaos-res (harness/run-chaos-byzantine-e2e (:seed sweep-res 42))
                       crypto-traj (run-monte-carlo-trajectory
                                    theta
                                    {:seed (:seed sweep-res 42)
                                     :path-id 0
                                     :epochs 16
                                     :verify-signatures? true})
                       exp-cfg {:experiment-id (str "pareto-" (:candidate-id cand))
                                :max-turns 2
                                :min-echo-balance (:min-signaling-burn theta 100)
                                :tokenomics-policy theta
                                :nodes [{:node-id :archivist-hypatia
                                         :parent-id :genesis-custody
                                         :start-balance (* 10 (:min-signaling-burn theta 100))
                                         :model-type "gemini-4-hydrogen-low"
                                         :dns-allow-list ["bitecho.org" "*.bitecho.org" "*.googleapis.com"]}]}]
                   {:candidate-id (:candidate-id cand)
                    :theta theta
                    :composite-score (:composite-score cand)
                    :chaos-healthy? (:chaos-healthy? chaos-res)
                    :crypto-trajectory-conserved? (get-in crypto-traj [:metrics :supply-conserved?])
                    :layer-5-experiment-config exp-cfg}))
               top-cands)]
     {:validated-candidates validated
      :all-valid? (every? #(and (:chaos-healthy? %) (:crypto-trajectory-conserved? %)) validated)})))
