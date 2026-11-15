(ns bitecho.stress.tokenomics-sim
  "30,000-Epoch Tokenomics Horizon & 3-Year Sunset Simulator (Milestone D15).
   Fast-forwards pure treasury, burn, custody drawdown, partner unlock, and epoch-pruning
   transitions across 30,000+ 1-hour epochs (~3.42 years, crossing the 26,280-epoch
   3-year Bootstrap custody sunset) under Low, Medium, and High volume regimes.
   Verifies INV-D15-2 (bounded epoch maps), INV-D15-6 (supply conservation & 23.1B cap),
   and B-CARB-5 (:last-pruned-mint-epoch monotonic double-mint guard)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.treasury :as treasury]
            [bitecho.state-machine :as sm]))

(def ^:private deterministic-kp
  (memoize
   (fn [seed]
     (let [kp (crypto/generate-keypair seed)]
       {:public (:public kp)
        :private (:private kp)
        :hex (basalt/bytes->hex (:public kp))}))))

(defn build-initial-tokenomics-state
  "Constructs the initial 45% Genesis Custody ledger (18.9B ECHO across Bootstrap, Team,
   Partners, and Ecosystem) plus 3 Streamlet validators and 6 Mesh validators.
   Accepts an optional policy parameter map `theta` (`A-D19-2`)."
  ([]
   (build-initial-tokenomics-state nil))
  ([theta]
   (let [treasury-kp (deterministic-kp "d15-tok-treasury")
         bootstrap-kp (deterministic-kp "d15-tok-bootstrap")
         team-kp (deterministic-kp "d15-tok-team")
         partners-kp (deterministic-kp "d15-tok-partners")
         ecosystem-kp (deterministic-kp "d15-tok-ecosystem")
         recipient-kp (deterministic-kp "d15-tok-grant-recipient")
         validators (mapv #(-> (str "d15-tok-val-" %) deterministic-kp :hex) (range 3))
         mesh-nodes (into (sorted-map)
                          (map (fn [i]
                                 [(-> (str "d15-tok-mesh-" i) deterministic-kp :hex) 1.0])
                               (range 6)))
         genesis-ledger (treasury/default-genesis-ledger
                         {:bootstrap (:hex bootstrap-kp)
                          :team (:hex team-kp)
                          :partners (:hex partners-kp)
                          :ecosystem (:hex ecosystem-kp)})
         trailing-ep (long (or (:treasury-trailing-epochs theta) 168))
         sunset-ep (long (or (:bootstrap-sunset-epoch theta) treasury/default-bootstrap-sunset-epoch))
         k-bps (long (or (:k-bps theta) treasury/default-k-bps))
         streamlet-pct (long (or (:streamlet-share-pct theta) treasury/streamlet-share-pct))
         take-bps (long (or (:settlement-take-bps theta) 50))
         min-stake (long (or (:min-node-stake theta) 250000))
         max-mult (double (or (:max-stake-multiplier theta) 4.0))
         min-burn (long (or (:min-signaling-burn theta) 100))
         drawdown-lambda (double (or (:bootstrap-drawdown-lambda theta) 0.0001))]
     {:keys {:treasury treasury-kp
             :bootstrap bootstrap-kp
             :team team-kp
             :partners partners-kp
             :ecosystem ecosystem-kp
             :recipient recipient-kp}
      :state {:epoch 0
              :ledger genesis-ledger
              :escrows {}
              :total-minted 0
              :mint-dust 0
              :unclaimed-mint 0
              :sunset-custody-burned 0
              :last-pruned-mint-epoch -1
              :minted-epochs #{}
              :epoch-burns {}
              :epoch-settlement-takes {}
              :epoch-mint-dust {}
              :epoch-unclaimed-mint {}
              :validators validators
              :mesh-nodes mesh-nodes
              :treasury-pubkey (:hex treasury-kp)
              :treasury-privkey (:private treasury-kp)
              :custody-pubkey (:hex bootstrap-kp)
              :custody-privkey (:private bootstrap-kp)
              :bootstrap-sunset-epoch sunset-ep
              :policy {:k-bps k-bps
                       :treasury-trailing-epochs trailing-ep
                       :settlement-take-bps take-bps
                       :streamlet-share-pct streamlet-pct
                       :min-node-stake min-stake
                       :max-stake-multiplier max-mult
                       :min-signaling-burn min-burn
                       :bootstrap-sunset-epoch sunset-ep
                       :bootstrap-drawdown-lambda drawdown-lambda}
              :config {:treasury-trailing-epochs trailing-ep
                       :streamlet-retention-epochs 256
                       :frozen-epoch-retention-window 16
                       :rendezvous-retention-epochs 16
                       :bootstrap-sunset-epoch sunset-ep}}})))

(defn step-tokenomics-epoch
  "Steps a single epoch in the fast-forward tokenomics simulation:
   1. Records synthetic epoch burn (`burn-per-epoch`) into `:epoch-burns` and optional
      `:settlement-take-per-epoch` into `:epoch-settlement-takes`.
   2. Computes trailing `N`-epoch revenue and runs `treasury/process-treasury-epoch`.
   3. Signs (when `:verify-signatures?` is true, default) and applies epoch mint via `treasury/apply-epoch-mint`.
   4. Prunes expired treasury epoch maps via `sm/prune-epoch-state`."
  ([st burn-per-epoch]
   (step-tokenomics-epoch st (inc (long (:epoch st 0))) burn-per-epoch nil nil))
  ([st burn-per-epoch opts]
   (step-tokenomics-epoch st (long (or (:epoch opts) (inc (long (:epoch st 0))))) burn-per-epoch (:custody-allocations opts) opts))
  ([st ep burn-per-epoch custody-allocs]
   (step-tokenomics-epoch st ep burn-per-epoch custody-allocs nil))
  ([st ep burn-per-epoch custody-allocs opts]
   (let [policy (:policy st)
         t-window (long (or (:treasury-trailing-epochs opts)
                            (:treasury-trailing-epochs policy)
                            (get-in st [:config :treasury-trailing-epochs])
                            168))
         k-bps (long (or (:k-bps opts)
                         (:k-bps policy)
                         treasury/default-k-bps))
         streamlet-pct (long (or (:streamlet-share-pct opts)
                                 (:streamlet-share-pct policy)
                                 treasury/streamlet-share-pct))
         sunset-ep (long (or (:bootstrap-sunset-epoch opts)
                             (:bootstrap-sunset-epoch policy)
                             (:bootstrap-sunset-epoch st)
                             treasury/default-bootstrap-sunset-epoch))
         take-per-epoch (long (or (:settlement-take-per-epoch opts) 0))
         verify-sigs? (if (contains? opts :verify-signatures?)
                        (boolean (:verify-signatures? opts))
                        true)
         st-with-burn (-> st
                          (assoc :epoch ep
                                 :bootstrap-sunset-epoch sunset-ep)
                          (assoc-in [:config :treasury-trailing-epochs] t-window)
                          (assoc-in [:config :bootstrap-sunset-epoch] sunset-ep)
                          (assoc-in [:epoch-burns (dec ep)] (long burn-per-epoch))
                          (cond-> (pos? take-per-epoch)
                            (assoc-in [:epoch-settlement-takes (dec ep)] take-per-epoch)))
         trailing-revs (treasury/extract-trailing-revenues st-with-burn ep t-window)
         t-res (treasury/process-treasury-epoch
                {:epoch ep
                 :trailing-burns trailing-revs
                 :n-epochs t-window
                 :k-bps k-bps
                 :streamlet-share-pct streamlet-pct
                 :carry-dust (:mint-dust st-with-burn 0)
                 :total-minted (:total-minted st-with-burn 0)
                 :sunset-custody-burned (:sunset-custody-burned st-with-burn 0)
                 :validators (:validators st-with-burn)
                 :mesh-nodes (:mesh-nodes st-with-burn)
                 :ledger (:ledger st-with-burn)
                 :custody-pubkey (:custody-pubkey st-with-burn)
                 :custody-privkey (:custody-privkey st-with-burn)
                 :custody-allocations custody-allocs
                 :bootstrap-sunset-epoch sunset-ep})
         allocs (:all-mint-shares t-res)
         dust (:mint-dust t-res)
         sig (if verify-sigs?
               (treasury/sign-epoch-mint (:treasury-privkey st-with-burn) ep allocs dust)
               "fast-forward-pure")
         st-custody (assoc st-with-burn
                           :ledger (:ledger t-res)
                           :sunset-custody-burned (:sunset-custody-burned t-res))
         st-minted (treasury/apply-epoch-mint
                    st-custody
                    {:epoch ep
                     :allocations allocs
                     :mint-dust dust
                     :unclaimed-mint (:unclaimed-mint t-res)
                     :epoch-gate (:epoch-mint t-res)
                     :treasury-pubkey (:treasury-pubkey st-with-burn)
                     :signature sig
                     :skip-signature-verification? (not verify-sigs?)})
         st-pruned (sm/prune-epoch-state st-minted ep (:config st-minted))]
     {:state st-pruned
      :treasury-res t-res})))

(defn run-tokenomics-horizon-sim
  "Runs the 30,000-epoch tokenomics horizon simulation for `regime` (`:low`, `:medium`, or `:high`).
   Options:
   - `:epochs` (default `30000`, crossing `26,280` 3-year Bootstrap custody sunset)
   - `:theta` (optional policy parameter map overrides `A-D21-2`, `A-CARB-D21-3`)
   - `:scheduled-upgrades` (optional `{epoch-num theta-map}` for mid-horizon cutover `INV-D22-4`)
   - `:verify-signatures?` (default `true`)."
  ([regime]
   (run-tokenomics-horizon-sim regime {:epochs 30000}))
  ([regime {:keys [epochs theta scheduled-upgrades verify-signatures?]
            :or {epochs 30000
                 verify-signatures? true}}]
   (let [{:keys [keys state]} (build-initial-tokenomics-state theta)
         bootstrap-hex (get-in keys [:bootstrap :hex])
         partners-kp (:partners keys)
         team-kp (:team keys)
         ecosystem-kp (:ecosystem keys)
         recipient-hex (get-in keys [:recipient :hex])
         burn-per-epoch (case regime
                          :low 2000
                          :medium 50000
                          :high 2000000
                          10000)
         all-thetas (cons (or theta (:policy state)) (vals (or scheduled-upgrades {})))
         max-trailing (apply max 168 (keep :treasury-trailing-epochs all-thetas))
         expected-bound (+ (max 256 (long max-trailing)) 4)]
     (loop [ep 1
            curr-st state
            curr-theta (or theta (:policy state))
            cumulative-burns 0
            cap-reached-epoch nil
            pre-sunset-custody-bal nil
            post-sunset-custody-bal nil
            post-sunset-drawdown-cmds nil
            max-map-size 0
            conservation-ok? true]
       (if (> ep epochs)
         (let [;; Verify post-sunset Partner / Team / Ecosystem accounts remain intact and transferable
               partner-acct (get-in curr-st [:ledger (:hex partners-kp)])
               partner-tx (account/create-transfer
                           (:private partners-kp)
                           {:sender (:hex partners-kp)
                            :receiver recipient-hex
                            :amount 1000000
                            :seq (inc (:seq partner-acct))
                            :deps (:deps partner-acct)})
               ledger-after-partner (account/apply-transfer (:ledger curr-st) partner-tx)
               partner-transfer-ok? (= (- (:balance partner-acct) 1000000)
                                       (get-in ledger-after-partner [(:hex partners-kp) :balance]))
               ;; Verify replay of a pruned epoch (e.g. epoch 1) is rejected fail-closed by :last-pruned-mint-epoch
               replay-sig (treasury/sign-epoch-mint (:treasury-privkey curr-st) 1 {(first (:validators curr-st)) 100} 0)
               st-after-replay (treasury/apply-epoch-mint
                                curr-st
                                {:epoch 1
                                 :allocations {(first (:validators curr-st)) 100}
                                 :mint-dust 0
                                 :treasury-pubkey (:treasury-pubkey curr-st)
                                 :signature replay-sig})
               pruned-replay-rejected? (= (:total-minted curr-st) (:total-minted st-after-replay))
               ledger-sum (reduce + 0 (map :balance (vals (:ledger curr-st))))]
           {:regime regime
            :theta (or theta (:policy curr-st))
            :active-theta curr-theta
            :epochs-simulated epochs
            :burn-per-epoch burn-per-epoch
            :cumulative-burns cumulative-burns
            :total-minted (:total-minted curr-st)
            :mint-dust (:mint-dust curr-st)
            :sunset-custody-burned (:sunset-custody-burned curr-st)
            :pre-sunset-custody-balance pre-sunset-custody-bal
            :post-sunset-custody-balance post-sunset-custody-bal
            :post-sunset-drawdown-rejected? (empty? post-sunset-drawdown-cmds)
            :partner-transfer-ok? partner-transfer-ok?
            :team-balance-intact? (= (:team treasury/genesis-custody-shares)
                                     (get-in curr-st [:ledger (:hex team-kp) :balance]))
            :ecosystem-balance-intact? (= (:ecosystem treasury/genesis-custody-shares)
                                          (get-in curr-st [:ledger (:hex ecosystem-kp) :balance]))
            :cap-reached-epoch cap-reached-epoch
            :supply-cap-respected? (and (<= (:total-minted curr-st) treasury/max-conditional-mint-supply)
                                        (<= ledger-sum treasury/hard-cap))
            :conservation-ok? conservation-ok?
            :pruned-replay-rejected? pruned-replay-rejected?
            :max-retained-epoch-entries max-map-size
            :bounded-state-ok? (<= max-map-size expected-bound)})
         (let [upgraded-theta (if-let [upg (get scheduled-upgrades ep)]
                                (merge curr-theta upg)
                                curr-theta)
               st-for-ep (if (identical? upgraded-theta curr-theta)
                           curr-st
                           (update curr-st :policy merge upgraded-theta))
               sunset-ep (long (or (:bootstrap-sunset-epoch upgraded-theta)
                                   treasury/default-bootstrap-sunset-epoch))
               step-opts (assoc upgraded-theta :verify-signatures? verify-signatures?)
               ;; Draw down 500,000 ECHO every 500 epochs prior to sunset, and attempt drawdown at sunset+1
               allocs (when (or (and (< ep sunset-ep) (zero? (mod ep 500)))
                                (= ep (inc sunset-ep)))
                        [{:receiver recipient-hex :amount 500000}])
               pre-bal (when (= ep sunset-ep)
                         (get-in st-for-ep [:ledger bootstrap-hex :balance]))
               {:keys [state treasury-res]} (step-tokenomics-epoch st-for-ep ep burn-per-epoch allocs step-opts)
               post-bal (when (= ep sunset-ep)
                          (get-in state [:ledger bootstrap-hex :balance]))
               post-cmds (when (= ep (inc sunset-ep))
                           (:commands treasury-res))
               new-cum-burns (+ cumulative-burns burn-per-epoch)
               ledger-sum (reduce + 0 (map :balance (vals (:ledger state))))
               expected-ledger-sum (- (+ treasury/genesis-custody-supply (:total-minted state))
                                      (:sunset-custody-burned state))
               step-conserved? (and (= ledger-sum expected-ledger-sum)
                                    (<= (:total-minted state) treasury/max-conditional-mint-supply)
                                    (<= ledger-sum treasury/hard-cap))
               curr-map-sz (max (count (:epoch-burns state))
                                (count (:epoch-mint-dust state))
                                (count (:minted-epochs state)))
               newly-capped (if (and (nil? cap-reached-epoch)
                                     (= treasury/max-conditional-mint-supply
                                        (+ (:total-minted state) (:mint-dust state))))
                              ep
                              cap-reached-epoch)]
           (recur (inc ep)
                  state
                  upgraded-theta
                  new-cum-burns
                  newly-capped
                  (or pre-sunset-custody-bal pre-bal)
                  (or post-sunset-custody-bal post-bal)
                  (if (= ep (inc sunset-ep)) post-cmds post-sunset-drawdown-cmds)
                  (long (max max-map-size curr-map-sz))
                  (and conservation-ok? step-conserved?))))))))

(defn run-all-tokenomics-regimes
  "Runs Low, Medium, and High volume 30,000-epoch simulations and returns a summary map."
  ([] (run-all-tokenomics-regimes 30000))
  ([epochs]
   (let [low (run-tokenomics-horizon-sim :low {:epochs epochs})
         medium (run-tokenomics-horizon-sim :medium {:epochs epochs})
         high (run-tokenomics-horizon-sim :high {:epochs epochs})]
     {:low low
      :medium medium
      :high high
      :all-compliant? (and (:conservation-ok? low)
                           (:supply-cap-respected? low)
                           (:post-sunset-drawdown-rejected? low)
                           (:partner-transfer-ok? low)
                           (:bounded-state-ok? low)
                           (:pruned-replay-rejected? low)
                           (pos? (:sunset-custody-burned low))
                           (zero? (:post-sunset-custody-balance low))
                           (:conservation-ok? medium)
                           (:supply-cap-respected? medium)
                           (:bounded-state-ok? medium)
                           ;; Medium volume is net deflationary: minted < cumulative burns
                           (< (:total-minted medium) (:cumulative-burns medium))
                           (:conservation-ok? high)
                           (:supply-cap-respected? high)
                           (:bounded-state-ok? high)
                           ;; High volume hits exact 23.1B conditional mint cap (minted + indivisible dust) before epoch 30,000
                           (= treasury/max-conditional-mint-supply
                              (+ (:total-minted high) (:mint-dust high)))
                           (<= (:total-minted high) treasury/max-conditional-mint-supply)
                           (some? (:cap-reached-epoch high)))})))
