(ns bitecho.d50-bip022-stage-b-contracts-test
  "BIP-022 Stage B: Contracts (Rows 4, 5, 10) — Strict TDD generative & model-based test suite.
   Covers:
   - Row 4: `bitecho.status.core` canonical `bitecho.status/v1` renderer, cross-shell key parity,
     browser projection preservation, Full Node `/statusz` contract, Rule 4 purity, and CLJS
     `safe-map-get` `sorted-map` CompareError safety.
   - Row 5: `bitecho.sync.core` generation-tagged `step-auto-sync` reducer, 15s/180s cadence,
     single-flight guard, secondary-tab quiescence, stale-generation isolation, and `F-EPOCH-1`
     loud stall detection + recovery.
   - Row 10: `bitecho.lifecycle.lock-core` generation-tagged `transition-lock` reducer for
     OS-atomic PID-file locking (acquire, live-holder rejection, bounded stale-PID reclaim,
     concurrent race handling) and Browser two-phase Web Locks + BroadcastChannel leader election
     and automatic handoff."
  (:require #?(:clj [bitecho.light-node.core :as light-core])
            #?(:clj [bitecho.shell.light-node :as jvm-shell])
            #?(:clj [clojure.java.io :as io])
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [bitecho.lifecycle.lock-core :as lock-core]
            [bitecho.status.core :as status-core]
            [bitecho.sync.core :as sync-core]
            [clojure.set :as set]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop :include-macros true]))

;; =============================================================================
;; Row 4: `bitecho.status.core` Generative Invariants
;; =============================================================================

(def ^:private required-canonical-status-keys
  #{"ok"
    "schema_version"
    "version"
    "runtime"
    "pubkey"
    "subnet_id"
    "subscribed_subnets"
    "connected"
    "transport_healthy"
    "phase"
    "generation"
    "finalized_epoch"
    "peers"
    "sessions"
    "sessions_detail"
    "petnames_count"
    "security_flags"
    "sync"
    "instance_lock"
    "delivery_telemetry"
    "diagnostics"
    "stalled"
    "stall_duration_ms"
    "finalized_epoch_stalled_count"
    "auto_sync_last_error"
    "mesh_open_peers"
    "relay_fallback_active"
    "epoch"
    "balance"
    "spendable"
    "unread_events"
    "inbox_count"
    "petnames"
    "wire_protocol"})

(def ^:private required-diagnostics-keys
  #{"phase"
    "generation"
    "last_error"
    "dropped"
    "ignored_stale"
    "auto_sync_stalled"
    "finalized_epoch_stalled"
    "auto_sync_failed"
    "duplicate_serve_instance_rejected"
    "stale_serve_lock_reclaimed"
    "browser_tab_leader_handoff"})

(def ^:private required-sync-keys
  #{"enabled"
    "interval_ms"
    "in_flight"
    "generation"
    "finalized_epoch"
    "stalled"
    "stall_duration_ms"
    "stall_threshold_ms"
    "stalled_count"
    "last_error"
    "last_advanced_ms"})

(def ^:private required-lock-keys
  #{"role"
    "lock_id"
    "holder_pid"
    "generation"
    "reclaimed_stale_lock"})

(def ^:private gen-non-empty-ascii
  (gen/fmap (fn [cs] (apply str cs))
            (gen/vector (gen/elements (vec "abcdefghijklmnopqrstuvwxyz0123456789-_")) 1 12)))

(def ^:private gen-petnames-sorted-map
  (gen/fmap (fn [pairs] (into (sorted-map) pairs))
            (gen/vector (gen/tuple gen-non-empty-ascii gen-non-empty-ascii) 0 6)))

(def ^:private gen-light-state
  (gen/let [pubkey (gen/one-of [(gen/return nil) gen-non-empty-ascii])
            subnet (gen/elements ["global" "devnet.bitecho.org" "circle" "staging"])
            subs (gen/vector (gen/elements ["global" "circle" "staging" "ops"]) 0 4)
            epoch (gen/choose 0 50000)
            balance (gen/choose 0 1000000)
            petnames gen-petnames-sorted-map
            stalled? gen/boolean
            stall-dur (gen/choose 0 600000)
            stalled-cnt (gen/choose 0 20)]
    {:pubkey pubkey
     :subnet-id subnet
     :subscribed-subnets (set subs)
     :epoch epoch
     :account {:finalized-epoch epoch
               :balance balance
               :spendable balance}
     :petnames petnames
     :inbox []
     :event-queue []
     :sessions {}
     :auto-sync-stall-tracker {:stalled? stalled?
                               :stall-duration-ms stall-dur
                               :last-finalized-epoch epoch
                               :last-advanced-ms 1000}
     :diagnostics (if (pos? stalled-cnt)
                    {:finalized-epoch-stalled stalled-cnt
                     :auto-sync-stalled stalled-cnt}
                    {})}))

(def ^:private gen-runtime-ctx
  (gen/let [rt (gen/elements [:browser :nodejs :jvm])
            now-ms (gen/choose 1000 900000000)
            phase (gen/elements [:idle :dialing :open :degraded :down :standby])
            gen-num (gen/choose 0 50)
            open-peers (gen/vector gen-non-empty-ascii 0 4)
            relay-fb? gen/boolean
            lock-role (gen/elements [:single :leader :secondary :unlocked])
            reclaimed? gen/boolean
            stalled? gen/boolean]
    {:runtime rt
     :now-ms now-ms
     :conn {:phase phase
            :generation gen-num
            :diagnostics {:phase phase
                          :generation gen-num
                          :dropped 0
                          :ignored-stale 0
                          :last-error nil}}
     :mesh-summary {:open-peers open-peers
                    :dialing-peers []
                    :closed-peers []
                    :relay-fallback-active? relay-fb?
                    :degraded? (= phase :degraded)}
     :sync-state (assoc (sync-core/init-sync-state {:generation (max 1 gen-num)})
                        :stalled? stalled?
                        :stall-duration-ms (if stalled? 190000 0)
                        :last-error (when stalled? "auto-sync-stalled"))
     :lock-state (assoc (lock-core/init-lock-state {:mode (if (= rt :browser) :web-lock :pid-file)
                                                    :lock-id "test.lock"
                                                    :self-id (if (= rt :browser) "tab-1" 4242)
                                                    :generation (max 1 gen-num)})
                        :role lock-role
                        :holder-pid (when (#{:single :leader} lock-role) 4242)
                        :reclaimed-stale-lock? reclaimed?)}))

(defspec ^{:doc "Row 4: render-status always produces 100% of required bitecho.status/v1 keys with valid types and non-negative counters across all runtimes, including populated string-keyed sorted-map :petnames."}
  status-schema-completeness-prop 60
  (prop/for-all [state gen-light-state
                 rctx gen-runtime-ctx]
                (let [rendered (status-core/render-status state rctx)
                      diag (get rendered "diagnostics")
                      sync-map (get rendered "sync")
                      lock-map (get rendered "instance_lock")
                      peers-map (get rendered "peers")]
                  (and (true? (get rendered "ok"))
                       (= status-core/status-schema-version (get rendered "schema_version"))
                       (set/subset? required-canonical-status-keys (set (keys rendered)))
                       (map? diag)
                       (set/subset? required-diagnostics-keys (set (keys diag)))
                       (map? sync-map)
                       (set/subset? required-sync-keys (set (keys sync-map)))
                       (map? lock-map)
                       (set/subset? required-lock-keys (set (keys lock-map)))
                       (map? peers-map)
                       (>= (get rendered "generation") 0)
                       (>= (get rendered "petnames_count") 0)
                       (>= (get diag "dropped") 0)
                       (>= (get diag "ignored_stale") 0)
                       (>= (get diag "auto_sync_stalled") 0)
                       (>= (get diag "finalized_epoch_stalled") 0)
                       (>= (get sync-map "interval_ms") 1000)
                       (>= (get sync-map "stall_threshold_ms") 1)
                       (boolean? (get rendered "connected"))
                       (boolean? (get rendered "transport_healthy"))))))

(defspec ^{:doc "Row 4: Canonical key set of render-status is strictly identical across :browser, :nodejs, and :jvm."}
  status-cross-shell-key-parity-prop 40
  (prop/for-all [state gen-light-state
                 rctx gen-runtime-ctx]
                (let [k-browser (set (keys (status-core/render-status state (assoc rctx :runtime :browser))))
                      k-node (set (keys (status-core/render-status state (assoc rctx :runtime :nodejs))))
                      k-jvm (set (keys (status-core/render-status state (assoc rctx :runtime :jvm))))]
                  (and (= k-browser k-node)
                       (= k-node k-jvm)))))

(defspec ^{:doc "Row 4: project-browser-status preserves every canonical snake_case key verbatim alongside camelCase aliases."}
  browser-status-projection-preserves-canonical-keys-prop 40
  (prop/for-all [state gen-light-state
                 rctx gen-runtime-ctx]
                (let [canon (status-core/render-status state (assoc rctx :runtime :browser))
                      proj (status-core/project-browser-status canon {"peerId" "peer-abc" "hardwareLocked" false})]
                  (and (every? (fn [[k v]] (= v (get proj k))) canon)
                       (= (get canon "subnet_id") (get proj "subnetId"))
                       (= (get canon "transport_healthy") (get proj "transportHealthy"))
                       (= (get canon "mesh_open_peers") (get proj "meshOpenPeers"))
                       (= (get canon "relay_fallback_active") (get proj "relayFallbackActive"))
                       (= "peer-abc" (get proj "peerId"))))))

(defspec ^{:doc "Row 4: safe-map-get on populated string-keyed sorted-map never throws CompareError on keyword probes."}
  status-safe-map-get-sorted-map-prop 50
  (prop/for-all [sm gen-petnames-sorted-map
                 probe-kw (gen/elements [:foo :bar :petnames :agent-pubkey :missing])]
                (let [res (status-core/safe-map-get sm probe-kw ::not-found)]
                  (= ::not-found res))))

(deftest status-rule4-purity-and-full-node-statusz-test
  (testing "Rule 4 purity: render-status reads liveness from runtime-ctx, not persisted :connected?"
    (let [persisted-stale {:pubkey "abcd"
                           :subnet-id "devnet.bitecho.org"
                           :connected? true
                           :connection-error "stale-disk-error"
                           :petnames (sorted-map "alice" "1111")}
          rendered (status-core/render-status
                    persisted-stale
                    {:runtime :nodejs
                     :now-ms 5000
                     :conn {:phase :down :generation 3 :diagnostics {:last-error "live-down"}}
                     :mesh-summary {:open-peers [] :relay-fallback-active? false}
                     :lock-state (assoc (lock-core/init-lock-state {:mode :pid-file :lock-id "/tmp/serve.lock" :self-id 99})
                                        :role :single :holder-pid 99)})]
      (is (false? (get rendered "connected")))
      (is (= "down" (get rendered "phase")))
      (is (= 3 (get rendered "generation")))
      (is (= "live-down" (get-in rendered ["diagnostics" "last_error"])))))

  (testing "Full Node /statusz contract preserves fleet fields while adding canonical Stage B keys"
    (let [base {:ok true
                :node_id "ns1"
                :role "leader"
                :leader "ns1"
                :term 7
                :finalized_epoch 420
                :memory {:rss_bytes 1024}
                :passthrough {:active_pairs 2}}
          merged (status-core/merge-full-node-statusz-contract
                  base
                  {:runtime :full-node
                   :lock-state (assoc (lock-core/init-lock-state {:mode :pid-file :lock-id "/var/lib/bitecho/serve.lock" :self-id 1234})
                                      :role :single :holder-pid 1234)})]
      (is (= "ns1" (:node_id merged)))
      (is (= "leader" (:role merged)))
      (is (= 420 (:finalized_epoch merged)))
      (is (= status-core/status-schema-version (:schema_version merged)))
      (is (map? (:security_flags merged)))
      (is (map? (:instance_lock merged)))
      (is (= "single" (get-in merged [:instance_lock "role"])))
      (is (map? (:diagnostics merged))))))

;; =============================================================================
;; Row 5: `bitecho.sync.core` Model-Based Command-Sequence Invariants
;; =============================================================================

(def ^:private gen-sync-command
  (gen/one-of
   [(gen/let [dt (gen/choose 1000 70000)
              vis (gen/elements [:visible :hidden])]
      {:cmd :tick :dt dt :visibility vis})
    (gen/let [dt (gen/choose 1000 70000)
              advance (gen/elements [0 0 0 1 5])]
      {:cmd :fetch-ok :dt dt :advance advance})
    (gen/let [dt (gen/choose 1000 30000)]
      {:cmd :fetch-error :dt dt :error "quorum-timeout"})
    (gen/let [dt (gen/choose 1000 30000)]
      {:cmd :timeout :dt dt})
    (gen/let [dt (gen/choose 1000 20000)
              vis (gen/elements [:visible :hidden])]
      {:cmd :visibility-change :dt dt :visibility vis})
    (gen/let [dt (gen/choose 1000 20000)]
      {:cmd :online :dt dt})
    (gen/let [role (gen/elements [:leader :secondary :single])]
      {:cmd :role-change :role role})
    (gen/let [stale-cmd (gen/elements [:tick :fetch-ok :fetch-error :timeout])]
      {:cmd :stale :stale-cmd stale-cmd})]))

(defspec ^{:doc "Row 5: Model-based command-sequence test for step-auto-sync verifying stale-gen isolation, single-flight guard, secondary-tab quiescence, and F-EPOCH-1 stall detection + recovery."}
  sync-core-model-based-command-sequence-prop 80
  (prop/for-all [cmds (gen/vector gen-sync-command 1 35)]
                (loop [remaining cmds
                       st (sync-core/init-sync-state {:generation 2
                                                      :interval-ms 15000
                                                      :hidden-interval-ms 180000
                                                      :stall-threshold-ms 180000})
                       now-ms 10000
                       cur-ep 10]
                  (if (empty? remaining)
                    true
                    (let [c (first remaining)
                          next-now (+ now-ms (long (or (:dt c) 1000)))
                          cur-gen (:generation st)]
                      (case (:cmd c)
                        :stale
                        (let [stale-gen (dec cur-gen)
                              ev (case (:stale-cmd c)
                                   :tick {:type :tick :generation stale-gen :now-ms next-now :active? true}
                                   :fetch-ok {:type :fetch-ok :generation stale-gen :now-ms next-now :finalized-epoch (+ cur-ep 100)}
                                   :fetch-error {:type :fetch-error :generation stale-gen :now-ms next-now :error "stale-err"}
                                   :timeout {:type :timeout :generation stale-gen :now-ms next-now})
                              [st' effs] (sync-core/step-auto-sync st ev)
                              diag-eff (first (filter #(= :diagnose (:effect %)) effs))]
                          (if (and (= (:in-flight? st) (:in-flight? st'))
                                   (= (:stalled? st) (:stalled? st'))
                                   (= (:last-finalized-epoch st) (:last-finalized-epoch st'))
                                   (= (inc (get-in st [:diagnostics :stale-auto-sync-callback] 0))
                                      (get-in st' [:diagnostics :stale-auto-sync-callback] 0))
                                   (= :stale-auto-sync-callback (:reason diag-eff)))
                            (recur (rest remaining) st' next-now cur-ep)
                            false))

                        :tick
                        (let [was-in-flight? (:in-flight? st)
                              was-secondary? (= :secondary (:role st))
                              [st' effs] (sync-core/step-auto-sync st {:type :tick
                                                                       :generation cur-gen
                                                                       :now-ms next-now
                                                                       :active? true
                                                                       :visibility (:visibility c)})
                              fetch-effs (filter #(= :fetch-quorum-sync (:effect %)) effs)]
                          (if (cond
                                was-secondary? (empty? fetch-effs)
                                was-in-flight? (and (empty? fetch-effs)
                                                    (some #(and (= :diagnose (:effect %))
                                                                (= :auto-sync-tick-skipped-in-flight (:reason %)))
                                                          effs))
                                :else (= 1 (count fetch-effs)))
                            (recur (rest remaining) st' next-now cur-ep)
                            false))

                        :fetch-ok
                        (let [next-ep (+ cur-ep (:advance c))
                              prev-fin (:last-finalized-epoch st)
                              prev-adv (:last-advanced-ms st)
                              [st' effs] (sync-core/step-auto-sync st {:type :fetch-ok
                                                                       :generation cur-gen
                                                                       :now-ms next-now
                                                                       :finalized-epoch next-ep
                                                                       :head-epoch (+ next-ep 2)
                                                                       :balance 500
                                                                       :spendable 500})
                              advanced? (or (nil? prev-fin) (zero? (long prev-fin)) (> next-ep (long prev-fin)))
                              frozen-ms (if advanced? 0 (max 0 (- next-now (long (or prev-adv next-now)))))
                              should-stall? (and (not advanced?) (pos? next-ep) (>= frozen-ms (:stall-threshold-ms st)))
                              stall-diag (first (filter #(and (= :diagnose (:effect %))
                                                              (= :auto-sync-stalled (:reason %)))
                                                        effs))
                              emit-ev (first (filter #(= :emit-event (:effect %)) effs))]
                          (if (and (false? (:in-flight? st'))
                                   (some? emit-ev)
                                   (if should-stall?
                                     (and (true? (:stalled? st'))
                                          (= "auto-sync-stalled" (:last-error st'))
                                          (some? stall-diag)
                                          (= :finalized-epoch-stalled (:alias-reason stall-diag))
                                          (true? (get-in emit-ev [:event "stalled"])))
                                     (and (false? (:stalled? st'))
                                          (false? (get-in emit-ev [:event "stalled"])))))
                            (recur (rest remaining) st' next-now next-ep)
                            false))

                        :fetch-error
                        (let [[st' effs] (sync-core/step-auto-sync st {:type :fetch-error
                                                                       :generation cur-gen
                                                                       :now-ms next-now
                                                                       :error (:error c)})]
                          (if (and (false? (:in-flight? st'))
                                   (some #(and (= :diagnose (:effect %)) (= :auto-sync-failed (:reason %))) effs))
                            (recur (rest remaining) st' next-now cur-ep)
                            false))

                        :timeout
                        (let [[st' effs] (sync-core/step-auto-sync st {:type :timeout
                                                                       :generation cur-gen
                                                                       :now-ms next-now})]
                          (if (and (false? (:in-flight? st'))
                                   (some #(and (= :diagnose (:effect %)) (= :auto-sync-timeout (:reason %))) effs))
                            (recur (rest remaining) st' next-now cur-ep)
                            false))

                        :visibility-change
                        (let [[st' _effs] (sync-core/step-auto-sync st {:type :visibility-change
                                                                        :generation cur-gen
                                                                        :now-ms next-now
                                                                        :visibility (:visibility c)})]
                          (if (= (sync-core/effective-interval-ms st')
                                 (if (= :hidden (:visibility c)) 180000 15000))
                            (recur (rest remaining) st' next-now cur-ep)
                            false))

                        :online
                        (let [[st' effs] (sync-core/step-auto-sync st {:type :online
                                                                       :generation cur-gen
                                                                       :now-ms next-now})]
                          (if (or (not= :secondary (:role st))
                                  (empty? (filter #(= :fetch-quorum-sync (:effect %)) effs)))
                            (recur (rest remaining) st' next-now cur-ep)
                            false))

                        :role-change
                        (let [was-sec? (= :secondary (:role st))
                              [st' effs] (sync-core/step-auto-sync st {:type :role-change
                                                                       :generation cur-gen
                                                                       :role (:role c)})]
                          (if (and (= (:role c) (:role st'))
                                   (if (and was-sec? (#{:leader :single} (:role c)))
                                     (and (> (:generation st') cur-gen)
                                          (some #(= :fetch-quorum-sync (:effect %)) effs))
                                     true))
                            (recur (rest remaining) st' next-now cur-ep)
                            false))))))))

;; =============================================================================
;; Row 10: `bitecho.lifecycle.lock-core` Model-Based Command-Sequence Invariants
;; =============================================================================

(def ^:private gen-pid-lock-scenario
  (gen/let [self-pid (gen/choose 1000 50000)
            other-pid (gen/choose 50001 99999)
            outcome (gen/elements [:create-ok
                                   :live-holder
                                   :dead-reclaim-ok
                                   :race-then-ok
                                   :race-exhausted])]
    {:self-pid self-pid
     :other-pid other-pid
     :outcome outcome}))

(defspec ^{:doc "Row 10: PID-file lock model verifies mutual exclusion, canonical :duplicate-instance rejection on live holder, stale-PID reclaim with counted :diagnose, bounded retries, and stale-generation isolation."}
  pid-file-lock-lifecycle-prop 80
  (prop/for-all [{:keys [self-pid other-pid outcome]} gen-pid-lock-scenario]
                (let [st0 (lock-core/init-lock-state {:mode :pid-file
                                                      :lock-id "/tmp/test-state/serve.lock"
                                                      :self-id self-pid
                                                      :token "tok-abcd1234"
                                                      :runtime "nodejs"
                                                      :generation 2})
          ;; Verify stale generation callback is ignored without mutating state
                      [st-stale stale-effs] (lock-core/transition-lock st0 {:type :create-exclusive-ok :generation 1 :now-ms 100})
                      stale-ok? (and (= :unlocked (:role st-stale))
                                     (= 1 (get-in st-stale [:diagnostics :stale-lock-callback]))
                                     (some #(and (= :diagnose (:effect %)) (= :stale-lock-callback (:reason %))) stale-effs))
                      [st1 eff1] (lock-core/transition-lock st-stale {:type :acquire-requested :now-ms 200})
                      gen1 (:generation st1)
                      create-req? (some #(= :fs-create-exclusive (:effect %)) eff1)]
                  (and stale-ok?
                       create-req?
                       (case outcome
                         :create-ok
                         (let [[st2 eff2] (lock-core/transition-lock st1 {:type :create-exclusive-ok :generation gen1 :now-ms 210})
                               [st3 eff3] (lock-core/transition-lock st2 {:type :release-requested})]
                           (and (= :single (:role st2))
                                (some #(= :activate-leader (:effect %)) eff2)
                                (= :unlocked (:role st3))
                                (> (:generation st3) gen1)
                                (some #(and (= :fs-release-lock (:effect %))
                                            (= self-pid (:expected-pid %))
                                            (= "tok-abcd1234" (:expected-token %)))
                                      eff3)))

                         :live-holder
                         (let [[st2 eff2] (lock-core/transition-lock st1 {:type :create-exclusive-exists
                                                                          :generation gen1
                                                                          :existing-holder {:pid other-pid :token "other" :timestamp-ms 50}
                                                                          :holder-alive? true
                                                                          :now-ms 210})
                               rej (first (filter #(= :reject-duplicate (:effect %)) eff2))]
                           (and (= :rejected (:role st2))
                                (not (some #(= :activate-leader (:effect %)) eff2))
                                (= :duplicate-instance (get-in rej [:error :error]))
                                (= 1 (get-in st2 [:diagnostics :duplicate-serve-instance-rejected]))
                                (some #(and (= :diagnose (:effect %))
                                            (= :duplicate-serve-instance-rejected (:reason %)))
                                      eff2)))

                         :dead-reclaim-ok
                         (let [[st2 eff2] (lock-core/transition-lock st1 {:type :create-exclusive-exists
                                                                          :generation gen1
                                                                          :existing-holder {:pid other-pid :token "dead" :timestamp-ms 50}
                                                                          :holder-alive? false
                                                                          :now-ms 210})
                               reclaim-eff? (some #(= :fs-reclaim-stale (:effect %)) eff2)
                               [st3 eff3] (lock-core/transition-lock st2 {:type :stale-reclaim-ok
                                                                          :generation gen1
                                                                          :stale-pid other-pid
                                                                          :now-ms 220})]
                           (and reclaim-eff?
                                (= :single (:role st3))
                                (true? (:reclaimed-stale-lock? st3))
                                (= 1 (get-in st3 [:diagnostics :stale-serve-lock-reclaimed]))
                                (some #(= :activate-leader (:effect %)) eff3)
                                (some #(and (= :diagnose (:effect %)) (= :stale-serve-lock-reclaimed (:reason %))) eff3)))

                         :race-then-ok
                         (let [[st2 _] (lock-core/transition-lock st1 {:type :create-exclusive-exists
                                                                       :generation gen1
                                                                       :existing-holder {:pid other-pid}
                                                                       :holder-alive? false
                                                                       :now-ms 210})
                               [st3 eff3] (lock-core/transition-lock st2 {:type :stale-reclaim-race
                                                                          :generation gen1
                                                                          :now-ms 215})
                               [st4 eff4] (lock-core/transition-lock st3 {:type :create-exclusive-ok
                                                                          :generation gen1
                                                                          :now-ms 220})]
                           (and (some #(= :fs-create-exclusive (:effect %)) eff3)
                                (= :single (:role st4))
                                (some #(= :activate-leader (:effect %)) eff4)))

                         :race-exhausted
                         (let [[st2 _] (lock-core/transition-lock st1 {:type :create-exclusive-exists
                                                                       :generation gen1
                                                                       :existing-holder {:pid other-pid}
                                                                       :holder-alive? false
                                                                       :now-ms 210})
                               [st3 _] (lock-core/transition-lock st2 {:type :stale-reclaim-race :generation gen1 :now-ms 215})
                               [st4 eff4] (lock-core/transition-lock st3 {:type :stale-reclaim-race :generation gen1 :now-ms 220})]
                           (and (= :rejected (:role st4))
                                (some #(= :reject-duplicate (:effect %)) eff4)
                                (not (some #(= :activate-leader (:effect %)) eff4)))))))))

(defspec ^{:doc "Row 10: Browser Web Locks two-phase leader election and automatic handoff preserves mutual exclusion and emits counted :browser-tab-leader-handoff."}
  browser-web-lock-leader-handoff-prop 50
  (prop/for-all [tab1-id gen-non-empty-ascii
                 tab2-id gen-non-empty-ascii]
                (let [t1 (str "t1-" tab1-id)
                      t2 (str "t2-" tab2-id)
                      lock-name "bitecho-node-devnet-pubkey123"
          ;; Tab 1 acquires immediately
                      [t1-s1 _] (lock-core/transition-lock
                                 (lock-core/init-lock-state {:mode :web-lock :lock-id lock-name :self-id t1 :generation 1})
                                 {:type :acquire-requested :now-ms 100})
                      [t1-s2 t1-e2] (lock-core/transition-lock t1-s1 {:type :web-lock-probe :generation 1 :available? true :now-ms 110})
          ;; Tab 2 probes while Tab 1 holds lock -> enters :secondary
                      [t2-s1 _] (lock-core/transition-lock
                                 (lock-core/init-lock-state {:mode :web-lock :lock-id lock-name :self-id t2 :generation 1})
                                 {:type :acquire-requested :now-ms 120})
                      [t2-s2 t2-e2] (lock-core/transition-lock t2-s1 {:type :web-lock-probe
                                                                      :generation 1
                                                                      :available? false
                                                                      :holder-tab-id t1
                                                                      :now-ms 130})
          ;; Tab 1 closes -> Tab 2 receives queued :web-lock-acquired :handoff? true
                      [t1-s3 _] (lock-core/transition-lock t1-s2 {:type :release-requested})
                      [t2-s3 t2-e3] (lock-core/transition-lock t2-s2 {:type :web-lock-acquired
                                                                      :generation 1
                                                                      :handoff? true
                                                                      :now-ms 200})]
                  (and (= :leader (:role t1-s2))
                       (some #(= :activate-leader (:effect %)) t1-e2)
                       (= :secondary (:role t2-s2))
                       (= t1 (:leader-tab-id t2-s2))
                       (some #(= :enter-secondary (:effect %)) t2-e2)
                       (not (some #(= :activate-leader (:effect %)) t2-e2))
                       (= :unlocked (:role t1-s3))
                       (= :leader (:role t2-s3))
                       (> (:generation t2-s3) (:generation t2-s2))
                       (= 1 (get-in t2-s3 [:diagnostics :browser-tab-leader-handoff]))
                       (some #(and (= :diagnose (:effect %)) (= :browser-tab-leader-handoff (:reason %))) t2-e3)
                       (some #(= :activate-leader (:effect %)) t2-e3)))))

#?(:clj
   (deftest jvm-shell-atomic-serve-lock-and-f-epoch-1-integration-test
     (testing "JVM OS-atomic FileChannel CREATE_NEW serve.lock: acquire, live reject, stale reclaim, owned release"
       (let [tmp-dir (java.nio.file.Files/createTempDirectory "bitecho-stageb-lock-" (make-array java.nio.file.attribute.FileAttribute 0))
             dir-path (.toString tmp-dir)
             ctrl-file (io/file dir-path "control.json")
             _ (spit ctrl-file "{\"port\":5020,\"pid\":11111}")
             acq1 (jvm-shell/acquire-serve-lock! dir-path {:current-pid 11111
                                                           :token "tok-owner-1"
                                                           :pid-alive-fn (fn [p] (= p 11111))})
             dup (jvm-shell/acquire-serve-lock! dir-path {:current-pid 22222
                                                          :token "tok-dup-2"
                                                          :pid-alive-fn (fn [p] (= p 11111))})
             reclaim (jvm-shell/acquire-serve-lock! dir-path {:current-pid 33333
                                                              :token "tok-reclaim-3"
                                                              :pid-alive-fn (constantly false)})]
         (try
           (is (true? (:ok? acq1)))
           (is (= :single (get-in acq1 [:lock-state :role])))
           (is (false? (:ok? dup)))
           (is (= :duplicate-instance (get-in dup [:canonical-error :error])))
           (is (= :duplicate-serve-instance-rejected (get-in dup [:diagnose :reason])))
           (is (= "{\"port\":5020,\"pid\":11111}" (slurp ctrl-file)))
           (is (true? (:ok? reclaim)))
           (is (true? (:reclaimed-stale-lock? reclaim)))
           (is (= 11111 (:stale-pid reclaim)))
           (is (some #(= :stale-serve-lock-reclaimed (:reason %)) (:effects reclaim)))
           ;; Wrong token must not unlink owner's lock
           (jvm-shell/release-serve-lock! dir-path 33333 "wrong-token")
           (is (.exists (io/file dir-path "serve.lock")))
           ;; Matching PID + token unlinks cleanly
           (jvm-shell/release-serve-lock! dir-path 33333 "tok-reclaim-3")
           (is (not (.exists (io/file dir-path "serve.lock"))))
           (finally
             (doseq [f (reverse (file-seq (io/file dir-path)))]
               (.delete f))))))

     (testing "JVM run-auto-sync-tick! drives bitecho.sync.core for F-EPOCH-1 loud stall & recovery"
       (let [clock-atom (atom 10000)
             epoch-atom (atom 42)
             events-atom (atom [])
             sync-atom (atom (sync-core/init-sync-state {:stall-threshold-ms 60000}))
             state-atom (atom {:pubkey "abcd"
                               :subnet-id "devnet.bitecho.org"
                               :epoch 42
                               :account {:finalized-epoch 42 :balance 100 :spendable 100}
                               :diagnostics {}})
             conn-opts {:sync-atom sync-atom
                        :now-ms-fn #(deref clock-atom)
                        :event-out #(swap! events-atom conj %)}]
         (with-redefs [jvm-shell/maybe-sync-account-state!
                       (fn [st-atom _boot _pk _sk _opts]
                         (swap! st-atom assoc
                                :epoch @epoch-atom
                                :account {:finalized-epoch @epoch-atom :balance 100 :spendable 100})
                         {:ok? true :head-epoch (+ @epoch-atom 3)})]
           ;; Tick 1: initial observation at t=10000, epoch=42
           (jvm-shell/run-auto-sync-tick! state-atom {} {:pubkey "abcd"} nil conn-opts)
           (is (false? (get-in (light-core/exec-status @state-atom @clock-atom) ["sync" "stalled"])))
           ;; Tick 2: t=80000 (70s >= 60s threshold), epoch still 42 -> STALLED!
           (reset! clock-atom 80000)
           (jvm-shell/run-auto-sync-tick! state-atom {} {:pubkey "abcd"} nil conn-opts)
           (let [st-stalled (light-core/exec-status @state-atom @clock-atom)]
             (is (true? (get-in st-stalled ["sync" "stalled"])))
             (is (true? (get st-stalled "stalled")))
             (is (= "auto-sync-stalled" (get-in st-stalled ["sync" "last_error"])))
             (is (>= (get-in st-stalled ["diagnostics" "auto_sync_stalled"]) 1))
             (is (>= (get-in st-stalled ["diagnostics" "finalized_epoch_stalled"]) 1))
             (is (true? (get (last @events-atom) "stalled"))))
           ;; Tick 3: epoch advances to 43 -> RECOVERED!
           (reset! epoch-atom 43)
           (reset! clock-atom 95000)
           (jvm-shell/run-auto-sync-tick! state-atom {} {:pubkey "abcd"} nil conn-opts)
           (let [st-rec (light-core/exec-status @state-atom @clock-atom)]
             (is (false? (get-in st-rec ["sync" "stalled"])))
             (is (false? (get st-rec "stalled")))
             (is (nil? (get-in st-rec ["sync" "last_error"])))))))))
