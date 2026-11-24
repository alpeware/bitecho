(ns bitecho.sync.core
  "Uniform Periodic Sync & F-EPOCH-1 Loud-Stall Contract (BIP-022 Stage B, Row 5; Rules 2, 4, 5).
   Single pure generation-tagged `.cljc` reducer shared identically across Browser, Node.js Light,
   and JVM Light shells."
  (:require [clojure.string :as str]))

(def default-sync-interval-ms
  "Unified periodic sync cadence (15s) across Node.js, JVM, and Browser (:visible)."
  15000)

(def min-sync-interval-ms
  "Minimum allowed periodic sync interval (1s)."
  1000)

(def browser-hidden-sync-interval-ms
  "Throttled periodic sync cadence (180s) when Browser tab visibilityState is hidden."
  180000)

(def default-fetch-timeout-ms
  "Default per-tick quorum sync fetch timeout (10s)."
  10000)

(def default-stall-threshold-ms
  "Default BIP-019 S3 F-EPOCH-1 stall threshold (180s)."
  180000)

(defn init-sync-state
  "Initializes single-authority generation-tagged periodic sync + F-EPOCH-1 stall state.
   Options: {:generation 1 :enabled? true :interval-ms 15000 :hidden-interval-ms 180000
             :stall-threshold-ms 180000 :fetch-timeout-ms 10000 :visibility :visible :role :single}."
  ([] (init-sync-state nil))
  ([opts]
   {:generation (max 1 (long (or (:generation opts) 1)))
    :enabled? (if (contains? opts :enabled?) (boolean (:enabled? opts)) true)
    :interval-ms (max min-sync-interval-ms (long (or (:interval-ms opts) default-sync-interval-ms)))
    :hidden-interval-ms (max min-sync-interval-ms (long (or (:hidden-interval-ms opts) browser-hidden-sync-interval-ms)))
    :stall-threshold-ms (max 1 (long (or (:stall-threshold-ms opts) default-stall-threshold-ms)))
    :fetch-timeout-ms (max 100 (long (or (:fetch-timeout-ms opts) default-fetch-timeout-ms)))
    :visibility (if (= :hidden (:visibility opts)) :hidden :visible)
    :role (or (:role opts) :single)
    :in-flight? false
    :active-fetch-gen nil
    :last-finalized-epoch nil
    :last-advanced-ms nil
    :stalled? false
    :stall-started-ms nil
    :stall-duration-ms 0
    :last-error nil
    :diagnostics {:stale-auto-sync-callback 0
                  :ignored-stale 0
                  :auto-sync-tick-skipped-in-flight 0
                  :auto-sync-stalled 0
                  :finalized-epoch-stalled 0
                  :auto-sync-failed 0
                  :auto-sync-timeout 0}}))

(defn effective-interval-ms
  "Returns active cadence (ms): `:hidden-interval-ms` when `:visibility` is `:hidden`, else `:interval-ms`."
  [sync-state]
  (let [st (or sync-state (init-sync-state))]
    (if (= :hidden (:visibility st))
      (long (or (:hidden-interval-ms st) browser-hidden-sync-interval-ms))
      (long (or (:interval-ms st) default-sync-interval-ms)))))

(defn- build-auto-sync-event
  [{:keys [ok? synced? stalled? stall-duration-ms finalized-epoch balance spendable error]}]
  (cond-> {"event" "auto-sync"
           "ok" (boolean ok?)
           "synced" (boolean synced?)
           "stalled" (boolean stalled?)
           "stall_duration_ms" (long (or stall-duration-ms 0))}
    (some? finalized-epoch) (assoc "finalized_epoch" (long finalized-epoch))
    (some? balance) (assoc "balance" (long balance))
    (some? spendable) (assoc "spendable" (long spendable))
    (and (string? error) (not (str/blank? error))) (assoc "error" error)))

(defn step-auto-sync
  "Pure generation-tagged reducer `(step-auto-sync sync-state event) -> [new-sync-state effects]`.
   Replaces divergent Node, JVM, and Browser sync/stall loops (Rules 2, 4, 5)."
  [sync-state event]
  (let [st (or sync-state (init-sync-state))
        ev-type (:type event)
        cur-gen (long (or (:generation st) 1))
        ev-gen (:generation event)
        stale? (and (not= ev-type :stop)
                    (some? ev-gen)
                    (< (long ev-gen) cur-gen))]
    (if stale?
      (let [st' (-> st
                    (update-in [:diagnostics :stale-auto-sync-callback] (fnil inc 0))
                    (update-in [:diagnostics :ignored-stale] (fnil inc 0)))
            diag {:effect :diagnose
                  :type :diagnose
                  :reason :stale-auto-sync-callback
                  :event-type ev-type
                  :event-generation (long ev-gen)
                  :current-generation cur-gen}]
        [st' [diag]])
      (case ev-type
        :tick
        (let [vis (if (contains? event :visibility)
                    (if (= :hidden (:visibility event)) :hidden :visible)
                    (:visibility st))
              st-vis (assoc st :visibility vis)
              active? (if (contains? event :active?) (boolean (:active? event)) true)]
          (cond
            (or (not (:enabled? st-vis)) (not active?))
            [st-vis (if (:enabled? st-vis)
                      [{:effect :reschedule-timer
                        :interval-ms (effective-interval-ms st-vis)
                        :generation cur-gen}]
                      [])]

            (= :secondary (:role st-vis))
            ;; Row 10 secondary-tab quiescence: never fire fetch-quorum-sync while non-leader
            [st-vis [{:effect :reschedule-timer
                      :interval-ms (effective-interval-ms st-vis)
                      :generation cur-gen}]]

            (:in-flight? st-vis)
            (let [st' (update-in st-vis [:diagnostics :auto-sync-tick-skipped-in-flight] (fnil inc 0))
                  diag {:effect :diagnose
                        :type :diagnose
                        :reason :auto-sync-tick-skipped-in-flight
                        :generation cur-gen}]
              [st' [diag
                    {:effect :reschedule-timer
                     :interval-ms (effective-interval-ms st')
                     :generation cur-gen}]])

            :else
            (let [st' (assoc st-vis
                             :in-flight? true
                             :active-fetch-gen cur-gen)]
              [st' [{:effect :fetch-quorum-sync
                     :generation cur-gen
                     :timeout-ms (long (or (:fetch-timeout-ms st') default-fetch-timeout-ms))
                     :reason :periodic-tick}
                    {:effect :reschedule-timer
                     :interval-ms (effective-interval-ms st')
                     :generation cur-gen}]])))

        :fetch-ok
        (let [fin (long (or (:finalized-epoch event) 0))
              now (max 0 (long (or (:now-ms event) 0)))
              head-ep (when (some? (:head-epoch event)) (long (:head-epoch event)))
              bal (:balance event)
              spend (:spendable event)
              threshold-ms (max 1 (long (or (:stall-threshold-ms st) default-stall-threshold-ms)))
              prev-fin (:last-finalized-epoch st)
              prev-adv-ms (:last-advanced-ms st)
              advanced? (or (nil? prev-fin)
                            (zero? (long prev-fin))
                            (> fin (long prev-fin)))]
          (if advanced?
            (let [st' (assoc st
                             :in-flight? false
                             :active-fetch-gen nil
                             :last-finalized-epoch fin
                             :last-advanced-ms now
                             :stalled? false
                             :stall-started-ms nil
                             :stall-duration-ms 0
                             :last-error nil)
                  ev (build-auto-sync-event {:ok? true
                                             :synced? true
                                             :stalled? false
                                             :stall-duration-ms 0
                                             :finalized-epoch fin
                                             :balance bal
                                             :spendable spend})]
              [st' [{:effect :emit-event :event ev}]])
            (let [anchor-ms (long (or prev-adv-ms now))
                  frozen-ms (max 0 (- now anchor-ms))]
              (if (and (pos? fin) (>= frozen-ms threshold-ms))
                (let [stall-start (long (or (:stall-started-ms st) anchor-ms))
                      obs-lag (when (some? head-ep) (max 0 (- head-ep fin)))
                      diag {:effect :diagnose
                            :type :diagnose
                            :reason :auto-sync-stalled
                            :alias-reason :finalized-epoch-stalled
                            :finalized-epoch fin
                            :observed-lag obs-lag
                            :stall-duration-ms frozen-ms
                            :threshold-ms threshold-ms
                            :generation cur-gen}
                      st' (-> st
                              (assoc :in-flight? false
                                     :active-fetch-gen nil
                                     :last-finalized-epoch (long prev-fin)
                                     :last-advanced-ms anchor-ms
                                     :stalled? true
                                     :stall-started-ms stall-start
                                     :stall-duration-ms frozen-ms
                                     :last-error "auto-sync-stalled")
                              (update-in [:diagnostics :auto-sync-stalled] (fnil inc 0))
                              (update-in [:diagnostics :finalized-epoch-stalled] (fnil inc 0)))
                      ev (build-auto-sync-event {:ok? false
                                                 :synced? false
                                                 :stalled? true
                                                 :stall-duration-ms frozen-ms
                                                 :finalized-epoch fin
                                                 :balance bal
                                                 :spendable spend
                                                 :error "auto-sync-stalled"})]
                  [st' [diag {:effect :emit-event :event ev}]])
                (let [st' (assoc st
                                 :in-flight? false
                                 :active-fetch-gen nil
                                 :last-finalized-epoch (long prev-fin)
                                 :last-advanced-ms anchor-ms
                                 :stalled? false
                                 :stall-started-ms nil
                                 :stall-duration-ms frozen-ms
                                 :last-error nil)
                      ev (build-auto-sync-event {:ok? true
                                                 :synced? true
                                                 :stalled? false
                                                 :stall-duration-ms frozen-ms
                                                 :finalized-epoch fin
                                                 :balance bal
                                                 :spendable spend})]
                  [st' [{:effect :emit-event :event ev}]])))))

        :fetch-error
        (let [err (str (or (:error event) "auto-sync-failed"))
              st' (-> st
                      (assoc :in-flight? false
                             :active-fetch-gen nil
                             :last-error err)
                      (update-in [:diagnostics :auto-sync-failed] (fnil inc 0)))
              diag {:effect :diagnose
                    :type :diagnose
                    :reason :auto-sync-failed
                    :error err
                    :generation cur-gen}
              ev (build-auto-sync-event {:ok? false
                                         :synced? false
                                         :stalled? (boolean (:stalled? st'))
                                         :stall-duration-ms (:stall-duration-ms st')
                                         :finalized-epoch (:last-finalized-epoch st')
                                         :error err})]
          [st' [diag {:effect :emit-event :event ev}]])

        :timeout
        (let [st' (-> st
                      (assoc :in-flight? false
                             :active-fetch-gen nil
                             :last-error "auto-sync-timeout")
                      (update-in [:diagnostics :auto-sync-timeout] (fnil inc 0))
                      (update-in [:diagnostics :auto-sync-failed] (fnil inc 0)))
              diag {:effect :diagnose
                    :type :diagnose
                    :reason :auto-sync-timeout
                    :generation cur-gen}
              ev (build-auto-sync-event {:ok? false
                                         :synced? false
                                         :stalled? (boolean (:stalled? st'))
                                         :stall-duration-ms (:stall-duration-ms st')
                                         :finalized-epoch (:last-finalized-epoch st')
                                         :error "auto-sync-timeout"})]
          [st' [diag {:effect :emit-event :event ev}]])

        :visibility-change
        (let [prev-vis (:visibility st)
              next-vis (if (= :hidden (:visibility event)) :hidden :visible)
              st-vis (assoc st :visibility next-vis)
              resume? (and (= :hidden prev-vis)
                           (= :visible next-vis)
                           (:enabled? st-vis)
                           (not= :secondary (:role st-vis))
                           (not (:in-flight? st-vis)))]
          (if resume?
            (let [st' (assoc st-vis :in-flight? true :active-fetch-gen cur-gen)]
              [st' [{:effect :fetch-quorum-sync
                     :generation cur-gen
                     :timeout-ms (long (or (:fetch-timeout-ms st') default-fetch-timeout-ms))
                     :reason :visibility-resume}
                    {:effect :reschedule-timer
                     :interval-ms (effective-interval-ms st')
                     :generation cur-gen}]])
            [st-vis (if (:enabled? st-vis)
                      [{:effect :reschedule-timer
                        :interval-ms (effective-interval-ms st-vis)
                        :generation cur-gen}]
                      [])]))

        :online
        (if (and (:enabled? st)
                 (not= :secondary (:role st))
                 (not (:in-flight? st)))
          (let [st' (assoc st :in-flight? true :active-fetch-gen cur-gen)]
            [st' [{:effect :fetch-quorum-sync
                   :generation cur-gen
                   :timeout-ms (long (or (:fetch-timeout-ms st') default-fetch-timeout-ms))
                   :reason :online-resume}
                  {:effect :reschedule-timer
                   :interval-ms (effective-interval-ms st')
                   :generation cur-gen}]])
          [st []])

        :role-change
        (let [prev-role (:role st)
              next-role (or (:role event) :single)]
          (cond
            (and (= :secondary prev-role) (#{:leader :single} next-role))
            (let [next-gen (inc cur-gen)
                  st-base (assoc st
                                 :role next-role
                                 :generation next-gen
                                 :in-flight? false
                                 :active-fetch-gen nil)]
              (if (:enabled? st-base)
                (let [st' (assoc st-base :in-flight? true :active-fetch-gen next-gen)]
                  [st' [{:effect :fetch-quorum-sync
                         :generation next-gen
                         :timeout-ms (long (or (:fetch-timeout-ms st') default-fetch-timeout-ms))
                         :reason :leader-promotion}
                        {:effect :reschedule-timer
                         :interval-ms (effective-interval-ms st')
                         :generation next-gen}]])
                [st-base []]))

            (and (not= :secondary prev-role) (= :secondary next-role))
            (let [next-gen (inc cur-gen)
                  st' (assoc st
                             :role :secondary
                             :generation next-gen
                             :in-flight? false
                             :active-fetch-gen nil)]
              [st' [{:effect :cancel-timer :generation next-gen}]])

            :else
            [(assoc st :role next-role) []]))

        :stop
        (let [next-gen (inc cur-gen)
              st' (assoc st
                         :generation next-gen
                         :enabled? false
                         :in-flight? false
                         :active-fetch-gen nil)]
          [st' [{:effect :cancel-timer :generation next-gen}]])

        ;; Unknown event -> zero silent failures (Rule 5)
        (let [st' (update-in st [:diagnostics :ignored-stale] (fnil inc 0))
              diag {:effect :diagnose
                    :type :diagnose
                    :reason :unknown-sync-event
                    :event-type ev-type
                    :generation cur-gen}]
          [st' [diag]])))))
