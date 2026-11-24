(ns bitecho.lifecycle.lock-core
  "Single-Authority Generation-Tagged Instance Lock & Multi-Tab Leader Election Core
   (BIP-022 Stage B, Row 10; Rules 2, 4, 5).
   Pure Sans-IO `.cljc` reducer governing:
   1. OS-atomic `O_CREAT|O_EXCL` / `CREATE_NEW` `serve.lock` acquisition, live-holder
      rejection (`:duplicate-instance`), bounded stale-PID reclaim, and owned release
      for Node.js Light, JVM Light, and Full Node shells.
   2. Two-phase Browser `navigator.locks` + `BroadcastChannel` multi-tab leader election
      and automatic leader handoff."
  (:require [bitecho.errors.core :as errors]))

(def default-max-reclaim-retries
  "Maximum bounded stale-lock reclaim retries to prevent livelock under concurrent startup races."
  2)

(defn init-lock-state
  "Initializes single-authority generation-tagged instance lock state.
   `:mode` is `:pid-file` (Node, JVM, Full Node) or `:web-lock` (Browser)."
  [{:keys [mode lock-id self-id token runtime generation max-reclaim-retries]
    :or {mode :pid-file
         generation 1
         runtime "unknown"}}]
  {:mode (if (= mode :web-lock) :web-lock :pid-file)
   :lock-id (or lock-id "serve.lock")
   :self-id self-id
   :token (or token (str "tok-" (or self-id "0")))
   :runtime (str (or runtime "unknown"))
   :generation (max 1 (long (or generation 1)))
   :role :unlocked
   :holder-pid nil
   :leader-tab-id nil
   :reclaimed-stale-lock? false
   :stale-pid nil
   :reclaim-retries 0
   :max-reclaim-retries (max 1 (long (or max-reclaim-retries default-max-reclaim-retries)))
   :last-error nil
   :diagnostics {:stale-lock-callback 0
                 :ignored-stale 0
                 :duplicate-serve-instance-rejected 0
                 :stale-serve-lock-reclaimed 0
                 :stale-serve-lock-race 0
                 :browser-tab-leader-handoff 0
                 :web-locks-unavailable 0}})

(defn- lock-payload
  [lock-state now-ms]
  {:pid (:self-id lock-state)
   :token (:token lock-state)
   :timestamp-ms (long (or now-ms 0))
   :runtime (:runtime lock-state)})

(defn- reject-duplicate-transition
  [lock-state existing-pid detail-extra]
  (let [detail (merge {:locked-pid existing-pid
                       :attempted-pid (:self-id lock-state)
                       :lock-file (:lock-id lock-state)}
                      detail-extra)
        err (errors/canonical-error :duplicate-instance detail)
        diag (merge {:effect :diagnose
                     :type :diagnose
                     :reason :duplicate-serve-instance-rejected
                     :locked-pid existing-pid
                     :attempted-pid (:self-id lock-state)
                     :lock-id (:lock-id lock-state)}
                    detail-extra)
        st' (-> lock-state
                (assoc :role :rejected
                       :holder-pid existing-pid
                       :last-error "duplicate-instance")
                (update-in [:diagnostics :duplicate-serve-instance-rejected] (fnil inc 0)))]
    [st' [diag {:effect :reject-duplicate :error err}]]))

(defn transition-lock
  "Pure generation-tagged reducer `(transition-lock lock-state event) -> [new-lock-state effects]`.
   Governs atomic PID-file acquisition/stale-reclaim/release AND Browser Web Locks
   multi-tab leader election + handoff (Rules 2, 4, 5)."
  [lock-state event]
  (let [st (or lock-state (init-lock-state {}))
        ev-type (:type event)
        cur-gen (long (or (:generation st) 1))
        ev-gen (:generation event)
        stale? (and (some? ev-gen) (< (long ev-gen) cur-gen))]
    (if stale?
      (let [st' (-> st
                    (update-in [:diagnostics :stale-lock-callback] (fnil inc 0))
                    (update-in [:diagnostics :ignored-stale] (fnil inc 0)))
            diag {:effect :diagnose
                  :type :diagnose
                  :reason :stale-lock-callback
                  :event-type ev-type
                  :event-generation (long ev-gen)
                  :current-generation cur-gen}]
        [st' [diag]])
      (case ev-type
        :acquire-requested
        (if (#{:single :leader} (:role st))
          [st []]
          (let [st' (assoc st :role :acquiring :reclaim-retries 0 :last-error nil)]
            (if (= :web-lock (:mode st'))
              [st' [{:effect :web-lock-request
                     :lock-id (:lock-id st')
                     :mode :probe-then-wait
                     :generation cur-gen}]]
              [st' [{:effect :fs-create-exclusive
                     :lock-id (:lock-id st')
                     :payload (lock-payload st' (:now-ms event))
                     :generation cur-gen}]])))

        :create-exclusive-ok
        (let [st' (assoc st
                         :role :single
                         :holder-pid (:self-id st)
                         :last-error nil
                         :reclaim-retries 0)]
          [st' [{:effect :activate-leader :generation cur-gen}]])

        :create-exclusive-exists
        (let [existing (:existing-holder event)
              existing-pid (:pid existing)
              alive? (boolean (:holder-alive? event))
              same-pid? (and (some? existing-pid) (= existing-pid (:self-id st)))]
          (if (and alive? (some? existing-pid) (not same-pid?))
            (reject-duplicate-transition st existing-pid nil)
            (let [retries (long (or (:reclaim-retries st) 0))
                  max-r (long (or (:max-reclaim-retries st) default-max-reclaim-retries))]
              (if (< retries max-r)
                (let [st' (assoc st :reclaim-retries (inc retries))]
                  [st' [{:effect :fs-reclaim-stale
                         :lock-id (:lock-id st')
                         :expected-stale-pid existing-pid
                         :payload (lock-payload st' (:now-ms event))
                         :generation cur-gen}]])
                (reject-duplicate-transition st existing-pid {:retry-exhausted? true})))))

        :stale-reclaim-ok
        (let [stale-pid (:stale-pid event)
              st' (-> st
                      (assoc :role :single
                             :holder-pid (:self-id st)
                             :reclaimed-stale-lock? true
                             :stale-pid stale-pid
                             :last-error nil
                             :reclaim-retries 0)
                      (update-in [:diagnostics :stale-serve-lock-reclaimed] (fnil inc 0)))
              diag {:effect :diagnose
                    :type :diagnose
                    :reason :stale-serve-lock-reclaimed
                    :stale-pid stale-pid
                    :new-pid (:self-id st')}]
          [st' [diag {:effect :activate-leader :generation cur-gen}]])

        :stale-reclaim-race
        (let [retries (long (or (:reclaim-retries st) 0))
              max-r (long (or (:max-reclaim-retries st) default-max-reclaim-retries))
              st-counted (update-in st [:diagnostics :stale-serve-lock-race] (fnil inc 0))]
          (if (< retries max-r)
            (let [next-retry (inc retries)
                  st' (assoc st-counted :reclaim-retries next-retry)
                  diag {:effect :diagnose
                        :type :diagnose
                        :reason :stale-serve-lock-race
                        :retry next-retry
                        :generation cur-gen}]
              [st' [diag
                    {:effect :fs-create-exclusive
                     :lock-id (:lock-id st')
                     :payload (lock-payload st' (:now-ms event))
                     :generation cur-gen}]])
            (reject-duplicate-transition st-counted nil {:retry-exhausted? true
                                                         :reason "stale-reclaim-race-exhausted"})))

        :web-lock-probe
        (if (:available? event)
          (let [st' (assoc st
                           :role :leader
                           :leader-tab-id (:self-id st)
                           :last-error nil)]
            [st' [{:effect :activate-leader :generation cur-gen}
                  {:effect :broadcast-channel
                   :channel (:lock-id st')
                   :message {:type "leader-elected"
                             :tab-id (:self-id st')
                             :generation cur-gen}}]])
          (let [holder-id (:holder-tab-id event)
                st' (assoc st
                           :role :secondary
                           :leader-tab-id holder-id)]
            [st' [{:effect :enter-secondary
                   :generation cur-gen
                   :leader-tab-id holder-id}]]))

        :web-lock-acquired
        (let [handoff? (boolean (or (:handoff? event) (= :secondary (:role st))))
              next-gen (if handoff? (inc cur-gen) cur-gen)
              st' (cond-> (assoc st
                                 :role :leader
                                 :generation next-gen
                                 :leader-tab-id (:self-id st)
                                 :last-error nil)
                    handoff? (update-in [:diagnostics :browser-tab-leader-handoff] (fnil inc 0)))
              effs (cond-> []
                     handoff? (conj {:effect :diagnose
                                     :type :diagnose
                                     :reason :browser-tab-leader-handoff
                                     :tab-id (:self-id st')
                                     :generation next-gen})
                     true (conj {:effect :activate-leader :generation next-gen})
                     true (conj {:effect :broadcast-channel
                                 :channel (:lock-id st')
                                 :message {:type "leader-elected"
                                           :tab-id (:self-id st')
                                           :generation next-gen}}))]
          [st' effs])

        :web-lock-unavailable
        (let [st' (-> st
                      (assoc :role :single
                             :leader-tab-id (:self-id st)
                             :last-error nil)
                      (update-in [:diagnostics :web-locks-unavailable] (fnil inc 0)))
              diag {:effect :diagnose
                    :type :diagnose
                    :reason :web-locks-unavailable
                    :lock-id (:lock-id st')}]
          [st' [diag {:effect :activate-leader :generation cur-gen}]])

        :broadcast-leader-heartbeat
        (if (= :secondary (:role st))
          [(assoc st :leader-tab-id (:leader-tab-id event)) []]
          [st []])

        :release-requested
        (let [was-owner? (boolean (#{:single :leader} (:role st)))
              next-gen (inc cur-gen)
              st' (assoc st
                         :role :unlocked
                         :generation next-gen
                         :holder-pid nil
                         :leader-tab-id nil)]
          (if was-owner?
            (if (= :web-lock (:mode st))
              [st' [{:effect :broadcast-channel
                     :channel (:lock-id st)
                     :message {:type "leader-released"
                               :tab-id (:self-id st)
                               :generation next-gen}}]]
              [st' [{:effect :fs-release-lock
                     :lock-id (:lock-id st)
                     :expected-pid (:self-id st)
                     :expected-token (:token st)}]])
            [st' []]))

        ;; Unknown event -> zero silent failures (Rule 5)
        (let [st' (update-in st [:diagnostics :ignored-stale] (fnil inc 0))
              diag {:effect :diagnose
                    :type :diagnose
                    :reason :unknown-lock-event
                    :event-type ev-type
                    :generation cur-gen}]
          [st' [diag]])))))
