(ns bitecho.core.lifecycle
  "Unified Rule 4 & Rule 5 pure lifecycle state machine reducer (BIP-005 / Milestone D31):
   `(transition-lifecycle state event) -> [new-state effects]`
   - Rule 4: Single-authority generation-tagged lifecycle state (`:phase`, `:generation`,
     `:last-error`, `:dropped`, `:ignored-stale`). Never stores derived boolean liveness
     (`:connected?`, `:connection-error`).
   - Rule 5: Zero silent failures. Every stale-generation callback (`event-gen < current-gen`),
     dropped frame, or dial/runtime failure increments a diagnostic counter and emits a
     counted `:diagnose` effect.")

(defn init-lifecycle-state
  "Initializes a pure Rule 4 generation-tagged lifecycle state map."
  ([]
   (init-lifecycle-state {}))
  ([opts]
   (cond-> {:phase (or (:phase opts) :idle)
            :generation (long (or (:generation opts) 0))
            :last-error nil
            :dropped 0
            :ignored-stale 0}
     (:id opts) (assoc :id (:id opts))
     (:target opts) (assoc :target (:target opts)))))

(defn stale-generation?
  "Returns true if `event` carries an explicit `:generation` strictly less than `(:generation state)`."
  [state event]
  (let [cur-gen (long (:generation state 0))
        ev-gen (:generation event)]
    (and (some? ev-gen)
         (< (long ev-gen) cur-gen))))

(defn transition-lifecycle
  "Pure Rule 4/5 lifecycle transition function: `(transition-lifecycle state event) -> [state' effects]`.
   Supported event `:type`s:
   - `:dial` / `:start`: increments `:generation`, sets `:phase` to `:dialing` (or `:starting`), clears `:last-error`.
   - `:open` / `:running`: generation-fenced transition to `:open` / `:running`.
   - `:close` / `:stop`: generation-fenced transition to `:closed` / `:stopped`, emits `:close-node` when active.
   - `:failed` / `:dial-failed`: generation-fenced transition to `:failed`, records `:last-error`, emits counted `:diagnose`.
   - `:drop`: increments `:dropped`, records `:last-error`, emits counted `:diagnose`.
   - `:diagnose`: records `:last-error` and emits counted `:diagnose`."
  [state event]
  (let [st0 (-> (or state (init-lifecycle-state))
                (dissoc :connected? :connection-error))
        cur-gen (long (:generation st0 0))
        ev-type (:type event)]
    (if (and (not (contains? #{:dial :start} ev-type))
             (stale-generation? st0 event))
      (let [ev-gen (long (:generation event 0))
            st' (update st0 :ignored-stale (fnil inc 0))
            diag {:effect :diagnose
                  :kind :ignored-stale
                  :reason :ignored-stale-generation
                  :event-type ev-type
                  :event-generation ev-gen
                  :current-generation cur-gen}]
        [st' [diag]])
      (case ev-type
        (:dial :start)
        (let [next-gen (inc cur-gen)
              next-phase (if (= ev-type :start) :starting :dialing)
              target (or (:target event) (:target-url event) (:target st0))
              st' (cond-> (assoc st0
                                 :phase next-phase
                                 :generation next-gen
                                 :last-error nil)
                    target (assoc :target target))
              effs (cond-> []
                     (contains? #{:dialing :open :starting :running} (:phase st0))
                     (conj {:effect :close-node
                            :generation cur-gen
                            :reason :superseded-by-new-generation}))]
          [st' effs])

        (:open :running)
        (let [next-phase (if (= ev-type :running) :running :open)
              st' (assoc st0
                         :phase next-phase
                         :last-error nil)]
          [st' []])

        (:close :stop)
        (let [next-phase (if (= ev-type :stop) :stopped :closed)
              reason (or (:reason event) (:cause event) :closed)
              was-active? (contains? #{:dialing :open :starting :running} (:phase st0))
              st' (assoc st0 :phase next-phase)
              effs (cond-> []
                     was-active?
                     (conj {:effect :close-node
                            :generation cur-gen
                            :reason reason}))]
          [st' effs])

        (:failed :dial-failed)
        (let [err (or (:error event) (:reason event) :lifecycle-failed)
              st' (-> st0
                      (assoc :phase :failed
                             :last-error err)
                      (update :dropped (fnil inc 0)))
              diag {:effect :diagnose
                    :kind :lifecycle-failed
                    :reason err
                    :generation cur-gen}]
          [st' [diag]])

        :drop
        (let [reason (or (:reason event) (:error event) :dropped-envelope)
              st' (-> st0
                      (assoc :last-error reason)
                      (update :dropped (fnil inc 0)))
              diag {:effect :diagnose
                    :kind :dropped
                    :reason reason
                    :generation cur-gen}]
          [st' [diag]])

        :diagnose
        (let [reason (or (:reason event) (:error event) :diagnostic-event)
              st' (assoc st0 :last-error reason)
              diag {:effect :diagnose
                    :kind :diagnose
                    :reason reason
                    :generation cur-gen}]
          [st' [diag]])

        ;; Unknown event type -> fail closed with counted :diagnose (Rule 5)
        (let [st' (-> st0
                      (assoc :last-error :unknown-lifecycle-event)
                      (update :dropped (fnil inc 0)))
              diag {:effect :diagnose
                    :kind :unknown-event
                    :reason :unknown-lifecycle-event
                    :event-type ev-type
                    :generation cur-gen}]
          [st' [diag]])))))
