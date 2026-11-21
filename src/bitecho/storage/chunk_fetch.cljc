(ns bitecho.storage.chunk-fetch
  "Pure Sans-IO generation-tagged chunk fetch state machine for BIP-017a (Rules 1, 2, 4, 5).
   - Single-authority generation-tagged state map updated exclusively by `(transition state event) -> [new-state effects]`.
   - Zero mutable MessageDigest inside reducer: incremental SHA-256 executes strictly via shell effects
     (`:digest-chunk` -> `:digest-result` -> `:digest-final`).
   - Zero silent failures: every fault, drop, stale callback, or cap clamp emits a counted `:diagnose` effect
     maintaining `:dropped == sum(causes)`."
  (:require [bitecho.storage.chunk-constants :as cc]))

;; =============================================================================
;; 1. Diagnostics Accounting Helper (Rule 5: :dropped == sum(causes))
;; =============================================================================

(defn- record-diagnose
  "Records a counted `:diagnose` event in `state` and returns `[new-state effect]`."
  [state kind reason & [extra]]
  (let [eff (merge {:type :diagnose
                    :kind kind
                    :reason reason
                    :generation (:generation state)}
                   extra)
        next-state (-> state
                       (update-in [:diagnostics :causes kind] (fnil inc 0))
                       (update-in [:diagnostics :dropped] (fnil inc 0))
                       (assoc-in [:diagnostics :last-error] reason))]
    [next-state eff]))

(defn- recompute-byte-accounting
  "Recomputes `:staged-unhashed-bytes`, `:hashed-bytes`, and `:bytes-at-rest`
   directly from `:staged-chunks` and `:hash-cursor`."
  [state]
  (let [cursor (long (:hash-cursor state))
        staged (:staged-chunks state)
        chunks (get-in state [:manifest "chunks"] [])
        hashed (reduce (fn [acc idx]
                         (+ acc (long (get (nth chunks idx) "size" 0))))
                       0
                       (range cursor))
        staged-unhashed (reduce-kv (fn [acc idx entry]
                                     (if (>= (long idx) cursor)
                                       (+ acc (long (:size entry 0)))
                                       acc))
                                   0
                                   staged)]
    (assoc state
           :hashed-bytes hashed
           :staged-unhashed-bytes staged-unhashed
           :bytes-at-rest (+ hashed staged-unhashed))))

;; =============================================================================
;; 2. Initialization
;; =============================================================================

(defn init-fetch-state
  "Initializes a pure single-authority generation-tagged fetch state map from `opts`:
   - `:manifest` (validated via `cc/validate-manifest`)
   - `:mirrors` (non-empty vector of mirror base URLs)
   - `:concurrency` (optional, clamped to `cc/max-fetch-concurrency-940mb`)
   - `:max-retries` (optional, default `cc/default-max-retries-per-chunk`)
   - `:max-bytes` (optional hard total-bytes cap)
   - `:generation` (optional starting generation, default 1)
   Returns `{:ok? true :state state :effects [...]}` or `{:ok? false :error kw :effects [...]}`."
  [{:keys [manifest mirrors concurrency max-retries max-bytes generation]
    :or {concurrency cc/default-fetch-concurrency
         max-retries cc/default-max-retries-per-chunk
         generation 1}}]
  (let [val-res (cc/validate-manifest manifest (cond-> {} (some? max-bytes) (assoc :max-bytes max-bytes)))]
    (if-not (:ok? val-res)
      val-res
      (let [norm-m (:manifest val-res)
            mcid (:manifest-cid val-res)
            chunks (get norm-m "chunks")
            chunk-size (long (get norm-m "chunk_size"))
            conc-clamp (cc/clamp-cap :concurrency cc/max-fetch-concurrency-940mb (max 1 (long concurrency)))
            eff-conc (:value conc-clamp)
            base-state {:generation (long generation)
                        :phase :idle
                        :manifest norm-m
                        :manifest-cid mcid
                        :total-chunks (count chunks)
                        :chunk-size chunk-size
                        :total-bytes (long (get norm-m "total_bytes"))
                        :total-sha256 (get norm-m "total_sha256")
                        :mirrors (vec (distinct (or mirrors [])))
                        :blacklisted-mirrors #{}
                        :concurrency eff-conc
                        :max-retries (max 1 (long max-retries))
                        :ram-budget-bytes (* eff-conc chunk-size)
                        :in-flight {}
                        :cached-chunks #{}
                        :staged-chunks {}
                        :chunk-status (into {} (map (fn [i] [i :pending]) (range (count chunks))))
                        :retries {}
                        :hash-cursor 0
                        :hash-in-flight? false
                        :hashed-bytes 0
                        :staged-unhashed-bytes 0
                        :bytes-at-rest 0
                        :network-fetches 0
                        :mirror-rr-index 0
                        :diagnostics {:last-error nil
                                      :dropped 0
                                      :causes {}}}
            [final-state diag-effects]
            (reduce (fn [[st effs] d]
                      (let [[st2 e2] (record-diagnose st (:kind d) (:reason d)
                                                      (dissoc d :type :kind :reason))]
                        [st2 (conj effs e2)]))
                    [base-state []]
                    (:effects conc-clamp))]
        {:ok? true
         :state final-state
         :effects diag-effects}))))

;; =============================================================================
;; 3. Pure Scheduling & Hash-Cursor Progression Helpers
;; =============================================================================

(defn- healthy-mirrors
  [state]
  (let [bl (:blacklisted-mirrors state)]
    (vec (remove bl (:mirrors state)))))

(defn- pick-mirror
  "Round-robin selects a healthy mirror for the current generation."
  [state]
  (let [hm (healthy-mirrors state)]
    (when (seq hm)
      (let [rr (long (:mirror-rr-index state 0))
            m (nth hm (mod rr (count hm)))]
        [m (assoc state :mirror-rr-index (inc rr))]))))

(defn- in-flight-bytes
  [state]
  (reduce (fn [acc [_ entry]] (+ acc (long (:size entry 0)))) 0 (:in-flight state)))

(defn- schedule-pending-chunks
  "Schedules pending chunks up to `:concurrency` and `:ram-budget-bytes`."
  [state]
  (if (not= :fetching (:phase state))
    [state []]
    (let [chunks (get-in state [:manifest "chunks"])
          pending-indices (->> (range (:total-chunks state))
                               (filter #(= :pending (get-in state [:chunk-status %]))))]
      (loop [st state
             rem-idx pending-indices
             effs []]
        (if (or (empty? rem-idx)
                (>= (count (:in-flight st)) (:concurrency st)))
          [st effs]
          (let [idx (first rem-idx)
                ch (nth chunks idx)
                sz (long (get ch "size"))
                curr-bytes (in-flight-bytes st)]
            (if (and (pos? (count (:in-flight st)))
                     (> (+ curr-bytes sz) (:ram-budget-bytes st)))
              [st effs]
              (if-let [[mirror st-m] (pick-mirror st)]
                (let [attempt (inc (long (get-in st-m [:retries idx] 0)))
                      st-next (-> st-m
                                  (assoc-in [:in-flight idx] {:mirror mirror :attempt attempt :size sz})
                                  (assoc-in [:chunk-status idx] :in-flight)
                                  (update :network-fetches inc))
                      fetch-eff {:type :fetch-chunk
                                 :generation (:generation st-next)
                                 :index idx
                                 :cid (get ch "cid")
                                 :size sz
                                 :mirror mirror
                                 :attempt attempt}]
                  (recur st-next (rest rem-idx) (conj effs fetch-eff)))
                ;; No healthy mirrors left -> loud failure
                (let [[st-fail d-eff] (record-diagnose st :no-healthy-mirrors "all-mirrors-blacklisted-or-empty")
                      st-fail (assoc st-fail :phase :failed)]
                  [st-fail (conj effs d-eff {:type :emit
                                             :event :chunked-artifact-failed
                                             :generation (:generation st-fail)
                                             :manifest-cid (:manifest-cid st-fail)
                                             :reason :no-healthy-mirrors})])))))))))

(defn- maybe-advance-hash-cursor
  "If not currently hashing and the chunk at `:hash-cursor` is staged, emits `:digest-chunk`.
   If all chunks are hashed (`hash-cursor == total-chunks`), emits `:digest-final`."
  [state]
  (cond
    (or (:hash-in-flight? state)
        (not (contains? #{:fetching :verifying} (:phase state))))
    [state []]

    (= (:hash-cursor state) (:total-chunks state))
    [(assoc state :phase :verifying :hash-in-flight? true)
     [{:type :digest-final
       :generation (:generation state)
       :manifest-cid (:manifest-cid state)
       :expected-sha256 (:total-sha256 state)}]]

    (contains? (:staged-chunks state) (:hash-cursor state))
    (let [idx (:hash-cursor state)
          ch (nth (get-in state [:manifest "chunks"]) idx)]
      [(assoc state :hash-in-flight? true)
       [{:type :digest-chunk
         :generation (:generation state)
         :index idx
         :cid (get ch "cid")
         :size (long (get ch "size"))}]])

    :else
    [state []]))

(defn- fail-fetch
  [state kind reason & [extra]]
  (let [[st1 d-eff] (record-diagnose state kind reason extra)
        st2 (assoc st1 :phase :failed :in-flight {} :hash-in-flight? false)]
    [st2 [d-eff {:type :emit
                 :event :chunked-artifact-failed
                 :generation (:generation st2)
                 :manifest-cid (:manifest-cid st2)
                 :reason kind}]]))

;; =============================================================================
;; 4. Pure State Machine Reducer: (transition state event) -> [new-state effects]
;; =============================================================================

(defn transition
  "Pure Sans-IO state transition function `(transition state event) -> [new-state effects]`.
   Ignores stale generations (`ev-gen < current`) with a counted `:ignored-stale-chunk`
   `:diagnose` effect and zero operational state mutation."
  [state event]
  (let [ev-type (:type event)
        cur-gen (long (:generation state))
        ev-gen (long (or (:generation event) cur-gen))]
    (cond
      ;; Stale generation guard (Rule 4 & Rule 5): zero operational state mutation
      (< ev-gen cur-gen)
      (let [[st2 d-eff] (record-diagnose state :ignored-stale-chunk
                                         (str "stale-generation:" ev-gen "<" cur-gen)
                                         {:event-type ev-type :stale-generation ev-gen})]
        [st2 [d-eff]])

      :else
      (case ev-type
        (:start :resume)
        (let [new-gen (max cur-gen ev-gen)
              cached-set (set (or (:cached-indices event) #{}))
              chunks (get-in state [:manifest "chunks"])
              ;; Merge newly reported cached indices with already staged chunks
              staged-after-cache
              (reduce (fn [acc idx]
                        (if (and (>= idx 0) (< idx (:total-chunks state)))
                          (let [ch (nth chunks idx)]
                            (assoc acc idx {:cid (get ch "cid")
                                            :size (long (get ch "size"))
                                            :verified? true}))
                          acc))
                      (:staged-chunks state)
                      cached-set)
              status-after-cache
              (reduce (fn [acc idx]
                        (cond
                          (< idx (:hash-cursor state)) (assoc acc idx :hashed)
                          (contains? staged-after-cache idx) (assoc acc idx :staged)
                          :else (assoc acc idx :pending)))
                      {}
                      (range (:total-chunks state)))
              st1 (-> state
                      (assoc :generation new-gen
                             :phase :fetching
                             :blacklisted-mirrors #{}
                             :in-flight {}
                             :hash-in-flight? false
                             :cached-chunks (into (:cached-chunks state) cached-set)
                             :staged-chunks staged-after-cache
                             :chunk-status status-after-cache)
                      (recompute-byte-accounting))
              [st2 effs-fetch] (schedule-pending-chunks st1)
              [st3 effs-hash] (maybe-advance-hash-cursor st2)]
          [st3 (into effs-fetch effs-hash)])

        :pause
        [(assoc state :phase :paused :in-flight {} :hash-in-flight? false)
         [{:type :emit
           :event :chunked-artifact-paused
           :generation (:generation state)
           :manifest-cid (:manifest-cid state)}]]

        :chunk-fetched
        (let [idx (:index event)
              mirror (:mirror event)
              actual-cid (:cid event)
              actual-size (long (or (:size event) -1))
              ch (when (and (integer? idx) (>= idx 0) (< idx (:total-chunks state)))
                   (nth (get-in state [:manifest "chunks"]) idx))
              expected-cid (when ch (get ch "cid"))
              expected-size (when ch (long (get ch "size")))]
          (cond
            (not= :fetching (:phase state))
            (let [[st2 d-eff] (record-diagnose state :ignored-chunk-wrong-phase
                                               (str "chunk-fetched-in-phase:" (name (:phase state)))
                                               {:index idx})]
              [st2 [d-eff]])

            (nil? ch)
            (let [[st2 d-eff] (record-diagnose state :invalid-chunk-index
                                               (str "invalid-chunk-index:" idx)
                                               {:index idx})]
              [st2 [d-eff]])

            (not= actual-size expected-size)
            (let [[st-d d-eff] (record-diagnose state :chunk-size-mismatch
                                                (str "chunk-" idx "-size-" actual-size "-expected-" expected-size)
                                                {:index idx :mirror mirror :actual-size actual-size :expected-size expected-size})
                  retries (inc (long (get-in st-d [:retries idx] 0)))
                  st-bl (-> st-d
                            (update :in-flight dissoc idx)
                            (update :blacklisted-mirrors conj mirror)
                            (assoc-in [:retries idx] retries)
                            (assoc-in [:chunk-status idx] :pending))]
              (if (or (>= retries (:max-retries st-bl))
                      (empty? (healthy-mirrors st-bl)))
                (let [[st-f f-effs] (fail-fetch st-bl :chunk-retries-exhausted
                                                (str "chunk-" idx "-exhausted-after-size-mismatch")
                                                {:index idx})]
                  [st-f (into [d-eff] f-effs)])
                (let [[st-s s-effs] (schedule-pending-chunks st-bl)]
                  [st-s (into [d-eff] s-effs)])))

            (not= actual-cid expected-cid)
            (let [[st-d d-eff] (record-diagnose state :chunk-cid-mismatch
                                                (str "chunk-" idx "-cid-mismatch")
                                                {:index idx :mirror mirror :actual-cid actual-cid :expected-cid expected-cid})
                  retries (inc (long (get-in st-d [:retries idx] 0)))
                  st-bl (-> st-d
                            (update :in-flight dissoc idx)
                            (update :blacklisted-mirrors conj mirror)
                            (assoc-in [:retries idx] retries)
                            (assoc-in [:chunk-status idx] :pending))]
              (if (or (>= retries (:max-retries st-bl))
                      (empty? (healthy-mirrors st-bl)))
                (let [[st-f f-effs] (fail-fetch st-bl :chunk-retries-exhausted
                                                (str "chunk-" idx "-exhausted-after-cid-mismatch")
                                                {:index idx})]
                  [st-f (into [d-eff] f-effs)])
                (let [[st-s s-effs] (schedule-pending-chunks st-bl)]
                  [st-s (into [d-eff] s-effs)])))

            :else
            (let [st1 (-> state
                          (update :in-flight dissoc idx)
                          (assoc-in [:staged-chunks idx] {:cid expected-cid :size expected-size :verified? true})
                          (assoc-in [:chunk-status idx] :staged)
                          (recompute-byte-accounting))
                  stage-eff {:type :stage-chunk
                             :generation (:generation st1)
                             :index idx
                             :cid expected-cid
                             :size expected-size}
                  [st2 effs-fetch] (schedule-pending-chunks st1)
                  [st3 effs-hash] (maybe-advance-hash-cursor st2)]
              [st3 (into (into [stage-eff] effs-fetch) effs-hash)])))

        :chunk-http-error
        (let [idx (:index event)
              mirror (:mirror event)
              status (long (or (:status event) 0))
              reason (or (:reason event) (str "http-" status))]
          (cond
            ;; HTTP 410 Gone: NEVER blacklist mirror, NEVER count :chunk-fetch-failed
            (= 410 status)
            (let [[st1 d-gone] (record-diagnose state :chunk-gone
                                                (str "chunk-" idx "-http-410-gone")
                                                {:index idx :mirror mirror :status 410})
                  [st2 d-grace] (record-diagnose st1 :grace-expired
                                                 (str "chunk-" idx "-grace-expired")
                                                 {:index idx :mirror mirror :status 410})
                  st3 (-> st2
                          (assoc :phase :failed :in-flight {} :hash-in-flight? false)
                          (assoc-in [:chunk-status idx] :failed))]
              [st3 [d-gone d-grace {:type :emit
                                    :event :chunked-artifact-failed
                                    :generation (:generation st3)
                                    :manifest-cid (:manifest-cid st3)
                                    :reason :chunk-gone}]])

            ;; HTTP 507 Insufficient Storage: quota exceeded, do NOT blacklist mirror
            (= 507 status)
            (fail-fetch state :chunk-store-quota-exceeded
                        (str "chunk-" idx "-http-507-quota-exceeded")
                        {:index idx :mirror mirror :status 507})

            :else
            (let [[st-d d-eff] (record-diagnose state :chunk-fetch-failed
                                                (str "chunk-" idx "-http-" status ":" reason)
                                                {:index idx :mirror mirror :status status})
                  retries (inc (long (get-in st-d [:retries idx] 0)))
                  st-q (-> st-d
                           (update :in-flight dissoc idx)
                           (assoc-in [:retries idx] retries)
                           (assoc-in [:chunk-status idx] :pending))]
              (if (>= retries (:max-retries st-q))
                (let [[st-f f-effs] (fail-fetch st-q :chunk-retries-exhausted
                                                (str "chunk-" idx "-http-retries-exhausted")
                                                {:index idx})]
                  [st-f (into [d-eff] f-effs)])
                (let [[st-s s-effs] (schedule-pending-chunks st-q)]
                  [st-s (into [d-eff] s-effs)])))))

        :cache-evicted
        (let [idx (:index event)
              [st-d d-eff] (record-diagnose state :cache-evicted
                                            (str "chunk-" idx "-evicted-from-cache")
                                            {:index idx})]
          (if (< (long idx) (long (:hash-cursor st-d)))
            ;; Already hashed into running digest; just record diagnostic & drop from cached set
            [(update st-d :cached-chunks disj idx) [d-eff]]
            (let [st-q (-> st-d
                           (update :cached-chunks disj idx)
                           (update :staged-chunks dissoc idx)
                           (assoc-in [:chunk-status idx] :pending)
                           (assoc :hash-in-flight? (if (= idx (:hash-cursor st-d)) false (:hash-in-flight? st-d)))
                           (recompute-byte-accounting))
                  [st-s s-effs] (schedule-pending-chunks st-q)]
              [st-s (into [d-eff] s-effs)])))

        :digest-result
        (let [idx (:index event)
              ok? (boolean (:ok? event))]
          (cond
            (not ok?)
            (let [[st-d d-eff] (record-diagnose state :staged-chunk-corrupt
                                                (str "staged-chunk-" idx "-corrupt:" (or (:reason event) "digest-error"))
                                                {:index idx})
                  retries (inc (long (get-in st-d [:retries idx] 0)))
                  st-q (-> st-d
                           (update :staged-chunks dissoc idx)
                           (update :cached-chunks disj idx)
                           (assoc :hash-in-flight? false)
                           (assoc-in [:retries idx] retries)
                           (assoc-in [:chunk-status idx] :pending)
                           (recompute-byte-accounting))]
              (if (>= retries (:max-retries st-q))
                (let [[st-f f-effs] (fail-fetch st-q :chunk-retries-exhausted
                                                (str "staged-chunk-" idx "-corrupt-retries-exhausted")
                                                {:index idx})]
                  [st-f (into [d-eff] f-effs)])
                (let [[st-s s-effs] (schedule-pending-chunks st-q)]
                  [st-s (into [d-eff] s-effs)])))

            (not= idx (:hash-cursor state))
            (let [[st-d d-eff] (record-diagnose state :out-of-order-digest-result
                                                (str "digest-index-" idx "-neq-cursor-" (:hash-cursor state))
                                                {:index idx :hash-cursor (:hash-cursor state)})]
              [st-d [d-eff]])

            :else
            (let [st1 (-> state
                          (assoc :hash-cursor (inc (long idx))
                                 :hash-in-flight? false)
                          (assoc-in [:chunk-status idx] :hashed)
                          (recompute-byte-accounting))
                  [st2 effs-hash] (maybe-advance-hash-cursor st1)]
              [st2 effs-hash])))

        :digest-final
        (let [actual-sha (:sha256 event)
              expected-sha (:total-sha256 state)]
          (if (= actual-sha expected-sha)
            (let [st-done (assoc state :phase :complete :hash-in-flight? false :in-flight {})]
              [st-done [{:type :emit
                         :event :chunked-artifact-complete
                         :generation (:generation st-done)
                         :manifest-cid (:manifest-cid st-done)
                         :total-sha256 expected-sha
                         :total-bytes (:total-bytes st-done)}]])
            (fail-fetch state :total-sha256-mismatch
                        (str "total-sha256-mismatch:actual=" actual-sha ":expected=" expected-sha)
                        {:actual-sha256 actual-sha :expected-sha256 expected-sha})))

        ;; Unknown event type -> counted diagnose (Rule 5)
        (let [[st2 d-eff] (record-diagnose state :unknown-chunk-fetch-event
                                           (str "unknown-event:" ev-type)
                                           {:event-type ev-type})]
          [st2 [d-eff]])))))
