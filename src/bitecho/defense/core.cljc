(ns bitecho.defense.core
  "Milestone D38 (`BIP-013` / `v0.23.16`): Pure Sans-IO Built-In Request Defense Engine (`P-OBS-6`, `Rule 2`, `Rule 5`).
   Fail2ban-class ingress defense for HTTP / DNS / Relay shells:
   - Per-source token buckets & rate windows
   - Strike counting (`:malformed`, `:auth-failed`, `:invalid-sig`, `:rate-exceeded`)
   - Escalating actions (`:allow` -> `:throttle` -> `:drop` -> `:ban` with timed expiry)
   - Strict fail-open exemptions for authenticated consensus & peer traffic (`:validator-sync`, `:p2p-session`, `:authenticated-peer`)
   - Exact defense counters + rate-capped detail sampling under flood
   - Pointer-delivered policy updates and `P-OBS-1` telemetry records with HMAC-SHA256 hashed source IDs (never raw IPs)."
  (:require [bitecho.observability.core :as obs]
            [clojure.string :as str]))

(def consensus-fail-open-classes
  "Traffic classes that consensus depends on — defense MUST always fail open for authenticated requests in these classes."
  #{:validator-sync :p2p-session :authenticated-peer})

(def default-defense-policy
  "Default P-OBS-6 defense policy (pointer-deliverable under `config/<network>/`)."
  {:enabled? true
   :window-ms 60000
   :token-bucket-capacity 60
   :refill-per-sec 10
   :throttle-threshold 3
   :drop-threshold 6
   :ban-threshold 10
   :ban-duration-ms 300000
   :strike-weights {:malformed 2
                    :auth-failed 3
                    :invalid-sig 4
                    :rate-exceeded 1}
   :detail-sample-cap-per-window 16
   :allowlist-pubkeys #{}
   :allowlist-source-hashes #{}
   :hmac-salt "bitecho-defense-v1"})

(defn init-defense-state
  "Initializes single-authority pure defense state."
  ([]
   (init-defense-state nil))
  ([policy-overrides]
   (let [policy (merge default-defense-policy (when (map? policy-overrides) policy-overrides))]
     {:policy policy
      :sources {}
      :detail-window-start-ms 0
      :detail-emitted-in-window 0
      :next-obs-seq 1
      :counters {:allowed 0
                 :throttled 0
                 :dropped 0
                 :banned 0
                 :exempt-allowed 0
                 :strikes-by-class {}}
      :diagnostics {}})))

(defn apply-defense-policy-pointer
  "Updates defense policy from a pointer-delivered config map."
  [defense-state policy-map]
  (if-not (map? policy-map)
    defense-state
    (update defense-state :policy merge policy-map)))

(defn- normalize-pk
  [pk]
  (when (and (string? pk) (not (str/blank? pk)))
    (str/lower-case (str/trim pk))))

(defn- exempt-request?
  [policy {:keys [traffic-class authenticated? source-pubkey]} source-hash]
  (let [tc (keyword (or traffic-class :unauthenticated-ingress))
        pk (normalize-pk source-pubkey)
        allow-pks (set (keep normalize-pk (:allowlist-pubkeys policy)))
        allow-hashes (set (:allowlist-source-hashes policy))]
    (or (and (true? authenticated?)
             (contains? consensus-fail-open-classes tc))
        (and pk (contains? allow-pks pk))
        (contains? allow-hashes source-hash))))

(defn- refill-tokens
  [bucket now-ms capacity refill-per-sec]
  (let [last-ms (long (or (:last-refill-ms bucket) now-ms))
        elapsed-ms (max 0 (- now-ms last-ms))
        added (* (/ (double elapsed-ms) 1000.0) (double refill-per-sec))
        tokens (min (double capacity) (+ (double (or (:tokens bucket) capacity)) added))]
    {:tokens tokens :last-refill-ms now-ms}))

(defn- maybe-emit-obs-effect
  [st now-ms policy source-hash action decision route]
  (let [win-ms (long (:window-ms policy 60000))
        win-start (long (:detail-window-start-ms st 0))
        reset-win? (or (zero? win-start) (>= (- now-ms win-start) win-ms))
        cur-start (if reset-win? now-ms win-start)
        cur-emitted (if reset-win? 0 (long (:detail-emitted-in-window st 0)))
        cap (long (:detail-sample-cap-per-window policy 16))]
    (if (< cur-emitted cap)
      (let [obs-seq (long (:next-obs-seq st 1))
            rec {:schema "bitecho-obs-record-v1"
                 :node-id "defense"
                 :seq obs-seq
                 :step :ingress-defense
                 :level (case action :ban :error :drop :warn :throttle :warn :info)
                 :duration-ms 0
                 :delta-summary {:action action}
                 :data {:source-hash source-hash
                        :route (str (or route "/"))
                        :action action
                        :strikes (:strikes decision 0)
                        :ban-until-ms (:ban-until-ms decision)}}]
        [(assoc st
                :detail-window-start-ms cur-start
                :detail-emitted-in-window (inc cur-emitted)
                :next-obs-seq (inc obs-seq))
         {:effect :obs-record :record rec}])
      [(assoc st
              :detail-window-start-ms cur-start
              :detail-emitted-in-window cur-emitted)
       nil])))

(defn evaluate-request
  "Pure P-OBS-6 ingress request evaluation:
   `(evaluate-request defense-state req-event) -> [new-defense-state decision effects]`.
   - Authenticated consensus/peer traffic ALWAYS fails open (`:allow`, `:exempt? true`).
   - Unauthenticated ingress abuse escalates `:allow` -> `:throttle` -> `:drop` -> `:ban` with expiry.
   - Emits rate-capped `P-OBS-1` telemetry records (hashed source IDs only) and counted `:diagnose` on throttle/drop/ban."
  [defense-state req-event]
  (let [policy (:policy defense-state default-defense-policy)
        now-ms (long (or (:now-ms req-event) 0))
        source-hash (obs/hash-source-id (:source-id req-event) (:hmac-salt policy))
        route (:route req-event)]
    (cond
      (not (true? (:enabled? policy)))
      [defense-state {:action :allow :exempt? false :source-hash source-hash} []]

      (exempt-request? policy req-event source-hash)
      (let [st' (update-in defense-state [:counters :exempt-allowed] (fnil inc 0))]
        [st' {:action :allow :exempt? true :source-hash source-hash} []])

      :else
      (let [src0 (get-in defense-state [:sources source-hash]
                         {:tokens (double (:token-bucket-capacity policy 60))
                          :last-refill-ms now-ms
                          :window-start-ms now-ms
                          :strikes 0
                          :ban-until-ms 0})
            ;; Check timed ban expiry
            ban-until (long (or (:ban-until-ms src0) 0))
            ban-active? (> ban-until now-ms)
            ban-expired? (and (pos? ban-until) (<= ban-until now-ms))
            src1 (if ban-expired?
                   (assoc src0
                          :ban-until-ms 0
                          :strikes 0
                          :tokens (double (:token-bucket-capacity policy 60))
                          :last-refill-ms now-ms
                          :window-start-ms now-ms)
                   src0)]
        (if ban-active?
          (let [decision {:action :ban
                          :exempt? false
                          :source-hash source-hash
                          :strikes (:strikes src1)
                          :ban-until-ms ban-until
                          :reason :active-ban}
                st1 (-> defense-state
                        (update-in [:counters :banned] (fnil inc 0))
                        (update-in [:diagnostics :defense-ban-enforced] (fnil inc 0)))
                [st2 obs-eff] (maybe-emit-obs-effect st1 now-ms policy source-hash :ban decision route)
                diag {:effect :diagnose
                      :type :diagnose
                      :reason :defense-ban-enforced
                      :source-hash source-hash
                      :ban-until-ms ban-until}
                effs (cond-> [diag] obs-eff (conj obs-eff))]
            [st2 decision effs])
          (let [win-ms (long (:window-ms policy 60000))
                win-expired? (>= (- now-ms (long (or (:window-start-ms src1) now-ms))) win-ms)
                base-strikes (if win-expired? 0 (long (or (:strikes src1) 0)))
                win-start (if win-expired? now-ms (long (or (:window-start-ms src1) now-ms)))
                refilled (refill-tokens src1 now-ms
                                        (:token-bucket-capacity policy 60)
                                        (:refill-per-sec policy 10))
                has-token? (>= (:tokens refilled) 1.0)
                tokens-after (if has-token? (- (:tokens refilled) 1.0) 0.0)
                violation (or (:violation req-event)
                              (when-not has-token? :rate-exceeded))
                weight (if violation
                         (long (get-in policy [:strike-weights violation] 1))
                         0)
                new-strikes (+ base-strikes weight)
                action (cond
                         (>= new-strikes (long (:ban-threshold policy 10))) :ban
                         (>= new-strikes (long (:drop-threshold policy 6))) :drop
                         (>= new-strikes (long (:throttle-threshold policy 3))) :throttle
                         :else :allow)
                new-ban-until (if (= action :ban)
                                (+ now-ms (long (:ban-duration-ms policy 300000)))
                                0)
                src2 {:tokens tokens-after
                      :last-refill-ms now-ms
                      :window-start-ms win-start
                      :strikes new-strikes
                      :ban-until-ms new-ban-until}
                counter-kw (case action
                             :allow :allowed
                             :throttle :throttled
                             :drop :dropped
                             :ban :banned)
                decision {:action action
                          :exempt? false
                          :source-hash source-hash
                          :strikes new-strikes
                          :violation violation
                          :ban-until-ms (when (pos? new-ban-until) new-ban-until)}
                st1 (-> defense-state
                        (assoc-in [:sources source-hash] src2)
                        (update-in [:counters counter-kw] (fnil inc 0))
                        (cond-> violation
                          (update-in [:counters :strikes-by-class violation] (fnil inc 0)))
                        (cond-> (not= action :allow)
                          (update-in [:diagnostics (keyword (str "defense-" (name action)))] (fnil inc 0))))
                [st2 obs-eff] (if (not= action :allow)
                                (maybe-emit-obs-effect st1 now-ms policy source-hash action decision route)
                                [st1 nil])
                diag (when (not= action :allow)
                       {:effect :diagnose
                        :type :diagnose
                        :reason (keyword (str "defense-" (name action)))
                        :source-hash source-hash
                        :strikes new-strikes
                        :violation violation})
                effs (cond-> []
                       diag (conj diag)
                       obs-eff (conj obs-eff))]
            [st2 decision effs]))))))

(defn defense-digest-counters
  "Returns exact P-OBS-6 defense counters suitable for inclusion in P-OBS-4 published digests."
  [defense-state]
  (let [c (:counters defense-state {})]
    {:allowed (long (:allowed c 0))
     :throttled (long (:throttled c 0))
     :dropped (long (:dropped c 0))
     :banned (long (:banned c 0))
     :exempt-allowed (long (:exempt-allowed c 0))
     :strikes-by-class (or (:strikes-by-class c) {})
     :active-sources (count (:sources defense-state {}))}))
