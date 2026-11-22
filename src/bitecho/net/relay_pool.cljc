(ns bitecho.net.relay-pool
  "Pure Sans-IO multi-relay pool health state machine and mechanical sync-stall classifier (BIP-018 Track 3).
   Conforms strictly to AGENTS.md Rules 1, 2, 4, and 5:
   - Single-authority generation-tagged map updated exclusively via `(transition pool event) -> [new-pool effects]`.
   - Never hardcodes `ns1` as sole primary; selects lowest-RTT healthy (or cooldown-expired) relay.
   - Exponential cooldown schedule: 5000ms -> 15000ms -> 60000ms.
   - Zero silent failures: every failover, stale-epoch demotion, recovery, or ignored stale-generation
     callback emits a counted `:diagnose` effect."
  (:require [clojure.string :as str]))

(def default-cooldown-schedule-ms
  "Exponential cooldown schedule in milliseconds for consecutive relay failures or stale epochs."
  [5000 15000 60000])

(def default-max-epoch-lag
  "Maximum finalized-epoch lag behind max peer finalized epoch before demoting a relay."
  6)

(def default-ewma-alpha
  "EWMA smoothing factor for relay RTT tracking."
  0.3)

(def default-initial-rtt-ms
  "Initial EWMA RTT estimate (ms) before the first observed response."
  100.0)

(defn- normalize-url
  [u]
  (when (and (string? u) (not (str/blank? u)))
    (str/replace (str/trim u) #"/+$" "")))

(defn- cooldown-for-failures
  [failures]
  (let [idx (max 0 (min (dec (count default-cooldown-schedule-ms))
                        (dec (long failures))))]
    (nth default-cooldown-schedule-ms idx)))

(defn init-relay-pool
  "Initializes a single-authority generation-tagged relay pool map from `relay-urls` and optional `opts`.
   Preserves caller-provided URL order without hardcoding `ns1` as sole primary."
  ([relay-urls]
   (init-relay-pool relay-urls nil))
  ([relay-urls opts]
   (let [norm-urls (->> (or relay-urls [])
                        (keep normalize-url)
                        distinct
                        vec)
         gen (long (or (:generation opts) 1))
         max-lag (long (or (:max-epoch-lag opts) default-max-epoch-lag))
         alpha (double (or (:ewma-alpha opts) default-ewma-alpha))
         quorum (long (or (:quorum opts) (max 1 (min 2 (count norm-urls)))))
         relays (into {}
                      (map (fn [u]
                             [u {:url u
                                 :status :healthy
                                 :ewma-rtt-ms default-initial-rtt-ms
                                 :rtt-samples 0
                                 :failures 0
                                 :cooldown-until-ms 0
                                 :finalized-epoch 0
                                 :last-error nil}]))
                      norm-urls)]
     {:generation gen
      :relays relays
      :order norm-urls
      :quorum quorum
      :max-epoch-lag max-lag
      :ewma-alpha alpha
      :diagnostics {:relay-failover 0
                    :relay-stale-epoch 0
                    :ignored-stale 0
                    :relay-recovered 0}})))

(defn- relay-eligible?
  [relay now-ms]
  (let [cd (long (or (:cooldown-until-ms relay) 0))
        st (:status relay)]
    (or (= :healthy st)
        (<= cd (long now-ms)))))

(defn select-healthy-relay
  "Selects the lowest-RTT healthy (or cooldown-expired) relay URL not in `exclude-set`.
   Uses `:order` index as deterministic tie-breaker. Returns URL string or `nil`."
  ([pool now-ms]
   (select-healthy-relay pool now-ms #{}))
  ([pool now-ms exclude-set]
   (let [excl (set (keep normalize-url (or exclude-set #{})))
         order-idx (into {} (map-indexed (fn [i u] [u i]) (:order pool)))
         candidates (->> (:order pool)
                         (remove excl)
                         (map #(get-in pool [:relays %]))
                         (filter #(and (some? %) (relay-eligible? % now-ms)))
                         (sort-by (fn [r]
                                    [(double (or (:ewma-rtt-ms r) default-initial-rtt-ms))
                                     (long (get order-idx (:url r) 0))])))]
     (:url (first candidates)))))

(defn- max-peer-finalized-epoch
  [relays]
  (reduce (fn [acc [_ r]]
            (max acc (long (or (:finalized-epoch r) 0))))
          0
          relays))

(defn transition
  "Pure generation-tagged reducer `(transition pool event) -> [new-pool effects]`.
   Handles:
   - Stale generations (`(< (:generation event) (:generation pool))`): counted `:ignored-stale`.
   - `:request-ok`: updates EWMA RTT, resets failures/cooldown, tracks recovery, and demotes relays
     whose `:finalized-epoch` lags more than `:max-epoch-lag` (default 6) behind max peer epoch.
   - `:request-failed`: increments failures, applies exponential cooldown (5s -> 15s -> 60s), selects
     next healthy relay, and emits counted `:relay-failover` diagnostic."
  [pool event]
  (let [curr-gen (long (:generation pool 1))
        ev-gen (:generation event)
        now-ms (long (or (:now-ms event) 0))]
    (if (and (some? ev-gen) (< (long ev-gen) curr-gen))
      (let [diag {:type :diagnose
                  :reason :ignored-stale
                  :generation (long ev-gen)
                  :current-generation curr-gen
                  :event-type (:type event)}
            next-pool (update-in pool [:diagnostics :ignored-stale] (fnil inc 0))]
        [next-pool [diag]])
      (case (:type event)
        :request-ok
        (let [url (normalize-url (:url event))
              prev (get-in pool [:relays url])]
          (if-not prev
            [pool []]
            (let [rtt (double (max 0.0 (double (or (:rtt-ms event) default-initial-rtt-ms))))
                  alpha (double (or (:ewma-alpha pool) default-ewma-alpha))
                  samples (long (or (:rtt-samples prev) 0))
                  new-ewma (if (zero? samples)
                             rtt
                             (+ (* alpha rtt) (* (- 1.0 alpha) (double (:ewma-rtt-ms prev default-initial-rtt-ms)))))
                  was-degraded? (or (not= :healthy (:status prev))
                                    (pos? (long (or (:failures prev) 0))))
                  fin-ep (if (some? (:finalized-epoch event))
                           (long (:finalized-epoch event))
                           (long (or (:finalized-epoch prev) 0)))
                  updated-relays (assoc (:relays pool)
                                        url
                                        (assoc prev
                                               :status :healthy
                                               :ewma-rtt-ms new-ewma
                                               :rtt-samples (inc samples)
                                               :failures 0
                                               :cooldown-until-ms 0
                                               :finalized-epoch fin-ep
                                               :last-error nil))
                  max-ep (max-peer-finalized-epoch updated-relays)
                  max-lag (long (or (:max-epoch-lag pool) default-max-epoch-lag))
                  stale-epoch? (and (some? (:finalized-epoch event))
                                    (> (- max-ep fin-ep) max-lag))]
              (if stale-epoch?
                (let [next-fails (inc (long (or (:failures prev) 0)))
                      cd-ms (cooldown-for-failures next-fails)
                      demoted-relay (assoc (get updated-relays url)
                                           :status :stale-epoch
                                           :failures next-fails
                                           :cooldown-until-ms (+ now-ms cd-ms)
                                           :last-error :relay-stale-epoch)
                      diag {:type :diagnose
                            :reason :relay-stale-epoch
                            :url url
                            :finalized-epoch fin-ep
                            :max-peer-epoch max-ep
                            :lag (- max-ep fin-ep)
                            :cooldown-ms cd-ms
                            :generation curr-gen}
                      next-pool (-> pool
                                    (assoc :relays (assoc updated-relays url demoted-relay))
                                    (update-in [:diagnostics :relay-stale-epoch] (fnil inc 0)))]
                  [next-pool [diag]])
                (if was-degraded?
                  (let [diag {:type :diagnose
                              :reason :relay-recovered
                              :url url
                              :ewma-rtt-ms new-ewma
                              :finalized-epoch fin-ep
                              :generation curr-gen}
                        next-pool (-> pool
                                      (assoc :relays updated-relays)
                                      (update-in [:diagnostics :relay-recovered] (fnil inc 0)))]
                    [next-pool [diag]])
                  [(assoc pool :relays updated-relays) []])))))

        :request-failed
        (let [url (normalize-url (:url event))
              prev (get-in pool [:relays url])]
          (if-not prev
            [pool []]
            (let [next-fails (inc (long (or (:failures prev) 0)))
                  cd-ms (cooldown-for-failures next-fails)
                  err-val (or (:error event) (:status event) :request-failed)
                  degraded-relay (assoc prev
                                        :status :degraded
                                        :failures next-fails
                                        :cooldown-until-ms (+ now-ms cd-ms)
                                        :last-error err-val)
                  pool1 (-> pool
                            (assoc-in [:relays url] degraded-relay)
                            (update-in [:diagnostics :relay-failover] (fnil inc 0)))
                  next-url (select-healthy-relay pool1 now-ms #{url})
                  diag {:type :diagnose
                        :reason :relay-failover
                        :from url
                        :to next-url
                        :chunk-idx (:chunk-idx event)
                        :status (:status event)
                        :error err-val
                        :failures next-fails
                        :cooldown-ms cd-ms
                        :generation curr-gen}]
              [pool1 [diag]])))

        [pool []]))))

(defn classify-sync-stall
  "Pure mechanical classifier separating:
   - `:healthy`: all relays healthy and quorum advancing beyond `local-epoch` within `max-lag`.
   - `:relay-degraded`: one or more relays down or lagging > `max-lag`, while healthy quorum relays
     advance beyond `local-epoch`.
   - `:chain-stalled`: healthy quorum relays are stalled at or below `local-epoch` (or no healthy quorum)."
  ([local-epoch relay-observations]
   (classify-sync-stall local-epoch relay-observations default-max-epoch-lag))
  ([local-epoch relay-observations max-lag]
   (let [loc (long (or local-epoch 0))
         lag-cap (long (or max-lag default-max-epoch-lag))
         obs (vec (or relay-observations []))
         total (count obs)
         quorum (if (>= total 2) (inc (quot total 2)) 1)
         healthy (filterv #(and (true? (:ok? %)) (some? (:finalized-epoch %))) obs)
         failed (filterv #(not (true? (:ok? %))) obs)
         max-healthy (when (seq healthy)
                       (reduce max (map #(long (:finalized-epoch %)) healthy)))
         stale (if (some? max-healthy)
                 (filterv #(> (- (long max-healthy) (long (:finalized-epoch %))) lag-cap) healthy)
                 [])
         quorum-healthy (filterv #(<= (- (long (or max-healthy 0)) (long (:finalized-epoch %))) lag-cap) healthy)
         quorum-met? (>= (count quorum-healthy) quorum)
         advancing? (and (some? max-healthy) (> (long max-healthy) loc))
         classification (cond
                          (not quorum-met?)
                          :chain-stalled

                          (not advancing?)
                          :chain-stalled

                          (or (seq failed) (seq stale))
                          :relay-degraded

                          :else
                          :healthy)]
     {:classification classification
      :local-epoch loc
      :max-healthy-epoch max-healthy
      :quorum quorum
      :quorum-met? quorum-met?
      :healthy-count (count quorum-healthy)
      :failed-urls (mapv :url failed)
      :stale-urls (mapv :url stale)})))
