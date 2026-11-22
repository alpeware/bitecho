(ns bitecho.ops.incident
  "Pure Sans-IO incident postmortem schema validator (`:bitecho/incident-postmortem-v1`),
   compact public `GET /status` snapshot builder, and sliding-window IP rate limiter (BIP-018 Track 4).
   Conforms strictly to AGENTS.md Rules 1, 2, and 5."
  (:require [clojure.string :as str]))

(def postmortem-schema-id
  "Canonical schema identifier for Bitecho blameless incident postmortem EDN records."
  :bitecho/incident-postmortem-v1)

(def valid-severities
  "Allowed incident severity tiers."
  #{:sev-1 :sev-2 :sev-3})

(def required-slo-tracks
  "All three mandatory SLO tracks required in every incident postmortem."
  [:consensus-finality :edge-fleet :single-relay-client])

(def default-status-rate-limit
  "Default maximum public `GET /status` requests per IP per minute."
  60)

(def default-status-window-ms
  "Sliding window duration (ms) for public `GET /status` rate limiting."
  60000)

(def default-status-retry-after-sec
  "Retry-After header duration (seconds) returned on HTTP 429."
  5)

(defn- non-blank-str?
  [v]
  (and (string? v) (not (str/blank? v))))

(defn- valid-cid64?
  [v]
  (and (string? v) (boolean (re-matches #"[0-9a-f]{64}" (str/lower-case (str/trim v))))))

(defn validate-postmortem-record
  "Validates a `:bitecho/incident-postmortem-v1` EDN record.
   Returns `{:ok? bool :errors [...] :diagnostics [...]}` with counted `:diagnose` effects on failure."
  [rec]
  (let [errors
        (cond-> []
          (not (map? rec))
          (conj :not-a-map)

          (and (map? rec) (not= postmortem-schema-id (:schema rec)))
          (conj :invalid-schema-id)

          (and (map? rec) (not (non-blank-str? (:incident-id rec))))
          (conj :missing-incident-id)

          (and (map? rec) (not (contains? valid-severities (:severity rec))))
          (conj :invalid-severity)

          (and (map? rec) (not (non-blank-str? (:window-utc rec))))
          (conj :missing-window-utc)

          (and (map? rec) (not (non-blank-str? (:window-cst rec))))
          (conj :missing-window-cst)

          (and (map? rec) (not (and (number? (:detection-lag-min rec))
                                    (not (neg? (double (:detection-lag-min rec)))))))
          (conj :invalid-detection-lag-min)

          (and (map? rec)
               (let [slo (:slo-breakdown rec)]
                 (or (not (map? slo))
                     (not (every? (fn [k]
                                    (let [entry (get slo k)]
                                      (and (map? entry)
                                           (number? (:error-budget-burn-pct entry)))))
                                  required-slo-tracks)))))
          (conj :invalid-slo-breakdown)

          (and (map? rec)
               (let [hyps (:hypotheses rec)]
                 (or (not (vector? hyps))
                     (empty? hyps)
                     (not (every? (fn [h]
                                    (and (map? h)
                                         (non-blank-str? (:claim h))
                                         (contains? #{:verified :falsified} (:status h))
                                         (or (= :verified (:status h))
                                             (non-blank-str? (:falsifier h)))))
                                  hyps)))))
          (conj :invalid-hypotheses)

          (and (map? rec)
               (let [items (:action-items rec)]
                 (or (not (vector? items))
                     (empty? items)
                     (not (every? (fn [a]
                                    (and (map? a)
                                         (non-blank-str? (:bip-id a))
                                         (non-blank-str? (:invariant-test a))))
                                  items)))))
          (conj :invalid-action-items)

          (and (map? rec)
               (let [cids (:evidence-cids rec)]
                 (or (not (vector? cids))
                     (empty? cids)
                     (not (every? valid-cid64? cids)))))
          (conj :invalid-evidence-cids))
        diags (mapv (fn [err]
                      {:type :diagnose
                       :reason :postmortem-validation-failed
                       :error err
                       :incident-id (when (map? rec) (:incident-id rec))})
                    errors)]
    {:ok? (empty? errors)
     :errors errors
     :diagnostics diags}))

(defn build-status-snapshot
  "Builds a compact (~2 KiB) JSON-ready map for public `GET /status`."
  [{:keys [finalized-epoch release-seq relays error-budget updated-at-ms ok?]}]
  {:ok (if (some? ok?) (boolean ok?) true)
   :finalized_epoch (long (or finalized-epoch 0))
   :release_seq (long (or release-seq 0))
   :relays (mapv (fn [r]
                   {:url (str (:url r))
                    :status (if (keyword? (:status r)) (name (:status r)) (str (or (:status r) "unknown")))
                    :ewma_rtt_ms (double (or (:ewma-rtt-ms r) (:ewma_rtt_ms r) 0.0))
                    :finalized_epoch (long (or (:finalized-epoch r) (:finalized_epoch r) 0))})
                 (or relays []))
   :error_budget (or error-budget
                     {:consensus_finality_pct 100.0
                      :edge_fleet_pct 100.0
                      :single_relay_client_pct 100.0})
   :updated_at_ms (long (or updated-at-ms 0))})

(defn init-status-rate-limiter
  "Initializes a pure sliding-window IP rate limiter for `GET /status` (default 60 req/min/IP)."
  ([]
   (init-status-rate-limiter nil))
  ([opts]
   {:limit (long (or (:limit opts) default-status-rate-limit))
    :window-ms (long (or (:window-ms opts) default-status-window-ms))
    :retry-after-sec (long (or (:retry-after-sec opts) default-status-retry-after-sec))
    :buckets {}
    :diagnostics {:rate-limited 0}}))

(defn check-status-rate-limit
  "Evaluates the sliding-window rate limit for `ip` at `now-ms`.
   Returns `{:allowed? bool :retry-after-sec int :remaining int :state new-state :diagnose diag-or-nil}`."
  [state ip now-ms]
  (let [st (or state (init-status-rate-limiter))
        limit (long (or (:limit st) default-status-rate-limit))
        window-ms (long (or (:window-ms st) default-status-window-ms))
        retry-sec (long (or (:retry-after-sec st) default-status-retry-after-sec))
        now (long (or now-ms 0))
        norm-ip (if (non-blank-str? ip) (str/trim ip) "unknown")
        cutoff (- now window-ms)
        prev-ts (get-in st [:buckets norm-ip] [])
        active-ts (filterv #(> (long %) cutoff) prev-ts)]
    (if (>= (count active-ts) limit)
      (let [diag {:type :diagnose
                  :reason :status-rate-limited
                  :ip norm-ip
                  :limit limit
                  :window-ms window-ms
                  :retry-after-sec retry-sec
                  :now-ms now}
            next-st (-> st
                        (assoc-in [:buckets norm-ip] active-ts)
                        (update-in [:diagnostics :rate-limited] (fnil inc 0)))]
        {:allowed? false
         :retry-after-sec retry-sec
         :remaining 0
         :state next-st
         :diagnose diag})
      (let [next-ts (conj active-ts now)
            next-st (assoc-in st [:buckets norm-ip] next-ts)]
        {:allowed? true
         :retry-after-sec retry-sec
         :remaining (max 0 (- limit (count next-ts)))
         :state next-st
         :diagnose nil}))))
