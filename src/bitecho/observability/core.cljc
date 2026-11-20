(ns bitecho.observability.core
  "Milestone D38 (`BIP-013` / `v0.23.16`): Pure Sans-IO Core Observability Engine (`Rule 2`, `Rule 4`, `Rule 5`).
   - `P-OBS-1`: Core step instrumentation (`decide-log-record`, `wrap-step`, bounded delta summaries & budgets)
   - `P-OBS-2`: Sequenced sink router, crash-context ring buffer (64 records, <= 32 KiB), disk rotation
     policy (50 MiB cap: 5 x 10 MiB), network digest paths (`bitecho.org/observability`), IndexedDB schema
   - `P-OBS-3`: Host & service collector schema constructors (Node.js, JVM, Browser, DNS, HTTP, Relay, Disk, Supervisor)
     with HMAC-SHA256 source-ID hashing (never raw client IPs in published digests)
   - `P-OBS-4`: Privacy-preserving network telemetry digest builder (<= 16 KiB cap) & pure six-nines SLA accountant."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

;; =============================================================================
;; 1. P-OBS-1: Core Step Instrumentation (Pure Sans-IO)
;; =============================================================================

(def level-rank
  "Ordered severity levels for observability records."
  {:debug 0
   :info 1
   :warn 2
   :error 3})

(def default-observability-config
  "Default configuration for P-OBS-1 core step instrumentation."
  {:enabled? true
   :default-level :info
   :step-levels {}
   :max-records-per-step 8
   :max-bytes-per-record 2048
   :sampling-rate 1.0
   :hmac-salt "bitecho-obs-v1"})

(defn level-enabled?
  "Returns true if `level` meets or exceeds `min-level`."
  [level min-level]
  (>= (long (get level-rank (keyword (or level :info)) 1))
      (long (get level-rank (keyword (or min-level :info)) 1))))

(defn estimate-record-bytes
  "Pure deterministic UTF-8 byte-size estimator for a record or structure."
  [x]
  (let [s (pr-str x)]
    (fressian/count-bytes (fressian/utf8->bytes s))))

(defn hash-source-id
  "Computes an HMAC-SHA256-equivalent keyed SHA-256 hex digest of `source-id` using `salt`.
   Published telemetry digests NEVER carry raw client IP addresses."
  ([source-id]
   (hash-source-id source-id (:hmac-salt default-observability-config)))
  ([source-id salt]
   (let [raw (str (or salt "bitecho-obs-v1") "|" (str/trim (str (or source-id "unknown"))))
         inner (crypto/sha256 (fressian/utf8->bytes raw))
         outer (crypto/sha256 (fressian/utf8->bytes (str (or salt "bitecho-obs-v1") "|hmac|" (basalt/bytes->hex inner))))]
     (str/lower-case (basalt/bytes->hex outer)))))

(defn- safe-truncate-str
  [s max-chars]
  (let [txt (str s)]
    (if (<= (count txt) max-chars)
      txt
      (subs txt 0 (max 0 max-chars)))))

(defn bounded-delta-summary
  "Pure bounded summary of state transition from `state-before` to `state-after`.
   Never throws on huge or adversarial state maps."
  ([state-before state-after]
   (bounded-delta-summary state-before state-after 512))
  ([state-before state-after max-bytes]
   (let [b (if (map? state-before) state-before {})
         a (if (map? state-after) state-after {})
         all-keys (into (set (keys b)) (keys a))
         changed (->> all-keys
                      (filter (fn [k] (not= (get b k) (get a k))))
                      (map #(if (keyword? %) (name %) (str %)))
                      sort
                      vec)
         cap-keys (vec (take 16 changed))
         head-before (long (or (:head-epoch b) (:epoch b) 0))
         head-after (long (or (:head-epoch a) (:epoch a) 0))
         fin-before (long (or (:finalized-epoch b) (:epoch b) 0))
         fin-after (long (or (:finalized-epoch a) (:epoch a) 0))
         summary {:changed-keys cap-keys
                  :changed-count (count changed)
                  :head-epoch-delta (- head-after head-before)
                  :finalized-epoch-delta (- fin-after fin-before)}]
     (if (<= (estimate-record-bytes summary) (long (or max-bytes 512)))
       summary
       {:changed-count (count changed)
        :head-epoch-delta (- head-after head-before)
        :finalized-epoch-delta (- fin-after fin-before)
        :truncated? true}))))

(defn- enforce-record-byte-budget
  [rec max-bytes]
  (let [budget (max 128 (long (or max-bytes 2048)))]
    (if (<= (estimate-record-bytes rec) budget)
      rec
      (let [r1 (assoc rec :data {:truncated? true} :truncated? true)]
        (if (<= (estimate-record-bytes r1) budget)
          r1
          (let [r2 (assoc r1 :delta-summary {:truncated? true})]
            (if (<= (estimate-record-bytes r2) budget)
              r2
              {:schema "bitecho-obs-record-v1"
               :node-id (safe-truncate-str (:node-id rec) 24)
               :seq (:seq rec)
               :step (:step rec)
               :level (:level rec)
               :head-epoch (:head-epoch rec)
               :finalized-epoch (:finalized-epoch rec)
               :duration-ms (:duration-ms rec)
               :truncated? true})))))))

(defn decide-log-record
  "Pure P-OBS-1 decision function:
   `(decide-log-record state-before state-after timing-ms config) -> record-or-nil`.
   Deterministic, side-effect-free, and strictly bounded by `:max-bytes-per-record`."
  [state-before state-after timing-ms config]
  (let [cfg (merge default-observability-config (when (map? config) config))]
    (when (true? (:enabled? cfg))
      (let [step (keyword (or (:step cfg) :step))
            level (keyword (or (:level cfg) :info))
            min-level (or (get-in cfg [:step-levels step])
                          (:default-level cfg)
                          :info)]
        (when (level-enabled? level min-level)
          (let [st-a (if (map? state-after) state-after {})
                st-b (if (map? state-before) state-before {})
                node-id (str (or (:node-id cfg) (:node-id st-a) (:node-id st-b) "unknown"))
                seq-num (long (or (:seq cfg) 1))
                head-ep (long (or (:head-epoch st-a) (:epoch st-a) (:head-epoch st-b) (:epoch st-b) 0))
                fin-ep (long (or (:finalized-epoch st-a) (:finalized-epoch st-b) head-ep))
                max-bytes (long (or (:max-bytes-per-record cfg) 2048))
                delta (bounded-delta-summary st-b st-a (quot max-bytes 2))
                raw-rec {:schema "bitecho-obs-record-v1"
                         :node-id node-id
                         :seq seq-num
                         :head-epoch head-ep
                         :finalized-epoch fin-ep
                         :epoch head-ep
                         :step step
                         :level level
                         :duration-ms (max 0 (long (or timing-ms 0)))
                         :delta-summary delta
                         :data (if (map? (:data cfg)) (:data cfg) {})
                         :truncated? false}]
            (enforce-record-byte-budget raw-rec max-bytes)))))))

(defn wrap-step
  "Pure P-OBS-1 instrumentation wrapper around a Sans-IO `step-fn`:
   - Always returns the exact `:result` of `(step-fn state event)` unaltered.
   - Never throws an instrumentation error into the step.
   - Enforces `:max-records-per-step` and `:max-bytes-per-record`."
  [step-fn state event opts]
  (let [result (step-fn state event)
        cfg (merge default-observability-config (when (map? opts) opts))
        base-seq (long (or (:seq cfg) 1))]
    (if-not (true? (:enabled? cfg))
      {:result result
       :records []
       :next-seq base-seq
       :obs-error nil}
      (try
        (let [state-after (cond
                            (and (map? result) (contains? result :state)) (:state result)
                            (and (vector? result) (seq result)) (first result)
                            (map? result) result
                            :else state)
              timing-ms (long (or (:duration-ms cfg) 0))
              rec (decide-log-record state state-after timing-ms (assoc cfg :seq base-seq))
              extra (vec (or (:extra-records cfg) []))
              max-recs (max 1 (long (or (:max-records-per-step cfg) 8)))
              all-recs (cond-> []
                         rec (conj rec)
                         (seq extra) (into extra))
              capped (vec (take max-recs all-recs))
              dropped-cnt (max 0 (- (count all-recs) (count capped)))]
          {:result result
           :records capped
           :next-seq (+ base-seq (count capped))
           :dropped-records dropped-cnt
           :obs-error nil})
        (catch #?(:clj Exception :cljs :default) ex
          {:result result
           :records []
           :next-seq base-seq
           :obs-error {:effect :diagnose
                       :type :diagnose
                       :reason :obs-instrumentation-error
                       :message (str ex)}})))))

;; =============================================================================
;; 2. P-OBS-2: Sequenced Sink Router, Crash-Context Ring Buffer & Disk Rotation
;; =============================================================================

(def default-crash-context-max-records
  "Maximum number of records retained in the P-OBS-2 crash-context ring buffer."
  64)
(def default-crash-context-max-bytes
  "Maximum byte budget (32 KiB) for the P-OBS-2 crash-context ring buffer."
  32768)
(def default-disk-file-bytes
  "Maximum bytes per rotated P-OBS-2 disk log file (10 MiB)."
  (* 10 1024 1024))
(def default-disk-max-files
  "Maximum number of rotated P-OBS-2 disk log files (5 files)."
  5)
(def default-disk-max-total-bytes
  "Maximum total bytes across rotated P-OBS-2 disk log files (50 MiB)."
  (* 50 1024 1024))
(def default-network-digest-max-bytes
  "Maximum byte budget per node for a P-OBS-4 published network telemetry digest (16 KiB)."
  16384)
(def default-network-publish-interval-ms
  "Default publish interval for P-OBS-4 network telemetry digests (60s)."
  60000)

(defn observability-paths
  "Canonical P-OBS-2 / P-OBS-4 Blob+Pointer paths on the `bitecho.org/observability` subnet."
  [node-id]
  (let [nid (str/replace (str (or node-id "unknown")) #"[^a-zA-Z0-9._-]" "_")]
    {:subnet "bitecho.org/observability"
     :digest-path (str "telemetry/" nid "/digest.edn")
     :crash-context-path (str "telemetry/" nid "/crash-context.edn")
     :index-path "telemetry/index.edn"}))

(defn indexeddb-record-schema
  "Canonical browser IndexedDB record schema matching P-OBS-1 core records."
  [rec]
  {:schema "bitecho-obs-record-v1"
   :store "records"
   :db "bitecho-observability"
   :node-id (str (or (:node-id rec) "browser"))
   :seq (long (or (:seq rec) 0))
   :head-epoch (long (or (:head-epoch rec) (:epoch rec) 0))
   :finalized-epoch (long (or (:finalized-epoch rec) (:epoch rec) 0))
   :step (keyword (or (:step rec) :step))
   :level (keyword (or (:level rec) :info))
   :duration-ms (long (or (:duration-ms rec) 0))
   :delta-summary (or (:delta-summary rec) {})
   :data (or (:data rec) {})})

(defn append-crash-context
  "Appends `rec` to the bounded crash-context ring buffer (<= 64 records, <= 32 KiB)."
  ([ring-buf rec]
   (append-crash-context ring-buf rec default-crash-context-max-records default-crash-context-max-bytes))
  ([ring-buf rec max-records max-bytes]
   (let [capped-rec (enforce-record-byte-budget rec (min 1024 (quot max-bytes 2)))
         buf0 (conj (vec (or ring-buf [])) capped-rec)
         buf1 (if (> (count buf0) max-records)
                (subvec buf0 (- (count buf0) max-records))
                buf0)]
     (loop [b buf1]
       (if (or (<= (count b) 1)
               (<= (estimate-record-bytes b) max-bytes))
         b
         (recur (subvec b 1)))))))

(defn plan-disk-rotation
  "Pure P-OBS-2 disk rotation policy enforcing the 50 MiB total cap (5 x 10 MiB files)."
  [disk-state record-bytes]
  (let [file-cap (long (or (:file-size-bytes disk-state) default-disk-file-bytes))
        max-files (long (or (:max-files disk-state) default-disk-max-files))
        total-cap (long (or (:max-bytes disk-state) default-disk-max-total-bytes))
        rec-b (max 0 (long (or record-bytes 0)))
        files (vec (or (:files disk-state) []))
        active-b (long (or (:active-bytes disk-state) 0))
        next-active (+ active-b rec-b)]
    (if (< next-active file-cap)
      (let [cur-total (reduce + 0 (conj (map :bytes files) next-active))]
        (assoc disk-state
               :active-bytes next-active
               :total-bytes (min total-cap cur-total)
               :rotated? false))
      (let [next-idx (inc (long (or (:rotation-seq disk-state) 0)))
            rotated-files (conj files {:file (str "obs-" next-idx ".log")
                                       :bytes (min file-cap next-active)})
            trimmed (if (> (count rotated-files) max-files)
                      (subvec rotated-files (- (count rotated-files) max-files))
                      rotated-files)
            total-b (reduce + 0 (map :bytes trimmed))]
        (assoc disk-state
               :files trimmed
               :active-bytes 0
               :rotation-seq next-idx
               :total-bytes (min total-cap total-b)
               :rotated? true)))))

(defn init-sink-router
  "Initializes single-authority P-OBS-2 sink router state (`Rule 4`)."
  [{:keys [node-id disk-enabled? network-enabled? indexeddb-enabled?]}]
  {:node-id (str (or node-id "unknown"))
   :next-seq 1
   :sinks {:disk {:enabled? (if (some? disk-enabled?) (boolean disk-enabled?) true)
                  :healthy? true
                  :max-bytes default-disk-max-total-bytes
                  :file-size-bytes default-disk-file-bytes
                  :max-files default-disk-max-files
                  :active-bytes 0
                  :total-bytes 0
                  :files []
                  :last-seq 0
                  :seq-gaps []}
           :network {:enabled? (if (some? network-enabled?) (boolean network-enabled?) true)
                     :healthy? true
                     :subnet "bitecho.org/observability"
                     :max-digest-bytes default-network-digest-max-bytes
                     :interval-ms default-network-publish-interval-ms
                     :last-seq 0
                     :seq-gaps []}
           :indexeddb {:enabled? (boolean indexeddb-enabled?)
                       :healthy? true
                       :db-name "bitecho-observability"
                       :store-name "records"
                       :max-records 4096
                       :last-seq 0
                       :seq-gaps []}}
   :crash-context []
   :dropped 0
   :diagnostics {}})

(defn route-records
  "Pure P-OBS-2 sink router transition:
   `(route-records router-state records sink-outcomes) -> [new-router-state effects]`.
   - Stamps monotonic `:seq` on each record at write time.
   - Appends to bounded crash-context ring buffer.
   - Isolates per-sink failures (`:disk-full`, `:network-unreachable`, `:indexeddb-quota-exceeded`):
     records seq gaps, emits counted `:diagnose` to surviving sinks, and never blocks core."
  [router-state records sink-outcomes]
  (let [outcomes (or sink-outcomes {})
        start-seq (long (:next-seq router-state 1))
        stamped (vec (map-indexed (fn [idx r]
                                    (assoc r
                                           :schema "bitecho-obs-record-v1"
                                           :node-id (or (:node-id r) (:node-id router-state))
                                           :seq (+ start-seq idx)))
                                  records))
        end-seq (+ start-seq (count stamped))
        new-crash-ctx (reduce append-crash-context (:crash-context router-state []) stamped)
        enabled-sinks (filterv (fn [k] (true? (get-in router-state [:sinks k :enabled?])))
                               [:disk :network :indexeddb])]
    (if (empty? stamped)
      [router-state []]
      (let [first-seq (:seq (first stamped))
            last-written-seq (:seq (peek stamped))
            batch-bytes (reduce + 0 (map estimate-record-bytes stamped))
            {:keys [sinks diagnostics dropped effects]}
            (reduce
             (fn [acc sink-kw]
               (let [outcome (get outcomes sink-kw {:ok? true})
                     s-state (get-in acc [:sinks sink-kw])]
                 (if (true? (:ok? outcome))
                   (let [prev-seq (long (:last-seq s-state 0))
                         gap? (> first-seq (inc prev-seq))
                         s1 (cond-> (assoc s-state :healthy? true :last-seq last-written-seq)
                              gap? (update :seq-gaps conj {:from (inc prev-seq) :to (dec first-seq)})
                              (= sink-kw :disk) (plan-disk-rotation batch-bytes))]
                     (-> acc
                         (assoc-in [:sinks sink-kw] s1)
                         (update :effects conj {:effect :write-sink
                                                :sink sink-kw
                                                :records (if (= sink-kw :indexeddb)
                                                           (mapv indexeddb-record-schema stamped)
                                                           stamped)})))
                   (let [cause (or (:error outcome) :sink-write-failed)
                         diag {:effect :diagnose
                               :type :diagnose
                               :reason :sink-write-failed
                               :sink sink-kw
                               :cause cause
                               :skipped-seq-from first-seq
                               :skipped-seq-to last-written-seq}
                         s1 (-> s-state
                                (assoc :healthy? false :last-error cause)
                                (update :seq-gaps conj {:from first-seq :to last-written-seq :cause cause}))]
                     (-> acc
                         (assoc-in [:sinks sink-kw] s1)
                         (update :dropped + (count stamped))
                         (update-in [:diagnostics :sink-write-failed] (fnil inc 0))
                         (update :effects conj diag))))))
             {:sinks (:sinks router-state)
              :diagnostics (:diagnostics router-state {})
              :dropped (long (:dropped router-state 0))
              :effects []}
             enabled-sinks)]
        [(assoc router-state
                :next-seq end-seq
                :sinks sinks
                :crash-context new-crash-ctx
                :dropped dropped
                :diagnostics diagnostics)
         effects]))))

;; =============================================================================
;; 3. P-OBS-3: Host & Service Collector Schema Constructors
;; =============================================================================

(def collector-node-type-matrix
  "Config-gated collector defaults per node type (`P-OBS-3`)."
  {:infra #{:nodejs-runtime :dns :http :relay :disk :supervisor}
   :validator #{:nodejs-runtime :jvm-runtime :disk :supervisor}
   :light #{:nodejs-runtime :disk}
   :browser #{:browser-runtime}
   :faucet #{:nodejs-runtime :http :disk :supervisor}})

(defn collector-enabled-for-node-type?
  "Returns true if `collector-kw` is enabled for `node-type`."
  [node-type collector-kw]
  (contains? (get collector-node-type-matrix (keyword node-type) #{}) (keyword collector-kw)))

(defn collect-nodejs-runtime
  "Builds a P-OBS-3 Node.js runtime telemetry record."
  [{:keys [node-id rss-bytes heap-used-bytes heap-total-bytes external-bytes event-loop-lag-ms gc-pause-ms]}]
  {:schema "bitecho-obs-collector-v1"
   :collector :nodejs-runtime
   :node-id (str (or node-id "unknown"))
   :rss-bytes (long (or rss-bytes 0))
   :heap-used-bytes (long (or heap-used-bytes 0))
   :heap-total-bytes (long (or heap-total-bytes 0))
   :external-bytes (long (or external-bytes 0))
   :event-loop-lag-ms (double (or event-loop-lag-ms 0.0))
   :gc-pause-ms (double (or gc-pause-ms 0.0))})

(defn collect-jvm-runtime
  "Builds a P-OBS-3 JVM runtime telemetry record."
  [{:keys [node-id heap-used-bytes heap-max-bytes gc-pause-ms thread-count]}]
  {:schema "bitecho-obs-collector-v1"
   :collector :jvm-runtime
   :node-id (str (or node-id "unknown"))
   :heap-used-bytes (long (or heap-used-bytes 0))
   :heap-max-bytes (long (or heap-max-bytes 0))
   :gc-pause-ms (double (or gc-pause-ms 0.0))
   :thread-count (long (or thread-count 0))})

(defn collect-browser-runtime
  "Builds a P-OBS-3 browser runtime telemetry record."
  [{:keys [node-id js-heap-used-bytes js-heap-limit-bytes nav-latency-ms]}]
  {:schema "bitecho-obs-collector-v1"
   :collector :browser-runtime
   :node-id (str (or node-id "browser"))
   :js-heap-used-bytes (long (or js-heap-used-bytes 0))
   :js-heap-limit-bytes (long (or js-heap-limit-bytes 0))
   :nav-latency-ms (double (or nav-latency-ms 0.0))})

(defn collect-dns-metric
  "Builds a P-OBS-3 DNS service telemetry record (hashes query name)."
  [{:keys [node-id query-type name latency-ms rcode salt]}]
  {:schema "bitecho-obs-collector-v1"
   :collector :dns
   :node-id (str (or node-id "unknown"))
   :query-type (str (or query-type "A"))
   :name-hash (hash-source-id name salt)
   :latency-ms (double (or latency-ms 0.0))
   :rcode (str (or rcode "NOERROR"))})

(defn collect-http-metric
  "Builds a P-OBS-3 HTTP service telemetry record (hashes client source ID; never stores raw IP)."
  [{:keys [node-id route status latency-ms bytes source-id salt]}]
  {:schema "bitecho-obs-collector-v1"
   :collector :http
   :node-id (str (or node-id "unknown"))
   :route (str (or route "/"))
   :status (long (or status 200))
   :latency-ms (double (or latency-ms 0.0))
   :bytes (long (or bytes 0))
   :source-hash (hash-source-id source-id salt)})

(defn collect-relay-metric
  "Builds a P-OBS-3 relay service telemetry record."
  [{:keys [node-id poll-queue-depth fanout-count active-waiters dropped]}]
  {:schema "bitecho-obs-collector-v1"
   :collector :relay
   :node-id (str (or node-id "unknown"))
   :poll-queue-depth (long (or poll-queue-depth 0))
   :fanout-count (long (or fanout-count 0))
   :active-waiters (long (or active-waiters 0))
   :dropped (long (or dropped 0))})

(defn collect-disk-metric
  "Builds a P-OBS-3 disk usage telemetry record."
  [{:keys [node-id mount used-bytes total-bytes]}]
  (let [used (max 0 (long (or used-bytes 0)))
        total (max 1 (long (or total-bytes 1)))
        free-pct (* 100.0 (/ (double (max 0 (- total used))) (double total)))]
    {:schema "bitecho-obs-collector-v1"
     :collector :disk
     :node-id (str (or node-id "unknown"))
     :mount (str (or mount "/"))
     :used-bytes used
     :total-bytes total
     :free-pct free-pct}))

(defn collect-supervisor-event
  "Builds a P-OBS-3 / P-OBS-4 supervisor lifecycle record carrying preserved crash-context."
  [{:keys [node-id event exit-code signal cause crash-context]}]
  {:schema "bitecho-obs-collector-v1"
   :collector :supervisor
   :node-id (str (or node-id "unknown"))
   :event (keyword (or event :respawn))
   :exit-code (when (some? exit-code) (long exit-code))
   :signal (when signal (str signal))
   :cause (keyword (or cause :unknown))
   :crash-context-count (count (or crash-context []))
   :crash-context (vec (take default-crash-context-max-records (or crash-context [])))})

;; =============================================================================
;; 4. P-OBS-4: Published Telemetry Digest & Pure Six-Nines SLA Accountant
;; =============================================================================

(def ^:private forbidden-raw-ip-keys
  #{:client-ip :source-ip :remote-addr :ip :raw-ip
    "client_ip" "source_ip" "remote_addr" "ip" "raw_ip"})

(defn strip-raw-ip-fields
  "Recursively strips any raw client IP keys from maps before network digest publication."
  [x]
  (cond
    (map? x) (into {}
                   (keep (fn [[k v]]
                           (when-not (contains? forbidden-raw-ip-keys k)
                             [k (strip-raw-ip-fields v)])))
                   x)
    (vector? x) (mapv strip-raw-ip-fields x)
    (sequential? x) (mapv strip-raw-ip-fields x)
    :else x))

(defn build-telemetry-digest
  "Builds a privacy-preserving P-OBS-4 published telemetry digest (<= 16 KiB).
   Explicitly names BOTH `:head-epoch` and `:finalized-epoch` and strips any raw client IPs."
  [{:keys [node-id uptime-ms restart-count restart-causes head-epoch finalized-epoch
           attest-root service-counters defense-counters crash-context-cid downtime-events
           runtime-summary]}]
  (let [base {:schema "bitecho-telemetry-digest-v1"
              :subnet "bitecho.org/observability"
              :node-id (str (or node-id "unknown"))
              :uptime-ms (max 0 (long (or uptime-ms 0)))
              :restart-count (max 0 (long (or restart-count 0)))
              :restart-causes (vec (take 16 (or restart-causes [])))
              :head-epoch (long (or head-epoch 0))
              :finalized-epoch (long (or finalized-epoch 0))
              :attest-root (when attest-root (str attest-root))
              :service-counters (strip-raw-ip-fields (or service-counters {}))
              :defense-counters (strip-raw-ip-fields (or defense-counters {}))
              :runtime-summary (strip-raw-ip-fields (or runtime-summary {}))
              :crash-context-cid (when crash-context-cid (str crash-context-cid))
              :downtime-events (vec (take 64 (strip-raw-ip-fields (or downtime-events []))))}]
    (if (<= (estimate-record-bytes base) default-network-digest-max-bytes)
      base
      (assoc base
             :service-counters {:truncated? true}
             :runtime-summary {:truncated? true}
             :truncated? true))))

(def deploy-attributable-causes
  "Restart/downtime causes attributable to planned deployments rather than service faults."
  #{:planned-deploy :unified-rollout :pointer-update :kexec-reboot :rolling-upgrade})

(defn compute-six-nines-sla
  "Pure P-OBS-4 six-nines SLA accountant over published telemetry digests.
   Separates `:deploy-downtime-ms` from `:service-downtime-ms` and reports both
   `:head-epoch-max` and `:finalized-epoch-max`."
  [digests {:keys [window-ms]}]
  (let [win-ms (max 1 (long (or window-ms 86400000)))
        all-events (mapcat #(or (:downtime-events %) []) digests)
        deploy-ms (reduce + 0 (map #(long (or (:duration-ms %) 0))
                                   (filter #(contains? deploy-attributable-causes (keyword (:cause %)))
                                           all-events)))
        service-ms (reduce + 0 (map #(long (or (:duration-ms %) 0))
                                    (remove #(contains? deploy-attributable-causes (keyword (:cause %)))
                                            all-events)))
        unexplained (count (filter #(or (nil? (:cause %)) (= :unknown (keyword (:cause %)))) all-events))
        svc-avail (max 0.0 (- 1.0 (/ (double service-ms) (double win-ms))))
        tot-avail (max 0.0 (- 1.0 (/ (double (+ deploy-ms service-ms)) (double win-ms))))
        head-max (if (seq digests) (apply max (map #(long (or (:head-epoch %) 0)) digests)) 0)
        fin-max (if (seq digests) (apply max (map #(long (or (:finalized-epoch %) 0)) digests)) 0)]
    {:window-ms win-ms
     :digest-count (count digests)
     :deploy-downtime-ms deploy-ms
     :service-downtime-ms service-ms
     :total-downtime-ms (+ deploy-ms service-ms)
     :service-availability svc-avail
     :total-availability tot-avail
     :six-nines-met? (>= svc-avail 0.999999)
     :unexplained-restarts unexplained
     :head-epoch-max head-max
     :finalized-epoch-max fin-max}))

(defn should-persist-validator-snapshot?
  "Pure throttle decision for synchronous Fressian validator snapshot persistence on single-threaded
   shells (`D38.1`). Always returns true when `force?` is true (graceful shutdown) or on first save
   (`last-saved-ms <= 0`). Otherwise strictly enforces `min-interval-ms` (default 60s) even when
   `finalized-epoch` advances every 10s tick, preventing 12MB synchronous serialization storms."
  [{:keys [force? last-saved-ms now-ms min-interval-ms]}]
  (let [last-ms (long (or last-saved-ms 0))
        curr-ms (long (or now-ms 0))
        min-ms (max 1000 (long (or min-interval-ms 60000)))]
    (or (boolean force?)
        (<= last-ms 0)
        (>= (- curr-ms last-ms) min-ms))))

(defn prepare-telemetry-publication
  "Pure P-OBS-4 publication builder: constructs a privacy-preserving `bitecho-telemetry-digest-v1`
   EDN payload (<= 16 KiB, zero raw IPs) along with its canonical `telemetry/<node-id>/digest.edn`
   path and UTF-8 bytes ready for Blob+Pointer publication."
  [opts]
  (let [digest (build-telemetry-digest opts)
        paths (observability-paths (:node-id digest))
        edn-str (pr-str digest)
        edn-bytes (fressian/utf8->bytes edn-str)]
    {:subnet (:subnet paths)
     :path (:digest-path paths)
     :digest digest
     :edn-str edn-str
     :edn-bytes edn-bytes
     :byte-size (fressian/count-bytes edn-bytes)}))
