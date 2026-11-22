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
   Explicitly names BOTH `:head-epoch` and `:finalized-epoch`, computes `:epoch-finality-gap`,
   includes `:version` / `:bundle-sha256`, and strips any raw client IPs."
  [{:keys [node-id version bundle-sha256 uptime-ms restart-count restart-causes
           head-epoch finalized-epoch attest-root service-counters defense-counters
           crash-context-cid downtime-events runtime-summary]}]
  (let [head (long (or head-epoch 0))
        fin (long (or finalized-epoch 0))
        gap (if (and (pos? head) (pos? fin)) (max 0 (- head fin)) 0)
        base (cond-> {:schema "bitecho-telemetry-digest-v1"
                      :subnet "bitecho.org/observability"
                      :node-id (str (or node-id "unknown"))
                      :uptime-ms (max 0 (long (or uptime-ms 0)))
                      :restart-count (max 0 (long (or restart-count 0)))
                      :restart-causes (vec (take 16 (or restart-causes [])))
                      :head-epoch head
                      :finalized-epoch fin
                      :epoch-finality-gap gap
                      :attest-root (when attest-root (str attest-root))
                      :service-counters (strip-raw-ip-fields (or service-counters {}))
                      :defense-counters (strip-raw-ip-fields (or defense-counters {}))
                      :runtime-summary (strip-raw-ip-fields (or runtime-summary {}))
                      :crash-context-cid (when crash-context-cid (str crash-context-cid))
                      :downtime-events (vec (take 64 (strip-raw-ip-fields (or downtime-events []))))}
               version (assoc :version (str version))
               bundle-sha256 (assoc :bundle-sha256 (str bundle-sha256)))]
    (if (<= (estimate-record-bytes base) default-network-digest-max-bytes)
      base
      (assoc base
             :service-counters {:truncated? true}
             :runtime-summary {:truncated? true}
             :truncated? true))))

(def deploy-attributable-causes
  "Restart/downtime causes attributable to planned deployments rather than service faults."
  #{:planned-deploy :unified-rollout :pointer-update :kexec-reboot :rolling-upgrade})

(defn p99-ms
  "Pure P99 percentile over a numeric sample collection (returns 0.0 when empty)."
  [samples]
  (let [v (vec (sort (keep #(when (number? %) (double %)) samples)))
        n (count v)]
    (if (zero? n)
      0.0
      (let [idx (min (dec n) (max 0 (dec (long (Math/ceil (* 0.99 (double n)))))))]
        (nth v idx)))))

(defn compute-heap-slope-bytes-per-min
  "Pure linear heap slope (bytes/minute) between earliest and latest `{:ts-ms :heap-used}` samples."
  [samples]
  (let [valid (vec (sort-by :ts-ms (filter #(and (number? (:ts-ms %)) (number? (:heap-used %))) samples)))]
    (if (< (count valid) 2)
      0.0
      (let [first-s (first valid)
            last-s (peek valid)
            dt-ms (- (double (:ts-ms last-s)) (double (:ts-ms first-s)))]
        (if (<= dt-ms 0.0)
          0.0
          (* (/ (- (double (:heap-used last-s)) (double (:heap-used first-s))) dt-ms) 60000.0))))))

(defn- clamp-interval
  [ev win-start now-ts]
  (let [s0 (long (or (:started-ms ev) (:start-ms ev) 0))
        e0 (long (or (:ended-ms ev) (:end-ms ev) (+ s0 (long (or (:duration-ms ev) 0)))))
        s (if win-start (max s0 win-start) s0)
        e (if now-ts (min e0 now-ts) e0)]
    (when (> e s)
      {:node-id (str (or (:node-id ev) "unknown"))
       :start-ms s
       :end-ms e
       :cause (keyword (or (:cause ev) :unknown))})))

(defn- merge-intervals
  "Pure sweepline union over `{:start-ms :end-ms :cause :slo}` intervals."
  [intervals]
  (let [sorted (sort-by (juxt :start-ms :end-ms) (filter #(> (:end-ms %) (:start-ms %)) intervals))]
    (reduce (fn [acc iv]
              (if (empty? acc)
                [iv]
                (let [prev (peek acc)]
                  (if (<= (:start-ms iv) (:end-ms prev))
                    (let [causes (into (set (or (:causes prev) [(:cause prev)]))
                                       (or (:causes iv) [(:cause iv)]))
                          slos (into (set (or (:slos prev) [(:slo prev)]))
                                     (or (:slos iv) [(:slo iv)]))
                          cause (if (every? deploy-attributable-causes causes) :planned-deploy :unplanned)]
                      (conj (pop acc)
                            {:start-ms (:start-ms prev)
                             :end-ms (max (:end-ms prev) (:end-ms iv))
                             :cause cause
                             :causes causes
                             :slo (if (= 1 (count slos)) (first slos) :multi)
                             :slos slos}))
                    (conj acc iv)))))
            []
            sorted)))

(defn- overlap-threshold-intervals
  "Sweepline emitting maximal intervals where >= `min-concurrent` distinct nodes are simultaneously down."
  [node-intervals min-concurrent slo-tag]
  (if (or (empty? node-intervals) (<= min-concurrent 0))
    []
    (let [points (sort-by (juxt :t :delta)
                          (mapcat (fn [iv]
                                    [{:t (:start-ms iv) :delta 1 :node (:node-id iv) :cause (:cause iv)}
                                     {:t (:end-ms iv) :delta -1 :node (:node-id iv) :cause (:cause iv)}])
                                  node-intervals))]
      (loop [pts points
             active-counts {}
             active-causes {}
             open-start nil
             open-causes #{}
             out []]
        (if (empty? pts)
          out
          (let [t (:t (first pts))
                [batch rest-pts] (split-with #(= t (:t %)) pts)
                [next-counts next-causes]
                (reduce (fn [[ac cs] {:keys [delta node cause]}]
                          (let [prev-c (long (get ac node 0))
                                new-c (+ prev-c delta)]
                            (if (pos? new-c)
                              [(assoc ac node new-c) (update cs node (fnil conj #{}) cause)]
                              [(dissoc ac node) (dissoc cs node)])))
                        [active-counts active-causes]
                        batch)
                now-down (count next-counts)
                cur-causes (into #{} (mapcat identity) (vals next-causes))]
            (cond
              (and (nil? open-start) (>= now-down min-concurrent))
              (recur rest-pts next-counts next-causes t cur-causes out)

              (and (some? open-start) (< now-down min-concurrent))
              (let [all-c (into open-causes cur-causes)
                    c (if (and (seq all-c) (every? deploy-attributable-causes all-c)) :planned-deploy :unplanned)]
                (recur rest-pts next-counts next-causes nil #{}
                       (if (> t open-start)
                         (conj out {:start-ms open-start :end-ms t :duration-ms (- t open-start) :cause c :slo slo-tag})
                         out)))

              (some? open-start)
              (recur rest-pts next-counts next-causes open-start (into open-causes cur-causes) out)

              :else
              (recur rest-pts next-counts next-causes nil #{} out))))))))

(defn compute-six-nines-sla
  "Pure P-OBS-4 / D39.6 six-nines SLA accountant over published telemetry digests.
   Computes true cluster/service-level availability via interval-sweepline Union-of-Breach-Intervals
   across three user-facing SLOs:
   1. Consensus quorum breach (`< 4/6` validators healthy simultaneously, i.e. >= 3 overlapping down)
   2. Consensus finalization stall (`:finalization-stall` intervals or live `head - finalized > 10`)
   3. Edge ingress outage (`< 1/3` infra nodes `ns1..ns3` serving simultaneously, i.e. all 3 down)
   Publishes auditable `:breach-intervals`, split `:consensus-availability` / `:edge-availability`,
   fixed-denominator `:per-node-fleet-availability` (`N * window-ms`), `:error-budget-remaining-ms`,
   and `:version-converged?`."
  [digests {:keys [window-ms now-ms quorum-loss-threshold edge-outage-threshold]}]
  (let [win-ms (max 1 (long (or window-ms 86400000)))
        now-ts (when (some? now-ms) (long now-ms))
        win-start (when now-ts (- now-ts win-ms))
        raw-events (mapcat (fn [d]
                             (let [nid (str (or (:node-id d) "unknown"))]
                               (map #(assoc % :node-id (or (:node-id %) nid))
                                    (or (:downtime-events d) []))))
                           digests)
        all-events (if win-start
                     (filter (fn [ev]
                               (let [ended (or (:ended-ms ev) (:started-ms ev))]
                                 (or (nil? ended) (>= (long ended) win-start))))
                             raw-events)
                     raw-events)
        ;; Per-node diagnostic totals (kept for fleet churn visibility)
        deploy-ms (reduce + 0 (map #(long (or (:duration-ms %) 0))
                                   (filter #(contains? deploy-attributable-causes (keyword (:cause %)))
                                           all-events)))
        node-service-ms (reduce + 0 (map #(long (or (:duration-ms %) 0))
                                         (remove #(contains? deploy-attributable-causes (keyword (:cause %)))
                                                 all-events)))
        unexplained (count (filter #(or (nil? (:cause %)) (= :unknown (keyword (:cause %)))) all-events))
        ;; Sweepline cluster breach intervals
        clamped (keep #(clamp-interval % win-start now-ts) all-events)
        stall-ivs (map #(assoc % :slo :finalization-stall :duration-ms (- (:end-ms %) (:start-ms %)))
                       (filter #(= :finalization-stall (:cause %)) clamped))
        node-down-ivs (remove #(= :finalization-stall (:cause %)) clamped)
        edge-down-ivs (filter #(str/starts-with? (str (:node-id %)) "ns") node-down-ivs)
        node-count (max 1 (count digests))
        q-thresh (long (or quorum-loss-threshold (if (>= node-count 4) 3 1)))
        e-thresh (long (or edge-outage-threshold 3))
        quorum-breaches (overlap-threshold-intervals node-down-ivs q-thresh :quorum-loss)
        stall-breaches (overlap-threshold-intervals stall-ivs q-thresh :finalization-stall)
        edge-breaches (overlap-threshold-intervals edge-down-ivs e-thresh :edge-outage)
        consensus-union (merge-intervals (concat quorum-breaches stall-breaches))
        edge-union (merge-intervals edge-breaches)
        cluster-union (merge-intervals (concat consensus-union edge-union))
        sum-ms (fn [ivs] (reduce + 0 (map #(- (:end-ms %) (:start-ms %)) ivs)))
        consensus-breach-ms (min win-ms (sum-ms consensus-union))
        edge-breach-ms (min win-ms (sum-ms edge-union))
        ;; Fallback to node-service-ms only when legacy events lack timestamps (duration-only fixtures)
        has-timestamps? (some #(or (:started-ms %) (:start-ms %)) all-events)
        service-breach-union (remove #(= :planned-deploy (:cause %)) cluster-union)
        cluster-breach-ms (if (or has-timestamps? (empty? all-events))
                            (min win-ms (sum-ms cluster-union))
                            (min win-ms node-service-ms))
        service-breach-ms (if (or has-timestamps? (empty? all-events))
                            (min win-ms (sum-ms service-breach-union))
                            (min win-ms node-service-ms))
        svc-avail (max 0.0 (- 1.0 (/ (double service-breach-ms) (double win-ms))))
        consensus-avail (max 0.0 (- 1.0 (/ (double consensus-breach-ms) (double win-ms))))
        edge-avail (max 0.0 (- 1.0 (/ (double edge-breach-ms) (double win-ms))))
        fleet-avail (max 0.0 (- 1.0 (/ (double (+ deploy-ms node-service-ms))
                                       (double (* node-count win-ms)))))
        tot-avail (max 0.0 (- 1.0 (/ (double (+ deploy-ms node-service-ms)) (double win-ms))))
        budget-ms (* 0.000001 (double win-ms))
        budget-rem-ms (- budget-ms (double service-breach-ms))
        head-max (if (seq digests) (apply max (map #(long (or (:head-epoch %) 0)) digests)) 0)
        fin-max (if (seq digests) (apply max (map #(long (or (:finalized-epoch %) 0)) digests)) 0)
        max-fin-lag (if (seq digests)
                      (apply max (map (fn [d]
                                        (let [h (long (or (:head-epoch d) 0))
                                              f (long (or (:finalized-epoch d) 0))]
                                          (if (and (pos? h) (pos? f)) (max 0 (- h f)) 0)))
                                      digests))
                      0)
        nodes-reporting (vec (sort (distinct (keep :node-id digests))))
        versions (vec (sort-by (juxt #(str (:version %)) #(str (:bundle-sha256 %)))
                               (distinct (keep (fn [d]
                                                 (when (or (:version d) (:bundle-sha256 d))
                                                   {:version (:version d) :bundle-sha256 (:bundle-sha256 d)}))
                                               digests))))
        version-converged? (<= (count versions) 1)
        pub-intervals (mapv (fn [iv]
                              {:start-ms (:start-ms iv)
                               :end-ms (:end-ms iv)
                               :duration-ms (- (:end-ms iv) (:start-ms iv))
                               :cause (:cause iv)
                               :slo (:slo iv)})
                            (take 64 cluster-union))]
    (cond-> {:schema "bitecho-sla-report-v1"
             :window-ms win-ms
             :digest-count (count digests)
             :nodes-reporting nodes-reporting
             :cluster-breach-ms cluster-breach-ms
             :consensus-breach-ms consensus-breach-ms
             :edge-breach-ms edge-breach-ms
             :deploy-downtime-ms deploy-ms
             :node-service-downtime-ms node-service-ms
             :service-downtime-ms service-breach-ms
             :total-downtime-ms (+ deploy-ms node-service-ms)
             :service-availability svc-avail
             :consensus-availability consensus-avail
             :edge-availability edge-avail
             :per-node-fleet-availability fleet-avail
             :total-availability tot-avail
             :error-budget-ms budget-ms
             :error-budget-remaining-ms budget-rem-ms
             :six-nines-met? (>= svc-avail 0.999999)
             :breach-intervals pub-intervals
             :unexplained-restarts unexplained
             :head-epoch-max head-max
             :finalized-epoch-max fin-max
             :max-finalization-lag-epochs max-fin-lag
             :version-converged? version-converged?
             :versions-reporting versions}
      now-ts (assoc :computed-at-ms now-ts :window-start-ms win-start))))

(defn- bounded-tail
  [coll max-n]
  (let [v (vec (or coll []))]
    (if (> (count v) max-n)
      (subvec v (- (count v) max-n))
      v)))

(defn record-startup-event
  "Pure D39.5 telemetry lifecycle transition on node startup.
   Classifies restarts as planned (`:clean-shutdown-cause` or `:planned-deploy`) when a
   graceful shutdown marker was persisted prior to exit, or `:unplanned-crash` otherwise."
  [prev-ledger {:keys [node-id now-ms]}]
  (let [nid (str (or node-id (:node-id prev-ledger) "unknown"))
        ts (max 0 (long (or now-ms 0)))]
    (if-not (map? prev-ledger)
      {:schema "bitecho-telemetry-lifecycle-v1"
       :node-id nid
       :restart-count 0
       :restart-causes []
       :downtime-events []
       :last-heartbeat-ms ts
       :clean-shutdown-ms nil
       :clean-shutdown-cause nil
       :active-stall-started-ms nil}
      (let [clean-ms (:clean-shutdown-ms prev-ledger)
            planned? (some? clean-ms)
            cause (if planned?
                    (keyword (or (:clean-shutdown-cause prev-ledger) :planned-deploy))
                    :unplanned-crash)
            started-ms (long (or (if planned? clean-ms (:last-heartbeat-ms prev-ledger)) ts))
            dur-ms (max 0 (- ts started-ms))
            ev {:node-id nid
                :cause cause
                :started-ms started-ms
                :ended-ms ts
                :duration-ms dur-ms}
            prev-causes (or (:restart-causes prev-ledger) [])
            prev-events (or (:downtime-events prev-ledger) [])]
        {:schema "bitecho-telemetry-lifecycle-v1"
         :node-id nid
         :restart-count (inc (max 0 (long (or (:restart-count prev-ledger) 0))))
         :restart-causes (bounded-tail (conj (vec prev-causes) cause) 16)
         :downtime-events (bounded-tail (conj (vec prev-events) ev) 64)
         :last-heartbeat-ms ts
         :clean-shutdown-ms nil
         :clean-shutdown-cause nil
         ;; BIP-019 S3: Preserve ongoing finalization stall across restarts so sla/latest.edn
         ;; records true end-to-end wall-clock stall duration until finalization advances.
         :active-stall-started-ms (:active-stall-started-ms prev-ledger)
         :last-finalized-epoch (:last-finalized-epoch prev-ledger)
         :last-finalized-advanced-ms (:last-finalized-advanced-ms prev-ledger)}))))

(defn record-shutdown-marker
  "Pure D39.5 transition on graceful shutdown (`SIGTERM`/`SIGINT`), marking the exit
   so the next startup classifies the restart as deploy-attributable rather than a crash."
  [ledger {:keys [now-ms cause]}]
  (let [ts (max 0 (long (or now-ms 0)))]
    (assoc (or ledger {})
           :clean-shutdown-ms ts
           :clean-shutdown-cause (keyword (or cause :planned-deploy))
           :last-heartbeat-ms ts)))

(defn record-stall-sample
  "Pure D39.5 / BIP-019 heartbeat & consensus finalization-stall detector.
   Opens a `:finalization-stall` interval when `head-epoch - finalized-epoch > max-healthy-lag`
   (default 10) OR when `:max-frozen-ms` is specified and `finalized-epoch` has not advanced
   for `>= max-frozen-ms`, and closes it into `:downtime-events` once finalization catches up."
  [ledger {:keys [node-id now-ms head-epoch finalized-epoch max-healthy-lag max-frozen-ms]}]
  (let [base (or ledger (record-startup-event nil {:node-id node-id :now-ms now-ms}))
        nid (str (or node-id (:node-id base) "unknown"))
        ts (max 0 (long (or now-ms 0)))
        head (long (or head-epoch 0))
        fin (long (or finalized-epoch 0))
        max-lag (max 1 (long (or max-healthy-lag 10)))
        prev-fin (:last-finalized-epoch base)
        prev-adv-ms (:last-finalized-advanced-ms base)
        fin-advanced? (and (pos? fin) (or (nil? prev-fin) (> fin (long prev-fin))))
        next-fin (if (pos? fin) fin prev-fin)
        next-adv-ms (cond
                      fin-advanced? ts
                      (some? prev-adv-ms) (long prev-adv-ms)
                      (pos? fin) ts
                      :else nil)
        frozen-stalled? (and (some? max-frozen-ms)
                             (pos? fin)
                             (not fin-advanced?)
                             (some? next-adv-ms)
                             (>= (- ts (long next-adv-ms)) (long max-frozen-ms)))
        lag-stalled? (and (pos? head) (pos? fin) (> (- head fin) max-lag))
        stalled? (or lag-stalled? frozen-stalled?)
        active-start (:active-stall-started-ms base)
        base' (assoc base
                     :last-heartbeat-ms ts
                     :last-finalized-epoch next-fin
                     :last-finalized-advanced-ms next-adv-ms)]
    (cond
      (and stalled? (nil? active-start))
      (assoc base' :active-stall-started-ms ts)

      (and (not stalled?) (some? active-start))
      (let [ev {:node-id nid
                :cause :finalization-stall
                :started-ms (long active-start)
                :ended-ms ts
                :duration-ms (max 0 (- ts (long active-start)))}]
        (-> base'
            (assoc :active-stall-started-ms nil)
            (update :downtime-events #(bounded-tail (conj (vec (or % [])) ev) 64))))

      :else
      base')))

(defn effective-downtime-events
  "Returns all recorded `:downtime-events` plus an in-progress `:finalization-stall`
   event if a consensus stall is currently active at `now-ms`."
  [ledger now-ms]
  (let [events (vec (or (:downtime-events ledger) []))
        active-start (:active-stall-started-ms ledger)]
    (if (some? active-start)
      (let [ts (max (long active-start) (long (or now-ms active-start)))]
        (bounded-tail (conj events {:node-id (str (or (:node-id ledger) "unknown"))
                                    :cause :finalization-stall
                                    :started-ms (long active-start)
                                    :ended-ms ts
                                    :duration-ms (max 0 (- ts (long active-start)))
                                    :ongoing? true})
                      64))
      events)))

(defn prepare-sla-publication
  "Pure D39.5 rolling SLA report builder (`sla/latest.edn`) over published node digests."
  [digests opts]
  (let [sla (compute-six-nines-sla digests opts)
        edn-str (pr-str sla)
        edn-bytes (fressian/utf8->bytes edn-str)]
    {:subnet "bitecho.org/infra"
     :path "sla/latest.edn"
     :sla sla
     :edn-str edn-str
     :edn-bytes edn-bytes
     :byte-size (fressian/count-bytes edn-bytes)}))

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
