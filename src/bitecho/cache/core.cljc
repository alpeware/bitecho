(ns bitecho.cache.core
  "BIP-025 Pure Sans-IO Value-Aware Local Blob Cache Core (Rules 2 & 5).
   Portable across Clojure (JVM), Node.js, and Browser.

   Implements:
   - Strict 3-tier retention priority: `:pinned` (Tier 0) > `:active-pointer` (Tier 1) > `:historical-unreferenced` (Tier 2).
   - Sublinear-size GDSF value scoring `S(b) = L + (f(b) * c(b)) / s_eff(b)` that retains large,
     high-value reusable assets (e.g., 350 MiB open model weights) over transient one-off blobs.
   - Dual configured cache budget (`--max-cache-bytes`) and host free-space watermark
     (`--min-free-disk-bytes`, `--min-free-disk-pct`) guardrails.
   - Reconstructible cache index (`cache/index.fressian`, NEVER inside `state.fressian` per Axiom A2).
   - Migration disk-headroom & Tier 2 spill / fail-closed ENOSPC planner (V2, A1)."
  (:require [clojure.string :as str]))

;; =============================================================================
;; 1. Constants & Defaults
;; =============================================================================

(def cache-index-schema-version
  "Canonical schema tag for `<state-dir>/cache/index.fressian`."
  :bitecho.cache.index/v1)

(def default-max-cache-bytes
  "Default local cache budget on desktop/server light nodes: 2 GiB."
  (* 2 1024 1024 1024))

(def default-constrained-max-cache-bytes
  "Default local cache budget on memory/disk-constrained hosts (e2-micro): 256 MiB."
  (* 256 1024 1024))

(def default-browser-max-cache-bytes
  "Upper bound for browser IndexedDB blob cache: 512 MiB."
  (* 512 1024 1024))

(def default-min-free-disk-bytes
  "Default host free-space watermark floor: 512 MiB."
  (* 512 1024 1024))

(def default-min-free-disk-pct
  "Default host free-space watermark percentage: 5% of volume."
  5.0)

(def ^:private one-mib-double 1048576.0)
(def ^:private ln2 #?(:clj (Math/log 2.0) :cljs (js/Math.log 2.0)))

(defn valid-cid?
  "Returns true iff `cid` is a 64-character lowercase hexadecimal SHA-256 string."
  [cid]
  (boolean (and (string? cid) (re-matches #"[0-9a-f]{64}" cid))))

(defn normalize-cid
  "Normalizes `cid` to lowercase trimmed string, or returns nil if invalid."
  [cid]
  (when (string? cid)
    (let [norm (str/lower-case (str/trim cid))]
      (when (valid-cid? norm) norm))))

(defn cid-shard-relpath
  "Returns `[shard-dir cid]` for 256-bucket sharded layout `cache/blobs/<cid[0..2]>/<cid>`."
  [cid]
  (when-let [norm (normalize-cid cid)]
    [(subs norm 0 2) norm]))

;; =============================================================================
;; 2. Retention Tiering & Sublinear-Size GDSF Scoring (§3.2, §3.3)
;; =============================================================================

(defn classify-tier
  "Classifies a CID into strict retention tier:
   - `:pinned` (Tier 0): explicitly pinned in Core State `:pinned-cids`
   - `:active-pointer` (Tier 1): referenced by at least one live signed pointer
   - `:historical-unreferenced` (Tier 2): superseded or unreferenced cached blob"
  [cid pinned-cids active-pointer-cids]
  (cond
    (contains? (or pinned-cids #{}) cid) :pinned
    (contains? (or active-pointer-cids #{}) cid) :active-pointer
    :else :historical-unreferenced))

(defn asset-class-weight
  "Returns class weight w_class(b) boosting high-value reusable asset classes:
   - `4.0` for `application/x-gguf`, `application/x-onnx`, `model/*`
   - `2.0` for chunked/release manifests
   - `1.0` default"
  [media-type]
  (let [mt (str/lower-case (str/trim (str (or media-type "application/octet-stream"))))]
    (cond
      (or (= mt "application/x-gguf")
          (= mt "application/x-onnx")
          (str/starts-with? mt "model/"))
      4.0

      (or (= mt "application/x-bitecho-chunked-manifest")
          (= mt "application/x-bitecho-release-manifest")
          (str/includes? mt "manifest"))
      2.0

      :else 1.0)))

(defn reacquisition-cost
  "Computes re-acquisition cost c(b):
   `c(b) = w_class(b) * (1 + chunk-count(b) + size-bytes(b) / 1 MiB) * fetch-cost-factor(b)`."
  [{:keys [size-bytes media-type chunk-count fetch-cost-factor]}]
  (let [w (asset-class-weight media-type)
        sz (double (max 0 (long (or size-bytes 0))))
        chunks (double (max 1 (long (or chunk-count 1))))
        fcf (max 1.0 (double (or fetch-cost-factor 1.0)))]
    (* w (+ 1.0 chunks (/ sz one-mib-double)) fcf)))

(defn effective-size
  "Computes sublinear size denominator:
   `s_eff(b) = max(1.0, log2(size-bytes(b) / 4096 + 2))`."
  [size-bytes]
  (let [sz (double (max 0 (long (or size-bytes 0))))
        arg (+ (/ sz 4096.0) 2.0)
        log2-val (/ #?(:clj (Math/log arg) :cljs (js/Math.log arg)) ln2)]
    (max 1.0 log2-val)))

(defn retention-score
  "Computes GDSF-style value score:
   `S(b) = L + (f(b) * c(b)) / s_eff(b)`."
  [clock-l entry]
  (let [l-val (double (or clock-l 0.0))
        freq (double (max 1 (long (or (:freq entry) 1))))
        cost (reacquisition-cost entry)
        s-eff (effective-size (:size-bytes entry))]
    (+ l-val (/ (* freq cost) s-eff))))

;; =============================================================================
;; 3. Pure Cache Index State Management
;; =============================================================================

(defn init-cache-index
  "Initializes an empty pure Sans-IO local cache index state map."
  ([] (init-cache-index {}))
  ([opts]
   {:schema cache-index-schema-version
    :clock-l (double (or (:clock-l opts) 0.0))
    :entries {}
    :total-bytes 0
    :access-seq 0
    :diagnostics {}}))

(defn record-put
  "Purely records or updates a cached blob entry in `cache-index`."
  [cache-index {:keys [cid size-bytes media-type tier freq chunk-count fetch-cost-factor now-ms]}]
  (let [idx (or cache-index (init-cache-index))
        norm (normalize-cid cid)]
    (if-not norm
      idx
      (let [existing (get-in idx [:entries norm])
            old-sz (long (or (:size-bytes existing) 0))
            sz (max 0 (long (or size-bytes old-sz 0)))
            next-seq (inc (long (or (:access-seq idx) 0)))
            mt (or media-type (:media-type existing) "application/octet-stream")
            entry {:cid norm
                   :size-bytes sz
                   :media-type mt
                   :tier (or tier (:tier existing) :historical-unreferenced)
                   :freq (max 1 (long (or freq (if existing (inc (long (or (:freq existing) 1))) 1))))
                   :chunk-count (max 1 (long (or chunk-count (:chunk-count existing) 1)))
                   :fetch-cost-factor (max 1.0 (double (or fetch-cost-factor (:fetch-cost-factor existing) 1.0)))
                   :last-access (long (or now-ms next-seq))
                   :inserted-l (double (or (:inserted-l existing) (:clock-l idx) 0.0))}]
        (-> idx
            (assoc :access-seq next-seq)
            (assoc-in [:entries norm] entry)
            (assoc :total-bytes (max 0 (+ (long (or (:total-bytes idx) 0)) (- sz old-sz)))))))))

(defn record-access
  "Purely increments reuse frequency and updates `:last-access` for a cached CID."
  ([cache-index cid] (record-access cache-index cid nil))
  ([cache-index cid now-ms]
   (let [idx (or cache-index (init-cache-index))
         norm (normalize-cid cid)]
     (if-let [entry (and norm (get-in idx [:entries norm]))]
       (let [next-seq (inc (long (or (:access-seq idx) 0)))]
         (-> idx
             (assoc :access-seq next-seq)
             (assoc-in [:entries norm]
                       (assoc entry
                              :freq (inc (long (or (:freq entry) 1)))
                              :last-access (long (or now-ms next-seq))))))
       idx))))

(defn reclassify-tiers
  "Purely reclassifies all entries in `cache-index` against current Core State
   `:pinned-cids` and `:active-pointer-cids`."
  [cache-index pinned-cids active-pointer-cids]
  (let [idx (or cache-index (init-cache-index))
        updated-entries (reduce-kv (fn [acc cid entry]
                                     (assoc acc cid
                                            (assoc entry :tier (classify-tier cid pinned-cids active-pointer-cids))))
                                   {}
                                   (:entries idx))]
    (assoc idx :entries updated-entries)))

;; =============================================================================
;; 4. Dual Budget, Host Watermark & Eviction Planner (§3.2)
;; =============================================================================

(defn compute-effective-budget
  "Computes `{:effective-budget-bytes n :cause kw :watermark-bytes w}` combining
   `max-cache-bytes` with the host free-space watermark (`max(min-free-disk-bytes, pct * host-total-bytes)`)."
  [{:keys [max-cache-bytes host-free-bytes host-total-bytes min-free-disk-bytes min-free-disk-pct current-cache-bytes]}]
  (let [cfg-budget (max 0 (long (or max-cache-bytes default-max-cache-bytes)))
        min-abs (max 0 (long (or min-free-disk-bytes default-min-free-disk-bytes)))
        pct (max 0.0 (double (or min-free-disk-pct default-min-free-disk-pct)))
        pct-bytes (if (and (number? host-total-bytes) (pos? (long host-total-bytes)))
                    (long (* (double host-total-bytes) (/ pct 100.0)))
                    0)
        watermark (max min-abs pct-bytes)]
    (if (and (number? host-free-bytes) (< (long host-free-bytes) watermark))
      (let [deficit (- watermark (long host-free-bytes))
            cur-bytes (max 0 (long (or current-cache-bytes 0)))
            disk-budget (max 0 (- cur-bytes deficit))]
        {:effective-budget-bytes (min cfg-budget disk-budget)
         :cause :host-disk-watermark
         :watermark-bytes watermark})
      {:effective-budget-bytes cfg-budget
       :cause :budget-exceeded
       :watermark-bytes watermark})))

(defn plan-evictions
  "Purely plans value-aware evictions to bring `cache-index` within effective budget.
   Strictly enforces tier priority (`:historical-unreferenced` before `:active-pointer`;
   `:pinned` never evicted unless `:allow-emergency-pinned? true`).
   Within each tier, evicts lowest GDSF `retention-score` first with deterministic CID tie-break.
   Emits counted Rule 5 `:diagnose` `{:reason :cache-blob-evicted}` and `:cache-delete` effects.
   Returns `{:cache-index updated-idx :evicted [cids...] :evicted-bytes n :effective-budget-bytes b :effects [...]}`."
  [cache-index {:keys [max-cache-bytes host-free-bytes host-total-bytes
                       min-free-disk-bytes min-free-disk-pct
                       pinned-cids active-pointer-cids allow-emergency-pinned? cause]
                :as opts}]
  (let [idx0 (cond-> (or cache-index (init-cache-index))
               (or (contains? opts :pinned-cids) (contains? opts :active-pointer-cids))
               (reclassify-tiers pinned-cids active-pointer-cids))
        {:keys [effective-budget-bytes] :as binfo}
        (compute-effective-budget {:max-cache-bytes max-cache-bytes
                                   :host-free-bytes host-free-bytes
                                   :host-total-bytes host-total-bytes
                                   :min-free-disk-bytes min-free-disk-bytes
                                   :min-free-disk-pct min-free-disk-pct
                                   :current-cache-bytes (:total-bytes idx0)})
        evict-cause (or cause (:cause binfo))
        total0 (long (or (:total-bytes idx0) 0))]
    (if (<= total0 effective-budget-bytes)
      {:cache-index idx0
       :evicted []
       :evicted-bytes 0
       :effective-budget-bytes effective-budget-bytes
       :effects []}
      (let [clock0 (double (or (:clock-l idx0) 0.0))
            tier-order (if allow-emergency-pinned?
                         [:historical-unreferenced :active-pointer :pinned]
                         [:historical-unreferenced :active-pointer])
            by-tier (group-by :tier (vals (:entries idx0)))
            ordered-candidates
            (mapcat (fn [t]
                      (->> (get by-tier t)
                           (map (fn [e]
                                  (let [sc (retention-score (or (:inserted-l e) 0.0) e)]
                                    {:entry e :score sc :cid (:cid e)})))
                           (sort-by (fn [{:keys [score cid]}] [score cid]))))
                    tier-order)]
        (loop [rem-cands ordered-candidates
               entries (:entries idx0)
               cur-bytes total0
               clock-l clock0
               evicted []
               evicted-bytes 0
               effects []
               diags (or (:diagnostics idx0) {})]
          (if (or (<= cur-bytes effective-budget-bytes) (empty? rem-cands))
            {:cache-index (assoc idx0
                                 :entries entries
                                 :total-bytes cur-bytes
                                 :clock-l clock-l
                                 :diagnostics diags)
             :evicted evicted
             :evicted-bytes evicted-bytes
             :effective-budget-bytes effective-budget-bytes
             :effects effects}
            (let [{:keys [entry score cid]} (first rem-cands)
                  sz (long (or (:size-bytes entry) 0))
                  tier (:tier entry)
                  reason (if (= tier :pinned)
                           :cache-pinned-emergency-evicted
                           :cache-blob-evicted)
                  diag {:effect :diagnose
                        :reason reason
                        :cid cid
                        :size-bytes sz
                        :tier tier
                        :score score
                        :cause evict-cause}
                  del-eff {:effect :cache-delete :cid cid}]
              (recur (rest rem-cands)
                     (dissoc entries cid)
                     (max 0 (- cur-bytes sz))
                     (max clock-l score)
                     (conj evicted cid)
                     (+ evicted-bytes sz)
                     (conj effects diag del-eff)
                     (update diags reason (fnil inc 0))))))))))

;; =============================================================================
;; 5. Index Reconstruction From Disk (§2.2, A2)
;; =============================================================================

(defn rebuild-index-from-disk
  "Purely reconstructs `cache-index` from a scanned inventory of `cache/blobs/<2>/<cid>`
   entries (`[{:cid :size-bytes :mtime-ms :media-type}]`), skipping corrupt/invalid CIDs.
   Deterministic across JVM and CLJS regardless of directory traversal order.
   Emits counted Rule 5 `:diagnose {:reason :cache-index-rebuilt :entry-count n :corrupt-skipped c}`."
  [disk-entries {:keys [pinned-cids active-pointer-cids]}]
  (let [sorted-valid (->> disk-entries
                          (keep (fn [item]
                                  (let [norm (normalize-cid (:cid item))
                                        sz (:size-bytes item)]
                                    (when (and norm (number? sz) (>= (long sz) 0))
                                      {:cid norm
                                       :size-bytes (long sz)
                                       :media-type (or (:media-type item) "application/octet-stream")
                                       :tier (classify-tier norm pinned-cids active-pointer-cids)
                                       :freq 1
                                       :chunk-count 1
                                       :fetch-cost-factor 1.0
                                       :last-access (long (or (:mtime-ms item) 0))
                                       :inserted-l 0.0}))))
                          (sort-by :cid))
        corrupt-skipped (- (count disk-entries) (count sorted-valid))
        entries-map (into {} (map (fn [e] [(:cid e) e])) sorted-valid)
        total-bytes (reduce + 0 (map :size-bytes sorted-valid))
        diag {:effect :diagnose
              :reason :cache-index-rebuilt
              :entry-count (count entries-map)
              :corrupt-skipped corrupt-skipped}
        idx (-> (init-cache-index)
                (assoc :entries entries-map
                       :total-bytes total-bytes
                       :diagnostics {:cache-index-rebuilt 1}))]
    {:cache-index idx
     :effects [diag]}))

;; =============================================================================
;; 6. Legacy Migration Disk-Headroom & Tier 2 Spill Planner (§2.4, V2 & A1)
;; =============================================================================

(defn plan-migration-spill
  "Pure pre-flight disk-headroom planner for extract-before-compact legacy migration (V2, A1).
   `unique-blobs` is a map `{cid {:cid :size-bytes :media-type ...}}`.
   - If `host-free-bytes >= total-unique + compacted-core + min-free-disk`: retains 100% of blobs.
   - If tight, spills lowest-GDSF Tier 2 (`:historical-unreferenced`) blobs with
     `:cache-blob-evicted {:cause :migration-disk-pressure}` and `:migration-disk-pressure`.
   - If even Tier 0 + Tier 1 + Core + `min-free-disk` exceeds `host-free-bytes`: fails closed
     with `:migration-insufficient-disk-space` so original `state.fressian` is never mutated."
  [unique-blobs {:keys [pinned-cids active-pointer-cids host-free-bytes
                        compacted-core-bytes min-free-disk-bytes legacy-state-bytes]}]
  (let [core-sz (max 0 (long (or compacted-core-bytes 0)))
        min-free (max 0 (long (or min-free-disk-bytes default-min-free-disk-bytes)))
        classified (mapv (fn [[cid info]]
                           (let [tier (classify-tier cid pinned-cids active-pointer-cids)
                                 sz (max 0 (long (or (:size-bytes info) 0)))]
                             (assoc info :cid cid :size-bytes sz :tier tier)))
                         (sort-by key unique-blobs))
        total-unique-bytes (reduce + 0 (map :size-bytes classified))
        required-all (+ total-unique-bytes core-sz min-free)]
    (if (or (nil? host-free-bytes) (>= (long host-free-bytes) required-all))
      {:ok? true
       :tight-disk? false
       :retained-cids (mapv :cid classified)
       :spilled-cids []
       :required-bytes required-all
       :effects []}
      (let [avail (max 0 (long host-free-bytes))
            protected (filterv #(contains? #{:pinned :active-pointer} (:tier %)) classified)
            tier2 (filterv #(= :historical-unreferenced (:tier %)) classified)
            protected-bytes (reduce + 0 (map :size-bytes protected))
            required-protected (+ protected-bytes core-sz min-free)]
        (if (< avail required-protected)
          {:ok? false
           :error :migration-insufficient-disk-space
           :retained-cids []
           :spilled-cids []
           :required-bytes required-protected
           :available-bytes avail
           :effects [{:effect :diagnose
                      :reason :migration-insufficient-disk-space
                      :required-bytes required-protected
                      :available-bytes avail
                      :state-bytes (long (or legacy-state-bytes 0))}]}
          (let [tier2-ordered (->> tier2
                                   (map (fn [e] (assoc e :score (retention-score 0.0 e))))
                                   (sort-by (fn [e] [(:score e) (:cid e)])))
                max-blob-budget (max 0 (- avail core-sz min-free))]
            (loop [rem-t2 tier2-ordered
                   cur-blob-bytes total-unique-bytes
                   spilled []
                   effs []]
              (if (or (<= cur-blob-bytes max-blob-budget) (empty? rem-t2))
                (let [spilled-set (set spilled)
                      retained-cids (->> classified
                                         (remove #(contains? spilled-set (:cid %)))
                                         (mapv :cid))
                      summary-diag {:effect :diagnose
                                    :reason :migration-disk-pressure
                                    :spilled-count (count spilled)
                                    :retained-count (count retained-cids)
                                    :available-bytes avail}]
                  {:ok? true
                   :tight-disk? true
                   :retained-cids retained-cids
                   :spilled-cids spilled
                   :required-bytes (+ cur-blob-bytes core-sz min-free)
                   :effects (conj effs summary-diag)})
                (let [victim (first rem-t2)
                      sz (:size-bytes victim)
                      ev-diag {:effect :diagnose
                               :reason :cache-blob-evicted
                               :cid (:cid victim)
                               :size-bytes sz
                               :tier :historical-unreferenced
                               :score (:score victim)
                               :cause :migration-disk-pressure}]
                  (recur (rest rem-t2)
                         (max 0 (- cur-blob-bytes sz))
                         (conj spilled (:cid victim))
                         (conj effs ev-diag)))))))))))

;; =============================================================================
;; 7. Storage Telemetry Projection (§5.3)
;; =============================================================================

(defn cache-storage-summary
  "Purely summarizes `cache-index` for `bitecho.status/v1` and `/statusz` `storage` telemetry."
  [cache-index]
  (let [entries (vals (or (:entries cache-index) {}))
        counts (reduce (fn [acc e]
                         (let [t (or (:tier e) :historical-unreferenced)]
                           (update acc t (fnil inc 0))))
                       {:pinned 0 :active-pointer 0 :historical-unreferenced 0}
                       entries)]
    {:cache-bytes (long (or (:total-bytes cache-index) 0))
     :cache-entries (count entries)
     :cache-entries-by-tier counts}))
