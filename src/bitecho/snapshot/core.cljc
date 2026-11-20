(ns bitecho.snapshot.core
  "Pure Sans-IO Immutable Epoch-Addressed Snapshot Core (BIP-014 / P-ASYNC-1).
   Shared across Node.js, JVM, and Browser (.cljc) with zero side effects:
   - Deterministic snapshot naming: `snapshot-<sanitized>-epoch-<012d>.fressian`
   - Strict filename parsing rejecting `.tmp`, foreign nodes, and malformed names
   - Highest-epoch recovery selection with seamless legacy `snapshot-<node>.edn` fallback
   - Tunable retention planner (`current_epoch - N`, hard floor `min-keep >= 2`)
   - Single-authority generation-tagged coalescing async writer reducer (Rules 4 & 5):
     at most 1 in-flight write + at most 1 latest pending epoch, stale-gen callbacks
     ignored and counted, failed writes never prune prior snapshots."
  (:require [clojure.string :as str]))

;; =============================================================================
;; Constants
;; =============================================================================

(def default-keep-epochs
  "Default epoch retention window (~1h at 10s/epoch)."
  360)

(def default-min-keep
  "Default minimum number of immutable epoch snapshots preserved (hard floor >= 2)."
  2)

(def ^:private epoch-pad-width 12)

;; =============================================================================
;; Pure Snapshot Naming, Parsing, Recovery Selection, & Retention Planning
;; =============================================================================

(defn sanitize-node-id
  "Normalizes a node-id (keyword, symbol, or string) into a safe filename token
   containing only `[A-Za-z0-9_-]`. Falls back to `\"node\"` when blank."
  [node-id]
  (let [raw (cond
              (keyword? node-id) (name node-id)
              (symbol? node-id) (name node-id)
              (some? node-id) (str node-id)
              :else "")
        cleaned (-> raw
                    str/trim
                    (str/replace #"[^A-Za-z0-9_-]+" "_")
                    (str/replace #"^_+|_+$" ""))]
    (if (str/blank? cleaned) "node" cleaned)))

(defn- zero-pad-epoch
  [epoch]
  (let [n (max 0 (long (or epoch 0)))
        s (str n)
        pad-len (max 0 (- epoch-pad-width (count s)))]
    (if (pos? pad-len)
      (str (apply str (repeat pad-len "0")) s)
      s)))

(defn- parse-nonneg-long
  [s]
  (when (and (string? s) (re-matches #"[0-9]+" s))
    #?(:clj (try (Long/parseLong s) (catch Exception _ nil))
       :cljs (let [n (js/parseInt s 10)]
               (when-not (js/isNaN n) n)))))

(defn snapshot-filename
  "Returns deterministic immutable epoch-addressed snapshot filename:
   `snapshot-<sanitized>-epoch-<zero-padded-12-digits>.fressian`."
  [node-id epoch]
  (str "snapshot-" (sanitize-node-id node-id) "-epoch-" (zero-pad-epoch epoch) ".fressian"))

(defn parse-snapshot-filename
  "Parses `filename` strictly for `node-id`.
   Returns `{:node-id <sanitized> :epoch <long> :filename <str>}` or `nil`.
   Rejects `.tmp` files, foreign node-ids, path separators, and malformed names."
  [node-id filename]
  (when (and (string? filename)
             (not (str/includes? filename "/"))
             (not (str/includes? filename "\\")))
    (let [nid (sanitize-node-id node-id)
          prefix (str "snapshot-" nid "-epoch-")
          suffix ".fressian"]
      (when (and (str/starts-with? filename prefix)
                 (str/ends-with? filename suffix))
        (let [ep-str (subs filename
                           (count prefix)
                           (- (count filename) (count suffix)))]
          (when (and (>= (count ep-str) epoch-pad-width)
                     (re-matches #"[0-9]+" ep-str))
            (when-let [ep (parse-nonneg-long ep-str)]
              {:node-id nid
               :epoch (long ep)
               :filename filename})))))))

(defn select-latest-snapshot
  "Selects the highest-epoch immutable snapshot filename for `node-id` from `filenames`.
   Falls back to `legacy-filename` (e.g. `snapshot-<node>.edn`) ONLY when present in
   `filenames` and no valid immutable epoch snapshots exist, or returns `nil`."
  ([node-id filenames]
   (select-latest-snapshot node-id filenames nil))
  ([node-id filenames legacy-filename]
   (let [parsed (keep #(parse-snapshot-filename node-id %) filenames)]
     (if (seq parsed)
       (:filename (first (sort-by (fn [{:keys [epoch filename]}] [(- (long epoch)) filename]) parsed)))
       (when (and (string? legacy-filename)
                  (contains? (set filenames) legacy-filename))
         legacy-filename)))))

(defn plan-snapshot-retention
  "Plans immutable epoch snapshot retention for `node-id` given `filenames`, `current-epoch`,
   and optional `{:keys [keep-epochs min-keep]}`.
   - `keep-epochs` defaults to `360` (~1h at 10s/epoch).
   - `min-keep` defaults to `2` and ALWAYS enforces a hard floor `>= 2` even when all
     snapshots are older than `current-epoch - keep-epochs`.
   - Foreign files, `.tmp` files, and legacy snapshots are never included in `:delete`.
   Returns `{:keep [...] :delete [...]}` ordered newest-first."
  ([node-id filenames current-epoch]
   (plan-snapshot-retention node-id filenames current-epoch nil))
  ([node-id filenames current-epoch {:keys [keep-epochs min-keep]}]
   (let [eff-keep-epochs (max 0 (long (if (some? keep-epochs) keep-epochs default-keep-epochs)))
         eff-min-keep (max 2 (long (if (some? min-keep) min-keep default-min-keep)))
         cutoff (- (long (or current-epoch 0)) eff-keep-epochs)
         sorted-snaps (->> filenames
                           (keep #(parse-snapshot-filename node-id %))
                           (distinct)
                           (sort-by (fn [{:keys [epoch filename]}] [(- (long epoch)) filename]))
                           vec)]
     (loop [idx 0
            keep-acc []
            del-acc []]
       (if (>= idx (count sorted-snaps))
         {:keep keep-acc
          :delete del-acc}
         (let [entry (nth sorted-snaps idx)
               keep? (or (< idx eff-min-keep)
                         (>= (long (:epoch entry)) cutoff))]
           (if keep?
             (recur (inc idx) (conj keep-acc (:filename entry)) del-acc)
             (recur (inc idx) keep-acc (conj del-acc (:filename entry))))))))))

;; =============================================================================
;; Single-Authority Generation-Tagged Coalescing Async Writer Reducer (Rules 4 & 5)
;; =============================================================================

(defn init-writer-state
  "Initializes a single-authority generation-tagged coalescing async snapshot writer state."
  ([] (init-writer-state nil))
  ([opts]
   {:phase :idle
    :generation 0
    :in-flight nil
    :pending nil
    :last-written-epoch nil
    :last-written-filename nil
    :last-error nil
    :writes-started 0
    :writes-succeeded 0
    :writes-failed 0
    :coalesced-count 0
    :ignored-stale 0
    :prunes-succeeded 0
    :prunes-failed 0
    :node-id (sanitize-node-id (or (:node-id opts) "node"))
    :keep-epochs (max 0 (long (if (some? (:keep-epochs opts)) (:keep-epochs opts) default-keep-epochs)))
    :min-keep (max 2 (long (if (some? (:min-keep opts)) (:min-keep opts) default-min-keep)))}))

(defn- start-write-transition
  [st {:keys [epoch payload force? node-id]}]
  (let [nid (sanitize-node-id (or node-id (:node-id st)))
        ep (max 0 (long (or epoch 0)))
        fname (snapshot-filename nid ep)
        next-gen (inc (long (:generation st 0)))
        new-st (assoc st
                      :phase :writing
                      :generation next-gen
                      :node-id nid
                      :in-flight {:generation next-gen
                                  :epoch ep
                                  :filename fname}
                      :pending nil
                      :writes-started (inc (long (:writes-started st 0))))
        write-eff {:effect :write-snapshot
                   :generation next-gen
                   :node-id nid
                   :epoch ep
                   :filename fname
                   :payload payload
                   :force? (boolean force?)}]
    [new-st write-eff]))

(defn- stale-callback-transition
  [st event]
  (let [curr-gen (long (:generation st 0))
        ev-gen (:generation event)
        diag {:effect :diagnose
              :reason :stale-snapshot-callback
              :event-type (:type event)
              :event-generation ev-gen
              :current-generation curr-gen}
        new-st (-> st
                   (update :ignored-stale (fnil inc 0))
                   (assoc :last-error :stale-snapshot-callback))]
    [new-st [diag]]))

(defn transition-writer
  "Pure generation-tagged reducer `(transition-writer st event) -> [new-st effects]`
   managing coalesced async immutable epoch snapshot writes (Rules 4 & 5).

   Events:
   - `{:type :request-write :epoch <n> :payload <any> :force? <bool>}`
   - `{:type :write-succeeded :generation <g> :epoch <n> :filename <str>}`
   - `{:type :write-failed :generation <g> :epoch <n> :error <any>}`
   - `{:type :prune-succeeded :generation <g> :deleted-count <n>}`
   - `{:type :prune-failed :generation <g> :error <any>}`

   Invariants:
   - At most 1 in-flight write and at most 1 latest pending epoch.
   - Overwriting an existing pending epoch emits a counted `:diagnose` `:snapshot-write-coalesced`.
   - Stale generation callbacks (`gen < current`, or write completions while `:idle`)
     are ignored with counted `:diagnose` `:stale-snapshot-callback`.
   - `:write-failed` NEVER emits `:prune-snapshots` and emits counted `:diagnose` `:snapshot-write-failed`."
  [st event]
  (let [st (merge (init-writer-state) st)
        curr-gen (long (:generation st 0))
        ev-type (:type event)
        ev-gen (:generation event)
        stale-gen? (and (some? ev-gen) (< (long ev-gen) curr-gen))]
    (case ev-type
      :request-write
      (if (= :idle (:phase st))
        (let [[new-st write-eff] (start-write-transition st event)]
          [new-st [write-eff]])
        (let [old-pending (:pending st)
              ep (max 0 (long (or (:epoch event) 0)))
              new-pending {:epoch ep
                           :payload (:payload event)
                           :force? (boolean (:force? event))
                           :node-id (or (:node-id event) (:node-id st))}]
          (if (some? old-pending)
            (let [diag {:effect :diagnose
                        :reason :snapshot-write-coalesced
                        :dropped-epoch (:epoch old-pending)
                        :kept-epoch ep
                        :generation curr-gen}
                  new-st (-> st
                             (assoc :pending new-pending)
                             (update :coalesced-count (fnil inc 0)))]
              [new-st [diag]])
            [(assoc st :pending new-pending) []])))

      :write-succeeded
      (if (or stale-gen?
              (not= :writing (:phase st))
              (and (some? ev-gen)
                   (not= (long ev-gen) (long (get-in st [:in-flight :generation] -1)))))
        (stale-callback-transition st event)
        (let [in-flight (:in-flight st)
              ep (long (or (:epoch event) (:epoch in-flight) 0))
              fname (or (:filename event) (:filename in-flight))
              pending (:pending st)
              prune-eff {:effect :prune-snapshots
                         :generation curr-gen
                         :node-id (:node-id st)
                         :current-epoch ep
                         :keep-epochs (:keep-epochs st)
                         :min-keep (:min-keep st)}
              base-st (assoc st
                             :last-written-epoch ep
                             :last-written-filename fname
                             :last-error nil
                             :writes-succeeded (inc (long (:writes-succeeded st 0))))]
          (if (some? pending)
            (let [[next-st write-eff] (start-write-transition base-st pending)]
              [next-st [prune-eff write-eff]])
            [(assoc base-st :phase :idle :in-flight nil) [prune-eff]])))

      :write-failed
      (if (or stale-gen?
              (not= :writing (:phase st))
              (and (some? ev-gen)
                   (not= (long ev-gen) (long (get-in st [:in-flight :generation] -1)))))
        (stale-callback-transition st event)
        (let [in-flight (:in-flight st)
              ep (long (or (:epoch event) (:epoch in-flight) 0))
              err (or (:error event) :snapshot-write-failed)
              pending (:pending st)
              diag {:effect :diagnose
                    :reason :snapshot-write-failed
                    :generation curr-gen
                    :epoch ep
                    :error err}
              base-st (assoc st
                             :last-error err
                             :writes-failed (inc (long (:writes-failed st 0))))]
          ;; CRITICAL INVARIANT: Failed writes NEVER emit :prune-snapshots!
          (if (some? pending)
            (let [[next-st write-eff] (start-write-transition base-st pending)]
              [next-st [diag write-eff]])
            [(assoc base-st :phase :idle :in-flight nil) [diag]])))

      :prune-succeeded
      (if stale-gen?
        (stale-callback-transition st event)
        [(update st :prunes-succeeded (fnil inc 0)) []])

      :prune-failed
      (if stale-gen?
        (stale-callback-transition st event)
        (let [err (or (:error event) :snapshot-prune-failed)
              diag {:effect :diagnose
                    :reason :snapshot-prune-failed
                    :generation curr-gen
                    :error err}
              new-st (-> st
                         (update :prunes-failed (fnil inc 0))
                         (assoc :last-error err))]
          [new-st [diag]]))

      ;; Unknown event fallback (Rule 5)
      (let [diag {:effect :diagnose
                  :reason :unknown-writer-event
                  :event event}]
        [(assoc st :last-error :unknown-writer-event) [diag]]))))
