(ns bitecho.core.window
  "Unified pure bounded-memory window primitives (BIP-005 / Milestone D31):
   1. Bounded FIFO deduplication window (`init-fifo-window`, `fifo-conj`, `fifo-contains?`, `fifo-items`).
   2. Byte-bounded LRU cache window (`init-byte-lru`, `lru-put`, `lru-get`, `lru-remove`).
   3. 64-bit sliding anti-replay bitmask window (`init-replay-bitmask`, `replay-accept`).
   100% pure Sans-IO (.cljc) across JVM and ClojureScript."
  (:require [clojure.set :as set]))

;; =============================================================================
;; 1. Bounded FIFO Deduplication Window
;; =============================================================================

(defn init-fifo-window
  "Initializes an empty bounded FIFO deduplication window with `max-size` capacity."
  ([]
   (init-fifo-window 1024))
  ([max-size]
   {:max-size (max 1 (long (or max-size 1024)))
    :items []
    :seen #{}
    :evicted 0}))

(defn fifo-contains?
  "Returns true if `item` is currently in the bounded FIFO window."
  [win item]
  (contains? (:seen win #{}) item))

(defn fifo-items
  "Returns the ordered vector of items currently retained in the FIFO window."
  [win]
  (vec (:items win [])))

(defn fifo-conj
  "Inserts `item` into the bounded FIFO window if not already present.
   When capacity `:max-size` is exceeded, evicts the oldest entries in FIFO order."
  [win item]
  (let [w (or win (init-fifo-window))]
    (if (contains? (:seen w #{}) item)
      w
      (let [max-sz (max 1 (long (:max-size w 1024)))
            next-items (conj (vec (:items w [])) item)
            overflow (- (count next-items) max-sz)]
        (if (pos? overflow)
          (let [dropped (subvec next-items 0 overflow)
                kept (subvec next-items overflow)]
            {:max-size max-sz
             :items kept
             :seen (conj (set/difference (:seen w #{}) (set dropped)) item)
             :evicted (+ (long (:evicted w 0)) overflow)})
          {:max-size max-sz
           :items next-items
           :seen (conj (:seen w #{}) item)
           :evicted (long (:evicted w 0))})))))

;; =============================================================================
;; 2. Byte-Bounded LRU Window
;; =============================================================================

(defn init-byte-lru
  "Initializes an empty byte-bounded LRU cache with `max-bytes` capacity."
  [max-bytes]
  {:max-bytes (max 0 (long (or max-bytes 0)))
   :total-bytes 0
   :access-seq 0
   :entries {}
   :evicted-count 0
   :evicted-bytes 0})

(defn- evict-byte-lru-if-needed
  [lru protected-key]
  (let [cap (long (:max-bytes lru 0))]
    (if (<= (long (:total-bytes lru 0)) cap)
      lru
      (let [candidates (->> (:entries lru)
                            (keep (fn [[k v]]
                                    (when (and (not= k protected-key)
                                               (zero? (long (:pins v 0))))
                                      (assoc v :key k))))
                            (sort-by (juxt #(long (:last-access % 0)) #(str (:key %)))))]
        (loop [st lru
               rem-cands candidates]
          (if (or (<= (long (:total-bytes st 0)) cap)
                  (empty? rem-cands))
            st
            (let [{:keys [key size]} (first rem-cands)
                  sz (long (or size 0))]
              (recur (-> st
                         (update :entries dissoc key)
                         (update :total-bytes #(max 0 (- (long (or % 0)) sz)))
                         (update :evicted-count (fnil inc 0))
                         (update :evicted-bytes (fnil + 0) sz))
                     (rest rem-cands)))))))))

(defn lru-put
  "Inserts or updates `k` with `value` of byte size `size-bytes` (and optional `:pins`)
   in the byte-bounded LRU window, evicting least-recently-used unpinned entries as needed."
  ([lru k value size-bytes]
   (lru-put lru k value size-bytes 0))
  ([lru k value size-bytes pins]
   (let [st0 (or lru (init-byte-lru (* 64 1024 1024)))
         next-seq (inc (long (:access-seq st0 0)))
         old-entry (get-in st0 [:entries k])
         old-sz (long (:size old-entry 0))
         new-sz (max 0 (long (or size-bytes 0)))
         eff-pins (max 0 (long (or pins (:pins old-entry 0))))
         st1 (-> st0
                 (assoc :access-seq next-seq)
                 (assoc-in [:entries k] {:value value
                                         :size new-sz
                                         :pins eff-pins
                                         :last-access next-seq})
                 (update :total-bytes #(max 0 (+ (- (long (or % 0)) old-sz) new-sz))))]
     (evict-byte-lru-if-needed st1 k))))

(defn lru-get
  "Looks up `k` in `lru`. On hit, advances `:last-access` and returns `{:hit? true :value ... :lru st'}`;
   on miss, returns `{:hit? false :value nil :lru lru}`."
  [lru k]
  (if-let [entry (get-in lru [:entries k])]
    (let [next-seq (inc (long (:access-seq lru 0)))
          st' (-> lru
                  (assoc :access-seq next-seq)
                  (assoc-in [:entries k :last-access] next-seq))]
      {:hit? true :value (:value entry) :lru st'})
    {:hit? false :value nil :lru lru}))

(defn lru-remove
  "Removes `k` from `lru` and subtracts its byte size."
  [lru k]
  (if-let [entry (get-in lru [:entries k])]
    (let [sz (long (:size entry 0))]
      (-> lru
          (update :entries dissoc k)
          (update :total-bytes #(max 0 (- (long (or % 0)) sz)))))
    lru))

;; =============================================================================
;; 3. Sliding Anti-Replay Window (64-sequence default)
;; =============================================================================

(defn init-replay-bitmask
  "Initializes a pure sliding anti-replay window with `window-size` (default 64)."
  ([]
   (init-replay-bitmask 64))
  ([window-size]
   {:highest-seq 0
    :seen #{}
    :window-size (max 1 (long (or window-size 64)))
    :replays-deduped 0}))

(defn replay-accept
  "Checks and records `seq-num` against sliding anti-replay window `win`.
   Returns:
   - `{:accepted? true :window win'}` when `seq-num` is fresh and within window
   - `{:accepted? false :reason :replay-duplicate|:replay-too-old|:invalid-seq :window win'}` otherwise."
  [win seq-num]
  (let [w (or win (init-replay-bitmask 64))
        s (long (or seq-num 0))
        high (long (:highest-seq w 0))
        win-sz (max 1 (long (:window-size w 64)))
        seen (:seen w #{})
        min-allowed (max 1 (- high win-sz -1))]
    (cond
      (<= s 0)
      {:accepted? false
       :reason :invalid-seq
       :window (update w :replays-deduped (fnil inc 0))}

      (contains? seen s)
      {:accepted? false
       :reason :replay-duplicate
       :window (update w :replays-deduped (fnil inc 0))}

      (and (pos? high) (< s min-allowed))
      {:accepted? false
       :reason :replay-too-old
       :window (update w :replays-deduped (fnil inc 0))}

      :else
      (let [new-high (max high s)
            new-min (max 1 (- new-high win-sz -1))
            pruned-seen (into #{s} (filter #(>= (long %) new-min) seen))]
        {:accepted? true
         :window (assoc w
                        :highest-seq new-high
                        :seen pruned-seen)}))))
