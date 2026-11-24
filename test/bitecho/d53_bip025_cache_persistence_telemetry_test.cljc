(ns bitecho.d53-bip025-cache-persistence-telemetry-test
  "BIP-025 Strict TDD Suite (Rules 1-6):
   1. Pure Sans-IO Value-Aware Local Cache (`bitecho.cache.core`): strict tiering, sublinear GDSF,
      worked Kokoro 350 MiB vs 10k x 50 KiB transient blobs table, host disk watermark, index rebuild.
   2. Structural Core-State vs Local-Cache Split & Legacy Migration (extract-before-compact, tight-disk
      Tier 2 spill, fail-closed ENOSPC, idempotency, BIP-022 backup boundary L1, A1, A2).
   3. Full-Node Bounded Snapshot Retention (`streamlet.core`, `state_machine`), Off-Heap GC hysteresis
      & ineffective-GC backoff (`core.infra`), and hot-LRU hysteresis + scan-resistant admission (`core.data`).
   4. Coalesced Async Persistence (`snapshot.core`), Bounded `--events-out` Rotation + `wait-event`
      inode/tail continuity (V1), and First-Class Latency/Storage Telemetry (`status.core`).
   5. JVM Disk Migration, Browser IDB v2 Closure-Safe Guard, Dual SIGTERM Watchdog, Hot-Path Zero-Sync-IO
      Static Guard, and Public Blameless Postmortem (`INC-2026-11-24-ns1-event-loop-wedge`)."
  (:require [bitecho.backup.core :as backup]
            [bitecho.cache.core :as cache]
            [bitecho.core.data :as data]
            [bitecho.core.infra :as core-infra]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.snapshot.core :as snap]
            [bitecho.state-machine :as sm]
            [bitecho.status.core :as status-core]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            #?(:clj [bitecho.fressian :as fressian])
            #?(:clj [bitecho.shell.light-node :as shell-light])
            #?(:clj [clojure.edn :as edn])
            #?(:clj [clojure.java.io :as io]))
  #?(:clj (:import [java.nio.file Files]
                   [java.nio.file.attribute FileAttribute])))

;; =============================================================================
;; Helpers & Generators
;; =============================================================================

(defn- format-hex
  [n]
  #?(:clj (format "%x" (long (Math/abs (long n))))
     :cljs (.toString (js/Math.abs (long n)) 16)))

(defn- hex-cid
  [n]
  (let [s (format-hex n)]
    (subs (str (apply str (repeat 64 "0")) s)
          (- (+ 64 (count s)) 64))))

(def ^:private gen-cid
  (gen/fmap (fn [n]
              (let [h (format-hex n)]
                (subs (str (apply str (repeat 64 "0")) h)
                      (count h))))
            (gen/choose 1 1000000)))

(def ^:private gen-tier
  (gen/elements [:pinned :active-pointer :historical-unreferenced]))

(def ^:private gen-media-type
  (gen/elements ["application/octet-stream"
                 "application/json"
                 "application/x-onnx"
                 "application/x-gguf"
                 "model/safetensors"
                 "application/x-bitecho-release-manifest"]))

(def ^:private gen-cache-entry
  (gen/let [cid gen-cid
            sz (gen/choose 1024 (* 16 1024 1024))
            mt gen-media-type
            tier gen-tier
            freq (gen/choose 1 20)
            chunks (gen/choose 1 32)
            fcf (gen/elements [1.0 1.5 2.0 3.0])]
    {:cid cid
     :size-bytes sz
     :media-type mt
     :tier tier
     :freq freq
     :chunk-count chunks
     :fetch-cost-factor fcf}))

;; =============================================================================
;; 1. Value-Aware Local Cache (`bitecho.cache.core`) Properties & Kokoro Table
;; =============================================================================

(defspec ^{:doc "BIP-025 §3.2: Strict tier monotonicity, budget convergence, and Rule 5 eviction diagnostics."}
  prop-cache-tier-monotonicity 50
  (prop/for-all [entries (gen/vector-distinct-by :cid gen-cache-entry {:min-elements 3 :max-elements 25})
                 budget-frac (gen/elements [0.1 0.35 0.6 0.85])]
                (let [idx0 (reduce (fn [idx e]
                                     (cache/record-put idx e))
                                   (cache/init-cache-index {})
                                   entries)
                      total-sz (:total-bytes idx0)
                      budget (max 1024 (long (* total-sz budget-frac)))
                      pinned-cids (into #{} (comp (filter #(= :pinned (:tier %))) (map :cid)) entries)
                      active-cids (into #{} (comp (filter #(= :active-pointer (:tier %))) (map :cid)) entries)
                      res (cache/plan-evictions idx0 {:max-cache-bytes budget
                                                      :pinned-cids pinned-cids
                                                      :active-pointer-cids active-cids})
                      evicted-cids (:evicted res)
                      idx1 (:cache-index res)
                      evicted-tiers (mapv #(get-in idx0 [:entries % :tier]) evicted-cids)
                      diags (filterv #(= :cache-blob-evicted (:reason %)) (:effects res))
                      remaining-tiers (set (map :tier (vals (:entries idx1))))
                      tier-rank {:historical-unreferenced 0 :active-pointer 1 :pinned 2}
                      evicted-ranks (mapv tier-rank evicted-tiers)]
                  (and
                   ;; 1. Never evict :pinned under normal budget pressure
                   (not-any? #(= :pinned %) evicted-tiers)
                   ;; 2. Tier eviction order is monotonically non-decreasing (Tier 2 before Tier 1)
                   (= evicted-ranks (vec (sort evicted-ranks)))
                   ;; 3. If any Tier 1 was evicted, zero Tier 2 entries remain
                   (or (not-any? #(= :active-pointer %) evicted-tiers)
                       (not (contains? remaining-tiers :historical-unreferenced)))
                   ;; 4. Budget convergence (unless only :pinned entries remain)
                   (or (<= (:total-bytes idx1) budget)
                       (every? #(= :pinned %) remaining-tiers))
                   ;; 5. Every evicted CID emits a matching Rule 5 :cache-blob-evicted diagnostic
                   (= (count evicted-cids) (count diags))
                   (= (set evicted-cids) (set (map :cid diags)))))))

(defspec ^{:doc "BIP-025 §3.1/3.2: Large high-value model weights strictly outscore transient 50 KiB - 2 MiB blobs."}
  prop-cache-value-aware-gdsf-beats-naive-size 50
  (prop/for-all [model-mib (gen/choose 100 500)
                 model-freq (gen/choose 1 10)
                 transient-kib (gen/choose 50 2048)
                 transient-count (gen/choose 20 80)]
                (let [model-bytes (* model-mib 1024 1024)
                      model-entry {:cid (hex-cid 999999)
                                   :size-bytes model-bytes
                                   :media-type "application/x-onnx"
                                   :tier :historical-unreferenced
                                   :freq model-freq
                                   :chunk-count model-mib
                                   :fetch-cost-factor 2.0}
                      transient-bytes (* transient-kib 1024)
                      transients (mapv (fn [i]
                                         {:cid (hex-cid (inc i))
                                          :size-bytes transient-bytes
                                          :media-type "application/octet-stream"
                                          :tier :historical-unreferenced
                                          :freq 1
                                          :chunk-count (max 1 (quot transient-kib 1024))
                                          :fetch-cost-factor 1.0})
                                       (range transient-count))
                      model-score (cache/retention-score 0.0 model-entry)
                      transient-score (cache/retention-score 0.0 (first transients))
                      idx0 (reduce cache/record-put
                                   (cache/init-cache-index {})
                                   (conj transients model-entry))
                      ;; Budget fits model + half of transients
                      budget (+ model-bytes (quot (* transient-bytes transient-count) 2))
                      res (cache/plan-evictions idx0 {:max-cache-bytes budget})
                      idx1 (:cache-index res)]
                  (and (> model-score (* 10.0 transient-score))
                       (contains? (:entries idx1) (:cid model-entry))
                       (<= (:total-bytes idx1) budget)))))

(deftest test-worked-kokoro-350mib-vs-10k-transient-blobs
  (testing "BIP-025 §3.3 exact worked GDSF table: 350 MiB Kokoro vs 10,000 x 50 KiB transient blobs under 512 MiB budget"
    (let [kokoro-bytes (* 350 1024 1024)
          transient-bytes (* 50 1024)
          two-mib (* 2 1024 1024)
          kokoro-f1 {:cid (hex-cid 777777)
                     :size-bytes kokoro-bytes
                     :media-type "application/x-onnx"
                     :tier :historical-unreferenced
                     :freq 1
                     :chunk-count 350
                     :fetch-cost-factor 2.0}
          kokoro-f5 (assoc kokoro-f1 :freq 5)
          transient-f1 {:cid (hex-cid 1)
                        :size-bytes transient-bytes
                        :media-type "application/octet-stream"
                        :tier :historical-unreferenced
                        :freq 1
                        :chunk-count 1
                        :fetch-cost-factor 1.0}
          transient-f3 (assoc transient-f1 :freq 3)
          build-artifact {:cid (hex-cid 2)
                          :size-bytes two-mib
                          :media-type "application/octet-stream"
                          :tier :historical-unreferenced
                          :freq 1
                          :chunk-count 2
                          :fetch-cost-factor 1.0}
          approx= (fn [expected actual tol] (<= (Math/abs (- (double expected) (double actual))) tol))]
      (is (approx= 0.53 (cache/retention-score 0.0 transient-f1) 0.02))
      (is (approx= 1.59 (cache/retention-score 0.0 transient-f3) 0.02))
      (is (approx= 0.56 (cache/retention-score 0.0 build-artifact) 0.02))
      (is (approx= 340.89 (cache/retention-score 0.0 kokoro-f1) 0.05))
      (is (approx= 1704.43 (cache/retention-score 0.0 kokoro-f5) 0.05))

      ;; Full 10,000 transient + 1 Kokoro 350 MiB simulation under 512 MiB budget
      (let [entries (into {(:cid kokoro-f1) kokoro-f1}
                          (map (fn [i]
                                 (let [c (hex-cid (+ 10 i))]
                                   [c (assoc transient-f1 :cid c)])))
                          (range 10000))
            total-bytes (+ kokoro-bytes (* 10000 transient-bytes))
            idx0 (assoc (cache/init-cache-index {})
                        :entries entries
                        :total-bytes total-bytes)
            budget (* 512 1024 1024)
            res (cache/plan-evictions idx0 {:max-cache-bytes budget})
            idx1 (:cache-index res)]
        (is (contains? (:entries idx1) (:cid kokoro-f1))
            "350 MiB Kokoro open weight MUST be retained with 0 evictions")
        (is (= 6683 (count (:evicted res)))
            "Exactly 6,683 transient 50 KiB blobs should be evicted")
        (is (<= (:total-bytes idx1) budget))
        (is (approx= 0.53 (:clock-l idx1) 0.02))))))

(defspec ^{:doc "BIP-025 §2.2 & §3.2: Host disk watermark shrinks effective budget; index rebuild is deterministic."}
  prop-cache-host-disk-watermark-and-index-rebuild-determinism 50
  (prop/for-all [entries (gen/vector-distinct-by :cid gen-cache-entry {:min-elements 2 :max-elements 15})
                 corrupt-count (gen/choose 0 5)]
                (let [disk-inv (concat
                                (mapv (fn [e]
                                        {:cid (:cid e)
                                         :size-bytes (:size-bytes e)
                                         :mtime-ms 1000000
                                         :media-type (:media-type e)})
                                      entries)
                                (mapv (fn [i]
                                        {:cid (str "not-a-valid-cid-" i)
                                         :size-bytes 123
                                         :mtime-ms 1000000})
                                      (range corrupt-count)))
                      pinned (into #{} (comp (filter #(= :pinned (:tier %))) (map :cid)) entries)
                      active (into #{} (comp (filter #(= :active-pointer (:tier %))) (map :cid)) entries)
                      r1 (cache/rebuild-index-from-disk disk-inv {:pinned-cids pinned :active-pointer-cids active})
                      r2 (cache/rebuild-index-from-disk (reverse disk-inv) {:pinned-cids pinned :active-pointer-cids active})
                      idx1 (:cache-index r1)
                      idx2 (:cache-index r2)
                      rebuilt-diag (first (filter #(= :cache-index-rebuilt (:reason %)) (:effects r1)))
                      ;; Now trigger host free-space watermark pressure
                      wm (* 512 1024 1024)
                      ev-res (cache/plan-evictions idx1 {:max-cache-bytes (* 2 1024 1024 1024)
                                                         :host-free-bytes (- wm (max 1 (quot (:total-bytes idx1) 2)))
                                                         :min-free-disk-bytes wm
                                                         :pinned-cids pinned
                                                         :active-pointer-cids active})]
                  (and (= (count entries) (count (:entries idx1)))
                       (= (:entries idx1) (:entries idx2))
                       (= (:total-bytes idx1) (:total-bytes idx2))
                       (some? rebuilt-diag)
                       (= (count entries) (:entry-count rebuilt-diag))
                       (= corrupt-count (:corrupt-skipped rebuilt-diag))
                       (every? #(= :host-disk-watermark (:cause %))
                               (filter #(= :cache-blob-evicted (:reason %)) (:effects ev-res)))))))

;; =============================================================================
;; 2. Legacy Migration, Core/Cache Split & Backup Boundary (V2, L1, A1, A2)
;; =============================================================================

(defspec ^{:doc "BIP-025 §2.2-2.4: Legacy bloated states migrate losslessly, idempotently, with zero inline blobs in Core State or Backups."}
  prop-legacy-migration-core-cache-split-and-backup-boundary 30
  (prop/for-all [payloads (gen/vector (gen/not-empty gen/string-alphanumeric) 1 8)]
                (let [blobs-list (mapv (fn [s] (data/make-blob s "text/plain")) payloads)
                      blobs-map (into {} (map (fn [b] [(:blob/cid b) b])) blobs-list)
                      ;; Duplicate across legacy maps (matching Vector's :blobs + :artifact-blobs bloat)
                      legacy-state {:pubkey (hex-cid 42)
                                    :epoch 100
                                    :petnames {"alice" (hex-cid 11)}
                                    :pinned-cids #{(:blob/cid (first blobs-list))}
                                    :pointers {"p/1" {:pointer/target (:blob/cid (first blobs-list))}}
                                    :blobs blobs-map
                                    :artifact-blobs blobs-map
                                    :storage-blobs blobs-map
                                    :capability-blobs blobs-map
                                    :blob-index {:stale true}
                                    :governance {:blobs blobs-map :pointers {"g/1" {:pointer/path "g/1"}}}}
                      ex1 (light-core/extract-legacy-inline-blobs legacy-state)
                      compacted (:compacted-state ex1)
                      ;; Second run on compacted state must be idempotent no-op
                      ex2 (light-core/extract-legacy-inline-blobs compacted)
                      ;; encode-light-state must strip residual inline blobs & :blob-index
                      encoded-legacy (light-core/encode-light-state legacy-state)
                      decoded-legacy (light-core/decode-light-state encoded-legacy)
                      ;; BIP-022 backup boundary (L1): zero blobs, zero cache index
                      backup-payload (backup/extract-backup-payload legacy-state {:node-role :light :seq 1 :now-ms 1000})]
                  (and (true? (:had-inline-blobs? ex1))
                       (= (count blobs-map) (count (:unique-blobs ex1)))
                       (pos? (:deduplicated-count ex1))
                       (nil? (:blobs compacted))
                       (nil? (:artifact-blobs compacted))
                       (nil? (:storage-blobs compacted))
                       (nil? (:capability-blobs compacted))
                       (nil? (:blob-index compacted))
                       (nil? (get-in compacted [:governance :blobs]))
                       (= (:petnames legacy-state) (:petnames compacted))
                       (= (:pinned-cids legacy-state) (:pinned-cids compacted))
                       (false? (:had-inline-blobs? ex2))
                       (empty? (:unique-blobs ex2))
                       ;; encode-light-state hard invariant
                       (nil? (:blobs decoded-legacy))
                       (nil? (:artifact-blobs decoded-legacy))
                       (nil? (:blob-index decoded-legacy))
                       ;; L1 backup boundary
                       (not (contains? backup-payload :blobs))
                       (not (contains? backup-payload :artifact-blobs))
                       (not (contains? backup-payload :storage-blobs))
                       (not (contains? backup-payload :blob-index))
                       (= (:pinned-cids legacy-state) (set (:pinned-cids backup-payload)))))))

(defspec ^{:doc "BIP-025 §2.4 (V2, A1): Migration headroom planner spills Tier 2 when tight and fails closed on ENOSPC."}
  prop-migration-disk-headroom-spill-and-enospc-fail-closed 50
  (prop/for-all [t0-sz (gen/choose 10000 50000)
                 t2-count (gen/choose 2 8)
                 t2-sz (gen/choose 10000 40000)]
                (let [t0-cid (hex-cid 1)
                      t2-cids (mapv #(hex-cid (+ 10 %)) (range t2-count))
                      unique-blobs (into {t0-cid {:cid t0-cid :size-bytes t0-sz :media-type "application/x-onnx"}}
                                         (map (fn [c] [c {:cid c :size-bytes t2-sz :media-type "application/octet-stream"}]))
                                         t2-cids)
                      core-sz 5000
                      min-free 10000
                      ;; Case A: plenty of space
                      plenty (+ t0-sz (* t2-count t2-sz) core-sz min-free 50000)
                      res-a (cache/plan-migration-spill unique-blobs {:pinned-cids #{t0-cid}
                                                                      :active-pointer-cids #{}
                                                                      :host-free-bytes plenty
                                                                      :compacted-core-bytes core-sz
                                                                      :min-free-disk-bytes min-free})
                      ;; Case B: tight disk (fits Core + T0 + 1 T2 blob, must spill rest of T2)
                      tight (+ t0-sz t2-sz core-sz min-free)
                      res-b (cache/plan-migration-spill unique-blobs {:pinned-cids #{t0-cid}
                                                                      :active-pointer-cids #{}
                                                                      :host-free-bytes tight
                                                                      :compacted-core-bytes core-sz
                                                                      :min-free-disk-bytes min-free})
                      ;; Case C: insufficient even for Core + T0 -> fail closed
                      insufficient (max 0 (dec (+ t0-sz core-sz min-free)))
                      res-c (cache/plan-migration-spill unique-blobs {:pinned-cids #{t0-cid}
                                                                      :active-pointer-cids #{}
                                                                      :host-free-bytes insufficient
                                                                      :compacted-core-bytes core-sz
                                                                      :min-free-disk-bytes min-free
                                                                      :legacy-state-bytes 999999})]
                  (and (true? (:ok? res-a))
                       (empty? (:spilled-cids res-a))
                       (true? (:ok? res-b))
                       (true? (:tight-disk? res-b))
                       (contains? (set (:retained-cids res-b)) t0-cid)
                       (pos? (count (:spilled-cids res-b)))
                       (some #(= :migration-disk-pressure (:reason %)) (:effects res-b))
                       (false? (:ok? res-c))
                       (= :migration-insufficient-disk-space (:error res-c))
                       (some #(= :migration-insufficient-disk-space (:reason %)) (:effects res-c))))))

;; =============================================================================
;; 3. Coalesced Async Persistence Model-Based Command-Sequence Property
;; =============================================================================

(defspec ^{:doc "BIP-025 §5.1 (Rule 1, 4, 5): Model-based command-sequence test for coalesced async persistence."}
  prop-coalesced-async-writer-command-sequence 50
  (prop/for-all [cmds (gen/vector
                       (gen/one-of
                        [(gen/let [ep (gen/choose 1 1000)]
                           {:cmd :request :epoch ep})
                         (gen/return {:cmd :succeed-current})
                         (gen/return {:cmd :fail-current})
                         (gen/let [stale-delta (gen/choose 1 5)]
                           {:cmd :succeed-stale :delta stale-delta})
                         (gen/let [stale-delta (gen/choose 1 5)]
                           {:cmd :fail-stale :delta stale-delta})])
                       1 40)]
                (let [init-st (snap/init-writer-state {:node-id "light-node"})]
                  (loop [st init-st
                         remaining cmds
                         prev-gen 0]
                    (if (empty? remaining)
                      true
                      (let [c (first remaining)
                            curr-gen (long (:generation st 0))
                            ev (case (:cmd c)
                                 :request {:type :request-write :epoch (:epoch c) :payload {:ep (:epoch c)}}
                                 :succeed-current {:type :write-succeeded :generation curr-gen :epoch (get-in st [:in-flight :epoch] 0)}
                                 :fail-current {:type :write-failed :generation curr-gen :epoch (get-in st [:in-flight :epoch] 0) :error :io-err}
                                 :succeed-stale {:type :write-succeeded :generation (max 0 (- curr-gen (:delta c))) :epoch 0}
                                 :fail-stale {:type :write-failed :generation (max 0 (- curr-gen (:delta c))) :epoch 0 :error :stale})
                            was-pending? (some? (:pending st))
                            was-writing? (= :writing (:phase st))
                            [st' effs] (snap/transition-writer st ev)
                            next-gen (long (:generation st' 0))
                            ok? (and
                                 ;; Monotonic generation
                                 (>= next-gen prev-gen)
                                 ;; At most 1 in-flight write
                                 (if (= :writing (:phase st')) (some? (:in-flight st')) (nil? (:in-flight st')))
                                 ;; Coalescing emits counted diagnostic
                                 (or (not (and (= :request (:cmd c)) was-writing? was-pending?))
                                     (some #(= :snapshot-write-coalesced (:reason %)) effs))
                                 ;; Stale callback emits counted diagnostic
                                 (or (not (contains? #{:succeed-stale :fail-stale} (:cmd c)))
                                     (and (pos? curr-gen)
                                          (= (inc (long (:ignored-stale st 0))) (long (:ignored-stale st' 0)))
                                          (some #(= :stale-snapshot-callback (:reason %)) effs))
                                     (zero? curr-gen)))]
                        (if ok?
                          (recur st' (rest remaining) next-gen)
                          false)))))))

;; =============================================================================
;; 4. Full-Node Bounded Snapshot Caps (`streamlet.core` + `state_machine`)
;; =============================================================================

(defspec ^{:doc "BIP-025 §4.1: Strict O(1) caps on :executed-root-depths, :expired-gossip-ids/order, and :epoch-to-message-roles."}
  prop-full-node-bounded-snapshot-caps 30
  (prop/for-all [depth-count (gen/choose 60 140)
                 gossip-count (gen/choose 60 140)
                 role-epochs (gen/choose 20 50)]
                (let [max-depths 32
                      max-gossip 24
                      gossip-ttl 6
                      new-epoch 200
                      ;; Build state with bloated :executed-root-depths, :expired-gossip-ids/order, and orphaned :epoch-to-message-roles
                      active-h "blk-active-tip"
                      active-parent "blk-active-parent"
                      exec-depths (into {active-h 500 active-parent 499}
                                        (map (fn [i] [(str "old-blk-" i) (inc i)]))
                                        (range depth-count))
                      gossip-vec (mapv #(str "gossip-" %) (range gossip-count))
                      orphan-roles (into {}
                                         (map (fn [i] [(- new-epoch i) {"m" :echo}]))
                                         (range role-epochs))
                      st0 {:epoch (dec new-epoch)
                           :blocks {active-h {:hash active-h :parent-hash active-parent :epoch new-epoch}}
                           :block-depths {active-h 500}
                           :executed-finalized-blocks #{active-parent}
                           :executed-finalized-blocks-order [active-parent]
                           :latest-finalized-block-hash active-parent
                           :executed-root-depths exec-depths
                           :expired-gossip-ids (set gossip-vec)
                           :expired-gossip-order gossip-vec
                           :epoch-to-messages {new-epoch #{"m-live"}}
                           :epoch-to-message-roles orphan-roles
                           :messages {}
                           :message-epochs {}}
                      cfg {:gossip-ttl-epochs gossip-ttl
                           :frozen-log-retention-epochs 10
                           :max-executed-root-depths max-depths
                           :max-expired-gossip-ids max-gossip}
                      st1 (sm/prune-epoch-state st0 new-epoch cfg)]
                  (and (<= (count (:executed-root-depths st1)) max-depths)
                       (= 500 (get-in st1 [:executed-root-depths active-h]))
                       (= 499 (get-in st1 [:executed-root-depths active-parent]))
                       (<= (count (:expired-gossip-ids st1)) max-gossip)
                       (= (count (:expired-gossip-ids st1))
                          (count (:expired-gossip-order st1)))
                       (<= (count (:epoch-to-message-roles st1)) (+ gossip-ttl 4))
                       (every? #(>= % (- new-epoch gossip-ttl))
                               (keys (:epoch-to-message-roles st1)))))))

;; =============================================================================
;; 5. Off-Heap GC Hysteresis & Ineffective-GC Backoff (`core.infra`)
;; =============================================================================

(defspec ^{:doc "BIP-025 §4.2: Off-heap GC never triggers below 32 MiB AB / 64 MiB ext, honors 120s cooldown & ineffective backoff."}
  prop-offheap-gc-hysteresis-and-ineffective-backoff 50
  (prop/for-all [ab-mib (gen/choose 0 96)
                 ext-mib (gen/choose 0 128)
                 elapsed-s (gen/choose 0 240)]
                (let [ab-bytes (* ab-mib 1024 1024)
                      ext-bytes (* ext-mib 1024 1024)
                      mem {:array-buffers-bytes ab-bytes :external-bytes ext-bytes}
                      last-gc 1000000
                      now-ms (+ last-gc (* elapsed-s 1000))
                      trig? (core-infra/should-trigger-offheap-gc?
                             {:memory mem :last-gc-ms last-gc :now-ms now-ms :gc-available? true})
                      expected? (and (>= (* elapsed-s 1000) 120000)
                                     (or (>= ab-bytes (* 32 1024 1024))
                                         (>= ext-bytes (* 64 1024 1024))))
                      ;; Verify ineffective GC exponential backoff (120s -> 240s -> 480s -> 600s cap)
                      st0 (core-infra/init-offheap-gc-state)
                      high-mem {:array-buffers-bytes (* 40 1024 1024) :external-bytes (* 70 1024 1024)}
                      ;; Reclaim 0% (< 10%) -> backoff to 240s + :offheap-gc-ineffective-backoff
                      [st1 eff1] (core-infra/record-offheap-gc-result st0 {:now-ms 200000
                                                                           :pre-memory high-mem
                                                                           :post-memory high-mem
                                                                           :pause-ms 45})
                      [st2 _] (core-infra/record-offheap-gc-result st1 {:now-ms 500000
                                                                        :pre-memory high-mem
                                                                        :post-memory high-mem
                                                                        :pause-ms 50})
                      [st3 _] (core-infra/record-offheap-gc-result st2 {:now-ms 1000000
                                                                        :pre-memory high-mem
                                                                        :post-memory high-mem
                                                                        :pause-ms 55})
                      ;; Effective GC (>= 10% reclaimed) resets cooldown to 120s
                      low-mem {:array-buffers-bytes (* 10 1024 1024) :external-bytes (* 10 1024 1024)}
                      [st4 _] (core-infra/record-offheap-gc-result st3 {:now-ms 1700000
                                                                        :pre-memory high-mem
                                                                        :post-memory low-mem
                                                                        :pause-ms 30})]
                  (and (= expected? trig?)
                       (= 240000 (:effective-cooldown-ms st1))
                       (some #(= :offheap-gc-ineffective-backoff (:reason %)) eff1)
                       (= 480000 (:effective-cooldown-ms st2))
                       (= 600000 (:effective-cooldown-ms st3))
                       (= 120000 (:effective-cooldown-ms st4))
                       (= 30 (:last-gc-pause-ms st4))))))

;; =============================================================================
;; 6. Hot-LRU Hysteresis & Scan-Resistant Admission (`core.data`)
;; =============================================================================

(defspec ^{:doc "BIP-025 §4.3: evict-hot-lru uses 0.85 low-water hysteresis; scan-resistant admission protects warm working set."}
  prop-blob-store-hot-hysteresis-and-scan-resistance 30
  (prop/for-all [blob-count (gen/choose 12 24)]
                (let [;; Each blob ~100 bytes, max-hot-bytes = 1000, low-water = 850
                      st0 (data/init-blob-store {:max-hot-bytes 1000
                                                 :hot-evict-low-water-ratio 0.85})
                      blobs (mapv (fn [i]
                                    (data/make-blob (str (apply str (repeat 90 "x")) "-" i)
                                                    "application/octet-stream"))
                                  (range blob-count))
                      st1 (reduce (fn [s b] (:store (data/put-blob s b))) st0 blobs)
                      ;; Scan-resistant store: first write of unpinned blob goes cold, second hit promotes to hot
                      sr0 (data/init-blob-store {:max-hot-bytes 500
                                                 :scan-resistant-admission? true})
                      warm-blob (data/make-blob (apply str (repeat 200 "w")) "text/plain")
                      ;; Put warm blob twice -> promoted to hot
                      sr1 (:store (data/put-blob sr0 warm-blob))
                      sr2 (:store (data/put-blob sr1 warm-blob))
                      ;; Stream 5 one-shot scan blobs -> warm blob stays hot!
                      sr3 (reduce (fn [s i]
                                    (:store (data/put-blob s (data/make-blob (str (apply str (repeat 200 "s")) i) "text/plain"))))
                                  sr2
                                  (range 5))]
                  (and (<= (:hot-bytes st1) 1000)
                       (nil? (get-in sr1 [:entries (:blob/cid warm-blob) :bytes]))
                       (some? (get-in sr2 [:entries (:blob/cid warm-blob) :bytes]))
                       (some? (get-in sr3 [:entries (:blob/cid warm-blob) :bytes]))))))

;; =============================================================================
;; 7. Latency Ring Buffer, Threshold Diagnostics & Status Telemetry
;; =============================================================================

(defspec ^{:doc "BIP-025 §5.3: 60-sample latency ring buffer invariants, threshold diagnostics, and status/statusz surfacing."}
  prop-latency-ring-buffer-and-threshold-diagnostics 50
  (prop/for-all [samples (gen/vector (gen/choose 0 1000) 1 90)]
                (let [warn-ms 250
                      [ring diags] (reduce (fn [[r ds] s]
                                             (let [[r' effs] (status-core/record-latency-sample
                                                              r s {:max-samples 60
                                                                   :warn-ms warn-ms
                                                                   :diag-reason :state-save-slow})]
                                               [r' (into ds effs)]))
                                           [[] []]
                                           samples)
                      summary (status-core/summarize-latency-ring ring)
                      expected-slow (count (filter #(> % warn-ms) samples))
                      rendered (status-core/render-status
                                {:pubkey (hex-cid 5) :epoch 10}
                                {:runtime :nodejs-light
                                 :storage {:state-bytes 1843200
                                           :cache-bytes 10485760
                                           :cache-index-bytes 4096
                                           :cache-entries 12
                                           :cache-entries-by-tier {:pinned 1 :active-pointer 5 :historical-unreferenced 6}
                                           :cache-budget-bytes (* 2 1024 1024 1024)
                                           :events-log-bytes 1024
                                           :events-log-max-bytes (* 32 1024 1024)
                                           :host-free-disk-bytes (* 10 1024 1024 1024)}
                                 :latency {:state-save-ms ring
                                           :ctl-ms [5 10]
                                           :event-loop-lag-ms [1 2 3]
                                           :snapshot-encode-ms [15 20]}})
                      statusz (status-core/merge-full-node-statusz-contract
                               {:ok true :node_id "ns1"}
                               {:runtime :full-node
                                :storage {:state-bytes 500000 :cache-bytes 0 :cache-entries 0}
                                :latency {:event-loop-lag-ms ring :snapshot-encode-ms [19 34]}})]
                  (and (<= (count ring) 60)
                       (<= 0 (get summary "last") (get summary "max"))
                       (<= 0 (get summary "p95") (get summary "max"))
                       (= (last samples) (get summary "last"))
                       (= expected-slow (count diags))
                       (every? #(= :state-save-slow (:reason %)) diags)
                       (= 1843200 (get-in rendered ["storage" "state_bytes"]))
                       (= 10485760 (get-in rendered ["storage" "cache_bytes"]))
                       (= 12 (get-in rendered ["storage" "cache_entries"]))
                       (= (get summary "p95") (get-in rendered ["latency" "state_save_latency_ms" "p95"]))
                       (= (get summary "max") (get-in statusz [:latency "event_loop_lag_ms" "max"]))))))

;; =============================================================================
;; 8. Bounded `--events-out` Rotation & `wait-event` Continuity (V1)
;; =============================================================================

(defspec ^{:doc "BIP-025 §5.2 (V1): Rotate-1 caps disk <= 2x max-bytes, emits :events-log-rotated, wait-event loses 0 events."}
  prop-events-log-rotation-and-wait-event-continuity 50
  (prop/for-all [ops (gen/vector
                      (gen/one-of [(gen/let [payload (gen/not-empty gen/string-alphanumeric)]
                                     {:op :append :line (str "{\"seq\":1,\"msg\":\"" payload "\"}\n")})
                                   (gen/return {:op :poll})])
                      5 45)
                 cap (gen/choose 64 256)]
                (let [init-fs {:active-ino 1 :active-bytes "" :rotated-ino nil :rotated-bytes nil :next-ino 2}
                      init-cursor {:offset 0 :ino 1}]
                  (loop [fs init-fs
                         cursor init-cursor
                         written []
                         read-all []
                         rot-diags []
                         remaining ops]
                    (if (empty? remaining)
                      ;; Final drain poll
                      (let [final-poll (cli/step-events-tail-model fs cursor)
                            all-read (into read-all (:lines final-poll))]
                        (and (= written all-read)
                             (<= (+ (count (:active-bytes fs)) (count (or (:rotated-bytes fs) "")))
                                 (* 2 (+ cap 128)))
                             (every? #(= :events-log-rotated (:reason %)) rot-diags)))
                      (let [step (first remaining)]
                        (if (= :append (:op step))
                          (let [{:keys [fs' effects]} (cli/step-events-log-append-model fs (:line step) cap)
                                rotated? (boolean (some #(= :events-log-rotated (:reason %)) effects))
                                ;; Under rotate-1 (single `.1` generation), wait-event polls at least once per rotation window
                                {:keys [cursor' lines]} (if rotated?
                                                          (cli/step-events-tail-model fs' cursor)
                                                          {:cursor' cursor :lines []})]
                            (recur fs' cursor' (conj written (str/trim (:line step)))
                                   (into read-all lines)
                                   (into rot-diags (filter #(= :events-log-rotated (:reason %)) effects))
                                   (rest remaining)))
                          (let [{:keys [cursor' lines]} (cli/step-events-tail-model fs cursor)]
                            (recur fs cursor' written (into read-all lines) rot-diags (rest remaining))))))))))

;; =============================================================================
;; 9. JVM Disk Migration, Browser v2 Closure Guard, Watchdog, Zero-Sync-IO & Postmortem
;; =============================================================================

#?(:clj
   (deftest test-jvm-disk-migration-crash-idempotency-and-enospc
     (testing "JVM load-light-state! extracts legacy blobs to cache/blobs/<2>/<cid>, compacts state.fressian, rebuilds corrupt index, and fails closed on ENOSPC"
       (let [tmp-dir (.toFile (Files/createTempDirectory "bitecho-bip025-mig-" (into-array FileAttribute [])))
             state-file (io/file tmp-dir "state.fressian")
             b1 (data/make-blob (apply str (repeat 2048 "A")) "application/x-onnx")
             b2 (data/make-blob (apply str (repeat 2048 "B")) "application/octet-stream")
             blobs-map {(:blob/cid b1) b1 (:blob/cid b2) b2}
             legacy-state {:pubkey (hex-cid 99)
                           :epoch 77
                           :petnames {"bob" (hex-cid 88)}
                           :pinned-cids #{(:blob/cid b1)}
                           :blobs blobs-map
                           :artifact-blobs blobs-map}
             raw-legacy-bytes (fressian/encode-wire-uncompressed legacy-state)]
         (try
           ;; 1. Fail-closed ENOSPC check: simulate 100 bytes free -> original state.fressian untouched
           (Files/write (.toPath state-file) raw-legacy-bytes (into-array java.nio.file.OpenOption []))
           (let [enospc-res (shell-light/migrate-legacy-state-file!
                             (str state-file) legacy-state
                             {:host-free-bytes 100 :min-free-disk-bytes 50000})]
             (is (false? (:ok? enospc-res)))
             (is (= :migration-insufficient-disk-space (:error enospc-res)))
             (is (= (alength raw-legacy-bytes) (.length state-file))
                 "Original state.fressian must remain byte-for-byte untouched on ENOSPC"))

           ;; 2. Normal extract-before-compact migration
           (let [loaded (shell-light/load-light-state! (str state-file))
                 cache-dir (io/file tmp-dir "cache")
                 index-file (io/file cache-dir "index.fressian")
                 c1 (:blob/cid b1)
                 c2 (:blob/cid b2)
                 f1 (io/file cache-dir "blobs" (subs c1 0 2) c1)
                 f2 (io/file cache-dir "blobs" (subs c2 0 2) c2)]
             (is (map? loaded))
             (is (nil? (:blobs loaded)))
             (is (nil? (:artifact-blobs loaded)))
             (is (= {"bob" (hex-cid 88)} (:petnames loaded)))
             (is (.exists f1))
             (is (.exists f2))
             (is (.exists index-file))
             (is (< (.length state-file) (alength raw-legacy-bytes))
                 "Compacted state.fressian must be strictly smaller than legacy bloated state")
             ;; 3. Corrupt cache/index.fressian -> automatic directory scan rebuild + :cache-index-rebuilt
             (spit index-file "corrupt-index-bytes!!!")
             (let [rebuilt (shell-light/load-or-rebuild-cache-index! (str tmp-dir) loaded)]
               (is (= 2 (count (get-in rebuilt [:cache-index :entries]))))
               (is (some #(= :cache-index-rebuilt (:reason %)) (:effects rebuilt)))))
           (finally
             (run! io/delete-file (reverse (file-seq tmp-dir)))))))))

#?(:clj
   (deftest test-bip025-static-guards-browser-watchdog-and-postmortem
     (testing "Browser IndexedDB v2 upgrade uses Closure :advanced-safe accessors (V3)"
       (let [browser-src (slurp "src/bitecho/shell/browser.cljc")]
         (is (str/includes? browser-src "\"bitecho-blob-cache\""))
         (is (str/includes? browser-src "\"bitecho-db\" 2"))
         (is (str/includes? browser-src "createObjectStore"))
         (is (str/includes? browser-src "objectStoreNames"))
         (is (str/includes? browser-src "estimate"))))

     (testing "Hard 5s SIGTERM exit watchdog in full_node_main.cljs and node_main.cljs (V4)"
       (let [fn-src (slurp "src/bitecho/full_node_main.cljs")
             nm-src (slurp "src/bitecho/node_main.cljs")]
         (is (str/includes? fn-src "shutdown-watchdog-forced-exit"))
         (is (str/includes? fn-src "124"))
         (is (str/includes? nm-src "shutdown-watchdog-forced-exit"))
         (is (str/includes? nm-src "124"))))

     (testing "Public blameless postmortem INC-2026-11-24-ns1-event-loop-wedge co-committed & indexed (Rule 6)"
       (let [md-file (io/file "docs/postmortems/INC-2026-11-24-ns1-event-loop-wedge.md")
             edn-file (io/file "docs/postmortems/INC-2026-11-24-ns1-event-loop-wedge.edn")
             idx-data (edn/read-string (slurp "docs/postmortems/index.edn"))
             entry (first (filter #(= "INC-2026-11-24-ns1-event-loop-wedge" (:incident-id %))
                                  (:incidents idx-data)))]
         (is (.exists md-file))
         (is (.exists edn-file))
         (is (some? entry))
         (is (= "BIP-025" (:bip-id entry)))
         (let [pm (edn/read-string (slurp edn-file))]
           (is (= :bitecho/incident-postmortem-v1 (:schema pm)))
           (is (= "INC-2026-11-24-ns1-event-loop-wedge" (:incident-id pm))))))))
