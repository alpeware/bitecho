(ns bitecho.d46-bip019-fepoch1-test
  "BIP-019 Draft 2 (`F-EPOCH-1` Finalization Stall) Strict TDD Verification Suite:
   - S2: Immutable `:executed-root-depths`, pruned-root late-fork & `ingest-verified-ancestors` depth safety,
         counted Rule 5 `:corrupt-block-depth-repaired` diagnostics, stateful lifecycle generator & MUT-* gate.
   - S3: Honest SLA stall persistence across restarts (`observability.core/record-startup-event`)
         and light-node `auto-sync` stall detection (`light_node.core/evaluate-auto-sync-stall` & `exec-status`).
   - Postmortem #2: `INC-2026-11-22-fepoch1.{edn,md}` schema validation and `index.edn` registration."
  (:require #?(:clj [bitecho.ops.incident :as incident])
            #?(:clj [clojure.edn :as edn])
            #?(:clj [clojure.java.io :as io])
            #?(:clj [clojure.string :as str])
            [bitecho.basalt.core :as basalt]
            [bitecho.core.mesh :as core-mesh]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.observability.core :as obs]
            [bitecho.streamlet.core :as streamlet]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; S2: Immutable :executed-root-depths & Pruned-Root Depth Invariants
;; =============================================================================

(defspec ^{:doc "S2.1: :executed-root-depths preserves true topological depth of executed roots across >256-epoch pruning; late forks on pruned executed roots use true depth (never epoch or :last-executed-finalized-epoch)."}
  prop-executed-root-depths-preserved-across-prune-and-late-fork 100
  (prop/for-all [skip-count (gen/choose 2 40)
                 prune-advance (gen/choose 260 320)]
                (let [;; Build a short chain with skipped epochs:
                      ;; root-1 at epoch (1 + skip-count), true depth = 1
                      ;; root-2 at epoch (2 + skip-count), true depth = 2
                      ep1 (+ 1 skip-count)
                      ep2 (+ 2 skip-count)
                      ep-tip (+ ep2 prune-advance)
                      h1 "exec-root-1"
                      h2 "exec-root-2"
                      h-tip "active-tip"
                      b1 (streamlet/->Block ep1 "genesis" [] "val1")
                      b2 (streamlet/->Block ep2 h1 [] "val2")
                      b-tip (streamlet/->Block ep-tip h2 [] "val1")
                      ;; Initial state before pruning: h1 and h2 are finalized & executed, with true depths 1 and 2
                      init-state {:epoch ep-tip
                                  :head-hash h-tip
                                  :latest-finalized-block-hash h2
                                  :blocks {h1 b1 h2 b2 h-tip b-tip}
                                  :notarized-blocks #{h1 h2 h-tip}
                                  :finalized-blocks #{h1 h2}
                                  :executed-finalized-blocks #{h1 h2}
                                  :last-executed-finalized-epoch ep2
                                  :block-depths {h1 1 h2 2 h-tip 3}
                                  :executed-root-depths {h1 1 h2 2}}
                      pruned (streamlet/prune-streamlet-state init-state)
                      ;; h1 is older than (ep-tip - 256) and not referenced as parent of h-tip, so it gets pruned from :blocks & :block-depths
                      ;; Its true depth MUST survive in :executed-root-depths!
                      h1-depth-survived? (= 1 (get-in pruned [:executed-root-depths h1]))
                      ;; Now a late fork block arrives whose parent is the pruned executed root h1
                      late-ep (inc ep1)
                      h-late "late-fork-on-pruned-root"
                      b-late (streamlet/->Block late-ep h1 [] "val2")
                      with-late (-> pruned
                                    (assoc-in [:blocks h-late] b-late)
                                    (streamlet/record-block-depth h-late)
                                    (update :notarized-blocks conj h-late))
                      d-late (get-in with-late [:block-depths h-late])
                      d-tip (get-in with-late [:block-depths h-tip])]
                  (and h1-depth-survived?
                       (= d-late 2)
                       (<= d-late late-ep)
                       (< d-late d-tip)
                       (streamlet/longest-notarized-parent? with-late h-tip (inc ep-tip))
                       (not (streamlet/longest-notarized-parent? with-late h-late (inc ep-tip)))))))

(defn- make-test-validators
  []
  (let [kps (mapv (fn [_]
                    (let [kp (crypto/generate-keypair)]
                      {:kp kp
                       :pub-hex (basalt/bytes->hex (:public kp))
                       :pub-bytes (:public kp)
                       :priv-bytes (:private kp)}))
                  (range 3))
        sorted-kps (vec (sort-by :pub-hex kps))
        peers-map (into {} (map (fn [{:keys [pub-hex pub-bytes]}] [pub-hex pub-bytes]) sorted-kps))
        validators (mapv :pub-hex sorted-kps)]
    {:kps sorted-kps
     :peers-map peers-map
     :validators validators}))

(defspec ^{:doc "S2.2: ingest-verified-ancestors consults :executed-root-depths before any fallback and NEVER seeds depth from :epoch or :last-executed-finalized-epoch."}
  prop-ingest-verified-ancestors-uses-executed-root-depths-never-epoch 50
  (prop/for-all [skip-epochs (gen/choose 10 80)
                 true-parent-depth (gen/choose 1 5)]
                (let [{:keys [kps peers-map validators]} (make-test-validators)
                      anc-epoch (+ true-parent-depth skip-epochs)
                      leader (nth kps (mod anc-epoch (count kps)))
                      pruned-parent-hash "pruned-exec-root-abc"
                      raw-blk (streamlet/->Block anc-epoch pruned-parent-hash [] (:pub-hex leader))
                      signed-blk (streamlet/sign-block raw-blk (:priv-bytes leader))
                      b-hash (streamlet/hash-block signed-blk)
                      votes-map (into {}
                                      (map (fn [{:keys [pub-hex priv-bytes]}]
                                             (let [sig (basalt/bytes->hex (crypto/sign priv-bytes (fressian/utf8->bytes b-hash)))]
                                               [pub-hex (streamlet/->Vote b-hash anc-epoch sig)]))
                                           kps))
                      ;; Case A: parent is in :executed-root-depths with true-parent-depth
                      state-a {:epoch anc-epoch
                               :peers-map peers-map
                               :validators validators
                               :blocks {}
                               :notarized-blocks #{}
                               :executed-finalized-blocks #{pruned-parent-hash}
                               :executed-root-depths {pruned-parent-hash true-parent-depth}
                               :last-executed-finalized-epoch (+ anc-epoch 25)
                               :block-depths {}}
                      ingested-a (streamlet/ingest-verified-ancestors state-a [{:block signed-blk :votes votes-map}])
                      d-a (get-in ingested-a [:block-depths b-hash])
                      ;; Case B: parent is completely unknown (not in :blocks, :block-depths, or :executed-root-depths)
                      state-b (assoc state-a :executed-finalized-blocks #{} :executed-root-depths {})
                      ingested-b (streamlet/ingest-verified-ancestors state-b [{:block signed-blk :votes votes-map}])
                      d-b (get-in ingested-b [:block-depths b-hash])]
                  (and (= d-a (inc true-parent-depth))
                       (<= d-a anc-epoch)
                       (some? d-b)
                       (pos? d-b)
                       (< d-b anc-epoch)
                       (<= d-b 2)))))

(defspec ^{:doc "S2.3: repair-corrupt-block-depths repairs all depth > epoch entries, increments counted Rule 5 :corrupt-block-depth-repaired diagnostic, emits :diagnose event, and surfaces counter in /statusz."}
  prop-repair-corrupt-block-depths-emits-counted-diagnose 100
  (prop/for-all [corrupt-count (gen/choose 1 5)
                 extra-poison (gen/choose 5 50)]
                (let [blocks (into {}
                                   (map (fn [i]
                                          (let [h (str "blk-" i)
                                                p (if (= i 1) "genesis" (str "blk-" (dec i)))]
                                            [h (streamlet/->Block (* i 2) p [] "val1")])))
                                   (range 1 (inc corrupt-count)))
                      poisoned-depths (into {}
                                            (map (fn [i]
                                                   [(str "blk-" i) (+ (* i 2) extra-poison)]))
                                            (range 1 (inc corrupt-count)))
                      state {:epoch (+ (* corrupt-count 2) extra-poison)
                             :node-pubkey "val1"
                             :validators ["val1"]
                             :blocks blocks
                             :notarized-blocks (set (keys blocks))
                             :block-depths poisoned-depths}
                      repaired (streamlet/repair-corrupt-block-depths state)
                      all-valid? (every? (fn [[h b]]
                                           (let [d (get-in repaired [:block-depths h])]
                                             (and (some? d) (<= (long d) (long (:epoch b))))))
                                         blocks)
                      diag-count (get-in repaired [:diagnostics :corrupt-block-depth-repaired] 0)
                      diag-events (get-in repaired [:diagnostics :corrupt-block-depth-repaired-events] [])
                      last-ev (peek diag-events)
                      statusz-line (core-mesh/render-statusz repaired 1 1)
                      parsed-statusz (core-mesh/parse-statusz-line statusz-line)]
                  (and all-valid?
                       (= diag-count corrupt-count)
                       (= :diagnose (:effect last-ev))
                       (= :corrupt-block-depth-repaired (:reason last-ev))
                       (= corrupt-count (:count last-ev))
                       (= corrupt-count (count (:hashes last-ev)))
                       (= corrupt-count (:corrupt_block_depth_repaired parsed-statusz))))))

(deftest test-s2-mut-non-vacuity-epoch-as-depth-deadlock-vs-hardened
  (testing "MUT-* non-vacuity: pre-fix epoch-as-depth logic poisons late fork above tip-depth, whereas hardened :executed-root-depths prevents it"
    (let [;; Skipped epochs: tip is at epoch 100, depth 60; executed root p is at epoch 50, true depth 10.
          ;; Watermark :last-executed-finalized-epoch is 95.
          p-hash "exec-root-p"
          late-hash "late-fork"
          tip-hash "canonical-tip"
          base-state {:epoch 100
                      :head-hash tip-hash
                      :blocks {late-hash (streamlet/->Block 51 p-hash [] "v1")
                               tip-hash (streamlet/->Block 100 "mid-99" [] "v1")}
                      :notarized-blocks #{late-hash tip-hash}
                      :executed-finalized-blocks #{p-hash}
                      :executed-root-depths {p-hash 10}
                      :last-executed-finalized-epoch 95
                      :block-depths {tip-hash 60}}
          ;; Mutant (pre-fix): seeds p-hash depth from :last-executed-finalized-epoch (95) -> late-hash gets depth 96 > 60 (DEADLOCK!)
          mutant-state (-> base-state
                           (assoc-in [:block-depths p-hash] 95)
                           (assoc-in [:block-depths late-hash] 96))
          ;; Hardened code: uses :executed-root-depths {p-hash 10} -> late-hash gets depth 11 < 60
          hardened-state (streamlet/record-block-depth base-state late-hash)]
      ;; Mutant deadlocks longest-notarized-parent? for true tip
      (is (not (streamlet/longest-notarized-parent? mutant-state tip-hash 101)))
      (is (streamlet/longest-notarized-parent? mutant-state late-hash 101))
      ;; Hardened code preserves true tip selection and depth <= epoch
      (is (= 11 (get-in hardened-state [:block-depths late-hash])))
      (is (streamlet/longest-notarized-parent? hardened-state tip-hash 101))
      (is (not (streamlet/longest-notarized-parent? hardened-state late-hash 101)))
      ;; Repair heals mutant and emits counted Rule 5 diagnostic
      (let [healed (streamlet/repair-corrupt-block-depths mutant-state)]
        (is (= 11 (get-in healed [:block-depths late-hash])))
        (is (pos? (get-in healed [:diagnostics :corrupt-block-depth-repaired] 0)))
        (is (streamlet/longest-notarized-parent? healed tip-hash 101))))))

(defspec ^{:doc "S2.4: Seeded stateful command-sequence lifecycle generator interleaving skipped epochs, forks, finalization, pruning (>256 epochs), and late-fork arrivals maintains depth <= epoch and 0 unexpected repairs."}
  prop-stateful-streamlet-lifecycle-depth-invariant 50
  (prop/for-all [steps (gen/vector
                        (gen/one-of
                         [(gen/tuple (gen/return :advance) (gen/choose 1 5))
                          (gen/tuple (gen/return :skip-and-advance) (gen/choose 2 15))
                          (gen/return :finalize-and-exec)
                          (gen/tuple (gen/return :prune-jump) (gen/choose 260 280))
                          (gen/return :late-fork-on-exec-root)])
                        5 25)]
                (let [init-state {:epoch 0
                                  :head-hash "genesis"
                                  :blocks {}
                                  :notarized-blocks #{}
                                  :finalized-blocks #{}
                                  :executed-finalized-blocks #{}
                                  :executed-root-depths {}
                                  :last-executed-finalized-epoch 0
                                  :block-depths {}
                                  :next-id 1}
                      final-st
                      (reduce
                       (fn [st step]
                         (let [op (if (vector? step) (first step) step)]
                           (case op
                             (:advance :skip-and-advance)
                             (let [delta (second step)
                                   ep (+ (long (:epoch st)) (long delta))
                                   parent (:head-hash st)
                                   h (str "b-" (:next-id st))
                                   blk (streamlet/->Block ep parent [] "v1")]
                               (-> st
                                   (assoc :epoch ep :head-hash h)
                                   (update :next-id inc)
                                   (assoc-in [:blocks h] blk)
                                   (streamlet/record-block-depth h)
                                   (update :notarized-blocks conj h)))

                             :finalize-and-exec
                             (let [h (:head-hash st)]
                               (if (= h "genesis")
                                 st
                                 (let [b (get-in st [:blocks h])
                                       d (or (get-in st [:block-depths h])
                                             (streamlet/chain-length (:blocks st) h (:block-depths st)))]
                                   (cond-> (-> st
                                               (update :finalized-blocks conj h)
                                               (assoc :latest-finalized-block-hash h)
                                               (update :executed-finalized-blocks conj h)
                                               (assoc :last-executed-finalized-epoch (max (long (:last-executed-finalized-epoch st 0))
                                                                                          (long (:epoch b 0)))))
                                     (and (integer? d) (pos? d))
                                     (update :executed-root-depths (fn [m] (if (contains? m h) m (assoc (or m {}) h d))))))))

                             :prune-jump
                             (let [jump (second step)
                                   ep (+ (long (:epoch st)) (long jump))]
                               (-> st
                                   (assoc :epoch ep)
                                   streamlet/prune-streamlet-state))

                             :late-fork-on-exec-root
                             (let [exec-roots (vec (keys (:executed-root-depths st)))]
                               (if (empty? exec-roots)
                                 st
                                 (let [root-h (first exec-roots)
                                       root-d (get-in st [:executed-root-depths root-h])
                                       fork-ep (max (inc (long root-d)) (inc (long (or (get-in st [:blocks root-h :epoch]) root-d))))
                                       h (str "fork-" (:next-id st))
                                       blk (streamlet/->Block fork-ep root-h [] "v2")]
                                   (-> st
                                       (update :next-id inc)
                                       (assoc-in [:blocks h] blk)
                                       (streamlet/record-block-depth h)
                                       (update :notarized-blocks conj h))))))))
                       init-state
                       steps)
                      all-depths-le-epoch? (every? (fn [[h d]]
                                                     (if-let [b (get-in final-st [:blocks h])]
                                                       (<= (long d) (long (:epoch b)))
                                                       true))
                                                   (:block-depths final-st))
                      repaired (streamlet/repair-corrupt-block-depths final-st)
                      zero-unexpected-repairs? (zero? (get-in repaired [:diagnostics :corrupt-block-depth-repaired] 0))]
                  (and all-depths-le-epoch? zero-unexpected-repairs?))))

;; =============================================================================
;; S3.1: Honest SLA Stall Persistence Across Restarts (observability.core)
;; =============================================================================

(defspec ^{:doc "S3.1: record-startup-event NEVER clears :active-stall-started-ms during an ongoing stall, so sla/latest.edn records true end-to-end wall-clock stall duration across restarts."}
  prop-observability-stall-persists-across-restarts 100
  (prop/for-all [restart-count (gen/choose 1 5)
                 restart-gap-ms (gen/choose 5000 60000)
                 post-restart-ms (gen/choose 10000 120000)
                 planned? gen/boolean]
                (let [t0 1795200000000
                      t-stall (+ t0 10000)
                      l0 (obs/record-startup-event nil {:node-id "node1" :now-ms t0})
                      ;; Stall starts at t-stall (head=85710, finalized=85690 -> lag 20 > 10)
                      l-stalled (obs/record-stall-sample l0 {:node-id "node1"
                                                             :now-ms t-stall
                                                             :head-epoch 85710
                                                             :finalized-epoch 85690
                                                             :max-healthy-lag 10})
                      ;; Perform restart-count restarts while stall is still ongoing
                      [l-after-restarts t-curr]
                      (reduce (fn [[l t] _]
                                (let [t-stop (+ t restart-gap-ms)
                                      t-start (+ t-stop 3000)
                                      l-marked (if planned?
                                                 (obs/record-shutdown-marker l {:now-ms t-stop :cause :planned-deploy})
                                                 l)
                                      l-up (obs/record-startup-event l-marked {:node-id "node1" :now-ms t-start})]
                                  [l-up t-start]))
                              [l-stalled t-stall]
                              (range restart-count))
                      ;; Active stall start MUST still be t-stall!
                      preserved-across-restarts? (= t-stall (:active-stall-started-ms l-after-restarts))
                      ;; Recovery occurs post-restart-ms later
                      t-recover (+ t-curr post-restart-ms)
                      l-recovered (obs/record-stall-sample l-after-restarts {:node-id "node1"
                                                                             :now-ms t-recover
                                                                             :head-epoch 85750
                                                                             :finalized-epoch 85749
                                                                             :max-healthy-lag 10})
                      expected-dur (- t-recover t-stall)
                      stall-ev (first (filter #(= :finalization-stall (:cause %)) (:downtime-events l-recovered)))
                      digest (obs/build-telemetry-digest {:node-id "node1"
                                                          :uptime-ms post-restart-ms
                                                          :restart-count (:restart-count l-recovered)
                                                          :restart-causes (:restart-causes l-recovered)
                                                          :downtime-events (obs/effective-downtime-events l-recovered t-recover)
                                                          :head-epoch 85750
                                                          :finalized-epoch 85749})
                      sla (obs/compute-six-nines-sla [digest] {:window-ms 86400000 :now-ms t-recover})]
                  (and preserved-across-restarts?
                       (nil? (:active-stall-started-ms l-recovered))
                       (some? stall-ev)
                       (= expected-dur (:duration-ms stall-ev))
                       (>= (:consensus-breach-ms sla) expected-dur)
                       (not (:six-nines-met? sla))))))

;; =============================================================================
;; S3.2: Light-Node auto-sync Stall Honesty (light_node.core)
;; =============================================================================

(defspec ^{:doc "S3.2: evaluate-auto-sync-stall emits counted Rule 5 :diagnose {:reason :finalized-epoch-stalled} and surfaces :stalled? true in exec-status when finalized-epoch is frozen beyond stall-threshold-ms, and clears once finalized-epoch advances."}
  prop-light-node-auto-sync-stall-honesty 100
  (prop/for-all [frozen-epoch (gen/choose 100 100000)
                 threshold-ms (gen/choose 30000 300000)
                 extra-stall-ms (gen/choose 1 120000)]
                (let [t0 1795200000000
                      st0 {:pubkey "abc" :epoch frozen-epoch :account {:finalized-epoch frozen-epoch :balance 1000 :spendable 1000}}
                      ;; First observation at t0 establishes baseline -> ok, synced, not stalled
                      r1 (light-core/evaluate-auto-sync-stall st0 frozen-epoch t0 {:stall-threshold-ms threshold-ms})
                      ;; Observation before threshold -> still ok, synced, not stalled
                      t-mid (+ t0 (quot threshold-ms 2))
                      r2 (light-core/evaluate-auto-sync-stall (:state r1) frozen-epoch t-mid {:stall-threshold-ms threshold-ms})
                      ;; Observation at/beyond threshold with same frozen-epoch -> STALLED!
                      t-stalled (+ t0 threshold-ms extra-stall-ms)
                      r3 (light-core/evaluate-auto-sync-stall (:state r2) frozen-epoch t-stalled {:stall-threshold-ms threshold-ms})
                      status-stalled (light-core/exec-status (:state r3))
                      ;; Finalized epoch advances -> stall clears!
                      t-rec (+ t-stalled 6000)
                      r4 (light-core/evaluate-auto-sync-stall (:state r3) (inc frozen-epoch) t-rec {:stall-threshold-ms threshold-ms})
                      status-recovered (light-core/exec-status (:state r4))]
                  (and (true? (:ok? r1)) (true? (:synced? r1)) (false? (:stalled? r1)) (nil? (:diagnose r1))
                       (true? (:ok? r2)) (true? (:synced? r2)) (false? (:stalled? r2)) (nil? (:diagnose r2))
                       (false? (:ok? r3))
                       (false? (:synced? r3))
                       (true? (:stalled? r3))
                       (= :diagnose (get-in r3 [:diagnose :effect]))
                       (= :finalized-epoch-stalled (get-in r3 [:diagnose :reason]))
                       (= frozen-epoch (get-in r3 [:diagnose :finalized-epoch]))
                       (= (+ threshold-ms extra-stall-ms) (get-in r3 [:diagnose :stall-duration-ms]))
                       (= 1 (get-in r3 [:state :diagnostics :finalized-epoch-stalled]))
                       (true? (get status-stalled "stalled"))
                       (true? (:stalled? status-stalled))
                       (true? (:ok? r4))
                       (true? (:synced? r4))
                       (false? (:stalled? r4))
                       (false? (get status-recovered "stalled"))
                       (false? (:stalled? status-recovered))))))

;; =============================================================================
;; Postmortem #2 (INC-2026-11-22-fepoch1) & Shell Wiring Verification
;; =============================================================================

#?(:clj
   (deftest test-bip019-postmortem-fepoch1-valid-and-indexed
     (testing "INC-2026-11-22-fepoch1.edn passes incident/validate-postmortem-record, has generator-case metadata, and is indexed"
       (let [pm-edn-file (io/file "docs/postmortems/INC-2026-11-22-fepoch1.edn")
             pm-md-file (io/file "docs/postmortems/INC-2026-11-22-fepoch1.md")
             idx-file (io/file "docs/postmortems/index.edn")]
         (is (.exists pm-edn-file) "INC-2026-11-22-fepoch1.edn must exist")
         (is (.exists pm-md-file) "INC-2026-11-22-fepoch1.md must exist")
         (let [pm (edn/read-string (slurp pm-edn-file))
               val-res (incident/validate-postmortem-record pm)
               idx (edn/read-string (slurp idx-file))
               entry (first (filter #(= "INC-2026-11-22-fepoch1" (:incident-id %)) (:incidents idx)))]
           (is (:ok? val-res) (str "Postmortem validation failed: " (pr-str (:errors val-res))))
           (is (= "INC-2026-11-22-fepoch1" (:incident-id pm)))
           (is (true? (:generator-case-added? pm)))
           (is (= "bitecho.d45-bip018-hardening-and-failover-test/prop-streamlet-block-depth-never-exceeds-epoch-and-self-heals"
                  (:generator-case-var pm)))
           (is (some? entry) "INC-2026-11-22-fepoch1 must be indexed in docs/postmortems/index.edn")
           (is (= "docs/postmortems/INC-2026-11-22-fepoch1.edn" (:edn-path entry)))
           (is (= "docs/postmortems/INC-2026-11-22-fepoch1.md" (:md-path entry))))))

     (testing "Shell wiring: node_main.cljs wires evaluate-auto-sync-stall and full_node_main.cljs surfaces :corrupt-block-depth-repaired"
       (let [node-src (slurp (io/file "src/bitecho/node_main.cljs"))
             full-src (slurp (io/file "src/bitecho/full_node_main.cljs"))]
         (is (str/includes? node-src "evaluate-auto-sync-stall")
             "node_main.cljs must evaluate auto-sync finalized-epoch stalls")
         (is (str/includes? node-src ":finalized-epoch-stalled")
             "node_main.cljs must emit counted :finalized-epoch-stalled diagnostic")
         (is (str/includes? full-src ":corrupt-block-depth-repaired")
             "full_node_main.cljs must surface :corrupt-block-depth-repaired in telemetry digest")))))

;; =============================================================================
;; BIP-019-SOAK-F1: Epoch-Dwell Double-Tick Guard (Eliminating ~97s Fork Stalls)
;; =============================================================================

(defn- make-timed-streamlet-cluster
  [n tick-ms]
  (let [kps (repeatedly n crypto/generate-keypair)
        hexes (mapv #(basalt/bytes->hex (:public %)) kps)
        sorted-pairs (sort-by first (map vector hexes kps))
        peers-map (into {} (map (fn [[h kp]] [h (:public kp)]) sorted-pairs))
        validators (mapv first sorted-pairs)]
    (mapv (fn [[h kp]]
            {:node-pubkey h
             :keypair kp
             :peers-map peers-map
             :validators validators
             :config {:tick-interval-ms tick-ms}
             :epoch 0
             :blocks {}
             :block-depths {}
             :notarized-blocks #{}
             :finalized-blocks #{}
             :block-votes {}
             :block-vote-proofs {}
             :voted-epochs #{}
             :head-hash "genesis"
             :mempool []})
          sorted-pairs)))

(defn- run-timed-streamlet-sim
  "Deterministic discrete-event simulator for N Streamlet validators with per-node
   tick phase offsets and network latency `net-ms`. Optionally supports killing
   `kill-idx` during `[kill-start-ms, kill-end-ms)` and restarting it with
   `restart-phase-ms` from a snapshot captured `snap-lag-ticks` (default 3) before kill."
  [{:keys [n tick-ms phases net-ms total-ticks kill-idx kill-start-ms kill-end-ms restart-phase-ms snap-lag-ticks]}]
  (let [snap-lag (long (or snap-lag-ticks 3))
        nodes (atom (make-timed-streamlet-cluster n tick-ms))
        saved-snap (atom nil)
        killed? (atom false)
        restarted? (atom false)
        seq-id (atom 0)
        q (atom (sorted-set-by (fn [a b] (compare [(first a) (second a)] [(first b) (second b)]))))
        hex->idx (into {} (map-indexed (fn [i st] [(:node-pubkey st) i]) @nodes))
        sched! (fn [t idx ev] (swap! q conj [t (swap! seq-id inc) idx ev]))
        total-ms (* total-ticks tick-ms)
        post-recovery-start-ms (when kill-end-ms (+ (long kill-end-ms) (* 4 (long tick-ms))))
        diag-suppressed (atom 0)]
    (dotimes [i n]
      (sched! (+ tick-ms (nth phases i)) i {:type :tick :now-ms (+ tick-ms (nth phases i))}))
    (loop [max-fin-gap 0
           post-restart-max-fin-gap 0]
      (if-let [[t _ idx ev :as item] (first @q)]
        (if (> t total-ms)
          (let [live-idx (if (= kill-idx 0) 1 0)
                live-st (nth @nodes live-idx)
                notarized-epochs (into #{}
                                       (keep #(get-in live-st [:blocks % :epoch]))
                                       (:notarized-blocks live-st))]
            {:final-epochs (mapv :epoch @nodes)
             :final-fin (mapv (fn [st]
                                (if-let [h (:latest-finalized-block-hash st)]
                                  (long (get-in st [:blocks h :epoch] 0))
                                  0))
                              @nodes)
             :max-fin-gap max-fin-gap
             :post-restart-max-fin-gap post-restart-max-fin-gap
             :notarized-epochs notarized-epochs
             :suppressed-diag-count @diag-suppressed
             :suppressed-state-counts (mapv #(long (get-in % [:diagnostics :tick-suppressed-epoch-already-advanced] 0)) @nodes)})
          (do
            (swap! q disj item)
            (when (and (some? kill-idx) (nil? @saved-snap) (>= t (- kill-start-ms (* snap-lag tick-ms))))
              (reset! saved-snap (core-mesh/strip-unserializable-state (nth @nodes kill-idx))))
            (when (and (some? kill-idx) (not @killed?) (>= t kill-start-ms))
              (reset! killed? true))
            (when (and (some? kill-idx) @killed? (not @restarted?) (>= t kill-end-ms))
              (reset! restarted? true)
              (let [orig (nth @nodes kill-idx)
                    restored (assoc (or @saved-snap orig)
                                    :keypair (:keypair orig)
                                    :peers-map (:peers-map orig)
                                    :validators (:validators orig)
                                    :config (:config orig))]
                (swap! nodes assoc kill-idx (dissoc restored :epoch-started-at-ms))
                (let [next-t (+ t (long (or restart-phase-ms 0)))]
                  (sched! next-t kill-idx {:type :tick :now-ms next-t}))))
            (let [node-down? (and (some? kill-idx) (= idx kill-idx) @killed? (not @restarted?))]
              (when-not node-down?
                (when (= (:type ev) :tick)
                  (let [next-t (+ t tick-ms)]
                    (sched! next-t idx {:type :tick :now-ms next-t})))
                (let [st (nth @nodes idx)
                      {:keys [state commands]} (streamlet/handle-streamlet-event st ev)]
                  (swap! nodes assoc idx state)
                  (doseq [cmd commands]
                    (case (:type cmd)
                      :diagnose
                      (when (= :tick-suppressed-epoch-already-advanced (:reason cmd))
                        (swap! diag-suppressed inc))
                      :send-propose
                      (doseq [target (:targets cmd) :when (not= target (:node-pubkey state))]
                        (when-let [tidx (get hex->idx target)]
                          (sched! (+ t net-ms) tidx
                                  {:type :receive-propose
                                   :block (:block cmd)
                                   :ancestors (:ancestors cmd)
                                   :sender (:node-pubkey state)
                                   :now-ms (+ t net-ms)})))
                      :send-vote
                      (doseq [target (:targets cmd) :when (not= target (:node-pubkey state))]
                        (when-let [tidx (get hex->idx target)]
                          (sched! (+ t net-ms) tidx
                                  {:type :receive-vote
                                   :vote (:vote cmd)
                                   :sender (:node-pubkey state)
                                   :now-ms (+ t net-ms)})))
                      nil)))))
            (let [live-idx (if (= kill-idx 0) 1 0)
                  live-st (nth @nodes live-idx)
                  ep (long (or (:epoch live-st) 0))
                  fin (if-let [h (:latest-finalized-block-hash live-st)]
                        (long (get-in live-st [:blocks h :epoch] 0))
                        0)
                  gap (- ep fin)]
              (recur (max max-fin-gap gap)
                     (if (and post-recovery-start-ms (>= t post-recovery-start-ms))
                       (max post-restart-max-fin-gap gap)
                       post-restart-max-fin-gap)))))
        {:empty true}))))

(defspec ^{:doc "BIP-019-SOAK-F1: Wall-clock-aligned validators firing within the (T_propose, T_notarize) killer window never double-tick into sibling forks; finalization advances cleanly at ~1 epoch/tick with counted Rule 5 suppression diagnostics."}
  prop-streamlet-epoch-dwell-prevents-double-tick-fork-stall 20
  (prop/for-all [n (gen/elements [3 6])
                 tick-ms (gen/choose 1000 2000)
                 net-ms (gen/choose 4 10)
                 extra-offset (gen/choose 1 4)]
                (let [step (+ net-ms (min extra-offset (dec net-ms)))
                      phases (mapv #(* % step) (range n))
                      res (run-timed-streamlet-sim {:n n
                                                    :tick-ms tick-ms
                                                    :phases phases
                                                    :net-ms net-ms
                                                    :total-ticks 24})]
                  (and (every? #(>= % 18) (:final-fin res))
                       (every? #(<= % 28) (:final-epochs res))
                       (<= (:max-fin-gap res) 4)
                       (pos? (:suppressed-diag-count res))
                       (some pos? (:suppressed-state-counts res))))))

(defspec ^{:doc "BIP-019-SOAK-F1 security invariant: replaying an old/same-epoch proposal or vote never updates :epoch-started-at-ms and never freezes future ticks; backwards clock jumps never suppress ticks."}
  prop-streamlet-byzantine-old-epoch-replay-never-freezes-tick 50
  (prop/for-all [tick-ms (gen/choose 1000 10000)
                 start-ms (gen/choose 100000 200000)
                 backwards-jump (gen/choose 1 5000)]
                (let [nodes (make-timed-streamlet-cluster 3 tick-ms)
                      v0 (nth nodes 0)
                      v1 (nth nodes 1)
                      r1 (streamlet/handle-streamlet-event v1 {:type :tick :now-ms start-ms})
                      prop-cmd (first (filter #(= :send-propose (:type %)) (:commands r1)))
                      r0-init (streamlet/handle-streamlet-event
                               v0 {:type :receive-propose
                                   :block (:block prop-cmd)
                                   :ancestors (:ancestors prop-cmd)
                                   :sender (:node-pubkey v1)
                                   :now-ms (+ start-ms 5)})
                      st0 (:state r0-init)
                      replay-ms (+ start-ms (- tick-ms 50))
                      r0-replay (streamlet/handle-streamlet-event
                                 st0 {:type :receive-propose
                                      :block (:block prop-cmd)
                                      :ancestors (:ancestors prop-cmd)
                                      :sender (:node-pubkey v1)
                                      :now-ms replay-ms})
                      st0-replayed (:state r0-replay)
                      r0-next (streamlet/handle-streamlet-event
                               st0-replayed {:type :tick :now-ms (+ start-ms tick-ms)})
                      r0-back (streamlet/handle-streamlet-event
                               st0 {:type :tick :now-ms (- start-ms backwards-jump)})]
                  (and (= (+ start-ms 5) (:epoch-started-at-ms st0))
                       (= (+ start-ms 5) (:epoch-started-at-ms st0-replayed))
                       (= 2 (:epoch (:state r0-next)))
                       (= 2 (:epoch (:state r0-back)))))))

(deftest test-bip019-soak-f1-kill-restart-and-shell-wiring
  (testing "6-node cluster with SIGKILL + restart into killer phase window continues finalizing cleanly without 97s stall"
    (let [res (run-timed-streamlet-sim {:n 6
                                        :tick-ms 1500
                                        :phases [0 8 16 24 32 40]
                                        :net-ms 5
                                        :total-ticks 36
                                        :kill-idx 5
                                        :kill-start-ms (* 12 1500)
                                        :kill-end-ms (* 16 1500)
                                        :restart-phase-ms 8})]
      (is (every? #(>= % 30) (:final-fin res))
          (str "All 6 nodes must finalize >= 30 epochs across kill+restart, got: " (pr-str res)))
      (is (<= (:max-fin-gap res) 5)
          (str "Finalization gap must remain bounded (<= 5 epochs), got: " (pr-str res)))))

  (testing "Rule 4: strip-unserializable-state and rebind-restored-state never persist or restore :epoch-started-at-ms or :last-proposal-dwell-epoch"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          ident {:pubkey-hex pub-hex :keypair kp}
          st {:epoch 42 :epoch-started-at-ms 123456789 :last-proposal-dwell-epoch 42 :blocks {} :ledger {}}
          stripped (core-mesh/strip-unserializable-state st)
          rebound (core-mesh/rebind-restored-state st {} ident)]
      (is (not (contains? stripped :epoch-started-at-ms)))
      (is (not (contains? stripped :last-proposal-dwell-epoch)))
      (is (not (contains? rebound :epoch-started-at-ms)))
      (is (not (contains? rebound :last-proposal-dwell-epoch)))))

  #?(:clj
     (testing "Shell wiring: full_node_main.cljs and shell/mesh.clj attach :now-ms to :tick and peer network events"
       (let [full-src (slurp (io/file "src/bitecho/full_node_main.cljs"))
             mesh-src (slurp (io/file "src/bitecho/shell/mesh.clj"))]
         (is (str/includes? full-src ":now-ms (.now js/Date)")
             "full_node_main.cljs must pass :now-ms on :tick and peer ingress events")
         (is (str/includes? mesh-src ":now-ms (System/currentTimeMillis)")
             "shell/mesh.clj must pass :now-ms on :tick and peer ingress events")))))

;; =============================================================================
;; BIP-019-SOAK-F2: Post-Restart 1-of-6 Leader-Slot Miss / Sawtooth Prevention
;; =============================================================================

(defspec ^{:doc "BIP-019-SOAK-F2: ingest-verified-ancestors re-anchors disconnected quorum-verified ancestors above any strictly older notarized depth (beating stale restored snapshot heads immediately) while strictly maintaining depth <= epoch and 0 corrupt-depth repairs."}
  prop-bip019-soak-f2-stale-snapshot-reanchor-invariants 100
  (prop/for-all [snap-depth (gen/choose 20 200)
                 snap-skip (gen/choose 0 25)
                 gap-epochs (gen/choose 17 60)]
                (let [{:keys [kps peers-map validators]} (make-test-validators)
                      snap-ep (+ snap-depth snap-skip)
                      anc-ep (+ snap-ep gap-epochs)
                      leader (nth kps (mod anc-ep (count kps)))
                      stale-hash "stale-snapshot-head"
                      stale-blk (streamlet/->Block snap-ep "stale-parent" [] (:pub-hex (first kps)))
                      raw-anc (streamlet/->Block anc-ep "unknown-gap-parent" [] (:pub-hex leader))
                      signed-anc (streamlet/sign-block raw-anc (:priv-bytes leader))
                      anc-hash (streamlet/hash-block signed-anc)
                      votes-map (into {}
                                      (map (fn [{:keys [pub-hex priv-bytes]}]
                                             (let [sig (basalt/bytes->hex (crypto/sign priv-bytes (fressian/utf8->bytes anc-hash)))]
                                               [pub-hex (streamlet/->Vote anc-hash anc-ep sig)]))
                                           kps))
                      init-state {:epoch snap-ep
                                  :head-hash stale-hash
                                  :peers-map peers-map
                                  :validators validators
                                  :blocks {stale-hash stale-blk}
                                  :notarized-blocks #{stale-hash}
                                  :block-depths {stale-hash snap-depth}}
                      ingested (streamlet/ingest-verified-ancestors init-state [{:block signed-anc :votes votes-map}])
                      d-anc (get-in ingested [:block-depths anc-hash])
                      repaired (streamlet/repair-corrupt-block-depths ingested)]
                  (and (some? d-anc)
                       (> d-anc snap-depth)
                       (<= d-anc anc-ep)
                       (streamlet/longest-notarized-parent? ingested anc-hash (inc anc-ep))
                       (not (streamlet/longest-notarized-parent? ingested stale-hash (inc anc-ep)))
                       (zero? (get-in repaired [:diagnostics :corrupt-block-depth-repaired] 0))
                       (= 1 (get-in ingested [:diagnostics :ancestor-sync-reanchored] 0))))))

(defspec ^{:doc "BIP-019-SOAK-F2: Restarting a validator from a stale snapshot (>16 epochs behind) with an arbitrary timer phase offset phi in [0, tick-ms) never induces a periodic 4-5 epoch sawtooth (post-restart maxGap <= 3 and zero missed post-recovery epochs)."}
  prop-bip019-soak-f2-post-restart-arbitrary-phase-and-stale-snapshot 8
  (prop/for-all [phi (gen/choose 0 1499)]
                (let [res (run-timed-streamlet-sim {:n 6
                                                    :tick-ms 1500
                                                    :phases [0 5 10 15 20 25]
                                                    :net-ms 5
                                                    :total-ticks 84
                                                    :kill-idx 0
                                                    :snap-lag-ticks 22
                                                    :kill-start-ms (* 52 1500)
                                                    :kill-end-ms (* 56 1500)
                                                    :restart-phase-ms phi})
                      notarized (:notarized-epochs res)
                      min-ep (reduce min (:final-epochs res))
                      post-epochs (range 62 (dec min-ep))
                      missed (filterv #(not (contains? notarized %)) post-epochs)]
                  (and (<= (:post-restart-max-fin-gap res) 3)
                       (empty? missed)))))

(deftest test-bip019-soak-f2-post-restart-stale-snapshot-and-phase-offset
  (testing "Stale-snapshot restart (snapshot depth 35 > default-max-ancestor-sync-depth=16) eliminates 1-of-6 leader-slot sawtooth"
    (let [res (run-timed-streamlet-sim {:n 6
                                        :tick-ms 1500
                                        :phases [0 5 10 15 20 25]
                                        :net-ms 5
                                        :total-ticks 90
                                        :kill-idx 0
                                        :snap-lag-ticks 22
                                        :kill-start-ms (* 57 1500)
                                        :kill-end-ms (* 61 1500)
                                        :restart-phase-ms 10})
          notarized (:notarized-epochs res)
          min-ep (reduce min (:final-epochs res))
          post-epochs (range 67 (dec min-ep))
          missed (filterv #(not (contains? notarized %)) post-epochs)]
      (is (<= (:post-restart-max-fin-gap res) 3)
          (str "Post-restart maxGap must be <= 3 (no 4-5 epoch sawtooth), got: "
               (select-keys res [:post-restart-max-fin-gap :max-fin-gap :final-epochs :final-fin])
               " missed=" missed))
      (is (empty? missed)
          (str "All post-recovery epochs (including restarted validator's leader slots) must be notarized, missed=" missed))))

  (testing "Knife-edge and arbitrary restart phase offsets phi in [0, tick-ms) maintain post-restart maxGap <= 3"
    (doseq [phi [0 250 500 740 760 1000 1250 1480]]
      (let [res (run-timed-streamlet-sim {:n 6
                                          :tick-ms 1500
                                          :phases [0 5 10 15 20 25]
                                          :net-ms 5
                                          :total-ticks 72
                                          :kill-idx 0
                                          :snap-lag-ticks 3
                                          :kill-start-ms (* 40 1500)
                                          :kill-end-ms (* 44 1500)
                                          :restart-phase-ms phi})
            notarized (:notarized-epochs res)
            min-ep (reduce min (:final-epochs res))
            post-epochs (range 50 (dec min-ep))
            missed (filterv #(not (contains? notarized %)) post-epochs)]
        (is (<= (:post-restart-max-fin-gap res) 3)
            (str "phi=" phi " post-restart maxGap must be <= 3, got: "
                 (select-keys res [:post-restart-max-fin-gap :max-fin-gap :final-epochs :final-fin])
                 " missed=" missed))
        (is (empty? missed)
            (str "phi=" phi " must not miss post-recovery epochs, missed=" missed)))))

  (testing "Byzantine same-epoch equivocation cannot refresh :epoch-started-at-ms more than once per epoch"
    (let [nodes (make-timed-streamlet-cluster 3 1500)
          v0 (nth nodes 0)
          v1 (nth nodes 1)
          b1 (streamlet/sign-block (streamlet/->Block 1 "genesis" [:tx1] (:node-pubkey v1)) (get-in v1 [:keypair :private]))
          b2 (streamlet/sign-block (streamlet/->Block 1 "genesis" [:tx2] (:node-pubkey v1)) (get-in v1 [:keypair :private]))
          ;; v0 ticks early to epoch 1 at t=1000
          s1 (:state (streamlet/handle-streamlet-event v0 {:type :tick :now-ms 1000}))
          ;; First valid leader proposal for epoch 1 arrives at t=1200 -> refreshes dwell once
          s2 (:state (streamlet/handle-streamlet-event s1 {:type :receive-propose :block b1 :ancestors [] :sender (:node-pubkey v1) :now-ms 1200}))
          ;; Equivocating 2nd signed block for epoch 1 arrives at t=1900 -> MUST NOT refresh dwell
          s3 (:state (streamlet/handle-streamlet-event s2 {:type :receive-propose :block b2 :ancestors [] :sender (:node-pubkey v1) :now-ms 1900}))
          ;; Next tick at t=2000 (elapsed 800 >= 750) MUST advance to epoch 2
          s4 (:state (streamlet/handle-streamlet-event s3 {:type :tick :now-ms 2000}))]
      (is (= 1200 (:epoch-started-at-ms s2)))
      (is (= 1200 (:epoch-started-at-ms s3)))
      (is (= 2 (:epoch s4))))))
