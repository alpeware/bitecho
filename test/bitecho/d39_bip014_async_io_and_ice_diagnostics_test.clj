(ns bitecho.d39-bip014-async-io-and-ice-diagnostics-test
  "Milestone D39 (BIP-014 / v0.23.17) Strict TDD Generative & Deterministic Proof Suite:
   - P-ASYNC-1: Pure shared .cljc snapshot naming, recovery, retention, and coalescing writer (bitecho.snapshot.core)
   - P-ASYNC-2: Node.js Zero-Sync-IO full node & light node hot-path audit
   - P-ASYNC-3: JVM Zero-Sync-IO parity (persistence, mesh, infra, light-node)
   - P-ASYNC-4: Browser WebRTC ICE & connection-state diagnostics (shell/browser.cljc, browser_main.cljs)"
  (:require [bitecho.core.mesh :as core-mesh]
            [bitecho.economy.account :as account]
            [bitecho.shell.browser :as browser]
            [bitecho.shell.persistence :as persistence]
            [bitecho.snapshot.core :as snap]
            [bitecho.streamlet.core :as streamlet]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.nio.file Files]))

;; =============================================================================
;; Generators
;; =============================================================================

(def ^:private gen-node-id
  (gen/such-that (complement str/blank?)
                 (gen/fmap #(apply str %)
                           (gen/vector (gen/elements (concat (map char (range 97 123))
                                                             (map char (range 48 58))
                                                             [\- \_]))
                                       1 12))))

(def ^:private gen-epoch
  (gen/choose 0 1000000000))

(def ^:private gen-writer-cmd
  (gen/one-of
   [(gen/hash-map :type (gen/return :request-write)
                  :epoch (gen/choose 1 5000)
                  :payload (gen/hash-map :epoch (gen/choose 1 5000))
                  :force? gen/boolean)
    (gen/hash-map :type (gen/return :write-succeeded)
                  :stale? gen/boolean)
    (gen/hash-map :type (gen/return :write-failed)
                  :stale? gen/boolean
                  :error (gen/elements [:disk-full :eacces :io-error]))
    (gen/hash-map :type (gen/return :prune-succeeded)
                  :stale? gen/boolean
                  :deleted-count (gen/choose 0 10))
    (gen/hash-map :type (gen/return :prune-failed)
                  :stale? gen/boolean
                  :error (gen/elements [:unlink-failed :ebusy]))]))

(def ^:private gen-ice-state
  (gen/elements ["new" "checking" "connected" "completed" "disconnected" "failed" "closed"]))

(def ^:private gen-conn-cmd
  (gen/one-of
   [(gen/hash-map :type (gen/return :dial)
                  :peer-id (gen/elements ["node1" "node2" "node3"]))
    (gen/hash-map :type (gen/return :open))
    (gen/hash-map :type (gen/return :ice-state-change)
                  :ice-state gen-ice-state
                  :stale? gen/boolean)
    (gen/hash-map :type (gen/return :connection-state-change)
                  :connection-state gen-ice-state
                  :stale? gen/boolean)
    (gen/hash-map :type (gen/return :close)
                  :cause (gen/elements ["peer-closed" "timeout"]))]))

;; =============================================================================
;; Rule 1 Generative Properties (clojure.test.check)
;; =============================================================================

(defspec ^{:doc "P-ASYNC-1 Prop 1: snapshot-filename / parse-snapshot-filename roundtrips cleanly and rejects .tmp, foreign nodes, and legacy names."}
  prop-snapshot-filename-roundtrip 100
  (prop/for-all [node-id gen-node-id
                 epoch gen-epoch]
                (let [fname (snap/snapshot-filename node-id epoch)
                      parsed (snap/parse-snapshot-filename node-id fname)
                      tmp-name (str fname ".tmp-123")
                      foreign-name (snap/snapshot-filename (str node-id "-other") epoch)]
                  (and (= (snap/sanitize-node-id node-id) (:node-id parsed))
                       (= (long epoch) (:epoch parsed))
                       (= fname (:filename parsed))
                       (nil? (snap/parse-snapshot-filename node-id tmp-name))
                       (nil? (snap/parse-snapshot-filename node-id foreign-name))
                       (nil? (snap/parse-snapshot-filename node-id (str "snapshot-" node-id ".edn")))))))

(defspec ^{:doc "P-ASYNC-1 Prop 2: select-latest-snapshot always picks highest valid epoch or falls back to legacy filename when present."}
  prop-select-latest-snapshot-highest-epoch 100
  (prop/for-all [node-id gen-node-id
                 epochs (gen/vector-distinct gen-epoch {:min-elements 0 :max-elements 15})
                 has-legacy? gen/boolean]
                (let [legacy (str "snapshot-" (snap/sanitize-node-id node-id) ".edn")
                      snap-files (mapv #(snap/snapshot-filename node-id %) epochs)
                      noise [(str (snap/snapshot-filename node-id 999999999) ".tmp")
                             (snap/snapshot-filename (str node-id "-foreign") 999999999)
                             "random-file.txt"]
                      all-files (cond-> (into snap-files noise)
                                  has-legacy? (conj legacy))
                      selected (snap/select-latest-snapshot node-id all-files legacy)]
                  (cond
                    (seq epochs)
                    (= selected (snap/snapshot-filename node-id (apply max epochs)))

                    has-legacy?
                    (= selected legacy)

                    :else
                    (nil? selected)))))

(defspec ^{:doc "P-ASYNC-1 Prop 3: plan-snapshot-retention partitions valid snapshots only, enforces min-keep >= 2, and preserves all epochs >= cutoff."}
  prop-plan-snapshot-retention-invariants 100
  (prop/for-all [node-id gen-node-id
                 epochs (gen/vector-distinct (gen/choose 0 5000) {:min-elements 0 :max-elements 25})
                 current-epoch (gen/choose 0 6000)
                 keep-epochs (gen/choose 0 1000)
                 min-keep (gen/choose 0 5)]
                (let [legacy (str "snapshot-" (snap/sanitize-node-id node-id) ".edn")
                      foreign (snap/snapshot-filename (str node-id "-other") 1)
                      tmp (str (snap/snapshot-filename node-id 2) ".tmp")
                      valid-files (mapv #(snap/snapshot-filename node-id %) epochs)
                      all-files (into valid-files [legacy foreign tmp])
                      {:keys [keep delete]} (snap/plan-snapshot-retention
                                             node-id all-files current-epoch
                                             {:keep-epochs keep-epochs :min-keep min-keep})
                      keep-set (set keep)
                      delete-set (set delete)
                      eff-min-keep (max 2 (long min-keep))
                      cutoff (- (long current-epoch) (long keep-epochs))
                      kept-epochs (mapv #(:epoch (snap/parse-snapshot-filename node-id %)) keep)
                      del-epochs (mapv #(:epoch (snap/parse-snapshot-filename node-id %)) delete)]
                  (and
       ;; Disjoint partition of valid files only
                   (empty? (set/intersection keep-set delete-set))
                   (= (set valid-files) (into keep-set delete-set))
       ;; Foreign, tmp, and legacy files are never scheduled for deletion
                   (not (contains? delete-set legacy))
                   (not (contains? delete-set foreign))
                   (not (contains? delete-set tmp))
       ;; Hard min-keep >= 2 floor
                   (>= (count keep) (min (count valid-files) eff-min-keep))
       ;; Every epoch >= cutoff is kept
                   (every? #(contains? keep-set (snap/snapshot-filename node-id %))
                           (filter #(>= % cutoff) epochs))
       ;; Kept epochs are always >= deleted epochs
                   (or (empty? kept-epochs)
                       (empty? del-epochs)
                       (>= (apply min kept-epochs) (apply max del-epochs)))))))

(defspec ^{:doc "P-ASYNC-1 Prop 4: Coalescing async writer enforces at most 1 in-flight + 1 pending, rejects stale generations, and never prunes on failed writes."}
  prop-coalescing-writer-model 100
  (prop/for-all [cmds (gen/vector gen-writer-cmd 1 40)]
                (loop [st (snap/init-writer-state {:node-id "node1" :keep-epochs 10 :min-keep 2})
                       rem cmds]
                  (if (empty? rem)
                    true
                    (let [raw-cmd (first rem)
                          curr-gen (:generation st)
                          ev (case (:type raw-cmd)
                               :request-write
                               raw-cmd

                               (:write-succeeded :write-failed :prune-succeeded :prune-failed)
                               (let [g (if (:stale? raw-cmd)
                                         (dec (max 0 curr-gen))
                                         curr-gen)
                                     ep (or (get-in st [:in-flight :epoch]) 1)
                                     fnm (or (get-in st [:in-flight :filename])
                                             (snap/snapshot-filename "node1" ep))]
                                 (-> raw-cmd
                                     (dissoc :stale?)
                                     (assoc :generation g :epoch ep :filename fnm))))
                          [st' effs] (snap/transition-writer st ev)
                          gen-monotonic? (>= (:generation st') (:generation st))
                          stale-cb? (and (contains? #{:write-succeeded :write-failed :prune-succeeded :prune-failed} (:type ev))
                                         (or (< (long (:generation ev)) (long curr-gen))
                                             (and (contains? #{:write-succeeded :write-failed} (:type ev))
                                                  (not= (:phase st) :writing))))
                          stale-ok? (if stale-cb?
                                      (and (= (inc (:ignored-stale st)) (:ignored-stale st'))
                                           (some #(and (= :diagnose (:effect %))
                                                       (= :stale-snapshot-callback (:reason %)))
                                                 effs)
                                           (= (:in-flight st) (:in-flight st'))
                                           (= (:phase st) (:phase st')))
                                      true)
                          fail-never-prunes? (if (and (= :write-failed (:type ev)) (not stale-cb?))
                                               (and (not-any? #(= :prune-snapshots (:effect %)) effs)
                                                    (some #(and (= :diagnose (:effect %))
                                                                (= :snapshot-write-failed (:reason %)))
                                                          effs))
                                               true)
                          coalesce-ok? (if (and (= :request-write (:type ev))
                                                (= :writing (:phase st))
                                                (some? (:pending st)))
                                         (and (= (inc (:coalesced-count st)) (:coalesced-count st'))
                                              (some #(and (= :diagnose (:effect %))
                                                          (= :snapshot-write-coalesced (:reason %)))
                                                    effs))
                                         true)
                          in-flight-ok? (if (= :writing (:phase st'))
                                          (some? (:in-flight st'))
                                          (nil? (:in-flight st')))]
                      (if (and gen-monotonic? stale-ok? fail-never-prunes? coalesce-ok? in-flight-ok?)
                        (recur st' (rest rem))
                        false))))))

(defspec ^{:doc "P-ASYNC-4 Prop 5: Browser transition-conn ICE and connection-state transitions count disconnects/reconnects and reject stale generations."}
  prop-browser-ice-diagnostics-model 100
  (prop/for-all [cmds (gen/vector gen-conn-cmd 1 35)]
                (loop [conn (browser/initial-conn-state {:peer-id "browser-test"})
                       rem cmds]
                  (if (empty? rem)
                    true
                    (let [raw-cmd (first rem)
                          curr-gen (:generation conn)
                          ev (case (:type raw-cmd)
                               (:ice-state-change :connection-state-change)
                               (assoc (dissoc raw-cmd :stale?)
                                      :generation (if (:stale? raw-cmd)
                                                    (dec curr-gen)
                                                    curr-gen))
                               raw-cmd)
                          [conn' effs] (browser/transition-conn conn ev)
                          stale? (and (some? (:generation ev))
                                      (< (long (:generation ev)) (long curr-gen)))
                          stale-ok? (if stale?
                                      (and (= (inc (get-in conn [:diagnostics :ignored-stale]))
                                              (get-in conn' [:diagnostics :ignored-stale]))
                                           (= (get-in conn [:diagnostics :last-ice-state])
                                              (get-in conn' [:diagnostics :last-ice-state]))
                                           (= (get-in conn [:diagnostics :ice-disconnects])
                                              (get-in conn' [:diagnostics :ice-disconnects]))
                                           (= (get-in conn [:diagnostics :ice-reconnects])
                                              (get-in conn' [:diagnostics :ice-reconnects]))
                                           (some #(and (= :diagnose (:type %))
                                                       (= :ignored-stale (:kind %)))
                                                 effs))
                                      true)
                          ice-ok? (if (and (= :ice-state-change (:type ev)) (not stale?))
                                    (let [prev-ice (get-in conn [:diagnostics :last-ice-state])
                                          nxt-ice (:ice-state ev)
                                          kind (browser/classify-ice-transition prev-ice nxt-ice)]
                                      (and (= nxt-ice (get-in conn' [:diagnostics :last-ice-state]))
                                           (case kind
                                             (:ice-disconnected :ice-failed)
                                             (and (= (inc (get-in conn [:diagnostics :ice-disconnects]))
                                                     (get-in conn' [:diagnostics :ice-disconnects]))
                                                  (some #(and (= :diagnose (:type %)) (= kind (:kind %))) effs))

                                             :ice-reconnected
                                             (and (= (inc (get-in conn [:diagnostics :ice-reconnects]))
                                                     (get-in conn' [:diagnostics :ice-reconnects]))
                                                  (some #(and (= :diagnose (:type %)) (= :ice-reconnected (:kind %))) effs))

                                             true)))
                                    true)]
                      (if (and stale-ok? ice-ok?)
                        (recur conn' (rest rem))
                        false))))))

;; =============================================================================
;; Deterministic Proof Scenarios S-D39-1 .. S-D39-6
;; =============================================================================

(deftest s-d39-1-highest-epoch-recovery-and-legacy-fallback-test
  (testing "S-D39-1: Highest-epoch immutable snapshot recovery + legacy snapshot-<node>.edn fallback"
    (let [legacy "snapshot-node1.edn"
          ep10 (snap/snapshot-filename :node1 10)
          ep250 (snap/snapshot-filename :node1 250)
          ep999-tmp (str (snap/snapshot-filename :node1 999) ".tmp-42")
          foreign-ep9999 (snap/snapshot-filename :node2 9999)]
      (is (= "snapshot-node1-epoch-000000000010.fressian" ep10))
      (is (= "snapshot-node1-epoch-000000000250.fressian" ep250))
      ;; Highest valid epoch wins over older epochs, .tmp files, foreign nodes, and legacy
      (is (= ep250
             (snap/select-latest-snapshot :node1 [legacy ep10 ep250 ep999-tmp foreign-ep9999] legacy)))
      ;; Legacy fallback when no valid epoch snapshots exist
      (is (= legacy
             (snap/select-latest-snapshot :node1 [legacy ep999-tmp foreign-ep9999] legacy)))
      ;; Nil when neither exists
      (is (nil? (snap/select-latest-snapshot :node1 [ep999-tmp foreign-ep9999] legacy))))))

(deftest s-d39-2-tunable-retention-pruning-and-min-keep-test
  (testing "S-D39-2: Tunable retention pruning (current_epoch - N) + min-keep >= 2 guarantee"
    (let [files (mapv #(snap/snapshot-filename :node1 %) [10 20 30 40 50])
          ;; With current-epoch 50, keep-epochs 15 -> cutoff 35 -> keeps 50, 40; deletes 30, 20, 10
          plan1 (snap/plan-snapshot-retention :node1 files 50 {:keep-epochs 15 :min-keep 2})
          ;; Even when ALL snapshots are older than cutoff (current-epoch 10000, keep-epochs 10)
          ;; and caller passes min-keep 0, hard floor min-keep >= 2 preserves 50 and 40!
          plan2 (snap/plan-snapshot-retention :node1 files 10000 {:keep-epochs 10 :min-keep 0})]
      (is (= [(snap/snapshot-filename :node1 50)
              (snap/snapshot-filename :node1 40)]
             (:keep plan1)))
      (is (= [(snap/snapshot-filename :node1 30)
              (snap/snapshot-filename :node1 20)
              (snap/snapshot-filename :node1 10)]
             (:delete plan1)))
      (is (= [(snap/snapshot-filename :node1 50)
              (snap/snapshot-filename :node1 40)]
             (:keep plan2)))
      (is (= 3 (count (:delete plan2)))))))

(deftest s-d39-3-coalescing-writer-stale-gen-and-write-failure-injection-test
  (testing "S-D39-3: Coalescing async writer + stale-gen rejection + write-failure injection"
    (let [st0 (snap/init-writer-state {:node-id :node1 :keep-epochs 360 :min-keep 2})
          ;; Start write for epoch 100 -> gen 1
          [st1 eff1] (snap/transition-writer st0 {:type :request-write :epoch 100 :payload {:e 100}})
          ;; Request epoch 101 while gen 1 is in-flight -> queued as pending
          [st2 eff2] (snap/transition-writer st1 {:type :request-write :epoch 101 :payload {:e 101}})
          ;; Request epoch 102 while gen 1 is in-flight -> coalesces over 101 with :diagnose
          [st3 eff3] (snap/transition-writer st2 {:type :request-write :epoch 102 :payload {:e 102}})
          ;; Inject stale callback (gen 0 < current gen 1) -> ignored & counted
          [st4 eff4] (snap/transition-writer st3 {:type :write-succeeded :generation 0 :epoch 99})
          ;; Inject write failure for gen 1 -> NEVER prunes, emits :diagnose, advances to pending 102 (gen 2)
          [st5 eff5] (snap/transition-writer st4 {:type :write-failed :generation 1 :epoch 100 :error :disk-full})
          ;; Succeed gen 2 (epoch 102) -> emits :prune-snapshots and returns to :idle
          [st6 eff6] (snap/transition-writer st5 {:type :write-succeeded :generation 2 :epoch 102})]
      (is (= :writing (:phase st1)))
      (is (= 1 (:generation st1)))
      (is (= :write-snapshot (:effect (first eff1))))
      (is (empty? eff2))
      (is (= 1 (:coalesced-count st3)))
      (is (= :snapshot-write-coalesced (:reason (first eff3))))
      (is (= 102 (get-in st3 [:pending :epoch])))
      ;; Stale gen rejected
      (is (= 1 (:ignored-stale st4)))
      (is (= :stale-snapshot-callback (:reason (first eff4))))
      (is (= 1 (:generation st4)))
      ;; Failed write never prunes, counts failure, and launches pending epoch 102 as gen 2
      (is (not-any? #(= :prune-snapshots (:effect %)) eff5))
      (is (some #(and (= :diagnose (:effect %)) (= :snapshot-write-failed (:reason %))) eff5))
      (is (some #(and (= :write-snapshot (:effect %)) (= 2 (:generation %)) (= 102 (:epoch %))) eff5))
      (is (= 1 (:writes-failed st5)))
      (is (= 2 (:generation st5)))
      ;; Succeeded gen 2 emits prune and returns to idle
      (is (= :idle (:phase st6)))
      (is (= 1 (:writes-succeeded st6)))
      (is (= 102 (:last-written-epoch st6)))
      (is (some #(and (= :prune-snapshots (:effect %)) (= 102 (:current-epoch %))) eff6)))))

(deftest s-d39-4-jvm-persistence-epoch-snapshots-and-retention-test
  (testing "S-D39-4: JVM shell/persistence.clj immutable epoch snapshot save, recovery, legacy fallback, and retention pruning"
    (let [tmp-dir (.toFile (Files/createTempDirectory "bitecho-d39-jvm-snap"
                                                      (make-array java.nio.file.attribute.FileAttribute 0)))]
      (try
        ;; 1. Legacy fallback first
        (let [legacy-file (io/file tmp-dir "snapshot-node1.edn")
              _ (persistence/save-state-to-disk (.getAbsolutePath legacy-file) {:epoch 5 :marker :legacy})
              loaded-legacy (persistence/load-latest-epoch-snapshot (.getAbsolutePath tmp-dir) :node1 (.getName legacy-file))]
          (is (= :legacy (:marker loaded-legacy)))
          (is (= 5 (:epoch loaded-legacy))))

        ;; 2. Save immutable epoch snapshots 10, 20, 30, 40 with keep-epochs 15, min-keep 2
        (doseq [ep [10 20 30 40]]
          (let [res (persistence/save-epoch-snapshot!
                     (.getAbsolutePath tmp-dir)
                     :node1
                     {:epoch ep :last-executed-finalized-epoch ep :marker (keyword (str "ep-" ep))}
                     {:keep-epochs 15 :min-keep 2})]
            (is (true? (:ok? res)))))

        ;; 3. Recovery loads highest epoch (40), not legacy
        (let [loaded (persistence/load-latest-epoch-snapshot (.getAbsolutePath tmp-dir) :node1 "snapshot-node1.edn")
              remaining (set (map #(.getName ^File %) (.listFiles tmp-dir)))]
          (is (= 40 (:epoch loaded)))
          (is (= :ep-40 (:marker loaded)))
          ;; Retention pruned epochs 10 and 20, kept 30 and 40 (and left legacy untouched)
          (is (contains? remaining (snap/snapshot-filename :node1 40)))
          (is (contains? remaining (snap/snapshot-filename :node1 30)))
          (is (not (contains? remaining (snap/snapshot-filename :node1 20))))
          (is (not (contains? remaining (snap/snapshot-filename :node1 10))))
          (is (contains? remaining "snapshot-node1.edn")))
        (finally
          (doseq [f (.listFiles tmp-dir)] (.delete ^File f))
          (.delete tmp-dir))))))

(deftest s-d39-5-browser-ice-diagnostics-and-surfacing-test
  (testing "S-D39-5: Browser transition-conn ICE connected->disconnected->connected & failed + stale-gen guard + browser_main.cljs surfacing"
    (let [c0 (browser/initial-conn-state {:peer-id "browser-1"})
          [c1 _] (browser/transition-conn c0 {:type :dial :peer-id "node1"})
          gen1 (:generation c1)
          [c2 _] (browser/transition-conn c1 {:type :open :generation gen1 :peer-id "node1"})
          [c3 eff3] (browser/transition-conn c2 {:type :ice-state-change :generation gen1 :ice-state "connected"})
          [c4 eff4] (browser/transition-conn c3 {:type :ice-state-change :generation gen1 :ice-state "disconnected"})
          [c5 eff5] (browser/transition-conn c4 {:type :ice-state-change :generation gen1 :ice-state "connected"})
          [c6 eff6] (browser/transition-conn c5 {:type :ice-state-change :generation gen1 :ice-state "failed"})
          [c7 eff7] (browser/transition-conn c6 {:type :connection-state-change :generation gen1 :connection-state "disconnected"})
          ;; Stale generation ICE callback ignored & counted
          [c8 eff8] (browser/transition-conn c7 {:type :ice-state-change :generation (dec gen1) :ice-state "disconnected"})
          browser-main-src (slurp "src/bitecho/browser_main.cljs")
          browser-shell-src (slurp "src/bitecho/shell/browser.cljc")]
      (is (empty? eff3))
      (is (= "connected" (get-in c3 [:diagnostics :last-ice-state])))
      (is (= 1 (get-in c4 [:diagnostics :ice-disconnects])))
      (is (= :ice-disconnected (:kind (first eff4))))
      (is (= 1 (get-in c5 [:diagnostics :ice-reconnects])))
      (is (= :ice-reconnected (:kind (first eff5))))
      (is (= 2 (get-in c6 [:diagnostics :ice-disconnects])))
      (is (= :ice-failed (:kind (first eff6))))
      (is (= "disconnected" (get-in c7 [:diagnostics :last-connection-state])))
      (is (= :connection-disconnected (:kind (first eff7))))
      ;; Stale callback did not increment ice-disconnects
      (is (= 2 (get-in c8 [:diagnostics :ice-disconnects])))
      (is (= 1 (get-in c8 [:diagnostics :ignored-stale])))
      (is (= :ignored-stale (:kind (first eff8))))
      ;; Verify browser_main.cljs surfaces all 4 diagnostic keys in getStatus().diagnostics
      (is (str/includes? browser-main-src ":iceDisconnects"))
      (is (str/includes? browser-main-src ":iceReconnects"))
      (is (str/includes? browser-main-src ":lastIceState"))
      (is (str/includes? browser-main-src ":lastConnectionState"))
      ;; Verify connect-webrtc! wires oniceconnectionstatechange and onconnectionstatechange
      (is (str/includes? browser-shell-src ".-oniceconnectionstatechange"))
      (is (str/includes? browser-shell-src ".-onconnectionstatechange")))))

(deftest s-d39-6-zero-sync-io-hot-path-audit-and-bip014-cid-test
  (testing "S-D39-6: Zero-*Sync hot-path audit across full_node_main.cljs & node_main.cljs + BIP-014 parent CID"
    (let [full-src (slurp "src/bitecho/full_node_main.cljs")
          node-src (slurp "src/bitecho/node_main.cljs")
          bip014 (edn/read-string (slurp "docs/bips/bip-014-v02317.edn"))]
      ;; 1. full_node_main.cljs must NOT use gzipSync in HTTP response path
      (is (not (str/includes? full-src ".gzipSync"))
          "full_node_main.cljs must use async node-zlib.gzip instead of .gzipSync")
      ;; 2. full_node_main.cljs must wire bitecho.snapshot.core + fs.promises async writer
      (is (str/includes? full-src "bitecho.snapshot.core"))
      (is (str/includes? full-src "atomic-write-file-async!"))
      (is (str/includes? full-src "read-disk-blob-async!"))
      (is (str/includes? full-src "resolve-safe-content-root-async!"))
      ;; 3. node_main.cljs must wire bitecho.snapshot.core + async state.fressian writer
      (is (str/includes? node-src "bitecho.snapshot.core"))
      (is (str/includes? node-src "save-light-state-async!"))
      ;; 4. BIP-014 parent CID must be full 64-char sha256 hex of BIP-013
      (is (= 64 (count (str (:bip/parent-bip-cid bip014)))))
      (is (boolean (re-matches #"[0-9a-f]{64}" (str (:bip/parent-bip-cid bip014))))))))

(deftest s-d39-7-hot-path-cost-budget-and-snapshot-sanitization-test
  (testing "S-D39-7 (V8 Trace Hot-Path Fix + Cost-Budget Sim Gate): strip-unserializable-state drops duplicate/ephemeral caches in < 50ms, restores losslessly, and truncate-ancestors-to-wire-budget runs in O(N) < 50ms"
    (let [ids (mapv #(str "rcpt-" %) (range 10000))
          big-state {:epoch 51800
                     :last-executed-finalized-epoch 51799
                     :keypair {:private "secret" :public "pub"}
                     :config {:node-private-key "secret2" :port 5000}
                     :ledger {"acct1" {:balance 1000 :seq 1 :deps []}}
                     :known-receipt-order ids
                     :known-receipt-ids (set ids)
                     :executed-receipt-order ids
                     :executed-receipt-ids (set ids)
                     :received-readies (into {} (map (fn [i] [(str "m" i) #{"v1"}]) (range 2000)))
                     :received-echoes (into {} (map (fn [i] [(str "m" i) #{"v1"}]) (range 2000)))
                     :echo-vote-counts {"m0" 2}
                     :ready-vote-counts {"m0" 2}
                     :delivery-vote-counts {"m0" 2}
                     :local-ready-set #{"m0"}
                     :sieve-delivered-set #{"m0"}
                     :delivered-set #{"m0"}}
          t0 (System/nanoTime)
          stripped (core-mesh/strip-unserializable-state big-state)
          strip-ms (/ (- (System/nanoTime) t0) 1e6)
          restored (core-mesh/restore-unserializable-state stripped)
          ancestors (mapv (fn [i]
                            {:block (streamlet/->Block (+ 51780 i) "parent" [] "pub")
                             :votes []})
                          (range 16))
          base-cmd {:type :send-propose :targets [] :block (streamlet/->Block 51800 "parent" [] "pub") :ancestors []}
          t1 (System/nanoTime)
          kept (#'streamlet/truncate-ancestors-to-wire-budget base-cmd ancestors 32768)
          trunc-ms (/ (- (System/nanoTime) t1) 1e6)]
      ;; Secrets stripped
      (is (not (contains? stripped :keypair)))
      (is (not (contains? (:config stripped) :node-private-key)))
      ;; Duplicate derived sets & ephemeral gossip caches stripped from persisted snapshot
      (is (not (contains? stripped :known-receipt-ids)))
      (is (not (contains? stripped :executed-receipt-ids)))
      (is (not (contains? stripped :received-readies)))
      (is (not (contains? stripped :received-echoes)))
      ;; Losslessly reconstructed on restore
      (is (= 10000 (count (:known-receipt-ids restored))))
      (is (= 10000 (count (:executed-receipt-ids restored))))
      (is (contains? (:known-receipt-ids restored) "rcpt-9999"))
      ;; Strict per-step cost-budget gate (<= 50 ms)
      (is (<= strip-ms 50.0) (str "strip-unserializable-state blew 50ms budget: " strip-ms "ms"))
      (is (pos? (count kept)))
      (is (<= trunc-ms 50.0) (str "truncate-ancestors-to-wire-budget blew 50ms budget: " trunc-ms "ms")))))

(deftest s-d39-8-stale-pending-receipt-eviction-test
  (testing "S-D39-8: rebind-restored-state evicts expired/stale pending-receipts older than 64 epochs while preserving fresh receipts"
    (let [loaded {:epoch 51920
                  :last-executed-finalized-epoch 51918
                  :executed-receipt-ids #{"exec-1"}
                  :pending-receipts [{:receipt-id "exec-1" :epoch 51915}
                                     {:receipt-id "stale-old" :epoch 34329}
                                     {:receipt-id "stale-edge" :epoch 51800}
                                     {:receipt-id "fresh-1" :epoch 51910}
                                     {:receipt-id "no-epoch" :type :burn}]}
          rebound (core-mesh/rebind-restored-state loaded {:node/id :node1} {:pubkey-hex "aa" :privkey-bytes (byte-array 32)})
          kept-ids (set (map :receipt-id (:pending-receipts rebound)))]
      (is (not (contains? kept-ids "exec-1")))
      (is (not (contains? kept-ids "stale-old")))
      (is (not (contains? kept-ids "stale-edge")))
      (is (contains? kept-ids "fresh-1"))
      (is (contains? kept-ids "no-epoch")))))

(deftest s-d39-9-record-serialization-and-tagged-record-recovery-test
  (testing "S-D39-9: strip-unserializable-state converts defrecords in :ledger/:blocks to plain maps without deep-walking bulk strings, and restore-unserializable-state unwraps legacy TaggedObject record maps losslessly"
    (let [acct (account/map->AccountState {:balance 50734898 :seq 13 :deps ["d1"]})
          blk (streamlet/->Block 51954 "parent" [] "pub")
          stripped (core-mesh/strip-unserializable-state {:ledger {"k1" acct} :blocks {"b1" blk}})
          ;; Simulate a TaggedObject record map from an unnormalized Fressian snapshot
          tagged-state {:ledger {"k1" {:tag "record" :value ["AccountState" {:balance 50734898 :seq 13 :deps ["d1"]}]}}
                        :blocks {"b1" {:tag "record" :value ["Block" {:epoch 51954 :parent-hash "parent" :payload [] :proposer "pub"}]}}}
          restored (core-mesh/restore-unserializable-state tagged-state)]
      (is (not (record? (get-in stripped [:ledger "k1"]))))
      (is (= 50734898 (get-in stripped [:ledger "k1" :balance])))
      (is (not (record? (get-in stripped [:blocks "b1"]))))
      (is (= 51954 (get-in stripped [:blocks "b1" :epoch])))
      ;; TaggedObject record maps unwrap losslessly back to real AccountState/Block records
      (is (= 50734898 (:balance (get-in restored [:ledger "k1"]))))
      (is (= 13 (:seq (get-in restored [:ledger "k1"]))))
      (is (= 51954 (:epoch (get-in restored [:blocks "b1"])))))))

(deftest s-d39-10-ephemeral-sets-reinitialized-and-list-healed-on-restore-and-tick-test
  (testing "S-D39-10: strip+restore re-initializes ephemeral Bracha/Sieve sets/maps and heals list-corrupted sets across :tick"
    (let [state0 {:epoch 52180
                  :config {:gossip-ttl-epochs 10
                           :frozen-log-retention-epochs 168
                           :max-tracked-receipts 10000
                           :max-escrow-horizon 168}
                  :sieve-delivered-set #{"m1"}
                  :local-ready-set #{"m1"}
                  :delivered-set #{"m1"}
                  :received-readies {"m1" #{"p1"}}
                  :received-echoes {"m1" #{"p1"}}
                  :echo-vote-counts {"m1" 1}
                  :ready-vote-counts {"m1" 1}
                  :delivery-vote-counts {"m1" 1}
                  :expired-gossip-ids #{"old-1"}
                  :expired-gossip-order ["old-1"]
                  :epoch-to-messages {52160 #{"deaf6ded"}}
                  :message-epochs {"deaf6ded" 52160}
                  :contagion-known-ids #{"deaf6ded"}
                  :murmur-cache {:set #{"deaf6ded"} :queue ["deaf6ded"]}}
          stripped (core-mesh/strip-unserializable-state state0)
          restored (core-mesh/restore-unserializable-state stripped)]
      ;; All ephemeral sets/maps stripped on save MUST be re-initialized as empty sets/maps (never nil!)
      (is (set? (:sieve-delivered-set restored)))
      (is (set? (:local-ready-set restored)))
      (is (set? (:delivered-set restored)))
      (is (set? (:expired-gossip-ids restored)))
      (is (map? (:received-readies restored)))
      (is (map? (:received-echoes restored)))
      (is (map? (:echo-vote-counts restored)))
      (is (map? (:ready-vote-counts restored)))
      (is (map? (:delivery-vote-counts restored)))
      ;; Conj onto restored ephemeral sets MUST produce sets, never lists
      (is (set? (conj (:sieve-delivered-set restored) "deaf6ded")))
      (is (set? (conj (:local-ready-set restored) "deaf6ded")))
      (is (set? (conj (:delivered-set restored) "deaf6ded")))
      ;; Even if a corrupted snapshot had lists in set-typed keys, restore heals them to sets
      (let [corrupted (assoc restored
                             :sieve-delivered-set (list "deaf6ded")
                             :local-ready-set (list "deaf6ded")
                             :delivered-set (list "deaf6ded")
                             :expired-gossip-ids (list "old-1")
                             :epoch-to-messages {52160 (list "deaf6ded")})
            healed (core-mesh/restore-unserializable-state corrupted)]
        (is (set? (:sieve-delivered-set healed)))
        (is (set? (:local-ready-set healed)))
        (is (set? (:delivered-set healed)))
        (is (set? (:expired-gossip-ids healed)))
        (is (set? (get-in healed [:epoch-to-messages 52160])))))))
