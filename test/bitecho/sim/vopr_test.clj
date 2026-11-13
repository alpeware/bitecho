(ns bitecho.sim.vopr-test
  "Comprehensive tests for Milestone D14: Full-Stack Deterministic Simulation & Jepsen Verification Engine (VOPR).
   Verifies:
   - Strict bit-for-bit determinism across seeds (verify-determinism)
   - O(1) Multiverse state branching and branch isolation (assert-pure-world!, fork-world)
   - Adversarial byte link router with Gilbert-Elliott Markov loss, propagation latency jitter,
     defensive byte copying (AR-3), bit-flip/truncation fuzzing, and RFC 4571 stream slicing
   - Protocol-aware Jepsen verification oracles:
       1. Streamlet Consensus Serializability (check-streamlet-list-append)
       2. Subnet Pointer Linearizability & Leader-Term Fencing (check-pointer-linearizability)
       3. Tokenomics v2.1 Exact Conservation & Deflation Fold (check-tokenomics-conservation)
   - Zero-pollution non-vacuity mutation testing gate (MUT-01..MUT-08 via with-redefs)"
  (:require [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.sim.vopr :as vopr]
            [bitecho.streamlet.core :as streamlet]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.buffer :as b])
  (:import [java.util Arrays]))

;; =============================================================================
;; 1. Determinism Auditor Tests
;; =============================================================================

(deftest test-vopr-determinism
  (testing "Exact bit-for-bit reproducibility of world digests from identical seeds"
    (doseq [seed [1337 4242 9999]]
      (let [run-sim (fn [s]
                      (-> (vopr/create-initial-world s)
                          (vopr/schedule-event 5000000 {:type :step-webrtc-light-channel})
                          (vopr/schedule-event 30000000 {:type :propose-streamlet-block :node-id "node1" :epoch 1})
                          (vopr/schedule-event 80000000 {:type :propose-streamlet-block :node-id "node2" :epoch 2})
                          (vopr/schedule-event 130000000 {:type :propose-streamlet-block :node-id "node3" :epoch 3})
                          (vopr/schedule-event 180000000 {:type :finalize-streamlet-blocks})
                          (vopr/run-simulation 120)))
            det-res (vopr/verify-determinism run-sim seed)]
        (is (true? (:deterministic? det-res))
            (str "Seed " seed " produced non-deterministic world state digests"))
        (is (= (:digest-1 det-res) (:digest-2 det-res)))))))

;; =============================================================================
;; 2. Multiverse Branching & Isolation (AR-4)
;; =============================================================================

(deftest test-multiverse-branching-isolation
  (testing "O(1) state branching preserves pure world state and branch isolation"
    (let [root-world (-> (vopr/create-initial-world 42)
                         (vopr/schedule-event 100 {:type :propose-streamlet-block :node-id "node1" :epoch 1})
                         (vopr/run-simulation 20))]
      ;; Assert world purity
      (is (true? (vopr/assert-pure-world! root-world)))

      ;; Fork 3 parallel timelines at high-leverage transition
      (let [branch-a (vopr/fork-world root-world "branch-a-partition")
            branch-b (vopr/fork-world root-world "branch-b-mtu-blackhole")
            branch-c (vopr/fork-world root-world "branch-c-honest")

            ;; Verify PRNG isolation: drawing from branch-a does NOT mutate root-world or branch-b
            nid (first (keys (:nodes root-world)))
            root-rng (get-in root-world [:nodes nid :state :rng])
            b-rng    (get-in branch-b [:nodes nid :state :rng])
            a-rng    (get-in branch-a [:nodes nid :state :rng])
            root-dc-rng (get-in root-world [:nodes nid :webrtc-conn :rng])
            b-dc-rng    (get-in branch-b [:nodes nid :webrtc-conn :rng])
            a-dc-rng    (get-in branch-a [:nodes nid :webrtc-conn :rng])

            init-root-val @root-rng
            init-b-val    @b-rng
            init-root-dc  @root-dc-rng
            init-b-dc     @b-dc-rng

            _ (crypto/next-long a-rng)
            _ (b/next-u64 a-dc-rng)]
        (is (= init-root-val @root-rng) "Root world :state :rng was mutated by branch-a draw!")
        (is (= init-b-val @b-rng) "Branch-b :state :rng was mutated by branch-a draw!")
        (is (= init-root-dc @root-dc-rng) "Root world :webrtc-conn :rng was mutated by branch-a draw!")
        (is (= init-b-dc @b-dc-rng) "Branch-b :webrtc-conn :rng was mutated by branch-a draw!")

        ;; Also test explicit "val-0" isolation with custom validator-ids
        (let [val0-root (vopr/create-initial-world 42 {:validator-ids ["val-0" "val-1" "val-2" "val-3"]})
              val0-a (vopr/fork-world val0-root "val0-a")
              val0-b (vopr/fork-world val0-root "val0-b")
              val0-root-rng (get-in val0-root [:nodes "val-0" :state :rng])
              val0-b-rng    (get-in val0-b [:nodes "val-0" :state :rng])
              val0-a-rng    (get-in val0-a [:nodes "val-0" :state :rng])
              val0-root-dc  (get-in val0-root [:nodes "val-0" :webrtc-conn :rng])
              val0-b-dc     (get-in val0-b [:nodes "val-0" :webrtc-conn :rng])
              val0-a-dc     (get-in val0-a [:nodes "val-0" :webrtc-conn :rng])
              init-v0-root-state @val0-root-rng
              init-v0-b-state    @val0-b-rng
              init-v0-root-dc    @val0-root-dc
              init-v0-b-dc       @val0-b-dc]
          (crypto/next-long val0-a-rng)
          (b/next-u64 val0-a-dc)
          (is (= init-v0-root-state @val0-root-rng) "val-0 root :state :rng mutated by branch draw!")
          (is (= init-v0-b-state @val0-b-rng) "val-0 branch-b :state :rng mutated by branch draw!")
          (is (= init-v0-root-dc @val0-root-dc) "val-0 root :webrtc-conn :rng mutated by branch draw!")
          (is (= init-v0-b-dc @val0-b-dc) "val-0 branch-b :webrtc-conn :rng mutated by branch draw!"))

        (let [sim-a (-> branch-a
                        (vopr/nemesis-partition #{"node1" "node2"} #{"node3" "node4"})
                        (vopr/schedule-event 100 {:type :propose-streamlet-block :node-id "node2" :epoch 2})
                        (vopr/run-simulation 30))
              sim-b (-> branch-b
                        (assoc-in [:links ["node1" "node2"] :mtu] 50)
                        (vopr/schedule-event 100 {:type :propose-streamlet-block :node-id "node2" :epoch 2})
                        (vopr/run-simulation 30))
              sim-c (-> branch-c
                        (vopr/schedule-event 100 {:type :propose-streamlet-block :node-id "node2" :epoch 2})
                        (vopr/schedule-event 200 {:type :finalize-streamlet-blocks})
                        (vopr/run-simulation 30))
              d-root (vopr/canonical-world-digest root-world)
              d-a (vopr/canonical-world-digest sim-a)
              d-b (vopr/canonical-world-digest sim-b)
              d-c (vopr/canonical-world-digest sim-c)]
          (is (not= d-a d-root))
          (is (not= d-b d-root))
          (is (not= d-c d-root))
          (is (not= d-a d-b))
          (is (not= d-a d-c))
          (is (not= d-b d-c))

          ;; Assert root world was never mutated in-place
          (is (= d-root (vopr/canonical-world-digest root-world))))))))

;; =============================================================================
;; 3. Adversarial Byte Link Router & Defensive Copying (AR-3)
;; =============================================================================

(deftest test-adversarial-byte-link-faults
  (testing "Defensive byte copying (AR-3) ensures sender retransmit buffers are never mutated"
    (let [orig-payload (.getBytes "Bitecho Immutable Wire Payload 2026" "UTF-8")
          sender-buf (Arrays/copyOf orig-payload (alength orig-payload))
          world (-> (vopr/create-initial-world 777)
                    (assoc-in [:links ["node1" "node2"] :bitflip-prob] 1.0)
                    (assoc-in [:links ["node1" "node2"] :truncate-prob] 0.5))
          world' (vopr/route-packet world "node1" "node2" sender-buf)]
      ;; The sender buffer in memory MUST NOT be modified
      (is (Arrays/equals ^bytes orig-payload ^bytes sender-buf)
          "AR-3 violation: sender-buf was mutated in place by byte-level fuzzer!")
      (is (pos? (count (:event-queue world'))))))

  (testing "RFC 4571 stream slicing and reassembly under extreme fragmentation"
    (let [world (vopr/create-initial-world 888)
          frames [(.getBytes "Frame 1 Hello" "UTF-8")
                  (.getBytes "Frame 2 World" "UTF-8")
                  (.getBytes "Frame 3 WebRTC" "UTF-8")]
          slice-res (vopr/test-rfc4571-slice-reassembly world frames)]
      (is (true? (:matches? slice-res)))
      (is (> (:chunks-count slice-res) (count frames))))))

;; =============================================================================
;; 4. Protocol-Aware Jepsen Oracles
;; =============================================================================

(deftest test-jepsen-oracles-honest-execution
  (testing "Oracle 1: Streamlet consensus serializability on honest progression"
    (let [w (-> (vopr/create-initial-world 999)
                (vopr/schedule-event 5000000 {:type :step-webrtc-light-channel})
                (vopr/schedule-event 30000000 {:type :propose-streamlet-block :node-id "node1" :epoch 1})
                (vopr/schedule-event 80000000 {:type :propose-streamlet-block :node-id "node2" :epoch 2})
                (vopr/schedule-event 130000000 {:type :propose-streamlet-block :node-id "node3" :epoch 3})
                (vopr/schedule-event 180000000 {:type :finalize-streamlet-blocks})
                (vopr/run-simulation 120))
          oracle-1 (vopr/check-streamlet-list-append w)
          nodes (vals (:nodes w))]
      (is (true? (:valid? oracle-1)))
      (is (nil? (:error oracle-1)))
      (is (every? #(> (count (:finalized-chain %)) 1) nodes)
          "Validators failed to genuinely finalize post-genesis blocks!")))

  (testing "Oracle 2: Subnet pointer linearizability and leader-term fencing"
    (let [kp (crypto/generate-keypair)
          pub (streamlet/bytes->hex (:public kp))
          priv (:private kp)
          p1 (data/sign-pointer priv {:pointer/authority pub
                                      :pointer/subnet "nexus" :pointer/path "dns/txt"
                                      :pointer/target "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                      :pointer/leader-term 1 :pointer/seq 1})
          p2 (data/sign-pointer priv {:pointer/authority pub
                                      :pointer/subnet "nexus" :pointer/path "dns/txt"
                                      :pointer/target "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                      :pointer/leader-term 1 :pointer/seq 2})
          p-stale (data/sign-pointer priv {:pointer/authority pub
                                           :pointer/subnet "nexus" :pointer/path "dns/txt"
                                           :pointer/target "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                           :pointer/leader-term 1 :pointer/seq 1})
          w (-> (vopr/create-initial-world 1001)
                ;; Valid monotonic write: Term 1, Seq 1
                (vopr/schedule-event 100 {:type :apply-subnet-pointer :node-id "node1" :pointer p1})
                ;; Valid monotonic write: Term 1, Seq 2
                (vopr/schedule-event 200 {:type :apply-subnet-pointer :node-id "node1" :pointer p2})
                ;; Stale write fenced out: Term 1, Seq 1
                (vopr/schedule-event 300 {:type :apply-subnet-pointer :node-id "node1" :pointer p-stale})
                (vopr/run-simulation 20))
          oracle-2 (vopr/check-pointer-linearizability w)]
      (is (true? (:valid? oracle-2)))
      (is (nil? (:error oracle-2)))))

  (testing "Oracle 3: Tokenomics v2.1 conservation fold"
    (let [w (vopr/create-initial-world 1002)
          oracle-3 (vopr/check-tokenomics-conservation w)]
      (is (true? (:valid? oracle-3)))
      (is (true? (:conservation? oracle-3)))
      (is (true? (:within-ceiling? oracle-3))))))

;; =============================================================================
;; 5. Zero-Pollution Non-Vacuity Mutation Testing Gate (MUT-01..MUT-08)
;; =============================================================================

(deftest test-mutation-testing-gate
  (testing "All 8 protocol mutations (MUT-01..MUT-08) are caught and killed by oracles"
    (let [results (vopr/run-mutation-suite {:seed 20261112})]
      (doseq [mut [:MUT-01 :MUT-02 :MUT-03 :MUT-04 :MUT-05 :MUT-06 :MUT-07 :MUT-08]]
        (let [res (get results mut)]
          (is (some? res) (str "Missing result for mutation " mut))
          (is (true? (:caught? res))
              (str "Mutation " mut " failed to be caught by its oracle! Result: " res))
          (is (true? (:baseline-valid? res))
              (str "Mutation " mut " failed baseline check! Result: " res))
          (is (false? (:mutated-valid? res))
              (str "Mutation " mut " failed mutated check! Result: " res)))))))

;; =============================================================================
;; 6. Generative Property Tests for Invariants
;; =============================================================================

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec prop-vopr-discrete-scheduler-ordering 50
  (prop/for-all [delays (gen/vector (gen/choose 0 100000) 20)]
                (let [world (reduce (fn [w d] (vopr/schedule-event w d {:action identity}))
                                    (vopr/create-initial-world 123)
                                    delays)]
                  (loop [w world
                         prev-t 0
                         prev-seq -1]
                    (if-let [evt (vopr/peek-event w)]
                      (let [t (:t-ns evt)
                            s (:seq evt)
                            in-order? (or (> t prev-t)
                                          (and (= t prev-t) (>= s prev-seq)))]
                        (if in-order?
                          (let [[w' _] (vopr/pop-event w)]
                            (recur w' t s))
                          false))
                      true)))))

;; =============================================================================
;; 7. Jepsen Campaign Bug-Hunt Verification (JEP-01..JEP-12)
;; =============================================================================

(deftest test-jepsen-bug-hunting-campaign
  (testing "D14 Jepsen Bug-Hunt campaign: all 12 production bugs (JEP-01..JEP-12) remediated and mutants caught"
    (let [res (vopr/run-jepsen-campaign {:seed 20261113})]
      (is (true? (:ok? res)))
      (is (= 12 (:remediated-count res)))
      (doseq [jep [:JEP-01 :JEP-02 :JEP-03 :JEP-04 :JEP-05 :JEP-06
                   :JEP-07 :JEP-08 :JEP-09 :JEP-10 :JEP-11 :JEP-12]]
        (let [bug (get-in res [:results jep])]
          (is (some? bug) (str "Missing result for bug " jep))
          (is (true? (:remediated-valid? bug)) (str "Bug " jep " failed remediated check: " bug))
          (is (true? (:pre-fix-caught? bug)) (str "Bug " jep " failed pre-fix caught check: " bug))
          (is (true? (:bug-reproduced? bug)) (str "Bug " jep " failed reproduction: " bug)))))))

;; =============================================================================
;; 7b. Transport-Layer Jepsen Bug-Hunt Verification (DCT-01..DCT-12)
;; =============================================================================

(deftest test-datachannel-jepsen-campaign
  (testing "Transport-Layer Jepsen Bug-Hunt campaign: all 12 transport bugs (DCT-01..DCT-12) remediated and mutants caught"
    (let [res (vopr/run-datachannel-jepsen-campaign {:seed 20261115})]
      (is (true? (:ok? res)))
      (is (= 12 (:remediated-count res)))
      (doseq [dct [:DCT-01 :DCT-02 :DCT-03 :DCT-04 :DCT-05 :DCT-06
                   :DCT-07 :DCT-08 :DCT-09 :DCT-10 :DCT-11 :DCT-12]]
        (let [bug (get-in res [:results dct])]
          (is (some? bug) (str "Missing result for bug " dct))
          (is (true? (:remediated-valid? bug)) (str "Bug " dct " failed remediated check: " bug))
          (is (true? (:pre-fix-caught? bug)) (str "Bug " dct " failed pre-fix caught check: " bug))
          (is (true? (:bug-reproduced? bug)) (str "Bug " dct " failed reproduction: " bug)))))))

;; =============================================================================
;; 8. WebRTC DataChannel Sans-IO Packet-Drop & Retransmission Simulation
;; =============================================================================

(deftest test-datachannel-packet-drop-simulation
  (testing "WebRTC DataChannel sans-IO packet-drop and retransmission simulation across seeds and fault schedules"
    ;; 1. Default fault schedule (DTLS flight loss, DATA drops, bit-flips, reordering)
    (let [res (vopr/run-datachannel-packet-drop-sim {:seed 20261114})]
      (is (true? (:valid? res)) (str "Default simulation failed: " res))
      (is (true? (:dtls-established? res)))
      (is (true? (:sctp-established? res)))
      (is (true? (:dtls-flight-rtx-recovered? res)))
      (is (= 2 (:dropped-packets-count res)))
      (is (= 1 (:bitflipped-packets-count res)))
      (is (= 5 (:sent-count res)))
      (is (= 5 (:delivered-count res)))
      (is (true? (:delivered-order-matches? res)))
      (is (pos? (:t3-rtx-retransmissions res)))
      (is (zero? (:client-unacked-remaining res))))

    ;; 2. Multi-seed and fault matrix verification
    (doseq [opts [{:seed 1337 :drop-indices #{0} :bitflip-indices #{} :reorder? false :payload-count 3}
                  {:seed 4242 :drop-indices #{1} :bitflip-indices #{0} :reorder? true :payload-count 4}
                  {:seed 9999 :drop-indices #{} :bitflip-indices #{} :reorder? false :payload-count 5 :dtls-flight-drop? false}]]
      (let [res (vopr/run-datachannel-packet-drop-sim opts)]
        (is (true? (:valid? res)) (str "Matrix scenario failed for opts: " opts " -> " res))
        (is (true? (:dtls-established? res)))
        (is (true? (:sctp-established? res)))
        (is (= (:payload-count opts) (:delivered-count res)))
        (is (true? (:delivered-order-matches? res)))
        (is (zero? (:client-unacked-remaining res)))
        (if (:dtls-flight-drop? opts true)
          (is (true? (:dtls-flight-rtx-recovered? res)))
          (is (false? (:dtls-flight-rtx-recovered? res))))
        (if (empty? (concat (:drop-indices opts) (:bitflip-indices opts)))
          (is (zero? (:t3-rtx-retransmissions res)))
          (is (pos? (:t3-rtx-retransmissions res))))))

    ;; 3. Determinism: identical seed produces identical diagnostics
    (let [run-1 (vopr/run-datachannel-packet-drop-sim {:seed 55555})
          run-2 (vopr/run-datachannel-packet-drop-sim {:seed 55555})]
      (is (= run-1 run-2) "Two runs with identical seed must yield identical diagnostic maps"))))

