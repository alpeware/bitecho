(ns bitecho.demo.angels-test
  "Unit and generative test.check property tests for Milestone 6:
   1. Multi-Harness Skill Neutrality Proof (JSONL external vs. JVM native).
   2. Three-Device / clj-einsum Angels Demo (Phone light node + 2-stage laptop pipeline shard)."
  (:require [bitecho.demo.angels :as angels]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; -----------------------------------------------------------------------------
;; 1. Pure Tensor & Einsum Unit Tests
;; -----------------------------------------------------------------------------

(deftest test-einsum-2d-basic
  (testing "Identity matrix contraction preserves input tensor"
    (let [a [[1.0 2.0]
             [3.0 4.0]]
          eye [[1.0 0.0]
               [0.0 1.0]]
          res (angels/einsum-2d a eye)]
      (is (angels/verify-tensor-parity res a 1e-9))))

  (testing "Rectangular matrix contraction matches golden values"
    ;; [1x3] * [3x2] -> [1x2]
    (let [a [[1.0 2.0 3.0]]
          b [[1.0 4.0]
             [2.0 5.0]
             [3.0 6.0]]
          ;; 1*1 + 2*2 + 3*3 = 14
          ;; 1*4 + 2*5 + 3*6 = 32
          expected [[14.0 32.0]]
          computed (angels/einsum-2d a b)]
      (is (angels/verify-tensor-parity computed expected 1e-9)))))

(deftest test-verify-tensor-parity-invariants
  (testing "Exact match passes"
    (is (angels/verify-tensor-parity [[1.0 2.0]] [[1.0 2.0]])))

  (testing "Within tolerance passes"
    (is (angels/verify-tensor-parity [[1.0000001]] [[1.0000002]] 1e-5)))

  (testing "Exceeding tolerance fails"
    (is (false? (angels/verify-tensor-parity [[1.0]] [[1.1]] 1e-3))))

  (testing "Shape mismatch fails closed"
    (is (false? (angels/verify-tensor-parity [[1.0 2.0]] [[1.0]])))
    (is (false? (angels/verify-tensor-parity [[1.0] [2.0]] [[1.0]])))
    (is (false? (angels/verify-tensor-parity nil [[1.0]])))))

(deftest test-deliverable-hash-determinism
  (testing "Same tensor produces identical SHA-256 deliverable hash"
    (let [t [[1.0 2.0] [3.0 4.0]]
          h1 (angels/tensor->deliverable-hash t)
          h2 (angels/tensor->deliverable-hash t)]
      (is (= 64 (count h1)))
      (is (= h1 h2))))

  (testing "Different tensors produce distinct deliverable hashes"
    (let [h1 (angels/tensor->deliverable-hash [[1.0]])
          h2 (angels/tensor->deliverable-hash [[2.0]])]
      (is (not= h1 h2)))))

;; -----------------------------------------------------------------------------
;; 2. Generative Property Tests (Rule 1)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property: einsum matrix contraction associativity (A * B) * C == A * (B * C)"}
  prop-einsum-associativity 50
  (prop/for-all [dim-m (gen/choose 1 4)
                 dim-k1 (gen/choose 1 4)
                 dim-k2 (gen/choose 1 4)
                 dim-n (gen/choose 1 4)
                 vals-a (gen/vector (gen/fmap double (gen/choose -10 10)) 16)
                 vals-b (gen/vector (gen/fmap double (gen/choose -10 10)) 16)
                 vals-c (gen/vector (gen/fmap double (gen/choose -10 10)) 16)]
                (let [mat-from-vals (fn [vals rows cols]
                                      (vec (for [r (range rows)]
                                             (vec (for [c (range cols)]
                                                    (nth vals (+ (* r cols) c)))))))
                      a (mat-from-vals vals-a dim-m dim-k1)
                      b (mat-from-vals vals-b dim-k1 dim-k2)
                      c (mat-from-vals vals-c dim-k2 dim-n)
                      ab_c (angels/einsum-2d (angels/einsum-2d a b) c)
                      a_bc (angels/einsum-2d a (angels/einsum-2d b c))]
                  (angels/verify-tensor-parity ab_c a_bc 1e-6))))

;; -----------------------------------------------------------------------------
;; 3. Multi-Harness Neutrality Proof Demo Test (Step 6B)
;; -----------------------------------------------------------------------------

(deftest test-multi-harness-neutrality-demo
  (testing "JSONL External Bridge vs. JVM Native Harness complete settled exchange on 3-Node Streamlet BFT Cluster"
    (let [res (angels/run-multi-harness-neutrality-demo)]
      (is (true? (:ok? res)))
      (is (true? (:directory-verified? res)))
      (is (string? (:sealed-session-id res)))
      (is (= 64 (count (:sealed-session-id res))))

      ;; Supply conservation and burn take invariants
      (is (true? (:supply-conserved? res)))
      (is (true? (:quorum-verified? res)))

      ;; Burn accounting: 50 bps on 10,000 gross = 50 ECH take
      (is (= 50 (get-in res [:burn-accounting :protocol-take-burned])))
      (is (= 50 (get-in res [:burn-accounting :take-bps])))

      ;; Escrow settlement invariants
      (is (= "esc-neutrality-1" (get-in res [:escrow :escrow-id])))
      (is (= :released (get-in res [:escrow :status])))
      (is (= 10000 (get-in res [:escrow :gross-amount])))
      (is (= 9950 (get-in res [:escrow :net-amount])))
      (is (= 50 (get-in res [:escrow :take-burned])))

      ;; Harness balance updates: Alice debited 10,000, Bob credited 9,950 net
      (is (= 90000 (get-in res [:harnesses :harness-a :final-balance])))
      (is (= 19950 (get-in res [:harnesses :harness-b :final-balance]))))))

;; -----------------------------------------------------------------------------
;; 4. Three-Device Einsum Angels Demo Test (Step 6B)
;; -----------------------------------------------------------------------------

(deftest test-three-device-einsum-demo
  (testing "Phone Light Node + 2-Stage Pipeline Shards compute einsum and settle escrows with BFT quorum"
    (let [res (angels/run-three-device-einsum-demo)]
      (is (true? (:ok? res)))
      (is (true? (:supply-conserved? res)))
      (is (true? (:quorum-verified? res)))

      ;; Devices
      (is (= "phone-light-node" (get-in res [:devices :device-1 :role])))
      (is (false? (get-in res [:devices :device-1 :local-inference])))
      (is (= 40000 (get-in res [:devices :device-1 :final-balance])))

      (is (= "laptop-stage1-einsum" (get-in res [:devices :device-2 :role])))
      (is (true? (get-in res [:devices :device-2 :parity-verified?])))
      (is (= 10950 (get-in res [:devices :device-2 :final-balance])))

      (is (= "laptop-stage2-einsum" (get-in res [:devices :device-3 :role])))
      (is (true? (get-in res [:devices :device-3 :parity-verified?])))
      (is (= 8980 (get-in res [:devices :device-3 :final-balance])))

      ;; Pipeline dimensions
      (is (= [1 4] (get-in res [:pipeline :prompt-shape])))
      (is (= [4 4] (get-in res [:pipeline :w1-shape])))
      (is (= [4 2] (get-in res [:pipeline :w2-shape])))
      (is (= [1 2] (get-in res [:pipeline :output-shape])))

      ;; Settlement: Stage 1 = 50 ECH take; Stage 2 = 20 ECH take; Total = 70 ECH take
      (is (= 70 (get-in res [:settlement :total-protocol-take-burned])))
      (is (= 50 (get-in res [:settlement :escrow-1 :take-burned])))
      (is (= 20 (get-in res [:settlement :escrow-2 :take-burned])))
      (is (= 9950 (get-in res [:settlement :escrow-1 :net-amount])))
      (is (= 3980 (get-in res [:settlement :escrow-2 :net-amount])))

      ;; Simulator framing assertions
      (is (= 3 (get-in res [:simulator-framing :cluster-nodes])))
      (is (= 3 (get-in res [:simulator-framing :devices])))
      (is (= "Streamlet 3-Node Genesis BFT" (get-in res [:simulator-framing :cluster-type]))))))

;; -----------------------------------------------------------------------------
;; 5. Testnet Readiness Gate Test (Milestone 7 / Master-Plan M4)
;; -----------------------------------------------------------------------------

(deftest test-testnet-readiness-gate
  (testing "Testnet launch exit gates verification: 4-validator BFT under demand gate, nickname directory, verified-outcome escrow, rolling wire versioning"
    (let [res (angels/run-testnet-readiness-gate)]
      (is (true? (:ok? res)))
      (is (true? (get-in res [:exit-gates :third-party-validators-finalizing?])))
      (is (true? (get-in res [:exit-gates :demand-gate-enforced?])))
      (is (true? (get-in res [:exit-gates :treasury-sla-healthy?])))
      (is (true? (get-in res [:exit-gates :directory-resolving?])))
      (is (true? (get-in res [:exit-gates :verified-outcome-workload-settled?])))
      (is (true? (get-in res [:exit-gates :rolling-upgrade-wire-compatible?])))
      (is (= 4 (get-in res [:cluster :validator-count])))
      (is (true? (boolean (get-in res [:cluster :partner-node4-present?]))))
      (is (= 50 (get-in res [:workload :settlement-take-burned])))
      (is (= 9950 (get-in res [:workload :worker-net-received]))))))
