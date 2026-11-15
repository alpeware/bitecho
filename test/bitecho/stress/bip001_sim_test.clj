(ns bitecho.stress.bip001-sim-test
  "Generative and unit tests for Milestone D21: Track A In-Memory End-to-End & Governance
   Simulation for BIP-001 (`A-D21-1`..`4`, `A-CARB-D21-1`..`5`)."
  (:require [bitecho.stress.bip001-sim :as bip001]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defspec ^{:doc "Property: Replaying a paramount-objection regression vector is bit-for-bit deterministic across seeds."}
  prop-bip001-counterexample-and-ratification-determinism 15
  (prop/for-all [seed (gen/choose 1 1000000)
                 path-id (gen/choose 0 5)]
                (let [reg-vec {:suite :monte-carlo-tokenomics
                               :seed seed
                               :path-id path-id
                               :epochs 24
                               :theta bip001/theta-flawed}
                      r1 (bip001/replay-regression-vector reg-vec)
                      r2 (bip001/replay-regression-vector reg-vec)]
                  (and (:reproduced? r1)
                       (= (:metrics r1) (:metrics r2))
                       (= (:demand-trace-digest r1) (:demand-trace-digest r2))
                       (get-in r1 [:metrics :supply-conserved?])))))

(deftest bip001-in-memory-e2e-fast-sim-test
  (testing "Track A fast E2E simulation blocks flawed draft via paramount objection and ratifies BIP-001 (A-CARB-D21-1)"
    (let [res (bip001/run-bip001-in-memory-e2e-sim {:fast? true :horizon-epochs 60 :mc-epochs 48})
          md (bip001/render-bip001-report-md res)]
      ;; Attempt 1: Flawed whale-heavy draft blocked by reproducible paramount objection
      (is (= :blocked-by-paramount-objection (get-in res [:attempt-1-flawed :status])))
      (is (false? (get-in res [:attempt-1-flawed :ratified?])))
      (is (true? (get-in res [:attempt-1-flawed :regression-replay :reproduced?])))
      ;; Attempt 2: Pareto-optimal BIP-001 (theta-12) ratified across all 4 governance layers
      (is (true? (get-in res [:attempt-2-bip001 :layer-1-lab-subnet :anchor-ok?])))
      (is (= 64 (count (get-in res [:attempt-2-bip001 :layer-1-lab-subnet :merkle-root]))))
      (is (true? (get-in res [:attempt-2-bip001 :layer-2-submission :ok?])))
      (is (= "bitecho-dev" (get-in res [:attempt-2-bip001 :layer-2-submission :subnet-id])))
      (is (= "bip/BIP-001" (get-in res [:attempt-2-bip001 :layer-2-submission :pointer-path])))
      ;; Layer 3: 10,000 ECH bounty settled with exact zero-dust split (8457 + 1493 + 50 = 10000)
      (is (true? (get-in res [:attempt-2-bip001 :layer-3-bounty :settled?])))
      (is (= {:gross-amount 10000
              :protocol-take 50
              :builder-net 8457
              :auditor-net 1493}
             (get-in res [:attempt-2-bip001 :layer-3-bounty :split])))
      ;; Layer 4: Unsubstantiated filibuster ignored, Tri-Circle consent ratified
      (is (= 1 (get-in res [:attempt-2-bip001 :layer-4-consent :unsubstantiated-objections-ignored])))
      (is (true? (get-in res [:attempt-2-bip001 :layer-4-consent :ratified?])))
      (is (= :ratified (get-in res [:attempt-2-bip001 :layer-4-consent :status])))
      ;; Comparative CRN & Horizon metrics show theta-12 improves decentralization over theta-0 and theta-flawed
      (is (< (get-in res [:comparison :crn-metrics :theta-12 :gini-index])
             (get-in res [:comparison :crn-metrics :theta-flawed :gini-index])))
      (is (str/includes? md "BIP-001"))
      (is (str/includes? md "8457")))))
