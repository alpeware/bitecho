(ns bitecho.stress.bip001-sim-test
  "Generative and unit tests for Milestone D21/D22: Track A In-Memory End-to-End & Governance
   Simulation for BIP-001 (`A-D21-1`..`4`, `A-CARB-D21-1`..`5`, `A-D22-1`..`5`)."
  (:require [bitecho.stress.bip001-sim :as bip001]
            [bitecho.stress.tokenomics-sim :as tok-sim]
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

(deftest d22-mid-horizon-epoch-cutover-and-child-subnet-test
  (testing "Mid-horizon :scheduled-upgrades cutover from theta-0 to theta-12 at epoch E_act conserves 100% of supply (A-D22-1)"
    (let [res-0 (tok-sim/run-tokenomics-horizon-sim :medium {:epochs 100 :theta bip001/theta-0 :verify-signatures? false})
          res-12 (tok-sim/run-tokenomics-horizon-sim :medium {:epochs 100 :theta bip001/theta-12 :verify-signatures? false})
          res-cutover (tok-sim/run-tokenomics-horizon-sim
                       :medium
                       {:epochs 100
                        :theta bip001/theta-0
                        :scheduled-upgrades {50 bip001/theta-12}
                        :verify-signatures? false})]
      (is (true? (:conservation-ok? res-cutover)))
      (is (true? (:supply-cap-respected? res-cutover)))
      (is (= bip001/theta-12 (:active-theta res-cutover)))
      ;; Minted total in cutover at epoch 50 lies strictly between pure theta-0 and pure theta-12
      (is (< (:total-minted res-0) (:total-minted res-cutover) (:total-minted res-12))))))
