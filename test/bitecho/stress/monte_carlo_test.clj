(ns bitecho.stress.monte-carlo-test
  "Generative and unit tests for Milestone D19: Sans-IO Monte Carlo Tokenomics Optimizer
   (`INV-D19-1`..`INV-D19-4`, `A-CARB-D19-1`..`A-CARB-D19-3`, `A-D19-1`..`A-D19-3`)."
  (:require [bitecho.economy.attestation :as attestation]
            [bitecho.economy.treasury :as treasury]
            [bitecho.stress.monte-carlo :as mc]
            [bitecho.stress.tokenomics-sim :as tok-sim]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def ^:private gen-theta
  (gen/let [k-bps (gen/choose 1500 5000)
            trailing (gen/elements [24 48 168 336 720])
            take-bps (gen/choose 10 200)
            streamlet-pct (gen/choose 10 40)
            min-stake (gen/elements [50000 100000 250000 500000 1000000])
            max-mult (gen/elements [2.0 3.0 4.0 6.0 8.0])
            min-burn (gen/elements [10 50 100 250 500 1000])
            sunset-ep (gen/elements [8760 17520 26280 35040])
            lambda (gen/elements [0.00003 0.0001 0.0003])]
    {:k-bps k-bps
     :treasury-trailing-epochs trailing
     :settlement-take-bps take-bps
     :streamlet-share-pct streamlet-pct
     :min-node-stake min-stake
     :max-stake-multiplier max-mult
     :min-signaling-burn min-burn
     :bootstrap-sunset-epoch sunset-ep
     :bootstrap-drawdown-lambda lambda}))

;; =============================================================================
;; 1. Core Arity & Parameterization Tests (A-D19-1, A-D19-2, A-D19-3)
;; =============================================================================

(deftest parameterized-treasury-and-attestation-test
  (testing "treasury/split-mint 2-arity and attestation/calculate-node-weight 4-arity (A-D19-1)"
    (is (= {:streamlet 200 :mesh 800} (treasury/split-mint 1000)))
    (is (= {:streamlet 350 :mesh 650} (treasury/split-mint 1000 35)))
    (is (= {:streamlet 1000 :mesh 0} (treasury/split-mint 1000 150)))
    (is (= {:streamlet 0 :mesh 1000} (treasury/split-mint 1000 -10)))
    (is (= 4.0 (attestation/calculate-node-weight 1.0 2000000 250000)))
    (is (= 6.0 (attestation/calculate-node-weight 1.0 2000000 250000 6.0)))
    (is (= 2.0 (attestation/calculate-node-weight 1.0 2000000 250000 2.0))))

  (testing "tokenomics_sim build-initial-tokenomics-state and step-tokenomics-epoch accept theta overrides (A-D19-2, A-D19-3)"
    (let [theta {:k-bps 3000
                 :treasury-trailing-epochs 48
                 :streamlet-share-pct 30
                 :settlement-take-bps 75
                 :min-signaling-burn 200}
          {:keys [state]} (tok-sim/build-initial-tokenomics-state theta)
          step1 (tok-sim/step-tokenomics-epoch state 1 48000 nil
                                               {:settlement-take-per-epoch 12000
                                                :verify-signatures? false})
          st1 (:state step1)]
      (is (= 48 (get-in st1 [:config :treasury-trailing-epochs])))
      (is (= 48000 (get-in st1 [:epoch-burns 0])))
      (is (= 12000 (get-in st1 [:epoch-settlement-takes 0])))
      ;; Trailing average over 48 epochs for epoch 1: (48000 + 12000) / 48 = 1250
      ;; k = 3000 bps (30%): 1250 * 3000 / 10000 = 375
      (is (= 375 (get-in step1 [:treasury-res :epoch-mint])))
      ;; 30% streamlet = 112, 70% mesh = 263
      (is (= 112 (get-in step1 [:treasury-res :m-streamlet])))
      (is (= 263 (get-in step1 [:treasury-res :m-mesh]))))))

;; =============================================================================
;; 2. Generative Properties: Common Random Numbers & Supply Conservation
;; =============================================================================

(defspec ^{:doc "Property: Common Random Numbers determinism and exact supply conservation across trajectories."}
  prop-crn-determinism-and-supply-conservation 20
  (prop/for-all [theta-a gen-theta
                 theta-b gen-theta
                 seed (gen/choose 1 1000000)
                 path-id (gen/choose 0 15)]
                (let [opts {:seed seed :path-id path-id :epochs 48 :verify-signatures? false}
                      res-a1 (mc/run-monte-carlo-trajectory theta-a opts)
                      res-a2 (mc/run-monte-carlo-trajectory theta-a opts)
                      ;; Same baseline burn/take parameters produce identical exogenous shock trace under CRN (A-CARB-D19-1)
                      theta-b-same-fees (assoc theta-b
                                               :min-signaling-burn (:min-signaling-burn theta-a)
                                               :settlement-take-bps (:settlement-take-bps theta-a))
                      res-b (mc/run-monte-carlo-trajectory theta-b-same-fees opts)]
                  (and (= (:metrics res-a1) (:metrics res-a2))
                       (:supply-conserved? (:metrics res-a1))
                       (:supply-conserved? (:metrics res-b))
                       (= (:demand-trace-digest res-a1) (:demand-trace-digest res-b))))))

;; =============================================================================
;; 3. Generative Property: Pareto Frontier Non-Dominance Invariant
;; =============================================================================

(defspec ^{:doc "Property: Pareto frontier contains only non-dominated candidates."}
  prop-pareto-dominance-invariants 25
  (prop/for-all [candidates (gen/not-empty
                             (gen/vector
                              (gen/let [cvar (gen/choose 1 20)
                                        longevity (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})
                                        deflation (gen/double* {:min 0.0 :max 5.0 :NaN? false :infinite? false})
                                        decentralization (gen/double* {:min 0.0 :max 1.0 :NaN? false :infinite? false})
                                        id gen/uuid]
                                {:candidate-id id
                                 :metrics {:cvar-5pct-active-nodes cvar
                                           :cap-longevity-score longevity
                                           :net-deflation-efficiency deflation
                                           :decentralization-score decentralization}})
                              2 16))]
                (let [frontier (mc/pareto-frontier candidates)]
                  (and (seq frontier)
                       ;; No candidate on the Pareto frontier is strictly dominated by any candidate in the full set
                       (every? (fn [f-cand]
                                 (not-any? (fn [other]
                                             (mc/pareto-dominates? (:metrics other) (:metrics f-cand)))
                                           candidates))
                               frontier)
                       ;; Every non-frontier candidate is dominated by at least one candidate in the full set
                       (let [frontier-ids (set (map :candidate-id frontier))]
                         (every? (fn [c]
                                   (or (contains? frontier-ids (:candidate-id c))
                                       (some (fn [other]
                                               (mc/pareto-dominates? (:metrics other) (:metrics c)))
                                             candidates)))
                                 candidates))))))

;; =============================================================================
;; 4. LHS Stratification, Operator Cohort, & Cross-Layer E2E Validation
;; =============================================================================

(deftest lhs-and-monte-carlo-sweep-test
  (testing "Latin Hypercube Sampling stratifies all 9 parameter dimensions within bounds"
    (let [samples (mc/sample-lhs-parameters 8 42)]
      (is (= 8 (count samples)))
      (doseq [theta samples]
        (is (<= 1500 (:k-bps theta) 5000))
        (is (<= 24 (:treasury-trailing-epochs theta) 720))
        (is (<= 10 (:settlement-take-bps theta) 200))
        (is (<= 10 (:streamlet-share-pct theta) 40))
        (is (<= 50000 (:min-node-stake theta) 1000000))
        (is (<= 2.0 (:max-stake-multiplier theta) 8.0))
        (is (<= 10 (:min-signaling-burn theta) 1000))
        (is (<= 8760 (:bootstrap-sunset-epoch theta) 35040))
        (is (<= 0.00003 (:bootstrap-drawdown-lambda theta) 0.0005)))))

  (testing "Parallel Monte Carlo sweep ranks Pareto frontier and validates top candidate in Layer 3 & Layer 5"
    (let [sweep (mc/run-monte-carlo-sweep {:num-candidates 4
                                           :num-paths 2
                                           :epochs 36
                                           :seed 20261115})
          validation (mc/validate-pareto-candidates-e2e! sweep {:top-k 1})]
      (is (= 4 (count (:results sweep))))
      (is (seq (:pareto-frontier sweep)))
      (is (seq (:top-candidates sweep)))
      (is (every? #(get-in % [:metrics :supply-conserved?]) (:results sweep)))
      (is (:all-valid? validation))
      (is (map? (:layer-5-experiment-config (first (:validated-candidates validation))))))))
