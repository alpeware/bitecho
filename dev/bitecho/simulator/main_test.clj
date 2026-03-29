(ns bitecho.simulator.main-test
  (:require [bitecho.simulator.main :as sim-main]
            [clojure.test :refer [deftest is testing]]))

(deftest calculate-ratio-test
  (testing "Ratio of dropped Byzantine packets vs successful honest deliveries"
    (is (= "Undefined (0 successful)" (sim-main/calculate-ratio 100 0)))
    (is (= "0.50 : 1" (sim-main/calculate-ratio 10 20)))
    (is (= "2.00 : 1" (sim-main/calculate-ratio 20 10)))
    (is (= "1.00 : 1" (sim-main/calculate-ratio 15 15)))))

(deftest calculate-circuit-lock-time-test
  (testing "Time-to-circuit-lock measurement"
    (is (= 500 (sim-main/calculate-circuit-lock-time 1000 1500)))))
