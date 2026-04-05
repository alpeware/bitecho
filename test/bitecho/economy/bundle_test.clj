(ns bitecho.economy.bundle-test
  (:require [bitecho.economy.bundle :as bundle]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest add-to-buffer-test
  (testing "Adds a transfer to an empty buffer and initializes the start time"
    (let [state {:buffer [] :bundle-start-time nil}
          transfer {:id 1 :amount 10}
          current-time 1000
          new-state (bundle/add-to-buffer state transfer current-time)]
      (is (= [{:id 1 :amount 10}] (:buffer new-state)))
      (is (= 1000 (:bundle-start-time new-state)))))

  (testing "Adds a transfer to an existing buffer and does not update start time"
    (let [state {:buffer [{:id 1 :amount 10}] :bundle-start-time 1000}
          transfer {:id 2 :amount 20}
          current-time 2000
          new-state (bundle/add-to-buffer state transfer current-time)]
      (is (= [{:id 1 :amount 10} {:id 2 :amount 20}] (:buffer new-state)))
      (is (= 1000 (:bundle-start-time new-state))))))

(deftest try-bundle-test
  (testing "Does not bundle if below limits"
    (let [state {:buffer [{:id 1} {:id 2}] :bundle-start-time 1000}
          current-time 1050
          max-size 10
          max-time 100
          result (bundle/try-bundle state current-time max-size max-time)]
      (is (nil? (:bundle result)))
      (is (= state (:state result)))))

  (testing "Bundles if size limit reached"
    (let [state {:buffer [{:id 1} {:id 2} {:id 3}] :bundle-start-time 1000}
          current-time 1050
          max-size 3
          max-time 100
          result (bundle/try-bundle state current-time max-size max-time)]
      (is (= [{:id 1} {:id 2} {:id 3}] (:bundle result)))
      (is (= [] (:buffer (:state result))))
      (is (nil? (:bundle-start-time (:state result))))))

  (testing "Bundles if time limit reached"
    (let [state {:buffer [{:id 1} {:id 2}] :bundle-start-time 1000}
          current-time 1150
          max-size 10
          max-time 100
          result (bundle/try-bundle state current-time max-size max-time)]
      (is (= [{:id 1} {:id 2}] (:bundle result)))
      (is (= [] (:buffer (:state result))))
      (is (nil? (:bundle-start-time (:state result)))))))

(defspec ^{:doc "Bundling preserves all transactions in the buffer"}
  bundle-preserves-tx-invariant 100
  (prop/for-all [txs (gen/vector gen/int)
                 current-time gen/nat
                 max-time (gen/elements [1 100])]
                (let [state {:buffer txs :bundle-start-time 0}
                      result (bundle/try-bundle state current-time 0 max-time)]
                  (if (empty? txs)
                    (nil? (:bundle result))
                    (= txs (:bundle result))))))