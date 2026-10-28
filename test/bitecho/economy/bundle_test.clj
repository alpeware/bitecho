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

(deftest compact-vouchers-test
  (testing "Rejects vouchers from prior epochs and retains only the highest-seq voucher per channel in current epoch"
    (let [current-epoch 5
          vouchers [{:callee "callee-b" :home-node "home-1" :epoch 5 :seq 1 :cumulative-debit 10}
                    {:callee "callee-b" :home-node "home-1" :epoch 5 :seq 3 :cumulative-debit 30}
                    {:callee "callee-b" :home-node "home-1" :epoch 5 :seq 2 :cumulative-debit 20}
                    {:callee "callee-b" :home-node "home-1" :epoch 4 :seq 9 :cumulative-debit 90}
                    {:callee "callee-b" :home-node "home-2" :epoch 5 :seq 1 :cumulative-debit 15}
                    {:callee "callee-c" :home-node "home-1" :epoch 3 :seq 5 :cumulative-debit 50}]
          compacted (bundle/compact-vouchers vouchers current-epoch)]
      (is (= 2 (count compacted)))
      (is (every? #(= current-epoch (:epoch %)) compacted))
      (let [h1-voucher (first (filter #(= "home-1" (:home-node %)) compacted))
            h2-voucher (first (filter #(= "home-2" (:home-node %)) compacted))]
        (is (= 3 (:seq h1-voucher)))
        (is (= 30 (:cumulative-debit h1-voucher)))
        (is (= 1 (:seq h2-voucher)))
        (is (= 15 (:cumulative-debit h2-voucher))))))

  (testing "Safe boundary handling"
    (is (= [] (bundle/compact-vouchers [] 5)))
    (is (= [] (bundle/compact-vouchers nil 5)))
    (is (= [] (bundle/compact-vouchers [{:callee "b" :home-node "h" :epoch 4 :seq 1}] 5))))

  (testing "3-arity compact-vouchers window filtering and deterministic ordering"
    (let [vouchers [{:callee "callee-b" :home-node "home-1" :epoch 3 :seq 1 :cumulative-debit 10}
                    {:callee "callee-b" :home-node "home-1" :epoch 3 :seq 2 :cumulative-debit 20}
                    {:callee "callee-b" :home-node "home-1" :epoch 4 :seq 5 :cumulative-debit 50}
                    {:callee "callee-b" :home-node "home-1" :epoch 5 :seq 3 :cumulative-debit 30}
                    {:callee "callee-b" :home-node "home-1" :epoch 2 :seq 9 :cumulative-debit 90}
                    {:callee "callee-b" :home-node "home-1" :epoch 6 :seq 1 :cumulative-debit 10}]
          ;; Window [3, 5]: epoch 2 is discarded (< 3), epoch 6 is discarded (> 5)
          compacted (bundle/compact-vouchers vouchers 5 3)]
      (is (= 3 (count compacted)))
      ;; Chronological sorting: epoch 3, then epoch 4, then epoch 5
      (is (= [3 4 5] (mapv :epoch compacted)))
      ;; Epoch 3 retains highest seq 2
      (is (= 2 (:seq (first compacted))))
      ;; Epoch 4 retains seq 5
      (is (= 5 (:seq (second compacted))))
      ;; Epoch 5 retains seq 3
      (is (= 3 (:seq (nth compacted 2)))))))

(defspec ^{:doc "Property: 3-arity compact-vouchers retains exactly the maximum-seq voucher per channel within [min-epoch, current-epoch] sorted chronologically"}
  prop-compact-vouchers-multi-epoch-window 50
  (prop/for-all [min-ep (gen/choose 1 5)
                 delta (gen/choose 0 5)
                 callees (gen/vector (gen/elements ["callee-1" "callee-2"]) 15)
                 home-nodes (gen/vector (gen/elements ["home-1" "home-2"]) 15)
                 epochs (gen/vector (gen/choose 0 12) 15)
                 seqs (gen/vector (gen/choose 1 50) 15)]
                (let [current-ep (+ min-ep delta)
                      vouchers (mapv (fn [c h ep s]
                                       {:callee c :home-node h :epoch ep :seq s :cumulative-debit (* s 10)})
                                     callees home-nodes epochs seqs)
                      compacted (bundle/compact-vouchers vouchers current-ep min-ep)
                      in-window? (fn [v] (and (integer? (:epoch v)) (<= min-ep (:epoch v) current-ep)))
                      valid-vouchers (filter in-window? vouchers)
                      expected-keys (set (map (fn [v] [(:callee v) (:home-node v) (:epoch v)]) valid-vouchers))]
                  (and (every? in-window? compacted)
                       (= (count expected-keys) (count compacted))
           ;; Sorted chronologically by epoch
                       (= (mapv :epoch compacted) (sort (mapv :epoch compacted)))
           ;; Max seq per channel
                       (every? (fn [v]
                                 (let [k [(:callee v) (:home-node v) (:epoch v)]
                                       matching (filter #(= k [(:callee %) (:home-node %) (:epoch %)]) valid-vouchers)
                                       max-seq (apply max (map :seq matching))]
                                   (= (:seq v) max-seq)))
                               compacted)))))

(defspec ^{:doc "Property: compact-vouchers retains exactly the maximum-seq voucher per channel in current epoch"}
  prop-compact-vouchers-soundness 50
  (prop/for-all [current-epoch (gen/choose 1 10)
                 callees (gen/vector (gen/elements ["callee-1" "callee-2"]) 10)
                 home-nodes (gen/vector (gen/elements ["home-1" "home-2"]) 10)
                 epochs (gen/vector (gen/choose 1 12) 10)
                 seqs (gen/vector (gen/choose 1 50) 10)]
                (let [vouchers (mapv (fn [c h ep s]
                                       {:callee c :home-node h :epoch ep :seq s :cumulative-debit (* s 10)})
                                     callees home-nodes epochs seqs)
                      compacted (bundle/compact-vouchers vouchers current-epoch)
                      valid-vouchers (filter #(= current-epoch (:epoch %)) vouchers)
                      expected-keys (set (map (fn [v] [(:callee v) (:home-node v) (:epoch v)]) valid-vouchers))]
                  (and (every? #(= current-epoch (:epoch %)) compacted)
                       (= (count expected-keys) (count compacted))
                       (every? (fn [v]
                                 (let [k [(:callee v) (:home-node v) (:epoch v)]
                                       matching (filter #(= k [(:callee %) (:home-node %) (:epoch %)]) valid-vouchers)
                                       max-seq (apply max (map :seq matching))]
                                   (= (:seq v) max-seq)))
                               compacted)))))
