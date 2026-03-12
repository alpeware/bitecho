(ns bitecho.routing.weighted-test
  "Tests for stake-weighted routing logic."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.routing.weighted :as weighted]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest ^{:doc "Tests selecting a next hop with stake weighting."} select-next-hop-test
  (testing "returns nil for an empty view"
    (is (nil? (weighted/select-next-hop (java.util.Random. 42) #{} {}))))

  (testing "selects proportional to balance (or default weight of 1)"
    (let [p1 (basalt/make-peer "1.1.1.1" 80 (byte-array [1])) ; hash will be consistent
          p2 (basalt/make-peer "2.2.2.2" 80 (byte-array [2]))
          p3 (basalt/make-peer "3.3.3.3" 80 (byte-array [3]))
          view #{p1 p2 p3}
          ;; Give p1 a huge balance so it is almost always picked
          balances {(:pubkey p1) 1000000
                    (:pubkey p2) 0} ; p2 and p3 default to 1
          rng (java.util.Random. 42)
          selections (repeatedly 1000 #(weighted/select-next-hop rng view balances))
          freqs (frequencies selections)]
      ;; p1 should be picked overwhelmingly more often
      (is (> (get freqs p1 0) 900))
      ;; but others still have a chance (though maybe not in 1000 samples due to 1,000,000 weight)
      ;; So instead of exact counts, let's just make sure p1 is dominant
      (is (= p1 (first (first (sort-by val > freqs)))))))

  (testing "deterministic with fixed seed"
    (let [p1 (basalt/make-peer "1.1.1.1" 80 (byte-array [1]))
          p2 (basalt/make-peer "2.2.2.2" 80 (byte-array [2]))
          view #{p1 p2}
          balances {(:pubkey p1) 10
                    (:pubkey p2) 10}
          rng1 (java.util.Random. 123)
          rng2 (java.util.Random. 123)
          sel1 (repeatedly 100 #(weighted/select-next-hop rng1 view balances))
          sel2 (repeatedly 100 #(weighted/select-next-hop rng2 view balances))]
      (is (= sel1 sel2)))))

(defspec ^{:doc "Generative testing for select-next-hop invariants."} select-next-hop-spec 100
  (prop/for-all [peers-data (gen/list (gen/tuple (gen/return "127.0.0.1") gen/nat (gen/return (byte-array 32))))
                 seed gen/int]
                (let [to-peer (fn [[ip port pubkey]] (basalt/make-peer ip port pubkey))
                      view (set (map to-peer peers-data))
                      balances {} ; Everyone gets weight 1
                      rng (java.util.Random. seed)
                      selected (weighted/select-next-hop rng view balances)]
                  (if (empty? view)
                    (nil? selected)
                    (contains? view selected)))))
