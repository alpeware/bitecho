(ns bitecho.basalt.core-test
  "Tests for Basalt peer sampling core logic."
  (:require [bitecho.basalt.core :as basalt]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest ^{:doc "Tests creation of peer records."} peer-creation-test
  (testing "creates a peer with proper hashed id"
    (let [peer (basalt/make-peer "127.0.0.1" 8080 (byte-array 32))]
      (is (= "127.0.0.1" (:ip peer)))
      (is (= 8080 (:port peer)))
      (is (= 0 (:age peer)))
      (is (some? (:pubkey peer)))
      (is (= 64 (count (:hash peer)))))))

(defspec ^{:doc "Tests view initialization spec."} view-initialization-spec 100
  (prop/for-all [peers (gen/list (gen/tuple
                                  (gen/return "127.0.0.1")
                                  gen/nat
                                  (gen/return (byte-array 32))))]
                (let [peer-records (map (fn [[ip port pubkey]]
                                          (basalt/make-peer ip port pubkey))
                                        peers)
                      view (basalt/init-view peer-records)]
                  (and (set? view)
                       (every? #(instance? bitecho.basalt.core.Peer %) view)))))

(defspec ^{:doc "Tests incrementing ages of all peers in a view."} increment-ages-spec 100
  (prop/for-all [peers (gen/list (gen/tuple
                                  (gen/return "127.0.0.1")
                                  gen/nat
                                  (gen/return (byte-array 32))))]
                (let [peer-records (map (fn [[ip port pubkey]]
                                          (basalt/make-peer ip port pubkey))
                                        peers)
                      view (basalt/init-view peer-records)
                      older-view (basalt/increment-ages view)]
                  (and (= (count view) (count older-view))
                       (every? (fn [p]
                                 (let [old-p (first (filter #(= (:hash %) (:hash p)) view))]
                                   (= (:age p) (inc (:age old-p)))))
                               older-view)))))

(deftest ^{:doc "Tests selection of random peers for exchange."} select-peers-test
  (testing "selects up to k random peers from view"
    (let [p1 (basalt/make-peer "1.1.1.1" 80 (byte-array 32))
          p2 (basalt/make-peer "2.2.2.2" 80 (byte-array 32))
          p3 (basalt/make-peer "3.3.3.3" 80 (byte-array 32))
          view #{p1 p2 p3}
          rng (java.util.Random. 42)
          selected-1 (basalt/select-peers rng view 1)
          selected-2 (basalt/select-peers rng view 2)
          selected-4 (basalt/select-peers rng view 4)]
      (is (= 1 (count selected-1)))
      (is (= 2 (count selected-2)))
      (is (= 3 (count selected-4)))
      (is (every? #(contains? view %) selected-2)))))
