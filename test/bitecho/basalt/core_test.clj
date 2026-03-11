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

(deftest ^{:doc "Tests merging of two Basalt views."} merge-views-test
  (testing "merging retains up to max-size elements, preferring younger ones"
    (let [p1 (assoc (basalt/make-peer "1.1.1.1" 80 (byte-array 32)) :age 5)
          p2 (assoc (basalt/make-peer "2.2.2.2" 80 (byte-array 32)) :age 2)
          p3 (assoc (basalt/make-peer "3.3.3.3" 80 (byte-array 32)) :age 10)
          p4 (assoc (basalt/make-peer "4.4.4.4" 80 (byte-array 32)) :age 1)
          p2-older (assoc p2 :age 8)
          local-view #{p1 p2-older p3}
          received-view #{p2 p4}
          merged-view (basalt/merge-views local-view received-view 3)]
      (is (= 3 (count merged-view)))
      (is (contains? merged-view p4))
      (is (contains? merged-view p2))
      (is (contains? merged-view p1))
      (is (not (contains? merged-view p2-older)))
      (is (not (contains? merged-view p3))))))

(defspec ^{:doc "Generative testing for merge-views invariants."} merge-views-spec 100
  (prop/for-all [peers-data-1 (gen/list (gen/tuple (gen/return "127.0.0.1") gen/nat (gen/return (byte-array 32)) gen/nat))
                 peers-data-2 (gen/list (gen/tuple (gen/return "127.0.0.1") gen/nat (gen/return (byte-array 32)) gen/nat))
                 max-size (gen/choose 1 100)]
                (let [to-peer (fn [[ip port pubkey age]] (assoc (basalt/make-peer ip port pubkey) :age age))
                      local-view (set (map to-peer peers-data-1))
                      received-view (set (map to-peer peers-data-2))
                      merged (basalt/merge-views local-view received-view max-size)
                      combined-raw (concat local-view received-view)
                      grouped-by-hash (group-by :hash combined-raw)]
                  (and (<= (count merged) max-size)
                       (set? merged)
                       (every? (fn [p]
                                 (let [same-hash-peers (get grouped-by-hash (:hash p))]
                                   (= (:age p) (apply min (map :age same-hash-peers)))))
                               merged)))))
