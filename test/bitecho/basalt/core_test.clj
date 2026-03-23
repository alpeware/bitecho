(ns bitecho.basalt.core-test
  "Tests for Basalt peer sampling core logic."
  (:require [bitecho.basalt.core :as basalt]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest ^{:doc "Tests invalid hex string parsing handling."} invalid-hex-test
  (testing "throws IllegalArgumentException on odd-length string"
    (is (thrown? IllegalArgumentException (basalt/hex->bytes "123"))))
  (testing "throws IllegalArgumentException on non-hex characters"
    (is (thrown? IllegalArgumentException (basalt/hex->bytes "123z")))))

(deftest ^{:doc "Tests creation of peer records."} peer-creation-test
  (testing "creates a peer with proper hashed id"
    (let [peer (basalt/make-peer "127.0.0.1" 8080 (byte-array 32))]
      (is (= "127.0.0.1" (:ip peer)))
      (is (= 8080 (:port peer)))
      (is (some? (:pubkey peer)))
      (is (= 64 (count (:hash peer)))))))

(deftest ^{:doc "Tests for sybil collision resistance."} peer-sybil-collision-test
  (testing "hashes are distinct when IP and port strings concatenate identically"
    (let [pubkey (byte-array 32)
          peer1 (basalt/make-peer "127.0.0.1" 80 pubkey)
          peer2 (basalt/make-peer "127.0.0.18" 0 pubkey)]
      (is (not= (:hash peer1) (:hash peer2))))))

(defspec ^{:doc "Tests view initialization spec."} view-initialization-spec 100
  (prop/for-all [peers (gen/list (gen/tuple
                                  (gen/return "127.0.0.1")
                                  gen/nat
                                  (gen/return (byte-array 32))))
                 view-size (gen/choose 1 50)]
                (let [peer-records (map (fn [[ip port pubkey]]
                                          (basalt/make-peer ip port pubkey))
                                        peers)
                      rng (java.util.Random. 42)
                      view (basalt/init-view peer-records view-size rng)]
                  (and (vector? view)
                       (= view-size (count view))
                       (every? map? view)
                       (every? #(string? (:seed %)) view)
                       (every? #(or (nil? (:peer %)) (instance? bitecho.basalt.core.Peer (:peer %))) view)))))

(deftest ^{:doc "Tests extract-peers."} extract-peers-test
  (testing "extracts distinct non-nil peers"
    (let [p1 (basalt/make-peer "1.1.1.1" 80 (byte-array 32))
          p2 (basalt/make-peer "2.2.2.2" 80 (byte-array 32))
          view [{:seed "a" :peer p1} {:seed "b" :peer nil} {:seed "c" :peer p2} {:seed "d" :peer p1}]
          extracted (basalt/extract-peers view)]
      (is (= 2 (count extracted)))
      (is (some #(= p1 %) extracted))
      (is (some #(= p2 %) extracted)))))

(defspec ^{:doc "Tests that update-view maximizes distinct participants."} update-view-spec 100
  (prop/for-all [peers-data (gen/list (gen/tuple (gen/return "127.0.0.1") gen/nat (gen/return (byte-array 32))))
                 view-size (gen/choose 1 20)]
                (let [peers (vals (reduce (fn [acc peer] (assoc acc (:hash peer) peer)) {}
                                          (map (fn [[ip port pubkey]] (basalt/make-peer ip port pubkey)) peers-data)))
                      rng (java.util.Random. 42)
                      empty-view (vec (repeatedly view-size #(let [sb (byte-array 32)]
                                                               (.nextBytes rng sb)
                                                               {:seed (basalt/bytes->hex sb) :peer nil})))
                      updated-view (basalt/update-view empty-view peers)
                      extracted (basalt/extract-peers updated-view)]
                  (and
                    ;; 1. The number of extracted peers should equal the minimum of view-size and unique peers
                   (= (count extracted) (min view-size (count peers)))
                    ;; 2. All extracted peers should be unique
                   (= (count extracted) (count (set (map :hash extracted))))))))

(deftest ^{:doc "Tests selection of random peers for exchange."} select-peers-test
  (testing "selects up to k random peers from view"
    (let [p1 (basalt/make-peer "1.1.1.1" 80 (byte-array 32))
          p2 (basalt/make-peer "2.2.2.2" 80 (byte-array 32))
          p3 (basalt/make-peer "3.3.3.3" 80 (byte-array 32))
          view [{:seed "a" :peer p1} {:seed "b" :peer p2} {:seed "c" :peer p3}]
          rng (java.util.Random. 42)
          selected-1 (basalt/select-peers rng view 1)
          selected-2 (basalt/select-peers rng view 2)
          selected-4 (basalt/select-peers rng view 4)]
      (is (= 1 (count selected-1)))
      (is (= 2 (count selected-2)))
      (is (= 3 (count selected-4)))
      (is (every? (set (map :peer view)) selected-2)))))

(deftest ^{:doc "Tests resetting slots and dynamic sampling."} reset-slots-test
  (testing "resets k slots starting at index r, wrap-around, and returns samples"
    (let [p1 (basalt/make-peer "1.1.1.1" 80 (byte-array 32))
          p2 (basalt/make-peer "2.2.2.2" 80 (byte-array 32))
          p3 (basalt/make-peer "3.3.3.3" 80 (byte-array 32))
          p4 (basalt/make-peer "4.4.4.4" 80 (byte-array 32))
          view [{:seed "seed0" :peer p1}
                {:seed "seed1" :peer p2}
                {:seed "seed2" :peer p3}
                {:seed "seed3" :peer p4}]
          rng (java.util.Random. 42)
          ;; reset 2 slots starting at index 3. Modulo will affect indices 3 and 0.
          result (basalt/reset-slots view rng 3 2)
          updated-view (:view result)
          samples (:samples result)
          next-r (:next-r result)]
      (is (= 1 next-r))
      (is (= 2 (count samples)))
      (is (some #(= p4 %) samples))
      (is (some #(= p1 %) samples))
      (is (= 4 (count updated-view)))
      ;; Seeds for 3 and 0 should be different from original
      (is (not= "seed3" (:seed (nth updated-view 3))))
      (is (not= "seed0" (:seed (nth updated-view 0))))
      ;; Remaining peers (p2, p3) should repopulate empty slots, so slot 0 and 3 should have peers, possibly p2 or p3
      (is (= 2 (count (remove #(nil? (:peer %)) updated-view)))))))