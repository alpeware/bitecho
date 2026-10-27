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
      ;; All peers (including displaced p4, p1) should be reassigned into new slots
      (is (= 4 (count (remove #(nil? (:peer %)) updated-view)))))))

(deftest ^{:doc "Tests deterministic slot seed derivation."} derive-slot-seed-test
  (testing "determinism: identical inputs produce identical slot seeds"
    (let [s1 (basalt/derive-slot-seed "genesis" "pubkey-1" 0)
          s2 (basalt/derive-slot-seed "genesis" "pubkey-1" 0)]
      (is (= s1 s2))
      (is (string? s1))
      (is (= 64 (count s1)))))

  (testing "sensitivity: different slot index, pubkey, or epoch entropy produce different seeds"
    (let [s-base (basalt/derive-slot-seed "genesis" "pubkey-1" 0)
          s-diff-idx (basalt/derive-slot-seed "genesis" "pubkey-1" 1)
          s-diff-pk (basalt/derive-slot-seed "genesis" "pubkey-2" 0)
          s-diff-entropy (basalt/derive-slot-seed "block-hash-1" "pubkey-1" 0)]
      (is (not= s-base s-diff-idx))
      (is (not= s-base s-diff-pk))
      (is (not= s-base s-diff-entropy))))

  (testing "polymorphic inputs: string vs byte-array inputs yield identical results"
    (let [s-str (basalt/derive-slot-seed "genesis" "pubkey-1" 0)
          s-bytes (basalt/derive-slot-seed (.getBytes "genesis" "UTF-8")
                                           (.getBytes "pubkey-1" "UTF-8")
                                           0)]
      (is (= s-str s-bytes)))))

(deftest ^{:doc "Tests deterministic view initialization and slot reset."} deterministic-init-and-reset-slots-test
  (let [entropy "epoch-entropy-xyz"
        pubkey "node-pubkey-abc"
        init-view (basalt/init-view [] 4 entropy pubkey)]
    (testing "init-view generates slots matching derive-slot-seed for each slot index"
      (is (= 4 (count init-view)))
      (is (= (:seed (nth init-view 0)) (basalt/derive-slot-seed entropy pubkey 0)))
      (is (= (:seed (nth init-view 1)) (basalt/derive-slot-seed entropy pubkey 1)))
      (is (= (:seed (nth init-view 2)) (basalt/derive-slot-seed entropy pubkey 2)))
      (is (= (:seed (nth init-view 3)) (basalt/derive-slot-seed entropy pubkey 3))))

    (testing "reset-slots with deterministic entropy matches init-view seed for that index"
      (let [result (basalt/reset-slots init-view entropy pubkey 1 1)
            updated-view (:view result)]
        (is (= (:seed (nth updated-view 1)) (basalt/derive-slot-seed entropy pubkey 1)))
        (is (= (:seed (nth updated-view 1)) (:seed (nth init-view 1))))))

    (testing "reset-slots-deterministic and clean delegator reset-slots match"
      (let [res1 (basalt/reset-slots-deterministic init-view entropy pubkey 2 1)
            res2 (basalt/reset-slots init-view entropy pubkey 2 1)]
        (is (= (:seed (nth (:view res1) 2)) (:seed (nth (:view res2) 2))))))))

(deftest ^{:doc "Tests deterministic reset-slots entry points and explicit RNG entry point."}
  reset-slots-explicit-entry-points-test
  (let [entropy "epoch-entropy-fixed"
        pubkey "node-pubkey-fixed"
        init-view (basalt/init-view [] 4 entropy pubkey)]
    (testing "reset-slots-deterministic yields identical seeds across repeated runs"
      (let [res1 (basalt/reset-slots-deterministic init-view entropy pubkey 0 2)
            res2 (basalt/reset-slots-deterministic init-view entropy pubkey 0 2)]
        (is (= (:view res1) (:view res2)))
        (is (= (:samples res1) (:samples res2)))
        (is (= (:next-r res1) (:next-r res2)))
        (is (= (:seed (nth (:view res1) 0)) (basalt/derive-slot-seed entropy pubkey 0)))
        (is (= (:seed (nth (:view res1) 1)) (basalt/derive-slot-seed entropy pubkey 1)))))

    (testing "reset-slots-rng yields deterministic results given seeded RNG"
      (let [res1 (basalt/reset-slots-rng init-view (java.util.Random. 42) 0 2)
            res2 (basalt/reset-slots-rng init-view (java.util.Random. 42) 0 2)]
        (is (= (:view res1) (:view res2)))
        (is (= (:next-r res1) (:next-r res2)))))

    (testing "reset-slots clean delegator routes 4-arity to RNG and 5-arity to deterministic"
      (let [res-rng (basalt/reset-slots init-view (java.util.Random. 42) 0 2)
            expected-rng (basalt/reset-slots-rng init-view (java.util.Random. 42) 0 2)
            res-det (basalt/reset-slots init-view entropy pubkey 0 2)
            expected-det (basalt/reset-slots-deterministic init-view entropy pubkey 0 2)]
        (is (= (:view res-rng) (:view expected-rng)))
        (is (= (:view res-det) (:view expected-det)))))))

(deftest ^{:doc "Tests deterministic rank-based peer selection."}
  select-peers-deterministic-test
  (let [p1 (basalt/make-peer "1.1.1.1" 80 (byte-array 32))
        p2 (basalt/make-peer "2.2.2.2" 80 (byte-array 32))
        p3 (basalt/make-peer "3.3.3.3" 80 (byte-array 32))
        peers [p1 p2 p3]
        entropy "entropy-test"
        pubkey "pubkey-test"]
    (testing "select-peers-deterministic returns identical peers in identical order across runs"
      (let [sel1 (basalt/select-peers-deterministic entropy pubkey peers 2)
            sel2 (basalt/select-peers-deterministic entropy pubkey peers 2)]
        (is (= 2 (count sel1)))
        (is (= sel1 sel2))))

    (testing "select-peers 4-arity delegates to select-peers-deterministic"
      (let [sel-del (basalt/select-peers entropy pubkey peers 2)
            sel-det (basalt/select-peers-deterministic entropy pubkey peers 2)]
        (is (= sel-del sel-det))))

    (testing "select-peers with string seed delegates to deterministic selection"
      (let [sel-seed (basalt/select-peers entropy peers 2)
            sel-det (basalt/select-peers-deterministic entropy "select" peers 2)]
        (is (= sel-seed sel-det))))))

(defspec ^{:doc "Property: Slot seeds are strictly deterministic and invariant to RNG state."}
  prop-deterministic-slot-seeding 50
  (prop/for-all [entropy (gen/not-empty gen/string-alphanumeric)
                 pubkey (gen/not-empty gen/string-alphanumeric)
                 view-size (gen/choose 1 20)]
                (let [init-view (basalt/init-view [] view-size entropy pubkey)
                      slot-idx (mod 7 view-size)
                      expected-seed (basalt/derive-slot-seed entropy pubkey slot-idx)
                      actual-init-seed (:seed (nth init-view slot-idx))
                      reset-result (basalt/reset-slots-deterministic init-view entropy pubkey slot-idx 1)
                      actual-reset-seed (:seed (nth (:view reset-result) slot-idx))]
                  (and (= actual-init-seed expected-seed)
                       (= actual-reset-seed expected-seed)))))

(defspec ^{:doc "Property: reset-slots-deterministic is strictly pure and repeatable"}
  prop-reset-slots-deterministic-purity 50
  (prop/for-all [entropy (gen/not-empty gen/string-alphanumeric)
                 pubkey (gen/not-empty gen/string-alphanumeric)
                 view-size (gen/choose 2 20)]
                (let [init-view (basalt/init-view [] view-size entropy pubkey)
                      r (mod 3 view-size)
                      k (max 1 (quot view-size 2))
                      res1 (basalt/reset-slots-deterministic init-view entropy pubkey r k)
                      res2 (basalt/reset-slots-deterministic init-view entropy pubkey r k)]
                  (= res1 res2))))

(defspec ^{:doc "Property: select-peers-deterministic is strictly pure and repeatable"}
  prop-select-peers-deterministic-purity 50
  (prop/for-all [entropy (gen/not-empty gen/string-alphanumeric)
                 pubkey (gen/not-empty gen/string-alphanumeric)
                 k (gen/choose 1 3)]
                (let [p1 (basalt/make-peer "1.1.1.1" 80 (byte-array 32))
                      p2 (basalt/make-peer "2.2.2.2" 80 (byte-array 32))
                      p3 (basalt/make-peer "3.3.3.3" 80 (byte-array 32))
                      peers [p1 p2 p3]
                      sel1 (basalt/select-peers-deterministic entropy pubkey peers k)
                      sel2 (basalt/select-peers-deterministic entropy pubkey peers k)]
                  (and (= sel1 sel2)
                       (= (count sel1) k)))))