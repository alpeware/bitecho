(ns bitecho.streamlet.core-test
  (:require [bitecho.crypto :as crypto]
            [bitecho.streamlet.core :as core]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest test-streamlet-records
  (testing "Block record can be instantiated"
    (let [block (core/->Block 1 "parent-hash-xyz" {:some "payload"} "proposer-xyz")]
      (is (= 1 (:epoch block)))
      (is (= "parent-hash-xyz" (:parent-hash block)))
      (is (= {:some "payload"} (:payload block)))
      (is (= "proposer-xyz" (:proposer block)))))

  (testing "Vote record can be instantiated"
    (let [vote (core/->Vote "block-hash-abc" 2 "signature-123")]
      (is (= "block-hash-abc" (:block-hash vote)))
      (is (= 2 (:epoch vote)))
      (is (= "signature-123" (:voter-signature vote))))))

(deftest test-propose-block
  (testing "propose-block uses correct state defaults"
    (let [state {:node-pubkey "pub1" :mempool ["tx1"] :head-hash "hash0"}
          block (core/propose-block state 5)]
      (is (= 5 (:epoch block)))
      (is (= "hash0" (:parent-hash block)))
      (is (= ["tx1"] (:payload block)))
      (is (= "pub1" (:proposer block)))))

  (testing "propose-block falls back to genesis and empty mempool"
    (let [state {:node-pubkey "pub2"}
          block (core/propose-block state 6)]
      (is (= 6 (:epoch block)))
      (is (= "genesis" (:parent-hash block)))
      (is (= [] (:payload block)))
      (is (= "pub2" (:proposer block))))))

(deftest test-cast-vote
  (testing "cast-vote prevents duplicate voting per epoch"
    (let [state {:voted-epochs #{7}}
          block (core/->Block 7 "hashX" [] "proposer1")
          vote (core/cast-vote state block)]
      (is (nil? vote))))

  (testing "cast-vote generates valid signed vote"
    (let [keypair (crypto/generate-keypair)
          state {:voted-epochs #{} :keypair keypair}
          block (core/->Block 8 "hashY" [] "proposer2")
          vote (core/cast-vote state block)]
      (is (not (nil? vote)))
      (is (= 8 (:epoch vote)))
      (is (string? (:block-hash vote)))
      (is (string? (:voter-signature vote)))
      ;; Verify signature
      (is (true? (crypto/verify
                  (:public keypair)
                  (.getBytes ^String (:block-hash vote) "UTF-8")
                  (core/hex->bytes (:voter-signature vote))))))))

(deftest test-quorum-threshold
  (testing "quorum-threshold calculates 2n/3 properly"
    (is (= 1 (core/quorum-threshold 1)))
    (is (= 2 (core/quorum-threshold 2)))
    (is (= 2 (core/quorum-threshold 3)))
    (is (= 3 (core/quorum-threshold 4)))
    (is (= 4 (core/quorum-threshold 5)))
    (is (= 4 (core/quorum-threshold 6)))
    (is (= 7 (core/quorum-threshold 10)))))

(deftest test-accumulate-vote
  (let [keypair1 (crypto/generate-keypair)
        pub1 (:public keypair1)
        priv1 (:private keypair1)

        keypair2 (crypto/generate-keypair)
        pub2 (:public keypair2)
        priv2 (:private keypair2)

        block-hash "test-block-hash"

        ;; valid vote from pub1
        sig1 (crypto/sign priv1 (.getBytes block-hash "UTF-8"))
        vote1 (core/->Vote block-hash 1 (#'core/bytes->hex sig1))

        ;; valid vote from pub2
        sig2 (crypto/sign priv2 (.getBytes block-hash "UTF-8"))
        vote2 (core/->Vote block-hash 1 (#'core/bytes->hex sig2))

        ;; invalid vote (wrong signature)
        invalid-sig (crypto/sign priv2 (.getBytes "wrong-hash" "UTF-8"))
        invalid-vote (core/->Vote block-hash 1 (#'core/bytes->hex invalid-sig))]

    (testing "accumulate-vote rejects invalid signatures"
      (let [state {:block-votes {} :notarized-blocks #{}}
            new-state (core/accumulate-vote state invalid-vote pub1 3)]
        (is (= state new-state))))

    (testing "accumulate-vote accepts valid signature but no notarization below threshold"
      (let [state {:block-votes {} :notarized-blocks #{}}
            new-state (core/accumulate-vote state vote1 pub1 3)]
        (is (= #{(#'core/bytes->hex pub1)} (get-in new-state [:block-votes block-hash])))
        (is (= #{} (:notarized-blocks new-state)))))

    (testing "accumulate-vote notarizes block when threshold is reached"
      (let [state {:block-votes {block-hash #{(#'core/bytes->hex pub1)}}
                   :notarized-blocks #{}}
            ;; threshold for n=3 is 2
            new-state (core/accumulate-vote state vote2 pub2 3)]
        (is (= #{(#'core/bytes->hex pub1) (#'core/bytes->hex pub2)} (get-in new-state [:block-votes block-hash])))
        (is (= #{block-hash} (:notarized-blocks new-state)))))))

(defn- build-test-chain
  "Builds a chain of blocks from a list of epochs."
  [epochs]
  (reduce (fn [acc epoch]
            (let [parent-hash (if (empty? acc) "genesis" (:hash (last acc)))
                  block (core/->Block epoch parent-hash [] "proposer")
                  b-hash (core/hash-block block)]
              (conj acc (assoc block :hash b-hash))))
          []
          epochs))

(deftest test-finalize-prefix-unit
  (testing "finalize-prefix finalizes nothing if no consecutive epochs"
    (let [chain (build-test-chain [1 3 5])
          blocks-map (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) chain))
          notarized (set (keys blocks-map))
          state {:blocks blocks-map
                 :notarized-blocks notarized
                 :finalized-blocks #{}}
          new-state (core/finalize-prefix state)]
      (is (= #{} (:finalized-blocks new-state)))))

  (testing "finalize-prefix finalizes middle block and ancestors on 3 consecutive epochs"
    (let [chain (build-test-chain [1 2 4 5 6 8])
          blocks-map (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) chain))
          notarized (set (keys blocks-map))
          state {:blocks blocks-map
                 :notarized-blocks notarized
                 :finalized-blocks #{}}
          new-state (core/finalize-prefix state)
          b1 (:hash (nth chain 0))
          b2 (:hash (nth chain 1))
          b4 (:hash (nth chain 2))
          b5 (:hash (nth chain 3))]
      ;; chain of 4, 5, 6 means 5 and its ancestors (4, 2, 1) should be finalized
      (is (contains? (:finalized-blocks new-state) b1))
      (is (contains? (:finalized-blocks new-state) b2))
      (is (contains? (:finalized-blocks new-state) b4))
      (is (contains? (:finalized-blocks new-state) b5))
      (is (not (contains? (:finalized-blocks new-state) (:hash (nth chain 4))))))))

(defspec ^{:doc "Property: any chain with a 3-consecutive epoch sequence finalizes up to the middle block."}
  prop-finalize-prefix 100
  (prop/for-all [epochs (gen/not-empty (gen/vector (gen/choose 1 100)))]
                (let [sorted-epochs (vec (distinct (sort epochs)))
                      chain (build-test-chain sorted-epochs)
                      blocks-map (into {} (map (fn [b] [(:hash b) (dissoc b :hash)]) chain))
                      notarized (set (keys blocks-map))
                      state {:blocks blocks-map
                             :notarized-blocks notarized
                             :finalized-blocks #{}}
                      new-state (core/finalize-prefix state)
                      finalized (:finalized-blocks new-state)

                      triplets (partition 3 1 chain)
                      consecutive-triplets (filter (fn [[b1 b2 b3]]
                                                     (and (= (:epoch b2) (inc (:epoch b1)))
                                                          (= (:epoch b3) (inc (:epoch b2)))))
                                                   triplets)
                      expected-finalized (set (mapcat (fn [[_ b2 _]]
                                                        (map :hash (take-while #(not= (:hash %) (:hash b2)) chain)))
                                                      consecutive-triplets))
                      expected-finalized (into expected-finalized (map (comp :hash second) consecutive-triplets))]
                  (= finalized expected-finalized))))
