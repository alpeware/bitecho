(ns bitecho.streamlet.core-test
  (:require [bitecho.crypto :as crypto]
            [bitecho.streamlet.core :as core]
            [clojure.test :refer [deftest is testing]]))

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
