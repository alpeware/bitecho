(ns bitecho.streamlet.core-test
  (:require [bitecho.streamlet.core :as core]
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
