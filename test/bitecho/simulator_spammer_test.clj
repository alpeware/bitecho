(ns bitecho.simulator-spammer-test
  (:require [bitecho.simulator.spammer :as spammer]
            [clojure.core.async :as async]
            [clojure.test :refer [deftest is testing]]))

(deftest test-spammer-generation
  (testing "Spammer shell generates invalid route-directed-message envelopes"
    (let [spammer-ch (async/chan 10)
          stop-ch (async/chan)
          _ (spammer/start-spammer "target-pubkey" spammer-ch stop-ch)
          msg (async/<!! spammer-ch)]
      (is (= :route-directed-message (:type msg)))
      (is (= "target-pubkey" (:destination msg)))
      (is (not (nil? (:envelope msg))))
      (async/put! stop-ch true))))

(deftest test-spammer-init-and-stop
  (testing "Spammer init-node and stop-node functions work correctly"
    (let [node (spammer/init-node "target-pubkey")
          msg (async/<!! (:net-out node))]
      (is (= :route-directed-message (:type msg)))
      (is (= "target-pubkey" (:destination msg)))
      (spammer/stop-node node))))
