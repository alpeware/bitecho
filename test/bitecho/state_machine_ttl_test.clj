(ns bitecho.state-machine-ttl-test
  (:require [bitecho.state-machine :as sm]
            [clojure.test :refer [deftest is]]))

(deftest ^{:doc "Tests that old messages are pruned from contagion-known-ids and messages maps based on TTL"} gossip-ttl-pruning-test
  (let [initial-peers [{:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "A"}]
        state-0 (sm/init-state initial-peers "node-pubkey-stub")
        ;; Broadcast a message to insert it
        broadcast-event {:type :broadcast :payload (.getBytes "hello") :rng (java.util.Random. 42)}
        result-1 (sm/handle-event state-0 broadcast-event)
        state-1 (:state result-1)
        message-id (first (:contagion-known-ids state-1))]
    (is (contains? (:contagion-known-ids state-1) message-id))
    (is (contains? (:messages state-1) message-id))

    ;; Tick N times to exceed the TTL (default gossip-ttl-epochs = 10)
    (let [ttl (:gossip-ttl-epochs (:config state-1))
          tick-event {:type :tick :rng (java.util.Random. 42)}
          state-after-ticks (reduce (fn [s _] (:state (sm/handle-event s tick-event)))
                                    state-1
                                    (range (inc ttl)))]
      (is (not (contains? (:contagion-known-ids state-after-ticks) message-id)))
      (is (not (contains? (:messages state-after-ticks) message-id)))
      ;; Verify epoch-to-messages index is also pruned
      (is (every? (fn [[_epoch ids]] (not (contains? ids message-id)))
                  (:epoch-to-messages state-after-ticks))))))
