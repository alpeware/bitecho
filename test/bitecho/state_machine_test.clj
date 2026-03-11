(ns bitecho.state-machine-test
  "Tests for the pure state machine integrating Basalt, Murmur, Sieve, and Contagion."
  (:require [bitecho.state-machine :as sm]
            [clojure.test :refer [deftest is]]))

(deftest ^{:doc "Tests that init-state returns a correctly shaped state map."} init-state-test
  (let [initial-peers [{:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :age 0 :hash "A"}
                       {:ip "127.0.0.1" :port 8001 :pubkey (byte-array 32) :age 0 :hash "B"}]
        state (sm/init-state initial-peers)]
    (is (set? (:basalt-view state)))
    (is (= 2 (count (:basalt-view state))))
    (is (map? (:murmur-cache state)))
    (is (set? (:set (:murmur-cache state))))
    (is (vector? (:queue (:murmur-cache state))))
    (is (map? (:sieve-history state)))
    (is (set? (:contagion-known-ids state)))))

(deftest ^{:doc "Tests handle-event with a :tick event."} handle-tick-test
  (let [initial-peers [{:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :age 0 :hash "A"}
                       {:ip "127.0.0.1" :port 8001 :pubkey (byte-array 32) :age 0 :hash "B"}]
        state (sm/init-state initial-peers)
        event {:type :tick :rng (java.util.Random. 42)}
        result (sm/handle-event state event)]
    (is (map? result))
    (is (contains? result :state))
    (is (contains? result :commands))
    ;; Basalt view ages should increment
    (is (= 1 (:age (first (:basalt-view (:state result))))))
    ;; A push-view command should be emitted
    (is (some #(= :send-push-view (:type %)) (:commands result)))
    ;; A contagion summary command should be emitted
    (is (some #(= :send-summary (:type %)) (:commands result)))))

(deftest ^{:doc "Tests handle-event with a :broadcast event."} handle-broadcast-test
  (let [initial-peers [{:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :age 0 :hash "A"}]
        state (sm/init-state initial-peers)
        payload (.getBytes "hello")
        event {:type :broadcast :payload payload :rng (java.util.Random. 42)}
        result (sm/handle-event state event)]
    (is (map? result))
    (is (contains? result :state))
    (is (contains? result :commands))
    (let [commands (:commands result)]
      (is (seq commands))
      (is (= :send-gossip (:type (first commands))))
      (is (some? (:message (first commands))))
      (is (= "A" (:hash (first (:targets (first commands)))))))))

(deftest ^{:doc "Tests handle-event with a :receive-push-view event."} handle-receive-push-view-test
  (let [state (sm/init-state [])
        received-view #{{:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :age 0 :hash "A"}}
        event {:type :receive-push-view :view received-view}
        result (sm/handle-event state event)]
    (is (= 1 (count (:basalt-view (:state result)))))
    (is (= "A" (:hash (first (:basalt-view (:state result))))))))

(deftest ^{:doc "Tests handle-event with a :receive-summary event."} handle-receive-summary-test
  (let [state (assoc (sm/init-state []) :contagion-known-ids #{"msg1"})
        event {:type :receive-summary :summary #{"msg1" "msg2"}}
        result (sm/handle-event state event)]
    ;; Should emit a pull request for "msg2"
    (is (some #(= :send-pull-request (:type %)) (:commands result)))
    (is (= #{"msg2"} (:missing-ids (first (:commands result)))))))
