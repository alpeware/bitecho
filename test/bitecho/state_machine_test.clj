(ns bitecho.state-machine-test
  "Tests for the pure state machine integrating Basalt, Murmur, Sieve, and Contagion."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.state-machine :as sm]
            [clojure.test :as t :refer [deftest is]]))

(deftest ^{:doc "Tests that init-state returns a correctly shaped state map."} init-state-test
  (let [initial-peers [{:ip "127.0.0.1" :port 8000 :pubkey (byte-array 32) :hash "A"}
                       {:ip "127.0.0.1" :port 8001 :pubkey (byte-array 32) :hash "B"}]
        state (sm/init-state initial-peers "node-pubkey-stub")]
    (is (vector? (:basalt-view state)))
    (is (= 20 (count (:basalt-view state))))
    (is (map? (:murmur-cache state)))
    (is (set? (:set (:murmur-cache state))))
    (is (= clojure.lang.PersistentQueue/EMPTY (:queue (:murmur-cache state))))
    (is (set? (:contagion-known-ids state)))
    (is (set? (:global-echo-sample state)))
    (is (set? (:global-ready-sample state)))
    (is (set? (:global-delivery-sample state)))
    (is (set? (:echo-subscribers state)))
    (is (set? (:ready-subscribers state)))
    (is (set? (:delivery-subscribers state)))
    (is (not (contains? state :echo-samples)))
    (is (not (contains? state :ready-samples)))
    (is (not (contains? state :delivery-samples)))))

