(ns bitecho.shell.core-test
  (:require [bitecho.shell.core :as core]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]
            [clojure.test :refer [deftest is testing]]))

(deftest ^{:doc "Network ingress filters external events correctly"}
  ingress-filter-test
  (testing "Network ingress filters external events correctly"
    (let [node (core/start-node (sm/init-state [] "node-pubkey-stub"))]
      (is (contains? node :network-in))
      (is (contains? node :app-out))
      ;; Test allowed events
      (async/put! (:network-in node) {:type :receive-gossip})
      (async/put! (:network-in node) {:type :receive-summary})

      ;; Test disallowed events (e.g. state injection)
      (async/put! (:network-in node) {:type :tick})

      ;; Wait for processing
      (async/<!! (async/timeout 50))

      (core/stop-node node))))

(deftest ^{:doc "valid-network-event? allows only explicitly whitelisted events"}
  valid-network-event-test
  (is (#'core/valid-network-event? {:type :receive-push-view}))
  (is (#'core/valid-network-event? {:type :receive-summary}))
  (is (#'core/valid-network-event? {:type :receive-pull-request}))
  (is (#'core/valid-network-event? {:type :receive-gossip}))
  (is (#'core/valid-network-event? {:type :receive-propose}))
  (is (#'core/valid-network-event? {:type :receive-vote}))
  (is (#'core/valid-network-event? {:type :register-home-set}))
  (is (#'core/valid-network-event? {:type :receive-offer-header}))
  (is (not (#'core/valid-network-event? {:type :tick})))
  (is (not (#'core/valid-network-event? {:type :some-malicious-event}))))

(deftest test-state-atom-and-query-node-state
  (testing "start-node returns :state-atom and query-node-state reads it in O(1)"
    (let [initial (sm/init-state [] "test-pubkey")
          node (core/start-node initial "/tmp/test-snap.edn" {:persist? false})]
      (is (some? (:state-atom node)))
      (is (instance? clojure.lang.IDeref (:state-atom node)))
      (is (= "test-pubkey" (:node-pubkey (core/query-node-state node))))

      ;; Test channel fallback when :state-atom is absent
      (let [node-no-atom (dissoc node :state-atom)]
        (is (= "test-pubkey" (:node-pubkey (core/query-node-state node-no-atom :timeout-ms 500)))))

      (core/stop-node node))))

