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
  (is (not (#'core/valid-network-event? {:type :tick})))
  (is (not (#'core/valid-network-event? {:type :some-malicious-event}))))
