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
  (is (#'core/valid-network-event? {:type :on-deliver}))
  (is (#'core/valid-network-event? {:type :submit-vouchers}))
  (is (#'core/valid-network-event? {:type :settle-intent}))
  (is (#'core/valid-network-event? {:type :submit-transcript}))
  (is (not (#'core/valid-network-event? {:type :tick})))
  (is (not (#'core/valid-network-event? {:type :some-malicious-event}))))

(deftest test-start-node-survives-exceptions-and-tracks-errors
  (testing "start-node survives throwing events in go-loop and tracks event-errors-count"
    (let [initial (assoc (sm/init-state [] "test-pubkey") :test-val 42)
          node (core/start-node initial "/tmp/test-snap-err.edn" {:persist? false})]
      (try
        ;; Hook into sm/handle-event dynamically to throw on a specific trigger
        (with-redefs [sm/handle-event (fn [st ev]
                                        (if (= (:type ev) :exploding-event)
                                          (throw (ex-info "BOOM: simulated crash" {:cause :test}))
                                          {:state (assoc st :last-processed (:type ev))
                                           :commands []}))]
          ;; 1. Send an exploding event on events-in
          (async/put! (:events-in node) {:type :exploding-event})
          (Thread/sleep 50)
          (let [st1 (core/query-node-state node)]
            (is (= 1 (:event-errors-count st1)))
            (is (re-find #"BOOM: simulated crash" (str (:last-event-error st1)))))

          ;; 2. Verify go-loop is still alive by processing a normal event on events-in
          (async/put! (:events-in node) {:type :normal-event})
          (Thread/sleep 50)
          (let [st2 (core/query-node-state node)]
            (is (= :normal-event (:last-processed st2)))
            (is (= 1 (:event-errors-count st2))))

          ;; 3. Send exploding event on network-in
          (async/put! (:network-in node) {:type :on-deliver}) ; allowed network event, will call handle-event
          (Thread/sleep 50)
          (let [st3 (core/query-node-state node)]
            (is (= :on-deliver (:last-processed st3))))

          ;; 4. Exploding allowed network event
          (with-redefs [sm/handle-event (fn [_ _]
                                          (throw (RuntimeException. "network crash")))]
            (async/put! (:network-in node) {:type :settle-intent})
            (Thread/sleep 50)
            (let [st4 (core/query-node-state node)]
              (is (= 2 (:event-errors-count st4)))
              (is (re-find #"network crash" (str (:last-event-error st4))))))

          ;; 5. Dropped network event increments :dropped-network-events-count
          (async/put! (:network-in node) {:type :disallowed-network-event})
          (Thread/sleep 50)
          (let [st5 (core/query-node-state node)]
            (is (= 1 (:dropped-network-events-count st5)))))
        (finally
          (core/stop-node node))))))

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

