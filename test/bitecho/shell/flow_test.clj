(ns bitecho.shell.flow-test
  "Tests for the pure core.async.flow adapter wrapping the state machine."
  (:require [bitecho.shell.flow :as flow]
            [bitecho.state-machine :as sm]
            [clojure.test :as t]))

(t/deftest ^{:doc "Tests the flow step function describing arity"}
  describe-arity-test
  (t/is (= {:params {:initial-peers "Initial Basalt peers for genesis"}
            :ins {:net-in "Incoming network messages from datachannels"
                  :events-in "Internal loopback events (ticks, self-messages)"}
            :outs {:net-out "Outgoing network messages to datachannels"
                   :events-out "Internal loopback events to be routed back to events-in"}}
           (flow/state-machine-step))))

(t/deftest ^{:doc "Tests the flow step function init arity"}
  init-arity-test
  (let [initial-peers [{:ip "127.0.0.1" :port 8080 :pubkey "abc" :age 0 :hash "def"}]
        state (flow/state-machine-step {:initial-peers initial-peers})]
    (t/is (map? state))
    (t/is (contains? state :basalt-view))
    (t/is (contains? state :ledger))))

(t/deftest ^{:doc "Tests the flow step function transition arity"}
  transition-arity-test
  (let [state {:dummy "state"}]
    (t/is (= state (flow/state-machine-step state :pause)))
    (t/is (= state (flow/state-machine-step state :resume)))
    (t/is (= state (flow/state-machine-step state :start)))
    (t/is (= state (flow/state-machine-step state :stop)))))

(t/deftest ^{:doc "Tests the flow step function transform arity"}
  transform-arity-test
  (let [initial-state (sm/init-state [])
        ;; A tick event that triggers both network and internal events.
        ;; We'll mock a simple event that generates a known set of commands.
        ;; Since sm/handle-event processes it, let's use a dummy event if possible,
        ;; or a real one like :tick that produces some output if we manipulate the RNG/state.
        ;; For simplicity, let's test with a fake event if sm allows it (it defaults to empty),
        ;; but we want to test the routing of :network-out vs other commands.
        ;; We can just use with-redefs to mock sm/handle-event to return specific commands.
        test-event {:type :dummy-event}]
    (with-redefs [sm/handle-event (fn [state event]
                                    (t/is (= test-event event))
                                    {:state (assoc state :updated true)
                                     :commands [{:type :network-out :target "A" :payload "msg"}
                                                {:type :send-gossip :target "B" :message "gossip"}
                                                {:type :network-out :target "C" :payload "msg2"}]})]
      (let [[new-state outs] (flow/state-machine-step initial-state :events-in test-event)]
        (t/is (:updated new-state))
        (t/is (= {:net-out [{:type :network-out :target "A" :payload "msg"}
                            {:type :network-out :target "C" :payload "msg2"}]
                  :events-out [{:type :send-gossip :target "B" :message "gossip"}]}
                 outs))))))

(t/deftest ^{:doc "Tests the create-topology function"}
  create-topology-test
  (let [topology (flow/create-topology [] "net-in-chan" "events-in-chan" "net-out-chan" "events-out-chan")]
    (t/is (map? topology))
    (t/is (contains? topology :procs))
    (t/is (contains? topology :conns))
    (t/is (contains? (:procs topology) :state-machine-proc))
    (t/is (vector? (:conns topology)))))
