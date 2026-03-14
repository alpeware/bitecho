(ns bitecho.shell.agent-test
  "Tests for the agent node entry point."
  (:require [bitecho.shell.agent :as agent]
            [clojure.test :refer [deftest is]]))

(deftest ^{:doc "Tests that the agent node can initialize its flow with a bootstrap peer."}
  test-agent-init
  ;; Test that an agent can configure a topology using a provided bootstrap peer stub.
  (let [bootstrap-peer {:pubkey "0000" :ip "127.0.0.1" :port 8000 :age 0 :hash "1234"}
        node (agent/init-node bootstrap-peer)]
    (is (map? node))
    (is (contains? node :events-in))
    (is (contains? node :net-out))
    (is (contains? node :stop-ch))))
