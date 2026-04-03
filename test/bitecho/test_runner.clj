(ns bitecho.test-runner
  "Test runner for Bitecho"
  (:require [bitecho.basalt.core-test]
            [bitecho.contagion.core-test]
            [bitecho.crypto-test]
            [bitecho.economy.account-test]
            [bitecho.murmur.core-test]
            [bitecho.shell.agent-test]
            [bitecho.shell.bootstrap-test]
            [bitecho.sieve.core-test]
            [bitecho.simulator-config-test]
            [bitecho.state-machine-fuzz-test]
            [bitecho.state-machine-test]
            [clojure.test :as t]))

(defn -main
  "Main entry point for running tests"
  [& _args]
  (let [results (t/run-all-tests #"bitecho.*")]
    (System/exit (+ (:fail results) (:error results)))))
