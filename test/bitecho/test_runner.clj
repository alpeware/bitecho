(ns bitecho.test-runner
  "Test runner for Bitecho"
  (:require [bitecho.basalt.core-test]
            [bitecho.channels.core-test]
            [bitecho.contagion.core-test]
            [bitecho.crypto-test]
            [bitecho.crypto.delegation-test]
            [bitecho.economy.difficulty-test]
            [bitecho.economy.ledger-test]
            [bitecho.economy.sci-sandbox-test]
            [bitecho.lottery.core-test]
            [bitecho.message.envelope-test]
            [bitecho.murmur.core-test]
            [bitecho.peer-review.core-test]
            [bitecho.routing.weighted-test]
            [bitecho.services.turn-test]
            [bitecho.shell.flow-test]
            [bitecho.sieve.core-test]
            [bitecho.state-machine-fuzz-test]
            [bitecho.state-machine-test]
            [clojure.test :as t]))

(defn -main
  "Main entry point for running tests"
  [& _args]
  (let [results (t/run-all-tests #"bitecho.*")]
    (System/exit (+ (:fail results) (:error results)))))
