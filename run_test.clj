(ns run-test
  (:require [bitecho.economy.ledger-test]
            [clojure.test :as t]))
(t/run-tests 'bitecho.economy.ledger-test)
