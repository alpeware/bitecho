(ns bitecho.cljs-test-runner
  "Node.js ClojureScript test runner for Bitecho portable core namespaces."
  (:require [bitecho.basalt.core-test]
            [bitecho.contagion.core-test]
            [bitecho.economy.account-test]
            [bitecho.economy.burn-test]
            [bitecho.economy.treasury-test]
            [bitecho.fressian-test]
            [bitecho.murmur.core-test]
            [bitecho.rendezvous.core-test]
            [bitecho.state-machine-portability-test]
            [bitecho.streamlet.core-test]
            [bitecho.wire-negotiation-test]
            [cljs.test :as test :refer-macros [run-tests]]))

(def ^{:doc "Atom holding aggregate test run summary."} summary-atom (atom {:fail 0 :error 0 :pass 0 :test 0}))

(defmethod test/report [::test/default :summary] [m]
  (reset! summary-atom m)
  (println "\nRan" (:test m) "tests containing"
           (+ (:pass m) (:fail m) (:error m)) "assertions.")
  (println (:fail m) "failures," (:error m) "errors."))

(defmethod test/report [::test/default :end-run-tests] [_m]
  (let [{:keys [fail error]} @summary-atom]
    (if (and (zero? fail) (zero? error))
      (.exit js/process 0)
      (.exit js/process 1))))

(defn -main
  "Main entry point for Node.js ClojureScript test runner."
  [& _args]
  (println "Running Bitecho ClojureScript tests on Node.js...")
  (run-tests 'bitecho.fressian-test
             'bitecho.basalt.core-test
             'bitecho.murmur.core-test
             'bitecho.contagion.core-test
             'bitecho.streamlet.core-test
             'bitecho.rendezvous.core-test
             'bitecho.economy.burn-test
             'bitecho.economy.account-test
             'bitecho.economy.treasury-test
             'bitecho.state-machine-portability-test
             'bitecho.wire-negotiation-test))

(set! *main-cli-fn* -main)
