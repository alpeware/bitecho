(ns bitecho.cljs-test-runner
  "Node.js ClojureScript test runner for Bitecho portable core namespaces."
  (:require [bitecho.anchor-webauthn-test]
            [bitecho.basalt.core-test]
            [bitecho.browser-cli-and-webrtc-diagnostics-test]
            [bitecho.contagion.core-test]
            [bitecho.core.anchoring-test]
            [bitecho.core.data-test]
            [bitecho.core.protocol-test]
            [bitecho.core.protocol.relay-test]
            [bitecho.core.subnet-test]
            [bitecho.d45-bip018-hardening-and-failover-test]
            [bitecho.d46-bip019-fepoch1-test]
            [bitecho.d47-bip020-delivery-telemetry-test]
            [bitecho.d48-bip021-subnet-session-updater-test]
            [bitecho.d49-bip022-stage-a-operator-safety-test]
            [bitecho.d50-bip022-stage-b-contracts-test]
            [bitecho.d51-bip022-stage-c-state-identity-test]
            [bitecho.economy.account-test]
            [bitecho.economy.burn-test]
            [bitecho.economy.treasury-test]
            [bitecho.fractal-federation-test]
            [bitecho.fressian-test]
            [bitecho.memento-golden-vectors-test]
            [bitecho.murmur.core-test]
            [bitecho.rendezvous.core-test]
            [bitecho.shell.browser-test]
            [bitecho.state-machine-portability-test]
            [bitecho.storage.app-release-test]
            [bitecho.storage.chunk-fetch-test]
            [bitecho.streamlet.core-test]
            [bitecho.v02322-hotfix-test]
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
  (run-tests 'bitecho.anchor-webauthn-test
             'bitecho.browser-cli-and-webrtc-diagnostics-test
             'bitecho.fressian-test
             'bitecho.memento-golden-vectors-test
             'bitecho.basalt.core-test
             'bitecho.murmur.core-test
             'bitecho.contagion.core-test
             'bitecho.streamlet.core-test
             'bitecho.rendezvous.core-test
             'bitecho.economy.burn-test
             'bitecho.economy.account-test
             'bitecho.economy.treasury-test
             'bitecho.shell.browser-test
             'bitecho.state-machine-portability-test
             'bitecho.storage.app-release-test
             'bitecho.storage.chunk-fetch-test
             'bitecho.wire-negotiation-test
             'bitecho.fractal-federation-test
             'bitecho.core.anchoring-test
             'bitecho.core.data-test
             'bitecho.core.protocol-test
             'bitecho.core.protocol.relay-test
             'bitecho.core.subnet-test
             'bitecho.d45-bip018-hardening-and-failover-test
             'bitecho.d46-bip019-fepoch1-test
             'bitecho.d47-bip020-delivery-telemetry-test
             'bitecho.d48-bip021-subnet-session-updater-test
             'bitecho.d49-bip022-stage-a-operator-safety-test
             'bitecho.d50-bip022-stage-b-contracts-test
             'bitecho.d51-bip022-stage-c-state-identity-test
             'bitecho.v02322-hotfix-test))

(set! *main-cli-fn* -main)
