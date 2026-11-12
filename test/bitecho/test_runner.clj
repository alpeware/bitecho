(ns bitecho.test-runner
  "Test runner for Bitecho"
  (:require [bitecho.anchor-webauthn-test]
            [bitecho.basalt.core-test]
            [bitecho.contagion.core-test]
            [bitecho.core.anchoring-test]
            [bitecho.core.data-test]
            [bitecho.core.protocol-test]
            [bitecho.core.protocol.relay-test]
            [bitecho.core.subnet-test]
            [bitecho.crypto-test]
            [bitecho.crypto.sealed-test]
            [bitecho.demo.angels-test]
            [bitecho.economy.account-fuzz-test]
            [bitecho.economy.account-test]
            [bitecho.economy.attestation-test]
            [bitecho.economy.bundle-test]
            [bitecho.economy.burn-test]
            [bitecho.economy.escrow-test]
            [bitecho.economy.treasury-test]
            [bitecho.fractal-federation-test]
            [bitecho.fressian-test]
            [bitecho.light-node.core-test]
            [bitecho.murmur.core-test]
            [bitecho.node-bundle-test]
            [bitecho.rendezvous.core-test]
            [bitecho.shell.agent-sim-test]
            [bitecho.shell.agent-test]
            [bitecho.shell.bootstrap-test]
            [bitecho.shell.browser-test]
            [bitecho.shell.core-test]
            [bitecho.shell.discovery-test]
            [bitecho.shell.http-relay-test]
            [bitecho.shell.infra-shells-test]
            [bitecho.shell.light-node-test]
            [bitecho.shell.mesh-test]
            [bitecho.shell.persistence-test]
            [bitecho.sieve.core-test]
            [bitecho.simulator-config-test]
            [bitecho.simulator-test]
            [bitecho.state-machine-fuzz-test]
            [bitecho.state-machine-portability-test]
            [bitecho.state-machine-test]
            [bitecho.state-machine-ttl-test]
            [bitecho.streamlet.core-test]
            [bitecho.streamlet.fuzz-test]
            [bitecho.tokenomics-v2-e2e-test]
            [bitecho.wire-negotiation-test]
            [clojure.string :as str]
            [clojure.test :as t]))

(defn- parse-args [args]
  (let [args-vec (vec args)
        skip-int? (or (some #{"--skip-integration"} args-vec)
                      (= "1" (System/getenv "BITECHO_SKIP_INTEGRATION")))
        explicit-nses (->> args-vec
                           (remove #(or (= % "--skip-integration")
                                        (= % "-n")
                                        (= % "--ns")))
                           (filter #(str/starts-with? % "bitecho."))
                           (map symbol)
                           vec)]
    {:skip-integration? skip-int?
     :namespaces (if (seq explicit-nses) explicit-nses nil)}))

(defn -main
  "Main entry point for running tests.
   Supports --skip-integration or BITECHO_SKIP_INTEGRATION=1 to skip ^:integration test vars/namespaces.
   Accepts targeted namespace names to run a subset of tests."
  [& args]
  (let [{:keys [skip-integration? namespaces]} (parse-args args)
        target-nses (or (seq namespaces)
                        (->> (all-ns)
                             (filter #(re-matches #"bitecho\..*" (name (ns-name %))))
                             (map ns-name)
                             sort))
        target-nses (if skip-integration?
                      (remove #{'bitecho.node-bundle-test 'bitecho.shell.http-relay-test} target-nses)
                      target-nses)
        orig-test-var t/test-var
        results (if skip-integration?
                  (with-redefs [t/test-var (fn [v]
                                             (if (:integration (meta v))
                                               (println "Skipping integration test:" (str (ns-name (:ns (meta v)))) "/" (:name (meta v)))
                                               (orig-test-var v)))]
                    (apply t/run-tests target-nses))
                  (apply t/run-tests target-nses))]
    (System/exit (+ (:fail results 0) (:error results 0)))))
