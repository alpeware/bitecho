(ns bitecho.test-runner
  "Test runner for Bitecho"
  (:require [bitecho.anchor-webauthn-test]
            [bitecho.basalt.core-test]
            [bitecho.bip016-shaped-sim-test]
            [bitecho.browser-cli-and-webrtc-diagnostics-test]
            [bitecho.contagion.core-test]
            [bitecho.core.anchoring-test]
            [bitecho.core.data-test]
            [bitecho.core.protocol-test]
            [bitecho.core.protocol.relay-test]
            [bitecho.core.storage-test]
            [bitecho.core.subnet-test]
            [bitecho.crypto-test]
            [bitecho.crypto.sealed-test]
            [bitecho.d24-remediation-scenarios-test]
            [bitecho.d25-remediation-scenarios-test]
            [bitecho.d26-remediation-scenarios-test]
            [bitecho.d27-publishing-and-remediation-test]
            [bitecho.d28-autosync-and-p2p-ack-hotfix-test]
            [bitecho.d30-artifact-publishing-scenarios-test]
            [bitecho.d31-unification-iii-scenarios-test]
            [bitecho.d32-bip006-onboarding-and-network-test]
            [bitecho.d33-bip007-low-latency-and-infra-test]
            [bitecho.d34-bip008-contagion-and-soak-test]
            [bitecho.d35-bip009-cluster-deployment-test]
            [bitecho.d36-bip010-yubikey-faucet-and-node-infra-test]
            [bitecho.d36-nodejs-infra-parity-test]
            [bitecho.d37-bip011-gentoo-host-and-unified-rollout-test]
            [bitecho.d38-bip013-observability-defense-and-autoupdate-test]
            [bitecho.d39-bip014-async-io-and-ice-diagnostics-test]
            [bitecho.d40-pupd1-self-update-test]
            [bitecho.d41-bip015-governance-and-docs-test]
            [bitecho.d45-bip018-hardening-and-failover-test]
            [bitecho.d46-bip019-fepoch1-test]
            [bitecho.d47-bip020-delivery-telemetry-test]
            [bitecho.d48-bip021-subnet-session-updater-test]
            [bitecho.d49-bip022-stage-a-operator-safety-test]
            [bitecho.d50-bip022-stage-b-contracts-test]
            [bitecho.d51-bip022-stage-c-state-identity-test]
            [bitecho.e2e.d29-remediation-scenario-test]
            [bitecho.economy.account-fuzz-test]
            [bitecho.economy.account-test]
            [bitecho.economy.attestation-test]
            [bitecho.economy.bundle-test]
            [bitecho.economy.burn-test]
            [bitecho.economy.escrow-test]
            [bitecho.economy.puzzle-test]
            [bitecho.economy.treasury-test]
            [bitecho.experiments-test]
            [bitecho.fractal-federation-test]
            [bitecho.fressian-test]
            [bitecho.governance.core-test]
            [bitecho.light-node.cli-flag-inventory-test]
            [bitecho.light-node.cli-test]
            [bitecho.light-node.core-test]
            [bitecho.memento-golden-vectors-test]
            [bitecho.memento-lumen-wakeup-sim-test]
            [bitecho.murmur.core-test]
            [bitecho.node-bundle-test]
            [bitecho.rendezvous.core-test]
            [bitecho.shell.agent-sim-test]
            [bitecho.shell.browser-test]
            [bitecho.shell.discovery-test]
            [bitecho.shell.http-relay-test]
            [bitecho.shell.http-test]
            [bitecho.shell.infra-shells-test]
            [bitecho.shell.infra-test]
            [bitecho.shell.light-node-test]
            [bitecho.shell.mesh-test]
            [bitecho.shell.persistence-test]
            [bitecho.sieve.core-test]
            [bitecho.sim.vopr-test]
            [bitecho.state-machine-fuzz-test]
            [bitecho.state-machine-portability-test]
            [bitecho.state-machine-test]
            [bitecho.state-machine-ttl-test]
            [bitecho.storage.app-release-test]
            [bitecho.storage.chunk-fetch-test]
            [bitecho.streamlet.core-test]
            [bitecho.streamlet.fuzz-test]
            [bitecho.stress-e2e-test]
            [bitecho.stress.bip001-sim-test]
            [bitecho.stress.monte-carlo-test]
            [bitecho.stress.release-proof-test]
            [bitecho.tokenomics-v2-e2e-test]
            [bitecho.v02322-hotfix-test]
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
