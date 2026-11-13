(ns bitecho.shell.infra-test
  "Unit and integration tests for co-located infra-node + validator and port separation (A-U2-3, A-CARB-1,3,5)."
  (:require [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.main :as main]
            [bitecho.shell.infra :as infra]
            [bitecho.shell.mesh :as mesh]
            [clojure.test :refer [deftest is testing]])
  (:import [java.nio.file Files]))

(defn- make-temp-dir!
  [prefix]
  (.toFile (Files/createTempDirectory prefix (into-array java.nio.file.attribute.FileAttribute []))))

(deftest test-devnet-6-config-invariants
  (testing "devnet-6-config contains 6 canonical nodes and quorum threshold 4"
    (let [cfg (config/devnet-6-config)]
      (is (= 6 (:validator-count cfg)))
      (is (= 4 (:quorum-threshold cfg)))
      (is (= #{:node1 :node2 :node3 :ns1 :ns2 :ns3} (:nodes cfg)))
      (is (= 5 (:echo-sample-size cfg)))
      (is (= 4 (:echo-threshold cfg)))
      (is (= 5 (:ready-sample-size cfg)))
      (is (= 2 (:ready-threshold cfg)))
      (is (= 5 (:delivery-sample-size cfg)))
      (is (= 4 (:delivery-threshold cfg))))))

(deftest test-infra-port-calculation
  (testing "Infra ports are disjoint from Streamlet BFT (5000..5005) when :infra-port 5006 is configured"
    (let [nodes-cfg {:ns1 {:infra-port 5006 :ip4 "10.0.0.1"}
                     :ns2 {:infra-port 5006 :ip4 "10.0.0.2"}
                     :ns3 {:infra-port 5006 :ip4 "10.0.0.3"}}
          cfg {:cluster {:nodes nodes-cfg}}]
      ;; ns1 (idx 0) connecting to ns2 (idx 1):
      ;; local-port = base-local-port + peer-idx = 5006 + 1 = 5007
      ;; remote-port = base-peer-port + my-idx = 5006 + 0 = 5006
      (let [ports (infra/calculate-infra-ports cfg :ns1 :ns2 nodes-cfg)]
        (is (= {:local-port 5007 :remote-port 5006} ports))
        (is (<= 5006 (:local-port ports) 5008))
        (is (<= 5006 (:remote-port ports) 5008)))
      ;; ns2 (idx 1) connecting to ns3 (idx 2):
      (let [ports (infra/calculate-infra-ports cfg :ns2 :ns3 nodes-cfg)]
        (is (= {:local-port 5008 :remote-port 5007} ports))
        (is (<= 5006 (:local-port ports) 5008))
        (is (<= 5006 (:remote-port ports) 5008))))))

(deftest test-in-process-validator-state-snapshot-ingestion
  (testing "Infra runtime directly ingests validator chain-state snapshot without UDP network dial"
    (let [tmp-dir (make-temp-dir! "bitecho-infra-test-")
          state-dir (str tmp-dir)
          ident (infra/load-or-create-infra-peer-identity! state-dir :ns1)
          kp (crypto/generate-keypair)
          policy (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                              :trust-anchors #{(:pubkey-hex ident)}})
          val-state (atom {:ledger {(:pubkey-hex ident) {:balance 1000 :seq 1}}
                           :last-executed-finalized-epoch 42
                           :keypair kp})
          val-node {:node-id :ns1
                    :identity ident
                    :state-atom val-state}
          rt (infra/start-subnet-runtime! {:state-dir state-dir
                                           :policy policy
                                           :node-id :ns1
                                           :peer-identity ident
                                           :default-sender (:pubkey-hex ident)
                                           :validator-node val-node
                                           :epoch-fn (fn [] (long (:last-executed-finalized-epoch @val-state)))
                                           :heartbeat-ticker? false})]
      (try
        ;; Verify initial epoch derivation from epoch-fn
        (is (= 42 (infra/current-runtime-epoch rt)))

        ;; Ingest a direct chain state snapshot
        (let [snap (mesh/build-validator-chain-state-snapshot
                    @val-state ident (:pubkey-hex ident) "nonce-123")
              ingest-res (infra/ingest-validator-chain-state! rt snap)]
          (is (:ok? ingest-res))
          (is (= 42 (:finalized-epoch ingest-res)))
          (is (= 42 (deref (:epoch-atom rt)))))

        ;; Advance validator state
        (swap! val-state assoc :last-executed-finalized-epoch 55)
        (is (= 55 (infra/current-runtime-epoch rt)))

        ;; Regressive snapshot rejection (B-OPUS-2, Rule 5)
        (let [stale-snap {:finalized-epoch 10}
              reg-res (infra/ingest-validator-chain-state! rt stale-snap)
              status (infra/runtime-status rt)
              diag (first (filter #(= :validator-epoch-regressive (:reason %))
                                  (:diagnostics status)))]
          (is (false? (:ok? reg-res)))
          (is (= :validator-epoch-regressive (:error reg-res)))
          (is (= 55 (:epoch reg-res)))
          (is (= 1 (get-in status [:diagnostics-counts :validator-epoch-regressive])))
          (is (some? diag))
          (is (= 55 (:current diag)))
          (is (= 10 (:proposed diag))))

        (finally
          (infra/stop-subnet-runtime! rt))))))

(deftest test-start-infra-node-with-co-located-validator-lifecycle
  (testing "start-infra-node! starts and stops in-process validator cleanly and shares identity"
    (let [tmp-dir (make-temp-dir! "bitecho-colocated-test-")
          state-dir (str tmp-dir)
          cfg {:node-id :ns1
               :state-dir state-dir
               :cluster {:enabled? false}
               :dns {:enabled? false}
               :http {:enabled? false}
               :smtp {:enabled? false}
               :acme {:enabled? false}
               :upnp {:enabled? false}
               :validator {:node-id :ns1
                           :transport :in-memory
                           :state-dir (str tmp-dir "/val")
                           :cluster {:nodes {:ns1 {:pubkey "0000000000000000000000000000000000000000000000000000000000000001"
                                                   :port 5000}}}}}
          stack (main/start-infra-node! cfg)]
      (try
        (is (some? (:runtime stack)))
        (is (some? (:validator stack)))
        (is (= :ns1 (:node-id stack)))
        (is (= :ns1 (:node-id (:validator stack))))
        (is (= (:pubkey stack) (:pubkey-hex (:identity (:validator stack)))))
        (is (fn? (:stop! stack)))
        (is (fn? (get-in stack [:runtime :epoch-fn])))
        (finally
          ((:stop! stack)))))))
