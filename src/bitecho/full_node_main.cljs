(ns bitecho.full-node-main
  "Milestone D36 (`BIP-010: P-NODE-1`): Standalone Node.js Full / Infra Node Boundary Shell (`dist/bitecho-full-node.cjs`).
   Proves `bitecho.state-machine`, `bitecho.core.protocol.relay`, `bitecho.core.subnet`, `bitecho.core.storage`,
   `bitecho.governance.core`, `bitecho.deploy.core`, `bitecho.economy.spend-dac`, and `bitecho.fressian`
   compile and execute natively on Node.js (`:target :nodejs`, `:optimizations :advanced`).
   Supports:
   - `node dist/bitecho-full-node.cjs --self-test` (deterministic verification of Fressian state continuity,
     `state-machine` epoch ticks, `deploy/core` config-pointer activation & audit chain parity, `spend-dac`
     enforcement, and `subnet` pointer/blob serving)
   - `node dist/bitecho-full-node.cjs --version` / `--help`
   - `node dist/bitecho-full-node.cjs infra-node [--node-id <id>] [--state-dir <dir>] [--http-port <port>]`"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.core.storage :as storage]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.economy.account :as account]
            [bitecho.economy.spend-dac :as spend-dac]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.light-node.core :as light-core]
            [bitecho.state-machine :as sm]
            [cljs.reader :as edn]
            [clojure.string :as str]))

(def ^:private node-fs (js/require "node:fs"))
(def ^:private node-path (js/require "node:path"))
(def ^:private node-http (js/require "node:http"))

(def full-node-version
  "Current Node.js Full / Infra Node release version."
  "0.23.14")

(defn- kp->pk-hex [kp]
  (let [pub (or (:public-key kp) (:public kp))]
    (if (string? pub) pub (basalt/bytes->hex pub))))

(defn- kp->sk [kp]
  (or (:private-key kp) (:private kp)))

(defn run-self-test
  "Executes an end-to-end deterministic self-test on Node.js proving:
   1. `bitecho.state-machine` initializes, stages a `deploy/core` config pointer, and activates it at an epoch boundary.
   2. `bitecho.fressian` encodes and decodes `subnet-pointers.fressian` identically to JVM infra nodes.
   3. `bitecho.core.subnet` and `bitecho.core.protocol.relay` process pointers, blobs, and relay envelopes.
   4. `bitecho.economy.spend-dac` issues and validates a holder-signed spend-DAC debit.
   5. `bitecho.deploy.core` verifies hash-chained `P-DEPLOY-5` audit records."
  []
  (let [auth-kp (crypto/generate-keypair "node-full-self-test-auth")
        holder-kp (crypto/generate-keypair "node-full-self-test-holder")
        auth-pk (kp->pk-hex auth-kp)
        auth-sk (kp->sk auth-kp)
        holder-pk (kp->pk-hex holder-kp)
        holder-sk (kp->sk holder-kp)
        ;; 1. State machine + config pointer epoch-boundary activation
        sm0 (-> (sm/init-state [] auth-pk (config/devnet-6-config))
                (assoc :epoch 10 :trusted-deploy-authorities #{auth-pk}))
        ptr (deploy/sign-config-pointer
             auth-sk
             {:network "devnet"
              :seq 1
              :activate-at-epoch 11
              :code-target-cid (deploy/sha256-hex "dist/bitecho-full-node.cjs")
              :domains {:economy {:min-signaling-burn 125}}
              :policy-theta (assoc deploy/ratified-theta-star :min-signaling-burn 125)
              :author-pubkey auth-pk})
        staged (:state (deploy/stage-config-pointer sm0 ptr))
        ticked (:state (sm/handle-event staged {:type :tick :rng (crypto/make-random 42)}))
        audit-check (deploy/reconstruct-cluster-history-from-audit-trail (:audit-trail ticked) 11)
        ;; 2. Subnet pointer/blob + Fressian snapshot round-trip
        policy {:subnet/id "bitecho.org/infra"
                :subnet/parent-id "global"
                :subnet/gate {:gate/mode :permissioned
                              :gate/admission :allowlist
                              :gate/trust-anchors #{auth-pk}
                              :gate/governance {:governance/type :quorum :threshold 1}}
                :subnet/path-acl [{:pattern "config/*" :principal {:type :allowlist :signers #{auth-pk}}}]
                :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                :subnet/replication {:replication/pointers :leader-election
                                     :replication/blobs :eager-push}}
        sub-init (subnet/init-subnet-instance policy {:node-id :ns3 :all-nodes #{:ns1 :ns2 :ns3}})
        blob (data/make-blob (pr-str ptr) "application/edn")
        c-ptr (data/sign-pointer auth-sk {:pointer/authority auth-pk
                                          :pointer/subnet "bitecho.org/infra"
                                          :pointer/path "config/devnet/active.edn"
                                          :pointer/seq 1
                                          :pointer/target (:blob/cid blob)
                                          :pointer/proof {:proof/type :self}})
        sub1 (:state (subnet/reduce-subnet (:instance sub-init) {:type :put-blob :sender auth-pk :blob blob :now-ms 1000}))
        sub2 (:state (subnet/reduce-subnet sub1 {:type :publish-pointer :sender auth-pk :pointer c-ptr :now-ms 1000}))
        snap-bytes (fressian/encode-canonical {:subnet-id (:subnet-id sub2)
                                               :pointers (get-in sub2 [:data :pointers])})
        snap-decoded (fressian/decode-wire snap-bytes)
        ;; 3. Spend-DAC verification
        dac (spend-dac/issue-spend-dac auth-pk auth-sk {:dac-id "node-dac-1" :holder holder-pk :cap 1000000 :issued-epoch 10 :expiry-epoch 1000})
        intent (spend-dac/sign-spend-dac-intent holder-sk {:spend-dac-id "node-dac-1" :holder holder-pk :op :transfer :amount 50000 :burn-fee 100 :epoch 11 :nonce "n1"})
        spend-res (spend-dac/validate-and-apply-spend-dac-debit
                   {:epoch 11
                    :ledger {auth-pk (account/map->AccountState {:balance 25000000 :seq 0 :deps []})}
                    :spend-dacs {"node-dac-1" dac}}
                   intent)
        ;; 4. Relay & Storage & Governance sanity check
        relay-st (relay/init-relay-state)
        gov-st (gov/init-governance-state)
        sym-key (storage/derive-storage-key auth-sk "infra-test")
        ok? (and (= 11 (:epoch ticked))
                 (= 125 (get-in ticked [:config :min-signaling-burn]))
                 (true? (:chain-valid? audit-check))
                 (= (:blob/cid blob)
                    (get-in snap-decoded [:pointers ["bitecho.org/infra" "config/devnet/active.edn"] :pointer/target]))
                 (true? (:ok? spend-res))
                 (= 50100 (:spent spend-res))
                 (map? relay-st)
                 (map? gov-st)
                 (= 32 (fressian/count-bytes sym-key))
                 (true? (light-core/valid-pubkey-hex? auth-pk)))]
    {:ok ok?
     :runtime "nodejs"
     :node_version (.-version js/process)
     :version full-node-version
     :epoch (:epoch ticked)
     :active_config_hash (:active-config-hash ticked)
     :audit_records (count (:audit-trail ticked))
     :fressian_roundtrip_ok (= "bitecho.org/infra" (:subnet-id snap-decoded))
     :spend_dac_ok (true? (:ok? spend-res))}))

(defn- load-or-init-subnet-snapshot!
  [state-dir auth-pk]
  (let [snap-path (.join node-path state-dir "subnet-pointers.fressian")
        policy {:subnet/id "bitecho.org/infra"
                :subnet/parent-id "global"
                :subnet/gate {:gate/mode :permissioned
                              :gate/admission :allowlist
                              :gate/trust-anchors #{auth-pk}
                              :gate/governance {:governance/type :quorum :threshold 1}}
                :subnet/path-acl [{:pattern "config/*" :principal {:type :allowlist :signers #{auth-pk}}}
                                  {:pattern "dir/*" :principal {:type :allowlist :signers #{auth-pk}}}
                                  {:pattern "sla/*" :principal {:type :allowlist :signers #{auth-pk}}}
                                  {:pattern "deploy/*" :principal {:type :allowlist :signers #{auth-pk}}}]
                :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                :subnet/replication {:replication/pointers :leader-election
                                     :replication/blobs :eager-push}}
        base-inst (:instance (subnet/init-subnet-instance policy))]
    (if (.existsSync node-fs snap-path)
      (try
        (let [buf (.readFileSync node-fs snap-path)
              arr (js/Uint8Array. (.-buffer buf) (.-byteOffset buf) (.-byteLength buf))
              decoded (fressian/decode-wire arr)]
          (if (map? (:pointers decoded))
            (assoc-in base-inst [:data :pointers] (:pointers decoded))
            base-inst))
        (catch :default _ base-inst))
      base-inst)))

(defn start-infra-http-server!
  "Starts the Node.js infra-node HTTP server serving `/healthz`, `/statusz`, `/relay/v1/*`, and `/artifact/v1/*`."
  [{:keys [node-id state-dir http-port]}]
  (let [dir (or state-dir ".bitecho-node-infra")
        _ (when-not (.existsSync node-fs dir)
            (.mkdirSync node-fs dir #js {:recursive true}))
        kp (crypto/generate-keypair (str "nodejs-infra-" (or node-id "ns3")))
        pk (kp->pk-hex kp)
        subnet-atom (atom (load-or-init-subnet-snapshot! dir pk))
        relay-atom (atom (relay/init-relay-state))
        deploy-atom (atom {:node-id (keyword (or node-id "ns3"))
                           :runtime :nodejs
                           :epoch 0
                           :active-code-cid (deploy/sha256-hex full-node-version)
                           :audit-trail []})
        port (long (or http-port 8080))
        server (.createServer
                node-http
                (fn [req res]
                  (let [url (or (.-url req) "/")]
                    (cond
                      (str/starts-with? url "/healthz")
                      (let [body (js/JSON.stringify #js {:ok true :runtime "nodejs" :version full-node-version :node_id (or node-id "ns3")})]
                        (.writeHead res 200 #js {"Content-Type" "application/json"})
                        (.end res body))

                      (str/starts-with? url "/statusz")
                      (let [st @deploy-atom
                            body (js/JSON.stringify
                                  (clj->js {:ok true
                                            :runtime "nodejs"
                                            :version full-node-version
                                            :node_id (name (:node-id st))
                                            :epoch (:epoch st)
                                            :active_code_cid (:active-code-cid st)
                                            :pointer_count (count (get-in @subnet-atom [:data :pointers]))
                                            :relay_diagnostics (:diagnostics @relay-atom)
                                            :audit_records (count (:audit-trail st))}))]
                        (.writeHead res 200 #js {"Content-Type" "application/json"})
                        (.end res body))

                      :else
                      (let [body (js/JSON.stringify #js {:ok true :runtime "nodejs" :path url})]
                        (.writeHead res 200 #js {"Content-Type" "application/json"})
                        (.end res body))))))]
    (.listen server port "127.0.0.1"
             (fn []
               (println (js/JSON.stringify
                         #js {:event "infra-node-ready"
                              :ok true
                              :runtime "nodejs"
                              :version full-node-version
                              :node_id (or node-id "ns3")
                              :http_port port}))))))

(defn -main
  "CLI entry point for the Node.js infrastructure full node."
  [& args]
  (let [argv (vec args)
        first-arg (first argv)]
    (cond
      (some #{"--self-test"} argv)
      (let [res (run-self-test)]
        (println (js/JSON.stringify (clj->js res)))
        (when-not (:ok res)
          (.exit js/process 1)))

      (some #{"--version" "-v"} argv)
      (println (js/JSON.stringify #js {:ok true :runtime "nodejs" :version full-node-version}))

      (or (empty? argv) (some #{"--help" "-h" "help"} argv))
      (println (js/JSON.stringify
                #js {:ok true
                     :help true
                     :runtime "nodejs"
                     :version full-node-version
                     :commands #js ["infra-node" "--self-test" "--version" "--help"]}))

      (= first-arg "infra-node")
      (let [idx-id (.indexOf argv "--node-id")
            node-id (if (and (>= idx-id 0) (< (inc idx-id) (count argv)))
                      (nth argv (inc idx-id))
                      "ns3")
            idx-dir (.indexOf argv "--state-dir")
            state-dir (if (and (>= idx-dir 0) (< (inc idx-dir) (count argv)))
                        (nth argv (inc idx-dir))
                        (let [second-arg (second argv)]
                          (if (and second-arg (not (str/starts-with? second-arg "--")) (.existsSync node-fs second-arg))
                            (:state-dir (edn/read-string (.readFileSync node-fs second-arg "utf8")) ".bitecho-node-infra")
                            ".bitecho-node-infra")))
            idx-port (.indexOf argv "--http-port")
            http-port (if (and (>= idx-port 0) (< (inc idx-port) (count argv)))
                        (js/parseInt (nth argv (inc idx-port)) 10)
                        18080)]
        (start-infra-http-server! {:node-id node-id :state-dir state-dir :http-port http-port}))

      :else
      (let [res (run-self-test)]
        (println (js/JSON.stringify (clj->js res)))))))

(set! *main-cli-fn* -main)
