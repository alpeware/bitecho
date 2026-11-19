(ns bitecho.stress.release-proof
  "Milestone D23 Release Proof Harness (A-CARB-D23-4):
   1. Verifies E2E transfers, escrows, fractal subnet governance, and Streamlet BFT
      finalization across `devnet.bitecho.org`, `testnet.bitecho.org`, and `mainnet.bitecho.org`.
   2. Proves fail-closed cross-network replay rejection across all 6 ordered network pairs
      plus Mainnet strict unscoped-transfer rejection.
   3. Proves N (`:subnet-id \"global\"`) <-> N+1 (`:subnet-id \"devnet.bitecho.org\"`)
      rolling-upgrade interoperability."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.d24-remediation-scenarios-test :as d24-test]
            [bitecho.d25-remediation-scenarios-test :as d25-test]
            [bitecho.d26-remediation-scenarios-test :as d26-test]
            [bitecho.d27-publishing-and-remediation-test :as d27-test]
            [bitecho.d28-autosync-and-p2p-ack-hotfix-test :as d28-test]
            [bitecho.d30-artifact-publishing-scenarios-test :as d30-test]
            [bitecho.d31-unification-iii-scenarios-test :as d31-test]
            [bitecho.d32-bip006-onboarding-and-network-test :as d32-test]
            [bitecho.d33-bip007-low-latency-and-infra-test :as d33-test]
            [bitecho.e2e.d29-remediation-scenario-test :as d29-test]
            [bitecho.economy.account :as account]
            [bitecho.economy.escrow :as escrow]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [clojure.test :as t])
  (:import [java.nio.file Files]))

(defn- run-single-network-e2e
  [net-kw]
  (let [net-uri (config/resolve-network-uri net-kw)
        base-cfg (case net-kw
                   :devnet config/devnet-config
                   :testnet config/testnet-config
                   :mainnet config/mainnet-config)
        alice-kp (crypto/generate-keypair (str "d23-alice-" (name net-kw)))
        bob-kp (crypto/generate-keypair (str "d23-bob-" (name net-kw)))
        val1-kp (crypto/generate-keypair (str "d23-val1-" (name net-kw)))
        val2-kp (crypto/generate-keypair (str "d23-val2-" (name net-kw)))
        val3-kp (crypto/generate-keypair (str "d23-val3-" (name net-kw)))
        alice-pub (basalt/bytes->hex (:public alice-kp))
        bob-pub (basalt/bytes->hex (:public bob-kp))
        val1-pub (basalt/bytes->hex (:public val1-kp))
        val2-pub (basalt/bytes->hex (:public val2-kp))
        val3-pub (basalt/bytes->hex (:public val3-kp))
        validators (vec (sort [val1-pub val2-pub val3-pub]))
        peers-map {val1-pub (:public val1-kp)
                   val2-pub (:public val2-kp)
                   val3-pub (:public val3-kp)}
        kp-by-pub {val1-pub val1-kp
                   val2-pub val2-kp
                   val3-pub val3-kp}
        init-alice-bal 100000
        tx-amount 2500
        escrow-amount 4000
        cfg (assoc base-cfg
                   :subnet-id net-uri
                   :network net-kw
                   :network-uri net-uri
                   :validators validators
                   :peers-map peers-map
                   :keypair val1-kp
                   :genesis-ledger {alice-pub {:balance init-alice-bal :seq 0 :deps []}
                                    bob-pub {:balance 0 :seq 0 :deps []}
                                    val1-pub {:balance 500000 :seq 0 :deps []}
                                    val2-pub {:balance 500000 :seq 0 :deps []}
                                    val3-pub {:balance 500000 :seq 0 :deps []}})
        ;; 1. Consensus mode Streamlet BFT transfer & block finalization
        st0 (-> (sm/init-state [] val1-pub cfg)
                (assoc :validators validators
                       :peers-map peers-map
                       :keypair val1-kp))
        tx (account/create-transfer
            (:private alice-kp)
            {:sender alice-pub
             :receiver bob-pub
             :amount tx-amount
             :seq 1
             :deps []
             :network-uri net-uri})
        tx-bytes (fressian/encode-canonical {:transfer (into {} tx)})
        st1 (:state (sm/handle-event st0 {:type :on-deliver
                                          :subnet-id net-uri
                                          :payload tx-bytes
                                          :message-id (str "tx-1-" net-uri)
                                          :sender alice-pub}))
        ;; Drive 3 consecutive Streamlet epochs (1, 2, 3) to finalize epoch 1 & 2 blocks
        drive-epoch (fn [st ep]
                      (let [leader-pub (nth validators (mod ep (count validators)))
                            leader-kp (get kp-by-pub leader-pub)
                            parent-hash (:head-hash st)
                            txs (if (= ep 1) (vec (:pending-receipts st)) [])
                            signed-block (streamlet/sign-block
                                          (streamlet/->Block ep parent-hash txs leader-pub)
                                          (:private leader-kp))
                            b-hash (streamlet/hash-block signed-block)
                            st-prop (:state (sm/handle-event (assoc st :epoch ep)
                                                             {:type :receive-propose
                                                              :subnet-id net-uri
                                                              :sender leader-pub
                                                              :block signed-block}))]
                        (reduce (fn [acc-st v-pub]
                                  (let [v-kp (get kp-by-pub v-pub)
                                        v-sig (basalt/bytes->hex
                                               (crypto/sign (:private v-kp)
                                                            (fressian/utf8->bytes b-hash)))
                                        vote (streamlet/->Vote b-hash ep v-sig)]
                                    (:state (sm/handle-event acc-st
                                                             {:type :receive-vote
                                                              :subnet-id net-uri
                                                              :sender v-pub
                                                              :vote vote}))))
                                st-prop
                                validators)))
        st-bft (-> st1
                   (drive-epoch 1)
                   (drive-epoch 2)
                   (drive-epoch 3))
        bft-finalized? (and (pos? (count (:finalized-blocks st-bft)))
                            (= (- init-alice-bal tx-amount)
                               (get-in st-bft [:ledger alice-pub :balance]))
                            (= tx-amount
                               (get-in st-bft [:ledger bob-pub :balance])))
        ;; 2. Standalone escrow lock + release with network-URI-bound escrow-id
        st-esc0 (sm/init-state [] val1-pub (dissoc cfg :peers-map :validators))
        d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes (str "deliverable-" net-uri))))
        eid (escrow/compute-escrow-id alice-pub bob-pub escrow-amount d-hash 1 10 "1" net-uri)
        st-esc1 (:state (sm/handle-event st-esc0 {:type :lock-intent
                                                  :subnet-id net-uri
                                                  :network-uri net-uri
                                                  :escrow-id eid
                                                  :payer alice-pub
                                                  :receiver bob-pub
                                                  :amount escrow-amount
                                                  :deliverable-hash d-hash
                                                  :created-epoch 1
                                                  :expires-epoch 10
                                                  :sender alice-pub}))
        st-esc2 (:state (sm/handle-event st-esc1 {:type :release-intent
                                                  :subnet-id net-uri
                                                  :network-uri net-uri
                                                  :escrow-id eid
                                                  :preimage (str "deliverable-" net-uri)
                                                  :sender bob-pub}))
        expected-bps (long (:settlement-take-bps base-cfg))
        expected-take (quot (* escrow-amount expected-bps) 10000)
        expected-net (- escrow-amount expected-take)
        escrow-passed? (and (= :released (get-in st-esc2 [:escrows eid :status]))
                            (= expected-net (get-in st-esc2 [:ledger bob-pub :balance]))
                            (= (- init-alice-bal escrow-amount) (get-in st-esc2 [:ledger alice-pub :balance])))
        ;; 3. Fractal subnet governance & deterministic epoch activation on root network URI
        gov0 (-> (gov/init-governance-state)
                 (gov/register-circle-member net-uri :builders-stewards alice-pub {:verified-commits 25})
                 (gov/register-circle-member net-uri :mesh-validators val1-pub {:participation 1.0 :stake 500000})
                 (gov/register-circle-member net-uri :anchor-agent-users bob-pub {:trailing-burned-ech 5000}))
        bip-id (str "BIP-D23-" (name net-kw))
        sub-res (gov/submit-bip
                 gov0
                 {:subnet-id net-uri
                  :bip-id bip-id
                  :title (str "Release verification BIP on " net-uri)
                  :author-pubkey alice-pub
                  :activate-at-epoch 2
                  :policy-theta {:burn-floor (long (:burn-floor base-cfg))
                                 :settlement-take-bps expected-bps}
                  :invariant-diff {:defspec-vars ["prop-network-uri-and-root-subnet-equivalence"]
                                   :seed 23
                                   :sans-io-pure? true
                                   :diagnose-coverage? true
                                   :co-committed-spec-and-flags? true}
                  :oracle-receipts {:four-way-golden-oracle {:passed? true :seed 23}
                                    :vopr-jepsen-non-vacuity {:passed? true :seed 23}
                                    :deterministic-bundle-sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                    :bwrap-civilization-regression {:passed? true}}}
                 (:private alice-kp))
        gov1 (-> (:state sub-res)
                 (gov/submit-circle-response net-uri bip-id :builders-stewards alice-pub {:stance :consent})
                 :state
                 (gov/submit-circle-response net-uri bip-id :mesh-validators val1-pub {:stance :consent})
                 :state
                 (gov/submit-circle-response net-uri bip-id :anchor-agent-users bob-pub {:stance :consent})
                 :state)
        eval-res (gov/evaluate-tri-circle-consent gov1 net-uri bip-id)
        act-res (gov/activate-epoch-upgrades (:state eval-res) 2)
        gov-passed? (and (:ok? sub-res)
                         (:ratified? eval-res)
                         (= 1 (count (:activated act-res)))
                         (= expected-bps (get-in (:state act-res) [:subnet-policies net-uri :settlement-take-bps])))]
    {:network net-kw
     :network-uri net-uri
     :bft-finalized? bft-finalized?
     :finalized-blocks-count (count (:finalized-blocks st-bft))
     :escrow-passed? escrow-passed?
     :settlement-take-bps expected-bps
     :governance-passed? gov-passed?
     :passed? (boolean (and bft-finalized? escrow-passed? gov-passed?))}))

(defn- run-cross-network-replay-matrix
  []
  (let [nets [:devnet :testnet :mainnet]
        pairs (for [s nets, t nets :when (not= s t)] [s t])
        alice-kp (crypto/generate-keypair "d23-replay-alice")
        bob-kp (crypto/generate-keypair "d23-replay-bob")
        alice-pub (basalt/bytes->hex (:public alice-kp))
        bob-pub (basalt/bytes->hex (:public bob-kp))
        acct (account/map->AccountState {:balance 50000 :seq 0 :deps []})
        pair-results
        (mapv (fn [[source-net target-net]]
                (let [source-uri (config/resolve-network-uri source-net)
                      target-uri (config/resolve-network-uri target-net)
                      target-cfg (case target-net
                                   :devnet config/devnet-config
                                   :testnet config/testnet-config
                                   :mainnet config/mainnet-config)
                      tx (account/create-transfer
                          (:private alice-kp)
                          {:sender alice-pub
                           :receiver bob-pub
                           :amount 1000
                           :seq 1
                           :deps []
                           :network-uri source-uri})
                      st0 (sm/init-state [] alice-pub
                                         (assoc target-cfg
                                                :genesis-ledger {alice-pub acct
                                                                 bob-pub {:balance 0 :seq 0 :deps []}}))
                      payload-bytes (fressian/encode-canonical {:transfer (into {} tx)})
                      res-tx (sm/handle-event st0 {:type :on-deliver
                                                   :payload payload-bytes
                                                   :message-id "replay-tx"
                                                   :sender alice-pub})
                      d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "replay-escrow")))
                      res-esc (sm/handle-event st0 {:type :lock-intent
                                                    :payer alice-pub
                                                    :receiver bob-pub
                                                    :amount 1000
                                                    :deliverable-hash d-hash
                                                    :created-epoch 1
                                                    :expires-epoch 10
                                                    :network-uri source-uri
                                                    :sender alice-pub})
                      rejected? (and (account/validate-transfer acct tx {:network-uri source-uri})
                                     (not (account/validate-transfer acct tx {:network-uri target-uri}))
                                     (= 50000 (get-in (:state res-tx) [:ledger alice-pub :balance]))
                                     (= 1 (get-in (:state res-tx) [:diagnostics :network-replay-rejected]))
                                     (= 1 (get-in (:state res-esc) [:diagnostics :network-replay-rejected])))]
                  {:source source-uri
                   :target target-uri
                   :rejected? (boolean rejected?)}))
              pairs)
        unscoped-tx (account/create-transfer
                     (:private alice-kp)
                     {:sender alice-pub
                      :receiver bob-pub
                      :amount 1000
                      :seq 1
                      :deps []})
        mainnet-unscoped-rejected? (not (account/validate-transfer
                                         acct unscoped-tx
                                         {:network-uri "mainnet.bitecho.org"
                                          :strict-network-uri? true}))
        devnet-unscoped-accepted? (boolean (account/validate-transfer
                                            acct unscoped-tx
                                            {:network-uri "devnet.bitecho.org"
                                             :strict-network-uri? false}))]
    {:pairs pair-results
     :mainnet-unscoped-rejected? mainnet-unscoped-rejected?
     :devnet-unscoped-accepted? devnet-unscoped-accepted?
     :all-rejected? (boolean (and (every? :rejected? pair-results)
                                  mainnet-unscoped-rejected?
                                  devnet-unscoped-accepted?))}))

(defn- run-rolling-upgrade-interop
  []
  (let [alice-kp (crypto/generate-keypair "d23-rolling-alice")
        bob-kp (crypto/generate-keypair "d23-rolling-bob")
        alice-pub (basalt/bytes->hex (:public alice-kp))
        bob-pub (basalt/bytes->hex (:public bob-kp))
        ledger {alice-pub {:balance 50000 :seq 0 :deps []}
                bob-pub {:balance 0 :seq 0 :deps []}}
        ;; Node N uses legacy :subnet-id "global", Node N+1 uses :subnet-id "devnet.bitecho.org"
        node-n (sm/init-state [] alice-pub (assoc config/devnet-config
                                                  :subnet-id "global"
                                                  :genesis-ledger ledger))
        node-n-plus-1 (sm/init-state [] bob-pub (assoc config/devnet-config
                                                       :subnet-id "devnet.bitecho.org"
                                                       :genesis-ledger ledger))
        tx (account/create-transfer
            (:private alice-kp)
            {:sender alice-pub
             :receiver bob-pub
             :amount 1500
             :seq 1
             :deps []
             :network-uri "devnet.bitecho.org"})
        payload-bytes (fressian/encode-canonical {:transfer (into {} tx)})
        ;; N+1 event ("devnet.bitecho.org") delivered to Node N ("global")
        res-n (sm/handle-event node-n {:type :on-deliver
                                       :subnet-id "devnet.bitecho.org"
                                       :payload payload-bytes
                                       :message-id "rolling-1"
                                       :sender alice-pub})
        ;; N event ("global") delivered to Node N+1 ("devnet.bitecho.org")
        res-n1 (sm/handle-event node-n-plus-1 {:type :on-deliver
                                               :subnet-id "global"
                                               :payload payload-bytes
                                               :message-id "rolling-1"
                                               :sender alice-pub})
        ;; Foreign network ("testnet.bitecho.org") delivered to Node N+1 ("devnet.bitecho.org")
        res-foreign (sm/handle-event node-n-plus-1 {:type :on-deliver
                                                    :subnet-id "testnet.bitecho.org"
                                                    :payload payload-bytes
                                                    :message-id "rolling-foreign"
                                                    :sender alice-pub})
        passed? (and (= 1500 (get-in (:state res-n) [:ledger bob-pub :balance]))
                     (zero? (get-in (:state res-n) [:diagnostics :subnet-mismatch-dropped] 0))
                     (= 1500 (get-in (:state res-n1) [:ledger bob-pub :balance]))
                     (zero? (get-in (:state res-n1) [:diagnostics :subnet-mismatch-dropped] 0))
                     (= 1 (get-in (:state res-foreign) [:diagnostics :subnet-mismatch-dropped] 0)))]
    {:node-n-subnet "global"
     :node-n-plus-1-subnet "devnet.bitecho.org"
     :n-accepted-n1-event? (= 1500 (get-in (:state res-n) [:ledger bob-pub :balance]))
     :n1-accepted-n-event? (= 1500 (get-in (:state res-n1) [:ledger bob-pub :balance]))
     :foreign-subnet-dropped? (= 1 (get-in (:state res-foreign) [:diagnostics :subnet-mismatch-dropped] 0))
     :passed? (boolean passed?)}))

(defn run-d24-scenarios
  "Executes Milestone D24 remediation and scenario verification suite (S1-S8)."
  []
  (let [scenarios [{:id "S1" :name "p2p-answer-candidate-fallback-and-persistence" :test-fn d24-test/test-scenario-s1-p2p-answer-candidate-fallback-and-persistence}
                   {:id "S2" :name "port-443-passthrough-and-signatures" :test-fn d24-test/test-scenario-s2-port-443-passthrough-and-signatures}
                   {:id "S3" :name "cross-subnet-relay-and-early-sealed-buffering" :test-fn d24-test/test-scenario-s3-cross-subnet-relay-and-early-sealed-buffering}
                   {:id "S4" :name "now-ms-injection-and-offline-shuttle" :test-fn d24-test/test-scenario-s4-now-ms-injection-and-offline-shuttle}
                   {:id "S5" :name "replication-auth-and-ctl-concurrency" :test-fn d24-test/test-scenario-s5-replication-auth-and-ctl-concurrency}
                   {:id "S6" :name "single-responder-and-newline-discipline" :test-fn d24-test/test-scenario-s6-single-responder-and-newline-discipline}
                   {:id "S7" :name "jepsen-and-datachannel-campaigns" :test-fn d24-test/test-scenario-s7-jepsen-and-datachannel-campaigns}
                   {:id "S8" :name "node-bundle-relay-send-and-failover" :test-fn d24-test/test-scenario-s8-node-bundle-relay-send-and-failover}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn run-d25-scenarios
  "Executes Milestone D25 remediation and scenario verification suite (S9-S15)."
  []
  (let [scenarios [{:id "S9" :name "handle-serve-line-state-commit-and-sequential-p2p-dial" :test-fn d25-test/test-scenario-s9-handle-serve-line-state-commit-and-sequential-p2p-dial}
                   {:id "S10" :name "relay-poll-ingest-ordering-and-no-poll-escape-hatch" :test-fn d25-test/test-scenario-s10-relay-poll-ingest-ordering-and-no-poll-escape-hatch}
                   {:id "S11" :name "stateless-offer-handshake-continuity-and-nonce-recovery" :test-fn d25-test/test-scenario-s11-stateless-offer-handshake-continuity-and-nonce-recovery}
                   {:id "S12" :name "inbox-peek-and-dual-key-broadcast-normalization" :test-fn d25-test/test-scenario-s12-inbox-peek-and-dual-key-broadcast-normalization}
                   {:id "S13" :name "subnet-filtering-relay-poll-and-wire-payload" :test-fn d25-test/test-scenario-s13-subnet-filtering-relay-poll-and-wire-payload}
                   {:id "S14" :name "flag-before-verb-parsing-and-help-isolation" :test-fn d25-test/test-scenario-s14-flag-before-verb-parsing-and-help-isolation}
                   {:id "S15" :name "upnp-renewal-loop-lifecycle" :test-fn d25-test/test-scenario-s15-upnp-renewal-loop-lifecycle}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn run-d26-scenarios
  "Executes Milestone D26 remediation and scenario verification suite (S16-S24)."
  []
  (let [scenarios [{:id "S16" :name "accountz-fallback-removal-and-fail-closed" :test-fn d26-test/test-scenario-s16-accountz-fallback-removal-and-fail-closed}
                   {:id "S17" :name "second-p2p-answer-preserves-open-state" :test-fn d26-test/test-scenario-s17-second-p2p-answer-preserves-open-state}
                   {:id "S18" :name "offer-hash-network-binding-and-rolling-upgrade" :test-fn d26-test/test-scenario-s18-offer-hash-network-binding-and-rolling-upgrade}
                   {:id "S19" :name "bip-000-charter-and-strict-admission" :test-fn d26-test/test-scenario-s19-bip-000-charter-and-strict-admission}
                   {:id "S20" :name "release-proof-generator-and-deploy-gate" :test-fn d26-test/test-scenario-s20-release-proof-generator-and-deploy-gate}
                   {:id "S21" :name "multi-cluster-network-profiles" :test-fn d26-test/test-scenario-s21-multi-cluster-network-profiles}
                   {:id "S22" :name "wait-event-broadcast-and-min-balance-guard" :test-fn d26-test/test-scenario-s22-wait-event-broadcast-and-min-balance-guard}
                   {:id "S23" :name "treasury-faucet-directory-and-blog" :test-fn d26-test/test-scenario-s23-treasury-faucet-directory-and-blog}
                   {:id "S24" :name "sea-build-script-and-skill-regrounding" :test-fn d26-test/test-scenario-s24-sea-build-script-and-skill-regrounding}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn run-d27-scenarios
  "Runs Milestone D27 (v0.23.5) remediation & scenario verification suite."
  []
  (let [scenarios [{:id "D27-1" :name "quorum-5-of-6-supermajority" :test-fn d27-test/test-f-d27-7-quorum-5-of-6-supermajority}
                   {:id "D27-2" :name "credited-tx-ids-hydration" :test-fn d27-test/test-f-d27-8-credited-tx-ids-hydration-prevents-double-credit}
                   {:id "D27-3" :name "network-uri-and-replay-equivalence" :test-fn d27-test/test-f-d27-12-network-uri-and-replay-equivalence}
                   {:id "D27-4" :name "recipient-first-unicast-filter" :test-fn d27-test/test-f-d27-12-recipient-first-unicast-filter-before-epoch-skew}
                   {:id "D27-5" :name "contagion-summary-pull-known-burn-mids" :test-fn d27-test/test-f-d27-13-contagion-summary-pull-known-burn-mids}
                   {:id "D27-6" :name "p2p-half-open-redial" :test-fn d27-test/test-p2p-half-open-redial-on-incoming-offer}
                   {:id "D27-7" :name "exec-status-auto-sync-diagnostics" :test-fn d27-test/test-exec-status-auto-sync-diagnostics}
                   {:id "D27-8" :name "http-subnet-publishing" :test-fn d27-test/test-http-subnet-publishing-bip-releases-and-blog}
                   {:id "D27-9" :name "version-and-cold-root-pins" :test-fn d27-test/test-d27-version-and-cold-root-pins}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn run-d28-scenarios
  "Runs Milestone D28 (v0.23.6) auto-sync, zombie gossip, & direct-leg ack hotfix verification suite."
  []
  (let [scenarios [{:id "D28-1" :name "preserve-dynamic-validators-across-restarts" :test-fn d28-test/test-f-d28-1-preserve-dynamic-validators-across-restarts}
                   {:id "D28-2" :name "three-node-lagging-peer-zombie-gossip-e2e" :test-fn d28-test/test-f-d28-2-three-node-lagging-peer-zombie-gossip-e2e}
                   {:id "D28-3" :name "lock-free-query-chain-state-and-no-empty-signing" :test-fn d28-test/test-f-d28-3-lock-free-query-chain-state-and-no-empty-signing}
                   {:id "D28-4" :name "direct-leg-session-ack-and-outbox-fallback" :test-fn d28-test/test-f-d28-4-direct-leg-session-ack-and-outbox-fallback}
                   {:id "D28-5" :name "relay-watermark-reset-on-restart" :test-fn d28-test/test-f-d28-4-relay-watermark-reset-on-restart}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn run-d29-scenarios
  "Runs Milestone D29 (v0.23.7 / BIP-003) overnight campaign remediation scenario suite."
  []
  (let [scenarios [{:id "D29-1" :name "receipt-epoch-horizon-and-gossiped-sig-auth" :test-fn d29-test/scenario-1-receipt-epoch-horizon-and-gossiped-sig-auth}
                   {:id "D29-2" :name "on-chain-bounty-escrow-lifecycle-survives-autosync" :test-fn d29-test/scenario-2-on-chain-bounty-escrow-lifecycle-survives-autosync}
                   {:id "D29-3" :name "validator-anon-query-reap-and-quorum-sync-under-flood" :test-fn d29-test/scenario-3-validator-anon-query-reap-and-quorum-sync-under-flood}
                   {:id "D29-4" :name "bounded-p2p-reoffer-backoff-and-peer-silence-watch" :test-fn d29-test/scenario-4-bounded-p2p-reoffer-backoff-and-peer-silence-watch}
                   {:id "D29-5" :name "strict-network-uri-accept-and-https-relay-p2p-candidate" :test-fn d29-test/scenario-5-strict-network-uri-accept-and-https-relay-p2p-candidate}
                   {:id "D29-6" :name "http-dist-bundle-sea-and-sha256-bridge" :test-fn d29-test/scenario-6-http-dist-bundle-sea-and-sha256-bridge}
                   {:id "D29-7" :name "relay-poll-subnet-filter-and-no-default-private-chat" :test-fn d29-test/scenario-7-relay-poll-subnet-filter-and-no-default-private-chat}
                   {:id "D29-8" :name "ctl-wait-block-honors-timeout-and-cursor" :test-fn d29-test/scenario-8-ctl-wait-block-honors-timeout-and-cursor}
                   {:id "D29-9" :name "cli-flag-parity-bip-submit-transfer-to-and-bounty-bip-cid" :test-fn d29-test/scenario-9-cli-flag-parity-bip-submit-transfer-to-and-bounty-bip-cid}
                   {:id "D29-10" :name "ops-build-and-release-hygiene-invariants" :test-fn d29-test/scenario-10-ops-build-and-release-hygiene-invariants}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn run-d30-scenarios
  "Runs Milestone D30 (v0.23.8 / BIP-004) on-network artifact publishing & HTTPS P2P scenario suite."
  []
  (let [scenarios [{:id "S-D30-1" :name "live-pointer-first-dist-cutover-and-artifact-verbs" :test-fn d30-test/scenario-s-d30-1-live-pointer-first-dist-cutover-and-artifact-verbs}
                   {:id "S-D30-2" :name "first-match-path-acl-stream-isolation" :test-fn d30-test/scenario-s-d30-2-first-match-path-acl-stream-isolation}
                   {:id "S-D30-3" :name "tombstone-and-denied-cids-hard-404" :test-fn d30-test/scenario-s-d30-3-tombstone-and-denied-cids-hard-404}
                   {:id "S-D30-4" :name "mid-fetch-range-immutability-across-pointer-advance" :test-fn d30-test/scenario-s-d30-4-mid-fetch-range-immutability-across-pointer-advance}
                   {:id "S-D30-5" :name "three-node-https-relay-p2p-broadcast-and-import-poll" :test-fn d30-test/scenario-s-d30-5-three-node-https-relay-p2p-broadcast-and-import-poll}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn run-d31-scenarios
  "Runs Milestone D31 (v0.23.9 / BIP-005: Unification III) scenario suite."
  []
  (let [scenarios [{:id "S-D31-1" :name "full-topology-five-leg-routing-and-mobility" :test-fn d31-test/scenario-s-d31-1-full-topology-five-leg-routing-and-mobility}
                   {:id "S-D31-2" :name "sync-pointer-convergence-and-rolling-interop" :test-fn d31-test/scenario-s-d31-2-sync-pointer-convergence-and-rolling-interop}
                   {:id "S-D31-3" :name "three-of-three-bounty-puzzle-vs-legacy-ledger" :test-fn d31-test/scenario-s-d31-3-three-of-three-bounty-puzzle-vs-legacy-ledger}
                   {:id "S-D31-4" :name "pointer-backed-tri-circle-governance-and-policy-upgrade-merge" :test-fn d31-test/scenario-s-d31-4-pointer-backed-tri-circle-governance-and-policy-upgrade-merge}
                   {:id "S-D31-5" :name "cli-desugaring-advanced-bundle-put-and-broadcast-drop" :test-fn d31-test/scenario-s-d31-5-cli-desugaring-advanced-bundle-put-and-broadcast-drop}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn- run-d32-scenarios
  "Executes the 5 Milestone D32 (BIP-006 / v0.23.10) onboarding and core network reliability scenarios (S-D32-1..S-D32-5)."
  []
  (let [scenarios [{:id "S-D32-1" :name "p2p-relay-recovery-and-actionable-events" :test-fn d32-test/scenario-s-d32-1-p2p-relay-recovery-and-actionable-events-test}
                   {:id "S-D32-2" :name "colocated-validator-sync-and-relay-mesh-bridge" :test-fn d32-test/scenario-s-d32-2-colocated-validator-sync-and-relay-mesh-bridge-test}
                   {:id "S-D32-3" :name "bitecho-mcp-stdio-server-e2e" :test-fn d32-test/scenario-s-d32-3-bitecho-mcp-stdio-server-e2e-test}
                   {:id "S-D32-4" :name "hardware-key-sponsored-faucet-http-e2e" :test-fn d32-test/scenario-s-d32-4-hardware-key-sponsored-faucet-http-e2e-test}
                   {:id "S-D32-5" :name "browser-app-refresh-governance-broadcast-and-faucet" :test-fn d32-test/scenario-s-d32-5-browser-app-refresh-governance-broadcast-and-faucet-test}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn- run-d33-scenarios
  "Executes the 5 Milestone D33 (BIP-007 / v0.23.11) low-latency quorum sync, zero-burn HTTPS relay legs & infra scenarios (S-D33-1..S-D33-5)."
  []
  (let [scenarios [{:id "S-D33-1" :name "fast-local-only-and-http-quorum-chain-state" :test-fn d33-test/scenario-s-d33-1-fast-local-only-and-http-quorum-chain-state-test}
                   {:id "S-D33-2" :name "zero-burn-https-relay-p2p-leg-e2e" :test-fn d33-test/scenario-s-d33-2-zero-burn-https-relay-p2p-leg-e2e-test}
                   {:id "S-D33-3" :name "canonical-put-relay-upload-and-idempotent-pointer" :test-fn d33-test/scenario-s-d33-3-canonical-put-relay-upload-and-idempotent-pointer-test}
                   {:id "S-D33-4" :name "light-node-https-relay-first-quorum-sync" :test-fn d33-test/scenario-s-d33-4-light-node-https-relay-first-quorum-sync-test}
                   {:id "S-D33-5" :name "ops-scripts-batchmode-rollback-and-sha256" :test-fn d33-test/scenario-s-d33-5-ops-scripts-batchmode-rollback-and-sha256-test}]
        results (mapv (fn [{:keys [id name test-fn]}]
                        (let [pass? (try
                                      (binding [t/*report-counters* (ref t/*initial-report-counters*)]
                                        (test-fn)
                                        (zero? (+ (:fail @t/*report-counters* 0)
                                                  (:error @t/*report-counters* 0))))
                                      (catch Exception _ false))]
                          {:scenario id
                           :name name
                           :passed? pass?}))
                      scenarios)]
    {:all-passed? (every? true? (map :passed? results))
     :count (count results)
     :scenarios results}))

(defn run-release-proof
  "Runs the complete Milestone D33 (v0.23.11) release verification proof and returns a deterministic EDN map."
  [opts]
  (let [ver (or (:version opts) (str "v" config/version))
        ms (or (:milestone opts) "D33")
        devnet-res (run-single-network-e2e :devnet)
        testnet-res (run-single-network-e2e :testnet)
        mainnet-res (run-single-network-e2e :mainnet)
        replay-res (run-cross-network-replay-matrix)
        rolling-res (run-rolling-upgrade-interop)
        d24-scenarios (run-d24-scenarios)
        d25-scenarios (run-d25-scenarios)
        d26-scenarios (run-d26-scenarios)
        d27-scenarios (run-d27-scenarios)
        d28-scenarios (run-d28-scenarios)
        d29-scenarios (run-d29-scenarios)
        d30-scenarios (run-d30-scenarios)
        d31-scenarios (run-d31-scenarios)
        d32-scenarios (run-d32-scenarios)
        d33-scenarios (run-d33-scenarios)
        bundle-file (io/file "dist/bitecho-light-node.cjs")
        _ (assert (and (.exists bundle-file) (pos? (.length bundle-file)))
                  "dist/bitecho-light-node.cjs must exist and be non-empty before release proof generation!")
        bundle-sha (basalt/bytes->hex (crypto/sha256 (Files/readAllBytes (.toPath bundle-file))))
        browser-file (io/file "dist/bitecho-browser.js")
        _ (assert (and (.exists browser-file) (pos? (.length browser-file)))
                  "dist/bitecho-browser.js must exist and be non-empty before release proof generation!")
        browser-sha (basalt/bytes->hex (crypto/sha256 (Files/readAllBytes (.toPath browser-file))))
        commit-sha (try (str/trim (slurp (io/file ".git/refs/heads/main"))) (catch Exception _ "uncommitted"))
        tree-sha (try (str/trim (:out (sh/sh "git" "write-tree"))) (catch Exception _ nil))
        all-passed? (boolean (and (:passed? devnet-res)
                                  (:passed? testnet-res)
                                  (:passed? mainnet-res)
                                  (:all-rejected? replay-res)
                                  (:passed? rolling-res)
                                  (:all-passed? d24-scenarios)
                                  (:all-passed? d25-scenarios)
                                  (:all-passed? d26-scenarios)
                                  (:all-passed? d27-scenarios)
                                  (:all-passed? d28-scenarios)
                                  (:all-passed? d29-scenarios)
                                  (:all-passed? d30-scenarios)
                                  (:all-passed? d31-scenarios)
                                  (:all-passed? d32-scenarios)
                                  (:all-passed? d33-scenarios)))]
    {:milestone ms
     :version ver
     :all-passed? all-passed?
     :commit-sha commit-sha
     :tree-sha tree-sha
     :node-bundle-sha256 bundle-sha
     :browser-bundle-sha256 browser-sha
     :test-namespaces ["bitecho.d24-remediation-scenarios-test"
                       "bitecho.d25-remediation-scenarios-test"
                       "bitecho.d26-remediation-scenarios-test"
                       "bitecho.d27-publishing-and-remediation-test"
                       "bitecho.d28-autosync-and-p2p-ack-hotfix-test"
                       "bitecho.e2e.d29-remediation-scenario-test"
                       "bitecho.d30-artifact-publishing-scenarios-test"
                       "bitecho.d31-unification-iii-scenarios-test"
                       "bitecho.d32-bip006-onboarding-and-network-test"
                       "bitecho.d33-bip007-low-latency-and-infra-test"
                       "bitecho.state-machine-test"]
     :d24-remediation-scenarios d24-scenarios
     :d25-remediation-scenarios d25-scenarios
     :d26-remediation-scenarios d26-scenarios
     :d27-remediation-scenarios d27-scenarios
     :d28-remediation-scenarios d28-scenarios
     :d29-remediation-scenarios d29-scenarios
     :d30-artifact-publishing-scenarios d30-scenarios
     :d31-unification-iii-scenarios d31-scenarios
     :d32-bip006-onboarding-and-network-scenarios d32-scenarios
     :d33-bip007-low-latency-and-infra-scenarios d33-scenarios
     :networks {"devnet.bitecho.org" devnet-res
                "testnet.bitecho.org" testnet-res
                "mainnet.bitecho.org" mainnet-res}
     :cross-network-replay replay-res
     :rolling-upgrade rolling-res}))

(defn -main
  "CLI entrypoint generating the Milestone D28 release proof EDN artifact."
  [& args]
  (let [out-path (or (first args) (str "docs/releases/v" config/version "-proof.edn"))
        proof (run-release-proof {})
        out-file (io/file out-path)]
    (when-let [parent (.getParentFile out-file)]
      (.mkdirs parent))
    (spit out-file (with-out-str (pprint/pprint proof)))
    (println (str "Wrote release proof to " out-path " (all-passed?=" (:all-passed? proof) ")"))
    (shutdown-agents)
    (System/exit (if (:all-passed? proof) 0 1))))
