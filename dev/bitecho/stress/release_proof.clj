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
            [bitecho.economy.account :as account]
            [bitecho.economy.escrow :as escrow]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint]))

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

(defn run-release-proof
  "Runs the complete Milestone D23 release verification proof and returns a deterministic EDN map."
  [_opts]
  (let [devnet-res (run-single-network-e2e :devnet)
        testnet-res (run-single-network-e2e :testnet)
        mainnet-res (run-single-network-e2e :mainnet)
        replay-res (run-cross-network-replay-matrix)
        rolling-res (run-rolling-upgrade-interop)
        all-passed? (boolean (and (:passed? devnet-res)
                                  (:passed? testnet-res)
                                  (:passed? mainnet-res)
                                  (:all-rejected? replay-res)
                                  (:passed? rolling-res)))]
    {:milestone "D23"
     :version "v0.23.0"
     :all-passed? all-passed?
     :networks {"devnet.bitecho.org" devnet-res
                "testnet.bitecho.org" testnet-res
                "mainnet.bitecho.org" mainnet-res}
     :cross-network-replay replay-res
     :rolling-upgrade rolling-res}))

(defn -main
  "CLI entrypoint generating the Milestone D23 release proof EDN artifact."
  [& args]
  (let [out-path (or (first args) "docs/releases/v0.23.0-proof.edn")
        proof (run-release-proof {})
        out-file (io/file out-path)]
    (when-let [parent (.getParentFile out-file)]
      (.mkdirs parent))
    (spit out-file (with-out-str (pprint/pprint proof)))
    (println (str "Wrote release proof to " out-path " (all-passed?=" (:all-passed? proof) ")"))
    (when-not (:all-passed? proof)
      (System/exit 1))))
