(ns bitecho.stress.release-proof-test
  "Generative and E2E tests for Milestone D23:
   - Network URI separation (devnet.bitecho.org, testnet.bitecho.org, mainnet.bitecho.org)
   - Root subnet equivalence & rolling-upgrade compatibility (N 'global' <-> N+1 'devnet.bitecho.org')
   - Cross-network transfer & escrow replay protection (A-D23-1, A-D23-2, A-CARB-D23-1, A-CARB-D23-2)
   - Mainnet hot :custody-privkey config rejection (A-D23-4)
   - Full in-memory release proof suite (A-CARB-D23-4)"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.escrow :as escrow]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.mesh :as mesh]
            [bitecho.state-machine :as sm]
            [bitecho.stress.release-proof :as release-proof]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def ^:private gen-network-kw
  (gen/elements [:devnet :testnet :mainnet]))

(def ^:private gen-distinct-network-pair
  (gen/such-that (fn [[n1 n2]] (not= n1 n2))
                 (gen/tuple gen-network-kw gen-network-kw)))

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec prop-network-uri-and-root-subnet-equivalence 50
  (prop/for-all [[net1 net2] gen-distinct-network-pair
                 child-subnet (gen/elements ["new-alexandria" "bitecho-dev" "homebrew-cafe" "chat/agents"])]
                (let [uri1 (config/resolve-network-uri net1)
                      uri2 (config/resolve-network-uri net2)]
                  (and (string? uri1)
                       (string? uri2)
                       (not= uri1 uri2)
                       (config/root-subnet-id? uri1)
                       (config/root-subnet-id? uri2)
                       (config/root-subnet-id? "global")
                       (config/root-subnet-id? "bitecho.org")
                       (config/root-subnet-id? "validator-core")
                       (not (config/root-subnet-id? child-subnet))
                       ;; Distinct explicit network URIs are NEVER equivalent
                       (not (config/equivalent-subnet-id? uri1 uri2 uri1))
                       (not (config/equivalent-subnet-id? uri1 uri2 uri2))
                       ;; "global" is equivalent to the active network's root URI
                       (config/equivalent-subnet-id? "global" uri1 uri1)
                       (config/equivalent-subnet-id? uri1 "global" uri1)
                       ;; Wildcard "*" matches any subnet
                       (config/equivalent-subnet-id? "*" uri1 uri1)
                       (config/equivalent-subnet-id? uri1 "*" uri1)
                       ;; Child subnet is only equivalent to itself or "*"
                       (config/equivalent-subnet-id? child-subnet child-subnet uri1)
                       (not (config/equivalent-subnet-id? child-subnet uri1 uri1))
                       (not (config/equivalent-subnet-id? child-subnet "global" uri1))))))

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec prop-cross-network-transfer-replay-protection 50
  (prop/for-all [[source-net target-net] gen-distinct-network-pair
                 amount (gen/choose 10 5000)
                 init-extra (gen/choose 1000 10000)]
                (let [source-uri (config/resolve-network-uri source-net)
                      target-uri (config/resolve-network-uri target-net)
                      alice-kp (crypto/generate-keypair)
                      bob-kp (crypto/generate-keypair)
                      alice-pub (basalt/bytes->hex (:public alice-kp))
                      alice-priv (:private alice-kp)
                      bob-pub (basalt/bytes->hex (:public bob-kp))
                      init-bal (+ amount init-extra)
                      acct (account/map->AccountState {:balance init-bal :seq 0 :deps []})
                      ;; Scoped transfer for source-uri
                      scoped-tx (account/create-transfer
                                 alice-priv
                                 {:sender alice-pub
                                  :receiver bob-pub
                                  :amount amount
                                  :seq 1
                                  :deps []
                                  :network-uri source-uri})
                      ;; Unscoped legacy transfer
                      unscoped-tx (account/create-transfer
                                   alice-priv
                                   {:sender alice-pub
                                    :receiver bob-pub
                                    :amount amount
                                    :seq 1
                                    :deps []})
                      ;; Target state machine configured for target-net
                      target-cfg (case target-net
                                   :devnet config/devnet-config
                                   :testnet config/testnet-config
                                   :mainnet config/mainnet-config)
                      st0 (sm/init-state [] alice-pub
                                         (assoc target-cfg
                                                :genesis-ledger {alice-pub acct
                                                                 bob-pub {:balance 0 :seq 0 :deps []}}))
                      payload-bytes (fressian/encode-canonical {:transfer (into {} scoped-tx)})
                      res-deliver (sm/handle-event st0 {:type :on-deliver
                                                        :payload payload-bytes
                                                        :message-id "replay-tx-1"
                                                        :sender alice-pub})]
                  (and ;; Valid on source network
                   (account/validate-transfer acct scoped-tx {:network-uri source-uri})
                       ;; Rejected on target network
                   (not (account/validate-transfer acct scoped-tx {:network-uri target-uri}))
                       ;; Unscoped transfer rejected on Mainnet (strict), accepted on Devnet/Testnet
                   (not (account/validate-transfer acct unscoped-tx {:network-uri "mainnet.bitecho.org"
                                                                     :strict-network-uri? true}))
                   (account/validate-transfer acct unscoped-tx {:network-uri "devnet.bitecho.org"
                                                                :strict-network-uri? false})
                       ;; State machine rejects foreign replay and increments :network-replay-rejected
                   (= init-bal (get-in (:state res-deliver) [:ledger alice-pub :balance]))
                   (zero? (get-in (:state res-deliver) [:ledger bob-pub :balance]))
                   (pos? (get-in (:state res-deliver) [:diagnostics :network-replay-rejected] 0))
                   (some #(= :network-replay-rejected (:reason %)) (:commands res-deliver))))))

#_{:clj-kondo/ignore [:missing-docstring]}
(defspec prop-cross-network-escrow-replay-protection 40
  (prop/for-all [[source-net target-net] gen-distinct-network-pair
                 amount (gen/choose 50 2000)]
                (let [source-uri (config/resolve-network-uri source-net)
                      target-uri (config/resolve-network-uri target-net)
                      alice-kp (crypto/generate-keypair)
                      bob-kp (crypto/generate-keypair)
                      alice-pub (basalt/bytes->hex (:public alice-kp))
                      bob-pub (basalt/bytes->hex (:public bob-kp))
                      d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "deliverable-payload")))
                      eid-source (escrow/compute-escrow-id alice-pub bob-pub amount d-hash 1 10 "1" source-uri)
                      eid-target (escrow/compute-escrow-id alice-pub bob-pub amount d-hash 1 10 "1" target-uri)
                      target-cfg (case target-net
                                   :devnet config/devnet-config
                                   :testnet config/testnet-config
                                   :mainnet config/mainnet-config)
                      st0 (sm/init-state [] alice-pub
                                         (assoc target-cfg
                                                :genesis-ledger {alice-pub {:balance 100000 :seq 0 :deps []}
                                                                 bob-pub {:balance 0 :seq 0 :deps []}}))
                      res-lock (sm/handle-event st0 {:type :lock-intent
                                                     :payer alice-pub
                                                     :receiver bob-pub
                                                     :amount amount
                                                     :deliverable-hash d-hash
                                                     :created-epoch 1
                                                     :expires-epoch 10
                                                     :network-uri source-uri
                                                     :sender alice-pub})]
                  (and (string? eid-source)
                       (string? eid-target)
                       (not= eid-source eid-target)
                       (empty? (get-in (:state res-lock) [:escrows]))
                       (= 100000 (get-in (:state res-lock) [:ledger alice-pub :balance]))
                       (= 1 (get-in (:state res-lock) [:diagnostics :network-replay-rejected]))
                       (some #(= :network-replay-rejected (:reason %)) (:commands res-lock))))))

(deftest test-root-subnet-policy-validation-and-light-node-replay
  (testing "Root subnet policies validate without requiring :subnet/parent-id across devnet/testnet/mainnet URIs"
    (doseq [root-id ["devnet.bitecho.org" "testnet.bitecho.org" "mainnet.bitecho.org" "bitecho.org" "global"]]
      (let [policy {:subnet/id root-id
                    :subnet/gate {:gate/mode :permissionless :gate/admission :open}
                    :subnet/economy {:economy/mode :full-settlement :economy/burn-floor 50}
                    :subnet/replication {:replication/pointers :gossip-crdt
                                         :replication/blobs :eager-push}}
            res (subnet/validate-subnet-policy policy)]
        (is (:ok? res) (str "Expected root subnet policy to be valid for " root-id)))))

  (testing "Light node rejects wire transfers carrying foreign :network-uri"
    (let [alice-kp (crypto/generate-keypair)
          bob-kp (crypto/generate-keypair)
          alice-pub (basalt/bytes->hex (:public alice-kp))
          alice-priv (:private alice-kp)
          bob-pub (basalt/bytes->hex (:public bob-kp))
          bob-st (light-core/init-light-state {:pubkey-hex bob-pub}
                                              {:network-uri "devnet.bitecho.org"
                                               :subnet-id "devnet.bitecho.org"})
          foreign-tx (account/create-transfer
                      alice-priv
                      {:sender alice-pub
                       :receiver bob-pub
                       :amount 500
                       :seq 1
                       :deps []
                       :network-uri "testnet.bitecho.org"})
          res (light-core/handle-wire-payload bob-st {:type :transfer :transfer (into {} foreign-tx)} (:private bob-kp))]
      (is (= 1 (get-in (:state res) [:diagnostics :network-replay-rejected])))
      (is (zero? (long (or (get-in (:state res) [:account :balance]) 0)))))))

(deftest test-mainnet-hot-custody-privkey-rejected
  (testing "A-D23-4: validate-node-config rejects hot :custody-privkey on Mainnet"
    (let [kp (crypto/generate-keypair)
          priv-hex (basalt/bytes->hex (:private kp))
          mainnet-cfg {:node/id :node1
                       :state-dir "/tmp/bitecho-d23-test"
                       :network :mainnet
                       :custody-privkey priv-hex}
          devnet-cfg {:node/id :node1
                      :state-dir "/tmp/bitecho-d23-test"
                      :network :devnet
                      :custody-privkey priv-hex}
          res-main (mesh/validate-node-config mainnet-cfg)
          res-dev (mesh/validate-node-config devnet-cfg)]
      (is (false? (:valid? res-main)))
      (is (re-find #"custody-privkey" (str (:error res-main))))
      (is (true? (:valid? res-dev))))))

(deftest test-release-proof-e2e-suite
  (testing "A-CARB-D23-4: Full in-memory release proof across devnet, testnet, mainnet, replay rejection, and N/N+1 rolling upgrade"
    (let [proof (release-proof/run-release-proof {})]
      (is (true? (:all-passed? proof)))
      (is (true? (get-in proof [:networks "devnet.bitecho.org" :passed?])))
      (is (true? (get-in proof [:networks "testnet.bitecho.org" :passed?])))
      (is (true? (get-in proof [:networks "mainnet.bitecho.org" :passed?])))
      (is (true? (get-in proof [:cross-network-replay :all-rejected?])))
      (is (true? (get-in proof [:rolling-upgrade :passed?]))))))
