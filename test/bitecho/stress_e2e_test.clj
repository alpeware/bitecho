(ns bitecho.stress-e2e-test
  "Automated Test & Generative Property Suite for Milestone D15:
   - INV-D15-1: Fressian-Only Persistence & Zero Nippy Dependency (A-D15-1, A-CARB-1)
   - INV-D15-2: Bounded Rolling State (:block-depths & treasury epoch maps) + :last-pruned-mint-epoch guard (B-CARB-4, B-CARB-5)
   - INV-D15-3: Streamlet BFT (:validators) vs. Validator Set (:peers-map) Separation & Verified :receive-receipt Gossip (B-CARB-1, A-D15-3, A-D15-4)
   - INV-D15-4: Zero-Reset Dynamic Validator Membership (:reconfigure-membership) & QC Checkpoint Catch-Up (B-CARB-2, B-CARB-3, A-D15-5)
   - INV-D15-5: 3-Way Golden Oracle Differential Parity (Clean Queue, Chaos/Byzantine Shell, Live Testnet Runner) (A-D15-6, A-CARB-3)
   - INV-D15-6: 30,000-Epoch Tokenomics Horizon & 26,280-Epoch 3-Year Bootstrap Custody Sunset"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.treasury :as treasury]
            [bitecho.fressian :as fressian]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.persistence :as persistence]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [bitecho.stress.e2e-workload :as workload]
            [bitecho.stress.harness :as harness]
            [bitecho.stress.live-testnet :as live-testnet]
            [bitecho.stress.tokenomics-sim :as tokenomics-sim]
            [clojure.edn :as edn]
            [clojure.pprint :as pprint]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]))

;; =============================================================================
;; 1. INV-D15-1: Fressian-Only Persistence & Record/Collection Restoration
;; =============================================================================

(deftest inv-d15-1-zero-nippy-and-fressian-persistence-test
  (testing "deps.edn has zero com.taoensso/nippy dependency"
    (let [deps-map (edn/read-string (slurp "deps.edn"))]
      (is (not (contains? (:deps deps-map) 'com.taoensso/nippy)))))

  (testing "Legacy Nippy magic header bytes ('NPY') fail closed in fressian and persistence"
    (let [npy-bytes (byte-array [(byte 78) (byte 80) (byte 89) (byte 0) (byte 1) (byte 2)])
          tmp-file (File/createTempFile "bitecho-d15-npy-" ".fressian")]
      (.deleteOnExit tmp-file)
      (is (true? (fressian/nippy-payload? npy-bytes)))
      (is (nil? (fressian/decode-wire npy-bytes)))
      (is (nil? (fressian/decode npy-bytes)))
      (java.nio.file.Files/write (.toPath tmp-file) npy-bytes (make-array java.nio.file.OpenOption 0))
      (is (nil? (persistence/load-state-from-disk (.getAbsolutePath tmp-file))))
      (.delete tmp-file))))

(defspec ^{:doc "Property: Fressian persistence losslessly round-trips domain records, sets, and PersistentQueues (INV-D15-1, A-D15-1)."}
  fressian-state-roundtrip-generative-prop 25
  (prop/for-all [bal (gen/choose 1 1000000)
                 seq-num (gen/choose 1 50)
                 ep (gen/choose 1 100)]
                (let [kp (crypto/generate-keypair (str "gen-kp-" bal "-" seq-num))
                      pk-hex (basalt/bytes->hex (:public kp))
                      blk (streamlet/map->Block {:parent-hash "genesis"
                                                 :epoch ep
                                                 :proposer pk-hex
                                                 :payload []
                                                 :signature [1 2 3]})
                      b-hash (streamlet/hash-block blk)
                      vote (streamlet/map->Vote {:block-hash b-hash
                                                 :epoch ep
                                                 :voter pk-hex
                                                 :signature [4 5 6]})
                      ack (rendezvous/create-delivery-ack (:private kp) pk-hex pk-hex ep "m1" seq-num (* seq-num 10))
                      peer (basalt/->Peer "127.0.0.1" 9000 pk-hex pk-hex)
                      state {:epoch ep
                             :ledger {pk-hex (account/map->AccountState {:balance bal :seq seq-num :deps ["d1"]})}
                             :blocks {b-hash blk}
                             :block-votes {b-hash #{pk-hex}}
                             :block-vote-proofs {b-hash {pk-hex vote}}
                             :notarized-blocks #{b-hash}
                             :finalized-blocks #{b-hash}
                             :executed-finalized-blocks #{b-hash}
                             :minted-epochs #{ep}
                             :contagion-known-ids #{"m1"}
                             :known-receipt-ids #{"r1"}
                             :executed-receipt-ids #{"r1"}
                             :settled-escrow-ids #{"e1"}
                             :voted-epochs #{ep}
                             :equivocated-voters #{}
                             :pending-vouchers [ack]
                             :basalt-view [{:hash "h1" :peer peer}]
                             :murmur-cache {:set #{"m1"}
                                            :queue (conj clojure.lang.PersistentQueue/EMPTY "m1")}}
                      tmp-file (File/createTempFile "bitecho-d15-prop-" ".fressian")]
                  (try
                    (persistence/save-state-to-disk (.getAbsolutePath tmp-file) state)
                    (let [loaded (persistence/load-state-from-disk (.getAbsolutePath tmp-file))]
                      (and (some? loaded)
                           (instance? bitecho.economy.account.AccountState (get-in loaded [:ledger pk-hex]))
                           (= bal (get-in loaded [:ledger pk-hex :balance]))
                           (instance? bitecho.streamlet.core.Block (get-in loaded [:blocks b-hash]))
                           (instance? bitecho.streamlet.core.Vote (get-in loaded [:block-vote-proofs b-hash pk-hex]))
                           (instance? bitecho.rendezvous.core.DeliveryAck (first (:pending-vouchers loaded)))
                           (instance? bitecho.basalt.core.Peer (get-in loaded [:basalt-view 0 :peer]))
                           (set? (:notarized-blocks loaded))
                           (set? (:finalized-blocks loaded))
                           (set? (:minted-epochs loaded))
                           (set? (get-in loaded [:block-votes b-hash]))
                           (instance? clojure.lang.PersistentQueue (get-in loaded [:murmur-cache :queue]))))
                    (finally
                      (.delete tmp-file))))))

;; =============================================================================
;; 2. INV-D15-2: Bounded :block-depths, Bounded Treasury Maps, & Pruned Mint Guard
;; =============================================================================

(defspec ^{:doc "Property: Rolling state pruning bounds :block-depths and treasury epoch maps and rejects pruned-epoch mint replays (INV-D15-2, B-CARB-4, B-CARB-5)."}
  bounded-rolling-state-and-pruned-mint-guard-prop 25
  (prop/for-all [retention (gen/choose 8 24)
                 extra-epochs (gen/choose 15 40)]
                (let [total-epochs (+ retention extra-epochs)
                      t-kp (crypto/generate-keypair "prop-treasury-d15-2")
                      t-pub (basalt/bytes->hex (:public t-kp))
                      t-priv (:private t-kp)
          ;; 1. Verify streamlet/prune-streamlet-state bounds orphan :block-depths even when expired-hashes is empty (B-CARB-4)
                      st-with-orphan-depths {:epoch total-epochs
                                             :head-hash "b-head"
                                             :latest-finalized-block-hash "genesis"
                                             :blocks {}
                                             :block-depths {"genesis" 0
                                                            "b-head" 1
                                                            "orphan-1" 1
                                                            "orphan-2" 2
                                                            "orphan-3" 3}
                                             :notarized-blocks #{"genesis" "b-head"}
                                             :finalized-blocks #{"genesis"}
                                             :config {:streamlet-retention-epochs retention}}
                      pruned-streamlet (streamlet/prune-streamlet-state st-with-orphan-depths)
                      depths-bounded? (= #{"genesis" "b-head"} (set (keys (:block-depths pruned-streamlet))))

          ;; 2. Step treasury epochs and prune via sm/prune-epoch-state; verify B-CARB-5 guard
                      cfg {:treasury-trailing-epochs retention
                           :streamlet-retention-epochs retention
                           :frozen-log-retention-epochs retention
                           :frozen-epoch-retention-window retention
                           :rendezvous-retention-epochs retention}
                      final-st
                      (reduce
                       (fn [s ep]
                         (let [sig (treasury/sign-epoch-mint t-priv ep {t-pub 10} 0)
                               s-minted (-> s
                                            (assoc :epoch ep)
                                            (assoc-in [:epoch-burns ep] 20)
                                            (assoc-in [:epoch-settlement-takes ep] 5)
                                            (treasury/apply-epoch-mint {:epoch ep
                                                                        :allocations {t-pub 10}
                                                                        :mint-dust 0
                                                                        :treasury-pubkey t-pub
                                                                        :signature sig}))]
                           (sm/prune-epoch-state s-minted ep cfg)))
                       {:epoch 0
                        :treasury-pubkey t-pub
                        :ledger {}
                        :total-minted 0
                        :minted-epochs #{}
                        :last-pruned-mint-epoch -1
                        :config cfg}
                       (range 1 (inc total-epochs)))
          ;; Attempt to re-mint epoch 1 (which has been pruned from :minted-epochs!)
                      pruned-ep 1
                      replay-sig (treasury/sign-epoch-mint t-priv pruned-ep {t-pub 10} 0)
                      after-replay (treasury/apply-epoch-mint
                                    final-st
                                    {:epoch pruned-ep
                                     :allocations {t-pub 10}
                                     :mint-dust 0
                                     :treasury-pubkey t-pub
                                     :signature replay-sig})]
                  (and depths-bounded?
                       (not (contains? (:minted-epochs final-st) pruned-ep))
                       (>= (:last-pruned-mint-epoch final-st) pruned-ep)
           ;; Replay of pruned epoch must be rejected fail-closed!
                       (= (:total-minted final-st) (:total-minted after-replay))
                       (<= (count (:epoch-burns final-st)) (+ retention 2))
                       (<= (count (:epoch-settlement-takes final-st)) (+ retention 2))
                       (<= (count (:epoch-mint-dust final-st)) (+ retention 2))
                       (<= (count (:minted-epochs final-st)) (+ retention 2))))))

;; =============================================================================
;; 3. INV-D15-3: Streamlet Committee vs. Mesh Validators & Receipt Gossip
;; =============================================================================

(defspec ^{:doc "Property: Streamlet BFT committee (:validators) is separated from mesh validator set (:peers-map) and single-hop receipt gossip verifies signatures fail-closed (INV-D15-3, B-CARB-1)."}
  role-separation-and-receipt-gossip-verification-prop 20
  (prop/for-all [ep (gen/choose 1 30)
                 burn-amt (gen/choose 100 500)]
                (let [topo (workload/build-topology)
                      states (harness/init-cluster-states topo)
                      n1-hex (get-in topo [:validators-by-id :node1 :pubkey-hex])
                      ns1-hex (get-in topo [:validators-by-id :ns1 :pubkey-hex])
                      ns1-priv (get-in topo [:validators-by-id :ns1 :private])
                      founder-hex (get-in topo [:identities-by-id :subnet-founder :pubkey-hex])
                      st-n1 (assoc (get states n1-hex) :epoch ep)
                      st-ns1 (assoc (get states ns1-hex) :epoch ep)

          ;; 1. Committee extraction: only 3 Streamlet BFT validators out of 6 peers
                      committee (streamlet/extract-validator-hexes st-ns1)
                      all-peers (streamlet/extract-peer-hexes st-ns1)

          ;; 2. Non-committee node (ns1) ticking never proposes a block
                      ns1-tick (streamlet/handle-streamlet-event st-ns1 {:type :tick})
                      ns1-proposed? (boolean (some #(#{:propose-block :send-propose} (:type %)) (:commands ns1-tick)))

          ;; 3. Unauthorized vote from non-committee node (ns1) is ignored by committee node (n1)
                      fake-sig (basalt/bytes->hex (crypto/sign ns1-priv (fressian/utf8->bytes "genesis")))
                      fake-vote (streamlet/->Vote "genesis" ep fake-sig)
                      n1-after-ns1-vote (streamlet/handle-streamlet-event
                                         st-n1
                                         {:type :vote :vote fake-vote :sender ns1-hex})
                      unauthorized-vote-ignored? (not (contains? (get-in (:state n1-after-ns1-vote) [:block-votes "genesis"] #{})
                                                                 ns1-hex))

          ;; 4. Local intent on ns1 emits single-hop :send-receipt; receiving on n1 stages without re-gossiping
                      burn-res (sm/handle-event st-ns1 {:type :signaling-burn :sender founder-hex :burn-amount burn-amt})
                      send-rcpt-cmd (first (filter #(= :send-receipt (:type %)) (:commands burn-res)))
                      recv-res (when send-rcpt-cmd
                                 (sm/handle-event st-n1 {:type :receive-receipt
                                                         :receipt (:receipt send-rcpt-cmd)
                                                         :sender ns1-hex}))
                      no-regossip? (and recv-res (empty? (:commands recv-res)))

          ;; 5. Forged receipt is rejected fail-closed with :diagnose
                      forged-res (sm/handle-event st-n1 {:type :receive-receipt
                                                         :receipt {:receipt-id (str "forged-" ep)
                                                                   :type :burn
                                                                   :sender "non-existent-account"
                                                                   :amount 999999999}
                                                         :sender ns1-hex})]
                  (and (= 3 (count committee))
                       (= 6 (count all-peers))
                       (not ns1-proposed?)
                       unauthorized-vote-ignored?
                       (some? send-rcpt-cmd)
                       no-regossip?
                       (= 1 (get-in (:state forged-res) [:diagnostics :unverified-gossip-receipt-rejected] 0))
                       (= :diagnose (:type (first (:commands forged-res))))))))

;; =============================================================================
;; 4. INV-D15-4: Dynamic Validator Membership & QC Checkpoint Catch-Up
;; =============================================================================

(deftest inv-d15-4-dynamic-membership-and-checkpoint-qc-test
  (testing "3 -> 6 -> 5 dynamic validator membership reconfiguration & QC checkpoint catch-up"
    (let [res (harness/run-dynamic-membership-e2e)]
      (is (:reconfig-add-applied? res))
      (is (:invalid-checkpoints-rejected? res))
      (is (:checkpoint-synced? res))
      (is (:converged-after-remove? res))
      (is (:all-passed? res))))

  (testing "late-joining validator recovering 16 ancestors at epoch 26 (oldest-epoch=10, newest-epoch=25 > 16) executes finalized blocks without stalling"
    (let [blocks (into {}
                       (for [ep (range 10 26)
                             :let [h (str "b-" ep)
                                   p (str "b-" (dec ep))]]
                         [h {:epoch ep :parent-hash p :payload []}]))
          finalized (set (for [ep (range 10 25)] (str "b-" ep)))
          st {:epoch 26
              :blocks blocks
              :finalized-blocks finalized
              :executed-finalized-blocks #{}
              :latest-finalized-block-hash "b-24"
              :last-executed-finalized-epoch 0
              :config {:max-ancestor-sync-depth 16}}
          exec-st (sm/execute-finalized-blocks st)]
      (is (= 24 (:last-executed-finalized-epoch exec-st)))
      (is (= 1 (get-in exec-st [:diagnostics :finalized-ancestor-gap-recovered] 0)))))

  (testing "live-testnet/reconfigure-live-validator! adds and removes validators with treasury signature"
    (let [topo (workload/build-topology)
          tmp-boot (File/createTempFile "bitecho-d15-boot-" ".edn")
          tmp-keys (File/createTempFile "bitecho-d15-keys-" ".edn")]
      (try
        (let [nodes-cfg (into {}
                              (map (fn [[vid v]]
                                     [vid {:ip "127.0.0.1" :port 5000 :pubkey (:pubkey-hex v)}])
                                   (:validators-by-id topo)))
              boot-data {:cluster {:network :devnet
                                   :treasury-pubkey (get-in topo [:treasury :pubkey-hex])
                                   :validators [:node1 :node2 :node3]
                                   :mesh-nodes {:node1 1.0 :node2 1.0 :node3 1.0}
                                   :nodes nodes-cfg}}
              keys-data {:treasury {:public (get-in topo [:treasury :pubkey-hex])
                                    :private (get-in topo [:treasury :privkey-hex])}}]
          (spit tmp-boot (with-out-str (pprint/pprint boot-data)))
          (spit tmp-keys (with-out-str (pprint/pprint keys-data)))
          (let [add-res (live-testnet/reconfigure-live-validator!
                         {:action :add
                          :node-id "ns1"
                          :role "mesh"
                          :bootstrap-file (.getAbsolutePath tmp-boot)
                          :keys-file (.getAbsolutePath tmp-keys)
                          :effective-epoch 5})
                rem-res (live-testnet/reconfigure-live-validator!
                         {:action :remove
                          :node-id "ns1"
                          :role "mesh"
                          :bootstrap-file (.getAbsolutePath tmp-boot)
                          :keys-file (.getAbsolutePath tmp-keys)
                          :effective-epoch 6})]
            (is (:ok? add-res))
            (is (contains? (:mesh-nodes add-res) :ns1))
            (is (seq (get-in add-res [:receipt :new-peers-map])))
            (is (sm/verify-reconfigure-membership?
                 {:treasury-pubkey (get-in topo [:treasury :pubkey-hex])}
                 (:receipt add-res)))
            (is (:ok? rem-res))
            (is (not (contains? (:mesh-nodes rem-res) :ns1)))))
        (finally
          (.delete tmp-boot)
          (.delete tmp-keys)))))

  (testing "live-testnet/reconfigure-live-validator! supports top-level devnet/bootstrap.edn and .ssh/devnet_treasury_keypair.edn schema (B-OPUS-D15-1, B-CARB-D15-1)"
    (let [topo (workload/build-topology)
          tmp-boot (File/createTempFile "bitecho-d15-top-boot-" ".edn")
          tmp-keys (File/createTempFile "bitecho-d15-ssh-keys-" ".edn")]
      (try
        (let [nodes-cfg (into {}
                              (map (fn [[vid v]]
                                     [vid {:ip "127.0.0.1" :port 5000 :agent-port 5010 :pubkey (:pubkey-hex v)}])
                                   (:validators-by-id topo)))
              top-boot-data {:network :devnet
                             :treasury-pubkey (get-in topo [:treasury :pubkey-hex])
                             :custody-pubkey (get-in topo [:custody :pubkey-hex])
                             :validators [:node1 :node2 :node3]
                             :mesh-nodes {:node1 1.0 :node2 1.0 :node3 1.0}
                             :nodes nodes-cfg}
              ssh-keys-data {:pubkey-hex (get-in topo [:treasury :pubkey-hex])
                             :privkey-hex (get-in topo [:treasury :privkey-hex])}]
          (spit tmp-boot (with-out-str (pprint/pprint top-boot-data)))
          (spit tmp-keys (with-out-str (pprint/pprint ssh-keys-data)))
          (let [add-bft (live-testnet/reconfigure-live-validator!
                         {:action :add
                          :node-id :ns1
                          :promote-bft? true
                          :bootstrap-file (.getAbsolutePath tmp-boot)
                          :treasury-key-file (.getAbsolutePath tmp-keys)
                          :effective-epoch 10})
                saved-boot (edn/read-string (slurp tmp-boot))]
            (is (:ok? add-bft))
            (is (= :bft (:role add-bft)))
            (is (some #{:ns1} (:validators saved-boot)))
            (is (contains? (:mesh-nodes saved-boot) :ns1))
            (is (nil? (:cluster saved-boot)) "Top-level bootstrap.edn layout must be preserved")
            (is (sm/verify-reconfigure-membership?
                 {:treasury-pubkey (get-in topo [:treasury :pubkey-hex])}
                 (:receipt add-bft)))))
        (finally
          (.delete tmp-boot)
          (.delete tmp-keys))))))

;; =============================================================================
;; 5. INV-D15-5: 3-Way Golden Oracle Differential Parity (Clean, Chaos/Byzantine, Live)
;; =============================================================================

(deftest inv-d15-5-three-way-golden-oracle-clean-and-chaos-byzantine-test
  (testing "Target 1: Clean 6-Node Queue Harness matches Golden Oracle 100% + Fressian round-trip"
    (let [clean-res (harness/run-clean-in-memory-e2e)]
      (is (:parity? clean-res))
      (is (:all-nodes-match? clean-res))
      (is (:offchain-match? clean-res))
      (is (:fressian-roundtrip-ok? clean-res))
      (is (= 7 (:adversarial-rejections clean-res)))))

  (testing "Target 2: Chaos + Byzantine Shell (f=1 equivocator + forged gossip + packet drops) converges to Golden Oracle"
    (let [chaos-res (harness/run-chaos-byzantine-e2e 15001)]
      (is (:parity? chaos-res))
      (is (:equivocation-detected? chaos-res))
      (is (:forged-gossip-rejected? chaos-res))
      (is (:chaos-healthy? chaos-res))))

  (testing "Target 3: Full Wire-Codec & Authenticated Agent-Ingress Boundary Runner + Live Testnet Verifier match Golden Oracle (B-OPUS-D15-2, B-OPUS-D15-3)"
    (let [wire-res (harness/run-wire-boundary-e2e)
          live-res (live-testnet/run-live-testnet-e2e!)]
      (is (:wire-boundary? wire-res))
      (is (:parity? wire-res))
      (is (:all-nodes-match? wire-res))
      (is (:fressian-roundtrip-ok? wire-res))
      (is (:wire-boundary? live-res))
      (is (:parity? live-res))
      (is (:deltas-match? live-res))
      (is (:escrows-match? live-res))
      (is (:fressian-roundtrip-ok? live-res)))))

;; =============================================================================
;; 6. INV-D15-6: 30,000-Epoch Tokenomics Horizon & 3-Year Sunset Simulation
;; =============================================================================

(deftest inv-d15-6-tokenomics-30000-epoch-horizon-and-sunset-test
  (testing "30,000-epoch simulation across Low, Medium, and High volume regimes (crossing epoch 26,280 sunset)"
    (let [sim (tokenomics-sim/run-all-tokenomics-regimes 30000)
          low (:low sim)
          medium (:medium sim)
          high (:high sim)]
      (is (:all-compliant? sim))
      ;; Low volume: 3-year Bootstrap custody sunset at epoch 26,280 burns remaining custody balance to 0
      (is (pos? (:sunset-custody-burned low)))
      (is (zero? (:post-sunset-custody-balance low)))
      (is (:post-sunset-drawdown-rejected? low))
      (is (:partner-transfer-ok? low))
      (is (:team-balance-intact? low))
      (is (:ecosystem-balance-intact? low))
      (is (:pruned-replay-rejected? low))
      (is (:bounded-state-ok? low))

      ;; Medium volume: net deflationary equilibrium (total minted < cumulative burns)
      (is (< (:total-minted medium) (:cumulative-burns medium)))
      (is (:conservation-ok? medium))
      (is (:bounded-state-ok? medium))

      ;; High volume: hits exact 23,100,000,000 conditional mint cap before epoch 30,000 and clamps to 0 thereafter
      (is (= treasury/max-conditional-mint-supply (+ (:total-minted high) (:mint-dust high))))
      (is (< (:cap-reached-epoch high) 30000))
      (is (:supply-cap-respected? high))
      (is (:conservation-ok? high))
      (is (:bounded-state-ok? high)))))
