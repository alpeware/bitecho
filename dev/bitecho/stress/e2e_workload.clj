(ns bitecho.stress.e2e-workload
  "Unified Full-Surface E2E Stress Workload & Deterministic Golden Oracle (Milestone D15).
   Defines 6 validators (3 Streamlet BFT committee + 3 mesh/infra validators),
   8 light-node identities with diverse 3-of-6 home sets, a 6-stage 'Fractal Intent Economy'
   scenario exercising every protocol subsystem, and a pure `compute-golden-expected-state`
   oracle for 3-way differential verification."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.storage :as storage]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [bitecho.rendezvous.core :as rendezvous]))

;; =============================================================================
;; 1. Deterministic Topology & Identities
;; =============================================================================

(def validator-ids
  "All 6 validator node IDs in the mesh."
  [:node1 :node2 :node3 :ns1 :ns2 :ns3])

(def streamlet-committee-ids
  "The 3 Streamlet BFT proposer/voter committee node IDs."
  [:node1 :node2 :node3])

(def light-identity-specs
  "8 light-node identities with diverse 3-of-6 home sets and initial balances."
  [{:id :treasury-funder
    :seed "d15-light-treasury-funder"
    :home-set [:node1 :node2 :ns1]
    :initial-balance 1000000
    :home-price 50}
   {:id :subnet-founder
    :seed "d15-light-subnet-founder"
    :home-set [:node1 :ns1 :ns2]
    :initial-balance 500000
    :home-price 50}
   {:id :kernel-author
    :seed "d15-light-kernel-author"
    :home-set [:node2 :ns2 :ns3]
    :initial-balance 200000
    :home-price 50}
   {:id :gpu-provider
    :seed "d15-light-gpu-provider"
    :home-set [:node3 :ns1 :ns3]
    :initial-balance 200000
    :home-price 50}
   {:id :oracle-verifier
    :seed "d15-light-oracle-verifier"
    :home-set [:node1 :node3 :ns2]
    :initial-balance 150000
    :home-price 50}
   {:id :agent-buyer-1
    :seed "d15-light-agent-buyer-1"
    :home-set [:node2 :node3 :ns1]
    :initial-balance 400000
    :home-price 50}
   {:id :agent-buyer-2
    :seed "d15-light-agent-buyer-2"
    :home-set [:ns1 :ns2 :ns3]
    :initial-balance 300000
    :home-price 50}
   {:id :byzantine-challenger
    :seed "d15-light-byzantine-challenger"
    :home-set [:node1 :ns2 :ns3]
    :initial-balance 100000
    :home-price 50}])

(defn deterministic-keypair
  "Generates a deterministic Ed25519 keypair from a string seed, returning
   {:public bytes :private bytes :pubkey-hex str :privkey-hex str}."
  [seed-str]
  (let [kp (crypto/generate-keypair seed-str)
        pub (:public kp)
        priv (:private kp)]
    {:public pub
     :private priv
     :pubkey-hex (basalt/bytes->hex pub)
     :privkey-hex (basalt/bytes->hex priv)}))

(defn build-topology
  "Constructs the deterministic 6-validator + 8-light-node topology and genesis ledger."
  []
  (let [treasury-kp (deterministic-keypair "d15-treasury-authority")
        custody-kp (deterministic-keypair "d15-bootstrap-custody")
        validators-by-id
        (into {}
              (map (fn [vid]
                     (let [kp (deterministic-keypair (str "d15-validator-" (name vid)))]
                       [vid (assoc kp :id vid)]))
                   validator-ids))
        identities-by-id
        (into {}
              (map (fn [spec]
                     (let [kp (deterministic-keypair (:seed spec))]
                       [(:id spec) (merge spec kp)]))
                   light-identity-specs))
        validator-hexes (mapv #(get-in validators-by-id [% :pubkey-hex]) streamlet-committee-ids)
        all-peer-hexes (mapv #(get-in validators-by-id [% :pubkey-hex]) validator-ids)
        peers-map (into {}
                        (map (fn [vid]
                               (let [v (get validators-by-id vid)]
                                 [(:pubkey-hex v) (:public v)]))
                             validator-ids))
        mesh-nodes (into (sorted-map)
                         (map (fn [pk] [pk 1.0]) all-peer-hexes))
        genesis-ledger
        (reduce
         (fn [acc [_ v]]
           (assoc acc (:pubkey-hex v)
                  (account/map->AccountState {:balance 50000 :seq 0 :deps []})))
         (reduce
          (fn [acc [_ id-map]]
            (assoc acc (:pubkey-hex id-map)
                   (account/map->AccountState {:balance (:initial-balance id-map) :seq 0 :deps []})))
          {}
          identities-by-id)
         validators-by-id)]
    {:treasury treasury-kp
     :custody custody-kp
     :validators-by-id validators-by-id
     :identities-by-id identities-by-id
     :streamlet-validator-hexes (vec (sort validator-hexes))
     :all-validator-hexes (vec (sort all-peer-hexes))
     :peers-map peers-map
     :mesh-nodes mesh-nodes
     :genesis-ledger genesis-ledger}))

;; =============================================================================
;; 2. Custom ChiaLisp-Style SCI Smart Contract Puzzles
;; =============================================================================

(def royalty-split-puzzle-source
  "3-way royalty split SCI smart contract (1500 GPU provider / 300 Kernel author / 200 Subnet founder)
   gated by SHA-256 tensor deliverable preimage and Oracle Verifier Ed25519 signature."
  "(fn [env solution]
     (if (and (= (sha256-hex (:deliverable solution)) (:deliverable-hash solution))
              (verify-sig (:oracle-pubkey solution)
                          (:benchmark-report solution)
                          (:oracle-sig solution)))
       [{:type :assert-sha256
         :preimage (:deliverable solution)
         :hash (:deliverable-hash solution)}
        {:type :assert-sig
         :pubkey (:oracle-pubkey solution)
         :message (:benchmark-report solution)
         :signature (:oracle-sig solution)}
        [:release 1500 (:gpu-provider solution)]
        [:release 300 (:kernel-author solution)]
        [:release 200 (:subnet-founder solution)]]
       false))")

(def multisig-2of2-puzzle-source
  "2-of-2 multisig vault SCI smart contract requiring signatures from both buyer and oracle."
  "(fn [env solution]
     (if (and (verify-sig (:signer-1 solution) (:vault-msg solution) (:sig-1 solution))
              (verify-sig (:signer-2 solution) (:vault-msg solution) (:sig-2 solution)))
       [{:type :assert-sig
         :pubkey (:signer-1 solution)
         :message (:vault-msg solution)
         :signature (:sig-1 solution)}
        {:type :assert-sig
         :pubkey (:signer-2 solution)
         :message (:vault-msg solution)
         :signature (:sig-2 solution)}
        [:release (:amount env) (:receiver env)]]
       false))")

(def adversarial-overspend-puzzle-source
  "Adversarial SCI puzzle attempting to release more than the locked escrow amount."
  "(fn [env solution]
     [[:release (+ (:amount env) 999999) (:receiver env)]])")

(def adversarial-fuel-exhaustion-puzzle-source
  "Adversarial SCI puzzle attempting to exceed range/step budget limits."
  "(fn [env solution]
     (let [xs (range 10000)]
       [[:release (:amount env) (:receiver env)]]))")

;; =============================================================================
;; 3. Subnets, E2EE Storage, Capabilities, & Streaming Artefacts
;; =============================================================================

(defn run-nested-subnet-hierarchy
  "Executes Stage 2: 3-level nested subnet hierarchy (`global` -> `ai-coop` -> `ai-coop/gpu-cluster-west`)
   with child-to-parent quorum state-root anchoring."
  [topo]
  (let [founder (get-in topo [:identities-by-id :subnet-founder])
        author (get-in topo [:identities-by-id :kernel-author])
        gpu (get-in topo [:identities-by-id :gpu-provider])
        oracle (get-in topo [:identities-by-id :oracle-verifier])
        v1 (get-in topo [:validators-by-id :node1])
        v2 (get-in topo [:validators-by-id :node2])
        v3 (get-in topo [:validators-by-id :node3])

        global-policy {:subnet/id "global"
                       :subnet/parent-id nil
                       :subnet/gate {:gate/mode :permissioned
                                     :gate/admission :allowlist
                                     :gate/trust-anchors #{(:pubkey-hex v1) (:pubkey-hex v2) (:pubkey-hex v3)
                                                           (:pubkey-hex founder) (:pubkey-hex author)}
                                     :gate/governance {:governance/type :quorum :threshold 2}}
                       :subnet/path-acl [{:pattern "anchor/*" :principal {:type :quorum :threshold 2}}
                                         {:pattern "cluster/*" :principal {:type :allowlist}}]
                       :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                       :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
        ai-coop-policy {:subnet/id "ai-coop"
                        :subnet/parent-id "global"
                        :subnet/gate {:gate/mode :permissioned
                                      :gate/admission :allowlist
                                      :gate/trust-anchors #{(:pubkey-hex founder) (:pubkey-hex author)
                                                            (:pubkey-hex oracle) (:pubkey-hex gpu)}
                                      :gate/governance {:governance/type :quorum :threshold 2}}
                        :subnet/path-acl [{:pattern "anchor/*" :principal {:type :quorum :threshold 2}}
                                          {:pattern "cluster/*" :principal {:type :allowlist}}]
                        :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                        :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
        gpu-west-policy {:subnet/id "ai-coop/gpu-cluster-west"
                         :subnet/parent-id "ai-coop"
                         :subnet/gate {:gate/mode :permissioned
                                       :gate/admission :allowlist
                                       :gate/trust-anchors #{(:pubkey-hex gpu) (:pubkey-hex author) (:pubkey-hex oracle)}
                                       :gate/governance {:governance/type :quorum :threshold 2}}
                         :subnet/path-acl [{:pattern "anchor/*" :principal {:type :quorum :threshold 2}}
                                           {:pattern "cluster/*" :principal {:type :allowlist}}]
                         :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                         :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}

        global-init (subnet/init-subnet-instance global-policy {:now-ms 1000})
        ai-coop-init (subnet/init-subnet-instance ai-coop-policy {:now-ms 1000})
        gpu-west-init (subnet/init-subnet-instance gpu-west-policy {:now-ms 1000})

        ;; Reduce local intents in grandchild subnet `ai-coop/gpu-cluster-west`
        node0-blob (data/make-blob (fressian/encode-canonical {:gpus 8 :arch "H100"}) "application/fressian")
        node0-ptr (data/sign-pointer (:private gpu)
                                     {:pointer/authority (:pubkey-hex gpu)
                                      :pointer/subnet "ai-coop/gpu-cluster-west"
                                      :pointer/path "cluster/node-0"
                                      :pointer/seq 1
                                      :pointer/target (:blob/cid node0-blob)
                                      :pointer/proof {:proof/type :self}})
        gpu-west-s1 (:state (subnet/reduce-subnet
                             (:instance gpu-west-init)
                             {:type :put-blob :sender (:pubkey-hex gpu) :blob node0-blob :now-ms 1100}))
        gpu-west-s2 (:state (subnet/reduce-subnet
                             gpu-west-s1
                             {:type :publish-pointer :sender (:pubkey-hex gpu) :pointer node0-ptr :now-ms 1200}))
        gpu-west-anchor (subnet/build-subnet-anchor
                         gpu-west-s2
                         {:quorum-signers [{:pubkey (:pubkey-hex gpu) :privkey (:private gpu)}
                                           {:pubkey (:pubkey-hex oracle) :privkey (:private oracle)}]
                          :parent-subnet "ai-coop"
                          :child-epoch 2
                          :anchor-seq 1
                          :now-ms 1300})
        gpu-west-anchor-v (subnet/verify-subnet-anchor
                           (:pointer gpu-west-anchor)
                           (:blob gpu-west-anchor)
                           (subnet/pointer-verify-ctx (:instance ai-coop-init) nil 1300))

        ;; Anchor grandchild state root into parent `ai-coop`
        ai-coop-s1 (:state (subnet/reduce-subnet
                            (:instance ai-coop-init)
                            {:type :put-blob
                             :sender (:pubkey-hex gpu)
                             :blob (:blob gpu-west-anchor)
                             :now-ms 1400}))
        ai-coop-s2 (:state (subnet/reduce-subnet
                            ai-coop-s1
                            {:type :publish-pointer
                             :sender (:pubkey-hex gpu)
                             :pointer (:pointer gpu-west-anchor)
                             :now-ms 1500}))
        ai-coop-anchor (subnet/build-subnet-anchor
                        ai-coop-s2
                        {:quorum-signers [{:pubkey (:pubkey-hex founder) :privkey (:private founder)}
                                          {:pubkey (:pubkey-hex author) :privkey (:private author)}]
                         :parent-subnet "global"
                         :child-epoch 2
                         :anchor-seq 1
                         :now-ms 1600})
        ai-coop-anchor-v (subnet/verify-subnet-anchor
                          (:pointer ai-coop-anchor)
                          (:blob ai-coop-anchor)
                          (subnet/pointer-verify-ctx (:instance global-init) nil 1600))

        ;; Anchor `ai-coop` state root into root `global`
        global-s1 (:state (subnet/reduce-subnet
                           (:instance global-init)
                           {:type :put-blob
                            :sender (:pubkey-hex founder)
                            :blob (:blob ai-coop-anchor)
                            :now-ms 1700}))
        global-s2 (:state (subnet/reduce-subnet
                           global-s1
                           {:type :publish-pointer
                            :sender (:pubkey-hex founder)
                            :pointer (:pointer ai-coop-anchor)
                            :now-ms 1800}))]
    {:global-state global-s2
     :ai-coop-state ai-coop-s2
     :gpu-west-state gpu-west-s2
     :gpu-west-anchor gpu-west-anchor
     :ai-coop-anchor ai-coop-anchor
     :all-anchors-valid? (boolean (and (:ok? global-init)
                                       (:ok? ai-coop-init)
                                       (:ok? gpu-west-init)
                                       (:ok? gpu-west-anchor-v)
                                       (:ok? ai-coop-anchor-v)))
     :anchored-grandchild-root (:merkle-root gpu-west-anchor)
     :anchored-child-root (:merkle-root ai-coop-anchor)}))

(defn run-e2ee-storage-and-capabilities
  "Executes Stage 3: E2EE state packing/unpacking, pointer monotonicity, and Capability Descriptors
   (`:compute/uop-kernel`, `:compute/gpu-access`, `:network/turn-relay`)."
  [topo]
  (let [author (get-in topo [:identities-by-id :kernel-author])
        gpu (get-in topo [:identities-by-id :gpu-provider])
        founder (get-in topo [:identities-by-id :subnet-founder])
        challenger (get-in topo [:identities-by-id :byzantine-challenger])

        ;; Pack E2EE state v1 and v2
        state-v1 {:weights-cid "bafy-weights-v1" :preferences {:subnet "ai-coop"} :seq 1}
        state-v2 {:weights-cid "bafy-weights-v2" :preferences {:subnet "ai-coop/gpu-cluster-west"} :seq 2}
        packed-v1 (storage/pack-encrypted-state
                   {:privkey (:private author)
                    :pubkey (:pubkey-hex author)
                    :subnet-id "ai-coop"
                    :slot "weights"
                    :seq 1
                    :state-data state-v1})
        packed-v2 (storage/pack-encrypted-state
                   {:privkey (:private author)
                    :pubkey (:pubkey-hex author)
                    :subnet-id "ai-coop"
                    :slot "weights"
                    :seq 2
                    :state-data state-v2})
        unpacked-v2 (storage/unpack-encrypted-state
                     {:privkey (:private author)
                      :pubkey (:pubkey-hex author)
                      :blob (:blob packed-v2)
                      :pointer (:pointer packed-v2)
                      :min-expected-seq 2})
        wrong-key-res (storage/unpack-encrypted-state
                       {:privkey (:private challenger)
                        :pubkey (:pubkey-hex author)
                        :blob (:blob packed-v2)
                        :pointer (:pointer packed-v2)
                        :min-expected-seq 2})
        stale-rollback-res (storage/unpack-encrypted-state
                            {:privkey (:private author)
                             :pubkey (:pubkey-hex author)
                             :blob (:blob packed-v1)
                             :pointer (:pointer packed-v1)
                             :min-expected-seq 2})

        ;; Capability descriptors across the 3 roles
        cap-kernel (storage/pack-capability-descriptor
                    {:privkey (:private author)
                     :pubkey (:pubkey-hex author)
                     :subnet-id "ai-coop"
                     :capability-id "flash-attn-v3"
                     :capability-type :compute/uop-kernel
                     :price-echo 300
                     :burn-floor 100
                     :seq 1
                     :metadata {:op :flash-attention :dtype :bf16}})
        cap-gpu (storage/pack-capability-descriptor
                 {:privkey (:private gpu)
                  :pubkey (:pubkey-hex gpu)
                  :subnet-id "ai-coop/gpu-cluster-west"
                  :capability-id "h100-node0"
                  :capability-type :compute/gpu-access
                  :price-echo 1500
                  :burn-floor 100
                  :seq 1
                  :metadata {:vram-gb 80 :count 8}})
        cap-turn (storage/pack-capability-descriptor
                  {:privkey (:private founder)
                   :pubkey (:pubkey-hex founder)
                   :subnet-id "global"
                   :capability-id "turn-ns1"
                   :capability-type :network/turn-relay
                   :price-echo 50
                   :burn-floor 100
                   :seq 1
                   :metadata {:bandwidth-mbps 1000}})

        unpacked-kernel (storage/unpack-capability-descriptor
                         {:blob (:blob cap-kernel)
                          :pointer (:pointer cap-kernel)
                          :min-expected-seq 1})
        unpacked-gpu (storage/unpack-capability-descriptor
                      {:blob (:blob cap-gpu)
                       :pointer (:pointer cap-gpu)
                       :min-expected-seq 1})
        unpacked-turn (storage/unpack-capability-descriptor
                       {:blob (:blob cap-turn)
                        :pointer (:pointer cap-turn)
                        :min-expected-seq 1})

        ;; Tampered capability signature check (byzantine challenger)
        tampered-res (storage/unpack-capability-descriptor
                      {:blob (assoc (:blob cap-gpu)
                                    :blob/cid "0000000000000000000000000000000000000000000000000000000000000000")
                       :pointer (:pointer cap-gpu)
                       :min-expected-seq 1})
        forged-signer-res (storage/unpack-capability-descriptor
                           {:blob (:blob cap-gpu)
                            :pointer (assoc (:pointer cap-gpu) :pointer/authority (:pubkey-hex challenger))
                            :min-expected-seq 1})]
    {:e2ee-v1-cid (:cid packed-v1)
     :e2ee-v2-cid (:cid packed-v2)
     :e2ee-decrypted (:data unpacked-v2)
     :e2ee-valid? (boolean (and (:ok? packed-v1)
                                (:ok? packed-v2)
                                (:ok? unpacked-v2)
                                (= state-v2 (:data unpacked-v2))
                                (not (:ok? wrong-key-res))
                                (not (:ok? stale-rollback-res))
                                (= :stale-pointer-rollback (:error stale-rollback-res))))
     :capabilities {:compute/uop-kernel (:cid cap-kernel)
                    :compute/gpu-access (:cid cap-gpu)
                    :network/turn-relay (:cid cap-turn)}
     :capabilities-valid? (boolean (and (:ok? unpacked-kernel)
                                        (:ok? unpacked-gpu)
                                        (:ok? unpacked-turn)
                                        (not (:ok? tampered-res))
                                        (not (:ok? forged-signer-res))))}))

(defn run-tensor-stream-verification
  "Executes Stage 5: 4-chunk binary DataChannel tensor stream assembly and SHA-256 verification."
  []
  (let [chunks ["tensor-chunk-0:bf16:header:64x64|"
                "tensor-chunk-1:layer0:weights:qkv|"
                "tensor-chunk-2:layer1:weights:mlp|"
                "tensor-chunk-3:norm:output:logits"]
        chunk-cids (mapv #(data/compute-cid (fressian/utf8->bytes %)) chunks)
        assembled (apply str chunks)
        assembled-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes assembled)))]
    {:chunks chunks
     :chunk-cids chunk-cids
     :assembled-payload assembled
     :deliverable-hash assembled-hash}))

;; =============================================================================
;; 4. Pure Scenario Builder & Golden Expected State Oracle
;; =============================================================================

(defn build-workload-scenario
  "Constructs the complete deterministic 6-stage workload scenario and all cryptographic
   artefacts (signed transfers, vouchers, SCI puzzles & solutions, escrows, and adversarial events)."
  []
  (let [topo (build-topology)
        ids (:identities-by-id topo)
        vals-by-id (:validators-by-id topo)
        funder (:treasury-funder ids)
        founder (:subnet-founder ids)
        author (:kernel-author ids)
        gpu (:gpu-provider ids)
        oracle (:oracle-verifier ids)
        buyer1 (:agent-buyer-1 ids)
        buyer2 (:agent-buyer-2 ids)
        challenger (:byzantine-challenger ids)

        ;; Stage 1 Transfers:
        ;; 1a. funder -> buyer1 (50,000, seq 1)
        tx1 (account/create-transfer
             (:private funder)
             {:sender (:pubkey-hex funder)
              :receiver (:pubkey-hex buyer1)
              :amount 50000
              :seq 1
              :deps []})
        tx1-hash (account/transfer-hash tx1)
        ;; 1b. funder -> buyer2 (30,000, seq 2, chained on tx1-hash)
        tx2 (account/create-transfer
             (:private funder)
             {:sender (:pubkey-hex funder)
              :receiver (:pubkey-hex buyer2)
              :amount 30000
              :seq 2
              :deps [tx1-hash]})
        ;; 1c. buyer1 -> author (10,000, seq 1)
        tx3 (account/create-transfer
             (:private buyer1)
             {:sender (:pubkey-hex buyer1)
              :receiver (:pubkey-hex author)
              :amount 10000
              :seq 1
              :deps []})

        ;; Stage 1 Routing Vouchers:
        ;; buyer1 -> ns1 (epoch 1, seq 2, price 50 -> debit 100)
        ns1-hex (get-in vals-by-id [:ns1 :pubkey-hex])
        ns2-hex (get-in vals-by-id [:ns2 :pubkey-hex])
        voucher1 (rendezvous/create-delivery-ack
                  (:private buyer1)
                  (:pubkey-hex buyer1)
                  ns1-hex
                  1
                  "offer-msg-buyer1-1"
                  2
                  100)
        ;; buyer2 -> ns2 (epoch 1, seq 3, price 50 -> debit 150)
        voucher2 (rendezvous/create-delivery-ack
                  (:private buyer2)
                  (:pubkey-hex buyer2)
                  ns2-hex
                  1
                  "offer-msg-buyer2-1"
                  3
                  150)

        ;; Stage 2 & 3 Off-chain / Anchored Subnets, E2EE Storage, Capabilities, Tensor Stream
        subnet-res (run-nested-subnet-hierarchy topo)
        storage-res (run-e2ee-storage-and-capabilities topo)
        stream-res (run-tensor-stream-verification)

        ;; Stage 4 Smart Contract Escrows:
        ;; Contract 1: 3-Way Royalty Split (2000 ECHO locked by buyer1 at epoch 3, released at epoch 4)
        royalty-p-hash (puzzle/puzzle-cid royalty-split-puzzle-source)
        royalty-escrow-id (escrow/compute-escrow-id
                           (:pubkey-hex buyer1)
                           (:pubkey-hex gpu)
                           2000
                           royalty-p-hash
                           3
                           10
                           "royalty-1")
        benchmark-report "bitecho-benchmark-v1|uop-kernel=flash-attn-v3|tflops=412|pass=true"
        oracle-bench-sig (basalt/bytes->hex
                          (crypto/sign (:private oracle)
                                       (fressian/utf8->bytes benchmark-report)))
        royalty-solution {:deliverable (:assembled-payload stream-res)
                          :deliverable-hash (:deliverable-hash stream-res)
                          :oracle-pubkey (:pubkey-hex oracle)
                          :benchmark-report benchmark-report
                          :oracle-sig oracle-bench-sig
                          :gpu-provider (:pubkey-hex gpu)
                          :kernel-author (:pubkey-hex author)
                          :subnet-founder (:pubkey-hex founder)}

        ;; Contract 2: 2-of-2 Multisig Vault (1000 ECHO locked by buyer2 at epoch 3, released at epoch 4)
        multisig-p-hash (puzzle/puzzle-cid multisig-2of2-puzzle-source)
        multisig-escrow-id (escrow/compute-escrow-id
                            (:pubkey-hex buyer2)
                            (:pubkey-hex author)
                            1000
                            multisig-p-hash
                            3
                            10
                            "multisig-1")
        vault-msg "bitecho-multisig-v1|release=1000|to=kernel-author"
        buyer2-vault-sig (basalt/bytes->hex
                          (crypto/sign (:private buyer2) (fressian/utf8->bytes vault-msg)))
        oracle-vault-sig (basalt/bytes->hex
                          (crypto/sign (:private oracle) (fressian/utf8->bytes vault-msg)))
        multisig-solution {:signer-1 (:pubkey-hex buyer2)
                           :sig-1 buyer2-vault-sig
                           :signer-2 (:pubkey-hex oracle)
                           :sig-2 oracle-vault-sig
                           :vault-msg vault-msg}

        ;; Contract 3: Standard HTLC Preimage Escrow (600 ECHO locked by founder at epoch 3, released at epoch 4)
        htlc-preimage "bitecho-htlc-secret-preimage-stage4"
        htlc-d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes htlc-preimage)))
        htlc-escrow-id (escrow/compute-escrow-id
                        (:pubkey-hex founder)
                        (:pubkey-hex gpu)
                        600
                        htlc-d-hash
                        3
                        10
                        "htlc-1")

        ;; Contract 4: Timeout Refund Escrow (400 ECHO locked by buyer1 at epoch 3, expires at epoch 4, refunded at epoch 6)
        timeout-d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "unrevealed-secret")))
        timeout-escrow-id (escrow/compute-escrow-id
                           (:pubkey-hex buyer1)
                           (:pubkey-hex challenger)
                           400
                           timeout-d-hash
                           3
                           4
                           "timeout-1")]
    {:topology topo
     :transfers {:tx1 tx1 :tx2 tx2 :tx3 tx3}
     :vouchers {:voucher1 voucher1 :voucher2 voucher2}
     :subnets subnet-res
     :storage storage-res
     :stream stream-res
     :contracts {:royalty {:escrow-id royalty-escrow-id
                           :payer (:pubkey-hex buyer1)
                           :receiver (:pubkey-hex gpu)
                           :amount 2000
                           :puzzle-hash royalty-p-hash
                           :puzzle-source royalty-split-puzzle-source
                           :solution royalty-solution
                           :created-epoch 3
                           :expires-epoch 10
                           :nonce "royalty-1"}
                 :multisig {:escrow-id multisig-escrow-id
                            :payer (:pubkey-hex buyer2)
                            :receiver (:pubkey-hex author)
                            :amount 1000
                            :puzzle-hash multisig-p-hash
                            :puzzle-source multisig-2of2-puzzle-source
                            :solution multisig-solution
                            :created-epoch 3
                            :expires-epoch 10
                            :nonce "multisig-1"}
                 :htlc {:escrow-id htlc-escrow-id
                        :payer (:pubkey-hex founder)
                        :receiver (:pubkey-hex gpu)
                        :amount 600
                        :deliverable-hash htlc-d-hash
                        :preimage htlc-preimage
                        :created-epoch 3
                        :expires-epoch 10
                        :nonce "htlc-1"}
                 :timeout {:escrow-id timeout-escrow-id
                           :payer (:pubkey-hex buyer1)
                           :receiver (:pubkey-hex challenger)
                           :amount 400
                           :deliverable-hash timeout-d-hash
                           :created-epoch 3
                           :expires-epoch 4
                           :nonce "timeout-1"}}}))

(defn compute-golden-expected-state
  "Pure Golden Oracle computing exact expected balance deltas, final light-node balances,
   escrow terminal statuses, royalty payouts, protocol burn/take totals, E2EE decrypted state,
   and capability CIDs for the 6-stage workload."
  ([] (compute-golden-expected-state (build-workload-scenario)))
  ([scenario]
   (let [topo (:topology scenario)
         ids (:identities-by-id topo)
         funder-pk (get-in ids [:treasury-funder :pubkey-hex])
         founder-pk (get-in ids [:subnet-founder :pubkey-hex])
         author-pk (get-in ids [:kernel-author :pubkey-hex])
         gpu-pk (get-in ids [:gpu-provider :pubkey-hex])
         oracle-pk (get-in ids [:oracle-verifier :pubkey-hex])
         buyer1-pk (get-in ids [:agent-buyer-1 :pubkey-hex])
         buyer2-pk (get-in ids [:agent-buyer-2 :pubkey-hex])
         challenger-pk (get-in ids [:byzantine-challenger :pubkey-hex])

         ;; Protocol settlement take calculation (50 bps = 0.5%, floor 1):
         ;; Direct settle-intent (founder -> oracle, 2000):
         direct-settle-take (burn/calculate-settlement-take 2000 burn/default-settlement-take-bps) ;; 10
         direct-settle-net (- 2000 direct-settle-take) ;; 1990

         ;; Contract 1 (Royalty split 1500 / 300 / 200):
         gpu-royalty-take (escrow/calculate-escrow-settlement-take 1500) ;; 7
         gpu-royalty-net (- 1500 gpu-royalty-take) ;; 1493
         author-royalty-take (escrow/calculate-escrow-settlement-take 300) ;; 1
         author-royalty-net (- 300 author-royalty-take) ;; 299
         founder-royalty-take (escrow/calculate-escrow-settlement-take 200) ;; 1
         founder-royalty-net (- 200 founder-royalty-take) ;; 199
         royalty-total-take (+ gpu-royalty-take author-royalty-take founder-royalty-take) ;; 9

         ;; Contract 2 (2-of-2 Multisig 1000 -> author):
         multisig-take (escrow/calculate-escrow-settlement-take 1000) ;; 5
         multisig-net (- 1000 multisig-take) ;; 995

         ;; Contract 3 (HTLC 600 -> gpu):
         htlc-take (escrow/calculate-escrow-settlement-take 600) ;; 3
         htlc-net (- 600 htlc-take) ;; 597

         ;; Voucher debits & burns:
         ;; voucher1: buyer1 -> ns1, debit = 100 (burn 0.5% = 0 on integer quot 100*50/10000 = 0, net 100)
         ;; voucher2: buyer2 -> ns2, debit = 150 (burn 0, net 150)
         voucher1-debit 100
         voucher2-debit 150

         ;; Signaling burns:
         ;; founder burns 500, author burns 300 -> total 800
         signaling-burn-founder 500
         signaling-burn-author 300

         ;; Exact net balance deltas for all 8 light-node identities:
         ;; 1. treasury-funder: -50000 (tx1) -30000 (tx2) = -80000
         funder-delta -80000
         ;; 2. subnet-founder: -2000 (settle-intent) -500 (burn) -600 (htlc lock) +199 (royalty split) = -2901
         founder-delta (+ -2000 (- signaling-burn-founder) -600 founder-royalty-net)
         ;; 3. kernel-author: +10000 (tx3) -300 (burn) +299 (royalty split) +995 (multisig release) = +10994
         author-delta (+ 10000 (- signaling-burn-author) author-royalty-net multisig-net)
         ;; 4. gpu-provider: +1493 (royalty split) +597 (htlc release) = +2090
         gpu-delta (+ gpu-royalty-net htlc-net)
         ;; 5. oracle-verifier: +1990 (settle-intent net) = +1990
         oracle-delta direct-settle-net
         ;; 6. agent-buyer-1: +50000 (tx1) -10000 (tx3) -100 (voucher1) -2000 (royalty lock) -400 (timeout lock) +400 (timeout refund) = +37900
         buyer1-delta (+ 50000 -10000 (- voucher1-debit) -2000 -400 400)
         ;; 7. agent-buyer-2: +30000 (tx2) -150 (voucher2) -1000 (multisig lock) = +28850
         buyer2-delta (+ 30000 (- voucher2-debit) -1000)
         ;; 8. byzantine-challenger: 0 (all 7 adversarial intents rejected, timeout escrow refunded to buyer1)
         challenger-delta 0

         deltas-by-id {:treasury-funder funder-delta
                       :subnet-founder founder-delta
                       :kernel-author author-delta
                       :gpu-provider gpu-delta
                       :oracle-verifier oracle-delta
                       :agent-buyer-1 buyer1-delta
                       :agent-buyer-2 buyer2-delta
                       :byzantine-challenger challenger-delta}
         deltas-by-pubkey {funder-pk funder-delta
                           founder-pk founder-delta
                           author-pk author-delta
                           gpu-pk gpu-delta
                           oracle-pk oracle-delta
                           buyer1-pk buyer1-delta
                           buyer2-pk buyer2-delta
                           challenger-pk challenger-delta}
         expected-balances-by-pubkey
         (into {}
               (map (fn [[id-kw spec]]
                      (let [pk (:pubkey-hex spec)]
                        [pk (+ (:initial-balance spec) (get deltas-by-id id-kw))]))
                    ids))
         contracts (:contracts scenario)]
     {:deltas-by-id deltas-by-id
      :deltas-by-pubkey deltas-by-pubkey
      :expected-balances-by-pubkey expected-balances-by-pubkey
      :escrow-statuses {(get-in contracts [:royalty :escrow-id]) :released
                        (get-in contracts [:multisig :escrow-id]) :released
                        (get-in contracts [:htlc :escrow-id]) :released
                        (get-in contracts [:timeout :escrow-id]) :refunded}
      :royalty-payouts {:gpu-provider gpu-royalty-net
                        :kernel-author author-royalty-net
                        :subnet-founder founder-royalty-net
                        :total-take royalty-total-take}
      :total-signaling-burns (+ signaling-burn-founder signaling-burn-author)
      :total-settlement-takes (+ direct-settle-take royalty-total-take multisig-take htlc-take)
      :subnets-valid? (get-in scenario [:subnets :all-anchors-valid?])
      :anchored-grandchild-root (get-in scenario [:subnets :anchored-grandchild-root])
      :anchored-child-root (get-in scenario [:subnets :anchored-child-root])
      :e2ee-valid? (get-in scenario [:storage :e2ee-valid?])
      :e2ee-decrypted (get-in scenario [:storage :e2ee-decrypted])
      :capabilities (get-in scenario [:storage :capabilities])
      :capabilities-valid? (get-in scenario [:storage :capabilities-valid?])
      :tensor-deliverable-hash (get-in scenario [:stream :deliverable-hash])
      :expected-adversarial-rejections 7})))
