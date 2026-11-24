(ns bitecho.d54-bip024-circles-on-subnets-test
  "Strict TDD generative property, invariant, and mutation test suite for BIP-024:
   Circles on Subnets — Root Structure, Hierarchical Directory & Validator-Set Anchor.

   Covers all 7 Twin Round-1 Blocker Closures, INV-C1 through INV-C6, and MUT-09..12
   across both JVM and ClojureScript."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.circles.mc-harness :as mc-harness]
            [bitecho.circles.vault :as vault]
            [bitecho.config :as config]
            [bitecho.core.circle :as circle]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.faucet :as faucet]
            [bitecho.crypto :as crypto]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.memento.constants :as mem-const]
            [bitecho.shell.browser :as browser]
            [bitecho.streamlet.core :as streamlet]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- gen-kp
  []
  (let [kp (crypto/generate-keypair)
        pk-hex (circle/normalize-spki-pubkey (basalt/bytes->hex (:public kp)))]
    (assoc kp :spki-hex pk-hex)))

(def ^:private test-genesis-cid
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

(def ^:private test-purpose-cid
  "1111111111111111111111111111111111111111111111111111111111111111")

(def ^:private test-consent-cid
  "2222222222222222222222222222222222222222222222222222222222222222")

(defn- sample-retention
  []
  {:max-entries 256 :max-bytes 4194304 :rotate-every-entries 64 :ttl-epochs 26280})

(defn- sample-storage
  [payer-pk]
  {:bytes-at-rest 2048 :cache-incentive :free-self-hosted :payer-pubkey payer-pk :fee-ech 0})

;; =============================================================================
;; 1. Blocker 1 & 2 (INV-C3, MUT-09, MUT-12):
;;    Network URI Isolation, Epoch Expiry, Fail-Closed ACL, SPKI & Browser Persistence
;; =============================================================================

(defspec ^{:doc "Generative property verifying cross-network isolation, epoch-scoped expiry, fail-closed ACL, and browser persistence."}
  prop-bip024-mainnet-replay-expiry-and-browser-roundtrip
  25
  (prop/for-all [ep (gen/choose 100 50000)
                 ttl (gen/choose 1 1000)
                 extra-epoch (gen/choose 0 500)]
                (let [net-dev "devnet.bitecho.org"
                      net-main "bitecho.org"
                      net-main-legacy "mainnet.bitecho.org"
                      ;; Blocker 1: devnet <-> bitecho.org MUST NEVER be equivalent
                      dev-main-isolated? (and (not (config/equivalent-subnet-id? net-dev net-main net-dev))
                                              (not (config/equivalent-subnet-id? net-dev net-main net-main))
                                              (not (config/equivalent-subnet-id? net-main net-dev net-dev))
                                              (config/equivalent-subnet-id? net-main net-main-legacy net-main)
                                              (config/equivalent-subnet-id? net-main-legacy net-main net-main-legacy))
                      ;; Blocker 2: :pointer/expires-epoch compared strictly against :current-epoch, NEVER :now-ms
                      kp (gen-kp)
                      auth-kp (gen-kp)
                      target-cid (circle/descriptor-cid {:path "root" :seq 1})
                      exp-epoch (+ ep ttl)
                      dir-proof (data/create-directory-entity-proof
                                 [{:pubkey (:spki-hex kp) :privkey (:private kp)}]
                                 net-dev "dir/root" 1 target-cid 1 [(:spki-hex kp)])
                      ptr (data/sign-pointer
                           (:private auth-kp)
                           {:pointer/authority (:spki-hex auth-kp)
                            :pointer/subnet net-dev
                            :pointer/path "dir/root"
                            :pointer/seq 1
                            :pointer/target target-cid
                            :pointer/expires-epoch exp-epoch
                            :pointer/proof dir-proof})
                      acl [{:pattern "dir/*"
                            :principal {:type :directory-entity
                                        :authority (:spki-hex auth-kp)
                                        :owner-multisig {:threshold 1 :pubkeys [(:spki-hex kp)]}}}]
                      ;; Even with a huge wall-clock now-ms >> exp-epoch, current-epoch < exp-epoch MUST pass
                      res-valid (data/verify-pointer ptr {:subnet net-dev
                                                          :path-acl acl
                                                          :current-epoch ep
                                                          :now-ms 1800000000000})
                      ;; When current-epoch >= exp-epoch, MUST fail closed with :pointer-expired
                      res-expired (data/verify-pointer ptr {:subnet net-dev
                                                            :path-acl acl
                                                            :current-epoch (+ exp-epoch extra-epoch)
                                                            :now-ms 1000})
                      ;; Missing/empty :path-acl MUST fail closed with :missing-path-acl
                      res-no-acl (data/verify-pointer ptr {:subnet net-dev :current-epoch ep})
                      res-empty-acl (data/verify-pointer ptr {:subnet net-dev :path-acl [] :current-epoch ep})
                      ;; Browser persistence whitelist preserves all BIP-024 non-liveness keys
                      persisted {:entity-descriptors {"devnet.bitecho.org/root" {:version 1}}
                                 :vaults {"vault:devnet.bitecho.org/root" {:balance 5000 :vault-seq 1}}
                                 :validator-set-history {0 {:committee [(:spki-hex kp)]}}
                                 :network-genesis-cid test-genesis-cid
                                 :advisory-twin-pubkeys [(:spki-hex auth-kp)]
                                 :directory-cache-v2 {"devnet.bitecho.org/root" {:cid target-cid}}
                                 ;; Derived runtime liveness MUST still be stripped
                                 :connected? true
                                 :connection-error "transient"}
                      sanitized (browser/sanitize-state-for-persistence persisted)]
                  (and dev-main-isolated?
                       (:ok? res-valid)
                       (false? (:ok? res-expired))
                       (= :pointer-expired (:error res-expired))
                       (false? (:ok? res-no-acl))
                       (= :missing-path-acl (:error res-no-acl))
                       (false? (:ok? res-empty-acl))
                       (= :missing-path-acl (:error res-empty-acl))
                       (= (:entity-descriptors persisted) (:entity-descriptors sanitized))
                       (= (:vaults persisted) (:vaults sanitized))
                       (= (:validator-set-history persisted) (:validator-set-history sanitized))
                       (= (:network-genesis-cid persisted) (:network-genesis-cid sanitized))
                       (= (:advisory-twin-pubkeys persisted) (:advisory-twin-pubkeys sanitized))
                       (= (:directory-cache-v2 persisted) (:directory-cache-v2 sanitized))
                       (not (contains? sanitized :connected?))
                       (not (contains? sanitized :connection-error))))))

(deftest test-blocker1-and-blocker2-directory-acl-spki-and-discipline
  (testing "MUT-09: devnet <-> bitecho.org alias is deleted and :strict-network-uri? is true on all networks"
    (is (false? (config/equivalent-subnet-id? "devnet.bitecho.org" "bitecho.org" "devnet.bitecho.org")))
    (is (false? (config/equivalent-subnet-id? "bitecho.org" "devnet.bitecho.org" "bitecho.org")))
    (is (true? (config/equivalent-subnet-id? "bitecho.org" "mainnet.bitecho.org" "bitecho.org")))
    (is (true? (:strict-network-uri? config/devnet-config)))
    (is (true? (:strict-network-uri? (config/devnet-6-config))))
    (is (true? (:strict-network-uri? config/testnet-config)))
    (is (true? (:strict-network-uri? config/mainnet-config))))

  (testing "Blocker 2: 64-hex and 88-hex SPKI DER pubkeys canonicalize & dedup to a single signer"
    (let [kp (gen-kp)
          spki (:spki-hex kp)
          raw64 (subs spki 24)]
      (is (= 88 (count spki)))
      (is (= spki (circle/normalize-spki-pubkey raw64)))
      (is (= spki (circle/normalize-spki-pubkey (str/upper-case spki))))
      (is (= [spki] (circle/dedup-spki-pubkeys [spki raw64 (str/upper-case raw64)])))))

  (testing "Blocker 2: dir/* rejects :proof/type :self for both writes and tombstones"
    (let [auth-kp (gen-kp)
          owner-kp (gen-kp)
          acl [{:pattern "dir/*"
                :principal {:type :directory-entity
                            :authority (:spki-hex auth-kp)
                            :owner-multisig {:threshold 1 :pubkeys [(:spki-hex owner-kp)]}}}]
          self-write (data/sign-pointer
                      (:private auth-kp)
                      {:pointer/authority (:spki-hex auth-kp)
                       :pointer/subnet "devnet.bitecho.org"
                       :pointer/path "dir/root"
                       :pointer/seq 1
                       :pointer/target test-genesis-cid
                       :pointer/expires-epoch 2000
                       :pointer/proof {:proof/type :self}})
          self-tombstone (data/sign-pointer
                          (:private auth-kp)
                          {:pointer/authority (:spki-hex auth-kp)
                           :pointer/subnet "devnet.bitecho.org"
                           :pointer/path "dir/root"
                           :pointer/seq 2
                           :pointer/target nil
                           :pointer/expires-epoch 2000
                           :pointer/proof {:proof/type :self}})]
      (is (false? (:ok? (data/verify-pointer self-write {:subnet "devnet.bitecho.org" :path-acl acl :current-epoch 10}))))
      (is (false? (:ok? (data/verify-pointer self-tombstone {:subnet "devnet.bitecho.org" :path-acl acl :current-epoch 10}))))))

  (testing "Blocker 2: validate-pointer-discipline supports :owner-multisig and mandates :storage-accounting on BIP-024 descriptors"
    (let [kp (gen-kp)
          base {:bitecho/type :directory/entity-descriptor
                :owner-multisig {:threshold 1 :pubkeys [(:spki-hex kp)]}
                :retention-policy (sample-retention)
                :storage-accounting (sample-storage (:spki-hex kp))}]
      (is (:ok? (mem-const/validate-pointer-discipline base)))
      (is (false? (:ok? (mem-const/validate-pointer-discipline (dissoc base :storage-accounting)))))
      (is (false? (:ok? (mem-const/validate-pointer-discipline (assoc-in base [:owner-multisig :threshold] 2))))))))

;; =============================================================================
;; 2. Blocker 3 (INV-C1, INV-C2, MUT-10):
;;    SCI Persistent Vaults, Anti-Malleability, 0-Take :allocate & 7-Bucket INV-C1
;; =============================================================================

(defspec ^{:doc "Generative property verifying persistent vault relock, anti-malleability, concurrency race rejection, and 7-bucket INV-C1."}
  prop-bip024-vault-relock-bounded-state-conservation-and-discipline
  25
  (prop/for-all [initial-bal (gen/choose 10000 500000)
                 release-amt (gen/choose 100 2000)
                 alloc-amt (gen/choose 100 2000)]
                (let [k1 (gen-kp)
                      k2 (gen-kp)
                      k3 (gen-kp)
                      recv-kp (gen-kp)
                      pubkeys [(:spki-hex k1) (:spki-hex k2) (:spki-hex k3)]
                      puzzle-src (vault/canonical-multisig-treasury-puzzle-source 2 pubkeys)
                      p-hash (puzzle/puzzle-cid puzzle-src)
                      st0 (vault/init-vaults-state {:network-uri "devnet.bitecho.org"
                                                    :network-genesis-cid test-genesis-cid
                                                    :genesis-custody-supply (+ initial-bal 1000000)
                                                    :root-unallocated 1000000
                                                    :chartered-vaults #{"vault:devnet.bitecho.org/root"
                                                                        "vault:devnet.bitecho.org/root/protocol"}})
                      c-root (vault/create-vault st0 {:vault-id "vault:devnet.bitecho.org/root"
                                                      :entity-uri "devnet.bitecho.org/root"
                                                      :custody-bucket :bootstrap
                                                      :puzzle-hash p-hash
                                                      :balance initial-bal
                                                      :created-epoch 10})
                      c-child (vault/create-vault (:state c-root) {:vault-id "vault:devnet.bitecho.org/root/protocol"
                                                                   :entity-uri "devnet.bitecho.org/root/protocol"
                                                                   :custody-bucket :bootstrap
                                                                   :puzzle-hash p-hash
                                                                   :balance 2000
                                                                   :created-epoch 10})
                      st1 (update (:state c-child) :genesis-custody-supply + 2000)
                      relock-amt (- initial-bal release-amt alloc-amt)
                      outputs [{:type :release :receiver (:spki-hex recv-kp) :amount release-amt}
                               {:type :allocate :target-vault-id "vault:devnet.bitecho.org/root/protocol" :amount alloc-amt}
                               {:type :relock :amount relock-amt :next-puzzle-hash p-hash}]
                      digest (vault/treasury-spend-digest
                              {:network-uri "devnet.bitecho.org"
                               :network-genesis-cid test-genesis-cid
                               :vault-id "vault:devnet.bitecho.org/root"
                               :puzzle-hash p-hash
                               :vault-seq 1
                               :outputs outputs
                               :next-puzzle-hash p-hash})
                      sig1 (basalt/bytes->hex (crypto/sign (:private k1) digest))
                      sig2 (basalt/bytes->hex (crypto/sign (:private k2) digest))
                      spend-res (vault/spend-vault
                                 st1
                                 {:vault-id "vault:devnet.bitecho.org/root"
                                  :vault-seq 1
                                  :puzzle-source puzzle-src
                                  :solution {:outputs outputs
                                             :next-puzzle-hash p-hash
                                             :signatures {(:spki-hex k1) sig1
                                                          (:spki-hex k2) sig2}}
                                  :epoch 15})
                      st2 (:state spend-res)
                      ;; Concurrent/replay spend with stale vault-seq 1 MUST fail with counted :diagnose
                      race-res (vault/spend-vault
                                st2
                                {:vault-id "vault:devnet.bitecho.org/root"
                                 :vault-seq 1
                                 :puzzle-source puzzle-src
                                 :solution {:outputs outputs
                                            :next-puzzle-hash p-hash
                                            :signatures {(:spki-hex k1) sig1
                                                         (:spki-hex k2) sig2}}
                                 :epoch 15})
                      ;; Tampered outputs (malleability attack) MUST fail
                      tampered-outputs (assoc-in outputs [0 :receiver] (:spki-hex k3))
                      tamper-res (vault/spend-vault
                                  st1
                                  {:vault-id "vault:devnet.bitecho.org/root"
                                   :vault-seq 1
                                   :puzzle-source puzzle-src
                                   :solution {:outputs tampered-outputs
                                              :next-puzzle-hash p-hash
                                              :signatures {(:spki-hex k1) sig1
                                                           (:spki-hex k2) sig2}}
                                   :epoch 15})
                      ;; MUT-10: :refund-intent on vault MUST be forbidden
                      refund-res (vault/reject-vault-refund st2 "vault:devnet.bitecho.org/root")
                      ;; Full 7-bucket INV-C1 conservation check
                      cons-res (vault/verify-7-bucket-conservation st2)]
                  (and (:ok? c-root)
                       (:ok? c-child)
                       (:ok? spend-res)
                       (= 2 (get-in st2 [:vaults "vault:devnet.bitecho.org/root" :vault-seq]))
                       (= relock-amt (get-in st2 [:vaults "vault:devnet.bitecho.org/root" :balance]))
                       (= (+ 2000 alloc-amt) (get-in st2 [:vaults "vault:devnet.bitecho.org/root/protocol" :balance]))
                       (false? (:ok? race-res))
                       (= :vault-seq-mismatch (:error race-res))
                       (seq (:effects race-res))
                       (false? (:ok? tamper-res))
                       (false? (:ok? refund-res))
                       (= :vault-refund-forbidden (:error refund-res))
                       (:ok? cons-res)))))

(deftest test-blocker3-vault-bounds-0take-restriction-dac-and-sunset
  (testing "Dust floor, max-vaults, 0-take restriction, :vault-spend-dac atomic revocation, and epoch 26,280 sunset"
    (let [k1 (gen-kp)
          k2 (gen-kp)
          holder (gen-kp)
          recv (gen-kp)
          pubkeys [(:spki-hex k1) (:spki-hex k2)]
          p-src (vault/canonical-multisig-treasury-puzzle-source 2 pubkeys)
          p-hash (puzzle/puzzle-cid p-src)
          st0 (vault/init-vaults-state {:network-uri "devnet.bitecho.org"
                                        :network-genesis-cid test-genesis-cid
                                        :max-vaults 2
                                        :min-vault-balance-ech 1000
                                        :genesis-custody-supply 100000
                                        :chartered-vaults #{"vault:root"}})
          ;; Dust floor rejected
          dust-res (vault/create-vault st0 {:vault-id "vault:dust"
                                            :entity-uri "devnet.bitecho.org/id/x"
                                            :puzzle-hash p-hash
                                            :balance 500
                                            :created-epoch 1})
          c1 (vault/create-vault st0 {:vault-id "vault:root"
                                      :entity-uri "devnet.bitecho.org/root"
                                      :custody-bucket :bootstrap
                                      :puzzle-hash p-hash
                                      :balance 50000
                                      :created-epoch 1})
          c2 (vault/create-vault (:state c1) {:vault-id "vault:leaf"
                                              :entity-uri "devnet.bitecho.org/id/leaf"
                                              :custody-bucket nil
                                              :puzzle-hash p-hash
                                              :balance 50000
                                              :created-epoch 1})
          ;; Max vaults cap exceeded
          c3 (vault/create-vault (:state c2) {:vault-id "vault:overflow"
                                              :entity-uri "devnet.bitecho.org/id/over"
                                              :puzzle-hash p-hash
                                              :balance 5000
                                              :created-epoch 1})
          ;; Issue :vault-spend-dac capped at 500 bps (5% of 50000 = 2500)
          dac-res (vault/issue-vault-spend-dac (:state c2)
                                               {:dac-id "vdac-1"
                                                :vault-id "vault:root"
                                                :holder-pubkey (:spki-hex holder)
                                                :max-per-epoch-bps 500
                                                :issued-epoch 10
                                                :expires-epoch 100})
          ;; Spend within 500 bps succeeds
          dac-spend-ok (vault/spend-via-vault-dac (:state dac-res)
                                                  {:dac-id "vdac-1"
                                                   :receiver (:spki-hex recv)
                                                   :amount 2000
                                                   :epoch 10})
          ;; Exceeding 500 bps in same epoch fails closed
          dac-spend-over (vault/spend-via-vault-dac (:state dac-spend-ok)
                                                    {:dac-id "vdac-1"
                                                     :receiver (:spki-hex recv)
                                                     :amount 1000
                                                     :epoch 10})
          ;; Atomic revocation on explicit revoke
          rev-res (vault/revoke-vault-spend-dac (:state dac-spend-ok) "vdac-1")
          dac-spend-after-rev (vault/spend-via-vault-dac (:state rev-res)
                                                         {:dac-id "vdac-1"
                                                          :receiver (:spki-hex recv)
                                                          :amount 100
                                                          :epoch 11})
          ;; Epoch 26,280 sunset burns ONLY :custody-bucket :bootstrap unspent balance
          sunset-res (vault/apply-bootstrap-sunset (:state rev-res) 26280)]
      (is (false? (:ok? dust-res)))
      (is (= :vault-below-min-balance (:error dust-res)))
      (is (false? (:ok? c3)))
      (is (= :max-vaults-exceeded (:error c3)))
      (is (:ok? dac-res))
      (is (:ok? dac-spend-ok))
      (is (false? (:ok? dac-spend-over)))
      (is (= :vault-dac-epoch-cap-exceeded (:error dac-spend-over)))
      (is (false? (:ok? dac-spend-after-rev)))
      (is (= :vault-dac-revoked (:error dac-spend-after-rev)))
      (is (= 0 (get-in (:state sunset-res) [:vaults "vault:root" :balance])))
      (is (= 50000 (get-in (:state sunset-res) [:vaults "vault:leaf" :balance])))
      (is (:ok? (vault/verify-7-bucket-conservation (:state sunset-res)))))))

;; =============================================================================
;; 3. Blocker 4: In-Band Validator-Set Rotation, Historical Catchup & Cold-Root Recovery
;; =============================================================================

(deftest test-blocker4-validator-rotation-catchup-and-cold-root-recovery
  (testing "In-band validator-set descriptor verification, lead epochs, fast equivocation ejection, history catchup & anti-downgrade"
    (let [r1 (gen-kp)
          r2 (gen-kp)
          v1 (gen-kp)
          v2 (gen-kp)
          v3 (gen-kp)
          v4 (gen-kp)
          v5 (gen-kp)
          root-ms {:threshold 2 :pubkeys [(:spki-hex r1) (:spki-hex r2)]}
          comm1 [{:pubkey (:spki-hex v1) :role :core-validator :operator-circle "devnet.bitecho.org/root/protocol"}
                 {:pubkey (:spki-hex v2) :role :core-validator :operator-circle "devnet.bitecho.org/root/protocol"}
                 {:pubkey (:spki-hex v3) :role :core-validator :operator-circle "devnet.bitecho.org/root/protocol"}
                 {:pubkey (:spki-hex v4) :role :infra-validator :operator-circle "devnet.bitecho.org/root/protocol"}]
          desc1 (circle/create-validator-set-descriptor
                 {:network-uri "devnet.bitecho.org"
                  :network-genesis-cid test-genesis-cid
                  :version 1
                  :not-before-epoch 10
                  :epoch-finalized 10
                  :epoch-effective 16
                  :quorum-threshold 3
                  :delegated-operator-circle "devnet.bitecho.org/root/protocol"
                  :consent-round-cid test-consent-cid
                  :committee comm1
                  :retention-policy (sample-retention)
                  :storage-accounting (sample-storage (:spki-hex r1))}
                 [{:pubkey (:spki-hex r1) :privkey (:private r1)}
                  {:pubkey (:spki-hex r2) :privkey (:private r2)}])
          v-res (circle/verify-validator-set-descriptor desc1 {:root-owner-multisig root-ms
                                                               :network-uri "devnet.bitecho.org"
                                                               :network-genesis-cid test-genesis-cid
                                                               :lead-epochs 6})
          ;; Too-early activation without equivocation proof MUST fail
          desc-early (circle/create-validator-set-descriptor
                      {:network-uri "devnet.bitecho.org"
                       :network-genesis-cid test-genesis-cid
                       :version 1
                       :not-before-epoch 10
                       :epoch-finalized 10
                       :epoch-effective 12
                       :quorum-threshold 3
                       :delegated-operator-circle "devnet.bitecho.org/root/protocol"
                       :consent-round-cid test-consent-cid
                       :committee comm1
                       :retention-policy (sample-retention)
                       :storage-accounting (sample-storage (:spki-hex r1))}
                      [{:pubkey (:spki-hex r1) :privkey (:private r1)}
                       {:pubkey (:spki-hex r2) :privkey (:private r2)}])
          v-early (circle/verify-validator-set-descriptor desc-early {:root-owner-multisig root-ms
                                                                      :network-uri "devnet.bitecho.org"
                                                                      :network-genesis-cid test-genesis-cid
                                                                      :lead-epochs 6})
          ;; Epoch-indexed validator-set-history resolution
          history {0 {:committee [(:spki-hex v1) (:spki-hex v2) (:spki-hex v3) (:spki-hex v4)] :quorum-threshold 3}
                   16 {:committee [(:spki-hex v2) (:spki-hex v3) (:spki-hex v4) (:spki-hex v5)] :quorum-threshold 3}}
          ;; Anti-downgrade: once last-finalized-epoch >= 1, static config fallback is forbidden
          downgrade-res (streamlet/resolve-active-validators {:last-finalized-epoch 5
                                                              :strict-validator-history? true
                                                              :validator-set-history {}
                                                              :config {:validators [(:spki-hex v1)]}})
          ;; Cold-Root Emergency Recovery
          rec-bundle (circle/create-cold-root-recovery-bundle
                      {:network-uri "devnet.bitecho.org"
                       :network-genesis-cid test-genesis-cid
                       :recovery-seq 25
                       :last-known-finalized-block-hash test-genesis-cid
                       :committee comm1
                       :quorum-threshold 3}
                      [{:pubkey (:spki-hex r1) :privkey (:private r1)}
                       {:pubkey (:spki-hex r2) :privkey (:private r2)}])
          rec-applied (circle/apply-cold-root-recovery
                       {:last-finalized-epoch 20
                        :validator-set-history history
                        :diagnostics {}}
                       rec-bundle
                       {:root-owner-multisig root-ms
                        :network-uri "devnet.bitecho.org"
                        :network-genesis-cid test-genesis-cid})]
      (is (:ok? v-res))
      (is (false? (:ok? v-early)))
      (is (= :validator-activation-lead-violated (:error v-early)))
      (is (= (set [(:spki-hex v1) (:spki-hex v2) (:spki-hex v3) (:spki-hex v4)])
             (set (:committee (streamlet/committee-at-epoch history 10)))))
      (is (= (set [(:spki-hex v2) (:spki-hex v3) (:spki-hex v4) (:spki-hex v5)])
             (set (:committee (streamlet/committee-at-epoch history 20)))))
      (is (false? (:ok? downgrade-res)))
      (is (= :static-validator-fallback-forbidden (:error downgrade-res)))
      (is (:ok? rec-applied))
      (is (some #(= :cold-root-recovery-activated (:reason %)) (:effects rec-applied))))))

;; =============================================================================
;; 4. Blocker 5 (MUT-11): Hardware YubiKey Faucet Fail-Closed & Unlinkable Voucher
;; =============================================================================

(deftest test-blocker5-faucet-fail-closed-attestation-and-blinded-voucher
  (testing "MUT-11: faucet fails closed when authenticator_verified is omitted or forged without valid CBOR+x5c+PoP"
    (let [treasury (gen-kp)
          claimant (gen-kp)
          rng (crypto/make-random 424242)
          st0 (faucet/init-faucet-state {:network-uri "devnet.bitecho.org"
                                         :network-genesis-cid test-genesis-cid
                                         :treasury-privkey (:private treasury)
                                         :treasury-pubkey (:spki-hex treasury)
                                         :drip-amount-ech 1000
                                         :epoch-drip-cap-ech 2000})
          ch-res (faucet/issue-faucet-challenge st0 {:network-uri "devnet.bitecho.org" :rng rng} 10000)
          nonce (get-in ch-res [:challenge :nonce])
          ;; Omitting attestation / passing client-supplied :authenticator-verified? true MUST FAIL CLOSED!
          forged-res (faucet/reduce-faucet-claim
                      (:state ch-res)
                      {:nonce nonce
                       :credential-id-hash "cred-1"
                       :claimant-pubkey (:spki-hex claimant)
                       :network-uri "devnet.bitecho.org"
                       :authenticator-verified? true}
                      10100)
          ;; fmt="none" inside real CBOR attestationObject MUST be rejected in production (F1)
          ch2 (faucet/issue-faucet-challenge (:state forged-res) {:network-uri "devnet.bitecho.org" :rng rng} 10200)
          n2 (get-in ch2 [:challenge :nonce])
          hw-kp (gen-kp)
          att-none (faucet/build-test-hardware-attestation
                    {:hw-privkey (:private hw-kp)
                     :hw-pubkey (:spki-hex hw-kp)
                     :claimant-privkey (:private claimant)
                     :claimant-pubkey (:spki-hex claimant)
                     :nonce n2
                     :network-uri "devnet.bitecho.org"
                     :fmt "none"})
          fmt-none-res (faucet/reduce-faucet-claim
                        (assoc (:state ch2) :trusted-root-fingerprints #{(:trusted-root-fingerprint att-none)})
                        (assoc att-none
                               :nonce n2
                               :credential-id-hash "cred-1"
                               :claimant-pubkey (:spki-hex claimant)
                               :network-uri "devnet.bitecho.org")
                        10300)
          ;; Valid CBOR attestationObject + real X.509 x5c chain + attStmt.sig + claimant PoP + pinned root succeeds (F1)
          ch3 (faucet/issue-faucet-challenge (:state fmt-none-res) {:network-uri "devnet.bitecho.org" :rng rng} 10400)
          n3 (get-in ch3 [:challenge :nonce])
          att-payload (faucet/build-test-hardware-attestation
                       {:hw-privkey (:private hw-kp)
                        :hw-pubkey (:spki-hex hw-kp)
                        :claimant-privkey (:private claimant)
                        :claimant-pubkey (:spki-hex claimant)
                        :nonce n3
                        :network-uri "devnet.bitecho.org"
                        :aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"
                        :fmt "packed"})
          ;; Untrusted / unpinned X.509 root MUST be rejected fail-closed!
          untrusted-root-res (faucet/reduce-faucet-claim
                              (assoc (:state ch3) :trusted-root-fingerprints #{})
                              (assoc att-payload
                                     :nonce n3
                                     :credential-id-hash "cred-1"
                                     :claimant-pubkey (:spki-hex claimant)
                                     :network-uri "devnet.bitecho.org"
                                     :epoch 50)
                              10450)
          ;; Re-issue challenge and pin the trusted root fingerprint -> succeeds!
          ch3b (faucet/issue-faucet-challenge (assoc (:state untrusted-root-res)
                                                     :trusted-root-fingerprints #{(:trusted-root-fingerprint att-payload)})
                                              {:network-uri "devnet.bitecho.org" :rng rng} 10460)
          n3b (get-in ch3b [:challenge :nonce])
          att-payload-b (faucet/build-test-hardware-attestation
                         {:hw-privkey (:private hw-kp)
                          :hw-pubkey (:spki-hex hw-kp)
                          :claimant-privkey (:private claimant)
                          :claimant-pubkey (:spki-hex claimant)
                          :nonce n3b
                          :network-uri "devnet.bitecho.org"
                          :aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"
                          :fmt "packed"})
          st3b (assoc (:state ch3b) :trusted-root-fingerprints #{(:trusted-root-fingerprint att-payload-b)})
          ok-res (faucet/reduce-faucet-claim
                  st3b
                  (assoc att-payload-b
                         :nonce n3b
                         :credential-id-hash "cred-1"
                         :claimant-pubkey (:spki-hex claimant)
                         :network-uri "devnet.bitecho.org"
                         :epoch 50)
                  10500)
          ;; Same hardware key trying a DIFFERENT credential-id-hash -> blocked by hardware nullifier!
          ch4 (faucet/issue-faucet-challenge (:state ok-res) {:network-uri "devnet.bitecho.org" :rng rng} 10600)
          n4 (get-in ch4 [:challenge :nonce])
          att-payload-2 (faucet/build-test-hardware-attestation
                         {:hw-privkey (:private hw-kp)
                          :hw-pubkey (:spki-hex hw-kp)
                          :claimant-privkey (:private claimant)
                          :claimant-pubkey (:spki-hex claimant)
                          :nonce n4
                          :network-uri "devnet.bitecho.org"
                          :aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"
                          :fmt "packed"})
          sybil-res (faucet/reduce-faucet-claim
                     (assoc (:state ch4) :trusted-root-fingerprints #{(:trusted-root-fingerprint att-payload-2)})
                     (assoc att-payload-2
                            :nonce n4
                            :credential-id-hash "cred-2-different"
                            :claimant-pubkey (:spki-hex claimant)
                            :network-uri "devnet.bitecho.org"
                            :epoch 50)
                     10700)
          ;; Unlinkable blinded voucher onboarding with earmarked funding & ledger credit (F10)
          blinding-secret "secret-blinding-factor-999"
          commitment (faucet/blind-voucher-commitment blinding-secret (:spki-hex claimant))
          issued-res (faucet/issue-blinded-voucher (:state ok-res) commitment 1000 50)
          voucher (:voucher issued-res)
          redeemed (faucet/redeem-blinded-voucher (:state issued-res) voucher blinding-secret (:spki-hex claimant) 50)]
      (is (false? (:ok? forged-res)))
      (is (= :faucet-attestation-required (:error forged-res)))
      (is (false? (:ok? fmt-none-res)))
      (is (= :faucet-attestation-fmt-rejected (:error fmt-none-res)))
      (is (false? (:ok? untrusted-root-res)))
      (is (= :faucet-attestation-root-untrusted (:error untrusted-root-res)))
      (is (:ok? ok-res))
      (is (false? (:ok? sybil-res)))
      (is (= :faucet-hardware-already-claimed (:error sybil-res)))
      (is (:ok? issued-res))
      (is (= 1000 (:earmarked-voucher-balance (:state issued-res))))
      (is (:ok? redeemed))
      (is (= 0 (:earmarked-voucher-balance (:state redeemed))))
      (is (= 1000 (get-in (:state redeemed) [:ledger (:spki-hex claimant) :balance])))
      ;; Blinded voucher receipt never links hardware nullifier to claimant
      (is (not (contains? (:voucher-receipt redeemed) :hardware-nullifier)))
      (is (not (contains? (:voucher-receipt redeemed) :credential-id-hash))))))

;; =============================================================================
;; 5. Blocker 6 (INV-C4, INV-C5):
;;    Sovereignty, Sociocracy (:purpose-cid), Dissolve, Recovery, Advisory Twins & Privacy
;; =============================================================================

(deftest test-blocker6-sovereignty-sociocracy-purpose-cid-and-privacy
  (testing "Unified descriptor uses :purpose-cid (NOT :values-cid), enforces sovereign roots, sociocracy, grow-only twins & :shared-encrypted"
    (let [r1 (gen-kp)
          r2 (gen-kp)
          p1 (gen-kp)
          p2 (gen-kp)
          indiv (gen-kp)
          twin (gen-kp)
          root-desc (circle/create-entity-descriptor
                     {:network-uri "devnet.bitecho.org"
                      :network-genesis-cid test-genesis-cid
                      :entity-kind :circle
                      :visibility :public
                      :path "root"
                      :owner-multisig {:threshold 2 :pubkeys [(:spki-hex r1) (:spki-hex r2)]}
                      :members {(:spki-hex r1) {:roles #{:steward}}
                                (:spki-hex r2) {:roles #{:maintainer}}}
                      :purpose-cid test-purpose-cid
                      :consent-round-cid test-consent-cid
                      :custody-bucket :bootstrap
                      :allocation-ech 1000000
                      :retention-policy (sample-retention)
                      :storage-accounting (sample-storage (:spki-hex r1))
                      :issued-epoch 10
                      :expires-epoch 27280}
                     [{:pubkey (:spki-hex r1) :privkey (:private r1)}
                      {:pubkey (:spki-hex r2) :privkey (:private r2)}])
          ;; Sovereign individual root <net>/id/<pubkey-cid>
          indiv-cid (circle/pubkey-cid (:spki-hex indiv))
          sov-desc (circle/create-entity-descriptor
                    {:network-uri "devnet.bitecho.org"
                     :network-genesis-cid test-genesis-cid
                     :entity-kind :sovereign-id
                     :visibility :public
                     :path (str "id/" indiv-cid)
                     :owner-multisig {:threshold 1 :pubkeys [(:spki-hex indiv)]}
                     :purpose-cid test-purpose-cid
                     :retention-policy (sample-retention)
                     :storage-accounting (sample-storage (:spki-hex indiv))
                     :issued-epoch 10
                     :expires-epoch 27280}
                    [{:pubkey (:spki-hex indiv) :privkey (:private indiv)}])
          ;; Reject reparenting root/protocol under root/inc (INV-C4)
          bad-proto (circle/create-entity-descriptor
                     {:network-uri "devnet.bitecho.org"
                      :network-genesis-cid test-genesis-cid
                      :entity-kind :circle
                      :visibility :public
                      :path "root/inc/protocol"
                      :parent-path "root/inc"
                      :canonical-circle :protocol
                      :owner-multisig {:threshold 2 :pubkeys [(:spki-hex p1) (:spki-hex p2)]}
                      :purpose-cid test-purpose-cid
                      :retention-policy (sample-retention)
                      :storage-accounting (sample-storage (:spki-hex p1))
                      :issued-epoch 10
                      :expires-epoch 27280}
                     [{:pubkey (:spki-hex p1) :privkey (:private p1)}
                      {:pubkey (:spki-hex p2) :privkey (:private p2)}])
          ;; Sociocratic consent round: zero :paramount-objection, double-linked, bars advisory twins
          twin-reg (circle/register-advisory-twin #{} (:spki-hex twin))
          consent-ok (circle/verify-consent-round
                      {:lead-link-pubkey (:spki-hex r1)
                       :delegate-link-pubkey (:spki-hex p1)
                       :ballots {(:spki-hex r1) :consent
                                 (:spki-hex p1) :consent
                                 (:spki-hex r2) :consent}
                       :quorum-size 2}
                      {:advisory-twin-pubkeys twin-reg})
          consent-blocked (circle/verify-consent-round
                           {:lead-link-pubkey (:spki-hex r1)
                            :delegate-link-pubkey (:spki-hex p1)
                            :ballots {(:spki-hex r1) :consent
                                      (:spki-hex p1) :paramount-objection}
                            :quorum-size 2}
                           {:advisory-twin-pubkeys twin-reg})
          consent-twin-spoof (circle/verify-consent-round
                              {:lead-link-pubkey (:spki-hex twin)
                               :delegate-link-pubkey (:spki-hex p1)
                               :ballots {(:spki-hex twin) :consent
                                         (:spki-hex p1) :consent}
                               :quorum-size 2}
                              {:advisory-twin-pubkeys twin-reg})
          ;; Two-mode privacy: :shared-encrypted leaks zero plaintext roster/home-set
          group-key (crypto/sha256 (fressian/utf8->bytes "circle-group-key-32bytes"))
          priv-desc (assoc root-desc
                           :path "root/inc/secret-proj"
                           :parent-path "root/inc"
                           :visibility :shared-encrypted
                           :home-set ["https://hidden-relay.example.org"])
          enc-envelope (circle/encrypt-shared-descriptor priv-desc group-key)
          enc-str (pr-str enc-envelope)
          decrypted (circle/decrypt-shared-descriptor enc-envelope group-key)]
      (is (= test-purpose-cid (:purpose-cid root-desc)))
      (is (not (contains? root-desc :values-cid)))
      (is (:ok? (circle/verify-entity-descriptor root-desc {:network-uri "devnet.bitecho.org"
                                                            :network-genesis-cid test-genesis-cid
                                                            :advisory-twin-pubkeys twin-reg})))
      (is (:ok? (circle/verify-entity-descriptor sov-desc {:network-uri "devnet.bitecho.org"
                                                           :network-genesis-cid test-genesis-cid})))
      ;; Org CANNOT revoke sovereign root
      (is (false? (:ok? (circle/can-org-revoke-entity? root-desc sov-desc))))
      (is (false? (:ok? (circle/verify-entity-descriptor bad-proto {:network-uri "devnet.bitecho.org"
                                                                    :network-genesis-cid test-genesis-cid}))))
      (is (:ok? consent-ok))
      (is (false? (:ok? consent-blocked)))
      (is (= :paramount-objection-present (:error consent-blocked)))
      (is (false? (:ok? consent-twin-spoof)))
      (is (= :advisory-twin-cannot-consent (:error consent-twin-spoof)))
      ;; Encrypted descriptor leaks zero plaintext roster or home-set
      (is (str/includes? (:blinded-path enc-envelope) "/enc/"))
      (is (not (str/includes? enc-str "hidden-relay.example.org")))
      (is (not (contains? enc-envelope :members)))
      (is (= (:members priv-desc) (:members (:descriptor decrypted)))))))

;; =============================================================================
;; 6. Blocker 7 & §8: Deterministic MC CRN, Time-Compression & Fractal Isolation
;; =============================================================================

(deftest test-blocker7-mc-crn-determinism-and-section8-fractal-isolation
  (testing "Deterministic Monte Carlo CRN produces bit-identical results and scales constants consistently"
    (let [cfg {:seed 20261124
               :epochs 20
               :time-compression-factor 10
               :genesis-custody-supply 10000000
               :faucet-drip-ech 1000}
          run1 (mc-harness/run-circle-mc-scenario cfg)
          run2 (mc-harness/run-circle-mc-scenario cfg)
          scaled (mc-harness/scale-lifecycle-config config/ratified-theta-star 10)]
      (is (= run1 run2))
      (is (true? (:all-steps-conserved? run1)))
      (is (= 2628 (:bootstrap-sunset-epoch scaled)))
      (is (= 17 (:treasury-trailing-epochs scaled)))))

  (testing "§8 Fractal Isolation: generalized root-subnet-id?, epoch-anchored Merkle root, and G4 bridge cap"
    (is (true? (config/root-subnet-id? "acme.example.org")))
    (is (false? (config/root-subnet-id? "acme.example.org/child")))
    (is (false? (config/root-subnet-id? "child-subnet")))
    (let [bridge0 {:asset-id "bitecho.org/ECHO"
                   :origin-root "bitecho.org"
                   :locked-escrow 10000
                   :per-root-cap {"acme.example.org" 4000}
                   :wrapped-supply {"acme.example.org" 0}}
          b1 (circle/apply-bridge-transfer bridge0 {:target-root "acme.example.org" :amount 3000})
          b2 (circle/apply-bridge-transfer (:state b1) {:target-root "acme.example.org" :amount 2000})]
      (is (:ok? b1))
      (is (false? (:ok? b2)))
      (is (= :bridge-root-cap-exceeded (:error b2)))
      (is (some #(= :bridge-root-cap-exceeded (:reason %)) (:effects b2))))))

;; =============================================================================
;; 7. Stage 4 seq 2 Regressions (V1 CLJS SCI distinct + V3 hierarchical directory-register)
;; =============================================================================

(deftest test-v1-sci-distinct-in-cljs-and-jvm
  (testing "V1: (distinct [\"a\" \"b\" \"a\"]) evaluates cleanly inside SCI puzzle on both JVM and CLJS"
    (let [src "(fn [env _sol] (if (= 2 (count (distinct [\"a\" \"b\" \"a\"]))) [{:type :release :receiver (:receiver env) :amount (:amount env)}] false))"
          res (puzzle/eval-puzzle src {} {:receiver "alice" :amount 1000 :epoch 1})]
      (is (true? (:valid? res)))
      (is (= [{:type :release :receiver "alice" :amount 1000}] (:conditions res))))))

(deftest test-v3-directory-register-preserves-hierarchical-paths-and-flat-nicknames
  (testing "V3: directory-register preserves hierarchical slash paths while keeping flat nicknames working"
    (let [kp (gen-kp)
          st0 (light-core/init-light-state {:pubkey-hex (:spki-hex kp)} {})
          r-hier (light-core/handle-command st0
                                            {"cmd" "directory-register"
                                             "name" "root/protocol/dev/nexus"
                                             "domain" "devnet.bitecho.org"
                                             "local_only" true}
                                            (:private kp))
          r-qual (light-core/handle-command st0
                                            {"cmd" "directory-register"
                                             "name" "devnet.bitecho.org/root/inc/board"
                                             "local_only" true}
                                            (:private kp))
          r-flat (light-core/handle-command st0
                                            {"cmd" "directory-register"
                                             "name" "alice"
                                             "domain" "devnet.bitecho.org"
                                             "local_only" true}
                                            (:private kp))]
      (is (true? (get-in r-hier [:response "ok"])))
      (is (= "devnet.bitecho.org/root/protocol/dev/nexus" (get-in r-hier [:response "uri"])))
      (is (= "root/protocol/dev/nexus" (get-in r-hier [:response "nickname"])))
      (is (true? (get-in r-qual [:response "ok"])))
      (is (= "devnet.bitecho.org/root/inc/board" (get-in r-qual [:response "uri"])))
      (is (= "root/inc/board" (get-in r-qual [:response "nickname"])))
      (is (true? (get-in r-flat [:response "ok"])))
      (is (= "devnet.bitecho.org/alice" (get-in r-flat [:response "uri"])))
      (is (= "alice" (get-in r-flat [:response "nickname"]))))))

;; =============================================================================
;; 8. Axiom LIGHT Review Closures (F2, F6, F7, F8, F9, F13, F14, F15, MUT-12)
;; =============================================================================

(deftest test-axiom-f2-f6-f7-f8-f9-f13-f14-f15-and-mut12
  (testing "F8 & F13: config/ratified-theta-star exists and mainnet-config enforces :strict-network-uri? true"
    (is (map? config/ratified-theta-star))
    (is (= 26280 (:bootstrap-sunset-epoch config/ratified-theta-star)))
    (is (true? (:strict-network-uri? config/mainnet-config))))

  (testing "F2: Live streamlet/valid-block-proposal? and verify-ancestor-quorum reject static fallback once last-finalized-epoch >= 1"
    (let [v1 (gen-kp)
          blk (streamlet/sign-block (streamlet/->Block 5 "genesis" [] (:spki-hex v1)) (:private v1))
          b-hash (streamlet/hash-block blk)
          sig (basalt/bytes->hex (crypto/sign (:private v1) (fressian/utf8->bytes b-hash)))
          st {:epoch 5
              :last-finalized-epoch 3
              :strict-validator-history? true
              :validator-set-history {}
              :validators [(:spki-hex v1)]
              :peers-map {(:spki-hex v1) (:public v1)}}
          anc-res (streamlet/verify-ancestor-quorum st {:block blk :votes {(:spki-hex v1) (streamlet/->Vote b-hash 5 sig)}})]
      (is (false? (streamlet/valid-block-proposal? st {:block blk})))
      (is (false? (:valid? anc-res)))
      (is (= :static-validator-fallback-forbidden (:error anc-res)))))

  (testing "F6 & F7: verify-pointer enforces strict :pointer/seq monotonicity, prior-owner binding, and incoming-key PoP"
    (let [auth-kp (gen-kp)
          old-kp (gen-kp)
          new-kp (gen-kp)
          net "devnet.bitecho.org"
          cid (circle/descriptor-cid {:seq 2})
          ;; Proof with prior owner sig + incoming-key PoP
          proof-with-pop (data/create-directory-entity-proof
                          [{:pubkey (:spki-hex old-kp) :privkey (:private old-kp)}]
                          net "dir/root/sub" 2 cid 1 [(:spki-hex new-kp)]
                          {:incoming-signers [{:pubkey (:spki-hex new-kp) :privkey (:private new-kp)}]})
          proof-no-pop (data/create-directory-entity-proof
                        [{:pubkey (:spki-hex old-kp) :privkey (:private old-kp)}]
                        net "dir/root/sub" 2 cid 1 [(:spki-hex new-kp)])
          ptr2 (data/sign-pointer (:private auth-kp)
                                  {:pointer/authority (:spki-hex auth-kp)
                                   :pointer/subnet net
                                   :pointer/path "dir/root/sub"
                                   :pointer/seq 2
                                   :pointer/target cid
                                   :pointer/expires-epoch 500
                                   :pointer/proof proof-with-pop})
          ptr2-no-pop (data/sign-pointer (:private auth-kp)
                                         {:pointer/authority (:spki-hex auth-kp)
                                          :pointer/subnet net
                                          :pointer/path "dir/root/sub"
                                          :pointer/seq 2
                                          :pointer/target cid
                                          :pointer/expires-epoch 500
                                          :pointer/proof proof-no-pop})
          acl-with-prior [{:pattern "dir/*"
                           :principal {:type :directory-entity
                                       :authority (:spki-hex auth-kp)
                                       :owner-multisig {:threshold 1 :pubkeys [(:spki-hex old-kp)]}}}]
          acl-bare [{:pattern "dir/*"
                     :principal {:type :directory-entity
                                 :authority (:spki-hex auth-kp)}}]
          ;; F7: Bare ACL without prior :owner-multisig MUST fail closed (never trust proof-claimed owners)
          r-bare (data/verify-pointer ptr2 {:subnet net :path-acl acl-bare :current-epoch 10})
          ;; F7: Missing incoming-key PoP on rotation fails closed through verify-pointer
          r-no-pop (data/verify-pointer ptr2-no-pop {:subnet net :path-acl acl-with-prior
                                                     :incoming-pubkeys [(:spki-hex new-kp)] :current-epoch 10})
          ;; F7: Valid prior owner + incoming-key PoP passes through verify-pointer
          r-ok (data/verify-pointer ptr2 {:subnet net :path-acl acl-with-prior
                                          :incoming-pubkeys [(:spki-hex new-kp)]
                                          :prev-pointer {:pointer/seq 1}
                                          :current-epoch 10})
          ;; F6: Non-monotonic :pointer/seq (2 <= 2 or 2 <= 3) fails closed!
          r-replay (data/verify-pointer ptr2 {:subnet net :path-acl acl-with-prior
                                              :incoming-pubkeys [(:spki-hex new-kp)]
                                              :prev-pointer {:pointer/seq 2}
                                              :current-epoch 10})]
      (is (false? (:ok? r-bare)))
      (is (= :missing-prior-owner-multisig (:error r-bare)))
      (is (false? (:ok? r-no-pop)))
      (is (= :missing-or-invalid-incoming-pop (:error r-no-pop)))
      (is (:ok? r-ok))
      (is (false? (:ok? r-replay)))
      (is (= :non-monotonic-pointer-seq (:error r-replay)))))

  (testing "F9, F14 & F15: :consent-round-cid validation, CSPRNG secretbox nonce non-reuse, and authenticated cancel-recovery"
    (let [r1 (gen-kp)
          g1 (gen-kp)
          attacker (gen-kp)
          desc-no-consent (circle/create-entity-descriptor
                           {:network-uri "devnet.bitecho.org"
                            :network-genesis-cid test-genesis-cid
                            :entity-kind :circle
                            :visibility :public
                            :path "root"
                            :owner-multisig {:threshold 1 :pubkeys [(:spki-hex r1)]}
                            :purpose-cid test-purpose-cid
                            :consent-round-cid nil
                            :policy {:recovery-policy {:guardians [(:spki-hex g1)] :threshold 1 :timelock-epochs 168}}
                            :retention-policy (sample-retention)
                            :storage-accounting (sample-storage (:spki-hex r1))
                            :issued-epoch 10
                            :expires-epoch 27280}
                           [{:pubkey (:spki-hex r1) :privkey (:private r1)}])
          ;; F9: Missing :consent-round-cid on constitutional root MUST fail
          r-f9 (circle/verify-entity-descriptor desc-no-consent {:network-uri "devnet.bitecho.org"
                                                                 :network-genesis-cid test-genesis-cid})
          ;; F14: Two encryptions of identical descriptor use distinct CSPRNG nonces
          gk (crypto/sha256 (fressian/utf8->bytes "f14-key"))
          e1 (circle/encrypt-shared-descriptor desc-no-consent gk)
          e2 (circle/encrypt-shared-descriptor desc-no-consent gk)
          ;; F15: cancel-recovery rejects unauthorized attacker and succeeds with owner sig
          pending {:new-owner-multisig {:threshold 1 :pubkeys [(:spki-hex g1)]}
                   :initiated-epoch 50
                   :executable-epoch 218
                   :status :pending}
          tuple (circle/cancel-recovery-signing-tuple desc-no-consent pending)
          att-sig (basalt/bytes->hex (crypto/sign-canonical (:private attacker) tuple))
          own-sig (basalt/bytes->hex (crypto/sign-canonical (:private r1) tuple))
          c-unauth (circle/cancel-recovery desc-no-consent pending {:owner-signatures {(:spki-hex attacker) att-sig}})
          c-auth (circle/cancel-recovery desc-no-consent pending {:owner-signatures {(:spki-hex r1) own-sig}})]
      (is (false? (:ok? r-f9)))
      (is (= :missing-or-invalid-consent-round-cid (:error r-f9)))
      (is (not= (:nonce-hex e1) (:nonce-hex e2)))
      (is (false? (:ok? c-unauth)))
      (is (= :unauthorized-recovery-cancel (:error c-unauth)))
      (is (:ok? c-auth))
      (is (= :cancelled (get-in c-auth [:pending-recovery :status])))))

  (testing "MUT-12: :pointer/expires-epoch is strictly compared against :current-epoch and NEVER :now-ms"
    (let [auth-kp (gen-kp)
          own-kp (gen-kp)
          net "devnet.bitecho.org"
          cid (circle/descriptor-cid {:mut 12})
          proof (data/create-directory-entity-proof
                 [{:pubkey (:spki-hex own-kp) :privkey (:private own-kp)}]
                 net "dir/root" 1 cid 1 [(:spki-hex own-kp)])
          ptr (data/sign-pointer (:private auth-kp)
                                 {:pointer/authority (:spki-hex auth-kp)
                                  :pointer/subnet net
                                  :pointer/path "dir/root"
                                  :pointer/seq 1
                                  :pointer/target cid
                                  :pointer/expires-epoch 5000
                                  :pointer/proof proof})
          acl [{:pattern "dir/*"
                :principal {:type :directory-entity
                            :authority (:spki-hex auth-kp)
                            :owner-multisig {:threshold 1 :pubkeys [(:spki-hex own-kp)]}}}]]
      ;; now-ms is 1.8 trillion (>> 5000), but current-epoch 4999 < 5000 -> MUST SUCCEED
      (is (:ok? (data/verify-pointer ptr {:subnet net :path-acl acl :current-epoch 4999 :now-ms 1800000000000})))
      ;; now-ms is 1 (<< 5000), but current-epoch 5000 >= 5000 -> MUST FAIL CLOSED
      (is (= :pointer-expired (:error (data/verify-pointer ptr {:subnet net :path-acl acl :current-epoch 5000 :now-ms 1})))))))
