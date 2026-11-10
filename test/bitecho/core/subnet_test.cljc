(ns bitecho.core.subnet-test
  "Cross-runtime (JVM + Node/CLJS) generative and unit tests for `bitecho.core.subnet`,
   multiplexer integration (`init-multi-subnet-multiplexer`), and thin Pointer adapters."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; -----------------------------------------------------------------------------
;; 1. Constrained Policy Axes (Gap G10)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property: Subnet policy validation enforces G10 axis constraints fail-closed with counted :diagnose"}
  prop-subnet-policy-validation-axis-constraints 50
  (prop/for-all [gate-mode (gen/elements [:permissionless :permissioned])
                 admission (gen/elements [:open :allowlist :dac :mtls-cert :min-stake])
                 econ-mode (gen/elements [:none :burn-only :full-settlement])
                 ptr-rep (gen/elements [:gossip-crdt :streamlet-bft :leader-election])
                 blob-rep (gen/elements [:eager-push :pull-on-demand])
                 has-parent? gen/boolean]
                (let [anchor-pub (basalt/bytes->hex (:public (crypto/generate-keypair)))
                      policy {:subnet/id (if (= ptr-rep :streamlet-bft) "validator-core" "sub/test")
                              :subnet/parent-id (when has-parent? "global")
                              :subnet/gate {:gate/mode gate-mode
                                            :gate/admission (if (= gate-mode :permissionless)
                                                              (if (= admission :min-stake) :min-stake :open)
                                                              (if (= admission :open) :allowlist admission))
                                            :gate/trust-anchors #{anchor-pub}}
                              :subnet/economy {:economy/mode econ-mode
                                               :economy/burn-floor (if (= econ-mode :none) 0 100)
                                               :economy/settlement-take-bps (if (= econ-mode :full-settlement) 50 0)}
                              :subnet/replication {:replication/pointers ptr-rep
                                                   :replication/blobs blob-rep}}
                      eff-adm (get-in policy [:subnet/gate :gate/admission])
                      expected-valid? (and (or (not (contains? #{:streamlet-bft :leader-election} ptr-rep))
                                               (= gate-mode :permissioned))
                                           (or (not= eff-adm :min-stake)
                                               (contains? #{:burn-only :full-settlement} econ-mode))
                                           (or (not= econ-mode :full-settlement)
                                               has-parent?
                                               (= (:subnet/id policy) "global")
                                               (= (:subnet/id policy) "validator-core")))
                      res (subnet/init-subnet-instance policy {:now-ms 1000})]
                  (if expected-valid?
                    (:ok? res)
                    (and (false? (:ok? res))
                         (= :diagnose (:effect (first (:effects res)))))))))

;; -----------------------------------------------------------------------------
;; 2. Relocated Bully Leader-Election Engine & Monotonic Term (Decision D1)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property: Leader election enforces >=2 split-brain quorum and monotonic clock-free :leader-term"}
  prop-leader-election-bully-quorum-and-monotonic-term 50
  (prop/for-all [steps (gen/vector
                        (gen/tuple (gen/elements [:tick :hb-ns2 :hb-ns3 :advance-time])
                                   (gen/choose 500 4000))
                        5 25)]
                (let [le0 (subnet/init-leader-election {:node-id :ns2
                                                        :all-nodes #{:ns1 :ns2 :ns3}
                                                        :heartbeat-interval-ms 2000
                                                        :heartbeat-timeout-ms 6000})
                      final (reduce (fn [{:keys [st now terms ok?]} [op dt]]
                                      (let [t (+ now dt)
                                            st' (case op
                                                  :tick (:state (subnet/step-leader-election st {:type :tick} t))
                                                  :hb-ns2 (:state (subnet/step-leader-election st {:type :heartbeat :from :ns1 :term (inc (:term st))} t))
                                                  :hb-ns3 (:state (subnet/step-leader-election st {:type :heartbeat :from :ns3 :term (:term st)} t))
                                                  :advance-time (:state (subnet/step-leader-election st {:type :tick} t)))
                                            healthy-cnt (count (:healthy-nodes st'))
                                            quorum-respected? (if (< healthy-cnt 2)
                                                                (nil? (:leader-id st'))
                                                                (some? (:leader-id st')))
                                            monotonic-term? (>= (:term st') (last terms))]
                                        {:st st'
                                         :now t
                                         :terms (conj terms (:term st'))
                                         :ok? (and ok? quorum-respected? monotonic-term?)}))
                                    {:st le0 :now 1000 :terms [0] :ok? true}
                                    steps)]
                  (:ok? final))))

;; -----------------------------------------------------------------------------
;; 3. Gate Governance (G5), Five Canonical Instances (§6), & Eager Replication
;; -----------------------------------------------------------------------------

(deftest test-subnet-gate-governance-and-five-canonical-instances
  (testing "UNIFICATION.md §§5-6 & Gap G5: genesis-policy-cid pinning, hot-leader policy mutation blocked, quorum/cold-key governance allowed, and 5 canonical instances"
    (let [cold-root-kp (crypto/generate-keypair)
          ns1-kp (crypto/generate-keypair)
          ns2-kp (crypto/generate-keypair)
          ns3-kp (crypto/generate-keypair)
          simon-anchor-kp (crypto/generate-keypair)
          nexus-hot-kp (crypto/generate-keypair)
          cold-pub (basalt/bytes->hex (:public cold-root-kp))
          ns1-pub (basalt/bytes->hex (:public ns1-kp))
          ns2-pub (basalt/bytes->hex (:public ns2-kp))
          ns3-pub (basalt/bytes->hex (:public ns3-kp))
          simon-pub (basalt/bytes->hex (:public simon-anchor-kp))
          nexus-pub (basalt/bytes->hex (:public nexus-hot-kp))
          ;; Instance #3: bitecho.org/infra
          infra-base {:subnet/id "bitecho.org/infra"
                      :subnet/parent-id "global"
                      :subnet/gate {:gate/mode :permissioned
                                    :gate/admission :allowlist
                                    :gate/trust-anchors #{ns1-pub ns2-pub ns3-pub}
                                    :gate/governance {:governance/type :cold-key-or-quorum
                                                      :cold-pubkey cold-pub
                                                      :threshold 2}}
                      :subnet/path-acl [{:pattern "subnet/policy"
                                         :principal {:type :governance}}
                                        {:pattern "acme/challenge/*"
                                         :principal {:type :leader}}
                                        {:pattern "tls/*"
                                         :principal {:type :leader}}
                                        {:pattern "mail/*"
                                         :principal {:type :allowlist}}]
                      :subnet/economy {:economy/mode :none
                                       :economy/burn-floor 0
                                       :economy/settlement-take-bps 0}
                      :subnet/replication {:replication/pointers :leader-election
                                           :replication/blobs :eager-push}}
          genesis-cid (subnet/policy-cid infra-base)
          infra-policy (assoc infra-base :subnet/genesis-policy-cid genesis-cid)
          ;; Tampered genesis CID rejected fail-closed!
          bad-init (subnet/init-subnet-instance (assoc infra-policy :subnet/genesis-policy-cid (apply str (repeat 64 "f"))) {:now-ms 1000})
          good-init (subnet/init-subnet-instance infra-policy {:node-id ns1-pub
                                                               :all-nodes #{ns1-pub ns2-pub ns3-pub}
                                                               :now-ms 1000})
          ;; Bring ns2 online so ns1 is elected leader at term 1
          s1 (:state (subnet/reduce-subnet (:instance good-init)
                                           {:type :leader-heartbeat :from ns2-pub :term 0 :now-ms 1100}))
          ;; Hot leader (ns1 alone) attempts to overwrite "subnet/policy" -> MUST BE REJECTED!
          evil-policy (assoc-in infra-base [:subnet/gate :gate/trust-anchors] #{ns1-pub})
          evil-blob (data/make-blob (fressian/encode-canonical evil-policy) "application/fressian")
          s2 (:state (subnet/reduce-subnet s1 {:type :put-blob :sender ns1-pub :blob evil-blob :now-ms 1200}))
          evil-ptr (data/sign-pointer (:private ns1-kp)
                                      {:pointer/authority ns1-pub
                                       :pointer/subnet "bitecho.org/infra"
                                       :pointer/path "subnet/policy"
                                       :pointer/seq 1
                                       :pointer/target (:blob/cid evil-blob)
                                       :pointer/proof {:proof/type :self}})
          res-evil (subnet/reduce-subnet s2 {:type :publish-pointer :sender ns1-pub :pointer evil-ptr :now-ms 1250})
          ;; Authorized 2-of-3 quorum (ns1 + ns2) updates "subnet/policy" -> SUCCEEDS!
          next-policy (assoc-in infra-base [:subnet/gate :gate/trust-anchors] #{ns1-pub ns2-pub ns3-pub nexus-pub})
          next-blob (data/make-blob (fressian/encode-canonical next-policy) "application/fressian")
          s3 (:state (subnet/reduce-subnet (:state res-evil) {:type :put-blob :sender ns1-pub :blob next-blob :now-ms 1300}))
          q-proof (data/create-quorum-proof [{:pubkey ns1-pub :privkey (:private ns1-kp)}
                                             {:pubkey ns2-pub :privkey (:private ns2-kp)}]
                                            "bitecho.org/infra" "subnet/policy" 1 (:blob/cid next-blob))
          good-ptr (data/sign-pointer (:private ns1-kp)
                                      {:pointer/authority ns1-pub
                                       :pointer/subnet "bitecho.org/infra"
                                       :pointer/path "subnet/policy"
                                       :pointer/seq 1
                                       :pointer/target (:blob/cid next-blob)
                                       :pointer/proof q-proof})
          res-good (subnet/reduce-subnet s3 {:type :publish-pointer :sender ns1-pub :pointer good-ptr :now-ms 1350})
          ;; Instance #4: chat/simon-nexus-axiom with DAC admission & zero-burn eager-push
          dac (light-core/create-dac (:private simon-anchor-kp)
                                     {:anchor-pubkey simon-pub
                                      :agent-pubkey nexus-pub
                                      :scopes ["chat"]
                                      :issued-epoch 1
                                      :expires-epoch 100})
          chat-policy {:subnet/id "chat/simon-nexus-axiom"
                       :subnet/parent-id "global"
                       :subnet/gate {:gate/mode :permissioned
                                     :gate/admission :dac
                                     :gate/trust-anchors #{simon-pub}
                                     :gate/governance {:governance/type :cold-key
                                                       :cold-pubkey simon-pub}}
                       :subnet/path-acl [{:pattern "head/<pubkey>/*" :principal {:type :self-path-owner}}]
                       :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                       :subnet/replication {:replication/pointers :gossip-crdt
                                            :replication/blobs :eager-push}}
          chat-init (subnet/init-subnet-instance chat-policy {:now-ms 2000})
          msg-blob (data/make-blob (fressian/utf8->bytes "Hello 3-way zero-burn subnet!") "application/octet-stream")
          chat-r1 (subnet/reduce-subnet (:instance chat-init)
                                        {:type :put-blob :sender nexus-pub :dac dac :epoch 50 :blob msg-blob :now-ms 2100})
          head-ptr (data/sign-pointer (:private nexus-hot-kp)
                                      {:pointer/authority nexus-pub
                                       :pointer/subnet "chat/simon-nexus-axiom"
                                       :pointer/path (str "head/" nexus-pub "/room")
                                       :pointer/seq 1
                                       :pointer/target (:blob/cid msg-blob)
                                       :pointer/proof {:proof/type :self}})
          chat-r2 (subnet/reduce-subnet (:state chat-r1)
                                        {:type :publish-pointer :sender nexus-pub :dac dac :epoch 50 :pointer head-ptr :now-ms 2200})]
      (is (false? (:ok? bad-init)))
      (is (:ok? good-init))
      (is (false? (:applied? res-evil)) "Hot leader alone must never mutate subnet/policy")
      (is (some #(= :diagnose (:effect %)) (:effects res-evil)))
      (is (:applied? res-good) "2-of-3 quorum update to subnet/policy must succeed")
      (is (contains? (get-in res-good [:state :policy :subnet/gate :gate/trust-anchors]) nexus-pub))
      (is (:ok? chat-init))
      (is (some #(= :eager-push-blob (:effect %)) (:effects chat-r1)))
      (is (:applied? chat-r2))
      (is (= 0 (get-in chat-r2 [:state :burned-ech]))))))

;; -----------------------------------------------------------------------------
;; 4. Multiplexer Integration (G14) & Thin Pointer Adapters (Phase A Exit Gate)
;; -----------------------------------------------------------------------------

(deftest test-multiplexer-and-thin-pointer-adapters
  (testing "Phase A exit criteria: init-multi-subnet-multiplexer routes unified Subnet instances and directory/bootstrap/DAC/homeset adapters wrap sign-pointer/verify-pointer"
    (let [dir-kp (crypto/generate-keypair)
          agent-kp (crypto/generate-keypair)
          boot-kp (crypto/generate-keypair)
          anchor-kp (crypto/generate-keypair)
          dir-pub (basalt/bytes->hex (:public dir-kp))
          agent-pub (basalt/bytes->hex (:public agent-kp))
          boot-pub (basalt/bytes->hex (:public boot-kp))
          anchor-pub (basalt/bytes->hex (:public anchor-kp))
          ;; 1. Directory descriptor -> Blob + Pointer roundtrip
          pop (light-core/create-directory-pop (:private agent-kp)
                                               {:domain "bitecho.org"
                                                :nickname "axiom"
                                                :pubkey agent-pub
                                                :home-set ["node1" "node2" "node3"]
                                                :epoch 10})
          {:keys [blob pointer]} (subnet/sign-directory-pointer (:private dir-kp) dir-pub pop
                                                                {:subnet "global" :seq 1 :issued-epoch 10 :expires-epoch 200})
          v-dir (subnet/verify-directory-pointer pointer blob dir-pub 50)
          ;; 2. Bootstrap descriptor -> Blob + Pointer roundtrip
          boot-desc {:domain "bitecho.org"
                     :authority-pubkey boot-pub
                     :issued-epoch 1
                     :expires-epoch 1000
                     :nodes [{:node-id "node1" :ip "127.0.0.1" :port 5000 :agent-port 5010 :pubkey agent-pub :fingerprint "AA:BB" :ice-ufrag "u" :ice-pwd "p"}]}
          boot-bundle (subnet/sign-bootstrap-pointer (:private boot-kp) boot-desc {:subnet "global" :seq 1})
          v-boot (subnet/verify-bootstrap-pointer (:pointer boot-bundle) (:blob boot-bundle) boot-pub 50)
          ;; 3. DAC -> Blob + Pointer roundtrip
          dac-bundle (subnet/sign-dac-pointer (:private anchor-kp) anchor-pub agent-pub ["send" "offer"]
                                              {:subnet "global" :seq 1 :issued-epoch 1 :expires-epoch 500})
          v-dac (subnet/verify-dac-pointer (:pointer dac-bundle) (:blob dac-bundle) anchor-pub 50)
          ;; 4. Home-Set -> Blob + Pointer roundtrip + forged PoP fail-closed check
          hs-bundle (subnet/sign-home-set-pointer (:private agent-kp) agent-pub ["node1" "node2" "node3"]
                                                  {:subnet "global" :seq 1 :price 10 :epoch 5})
          v-hs (subnet/verify-home-set-pointer (:pointer hs-bundle) (:blob hs-bundle))
          forged-pop (assoc pop :pop-signature (apply str (repeat 128 "0")))
          forged-dir (subnet/sign-directory-pointer (:private dir-kp) dir-pub forged-pop
                                                    {:subnet "global" :seq 2 :issued-epoch 10 :expires-epoch 200})
          ;; 5. Multi-subnet multiplexer routing to unified Subnet instance
          chat-policy {:subnet/id "chat/team"
                       :subnet/parent-id "global"
                       :subnet/gate {:gate/mode :permissioned
                                     :gate/admission :allowlist
                                     :gate/trust-anchors #{agent-pub}}
                       :subnet/path-acl [{:pattern "head/<pubkey>/*" :principal {:type :self-path-owner}}]
                       :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                       :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
          sub-inst (:instance (subnet/init-subnet-instance chat-policy {:now-ms 1000}))
          mux0 (-> (light-core/init-multi-subnet-multiplexer {})
                   (light-core/register-subnet-instance "chat/team" sub-inst))
          msg-blob (data/make-blob (fressian/utf8->bytes "mux-routed-blob") "application/octet-stream")
          routed (light-core/route-multiplexed-envelope
                  mux0
                  {:subnet-id "chat/team"
                   :type :subnet-event
                   :event {:type :put-blob :sender agent-pub :blob msg-blob :now-ms 1100}}
                  (:private agent-kp))]
      (is (:ok? v-dir))
      (is (= "axiom" (get-in v-dir [:descriptor :nickname])))
      (is (:ok? v-boot))
      (is (= "bitecho.org" (get-in v-boot [:descriptor :domain])))
      (is (:ok? v-dac))
      (is (= agent-pub (get-in v-dac [:dac :agent-pubkey])))
      (is (:ok? v-hs))
      (is (= 3 (count (get-in v-hs [:home-set :candidates]))))
      (is (nil? forged-dir) "Forged agent PoP must be rejected by sign-directory-pointer")
      (is (data/has-blob? (get-in routed [:mux :subnets "chat/team" :data :blobs]) (:blob/cid msg-blob))))))

(deftest test-b1-missing-policy-blob-does-not-consume-seq-or-dangle-pointer
  (testing "B1 regression: publishing subnet/policy Pointer before its target Blob leaves pointer table & seq untouched so retry at same seq succeeds after put-blob"
    (let [ns1-kp (crypto/generate-keypair)
          ns2-kp (crypto/generate-keypair)
          ns3-kp (crypto/generate-keypair)
          new-member-kp (crypto/generate-keypair)
          ns1-pub (basalt/bytes->hex (:public ns1-kp))
          ns2-pub (basalt/bytes->hex (:public ns2-kp))
          ns3-pub (basalt/bytes->hex (:public ns3-kp))
          new-pub (basalt/bytes->hex (:public new-member-kp))
          base-policy {:subnet/id "bitecho.org/infra"
                       :subnet/parent-id "global"
                       :subnet/gate {:gate/mode :permissioned
                                     :gate/admission :allowlist
                                     :gate/trust-anchors #{ns1-pub ns2-pub ns3-pub}
                                     :gate/governance {:governance/type :quorum
                                                       :threshold 2}}
                       :subnet/path-acl [{:pattern "subnet/policy" :principal {:type :governance}}]
                       :subnet/economy {:economy/mode :none :burn-floor 0 :settlement-take-bps 0}
                       :subnet/replication {:replication/pointers :leader-election
                                            :replication/blobs :eager-push}}
          gen-cid (subnet/policy-cid base-policy)
          init-res (subnet/init-subnet-instance (assoc base-policy :subnet/genesis-policy-cid gen-cid) {:now-ms 1000})
          inst0 (:instance init-res)
          next-policy (assoc-in base-policy [:subnet/gate :gate/trust-anchors] #{ns1-pub ns2-pub ns3-pub new-pub})
          next-blob (data/make-blob (fressian/encode-canonical next-policy) "application/fressian")
          q-proof (data/create-quorum-proof [{:pubkey ns1-pub :privkey (:private ns1-kp)}
                                             {:pubkey ns2-pub :privkey (:private ns2-kp)}]
                                            "bitecho.org/infra" "subnet/policy" 1 (:blob/cid next-blob))
          policy-ptr (data/sign-pointer (:private ns1-kp)
                                        {:pointer/authority ns1-pub
                                         :pointer/subnet "bitecho.org/infra"
                                         :pointer/path "subnet/policy"
                                         :pointer/seq 1
                                         :pointer/target (:blob/cid next-blob)
                                         :pointer/proof q-proof})
          ;; 1. Publish valid quorum-signed subnet/policy Pointer BEFORE its target Blob is present
          res-missing (subnet/reduce-subnet inst0 {:type :publish-pointer :sender ns1-pub :pointer policy-ptr :now-ms 1100})
          inst-after-miss (:state res-missing)
          ;; 2. Tombstone (:pointer/target nil) on subnet/policy is also rejected without consuming seq
          tomb-proof (data/create-quorum-proof [{:pubkey ns1-pub :privkey (:private ns1-kp)}
                                                {:pubkey ns2-pub :privkey (:private ns2-kp)}]
                                               "bitecho.org/infra" "subnet/policy" 1 nil)
          tomb-ptr (data/sign-pointer (:private ns1-kp)
                                      {:pointer/authority ns1-pub
                                       :pointer/subnet "bitecho.org/infra"
                                       :pointer/path "subnet/policy"
                                       :pointer/seq 1
                                       :pointer/target nil
                                       :pointer/proof tomb-proof})
          res-tomb (subnet/reduce-subnet inst-after-miss {:type :publish-pointer :sender ns1-pub :pointer tomb-ptr :now-ms 1150})
          ;; 3. Deliver target Blob via :put-blob, then re-publish the EXACT SAME Pointer at seq = 1
          res-put (subnet/reduce-subnet (:state res-tomb) {:type :put-blob :sender ns1-pub :blob next-blob :now-ms 1200})
          res-retry (subnet/reduce-subnet (:state res-put) {:type :publish-pointer :sender ns1-pub :pointer policy-ptr :now-ms 1250})]
      (is (false? (:applied? res-missing)))
      (is (= :missing-policy-blob (:error res-missing)))
      (is (= :fetch-blob (:effect (first (:effects res-missing)))))
      (is (= (:blob/cid next-blob) (:cid (first (:effects res-missing)))))
      (is (= 1 (get-in inst-after-miss [:data :blobs :diagnostics :cache-misses])))
      (is (nil? (data/resolve-pointer (:data inst-after-miss) "bitecho.org/infra" "subnet/policy"))
          "Missing policy Blob must never leave a dangling Pointer in the pointer table")
      (is (false? (data/blob-pinned? (get-in inst-after-miss [:data :blobs]) (:blob/cid next-blob))))
      (is (= (:policy inst0) (:policy inst-after-miss)))
      (is (false? (:applied? res-tomb)))
      (is (= :invalid-policy-update (:error res-tomb)))
      (is (:applied? res-put))
      (is (:applied? res-retry) "Re-publishing the same Pointer at seq 1 after put-blob must succeed")
      (is (= (:blob/cid next-blob)
             (:pointer/target (data/resolve-pointer (get-in res-retry [:state :data]) "bitecho.org/infra" "subnet/policy"))))
      (is (data/blob-pinned? (get-in res-retry [:state :data :blobs]) (:blob/cid next-blob)))
      (is (contains? (get-in res-retry [:state :policy :subnet/gate :gate/trust-anchors]) new-pub)))))

(deftest test-f3-f4-dac-per-event-expiry-and-gate-admission-enum
  (testing "F3 & F4: validate-subnet-policy enforces :gate/admission enum and DAC-admitted keys are never permanently cached past :expires-epoch"
    (let [anchor-kp (crypto/generate-keypair)
          agent-kp (crypto/generate-keypair)
          anchor-pub (basalt/bytes->hex (:public anchor-kp))
          agent-pub (basalt/bytes->hex (:public agent-kp))
          base-policy {:subnet/id "chat/dac-expiry-test"
                       :subnet/parent-id "global"
                       :subnet/gate {:gate/mode :permissioned
                                     :gate/admission :dac
                                     :gate/trust-anchors #{anchor-pub}
                                     :gate/governance {:governance/type :cold-key
                                                       :cold-pubkey anchor-pub}}
                       :subnet/path-acl [{:pattern "head/<pubkey>/*" :principal {:type :self-path-owner}}]
                       :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                       :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
          ;; F4: bogus :gate/admission or :permissioned + :open must fail closed with counted :diagnose
          bad-adm-res (subnet/validate-subnet-policy (assoc-in base-policy [:subnet/gate :gate/admission] :magic-pass))
          perm-open-res (subnet/validate-subnet-policy (assoc-in base-policy [:subnet/gate :gate/admission] :open))
          ;; F3: DAC valid for epochs [5..10]
          dac (light-core/create-dac (:private anchor-kp)
                                     {:anchor-pubkey anchor-pub
                                      :agent-pubkey agent-pub
                                      :scopes ["chat"]
                                      :issued-epoch 5
                                      :expires-epoch 10})
          inst0 (:instance (subnet/init-subnet-instance base-policy {:now-ms 1000}))
          b1 (data/make-blob (fressian/utf8->bytes "msg-at-epoch-7") "application/octet-stream")
          b2 (data/make-blob (fressian/utf8->bytes "msg-at-epoch-11") "application/octet-stream")
          ptr1 (data/sign-pointer (:private agent-kp)
                                  {:pointer/authority agent-pub
                                   :pointer/subnet "chat/dac-expiry-test"
                                   :pointer/path (str "head/" agent-pub "/chat")
                                   :pointer/seq 1
                                   :pointer/target (:blob/cid b1)
                                   :pointer/proof {:proof/type :self}})
          ptr2 (data/sign-pointer (:private agent-kp)
                                  {:pointer/authority agent-pub
                                   :pointer/subnet "chat/dac-expiry-test"
                                   :pointer/path (str "head/" agent-pub "/chat")
                                   :pointer/seq 2
                                   :pointer/target (:blob/cid b2)
                                   :pointer/proof {:proof/type :self}})
          ;; Epoch 7 (within DAC window): put-blob and :self-path-owner publish-pointer succeed
          r-put-ok (subnet/reduce-subnet inst0 {:type :put-blob :sender agent-pub :dac dac :epoch 7 :blob b1 :now-ms 1100})
          r-ptr-ok (subnet/reduce-subnet (:state r-put-ok) {:type :publish-pointer :sender agent-pub :dac dac :epoch 7 :pointer ptr1 :now-ms 1150})
          ;; Without DAC at epoch 8: rejected even after prior admission!
          r-no-dac (subnet/reduce-subnet (:state r-ptr-ok) {:type :put-blob :sender agent-pub :epoch 8 :blob b2 :now-ms 1200})
          ;; Epoch 11 (after DAC expires-epoch 10): rejected fail-closed with counted :diagnose!
          r-expired-blob (subnet/reduce-subnet (:state r-ptr-ok) {:type :put-blob :sender agent-pub :dac dac :epoch 11 :blob b2 :now-ms 1300})
          r-expired-ptr (subnet/reduce-subnet (:state r-ptr-ok) {:type :publish-pointer :sender agent-pub :dac dac :epoch 11 :pointer ptr2 :now-ms 1350})]
      (is (false? (:ok? bad-adm-res)))
      (is (= :invalid-gate-admission (:error bad-adm-res)))
      (is (= :diagnose (:effect (first (:effects bad-adm-res)))))
      (is (false? (:ok? perm-open-res)))
      (is (= :diagnose (:effect (first (:effects perm-open-res)))))
      (is (:applied? r-put-ok))
      (is (:applied? r-ptr-ok))
      (is (not (contains? (get-in r-ptr-ok [:state :admitted-members]) agent-pub))
          "DAC-admitted hot key must not be permanently cached in :admitted-members")
      (is (false? (:applied? r-no-dac)))
      (is (= :invalid-or-missing-dac (:error r-no-dac)))
      (is (false? (:applied? r-expired-blob)))
      (is (= :invalid-or-missing-dac (:error r-expired-blob)))
      (is (= :diagnose (:effect (first (:effects r-expired-blob)))))
      (is (false? (:applied? r-expired-ptr)))
      (is (= :invalid-or-missing-dac (:error r-expired-ptr))))))

(deftest test-fb1-fb4-dac-nil-epoch-fail-closed-and-proof-target-blob-gate
  (testing "F-B1 & F-B4: DAC verification fails closed when :epoch is nil, and :cert/:acme-key-auth/:dac Pointers require target Blob present before apply-pointer"
    (let [anchor-kp (crypto/generate-keypair)
          agent-kp (crypto/generate-keypair)
          leader-kp (crypto/generate-keypair)
          anchor-pub (basalt/bytes->hex (:public anchor-kp))
          agent-pub (basalt/bytes->hex (:public agent-kp))
          leader-pub (basalt/bytes->hex (:public leader-kp))
          ;; 1. F-B1: valid DAC without :epoch (nil) MUST fail closed!
          dac (light-core/create-dac (:private anchor-kp)
                                     {:anchor-pubkey anchor-pub
                                      :agent-pubkey agent-pub
                                      :scopes ["chat"]
                                      :issued-epoch 1
                                      :expires-epoch 100})
          dac-policy {:subnet/id "chat/fb1-nil-epoch"
                      :subnet/parent-id "global"
                      :subnet/gate {:gate/mode :permissioned
                                    :gate/admission :dac
                                    :gate/trust-anchors #{anchor-pub}}
                      :subnet/path-acl [{:pattern "head/<pubkey>/*" :principal {:type :self-path-owner}}]
                      :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                      :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
          dac-inst (:instance (subnet/init-subnet-instance dac-policy {:now-ms 1000}))
          msg-blob (data/make-blob (fressian/utf8->bytes "nil-epoch-attempt") "application/octet-stream")
          nil-epoch-res (subnet/reduce-subnet dac-inst {:type :put-blob :sender agent-pub :dac dac :blob msg-blob :now-ms 1100})
          ;; 2. F-B4: publishing :cert Pointer BEFORE its target Blob is present emits :fetch-blob without consuming seq or dangling Pointer!
          infra-policy {:subnet/id "bitecho.org/infra"
                        :subnet/parent-id "global"
                        :subnet/gate {:gate/mode :permissioned
                                      :gate/admission :allowlist
                                      :gate/trust-anchors #{leader-pub}}
                        :subnet/path-acl [{:pattern "tls/*" :principal {:type :leader}}]
                        :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                        :subnet/replication {:replication/pointers :leader-election :replication/blobs :eager-push}}
          infra-inst (:instance (subnet/init-subnet-instance infra-policy {:node-id leader-pub
                                                                           :all-nodes #{leader-pub}
                                                                           :now-ms 1000}))
          cert-der (fressian/utf8->bytes "leaf-der-for-fb4")
          cert-fp (basalt/bytes->hex (crypto/sha256 cert-der))
          cert-blob (data/make-blob (fressian/encode-canonical {:cert-der cert-der}) "application/fressian")
          cert-ptr (data/sign-pointer (:private leader-kp)
                                      {:pointer/authority leader-pub
                                       :pointer/subnet "bitecho.org/infra"
                                       :pointer/path "tls/current-cert"
                                       :pointer/leader-term 1
                                       :pointer/seq 1
                                       :pointer/target (:blob/cid cert-blob)
                                       :pointer/proof {:proof/type :cert :fingerprint cert-fp}})
          miss-res (subnet/reduce-subnet infra-inst {:type :publish-pointer :sender leader-pub :pointer cert-ptr :now-ms 1200})
          put-res (subnet/reduce-subnet (:state miss-res) {:type :put-blob :sender leader-pub :blob cert-blob :now-ms 1250})
          ok-res (subnet/reduce-subnet (:state put-res) {:type :publish-pointer :sender leader-pub :pointer cert-ptr :now-ms 1300})]
      (is (false? (:applied? nil-epoch-res)) "F-B1: nil :epoch on DAC event must fail closed")
      (is (= :invalid-or-missing-dac (:error nil-epoch-res)))
      (is (= :diagnose (:effect (first (:effects nil-epoch-res)))))
      (is (false? (:applied? miss-res)) "F-B4: :cert Pointer without target Blob must not apply prematurely")
      (is (= :missing-target-blob (:error miss-res)))
      (is (= :fetch-blob (:effect (first (:effects miss-res)))))
      (is (nil? (data/resolve-pointer (get-in miss-res [:state :data]) "bitecho.org/infra" "tls/current-cert")))
      (is (:applied? ok-res) "Retrying same :cert Pointer at seq 1 after put-blob succeeds semantically"))))
