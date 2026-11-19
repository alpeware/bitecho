(ns bitecho.d35-bip009-cluster-deployment-test
  "Milestone D35 (`BIP-009: Self-Managing Cluster Deployment — Config/Code-as-Pointers,
   Simulation-Gated Zero-Downtime Rolling Upgrades, Full Audit Trail, Six-Nines Availability Target` / `v0.23.13`)
   Generative `test.check` Invariants (Rule 1 Strict TDD, >= 50 trials each) & Deterministic Scenarios:
   1. `prop-config-change-activates-only-at-epoch-boundary` (`P-DEPLOY-1`)
   2. `prop-code-switch-requires-verified-artifact-hash` (`P-DEPLOY-2`)
   3. `prop-rolling-upgrade-preserves-quorum-and-delivery` (`P-DEPLOY-3`)
   4. `prop-failed-gate-halts-rollout-without-cluster-impact` (`P-DEPLOY-3`, `P-DEPLOY-4`)
   5. `prop-rollback-restores-last-known-good-code-and-config` (`P-DEPLOY-2`, `P-DEPLOY-3`)
   6. `prop-every-deploy-step-emits-audit-record` (`P-DEPLOY-5`, `P-DEPLOY-8`)
   7. `prop-control-envelopes-delivered-on-any-single-transport` (`P-DEPLOY-7`)
   8. `prop-heterogeneous-cluster-finalizes-during-rollout` (`P-DEPLOY-3`, `P-DEPLOY-6`)
   9. `S-D35-1..S-D35-4`: Deterministic E2E scenarios for `P-DEPLOY-1..P-DEPLOY-9`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.economy.account :as account]
            [bitecho.governance.core :as gov]
            [bitecho.light-node.core :as light-core]
            [bitecho.state-machine :as sm]
            [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.nio.charset StandardCharsets]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- kp->pk-hex [kp]
  (let [pub (:public kp)]
    (if (string? pub) pub (basalt/bytes->hex pub))))

(defn- kp->sk [kp]
  (:private kp))

(defn- utf8-bytes [s]
  (.getBytes (str s) StandardCharsets/UTF_8))

;; =============================================================================
;; 1. Generative Properties (Rule 1: >= 50 trials each)
;; =============================================================================

(defspec ^{:doc "BIP-009 Prop 1 (P-DEPLOY-1): Config-pointer changes never mutate active config mid-epoch and activate atomically at the exact :activate-at-epoch boundary."}
  prop-config-change-activates-only-at-epoch-boundary 50
  (prop/for-all
   [start-epoch (gen/choose 1 50)
    offset (gen/choose 2 10)
    new-burn (gen/choose 50 500)
    new-take-bps (gen/choose 10 200)]
   (let [auth-kp (crypto/generate-keypair (str "d35-p1-auth-" start-epoch "-" offset))
         auth-pk (kp->pk-hex auth-kp)
         auth-sk (kp->sk auth-kp)
         activate-ep (+ start-epoch offset)
         st0 (-> (sm/init-state [] auth-pk (assoc (config/devnet-6-config)
                                                  :burn-floor 100
                                                  :min-signaling-burn 100
                                                  :settlement-take-bps 50))
                 (assoc :epoch start-epoch
                        :trusted-deploy-authorities #{auth-pk}))
         theta (assoc deploy/ratified-theta-star
                      :min-signaling-burn new-burn
                      :settlement-take-bps new-take-bps)
         pointer (deploy/sign-config-pointer
                  auth-sk
                  {:network "devnet"
                   :seq 1
                   :activate-at-epoch activate-ep
                   :code-target-cid (deploy/sha256-hex (utf8-bytes "code-v1"))
                   :domains {:consensus {:quorum-threshold 4}
                             :economy {:settlement-take-bps new-take-bps
                                       :min-signaling-burn new-burn}
                             :transport {:so-rcvbuf-bytes 4194304}
                             :storage {:max-hot-bytes 134217728}}
                   :policy-theta theta
                   :author-pubkey auth-pk})
         staged-res (deploy/stage-config-pointer st0 pointer)
         st-staged (:state staged-res)
         ;; Step through epochs strictly before activate-ep: active config must NOT change
         pre-epochs (range (inc start-epoch) activate-ep)
         st-pre (reduce (fn [s ep]
                          (:state (deploy/apply-epoch-boundary-configs s ep)))
                        st-staged
                        pre-epochs)
         ;; Step at exact activate-ep: config MUST activate atomically
         at-res (deploy/apply-epoch-boundary-configs st-pre activate-ep)
         st-at (:state at-res)]
     (and (true? (:ok? staged-res))
          (= 100 (get-in st-staged [:config :min-signaling-burn]))
          (= 50 (get-in st-staged [:config :settlement-take-bps]))
          (= 100 (get-in st-pre [:config :min-signaling-burn]))
          (= 50 (get-in st-pre [:config :settlement-take-bps]))
          (nil? (:active-config-hash st-pre))
          (= new-burn (get-in st-at [:config :min-signaling-burn]))
          (= new-take-bps (get-in st-at [:config :settlement-take-bps]))
          (string? (:active-config-hash st-at))
          (some #(= :config-activated (:event-type %)) (:audit-trail st-at))))))

(defspec ^{:doc "BIP-009 Prop 2 (P-DEPLOY-2): Code self-update requires SHA-256 artifact hash match and valid authority signature chained to ratified-bip-cid; any mismatch refuses switch and emits counted :diagnose."}
  prop-code-switch-requires-verified-artifact-hash 50
  (prop/for-all
   [payload-seed (gen/choose 1000 9999)
    fault-mode (gen/elements [:valid :corrupt-bytes :wrong-target-cid :bad-signature :unratified-bip])]
   (let [auth-kp (crypto/generate-keypair (str "d35-p2-auth-" payload-seed))
         other-kp (crypto/generate-keypair (str "d35-p2-other-" payload-seed))
         auth-pk (kp->pk-hex auth-kp)
         auth-sk (kp->sk auth-kp)
         other-sk (kp->sk other-kp)
         artifact-bytes (utf8-bytes (str "(ns bitecho.release.v" payload-seed ")"))
         true-cid (deploy/sha256-hex artifact-bytes)
         bip-cid (deploy/sha256-hex (utf8-bytes (str "BIP-009-" payload-seed)))
         st0 {:node-id :node1
              :epoch 10
              :active-code-cid "0000000000000000000000000000000000000000000000000000000000000000"
              :ratified-bip-cids #{bip-cid}
              :trusted-deploy-authorities #{auth-pk}
              :diagnostics {}}
         target-cid (if (= fault-mode :wrong-target-cid)
                      (deploy/sha256-hex (utf8-bytes "wrong-target"))
                      true-cid)
         effective-bip-cid (if (= fault-mode :unratified-bip)
                             (deploy/sha256-hex (utf8-bytes "unratified-bip"))
                             bip-cid)
         signer-sk (if (= fault-mode :bad-signature) other-sk auth-sk)
         pointer-sig (deploy/sign-code-pointer signer-sk {:target-cid target-cid
                                                          :ratified-bip-cid effective-bip-cid
                                                          :authority-pubkey auth-pk})
         fetched-bytes (if (= fault-mode :corrupt-bytes)
                         (utf8-bytes (str "corrupted-" payload-seed))
                         artifact-bytes)
         res (deploy/verify-and-stage-code-switch
              st0
              {:target-cid target-cid
               :artifact-bytes fetched-bytes
               :pointer-sig pointer-sig
               :authority-pubkey auth-pk
               :ratified-bip-cid effective-bip-cid
               :gate-epoch 18})
         st1 (:state res)]
     (if (= fault-mode :valid)
       (and (true? (:ok? res))
            (= true-cid (get-in st1 [:staged-code-switch :target-cid]))
            (= 18 (get-in st1 [:staged-code-switch :gate-epoch]))
            (zero? (get-in st1 [:diagnostics :code-switch-rejected] 0)))
       (and (false? (:ok? res))
            (nil? (:staged-code-switch st1))
            (= "0000000000000000000000000000000000000000000000000000000000000000"
               (:active-code-cid st1))
            (= 1 (get-in st1 [:diagnostics :code-switch-rejected]))
            (some #(and (= :diagnose (:effect %))
                        (= :code-verification-failed (:reason %)))
                  (:effects res)))))))

(defspec ^{:doc "BIP-009 Prop 3 (P-DEPLOY-3): Rolling upgrade across 6-validator cluster (:canary -> :minority -> :remainder -> :completed) preserves >= 4/6 quorum and 100% delivery at every epoch."}
  prop-rolling-upgrade-preserves-quorum-and-delivery 50
  (prop/for-all
   [seed (gen/choose 1 10000)
    start-epoch (gen/choose 10 40)]
   (let [cluster-spec (deploy/default-six-validator-cluster-spec)
         plan (deploy/build-rollout-plan
               cluster-spec
               {:start-epoch start-epoch
                :gate-window-epochs 8
                :old-code-cid (deploy/sha256-hex (utf8-bytes "v0.23.12"))
                :target-code-cid (deploy/sha256-hex (utf8-bytes (str "v0.23.13-" seed)))
                :old-config-hash (deploy/sha256-hex (utf8-bytes "cfg-v02312"))
                :target-config-hash (deploy/sha256-hex (utf8-bytes (str "cfg-v02313-" seed)))
                :ratified-bip-cid (deploy/sha256-hex (utf8-bytes "bip-009"))})
         sim-res (deploy/simulate-rollout-plan cluster-spec plan {:seed seed :fault-schedule nil})]
     (and (true? (:ok? sim-res))
          (true? (:completed? sim-res))
          (false? (:halted? sim-res))
          (false? (:rolled-back? sim-res))
          (= 1 (count (get-in plan [:stages :canary])))
          (true? (:quorum-preserved? sim-res))
          (= 0 (:finalization-stall-epochs sim-res))
          (= 1.0 (:delivery-ratio sim-res))
          (= (:target-code-cid plan) (:final-cluster-code-cid sim-res))))))

(defspec ^{:doc "BIP-009 Prop 4 (P-DEPLOY-3, P-DEPLOY-4): Any mechanical gate failure (crash mid-switch, gate partition, corrupt hash, or Byzantine wrong code hash) halts rollout without losing cluster quorum or delivery."}
  prop-failed-gate-halts-rollout-without-cluster-impact 50
  (prop/for-all
   [seed (gen/choose 1 10000)
    fault-type (gen/elements [:node-crash-mid-switch
                              :gate-epoch-partition
                              :corrupt-artifact-hash
                              :byzantine-wrong-code-hash])
    fault-stage (gen/elements [:canary :minority])]
   (let [cluster-spec (deploy/default-six-validator-cluster-spec)
         plan (deploy/build-rollout-plan
               cluster-spec
               {:start-epoch 10
                :gate-window-epochs 8
                :old-code-cid (deploy/sha256-hex (utf8-bytes "v0.23.12"))
                :target-code-cid (deploy/sha256-hex (utf8-bytes (str "v0.23.13-bad-" seed)))
                :old-config-hash (deploy/sha256-hex (utf8-bytes "cfg-v02312"))
                :target-config-hash (deploy/sha256-hex (utf8-bytes "cfg-v02313"))
                :ratified-bip-cid (deploy/sha256-hex (utf8-bytes "bip-009"))})
         sim-res (deploy/simulate-rollout-plan
                  cluster-spec
                  plan
                  {:seed seed
                   :fault-schedule {:fault-type fault-type
                                    :stage fault-stage}})]
     (and (true? (:ok? sim-res))
          (true? (:halted? sim-res))
          (true? (:rolled-back? sim-res))
          (true? (:quorum-preserved? sim-res))
          (= 1.0 (:delivery-ratio sim-res))
          (= seed (:replay-seed sim-res))
          (map? (:regression-scenario sim-res))
          (pos? (get-in sim-res [:diagnostics :rollout-gate-failed-auto-rollback] 0))))))

(defspec ^{:doc "BIP-009 Prop 5 (P-DEPLOY-2, P-DEPLOY-3): Automatic rollback restores every validator and light node to :last-known-good-code-cid and :last-known-good-config and captures a deterministic regression seed."}
  prop-rollback-restores-last-known-good-code-and-config 50
  (prop/for-all
   [seed (gen/choose 1 10000)
    stage (gen/elements [:canary :minority :remainder])]
   (let [old-code (deploy/sha256-hex (utf8-bytes (str "lkg-code-" seed)))
         new-code (deploy/sha256-hex (utf8-bytes (str "bad-code-" seed)))
         old-cfg (deploy/sha256-hex (utf8-bytes (str "lkg-cfg-" seed)))
         new-cfg (deploy/sha256-hex (utf8-bytes (str "bad-cfg-" seed)))
         cluster-spec (deploy/default-six-validator-cluster-spec)
         plan (deploy/build-rollout-plan
               cluster-spec
               {:start-epoch 20
                :gate-window-epochs 8
                :old-code-cid old-code
                :target-code-cid new-code
                :old-config-hash old-cfg
                :target-config-hash new-cfg
                :ratified-bip-cid (deploy/sha256-hex (utf8-bytes "bip-009"))})
         sim-res (deploy/simulate-rollout-plan
                  cluster-spec
                  plan
                  {:seed seed
                   :fault-schedule {:fault-type :node-crash-mid-switch
                                    :stage stage}})]
     (and (true? (:rolled-back? sim-res))
          (= old-code (:final-cluster-code-cid sim-res))
          (= old-cfg (:final-cluster-config-hash sim-res))
          (every? #(= old-code (:active-code-cid %)) (vals (:final-nodes sim-res)))
          (every? #(= old-cfg (:active-config-hash %)) (vals (:final-nodes sim-res)))
          (some #(= :regression-seed-capture (:effect %)) (:effects sim-res))))))

(defspec ^{:doc "BIP-009 Prop 6 (P-DEPLOY-5, P-DEPLOY-8): Every deployment transition appends a signed hash-chained audit record, and reconstruct-cluster-history-from-audit-trail reconstructs exact node state at any query epoch."}
  prop-every-deploy-step-emits-audit-record 50
  (prop/for-all
   [seed (gen/choose 1 10000)
    query-offset (gen/choose 0 30)]
   (let [cluster-spec (deploy/default-six-validator-cluster-spec)
         start-ep 10
         plan (deploy/build-rollout-plan
               cluster-spec
               {:start-epoch start-ep
                :gate-window-epochs 8
                :old-code-cid (deploy/sha256-hex (utf8-bytes "v0.23.12"))
                :target-code-cid (deploy/sha256-hex (utf8-bytes (str "v0.23.13-" seed)))
                :old-config-hash (deploy/sha256-hex (utf8-bytes "cfg-v02312"))
                :target-config-hash (deploy/sha256-hex (utf8-bytes (str "cfg-v02313-" seed)))
                :ratified-bip-cid (deploy/sha256-hex (utf8-bytes "bip-009"))})
         sim-res (deploy/simulate-rollout-plan cluster-spec plan {:seed seed :fault-schedule nil})
         records (:audit-trail sim-res)
         q-epoch (+ start-ep query-offset)
         reconstructed (deploy/reconstruct-cluster-history-from-audit-trail records q-epoch)]
     (and (seq records)
          (true? (:chain-valid? reconstructed))
          (true? (:signatures-valid? reconstructed))
          (= 6 (count (:nodes-at-epoch reconstructed)))
          (every? #(and (string? (:active-code-cid %))
                        (string? (:active-config-hash %))
                        (string? (:authorizing-bip-cid %)))
                  (vals (:nodes-at-epoch reconstructed)))))))

(defspec ^{:doc "BIP-009 Prop 7 (P-DEPLOY-7): Control-plane envelopes are mirrored across all available transports, delivered if ANY single transport succeeds, and emit counted :control-plane-transports-exhausted :diagnose when all fail."}
  prop-control-envelopes-delivered-on-any-single-transport 60
  (prop/for-all
   [ctrl-type (gen/elements [:channel-offer :channel-accept :channel-close
                             :p2p-offer :p2p-answer :sync-pointer
                             :artifact-replicate :replicate-pointer :governance-replicate])
    udp-up? gen/boolean
    relay-up? gen/boolean]
   (let [st0 {:pubkey "302a300506032b65700321009b33a9ebd1866d6db419edabe2de9ee74c884dc86b4214f60e3a26f04cbd9cfc"
              :diagnostics {}}
         env {:bitecho/type ctrl-type
              :type ctrl-type
              :peer "302a300506032b6570032100ccc35a321c00d0f05a056228a5d0682038235aea817a4a0bd4d6c681f5c970de"
              :session-id "sess-ctrl-1"}
         transports [{:id :validator-udp :available? true :send-ok? udp-up?}
                     {:id :https-relay :available? true :send-ok? relay-up?}]
         res (deploy/route-control-plane-envelope st0 env transports)
         st1 (:state res)]
     (if (or udp-up? relay-up?)
       (and (true? (:delivered? res))
            (= 2 (count (:transports-tried res)))
            (zero? (get-in st1 [:diagnostics :control-plane-transports-exhausted] 0)))
       (and (false? (:delivered? res))
            (= [:validator-udp :https-relay] (:transports-tried res))
            (= 1 (get-in st1 [:diagnostics :control-plane-transports-exhausted]))
            (some #(and (= :diagnose (:effect %))
                        (= :control-plane-transports-exhausted (:reason %)))
                  (:effects res)))))))

(defspec ^{:doc "BIP-009 Prop 8 (P-DEPLOY-3, P-DEPLOY-6): Heterogeneous cluster mixing :jvm and :nodejs validators and N / N+1 protocol versions finalizes blocks continuously during every stage of a rolling upgrade."}
  prop-heterogeneous-cluster-finalizes-during-rollout 50
  (prop/for-all
   [seed (gen/choose 1 10000)
    jvm-count (gen/choose 2 4)]
   (let [node-ids [:node1 :node2 :node3 :ns1 :ns2 :ns3]
         runtimes (into (vec (repeat jvm-count :jvm))
                        (repeat (- 6 jvm-count) :nodejs))
         cluster-spec (deploy/make-cluster-spec
                       (mapv (fn [nid rt] {:node-id nid :runtime rt}) node-ids runtimes))
         stages (deploy/order-rollout-stages-mixed-runtime (:nodes cluster-spec))
         plan (deploy/build-rollout-plan
               cluster-spec
               {:start-epoch 10
                :gate-window-epochs 8
                :old-code-cid (deploy/sha256-hex (utf8-bytes "v0.23.12"))
                :target-code-cid (deploy/sha256-hex (utf8-bytes (str "v0.23.13-hetero-" seed)))
                :old-config-hash (deploy/sha256-hex (utf8-bytes "cfg-v02312"))
                :target-config-hash (deploy/sha256-hex (utf8-bytes "cfg-v02313"))
                :ratified-bip-cid (deploy/sha256-hex (utf8-bytes "bip-009"))})
         sim-res (deploy/simulate-rollout-plan cluster-spec plan {:seed seed :fault-schedule nil})
         canary-plus-minority (into (vec (:canary stages)) (:minority stages))
         mixed-rts (set (map #(get-in cluster-spec [:nodes % :runtime]) canary-plus-minority))]
     (and (= #{:jvm :nodejs} mixed-rts)
          (true? (:ok? sim-res))
          (true? (:completed? sim-res))
          (= 0 (:finalization-stall-epochs sim-res))
          (pos? (:finalized-blocks-during-heterogeneous-window sim-res))))))

;; =============================================================================
;; 2. Deterministic E2E Scenarios (S-D35-1..S-D35-4)
;; =============================================================================

(deftest scenario-s-d35-1-mixed-runtime-six-validator-rolling-upgrade-zero-loss-test
  (testing "S-D35-1 (P-DEPLOY-2, P-DEPLOY-3, P-DEPLOY-5, P-DEPLOY-6, P-DEPLOY-8): 6-validator mixed JVM/Node.js rolling upgrade completes with 0 delivery loss, 0 quorum loss, full audit reconstruction, and 1.0 deploy-attributable availability"
    (let [cluster-spec (deploy/default-six-validator-cluster-spec)
          plan (deploy/build-rollout-plan
                cluster-spec
                {:start-epoch 100
                 :gate-window-epochs 8
                 :old-code-cid (deploy/sha256-hex (utf8-bytes "bitecho-v0.23.12"))
                 :target-code-cid (deploy/sha256-hex (utf8-bytes "bitecho-v0.23.13"))
                 :old-config-hash (deploy/sha256-hex (utf8-bytes "config-v0.23.12"))
                 :target-config-hash (deploy/sha256-hex (utf8-bytes "config-v0.23.13"))
                 :ratified-bip-cid "6d7d8455fbc1f4fa0cce961831ce0e921632c8e248bd5d781090747ae6302b2d"})
          sim-res (deploy/simulate-rollout-plan cluster-spec plan {:seed 1795112000 :fault-schedule nil})
          audit-trail (:audit-trail sim-res)
          sla-report (deploy/compute-sla-and-velocity-report
                      audit-trail
                      {:window-seconds 2592000
                       :target-availability 0.999999})]
      (is (true? (:ok? sim-res)))
      (is (true? (:completed? sim-res)))
      (is (= 0 (:finalization-stall-epochs sim-res)))
      (is (= 1.0 (:delivery-ratio sim-res)))
      (is (= 0 (:deploy-attributable-downtime-seconds sla-report)))
      (is (>= (:rolling-30d-availability sla-report) 0.999999))
      (is (true? (:meets-six-nines-target? sla-report)))
      (is (pos? (get-in sla-report [:velocity :total-ratified-to-live-ms])))
      ;; Reconstruct history mid-rollout (canary active, rest on old code) and post-rollout
      (let [mid-history (deploy/reconstruct-cluster-history-from-audit-trail audit-trail 104)
            end-history (deploy/reconstruct-cluster-history-from-audit-trail audit-trail 130)]
        (is (true? (:chain-valid? mid-history)))
        (is (= 1 (count (filter #(= (:target-code-cid plan) (:active-code-cid %))
                                (vals (:nodes-at-epoch mid-history))))))
        (is (= 6 (count (filter #(= (:target-code-cid plan) (:active-code-cid %))
                                (vals (:nodes-at-epoch end-history))))))))))

(deftest scenario-s-d35-2-canary-gate-failure-auto-rollback-and-seed-capture-test
  (testing "S-D35-2 (P-DEPLOY-3, P-DEPLOY-4): Canary fault triggers automatic mechanical rollback without human intervention and captures replayable regression scenario"
    (let [cluster-spec (deploy/default-six-validator-cluster-spec)
          old-code (deploy/sha256-hex (utf8-bytes "bitecho-v0.23.12"))
          bad-code (deploy/sha256-hex (utf8-bytes "bitecho-v0.23.13-broken"))
          plan (deploy/build-rollout-plan
                cluster-spec
                {:start-epoch 50
                 :gate-window-epochs 8
                 :old-code-cid old-code
                 :target-code-cid bad-code
                 :old-config-hash (deploy/sha256-hex (utf8-bytes "config-v0.23.12"))
                 :target-config-hash (deploy/sha256-hex (utf8-bytes "config-v0.23.13-broken"))
                 :ratified-bip-cid "6d7d8455fbc1f4fa0cce961831ce0e921632c8e248bd5d781090747ae6302b2d"})
          sim-res (deploy/simulate-rollout-plan
                   cluster-spec
                   plan
                   {:seed 20261119
                    :fault-schedule {:fault-type :byzantine-wrong-code-hash
                                     :stage :canary}})
          reg-eff (first (filter #(= :regression-seed-capture (:effect %)) (:effects sim-res)))]
      (is (true? (:halted? sim-res)))
      (is (true? (:rolled-back? sim-res)))
      (is (true? (:quorum-preserved? sim-res)))
      (is (= 1.0 (:delivery-ratio sim-res)))
      (is (= old-code (:final-cluster-code-cid sim-res)))
      (is (some? reg-eff))
      (is (= 20261119 (:seed reg-eff)))
      ;; Replay with the captured regression seed produces the exact same rollback verdict deterministically
      (let [replay-res (deploy/simulate-rollout-plan
                        cluster-spec
                        plan
                        {:seed (:seed reg-eff)
                         :fault-schedule (:fault-schedule reg-eff)})]
        (is (= (:audit-trail sim-res) (:audit-trail replay-res)))))))

(deftest scenario-s-d35-3-dual-transport-control-plane-redundancy-and-diagnose-test
  (testing "S-D35-3 (P-DEPLOY-7): Control-plane envelopes arrive when validator-udp drops unicast but https-relay is up, and emit counted :diagnose when all transports fail"
    (let [axiom-kp (crypto/generate-keypair "d35-s3-axiom")
          lumen-kp (crypto/generate-keypair "d35-s3-lumen")
          axiom-pk (kp->pk-hex axiom-kp)
          axiom-sk (kp->sk axiom-kp)
          lumen-pk (kp->pk-hex lumen-kp)
          lumen-sk (kp->sk lumen-kp)
          axiom-st (-> (light-core/init-light-state {:pubkey-hex axiom-pk} {:subnet-id "devnet.bitecho.org" :economy-enabled? true :burn-floor 100 :epoch 20})
                       (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
          lumen-st (-> (light-core/init-light-state {:pubkey-hex lumen-pk} {:subnet-id "devnet.bitecho.org" :economy-enabled? true :burn-floor 100 :epoch 20 :autonomous? true})
                       (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
          off-res (light-core/handle-command axiom-st {"cmd" "offer" "callee" lumen-pk "peer" lumen-pk "price" 10 "burn" 100} axiom-sk)
          offer-env (last (:net-envelopes off-res))
          ;; Transport 1 (validator UDP) fails for unicast offer, Transport 2 (HTTPS relay) succeeds
          route-ok (deploy/route-control-plane-envelope
                    (:state off-res)
                    (assoc offer-env :bitecho/type :channel-offer :peer lumen-pk)
                    [{:id :validator-udp :available? true :send-ok? false}
                     {:id :https-relay :available? true :send-ok? true}])
          ;; Lumen receives the mirrored envelope from HTTPS relay and opens the session
          lumen-rx (light-core/handle-wire-payload lumen-st offer-env lumen-sk)
          sid (get-in off-res [:response "session_id"])
          ;; Now both transports fail -> must emit counted :control-plane-transports-exhausted
          route-fail (deploy/route-control-plane-envelope
                      (:state route-ok)
                      (assoc offer-env :bitecho/type :channel-offer :peer lumen-pk)
                      [{:id :validator-udp :available? true :send-ok? false}
                       {:id :https-relay :available? true :send-ok? false}])]
      (is (true? (:delivered? route-ok)))
      (is (= [:https-relay] (:succeeded-transports route-ok)))
      (is (= "open" (get-in (:state lumen-rx) [:sessions sid :state])))
      (is (false? (:delivered? route-fail)))
      (is (= 1 (get-in (:state route-fail) [:diagnostics :control-plane-transports-exhausted])))
      (is (some #(= :control-plane-transports-exhausted (:reason %)) (:effects route-fail))))))

(deftest scenario-s-d35-4-monte-carlo-theta-star-config-pointer-and-genesis-reset-test
  (testing "S-D35-4 (P-DEPLOY-1, P-DEPLOY-9): Selected Monte Carlo v2.1 theta* activates via config-pointer, balance-preserving genesis reset increments :network-generation and preserves exact balances, and light-node auto-resyncs generation while preserving sessions and petnames"
    (let [val1-kp (crypto/generate-keypair "d35-s4-val1")
          val2-kp (crypto/generate-keypair "d35-s4-val2")
          val3-kp (crypto/generate-keypair "d35-s4-val3")
          val4-kp (crypto/generate-keypair "d35-s4-val4")
          val-kps [val1-kp val2-kp val3-kp val4-kp]
          val-pks (mapv kp->pk-hex val-kps)
          alice-kp (crypto/generate-keypair "d35-s4-alice")
          bob-kp (crypto/generate-keypair "d35-s4-bob")
          alice-pk (kp->pk-hex alice-kp)
          bob-pk (kp->pk-hex bob-kp)
          pre-ledger {alice-pk (account/map->AccountState {:balance 123456 :seq 9 :deps ["tx-old-9"]})
                      bob-pk (account/map->AccountState {:balance 789000 :seq 4 :deps ["tx-old-4"]})}
          st0 (-> (sm/init-state [] (first val-pks) (config/devnet-6-config {:validators val-pks}))
                  (assoc :epoch 420
                         :network-generation 1
                         :validators val-pks
                         :trusted-deploy-authorities (set val-pks)
                         :ledger pre-ledger))
          preserved-blob (deploy/make-preserved-accounts-blob pre-ledger)
          reset-ptr (deploy/build-signed-genesis-reset-pointer
                     (mapv (fn [kp] {:pubkey (kp->pk-hex kp) :privkey (kp->sk kp)}) val-kps)
                     {:network "devnet"
                      :seq 1
                      :from-generation 1
                      :to-generation 2
                      :preserved-accounts-cid (:cid preserved-blob)
                      :policy-theta deploy/ratified-theta-star
                      :ratified-bip-cid "6d7d8455fbc1f4fa0cce961831ce0e921632c8e248bd5d781090747ae6302b2d"})
          reset-res (deploy/execute-balance-preserving-genesis-reset st0 reset-ptr preserved-blob)
          st-reset (:state reset-res)
          ;; Stale pre-reset envelope (generation 1) must be rejected with counted :stale-network-generation
          stale-check (deploy/validate-envelope-network-generation st-reset {:network-generation 1 :type :transfer})
          ;; Light node observing generation 2 in a quorum-verified chain-state snapshot re-baselines epoch/seq while keeping petnames & sessions
          nodes-map (into {} (map-indexed (fn [i kp] [(keyword (str "node" (inc i))) {:pubkey (kp->pk-hex kp)}]) val-kps))
          ln-st0 (-> (light-core/init-light-state {:pubkey-hex alice-pk} {:subnet-id "devnet.bitecho.org" :epoch 420 :bootstrap {:nodes nodes-map}})
                     (assoc :network-generation 1
                            :petnames {"bob" bob-pk}
                            :sessions {"sess-1" {:session-id "sess-1" :peer bob-pk :state "open"}}
                            :account {:balance 123456 :spendable 123456 :seq 9 :deps ["tx-old-9"] :finalized-epoch 420}
                            :transfer-seq 9
                            :last-transfer-hash "tx-old-9"))
          snaps (mapv (fn [kp]
                        (-> (light-core/sign-chain-state-snapshot
                             {:validator-pubkey (kp->pk-hex kp)
                              :pubkey alice-pk
                              :finalized-epoch 2
                              :balance 123456
                              :spendable 123456
                              :seq 0
                              :deps []
                              :escrows []
                              :nonce "gen2-sync"}
                             (kp->sk kp))
                            (assoc :network-generation 2)))
                      val-kps)
          ln-synced (reduce (fn [acc s]
                              (let [r (light-core/handle-wire-chain-state-snapshot (:state acc) s)]
                                {:state (:state r)
                                 :events (into (:events acc) (:stdout-events r))}))
                            {:state ln-st0 :events []}
                            snaps)
          ln-st1 (:state ln-synced)]
      (is (true? (:ok? reset-res)))
      (is (= 0 (:epoch st-reset)))
      (is (= 2 (:network-generation st-reset)))
      (is (= 123456 (get-in st-reset [:ledger alice-pk :balance])))
      (is (= 0 (get-in st-reset [:ledger alice-pk :seq])))
      (is (= 789000 (get-in st-reset [:ledger bob-pk :balance])))
      (is (= 0 (get-in st-reset [:ledger bob-pk :seq])))
      (is (= deploy/ratified-theta-star (get-in st-reset [:config :policy-theta])))
      (is (= 100 (get-in st-reset [:config :min-signaling-burn])))
      (is (false? (:ok? stale-check)))
      (is (= 1 (get-in (:state stale-check) [:diagnostics :stale-network-generation])))
      ;; Light node checks
      (is (= 2 (:network-generation ln-st1)))
      (is (= 2 (:epoch ln-st1)))
      (is (= 123456 (get-in ln-st1 [:account :balance])))
      (is (= 0 (get-in ln-st1 [:account :seq])))
      (is (= 0 (:transfer-seq ln-st1)))
      (is (= {"bob" bob-pk} (:petnames ln-st1)))
      (is (= "open" (get-in ln-st1 [:sessions "sess-1" :state])))
      (is (some #(= "network-generation-resynced" (get % "event")) (:events ln-synced)))
      (is (= "0.23.13" config/version))
      (let [bip009-spec (edn/read-string (slurp "docs/bips/bip-009-v02313.edn"))
            gate-check (gov/verify-bip-admission-gates bip009-spec)]
        (is (true? (:ok? gate-check)))
        (is (empty? (:missing-gates gate-check)))))))
