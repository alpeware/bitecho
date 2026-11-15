(ns bitecho.governance.core-test
  "Generative and unit tests for Milestone D20: Autonomous Development & Tri-Circle
   Sociocratic Governance Protocol (`INV-D20-1`..`INV-D20-4`, `A-CARB-D20-1`..`A-CARB-D20-3`, `A-D20-1`..`A-D20-3`)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def ^:private make-kp
  (memoize
   (fn [seed]
     (let [kp (crypto/generate-keypair seed)]
       {:public (:public kp)
        :private (:private kp)
        :hex (basalt/bytes->hex (:public kp))}))))

(def ^:private valid-invariant-diff
  {:defspec-vars ["bitecho.governance.core-test/prop-bip-admission-gate-completeness"]
   :sans-io-pure? true
   :diagnose-coverage? true
   :co-committed-spec-and-flags? true})

(def ^:private valid-oracle-receipts
  {:four-way-golden-oracle {:passed? true :digest "a1b2c3d4"}
   :vopr-jepsen-non-vacuity {:passed? true :seed 20261115}
   :deterministic-bundle-sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
   :bwrap-civilization-regression {:passed? true :experiment-id "homebrew-cafe-civilization-01"}})

;; =============================================================================
;; 1. Layer 1: Fractal Lab Subnets & RFC 6962 Domain-Separated Merkle Anchoring
;; =============================================================================

(defspec ^{:doc "Property: Lab subnet RFC 6962 domain-separated binary Merkle root anchoring."}
  prop-lab-subnet-rfc6962-merkle-anchoring 30
  (prop/for-all [leaves (gen/not-empty (gen/vector (gen/not-empty gen/string-alphanumeric) 1 12))
                 subnet-suffix (gen/not-empty gen/string-alphanumeric)
                 min-burn (gen/choose 0 500)]
                (let [subnet-id (str "lab/" subnet-suffix)
                      st0 (gov/init-governance-state)
                      reg-res (gov/register-lab-subnet
                               st0
                               {:subnet-id subnet-id
                                :min-signaling-burn min-burn
                                :admission-gate :permissionless
                                :capability-schemas [:capability/uop-kernel :capability/oracle]
                                :settlement-take-bps 50})
                      st1 (:state reg-res)
                      root1 (gov/compute-rfc6962-merkle-root leaves)
                      root2 (gov/compute-rfc6962-merkle-root leaves)
                      ;; Verify RFC 6962 domain separation: single leaf hash must equal SHA-256(0x00 || utf8(leaf))
                      single-leaf (first leaves)
                      expected-single (basalt/bytes->hex
                                       (crypto/sha256
                                        (fressian/concat-bytes (byte-array [(byte 0x00)])
                                                               (fressian/utf8->bytes single-leaf))))
                      anchor-res (gov/anchor-subnet-merkle-root st1 subnet-id 10 leaves)]
                  (and (:ok? reg-res)
                       (= root1 root2)
                       (= 64 (count root1))
                       (= expected-single (gov/compute-rfc6962-merkle-root [single-leaf]))
                       ;; Modifying a leaf or duplicating to internal node never collides with single leaf
                       (or (= 1 (count leaves))
                           (not= expected-single root1))
                       (:ok? anchor-res)
                       (= root1 (get-in (:state anchor-res) [:subnet-anchors [subnet-id 10] :merkle-root]))))))

;; =============================================================================
;; 2. Layer 2: Executable BIP Admission Gates (INV-D20-1, Rule 5)
;; =============================================================================

(defspec ^{:doc "Property: BIP admission gate completeness and counted diagnostic rejection."}
  prop-bip-admission-gate-completeness 30
  (prop/for-all [drop-inv-key (gen/elements [nil :defspec-vars :sans-io-pure? :diagnose-coverage? :co-committed-spec-and-flags?])
                 drop-oracle-key (gen/elements [nil :four-way-golden-oracle :vopr-jepsen-non-vacuity :deterministic-bundle-sha256 :bwrap-civilization-regression])]
                (let [author (make-kp "bip-author-1")
                      inv-diff (if drop-inv-key
                                 (dissoc valid-invariant-diff drop-inv-key)
                                 valid-invariant-diff)
                      oracles (if drop-oracle-key
                                (dissoc valid-oracle-receipts drop-oracle-key)
                                valid-oracle-receipts)
                      bip {:bip-id "BIP-0042"
                           :title "Demand-Gated Minting Adjustment"
                           :author-pubkey (:hex author)
                           :invariant-diff inv-diff
                           :oracle-receipts oracles}
                      st0 (gov/init-governance-state)
                      res (gov/submit-bip st0 bip (:private author))
                      should-pass? (and (nil? drop-inv-key) (nil? drop-oracle-key))]
                  (if should-pass?
                    (and (:ok? res)
                         (string? (:cid res))
                         (= "bip/BIP-0042" (get-in res [:pointer :pointer/path]))
                         (= "bitecho.org/dev" (get-in res [:pointer :pointer/subnet])))
                    (and (false? (:ok? res))
                         (seq (:missing-gates res))
                         (= :bip-admission-rejected (get-in res [:effects 0 :reason]))
                         (pos? (get-in (:state res) [:diagnostics :bip-admission-rejected] 0)))))))

;; =============================================================================
;; 3. Layer 3: Bilateral Bounty Conservation & Heterogeneous Quorum (A-CARB-D20-1..2, A-D20-2)
;; =============================================================================

(defspec ^{:doc "Property: Bilateral bounty zero-dust conservation and heterogeneous 3-party quorum."}
  prop-bilateral-bounty-conservation-and-heterogeneous-quorum 40
  (prop/for-all [gross-amount (gen/choose 1 100000000)
                 take-bps (gen/choose 10 500)
                 builder-bps (gen/choose 5000 9500)
                 distinct-signers? gen/boolean]
                (let [split (gov/calculate-bounty-split gross-amount {:take-bps take-bps :builder-bps builder-bps})
                      builder (make-kp "bounty-builder")
                      auditor (if distinct-signers? (make-kp "bounty-auditor") builder)
                      maintainer (make-kp "bounty-maintainer")
                      st0 (gov/init-governance-state)
                      esc-res (gov/create-bounty-escrow
                               st0
                               {:bounty-id "bounty-42"
                                :target-bip-cid "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                :gross-amount gross-amount
                                :take-bps take-bps
                                :builder-bps builder-bps
                                :maintainer-pubkey (:hex maintainer)})
                      st1 (:state esc-res)
                      bundle-sha "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                      claim (gov/build-signed-bounty-claim
                             {:bounty-id "bounty-42"
                              :patch-bundle-cid "aaaa"
                              :reproducible-sha256 bundle-sha
                              :builder-kp builder
                              :auditor-kp auditor
                              :auditor-model "claude-opus-5-5"
                              :maintainer-kp maintainer})
                      settle-res (gov/settle-bounty-escrow st1 "bounty-42" claim)]
                  (and (= gross-amount (+ (:builder-net split)
                                          (:auditor-net split)
                                          (:protocol-take split)))
                       (>= (:protocol-take split) 1)
                       (if distinct-signers?
                         (and (:ok? settle-res)
                              (= (:builder-net split) (get-in settle-res [:payouts (:hex builder)]))
                              (= (:auditor-net split) (get-in settle-res [:payouts (:hex auditor)])))
                         (and (false? (:ok? settle-res))
                              (= :sybil-bounty-claim-rejected (:error settle-res))
                              (pos? (get-in (:state settle-res) [:diagnostics :sybil-bounty-claim-rejected] 0))))))))

;; =============================================================================
;; 4. Layer 4: Tri-Circle Sociocratic Consent & Paramount Objection Gate
;; =============================================================================

(defspec ^{:doc "Property: Tri-Circle Sociocratic consent and reproducible counterexample regression gate."}
  prop-tri-circle-sociocratic-consent-and-counterexample-gate 30
  (prop/for-all [objection-mode (gen/elements [:none :unsubstantiated :valid-vopr :valid-mc :valid-sec])
                 seed (gen/choose 1 999999)]
                (let [author (make-kp "gov-author")
                      steward (make-kp "gov-steward")
                      validator (make-kp "gov-validator")
                      anchor-user (make-kp "gov-user")
                      st0 (-> (gov/init-governance-state)
                              (gov/register-circle-member :builders-stewards (:hex steward) {:verified-commits 12})
                              (gov/register-circle-member :mesh-validators (:hex validator) {:participation 1.0 :stake 500000})
                              (gov/register-circle-member :anchor-agent-users (:hex anchor-user) {:trailing-burned-ech 25000}))
                      bip {:bip-id "BIP-0099"
                           :title "Autonomous Lab Subnet Upgrade"
                           :author-pubkey (:hex author)
                           :invariant-diff valid-invariant-diff
                           :oracle-receipts valid-oracle-receipts}
                      st1 (:state (gov/submit-bip st0 bip (:private author)))
                      st2 (:state (gov/submit-circle-response
                                   st1 "BIP-0099" :builders-stewards (:hex steward)
                                   {:stance :consent}))
                      st3 (:state (gov/submit-circle-response
                                   st2 "BIP-0099" :mesh-validators (:hex validator)
                                   {:stance :consent}))
                      user-resp (case objection-mode
                                  :none {:stance :consent}
                                  :unsubstantiated {:stance :paramount-objection
                                                    :reason "I just don't like this parameter"}
                                  :valid-vopr {:stance :paramount-objection
                                               :counterexample {:type :vopr-seed
                                                                :seed seed
                                                                :failing-invariant :INV-CF-1}}
                                  :valid-mc {:stance :paramount-objection
                                             :counterexample {:type :monte-carlo-insolvency
                                                              :seed seed
                                                              :path-id 2
                                                              :theta {:k-bps 4500}}}
                                  :valid-sec {:stance :paramount-objection
                                              :counterexample {:type :security-regression
                                                               :reproducer-cid "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                                               :violated-rule :INV-D20-1}})
                      resp-res (gov/submit-circle-response
                                st3 "BIP-0099" :anchor-agent-users (:hex anchor-user) user-resp)
                      st4 (:state resp-res)
                      eval-res (gov/evaluate-tri-circle-consent st4 "BIP-0099")]
                  (case objection-mode
                    :none
                    (and (:ratified? eval-res)
                         (= :ratified (:status eval-res)))

                    :unsubstantiated
                    (and (:ratified? eval-res)
                         (= :ratified (:status eval-res))
                         (pos? (get-in st4 [:diagnostics :unsubstantiated-objection-ignored] 0)))

                    (:valid-vopr :valid-mc :valid-sec)
                    (and (false? (:ratified? eval-res))
                         (= :blocked-by-paramount-objection (:status eval-res))
                         (= 1 (count (:regression-vectors st4))))))))

(deftest unauthorized-circle-member-rejected-test
  (testing "Zero-weight or unregistered circle responses fail closed with counted diagnostic (A-CARB-D20-3)"
    (let [author (make-kp "auth-kp")
          outsider (make-kp "outsider-kp")
          st0 (:state (gov/submit-bip
                       (gov/init-governance-state)
                       {:bip-id "BIP-0100"
                        :title "Test BIP"
                        :author-pubkey (:hex author)
                        :invariant-diff valid-invariant-diff
                        :oracle-receipts valid-oracle-receipts}
                       (:private author)))
          res (gov/submit-circle-response
               st0 "BIP-0100" :builders-stewards (:hex outsider) {:stance :consent})]
      (is (false? (:ok? res)))
      (is (= :unauthorized-circle-member (:error res)))
      (is (= 1 (get-in (:state res) [:diagnostics :unauthorized-circle-member]))))))

;; =============================================================================
;; 5. Milestone D22: Fractal Subnet Governance Isolation & Epoch Activation
;; =============================================================================

(defspec ^{:doc "Property: Concurrent fractal subnets isolate BIPs, circle rosters, capability-backed bounties, regression vectors, and epoch-boundary policy activations (`A-D22-1`, `A-CARB-D22-1`, `A-CARB-D22-2`)."}
  prop-fractal-subnet-governance-isolation-and-epoch-activation 25
  (prop/for-all [act-epoch-dev (gen/choose 5 25)
                 act-epoch-child (gen/choose 26 50)
                 bounty-dev (gen/choose 1000 50000)
                 bounty-child (gen/choose 500 25000)
                 block-child-bip2? gen/boolean]
                (let [sub-dev "bitecho-dev"
                      sub-child "new-alexandria"
                      dev-steward (make-kp "d22-dev-steward")
                      dev-val (make-kp "d22-dev-val")
                      dev-user (make-kp "d22-dev-user")
                      child-steward (make-kp "d22-child-steward")
                      child-val (make-kp "d22-child-val")
                      child-user (make-kp "d22-child-user")
                      builder (make-kp "d22-builder")
                      auditor (make-kp "d22-auditor")
                      ;; Register distinct circle rosters on sub-dev and sub-child
                      st0 (-> (gov/init-governance-state)
                              (gov/register-circle-member sub-dev :builders-stewards (:hex dev-steward) {:verified-commits 15})
                              (gov/register-circle-member sub-dev :mesh-validators (:hex dev-val) {:participation 1.0 :stake 500000})
                              (gov/register-circle-member sub-dev :anchor-agent-users (:hex dev-user) {:trailing-burned-ech 10000})
                              (gov/register-circle-member sub-child :builders-stewards (:hex child-steward) {:verified-commits 8})
                              (gov/register-circle-member sub-child :mesh-validators (:hex child-val) {:participation 0.95 :stake 300000})
                              (gov/register-circle-member sub-child :anchor-agent-users (:hex child-user) {:trailing-burned-ech 4000}))
                      ;; Cross-subnet circle member cannot vote on the other subnet
                      cross-vote (gov/submit-circle-response
                                  st0 sub-dev "BIP-001" :builders-stewards (:hex child-steward) {:stance :consent})
                      ;; Submit BIP-001 on sub-dev and NAF-BIP-01 on sub-child with distinct policy-theta and activate-at-epoch
                      theta-dev {:k-bps 4582 :max-stake-multiplier 2.2 :treasury-trailing-epochs 78}
                      theta-child {:min-signaling-burn 25 :settlement-take-bps 100}
                      bip-dev {:bip-id "BIP-001"
                               :subnet-id sub-dev
                               :title "Tokenomics v2.2"
                               :author-pubkey (:hex dev-steward)
                               :policy-theta theta-dev
                               :activate-at-epoch act-epoch-dev
                               :invariant-diff valid-invariant-diff
                               :oracle-receipts valid-oracle-receipts}
                      bip-child {:bip-id "NAF-BIP-01"
                                 :subnet-id sub-child
                                 :title "New Alexandria Local Burn Policy"
                                 :author-pubkey (:hex child-steward)
                                 :policy-theta theta-child
                                 :activate-at-epoch act-epoch-child
                                 :invariant-diff valid-invariant-diff
                                 :oracle-receipts valid-oracle-receipts}
                      res-bip-dev (gov/submit-bip st0 bip-dev (:private dev-steward))
                      res-bip-child (gov/submit-bip (:state res-bip-dev) bip-child (:private child-steward))
                      st1 (:state res-bip-child)
                      ;; Create capability-backed bounties on both subnets with the SAME local bounty-id "bounty-1" to verify zero collision
                      esc-dev (gov/create-bounty-escrow
                               st1
                               {:bounty-id "bounty-1"
                                :subnet-id sub-dev
                                :target-bip-cid (:cid res-bip-dev)
                                :gross-amount bounty-dev
                                :maintainer-pubkey (:hex dev-steward)}
                               (:private dev-steward))
                      esc-child (gov/create-bounty-escrow
                                 (:state esc-dev)
                                 {:bounty-id "bounty-1"
                                  :subnet-id sub-child
                                  :target-bip-cid (:cid res-bip-child)
                                  :gross-amount bounty-child
                                  :maintainer-pubkey (:hex child-steward)}
                                 (:private child-steward))
                      st2 (:state esc-child)
                      ;; Settle sub-dev bounty-1; sub-child bounty-1 must remain :locked
                      bundle-sha "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                      claim-dev (gov/build-signed-bounty-claim
                                 {:bounty-id "bounty-1"
                                  :patch-bundle-cid "cid-dev-patch"
                                  :reproducible-sha256 bundle-sha
                                  :builder-kp builder
                                  :auditor-kp auditor
                                  :maintainer-kp dev-steward})
                      settle-dev (gov/settle-bounty-escrow st2 sub-dev "bounty-1" claim-dev)
                      st3 (:state settle-dev)
                      ;; Ratify both BIP-001 on sub-dev and NAF-BIP-01 on sub-child
                      st4 (-> st3
                              (gov/submit-circle-response sub-dev "BIP-001" :builders-stewards (:hex dev-steward) {:stance :consent})
                              :state
                              (gov/submit-circle-response sub-dev "BIP-001" :mesh-validators (:hex dev-val) {:stance :consent})
                              :state
                              (gov/submit-circle-response sub-dev "BIP-001" :anchor-agent-users (:hex dev-user) {:stance :consent})
                              :state
                              (gov/submit-circle-response sub-child "NAF-BIP-01" :builders-stewards (:hex child-steward) {:stance :consent})
                              :state
                              (gov/submit-circle-response sub-child "NAF-BIP-01" :mesh-validators (:hex child-val) {:stance :consent})
                              :state
                              (gov/submit-circle-response sub-child "NAF-BIP-01" :anchor-agent-users (:hex child-user) {:stance :consent})
                              :state)
                      eval-dev (gov/evaluate-tri-circle-consent st4 sub-dev "BIP-001")
                      eval-child (gov/evaluate-tri-circle-consent (:state eval-dev) sub-child "NAF-BIP-01")
                      st5 (:state eval-child)
                      ;; Optional second BIP on sub-child that gets blocked by paramount objection
                      st6 (if block-child-bip2?
                            (let [b2 (assoc bip-child :bip-id "NAF-BIP-02")
                                  s-b2 (:state (gov/submit-bip st5 b2 (:private child-steward)))
                                  s-obj (:state (gov/submit-circle-response
                                                 s-b2 sub-child "NAF-BIP-02" :mesh-validators (:hex child-val)
                                                 {:stance :paramount-objection
                                                  :counterexample {:type :vopr-seed
                                                                   :seed 424242
                                                                   :failing-invariant :INV-NAF-1}}))]
                              (:state (gov/evaluate-tri-circle-consent s-obj sub-child "NAF-BIP-02")))
                            st5)
                      ;; Activate epoch upgrades at act-epoch-dev (only sub-dev activates) and then at act-epoch-child (sub-child activates)
                      act1 (gov/activate-epoch-upgrades st6 act-epoch-dev)
                      st7 (:state act1)
                      act2 (gov/activate-epoch-upgrades st7 act-epoch-child)
                      st8 (:state act2)]
                  (and (false? (:ok? cross-vote))
                       (= :unauthorized-circle-member (:error cross-vote))
                       (:ok? settle-dev)
                       (= :settled (:status (gov/get-bounty st8 sub-dev "bounty-1")))
                       (= :locked (:status (gov/get-bounty st8 sub-child "bounty-1")))
                       (some? (get-in st8 [:capabilities [sub-dev "bounty/bounty-1"]]))
                       (some? (get-in st8 [:capabilities [sub-child "bounty/bounty-1"]]))
                       (:ratified? eval-dev)
                       (:ratified? eval-child)
                       (= :ratified (:status (gov/get-bip st8 sub-dev "BIP-001")))
                       (= :ratified (:status (gov/get-bip st8 sub-child "NAF-BIP-01")))
                       ;; At act-epoch-dev: sub-dev policy is active, sub-child policy is not yet active
                       (= theta-dev (get-in st7 [:subnet-policies sub-dev]))
                       (nil? (get-in st7 [:subnet-policies sub-child]))
                       ;; At act-epoch-child: both subnet policies are active and isolated
                       (= theta-dev (get-in st8 [:subnet-policies sub-dev]))
                       (= theta-child (get-in st8 [:subnet-policies sub-child]))
                       ;; Regression vectors are strictly isolated per subnet
                       (empty? (gov/get-subnet-regression-vectors st8 sub-dev))
                       (if block-child-bip2?
                         (= 1 (count (gov/get-subnet-regression-vectors st8 sub-child)))
                         (empty? (gov/get-subnet-regression-vectors st8 sub-child)))))))

