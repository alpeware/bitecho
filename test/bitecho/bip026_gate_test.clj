(ns bitecho.bip026-gate-test
  "BIP-026 Draft 2 Bug-Confirmation Gate Scenarios (B1–B12).
   Adopted directly from Lumen's Batch 1 (CID 6d0ab3ab...) & Batch 2 (CID 8392e7e7...) specs.

   Acceptance rule:
   1. Baseline sanity check passes on pre-fix code (anti-vacuity guard).
   2. Fails RED on pre-fix c6b558c for the exact documented reason.
   3. Flips GREEN only when BIP-026 Draft 2 (CID c72d4614...) normative fix lands."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.circles.mc-harness :as mc-harness]
            [bitecho.circles.vault :as vault]
            [bitecho.config :as config]
            [bitecho.core.circle :as circle]
            [bitecho.core.data :as data]
            [bitecho.core.mesh :as core-mesh]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defn- gen-kp
  []
  (let [kp (crypto/generate-keypair)
        spki (circle/normalize-spki-pubkey (basalt/bytes->hex (:public kp)))]
    (assoc kp :spki spki)))

(defn- finalize-single-block
  "Helper: constructs a single finalized block at `epoch` containing `receipts`
   and runs `sm/execute-finalized-blocks` cleanly on `state`."
  [state epoch receipts]
  (let [b-hash (str "blk-bip026-" epoch "-" (count receipts))
        blk (streamlet/map->Block {:hash b-hash
                                   :epoch epoch
                                   :parent-hash (or (:latest-finalized-block-hash state) "genesis")
                                   :payload (vec receipts)
                                   :receipts (vec receipts)})
        st (-> state
               (assoc-in [:blocks b-hash] blk)
               (assoc :latest-finalized-block-hash b-hash)
               (update :finalized-blocks (fnil conj #{}) b-hash))]
    (sm/execute-finalized-blocks st)))

;; =============================================================================
;; SCEN-B1: Unsigned :vault-create & :vault-spend-dac-issue Unbacked Minting
;; =============================================================================

(deftest scen-b1-unsigned-vault-create-and-dac-issue-rejected
  (let [payer (gen-kp)
        root-kp (gen-kp)
        attacker (gen-kp)
        ph (puzzle/puzzle-cid (vault/canonical-multisig-treasury-puzzle-source 1 [(:spki root-kp)]))
        s0 (vault/init-vaults-state
            {:network-uri "devnet.bitecho.org"
             :network-genesis-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             :genesis-custody-supply 1010000
             :ledger {(:spki payer) {:balance 10000 :seq 0 :deps []}}
             :vaults {"vault:root" {:vault-id "vault:root"
                                    :entity-uri "root"
                                    :custody-bucket :ecosystem
                                    :puzzle-hash ph
                                    :balance 1000000
                                    :vault-seq 1
                                    :created-epoch 0
                                    :status :active}}
             :chartered-vaults #{"vault:root"}})]
    (testing "Baseline sanity: 7-bucket conservation holds before trigger"
      (is (:ok? (vault/verify-7-bucket-conservation s0))))

    (testing "B1-a: Unsigned :vault-create minting 1B ECH out of thin air MUST fail closed"
      (let [res (vault/create-vault s0 {:vault-id "vault:attacker/mint"
                                        :entity-uri "attacker/mint"
                                        :custody-bucket nil
                                        :puzzle-hash ph
                                        :payer (:spki payer)
                                        :balance 1000000000
                                        :created-epoch 1})]
        (is (not (:ok? res)) "Unsigned/unfunded :vault-create must be rejected")
        (is (nil? (get-in (:state res) [:vaults "vault:attacker/mint"])))
        (is (:ok? (vault/verify-7-bucket-conservation (:state res))))))

    (testing "B1-b: Signed :vault-create exceeding payer ledger balance MUST fail closed"
      (let [r-unfunded {:vault-id "vault:payer/overdraft"
                        :entity-uri "payer/overdraft"
                        :custody-bucket nil
                        :puzzle-hash ph
                        :payer (:spki payer)
                        :balance 50000
                        :created-epoch 1}
            sig-bytes (fressian/encode-canonical
                       ["bitecho-vault-create-v1"
                        (:network-uri s0)
                        (:network-genesis-cid s0)
                        (:vault-id r-unfunded)
                        (:entity-uri r-unfunded)
                        (:custody-bucket r-unfunded)
                        (:puzzle-hash r-unfunded)
                        (:payer r-unfunded)
                        (long (:balance r-unfunded))
                        (long (:created-epoch r-unfunded))])
            r-signed (assoc r-unfunded :signature (basalt/bytes->hex (crypto/sign (:private payer) sig-bytes)))
            res (vault/create-vault s0 r-signed)]
        (is (not (:ok? res)) "Unfunded :vault-create must fail with :insufficient-funds")
        (is (:ok? (vault/verify-7-bucket-conservation (:state res))))))

    (testing "B1-c: Unsigned :vault-spend-dac-issue against vault:root MUST fail closed"
      (let [res (vault/issue-vault-spend-dac s0 {:dac-id "dac-forged-1"
                                                 :vault-id "vault:root"
                                                 :holder-pubkey (:spki attacker)
                                                 :max-per-epoch-bps 500
                                                 :issued-epoch 1
                                                 :expires-epoch 100})]
        (is (not (:ok? res)) "Unsigned :vault-spend-dac-issue must fail closed")
        (is (nil? (get-in (:state res) [:vault-spend-dacs "dac-forged-1"])))))

    (testing "Control: Validly signed & funded :vault-create debits payer and preserves conservation"
      (let [r-legit {:type :vault-create
                     :receipt-id "rcpt-vault-create-legit-1"
                     :vault-id "vault:payer/legit"
                     :entity-uri "payer/legit"
                     :custody-bucket nil
                     :puzzle-hash ph
                     :payer (:spki payer)
                     :balance 1000
                     :created-epoch 1}
            sig-bytes (fressian/encode-canonical
                       ["bitecho-vault-create-v1"
                        (:network-uri s0)
                        (:network-genesis-cid s0)
                        (:vault-id r-legit)
                        (:entity-uri r-legit)
                        (:custody-bucket r-legit)
                        (:puzzle-hash r-legit)
                        (:payer r-legit)
                        (long (:balance r-legit))
                        (long (:created-epoch r-legit))])
            r-signed (assoc r-legit :signature (basalt/bytes->hex (crypto/sign (:private payer) sig-bytes)))
            sm-state (merge (sm/init-state [] {:network-uri "devnet.bitecho.org"
                                               :network-genesis-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                               :ledger (:ledger s0)})
                            s0)
            res (vault/create-vault s0 r-signed)]
        (is (true? (sm/validate-gossiped-receipt? sm-state r-signed))
            "Validly signed & funded :vault-create must be admitted by validate-gossiped-receipt?")
        (is (:ok? res))
        (is (= 9000 (get-in (:state res) [:ledger (:spki payer) :balance])))
        (is (= 1000 (get-in (:state res) [:vaults "vault:payer/legit" :balance])))
        (is (:ok? (vault/verify-7-bucket-conservation (:state res))))))))

;; =============================================================================
;; SCEN-B2: Custody-Vault Burns Isolated from R_trailing + Checkpoint Compatibility
;; =============================================================================

(deftest scen-b2-custody-burn-isolation-and-checkpoint-compat
  (let [owner (gen-kp)
        recv (gen-kp)
        p-src (vault/canonical-multisig-treasury-puzzle-source 1 [(:spki owner)])
        ph (puzzle/puzzle-cid p-src)
        net-uri "devnet.bitecho.org"
        gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        s0 (merge (sm/init-state [] {:network-uri net-uri
                                     :network-genesis-cid gen-cid
                                     :treasury-pubkey (:spki owner)})
                  (vault/init-vaults-state
                   {:network-uri net-uri
                    :network-genesis-cid gen-cid
                    :genesis-custody-supply 2100100000
                    :vaults {"v-boot" {:vault-id "v-boot"
                                       :entity-uri "root/bootstrap"
                                       :custody-bucket :bootstrap
                                       :puzzle-hash ph
                                       :balance 2100000000
                                       :vault-seq 1
                                       :created-epoch 0
                                       :status :active}
                             "v-org" {:vault-id "v-org"
                                      :entity-uri "org/main"
                                      :custody-bucket nil
                                      :puzzle-hash ph
                                      :balance 100000
                                      :vault-seq 1
                                      :created-epoch 0
                                      :status :active}}}))]
    (testing "Baseline sanity: 7-bucket conservation holds"
      (is (:ok? (vault/verify-7-bucket-conservation s0))))

    (testing "B2-a: Custody vault :release burn goes to :total-burned ONLY, NEVER :epoch-settlement-takes; organic goes to BOTH"
      (let [boot-outs [{:type :release :receiver (:spki recv) :amount 2100000000}]
            boot-digest (vault/treasury-spend-digest {:network-uri net-uri
                                                      :network-genesis-cid gen-cid
                                                      :vault-id "v-boot"
                                                      :puzzle-hash ph
                                                      :vault-seq 1
                                                      :outputs boot-outs
                                                      :next-puzzle-hash ph})
            boot-sig (basalt/bytes->hex (crypto/sign (:private owner) boot-digest))
            res-boot (vault/spend-vault s0 {:vault-id "v-boot"
                                            :vault-seq 1
                                            :puzzle-source p-src
                                            :solution {:outputs boot-outs
                                                       :signatures {(:spki owner) boot-sig}}
                                            :epoch 10})
            s1 (:state res-boot)
            org-outs [{:type :release :receiver (:spki recv) :amount 10000}
                      {:type :relock :amount 90000 :next-puzzle-hash ph}]
            org-digest (vault/treasury-spend-digest {:network-uri net-uri
                                                     :network-genesis-cid gen-cid
                                                     :vault-id "v-org"
                                                     :puzzle-hash ph
                                                     :vault-seq 1
                                                     :outputs org-outs
                                                     :next-puzzle-hash ph})
            org-sig (basalt/bytes->hex (crypto/sign (:private owner) org-digest))
            res-org (vault/spend-vault s1 {:vault-id "v-org"
                                           :vault-seq 1
                                           :puzzle-source p-src
                                           :solution {:outputs org-outs
                                                      :signatures {(:spki owner) org-sig}}
                                           :epoch 10})
            s2 (:state res-org)]
        (is (:ok? res-boot))
        (is (= 10500000 (:total-burned s1)))
        (is (= 0 (long (get-in s1 [:epoch-settlement-takes 10] 0)))
            "Custody vault take MUST NOT feed :epoch-settlement-takes / R_trailing")
        (is (:ok? res-org))
        (is (= 10500050 (:total-burned s2)))
        (is (= 50 (long (get-in s2 [:epoch-settlement-takes 10] 0)))
            "Organic non-custody vault take MUST feed :epoch-settlement-takes")
        (is (:ok? (vault/verify-7-bucket-conservation s2)))))

    (testing "B2-b: Checkpoint snapshot preserves :vaults, :bounty-escrows, :total-burned, :validator-set-history & digest is backward-compatible at 0"
      (let [s-zero (sm/init-state [] {:ledger {} :validators ["v1"]})
            d-zero (sm/compute-checkpoint-state-digest s-zero)
            d-zero-explicit (sm/compute-checkpoint-state-digest (assoc s-zero :total-burned 0))
            s-burned (assoc s-zero :total-burned 100 :vaults {"v1" {:balance 1000}} :bounty-escrows {"b1" {:status :locked :gross-amount 500}})
            snap (sm/build-checkpoint-snapshot s-burned)]
        (is (= d-zero d-zero-explicit) "Zero :total-burned must not change v0.23.22 checkpoint digest")
        (is (not= d-zero (sm/compute-checkpoint-state-digest (assoc s-zero :total-burned 100)))
            "Positive :total-burned must be committed into checkpoint digest")
        (is (= 100 (:total-burned snap)))
        (is (contains? snap :vaults))
        (is (contains? snap :bounty-escrows))
        (is (contains? snap :validator-set-history))))))

;; =============================================================================
;; SCEN-B3: 7-Bucket Conservation on :bounty-create, Bootstrap Sunset, Unknown Receipt
;; =============================================================================

(deftest scen-b3-bounty-conservation-sunset-and-unknown-receipt
  (let [payer (gen-kp)
        ph (puzzle/puzzle-cid (vault/canonical-multisig-treasury-puzzle-source 1 [(:spki payer)]))
        s0 (-> (sm/init-state [] {:bootstrap-sunset-epoch 26280})
               (assoc :ledger {(:spki payer) {:balance 50000 :seq 0 :deps []}}
                      :genesis-custody-supply 150000
                      :total-minted 0
                      :root-unallocated 0
                      :total-burned 0
                      :sunset-custody-burned 0
                      :minted-epochs #{26280}
                      :vaults {"v-boot" {:vault-id "v-boot"
                                         :entity-uri "root/bootstrap"
                                         :custody-bucket :bootstrap
                                         :puzzle-hash ph
                                         :balance 100000
                                         :vault-seq 1
                                         :created-epoch 0
                                         :status :active}})
               (dissoc :bootstrap-sunset-epoch))]
    (testing "Baseline sanity: 7-bucket conservation holds before trigger"
      (is (:ok? (vault/verify-7-bucket-conservation s0))))

    (testing "B3-a: :bounty-create preserves 7-bucket conservation and rejects invalid gross/bps"
      (let [b-rcpt {:type :bounty-create
                    :receipt-id "rcpt-bounty-1"
                    :bounty-id "bounty-026-1"
                    :maintainer-pubkey (:spki payer)
                    :payer (:spki payer)
                    :gross-amount 1000
                    :take-bps 50
                    :builder-bps 500
                    :epoch 5}
            s1 (finalize-single-block s0 5 [b-rcpt])
            s-bad (finalize-single-block s0 5 [(assoc b-rcpt :receipt-id "rcpt-bounty-bad" :bounty-id "b-bad" :gross-amount 0)])]
        (is (= :locked (get-in s1 [:bounty-escrows "bounty-026-1" :status])))
        (is (:ok? (vault/verify-7-bucket-conservation s1))
            "verify-7-bucket-conservation MUST count :locked :gross-amount bounty-escrows")
        (is (nil? (get-in s-bad [:bounty-escrows "b-bad"]))
            "gross-amount <= 0 must be rejected fail-closed")
        (is (pos? (long (or (:failed-receipts-count s-bad) 0))))))

    (testing "B3-b: apply-epoch-treasury-boundary runs bootstrap sunset BEFORE :minted-epochs early return using [:config :bootstrap-sunset-epoch]"
      (let [s-sun (sm/apply-epoch-treasury-boundary s0 26280)]
        (is (= 0 (get-in s-sun [:vaults "v-boot" :balance])))
        (is (= :sunset-burned (get-in s-sun [:vaults "v-boot" :status])))
        (is (= 100000 (:sunset-custody-burned s-sun)))
        (is (:ok? (vault/verify-7-bucket-conservation s-sun)))))

    (testing "B3-c: Unknown receipt type increments :failed-receipts-count and [:diagnostics :unknown-receipt-type]"
      (let [s-unk (finalize-single-block s0 6 [{:type :bogus-unknown-op-026 :receipt-id "rcpt-unk-1"}])]
        (is (= 1 (long (or (:failed-receipts-count s-unk) 0))))
        (is (= 1 (long (get-in s-unk [:diagnostics :unknown-receipt-type] 0))))))))

;; =============================================================================
;; SCEN-B7: Custody-Bucket Laundering in vault/spend-vault & dissolve-circle
;; =============================================================================

(deftest scen-b7-custody-bucket-non-laundering-and-directory-envelope
  (let [owner (gen-kp)
        p-src (vault/canonical-multisig-treasury-puzzle-source 1 [(:spki owner)])
        ph (puzzle/puzzle-cid p-src)
        net-uri "devnet.bitecho.org"
        gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        s0 (vault/init-vaults-state
            {:network-uri net-uri
             :network-genesis-cid gen-cid
             :genesis-custody-supply 52000
             :vaults {"p-dev" {:vault-id "p-dev" :entity-uri "root/dev" :custody-bucket :development
                               :puzzle-hash ph :balance 1000 :vault-seq 1 :created-epoch 0 :status :active}
                      "p-nil" {:vault-id "p-nil" :entity-uri "root/org" :custody-bucket nil
                               :puzzle-hash ph :balance 1000 :vault-seq 1 :created-epoch 0 :status :active}
                      "p-closed" {:vault-id "p-closed" :entity-uri "root/closed" :custody-bucket :bootstrap
                                  :puzzle-hash ph :balance 0 :vault-seq 1 :created-epoch 0 :status :closed}
                      "c-boot" {:vault-id "c-boot" :entity-uri "root/boot-child" :custody-bucket :bootstrap
                                :puzzle-hash ph :balance 50000 :vault-seq 1 :created-epoch 0 :status :active}}
             :chartered-vaults #{"p-dev" "p-nil" "p-closed" "c-boot"}})]
    (testing "Baseline sanity: 7-bucket conservation holds"
      (is (:ok? (vault/verify-7-bucket-conservation s0))))

    (testing "B7-a: vault/spend-vault :allocate from :bootstrap -> :development MUST fail closed"
      (let [outs [{:type :allocate :target-vault-id "p-dev" :amount 50000}]
            digest (vault/treasury-spend-digest {:network-uri net-uri :network-genesis-cid gen-cid
                                                 :vault-id "c-boot" :puzzle-hash ph :vault-seq 1
                                                 :outputs outs :next-puzzle-hash ph})
            sig (basalt/bytes->hex (crypto/sign (:private owner) digest))
            res (vault/spend-vault s0 {:vault-id "c-boot" :vault-seq 1 :puzzle-source p-src
                                       :solution {:outputs outs :signatures {(:spki owner) sig}}
                                       :epoch 10})]
        (is (not (:ok? res)) "Cross-bucket :allocate (:bootstrap -> :development) MUST fail closed")
        (is (= 50000 (get-in (:state res) [:vaults "c-boot" :balance])))
        (is (:ok? (vault/verify-7-bucket-conservation (:state res))))))

    (testing "B7-b & B7-c: dissolve-circle rejects cross-bucket (:development / nil) and :closed parent"
      (let [s-with-desc (assoc-in s0 [:entity-descriptors "root/boot-child"]
                                  {:entity-kind :circle :path "root/boot-child" :vault-id "c-boot" :status :active})
            proposal-cid "1111111111111111111111111111111111111111111111111111111111111111"
            sign-ballot-fn (resolve 'bitecho.core.circle/sign-consent-ballot)
            lead-ballot (if sign-ballot-fn
                          (sign-ballot-fn (:private owner) (:spki owner) proposal-cid :consent)
                          {:vote :consent})
            consent-round {:proposal-cid proposal-cid
                           :lead-link-pubkey (:spki owner)
                           :eligible-voters [(:spki owner)]
                           :ballots {(:spki owner) lead-ballot}
                           :quorum-size 1}
            r-dev (circle/dissolve-circle s-with-desc {:circle-path "root/boot-child" :parent-vault-id "p-dev" :consent-round consent-round} {})
            r-nil (circle/dissolve-circle s-with-desc {:circle-path "root/boot-child" :parent-vault-id "p-nil" :consent-round consent-round} {})
            r-closed (circle/dissolve-circle s-with-desc {:circle-path "root/boot-child" :parent-vault-id "p-closed" :consent-round consent-round} {})]
        (is (not (:ok? r-dev)) "dissolve-circle into :development parent MUST fail closed")
        (is (= :custody-bucket-mismatch (:error r-dev)))
        (is (not (:ok? r-nil)) "dissolve-circle into nil-bucket parent MUST fail closed")
        (is (= :custody-bucket-mismatch (:error r-nil)))
        (is (not (:ok? r-closed)) "dissolve-circle into :closed parent MUST fail closed")
        (is (= :parent-vault-not-active (:error r-closed)))))

    (testing "B7-d: subnet/sign-directory-pointer passes BOTH data/verify-pointer AND subnet/verify-directory-pointer"
      (let [dir-kp (gen-kp)
            agent-kp (gen-kp)
            pop-map (light-core/create-directory-pop (:private agent-kp)
                                                     {:domain "devnet.bitecho.org"
                                                      :nickname "alice"
                                                      :pubkey (:spki agent-kp)
                                                      :home-set ["https://ns1.bitecho.org"]
                                                      :epoch 10})
            signed (subnet/sign-directory-pointer (:private dir-kp) (:spki dir-kp) pop-map {:subnet "devnet.bitecho.org" :seq 1})
            ptr (:pointer signed)
            blob (:blob signed)
            acl [{:pattern "dir/*"
                  :principal {:type :directory-entity
                              :authority (:spki dir-kp)
                              :owner-multisig {:threshold 1 :pubkeys [(:spki dir-kp)]}}}]]
        (is (:ok? (data/verify-pointer ptr {:subnet "devnet.bitecho.org" :path-acl acl :current-epoch 10}))
            "sign-directory-pointer must pass data/verify-pointer on dir/*")
        (is (:ok? (subnet/verify-directory-pointer ptr blob (:spki dir-kp) 10))
            "sign-directory-pointer must also pass subnet/verify-directory-pointer")))))

;; =============================================================================
;; SCEN-B5: Multi-Output :release Hamilton Largest-Remainder Apportionment
;; =============================================================================

(deftest scen-b5-hamilton-largest-remainder-and-oneshot-escrow-guard
  (testing "B5-a: Adversarial 5-output split [24999, 24999, 24999, 25002, 1] produces exact [125, 125, 125, 125, 0] with zero underflow"
    (let [releases [{:type :release :receiver "r1" :amount 24999}
                    {:type :release :receiver "r2" :amount 24999}
                    {:type :release :receiver "r3" :amount 24999}
                    {:type :release :receiver "r4" :amount 25002}
                    {:type :release :receiver "r5" :amount 1}]
          apportion-fn (resolve 'bitecho.economy.escrow/apportion-settlement-take)]
      (is (some? apportion-fn) "escrow/apportion-settlement-take must exist")
      (when apportion-fn
        (let [res (apportion-fn releases 50)
              takes (mapv :take res)
              nets (mapv :net res)]
          (is (= [125 125 125 125 0] takes))
          (is (= [24874 24874 24874 24877 1] nets))
          (is (every? #(>= % 0) nets))
          (is (= 500 (reduce + 0 takes)))
          (is (= 100000 (+ (reduce + 0 nets) (reduce + 0 takes))))))))

  (testing "B5-b (F5): Many 1-ECH micro-outputs + larger output apportion exact take with multi-pass cap safety"
    (let [apportion-fn (resolve 'bitecho.economy.escrow/apportion-settlement-take)]
      (is (some? apportion-fn) "escrow/apportion-settlement-take must exist")
      (when apportion-fn
        (let [micro-only (mapv (fn [i] {:type :release :receiver (str "micro-" i) :amount 1})
                               (range 200))
              expected-micro (escrow/calculate-escrow-settlement-take 200 200)
              res-micro (apportion-fn micro-only 200)
              takes-micro (mapv :take res-micro)
              nets-micro (mapv :net res-micro)
              mixed-outs (conj (mapv (fn [i] {:type :release :receiver (str "micro-" i) :amount 1})
                                     (range 50))
                               {:type :release :receiver "big" :amount 950})
              expected-mixed (escrow/calculate-escrow-settlement-take 1000 200)
              res-mixed (apportion-fn mixed-outs 200)
              takes-mixed (mapv :take res-mixed)
              nets-mixed (mapv :net res-mixed)]
          (is (every? #(and (>= (:take %) 0) (<= (:take %) (:amount %))) res-micro))
          (is (every? #(>= % 0) nets-micro))
          (is (= expected-micro (reduce + 0 takes-micro)))
          (is (= 200 (+ (reduce + 0 nets-micro) (reduce + 0 takes-micro))))
          (is (every? #(and (>= (:take %) 0) (<= (:take %) (:amount %))) res-mixed))
          (is (every? #(>= % 0) nets-mixed))
          (is (= expected-mixed (reduce + 0 takes-mixed)))
          (is (= 1000 (+ (reduce + 0 nets-mixed) (reduce + 0 takes-mixed)))))))))

;; =============================================================================
;; BIP-026 §4 Generative Properties (test.check defspec) for P1, P3, P5
;; =============================================================================

(defspec ^{:doc "P3.1 & P3.2 (B5): Hamilton largest-remainder apportionment guarantees 0 <= take_i <= amt_i, net_i >= 0, exact single-take conservation across escrows and vaults, and rejects :allocate/:relock on one-shot escrows."}
  prop-multi-output-release-single-take-exact
  50
  (prop/for-all [amounts (gen/not-empty (gen/vector (gen/choose 1 50000) 1 8))
                 bps (gen/choose 1 500)]
                (if-let [apportion-fn (resolve 'bitecho.economy.escrow/apportion-settlement-take)]
                  (let [releases (mapv (fn [idx amt]
                                         {:type :release :receiver (str "recv-" idx) :amount amt})
                                       (range (count amounts))
                                       amounts)
                        total-gross (reduce + 0 amounts)
                        expected-take (escrow/calculate-escrow-settlement-take total-gross bps)
                        apportioned (apportion-fn releases bps)
                        takes (mapv :take apportioned)
                        nets (mapv :net apportioned)
                        ;; Also verify one-shot escrow rejects :allocate / :relock fail-closed
                        payer (gen-kp)
                        recv (gen-kp)
                        alloc-src "(fn [_env _sol] [{:type :allocate :target-vault-id \"v1\" :amount 1000}])"
                        alloc-ph (puzzle/puzzle-cid alloc-src)
                        st0 (-> (sm/init-state [] (:spki payer))
                                (assoc :escrows {"esc-1" {:escrow-id "esc-1"
                                                          :payer (:spki payer)
                                                          :receiver (:spki recv)
                                                          :amount 1000
                                                          :deliverable-hash alloc-ph
                                                          :puzzle-hash alloc-ph
                                                          :created-epoch 1
                                                          :expires-epoch 100
                                                          :status :locked}}
                                       :ledger {(:spki payer) {:balance 0 :seq 0 :deps []}}
                                       :genesis-custody-supply 1000))
                        rel-rcpt {:type :release-intent
                                  :receipt-id "rel-forbid-1"
                                  :escrow-id "esc-1"
                                  :puzzle-source alloc-src
                                  :solution {}
                                  :sender (:spki recv)}
                        st1 (finalize-single-block st0 2 [rel-rcpt])]
                    (and (= (count amounts) (count apportioned))
                         (every? #(and (>= (:take %) 0) (<= (:take %) (:amount %))) apportioned)
                         (every? #(>= (:net %) 0) apportioned)
                         (= expected-take (reduce + 0 takes))
                         (= total-gross (+ (reduce + 0 nets) (reduce + 0 takes)))
                         (= :locked (get-in st1 [:escrows "esc-1" :status]))
                         (pos? (long (get-in st1 [:diagnostics :escrow-vault-condition-forbidden] 0)))
                         (pos? (long (or (:failed-receipts-count st1) 0)))
                         (:ok? (vault/verify-7-bucket-conservation st1))))
                  false)))

(defspec ^{:doc "P1.3 (B2): Custody-vault :release takes go to :total-burned ONLY and NEVER inflate [:epoch-settlement-takes ep]; organic (nil bucket) vault takes feed BOTH."}
  prop-custody-burns-never-inflate-r-trailing
  25
  (prop/for-all [bucket (gen/elements [:bootstrap :team :partners :ecosystem])
                 custody-amt (gen/choose 2000 500000)
                 organic-amt (gen/choose 2000 500000)
                 ep (gen/choose 1 1000)]
                (let [owner (gen-kp)
                      recv (gen-kp)
                      p-src (vault/canonical-multisig-treasury-puzzle-source 1 [(:spki owner)])
                      ph (puzzle/puzzle-cid p-src)
                      net-uri "devnet.bitecho.org"
                      gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      s0 (vault/init-vaults-state
                          {:network-uri net-uri
                           :network-genesis-cid gen-cid
                           :genesis-custody-supply (+ custody-amt organic-amt)
                           :vaults {"v-cust" {:vault-id "v-cust" :entity-uri "root/cust" :custody-bucket bucket
                                              :puzzle-hash ph :balance custody-amt :vault-seq 1 :created-epoch 0 :status :active}
                                    "v-org" {:vault-id "v-org" :entity-uri "org/main" :custody-bucket nil
                                             :puzzle-hash ph :balance organic-amt :vault-seq 1 :created-epoch 0 :status :active}}})
                      c-outs [{:type :release :receiver (:spki recv) :amount custody-amt}]
                      c-sig (basalt/bytes->hex (crypto/sign (:private owner)
                                                            (vault/treasury-spend-digest
                                                             {:network-uri net-uri :network-genesis-cid gen-cid
                                                              :vault-id "v-cust" :puzzle-hash ph :vault-seq 1
                                                              :outputs c-outs :next-puzzle-hash ph})))
                      r1 (vault/spend-vault s0 {:vault-id "v-cust" :vault-seq 1 :puzzle-source p-src
                                                :solution {:outputs c-outs :signatures {(:spki owner) c-sig}}
                                                :epoch ep})
                      s1 (:state r1)
                      c-take (escrow/calculate-escrow-settlement-take custody-amt 50)
                      o-outs [{:type :release :receiver (:spki recv) :amount organic-amt}]
                      o-sig (basalt/bytes->hex (crypto/sign (:private owner)
                                                            (vault/treasury-spend-digest
                                                             {:network-uri net-uri :network-genesis-cid gen-cid
                                                              :vault-id "v-org" :puzzle-hash ph :vault-seq 1
                                                              :outputs o-outs :next-puzzle-hash ph})))
                      r2 (vault/spend-vault s1 {:vault-id "v-org" :vault-seq 1 :puzzle-source p-src
                                                :solution {:outputs o-outs :signatures {(:spki owner) o-sig}}
                                                :epoch ep})
                      s2 (:state r2)
                      o-take (escrow/calculate-escrow-settlement-take organic-amt 50)]
                  (and (:ok? r1)
                       (= c-take (:total-burned s1))
                       (= 0 (long (get-in s1 [:epoch-settlement-takes ep] 0)))
                       (:ok? r2)
                       (= (+ c-take o-take) (:total-burned s2))
                       (= o-take (long (get-in s2 [:epoch-settlement-takes ep] 0)))
                       (:ok? (vault/verify-7-bucket-conservation s2))))))

(defspec ^{:doc "P1.3 (B2): Checkpoint digest is identical to v0.23.22 when :total-burned == 0 and commits :total-burned when positive."}
  prop-checkpoint-digest-rolling-upgrade-compat
  30
  (prop/for-all [bal (gen/choose 0 1000000)
                 burned (gen/choose 1 100000)]
                (let [s-base (assoc (sm/init-state [] "v1")
                                    :validators ["v1"]
                                    :ledger {"acct1" {:balance bal :seq 0 :deps []}})
                      d-omitted (sm/compute-checkpoint-state-digest (dissoc s-base :total-burned))
                      d-zero (sm/compute-checkpoint-state-digest (assoc s-base :total-burned 0))
                      d-pos (sm/compute-checkpoint-state-digest (assoc s-base :total-burned burned))
                      snap (sm/build-checkpoint-snapshot (assoc s-base
                                                                :total-burned burned
                                                                :vaults {"v1" {:balance 1000}}
                                                                :bounty-escrows {"b1" {:status :locked :gross-amount 500}}
                                                                :validator-set-history {0 {:committee ["v1"] :quorum-threshold 1}}))]
                  (and (= d-omitted d-zero)
                       (not= d-zero d-pos)
                       (= burned (:total-burned snap))
                       (contains? snap :vaults)
                       (contains? snap :bounty-escrows)
                       (contains? snap :validator-set-history)))))

(defspec ^{:doc "P1.1–P1.4 (B1, B3): 7-bucket conservation holds across mixed :burn, :bounty-create, signed :vault-create, unknown receipts, and bootstrap sunset even when sunset epoch is already in :minted-epochs."}
  prop-7-bucket-conservation-under-mixed-receipts
  25
  (prop/for-all [burn-amt (gen/choose 1 500)
                 bounty-amt (gen/choose 100 5000)
                 vault-amt (gen/choose 1000 5000)
                 boot-amt (gen/choose 1000 50000)]
                (let [payer (gen-kp)
                      p-src (vault/canonical-multisig-treasury-puzzle-source 1 [(:spki payer)])
                      ph (puzzle/puzzle-cid p-src)
                      net-uri "devnet.bitecho.org"
                      gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      init-bal (+ burn-amt bounty-amt vault-amt 10000)
                      s0 (-> (sm/init-state [] (:spki payer))
                             (assoc-in [:config :network-uri] net-uri)
                             (assoc-in [:config :network-genesis-cid] gen-cid)
                             (assoc-in [:config :bootstrap-sunset-epoch] 26280)
                             (assoc :network-uri net-uri
                                    :network-genesis-cid gen-cid
                                    :ledger {(:spki payer) {:balance init-bal :seq 0 :deps []}}
                                    :genesis-custody-supply (+ init-bal boot-amt)
                                    :minted-epochs #{26280}
                                    :vaults {"v-boot" {:vault-id "v-boot"
                                                       :entity-uri "root/bootstrap"
                                                       :custody-bucket :bootstrap
                                                       :puzzle-hash ph
                                                       :balance boot-amt
                                                       :vault-seq 1
                                                       :created-epoch 0
                                                       :status :active}}))
                      v-params {:type :vault-create
                                :receipt-id "rcpt-vc-1"
                                :vault-id "vault:payer/prop"
                                :entity-uri "payer/prop"
                                :custody-bucket nil
                                :puzzle-hash ph
                                :payer (:spki payer)
                                :balance vault-amt
                                :created-epoch 4}
                      v-tuple-fn (resolve 'bitecho.circles.vault/vault-create-signing-tuple)
                      v-tuple (if v-tuple-fn
                                (v-tuple-fn (assoc v-params :network-uri net-uri :network-genesis-cid gen-cid))
                                ["bitecho-vault-create-v1"
                                 net-uri gen-cid (:vault-id v-params) (:entity-uri v-params)
                                 (:custody-bucket v-params) (:puzzle-hash v-params)
                                 (:payer v-params) (long (:balance v-params)) (long (:created-epoch v-params))])
                      v-rcpt (assoc v-params :signature (basalt/bytes->hex (crypto/sign-canonical (:private payer) v-tuple)))
                      rcpts [{:type :burn :receipt-id "rcpt-burn-1" :sender (:spki payer) :amount burn-amt}
                             {:type :bounty-create :receipt-id "rcpt-bounty-1" :bounty-id "b-prop-1"
                              :maintainer-pubkey (:spki payer) :payer (:spki payer) :gross-amount bounty-amt
                              :take-bps 50 :builder-bps 500 :epoch 4}
                             v-rcpt
                             {:type :bogus-unknown-prop :receipt-id "rcpt-unk-prop"}]
                      s1 (finalize-single-block s0 5 rcpts)
                      s2 (sm/apply-epoch-treasury-boundary s1 26280)]
                  (and (:ok? (vault/verify-7-bucket-conservation s0))
                       (:ok? (vault/verify-7-bucket-conservation s1))
                       (= 1 (long (get-in s1 [:diagnostics :unknown-receipt-type] 0)))
                       (= 0 (get-in s2 [:vaults "v-boot" :balance]))
                       (= :sunset-burned (get-in s2 [:vaults "v-boot" :status]))
                       (= boot-amt (:sunset-custody-burned s2))
                       (:ok? (vault/verify-7-bucket-conservation s2))))))

(defspec ^{:doc "P5.1 & P5.2 (B7): Cross-bucket :allocate / dissolve-circle, :closed parents, unsigned consent ballots, and non-blinded encrypted envelope paths always fail closed."}
  prop-dissolve-circle-forbids-custody-bucket-laundering
  25
  (prop/for-all [child-bucket (gen/elements [:bootstrap :team :partners :ecosystem])
                 parent-bucket (gen/elements [:bootstrap :team :partners :ecosystem nil])
                 principal (gen/choose 1000 50000)]
                (let [owner (gen-kp)
                      p-src (vault/canonical-multisig-treasury-puzzle-source 1 [(:spki owner)])
                      ph (puzzle/puzzle-cid p-src)
                      net-uri "devnet.bitecho.org"
                      gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      prop-cid "1111111111111111111111111111111111111111111111111111111111111111"
                      s0 (assoc (vault/init-vaults-state
                                 {:network-uri net-uri
                                  :network-genesis-cid gen-cid
                                  :genesis-custody-supply (+ principal 1000)
                                  :vaults {"p-v" {:vault-id "p-v" :entity-uri "root/p" :custody-bucket parent-bucket
                                                  :puzzle-hash ph :balance 1000 :vault-seq 1 :created-epoch 0 :status :active}
                                           "c-v" {:vault-id "c-v" :entity-uri "root/c" :custody-bucket child-bucket
                                                  :puzzle-hash ph :balance principal :vault-seq 1 :created-epoch 0 :status :active}}})
                                :entity-descriptors {"root/c" {:entity-kind :circle :path "root/c" :vault-id "c-v" :status :active}})
                      sign-ballot-fn (resolve 'bitecho.core.circle/sign-consent-ballot)
                      verify-env-fn (resolve 'bitecho.core.circle/verify-encrypted-entity-envelope)
                      signed-round {:proposal-cid prop-cid
                                    :lead-link-pubkey (:spki owner)
                                    :ballots {(:spki owner) (if sign-ballot-fn
                                                              (sign-ballot-fn (:private owner) (:spki owner) prop-cid :consent)
                                                              {:vote :consent})}
                                    :quorum-size 1}
                      unsigned-round {:proposal-cid prop-cid
                                      :lead-link-pubkey (:spki owner)
                                      :ballots {(:spki owner) {:vote :consent}}
                                      :quorum-size 1}
                      res-signed (circle/dissolve-circle s0 {:circle-path "root/c" :parent-vault-id "p-v" :consent-round signed-round} {})
                      res-unsigned (circle/dissolve-circle s0 {:circle-path "root/c" :parent-vault-id "p-v" :consent-round unsigned-round} {})
                      ;; Encrypted envelope P5.2 check
                      gk (crypto/sha256 (fressian/utf8->bytes "bip026-p52-gk"))
                      desc {:network-uri net-uri
                            :network-genesis-cid gen-cid
                            :path "root/secret"
                            :parent-path "root"
                            :version 1
                            :owner-multisig {:threshold 1 :pubkeys [(:spki owner)]}
                            :storage-accounting {:bytes-at-rest 512 :payer-pubkey (:spki owner) :fee-ech 0}}
                      enc-ok (circle/encrypt-shared-descriptor desc gk {:owner-signers [{:pubkey (:spki owner) :privkey (:private owner)}]})
                      enc-bad-path (assoc enc-ok :blinded-path "root/protocol")
                      v-enc-ok (when verify-env-fn (verify-env-fn enc-ok {:network-uri net-uri :network-genesis-cid gen-cid}))
                      v-enc-bad (when verify-env-fn (verify-env-fn enc-bad-path {:network-uri net-uri :network-genesis-cid gen-cid}))]
                  (and (some? sign-ballot-fn)
                       (some? verify-env-fn)
                       (false? (:ok? res-unsigned))
                       (if (= child-bucket parent-bucket)
                         (and (:ok? res-signed)
                              (:ok? (vault/verify-7-bucket-conservation (:state res-signed))))
                         (and (false? (:ok? res-signed))
                              (= :custody-bucket-mismatch (:error res-signed))))
                       (not (contains? (:storage-accounting enc-ok) :payer-pubkey))
                       (:ok? v-enc-ok)
                       (false? (:ok? v-enc-bad))))))

;; =============================================================================
;; SCEN-B12: mc_harness.cljc Lead >= 3 Floor & Compound Drawdown 1 - (1 - lambda)^C
;; =============================================================================

(deftest scen-b12-mc-harness-lead-floor-and-compound-drawdown
  (let [base-cfg {:bootstrap-drawdown-lambda 0.01
                  :validator-activation-lead-epochs 6}]
    (testing "Baseline sanity: at compression-factor C = 1, lambda = 0.01 and lead = 6"
      (let [s1 (mc-harness/scale-lifecycle-config base-cfg 1)]
        (is (< (Math/abs (- 0.01 (double (:bootstrap-drawdown-lambda s1)))) 1.0e-12))
        (is (= 6 (:validator-activation-lead-epochs s1)))))

    (testing "B12: at C = 120, compound drawdown is 1 - (1 - 0.01)^120 < 1.0 and lead >= 3"
      (let [s120 (mc-harness/scale-lifecycle-config base-cfg 120)
            expected-lambda (- 1.0 (Math/pow (- 1.0 0.01) 120))
            actual-lambda (double (:bootstrap-drawdown-lambda s120))
            actual-lead (long (:validator-activation-lead-epochs s120))]
        (is (> actual-lambda 0.0))
        (is (< actual-lambda 1.0)
            "Compressed drawdown lambda MUST remain strictly < 1.0 (no 100%+ wipeout)")
        (is (< (Math/abs (- expected-lambda actual-lambda)) 1.0e-12)
            "Compressed drawdown lambda MUST equal exact compound 1 - (1 - lambda)^C")
        (is (>= actual-lead 3)
            "Compressed :validator-activation-lead-epochs MUST be clamped >= 3")))))

;; =============================================================================
;; SCEN-B6: SLA-Vesting Oracle Attestation Hardening (P4.1 / B6)
;; =============================================================================

(defn- make-sla-attestation
  [oracle-kp {:keys [network-uri network-genesis-cid vault-id vault-seq epoch metric-id score-bps]}]
  (let [tuple ["bitecho-sla-attestation-v1"
               (str network-uri)
               (str network-genesis-cid)
               (str vault-id)
               (long vault-seq)
               (long epoch)
               (str (or metric-id "sla-uptime"))
               (long score-bps)]
        sig-hex (basalt/bytes->hex (crypto/sign (:private oracle-kp) (fressian/encode-canonical tuple)))]
    {:vault-id vault-id
     :vault-seq (long vault-seq)
     :epoch (long epoch)
     :metric-id (str (or metric-id "sla-uptime"))
     :score-bps (long score-bps)
     :signature sig-hex}))

(deftest scen-b6-sla-vesting-oracle-attestation-hardening
  (let [o1 (gen-kp)
        o2 (gen-kp)
        twin (gen-kp)
        recv (gen-kp)
        o1-raw (subs (:spki o1) 24)
        net-uri "devnet.bitecho.org"
        gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ;; SLA-vesting puzzle: requires 2 distinct verified oracle attestations in (:oracle-attestations env)
        ;; matching [o1, o2] with score-bps >= 9500, releasing 1000 and relocking 9000.
        sla-puzzle-src (str "(fn [env sol]"
                            "  (let [atts (or (:oracle-attestations env) {})"
                            "        allowed #{" (pr-str (:spki o1)) " " (pr-str (:spki o2)) "}"
                            "        valid-oracles (filter (fn [pk]"
                            "                                (let [att (get atts pk)]"
                            "                                  (and (contains? allowed pk)"
                            "                                       (map? att)"
                            "                                       (:verified? att)"
                            "                                       (>= (:score-bps att) 9500))))"
                            "                              (keys atts))]"
                            "    (if (>= (count valid-oracles) 2)"
                            "      [{:type :release :receiver " (pr-str (:spki recv)) " :amount 1000}"
                            "       {:type :relock :amount 9000 :next-puzzle-hash (or (:forced-relock-ph sol) (:puzzle-hash env))}]"
                            "      false)))")
        ph (puzzle/puzzle-cid sla-puzzle-src)
        s0 (vault/init-vaults-state
            {:network-uri net-uri
             :network-genesis-cid gen-cid
             :genesis-custody-supply 10000
             :advisory-twin-pubkeys #{(:spki twin)}
             :max-attestation-lag 5
             :vaults {"v-sla" {:vault-id "v-sla"
                               :entity-uri "root/sla"
                               :custody-bucket nil
                               :puzzle-hash ph
                               :balance 10000
                               :vault-seq 1
                               :created-epoch 0
                               :status :active}}})
        att-o1 (make-sla-attestation o1 {:network-uri net-uri :network-genesis-cid gen-cid
                                         :vault-id "v-sla" :vault-seq 1 :epoch 50 :score-bps 9900})
        att-o2 (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                         :vault-id "v-sla" :vault-seq 1 :epoch 50 :score-bps 9800})
        att-twin (make-sla-attestation twin {:network-uri net-uri :network-genesis-cid gen-cid
                                             :vault-id "v-sla" :vault-seq 1 :epoch 50 :score-bps 9900})]
    (testing "Baseline sanity: 7-bucket conservation holds before trigger"
      (is (:ok? (vault/verify-7-bucket-conservation s0))))

    (testing "B6-a: Advisory twin pubkey in :oracle-attestations MUST fail closed with :advisory-twin-signing-forbidden"
      (let [res (vault/spend-vault s0 {:vault-id "v-sla"
                                       :vault-seq 1
                                       :puzzle-source sla-puzzle-src
                                       :solution {:oracle-attestations {(:spki o1) att-o1
                                                                        (:spki twin) att-twin}}
                                       :epoch 50})]
        (is (not (:ok? res)))
        (is (= :advisory-twin-signing-forbidden (:error res)))))

    (testing "B6-b: 64-hex / 88-hex key aliasing for same oracle collapses to 1 canonical entry (cannot satisfy 2-of-2)"
      (let [res (vault/spend-vault s0 {:vault-id "v-sla"
                                       :vault-seq 1
                                       :puzzle-source sla-puzzle-src
                                       :solution {:oracle-attestations {(:spki o1) att-o1
                                                                        o1-raw att-o1}}
                                       :epoch 50})
            ;; Allowlist-free counting puzzle: directly observes (count (:oracle-attestations env))
            ;; so 64-hex + 88-hex aliasing collapse (2 -> 1) is directly observable without an allowlist
            count-puzzle-src (str "(fn [env _sol]"
                                  "  (let [atts (or (:oracle-attestations env) {})]"
                                  "    (if (>= (count atts) 2)"
                                  "      [{:type :release :receiver " (pr-str (:spki recv)) " :amount 1000}"
                                  "       {:type :relock :amount 9000 :next-puzzle-hash (:puzzle-hash env)}]"
                                  "      false)))")
            count-ph (puzzle/puzzle-cid count-puzzle-src)
            s-count (assoc-in s0 [:vaults "v-sla-count"]
                              {:vault-id "v-sla-count"
                               :entity-uri "root/sla-count"
                               :custody-bucket nil
                               :puzzle-hash count-ph
                               :balance 10000
                               :vault-seq 1
                               :created-epoch 0
                               :status :active})
            att-c1 (make-sla-attestation o1 {:network-uri net-uri :network-genesis-cid gen-cid
                                             :vault-id "v-sla-count" :vault-seq 1 :epoch 50 :score-bps 9900})
            att-c2 (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                             :vault-id "v-sla-count" :vault-seq 1 :epoch 50 :score-bps 9800})
            r-alias-count (vault/spend-vault s-count {:vault-id "v-sla-count"
                                                      :vault-seq 1
                                                      :puzzle-source count-puzzle-src
                                                      :solution {:oracle-attestations {(:spki o1) att-c1
                                                                                       o1-raw att-c1}}
                                                      :epoch 50})
            r-distinct-count (vault/spend-vault s-count {:vault-id "v-sla-count"
                                                         :vault-seq 1
                                                         :puzzle-source count-puzzle-src
                                                         :solution {:oracle-attestations {(:spki o1) att-c1
                                                                                          (:spki o2) att-c2}}
                                                         :epoch 50})]
        (is (not (:ok? res)) "Aliased 64-hex + 88-hex same oracle must not satisfy 2-of-2 quorum")
        (is (not (:ok? r-alias-count))
            "Allowlist-free counting puzzle MUST observe 2 -> 1 collapse on 64-hex + 88-hex aliasing")
        (is (:ok? r-distinct-count)
            "Allowlist-free counting puzzle MUST succeed with 2 distinct verified oracles")))

    (testing "B6-c: Stale epoch, mismatched :vault-seq, and score-bps > 10000 MUST fail closed"
      (let [att-stale (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                                :vault-id "v-sla" :vault-seq 1 :epoch 10 :score-bps 9800})
            att-bad-seq (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                                  :vault-id "v-sla" :vault-seq 2 :epoch 50 :score-bps 9800})
            att-bad-bps (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                                  :vault-id "v-sla" :vault-seq 1 :epoch 50 :score-bps 10001})
            r-stale (vault/spend-vault s0 {:vault-id "v-sla" :vault-seq 1 :puzzle-source sla-puzzle-src
                                           :solution {:oracle-attestations {(:spki o1) att-o1 (:spki o2) att-stale}}
                                           :epoch 50})
            r-seq (vault/spend-vault s0 {:vault-id "v-sla" :vault-seq 1 :puzzle-source sla-puzzle-src
                                         :solution {:oracle-attestations {(:spki o1) att-o1 (:spki o2) att-bad-seq}}
                                         :epoch 50})
            r-bps (vault/spend-vault s0 {:vault-id "v-sla" :vault-seq 1 :puzzle-source sla-puzzle-src
                                         :solution {:oracle-attestations {(:spki o1) att-o1 (:spki o2) att-bad-bps}}
                                         :epoch 50})]
        (is (not (:ok? r-stale)) "Stale oracle attestation must fail closed")
        (is (= :stale-oracle-attestation (:error r-stale)))
        (is (not (:ok? r-seq)) "Mismatched :vault-seq attestation must fail closed")
        (is (= :oracle-vault-seq-mismatch (:error r-seq)))
        (is (not (:ok? r-bps)) "score-bps > 10000 must fail closed")
        (is (= :invalid-oracle-score-bps (:error r-bps)))))

    (testing "B6-d: Mismatched relock :next-puzzle-hash vs solution next-ph MUST fail closed with :relock-puzzle-hash-mismatch"
      (let [hijacked-ph "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            res (vault/spend-vault s0 {:vault-id "v-sla"
                                       :vault-seq 1
                                       :puzzle-source sla-puzzle-src
                                       :solution {:oracle-attestations {(:spki o1) att-o1
                                                                        (:spki o2) att-o2}
                                                  :next-puzzle-hash ph
                                                  :forced-relock-ph hijacked-ph}
                                       :epoch 50})]
        (is (not (:ok? res)))
        (is (= :relock-puzzle-hash-mismatch (:error res)))))

    (testing "Control: Fresh canonical non-twin 2-of-2 attestations with matching next-ph unlock tranche"
      (let [res (vault/spend-vault s0 {:vault-id "v-sla"
                                       :vault-seq 1
                                       :puzzle-source sla-puzzle-src
                                       :solution {:oracle-attestations {(:spki o1) att-o1
                                                                        (:spki o2) att-o2}
                                                  :next-puzzle-hash ph}
                                       :epoch 50})]
        (is (:ok? res) "Valid 2-of-2 SLA oracle attestations must unlock tranche")
        (is (= 9000 (get-in (:state res) [:vaults "v-sla" :balance])))
        (is (= 2 (get-in (:state res) [:vaults "v-sla" :vault-seq])))
        (is (:ok? (vault/verify-7-bucket-conservation (:state res))))))))

;; =============================================================================
;; SCEN-B4: Streamlet Validator-Rotation Deadlock, lead >= 3, & Light-Node Trust
;; =============================================================================

(defn- build-cluster-node
  "Builds a deterministic consensus-mode validator node map for VOPR testing."
  [kp-entry all-kps validators-vec root-ms net-uri gen-cid]
  (let [my-pub (:wire-pub kp-entry)
        peers-map (into {} (map (fn [k] [(:wire-pub k) (:public k)]) all-kps))
        cfg (merge config/default-config
                   {:network-uri net-uri
                    :network-genesis-cid gen-cid
                    :root-owner-multisig root-ms
                    :validator-activation-lead-epochs 3
                    :validators (vec validators-vec)
                    :peers-map peers-map
                    :keypair {:public (:public kp-entry) :private (:private kp-entry)}
                    :economy-enabled? false
                    :min-proposal-dwell-ms 0
                    :require-signed-control-frames false
                    :basalt-max-view-size 10})]
    (-> (sm/init-state (mapv (fn [k] {:pubkey (:wire-pub k)}) all-kps) my-pub cfg)
        (assoc :validators (vec validators-vec)
               :peers-map peers-map
               :node-pubkey my-pub
               :node-private-key (:private kp-entry)
               :keypair {:public (:public kp-entry) :private (:private kp-entry)}
               :root-owner-multisig root-ms
               :network-uri net-uri
               :network-genesis-cid gen-cid))))

(defn- step-cluster-epoch
  "Runs one deterministic Streamlet epoch tick + message delivery round across `nodes-map`
   (keyed by `:wire-pub`). Delivers all `:send-propose` and `:send-vote` commands synchronously."
  [nodes-map]
  (let [tick-results (into {}
                           (map (fn [[pk st]]
                                  [pk (sm/handle-event st {:type :tick})]))
                           nodes-map)
        after-tick (into {} (map (fn [[pk r]] [pk (:state r)]) tick-results))
        init-msgs (vec (for [[sender-pk r] tick-results
                             cmd (:commands r)
                             :when (#{:send-propose :send-vote} (:type cmd))
                             target (:targets cmd)]
                         {:from sender-pk :to target :cmd cmd}))]
    (loop [st-map after-tick
           queue init-msgs
           rounds 0]
      (if (or (empty? queue) (>= rounds 16))
        st-map
        (let [[next-map next-q]
              (reduce (fn [[acc q] {:keys [from to cmd]}]
                        (if-let [target-st (get acc to)]
                          (let [ev (case (:type cmd)
                                     :send-propose {:type :receive-propose
                                                    :sender from
                                                    :block (:block cmd)
                                                    :ancestors (:ancestors cmd)}
                                     :send-vote {:type :receive-vote
                                                 :sender from
                                                 :vote (:vote cmd)})
                                res (sm/handle-event target-st ev)
                                emitted (for [c (:commands res)
                                              :when (#{:send-propose :send-vote} (:type c))
                                              t (:targets c)]
                                          {:from to :to t :cmd c})]
                            [(assoc acc to (:state res)) (into q emitted)])
                          [acc q]))
                      [st-map []]
                      queue)]
          (recur next-map next-q (inc rounds)))))))

(deftest scen-b4-validator-rotation-lead-floor-and-light-node-trust
  (let [root-kp (gen-kp)
        root-ms {:threshold 1 :pubkeys [(:spki root-kp)]}
        net-uri "devnet.bitecho.org"
        gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ;; 10 validator keypairs: V0 uses canonical SPKI hex so baseline sanity passes on pre-fix code,
        ;; while rotated V1 mixes 64-char raw hex and 88-char SPKI hex keys
        raw-kps (vec (repeatedly 10 gen-kp))
        kps (mapv (fn [idx kp]
                    (assoc kp :wire-pub (:spki kp)
                           :mixed-pub (if (even? idx) (subs (:spki kp) 24) (:spki kp))))
                  (range 10)
                  raw-kps)
        v0-kps (subvec kps 0 6)
        v1-kps (vec (concat (subvec kps 0 2) (subvec kps 6 10)))
        v0-pubs (mapv :wire-pub v0-kps)
        v1-pubs (mapv :wire-pub v1-kps)
        consent-cid "2222222222222222222222222222222222222222222222222222222222222222"
        disc-fields {:retention-policy {:max-entries 128 :max-bytes 1048576 :rotate-every-entries 32 :ttl-epochs 52560}
                     :storage-accounting {:bytes-at-rest 2048 :cache-incentive :free-self-hosted :payer-pubkey (:spki root-kp) :fee-ech 0}}
        base-cluster (into {}
                           (map (fn [kp]
                                  [(:wire-pub kp) (build-cluster-node kp kps v0-pubs root-ms net-uri gen-cid)]))
                           kps)
        ;; Advance 10 epochs so V0 finalizes blocks cleanly
        warmed-cluster (nth (iterate step-cluster-epoch base-cluster) 10)
        v0-fin-ep (long (or (:last-executed-finalized-epoch (get warmed-cluster (first v0-pubs))) 0))
        agent-kp (gen-kp)
        bs-v0 {:network-uri net-uri
               :nodes (into {}
                            (map-indexed (fn [i kp]
                                           [(keyword (str "v" i)) {:pubkey (:wire-pub kp)}])
                                         v0-kps))}
        l0 (light-core/init-light-state (:spki agent-kp) {:bootstrap bs-v0})]

    (testing "Baseline sanity: V0 finalizes blocks cleanly and L0 verifies V0-signed snapshot"
      (is (>= v0-fin-ep 5) "V0 6-node cluster must finalize blocks cleanly before rotation")
      (let [v0-st (get warmed-cluster (first v0-pubs))
            snap (core-mesh/build-validator-chain-state-snapshot v0-st nil (:spki agent-kp) "n0")
            v-res (light-core/verify-chain-state-snapshot snap {:expected-pubkey (:spki agent-kp)
                                                                :expected-nonce "n0"
                                                                :trusted-validators (set v0-pubs)})]
        (is (:ok? v-res) "L0 must verify V0-signed snapshot before rotation")))

    (testing "B4-b: Normal rotation with lead = 2 MUST fail closed with :validator-rotation-lead-too-short; fast equivocation ejection at ep-fin + 1 MUST succeed"
      (let [desc-short (circle/create-validator-set-descriptor
                        (merge disc-fields
                               {:network-uri net-uri
                                :network-genesis-cid gen-cid
                                :version 2
                                :not-before-epoch 100
                                :epoch-finalized 100
                                :epoch-effective 102
                                :quorum-threshold 4
                                :consent-round-cid consent-cid
                                :committee (mapv :spki v1-kps)})
                        [{:pubkey (:spki root-kp) :privkey (:private root-kp)}])
            v-short (circle/verify-validator-set-descriptor
                     desc-short
                     {:root-owner-multisig root-ms
                      :network-uri net-uri
                      :network-genesis-cid gen-cid
                      :lead-epochs 2})
            ;; Equivocation proof for v0[5]
            bad-v (nth v0-kps 5)
            m1 (fressian/encode-canonical [:vote 100 "hash-a"])
            m2 (fressian/encode-canonical [:vote 100 "hash-b"])
            equiv-proof {:validator-pubkey (:spki bad-v)
                         :epoch 100
                         :message-1 m1
                         :sig-1 (basalt/bytes->hex (crypto/sign (:private bad-v) m1))
                         :message-2 m2
                         :sig-2 (basalt/bytes->hex (crypto/sign (:private bad-v) m2))}
            desc-equiv (circle/create-validator-set-descriptor
                        (merge disc-fields
                               {:network-uri net-uri
                                :network-genesis-cid gen-cid
                                :version 2
                                :not-before-epoch 100
                                :epoch-finalized 100
                                :epoch-effective 101
                                :quorum-threshold 4
                                :consent-round-cid consent-cid
                                :committee (mapv :spki (subvec v0-kps 0 5))
                                :equivocation-proof equiv-proof})
                        [{:pubkey (:spki root-kp) :privkey (:private root-kp)}])
            v-equiv (circle/verify-validator-set-descriptor
                     desc-equiv
                     {:root-owner-multisig root-ms
                      :network-uri net-uri
                      :network-genesis-cid gen-cid
                      :lead-epochs 6})]
        (is (not (:ok? v-short)) "Normal rotation with lead = 2 (< 3) must be rejected")
        (is (= :validator-rotation-lead-too-short (:error v-short)))
        (is (:ok? v-equiv) "Fast equivocation ejection at ep-fin + 1 with valid proof must succeed")))

    (testing "B4-a & B4-c: Scheduled 4/6 validator rotation across ep-eff promotes active committee without deadlock and L0 verifies V1 snapshots"
      (let [cur-ep (long (:epoch (get warmed-cluster (first v0-pubs))))
            ep-eff (+ cur-ep 3)
            rot-desc (circle/create-validator-set-descriptor
                      (merge disc-fields
                             {:network-uri net-uri
                              :network-genesis-cid gen-cid
                              :version 2
                              :not-before-epoch cur-ep
                              :epoch-finalized cur-ep
                              :epoch-effective ep-eff
                              :quorum-threshold 4
                              :consent-round-cid consent-cid
                              :committee (mapv :mixed-pub v1-kps)})
                      [{:pubkey (:spki root-kp) :privkey (:private root-kp)}])
            rot-rcpt {:type :rotate-validator-set
                      :receipt-id "rcpt-rot-b4-1"
                      :descriptor rot-desc
                      :epoch cur-ep}
            ;; Stage rotation receipt on all nodes
            staged-cluster (into {}
                                 (map (fn [[pk st]]
                                        [pk (update st :pending-receipts (fnil conj []) rot-rcpt)]))
                                 warmed-cluster)
            ;; Run 20 epochs past ep-eff
            rotated-cluster (nth (iterate step-cluster-epoch staged-cluster) 20)
            v1-sample (get rotated-cluster (nth v1-pubs 2))
            v1-fin-ep (long (or (:last-executed-finalized-epoch v1-sample) 0))
            promoted-diag (long (get-in v1-sample [:diagnostics :validator-set-promoted] 0))]
        (is (> v1-fin-ep (+ ep-eff 8))
            (str "Cluster must finalize continuously past ep-eff+8 after 4/6 rotation, got fin-ep=" v1-fin-ep " ep-eff=" ep-eff))
        (is (pos? promoted-diag)
            "Promoting rotated validators must emit/count :validator-set-promoted")
        ;; B4-c: V1-signed snapshots carry :validator-set-history and L0 verifies them via trusted-validators-for-epoch
        (let [v1-snaps (mapv (fn [pk]
                               (core-mesh/build-validator-chain-state-snapshot
                                (get rotated-cluster pk) nil (:spki agent-kp) "n-rot"))
                             (take 4 v1-pubs))
              snap0 (first v1-snaps)
              l0-with-hist (assoc l0 :validator-set-history (:validator-set-history v1-sample))
              ;; Test handle-wire-chain-state-snapshot across 4 V1 snapshots
              l0-synced (reduce (fn [st snap]
                                  (:state (light-core/handle-wire-chain-state-snapshot st snap)))
                                l0-with-hist
                                v1-snaps)
              ;; Also test exec-sync-account via handle-command
              cmd-res (light-core/handle-command l0-with-hist
                                                 {"cmd" "sync-account" "snapshots" v1-snaps}
                                                 (:private agent-kp))]
          (is (seq (:validator-set-history snap0))
              "build-validator-chain-state-snapshot must include :validator-set-history")
          (is (= v1-fin-ep (get-in l0-synced [:account :finalized-epoch]))
              "handle-wire-chain-state-snapshot must trust rotated V1 committee")
          (is (true? (get-in cmd-res [:response "ok"]))
              "exec-sync-account must trust rotated V1 committee"))))))

;; =============================================================================
;; BIP-026 §4 Generative Properties (test.check defspec) for P2, P4, B12
;; =============================================================================

(defspec ^{:doc "P2.2 (B12): mc_harness/scale-lifecycle-config clamps :validator-activation-lead-epochs >= 3 and computes exact compound drawdown 1 - (1 - lambda)^C strictly in (0.0, 1.0) for all 0 < lambda < 1, C >= 1."}
  prop-mc-harness-lead-floor-and-compound-drawdown
  100
  (prop/for-all [lambda-bps (gen/choose 1 9999)
                 lead-base (gen/choose 1 30)
                 c (gen/choose 1 500)]
                (let [lam (/ (double lambda-bps) 10000.0)
                      scaled (mc-harness/scale-lifecycle-config
                              {:bootstrap-drawdown-lambda lam
                               :validator-activation-lead-epochs lead-base}
                              c)
                      expected (- 1.0 (Math/pow (- 1.0 lam) (double c)))
                      actual (double (:bootstrap-drawdown-lambda scaled))
                      actual-lead (long (:validator-activation-lead-epochs scaled))]
                  (and (>= actual-lead 3)
                       (> actual 0.0)
                       (<= actual 1.0)
                       (< (Math/abs (- expected actual)) 1.0e-12)))))

(defspec ^{:doc "P4.1 (B6): SLA-vesting vault spends enforce advisory-twin rejection, 64/88-hex oracle key deduplication, :vault-seq + epoch freshness + score-bps bounds, relock puzzle-hash binding, and 7-bucket conservation."}
  prop-sla-vesting-oracle-attestation
  25
  (prop/for-all [cur-ep (gen/choose 20 500)
                 lag (gen/choose 0 5)
                 stale-extra (gen/choose 6 20)
                 score1 (gen/choose 9500 10000)
                 score2 (gen/choose 9500 10000)
                 tranche (gen/choose 200 2000)]
                (let [o1 (gen-kp)
                      o2 (gen-kp)
                      twin (gen-kp)
                      recv (gen-kp)
                      o1-raw (subs (:spki o1) 24)
                      net-uri "devnet.bitecho.org"
                      gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      total-bal (+ tranche 5000)
                      relock-amt (- total-bal tranche)
                      sla-src (str "(fn [env sol]"
                                   "  (let [atts (or (:oracle-attestations env) {})"
                                   "        allowed #{" (pr-str (:spki o1)) " " (pr-str (:spki o2)) "}"
                                   "        valid (filter (fn [pk]"
                                   "                        (let [a (get atts pk)]"
                                   "                          (and (contains? allowed pk)"
                                   "                               (map? a)"
                                   "                               (:verified? a)"
                                   "                               (>= (:score-bps a) 9500))))"
                                   "                      (keys atts))]"
                                   "    (if (>= (count valid) 2)"
                                   "      [{:type :release :receiver " (pr-str (:spki recv)) " :amount " tranche "}"
                                   "       {:type :relock :amount " relock-amt " :next-puzzle-hash (or (:forced-ph sol) (:puzzle-hash env))}]"
                                   "      false)))")
                      ph (puzzle/puzzle-cid sla-src)
                      s0 (vault/init-vaults-state
                          {:network-uri net-uri
                           :network-genesis-cid gen-cid
                           :genesis-custody-supply total-bal
                           :advisory-twin-pubkeys #{(:spki twin)}
                           :max-attestation-lag 5
                           :vaults {"v-sla-prop" {:vault-id "v-sla-prop"
                                                  :entity-uri "root/sla-prop"
                                                  :custody-bucket nil
                                                  :puzzle-hash ph
                                                  :balance total-bal
                                                  :vault-seq 1
                                                  :created-epoch 0
                                                  :status :active}}})
                      att1 (make-sla-attestation o1 {:network-uri net-uri :network-genesis-cid gen-cid
                                                     :vault-id "v-sla-prop" :vault-seq 1 :epoch (- cur-ep lag) :score-bps score1})
                      att2 (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                                     :vault-id "v-sla-prop" :vault-seq 1 :epoch (- cur-ep lag) :score-bps score2})
                      att-stale (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                                          :vault-id "v-sla-prop" :vault-seq 1 :epoch (- cur-ep stale-extra) :score-bps score2})
                      att-bad-seq (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                                            :vault-id "v-sla-prop" :vault-seq 2 :epoch cur-ep :score-bps score2})
                      att-bad-bps (make-sla-attestation o2 {:network-uri net-uri :network-genesis-cid gen-cid
                                                            :vault-id "v-sla-prop" :vault-seq 1 :epoch cur-ep :score-bps 10001})
                      att-twin (make-sla-attestation twin {:network-uri net-uri :network-genesis-cid gen-cid
                                                           :vault-id "v-sla-prop" :vault-seq 1 :epoch cur-ep :score-bps score2})
                      r-twin (vault/spend-vault s0 {:vault-id "v-sla-prop" :vault-seq 1 :puzzle-source sla-src
                                                    :solution {:oracle-attestations {(:spki o1) att1 (:spki twin) att-twin}}
                                                    :epoch cur-ep})
                      r-alias (vault/spend-vault s0 {:vault-id "v-sla-prop" :vault-seq 1 :puzzle-source sla-src
                                                     :solution {:oracle-attestations {(:spki o1) att1 o1-raw att1}}
                                                     :epoch cur-ep})
                      r-stale (vault/spend-vault s0 {:vault-id "v-sla-prop" :vault-seq 1 :puzzle-source sla-src
                                                     :solution {:oracle-attestations {(:spki o1) att1 (:spki o2) att-stale}}
                                                     :epoch cur-ep})
                      r-seq (vault/spend-vault s0 {:vault-id "v-sla-prop" :vault-seq 1 :puzzle-source sla-src
                                                   :solution {:oracle-attestations {(:spki o1) att1 (:spki o2) att-bad-seq}}
                                                   :epoch cur-ep})
                      r-bps (vault/spend-vault s0 {:vault-id "v-sla-prop" :vault-seq 1 :puzzle-source sla-src
                                                   :solution {:oracle-attestations {(:spki o1) att1 (:spki o2) att-bad-bps}}
                                                   :epoch cur-ep})
                      r-hijack (vault/spend-vault s0 {:vault-id "v-sla-prop" :vault-seq 1 :puzzle-source sla-src
                                                      :solution {:oracle-attestations {(:spki o1) att1 (:spki o2) att2}
                                                                 :next-puzzle-hash ph
                                                                 :forced-ph "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
                                                      :epoch cur-ep})
                      r-ok (vault/spend-vault s0 {:vault-id "v-sla-prop" :vault-seq 1 :puzzle-source sla-src
                                                  :solution {:oracle-attestations {(:spki o1) att1 (:spki o2) att2}
                                                             :next-puzzle-hash ph}
                                                  :epoch cur-ep})]
                  (and (= :advisory-twin-signing-forbidden (:error r-twin))
                       (not (:ok? r-alias))
                       (= :stale-oracle-attestation (:error r-stale))
                       (= :oracle-vault-seq-mismatch (:error r-seq))
                       (= :invalid-oracle-score-bps (:error r-bps))
                       (= :relock-puzzle-hash-mismatch (:error r-hijack))
                       (:ok? r-ok)
                       (= relock-amt (get-in (:state r-ok) [:vaults "v-sla-prop" :balance]))
                       (:ok? (vault/verify-7-bucket-conservation (:state r-ok)))))))

(defspec ^{:doc "P2.1–P2.3 (B4): Deterministic 6-node Streamlet cluster rotating 4/6 validators across ep-eff (with lead >= 3) promotes active committee without deadlock, finalizes past ep-eff + 12, and light-node verifies rotated snapshots."}
  vopr-6-node-validator-rotation-no-deadlock
  3
  (prop/for-all [lead (gen/elements [3 4 6])]
                (let [root-kp (gen-kp)
                      root-ms {:threshold 1 :pubkeys [(:spki root-kp)]}
                      net-uri "devnet.bitecho.org"
                      gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      raw-kps (vec (repeatedly 10 gen-kp))
                      kps (mapv (fn [idx kp]
                                  (assoc kp :wire-pub (if (even? idx) (subs (:spki kp) 24) (:spki kp))))
                                (range 10)
                                raw-kps)
                      v0-kps (subvec kps 0 6)
                      v1-kps (vec (concat (subvec kps 0 2) (subvec kps 6 10)))
                      v0-pubs (mapv :wire-pub v0-kps)
                      v1-pubs (mapv :wire-pub v1-kps)
                      consent-cid "3333333333333333333333333333333333333333333333333333333333333333"
                      disc-fields {:retention-policy {:max-entries 128 :max-bytes 1048576 :rotate-every-entries 32 :ttl-epochs 52560}
                                   :storage-accounting {:bytes-at-rest 2048 :cache-incentive :free-self-hosted :payer-pubkey (:spki root-kp) :fee-ech 0}}
                      base-cluster (into {}
                                         (map (fn [kp]
                                                [(:wire-pub kp) (build-cluster-node kp kps v0-pubs root-ms net-uri gen-cid)]))
                                         kps)
                      warmed (nth (iterate step-cluster-epoch base-cluster) 6)
                      cur-ep (long (:epoch (get warmed (first v0-pubs))))
                      ep-eff (+ cur-ep lead)
                      rot-desc (circle/create-validator-set-descriptor
                                (merge disc-fields
                                       {:network-uri net-uri
                                        :network-genesis-cid gen-cid
                                        :version 2
                                        :not-before-epoch cur-ep
                                        :epoch-finalized cur-ep
                                        :epoch-effective ep-eff
                                        :quorum-threshold 4
                                        :consent-round-cid consent-cid
                                        :committee (mapv :spki v1-kps)})
                                [{:pubkey (:spki root-kp) :privkey (:private root-kp)}])
                      rot-rcpt {:type :rotate-validator-set
                                :receipt-id (str "rcpt-vopr-rot-" lead)
                                :descriptor rot-desc
                                :epoch cur-ep}
                      staged (into {}
                                   (map (fn [[pk st]]
                                          [pk (update st :pending-receipts (fnil conj []) rot-rcpt)]))
                                   warmed)
                      ;; Advance enough epochs to clear lead + 12+ finalized epochs
                      after-rot (nth (iterate step-cluster-epoch staged) (+ lead 18))
                      v1-node (get after-rot (nth v1-pubs 3))
                      v1-fin-ep (long (or (:last-executed-finalized-epoch v1-node) 0))
                      agent-kp (gen-kp)
                      bs-v0 {:network-uri net-uri
                             :nodes (into {} (map-indexed (fn [i kp] [(keyword (str "v" i)) {:pubkey (:wire-pub kp)}]) v0-kps))}
                      l0 (-> (light-core/init-light-state (:spki agent-kp) {:bootstrap bs-v0})
                             (assoc :validator-set-history (:validator-set-history v1-node)))
                      v1-snaps (mapv (fn [pk]
                                       (core-mesh/build-validator-chain-state-snapshot
                                        (get after-rot pk) nil (:spki agent-kp) "n-vopr"))
                                     (take 4 v1-pubs))
                      l0-synced (reduce (fn [st snap]
                                          (:state (light-core/handle-wire-chain-state-snapshot st snap)))
                                        l0
                                        v1-snaps)]
                  (and (>= v1-fin-ep (+ ep-eff 12))
                       (pos? (long (get-in v1-node [:diagnostics :validator-set-promoted] 0)))
                       (seq (:validator-set-history (first v1-snaps)))
                       (= v1-fin-ep (get-in l0-synced [:account :finalized-epoch]))))))
