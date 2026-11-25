(ns bitecho.bip026-gate-test
  "BIP-026 Draft 2 Bug-Confirmation Gate Scenarios (B1–B12).
   Adopted directly from Lumen's Batch 1 (CID 6d0ab3ab...) & Batch 2 (CID 8392e7e7...) specs.

   Acceptance rule:
   1. Baseline sanity check passes on pre-fix code (anti-vacuity guard).
   2. Fails RED on pre-fix c6b558c for the exact documented reason.
   3. Flips GREEN only when BIP-026 Draft 2 (CID c72d4614...) normative fix lands."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.circles.vault :as vault]
            [bitecho.core.circle :as circle]
            [bitecho.core.data :as data]
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
            consent-round {:proposal-cid proposal-cid
                           :eligible-voters [(:spki owner)]
                           :ballots {(:spki owner) {:vote :consent}}}
            r-dev (circle/dissolve-circle s-with-desc {:circle-path "root/boot-child" :parent-vault-id "p-dev" :consent-round consent-round} {})
            r-nil (circle/dissolve-circle s-with-desc {:circle-path "root/boot-child" :parent-vault-id "p-nil" :consent-round consent-round} {})
            r-closed (circle/dissolve-circle s-with-desc {:circle-path "root/boot-child" :parent-vault-id "p-closed" :consent-round consent-round} {})]
        (is (not (:ok? r-dev)) "dissolve-circle into :development parent MUST fail closed")
        (is (not (:ok? r-nil)) "dissolve-circle into nil-bucket parent MUST fail closed")
        (is (not (:ok? r-closed)) "dissolve-circle into :closed parent MUST fail closed")))

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
          (is (= 100000 (+ (reduce + 0 nets) (reduce + 0 takes)))))))))

;; =============================================================================
;; BIP-026 §4 Generative Properties (test.check defspec) for P1, P3, P5
;; =============================================================================

(defspec ^{:doc "P3.1 & P3.2 (B5): Hamilton largest-remainder apportionment guarantees 0 <= take_i <= amt_i, net_i >= 0, exact single-take conservation across escrows and vaults, and rejects :allocate/:relock on one-shot escrows."}
  prop-multi-output-release-single-take-exact
  50
  (prop/for-all [amounts (gen/not-empty (gen/vector (gen/choose 1 50000) 1 8))
                 bps (gen/choose 1 500)]
                (let [releases (mapv (fn [idx amt]
                                       {:type :release :receiver (str "recv-" idx) :amount amt})
                                     (range (count amounts))
                                     amounts)
                      total-gross (reduce + 0 amounts)
                      expected-take (escrow/calculate-escrow-settlement-take total-gross bps)
                      apportioned (escrow/apportion-settlement-take releases bps)
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
                       (:ok? (vault/verify-7-bucket-conservation st1))))))

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
                      v-tuple (vault/vault-create-signing-tuple
                               (assoc v-params :network-uri net-uri :network-genesis-cid gen-cid))
                      v-rcpt (assoc v-params :signature (basalt/bytes->hex (crypto/sign-canonical (:private payer) v-tuple)))
                      rcpts [{:type :burn :receipt-id "rcpt-burn-1" :sender (:spki payer) :amount burn-amt}
                             {:type :bounty-create :receipt-id "rcpt-bounty-1" :bounty-id "b-prop-1"
                              :payer (:spki payer) :gross-amount bounty-amt :take-bps 50 :builder-bps 500 :epoch 4}
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
                      signed-round {:proposal-cid prop-cid
                                    :lead-link-pubkey (:spki owner)
                                    :ballots {(:spki owner) (circle/sign-consent-ballot (:private owner) (:spki owner) prop-cid :consent)}
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
                      v-enc-ok (circle/verify-encrypted-entity-envelope enc-ok {:network-uri net-uri :network-genesis-cid gen-cid})
                      v-enc-bad (circle/verify-encrypted-entity-envelope enc-bad-path {:network-uri net-uri :network-genesis-cid gen-cid})]
                  (and (false? (:ok? res-unsigned))
                       (if (= child-bucket parent-bucket)
                         (and (:ok? res-signed)
                              (:ok? (vault/verify-7-bucket-conservation (:state res-signed))))
                         (and (false? (:ok? res-signed))
                              (= :custody-bucket-mismatch (:error res-signed))))
                       (not (contains? (:storage-accounting enc-ok) :payer-pubkey))
                       (:ok? v-enc-ok)
                       (false? (:ok? v-enc-bad))))))
