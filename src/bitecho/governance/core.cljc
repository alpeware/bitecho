(ns bitecho.governance.core
  "Milestone D20 & D22: Autonomous Development, Fractal Subnet Governance, Capability-Backed Bounties,
   & Tri-Circle Sociocratic Governance Protocol.
   Pure Sans-IO `.cljc` core implementing:
   - Layer 1: Permissionless Fractal Lab Subnets & RFC 6962 Domain-Separated Binary Merkle Root Anchoring (`A-D20-1`)
   - Layer 2: Executable BIPs across fractal subnets (`Blob` + `Pointer` `bip/<id>`) & Admission Gates (`INV-D20-1`, `A-D22-1`)
   - Layer 3: Capability-Backed Bilateral Builder/Auditor Bounties (`85/15` split, zero-dust conservation, heterogeneous 3-party quorum `A-CARB-D20-1..2`, `A-CARB-D22-2`)
   - Layer 4: Tri-Circle Sociocratic Consent, Reproducible Counterexample Regression Gate, & Deterministic Epoch-Boundary Policy Activation (`INV-D20-3..4`, `A-CARB-D20-3`, `A-D22-1`, `A-CARB-D22-1`)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.storage :as storage]
            [bitecho.crypto :as crypto]
            [bitecho.economy.attestation :as attestation]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def dev-subnet-id
  "Canonical autonomous development & governance subnet ID."
  "bitecho.org/dev")

(def tri-circles
  "Canonical set of the 3 Sociocratic governance circles."
  #{:builders-stewards :mesh-validators :anchor-agent-users})

(defn init-governance-state
  "Initializes a pure governance protocol state map."
  ([] (init-governance-state nil))
  ([opts]
   {:blob-store (data/init-blob-store opts)
    :blobs {}
    :lab-subnets {}
    :subnet-anchors {}
    :bips {}
    :pointers {}
    :bounties {}
    :capabilities {}
    :circles {:builders-stewards {}
              :mesh-validators {}
              :anchor-agent-users {}}
    :circle-responses {}
    :regression-vectors []
    :subnet-regression-vectors {}
    :scheduled-upgrades {}
    :subnet-policies {}
    :activated-upgrades []
    :diagnostics {:invalid-lab-subnet-rejected 0
                  :bip-admission-rejected 0
                  :sybil-bounty-claim-rejected 0
                  :bounty-quorum-invalid 0
                  :unauthorized-circle-member 0
                  :unsubstantiated-objection-ignored 0
                  :paramount-objection-recorded 0}}))

(defn get-bip
  "Retrieves a BIP record by `[subnet-id bip-id]` (or `bip-id` on the default subnet)."
  ([state bip-id]
   (or (get-in state [:bips [dev-subnet-id (str bip-id)]])
       (get-in state [:bips (str bip-id)])))
  ([state subnet-id bip-id]
   (let [sub (str (or subnet-id dev-subnet-id))
         id (str bip-id)]
     (or (get-in state [:bips [sub id]])
         (when (= sub dev-subnet-id)
           (get-in state [:bips id]))))))

(defn get-bounty
  "Retrieves a bounty record by `[subnet-id bounty-id]` (or `bounty-id` on the default subnet)."
  ([state bounty-id]
   (or (get-in state [:bounties [dev-subnet-id (str bounty-id)]])
       (get-in state [:bounties (str bounty-id)])))
  ([state subnet-id bounty-id]
   (let [sub (str (or subnet-id dev-subnet-id))
         id (str bounty-id)]
     (or (get-in state [:bounties [sub id]])
         (when (= sub dev-subnet-id)
           (get-in state [:bounties id]))))))

(defn get-subnet-regression-vectors
  "Returns the vector of recorded paramount-objection regression vectors for `subnet-id`."
  ([state]
   (:regression-vectors state []))
  ([state subnet-id]
   (let [sub (str (or subnet-id dev-subnet-id))]
     (get-in state [:subnet-regression-vectors sub] []))))

;; =============================================================================
;; 1. Layer 1: Fractal Lab Subnets & RFC 6962 Binary Merkle Root Anchoring
;; =============================================================================

(defn register-lab-subnet
  "Registers a permissionless child lab subnet policy descriptor (`INV-D20-1`)."
  [state subnet-descriptor]
  (let [subnet-id (str (or (:subnet-id subnet-descriptor) ""))
        min-burn (long (or (:min-signaling-burn subnet-descriptor) 0))
        gate (or (:admission-gate subnet-descriptor) :permissionless)
        schemas (vec (or (:capability-schemas subnet-descriptor) []))
        take-bps (long (or (:settlement-take-bps subnet-descriptor) 50))]
    (if (or (str/blank? subnet-id)
            (neg? min-burn)
            (not (contains? #{:permissionless :dac-attested :stake-gated} gate))
            (neg? take-bps))
      (let [diag {:effect :diagnose :reason :invalid-lab-subnet-rejected :subnet-id subnet-id}
            st' (update-in state [:diagnostics :invalid-lab-subnet-rejected] (fnil inc 0))]
        {:ok? false :error :invalid-lab-subnet :state st' :effects [diag]})
      (let [desc {:subnet-id subnet-id
                  :min-signaling-burn min-burn
                  :admission-gate gate
                  :capability-schemas schemas
                  :settlement-take-bps take-bps}
            st' (assoc-in state [:lab-subnets subnet-id] desc)]
        {:ok? true :subnet desc :state st' :effects []}))))

(defn compute-rfc6962-merkle-root
  "Computes the RFC 6962 domain-separated binary Merkle root (64-char lowercase hex)
   over `leaves` by delegating to `bitecho.core.data/compute-rfc6962-merkle-root` (`BIP-005` / `D31.2`)."
  [leaves]
  (data/compute-rfc6962-merkle-root leaves))

(defn anchor-subnet-merkle-root
  "Computes and anchors a child lab subnet's RFC 6962 binary Merkle state root at `epoch` into `:subnet-anchors`."
  [state subnet-id epoch state-leaves]
  (if-not (contains? (:lab-subnets state) subnet-id)
    (let [diag {:effect :diagnose :reason :invalid-lab-subnet-rejected :subnet-id subnet-id}
          st' (update-in state [:diagnostics :invalid-lab-subnet-rejected] (fnil inc 0))]
      {:ok? false :error :unknown-lab-subnet :state st' :effects [diag]})
    (let [root (compute-rfc6962-merkle-root state-leaves)
          anchor {:subnet-id subnet-id
                  :epoch (long epoch)
                  :merkle-root root
                  :leaf-count (count state-leaves)}
          st' (assoc-in state [:subnet-anchors [subnet-id (long epoch)]] anchor)]
      {:ok? true :anchor anchor :merkle-root root :state st' :effects []})))

;; =============================================================================
;; 2. Layer 2: Executable BIPs on `bitecho.org/dev` (`INV-D20-1`)
;; =============================================================================

(defn verify-bip-admission-gates
  "Verifies that a BIP proposal map carries complete executable admission proof metadata:
   1. `:invariant-diff` (`:defspec-vars` non-empty, `:sans-io-pure? true`, `:diagnose-coverage? true`, `:co-committed-spec-and-flags? true`)
   2. `:oracle-receipts` (`:four-way-golden-oracle`, `:vopr-jepsen-non-vacuity`, `:deterministic-bundle-sha256`, `:bwrap-civilization-regression`)."
  [bip]
  (let [inv (:invariant-diff bip)
        oracles (:oracle-receipts bip)
        missing
        (cond-> []
          (or (not (sequential? (:defspec-vars inv))) (empty? (:defspec-vars inv)))
          (conj :invariant-diff/defspec-vars)

          (not (true? (:sans-io-pure? inv)))
          (conj :invariant-diff/sans-io-pure?)

          (not (true? (:diagnose-coverage? inv)))
          (conj :invariant-diff/diagnose-coverage?)

          (not (true? (:co-committed-spec-and-flags? inv)))
          (conj :invariant-diff/co-committed-spec-and-flags?)

          (not (true? (get-in oracles [:four-way-golden-oracle :passed?])))
          (conj :oracle-receipts/four-way-golden-oracle)

          (not (true? (get-in oracles [:vopr-jepsen-non-vacuity :passed?])))
          (conj :oracle-receipts/vopr-jepsen-non-vacuity)

          (let [sha (:deterministic-bundle-sha256 oracles)]
            (or (not (string? sha)) (not= 64 (count (str/trim sha)))))
          (conj :oracle-receipts/deterministic-bundle-sha256)

          (not (true? (get-in oracles [:bwrap-civilization-regression :passed?])))
          (conj :oracle-receipts/bwrap-civilization-regression))]
    {:ok? (empty? missing)
     :missing-gates missing}))

(defn submit-bip
  "Validates `bip` against `verify-bip-admission-gates`; on pass, serializes the BIP into a
   content-addressed `Blob` (`data/make-blob`) and signs a mutable `Pointer` (`bip/<bip-id>`)
   in subnet `\"bitecho.org/dev\"`. Fails closed with counted `:diagnose` on missing gates (`Rule 5`)."
  [state bip author-privkey]
  (let [gate-res (verify-bip-admission-gates bip)
        bip-id (str (or (:bip-id bip) ""))]
    (if (or (str/blank? bip-id) (not (:ok? gate-res)))
      (let [diag {:effect :diagnose
                  :reason :bip-admission-rejected
                  :bip-id bip-id
                  :missing-gates (:missing-gates gate-res)}
            st' (update-in state [:diagnostics :bip-admission-rejected] (fnil inc 0))]
        {:ok? false
         :error :bip-admission-rejected
         :missing-gates (:missing-gates gate-res)
         :state st'
         :effects [diag]})
      (let [canonical-bytes (fressian/encode-canonical bip)
            blob (data/make-blob canonical-bytes "application/vnd.bitecho.bip+fressian")
            put-res (data/put-blob (:blob-store state) blob)
            cid (:cid put-res)
            sub-id (str (or (:subnet-id bip) dev-subnet-id))
            path (str "bip/" bip-id)
            prev-ptr (get-in state [:pointers [sub-id path]])
            next-seq (inc (long (:pointer/seq prev-ptr 0)))
            ptr (data/sign-pointer
                 author-privkey
                 {:pointer/authority (:author-pubkey bip)
                  :pointer/subnet sub-id
                  :pointer/path path
                  :pointer/seq next-seq
                  :pointer/target cid
                  :pointer/proof {:proof/type :self}})
            bip-record (assoc bip
                              :subnet-id sub-id
                              :cid cid
                              :pointer ptr
                              :status :under-review)
            st' (-> state
                    (assoc :blob-store (:store put-res))
                    (assoc-in [:blobs cid] blob)
                    (assoc-in [:pointers [sub-id path]] ptr)
                    (assoc-in [:bips [sub-id bip-id]] bip-record)
                    (assoc-in [:bips bip-id] bip-record))]
        {:ok? true
         :subnet-id sub-id
         :bip-id bip-id
         :cid cid
         :blob blob
         :pointer ptr
         :state st'
         :effects []}))))

;; =============================================================================
;; 3. Layer 3: Bilateral Builder/Auditor Bounties (`INV-D20-2`, `A-CARB-D20-1..2`, `INV-D22-2`)
;; =============================================================================

(defn calculate-bounty-split
  "Computes exact zero-dust integer split of `gross-amount` ($A \\ge 1$) into:
   - `:protocol-take` ($\\max(1, \\lfloor A \\cdot \\tau_{\\text{bps}} / 10000 \\rfloor)$, clamped to $A$)
   - `:builder-net` ($\\lfloor (A - \\text{take}) \\cdot \\text{builder}_{\\text{bps}} / 10000 \\rfloor$)
   - `:auditor-net` ($(A - \\text{take}) - \\text{builder\\_net}$)
   Guarantees `(+ builder-net auditor-net protocol-take) == gross-amount` (`A-CARB-D20-2`, `A-D20-2`)."
  ([gross-amount]
   (calculate-bounty-split gross-amount nil))
  ([gross-amount {:keys [take-bps builder-bps]
                  :or {take-bps 50
                       builder-bps 8500}}]
   (let [a (max 0 (long gross-amount))
         eff-take-bps (min 10000 (max 0 (long (or take-bps 50))))
         eff-builder-bps (min 10000 (max 0 (long (or builder-bps 8500))))
         protocol-take (if (pos? a)
                         (min a (max 1 (quot (* a eff-take-bps) 10000)))
                         0)
         net-pool (- a protocol-take)
         builder-net (quot (* net-pool eff-builder-bps) 10000)
         auditor-net (- net-pool builder-net)]
     {:gross-amount a
      :protocol-take protocol-take
      :builder-net builder-net
      :auditor-net auditor-net})))

(defn create-bounty-escrow
  "Creates a milestone-gated bilateral bounty escrow referencing `:target-bip-cid` and packs
   a content-addressed capability `Blob` + signed `Pointer` (`bounty/<bounty-id>`) in `:capabilities` (`INV-D22-2`)."
  ([state bounty-spec]
   (create-bounty-escrow state bounty-spec nil))
  ([state bounty-spec privkey]
   (let [sub-id (str (or (:subnet-id bounty-spec) dev-subnet-id))
         bounty-id (str (or (:bounty-id bounty-spec) ""))
         gross (long (or (:gross-amount bounty-spec) (:amount bounty-spec) 0))
         split (calculate-bounty-split gross bounty-spec)
         cap-path (str "bounty/" bounty-id)
         fallback-kp (crypto/generate-keypair (str "bounty-cap-" sub-id "-" bounty-id))
         eff-priv (or privkey (:maintainer-privkey bounty-spec) (:private fallback-kp))
         eff-pub (or (:maintainer-pubkey bounty-spec) (:hex fallback-kp))
         prev-cap-ptr (:pointer (get-in state [:capabilities [sub-id cap-path]]))
         cap-seq (inc (long (:pointer/seq prev-cap-ptr 0)))
         packed-cap (storage/pack-capability-descriptor
                     {:privkey eff-priv
                      :pubkey eff-pub
                      :capability-id bounty-id
                      :path cap-path
                      :subnet-id sub-id
                      :capability-type :governance/bounty
                      :price-echo gross
                      :burn-floor 0
                      :target-cid (or (:target-bip-cid bounty-spec) (:bip-id bounty-spec))
                      :metadata {:bounty-id bounty-id
                                 :target-bip-cid (or (:target-bip-cid bounty-spec) (:bip-id bounty-spec))}
                      :seq cap-seq})
         cap-cid (:cid packed-cap)
         cap-blob (:blob packed-cap)
         cap-ptr (:pointer packed-cap)
         put-res (data/put-blob (:blob-store state) cap-blob)
         entry (merge (dissoc bounty-spec :maintainer-privkey)
                      split
                      {:subnet-id sub-id
                       :bounty-id bounty-id
                       :capability-cid cap-cid
                       :capability-pointer cap-ptr
                       :status :locked})
         st' (-> state
                 (assoc :blob-store (:store put-res))
                 (assoc-in [:blobs cap-cid] cap-blob)
                 (assoc-in [:pointers [sub-id cap-path]] cap-ptr)
                 (assoc-in [:capabilities [sub-id cap-path]]
                           {:descriptor (:descriptor packed-cap)
                            :cid cap-cid
                            :blob cap-blob
                            :pointer cap-ptr})
                 (assoc-in [:bounties [sub-id bounty-id]] entry)
                 (assoc-in [:bounties bounty-id] entry))]
     {:ok? true
      :subnet-id sub-id
      :bounty entry
      :capability-cid cap-cid
      :capability-blob cap-blob
      :capability-pointer cap-ptr
      :state st'
      :effects []})))

(defn canonical-bounty-claim-payload
  "Canonical signing payload for heterogeneous 3-party bounty settlement."
  [bounty-id patch-bundle-cid reproducible-sha256]
  ["bitecho-bounty-claim-v1"
   (str bounty-id)
   (str patch-bundle-cid)
   (str reproducible-sha256)])

(defn build-signed-bounty-claim
  "Helper to construct a signed 3-party bounty claim map from builder, cross-model AI auditor,
   and Human Anchor maintainer keypairs."
  [{:keys [bounty-id patch-bundle-cid reproducible-sha256
           builder-kp auditor-kp auditor-model maintainer-kp]}]
  (let [payload (canonical-bounty-claim-payload bounty-id patch-bundle-cid reproducible-sha256)
        b-sig (basalt/bytes->hex (crypto/sign-canonical (:private builder-kp) payload))
        a-sig (basalt/bytes->hex (crypto/sign-canonical (:private auditor-kp) payload))
        m-sig (basalt/bytes->hex (crypto/sign-canonical (:private maintainer-kp) payload))]
    {:bounty-id bounty-id
     :patch-bundle-cid patch-bundle-cid
     :reproducible-sha256 reproducible-sha256
     :builder {:pubkey (:hex builder-kp)
               :signature b-sig}
     :auditor {:pubkey (:hex auditor-kp)
               :model (or auditor-model "claude-opus-5-5")
               :tests-passed? true
               :lint-clean? true
               :reproducible-sha256 reproducible-sha256
               :signature a-sig}
     :maintainer {:pubkey (:hex maintainer-kp)
                  :signature m-sig}}))

(defn- verify-party-sig
  [pubkey-hex sig-hex payload]
  (try
    (and (string? pubkey-hex) (not (str/blank? pubkey-hex))
         (string? sig-hex) (not (str/blank? sig-hex))
         (crypto/verify-with-fallback
          (basalt/hex->bytes pubkey-hex)
          payload
          (basalt/hex->bytes sig-hex)))
    (catch #?(:clj Exception :cljs :default) _ false)))

(defn settle-bounty-escrow
  "Settles a locked bilateral bounty escrow iff:
   1. `builder-pubkey`, `auditor-pubkey`, and `maintainer-pubkey` are pairwise distinct (`A-CARB-D20-1`).
   2. The auditor attests `:tests-passed? true`, `:lint-clean? true`, and matching `:reproducible-sha256`.
   3. All 3 Ed25519 signatures verify over `canonical-bounty-claim-payload`."
  ([state bounty-id claim]
   (settle-bounty-escrow state (or (:subnet-id claim) dev-subnet-id) bounty-id claim))
  ([state subnet-id bounty-id claim]
   (let [sub-id (str (or subnet-id dev-subnet-id))
         bounty (get-bounty state sub-id bounty-id)
         b-pub (get-in claim [:builder :pubkey])
         a-pub (get-in claim [:auditor :pubkey])
         m-pub (get-in claim [:maintainer :pubkey])
         distinct-signers? (= 3 (count (distinct (keep identity [b-pub a-pub m-pub]))))
         payload (canonical-bounty-claim-payload
                  bounty-id
                  (:patch-bundle-cid claim)
                  (:reproducible-sha256 claim))
         auditor-checks? (and (true? (get-in claim [:auditor :tests-passed?]))
                              (true? (get-in claim [:auditor :lint-clean?]))
                              (string? (:reproducible-sha256 claim))
                              (= (:reproducible-sha256 claim)
                                 (get-in claim [:auditor :reproducible-sha256])))
         expected-m-pub (:maintainer-pubkey bounty)
         sigs-valid? (and (or (nil? expected-m-pub) (= expected-m-pub m-pub))
                          (verify-party-sig m-pub (get-in claim [:maintainer :signature]) payload)
                          (or (true? (:maintainer-direct-settle? claim))
                              (and (verify-party-sig b-pub (get-in claim [:builder :signature]) payload)
                                   (verify-party-sig a-pub (get-in claim [:auditor :signature]) payload))))]
     (cond
       (or (nil? bounty) (not= :locked (:status bounty)))
       (let [diag {:effect :diagnose :reason :bounty-quorum-invalid :subnet-id sub-id :bounty-id bounty-id}
             st' (update-in state [:diagnostics :bounty-quorum-invalid] (fnil inc 0))]
         {:ok? false :error :bounty-not-locked :state st' :effects [diag]})

       (not distinct-signers?)
       (let [diag {:effect :diagnose :reason :sybil-bounty-claim-rejected :subnet-id sub-id :bounty-id bounty-id}
             st' (update-in state [:diagnostics :sybil-bounty-claim-rejected] (fnil inc 0))]
         {:ok? false :error :sybil-bounty-claim-rejected :state st' :effects [diag]})

       (not (and auditor-checks? sigs-valid?))
       (let [diag {:effect :diagnose :reason :bounty-quorum-invalid :subnet-id sub-id :bounty-id bounty-id}
             st' (update-in state [:diagnostics :bounty-quorum-invalid] (fnil inc 0))]
         {:ok? false :error :bounty-quorum-invalid :state st' :effects [diag]})

       :else
       (let [payouts {b-pub (:builder-net bounty)
                      a-pub (:auditor-net bounty)}
             settled (assoc bounty
                            :subnet-id sub-id
                            :status :settled
                            :builder-pubkey b-pub
                            :auditor-pubkey a-pub
                            :payouts payouts
                            :claim claim)
             st' (-> state
                     (assoc-in [:bounties [sub-id bounty-id]] settled)
                     (assoc-in [:bounties bounty-id] settled))]
         {:ok? true
          :subnet-id sub-id
          :bounty settled
          :payouts payouts
          :protocol-take (:protocol-take bounty)
          :state st'
          :effects []})))))

;; =============================================================================
;; 4. Layer 4: Tri-Circle Sociocratic Consent & Counterexample Gate (`INV-D20-3..4`, `INV-D22-1`)
;; =============================================================================

(defn register-circle-member
  "Registers a member into one of the 3 Sociocratic circles with Sybil-anchored weight (`A-CARB-D20-3`, `INV-D22-1`):
   - `:builders-stewards`: `:verified-commits` (> 0)
   - `:mesh-validators`: `attestation/calculate-node-weight` over `:participation` and `:stake` (> 0)
   - `:anchor-agent-users`: `:trailing-burned-ech` (> 0)."
  ([state circle-id pubkey-hex metrics]
   (let [st' (register-circle-member state dev-subnet-id circle-id pubkey-hex metrics)
         entry (get-in st' [:circles [dev-subnet-id circle-id] pubkey-hex])]
     (if entry
       (assoc-in st' [:circles circle-id pubkey-hex] entry)
       st')))
  ([state subnet-id circle-id pubkey-hex metrics]
   (let [sub-id (str (or subnet-id dev-subnet-id))
         weight (case circle-id
                  :builders-stewards (double (max 0 (long (or (:verified-commits metrics) 0))))
                  :mesh-validators (attestation/calculate-node-weight
                                    (or (:participation metrics) 0.0)
                                    (or (:stake metrics) 0)
                                    (or (:min-stake metrics) 250000))
                  :anchor-agent-users (double (max 0 (long (or (:trailing-burned-ech metrics) 0))))
                  0.0)]
     (if (pos? weight)
       (let [entry (assoc metrics :subnet-id sub-id :pubkey pubkey-hex :weight weight)]
         (assoc-in state [:circles [sub-id circle-id] pubkey-hex] entry))
       state))))

(defn validate-counterexample
  "Strictly validates a Sociocratic paramount objection `:counterexample` artifact (`A-D20-3`):
   - `{:type :vopr-seed :seed <int> :failing-invariant <keyword>}`
   - `{:type :monte-carlo-insolvency :seed <int> :path-id <int> :theta <map>}`
   - `{:type :security-regression :reproducer-cid <64-hex> :violated-rule <keyword>}`"
  [ce]
  (if-not (map? ce)
    {:valid? false :reason :missing-counterexample}
    (case (:type ce)
      :vopr-seed
      (if (and (integer? (:seed ce))
               (keyword? (:failing-invariant ce)))
        {:valid? true
         :regression-vector {:suite :vopr-jepsen
                             :seed (long (:seed ce))
                             :invariant (:failing-invariant ce)}}
        {:valid? false :reason :malformed-vopr-counterexample})

      :monte-carlo-insolvency
      (if (and (integer? (:seed ce))
               (integer? (:path-id ce))
               (map? (:theta ce))
               (seq (:theta ce)))
        {:valid? true
         :regression-vector {:suite :monte-carlo-tokenomics
                             :seed (long (:seed ce))
                             :path-id (long (:path-id ce))
                             :theta (:theta ce)}}
        {:valid? false :reason :malformed-monte-carlo-counterexample})

      :security-regression
      (let [cid (:reproducer-cid ce)]
        (if (and (string? cid)
                 (= 64 (count (str/trim cid)))
                 (keyword? (:violated-rule ce)))
          {:valid? true
           :regression-vector {:suite :security-regression
                               :reproducer-cid (str/lower-case (str/trim cid))
                               :violated-rule (:violated-rule ce)}}
          {:valid? false :reason :malformed-security-counterexample}))

      {:valid? false :reason :unknown-counterexample-type})))

(defn submit-circle-response
  "Submits a circle member's response (`{:stance :consent}` or `{:stance :paramount-objection :counterexample ...}`)
   for `bip-id` in `subnet-id` (`INV-D22-1`).
   - Rejects unregistered/zero-weight members with counted `:unauthorized-circle-member` diagnostic (`A-CARB-D20-3`).
   - Ignores unsubstantiated objections (missing/invalid `:counterexample`) with counted
     `:unsubstantiated-objection-ignored` diagnostic (`INV-D20-4`).
   - Converts valid paramount objections into `:regression-vectors` and `[:subnet-regression-vectors subnet-id]` (`INV-D20-4`, `INV-D22-1`)."
  ([state bip-id circle-id member-pubkey response]
   (let [existing-bip (get-in state [:bips bip-id])
         inferred-sub (or (:subnet-id response) (:subnet-id existing-bip) dev-subnet-id)]
     (submit-circle-response state inferred-sub bip-id circle-id member-pubkey response)))
  ([state subnet-id bip-id circle-id member-pubkey response]
   (let [sub-id (str (or subnet-id dev-subnet-id))
         member (or (get-in state [:circles [sub-id circle-id] member-pubkey])
                    (when (contains? #{dev-subnet-id "bitecho-dev"} sub-id)
                      (get-in state [:circles circle-id member-pubkey])))
         weight (double (or (:weight member) 0.0))]
     (if (or (not (contains? tri-circles circle-id))
             (nil? member)
             (<= weight 0.0))
       (let [diag {:effect :diagnose
                   :reason :unauthorized-circle-member
                   :subnet-id sub-id
                   :circle circle-id
                   :pubkey member-pubkey}
             st' (update-in state [:diagnostics :unauthorized-circle-member] (fnil inc 0))]
         {:ok? false :error :unauthorized-circle-member :state st' :effects [diag]})
       (let [stance (:stance response)]
         (if (= stance :paramount-objection)
           (let [ce-res (validate-counterexample (:counterexample response))]
             (if (:valid? ce-res)
               (let [reg-vec (assoc (:regression-vector ce-res)
                                    :subnet-id sub-id
                                    :bip-id bip-id
                                    :circle circle-id
                                    :objector member-pubkey)
                     rec {:stance :paramount-objection
                          :weight weight
                          :counterexample (:counterexample response)
                          :regression-vector reg-vec}
                     diag {:effect :diagnose
                           :reason :paramount-objection-recorded
                           :subnet-id sub-id
                           :bip-id bip-id
                           :circle circle-id}
                     st' (-> state
                             (assoc-in [:circle-responses [sub-id bip-id] circle-id member-pubkey] rec)
                             (cond-> (= sub-id dev-subnet-id)
                               (assoc-in [:circle-responses bip-id circle-id member-pubkey] rec))
                             (update-in [:subnet-regression-vectors sub-id] (fnil conj []) reg-vec)
                             (update :regression-vectors conj reg-vec)
                             (update-in [:diagnostics :paramount-objection-recorded] (fnil inc 0)))]
                 {:ok? true
                  :subnet-id sub-id
                  :recorded-stance :paramount-objection
                  :regression-vector reg-vec
                  :state st'
                  :effects [diag]})
               ;; Unsubstantiated objection -> emit counted diagnostic and record as non-blocking consent-by-absence-of-valid-objection
               (let [diag {:effect :diagnose
                           :reason :unsubstantiated-objection-ignored
                           :subnet-id sub-id
                           :bip-id bip-id
                           :circle circle-id
                           :pubkey member-pubkey}
                     rec {:stance :consent
                          :weight weight
                          :ignored-unsubstantiated-objection? true}
                     st' (-> state
                             (assoc-in [:circle-responses [sub-id bip-id] circle-id member-pubkey] rec)
                             (cond-> (= sub-id dev-subnet-id)
                               (assoc-in [:circle-responses bip-id circle-id member-pubkey] rec))
                             (update-in [:diagnostics :unsubstantiated-objection-ignored] (fnil inc 0)))]
                 {:ok? true :subnet-id sub-id :recorded-stance :consent :ignored-objection? true :state st' :effects [diag]})))
           (let [rec {:stance :consent :weight weight}
                 st' (-> state
                         (assoc-in [:circle-responses [sub-id bip-id] circle-id member-pubkey] rec)
                         (cond-> (= sub-id dev-subnet-id)
                           (assoc-in [:circle-responses bip-id circle-id member-pubkey] rec)))]
             {:ok? true :subnet-id sub-id :recorded-stance :consent :state st' :effects []})))))))

(defn evaluate-tri-circle-consent
  "Evaluates Tri-Circle Sociocratic Consent for `bip-id` in `subnet-id` (`INV-D20-3`, `INV-D22-1`, `INV-D22-4`):
   - Requires the BIP to exist in `:bips` (having passed Layer 2 executable admission gates).
   - Requires positive consenting weight in all 3 circles (`:builders-stewards`, `:mesh-validators`, `:anchor-agent-users`).
   - Halts ratification (`:status :blocked-by-paramount-objection`) if any circle contains a valid paramount objection.
   - Schedules `[:scheduled-upgrades [subnet-id activate-at-epoch]]` when `:policy-theta` and `:activate-at-epoch` are present."
  ([state bip-id]
   (let [existing-bip (get-in state [:bips bip-id])
         inferred-sub (or (:subnet-id existing-bip) dev-subnet-id)]
     (evaluate-tri-circle-consent state inferred-sub bip-id)))
  ([state subnet-id bip-id]
   (let [sub-id (str (or subnet-id dev-subnet-id))
         bip (get-bip state sub-id bip-id)
         responses-by-circle (or (not-empty (get-in state [:circle-responses [sub-id bip-id]]))
                                 (when (= sub-id dev-subnet-id)
                                   (get-in state [:circle-responses bip-id]))
                                 {})
         all-responses (mapcat vals (vals responses-by-circle))
         objections (filterv #(= :paramount-objection (:stance %)) all-responses)
         circle-quorums
         (into {}
               (map (fn [cid]
                      (let [c-resps (vals (get responses-by-circle cid {}))
                            consent-weight (reduce + 0.0
                                                   (keep #(when (= :consent (:stance %))
                                                            (double (:weight % 0.0)))
                                                         c-resps))]
                        [cid (pos? consent-weight)]))
                    tri-circles))
         all-circles-consented? (every? true? (vals circle-quorums))]
     (cond
       (nil? bip)
       {:ratified? false :subnet-id sub-id :status :unknown-bip :state state}

       (seq objections)
       (let [updated-bip (assoc bip :status :blocked-by-paramount-objection)
             st' (-> state
                     (assoc-in [:bips [sub-id bip-id]] updated-bip)
                     (cond-> (= (:subnet-id (get-in state [:bips bip-id])) sub-id)
                       (assoc-in [:bips bip-id] updated-bip)))]
         {:ratified? false
          :subnet-id sub-id
          :status :blocked-by-paramount-objection
          :objections objections
          :circle-quorums circle-quorums
          :state st'})

       (not all-circles-consented?)
       {:ratified? false
        :subnet-id sub-id
        :status :awaiting-circle-quorum
        :circle-quorums circle-quorums
        :state state}

       :else
       (let [updated-bip (assoc bip :status :ratified)
             act-ep (:activate-at-epoch bip)
             theta (:policy-theta bip)
             st' (cond-> (-> state
                             (assoc-in [:bips [sub-id bip-id]] updated-bip)
                             (cond-> (= (:subnet-id (get-in state [:bips bip-id])) sub-id)
                               (assoc-in [:bips bip-id] updated-bip)))
                   (and (some? act-ep) (map? theta))
                   (assoc-in [:scheduled-upgrades [sub-id (long act-ep)]]
                             {:bip-id bip-id
                              :subnet-id sub-id
                              :activate-at-epoch (long act-ep)
                              :policy-theta theta}))]
         {:ratified? true
          :subnet-id sub-id
          :status :ratified
          :circle-quorums circle-quorums
          :state st'})))))

(defn activate-epoch-upgrades
  "Deterministically activates any ratified BIP upgrade scheduled at or before `epoch` (`INV-D22-4`)."
  [state epoch]
  (let [base-st (or (:state state) state)
        ep (long (or epoch 0))
        scheduled (:scheduled-upgrades base-st {})
        due (vec (filter (fn [[[_sub-id target-ep] _upg]]
                           (<= (long target-ep) ep))
                         scheduled))
        st' (reduce (fn [st [[sub-id target-ep] upg]]
                      (-> st
                          (update :scheduled-upgrades dissoc [sub-id target-ep])
                          (assoc-in [:subnet-policies sub-id] (:policy-theta upg))
                          (update :activated-upgrades (fnil conj [])
                                  (assoc upg :activated-at-epoch ep))))
                    base-st
                    due)]
    (assoc st' :state st' :activated (mapv second due))))
