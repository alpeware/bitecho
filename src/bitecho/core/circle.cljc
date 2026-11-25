(ns bitecho.core.circle
  "Pure Sans-IO Circles on Subnets, Hierarchical Directory, Sociocratic Governance,
   In-Band Validator-Set Descriptors, Cold-Root Recovery, Two-Mode Privacy & Fractal Isolation (BIP-024).

   Strictly adheres to AGENTS.md Rule 2 (Pure Functions / Sans-IO) and Rule 5 (Zero Silent Failures)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.memento.constants :as mem-const]
            [clojure.string :as str]))

;; =============================================================================
;; 1. Canonical 88-Char SPKI DER Ed25519 Pubkey Encoding (Blocker 2, INV-C3)
;; =============================================================================

(def spki-ed25519-prefix
  "X.509 SPKI DER hex prefix for raw 32-byte Ed25519 public keys."
  "302a300506032b6570032100")

(defn normalize-spki-pubkey
  "Canonicalizes an Ed25519 public key (64-char raw hex or 88-char SPKI DER hex,
   in any case, or raw bytes) to lowercase 88-char SPKI DER hex. Returns nil if invalid."
  [pk]
  (let [raw-s (cond
                (string? pk) (str/lower-case (str/trim pk))
                (fressian/bytes? pk) (str/lower-case (basalt/bytes->hex pk))
                :else nil)]
    (when (string? raw-s)
      (cond
        (and (= 88 (count raw-s))
             (str/starts-with? raw-s spki-ed25519-prefix)
             (re-matches #"[0-9a-f]{88}" raw-s))
        raw-s

        (and (= 64 (count raw-s))
             (re-matches #"[0-9a-f]{64}" raw-s))
        (str spki-ed25519-prefix raw-s)

        :else nil))))

(defn valid-spki-pubkey?
  "Returns true iff pk is a canonical lowercase 88-char SPKI DER Ed25519 hex string."
  [pk]
  (and (string? pk)
       (= 88 (count pk))
       (str/starts-with? pk spki-ed25519-prefix)
       (boolean (re-matches #"[0-9a-f]{88}" pk))))

(defn dedup-spki-pubkeys
  "Canonicalizes and deduplicates a collection of Ed25519 pubkeys into a deterministically
   sorted vector of 88-char SPKI DER hex strings, eliminating 64-vs-88 duplicate-signer bypass."
  [pubkeys]
  (->> pubkeys
       (keep normalize-spki-pubkey)
       distinct
       sort
       vec))

(defn pubkey-cid
  "Computes the 64-char lowercase SHA-256 CID of a canonical 88-char SPKI DER pubkey."
  [pk]
  (when-let [spki (normalize-spki-pubkey pk)]
    (str/lower-case (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes spki))))))

(defn- valid-cid-64?
  [s]
  (and (string? s) (boolean (re-matches #"[0-9a-f]{64}" (str/lower-case (str/trim s))))))

(defn- diag-fail
  ([reason]
   (diag-fail reason {}))
  ([reason detail]
   {:ok? false
    :error reason
    :effects [(merge {:effect :diagnose :reason reason} detail)]}))

;; =============================================================================
;; 2. Grow-Only Advisory Twin Registry (Blocker 6, INV-C5)
;; =============================================================================

(defn register-advisory-twin
  "Adds a canonical 88-char SPKI pubkey to the grow-only `:advisory-twin-pubkeys` set.
   Advisory twins can never be removed or flipped to gain real consent/signing authority."
  [twin-set pubkey]
  (if-let [spki (normalize-spki-pubkey pubkey)]
    (conj (set (keep normalize-spki-pubkey twin-set)) spki)
    (set (keep normalize-spki-pubkey twin-set))))

(defn advisory-twin?
  "Returns true if pubkey is registered in the grow-only advisory-twin set."
  [twin-set pubkey]
  (let [spki (normalize-spki-pubkey pubkey)
        norm-set (set (keep normalize-spki-pubkey twin-set))]
    (boolean (and spki (contains? norm-set spki)))))

(defn validate-advisory-twin-registry-transition
  "Enforces that `:advisory-twin-pubkeys` is strictly grow-only (monotonic superset)."
  [prev-set next-set]
  (let [p (set (keep normalize-spki-pubkey prev-set))
        n (set (keep normalize-spki-pubkey next-set))]
    (if (every? #(contains? n %) p)
      {:ok? true :advisory-twin-pubkeys n}
      (diag-fail :advisory-twin-registry-shrunk {:removed (vec (remove n p))}))))

;; =============================================================================
;; 3. Unified `:directory/entity-descriptor` v2 (Blocker 2, 6, INV-C2..C5)
;; =============================================================================

(def valid-entity-kinds
  "Allowed `:entity-kind` values for v2 `:directory/entity-descriptor`."
  #{:circle :sovereign-id :seat-lease})

(def valid-visibilities
  "Allowed `:visibility` modes for v2 `:directory/entity-descriptor`."
  #{:public :shared-encrypted})

(def valid-custody-buckets
  "Allowed `:custody-bucket` provenance tags for Genesis custody allocations."
  #{:bootstrap :team :partners :ecosystem nil})

(def default-human-anchor-sunset-epoch
  "2027-06-30 default human-anchor sunset epoch marker."
  20270630)

(def min-recovery-timelock-epochs
  "Minimum timelock window (168 epochs) for lost-key recovery."
  168)

(defn descriptor-cid
  "Computes the 64-char SHA-256 CID of a canonical Fressian-encoded descriptor."
  [descriptor]
  (str/lower-case (basalt/bytes->hex (crypto/sha256 (fressian/encode-canonical descriptor)))))

(defn descriptor-signing-tuple
  "Domain-separated canonical signing tuple for `:directory/entity-descriptor` v2:
   [\"bitecho-directory-entity-v2\" network-uri network-genesis-cid unsigned-descriptor]."
  [descriptor]
  (let [unsigned (dissoc descriptor :owner-signatures :parent-admission-proof :incoming-pop-signatures)]
    ["bitecho-directory-entity-v2"
     (str (:network-uri descriptor))
     (str/lower-case (str (:network-genesis-cid descriptor)))
     unsigned]))

(defn incoming-pop-signing-tuple
  "Domain-separated signing tuple for incoming-key Proof-of-Possession on creation/rotation."
  [descriptor pubkey]
  ["bitecho-directory-incoming-pop-v2"
   (str (:network-uri descriptor))
   (str/lower-case (str (:network-genesis-cid descriptor)))
   (str (:path descriptor))
   (long (or (:version descriptor) 1))
   (normalize-spki-pubkey pubkey)])

(defn- normalize-owner-multisig
  [ms]
  (when (map? ms)
    (let [pks (dedup-spki-pubkeys (:pubkeys ms))
          th (long (or (:threshold ms) 0))]
      {:threshold th :pubkeys pks})))

(defn create-entity-descriptor
  "Constructs and signs a canonical v2 `:directory/entity-descriptor` using `:purpose-cid`
   (Simon's ratified sociocratic amendment; `:values-cid` is rejected).
   `signers` is a vector of `{:pubkey <hex> :privkey <bytes>}` maps.
   Optionally accepts `opts` with `:parent-signers` and `:incoming-signers`."
  ([fields signers]
   (create-entity-descriptor fields signers nil))
  ([fields signers opts]
   (let [net-uri (str/trim (str (:network-uri fields)))
         gen-cid (str/lower-case (str/trim (str (:network-genesis-cid fields))))
         path (str/replace (str/trim (str (:path fields))) #"^/+|/+$" "")
         uri (or (:uri fields) (str net-uri "/" path))
         owner-ms (normalize-owner-multisig (:owner-multisig fields))
         norm-members (into (sorted-map)
                            (keep (fn [[k v]]
                                    (when-let [spki (normalize-spki-pubkey k)]
                                      [spki v]))
                                  (or (:members fields) {})))
         base (cond-> {:bitecho/type :directory/entity-descriptor
                       :schema-version 2
                       :network-uri net-uri
                       :network-genesis-cid gen-cid
                       :entity-kind (or (:entity-kind fields) :circle)
                       :visibility (or (:visibility fields) :public)
                       :path path
                       :uri uri
                       :subnet-id (or (:subnet-id fields) uri)
                       :parent-path (:parent-path fields)
                       :lease-holder-uri (:lease-holder-uri fields)
                       :version (long (or (:version fields) 1))
                       :prev-descriptor-cid (:prev-descriptor-cid fields)
                       :owner-multisig owner-ms
                       :members norm-members
                       :purpose-cid (:purpose-cid fields)
                       :consent-round-cid (:consent-round-cid fields)
                       :vault-id (:vault-id fields)
                       :custody-bucket (:custody-bucket fields)
                       :allocation-ech (long (or (:allocation-ech fields) 0))
                       :policy (merge {:human-anchor nil
                                       :human-anchor-sunset-epoch default-human-anchor-sunset-epoch
                                       :delegated-path-prefix (str path "/")
                                       :allow-child-delegation? true
                                       :recovery-policy {:guardians [] :threshold 0 :timelock-epochs min-recovery-timelock-epochs}}
                                      (:policy fields))
                       :retention-policy (:retention-policy fields)
                       :storage-accounting (:storage-accounting fields)
                       :issued-epoch (long (or (:issued-epoch fields) 0))
                       :expires-epoch (long (or (:expires-epoch fields) 0))}
                (:canonical-circle fields) (assoc :canonical-circle (:canonical-circle fields))
                (:home-set fields) (assoc :home-set (:home-set fields)))
         tuple (descriptor-signing-tuple base)
         owner-sigs (into (sorted-map)
                          (keep (fn [{:keys [pubkey privkey]}]
                                  (when-let [spki (normalize-spki-pubkey pubkey)]
                                    [spki (str/lower-case (basalt/bytes->hex (crypto/sign-canonical privkey tuple)))])))
                          signers)
         pop-signers (or (:incoming-signers opts) signers)
         pop-sigs (into (sorted-map)
                        (keep (fn [{:keys [pubkey privkey]}]
                                (when-let [spki (normalize-spki-pubkey pubkey)]
                                  (let [pt (incoming-pop-signing-tuple base spki)]
                                    [spki (str/lower-case (basalt/bytes->hex (crypto/sign-canonical privkey pt)))]))))
                        pop-signers)
         parent-sigs (when (seq (:parent-signers opts))
                       {:proof/type :directory-entity
                        :signatures (into (sorted-map)
                                          (keep (fn [{:keys [pubkey privkey]}]
                                                  (when-let [spki (normalize-spki-pubkey pubkey)]
                                                    [spki (str/lower-case (basalt/bytes->hex (crypto/sign-canonical privkey tuple)))])))
                                          (:parent-signers opts))})]
     (cond-> (assoc base
                    :owner-signatures owner-sigs
                    :incoming-pop-signatures pop-sigs)
       parent-sigs (assoc :parent-admission-proof parent-sigs)))))

(defn- count-valid-multisig-signatures
  [sigs allowed-pubkeys tuple twin-set]
  (let [allowed-set (set (dedup-spki-pubkeys allowed-pubkeys))
        valid (keep (fn [[pk sig]]
                      (let [spki (normalize-spki-pubkey pk)]
                        (when (and spki
                                   (contains? allowed-set spki)
                                   (not (advisory-twin? twin-set spki))
                                   (string? sig)
                                   (crypto/verify-with-fallback spki tuple sig))
                          spki)))
                    (or sigs {}))]
    (count (distinct valid))))

(defn- valid-hierarchy-and-containment?
  [desc]
  (let [kind (:entity-kind desc)
        path (str (:path desc))
        parent (:parent-path desc)
        canonical (:canonical-circle desc)]
    (cond
      ;; Reject legacy "global" flat descriptors on hierarchical paths
      (or (= "global" (:network-uri desc))
          (= "global" path)
          (str/starts-with? path "global/"))
      {:ok? false :error :global-flat-descriptor-forbidden}

      ;; INV-C4: root/protocol MUST NEVER be reparented under root/inc
      (or (and (= :protocol canonical) (not= "root/protocol" path))
          (= "root/inc/protocol" path)
          (and (= "root/inc" parent) (str/ends-with? path "/protocol")))
      {:ok? false :error :protocol-subordination-forbidden}

      ;; Sovereign individual root <net>/id/<pubkey-cid>
      (= :sovereign-id kind)
      (let [pks (get-in desc [:owner-multisig :pubkeys])
            th (get-in desc [:owner-multisig :threshold])
            expected-path (when (= 1 (count pks)) (str "id/" (pubkey-cid (first pks))))]
        (cond
          (some? parent) {:ok? false :error :sovereign-id-must-have-nil-parent}
          (not= 1 th) {:ok? false :error :sovereign-id-must-be-1-of-1}
          (not= path expected-path) {:ok? false :error :sovereign-id-path-mismatch}
          :else {:ok? true}))

      ;; Org seat lease must point to sovereign lease-holder-uri and sit under parent
      (= :seat-lease kind)
      (let [holder (:lease-holder-uri desc)]
        (cond
          (or (not (string? parent)) (str/blank? parent))
          {:ok? false :error :seat-lease-requires-parent}

          (not (str/starts-with? path (str parent "/")))
          {:ok? false :error :path-prefix-containment-violated}

          (not (and (string? holder) (str/includes? holder "/id/")))
          {:ok? false :error :seat-lease-requires-sovereign-holder}

          :else {:ok? true}))

      ;; Circle: "root" has nil parent; child circles must be contained under parent-path/
      (= :circle kind)
      (cond
        (= "root" path)
        (if (nil? parent)
          {:ok? true}
          {:ok? false :error :root-must-have-nil-parent})

        (str/starts-with? path "commons/")
        (if (nil? parent)
          {:ok? true}
          {:ok? false :error :commons-must-have-nil-parent})

        (or (not (string? parent)) (str/blank? parent))
        {:ok? false :error :missing-parent-path}

        (= path parent)
        {:ok? false :error :cyclic-parent-path}

        (not (str/starts-with? path (str parent "/")))
        {:ok? false :error :path-prefix-containment-violated}

        :else {:ok? true})

      :else
      {:ok? false :error :invalid-entity-kind})))

(defn verify-entity-descriptor
  "Purely verifies a v2 `:directory/entity-descriptor` against `ctx`:
   - `:network-uri`, `:network-genesis-cid` (strict cross-network isolation, INV-C3)
   - `:purpose-cid` present and `:values-cid` absent
   - BIP-016 discipline (`validate-pointer-discipline`, mandatory `:storage-accounting`)
   - Sovereign root / org seat lease / path-prefix containment / non-subordination (INV-C4)
   - Monotonic version + prev-descriptor-cid + prior-owner quorum + incoming-key PoP (INV-C2)
   - Grow-only advisory-twin exclusion (INV-C5)
   Returns `{:ok? true :cid <cid>}` or `{:ok? false :error <kw> :effects [diagnose]}`."
  ([desc]
   (verify-entity-descriptor desc {}))
  ([desc ctx]
   (let [twin-set (or (:advisory-twin-pubkeys ctx) #{})
         prev (:prev-descriptor ctx)
         owner-ms (:owner-multisig desc)
         pks (dedup-spki-pubkeys (:pubkeys owner-ms))
         th (long (or (:threshold owner-ms) 0))
         disc (mem-const/validate-pointer-discipline desc)
         hier (valid-hierarchy-and-containment? desc)
         tuple (descriptor-signing-tuple desc)
         expected-net (:network-uri ctx)
         expected-gen (:network-genesis-cid ctx)
         signing-ms (if prev (:owner-multisig prev) owner-ms)
         signing-pks (dedup-spki-pubkeys (:pubkeys signing-ms))
         signing-th (long (or (:threshold signing-ms) 1))
         valid-sig-count (count-valid-multisig-signatures (:owner-signatures desc) signing-pks tuple twin-set)
         prev-pks-set (if prev (set (dedup-spki-pubkeys (get-in prev [:owner-multisig :pubkeys]))) #{})
         newly-added-pks (if prev (vec (remove prev-pks-set pks)) [])
         pop-sigs (or (:incoming-pop-signatures desc) {})
         all-pops-valid? (every? (fn [pk]
                                   (let [sig (get pop-sigs pk)
                                         pt (incoming-pop-signing-tuple desc pk)]
                                     (and (string? sig) (crypto/verify-with-fallback pk pt sig))))
                                 newly-added-pks)
         has-twin-owner? (some #(advisory-twin? twin-set %) pks)]
     (cond
       (not (map? desc))
       (diag-fail :malformed-entity-descriptor)

       (not= :directory/entity-descriptor (:bitecho/type desc))
       (diag-fail :invalid-descriptor-type)

       (contains? desc :values-cid)
       (diag-fail :deprecated-values-cid-forbidden)

       (not (valid-cid-64? (:purpose-cid desc)))
       (diag-fail :missing-or-invalid-purpose-cid)

       ;; F9: Constitutional entity descriptors and rotations MUST carry a valid 64-char hex :consent-round-cid
       (and (or (contains? #{"root" "root/protocol" "root/inc"} (:path desc))
                (> (long (or (:version desc) 1)) 1)
                (some? (:consent-round-cid desc)))
            (not (valid-cid-64? (:consent-round-cid desc))))
       (diag-fail :missing-or-invalid-consent-round-cid)

       (not (contains? valid-entity-kinds (:entity-kind desc)))
       (diag-fail :invalid-entity-kind)

       (not (contains? valid-visibilities (:visibility desc)))
       (diag-fail :invalid-visibility)

       (and (= :shared-encrypted (:visibility desc))
            (contains? #{"root" "root/protocol" "root/inc"} (:path desc)))
       (diag-fail :constitutional-root-must-be-public)

       (not (valid-cid-64? (:network-genesis-cid desc)))
       (diag-fail :missing-network-genesis-cid)

       (and expected-net (not= (str expected-net) (str (:network-uri desc))))
       (diag-fail :network-uri-mismatch {:expected expected-net :actual (:network-uri desc)})

       (and expected-gen (not= (str/lower-case (str expected-gen))
                               (str/lower-case (str (:network-genesis-cid desc)))))
       (diag-fail :network-genesis-cid-mismatch)

       (not (contains? valid-custody-buckets (:custody-bucket desc)))
       (diag-fail :invalid-custody-bucket)

       (not (:ok? disc))
       (diag-fail (:code disc) (:detail disc))

       (not (:ok? hier))
       (diag-fail (:error hier))

       (or (empty? pks) (< th 1) (> th (count pks)))
       (diag-fail :invalid-owner-multisig)

       has-twin-owner?
       (diag-fail :advisory-twin-cannot-own-entity)

       (and prev (not= (long (:version desc)) (inc (long (:version prev)))))
       (diag-fail :non-monotonic-descriptor-version)

       (and prev (not= (str/lower-case (str (:prev-descriptor-cid desc)))
                       (descriptor-cid prev)))
       (diag-fail :prev-descriptor-cid-mismatch)

       (< valid-sig-count signing-th)
       (diag-fail :insufficient-owner-signatures {:valid valid-sig-count :required signing-th})

       (not all-pops-valid?)
       (diag-fail :missing-or-invalid-incoming-pop)

       :else
       {:ok? true :cid (descriptor-cid desc)}))))

;; =============================================================================
;; 4. Sovereignty, Seat Leases, Sociocratic Consent, Dissolve & Recovery (Blocker 6)
;; =============================================================================

(defn can-org-revoke-entity?
  "Enforces INV-C4: an organization can revoke a child `:seat-lease` under its delegated
   path prefix, NEVER a sovereign `<net>/id/<pubkey-cid>` or `<net>/commons/<handle>` root."
  [org-desc target-desc]
  (let [org-path (str (:path org-desc))
        target-path (str (:path target-desc))
        target-kind (:entity-kind target-desc)]
    (cond
      (= :sovereign-id target-kind)
      (diag-fail :sovereign-root-non-revocable {:target target-path})

      (str/starts-with? target-path "commons/")
      (diag-fail :commons-handle-non-revocable {:target target-path})

      (and (= :seat-lease target-kind)
           (str/starts-with? target-path (str org-path "/")))
      {:ok? true}

      :else
      (diag-fail :unauthorized-org-revocation {:org org-path :target target-path}))))

(defn human-anchor-active?
  "Returns true iff `:human-anchor` is configured AND `current-epoch < sunset-epoch`
   (default `2027-06-30`). After sunset, pure sociocratic double-linked consent applies
   with zero founder veto."
  [descriptor current-epoch]
  (let [anchor (get-in descriptor [:policy :human-anchor])
        sunset (long (or (get-in descriptor [:policy :human-anchor-sunset-epoch])
                         default-human-anchor-sunset-epoch))]
    (boolean (and (some? anchor) (< (long current-epoch) sunset)))))

(defn consent-ballot-signing-tuple
  "Domain-separated canonical signing tuple for a sociocratic consent ballot (BIP-026 §1.5 P5.1, B7)."
  [proposal-cid voter-pubkey vote]
  ["bitecho-consent-ballot-v1"
   (str proposal-cid)
   (or (normalize-spki-pubkey voter-pubkey) (str voter-pubkey))
   (if (keyword? vote) (name vote) (str vote))])

(defn sign-consent-ballot
  "Signs a sociocratic consent ballot `{:vote vote :signature sig-hex}` for `proposal-cid`."
  [privkey voter-pubkey proposal-cid vote]
  (let [spki (normalize-spki-pubkey voter-pubkey)
        tuple (consent-ballot-signing-tuple proposal-cid spki vote)
        sig (str/lower-case (basalt/bytes->hex (crypto/sign-canonical privkey tuple)))]
    {:vote vote :signature sig}))

(defn verify-consent-round
  "Verifies a constitutional sociocratic consent round (§2.6.1, BIP-026 §1.5 P5.1):
   1. Zero unresolved `:paramount-objection` ballots.
   2. Double-linking: lead-link (and delegate-link when specified) both consented.
   3. Cryptographic Ed25519 signature verification on all voter ballots (`B7`).
   4. Quorum participation strictly across non-twin human/org seats.
   5. Advisory twins barred from consenting or holding link seats."
  [round ctx]
  (let [twin-set (or (:advisory-twin-pubkeys ctx) #{})
        proposal-cid (:proposal-cid round)
        lead (normalize-spki-pubkey (:lead-link-pubkey round))
        delegate (when (:delegate-link-pubkey round) (normalize-spki-pubkey (:delegate-link-pubkey round)))
        ballots (into {}
                      (keep (fn [[pk v]]
                              (when-let [spki (normalize-spki-pubkey pk)]
                                [spki v]))
                            (or (:ballots round) {})))
        vote-of (fn [v] (if (map? v) (:vote v) v))
        sig-of (fn [v] (when (map? v) (:signature v)))
        quorum (long (or (:quorum-size round) 1))
        has-twin-voter? (or (and lead (advisory-twin? twin-set lead))
                            (and delegate (advisory-twin? twin-set delegate))
                            (some #(advisory-twin? twin-set %) (keys ballots)))
        has-paramount? (some #(= :paramount-objection (vote-of %)) (vals ballots))
        invalid-ballot-sig? (or (empty? ballots)
                                (not (string? proposal-cid))
                                (str/blank? proposal-cid)
                                (some (fn [[pk v]]
                                        (let [vote (vote-of v)
                                              sig (sig-of v)
                                              tuple (consent-ballot-signing-tuple proposal-cid pk vote)]
                                          (not (and (string? sig)
                                                    (not (str/blank? sig))
                                                    (crypto/verify-with-fallback pk tuple sig)))))
                                      ballots))
        non-twin-consents (count (filter (fn [[pk v]]
                                           (and (= :consent (vote-of v)) (not (advisory-twin? twin-set pk))))
                                         ballots))]
    (cond
      has-twin-voter?
      (diag-fail :advisory-twin-cannot-consent)

      has-paramount?
      (diag-fail :paramount-objection-present)

      invalid-ballot-sig?
      (diag-fail :invalid-ballot-signature)

      (or (nil? lead) (not= :consent (vote-of (get ballots lead))))
      (diag-fail :missing-lead-link-consent)

      (and delegate (not= :consent (vote-of (get ballots delegate))))
      (diag-fail :missing-delegate-link-consent)

      (< non-twin-consents quorum)
      (diag-fail :insufficient-consent-quorum {:consents non-twin-consents :required quorum})

      :else
      {:ok? true :consent-count non-twin-consents})))

(defn dissolve-circle
  "Pure `:dissolve-circle` lifecycle reducer (§2.6.1, BIP-026 §1.5 P5.1, B7):
   Tombstones the circle's org path, revokes child seat leases, and atomically returns
   remaining vault principal to an active parent/Root vault with strict custody-bucket
   equality (`(= (:custody-bucket p-vault) (:custody-bucket c-vault))`) and 0 take."
  [state {:keys [circle-path parent-vault-id consent-round]} ctx]
  (let [c-res (verify-consent-round consent-round ctx)
        circle-desc (get-in state [:entity-descriptors circle-path])
        c-vault-id (:vault-id circle-desc)
        c-vault (when c-vault-id (get-in state [:vaults c-vault-id]))
        p-vault (when parent-vault-id (get-in state [:vaults parent-vault-id]))
        has-principal? (and c-vault (pos? (long (or (:balance c-vault) 0))))]
    (cond
      (nil? circle-desc) (diag-fail :circle-not-found {:path circle-path})
      (= :sovereign-id (:entity-kind circle-desc)) (diag-fail :sovereign-root-cannot-be-dissolved)
      (and has-principal? (nil? p-vault)) (diag-fail :missing-parent-vault-for-dissolution)
      (and has-principal? (not= :active (:status p-vault)))
      (diag-fail :parent-vault-not-active {:parent-vault-id parent-vault-id :status (:status p-vault)})
      (and has-principal? (not= (:custody-bucket p-vault) (:custody-bucket c-vault)))
      (diag-fail :custody-bucket-mismatch {:child-bucket (:custody-bucket c-vault)
                                           :parent-bucket (:custody-bucket p-vault)})
      (not (:ok? c-res)) c-res
      :else
      (let [principal (long (or (:balance c-vault) 0))
            revoked-leases (into []
                                 (keep (fn [[p d]]
                                         (when (and (= :seat-lease (:entity-kind d))
                                                    (str/starts-with? (str p) (str circle-path "/")))
                                           p)))
                                 (:entity-descriptors state))
            st1 (reduce (fn [s lp] (assoc-in s [:entity-descriptors lp :status] :revoked))
                        state
                        revoked-leases)
            st2 (assoc-in st1 [:entity-descriptors circle-path :status] :dissolved)
            st3 (if has-principal?
                  (-> st2
                      (assoc-in [:vaults c-vault-id :balance] 0)
                      (assoc-in [:vaults c-vault-id :status] :dissolved)
                      (update-in [:vaults parent-vault-id :balance] (fnil + 0) principal))
                  st2)]
        {:ok? true
         :state st3
         :returned-principal principal
         :revoked-leases revoked-leases
         :effects []}))))

(defn initiate-recovery
  "Initiates timelocked lost-key recovery (`timelock-epochs >= 168`) with guardian quorum."
  [descriptor {:keys [new-owner-multisig guardian-signatures current-epoch]}]
  (let [rp (get-in descriptor [:policy :recovery-policy])
        guardians (dedup-spki-pubkeys (:guardians rp))
        th (long (or (:threshold rp) 0))
        tl (long (or (:timelock-epochs rp) 0))
        tuple ["bitecho-recovery-v1" (:uri descriptor) (normalize-owner-multisig new-owner-multisig) (long current-epoch)]
        valid-g (count-valid-multisig-signatures guardian-signatures guardians tuple #{})]
    (cond
      (or (empty? guardians) (< th 1))
      (diag-fail :recovery-policy-not-configured)

      (< tl min-recovery-timelock-epochs)
      (diag-fail :recovery-timelock-too-short {:timelock tl :min min-recovery-timelock-epochs})

      (< valid-g th)
      (diag-fail :insufficient-guardian-signatures {:valid valid-g :required th})

      :else
      {:ok? true
       :pending-recovery {:new-owner-multisig (normalize-owner-multisig new-owner-multisig)
                          :initiated-epoch (long current-epoch)
                          :executable-epoch (+ (long current-epoch) tl)
                          :status :pending}})))

(defn cancel-recovery-signing-tuple
  "Domain-separated canonical signing tuple for authenticating `cancel-recovery` (F15)."
  [descriptor pending-recovery]
  ["bitecho-cancel-recovery-v1"
   (str (:uri descriptor))
   (long (or (:initiated-epoch pending-recovery) 0))])

(defn cancel-recovery
  "Authenticates and cancels a pending timelocked recovery (F15).
   Requires `>= threshold` valid signatures from the active `:owner-multisig` (excluding
   advisory twins) over `cancel-recovery-signing-tuple`. Fails closed with `:unauthorized-recovery-cancel`."
  [descriptor pending-recovery {:keys [owner-signatures advisory-twin-pubkeys]}]
  (let [owner-ms (:owner-multisig descriptor)
        owners (dedup-spki-pubkeys (:pubkeys owner-ms))
        th (long (or (:threshold owner-ms) 1))
        twin-set (or advisory-twin-pubkeys #{})
        tuple (cancel-recovery-signing-tuple descriptor pending-recovery)
        valid-sigs (count-valid-multisig-signatures owner-signatures owners tuple twin-set)]
    (cond
      (not= :pending (:status pending-recovery))
      (diag-fail :recovery-not-pending)

      (or (empty? owners) (< valid-sigs th))
      (diag-fail :unauthorized-recovery-cancel {:valid valid-sigs :required th})

      :else
      {:ok? true
       :pending-recovery (assoc pending-recovery :status :cancelled)
       :effects []})))

(defn execute-recovery
  "Executes a pending recovery once `current-epoch >= executable-epoch` and not cancelled."
  [descriptor pending-recovery current-epoch]
  (cond
    (not= :pending (:status pending-recovery))
    (diag-fail :recovery-not-pending)

    (< (long current-epoch) (long (:executable-epoch pending-recovery)))
    (diag-fail :recovery-timelock-active {:current-epoch current-epoch
                                          :executable-epoch (:executable-epoch pending-recovery)})

    :else
    {:ok? true
     :descriptor (assoc descriptor :owner-multisig (:new-owner-multisig pending-recovery))}))

;; =============================================================================
;; 5. Two-Mode Privacy: `:shared-encrypted` AEAD + Blinded Subpath (Blocker 6, INV-C5)
;; =============================================================================

(defn blinded-subpath
  "Derives a blinded directory subpath `dir/<parent-path>/enc/<hmac-subpath>`."
  [parent-path subpath group-key-bytes]
  (let [tag-bytes (crypto/sha256 (fressian/encode-canonical ["bitecho-blinded-subpath-v1"
                                                             (str parent-path)
                                                             (str subpath)
                                                             (basalt/bytes->hex group-key-bytes)]))
        tag-hex (subs (str/lower-case (basalt/bytes->hex tag-bytes)) 0 32)]
    (str "dir/" parent-path "/enc/" tag-hex)))

(def blinded-envelope-path-pattern
  "Strict regex for blinded `:directory/encrypted-entity-envelope` paths (BIP-026 §1.5 P5.2, B7)."
  #"^dir/.+/enc/[0-9a-f]{32}$")

(defn encrypted-envelope-signing-tuple
  "Domain-separated canonical signing tuple for outer `:owner-signatures` on `:directory/encrypted-entity-envelope`."
  [envelope]
  ["bitecho-encrypted-entity-v1"
   (str (:network-uri envelope))
   (str/lower-case (str (:network-genesis-cid envelope)))
   (str (:blinded-path envelope))
   (str/lower-case (str (:ciphertext-hex envelope)))
   (str/lower-case (str (:nonce-hex envelope)))])

(defn encrypt-shared-descriptor
  "Encrypts sensitive payload fields (`:members`, `:home-set`, `:allocation-ech`, `:purpose-cid`,
   `:policy`) of a `:shared-encrypted` descriptor with AEAD (`crypto/secretbox`) using a fresh
   CSPRNG 24-byte nonce (`F14`, never deterministic nonce reuse), omits plaintext `:payer-pubkey`
   from `:storage-accounting`, and optionally attaches verifiable outer `:owner-signatures`
   via `(:owner-signers opts)` or `(:signers opts)` (BIP-026 §1.5 P5.2, B7)."
  ([descriptor group-key-bytes]
   (encrypt-shared-descriptor descriptor group-key-bytes nil))
  ([descriptor group-key-bytes opts]
   (let [sensitive (select-keys descriptor [:members :home-set :allocation-ech :purpose-cid :policy :lease-holder-uri])
         plaintext (fressian/encode-canonical sensitive)
         nonce-24 (or (:nonce-bytes opts) (crypto/random-bytes 24))
         ciphertext (crypto/secretbox group-key-bytes nonce-24 plaintext)
         norm-ms (normalize-owner-multisig (:owner-multisig descriptor))
         owner-commitment (str/lower-case (basalt/bytes->hex (crypto/sha256 (fressian/encode-canonical (or norm-ms (:owner-multisig descriptor))))))
         clean-storage (when-let [sa (:storage-accounting descriptor)]
                         (dissoc sa :payer-pubkey))
         b-path (or (:blinded-path opts)
                    (blinded-subpath (or (:parent-path descriptor) "root") (:path descriptor) group-key-bytes))
         base (cond-> {:bitecho/type :directory/encrypted-entity-envelope
                       :schema-version 2
                       :visibility :shared-encrypted
                       :network-uri (:network-uri descriptor)
                       :network-genesis-cid (:network-genesis-cid descriptor)
                       :blinded-path b-path
                       :version (:version descriptor)
                       :prev-descriptor-cid (:prev-descriptor-cid descriptor)
                       :owner-multisig-commitment owner-commitment
                       :retention-policy (:retention-policy descriptor)
                       :storage-accounting clean-storage
                       :nonce-hex (str/lower-case (basalt/bytes->hex nonce-24))
                       :ciphertext-hex (str/lower-case (basalt/bytes->hex ciphertext))}
                norm-ms (assoc :owner-multisig norm-ms))
         signers (or (:owner-signers opts) (:signers opts))
         tuple (encrypted-envelope-signing-tuple base)
         owner-sigs (cond
                      (seq signers)
                      (into (sorted-map)
                            (keep (fn [{:keys [pubkey privkey]}]
                                    (when-let [spki (normalize-spki-pubkey pubkey)]
                                      [spki (str/lower-case (basalt/bytes->hex (crypto/sign-canonical privkey tuple)))])))
                            signers)

                      (map? (:owner-signatures opts))
                      (:owner-signatures opts)

                      :else nil)]
     (cond-> base
       (seq owner-sigs) (assoc :owner-signatures owner-sigs)))))

(defn verify-encrypted-entity-envelope
  "Verifies a `:directory/encrypted-entity-envelope` for validator admission (BIP-026 §1.5 P5.2, B7):
   1. `:blinded-path` strictly matches `^dir/.+/enc/[0-9a-f]{32}$`.
   2. `:network-uri`, `:network-genesis-cid`, `:ciphertext-hex`, and `:nonce-hex` are valid.
   3. `:storage-accounting` does not leak plaintext `:payer-pubkey`.
   4. Outer `:owner-signatures` satisfy the owning entity's `:owner-multisig` quorum
      (excluding `:advisory-twin-pubkeys`)."
  [envelope ctx]
  (let [b-path (:blinded-path envelope)
        exp-net (:network-uri ctx)
        exp-gen (:network-genesis-cid ctx)
        prev-desc (:prev-descriptor ctx)
        twin-set (or (:advisory-twin-pubkeys ctx) #{})
        ms (or (:owner-multisig prev-desc)
               (:owner-multisig ctx)
               (let [env-ms (normalize-owner-multisig (:owner-multisig envelope))
                     env-comm (when env-ms
                                (str/lower-case (basalt/bytes->hex (crypto/sha256 (fressian/encode-canonical env-ms)))))]
                 (when (and env-ms (= env-comm (:owner-multisig-commitment envelope)))
                   env-ms)))
        owners (when (map? ms) (dedup-spki-pubkeys (:pubkeys ms)))
        th (when (map? ms) (long (or (:threshold ms) 0)))
        tuple (encrypted-envelope-signing-tuple envelope)
        valid-sigs (if (and (seq owners) (pos? (long (or th 0))))
                     (count-valid-multisig-signatures (:owner-signatures envelope) owners tuple twin-set)
                     0)]
    (cond
      (not= :directory/encrypted-entity-envelope (:bitecho/type envelope))
      (diag-fail :invalid-encrypted-envelope-type)

      (not (and (string? b-path) (boolean (re-matches blinded-envelope-path-pattern b-path))))
      (diag-fail :invalid-blinded-envelope-path {:blinded-path b-path})

      (and exp-net (not= (str exp-net) (str (:network-uri envelope))))
      (diag-fail :network-uri-mismatch)

      (and exp-gen (not= (str/lower-case (str exp-gen)) (str/lower-case (str (:network-genesis-cid envelope)))))
      (diag-fail :network-genesis-cid-mismatch)

      (not (and (string? (:nonce-hex envelope)) (re-matches #"[0-9a-f]{48}" (str/lower-case (:nonce-hex envelope)))))
      (diag-fail :invalid-envelope-nonce)

      (not (and (string? (:ciphertext-hex envelope)) (pos? (count (:ciphertext-hex envelope)))
                (re-matches #"[0-9a-f]+" (str/lower-case (:ciphertext-hex envelope)))))
      (diag-fail :invalid-envelope-ciphertext)

      (contains? (or (:storage-accounting envelope) {}) :payer-pubkey)
      (diag-fail :encrypted-envelope-payer-pubkey-leak)

      (or (empty? owners) (< (long (or th 0)) 1) (< valid-sigs (long th)))
      (diag-fail :insufficient-encrypted-envelope-signatures {:valid valid-sigs :required (or th 1)})

      :else
      {:ok? true :cid (descriptor-cid envelope) :blinded-path b-path})))

(defn decrypt-shared-descriptor
  "Decrypts a `:directory/encrypted-entity-envelope` using `group-key-bytes`."
  [envelope group-key-bytes]
  (try
    (let [nonce-24 (basalt/hex->bytes (:nonce-hex envelope))
          ct (basalt/hex->bytes (:ciphertext-hex envelope))
          pt (crypto/secretbox-open group-key-bytes nonce-24 ct)]
      (if-not pt
        (diag-fail :shared-descriptor-decryption-failed)
        {:ok? true
         :descriptor (merge (select-keys envelope [:network-uri :network-genesis-cid :version
                                                   :prev-descriptor-cid :retention-policy
                                                   :storage-accounting :visibility])
                            (fressian/decode-wire pt))}))
    (catch #?(:clj Throwable :cljs :default) _
      (diag-fail :shared-descriptor-decryption-failed))))

;; =============================================================================
;; 6. In-Band `:root/validator-set-descriptor` & Cold-Root Recovery (Blocker 4)
;; =============================================================================

(defn validator-set-signing-tuple
  "Returns the domain-separated canonical signing tuple for `:root/validator-set-descriptor` v2."
  [desc]
  ["bitecho-validator-set-v2"
   (str (:network-uri desc))
   (str/lower-case (str (:network-genesis-cid desc)))
   (dissoc desc :root-signatures)])

(defn create-validator-set-descriptor
  "Creates and Root-signs a `:root/validator-set-descriptor` v2."
  [fields root-signers]
  (let [norm-comm (mapv (fn [entry]
                          (if (map? entry)
                            (assoc entry :pubkey (normalize-spki-pubkey (:pubkey entry)))
                            {:pubkey (normalize-spki-pubkey entry) :role :core-validator}))
                        (:committee fields))
        base (cond-> {:bitecho/type :root/validator-set-descriptor
                      :schema-version 2
                      :network-uri (str/trim (str (:network-uri fields)))
                      :network-genesis-cid (str/lower-case (str/trim (str (:network-genesis-cid fields))))
                      :version (long (or (:version fields) 1))
                      :prev-descriptor-cid (:prev-descriptor-cid fields)
                      :not-before-epoch (long (or (:not-before-epoch fields) 0))
                      :epoch-finalized (long (or (:epoch-finalized fields) 0))
                      :epoch-effective (long (or (:epoch-effective fields) 0))
                      :quorum-threshold (long (or (:quorum-threshold fields) 1))
                      :delegated-operator-circle (:delegated-operator-circle fields)
                      :consent-round-cid (:consent-round-cid fields)
                      :committee norm-comm
                      :policy-refs (or (:policy-refs fields) {:theta-version "v2.1" :validator-activation-lead-epochs 6})
                      :retention-policy (:retention-policy fields)
                      :storage-accounting (:storage-accounting fields)}
               (:equivocation-proof fields) (assoc :equivocation-proof (:equivocation-proof fields)))
        tuple (validator-set-signing-tuple base)
        sigs (into (sorted-map)
                   (keep (fn [{:keys [pubkey privkey]}]
                           (when-let [spki (normalize-spki-pubkey pubkey)]
                             [spki (str/lower-case (basalt/bytes->hex (crypto/sign-canonical privkey tuple)))])))
                   root-signers)]
    (assoc base :root-signatures sigs)))

(defn verify-equivocation-proof?
  "Verifies a fast-ejection equivocation proof: two distinct conflicting signed votes/proposals
   by the same validator pubkey in the same epoch."
  [proof]
  (let [pk (normalize-spki-pubkey (:validator-pubkey proof))
        ep (:epoch proof)
        m1 (:message-1 proof)
        s1 (:sig-1 proof)
        m2 (:message-2 proof)
        s2 (:sig-2 proof)]
    (boolean
     (and pk
          (integer? ep)
          (some? m1) (some? m2) (not= m1 m2)
          (string? s1) (string? s2)
          (crypto/verify-with-fallback pk m1 s1)
          (crypto/verify-with-fallback pk m2 s2)))))

(def min-validator-activation-lead-epochs
  "Minimum activation lead time in epochs for normal scheduled validator-set rotations
   to preserve Streamlet 3-chain finality (BIP-026 §1.2 P2.2, B4)."
  3)

(defn verify-validator-set-descriptor
  "Verifies a `:root/validator-set-descriptor` v2:
   - Network URI & genesis CID match
   - BIP-016 discipline (`:retention-policy` + `:storage-accounting`)
   - Root Association multisig quorum (excluding advisory twins)
   - Activation lead time (`(- epoch-effective epoch-finalized) >= (max 3 configured-lead-epochs)`,
     `epoch-effective >= not-before-epoch`) OR fast equivocation ejection
     (`epoch-effective >= epoch-finalized + 1`, remaining >= 4) (BIP-026 §1.2 P2.2, B4)."
  [desc ctx]
  (let [root-ms (:root-owner-multisig ctx)
        root-pks (dedup-spki-pubkeys (:pubkeys root-ms))
        root-th (long (or (:threshold root-ms) 1))
        twin-set (or (:advisory-twin-pubkeys ctx) #{})
        configured-lead (long (or (:lead-epochs ctx) 6))
        effective-lead (max min-validator-activation-lead-epochs configured-lead)
        comm-pks (dedup-spki-pubkeys (map :pubkey (:committee desc)))
        ep-fin (long (or (:epoch-finalized desc) 0))
        ep-nb (long (or (:not-before-epoch desc) 0))
        ep-eff (long (or (:epoch-effective desc) 0))
        equiv-ok? (and (some? (:equivocation-proof desc))
                       (verify-equivocation-proof? (:equivocation-proof desc)))
        min-eff (if equiv-ok?
                  (inc ep-fin)
                  (max ep-nb (+ ep-fin effective-lead)))
        tuple (validator-set-signing-tuple desc)
        valid-sigs (count-valid-multisig-signatures (:root-signatures desc) root-pks tuple twin-set)
        disc (mem-const/validate-pointer-discipline (assoc desc :owner-multisig root-ms))]
    (cond
      (not= :root/validator-set-descriptor (:bitecho/type desc))
      (diag-fail :invalid-validator-descriptor-type)

      ;; F9: Validator-set rotation is a constitutional act requiring valid 64-char hex :consent-round-cid
      (not (valid-cid-64? (:consent-round-cid desc)))
      (diag-fail :missing-or-invalid-consent-round-cid)

      (and (:network-uri ctx) (not= (str (:network-uri ctx)) (str (:network-uri desc))))
      (diag-fail :network-uri-mismatch)

      (and (:network-genesis-cid ctx)
           (not= (str/lower-case (str (:network-genesis-cid ctx)))
                 (str/lower-case (str (:network-genesis-cid desc)))))
      (diag-fail :network-genesis-cid-mismatch)

      (not (:ok? disc))
      (diag-fail (:code disc) (:detail disc))

      (or (empty? comm-pks) (and equiv-ok? (< (count comm-pks) 4)))
      (diag-fail :insufficient-validator-committee-size {:size (count comm-pks)})

      (and (not equiv-ok?) (< (- ep-eff ep-fin) effective-lead))
      (diag-fail :validator-rotation-lead-too-short
                 {:epoch-effective ep-eff
                  :epoch-finalized ep-fin
                  :lead-epochs effective-lead
                  :min-lead min-validator-activation-lead-epochs})

      (< ep-eff min-eff)
      (diag-fail :validator-activation-lead-violated {:epoch-effective ep-eff :min-effective min-eff})

      (< valid-sigs root-th)
      (diag-fail :insufficient-root-signatures {:valid valid-sigs :required root-th})

      :else
      {:ok? true
       :cid (descriptor-cid desc)
       :committee comm-pks
       :epoch-effective ep-eff
       :quorum-threshold (long (:quorum-threshold desc))})))

(defn cold-root-recovery-signing-tuple
  "Returns the domain-separated canonical signing tuple for `:cold-root-recovery` bundles."
  [bundle]
  ["bitecho-cold-root-recovery-v1"
   (str (:network-uri bundle))
   (str/lower-case (str (:network-genesis-cid bundle)))
   (dissoc bundle :root-signatures)])

(defn create-cold-root-recovery-bundle
  "Creates and signs an offline Cold-Root Emergency Recovery bundle (§2.5 item 5)."
  [fields root-signers]
  (let [norm-comm (mapv (fn [entry]
                          (if (map? entry)
                            (assoc entry :pubkey (normalize-spki-pubkey (:pubkey entry)))
                            {:pubkey (normalize-spki-pubkey entry) :role :core-validator}))
                        (:committee fields))
        base {:bitecho/type :cold-root-recovery
              :network-uri (str/trim (str (:network-uri fields)))
              :network-genesis-cid (str/lower-case (str/trim (str (:network-genesis-cid fields))))
              :recovery-seq (long (or (:recovery-seq fields) 0))
              :last-known-finalized-block-hash (str/lower-case (str/trim (str (:last-known-finalized-block-hash fields))))
              :committee norm-comm
              :quorum-threshold (long (or (:quorum-threshold fields) 1))}
        tuple (cold-root-recovery-signing-tuple base)
        sigs (into (sorted-map)
                   (keep (fn [{:keys [pubkey privkey]}]
                           (when-let [spki (normalize-spki-pubkey pubkey)]
                             [spki (str/lower-case (basalt/bytes->hex (crypto/sign-canonical privkey tuple)))])))
                   root-signers)]
    (assoc base :root-signatures sigs)))

(defn verify-cold-root-recovery-bundle
  "Verifies a signed `:cold-root-recovery` bundle against Root Association multisig and network/genesis binding."
  [bundle ctx]
  (let [root-ms (:root-owner-multisig ctx)
        root-pks (dedup-spki-pubkeys (:pubkeys root-ms))
        root-th (long (or (:threshold root-ms) 1))
        twin-set (or (:advisory-twin-pubkeys ctx) #{})
        tuple (cold-root-recovery-signing-tuple bundle)
        valid-sigs (count-valid-multisig-signatures (:root-signatures bundle) root-pks tuple twin-set)
        comm-pks (dedup-spki-pubkeys (map :pubkey (:committee bundle)))]
    (cond
      (not= :cold-root-recovery (:bitecho/type bundle))
      (diag-fail :invalid-cold-root-recovery-type)

      (and (:network-uri ctx) (not= (str (:network-uri ctx)) (str (:network-uri bundle))))
      (diag-fail :network-uri-mismatch)

      (and (:network-genesis-cid ctx)
           (not= (str/lower-case (str (:network-genesis-cid ctx)))
                 (str/lower-case (str (:network-genesis-cid bundle)))))
      (diag-fail :network-genesis-cid-mismatch)

      (empty? comm-pks)
      (diag-fail :empty-recovery-committee)

      (< valid-sigs root-th)
      (diag-fail :insufficient-root-signatures {:valid valid-sigs :required root-th})

      :else
      {:ok? true :cid (descriptor-cid bundle) :committee comm-pks})))

(defn apply-cold-root-recovery
  "Applies a verified Cold-Root Emergency Recovery bundle to state, recording it permanently
   in `:validator-set-history` and emitting a high-severity `:cold-root-recovery-activated` diagnostic."
  [state bundle ctx]
  (let [v-res (verify-cold-root-recovery-bundle bundle ctx)
        last-fin (long (or (:last-finalized-epoch state) 0))
        rec-seq (long (or (:recovery-seq bundle) 0))]
    (cond
      (not (:ok? v-res)) v-res

      (<= rec-seq last-fin)
      (diag-fail :stale-cold-root-recovery-seq {:recovery-seq rec-seq :last-finalized-epoch last-fin})

      :else
      (let [entry {:committee (:committee v-res)
                   :quorum-threshold (long (:quorum-threshold bundle))
                   :descriptor-cid (:cid v-res)
                   :cold-root-recovery? true}
            diag {:effect :diagnose
                  :severity :high
                  :reason :cold-root-recovery-activated
                  :recovery-seq rec-seq
                  :recovery-cid (:cid v-res)}
            st' (-> state
                    (assoc-in [:validator-set-history rec-seq] entry)
                    (assoc :validators (:committee v-res))
                    (update-in [:diagnostics :cold-root-recovery-activated] (fnil inc 0)))]
        {:ok? true :state st' :effects [diag]}))))

(defn verify-and-apply-cold-root-recovery-by-cid
  "Pure startup helper (F4): verifies `SHA-256(raw-bytes) == expected-cid`, decodes the
   canonical Fressian `:cold-root-recovery` bundle, and applies it via `apply-cold-root-recovery`.
   Fails closed with counted `:diagnose` on CID mismatch, decode failure, or invalid signatures."
  [state expected-cid raw-bytes ctx]
  (let [norm-cid (when (string? expected-cid) (str/lower-case (str/trim expected-cid)))]
    (cond
      (not (valid-cid-64? norm-cid))
      (diag-fail :invalid-cold-root-recovery-cid {:cid expected-cid})

      (not (and (fressian/bytes? raw-bytes) (pos? (fressian/count-bytes raw-bytes))))
      (diag-fail :cold-root-recovery-bundle-missing {:cid norm-cid})

      :else
      (let [actual-cid (str/lower-case (basalt/bytes->hex (crypto/sha256 raw-bytes)))]
        (if (not= actual-cid norm-cid)
          (diag-fail :cold-root-recovery-cid-mismatch {:expected norm-cid :actual actual-cid})
          (let [bundle (try (fressian/decode-wire raw-bytes)
                            (catch #?(:clj Throwable :cljs :default) _ nil))]
            (if-not (map? bundle)
              (diag-fail :cold-root-recovery-decode-failed {:cid norm-cid})
              (apply-cold-root-recovery state bundle ctx))))))))

;; =============================================================================
;; 7. Section 8 Foundations: Asset-ID, Supply Commitment, 3-Chain QC & G4 Bridge Caps
;; =============================================================================

(defn valid-asset-id?
  "Validates canonical `:asset-id` format `<root-uri>/<SYMBOL>` (e.g. `bitecho.org/ECHO`)."
  [asset-id]
  (if-not (string? asset-id)
    false
    (let [[root-uri sym & extra] (str/split asset-id #"/")]
      (boolean (and (nil? extra)
                    (config/root-subnet-id? root-uri)
                    (string? sym)
                    (re-matches #"[A-Z0-9]{2,16}" sym))))))

(defn build-supply-commitment
  "Constructs a deterministic epoch-anchored `:supply-commitment` for cross-root anchoring (§8.2 G2)."
  [{:keys [asset-id genesis-cid anchor-epoch ledger-merkle-root circulating-supply total-minted total-burned locked-bridge-out]}]
  {:bitecho/type :supply-commitment
   :asset-id (str asset-id)
   :genesis-cid (str/lower-case (str genesis-cid))
   :anchor-epoch (long anchor-epoch)
   :ledger-merkle-root (str/lower-case (str ledger-merkle-root))
   :circulating-supply (long circulating-supply)
   :total-minted (long total-minted)
   :total-burned (long total-burned)
   :locked-bridge-out (long (or locked-bridge-out 0))})

(defn verify-3chain-qc
  "Verifies a 3-chain Streamlet Quorum Certificate (`[b1 b2 b3]` with consecutive epochs
   and valid quorum vote proofs against epoch-indexed `validator-set-history`, §8.2 G3)."
  [chain-blocks validator-set-history]
  (if (not= 3 (count chain-blocks))
    (diag-fail :invalid-3chain-length)
    (let [[b1 b2 b3] chain-blocks
          e1 (long (or (:epoch b1) -1))
          e2 (long (or (:epoch b2) -1))
          e3 (long (or (:epoch b3) -1))
          consecutive? (and (= e2 (inc e1))
                            (= e3 (inc e2))
                            (= (:block-hash b1) (:parent-hash b2))
                            (= (:block-hash b2) (:parent-hash b3)))
          committee-for (fn [ep]
                          (let [ks (filter #(<= (long %) (long ep)) (keys validator-set-history))]
                            (when (seq ks)
                              (get validator-set-history (apply max ks)))))
          block-qc-ok? (fn [b]
                         (if-let [entry (committee-for (:epoch b))]
                           (let [comm (set (dedup-spki-pubkeys (:committee entry)))
                                 th (long (or (:quorum-threshold entry) 1))
                                 votes (or (:votes b) {})
                                 valid-v (keep (fn [[pk sig]]
                                                 (let [spki (normalize-spki-pubkey pk)]
                                                   (when (and spki
                                                              (contains? comm spki)
                                                              (crypto/verify-with-fallback spki ["streamlet-vote" (:epoch b) (:block-hash b)] sig))
                                                     spki)))
                                               votes)]
                             (>= (count (distinct valid-v)) th))
                           false))]
      (cond
        (not consecutive?) (diag-fail :non-consecutive-3chain)
        (not (every? block-qc-ok? chain-blocks)) (diag-fail :invalid-3chain-qc-signatures)
        :else {:ok? true :finalized-block b1}))))

(defn apply-bridge-transfer
  "Enforces §8.2 G4 per-root, per-asset bridge caps and global conservation:
   sum(wrapped_supply(r, A)) <= locked_escrow(origin(A), A) with automatic circuit-breaking `:diagnose`."
  [bridge-state {:keys [target-root amount]}]
  (let [amt (long (or amount 0))
        root-cap (long (get-in bridge-state [:per-root-cap target-root] 0))
        curr-root (long (get-in bridge-state [:wrapped-supply target-root] 0))
        next-root (+ curr-root amt)
        total-wrapped (+ amt (reduce + 0 (vals (:wrapped-supply bridge-state))))
        locked (long (or (:locked-escrow bridge-state) 0))]
    (cond
      (<= amt 0)
      (diag-fail :invalid-bridge-amount)

      (> next-root root-cap)
      (diag-fail :bridge-root-cap-exceeded {:target-root target-root :next next-root :cap root-cap})

      (> total-wrapped locked)
      (diag-fail :bridge-global-conservation-violated {:total-wrapped total-wrapped :locked locked})

      :else
      {:ok? true
       :state (assoc-in bridge-state [:wrapped-supply target-root] next-root)
       :effects []})))
