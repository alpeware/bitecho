(ns bitecho.circles.vault
  "Pure Sans-IO Persistent Circle Vaults, Anti-Malleability Spend Digest,
   Dedicated `:vault-spend-dac` With Atomic Revocation & Full 7-Bucket `INV-C1` (BIP-024 §2.8.2).

   Strictly adheres to AGENTS.md Rule 2 (Pure Functions / Sans-IO) and Rule 5 (Zero Silent Failures)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.circle :as circle]
            [bitecho.crypto :as crypto]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def max-supply-cap-ech
  "Absolute 42B ECHO supply conservation cap (`INV-C1`)."
  42000000000)

(def default-max-vaults
  "Default maximum number of concurrent persistent vaults (`BIP-024 §2.8.2`)."
  4096)

(def default-min-vault-balance-ech
  "Default minimum balance dust floor (1,000 ECHO) for TTL-exempt persistent vaults."
  1000)

(def default-max-dac-spend-per-epoch-bps
  "Default per-epoch `:vault-spend-dac` cap (500 bps = 5% of vault balance per epoch)."
  500)

(def default-settlement-take-bps
  "Non-waivable commercial `:release` settlement take (50 bps)."
  50)

(def default-bootstrap-sunset-epoch
  "Epoch 26,280 sunset burning strictly unspent `:custody-bucket :bootstrap` balances."
  26280)

(defn- diag-fail
  ([state reason]
   (diag-fail state reason {}))
  ([state reason detail]
   {:ok? false
    :error reason
    :state (update-in state [:diagnostics reason] (fnil inc 0))
    :effects [(merge {:effect :diagnose :reason reason} detail)]}))

(defn treasury-spend-digest-tuple
  "Returns the domain-separated Canonical Fressian tuple for a persistent vault spend (BIP-024 §2.8.2):
   [\"bitecho-treasury-spend-v1\" network-uri network-genesis-cid vault-id puzzle-hash vault-seq outputs-hash]."
  [{:keys [network-uri network-genesis-cid vault-id puzzle-hash vault-seq outputs next-puzzle-hash]}]
  (let [outputs-hash (str/lower-case
                      (basalt/bytes->hex
                       (crypto/sha256
                        (fressian/encode-canonical {:outputs (vec (or outputs []))
                                                    :next-puzzle-hash (str/lower-case (str next-puzzle-hash))}))))]
    ["bitecho-treasury-spend-v1"
     (str network-uri)
     (str/lower-case (str network-genesis-cid))
     (str vault-id)
     (str/lower-case (str puzzle-hash))
     (long vault-seq)
     outputs-hash]))

(defn treasury-spend-digest
  "Returns the Canonical Fressian bytes of `treasury-spend-digest-tuple` for signing/verification."
  [params]
  (fressian/encode-canonical (treasury-spend-digest-tuple params)))

(defn canonical-multisig-treasury-puzzle-source
  "Returns a canonical SCI multisig treasury puzzle source for `threshold`-of-`pubkeys`
   that verifies `>= threshold` distinct canonical 88-char SPKI signatures over the full
   anti-malleability spend digest bound to `outputs`, `next-puzzle-hash`, `vault-id`,
   `puzzle-hash`, `vault-seq`, `network-uri`, and `network-genesis-cid`."
  [threshold pubkeys]
  (let [canon-pks (circle/dedup-spki-pubkeys pubkeys)
        k (long threshold)]
    (pr-str
     (list 'fn ['env 'solution]
           (list 'let ['allowed (set canon-pks)
                       'sigs (list 'or (list :signatures 'solution) {})
                       'digest (list :spend-digest 'env)
                       'outputs (list :outputs 'solution)
                       'valid-signers (list 'distinct
                                            (list 'filter
                                                  (list 'fn ['pk]
                                                        (list 'and
                                                              (list 'contains? 'allowed 'pk)
                                                              (list 'let ['s (list 'get 'sigs 'pk)]
                                                                    (list 'and
                                                                          (list 'string? 's)
                                                                          (list 'verify-sig 'pk 'digest 's)))))
                                                  (list 'keys 'sigs)))]
                 (list 'if (list '>= (list 'count 'valid-signers) k)
                       'outputs
                       false))))))

(def default-max-attestation-lag-epochs
  "Default maximum epoch lag allowed for fresh SLA oracle attestations (BIP-026 §1.4 P4.1)."
  10)

(defn init-vaults-state
  "Initializes pure Sans-IO persistent vaults & 7-bucket conservation state."
  ([] (init-vaults-state {}))
  ([opts]
   {:network-uri            (or (:network-uri opts) "devnet.bitecho.org")
    :network-genesis-cid    (or (:network-genesis-cid opts) "")
    :max-vaults             (long (or (:max-vaults opts) default-max-vaults))
    :min-vault-balance-ech  (long (or (:min-vault-balance-ech opts) default-min-vault-balance-ech))
    :settlement-take-bps    (long (or (:settlement-take-bps opts) default-settlement-take-bps))
    :advisory-twin-pubkeys  (set (or (:advisory-twin-pubkeys opts) #{}))
    :max-attestation-lag    (long (or (:max-attestation-lag opts) default-max-attestation-lag-epochs))
    :bootstrap-sunset-epoch (long (or (:bootstrap-sunset-epoch opts) default-bootstrap-sunset-epoch))
    :genesis-custody-supply (long (or (:genesis-custody-supply opts) 0))
    :total-minted           (long (or (:total-minted opts) 0))
    :root-unallocated       (long (or (:root-unallocated opts) 0))
    :total-burned           (long (or (:total-burned opts) 0))
    :sunset-custody-burned  (long (or (:sunset-custody-burned opts) 0))
    :ledger                 (or (:ledger opts) {})
    :escrows                (or (:escrows opts) {})
    :bounty-escrows         (or (:bounty-escrows opts) {})
    :vaults                 (or (:vaults opts) {})
    :chartered-vaults       (set (or (:chartered-vaults opts) #{}))
    :vault-spend-dacs       (or (:vault-spend-dacs opts) {})
    :diagnostics            (or (:diagnostics opts) {})}))

(defn vault-create-signing-tuple
  "Returns the domain-separated Canonical Fressian tuple for `:vault-create` authorization (BIP-026 §1.1 P1.4, B1):
   [\"bitecho-vault-create-v1\" network-uri network-genesis-cid vault-id entity-uri custody-bucket puzzle-hash payer balance created-epoch]."
  [{:keys [network-uri network-genesis-cid vault-id entity-uri custody-bucket puzzle-hash payer balance created-epoch]}]
  ["bitecho-vault-create-v1"
   (str network-uri)
   (str/lower-case (str network-genesis-cid))
   (str vault-id)
   (str entity-uri)
   custody-bucket
   (str/lower-case (str/trim (str puzzle-hash)))
   (when payer (or (circle/normalize-spki-pubkey payer) (str payer)))
   (long (or balance 0))
   (long (or created-epoch 0))])

(defn dac-issue-signing-tuple
  "Domain-separated Canonical Fressian tuple for `:vault-spend-dac-issue` authorization (BIP-026 B1)."
  [{:keys [network-uri network-genesis-cid dac-id vault-id holder-pubkey max-per-epoch-bps issued-epoch expires-epoch]}]
  ["bitecho-vault-dac-issue-v1"
   (str network-uri)
   (str/lower-case (str network-genesis-cid))
   (str dac-id)
   (str vault-id)
   (or (circle/normalize-spki-pubkey holder-pubkey) (str holder-pubkey))
   (long (or max-per-epoch-bps default-max-dac-spend-per-epoch-bps))
   (long (or issued-epoch 0))
   (long (or expires-epoch 0))])

(defn dac-revoke-signing-tuple
  "Domain-separated Canonical Fressian tuple for `:vault-spend-dac-revoke` authorization (BIP-026 B1)."
  [{:keys [network-uri network-genesis-cid dac-id vault-id]}]
  ["bitecho-vault-dac-revoke-v1"
   (str network-uri)
   (str/lower-case (str network-genesis-cid))
   (str dac-id)
   (str vault-id)])

(defn dac-spend-signing-tuple
  "Domain-separated Canonical Fressian tuple for `:vault-spend-dac-spend` authorization (BIP-026 B1)."
  [{:keys [network-uri network-genesis-cid dac-id vault-id receiver amount epoch]}]
  ["bitecho-vault-dac-spend-v1"
   (str network-uri)
   (str/lower-case (str network-genesis-cid))
   (str dac-id)
   (str vault-id)
   (or (circle/normalize-spki-pubkey receiver) (str receiver))
   (long (or amount 0))
   (long (or epoch 0))])

(defn- count-valid-multisig-sigs
  [sigs allowed-pubkeys tuple twin-set]
  (let [allowed-set (set (circle/dedup-spki-pubkeys allowed-pubkeys))
        valid (keep (fn [[pk sig]]
                      (let [spki (circle/normalize-spki-pubkey pk)]
                        (when (and spki
                                   (contains? allowed-set spki)
                                   (not (circle/advisory-twin? twin-set spki))
                                   (string? sig)
                                   (crypto/verify-with-fallback spki tuple sig))
                          spki)))
                    (or sigs {}))]
    (count (distinct valid))))

(defn- vault-authority-multisig
  "Resolves the authorizing `:owner-multisig` for a vault (vault-level, entity-descriptor, or root-owner-multisig)."
  [state v]
  (or (:owner-multisig v)
      (when-let [euri (:entity-uri v)]
        (or (get-in state [:entity-descriptors euri :owner-multisig])
            (let [net-prefix (str (:network-uri state) "/")]
              (when (str/starts-with? (str euri) net-prefix)
                (get-in state [:entity-descriptors (subs (str euri) (count net-prefix)) :owner-multisig])))))
      (:root-owner-multisig state)
      (get-in state [:config :root-owner-multisig])))

(defn- authorized-vault-action?
  "Verifies authority over a vault action via multisig signatures or authorized single-signer Ed25519 signature."
  [state v tuple {:keys [owner-signatures root-signatures signatures signer-pubkey issuer-pubkey revoker-pubkey signature]}]
  (let [twin-set (or (:advisory-twin-pubkeys state) #{})
        ms (vault-authority-multisig state v)
        sig-map (or owner-signatures root-signatures signatures)
        single-pk (circle/normalize-spki-pubkey (or signer-pubkey issuer-pubkey revoker-pubkey))
        vault-payer (circle/normalize-spki-pubkey (:payer v))]
    (cond
      (and (map? ms) (seq (:pubkeys ms)) (map? sig-map))
      (let [th (long (or (:threshold ms) 1))]
        (and (>= th 1)
             (>= (count-valid-multisig-sigs sig-map (:pubkeys ms) tuple twin-set) th)))

      (and single-pk (string? signature) (not (circle/advisory-twin? twin-set single-pk)))
      (let [allowed? (or (and vault-payer (= single-pk vault-payer))
                         (and (map? ms)
                              (= 1 (long (or (:threshold ms) 1)))
                              (contains? (set (circle/dedup-spki-pubkeys (:pubkeys ms))) single-pk)))]
        (boolean (and allowed? (crypto/verify-with-fallback single-pk tuple signature))))

      :else false)))

(defn- lookup-ledger-key
  [ledger raw-pk norm-pk]
  (cond
    (and norm-pk (contains? ledger norm-pk)) norm-pk
    (and raw-pk (contains? ledger raw-pk)) raw-pk
    :else nil))

(defn create-vault
  "Creates a new persistent vault in dedicated `[:vaults vault-id]` state map.
   Enforces `:max-vaults` cap, `:min-vault-balance-ech` dust floor, cryptographic Ed25519 / Root
   multisig authorization, and atomic funding debit from `[:ledger payer]` or `:root-unallocated`
   (BIP-026 §1.1 P1.4, B1)."
  [state {:keys [vault-id entity-uri custody-bucket puzzle-hash balance created-epoch
                 payer signature funding-source root-signatures signatures owner-signatures]}]
  (let [bal (long (or balance 0))
        max-v (long (or (:max-vaults state) default-max-vaults))
        min-bal (long (or (:min-vault-balance-ech state) default-min-vault-balance-ech))
        active-count (count (filter #(= :active (:status (val %))) (:vaults state)))
        twin-set (or (:advisory-twin-pubkeys state) #{})
        norm-payer (circle/normalize-spki-pubkey payer)
        root-funding? (or (= :root-unallocated funding-source)
                          (and (nil? payer) (or (seq root-signatures) (seq signatures) (seq owner-signatures))))
        tuple (vault-create-signing-tuple
               {:network-uri (or (:network-uri state) (get-in state [:config :network-uri]) "")
                :network-genesis-cid (or (:network-genesis-cid state) (get-in state [:config :network-genesis-cid]) "")
                :vault-id vault-id
                :entity-uri entity-uri
                :custody-bucket custody-bucket
                :puzzle-hash puzzle-hash
                :payer (if root-funding? nil (or norm-payer payer))
                :balance bal
                :created-epoch created-epoch})]
    (cond
      (or (not (string? vault-id)) (str/blank? vault-id))
      (diag-fail state :invalid-vault-id)

      (contains? (:vaults state) vault-id)
      (diag-fail state :vault-already-exists {:vault-id vault-id})

      (>= active-count max-v)
      (diag-fail state :max-vaults-exceeded {:active active-count :max max-v})

      (< bal min-bal)
      (diag-fail state :vault-below-min-balance {:balance bal :min-balance min-bal})

      (not (and (string? puzzle-hash) (re-matches #"[0-9a-f]{64}" (str/lower-case (str/trim puzzle-hash)))))
      (diag-fail state :invalid-vault-puzzle-hash)

      (not (contains? circle/valid-custody-buckets custody-bucket))
      (diag-fail state :invalid-custody-bucket)

      root-funding?
      (let [root-ms (or (:root-owner-multisig state) (get-in state [:config :root-owner-multisig]))
            sigs (or root-signatures signatures owner-signatures)
            th (long (or (:threshold root-ms) 1))
            valid-cnt (if (and (map? root-ms) (seq (:pubkeys root-ms)))
                        (count-valid-multisig-sigs sigs (:pubkeys root-ms) tuple twin-set)
                        0)
            unalloc (long (or (:root-unallocated state) 0))]
        (cond
          (or (not (map? root-ms)) (< th 1) (< valid-cnt th))
          (diag-fail state :unauthorized-vault-create {:vault-id vault-id})

          (< unalloc bal)
          (diag-fail state :insufficient-funds {:vault-id vault-id :available unalloc :required bal})

          :else
          (let [entry (cond-> {:vault-id vault-id
                               :entity-uri (str entity-uri)
                               :custody-bucket custody-bucket
                               :puzzle-hash (str/lower-case (str/trim puzzle-hash))
                               :balance bal
                               :vault-seq 1
                               :created-epoch (long (or created-epoch 0))
                               :status :active}
                        (map? root-ms) (assoc :owner-multisig root-ms))]
            {:ok? true
             :vault entry
             :state (-> state
                        (update :root-unallocated (fnil - 0) bal)
                        (assoc-in [:vaults vault-id] entry))
             :effects []})))

      :else
      (let [sig-ok? (and norm-payer
                         (not (circle/advisory-twin? twin-set norm-payer))
                         (string? signature)
                         (not (str/blank? signature))
                         (crypto/verify-with-fallback norm-payer tuple signature))
            ledger-k (lookup-ledger-key (:ledger state) payer norm-payer)
            payer-bal (if ledger-k (long (or (get-in state [:ledger ledger-k :balance]) 0)) 0)]
        (cond
          (not sig-ok?)
          (diag-fail state :unauthorized-vault-create {:vault-id vault-id})

          (or (nil? ledger-k) (< payer-bal bal))
          (diag-fail state :insufficient-funds {:vault-id vault-id :payer norm-payer :available payer-bal :required bal})

          :else
          (let [entry {:vault-id vault-id
                       :entity-uri (str entity-uri)
                       :custody-bucket custody-bucket
                       :puzzle-hash (str/lower-case (str/trim puzzle-hash))
                       :payer norm-payer
                       :balance bal
                       :vault-seq 1
                       :created-epoch (long (or created-epoch 0))
                       :status :active}]
            {:ok? true
             :vault entry
             :state (-> state
                        (update-in [:ledger ledger-k :balance] - bal)
                        (assoc-in [:vaults vault-id] entry))
             :effects []}))))))

(defn reject-vault-refund
  "BIP-024 §2.8.2 (MUT-10): `:refund-intent` is unconditionally forbidden on persistent vaults."
  [state vault-id]
  (diag-fail state :vault-refund-forbidden {:vault-id vault-id}))

(defn- revoke-dacs-for-vault
  [dacs vault-id]
  (into {}
        (map (fn [[dac-id dac]]
               [dac-id (if (= vault-id (:vault-id dac))
                         (assoc dac :revoked? true)
                         dac)]))
        (or dacs {})))

(defn sla-attestation-tuple
  "Returns the domain-separated canonical tuple for an SLA oracle attestation (BIP-026 §1.4 P4.1, B6).
   Explicitly binds `:network-uri`, `:network-genesis-cid`, `:vault-id`, `:vault-seq`, `:epoch`,
   optional `:metric-id`, and `:score-bps`."
  [{:keys [network-uri network-genesis-cid vault-id vault-seq epoch metric-id score-bps]}]
  (if (some? metric-id)
    ["bitecho-sla-attestation-v1"
     (str network-uri)
     (str network-genesis-cid)
     (str vault-id)
     (long (or vault-seq 0))
     (long (or epoch 0))
     (str metric-id)
     (long (or score-bps 0))]
    ["bitecho-sla-attestation-v1"
     (str network-uri)
     (str network-genesis-cid)
     (str vault-id)
     (long (or vault-seq 0))
     (long (or epoch 0))
     (long (or score-bps 0))]))

(defn sla-attestation-bytes
  "Returns canonical Fressian bytes for an SLA oracle attestation tuple (BIP-026 §1.4 P4.1, B6)."
  [params]
  (fressian/encode-canonical (sla-attestation-tuple params)))

(defn- verify-and-canonicalize-oracle-attestations
  "Pre-validates and canonicalizes `:oracle-attestations` fail-closed before SCI evaluation (BIP-026 §1.4 P4.1, B6):
   1. Rejects any oracle pubkey in `:advisory-twin-pubkeys` with `:advisory-twin-signing-forbidden`.
   2. Canonicalizes oracle pubkeys via `circle/normalize-spki-pubkey` (collapsing 64-hex & 88-hex aliasing).
   3. Enforces exact `:vault-seq` match, epoch freshness (`cur-ep - max-lag <= att-ep <= cur-ep`),
      `(<= 0 score-bps 10000)`, and valid Ed25519 signature over `sla-attestation-bytes`."
  [state v raw-atts cur-ep]
  (if (empty? raw-atts)
    {:ok? true :attestations {}}
    (let [twin-set (or (:advisory-twin-pubkeys state) #{})
          net-uri (or (:network-uri state) (get-in state [:config :network-uri]) "")
          gen-cid (or (:network-genesis-cid state) (get-in state [:config :network-genesis-cid]) "")
          max-lag (long (or (:max-attestation-lag state)
                            (get-in state [:config :max-attestation-lag])
                            default-max-attestation-lag-epochs))
          entries (cond
                    (map? raw-atts) (seq raw-atts)
                    (sequential? raw-atts) (map (fn [a] [(:oracle-pubkey a) a]) raw-atts)
                    :else nil)]
      (if-not entries
        {:ok? false :error :invalid-oracle-attestations}
        (loop [rem-entries entries
               acc {}]
          (if (empty? rem-entries)
            {:ok? true :attestations acc}
            (let [[raw-pk att] (first rem-entries)
                  norm-pk (circle/normalize-spki-pubkey (or (when (map? att) (:oracle-pubkey att)) raw-pk))
                  att-ep (when (map? att) (:epoch att))
                  att-seq (when (map? att) (:vault-seq att))
                  score-bps (when (map? att) (:score-bps att))
                  sig (when (map? att) (:signature att))
                  att-vid (or (when (map? att) (:vault-id att)) (:vault-id v))]
              (cond
                (or (not (map? att)) (nil? norm-pk))
                {:ok? false :error :invalid-oracle-pubkey :detail {:oracle-pubkey raw-pk}}

                (circle/advisory-twin? twin-set norm-pk)
                {:ok? false :error :advisory-twin-signing-forbidden :detail {:pubkey norm-pk}}

                (not= (str att-vid) (str (:vault-id v)))
                {:ok? false :error :oracle-vault-id-mismatch :detail {:expected (:vault-id v) :actual att-vid}}

                (or (not (integer? att-seq)) (not= (long att-seq) (long (:vault-seq v))))
                {:ok? false :error :oracle-vault-seq-mismatch :detail {:expected (:vault-seq v) :actual att-seq}}

                (or (not (integer? att-ep))
                    (> (long att-ep) cur-ep)
                    (> (- cur-ep (long att-ep)) max-lag))
                {:ok? false :error :stale-oracle-attestation :detail {:epoch att-ep :current-epoch cur-ep :max-lag max-lag}}

                (or (not (integer? score-bps))
                    (< (long score-bps) 0)
                    (> (long score-bps) 10000))
                {:ok? false :error :invalid-oracle-score-bps :detail {:score-bps score-bps}}

                (or (not (string? sig)) (str/blank? sig))
                {:ok? false :error :invalid-oracle-signature :detail {:oracle-pubkey norm-pk}}

                :else
                (let [params-with-metric {:network-uri net-uri
                                          :network-genesis-cid gen-cid
                                          :vault-id (:vault-id v)
                                          :vault-seq (long att-seq)
                                          :epoch (long att-ep)
                                          :metric-id (:metric-id att)
                                          :score-bps (long score-bps)}
                      bytes-primary (sla-attestation-bytes params-with-metric)
                      sig-ok? (boolean (crypto/verify-with-fallback norm-pk bytes-primary sig))]
                  (if-not sig-ok?
                    {:ok? false :error :invalid-oracle-signature :detail {:oracle-pubkey norm-pk}}
                    (recur (rest rem-entries)
                           (assoc acc norm-pk
                                  (assoc att
                                         :oracle-pubkey norm-pk
                                         :vault-id (:vault-id v)
                                         :vault-seq (long att-seq)
                                         :epoch (long att-ep)
                                         :score-bps (long score-bps)
                                         :verified? true)))))))))))))

(defn spend-vault
  "Executes an in-place persistent vault spend against `[:vaults vault-id]`:
   - Matches exact `:vault-seq` and atomically increments `:vault-seq` in place.
   - Evaluates SCI puzzle in `:vault-mode? true` (forbids `:refund`/`:refund-remainder`, enforces exact conservation).
   - Restricts `0-take :allocate` strictly to Root-chartered custody-bucket vaults transferring
     into registered chartered circle vaults preserving `:custody-bucket`.
   - Charges non-waivable `:settlement-take-bps` (`50 bps`) on all `:release` outputs.
   - Atomically revokes any `:vault-spend-dac`s on `:puzzle-hash` rotation.
   - Enforces advisory-twin isolation, canonical SLA oracle attestation verification, and relock
     puzzle-hash binding (BIP-026 §1.4 P4.1, B6)."
  [state {:keys [vault-id vault-seq puzzle-source solution epoch oracle-attestations]}]
  (let [v (get-in state [:vaults vault-id])
        take-bps (long (or (:settlement-take-bps state) default-settlement-take-bps))
        min-bal (long (or (:min-vault-balance-ech state) default-min-vault-balance-ech))
        chartered (or (:chartered-vaults state) #{})
        twin-set (or (:advisory-twin-pubkeys state) #{})
        ep (long (or epoch 0))
        sol-sigs (when (map? (:signatures solution)) (:signatures solution))
        twin-signer (when (seq sol-sigs)
                      (some (fn [[raw-pk _]]
                              (let [norm-pk (circle/normalize-spki-pubkey raw-pk)]
                                (when (and norm-pk (circle/advisory-twin? twin-set norm-pk))
                                  norm-pk)))
                            sol-sigs))]
    (cond
      (nil? v)
      (diag-fail state :vault-not-found {:vault-id vault-id})

      (not= :active (:status v))
      (diag-fail state :vault-not-active {:vault-id vault-id :status (:status v)})

      (not= (long (or vault-seq -1)) (long (:vault-seq v)))
      (diag-fail state :vault-seq-mismatch {:vault-id vault-id :expected (:vault-seq v) :actual vault-seq})

      twin-signer
      (diag-fail state :advisory-twin-signing-forbidden {:vault-id vault-id :pubkey twin-signer})

      :else
      (let [raw-atts (or oracle-attestations (:oracle-attestations solution))
            att-res (verify-and-canonicalize-oracle-attestations state v raw-atts ep)]
        (if-not (:ok? att-res)
          (diag-fail state (:error att-res) (assoc (or (:detail att-res) {}) :vault-id vault-id))
          (let [outputs (:outputs solution)
                next-ph (or (:next-puzzle-hash solution) (:puzzle-hash v))
                net-uri (or (:network-uri state) (get-in state [:config :network-uri]) "")
                gen-cid (or (:network-genesis-cid state) (get-in state [:config :network-genesis-cid]) "")
                digest (treasury-spend-digest
                        {:network-uri net-uri
                         :network-genesis-cid gen-cid
                         :vault-id vault-id
                         :puzzle-hash (:puzzle-hash v)
                         :vault-seq (:vault-seq v)
                         :outputs outputs
                         :next-puzzle-hash next-ph})
                env-ctx {:vault-mode? true
                         :amount (:balance v)
                         :puzzle-hash (:puzzle-hash v)
                         :vault-id vault-id
                         :vault-seq (:vault-seq v)
                         :epoch ep
                         :network-uri net-uri
                         :network-genesis-cid gen-cid
                         :oracle-attestations (:attestations att-res)
                         :spend-digest digest}
                eval-res (puzzle/eval-puzzle puzzle-source solution env-ctx)]
            (if-not (:valid? eval-res)
              (diag-fail state (or (:error eval-res) :vault-puzzle-rejected) {:vault-id vault-id})
              (let [conds (:conditions eval-res)
                    relocks (filter #(= :relock (:type %)) conds)
                    allocs (filter #(= :allocate (:type %)) conds)
                    releases (filter #(= :release (:type %)) conds)
                    relock-amt (reduce + 0 (map (comp long :amount) relocks))
                    relock-ph (or (:next-puzzle-hash (first relocks)) (:puzzle-hash v))
                    relock-ph-mismatch? (and (seq relocks)
                                             (not= (str/lower-case (str relock-ph))
                                                   (str/lower-case (str next-ph))))
                    next-puzzle-hash relock-ph
                    alloc-custody-mismatch? (some (fn [a]
                                                    (let [tid (:target-vault-id a)
                                                          tv (get-in state [:vaults tid])]
                                                      (and (some? tv)
                                                           (some? (:custody-bucket v))
                                                           (not= (:custody-bucket v) (:custody-bucket tv)))))
                                                  allocs)
                    alloc-valid? (every? (fn [a]
                                           (let [tid (:target-vault-id a)
                                                 tv (get-in state [:vaults tid])]
                                             (and (contains? chartered vault-id)
                                                  (some? (:custody-bucket v))
                                                  (contains? chartered tid)
                                                  (some? tv)
                                                  (= :active (:status tv))
                                                  (= (:custody-bucket v) (:custody-bucket tv)))))
                                         allocs)]
                (cond
                  (> (count relocks) 1)
                  (diag-fail state :multiple-relock-conditions {:vault-id vault-id})

                  relock-ph-mismatch?
                  (diag-fail state :relock-puzzle-hash-mismatch {:vault-id vault-id :expected next-ph :actual relock-ph})

                  (and (pos? relock-amt) (< relock-amt min-bal))
                  (diag-fail state :vault-relock-below-min-balance {:vault-id vault-id :relock-amount relock-amt :min-balance min-bal})

                  (and (seq allocs) alloc-custody-mismatch?)
                  (diag-fail state :custody-bucket-mismatch {:vault-id vault-id :custody-bucket (:custody-bucket v)})

                  (and (seq allocs) (not alloc-valid?))
                  (diag-fail state :unauthorized-zero-take-allocate {:vault-id vault-id})

                  :else
                  (let [;; Apply commercial :release outputs using Hamilton largest-remainder apportionment (B5)
                        ;; Custody vault burns go to :total-burned ONLY, NEVER :epoch-settlement-takes (B2)
                        apportioned (escrow/apportion-settlement-take releases take-bps)
                        total-take (reduce + 0 (map :take apportioned))
                        custody-vault? (some? (:custody-bucket v))
                        rel-applied (-> (reduce (fn [acc r]
                                                  (let [net-amt (long (:net r))
                                                        rec (or (circle/normalize-spki-pubkey (:receiver r)) (:receiver r))]
                                                    (update-in acc [:ledger rec :balance] (fnil + 0) net-amt)))
                                                state
                                                apportioned)
                                        (update :total-burned (fnil + 0) total-take)
                                        (cond-> (and (not custody-vault?) (pos? total-take))
                                          (update-in [:epoch-settlement-takes ep] (fnil + 0) total-take)))
                        ;; Apply chartered 0-take :allocate outputs preserving exact :custody-bucket
                        alloc-applied (reduce (fn [acc a]
                                                (let [tid (:target-vault-id a)
                                                      amt (long (:amount a))]
                                                  (update-in acc [:vaults tid :balance] (fnil + 0) amt)))
                                              rel-applied
                                              allocs)
                        rotated? (not= next-puzzle-hash (:puzzle-hash v))
                        updated-v (assoc v
                                         :balance relock-amt
                                         :vault-seq (inc (long (:vault-seq v)))
                                         :puzzle-hash next-puzzle-hash
                                         :status (if (zero? relock-amt) :closed :active))
                        st' (-> alloc-applied
                                (assoc-in [:vaults vault-id] updated-v)
                                (cond-> rotated?
                                  (update :vault-spend-dacs revoke-dacs-for-vault vault-id)))]
                    {:ok? true
                     :vault updated-v
                     :state st'
                     :effects []}))))))))))

(defn issue-vault-spend-dac
  "Issues a dedicated `:vault-spend-dac` bounded by `:max-per-epoch-bps` (default 500 bps).
   Requires valid cryptographic authorization from the vault's owner/Root authority (BIP-026 B1)."
  [state {:keys [dac-id vault-id holder-pubkey max-per-epoch-bps issued-epoch expires-epoch] :as params}]
  (let [v (get-in state [:vaults vault-id])
        bps (long (or max-per-epoch-bps default-max-dac-spend-per-epoch-bps))
        norm-holder (circle/normalize-spki-pubkey holder-pubkey)
        twin-set (or (:advisory-twin-pubkeys state) #{})
        tuple (dac-issue-signing-tuple
               {:network-uri (or (:network-uri state) (get-in state [:config :network-uri]) "")
                :network-genesis-cid (or (:network-genesis-cid state) (get-in state [:config :network-genesis-cid]) "")
                :dac-id dac-id
                :vault-id vault-id
                :holder-pubkey norm-holder
                :max-per-epoch-bps bps
                :issued-epoch issued-epoch
                :expires-epoch expires-epoch})]
    (cond
      (nil? v) (diag-fail state :vault-not-found {:vault-id vault-id})
      (not= :active (:status v)) (diag-fail state :vault-not-active {:vault-id vault-id})
      (nil? norm-holder) (diag-fail state :invalid-dac-holder-pubkey)
      (circle/advisory-twin? twin-set norm-holder) (diag-fail state :advisory-twin-signing-forbidden {:pubkey norm-holder})
      (or (<= bps 0) (> bps 10000)) (diag-fail state :invalid-dac-bps)
      (not (authorized-vault-action? state v tuple params))
      (diag-fail state :unauthorized-dac-issue {:dac-id dac-id :vault-id vault-id})
      :else
      (let [dac {:dac-id dac-id
                 :vault-id vault-id
                 :holder-pubkey norm-holder
                 :max-per-epoch-bps bps
                 :issued-epoch (long (or issued-epoch 0))
                 :expires-epoch (long (or expires-epoch 0))
                 :epoch-spent {}
                 :revoked? false}]
        {:ok? true
         :dac dac
         :state (assoc-in state [:vault-spend-dacs dac-id] dac)
         :effects []}))))

(defn revoke-vault-spend-dac
  "Atomically revokes a `:vault-spend-dac`.
   Requires valid cryptographic authorization from the vault's owner/Root authority (BIP-026 B1)."
  ([state dac-id-or-params]
   (if (map? dac-id-or-params)
     (let [dac-id (:dac-id dac-id-or-params)
           dac (get-in state [:vault-spend-dacs dac-id])
           v (when dac (get-in state [:vaults (:vault-id dac)]))]
       (cond
         (nil? dac) (diag-fail state :vault-dac-not-found {:dac-id dac-id})
         (nil? v) (diag-fail state :vault-not-found {:vault-id (:vault-id dac)})
         :else
         (let [tuple (dac-revoke-signing-tuple
                      {:network-uri (or (:network-uri state) (get-in state [:config :network-uri]) "")
                       :network-genesis-cid (or (:network-genesis-cid state) (get-in state [:config :network-genesis-cid]) "")
                       :dac-id dac-id
                       :vault-id (:vault-id dac)})]
           (if-not (authorized-vault-action? state v tuple dac-id-or-params)
             (diag-fail state :unauthorized-dac-revoke {:dac-id dac-id :vault-id (:vault-id dac)})
             {:ok? true
              :state (assoc-in state [:vault-spend-dacs dac-id :revoked?] true)
              :effects []}))))
     (diag-fail state :unauthorized-dac-revoke {:dac-id dac-id-or-params})))
  ([state dac-id auth-opts]
   (revoke-vault-spend-dac state (assoc (or auth-opts {}) :dac-id dac-id))))

(defn spend-via-vault-dac
  "Debits a vault via a non-revoked, non-expired `:vault-spend-dac` within its per-epoch bps cap.
   Requires valid Ed25519 signature from the delegated `:holder-pubkey` (BIP-026 B1) and
   isolates custody vault burns from `:epoch-settlement-takes` (BIP-026 B2)."
  [state {:keys [dac-id receiver amount epoch signature]}]
  (let [dac (get-in state [:vault-spend-dacs dac-id])
        v (when dac (get-in state [:vaults (:vault-id dac)]))
        ep (long (or epoch 0))
        amt (long (or amount 0))
        take-bps (long (or (:settlement-take-bps state) default-settlement-take-bps))
        twin-set (or (:advisory-twin-pubkeys state) #{})
        holder-pk (:holder-pubkey dac)
        tuple (when dac
                (dac-spend-signing-tuple
                 {:network-uri (or (:network-uri state) (get-in state [:config :network-uri]) "")
                  :network-genesis-cid (or (:network-genesis-cid state) (get-in state [:config :network-genesis-cid]) "")
                  :dac-id dac-id
                  :vault-id (:vault-id dac)
                  :receiver receiver
                  :amount amt
                  :epoch ep}))]
    (cond
      (nil? dac) (diag-fail state :vault-dac-not-found {:dac-id dac-id})
      (:revoked? dac) (diag-fail state :vault-dac-revoked {:dac-id dac-id})
      (>= ep (long (:expires-epoch dac))) (diag-fail state :vault-dac-expired {:dac-id dac-id})
      (or (nil? v) (not= :active (:status v))) (diag-fail state :vault-not-active {:vault-id (:vault-id dac)})
      (<= amt 0) (diag-fail state :invalid-dac-spend-amount)
      (or (nil? holder-pk)
          (circle/advisory-twin? twin-set holder-pk)
          (not (string? signature))
          (str/blank? signature)
          (not (crypto/verify-with-fallback holder-pk tuple signature)))
      (diag-fail state :unauthorized-dac-spend {:dac-id dac-id :vault-id (:vault-id dac)})
      :else
      (let [already-spent (long (get-in dac [:epoch-spent ep] 0))
            epoch-start-bal (+ (long (:balance v)) already-spent)
            epoch-cap (quot (* epoch-start-bal (long (:max-per-epoch-bps dac))) 10000)]
        (cond
          (> (+ already-spent amt) epoch-cap)
          (diag-fail state :vault-dac-epoch-cap-exceeded {:spent (+ already-spent amt) :cap epoch-cap})

          (> amt (long (:balance v)))
          (diag-fail state :insufficient-vault-balance)

          :else
          (let [take-amt (escrow/calculate-escrow-settlement-take amt take-bps)
                net-amt (- amt take-amt)
                rec (or (circle/normalize-spki-pubkey receiver) receiver)
                custody-vault? (some? (:custody-bucket v))
                st' (-> state
                        (update-in [:vaults (:vault-id dac) :balance] - amt)
                        (update-in [:vault-spend-dacs dac-id :epoch-spent ep] (fnil + 0) amt)
                        (update-in [:ledger rec :balance] (fnil + 0) net-amt)
                        (update :total-burned (fnil + 0) take-amt)
                        (cond-> (and (not custody-vault?) (pos? take-amt))
                          (update-in [:epoch-settlement-takes ep] (fnil + 0) take-amt)))]
            {:ok? true :state st' :net-amount net-amt :take-amount take-amt :effects []}))))))

(defn apply-bootstrap-sunset
  "At `current-epoch >= bootstrap-sunset-epoch` (default 26,280), burns strictly unspent
   `:custody-bucket :bootstrap` vault balances into `:sunset-custody-burned` (preserving `INV-C1`)."
  [state current-epoch]
  (let [sunset-ep (long (or (:bootstrap-sunset-epoch state)
                            (get-in state [:config :bootstrap-sunset-epoch])
                            default-bootstrap-sunset-epoch))]
    (if (< (long current-epoch) sunset-ep)
      {:ok? true :burned 0 :state state :effects []}
      (let [[vaults' burned]
            (reduce (fn [[vm acc-burned] [vid v]]
                      (if (and (= :bootstrap (:custody-bucket v))
                               (pos? (long (or (:balance v) 0))))
                        (let [b (long (:balance v))]
                          [(assoc vm vid (assoc v :balance 0 :status :sunset-burned))
                           (+ acc-burned b)])
                        [(assoc vm vid v) acc-burned]))
                    [{} 0]
                    (:vaults state))]
        {:ok? true
         :burned burned
         :state (-> state
                    (assoc :vaults vaults')
                    (update :sunset-custody-burned (fnil + 0) burned))
         :effects []}))))

(defn verify-7-bucket-conservation
  "Enforces the full 7-bucket 42B `INV-C1` conservation law:
   sum(liquid_ledger) + sum(escrows) + sum(bounty_escrows) + sum(vaults)
   + root_unallocated + total_burned + sunset_custody_burned
   == genesis_custody_supply + total_minted <= 42B."
  [state]
  (let [sum-bal (fn [m] (reduce + 0 (map (fn [[_ v]] (long (or (:balance v) (:amount v) 0))) (or m {}))))
        liquid (sum-bal (:ledger state))
        escrows (reduce + 0 (keep (fn [[_ e]] (when (= :locked (:status e)) (long (or (:amount e) 0)))) (or (:escrows state) {})))
        bounties (reduce + 0 (keep (fn [[_ b]]
                                     (when (#{:open :locked} (:status b))
                                       (long (or (:gross-amount b) (:reward-amount b) (:amount b) 0))))
                                   (or (:bounty-escrows state) {})))
        vaults (sum-bal (:vaults state))
        unalloc (long (or (:root-unallocated state) 0))
        burned (long (or (:total-burned state) 0))
        sunset (long (or (:sunset-custody-burned state) 0))
        lhs (+ liquid escrows bounties vaults unalloc burned sunset)
        rhs (+ (long (or (:genesis-custody-supply state) 0))
               (long (or (:total-minted state) 0)))]
    (cond
      (> rhs max-supply-cap-ech)
      {:ok? false :error :supply-cap-exceeded :lhs lhs :rhs rhs}

      (not= lhs rhs)
      {:ok? false :error :conservation-law-violated :lhs lhs :rhs rhs
       :buckets {:liquid liquid :escrows escrows :bounties bounties :vaults vaults
                 :root-unallocated unalloc :total-burned burned :sunset-custody-burned sunset}}

      :else
      {:ok? true :total-supply rhs})))
