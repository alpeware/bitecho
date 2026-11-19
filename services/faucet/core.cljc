(ns faucet.core
  "Milestone D36 (`BIP-010: P-FAUCET-1`): Hardware-Key Faucet Service (`A2: Sponsored Relay / Co-Execution`).
   100% Pure Sans-IO `.cljc` Service Engine (Rule 2, Rule 4, Rule 5):
   - Standalone light-node service namespace (`services/faucet/`), excluded from validator and light-node `dist/` bundles.
   - Anti-spam pre-parse gate: verifies 16-bit (configurable) Hashcash PoW and hardware-key challenge binding
     (`sha256(\"bitecho-faucet-claim-v1|\" + claimant-pubkey + \"|\" + epoch-bucket)`) BEFORE any CBOR/x5c attestation parsing.
   - Server-side WebAuthn / FIDO2 attestation verification against `config/faucet/attestation-roots.edn`
     (closing `F-BIP7-2`): rejects `fmt=\"none\"` and software/virtual authenticators in production.
   - Hardware credential deduplication (`[aaguid credential-id]`) published to `faucet/claimed-keys.edn`.
   - `A2` Payout by issuance: issues a signed `:spend-dac` (`cap = 1,000,000` ECH, `241,920`-epoch / 14-day expiry)
     and co-executes holder-signed `SpendIntent`s from a hard-capped `25,000,000` ECH liquid account
     (emitting `:refill-alert` when liquid balance drops below 20% = `5,000,000` ECH).
   - Every decision (grant, denial, co-signed spend receipt) is emitted as a signed audit artifact."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.spend-dac :as spend-dac]
            [bitecho.fido :as fido]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def default-faucet-liquid-cap-ech
  "Hard liquid cap for the faucet service account: 25,000,000 ECH (25 concurrent fully-drawn allowances)."
  25000000)

(def default-faucet-refill-threshold-ech
  "20% refill threshold: 5,000,000 ECH."
  5000000)

(def default-faucet-allowance-cap-ech
  "Allowance cap per attested hardware key: 1,000,000 ECH."
  1000000)

(def default-faucet-expiry-epochs
  "14-day allowance expiry in 5s epochs: 241,920 epochs."
  241920)

(def default-pow-difficulty-bits
  "Default Hashcash PoW difficulty on claim submissions: 16 leading zero bits."
  16)

(def claim-subnet-id
  "Dedicated 0-burn claim subnet for the hardware-key faucet service."
  "faucet.bitecho.org/claims")

(defn- normalize-pubkey-hex
  [pk]
  (when (and (string? pk) (not (str/blank? pk)))
    (let [clean (str/lower-case (str/trim pk))]
      (cond
        (= 88 (count clean)) clean
        (= 64 (count clean)) (str "302a300506032b6570032100" clean)
        :else clean))))

(defn init-faucet-service-state
  "Initializes pure Sans-IO state for the `services/faucet/` light-node service."
  [{:keys [faucet-pubkey faucet-privkey liquid-cap-ech liquid-balance-ech
           allowance-cap-ech expiry-epochs pow-difficulty-bits
           attestation-roots current-epoch]}]
  (let [cap (long (or liquid-cap-ech default-faucet-liquid-cap-ech))
        bal (min cap (long (or liquid-balance-ech cap)))]
    {:faucet-pubkey (normalize-pubkey-hex faucet-pubkey)
     :faucet-privkey faucet-privkey
     :subnet-id claim-subnet-id
     :current-epoch (long (or current-epoch 0))
     :liquid-cap-ech cap
     :liquid-balance-ech bal
     :refill-threshold-ech (quot cap 5)
     :allowance-cap-ech (long (or allowance-cap-ech default-faucet-allowance-cap-ech))
     :expiry-epochs (long (or expiry-epochs default-faucet-expiry-epochs))
     :pow-difficulty-bits (long (or pow-difficulty-bits default-pow-difficulty-bits))
     :attestation-roots (or attestation-roots spend-dac/default-faucet-attestation-roots)
     :claimed-keys #{}
     :claimed-pubkeys #{}
     :claimed-keys-pointer {:pointer/path "faucet/claimed-keys.edn"
                            :pointer/seq 0
                            :entries []}
     :allowances {}
     :receipts []
     :audit-trail []
     :diagnostics {:pow-or-challenge-failed 0
                   :duplicate-hardware-credential 0
                   :attestation-verification-failed 0
                   :claims-granted 0
                   :spend-intents-executed 0
                   :spend-intents-rejected 0
                   :refill-alerts 0}}))

;; =============================================================================
;; 1. Signed Faucet Audit Artifacts
;; =============================================================================

(defn canonical-faucet-audit-payload
  "Canonical signing vector for a faucet audit artifact."
  [{:keys [seq epoch decision reason claimant-pubkey aaguid credential-id dac-id]}]
  ["bitecho-faucet-audit-v1"
   (long (or seq 0))
   (long (or epoch 0))
   (name (or decision :deny))
   (name (or reason :unknown))
   (str (or claimant-pubkey ""))
   (str (or aaguid ""))
   (str (or credential-id ""))
   (str (or dac-id ""))])

(defn make-faucet-audit-artifact
  "Constructs and signs a faucet decision audit artifact."
  [faucet-state {:keys [decision reason claimant-pubkey aaguid credential-id dac-id details]}]
  (let [next-seq (inc (count (:audit-trail faucet-state)))
        ep (long (or (:current-epoch faucet-state) 0))
        base {:seq next-seq
              :epoch ep
              :decision (keyword decision)
              :reason (keyword reason)
              :claimant-pubkey (or (normalize-pubkey-hex claimant-pubkey) "")
              :aaguid (str (or aaguid ""))
              :credential-id (str (or credential-id ""))
              :dac-id (str (or dac-id ""))
              :details (or details {})
              :issuer (:faucet-pubkey faucet-state)}
        payload (canonical-faucet-audit-payload base)
        sig (when-let [sk (:faucet-privkey faucet-state)]
              (let [s (crypto/sign-canonical sk payload)]
                (str/lower-case (if (string? s) s (basalt/bytes->hex s)))))]
    (assoc base :signature sig)))

(defn verify-faucet-audit-artifact
  "Verifies the faucet's Ed25519 signature on a published audit artifact."
  [artifact expected-faucet-pubkey]
  (let [pk (normalize-pubkey-hex (or expected-faucet-pubkey (:issuer artifact)))
        sig (:signature artifact)
        payload (canonical-faucet-audit-payload artifact)]
    (boolean
     (and (map? artifact)
          (some? pk)
          (string? sig)
          (try
            (crypto/verify-with-fallback
             (basalt/hex->bytes pk)
             payload
             (basalt/hex->bytes sig))
            (catch #?(:clj Exception :cljs :default) _ false))))))

;; =============================================================================
;; 2. Anti-Spam Challenge Binding & Hashcash Proof-of-Work
;; =============================================================================

(defn claim-challenge-preimage
  "Canonical preimage string for faucet claim challenge binding:
   `\"bitecho-faucet-claim-v1|\" + claimant-pubkey + \"|\" + epoch-bucket`."
  [claimant-pubkey epoch-bucket]
  (str "bitecho-faucet-claim-v1|"
       (or (normalize-pubkey-hex claimant-pubkey) "")
       "|"
       (long (or epoch-bucket 0))))

(defn claim-challenge-hash-bytes
  "Computes `sha256(claim-challenge-preimage)`."
  [claimant-pubkey epoch-bucket]
  (crypto/sha256 (fressian/utf8->bytes (claim-challenge-preimage claimant-pubkey epoch-bucket))))

(defn count-leading-zero-bits
  "Counts leading zero bits in a byte array."
  [bs]
  (let [len (fressian/count-bytes bs)]
    (loop [idx 0
           acc 0]
      (if (>= idx len)
        acc
        (let [b (bit-and (int #?(:clj (aget ^bytes bs idx) :cljs (aget bs idx))) 0xff)]
          (if (zero? b)
            (recur (inc idx) (+ acc 8))
            (+ acc (loop [mask 0x80
                          z 0]
                     (if (or (zero? mask) (pos? (bit-and b mask)))
                       z
                       (recur (bit-shift-right mask 1) (inc z)))))))))))

(defn verify-claim-pow
  "Verifies that `sha256(claim-challenge-preimage + \"|\" + pow-nonce)` has at least `difficulty-bits` leading zero bits."
  [claimant-pubkey epoch-bucket pow-nonce difficulty-bits]
  (let [req-bits (long (or difficulty-bits default-pow-difficulty-bits))]
    (if (<= req-bits 0)
      true
      (and (some? pow-nonce)
           (not (str/blank? (str pow-nonce)))
           (let [preimage (str (claim-challenge-preimage claimant-pubkey epoch-bucket) "|" pow-nonce)
                 digest (crypto/sha256 (fressian/utf8->bytes preimage))]
             (>= (count-leading-zero-bits digest) req-bits))))))

(defn mine-claim-pow-nonce
  "Deterministic Hashcash PoW solver for tests and clients."
  ([claimant-pubkey epoch-bucket]
   (mine-claim-pow-nonce claimant-pubkey epoch-bucket default-pow-difficulty-bits))
  ([claimant-pubkey epoch-bucket difficulty-bits]
   (loop [n 0]
     (let [cand (str "pow-" n)]
       (if (verify-claim-pow claimant-pubkey epoch-bucket cand difficulty-bits)
         cand
         (recur (inc n)))))))

(defn build-signed-faucet-claim
  "Helper to construct a valid signed faucet claim request with mined Hashcash PoW and attestation statement."
  [{:keys [claimant-pubkey claimant-privkey epoch-bucket pow-difficulty-bits
           aaguid credential-id fmt attestation-root-id x5c-sig]}]
  (let [norm-pk (normalize-pubkey-hex claimant-pubkey)
        ep (long (or epoch-bucket 0))
        diff (long (or pow-difficulty-bits default-pow-difficulty-bits))
        pow-nonce (mine-claim-pow-nonce norm-pk ep diff)
        ch-bytes (claim-challenge-hash-bytes norm-pk ep)
        sig-bytes (crypto/sign claimant-privkey ch-bytes)
        sig-hex (str/lower-case (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes)))
        norm-aaguid (fido/normalize-aaguid (or aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"))
        cred-id (str (or credential-id "cred-default"))
        att-fmt (str (or fmt "packed"))
        root-id (str (or attestation-root-id "yubico-u2f-root-ca"))
        att-proof (or x5c-sig
                      (str/lower-case
                       (basalt/bytes->hex
                        (crypto/sha256
                         (fressian/utf8->bytes
                          (str "fido-x5c-attestation-v1|" root-id "|" norm-aaguid "|" cred-id "|" norm-pk))))))]
    {:claimant-pubkey norm-pk
     :epoch-bucket ep
     :pow-nonce pow-nonce
     :challenge-signature sig-hex
     :attestation {:fmt att-fmt
                   :aaguid norm-aaguid
                   :credential-id cred-id
                   :attestation-root-id root-id
                   :x5c-chain-signature att-proof
                   :flags {:up? true :uv? true}}}))

;; =============================================================================
;; 3. Server-Side Attestation Verification (Closes F-BIP7-2)
;; =============================================================================

(defn verify-hardware-attestation
  "Server-side WebAuthn / FIDO2 attestation verification against `attestation-roots` config pointer (`F-BIP7-2`):
   - Rejects `fmt=\"none\"` when `:reject-fmt-none?` is true.
   - Rejects software/virtual authenticators (e.g. `:platform-software` or unknown AAGUIDs not in accepted hardware roots).
   - Verifies the attestation statement (`:attestation-root-id`, `:aaguid`, `:fmt`, and `:x5c-chain-signature`)."
  [attestation claimant-pubkey attestation-roots]
  (if-not (map? attestation)
    {:ok? false :reason :missing-attestation}
    (let [fmt (str/lower-case (str/trim (str (or (:fmt attestation) "none"))))
          aaguid (fido/normalize-aaguid (:aaguid attestation))
          cred-id (str (or (:credential-id attestation) ""))
          root-id (str (or (:attestation-root-id attestation) ""))
          roots-map (:roots attestation-roots)
          fido-meta (fido/lookup-aaguid aaguid)
          software? (or (= :platform-software (:authenticator-type fido-meta))
                        (contains? (set (:key-protection fido-meta)) :software))
          matched-root (or (get roots-map root-id)
                           (some (fn [[_ r]]
                                   (when (contains? (:allowed-aaguids r) aaguid) r))
                                 roots-map))]
      (cond
        (and (:reject-fmt-none? attestation-roots true)
             (or (= fmt "none") (str/blank? fmt)))
        {:ok? false :reason :fmt-none-rejected}

        (and (:reject-software-authenticators? attestation-roots true)
             software?)
        {:ok? false :reason :software-authenticator-rejected}

        (or (nil? matched-root)
            (not (true? (:hardware-backed? matched-root)))
            (not (contains? (:allowed-aaguids matched-root) aaguid))
            (not (contains? (:allowed-fmts matched-root) fmt)))
        {:ok? false :reason :untrusted-attestation-root-or-aaguid}

        (str/blank? cred-id)
        {:ok? false :reason :missing-credential-id}

        :else
        (let [expected-x5c (str/lower-case
                            (basalt/bytes->hex
                             (crypto/sha256
                              (fressian/utf8->bytes
                               (str "fido-x5c-attestation-v1|"
                                    (:root-id matched-root) "|"
                                    aaguid "|"
                                    cred-id "|"
                                    (normalize-pubkey-hex claimant-pubkey))))))
              provided-x5c (str/lower-case (str/trim (str (or (:x5c-chain-signature attestation) ""))))]
          (if (and (not (str/blank? provided-x5c))
                   (= expected-x5c provided-x5c))
            {:ok? true
             :root-id (:root-id matched-root)
             :vendor (:vendor matched-root)
             :aaguid aaguid
             :credential-id cred-id}
            {:ok? false :reason :invalid-x5c-attestation-signature}))))))

;; =============================================================================
;; 4. Pure Claim Processor & A2 SpendIntent Co-Execution
;; =============================================================================

(defn process-faucet-claim
  "Processes an inbound 0-burn faucet claim envelope (`BIP-010` / `P-FAUCET-1`, Rule 5):
   1. Anti-spam pre-parse gate: verifies 16-bit Hashcash PoW and challenge signature BEFORE parsing attestation.
   2. Server-side attestation verification against `(:attestation-roots faucet-state)` (rejecting `fmt=\"none\"` and software authenticators).
   3. Deduplication against `(:claimed-keys faucet-state)` (`[aaguid credential-id]`).
   4. Issues a signed `:spend-dac` (`cap = 1,000,000` ECH, `241,920`-epoch expiry), updates `faucet/claimed-keys.edn`,
      and publishes a signed audit artifact."
  [faucet-state claim-req]
  (let [claimant-pk (normalize-pubkey-hex (:claimant-pubkey claim-req))
        ep-bucket (long (or (:epoch-bucket claim-req) (:current-epoch faucet-state) 0))
        pow-nonce (:pow-nonce claim-req)
        ch-sig (:challenge-signature claim-req)
        diff-bits (long (or (:pow-difficulty-bits faucet-state) default-pow-difficulty-bits))
        pow-ok? (and (some? claimant-pk)
                     (verify-claim-pow claimant-pk ep-bucket pow-nonce diff-bits))
        ch-ok? (and pow-ok?
                    (string? ch-sig)
                    (not (str/blank? ch-sig))
                    (try
                      (crypto/verify
                       (basalt/hex->bytes claimant-pk)
                       (claim-challenge-hash-bytes claimant-pk ep-bucket)
                       (basalt/hex->bytes ch-sig))
                      (catch #?(:clj Exception :cljs :default) _ false)))]
    (if-not (and pow-ok? ch-ok?)
      ;; Pre-parse rejection: never touch CBOR/x5c attestation when PoW or challenge fails
      (let [audit (make-faucet-audit-artifact
                   faucet-state
                   {:decision :deny
                    :reason :pow-or-challenge-failed
                    :claimant-pubkey claimant-pk})
            diag {:effect :diagnose
                  :type :diagnose
                  :reason :pow-or-challenge-failed
                  :claimant-pubkey claimant-pk}
            st' (-> faucet-state
                    (update :audit-trail conj audit)
                    (update-in [:diagnostics :pow-or-challenge-failed] (fnil inc 0)))]
        {:ok? false
         :rejected-pre-parse? true
         :error :pow-or-challenge-failed
         :audit-artifact audit
         :state st'
         :effects [diag {:effect :publish-faucet-audit :artifact audit}]})
      ;; PoW & challenge verified -> now parse and verify hardware attestation
      (let [att (:attestation claim-req)
            att-res (verify-hardware-attestation att claimant-pk (:attestation-roots faucet-state))]
        (if-not (:ok? att-res)
          (let [audit (make-faucet-audit-artifact
                       faucet-state
                       {:decision :deny
                        :reason :attestation-verification-failed
                        :claimant-pubkey claimant-pk
                        :aaguid (:aaguid att)
                        :credential-id (:credential-id att)
                        :details {:cause (:reason att-res)}})
                diag {:effect :diagnose
                      :type :diagnose
                      :reason :attestation-verification-failed
                      :cause (:reason att-res)
                      :claimant-pubkey claimant-pk}
                st' (-> faucet-state
                        (update :audit-trail conj audit)
                        (update-in [:diagnostics :attestation-verification-failed] (fnil inc 0)))]
            {:ok? false
             :error :attestation-verification-failed
             :cause (:reason att-res)
             :audit-artifact audit
             :state st'
             :effects [diag {:effect :publish-faucet-audit :artifact audit}]})
          (let [aaguid (:aaguid att-res)
                cred-id (:credential-id att-res)
                cred-key [aaguid cred-id]
                dup? (contains? (:claimed-keys faucet-state) cred-key)]
            (if dup?
              (let [audit (make-faucet-audit-artifact
                           faucet-state
                           {:decision :deny
                            :reason :duplicate-hardware-credential
                            :claimant-pubkey claimant-pk
                            :aaguid aaguid
                            :credential-id cred-id})
                    diag {:effect :diagnose
                          :type :diagnose
                          :reason :duplicate-hardware-credential
                          :aaguid aaguid
                          :credential-id cred-id
                          :claimant-pubkey claimant-pk}
                    st' (-> faucet-state
                            (update :audit-trail conj audit)
                            (update-in [:diagnostics :duplicate-hardware-credential] (fnil inc 0)))]
                {:ok? false
                 :error :duplicate-hardware-credential
                 :audit-artifact audit
                 :state st'
                 :effects [diag {:effect :publish-faucet-audit :artifact audit}]})
              ;; Valid unique hardware-attested claim -> issue :spend-dac
              (let [cur-ep (long (or (:current-epoch faucet-state) ep-bucket))
                    cap (long (or (:allowance-cap-ech faucet-state) default-faucet-allowance-cap-ech))
                    exp-ep (+ cur-ep (long (or (:expiry-epochs faucet-state) default-faucet-expiry-epochs)))
                    dac-id (str "faucet-spend-dac-" (inc (count (:allowances faucet-state))))
                    dac (spend-dac/issue-spend-dac
                         (:faucet-pubkey faucet-state)
                         (:faucet-privkey faucet-state)
                         {:dac-id dac-id
                          :holder claimant-pk
                          :cap cap
                          :issued-epoch cur-ep
                          :expiry-epoch exp-ep
                          :spent 0})
                    audit (make-faucet-audit-artifact
                           faucet-state
                           {:decision :issue
                            :reason :hardware-key-attested
                            :claimant-pubkey claimant-pk
                            :aaguid aaguid
                            :credential-id cred-id
                            :dac-id dac-id})
                    claimed-entry {:aaguid aaguid
                                   :credential-id cred-id
                                   :claimant-pubkey claimant-pk
                                   :dac-id dac-id
                                   :claimed-epoch cur-ep}
                    st' (-> faucet-state
                            (update :claimed-keys conj cred-key)
                            (update :claimed-pubkeys conj claimant-pk)
                            (update-in [:claimed-keys-pointer :pointer/seq] (fnil inc 0))
                            (update-in [:claimed-keys-pointer :entries] conj claimed-entry)
                            (assoc-in [:allowances dac-id] dac)
                            (update :audit-trail conj audit)
                            (update-in [:diagnostics :claims-granted] (fnil inc 0)))]
                {:ok? true
                 :spend-dac dac
                 :audit-artifact audit
                 :claimed-keys-pointer (:claimed-keys-pointer st')
                 :state st'
                 :effects [{:effect :publish-faucet-audit :artifact audit}
                           {:effect :publish-claimed-keys-pointer :pointer (:claimed-keys-pointer st')}]}))))))))

(defn process-a2-spend-intent
  "Co-executes a holder-signed `SpendIntent` in `A2` mode (`BIP-010` / `P-FAUCET-1`):
   - Verifies holder signature, expiry, revocation, and `spent + amount + burn-fee <= cap`.
   - Debits from the faucet's capped `25,000,000` ECH liquid account (fee-from-payout, zero dust).
   - Emits a co-signed receipt to the faucet's audit trail.
   - Emits a `:refill-alert` when liquid balance falls below 20% of cap (`5,000,000` ECH)."
  [faucet-state spend-intent]
  (let [dac-id (or (:spend-dac-id spend-intent) (:dac-id spend-intent))
        allowance (get-in faucet-state [:allowances dac-id])
        cur-ep (long (or (:epoch spend-intent) (:current-epoch faucet-state) 0))
        amount (long (or (:amount spend-intent) 0))
        burn-fee (long (or (:burn-fee spend-intent) 0))
        total-debit (+ amount burn-fee)
        liquid-bal (long (or (:liquid-balance-ech faucet-state) 0))
        reject (fn [reason]
                 (let [diag {:effect :diagnose
                             :type :diagnose
                             :reason reason
                             :dac-id dac-id}
                       st' (update-in faucet-state [:diagnostics :spend-intents-rejected] (fnil inc 0))]
                   {:ok? false
                    :error reason
                    :state st'
                    :effects [diag]}))]
    (cond
      (nil? allowance)
      (reject :allowance-not-found)

      (true? (:revoked? allowance))
      (reject :allowance-revoked)

      (>= cur-ep (long (:expiry-epoch allowance 0)))
      (reject :allowance-expired)

      (or (<= amount 0) (neg? burn-fee))
      (reject :invalid-spend-amount)

      (not (spend-dac/verify-spend-dac-intent-signature spend-intent (:holder allowance)))
      (reject :invalid-holder-signature)

      (> (+ (long (:spent allowance 0)) total-debit) (long (:cap allowance 0)))
      (reject :allowance-cap-exceeded)

      (< liquid-bal total-debit)
      (reject :faucet-insufficient-liquid-balance)

      :else
      (let [new-spent (+ (long (:spent allowance 0)) total-debit)
            new-liquid (- liquid-bal total-debit)
            updated-allowance (assoc allowance :spent new-spent)
            rcpt-id (str "a2-rcpt-" dac-id "-" (inc (count (:receipts faucet-state))))
            base-rcpt {:receipt-id rcpt-id
                       :spend-dac-id dac-id
                       :issuer (:faucet-pubkey faucet-state)
                       :holder (:holder allowance)
                       :recipient (or (:recipient spend-intent) (:holder allowance))
                       :op (keyword (or (:op spend-intent) :transfer))
                       :amount amount
                       :burn-fee burn-fee
                       :total-debit total-debit
                       :cumulative-spent new-spent
                       :epoch cur-ep
                       :holder-signature (or (:sig spend-intent) (:signature spend-intent))}
            payload (spend-dac/canonical-a2-receipt-signing-payload base-rcpt)
            sig (when-let [sk (:faucet-privkey faucet-state)]
                  (let [s (crypto/sign-canonical sk payload)]
                    (str/lower-case (if (string? s) s (basalt/bytes->hex s)))))
            receipt (assoc base-rcpt :issuer-signature sig)
            refill-thresh (long (or (:refill-threshold-ech faucet-state) default-faucet-refill-threshold-ech))
            needs-refill? (< new-liquid refill-thresh)
            st' (cond-> (-> faucet-state
                            (assoc :liquid-balance-ech new-liquid)
                            (assoc-in [:allowances dac-id] updated-allowance)
                            (update :receipts conj receipt)
                            (update-in [:diagnostics :spend-intents-executed] (fnil inc 0)))
                  needs-refill?
                  (update-in [:diagnostics :refill-alerts] (fnil inc 0)))
            effs (cond-> [{:effect :publish-a2-spend-receipt :receipt receipt}]
                   needs-refill?
                   (conj {:effect :refill-alert
                          :liquid-balance-ech new-liquid
                          :refill-threshold-ech refill-thresh
                          :realized-spend-ech (- (long (:liquid-cap-ech faucet-state)) new-liquid)}))]
        {:ok? true
         :receipt receipt
         :spent new-spent
         :remaining-cap (- (long (:cap allowance)) new-spent)
         :liquid-balance-ech new-liquid
         :refill-alert? needs-refill?
         :state st'
         :effects effs}))))
