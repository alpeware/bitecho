(ns bitecho.economy.spend-dac
  "Milestone D36 (`BIP-010: P-FAUCET-2`): On-Chain `:spend-dac` Allowance State (`A1` Economy-Layer Primitive).
   100% Pure Sans-IO `.cljc` Engine (Rule 2, Rule 4, Rule 5):
   - Preserves the settled 2026-11-10 invariant: admission DACs (`:type :admission-dac`) NEVER move money;
     `:spend-dac` is a distinct sibling credential type.
   - Enforces holder signature (never bearer), cap (`spent + amount + burn-fee <= cap`),
     expiry (`current-epoch < expiry-epoch`), and revocation (`not revoked?`).
   - Both transfers and signaling/settlement burns charge the allowance; fees come out of the allowance
     (fee-from-allowance), leaving zero dust in a fresh holder account.
   - Supports `A2 -> A1` migration (`migrate-a2-allowance-to-a1`) registering an outstanding `A2` allowance
     on-chain at its remaining cap attested by co-signed receipts."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def default-spend-dac-cap-ech
  "Default faucet / allowance cap: 1,000,000 ECH."
  1000000)

(def default-spend-dac-expiry-epochs
  "Default allowance validity window: 241,920 epochs (14 days at 5s epochs)."
  241920)

(def default-faucet-attestation-roots
  "Default FIDO MDS3 / WebAuthn hardware attestation roots config pointer schema
   (`config/faucet/attestation-roots.edn`, `BIP-010` / `P-FAUCET-2`).
   Rejects software/virtual authenticators and `fmt=\"none\"` in production."
  {:schema "bitecho.faucet.attestation-roots/v1"
   :pointer-path "config/faucet/attestation-roots.edn"
   :reject-fmt-none? true
   :reject-software-authenticators? true
   :roots
   {"yubico-u2f-root-ca"
    {:root-id "yubico-u2f-root-ca"
     :vendor "Yubico"
     :family "YubiKey 5 / Security Key NFC"
     :hardware-backed? true
     :allowed-aaguids #{"2fc0579f-8113-47ea-b116-bb5a8db9202a"
                        "cb69481e-8ff7-4039-93ec-0a2729a1e67d"
                        "ee882879-721c-4916-acfe-341a9c4021e1"}
     :allowed-fmts #{"packed" "fido-u2f"}}
    "google-titan-root-ca"
    {:root-id "google-titan-root-ca"
     :vendor "Google"
     :family "Google Titan Security Key"
     :hardware-backed? true
     :allowed-aaguids #{"42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3"}
     :allowed-fmts #{"packed" "fido-u2f"}}
    "apple-webauthn-root-ca"
    {:root-id "apple-webauthn-root-ca"
     :vendor "Apple"
     :family "Apple Secure Enclave / Touch ID / Face ID"
     :hardware-backed? true
     :allowed-aaguids #{"adce0002-35bc-c60a-648b-0b25f1f05503"}
     :allowed-fmts #{"packed" "apple"}}
    "android-hardware-attestation-root-ca"
    {:root-id "android-hardware-attestation-root-ca"
     :vendor "Google / Android"
     :family "Android Hardware Key Attestation (TEE / StrongBox)"
     :hardware-backed? true
     :allowed-aaguids #{"b93fd961-f2e6-462f-b122-82002247de78"}
     :allowed-fmts #{"android-key" "packed"}}
    "microsoft-tpm20-root-ca"
    {:root-id "microsoft-tpm20-root-ca"
     :vendor "Microsoft"
     :family "Windows Hello TPM 2.0 Hardware-Backed"
     :hardware-backed? true
     :allowed-aaguids #{"9f727d30-6595-4809-baee-08879813b2c9"}
     :allowed-fmts #{"tpm" "packed"}}}})

(defn- normalize-pubkey-hex
  [pk]
  (when (and (string? pk) (not (str/blank? pk)))
    (let [clean (str/lower-case (str/trim pk))]
      (cond
        (= 88 (count clean)) clean
        (= 64 (count clean)) (str "302a300506032b6570032100" clean)
        :else clean))))

(defn canonical-spend-dac-signing-payload
  "Canonical domain-separated vector signed by the issuer of a `:spend-dac`."
  [{:keys [dac-id issuer holder cap issued-epoch expiry-epoch]}]
  ["bitecho-spend-dac-v1"
   (str dac-id)
   (or (normalize-pubkey-hex issuer) "")
   (or (normalize-pubkey-hex holder) "")
   (long (or cap default-spend-dac-cap-ech))
   (long (or issued-epoch 0))
   (long (or expiry-epoch default-spend-dac-expiry-epochs))])

(defn issue-spend-dac
  "Issues and signs a new `:spend-dac` credential record attributable to `issuer-pubkey`."
  [issuer-pubkey issuer-privkey {:keys [dac-id holder cap issued-epoch expiry-epoch spent]}]
  (let [norm-issuer (normalize-pubkey-hex issuer-pubkey)
        norm-holder (normalize-pubkey-hex holder)
        iss-ep (long (or issued-epoch 0))
        exp-ep (long (or expiry-epoch (+ iss-ep default-spend-dac-expiry-epochs)))
        cap-ech (long (or cap default-spend-dac-cap-ech))
        spent-ech (long (or spent 0))
        id (str (or dac-id
                    (str "spend-dac-"
                         (subs (str/lower-case
                                (basalt/bytes->hex
                                 (crypto/sha256
                                  (fressian/utf8->bytes (str norm-issuer "|" norm-holder "|" iss-ep "|" cap-ech)))))
                               0 16))))
        base {:dac-id id
              :type :spend-dac
              :issuer norm-issuer
              :holder norm-holder
              :cap cap-ech
              :issued-epoch iss-ep
              :expiry-epoch exp-ep
              :spent spent-ech
              :revoked? false}
        payload (canonical-spend-dac-signing-payload base)
        sig (crypto/sign-canonical issuer-privkey payload)
        sig-hex (str/lower-case (if (string? sig) sig (basalt/bytes->hex sig)))]
    (assoc base :signature sig-hex)))

(defn verify-spend-dac-signature
  "Verifies the issuer's Ed25519 signature on a `:spend-dac` record."
  [spend-dac]
  (if-not (and (map? spend-dac)
               (= :spend-dac (:type spend-dac))
               (string? (:issuer spend-dac))
               (string? (:holder spend-dac))
               (string? (:signature spend-dac)))
    false
    (let [issuer (normalize-pubkey-hex (:issuer spend-dac))
          sig (:signature spend-dac)
          payload (canonical-spend-dac-signing-payload spend-dac)]
      (boolean
       (try
         (crypto/verify-with-fallback
          (basalt/hex->bytes issuer)
          payload
          (basalt/hex->bytes sig))
         (catch #?(:clj Exception :cljs :default) _ false))))))

(defn canonical-spend-intent-signing-payload
  "Canonical domain-separated vector signed by the `:holder` of a `:spend-dac` for a `SpendIntent`."
  [{:keys [spend-dac-id dac-id holder recipient op amount burn-fee nonce]}]
  ["bitecho-spend-dac-intent-v1"
   (str (or spend-dac-id dac-id ""))
   (or (normalize-pubkey-hex holder) "")
   (or (normalize-pubkey-hex recipient) "")
   (name (or op :transfer))
   (long (or amount 0))
   (long (or burn-fee 0))
   (str (or nonce ""))])

(defn sign-spend-dac-intent
  "Signs a `SpendIntent` map with `holder-privkey`."
  [holder-privkey intent-map]
  (let [dac-id (or (:spend-dac-id intent-map) (:dac-id intent-map))
        norm-holder (normalize-pubkey-hex (:holder intent-map))
        norm-recip (normalize-pubkey-hex (:recipient intent-map))
        op (keyword (or (:op intent-map) :transfer))
        amt (long (or (:amount intent-map) 0))
        fee (long (or (:burn-fee intent-map) 0))
        nonce (str (or (:nonce intent-map) "0"))
        base (cond-> (assoc intent-map
                            :spend-dac-id dac-id
                            :dac-id dac-id
                            :holder norm-holder
                            :op op
                            :amount amt
                            :burn-fee fee
                            :nonce nonce)
               norm-recip (assoc :recipient norm-recip))
        payload (canonical-spend-intent-signing-payload base)
        sig (crypto/sign-canonical holder-privkey payload)
        sig-hex (str/lower-case (if (string? sig) sig (basalt/bytes->hex sig)))]
    (assoc base :sig sig-hex :signature sig-hex)))

(defn verify-spend-dac-intent-signature
  "Verifies that `spend-intent` is signed by `expected-holder-pubkey` (holder-key-bound, never bearer)."
  [spend-intent expected-holder-pubkey]
  (let [holder (normalize-pubkey-hex expected-holder-pubkey)
        intent-holder (normalize-pubkey-hex (:holder spend-intent))
        sig (or (:sig spend-intent) (:signature spend-intent))
        payload (canonical-spend-intent-signing-payload spend-intent)]
    (boolean
     (and (some? holder)
          (= holder intent-holder)
          (string? sig)
          (not (str/blank? sig))
          (try
            (crypto/verify-with-fallback
             (basalt/hex->bytes holder)
             payload
             (basalt/hex->bytes sig))
            (catch #?(:clj Exception :cljs :default) _ false))))))

(defn revoke-spend-dac
  "Revokes an existing `:spend-dac` on-chain attributable to `issuer-pubkey`, freezing further spends immediately."
  [ledger-state issuer-pubkey issuer-privkey dac-id epoch]
  (let [allowance (get-in ledger-state [:spend-dacs dac-id])
        norm-issuer (normalize-pubkey-hex issuer-pubkey)]
    (cond
      (nil? allowance)
      (let [diag {:effect :diagnose :type :diagnose :reason :allowance-not-found :dac-id dac-id}
            st' (update-in ledger-state [:diagnostics :spend-dac-rejected] (fnil inc 0))]
        {:ok? false :error :allowance-not-found :state st' :effects [diag]})

      (not= norm-issuer (normalize-pubkey-hex (:issuer allowance)))
      (let [diag {:effect :diagnose :type :diagnose :reason :unauthorized-spend-dac-revocation :dac-id dac-id}
            st' (update-in ledger-state [:diagnostics :spend-dac-rejected] (fnil inc 0))]
        {:ok? false :error :unauthorized-spend-dac-revocation :state st' :effects [diag]})

      :else
      (let [rev-payload ["bitecho-spend-dac-revoke-v1" (str dac-id) norm-issuer (long (or epoch 0))]
            rev-sig (when issuer-privkey
                      (let [s (crypto/sign-canonical issuer-privkey rev-payload)]
                        (str/lower-case (if (string? s) s (basalt/bytes->hex s)))))
            updated (assoc allowance
                           :revoked? true
                           :revoked-epoch (long (or epoch (:epoch ledger-state) 0))
                           :revocation-signature rev-sig)
            st' (assoc-in ledger-state [:spend-dacs dac-id] updated)]
        {:ok? true
         :spend-dac updated
         :state st'
         :effects []}))))

(defn validate-and-apply-spend-dac-debit
  "Pure validator/economy reducer (`BIP-010` / `P-FAUCET-2`, Rule 2, Rule 5):
   Validates `spend-event` against on-chain `[:spend-dacs dac-id]` and applies the debit:
   1. Allowance exists and `(= :spend-dac (:type allowance))` (admission DACs never move money!).
   2. Allowance is not revoked (`(not (:revoked? allowance))`).
   3. Current epoch is strictly before `:expiry-epoch` (`(< current-epoch (:expiry-epoch allowance))`).
   4. Holder signature on `spend-event` verifies against `(:holder allowance)` (holder-key-bound, not bearer).
   5. `(+ (:spent allowance) amount burn-fee) <= (:cap allowance)` (both transfer amounts and signaling/settlement burns charge the allowance; fees come out of the allowance leaving zero dust in the holder account).
   6. Issuer has sufficient liquid balance in `[:ledger issuer]` to cover `total-debit = (+ amount burn-fee)`.
   On any violation, refuses the spend, increments `[:diagnostics :spend-dac-rejected]`, and emits a counted `:diagnose`."
  [ledger-state spend-event]
  (let [dac-id (or (:spend-dac-id spend-event) (:dac-id spend-event))
        allowance (get-in ledger-state [:spend-dacs dac-id])
        cur-ep (long (or (:epoch spend-event) (:epoch ledger-state) 0))
        amount (long (or (:amount spend-event) 0))
        burn-fee (long (or (:burn-fee spend-event) 0))
        total-debit (+ amount burn-fee)
        op (keyword (or (:op spend-event) :transfer))
        reject (fn [reason]
                 (let [diag {:effect :diagnose
                             :type :diagnose
                             :reason reason
                             :dac-id dac-id
                             :epoch cur-ep}
                       st' (update-in ledger-state [:diagnostics :spend-dac-rejected] (fnil inc 0))]
                   {:ok? false
                    :error reason
                    :state st'
                    :effects [diag]}))]
    (cond
      (nil? allowance)
      (reject :allowance-not-found)

      (not= :spend-dac (:type allowance))
      (reject :not-a-spend-dac)

      (true? (:revoked? allowance))
      (reject :allowance-revoked)

      (>= cur-ep (long (:expiry-epoch allowance 0)))
      (reject :allowance-expired)

      (or (<= amount 0) (neg? burn-fee))
      (reject :invalid-spend-amount)

      (not (verify-spend-dac-intent-signature spend-event (:holder allowance)))
      (reject :invalid-holder-signature)

      (> (+ (long (:spent allowance 0)) total-debit) (long (:cap allowance 0)))
      (reject :allowance-cap-exceeded)

      :else
      (let [issuer-pk (normalize-pubkey-hex (:issuer allowance))
            issuer-acct (get-in ledger-state [:ledger issuer-pk])
            issuer-bal (long (or (:balance issuer-acct) 0))]
        (if (< issuer-bal total-debit)
          (reject :issuer-insufficient-liquid-balance)
          (let [new-spent (+ (long (:spent allowance 0)) total-debit)
                updated-allowance (assoc allowance :spent new-spent)
                new-issuer-acct (assoc (or issuer-acct (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                                       :balance (- issuer-bal total-debit))
                recip-pk (normalize-pubkey-hex (or (:recipient spend-event) (:holder allowance)))
                st1 (-> ledger-state
                        (assoc-in [:spend-dacs dac-id] updated-allowance)
                        (assoc-in [:ledger issuer-pk] new-issuer-acct)
                        (update-in [:epoch-burns cur-ep] (fnil + 0)
                                   (if (= op :burn-for-credit)
                                     total-debit
                                     burn-fee)))
                st2 (if (= op :transfer)
                      (let [r-acct (get-in st1 [:ledger recip-pk]
                                           (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                            new-r-acct (assoc r-acct :balance (+ (long (or (:balance r-acct) 0)) amount))]
                        (assoc-in st1 [:ledger recip-pk] new-r-acct))
                      (update-in st1 [:signaling-credits (:holder allowance)] (fnil + 0) amount))]
            {:ok? true
             :dac-id dac-id
             :total-debit total-debit
             :spent new-spent
             :remaining-cap (- (long (:cap allowance)) new-spent)
             :spend-dac updated-allowance
             :state st2
             :effects []}))))))

(defn canonical-a2-receipt-signing-payload
  "Canonical signing payload for an `A2` co-signed faucet spend receipt."
  [{:keys [receipt-id spend-dac-id issuer holder op amount burn-fee total-debit cumulative-spent epoch]}]
  ["bitecho-a2-spend-receipt-v1"
   (str receipt-id)
   (str spend-dac-id)
   (or (normalize-pubkey-hex issuer) "")
   (or (normalize-pubkey-hex holder) "")
   (name (or op :transfer))
   (long (or amount 0))
   (long (or burn-fee 0))
   (long (or total-debit (+ (long (or amount 0)) (long (or burn-fee 0)))))
   (long (or cumulative-spent 0))
   (long (or epoch 0))])

(defn verify-a2-co-signed-receipt
  "Verifies an `A2` co-signed receipt against `issuer-pubkey`."
  [receipt issuer-pubkey]
  (let [norm-issuer (normalize-pubkey-hex issuer-pubkey)
        sig (:issuer-signature receipt)
        payload (canonical-a2-receipt-signing-payload receipt)]
    (boolean
     (and (map? receipt)
          (some? norm-issuer)
          (string? sig)
          (try
            (crypto/verify-with-fallback
             (basalt/hex->bytes norm-issuer)
             payload
             (basalt/hex->bytes sig))
            (catch #?(:clj Exception :cljs :default) _ false))))))

(defn migrate-a2-allowance-to-a1
  "Pure migration helper (`BIP-010` / `P-FAUCET-2` item 4, `S-D36-5`):
   Registers an outstanding `A2`-issued `:spend-dac` on-chain into `[:spend-dacs dac-id]`
   with its `:spent` attested by the faucet's published `co-signed-receipts`.
   Once registered on-chain, post-migration spends validate natively via `validate-and-apply-spend-dac-debit`
   without requiring the faucet service to be online."
  [ledger-state a2-allowance co-signed-receipts current-epoch]
  (let [dac-id (:dac-id a2-allowance)
        issuer-pk (normalize-pubkey-hex (:issuer a2-allowance))
        cap (long (or (:cap a2-allowance) 0))
        exp-ep (long (or (:expiry-epoch a2-allowance) 0))
        cur-ep (long (or current-epoch (:epoch ledger-state) 0))
        sig-ok? (verify-spend-dac-signature a2-allowance)
        receipts-vec (vec (or co-signed-receipts []))
        receipts-valid? (every? #(and (= dac-id (:spend-dac-id %))
                                      (verify-a2-co-signed-receipt % issuer-pk))
                                receipts-vec)
        attested-spent (if (seq receipts-vec)
                         (long (apply max (cons (long (or (:spent a2-allowance) 0))
                                                (map #(long (or (:cumulative-spent %) 0)) receipts-vec))))
                         (long (or (:spent a2-allowance) 0)))]
    (cond
      (not sig-ok?)
      (let [diag {:effect :diagnose :type :diagnose :reason :invalid-a2-allowance-signature :dac-id dac-id}
            st' (update-in ledger-state [:diagnostics :spend-dac-migration-rejected] (fnil inc 0))]
        {:ok? false :error :invalid-a2-allowance-signature :state st' :effects [diag]})

      (not receipts-valid?)
      (let [diag {:effect :diagnose :type :diagnose :reason :invalid-a2-co-signed-receipt :dac-id dac-id}
            st' (update-in ledger-state [:diagnostics :spend-dac-migration-rejected] (fnil inc 0))]
        {:ok? false :error :invalid-a2-co-signed-receipt :state st' :effects [diag]})

      (or (>= cur-ep exp-ep) (> attested-spent cap))
      (let [diag {:effect :diagnose :type :diagnose :reason :expired-or-exhausted-a2-allowance :dac-id dac-id}
            st' (update-in ledger-state [:diagnostics :spend-dac-migration-rejected] (fnil inc 0))]
        {:ok? false :error :expired-or-exhausted-a2-allowance :state st' :effects [diag]})

      :else
      (let [a1-record (assoc a2-allowance
                             :type :spend-dac
                             :spent attested-spent
                             :migrated-from-a2? true
                             :migrated-at-epoch cur-ep)
            st' (assoc-in ledger-state [:spend-dacs dac-id] a1-record)]
        {:ok? true
         :dac-id dac-id
         :spent attested-spent
         :remaining-cap (- cap attested-spent)
         :spend-dac a1-record
         :state st'
         :effects []}))))
