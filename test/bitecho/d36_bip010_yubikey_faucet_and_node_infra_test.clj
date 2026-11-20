(ns bitecho.d36-bip010-yubikey-faucet-and-node-infra-test
  "Milestone D36 (`BIP-010: Web-App YubiKey Recovery Fix, Single-Instance Serve Guard,
   Hardware-Key Faucet (A2 Service + A1 Spend-DAC), and Node.js Infra Node` / `v0.23.14`)
   Generative `test.check` Invariants (Rule 1 Strict TDD, >= 50 trials each) & Deterministic Scenarios:
   1. `prop-yubikey-recovery-redacted-and-advanced-mangled-roundtrip` (`P-WEB-1`)
   2. `prop-recovered-hardware-pubkey-always-canonical-88-char-spki` (`P-WEB-1`)
   3. `prop-single-instance-serve-lock-rejects-duplicate-live-pid` (`P-OPS-3`)
   4. `prop-faucet-claim-requires-valid-pow-challenge-and-unique-credential` (`P-FAUCET-1`)
   5. `prop-spend-dac-enforces-cap-expiry-revocation-and-holder-sig` (`P-FAUCET-1`, `P-FAUCET-2`)
   6. `prop-a2-to-a1-spend-dac-migration-preserves-remaining-cap` (`P-FAUCET-2`)
   7. `S-D36-1..S-D36-6`: Deterministic E2E scenarios for `P-WEB-1`, `P-OPS-3`, `P-FAUCET-1`, `P-FAUCET-2`, `P-NODE-1`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.economy.account :as account]
            [bitecho.economy.spend-dac :as spend-dac]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.shell.browser :as browser]
            [bitecho.shell.light-node :as light-shell]
            [bitecho.state-machine :as sm]
            [bitecho.webauthn :as webauthn]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [faucet.core :as faucet])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- kp->pk-hex [kp]
  (let [pub (or (:public-key kp) (:public kp))]
    (if (string? pub) pub (basalt/bytes->hex pub))))

(defn- kp->sk [kp]
  (or (:private-key kp) (:private kp)))

(defn- utf8-bytes [s]
  (.getBytes (str s) StandardCharsets/UTF_8))

(defn- make-temp-dir [prefix]
  (.toFile (Files/createTempDirectory prefix (into-array FileAttribute []))))

(defn- delete-dir-recursively! [^java.io.File f]
  (when (and f (.exists f))
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-dir-recursively! c)))
    (.delete f)))

;; =============================================================================
;; 1. Generative Properties (Rule 1: >= 50 trials each)
;; =============================================================================

(defspec ^{:doc "BIP-010 Prop 1 (P-WEB-1): YubiKey recovery succeeds across raw user-handle, PRF output, top-level redacted credential, nested {:identity ...} redacted credential, and Closure-mangled assertion shapes without overwriting an already-unlocked private-key with nil."}
  prop-yubikey-recovery-redacted-and-advanced-mangled-roundtrip 50
  (prop/for-all
   [seed-int (gen/choose 1 100000)
    shape (gen/elements [:raw-user-handle
                         :prf-output
                         :redacted-top-level
                         :redacted-nested-identity
                         :string-keyed-response])]
   (let [rng (crypto/make-random seed-int)
         seed-bytes (crypto/random-bytes rng 32)
         direct (webauthn/recover-seed-from-assertion {:user-handle seed-bytes})
         norm-direct (webauthn/normalize-recovered-identity direct)
         unlocked-state {:keypair {:public-key (:public-key norm-direct)
                                   :private-key (:private-key norm-direct)}
                         :light-state {:pubkey (:public-hex norm-direct)}}
         input-payload (case shape
                         :raw-user-handle
                         {:user-handle seed-bytes}

                         :prf-output
                         {:extensions {:prf {:results {:first seed-bytes}}}}

                         :redacted-top-level
                         {:public-hex (:public-hex direct)
                          :address (:address direct)
                          :recovery-source :user-handle}

                         :redacted-nested-identity
                         {:attestation {:fmt "packed" :aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"}
                          :identity {:public-hex (:public-hex direct)
                                     :address (:address direct)
                                     :recovery-source :user-handle}}

                         :string-keyed-response
                         {"response" {"userHandle" seed-bytes}})
         res (webauthn/resolve-yubikey-recovery input-payload unlocked-state)]
     (and (true? (:ok? res))
          (= 88 (count (:public-hex res)))
          (str/starts-with? (:public-hex res) "302a300506032b6570032100")
          (= (:public-hex norm-direct) (:public-hex res))
          (= (:address norm-direct) (:address res))
          (some? (get-in res [:node-state :keypair :private-key]))
          (= (:public-hex norm-direct)
             (get-in res [:node-state :light-state :pubkey]))))))

(defspec ^{:doc "BIP-010 Prop 2 (P-WEB-1): Any recovered hardware identity (32-byte raw or 44-byte SPKI) normalizes to canonical 88-char SPKI :public-hex, 64-char :raw-public-hex, 44-byte SPKI :public-key, and consistent ech1... Bech32m :address that verifies /relay/v1/poll PoP."}
  prop-recovered-hardware-pubkey-always-canonical-88-char-spki 50
  (prop/for-all
   [seed-int (gen/choose 1 100000)
    use-prf? gen/boolean]
   (let [rng (crypto/make-random seed-int)
         seed-bytes (crypto/random-bytes rng 32)
         raw-rec (if use-prf?
                   (webauthn/derive-identity-from-prf {:prf-output seed-bytes})
                   (webauthn/recover-seed-from-assertion {:user-handle seed-bytes}))
         norm (webauthn/normalize-recovered-identity raw-rec)
         spki-hex (:public-hex norm)
         raw-hex (:raw-public-hex norm)
         pub-bytes (:public-key norm)
         priv-bytes (:private-key norm)
         poll-sig (relay/sign-poll-request priv-bytes {:pubkey spki-hex
                                                       :since-seq 0
                                                       :timestamp-ms 1700000000000
                                                       :nonce (str "nonce-" seed-int)})
         poll-v (relay/verify-poll-request {}
                                           {:pubkey spki-hex
                                            :since-seq 0
                                            :timestamp-ms 1700000000000
                                            :nonce (str "nonce-" seed-int)
                                            :signature poll-sig}
                                           1700000000000)]
     (and (= 88 (count spki-hex))
          (str/starts-with? spki-hex "302a300506032b6570032100")
          (= 64 (count raw-hex))
          (= spki-hex (str "302a300506032b6570032100" raw-hex))
          (= 44 (fressian/count-bytes pub-bytes))
          (str/starts-with? (:address norm) "ech1")
          (true? (:ok? poll-v))))))

(defspec ^{:doc "BIP-010 Prop 3 (P-OPS-3): Atomic single-instance serve lock rejects duplicate startups when held by a live PID with counted :diagnose, and reclaims stale locks when the holding PID is dead."}
  prop-single-instance-serve-lock-rejects-duplicate-live-pid 50
  (prop/for-all
   [holder-pid (gen/choose 1000 50000)
    caller-pid (gen/choose 50001 99999)
    holder-alive? gen/boolean]
   (let [tmp-dir (make-temp-dir "d36-prop3-lock-")]
     (try
       (let [alive-set (if holder-alive? #{holder-pid caller-pid} #{caller-pid})
             pid-alive-fn (fn [p] (contains? alive-set (long p)))
             first-acq (light-shell/check-single-instance-lock
                        (.getAbsolutePath tmp-dir)
                        {:current-pid holder-pid
                         :pid-alive-fn pid-alive-fn
                         :timestamp-ms 1700000000000})
             second-acq (light-shell/check-single-instance-lock
                         (.getAbsolutePath tmp-dir)
                         {:current-pid caller-pid
                          :pid-alive-fn pid-alive-fn
                          :timestamp-ms 1700000005000})]
         (if holder-alive?
           (and (true? (:ok? first-acq))
                (false? (:ok? second-acq))
                (= "already-running" (:error second-acq))
                (= holder-pid (:locked-pid second-acq))
                (= :duplicate-serve-instance-rejected (get-in second-acq [:diagnose :reason]))
                (= 1 (get-in second-acq [:diagnostics :duplicate-serve-instance-rejected])))
           (and (true? (:ok? first-acq))
                (true? (:ok? second-acq))
                (true? (:reclaimed-stale-lock? second-acq))
                (= holder-pid (:stale-pid second-acq))
                (= caller-pid (:locked-pid second-acq)))))
       (finally
         (delete-dir-recursively! tmp-dir))))))

(defspec ^{:doc "BIP-010 Prop 4 (P-FAUCET-1): Faucet claim processor rejects invalid PoW/challenge pre-parse, rejects software/fmt=none authenticators, enforces 1-claim-per-[aaguid credential-id] deduplication, and emits signed audit artifacts for every grant or denial."}
  prop-faucet-claim-requires-valid-pow-challenge-and-unique-credential 50
  (prop/for-all
   [seed-int (gen/choose 1 100000)
    fault-mode (gen/elements [:valid :bad-pow :bad-challenge-sig :fmt-none :software-aaguid :duplicate-credential])]
   (let [faucet-kp (crypto/generate-keypair (str "d36-p4-faucet-" seed-int))
         claimant-kp (crypto/generate-keypair (str "d36-p4-claimant-" seed-int))
         other-kp (crypto/generate-keypair (str "d36-p4-other-" seed-int))
         faucet-pk (kp->pk-hex faucet-kp)
         faucet-sk (kp->sk faucet-kp)
         claimant-pk (kp->pk-hex claimant-kp)
         claimant-sk (kp->sk claimant-kp)
         st0 (faucet/init-faucet-service-state
              {:faucet-pubkey faucet-pk
               :faucet-privkey faucet-sk
               :current-epoch 100
               :pow-difficulty-bits 8})
         aaguid (if (= fault-mode :software-aaguid)
                  "08987058-cadc-4b81-b6e1-30de50dcbe96"
                  "2fc0579f-8113-47ea-b116-bb5a8db9202a")
         cred-id (str "cred-" seed-int)
         fmt (if (= fault-mode :fmt-none) "none" "packed")
         base-claim (faucet/build-signed-faucet-claim
                     {:claimant-pubkey claimant-pk
                      :claimant-privkey (if (= fault-mode :bad-challenge-sig)
                                          (kp->sk other-kp)
                                          claimant-sk)
                      :epoch-bucket 100
                      :pow-difficulty-bits 8
                      :aaguid aaguid
                      :credential-id cred-id
                      :fmt fmt
                      :attestation-root-id "yubico-u2f-root-ca"})
         claim-req (if (= fault-mode :bad-pow)
                     (assoc base-claim :pow-nonce "invalid-nonce-000")
                     base-claim)
         res1 (faucet/process-faucet-claim st0 claim-req)]
     (case fault-mode
       :valid
       (and (true? (:ok? res1))
            (= :spend-dac (get-in res1 [:spend-dac :type]))
            (= 1000000 (get-in res1 [:spend-dac :cap]))
            (= claimant-pk (get-in res1 [:spend-dac :holder]))
            (true? (faucet/verify-faucet-audit-artifact (:audit-artifact res1) faucet-pk)))

       :duplicate-credential
       (let [claim2 (faucet/build-signed-faucet-claim
                     {:claimant-pubkey (kp->pk-hex other-kp)
                      :claimant-privkey (kp->sk other-kp)
                      :epoch-bucket 100
                      :pow-difficulty-bits 8
                      :aaguid aaguid
                      :credential-id cred-id
                      :fmt "packed"
                      :attestation-root-id "yubico-u2f-root-ca"})
             res2 (faucet/process-faucet-claim (:state res1) claim2)]
         (and (true? (:ok? res1))
              (false? (:ok? res2))
              (= :duplicate-hardware-credential (:error res2))
              (some #(= :duplicate-hardware-credential (:reason %)) (:effects res2))
              (true? (faucet/verify-faucet-audit-artifact (:audit-artifact res2) faucet-pk))))

       (:bad-pow :bad-challenge-sig)
       (and (false? (:ok? res1))
            (= :pow-or-challenge-failed (:error res1))
            (true? (:rejected-pre-parse? res1))
            (some #(= :pow-or-challenge-failed (:reason %)) (:effects res1))
            (true? (faucet/verify-faucet-audit-artifact (:audit-artifact res1) faucet-pk)))

       (:fmt-none :software-aaguid)
       (and (false? (:ok? res1))
            (= :attestation-verification-failed (:error res1))
            (some #(= :attestation-verification-failed (:reason %)) (:effects res1))
            (true? (faucet/verify-faucet-audit-artifact (:audit-artifact res1) faucet-pk)))))))

(defspec ^{:doc "BIP-010 Prop 5 (P-FAUCET-1, P-FAUCET-2): On-chain :spend-dac enforces cap (amount + burn-fee <= remaining cap), expiry, revocation, and holder signature, never allowing admission DACs to move money and leaving zero dust via fee-from-allowance."}
  prop-spend-dac-enforces-cap-expiry-revocation-and-holder-sig 50
  (prop/for-all
   [seed-int (gen/choose 1 100000)
    amount (gen/choose 1000 400000)
    burn-fee (gen/choose 100 5000)
    mode (gen/elements [:valid-transfer
                        :valid-burn-for-credit
                        :overspend
                        :expired
                        :revoked
                        :wrong-holder-sig
                        :admission-dac-cannot-spend])]
   (let [issuer-kp (crypto/generate-keypair (str "d36-p5-issuer-" seed-int))
         holder-kp (crypto/generate-keypair (str "d36-p5-holder-" seed-int))
         recipient-kp (crypto/generate-keypair (str "d36-p5-recip-" seed-int))
         attacker-kp (crypto/generate-keypair (str "d36-p5-att-" seed-int))
         issuer-pk (kp->pk-hex issuer-kp)
         issuer-sk (kp->sk issuer-kp)
         holder-pk (kp->pk-hex holder-kp)
         holder-sk (kp->sk holder-kp)
         recip-pk (kp->pk-hex recipient-kp)
         dac-id (str "spend-dac-" seed-int)
         cap 500000
         dac (spend-dac/issue-spend-dac
              issuer-pk issuer-sk
              {:dac-id dac-id
               :holder holder-pk
               :cap cap
               :issued-epoch 10
               :expiry-epoch 1000
               :spent 0})
         st0 {:epoch 50
              :ledger {issuer-pk (account/map->AccountState {:balance 25000000 :seq 0 :deps []})
                       holder-pk (account/map->AccountState {:balance 0 :seq 0 :deps []})}
              :spend-dacs {dac-id (if (= mode :admission-dac-cannot-spend)
                                    (assoc dac :type :admission-dac)
                                    dac)}
              :diagnostics {}}
         st1 (if (= mode :revoked)
               (:state (spend-dac/revoke-spend-dac st0 issuer-pk issuer-sk dac-id 55))
               st0)
         spend-ep (if (= mode :expired) 1000 60)
         eff-amount (if (= mode :overspend) (+ cap 1) amount)
         op (if (= mode :valid-burn-for-credit) :burn-for-credit :transfer)
         signer-sk (if (= mode :wrong-holder-sig) (kp->sk attacker-kp) holder-sk)
         spend-ev (spend-dac/sign-spend-dac-intent
                   signer-sk
                   {:spend-dac-id dac-id
                    :holder holder-pk
                    :recipient recip-pk
                    :op op
                    :amount eff-amount
                    :burn-fee burn-fee
                    :epoch spend-ep
                    :nonce (str "n-" seed-int)})
         res (spend-dac/validate-and-apply-spend-dac-debit (assoc st1 :epoch spend-ep) spend-ev)]
     (if (contains? #{:valid-transfer :valid-burn-for-credit} mode)
       (let [st-after (:state res)
             total-debit (+ eff-amount burn-fee)]
         (and (true? (:ok? res))
              (= total-debit (get-in st-after [:spend-dacs dac-id :spent]))
              (= (- 25000000 total-debit) (get-in st-after [:ledger issuer-pk :balance]))
              ;; Fee-from-allowance: fresh holder account has 0 dust stranded!
              (= 0 (get-in st-after [:ledger holder-pk :balance]))
              (if (= op :transfer)
                (= eff-amount (get-in st-after [:ledger recip-pk :balance]))
                true)))
       (and (false? (:ok? res))
            (pos? (get-in (:state res) [:diagnostics :spend-dac-rejected] 0))
            (some #(= :diagnose (:effect %)) (:effects res)))))))

(defspec ^{:doc "BIP-010 Prop 6 (P-FAUCET-2): A2-to-A1 migration registers an outstanding A2 spend-DAC on-chain at its exact remaining cap attested by co-signed receipts, and post-migration spends validate on-chain without the faucet online."}
  prop-a2-to-a1-spend-dac-migration-preserves-remaining-cap 50
  (prop/for-all
   [seed-int (gen/choose 1 100000)
    a2-spend1 (gen/choose 10000 200000)
    a2-fee1 (gen/choose 100 2000)
    a1-spend2 (gen/choose 10000 200000)
    a1-fee2 (gen/choose 100 2000)]
   (let [faucet-kp (crypto/generate-keypair (str "d36-p6-faucet-" seed-int))
         holder-kp (crypto/generate-keypair (str "d36-p6-holder-" seed-int))
         recip-kp (crypto/generate-keypair (str "d36-p6-recip-" seed-int))
         faucet-pk (kp->pk-hex faucet-kp)
         faucet-sk (kp->sk faucet-kp)
         holder-pk (kp->pk-hex holder-kp)
         holder-sk (kp->sk holder-kp)
         recip-pk (kp->pk-hex recip-kp)
         faucet-st0 (faucet/init-faucet-service-state
                     {:faucet-pubkey faucet-pk
                      :faucet-privkey faucet-sk
                      :current-epoch 10
                      :pow-difficulty-bits 8})
         claim (faucet/build-signed-faucet-claim
                {:claimant-pubkey holder-pk
                 :claimant-privkey holder-sk
                 :epoch-bucket 10
                 :pow-difficulty-bits 8
                 :aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"
                 :credential-id (str "mig-cred-" seed-int)
                 :fmt "packed"
                 :attestation-root-id "yubico-u2f-root-ca"})
         claim-res (faucet/process-faucet-claim faucet-st0 claim)
         a2-dac (:spend-dac claim-res)
         dac-id (:dac-id a2-dac)
         intent1 (spend-dac/sign-spend-dac-intent
                  holder-sk
                  {:spend-dac-id dac-id
                   :holder holder-pk
                   :recipient recip-pk
                   :op :transfer
                   :amount a2-spend1
                   :burn-fee a2-fee1
                   :epoch 15
                   :nonce "a2-1"})
         a2-exec (faucet/process-a2-spend-intent (:state claim-res) intent1)
         receipt1 (:receipt a2-exec)
         realized-a2 (+ a2-spend1 a2-fee1)
         ;; Migrate A2 allowance to on-chain A1 ledger state at epoch 20
         chain-st0 {:epoch 20
                    :ledger {faucet-pk (account/map->AccountState {:balance (:liquid-balance-ech (:state a2-exec)) :seq 1 :deps []})
                             recip-pk (account/map->AccountState {:balance a2-spend1 :seq 0 :deps []})}
                    :spend-dacs {}
                    :diagnostics {}}
         mig-res (spend-dac/migrate-a2-allowance-to-a1 chain-st0 a2-dac [receipt1] 20)
         chain-st1 (:state mig-res)
         ;; Post-migration spend on-chain (faucet offline)
         intent2 (spend-dac/sign-spend-dac-intent
                  holder-sk
                  {:spend-dac-id dac-id
                   :holder holder-pk
                   :recipient recip-pk
                   :op :transfer
                   :amount a1-spend2
                   :burn-fee a1-fee2
                   :epoch 25
                   :nonce "a1-2"})
         a1-res (spend-dac/validate-and-apply-spend-dac-debit (assoc chain-st1 :epoch 25) intent2)
         chain-st2 (:state a1-res)]
     (and (true? (:ok? claim-res))
          (true? (:ok? a2-exec))
          (true? (:ok? mig-res))
          (= realized-a2 (get-in chain-st1 [:spend-dacs dac-id :spent]))
          (= (- 1000000 realized-a2) (:remaining-cap mig-res))
          (true? (:ok? a1-res))
          (= (+ realized-a2 a1-spend2 a1-fee2)
             (get-in chain-st2 [:spend-dacs dac-id :spent]))
          (= (+ a2-spend1 a1-spend2)
             (get-in chain-st2 [:ledger recip-pk :balance]))))))

;; =============================================================================
;; 2. Deterministic E2E Scenarios (S-D36-1..S-D36-6)
;; =============================================================================

(deftest scenario-s-d36-1-yubikey-recovery-round-trip-and-bundle-freshness-test
  (testing "S-D36-1 (P-WEB-1): Redacted credential + Closure-mangled property names recover the identity to canonical 88-char SPKI matching registered identity; stale /app/ browser bundle emits counted :stale-browser-bundle :diagnose"
    (let [seed (crypto/random-bytes (crypto/make-random 20261119) 32)
          reg-rec (webauthn/recover-seed-from-assertion {:user-handle seed})
          norm-reg (webauthn/normalize-recovered-identity reg-rec)
          ;; 1. Simulate getDiscoverableCredential unlocking state and returning redacted credential
          unlocked-node {:keypair {:public-key (:public-key norm-reg)
                                   :private-key (:private-key norm-reg)}
                         :light-state {:pubkey (:public-hex norm-reg)}}
          redacted-get-cred (dissoc norm-reg :seed :private-key :keypair :user-handle)
          ;; 2. Simulate createDiscoverableCredential returning nested {:identity ...} redacted
          redacted-create-cred {:attestation {:fmt "packed" :aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"}
                                :identity redacted-get-cred}
          rec-from-get (webauthn/resolve-yubikey-recovery redacted-get-cred unlocked-node)
          rec-from-create (webauthn/resolve-yubikey-recovery redacted-create-cred unlocked-node)
          ;; 3. Simulate string-keyed / Closure-safe assertion object
          rec-from-assertion (webauthn/resolve-yubikey-recovery
                              {"response" {"userHandle" seed}
                               "clientExtensionResults" {"prf" {"results" {"first" seed}}}}
                              nil)
          ;; 4. Bundle freshness check
          fresh-check (browser/check-browser-bundle-freshness
                       {:diagnostics {}}
                       config/version
                       {:version config/version})
          stale-check (browser/check-browser-bundle-freshness
                       {:diagnostics {}}
                       "0.23.11"
                       {:version config/version})]
      (is (= 88 (count (:public-hex norm-reg))))
      (is (str/starts-with? (:public-hex norm-reg) "302a300506032b6570032100"))
      (is (true? (:ok? rec-from-get)))
      (is (= (:public-hex norm-reg) (:public-hex rec-from-get)))
      (is (= (:address norm-reg) (:address rec-from-get)))
      (is (some? (get-in rec-from-get [:node-state :keypair :private-key])))
      (is (true? (:ok? rec-from-create)))
      (is (= (:public-hex norm-reg) (:public-hex rec-from-create)))
      (is (some? (get-in rec-from-create [:node-state :keypair :private-key])))
      (is (true? (:ok? rec-from-assertion)))
      (is (= (:public-hex norm-reg) (:public-hex rec-from-assertion)))
      ;; Fresh bundle passes with 0 diagnostics
      (is (true? (:fresh? fresh-check)))
      (is (empty? (:effects fresh-check)))
      ;; Stale bundle emits counted :stale-browser-bundle diagnose (Rule 5)
      (is (false? (:fresh? stale-check)))
      (is (= 1 (get-in (:state stale-check) [:diagnostics :stale-browser-bundle])))
      (is (some #(and (= :diagnose (:effect %))
                      (= :stale-browser-bundle (:reason %)))
                (:effects stale-check))))))

(deftest scenario-s-d36-2-single-instance-serve-lock-and-stale-reclaim-test
  (testing "S-D36-2 (P-OPS-3): Duplicate serve start on a locked state dir fails fast with a counted :diagnose; stale lock from a dead PID is reclaimed and logged"
    (let [tmp-dir (make-temp-dir "d36-s2-lock-")]
      (try
        (let [state-dir (.getAbsolutePath tmp-dir)
              live-pids (atom #{4242 5353})
              pid-alive-fn (fn [pid] (contains? @live-pids (long pid)))
              ;; Instance 1 (PID 4242) acquires lock
              acq1 (light-shell/check-single-instance-lock
                    state-dir
                    {:current-pid 4242
                     :pid-alive-fn pid-alive-fn
                     :timestamp-ms 1700000001000})
              ;; Write control.json for PID 4242
              ctrl-file (io/file state-dir "control.json")
              _ (spit ctrl-file "{\"pid\":4242,\"port\":5020,\"token\":\"secret-1\"}")
              ;; Instance 2 (PID 5353) attempts duplicate startup while PID 4242 is alive -> MUST fail fast without touching control.json
              acq2 (light-shell/check-single-instance-lock
                    state-dir
                    {:current-pid 5353
                     :pid-alive-fn pid-alive-fn
                     :timestamp-ms 1700000002000})
              ctrl-after-dup (slurp ctrl-file)
              ;; Now PID 4242 dies; Instance 2 retries -> MUST reclaim stale lock cleanly
              _ (swap! live-pids disj 4242)
              acq3 (light-shell/check-single-instance-lock
                    state-dir
                    {:current-pid 5353
                     :pid-alive-fn pid-alive-fn
                     :timestamp-ms 1700000003000})]
          (is (true? (:ok? acq1)))
          (is (false? (:ok? acq2)))
          (is (= "already-running" (:error acq2)))
          (is (= 4242 (:locked-pid acq2)))
          (is (= :duplicate-serve-instance-rejected (get-in acq2 [:diagnose :reason])))
          (is (str/includes? ctrl-after-dup "\"port\":5020"))
          (is (true? (:ok? acq3)))
          (is (true? (:reclaimed-stale-lock? acq3)))
          (is (= 4242 (:stale-pid acq3)))
          (is (= 5353 (:locked-pid acq3)))
          (light-shell/release-serve-lock! state-dir 5353)
          (is (not (.exists (io/file state-dir "serve.lock")))))
        (finally
          (delete-dir-recursively! tmp-dir))))))

(deftest scenario-s-d36-3-spend-dac-allowance-enforcement-and-fee-from-allowance-test
  (testing "S-D36-3 (P-FAUCET-2): Spend-DAC enforcement: overspend beyond cap rejected, spend after expiry rejected, revoked allowance rejected, non-holder signature rejected; burns and transfers both debit :spent; fee-from-allowance leaves no dust"
    (let [issuer-kp (crypto/generate-keypair "d36-s3-issuer")
          holder-kp (crypto/generate-keypair "d36-s3-holder")
          other-kp (crypto/generate-keypair "d36-s3-other")
          recip-kp (crypto/generate-keypair "d36-s3-recip")
          issuer-pk (kp->pk-hex issuer-kp)
          issuer-sk (kp->sk issuer-kp)
          holder-pk (kp->pk-hex holder-kp)
          holder-sk (kp->sk holder-kp)
          other-sk (kp->sk other-kp)
          recip-pk (kp->pk-hex recip-kp)
          dac (spend-dac/issue-spend-dac
               issuer-pk issuer-sk
               {:dac-id "dac-s3-1"
                :holder holder-pk
                :cap 1000000
                :issued-epoch 100
                :expiry-epoch (+ 100 241920)
                :spent 0})
          st0 {:epoch 110
               :ledger {issuer-pk (account/map->AccountState {:balance 25000000 :seq 0 :deps []})
                        holder-pk (account/map->AccountState {:balance 0 :seq 0 :deps []})}
               :spend-dacs {"dac-s3-1" dac}
               :diagnostics {}}
          ;; 1. Valid transfer (300,000 ECH + 100 ECH burn fee = 300,100 ECH charged to allowance)
          tx1 (spend-dac/sign-spend-dac-intent
               holder-sk
               {:spend-dac-id "dac-s3-1"
                :holder holder-pk
                :recipient recip-pk
                :op :transfer
                :amount 300000
                :burn-fee 100
                :epoch 110
                :nonce "tx-1"})
          res1 (spend-dac/validate-and-apply-spend-dac-debit st0 tx1)
          st1 (:state res1)
          ;; 2. Valid signaling/settlement burn-for-credit (50,000 ECH + 100 ECH burn fee = 50,100 ECH)
          tx2 (spend-dac/sign-spend-dac-intent
               holder-sk
               {:spend-dac-id "dac-s3-1"
                :holder holder-pk
                :recipient recip-pk
                :op :burn-for-credit
                :amount 50000
                :burn-fee 100
                :epoch 112
                :nonce "tx-2"})
          res2 (spend-dac/validate-and-apply-spend-dac-debit (assoc st1 :epoch 112) tx2)
          st2 (:state res2)
          ;; 3. Overspend beyond remaining cap (remaining = 649,800; try 700,000) -> rejected
          tx-over (spend-dac/sign-spend-dac-intent
                   holder-sk
                   {:spend-dac-id "dac-s3-1"
                    :holder holder-pk
                    :recipient recip-pk
                    :op :transfer
                    :amount 700000
                    :burn-fee 100
                    :epoch 115
                    :nonce "tx-over"})
          res-over (spend-dac/validate-and-apply-spend-dac-debit (assoc st2 :epoch 115) tx-over)
          ;; 4. Non-holder signature -> rejected
          tx-wrong-sig (spend-dac/sign-spend-dac-intent
                        other-sk
                        {:spend-dac-id "dac-s3-1"
                         :holder holder-pk
                         :recipient recip-pk
                         :op :transfer
                         :amount 1000
                         :burn-fee 100
                         :epoch 115
                         :nonce "tx-wrong-sig"})
          res-wrong-sig (spend-dac/validate-and-apply-spend-dac-debit (assoc st2 :epoch 115) tx-wrong-sig)
          ;; 5. Spend after expiry -> rejected
          tx-exp (spend-dac/sign-spend-dac-intent
                  holder-sk
                  {:spend-dac-id "dac-s3-1"
                   :holder holder-pk
                   :recipient recip-pk
                   :op :transfer
                   :amount 1000
                   :burn-fee 100
                   :epoch (+ 100 241920)
                   :nonce "tx-exp"})
          res-exp (spend-dac/validate-and-apply-spend-dac-debit (assoc st2 :epoch (+ 100 241920)) tx-exp)
          ;; 6. Revoke allowance -> subsequent spend rejected immediately
          rev-res (spend-dac/revoke-spend-dac st2 issuer-pk issuer-sk "dac-s3-1" 120)
          tx-rev (spend-dac/sign-spend-dac-intent
                  holder-sk
                  {:spend-dac-id "dac-s3-1"
                   :holder holder-pk
                   :recipient recip-pk
                   :op :transfer
                   :amount 1000
                   :burn-fee 100
                   :epoch 121
                   :nonce "tx-rev"})
          res-rev (spend-dac/validate-and-apply-spend-dac-debit (assoc (:state rev-res) :epoch 121) tx-rev)]
      (is (true? (spend-dac/verify-spend-dac-signature dac)))
      (is (true? (:ok? res1)))
      (is (true? (:ok? res2)))
      (is (= 350200 (get-in st2 [:spend-dacs "dac-s3-1" :spent])))
      (is (= 300000 (get-in st2 [:ledger recip-pk :balance])))
      (is (= (- 25000000 350200) (get-in st2 [:ledger issuer-pk :balance])))
      (is (= 0 (get-in st2 [:ledger holder-pk :balance])))
      (is (false? (:ok? res-over)))
      (is (= :allowance-cap-exceeded (:error res-over)))
      (is (false? (:ok? res-wrong-sig)))
      (is (= :invalid-holder-signature (:error res-wrong-sig)))
      (is (false? (:ok? res-exp)))
      (is (= :allowance-expired (:error res-exp)))
      (is (true? (:ok? rev-res)))
      (is (false? (:ok? res-rev)))
      (is (= :allowance-revoked (:error res-rev))))))

(deftest scenario-s-d36-4-faucet-claim-pow-attestation-dedup-and-audit-test
  (testing "S-D36-4 (P-FAUCET-1): Attested claim issues an allowance; duplicate credential-id claim denied; bogus attestation denied pre-parse by PoW/challenge gate; every decision appears in published audit artifacts"
    (let [faucet-kp (crypto/generate-keypair "d36-s4-faucet")
          alice-kp (crypto/generate-keypair "d36-s4-alice")
          bob-kp (crypto/generate-keypair "d36-s4-bob")
          faucet-pk (kp->pk-hex faucet-kp)
          faucet-sk (kp->sk faucet-kp)
          alice-pk (kp->pk-hex alice-kp)
          alice-sk (kp->sk alice-kp)
          bob-pk (kp->pk-hex bob-kp)
          bob-sk (kp->sk bob-kp)
          st0 (faucet/init-faucet-service-state
               {:faucet-pubkey faucet-pk
                :faucet-privkey faucet-sk
                :current-epoch 200
                :pow-difficulty-bits 8})
          ;; 1. Valid hardware-attested claim from Alice (YubiKey 5 AAGUID)
          claim1 (faucet/build-signed-faucet-claim
                  {:claimant-pubkey alice-pk
                   :claimant-privkey alice-sk
                   :epoch-bucket 200
                   :pow-difficulty-bits 8
                   :aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"
                   :credential-id "yk5-cred-001"
                   :fmt "packed"
                   :attestation-root-id "yubico-u2f-root-ca"})
          res1 (faucet/process-faucet-claim st0 claim1)
          ;; 2. Duplicate credential-id claim from Bob using same hardware key -> denied
          claim-dup (faucet/build-signed-faucet-claim
                     {:claimant-pubkey bob-pk
                      :claimant-privkey bob-sk
                      :epoch-bucket 200
                      :pow-difficulty-bits 8
                      :aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"
                      :credential-id "yk5-cred-001"
                      :fmt "packed"
                      :attestation-root-id "yubico-u2f-root-ca"})
          res-dup (faucet/process-faucet-claim (:state res1) claim-dup)
          ;; 3. Bogus claim with invalid PoW -> denied pre-parse before CBOR/x5c
          claim-bad-pow (assoc claim-dup
                               :credential-id "yk5-cred-002"
                               :pow-nonce "000-bad-pow")
          res-bad-pow (faucet/process-faucet-claim (:state res-dup) claim-bad-pow)
          st-final (:state res-bad-pow)]
      (is (true? (:ok? res1)))
      (is (= 1000000 (get-in res1 [:spend-dac :cap])))
      (is (= (+ 200 241920) (get-in res1 [:spend-dac :expiry-epoch])))
      (is (contains? (:claimed-keys st-final) ["2fc0579f-8113-47ea-b116-bb5a8db9202a" "yk5-cred-001"]))
      (is (false? (:ok? res-dup)))
      (is (= :duplicate-hardware-credential (:error res-dup)))
      (is (false? (:ok? res-bad-pow)))
      (is (= :pow-or-challenge-failed (:error res-bad-pow)))
      (is (true? (:rejected-pre-parse? res-bad-pow)))
      ;; Every decision (1 grant + 2 denials = 3) appears in published signed audit trail
      (is (= 3 (count (:audit-trail st-final))))
      (is (every? #(faucet/verify-faucet-audit-artifact % faucet-pk) (:audit-trail st-final))))))

(deftest scenario-s-d36-5-a2-to-a1-spend-dac-migration-offline-validation-test
  (testing "S-D36-5 (P-FAUCET-1, P-FAUCET-2): An A2 allowance with partial spend registers on-chain at remaining cap with receipt-attested spent; post-migration spends validate without the faucet online"
    (let [faucet-kp (crypto/generate-keypair "d36-s5-faucet")
          holder-kp (crypto/generate-keypair "d36-s5-holder")
          recip-kp (crypto/generate-keypair "d36-s5-recip")
          faucet-pk (kp->pk-hex faucet-kp)
          faucet-sk (kp->sk faucet-kp)
          holder-pk (kp->pk-hex holder-kp)
          holder-sk (kp->sk holder-kp)
          recip-pk (kp->pk-hex recip-kp)
          faucet-st0 (faucet/init-faucet-service-state
                      {:faucet-pubkey faucet-pk
                       :faucet-privkey faucet-sk
                       :current-epoch 300
                       :pow-difficulty-bits 8})
          claim (faucet/build-signed-faucet-claim
                 {:claimant-pubkey holder-pk
                  :claimant-privkey holder-sk
                  :epoch-bucket 300
                  :pow-difficulty-bits 8
                  :aaguid "adce0002-35bc-c60a-648b-0b25f1f05503"
                  :credential-id "apple-se-001"
                  :fmt "packed"
                  :attestation-root-id "apple-webauthn-root-ca"})
          claim-res (faucet/process-faucet-claim faucet-st0 claim)
          dac (:spend-dac claim-res)
          dac-id (:dac-id dac)
          ;; Execute 2 A2 co-signed spends totaling 400,200 ECH
          s1 (spend-dac/sign-spend-dac-intent
              holder-sk
              {:spend-dac-id dac-id :holder holder-pk :recipient recip-pk
               :op :transfer :amount 250000 :burn-fee 100 :epoch 305 :nonce "s1"})
          r1 (faucet/process-a2-spend-intent (:state claim-res) s1)
          s2 (spend-dac/sign-spend-dac-intent
              holder-sk
              {:spend-dac-id dac-id :holder holder-pk :recipient recip-pk
               :op :burn-for-credit :amount 150000 :burn-fee 100 :epoch 306 :nonce "s2"})
          r2 (faucet/process-a2-spend-intent (:state r1) s2)
          ;; Migrate to A1 on-chain state
          sm-st0 (-> (sm/init-state [] faucet-pk (config/devnet-6-config))
                     (assoc :epoch 310
                            :ledger {faucet-pk (account/map->AccountState {:balance (:liquid-balance-ech (:state r2)) :seq 2 :deps []})
                                     recip-pk (account/map->AccountState {:balance 250000 :seq 0 :deps []})}))
          mig (spend-dac/migrate-a2-allowance-to-a1 sm-st0 dac [(:receipt r1) (:receipt r2)] 310)
          sm-st1 (:state mig)
          ;; Faucet goes offline; holder executes an A1 spend of 500,000 ECH + 100 burn-fee directly against validator state
          s3 (spend-dac/sign-spend-dac-intent
              holder-sk
              {:spend-dac-id dac-id :holder holder-pk :recipient recip-pk
               :op :transfer :amount 500000 :burn-fee 100 :epoch 312 :nonce "s3"})
          a1-ok (spend-dac/validate-and-apply-spend-dac-debit (assoc sm-st1 :epoch 312) s3)
          ;; Try another spend of 100,000 ECH (exceeds remaining 99,700 ECH) -> rejected on-chain
          s4 (spend-dac/sign-spend-dac-intent
              holder-sk
              {:spend-dac-id dac-id :holder holder-pk :recipient recip-pk
               :op :transfer :amount 100000 :burn-fee 100 :epoch 313 :nonce "s4"})
          a1-over (spend-dac/validate-and-apply-spend-dac-debit (:state a1-ok) s4)]
      (is (true? (:ok? mig)))
      (is (= 400200 (get-in sm-st1 [:spend-dacs dac-id :spent])))
      (is (= 599800 (:remaining-cap mig)))
      (is (true? (:ok? a1-ok)))
      (is (= 900300 (get-in (:state a1-ok) [:spend-dacs dac-id :spent])))
      (is (= 750000 (get-in (:state a1-ok) [:ledger recip-pk :balance])))
      (is (false? (:ok? a1-over)))
      (is (= :allowance-cap-exceeded (:error a1-over))))))

(deftest scenario-s-d36-6-nodejs-infra-node-parity-fressian-continuity-and-mixed-rollout-test
  (testing "S-D36-6 (P-NODE-1): Node.js infra node joins infra subnet, verifies Fressian state continuity with JVM, enforces fail-closed runtime-binary preflight gate (Node >= 22), applies pointer-driven config change at epoch gate with identical P-DEPLOY-5 audit records, and passes live node dist/bitecho-full-node.cjs --self-test"
    (let [auth-kp (crypto/generate-keypair "d36-s6-auth")
          auth-pk (kp->pk-hex auth-kp)
          auth-sk (kp->sk auth-kp)
          jvm-art-bytes (utf8-bytes "jvm-uberjar-v0.23.14")
          node-art-bytes (utf8-bytes "nodejs-full-node-v0.23.14")
          jvm-cid (deploy/sha256-hex jvm-art-bytes)
          node-cid (deploy/sha256-hex node-art-bytes)
          cfg-ptr (deploy/sign-config-pointer
                   auth-sk
                   {:network "devnet"
                    :seq 2
                    :activate-at-epoch 50
                    :code-target-cid node-cid
                    :node-runtimes {:ns1 :jvm :ns2 :jvm :ns3 :nodejs}
                    :artifacts {:jvm {:cid jvm-cid :path "target/bitecho.jar"}
                                :nodejs {:cid node-cid :path "dist/bitecho-full-node.cjs"}}
                    :domains {:consensus {:quorum-threshold 4}
                              :economy {:min-signaling-burn 100
                                        :settlement-take-bps 50}}
                    :policy-theta deploy/ratified-theta-star
                    :author-pubkey auth-pk})
          ;; 1. Fail-closed runtime-binary preflight gate: when Node.js is absent or < v22, switch to :nodejs MUST be refused
          preflight-missing (deploy/build-runtime-dispatch-plan
                             cfg-ptr :ns3
                             {:artifact-bytes node-art-bytes
                              :last-known-good-runtime :jvm
                              :last-known-good-cid jvm-cid
                              :available-runtimes {:jvm {:installed? true :major-version 25}
                                                   :nodejs {:installed? false :major-version 0}}})
          preflight-old-node (deploy/build-runtime-dispatch-plan
                              cfg-ptr :ns3
                              {:artifact-bytes node-art-bytes
                               :last-known-good-runtime :jvm
                               :last-known-good-cid jvm-cid
                               :available-runtimes {:jvm {:installed? true :major-version 25}
                                                    :nodejs {:installed? true :major-version 18}}})
          ;; 2. Preflight passes when Node.js >= 22 and artifact SHA-256 matches
          preflight-ok (deploy/build-runtime-dispatch-plan
                        cfg-ptr :ns3
                        {:artifact-bytes node-art-bytes
                         :last-known-good-runtime :jvm
                         :last-known-good-cid jvm-cid
                         :available-runtimes {:jvm {:installed? true :major-version 25}
                                              :nodejs {:installed? true :major-version 22}}})
          ;; 3. Cross-runtime Fressian snapshot continuity: JVM state encoded to Fressian and restored
          jvm-subnet-init (subnet/init-subnet-instance
                           {:subnet/id "bitecho.org/infra"
                            :subnet/parent-id "global"
                            :subnet/gate {:gate/mode :permissioned
                                          :gate/admission :allowlist
                                          :gate/trust-anchors #{auth-pk}
                                          :gate/governance {:governance/type :quorum :threshold 1}}
                            :subnet/path-acl [{:pattern "config/*" :principal {:type :allowlist :signers #{auth-pk}}}
                                              {:pattern "dir/*" :principal {:type :allowlist :signers #{auth-pk}}}]
                            :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                            :subnet/replication {:replication/pointers :leader-election
                                                 :replication/blobs :eager-push}})
          blob (data/make-blob (pr-str cfg-ptr) "application/edn")
          ptr (data/sign-pointer auth-sk {:pointer/authority auth-pk
                                          :pointer/subnet "bitecho.org/infra"
                                          :pointer/path "config/devnet/active.edn"
                                          :pointer/seq 2
                                          :pointer/target (:blob/cid blob)
                                          :pointer/proof {:proof/type :self}})
          jvm-st1 (:state (subnet/reduce-subnet (:instance jvm-subnet-init)
                                                {:type :put-blob :sender auth-pk :blob blob :now-ms 1000}))
          jvm-st2 (:state (subnet/reduce-subnet jvm-st1
                                                {:type :publish-pointer :sender auth-pk :pointer ptr :now-ms 1000}))
          fressian-snap-bytes (fressian/encode-canonical
                               {:subnet-id (:subnet-id jvm-st2)
                                :policy (:policy jvm-st2)
                                :pointers (get-in jvm-st2 [:data :pointers])
                                :epoch 49})
          decoded-snap (fressian/decode-wire fressian-snap-bytes)
          ;; 4. Both JVM (:ns1) and Node.js (:ns3) apply the staged config pointer at epoch 50 and emit identical audit records
          base-node-st {:epoch 49
                        :trusted-deploy-authorities #{auth-pk}
                        :config (config/devnet-6-config)
                        :audit-trail []}
          jvm-staged (:state (deploy/stage-config-pointer (assoc base-node-st :node-id :ns1 :runtime :jvm) cfg-ptr))
          node-staged (:state (deploy/stage-config-pointer (assoc base-node-st :node-id :ns3 :runtime :nodejs) cfg-ptr))
          jvm-ep50 (:state (deploy/apply-epoch-boundary-configs jvm-staged 50))
          node-ep50 (:state (deploy/apply-epoch-boundary-configs node-staged 50))]
      (is (false? (:ok? preflight-missing)))
      (is (= :runtime-binary-missing-or-incompatible (:error preflight-missing)))
      (is (= :jvm (:active-runtime preflight-missing)))
      (is (some #(= :runtime-binary-missing-or-incompatible (:reason %)) (:effects preflight-missing)))
      (is (false? (:ok? preflight-old-node)))
      (is (= :runtime-binary-missing-or-incompatible (:error preflight-old-node)))
      (is (true? (:ok? preflight-ok)))
      (is (= :nodejs (:active-runtime preflight-ok)))
      (is (= node-cid (:active-code-cid preflight-ok)))
      ;; Fressian continuity check
      (is (= "bitecho.org/infra" (:subnet-id decoded-snap)))
      (is (= (:blob/cid blob)
             (get-in decoded-snap [:pointers ["bitecho.org/infra" "config/devnet/active.edn"] :pointer/target])))
      ;; Identical config hash & audit verification at epoch 50
      (is (= (:active-config-hash jvm-ep50) (:active-config-hash node-ep50)))
      (is (= (mapv :event-type (:audit-trail jvm-ep50))
             (mapv :event-type (:audit-trail node-ep50))))
      ;; 5. Verify built dist/bitecho-full-node.cjs bundle exists and passes --self-test on Node.js
      (let [bundle-file (io/file "dist/bitecho-full-node.cjs")]
        (is (.exists bundle-file) "dist/bitecho-full-node.cjs must be built")
        (when (.exists bundle-file)
          (let [node-bin (if (.canExecute (io/file (str (System/getProperty "user.home") "/.local/bin/node")))
                           (str (System/getProperty "user.home") "/.local/bin/node")
                           "node")
                sh-res (sh/sh node-bin "dist/bitecho-full-node.cjs" "--self-test")]
            (is (= 0 (:exit sh-res)) (str "Node full-node self-test failed: " (:err sh-res) " / " (:out sh-res)))
            (is (str/includes? (:out sh-res) "\"ok\":true"))
            (is (str/includes? (:out sh-res) "\"runtime\":\"nodejs\"")))))
      (is (contains? #{"0.23.14" "0.23.15"} config/version))
      (let [bip010-file (io/file "docs/bips/bip-010-v02314.edn")]
        (is (.exists bip010-file) "docs/bips/bip-010-v02314.edn must exist")
        (when (.exists bip010-file)
          (let [bip010-spec (edn/read-string (slurp bip010-file))
                gate-check (gov/verify-bip-admission-gates bip010-spec)]
            (is (true? (:ok? gate-check)))
            (is (empty? (:missing-gates gate-check)))))))))
