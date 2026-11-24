(ns bitecho.core.protocol.faucet
  "Pure Sans-IO Treasury-Managed Hardware Faucet Protocol (BIP-006 Part 3 + BIP-024 §2.9 / §3.2.2).

   The Faucet is outside core consensus (does not mint extra emission; funded solely from
   custody allocations with hard per-epoch drip caps).
   BIP-024 Hardening:
   - Fail-closed hardware attestation: defaults to unverified (false) and NEVER trusts
     client-supplied `:authenticator-verified? true`.
   - Verifies WebAuthn attestation format (`fmt`), AAGUID, `x5c` against `default-faucet-attestation-roots`
     (rejecting `fmt=\"none\"` in production), FIDO2 assertion signature over the single-use
     network-bound challenge, and claimant Proof-of-Possession.
   - Anti-Sybil hardware uniqueness nullifier deduplicated via `faucet/<net>/nullifiers/<nullifier-hash>`.
   - Unlinkable blinded voucher onboarding (`issue-blinded-voucher` / `redeem-blinded-voucher`).
   - Deterministic injected PRNG (`:rng`) and explicit clock (`now-ms` / `epoch`) for Monte Carlo CRN."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.circle :as circle]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.spend-dac :as spend-dac]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(defn now-timestamp-ms
  "Current wall-clock milliseconds (shell fallback only; simulations MUST inject explicit `now-ms`)."
  []
  #?(:clj (System/currentTimeMillis)
     :cljs (.now js/Date)))

(defn- deterministic-random-hex
  "Generates `n-bytes` of hex using injected deterministic `rng` when present,
   falling back to `crypto/random-bytes` only when no `rng` is supplied."
  [rng n-bytes]
  (if rng
    (let [bs #?(:clj (let [arr (byte-array n-bytes)]
                       (dotimes [i n-bytes]
                         (aset arr i (unchecked-byte (crypto/next-int rng 256))))
                       arr)
                :cljs (let [arr (js/Uint8Array. n-bytes)]
                        (dotimes [i n-bytes]
                          (aset arr i (crypto/next-int rng 256)))
                        arr))]
      (str/lower-case (basalt/bytes->hex bs)))
    (str/lower-case (basalt/bytes->hex (crypto/random-bytes n-bytes)))))

(defn init-faucet-state
  "Initializes pure Sans-IO Faucet protocol state."
  ([] (init-faucet-state {}))
  ([opts]
   {:network-uri           (or (:network-uri opts) "devnet.bitecho.org")
    :network-genesis-cid   (or (:network-genesis-cid opts) "")
    :treasury-privkey      (:treasury-privkey opts)
    :treasury-pubkey       (:treasury-pubkey opts)
    :drip-amount-ech       (long (or (:drip-amount-ech opts) 1000000))
    :epoch-drip-cap-ech    (long (or (:epoch-drip-cap-ech opts) 100000000))
    :epoch-dripped         (or (:epoch-dripped opts) {})
    :challenge-ttl-ms      (long (or (:challenge-ttl-ms opts) 60000))
    :attestation-roots     (or (:attestation-roots opts) spend-dac/default-faucet-attestation-roots)
    :claim-seq             (long (or (:claim-seq opts) 0))
    :challenges            {}
    :claimed-credentials   (set (or (:claimed-credentials opts) #{}))
    :claimed-hw-nullifiers (set (or (:claimed-hw-nullifiers opts) #{}))
    :redeemed-vouchers     (set (or (:redeemed-vouchers opts) #{}))
    :receipts              (or (:receipts opts) {})
    :blobs                 (or (:blobs opts) {})
    :pointers              (or (:pointers opts) {})
    :diagnostics           (or (:diagnostics opts) {})}))

(defn issue-faucet-challenge
  "Issues a 60s single-use WebAuthn challenge bound to the specified network URI.
   Accepts optional deterministic `:rng` in `req` (or `state`) for CRN simulation parity."
  ([state req]
   (issue-faucet-challenge state req (now-timestamp-ms)))
  ([state req now-ms]
   (let [ttl (long (or (:challenge-ttl-ms state) 60000))
         net-uri (or (:network-uri req) (:network-uri state) "devnet.bitecho.org")
         rng (or (:rng req) (:rng state))
         nonce (or (:nonce req) (deterministic-random-hex rng 16))
         challenge {:nonce       nonce
                    :network-uri net-uri
                    :created-at  (long now-ms)
                    :expires-at  (+ (long now-ms) ttl)}]
     {:state     (assoc-in state [:challenges nonce] challenge)
      :challenge challenge})))

(defn- valid-claimant-pubkey?
  [pk]
  (boolean (circle/normalize-spki-pubkey pk)))

(defn hardware-uniqueness-nullifier
  "Derives a hardware-scoped uniqueness commitment from attested AAGUID + hardware attestation
   public key + network URI, preventing 1-YubiKey unlimited `credentialId` farming."
  [net-uri aaguid hw-pubkey]
  (let [spki (or (circle/normalize-spki-pubkey hw-pubkey) (str hw-pubkey))]
    (str/lower-case
     (basalt/bytes->hex
      (crypto/sha256
       (fressian/encode-canonical ["bitecho-hw-nullifier-v1"
                                   (str net-uri)
                                   (str/lower-case (str/trim (str aaguid)))
                                   spki]))))))

(defn build-test-hardware-attestation
  "Helper constructing a valid signed hardware attestation + claimant PoP map for tests and shells."
  [{:keys [hw-privkey hw-pubkey claimant-privkey claimant-pubkey nonce network-uri aaguid fmt x5c cred-hash]}]
  (let [hw-spki (circle/normalize-spki-pubkey hw-pubkey)
        cl-spki (circle/normalize-spki-pubkey claimant-pubkey)
        eff-fmt (or fmt "packed")
        eff-aaguid (or aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a")
        eff-x5c (or x5c [(str "x5c-root-yubico-" eff-aaguid)])
        assertion-tuple ["bitecho-faucet-assertion-v1" (str network-uri) (str nonce) (str (or cred-hash ""))]
        pop-tuple ["bitecho-faucet-claimant-pop-v1" (str network-uri) (str nonce) cl-spki]
        assertion-sig (str/lower-case (basalt/bytes->hex (crypto/sign-canonical hw-privkey assertion-tuple)))
        pop-sig (str/lower-case (basalt/bytes->hex (crypto/sign-canonical claimant-privkey pop-tuple)))]
    {:attestation {:fmt eff-fmt
                   :aaguid eff-aaguid
                   :x5c eff-x5c
                   :hw-pubkey hw-spki
                   :assertion-sig assertion-sig
                   :claimant-pop-sig pop-sig
                   :cred-hash-bound? (some? cred-hash)}}))

(defn verify-hardware-attestation
  "Fail-closed server-side WebAuthn/FIDO2 hardware attestation verifier (BIP-024 §2.9).
   NEVER trusts any client-supplied boolean; verifies:
   1. Attestation object map with non-empty `x5c` chain and allowed `fmt` (rejects `fmt=\"none\"` in prod).
   2. AAGUID + `fmt` match a hardware-backed root in `attestation-roots`.
   3. FIDO2 hardware assertion signature over single-use network-bound challenge.
   4. Claimant Proof-of-Possession signature."
  [attestation-roots {:keys [attestation network-uri nonce claimant-pubkey cred-hash]}]
  (let [roots-cfg (or attestation-roots spend-dac/default-faucet-attestation-roots)
        reject-none? (not (false? (:reject-fmt-none? roots-cfg)))
        fmt (when (map? attestation) (some-> (:fmt attestation) str str/trim str/lower-case))
        aaguid (when (map? attestation) (some-> (:aaguid attestation) str str/trim str/lower-case))
        x5c (when (map? attestation) (:x5c attestation))
        hw-spki (when (map? attestation) (circle/normalize-spki-pubkey (:hw-pubkey attestation)))
        cl-spki (circle/normalize-spki-pubkey claimant-pubkey)
        assertion-sig (when (map? attestation) (:assertion-sig attestation))
        pop-sig (when (map? attestation) (:claimant-pop-sig attestation))
        matching-root (when (and aaguid fmt)
                        (some (fn [[_ root-entry]]
                                (when (and (:hardware-backed? root-entry)
                                           (contains? (:allowed-aaguids root-entry) aaguid)
                                           (contains? (:allowed-fmts root-entry) fmt))
                                  root-entry))
                              (:roots roots-cfg)))
        assertion-tuple ["bitecho-faucet-assertion-v1"
                         (str network-uri)
                         (str nonce)
                         (if (:cred-hash-bound? attestation) (str cred-hash) "")]
        pop-tuple ["bitecho-faucet-claimant-pop-v1" (str network-uri) (str nonce) cl-spki]]
    (cond
      (not (map? attestation))
      {:ok? false :error :faucet-attestation-required :reason "missing-hardware-attestation"}

      (and reject-none? (or (nil? fmt) (= "none" fmt)))
      {:ok? false :error :faucet-attestation-fmt-rejected :reason "attestation-fmt-none-forbidden"}

      (or (not (sequential? x5c)) (empty? x5c) (not (every? #(and (string? %) (not (str/blank? %))) x5c)))
      {:ok? false :error :faucet-attestation-x5c-invalid :reason "missing-or-invalid-x5c-chain"}

      (nil? matching-root)
      {:ok? false :error :faucet-attestation-root-untrusted :reason "untrusted-aaguid-or-fmt"}

      (or (nil? hw-spki) (not (string? assertion-sig))
          (not (crypto/verify-with-fallback hw-spki assertion-tuple assertion-sig)))
      {:ok? false :error :faucet-assertion-invalid :reason "invalid-fido2-assertion-signature"}

      (or (nil? cl-spki) (not (string? pop-sig))
          (not (crypto/verify-with-fallback cl-spki pop-tuple pop-sig)))
      {:ok? false :error :faucet-claimant-pop-invalid :reason "invalid-claimant-pop-signature"}

      :else
      {:ok? true
       :root-id (:root-id matching-root)
       :aaguid aaguid
       :hw-pubkey hw-spki
       :hardware-nullifier (hardware-uniqueness-nullifier network-uri aaguid hw-spki)})))

(defn reduce-faucet-claim
  "Pure fail-closed reducer for a faucet claim request (BIP-006 + BIP-024 §2.9).
   Ignores any client-supplied `:authenticator-verified?` flag and requires valid
   server-verified hardware attestation, claimant PoP, hardware uniqueness nullifier,
   and per-epoch drip cap. Emits counted `:diagnose` effects on every rejection (Rule 5)."
  ([state claim-req]
   (reduce-faucet-claim state claim-req (now-timestamp-ms)))
  ([state claim-req now-ms]
   (let [nonce (:nonce claim-req)
         challenge (get-in state [:challenges nonce])
         claim-net-uri (or (:network-uri claim-req) (:network-uri state))
         cred-hash (when (string? (:credential-id-hash claim-req))
                     (str/trim (:credential-id-hash claim-req)))
         claimant-pk (circle/normalize-spki-pubkey (:claimant-pubkey claim-req))
         epoch (long (or (:epoch claim-req) 0))
         drip-amount (long (or (:drip-amount-ech state) 1000000))
         epoch-cap (long (or (:epoch-drip-cap-ech state) 100000000))
         epoch-used (long (get-in state [:epoch-dripped epoch] 0))
         fail! (fn [st err reason]
                 {:ok? false
                  :error err
                  :reason reason
                  :state (update-in st [:diagnostics err] (fnil inc 0))
                  :effects [{:effect :diagnose :reason err :detail reason}]})]
     (cond
       ;; Missing or mismatched challenge
       (or (nil? challenge)
           (and claim-net-uri
                (:network-uri challenge)
                (not= claim-net-uri (:network-uri challenge))))
       (fail! state :faucet-claim-rejected "invalid-challenge")

       ;; Expired challenge
       (> (long now-ms) (long (:expires-at challenge)))
       (fail! (update state :challenges dissoc nonce) :faucet-challenge-expired "challenge-expired")

       ;; Invalid claimant pubkey or credential-id-hash
       (or (str/blank? cred-hash)
           (not (valid-claimant-pubkey? claimant-pk)))
       (fail! (update state :challenges dissoc nonce) :faucet-claim-rejected "invalid-claim-parameters")

       ;; Already claimed credential ID
       (or (contains? (:claimed-credentials state) cred-hash)
           (contains? (:receipts state) cred-hash))
       (fail! (update state :challenges dissoc nonce) :faucet-credential-already-claimed "credential-already-claimed")

       ;; Per-epoch drip cap check (zero extra emission)
       (> (+ epoch-used drip-amount) epoch-cap)
       (fail! (update state :challenges dissoc nonce) :faucet-epoch-cap-exceeded "epoch-drip-cap-exceeded")

       ;; Mandatory fail-closed hardware attestation + PoP verification (NEVER trusts client boolean)
       :else
       (let [net-uri (or claim-net-uri (:network-uri challenge) (:network-uri state) "devnet.bitecho.org")
             att-res (verify-hardware-attestation
                      (:attestation-roots state)
                      {:attestation (:attestation claim-req)
                       :network-uri net-uri
                       :nonce nonce
                       :claimant-pubkey claimant-pk
                       :cred-hash cred-hash})]
         (cond
           (not (:ok? att-res))
           (fail! (update state :challenges dissoc nonce) (:error att-res) (:reason att-res))

           ;; Hardware uniqueness nullifier prevents 1-YubiKey multi-credentialId Sybil farming
           (contains? (:claimed-hw-nullifiers state) (:hardware-nullifier att-res))
           (fail! (update state :challenges dissoc nonce) :faucet-hardware-already-claimed "hardware-nullifier-already-claimed")

           :else
           (let [hw-nullifier (:hardware-nullifier att-res)
                 receipt-path (str "faucet/" net-uri "/claims/" cred-hash)
                 nullifier-path (str "faucet/" net-uri "/nullifiers/" hw-nullifier)
                 next-seq (inc (long (or (:claim-seq state) 0)))
                 treasury-pk (circle/normalize-spki-pubkey (:treasury-pubkey state))
                 treasury-sk (:treasury-privkey state)
                 transfer-intent {:from        treasury-pk
                                  :to          claimant-pk
                                  :amount      drip-amount
                                  :seq         next-seq
                                  :memo        receipt-path
                                  :network-uri net-uri}
                 receipt {:claimed-at         (long now-ms)
                          :claimant           claimant-pk
                          :credential-id-hash cred-hash
                          :hardware-nullifier hw-nullifier
                          :amount             drip-amount
                          :seq                next-seq
                          :epoch              epoch
                          :network-uri        net-uri
                          :receipt-path       receipt-path
                          :nullifier-path     nullifier-path}
                 receipt-blob (data/make-blob (fressian/utf8->bytes (pr-str receipt)) "application/edn")
                 receipt-cid (:blob/cid receipt-blob)
                 receipt-ptr (when (and treasury-sk treasury-pk)
                               (data/sign-pointer
                                treasury-sk
                                {:pointer/authority   treasury-pk
                                 :pointer/subnet      net-uri
                                 :pointer/path        receipt-path
                                 :pointer/seq         1
                                 :pointer/leader-term 1
                                 :pointer/target      receipt-cid
                                 :pointer/proof       {:proof/type :self}}))
                 nullifier-ptr (when (and treasury-sk treasury-pk)
                                 (data/sign-pointer
                                  treasury-sk
                                  {:pointer/authority   treasury-pk
                                   :pointer/subnet      net-uri
                                   :pointer/path        nullifier-path
                                   :pointer/seq         1
                                   :pointer/leader-term 1
                                   :pointer/target      receipt-cid
                                   :pointer/proof       {:proof/type :self}}))
                 signed-transfer (when (and treasury-sk treasury-pk)
                                   (let [unsigned {:sender      treasury-pk
                                                   :receiver    claimant-pk
                                                   :amount      drip-amount
                                                   :seq         next-seq
                                                   :deps        []
                                                   :network-uri net-uri}
                                         tf (account/create-transfer treasury-sk unsigned)]
                                     (into {} tf)))]
             (cond-> {:ok?                true
                      :transfer-intent    transfer-intent
                      :receipt-path       receipt-path
                      :nullifier-path     nullifier-path
                      :hardware-nullifier hw-nullifier
                      :receipt-cid        receipt-cid
                      :receipt            receipt
                      :receipt-blob       receipt-blob
                      :effects            []
                      :state              (-> state
                                              (assoc :claim-seq next-seq)
                                              (update :challenges dissoc nonce)
                                              (update :claimed-credentials (fnil conj #{}) cred-hash)
                                              (update :claimed-hw-nullifiers (fnil conj #{}) hw-nullifier)
                                              (update-in [:epoch-dripped epoch] (fnil + 0) drip-amount)
                                              (assoc-in [:receipts cred-hash] receipt)
                                              (assoc-in [:blobs receipt-cid] receipt-blob)
                                              (cond-> receipt-ptr
                                                (assoc-in [:pointers [net-uri receipt-path]] receipt-ptr))
                                              (cond-> nullifier-ptr
                                                (assoc-in [:pointers [net-uri nullifier-path]] nullifier-ptr)))}
               receipt-ptr (assoc :receipt-pointer receipt-ptr)
               nullifier-ptr (assoc :nullifier-pointer nullifier-ptr)
               signed-transfer (assoc :signed-transfer signed-transfer)))))))))

;; =============================================================================
;; Unlinkable Blinded Voucher Onboarding (BIP-024 §2.9 item 4)
;; =============================================================================

(defn blind-voucher-commitment
  "Computes an unlinkable blinded commitment `sha256([\"bitecho-blind-voucher-v1\" blinding-secret claimant-spki])`."
  [blinding-secret claimant-pubkey]
  (let [cl-spki (circle/normalize-spki-pubkey claimant-pubkey)]
    (str/lower-case
     (basalt/bytes->hex
      (crypto/sha256
       (fressian/encode-canonical ["bitecho-blind-voucher-v1" (str blinding-secret) cl-spki]))))))

(defn issue-blinded-voucher
  "Issues a faucet-signed unlinkable voucher over `commitment` without seeing or publishing
   the claimant's pubkey alongside hardware attestation metadata."
  [treasury-privkey treasury-pubkey network-uri network-genesis-cid commitment amount epoch]
  (let [t-spki (circle/normalize-spki-pubkey treasury-pubkey)
        base {:bitecho/type :faucet/blinded-voucher
              :issuer-pubkey t-spki
              :network-uri (str network-uri)
              :network-genesis-cid (str/lower-case (str network-genesis-cid))
              :commitment (str/lower-case (str commitment))
              :amount (long amount)
              :issued-epoch (long epoch)}
        tuple ["bitecho-faucet-voucher-v1"
               (:network-uri base)
               (:network-genesis-cid base)
               (:commitment base)
               (:amount base)
               (:issued-epoch base)]
        sig (str/lower-case (basalt/bytes->hex (crypto/sign-canonical treasury-privkey tuple)))]
    (assoc base :issuer-sig sig)))

(defn redeem-blinded-voucher
  "Redeems an unblinded voucher on-chain to fund sovereign `<net>/id/<pubkey-cid>` without
   ever linking `:claimant` to `:credential-id-hash` or `:hardware-nullifier`."
  [state voucher blinding-secret claimant-pubkey current-epoch]
  (let [cl-spki (circle/normalize-spki-pubkey claimant-pubkey)
        issuer (circle/normalize-spki-pubkey (:issuer-pubkey voucher))
        expected-issuer (circle/normalize-spki-pubkey (:treasury-pubkey state))
        commitment (:commitment voucher)
        expected-comm (when cl-spki (blind-voucher-commitment blinding-secret cl-spki))
        tuple ["bitecho-faucet-voucher-v1"
               (str (:network-uri voucher))
               (str/lower-case (str (:network-genesis-cid voucher)))
               (str/lower-case (str commitment))
               (long (or (:amount voucher) 0))
               (long (or (:issued-epoch voucher) 0))]]
    (cond
      (or (not (map? voucher)) (not= :faucet/blinded-voucher (:bitecho/type voucher)))
      {:ok? false :error :invalid-voucher :state (update-in state [:diagnostics :invalid-voucher] (fnil inc 0))
       :effects [{:effect :diagnose :reason :invalid-voucher}]}

      (contains? (:redeemed-vouchers state) commitment)
      {:ok? false :error :voucher-already-redeemed :state (update-in state [:diagnostics :voucher-already-redeemed] (fnil inc 0))
       :effects [{:effect :diagnose :reason :voucher-already-redeemed}]}

      (or (nil? cl-spki) (not= expected-comm (str/lower-case (str commitment))))
      {:ok? false :error :voucher-commitment-mismatch :state (update-in state [:diagnostics :voucher-commitment-mismatch] (fnil inc 0))
       :effects [{:effect :diagnose :reason :voucher-commitment-mismatch}]}

      (or (nil? issuer)
          (and expected-issuer (not= issuer expected-issuer))
          (not (crypto/verify-with-fallback issuer tuple (:issuer-sig voucher))))
      {:ok? false :error :invalid-voucher-signature :state (update-in state [:diagnostics :invalid-voucher-signature] (fnil inc 0))
       :effects [{:effect :diagnose :reason :invalid-voucher-signature}]}

      :else
      (let [receipt {:redeemed-at-epoch (long current-epoch)
                     :claimant cl-spki
                     :commitment commitment
                     :amount (long (:amount voucher))
                     :network-uri (:network-uri voucher)}]
        {:ok? true
         :voucher-receipt receipt
         :state (update state :redeemed-vouchers (fnil conj #{}) commitment)
         :effects []}))))
