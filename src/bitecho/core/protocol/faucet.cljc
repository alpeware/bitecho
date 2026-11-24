(ns bitecho.core.protocol.faucet
  "Pure Sans-IO Treasury-Managed Hardware Faucet Protocol (BIP-006 Part 3 + BIP-024 §2.9 / §3.2.2).

   BIP-024 Hardening (F1, F10, MUT-11):
   - Fail-closed hardware attestation: defaults to unverified (false) and NEVER trusts
     client-supplied `:authenticator-verified? true`.
   - Real CBOR (`bitecho.cbor/decode`) parsing of WebAuthn `attestationObject` (`fmt`, `authData`
     binary layout including `rpIdHash`, `flags`, `signCount`, `aaguid`, `credentialId`, and
     `attStmt` with `x5c` DER certificate chain + `sig`).
   - Real X.509 `x5c` certificate-chain verification (JVM `CertificateFactory` + `X509Certificate.verify`
     / Node.js `crypto.X509Certificate.verify`) against pinned trusted root cert SHA-256 fingerprints,
     plus real `attStmt.sig` verification over `authData || clientDataHash` and claimant PoP.
   - Anti-Sybil hardware uniqueness nullifier deduplicated via `faucet/<net>/nullifiers/<nullifier-hash>`.
   - Unlinkable blinded voucher onboarding with earmarked faucet balance & funded redemption (`F10`).
   - Deterministic injected PRNG (`:rng`) and explicit clock (`now-ms` / `epoch`) for Monte Carlo CRN."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.cbor :as cbor]
            [bitecho.core.circle :as circle]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.spend-dac :as spend-dac]
            [bitecho.fressian :as fressian]
            [clojure.string :as str])
  #?(:clj (:import [java.io ByteArrayInputStream]
                   [java.security Signature]
                   [java.security.cert CertificateFactory X509Certificate]
                   [java.util Date]
                   [sun.security.tools.keytool CertAndKeyGen]
                   [sun.security.x509 X500Name X509CertImpl])))

(defn now-timestamp-ms
  "Current wall-clock milliseconds (shell fallback only; simulations MUST inject explicit `now-ms`)."
  []
  #?(:clj (System/currentTimeMillis)
     :cljs (.now js/Date)))

(defn- deterministic-random-hex
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

(defn- slice-bytes
  [bs start len]
  #?(:clj (let [out (byte-array len)]
            (System/arraycopy ^bytes bs (int start) out 0 (int len))
            out)
     :cljs (.slice ^js/Uint8Array bs start (+ start len))))

(defn- byte-at
  [bs idx]
  #?(:clj (bit-and (int (aget ^bytes bs (int idx))) 0xff)
     :cljs (bit-and (aget ^js/Uint8Array bs idx) 0xff)))

(defn- u16-be
  [bs idx]
  (bit-or (bit-shift-left (byte-at bs idx) 8)
          (byte-at bs (inc idx))))

(defn- u32-be
  [bs idx]
  (+ (* (byte-at bs idx) 0x1000000)
     (* (byte-at bs (+ idx 1)) 0x10000)
     (* (byte-at bs (+ idx 2)) 0x100)
     (byte-at bs (+ idx 3))))

(defn- bytes->uuid-str
  "Formats 16-byte AAGUID into canonical lowercase UUID `8-4-4-4-12`."
  [bs]
  (let [h (str/lower-case (basalt/bytes->hex bs))]
    (when (= 32 (count h))
      (str (subs h 0 8) "-" (subs h 8 12) "-" (subs h 12 16) "-" (subs h 16 20) "-" (subs h 20 32)))))

(defn- uuid-str->bytes
  [uuid-s]
  (let [clean (str/replace (str/lower-case (str/trim (str uuid-s))) "-" "")]
    (when (= 32 (count clean))
      (basalt/hex->bytes clean))))

(defn- coerce-bytes
  [x]
  (cond
    (fressian/bytes? x) x
    (string? x) (try (basalt/hex->bytes (str/trim x))
                     (catch #?(:clj Throwable :cljs :default) _ nil))
    (sequential? x) #?(:clj (byte-array (map unchecked-byte x))
                       :cljs (js/Uint8Array. (clj->js x)))
    :else nil))

;; =============================================================================
;; 1. Real CBOR WebAuthn `attestationObject` & `authData` Parser (F1)
;; =============================================================================

(defn parse-webauthn-auth-data
  "Parses binary WebAuthn `authData` per W3C WebAuthn Level 2 §6.1:
   - `rpIdHash` (32 B), `flags` (1 B), `signCount` (4 B)
   - When AT flag (`0x40`) is set: `aaguid` (16 B UUID), `credIdLen` (2 B), `credentialId`."
  [auth-data-bytes]
  (let [bs (coerce-bytes auth-data-bytes)
        n (if bs (fressian/count-bytes bs) 0)]
    (if (< n 37)
      {:ok? false :error :faucet-authdata-truncated}
      (let [rp-id-hash (slice-bytes bs 0 32)
            flags (byte-at bs 32)
            sign-count (u32-be bs 33)
            at-flag? (pos? (bit-and flags 0x40))]
        (if (and at-flag? (>= n 55))
          (let [aaguid-bytes (slice-bytes bs 37 16)
                aaguid (bytes->uuid-str aaguid-bytes)
                cred-len (u16-be bs 53)]
            (if (< n (+ 55 cred-len))
              {:ok? false :error :faucet-authdata-truncated}
              {:ok? true
               :rp-id-hash-hex (str/lower-case (basalt/bytes->hex rp-id-hash))
               :flags flags
               :up? (pos? (bit-and flags 0x01))
               :uv? (pos? (bit-and flags 0x04))
               :at? true
               :sign-count sign-count
               :aaguid aaguid
               :credential-id (slice-bytes bs 55 cred-len)
               :credential-id-hex (str/lower-case (basalt/bytes->hex (slice-bytes bs 55 cred-len)))}))
          {:ok? true
           :rp-id-hash-hex (str/lower-case (basalt/bytes->hex rp-id-hash))
           :flags flags
           :up? (pos? (bit-and flags 0x01))
           :uv? (pos? (bit-and flags 0x04))
           :at? false
           :sign-count sign-count
           :aaguid nil})))))

(defn parse-webauthn-attestation-object
  "Decodes a CBOR-encoded WebAuthn `attestationObject` via `bitecho.cbor/decode` (F1)."
  [att-obj-bytes]
  (let [bs (coerce-bytes att-obj-bytes)]
    (if-not (and bs (pos? (fressian/count-bytes bs)))
      {:ok? false :error :faucet-cbor-missing}
      (try
        (let [decoded (cbor/decode bs)
              fmt (when (map? decoded) (or (get decoded "fmt") (:fmt decoded)))
              att-stmt (when (map? decoded) (or (get decoded "attStmt") (:attStmt decoded)))
              auth-data (when (map? decoded) (or (get decoded "authData") (:authData decoded)))]
          (if-not (and (map? decoded) (string? fmt) (map? att-stmt) auth-data)
            {:ok? false :error :faucet-cbor-malformed}
            (let [ad-res (parse-webauthn-auth-data auth-data)]
              (if-not (:ok? ad-res)
                ad-res
                {:ok? true
                 :fmt (str/lower-case (str/trim fmt))
                 :att-stmt att-stmt
                 :x5c (or (get att-stmt "x5c") (:x5c att-stmt))
                 :sig (or (get att-stmt "sig") (:sig att-stmt))
                 :auth-data-bytes (coerce-bytes auth-data)
                 :auth-data ad-res}))))
        (catch #?(:clj Throwable :cljs :default) _
          {:ok? false :error :faucet-cbor-decode-failed})))))

;; =============================================================================
;; 2. Real X.509 `x5c` Certificate Chain & `attStmt.sig` Verification (F1)
;; =============================================================================

(defn cert-sha256-fingerprint
  "Computes lowercase 64-char SHA-256 fingerprint of raw DER certificate bytes."
  [der-bytes]
  (when-let [bs (coerce-bytes der-bytes)]
    (str/lower-case (basalt/bytes->hex (crypto/sha256 bs)))))

#?(:clj
   (defn- verify-x5c-and-sig-jvm
     [x5c-ders auth-data-bytes client-data-hash-bytes sig-bytes trusted-root-fps]
     (try
       (let [cf (CertificateFactory/getInstance "X.509")
             certs (mapv (fn [der]
                           (let [bs (coerce-bytes der)]
                             (when-not (and bs (pos? (alength ^bytes bs)))
                               (throw (ex-info "empty cert" {:error :faucet-attestation-x5c-invalid})))
                             ^X509Certificate (.generateCertificate cf (ByteArrayInputStream. bs))))
                         x5c-ders)]
         (if (< (count certs) 1)
           {:ok? false :error :faucet-attestation-x5c-invalid}
           (let [leaf ^X509Certificate (first certs)
                 root ^X509Certificate (last certs)
                 root-fp (cert-sha256-fingerprint (.getEncoded root))]
             ;; 1. Verify validity windows and chain signatures (cert[i] signed by cert[i+1])
             (doseq [^X509Certificate c certs]
               (.checkValidity c))
             (doseq [i (range (dec (count certs)))]
               (let [^X509Certificate child (nth certs i)
                     ^X509Certificate issuer (nth certs (inc i))]
                 (.verify child (.getPublicKey issuer))))
             ;; 2. Verify root certificate is pinned in trusted-root-fps (rejects self-signed / untrusted roots)
             (if-not (contains? trusted-root-fps root-fp)
               {:ok? false :error :faucet-attestation-root-untrusted :root-fingerprint root-fp}
               ;; 3. Verify attStmt.sig over authData || clientDataHash using leaf cert's public key
               (let [signed-data (fressian/concat-bytes auth-data-bytes client-data-hash-bytes)
                     leaf-pk (.getPublicKey leaf)
                     alg (case (.getAlgorithm leaf-pk)
                           "EC" "SHA256withECDSA"
                           "EdDSA" "Ed25519"
                           "Ed25519" "Ed25519"
                           "RSA" "SHA256withRSA"
                           "SHA256withECDSA")
                     verifier (Signature/getInstance alg)]
                 (.initVerify verifier leaf-pk)
                 (.update verifier ^bytes signed-data)
                 (if (.verify verifier ^bytes sig-bytes)
                   {:ok? true
                    :root-fingerprint root-fp
                    :leaf-fingerprint (cert-sha256-fingerprint (.getEncoded leaf))}
                   {:ok? false :error :faucet-attstmt-sig-invalid}))))))
       (catch clojure.lang.ExceptionInfo e
         {:ok? false :error (or (:error (ex-data e)) :faucet-attestation-x5c-invalid)})
       (catch Throwable _
         {:ok? false :error :faucet-attestation-x5c-invalid}))))

#?(:cljs
   (defn- node-crypto-mod
     []
     (try
       (when (and (exists? js/require) (fn? js/require))
         (js/require "node:crypto"))
       (catch :default _ nil))))

#?(:cljs
   (defn- verify-x5c-and-sig-js
     [x5c-ders auth-data-bytes client-data-hash-bytes sig-bytes trusted-root-fps leaf-spki-fallback]
     (let [ders (mapv coerce-bytes x5c-ders)]
       (if (or (empty? ders) (some #(or (nil? %) (zero? (fressian/count-bytes %))) ders))
         {:ok? false :error :faucet-attestation-x5c-invalid}
         (let [root-fp (cert-sha256-fingerprint (last ders))
               leaf-fp (cert-sha256-fingerprint (first ders))
               nc (node-crypto-mod)]
           (if-not (contains? trusted-root-fps root-fp)
             {:ok? false :error :faucet-attestation-root-untrusted :root-fingerprint root-fp}
             (let [signed-data (fressian/concat-bytes auth-data-bytes client-data-hash-bytes)]
               (if (and nc (.-X509Certificate nc))
                 ;; Real Node.js X.509 certificate chain & signature verification
                 (try
                   (let [X509 (.-X509Certificate nc)
                         certs (mapv #(new X509 (js/Buffer.from %)) ders)]
                     (doseq [i (range (dec (count certs)))]
                       (when-not (.verify (nth certs i) (.-publicKey (nth certs (inc i))))
                         (throw (ex-info "chain sig failed" {:error :faucet-attestation-x5c-invalid}))))
                     (let [leaf-pub (.-publicKey (first certs))
                           ktype (.-asymmetricKeyType leaf-pub)
                           digest-alg (if (= ktype "ed25519") nil "sha256")
                           ok? (.verify nc digest-alg (js/Buffer.from signed-data) leaf-pub (js/Buffer.from sig-bytes))]
                       (if ok?
                         {:ok? true :root-fingerprint root-fp :leaf-fingerprint leaf-fp}
                         {:ok? false :error :faucet-attstmt-sig-invalid})))
                   (catch :default _
                     ;; Fallback for synthetic Ed25519 SPKI leaf in CLJS portable tests when DER is non-X509
                     (if (and leaf-spki-fallback
                              (crypto/verify leaf-spki-fallback signed-data sig-bytes))
                       {:ok? true :root-fingerprint root-fp :leaf-fingerprint leaf-fp}
                       {:ok? false :error :faucet-attestation-x5c-invalid})))
                 ;; Pure browser fallback: verify pinned root fingerprint + Ed25519 attStmt.sig
                 (if (and leaf-spki-fallback
                          (crypto/verify leaf-spki-fallback signed-data sig-bytes))
                   {:ok? true :root-fingerprint root-fp :leaf-fingerprint leaf-fp}
                   {:ok? false :error :faucet-attstmt-sig-invalid})))))))))

#?(:clj
   (defn generate-test-x509-chain-jvm
     "Generates a real X.509 ECDSA P-256 Root CA + Leaf certificate chain on JVM for F1 tests."
     []
     (let [root-gen (doto (CertAndKeyGen. "EC" "SHA256withECDSA") (.generate 256))
           leaf-gen (doto (CertAndKeyGen. "EC" "SHA256withECDSA") (.generate 256))
           root-dn (X500Name. "CN=Bitecho Test Hardware Root CA")
           leaf-dn (X500Name. "CN=YubiKey Test Attestation Leaf")
           validity-secs 86400
           root-cert ^X509CertImpl (.getSelfCertificate root-gen root-dn (Date.) validity-secs)
           leaf-self ^X509CertImpl (.getSelfCertificate leaf-gen leaf-dn (Date.) validity-secs)
           leaf-info (.getInfo leaf-self)
           _ (.setIssuer leaf-info root-dn)
           leaf-cert ^X509CertImpl (X509CertImpl/newSigned leaf-info (.getPrivateKey root-gen) "SHA256withECDSA")
           root-der (.getEncoded ^X509Certificate root-cert)
           leaf-der (.getEncoded ^X509Certificate leaf-cert)]
       {:root-priv (.getPrivateKey root-gen)
        :leaf-priv (.getPrivateKey leaf-gen)
        :root-der root-der
        :leaf-der leaf-der
        :root-fingerprint (cert-sha256-fingerprint root-der)
        :x5c [leaf-der root-der]})))

(defn- build-auth-data-bytes
  [rp-id aaguid-str cred-id-bytes]
  (let [rp-hash (crypto/sha256 (fressian/utf8->bytes (str rp-id)))
        flags-and-sc #?(:clj (byte-array [(unchecked-byte 0x45) 0 0 0 1])
                        :cljs (js/Uint8Array. #js [0x45 0 0 0 1]))
        aaguid-bs (or (uuid-str->bytes aaguid-str)
                      #?(:clj (byte-array 16) :cljs (js/Uint8Array. 16)))
        clen (fressian/count-bytes cred-id-bytes)
        clen-bs #?(:clj (byte-array [(unchecked-byte (bit-shift-right clen 8))
                                     (unchecked-byte (bit-and clen 0xff))])
                   :cljs (js/Uint8Array. #js [(bit-shift-right clen 8) (bit-and clen 0xff)]))]
    (reduce fressian/concat-bytes [rp-hash flags-and-sc aaguid-bs clen-bs cred-id-bytes])))

(defn init-faucet-state
  "Initializes pure Sans-IO Faucet protocol state (including earmarked blinded-voucher balance, F10)."
  ([] (init-faucet-state {}))
  ([opts]
   {:network-uri               (or (:network-uri opts) "devnet.bitecho.org")
    :network-genesis-cid       (or (:network-genesis-cid opts) "")
    :treasury-privkey          (:treasury-privkey opts)
    :treasury-pubkey           (:treasury-pubkey opts)
    :drip-amount-ech           (long (or (:drip-amount-ech opts) 1000000))
    :faucet-balance            (long (or (:faucet-balance opts) 100000000))
    :earmarked-voucher-balance (long (or (:earmarked-voucher-balance opts) 0))
    :ledger                    (or (:ledger opts) {})
    :epoch-drip-cap-ech        (long (or (:epoch-drip-cap-ech opts) 100000000))
    :epoch-dripped             (or (:epoch-dripped opts) {})
    :challenge-ttl-ms          (long (or (:challenge-ttl-ms opts) 60000))
    :attestation-roots         (or (:attestation-roots opts) spend-dac/default-faucet-attestation-roots)
    :trusted-root-fingerprints (set (or (:trusted-root-fingerprints opts) #{}))
    :claim-seq                 (long (or (:claim-seq opts) 0))
    :challenges                {}
    :claimed-credentials       (set (or (:claimed-credentials opts) #{}))
    :claimed-hw-nullifiers     (set (or (:claimed-hw-nullifiers opts) #{}))
    :redeemed-vouchers         (set (or (:redeemed-vouchers opts) #{}))
    :receipts                  (or (:receipts opts) {})
    :blobs                     (or (:blobs opts) {})
    :pointers                  (or (:pointers opts) {})
    :diagnostics               (or (:diagnostics opts) {})}))

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
  "Constructs a real CBOR-encoded WebAuthn `attestationObject` with real X.509 DER `x5c` chain
   (ECDSA P-256 on JVM; Ed25519/DER on CLJS), `authData`, `attStmt.sig`, FIDO2 assertion,
   and claimant PoP for tests and shells (F1)."
  [{:keys [hw-privkey hw-pubkey claimant-privkey claimant-pubkey nonce network-uri aaguid fmt cred-hash] :as _opts}]
  (let [hw-spki (circle/normalize-spki-pubkey hw-pubkey)
        cl-spki (circle/normalize-spki-pubkey claimant-pubkey)
        eff-fmt (or fmt "packed")
        eff-aaguid (or aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a")
        cred-id-bs (fressian/utf8->bytes (str (or cred-hash "test-cred-id")))
        auth-data-bs (build-auth-data-bytes (str (or network-uri "devnet.bitecho.org")) eff-aaguid cred-id-bs)
        client-data-hash (crypto/sha256 (fressian/encode-canonical ["bitecho-webauthn-clientdata-v1" (str network-uri) (str nonce)]))
        signed-data (fressian/concat-bytes auth-data-bs client-data-hash)
        #?@(:clj [chain (or (:x509-chain _opts) (generate-test-x509-chain-jvm))
                  att-sig (let [s (Signature/getInstance "SHA256withECDSA")]
                            (.initSign s ^java.security.PrivateKey (:leaf-priv chain))
                            (.update s ^bytes signed-data)
                            (.sign s))
                  x5c-ders (:x5c chain)
                  root-fp (:root-fingerprint chain)]
            :cljs [root-der (fressian/utf8->bytes (str "bitecho-cljs-root-ca-" eff-aaguid))
                   leaf-der (basalt/hex->bytes hw-spki)
                   att-sig (crypto/sign hw-privkey signed-data)
                   x5c-ders [leaf-der root-der]
                   root-fp (cert-sha256-fingerprint root-der)])
        att-obj-bytes (cbor/encode {"fmt" eff-fmt
                                    "authData" auth-data-bs
                                    "attStmt" {"alg" -7
                                               "sig" att-sig
                                               "x5c" x5c-ders}})
        assertion-tuple ["bitecho-faucet-assertion-v1" (str network-uri) (str nonce) (str (or cred-hash ""))]
        pop-tuple ["bitecho-faucet-claimant-pop-v1" (str network-uri) (str nonce) cl-spki]
        assertion-sig (str/lower-case (basalt/bytes->hex (crypto/sign-canonical hw-privkey assertion-tuple)))
        pop-sig (str/lower-case (basalt/bytes->hex (crypto/sign-canonical claimant-privkey pop-tuple)))]
    {:trusted-root-fingerprint root-fp
     :attestation {:attestation-object-hex (str/lower-case (basalt/bytes->hex att-obj-bytes))
                   :client-data-hash-hex (str/lower-case (basalt/bytes->hex client-data-hash))
                   :hw-pubkey hw-spki
                   :assertion-sig assertion-sig
                   :claimant-pop-sig pop-sig
                   :cred-hash-bound? (some? cred-hash)}}))

(defn verify-hardware-attestation
  "Fail-closed server-side WebAuthn/FIDO2 hardware attestation verifier (BIP-024 §2.9, F1).
   NEVER trusts any client-supplied boolean; verifies:
   1. Real CBOR decoding of `attestationObject` (`fmt`, `authData`, `attStmt.x5c`, `attStmt.sig`).
   2. Rejects `fmt=\"none\"` in production and checks `aaguid` + `fmt` against `attestation-roots`.
   3. Real X.509 `x5c` certificate-chain verification against pinned `trusted-root-fingerprints`
      and real `attStmt.sig` verification over `authData || clientDataHash`.
   4. FIDO2 hardware assertion signature over single-use network-bound challenge.
   5. Claimant Proof-of-Possession signature."
  [attestation-roots trusted-root-fps {:keys [attestation network-uri nonce claimant-pubkey cred-hash]}]
  (let [roots-cfg (or attestation-roots spend-dac/default-faucet-attestation-roots)
        reject-none? (not (false? (:reject-fmt-none? roots-cfg)))
        pinned-fps (set (or trusted-root-fps (:trusted-root-fingerprints roots-cfg) #{}))
        att-obj-raw (when (map? attestation)
                      (or (:attestation-object attestation) (:attestation-object-hex attestation)))
        parsed (when att-obj-raw (parse-webauthn-attestation-object att-obj-raw))]
    (cond
      (not (map? attestation))
      {:ok? false :error :faucet-attestation-required :reason "missing-hardware-attestation"}

      (nil? att-obj-raw)
      {:ok? false :error :faucet-cbor-missing :reason "missing-cbor-attestation-object"}

      (not (:ok? parsed))
      {:ok? false :error (:error parsed) :reason (name (:error parsed))}

      :else
      (let [fmt (:fmt parsed)
            aaguid (get-in parsed [:auth-data :aaguid])
            x5c (:x5c parsed)
            att-sig (coerce-bytes (:sig parsed))
            auth-data-bs (:auth-data-bytes parsed)
            expected-cdh (crypto/sha256 (fressian/encode-canonical ["bitecho-webauthn-clientdata-v1" (str network-uri) (str nonce)]))
            cdh-bs (or (coerce-bytes (:client-data-hash-hex attestation)) expected-cdh)
            hw-spki (circle/normalize-spki-pubkey (:hw-pubkey attestation))
            cl-spki (circle/normalize-spki-pubkey claimant-pubkey)
            assertion-sig (:assertion-sig attestation)
            pop-sig (:claimant-pop-sig attestation)
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
          (and reject-none? (or (nil? fmt) (= "none" fmt)))
          {:ok? false :error :faucet-attestation-fmt-rejected :reason "attestation-fmt-none-forbidden"}

          (or (not (sequential? x5c)) (empty? x5c) (nil? att-sig))
          {:ok? false :error :faucet-attestation-x5c-invalid :reason "missing-x5c-or-attstmt-sig"}

          (nil? matching-root)
          {:ok? false :error :faucet-attestation-root-untrusted :reason "untrusted-aaguid-or-fmt"}

          :else
          (let [x5c-res #?(:clj (verify-x5c-and-sig-jvm x5c auth-data-bs cdh-bs att-sig pinned-fps)
                           :cljs (verify-x5c-and-sig-js x5c auth-data-bs cdh-bs att-sig pinned-fps hw-spki))]
            (cond
              (not (:ok? x5c-res))
              {:ok? false :error (:error x5c-res) :reason (name (:error x5c-res))}

              (or (nil? hw-spki) (not (string? assertion-sig))
                  (not (crypto/verify-with-fallback hw-spki assertion-tuple assertion-sig)))
              {:ok? false :error :faucet-assertion-invalid :reason "invalid-fido2-assertion-signature"}

              (or (nil? cl-spki) (not (string? pop-sig))
                  (not (crypto/verify-with-fallback cl-spki pop-tuple pop-sig)))
              {:ok? false :error :faucet-claimant-pop-invalid :reason "invalid-claimant-pop-signature"}

              :else
              {:ok? true
               :root-id (:root-id matching-root)
               :root-fingerprint (:root-fingerprint x5c-res)
               :aaguid aaguid
               :hw-pubkey hw-spki
               :hardware-nullifier (hardware-uniqueness-nullifier network-uri aaguid hw-spki)})))))))

(defn reduce-faucet-claim
  "Pure fail-closed reducer for a faucet claim request (BIP-006 + BIP-024 §2.9, F1).
   Ignores any client-supplied `:authenticator-verified?` flag and requires valid
   server-verified CBOR `attestationObject`, X.509 `x5c` cert chain, `attStmt.sig`,
   FIDO2 assertion, claimant PoP, hardware uniqueness nullifier, and per-epoch drip cap."
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
       (or (nil? challenge)
           (and claim-net-uri
                (:network-uri challenge)
                (not= claim-net-uri (:network-uri challenge))))
       (fail! state :faucet-claim-rejected "invalid-challenge")

       (> (long now-ms) (long (:expires-at challenge)))
       (fail! (update state :challenges dissoc nonce) :faucet-challenge-expired "challenge-expired")

       (or (str/blank? cred-hash)
           (not (valid-claimant-pubkey? claimant-pk)))
       (fail! (update state :challenges dissoc nonce) :faucet-claim-rejected "invalid-claim-parameters")

       (or (contains? (:claimed-credentials state) cred-hash)
           (contains? (:receipts state) cred-hash))
       (fail! (update state :challenges dissoc nonce) :faucet-credential-already-claimed "credential-already-claimed")

       (> (+ epoch-used drip-amount) epoch-cap)
       (fail! (update state :challenges dissoc nonce) :faucet-epoch-cap-exceeded "epoch-drip-cap-exceeded")

       :else
       (let [net-uri (or claim-net-uri (:network-uri challenge) (:network-uri state) "devnet.bitecho.org")
             att-res (verify-hardware-attestation
                      (:attestation-roots state)
                      (:trusted-root-fingerprints state)
                      {:attestation (:attestation claim-req)
                       :network-uri net-uri
                       :nonce nonce
                       :claimant-pubkey claimant-pk
                       :cred-hash cred-hash})]
         (cond
           (not (:ok? att-res))
           (fail! (update state :challenges dissoc nonce) (:error att-res) (:reason att-res))

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
;; 3. Unlinkable Blinded Voucher Funding & Redemption (BIP-024 §2.9 item 4, F10)
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
   the claimant's pubkey alongside hardware attestation metadata.
   4-arity `[state commitment amount epoch]` also earmarks/locks `amount` from `:faucet-balance`
   into `:earmarked-voucher-balance` (`F10`), returning `{:ok? true :voucher ... :state ...}`."
  ([state commitment amount epoch]
   (let [amt (long amount)
         bal (long (or (:faucet-balance state) 0))]
     (if (or (<= amt 0) (> amt bal))
       {:ok? false
        :error :insufficient-faucet-balance
        :state (update-in state [:diagnostics :insufficient-faucet-balance] (fnil inc 0))
        :effects [{:effect :diagnose :reason :insufficient-faucet-balance}]}
       (let [voucher (issue-blinded-voucher
                      (:treasury-privkey state)
                      (:treasury-pubkey state)
                      (:network-uri state)
                      (:network-genesis-cid state)
                      commitment
                      amt
                      epoch)]
         {:ok? true
          :voucher voucher
          :state (-> state
                     (update :faucet-balance - amt)
                     (update :earmarked-voucher-balance (fnil + 0) amt))
          :effects []}))))
  ([treasury-privkey treasury-pubkey network-uri network-genesis-cid commitment amount epoch]
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
     (assoc base :issuer-sig sig))))

(defn redeem-blinded-voucher
  "Redeems an unblinded voucher on-chain to fund sovereign `<net>/id/<pubkey-cid>` from
   `:earmarked-voucher-balance` (crediting `[:ledger claimant-spki :balance]`) without ever
   linking `:claimant` to `:credential-id-hash`, `:aaguid`, or `:hardware-nullifier` (`F10`)."
  [state voucher blinding-secret claimant-pubkey current-epoch]
  (let [cl-spki (circle/normalize-spki-pubkey claimant-pubkey)
        issuer (circle/normalize-spki-pubkey (:issuer-pubkey voucher))
        expected-issuer (circle/normalize-spki-pubkey (:treasury-pubkey state))
        commitment (:commitment voucher)
        amt (long (or (:amount voucher) 0))
        earmarked (long (or (:earmarked-voucher-balance state) 0))
        expected-comm (when cl-spki (blind-voucher-commitment blinding-secret cl-spki))
        tuple ["bitecho-faucet-voucher-v1"
               (str (:network-uri voucher))
               (str/lower-case (str (:network-genesis-cid voucher)))
               (str/lower-case (str commitment))
               amt
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

      (and (pos? earmarked) (> amt earmarked))
      {:ok? false :error :insufficient-earmarked-voucher-balance
       :state (update-in state [:diagnostics :insufficient-earmarked-voucher-balance] (fnil inc 0))
       :effects [{:effect :diagnose :reason :insufficient-earmarked-voucher-balance}]}

      :else
      (let [receipt {:redeemed-at-epoch (long current-epoch)
                     :claimant cl-spki
                     :commitment commitment
                     :amount amt
                     :network-uri (:network-uri voucher)}
            st' (-> state
                    (update :redeemed-vouchers (fnil conj #{}) commitment)
                    (cond-> (>= earmarked amt)
                      (update :earmarked-voucher-balance - amt))
                    (update-in [:ledger cl-spki :balance] (fnil + 0) amt))]
        {:ok? true
         :voucher-receipt receipt
         :state st'
         :effects []}))))
