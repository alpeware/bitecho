(ns bitecho.webauthn
  "WebAuthn / CTAP2 structures, authenticatorData parsers, attestationObject decoders,
   discoverable credential seed recovery, PRF extensions, non-extractable WebCrypto key specs,
   and cold-certifies-hot DAC delegation for Human Anchors (Milestone 11)."
  (:require [bitecho.bech32m :as bech32m]
            [bitecho.cbor :as cbor]
            [bitecho.crypto :as crypto]
            [bitecho.fido :as fido]
            [bitecho.light-node.core :as light-core]
            [clojure.string :as str]))

;;; ---------------------------------------------------------------------------
;;; Disclosures & Policy Constants
;;; ---------------------------------------------------------------------------

(def ^:const ^{:doc "Explicit trust boundary disclosure regarding memory seed recovery."}
  trust-boundary-disclosure
  "Trust boundary: when using user.id/PRF seed recovery, the 32-byte seed is reconstructed in browser memory during signing; the local device and JavaScript bundle (verified via SRI) must be trusted.")

(def ^:const ^{:doc "Origin scoping disclosure for WebAuthn RP ID boundaries."}
  origin-scoping-disclosure
  "Credentials are scoped per WebAuthn RP ID / origin; self-hosted origins must re-register or import via backup seed.")

(def ^:const ^{:doc "Non-extractable WebCrypto key warning."}
  non-extractable-warning
  "Non-extractable WebCrypto key: no backups possible. If browser storage is cleared, this identity cannot be recovered.")

(def ^:const ^{:doc "Yubico central enrollment status per decentralized architecture decision."}
  yubico-enrollment-policy
  {:yubico-enrollment :parked
   :reason "Centralizing step in tension with Bitecho decentralized ethos"})

;;; ---------------------------------------------------------------------------
;;; Byte Helpers
;;; ---------------------------------------------------------------------------

(defn- to-byte-seq [bytes-or-seq]
  #?(:clj
     (cond
       (bytes? bytes-or-seq) (mapv #(bit-and (int %) 0xff) ^bytes bytes-or-seq)
       (sequential? bytes-or-seq) (mapv #(bit-and (int %) 0xff) bytes-or-seq)
       :else nil)
     :cljs
     (cond
       (instance? js/Uint8Array bytes-or-seq) (vec (js/Array.from bytes-or-seq))
       (sequential? bytes-or-seq) (mapv #(bit-and (int %) 0xff) bytes-or-seq)
       :else nil)))

(defn- to-byte-array [seq-of-ints]
  #?(:clj  (byte-array (map byte (map #(if (> % 127) (- % 256) %) seq-of-ints)))
     :cljs (js/Uint8Array. (clj->js seq-of-ints))))

(defn- bytes->hex-str [ba]
  #?(:clj
     (let [sb (StringBuilder.)]
       (doseq [b ba]
         (.append sb (String/format "%02x" (to-array [(bit-and (int b) 0xff)]))))
       (.toString sb))
     :cljs
     (let [arr (if (instance? js/Uint8Array ba) ba (js/Uint8Array. (clj->js ba)))]
       (apply str (map (fn [b]
                         (let [s (.toString b 16)]
                           (if (< (count s) 2) (str "0" s) s)))
                       arr)))))

(defn- u16 [b1 b2]
  (bit-or (bit-shift-left (bit-and (int b1) 0xff) 8)
          (bit-and (int b2) 0xff)))

(defn- u32 [b1 b2 b3 b4]
  (+ (* (bit-and (int b1) 0xff) 0x1000000)
     (* (bit-and (int b2) 0xff) 0x10000)
     (* (bit-and (int b3) 0xff) 0x100)
     (bit-and (int b4) 0xff)))

;;; ---------------------------------------------------------------------------
;;; authenticatorData & attestationObject Parsing
;;; ---------------------------------------------------------------------------

(defn parse-auth-data
  "Parses binary authenticatorData (RFC / W3C WebAuthn §6.1).
   Extracts rpIdHash, flags (UP, UV, BE, BS, AT, ED), signCount,
   and if attestedCredentialData is present: AAGUID, credentialId, decoded COSE key,
   and optional decoded CBOR extensions."
  [data-bytes]
  (when-let [bs (to-byte-seq data-bytes)]
    (when (>= (count bs) 37)
      (let [rp-id-hash (subvec bs 0 32)
            flags-byte (nth bs 32)
            up? (pos? (bit-and flags-byte 0x01))
            uv? (pos? (bit-and flags-byte 0x04))
            be? (pos? (bit-and flags-byte 0x08))
            bs? (pos? (bit-and flags-byte 0x10))
            at? (pos? (bit-and flags-byte 0x40))
            ed? (pos? (bit-and flags-byte 0x80))
            sign-count (u32 (nth bs 33) (nth bs 34) (nth bs 35) (nth bs 36))
            flags {:up? up? :uv? uv? :be? be? :bs? bs? :at? at? :ed? ed?}
            base-result {:rp-id-hash-bytes (to-byte-array rp-id-hash)
                         :rp-id-hash-hex (bytes->hex-str rp-id-hash)
                         :flags flags
                         :sign-count sign-count}]
        (if-not at?
          base-result
          (let [aaguid-bytes (subvec bs 37 53)
                aaguid-hex (bytes->hex-str aaguid-bytes)
                aaguid-uuid (fido/normalize-aaguid aaguid-hex)
                cred-id-len (u16 (nth bs 53) (nth bs 54))
                cred-id-end (+ 55 cred-id-len)
                cred-id (subvec bs 55 cred-id-end)
                remaining-offset cred-id-end
                [cose-key after-cose-offset] (if (< remaining-offset (count bs))
                                               (cbor/decode-first bs remaining-offset)
                                               [nil remaining-offset])
                [extensions _] (if (and ed? (< after-cose-offset (count bs)))
                                 (cbor/decode-first bs after-cose-offset)
                                 [nil after-cose-offset])
                strength-hint (fido/evaluate-authenticator-strength {:aaguid aaguid-uuid
                                                                     :up? up? :uv? uv?
                                                                     :be? be? :bs? bs?})]
            (assoc base-result
                   :aaguid aaguid-uuid
                   :aaguid-bytes (to-byte-array aaguid-bytes)
                   :cred-id-len cred-id-len
                   :credential-id (to-byte-array cred-id)
                   :credential-id-hex (bytes->hex-str cred-id)
                   :cose-key cose-key
                   :extensions extensions
                   :strength-hint strength-hint)))))))

(defn parse-attestation-object
  "Decodes a WebAuthn attestationObject CBOR structure (fmt, attStmt, authData)
   and parses its authenticatorData."
  [cbor-bytes]
  (when-let [decoded (cbor/decode cbor-bytes)]
    (when (map? decoded)
      (let [fmt (get decoded "fmt" (get decoded :fmt))
            att-stmt (get decoded "attStmt" (get decoded :attStmt))
            auth-data-raw (get decoded "authData" (get decoded :authData))
            parsed-auth (parse-auth-data auth-data-raw)]
        {:fmt fmt
         :att-stmt att-stmt
         :auth-data parsed-auth
         :aaguid (:aaguid parsed-auth)
         :credential-id (:credential-id parsed-auth)
         :cose-key (:cose-key parsed-auth)
         :strength-hint (:strength-hint parsed-auth)
         :yubico-enrollment :parked}))))

;;; ---------------------------------------------------------------------------
;;; Discoverable Credential & PRF Seed Management (Step 11B)
;;; ---------------------------------------------------------------------------

(defn build-registration-options
  "Builds WebAuthn PublicKeyCredentialCreationOptions for discoverable credential
   registration with 32-byte seed entropy stored in user.id and PRF extension."
  ([] (build-registration-options {}))
  ([opts]
   (let [seed (or (:seed-bytes opts) (crypto/random-bytes 32))
         challenge (or (:challenge opts) (crypto/random-bytes 32))
         rp-name (or (:rp-name opts) "Bitecho")
         rp-id (or (:rp-id opts) "bitecho.org")
         username (or (:username opts) "anchor")
         display-name (or (:display-name opts) "Human Anchor")
         timeout (or (:timeout opts) 300000)]
     {:challenge challenge
      :rp {:name rp-name :id rp-id}
      :user {:id seed
             :name username
             :displayName display-name}
      :pubKeyCredParams [{:type "public-key" :alg -7}   ;; ES256
                         {:type "public-key" :alg -8}]  ;; Ed25519
      :authenticatorSelection {:residentKey "required"
                               :requireResidentKey true
                               :userVerification "required"
                               :authenticatorAttachment :cross-platform}
      :extensions {:credProtect {:credentialProtectionPolicy "userVerificationRequired"}
                   :prf {:eval {:first seed}}}
      :timeout timeout
      :attestation "direct"
      :metadata {:origin-scoping origin-scoping-disclosure
                 :trust-boundary trust-boundary-disclosure
                 :yubico-enrollment :parked}})))

(defn build-assertion-options
  "Builds WebAuthn PublicKeyCredentialRequestOptions for discoverable credential
   login/seed-recovery with allowCredentials: [] and userVerification: 'required'."
  ([] (build-assertion-options {}))
  ([opts]
   (let [challenge (or (:challenge opts) (crypto/random-bytes 32))
         rp-id (or (:rp-id opts) "bitecho.org")
         timeout (or (:timeout opts) 300000)]
     {:challenge challenge
      :rpId rp-id
      :allowCredentials []  ;; discoverable credential flow
      :userVerification "required"
      :extensions (when-let [seed (:seed-bytes opts)]
                    {:prf {:eval {:first seed}}})
      :timeout timeout
      :metadata {:origin-scoping origin-scoping-disclosure
                 :trust-boundary trust-boundary-disclosure}})))

(defn recover-seed-from-assertion
  "Recovers the 32-byte seed from WebAuthn assertion response (PRF extension output or userHandle)
   and deterministically derives the Ed25519 identity keypair."
  [assertion-or-response]
  (let [prf-out (or (when (map? assertion-or-response)
                      (or (:prf-output assertion-or-response)
                          (get-in assertion-or-response [:extensions :prf :results :first])
                          (get-in assertion-or-response [:client-extension-results :prf :results :first])))
                    #?(:cljs (when (and (some? assertion-or-response)
                                        (fn? (.-getClientExtensionResults assertion-or-response)))
                               (some-> (.getClientExtensionResults assertion-or-response)
                                       (.-prf)
                                       (.-results)
                                       (.-first)))))
        user-handle (or (when (map? assertion-or-response)
                          (or (get assertion-or-response :user-handle)
                              (get assertion-or-response "userHandle")
                              (get-in assertion-or-response [:response :user-handle])
                              (:user-id assertion-or-response)))
                        #?(:cljs (when (and (some? assertion-or-response)
                                            (some? (.-response assertion-or-response)))
                                   (.-userHandle (.-response assertion-or-response)))))
        raw-seed (or prf-out user-handle)
        recovery-source (if (some? prf-out) :prf :user-handle)]
    (when-let [bs (to-byte-seq raw-seed)]
      (let [seed-32 (cond
                      (= (count bs) 32) bs
                      (> (count bs) 32) (subvec bs 0 32)
                      :else (to-byte-seq (crypto/sha256 (to-byte-array bs))))
            seed-arr (to-byte-array seed-32)
            kp (crypto/pure-ed25519-keypair seed-arr)
            pub-hex (bytes->hex-str (to-byte-seq (:public kp)))
            bech-addr (bech32m/pubkey->bech32m pub-hex "ech")]
        {:seed seed-arr
         :recovery-source recovery-source
         :keypair kp
         :public-key (:public kp)
         :private-key (:private kp)
         :public-hex pub-hex
         :address bech-addr
         :origin-scoping origin-scoping-disclosure
         :trust-boundary trust-boundary-disclosure}))))

;;; ---------------------------------------------------------------------------
;;; Non-Extractable WebCrypto Key Specification & Browser Interop (Step 11B.1)
;;; ---------------------------------------------------------------------------

(defn generate-non-extractable-keypair-spec
  "Returns the specification and security warning metadata for native non-extractable WebCrypto keys."
  ([] (generate-non-extractable-keypair-spec {}))
  ([opts]
   (let [name (or (:algorithm opts) "Ed25519")]
     {:key-mode :webcrypto-non-extractable
      :algorithm {:name name}
      :extractable? false
      :key-usages ["sign" "verify"]
      :backup-available? false
      :warning non-extractable-warning})))

#?(:cljs
   (defn create-non-extractable-webcrypto-key!
     "Creates a native non-extractable WebCrypto keypair via crypto.subtle.generateKey(alg, false, ['sign','verify'])
      when WebCrypto SubtleCrypto is available in the browser; invokes (cb err result-map)."
     [opts cb]
     (let [spec (generate-non-extractable-keypair-spec opts)]
       (if (and (exists? js/globalThis)
                (.-crypto js/globalThis)
                (.-subtle (.-crypto js/globalThis)))
         (-> (.generateKey (.-subtle (.-crypto js/globalThis))
                           (clj->js (:algorithm spec))
                           false
                           (clj->js (:key-usages spec)))
             (.then (fn [kp]
                      (cb nil (assoc spec
                                     :webcrypto-keypair kp
                                     :public-key-handle (.-publicKey kp)
                                     :private-key-handle (.-privateKey kp)))))
             (.catch (fn [err]
                       (cb {:error (str err) :spec spec} nil))))
         (cb nil spec)))))

#?(:cljs
   (defn create-discoverable-credential!
     "Executes navigator.credentials.create({publicKey: ...}) in the browser for a YubiKey
      discoverable credential (residentKey: required, credProtect: userVerificationRequired,
      32-byte seed in user.id, PRF extension). Never transmits anything to a server."
     [opts cb]
     (let [reg-opts (build-registration-options opts)]
       (if (and (exists? js/navigator) (.-credentials js/navigator))
         (-> (.create (.-credentials js/navigator)
                      (clj->js {:publicKey (dissoc reg-opts :metadata)}))
             (.then (fn [cred]
                      (let [att-buf (some-> cred (.-response) (.-attestationObject))
                            att-bytes (when att-buf (js/Uint8Array. att-buf))
                            parsed-att (when att-bytes (parse-attestation-object att-bytes))
                            recovered (recover-seed-from-assertion {:user-handle (get-in reg-opts [:user :id])})]
                        (cb nil {:credential cred
                                 :registration-options reg-opts
                                 :attestation parsed-att
                                 :identity recovered}))))
             (.catch (fn [err]
                       (cb {:error (str err)} nil))))
         (cb {:error "webauthn-navigator-credentials-unavailable" :registration-options reg-opts} nil)))))

#?(:cljs
   (defn get-discoverable-credential!
     "Executes navigator.credentials.get({publicKey: ...}) with allowCredentials: []
      to recover the 32-byte seed from userHandle or PRF extension on a YubiKey."
     [opts cb]
     (let [req-opts (build-assertion-options opts)]
       (if (and (exists? js/navigator) (.-credentials js/navigator))
         (-> (.get (.-credentials js/navigator)
                   (clj->js {:publicKey (dissoc req-opts :metadata)}))
             (.then (fn [assertion]
                      (cb nil (recover-seed-from-assertion assertion))))
             (.catch (fn [err]
                       (cb {:error (str err)} nil))))
         (cb {:error "webauthn-navigator-credentials-unavailable" :assertion-options req-opts} nil)))))

;;; ---------------------------------------------------------------------------
;;; Cold-Certifies-Hot DAC & Second-Key Redundancy (Step 11B)
;;; ---------------------------------------------------------------------------

(defn- to-valid-spki-hex [pub]
  (cond
    (string? pub)
    (let [clean (str/lower-case (str/trim pub))]
      (cond
        (= (count clean) 88) clean
        (= (count clean) 64) (str "302a300506032b6570032100" clean)
        :else nil))

    #?(:clj (bytes? pub) :cljs (instance? js/Uint8Array pub))
    (let [bs (to-byte-seq pub)]
      (cond
        (= (count bs) 44) (bytes->hex-str bs)
        (= (count bs) 32) (str "302a300506032b6570032100" (bytes->hex-str bs))
        :else nil))

    (sequential? pub)
    (cond
      (= (count pub) 44) (bytes->hex-str pub)
      (= (count pub) 32) (str "302a300506032b6570032100" (bytes->hex-str pub))
      :else nil)

    :else nil))

(defn- to-pkcs8-der [priv]
  (let [bs (to-byte-seq priv)]
    (cond
      (= (count bs) 48) (to-byte-array bs)
      (= (count bs) 32)
      (let [prefix [0x30 0x2e 0x02 0x01 0x00 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x04 0x22 0x04 0x20]]
        (to-byte-array (concat prefix bs)))
      :else (to-byte-array bs))))

(defn cold-certify-hot-key
  "Issues a Delegation Attestation Certificate (DAC) from an anchor cold key to a hot operational key."
  [cold-privkey hot-pubkey & [opts]]
  (let [pkcs8-priv (to-pkcs8-der cold-privkey)
        seed (take-last 32 (to-byte-seq pkcs8-priv))
        cold-kp (crypto/pure-ed25519-keypair (to-byte-array seed))
        derived-spki (to-valid-spki-hex (:public cold-kp))
        anchor-pub-hex (or (when-let [p (:anchor-pubkey opts)] (to-valid-spki-hex p))
                           derived-spki)
        agent-pub-hex (to-valid-spki-hex hot-pubkey)
        params {:anchor-pubkey anchor-pub-hex
                :agent-pubkey agent-pub-hex
                :issued-epoch (or (:issued-epoch opts) 0)
                :expires-epoch (or (:expires-epoch opts) 1000)
                :max-spend-per-epoch (or (:max-spend-per-epoch opts) 10000)
                :scopes (or (:scopes opts) ["gossip" "offer" "settle-intent" "transfer"])}]
    (light-core/create-dac pkcs8-priv params)))

(defn register-backup-key
  "Registers a second hardware backup key configuration."
  [primary-state backup-opts]
  (let [backup-seed (or (:backup-seed backup-opts) (crypto/random-bytes 32))
        backup-kp (crypto/pure-ed25519-keypair backup-seed)
        backup-pub-hex (bytes->hex-str (to-byte-seq (:public backup-kp)))]
    (assoc primary-state
           :backup-key {:public-hex backup-pub-hex
                        :address (bech32m/pubkey->bech32m backup-pub-hex "ech")
                        :registered-at (or (:current-epoch primary-state) 0)
                        :description (or (:description backup-opts) "Secondary Hardware YubiKey Backup")
                        :yubico-enrollment :parked})))

(defn recover-from-backup-key
  "Recovers identity state using a verified backup key seed."
  [backup-seed]
  (recover-seed-from-assertion {:user-handle backup-seed}))
