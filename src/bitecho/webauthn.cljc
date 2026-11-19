(ns bitecho.webauthn
  "WebAuthn / CTAP2 structures, authenticatorData parsers, attestationObject decoders,
   discoverable credential seed recovery, PRF extensions, non-extractable WebCrypto key specs,
   and cold-certifies-hot DAC delegation for Human Anchors (Milestone 11)."
  (:require [bitecho.bech32m :as bech32m]
            [bitecho.cbor :as cbor]
            [bitecho.crypto :as crypto]
            [bitecho.fido :as fido]
            [bitecho.light-node.core :as light-core]
            [clojure.string :as str]
            #?(:cljs [goog.object :as gobj])))

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
       (instance? java.nio.ByteBuffer bytes-or-seq)
       (let [dup (.duplicate ^java.nio.ByteBuffer bytes-or-seq)
             arr (byte-array (.remaining dup))]
         (.get dup arr)
         (mapv #(bit-and (int %) 0xff) arr))
       (sequential? bytes-or-seq) (mapv #(bit-and (int %) 0xff) bytes-or-seq)
       :else nil)
     :cljs
     (cond
       (instance? js/Uint8Array bytes-or-seq) (vec (js/Array.from bytes-or-seq))
       (and (exists? js/ArrayBuffer) (instance? js/ArrayBuffer bytes-or-seq))
       (vec (js/Array.from (js/Uint8Array. bytes-or-seq)))
       (and (exists? js/ArrayBuffer) (.isView js/ArrayBuffer bytes-or-seq))
       (vec (js/Array.from (js/Uint8Array. (.-buffer bytes-or-seq)
                                           (.-byteOffset bytes-or-seq)
                                           (.-byteLength bytes-or-seq))))
       (sequential? bytes-or-seq) (mapv #(bit-and (int %) 0xff) bytes-or-seq)
       :else nil)))

(defn- to-byte-array [seq-of-ints]
  #?(:clj  (byte-array (map byte (map #(if (> % 127) (- % 256) %) seq-of-ints)))
     :cljs (js/Uint8Array. (clj->js seq-of-ints))))

(defn ->byte-array
  "Converts input (byte[], Uint8Array, sequential of ints, or hex string) to platform byte array representation."
  [x]
  (cond
    (string? x)
    (let [cleaned (str/trim x)]
      (if (and (even? (count cleaned)) (re-matches #"^[0-9a-fA-F]+$" cleaned))
        (to-byte-array (mapv #(let [sub (subs cleaned (* 2 %) (+ (* 2 %) 2))]
                                #?(:clj (Integer/parseInt sub 16) :cljs (js/parseInt sub 16)))
                             (range (/ (count cleaned) 2))))
        (to-byte-array (mapv #(bit-and (int %) 0xff) #?(:clj (.getBytes cleaned "UTF-8")
                                                        :cljs (js/Array.from (.encode (js/TextEncoder.) cleaned)))))))
    #?(:clj (bytes? x) :cljs (instance? js/Uint8Array x)) x
    :else
    (when-let [bs (to-byte-seq x)]
      (to-byte-array bs))))

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
  (try
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
                  cred-id-end (+ 55 cred-id-len)]
              (when (<= cred-id-end (count bs))
                (let [cred-id (subvec bs 55 cred-id-end)
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
                         :strength-hint strength-hint))))))))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(defn parse-attestation-object
  "Decodes a WebAuthn attestationObject CBOR structure (fmt, attStmt, authData)
   and parses its authenticatorData."
  [cbor-bytes]
  (try
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
           :yubico-enrollment :parked})))
    (catch #?(:clj Exception :cljs :default) _ nil)))

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
      :pubKeyCredParams [{:type "public-key" :alg -7}     ;; ES256
                         {:type "public-key" :alg -8}     ;; Ed25519
                         {:type "public-key" :alg -257}]  ;; RS256
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

#?(:cljs
   (do
     (defn- js-prop
       "Externs-safe property lookup on native WebAuthn / DOM objects under Closure :advanced."
       [obj k]
       (when (and (some? obj) (object? obj))
         (gobj/get obj k)))

     (defn- js-call-0
       "Externs-safe 0-arg method invocation on native WebAuthn / DOM objects under Closure :advanced."
       [obj method-name]
       (when (and (some? obj) (object? obj))
         (when-let [f (gobj/get obj method-name)]
           (when (fn? f)
             (.call f obj)))))))

(defn recover-seed-from-assertion
  "Recovers the 32-byte seed from WebAuthn assertion response (userHandle as canonical default, with PRF extension fallback)
   and deterministically derives the Ed25519 identity keypair."
  [assertion-or-response]
  (try
    (let [user-handle (or (when (map? assertion-or-response)
                            (or (get assertion-or-response :user-handle)
                                (get assertion-or-response :userHandle)
                                (get assertion-or-response "userHandle")
                                (get assertion-or-response "user_handle")
                                (get-in assertion-or-response [:response :user-handle])
                                (get-in assertion-or-response [:response :userHandle])
                                (get-in assertion-or-response [:response "userHandle"])
                                (get-in assertion-or-response [:response "user_handle"])
                                (get-in assertion-or-response ["response" "userHandle"])
                                (get-in assertion-or-response ["response" "user_handle"])
                                (get-in assertion-or-response ["response" :user-handle])
                                (:user-id assertion-or-response)
                                (get assertion-or-response "user_id")))
                          #?(:cljs (when (some? assertion-or-response)
                                     (or (js-prop assertion-or-response "userHandle")
                                         (js-prop assertion-or-response "user_handle")
                                         (when-let [resp (js-prop assertion-or-response "response")]
                                           (or (js-prop resp "userHandle")
                                               (js-prop resp "user_handle")))))))
          prf-out (or (when (map? assertion-or-response)
                        (or (:prf-output assertion-or-response)
                            (:prfOutput assertion-or-response)
                            (get assertion-or-response "prfOutput")
                            (get assertion-or-response "prf_output")
                            (get-in assertion-or-response [:extensions :prf :results :first])
                            (get-in assertion-or-response [:client-extension-results :prf :results :first])
                            (get-in assertion-or-response [:clientExtensionResults :prf :results :first])
                            (get-in assertion-or-response ["clientExtensionResults" "prf" "results" "first"])
                            (get-in assertion-or-response ["extensions" "prf" "results" "first"])))
                      #?(:cljs (when (some? assertion-or-response)
                                 (let [cer (or (js-call-0 assertion-or-response "getClientExtensionResults")
                                               (js-prop assertion-or-response "clientExtensionResults")
                                               (js-prop assertion-or-response "client_extension_results")
                                               (js-prop assertion-or-response "extensions"))
                                       prf (or (when cer (js-prop cer "prf"))
                                               (js-prop assertion-or-response "prf"))
                                       results (or (when prf (js-prop prf "results"))
                                                   (js-prop assertion-or-response "results"))]
                                   (or (when results (js-prop results "first"))
                                       (when prf (js-prop prf "first"))
                                       (js-prop assertion-or-response "prfOutput")
                                       (js-prop assertion-or-response "prf_output"))))))
          raw-seed (or user-handle prf-out)
          recovery-source (if (some? user-handle) :user-handle :prf)]
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
           :trust-boundary trust-boundary-disclosure})))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(defn derive-identity-from-prf
  "Deterministically derives an Ed25519 identity keypair and Bech32m address
   directly from WebAuthn PRF extension output (Uint8Array, byte array, or assertion map)."
  [prf-or-assertion]
  (try
    (let [prf-raw (cond
                    (map? prf-or-assertion)
                    (or (:prf-output prf-or-assertion)
                        (:prfOutput prf-or-assertion)
                        (get prf-or-assertion "prfOutput")
                        (get prf-or-assertion "prf_output")
                        (get-in prf-or-assertion [:extensions :prf :results :first])
                        (get-in prf-or-assertion [:client-extension-results :prf :results :first])
                        (get-in prf-or-assertion [:clientExtensionResults :prf :results :first])
                        (get-in prf-or-assertion ["clientExtensionResults" "prf" "results" "first"])
                        (get-in prf-or-assertion ["extensions" "prf" "results" "first"])
                        (get prf-or-assertion :first)
                        (get-in prf-or-assertion [:results :first]))

                    #?@(:cljs
                        [(and (some? prf-or-assertion)
                              (or (some? (js-call-0 prf-or-assertion "getClientExtensionResults"))
                                  (some? (js-prop prf-or-assertion "clientExtensionResults"))
                                  (some? (js-prop prf-or-assertion "prf"))
                                  (some? (js-prop prf-or-assertion "results"))))
                         (let [cer (or (js-call-0 prf-or-assertion "getClientExtensionResults")
                                       (js-prop prf-or-assertion "clientExtensionResults"))
                               prf (or (when cer (js-prop cer "prf"))
                                       (js-prop prf-or-assertion "prf"))
                               results (or (when prf (js-prop prf "results"))
                                           (js-prop prf-or-assertion "results"))]
                           (or (when results (js-prop results "first"))
                               (when prf (js-prop prf "first"))))])

                    :else prf-or-assertion)]
      (when-let [bs (to-byte-seq prf-raw)]
        (let [seed-32 (cond
                        (= (count bs) 32) bs
                        (> (count bs) 32) (subvec bs 0 32)
                        :else (to-byte-seq (crypto/sha256 (to-byte-array bs))))
              seed-arr (to-byte-array seed-32)
              kp (crypto/pure-ed25519-keypair seed-arr)
              pub-hex (bytes->hex-str (to-byte-seq (:public kp)))
              bech-addr (bech32m/pubkey->bech32m pub-hex "ech")]
          {:seed seed-arr
           :recovery-source :prf
           :keypair kp
           :public-key (:public kp)
           :private-key (:private kp)
           :public-hex pub-hex
           :address bech-addr
           :origin-scoping origin-scoping-disclosure
           :trust-boundary trust-boundary-disclosure})))
    (catch #?(:clj Exception :cljs :default) _ nil)))

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
                      (let [resp (js-prop cred "response")
                            att-buf (or (when resp (js-prop resp "attestationObject"))
                                        (js-prop cred "attestationObject"))
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
  "Registers a second hardware backup key configuration.
   Accepts optional :backup-seed in backup-opts and includes derived key material in return map."
  [primary-state backup-opts]
  (let [backup-seed (or (:backup-seed backup-opts)
                        (get backup-opts "backup_seed")
                        (get backup-opts "backup-seed")
                        (crypto/random-bytes 32))
        backup-seed-arr (if #?(:clj (bytes? backup-seed) :cljs (instance? js/Uint8Array backup-seed))
                          backup-seed
                          (to-byte-array (to-byte-seq backup-seed)))
        backup-kp (crypto/pure-ed25519-keypair backup-seed-arr)
        backup-pub-hex (bytes->hex-str (to-byte-seq (:public backup-kp)))
        backup-info {:public-hex backup-pub-hex
                     :public-key (:public backup-kp)
                     :backup-seed backup-seed-arr
                     :address (bech32m/pubkey->bech32m backup-pub-hex "ech")
                     :registered-at (or (:current-epoch primary-state) 0)
                     :description (or (:description backup-opts) "Secondary Hardware YubiKey Backup")
                     :yubico-enrollment :parked}]
    (assoc primary-state :backup-key backup-info)))

(defn normalize-spki-pubkey-hex
  "Normalizes an Ed25519 public key (64-char raw hex, 88-char SPKI hex, 32-byte raw bytes,
   or 44-byte SPKI bytes) into canonical lowercase 88-char SPKI hex (`302a300506032b6570032100` + 64-char raw hex)."
  [pub]
  (to-valid-spki-hex pub))

(defn normalize-recovered-identity
  "Normalizes a recovered hardware identity map (or nested `{:identity ...}` map) so:
   - `:public-hex` is canonical 88-char SPKI hex (`302a300506032b6570032100` + 64-char raw hex)
   - `:raw-public-hex` retains the 64-char raw Ed25519 public key hex
   - `:public-key` is 44-byte SPKI bytes
   - `:address` is the consistent `ech1...` Bech32m address."
  [recovered]
  (let [ident (if (and (map? recovered) (map? (:identity recovered)))
                (:identity recovered)
                recovered)]
    (when (map? ident)
      (let [raw-pub (or (:public-hex ident)
                        (get ident "public-hex")
                        (get ident "publicHex")
                        (:public-key ident)
                        (get-in ident [:keypair :public]))
            spki-hex (to-valid-spki-hex raw-pub)]
        (when (and (string? spki-hex) (= 88 (count spki-hex)))
          (let [raw-64 (subs spki-hex 24)
                spki-bytes (->byte-array spki-hex)
                addr (or (when (and (string? (:address ident))
                                    (str/starts-with? (:address ident) "ech1"))
                           (:address ident))
                         (bech32m/pubkey->bech32m spki-hex "ech"))
                priv (or (:private-key ident)
                         (get-in ident [:keypair :private]))]
            (cond-> (assoc ident
                           :public-hex spki-hex
                           :raw-public-hex raw-64
                           :public-key spki-bytes
                           :address addr)
              priv (assoc :private-key (to-pkcs8-der priv))
              (:keypair ident)
              (assoc :keypair {:public spki-bytes
                               :private (when priv (to-pkcs8-der priv))
                               :public-key spki-bytes
                               :private-key (when priv (to-pkcs8-der priv))}))))))))

(defn resolve-yubikey-recovery
  "Pure single-recovery-path helper (`BIP-010` / `P-WEB-1`):
   Resolves a YubiKey recovery request from:
   - raw seed/user-handle bytes,
   - PRF extension output,
   - native / Closure-mangled WebAuthn assertion object or string-keyed map,
   - top-level redacted credential `{:public-hex ... :address ...}`, or
   - nested redacted credential `{:identity {:public-hex ... :address ...}}`.
   Normalizes the recovered key to canonical 88-char SPKI `:public-hex` and 44-byte SPKI `:public-key`,
   and when `current-node-state` already holds an unlocked `:private-key` for the same identity,
   never overwrites `:private-key` with `nil`."
  ([seed-or-opts]
   (resolve-yubikey-recovery seed-or-opts nil))
  ([seed-or-opts current-node-state]
   (let [direct-rec (or (recover-seed-from-assertion seed-or-opts)
                        (derive-identity-from-prf seed-or-opts))
         existing-ident (when (map? seed-or-opts)
                          (or (when (map? (:identity seed-or-opts)) (:identity seed-or-opts))
                              (when (map? (get seed-or-opts "identity")) (get seed-or-opts "identity"))
                              (when (or (:public-hex seed-or-opts)
                                        (get seed-or-opts "public-hex")
                                        (get seed-or-opts "publicHex"))
                                seed-or-opts)))
         cand (or (when direct-rec (normalize-recovered-identity direct-rec))
                  (when existing-ident (normalize-recovered-identity existing-ident)))]
     (if-not cand
       {:ok? false :ok false :error "recovery-failed"}
       (let [spki-hex (:public-hex cand)
             existing-node-pub (when (map? current-node-state)
                                 (or (to-valid-spki-hex (get-in current-node-state [:light-state :pubkey]))
                                     (to-valid-spki-hex (get-in current-node-state [:keypair :public-key]))))
             existing-node-priv (when (map? current-node-state)
                                  (get-in current-node-state [:keypair :private-key]))
             eff-priv (or (:private-key cand)
                          (when (and existing-node-priv
                                     (or (nil? existing-node-pub)
                                         (= existing-node-pub spki-hex)))
                            existing-node-priv))
             eff-ident (cond-> cand
                         eff-priv (assoc :private-key eff-priv))
             next-node-state (when (map? current-node-state)
                               (cond-> (-> current-node-state
                                           (assoc-in [:light-state :pubkey] spki-hex)
                                           (assoc-in [:keypair :public-key] (:public-key eff-ident)))
                                 eff-priv
                                 (assoc-in [:keypair :private-key] eff-priv)))]
         {:ok? true
          :ok true
          :public-hex spki-hex
          :raw-public-hex (:raw-public-hex eff-ident)
          :address (:address eff-ident)
          :identity eff-ident
          :node-state next-node-state})))))

(defn recover-from-backup-key
  "Recovers identity state using a verified backup key seed."
  [backup-seed]
  (recover-seed-from-assertion {:user-handle backup-seed}))
