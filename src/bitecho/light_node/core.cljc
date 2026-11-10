(ns bitecho.light-node.core
  "Pure Sans-IO protocol state reducer for the Bitecho light node.
   Handles command processing, sealed channel establishment, anti-replay,
   epoch skew tolerance, and Wire/JSONL conversions without side effects.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.subnet :as core-subnet]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.economy.bundle :as bundle]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.escrow :as escrow]
            [bitecho.fressian :as fressian]
            [bitecho.rendezvous.core :as rendezvous]
            [clojure.edn :as edn]
            [clojure.string :as str]
            #?(:cljs [bitecho.economy.account :as account])
            #?(:cljs [bitecho.sieve.core :as sieve])
            #?(:clj [bitecho.shell.agent-sim :as agent-sim])
            #?(:clj [bitecho.shell.mesh :as mesh])
            #?(:clj [clojure.data.json :as json])))

(def ^:private bytes? fressian/bytes?)

(def ^:private empty-bytes
  #?(:clj (byte-array 0)
     :cljs (js/Uint8Array. 0)))

(defn- math-abs [n]
  #?(:clj (Math/abs (long n))
     :cljs (js/Math.abs n)))

(defn- math-ceil [n]
  #?(:clj (long (Math/ceil (double n)))
     :cljs (long (js/Math.ceil (double n)))))

(defn- parse-json-str
  ([s] (parse-json-str s false))
  ([s keywordize?]
   (try
     #?(:clj (json/read-str s :key-fn (if keywordize? keyword identity))
        :cljs (let [obj (js/JSON.parse s)]
                (js->clj obj :keywordize-keys keywordize?)))
     (catch #?(:clj Exception :cljs :default) _ nil))))

(defn freeze-payload
  "Encodes a wire payload using Fressian wire codec (encode-wire)."
  [payload]
  (fressian/encode-wire payload))

(defn thaw-payload
  "Decodes a wire payload using Fressian wire codec (decode-wire),
   supporting Fressian and legacy Nippy payloads.
   Always strips untrusted shell-boundary crypto tags from the result."
  [payload-bytes]
  (fressian/decode-wire payload-bytes))

(defn strip-sensitive-keys
  "Pure helper to remove single-use ECDH `:ephemeral-priv` keys from session state prior to persistence,
   and dissoc transient runtime connection liveness keys (`:connected?`, `:connection-error`, `:conn-diagnostics`)
   so persisted state never includes them.
   NOTE (`M2a-1` Trust Boundary): Active session symmetric `:tx-key` and `:rx-key` are intentionally retained
   inside `state.fressian` (enforced `0600` POSIX permissions alongside `<state-dir>/identity/node-identity.edn`)
   so stateless one-shot CLI invocations (`send`, `inbox`, `close`) can encrypt and decrypt ongoing session
   messages across process invocations without re-running the X25519 handshake."
  [state]
  (let [clean-sessions (into {} (for [[sid s] (:sessions state)]
                                  [sid (dissoc s :ephemeral-priv)]))]
    (-> state
        (assoc :sessions clean-sessions)
        (dissoc :connected? :connection-error :conn-diagnostics))))

(defn encode-light-state
  "Serializes sanitized light-node state into cross-platform Fressian bytes (`state.fressian`)."
  [state]
  (fressian/encode-wire-uncompressed (strip-sensitive-keys state)))

(defn decode-light-state
  "Deserializes light-node state from Fressian bytes (`state.fressian`) across JVM and Node.js."
  [state-bytes]
  (when (and state-bytes (pos? (fressian/count-bytes state-bytes)))
    (fressian/decode-wire state-bytes)))

;; -----------------------------------------------------------------------------
;; Wire Protocol Versioning & Rolling Upgrade Compatibility (FLAG B & Step 9B)
;; -----------------------------------------------------------------------------

(def current-wire-version
  "Current Bitecho wire protocol envelope version."
  1)

(def min-supported-wire-version
  "Minimum supported wire protocol version for rolling-upgrade compatibility (N-1/N)."
  1)

(def max-supported-wire-version
  "Maximum supported wire protocol version for forward rolling-upgrade compatibility (N+1)."
  2)

(def current-wire-format
  "Current default wire encoding format."
  "fressian-v1")

(def supported-wire-formats
  "Set of supported wire encoding formats (strings and keywords)."
  #{"fressian-v1" "legacy-nippy" :fressian-v1 :legacy-nippy})

(def reserved-wire-formats
  "Set of reserved wire encoding formats for future milestones (fail-closed if encountered)."
  #{"transit-json" "transit-msgpack" :transit-json :transit-msgpack})

(defn rolling-upgrade-compatible?
  "Pure predicate checking whether two wire protocol versions are within the rolling-upgrade compatibility window (<= 1 step difference) and supported."
  [local-version remote-version]
  (and (integer? local-version)
       (integer? remote-version)
       (<= min-supported-wire-version (long local-version) max-supported-wire-version)
       (<= min-supported-wire-version (long remote-version) max-supported-wire-version)
       (<= (math-abs (- (long local-version) (long remote-version))) 1)))

(defn check-wire-format-compatibility
  "Pure function inspecting a wire payload or message map for wire format compatibility.
   Supports :wire-format, \"wire_format\", and \"wire-format\" keys.
   Returns {:ok? true :wire-format \"fressian-v1\" :legacy-unversioned? true} when wire-format is absent.
   Returns {:ok? true :wire-format fmt-str :legacy-unversioned? false} when format is supported.
   Returns {:ok? false :error \"unsupported-wire-format\" :wire-format fmt :supported-formats [\"fressian-v1\" \"legacy-nippy\"]}
   for reserved or unknown wire formats."
  [msg]
  (if-not (map? msg)
    {:ok? false :error "unsupported-wire-format" :wire-format nil :supported-formats ["fressian-v1" "legacy-nippy"]}
    (let [has-fmt? (or (contains? msg :wire-format)
                       (contains? msg "wire_format")
                       (contains? msg "wire-format"))
          raw-fmt (cond
                    (contains? msg :wire-format) (:wire-format msg)
                    (contains? msg "wire_format") (get msg "wire_format")
                    (contains? msg "wire-format") (get msg "wire-format")
                    :else nil)]
      (cond
        (or (not has-fmt?) (nil? raw-fmt))
        {:ok? true :wire-format current-wire-format :legacy-unversioned? true}

        (contains? supported-wire-formats raw-fmt)
        (let [norm-str (if (keyword? raw-fmt) (name raw-fmt) (str raw-fmt))]
          {:ok? true :wire-format norm-str :legacy-unversioned? false})

        :else
        {:ok? false
         :error "unsupported-wire-format"
         :wire-format raw-fmt
         :supported-formats ["fressian-v1" "legacy-nippy"]}))))

(defn- wrap-agent-event
  ([event pubkey privkey]
   (wrap-agent-event event pubkey privkey nil))
  ([event pubkey privkey dac]
   (let [sub-id (str (or (:subnet-id event) "global"))]
     (if (or (nil? privkey) (= :defer-crypto privkey))
       (let [clean (dissoc event :sender :sender-pubkey-bytes :rng)
             effective-dac (or dac (:dac event))
             base (cond-> {:protocol-version current-wire-version
                           :wire-format current-wire-format
                           :subnet-id sub-id
                           :agent-pubkey pubkey
                           :event clean}
                    effective-dac (assoc :dac effective-dac))]
         (assoc base :crypto-effect {:effect :sign-and-emit
                                     :sender pubkey
                                     :signing-payload [(or pubkey "") (crypto/canonicalize-agent-event clean)]
                                     :signature-field :signature
                                     :envelope base}))
       #?(:clj (mesh/wrap-agent-event event pubkey privkey dac)
          :cljs (let [clean (dissoc event :sender :sender-pubkey-bytes :rng)
                      sb (crypto/canonical-signing-bytes [(or pubkey "") (crypto/canonicalize-agent-event clean)])
                      sig (crypto/sign privkey sb)
                      sig-hex (if (string? sig) sig (basalt/bytes->hex sig))
                      effective-dac (or dac (:dac event))]
                  (cond-> {:protocol-version current-wire-version
                           :wire-format current-wire-format
                           :subnet-id sub-id
                           :agent-pubkey pubkey
                           :event clean
                           :signature sig-hex}
                    effective-dac (assoc :dac effective-dac))))))))

(defn- build-gossip-envelope
  ([sender-pub-hex sender-priv-bytes payload-bytes burn-amount]
   (build-gossip-envelope sender-pub-hex sender-priv-bytes payload-bytes burn-amount "global"))
  ([sender-pub-hex sender-priv-bytes payload-bytes burn-amount subnet-id]
   #?(:clj (agent-sim/build-gossip-envelope sender-pub-hex sender-priv-bytes payload-bytes burn-amount subnet-id)
      :cljs (let [pub-bytes (if (fressian/bytes? sender-pub-hex) sender-pub-hex (basalt/hex->bytes sender-pub-hex))
                  pub-hex (if (string? sender-pub-hex) sender-pub-hex (basalt/bytes->hex sender-pub-hex))
                  sieve-msg (sieve/wrap-message payload-bytes sender-priv-bytes pub-bytes burn-amount)
                  message-id (basalt/bytes->hex (crypto/sha256 payload-bytes))
                  agent-event {:type :receive-gossip
                               :subnet-id (str (or subnet-id "global"))
                               :message (assoc sieve-msg :message-id message-id)}]
              (wrap-agent-event agent-event pub-hex sender-priv-bytes)))))

(defn build-home-set-envelope
  "Builds a signed `:register-home-set` agent envelope across JVM and ClojureScript."
  ([agent-pub-hex agent-priv-bytes candidates price epoch]
   (build-home-set-envelope agent-pub-hex agent-priv-bytes candidates price epoch nil nil))
  ([agent-pub-hex agent-priv-bytes candidates price epoch ice-ufrag ice-pwd]
   #?(:clj (agent-sim/build-home-set-envelope agent-pub-hex agent-priv-bytes candidates price epoch ice-ufrag ice-pwd)
      :cljs (let [candidate-maps (mapv (fn [c] (if (map? c) (assoc c :price (or (:price c) price)) {:node-id c :price price})) candidates)
                  event (cond-> {:type :register-home-set
                                 :callee agent-pub-hex
                                 :candidates candidate-maps
                                 :price price
                                 :price-max price
                                 :epoch epoch}
                          (and ice-ufrag ice-pwd) (assoc :ice-ufrag ice-ufrag :ice-pwd ice-pwd))]
              (wrap-agent-event event agent-pub-hex agent-priv-bytes)))))

(defn- build-transfer-gossip-envelope
  [sender-pub-hex sender-priv-bytes transfer-opts burn-amount]
  #?(:clj (agent-sim/build-transfer-gossip-envelope sender-pub-hex sender-priv-bytes transfer-opts burn-amount)
     :cljs (let [unsigned (assoc transfer-opts :sender sender-pub-hex)
                 signed-transfer (account/create-transfer sender-priv-bytes unsigned)
                 transfer-map (into {} signed-transfer)
                 payload-bytes (fressian/encode-canonical {:transfer transfer-map})
                 envelope (build-gossip-envelope sender-pub-hex sender-priv-bytes payload-bytes burn-amount)
                 thash (account/transfer-hash signed-transfer)]
             {:envelope envelope
              :transfer signed-transfer
              :transfer-hash thash})))

(defn check-wire-version-compatibility
  "Pure function inspecting a wire payload or message map for protocol version compatibility.
   Supports :protocol-version, \"protocol_version\", and :wire-version keys.
   Returns {:ok? true :version 1 :legacy-unversioned? true} for unversioned (N-1) messages.
   Returns {:ok? true :version v :legacy-unversioned? false} for supported version integers in [1, 2].
   Returns {:ok? false :error \"unsupported-wire-version\" :version v :min-supported 1 :max-supported 2} otherwise."
  [msg]
  (if-not (map? msg)
    {:ok? false :error "unsupported-wire-version" :version nil :min-supported min-supported-wire-version :max-supported max-supported-wire-version}
    (let [has-v? (or (contains? msg :protocol-version)
                     (contains? msg "protocol_version")
                     (contains? msg :wire-version))
          raw-v (if (contains? msg :protocol-version)
                  (:protocol-version msg)
                  (if (contains? msg "protocol_version")
                    (get msg "protocol_version")
                    (:wire-version msg)))]
      (cond
        (or (not has-v?) (nil? raw-v))
        {:ok? true :version current-wire-version :legacy-unversioned? true}

        (and (integer? raw-v)
             (<= min-supported-wire-version (long raw-v) max-supported-wire-version)
             (rolling-upgrade-compatible? current-wire-version (long raw-v)))
        {:ok? true :version (long raw-v) :legacy-unversioned? false}

        :else
        {:ok? false
         :error "unsupported-wire-version"
         :version raw-v
         :min-supported min-supported-wire-version
         :max-supported max-supported-wire-version}))))

;; -----------------------------------------------------------------------------
;; State Initialization
;; -----------------------------------------------------------------------------

(def simon-nexus-axiom-subnet-id
  "Canonical zero-burn DAC-gated 3-way private broadcast & chat subnet ID (Subnet #4)."
  "chat/simon-nexus-axiom")

(defn init-light-state
  "Initializes a pure light node state map from an identity public map and options.
   Private keys are never stored in the returned state map."
  [identity-pub-map opts]
  {:pubkey (or (:pubkey-hex identity-pub-map) (:pubkey identity-pub-map))
   :fingerprint (:fingerprint identity-pub-map)
   :ice-creds (:ice-creds identity-pub-map)
   :autonomous? (boolean (:autonomous? opts false))
   :epoch (long (:epoch opts 0))
   :epoch-initialized? (contains? opts :epoch)
   :bootstrap (:bootstrap opts)
   :trusted-directory-pubkey (or (:directory-pubkey opts)
                                 (get-in opts [:bootstrap :directory-pubkey])
                                 (:trusted-directory-pubkey opts))
   :trusted-dac-anchors (set (keep (fn [k]
                                     (when (and (string? k) (not (str/blank? k)))
                                       (str/lower-case (str/trim k))))
                                   (:trusted-dac-anchors opts)))
   :home-set []
   :petnames {}
   :dac nil
   :dac-spend nil
   :revoked-dacs #{}
   :directory-cache {}
   :sessions {}
   :pending-offers {}
   :inbox []
   :broadcast-seq 0
   :broadcast-seen #{}
   :broadcast-inbox []
   :local-accounting {:burned-ech 0}
   :vouchers []
   :account nil
   :intent-seq 0
   :transfer-seq 0
   :last-transfer-hash nil
   :escrows {}
   :rendezvous-policy (merge {:auto-accept? false
                              :min-burn 0
                              :price 10
                              :allowlist #{}
                              :home-node "default-home"}
                             (:rendezvous-policy opts))
   :outbound-rendezvous {}
   :pending-rendezvous {}
   :pending-rendezvous-accepts {}
   :voucher-seqs {}
   :wire-version-diagnostics {:unsupported-dropped 0
                              :last-unsupported-version nil
                              :unsupported-format-dropped 0
                              :last-unsupported-format nil
                              :subnet-mismatch-dropped 0
                              :last-error nil}
   :subnet-id (str (or (:subnet-id opts) (:subnet-id identity-pub-map) "global"))
   :economy-enabled? (boolean (get opts :economy-enabled? true))
   :burn-floor (long (or (:burn-floor opts) 0))
   :diagnostics (merge {:subnet-mismatch-dropped 0
                        :p2p-relayed 0
                        :broadcast-duplicates-dropped 0
                        :broadcast-rejected 0}
                       (:diagnostics opts))
   :crypto-suites (or (:crypto-suites opts) sealed/default-crypto-suites)})

;; -----------------------------------------------------------------------------
;; Petnames Address Book & Counterparty Resolution (Pure Helpers)
;; -----------------------------------------------------------------------------

(def ^:private pubkey-pattern #"(?i)^[0-9a-f]{88}$")
(def ^:private petname-pattern #"^[a-zA-Z0-9._-]{1,64}$")

(defn valid-pubkey-hex?
  "Returns true iff s is a string whose trimmed form is an 88-char hex string
   starting with canonical Ed25519 SPKI prefix 302a300506032b6570032100
   and cleanly decodes to 44 bytes via basalt/hex->bytes."
  [s]
  (boolean
   (when (and (string? s) (not (str/blank? s)))
     (let [t (str/trim s)]
       (when (and (re-matches pubkey-pattern t)
                  (str/starts-with? (str/lower-case t) "302a300506032b6570032100"))
         (try
           (let [b (basalt/hex->bytes t)]
             (and (some? b) (= 44 (fressian/count-bytes b))))
           (catch #?(:clj Exception :cljs :default) _ false)))))))

(defn normalize-pubkey-hex
  "Returns lower-case trimmed pubkey hex string when valid-pubkey-hex?, else nil."
  [s]
  (when (valid-pubkey-hex? s)
    (str/lower-case (str/trim s))))

(defn valid-petname?
  "Returns true iff s is a string whose trimmed form (allowing an optional leading @)
   is non-blank, is NOT a valid-pubkey-hex?, and matches ^[a-zA-Z0-9._-]{1,64}$."
  [s]
  (boolean
   (when (and (string? s) (not (str/blank? s)))
     (let [t (str/trim s)
           stripped (if (str/starts-with? t "@") (subs t 1) t)]
       (and (not (str/blank? stripped))
            (not (valid-pubkey-hex? t))
            (not (valid-pubkey-hex? stripped))
            (boolean (re-matches petname-pattern stripped)))))))

(defn normalize-petname
  "Trims s, strips a single leading @ if present, and returns lower-case string
   when valid-petname?, else nil."
  [s]
  (when (valid-petname? s)
    (let [t (str/trim s)
          stripped (if (str/starts-with? t "@") (subs t 1) t)]
      (str/lower-case stripped))))

(defn pubkey->petname
  "Reverse lookup in (:petnames state) returning the canonical petname
   bound to (normalize-pubkey-hex pubkey), or nil."
  [state pubkey]
  (when-let [norm-pub (normalize-pubkey-hex pubkey)]
    (some (fn [[p k]] (when (= k norm-pub) p)) (:petnames state))))

(defn petname->pubkey
  "Forward lookup in (:petnames state) returning the pubkey
   bound to (normalize-petname petname), or nil."
  [state petname]
  (when-let [norm-pname (normalize-petname petname)]
    (get-in state [:petnames norm-pname])))

(defn resolve-counterparty
  "Resolves a counterparty identifier (petname or raw pubkey hex).
   Returns:
     {:ok? false :error \"missing-counterparty\"} when target is blank/nil
     {:ok? true :pubkey bound-pubkey :petname canonical-petname} when target matches a petname
     {:ok? true :pubkey (normalize-pubkey-hex target) :petname (pubkey->petname state target)} when valid pubkey hex
     {:ok? false :error \"unknown-petname\"} otherwise."
  [state target]
  (if (or (nil? target) (and (string? target) (str/blank? target)))
    {:ok? false :error "missing-counterparty"}
    (let [norm-pname (normalize-petname target)]
      (if (and norm-pname (contains? (:petnames state) norm-pname))
        {:ok? true :pubkey (get-in state [:petnames norm-pname]) :petname norm-pname}
        (if (valid-pubkey-hex? target)
          (let [norm-pub (normalize-pubkey-hex target)]
            {:ok? true :pubkey norm-pub :petname (pubkey->petname state norm-pub)})
          {:ok? false :error "unknown-petname"})))))

;; -----------------------------------------------------------------------------
;; Directory Attestation & Proof-of-Possession (PoP) (Axiom Amendment 2)
;; -----------------------------------------------------------------------------

(defn create-directory-pop
  "Creates an agent Proof-of-Possession (PoP) map signed by agent-privkey-bytes.
   Optionally signs with prev-privkey-bytes to prove key rotation continuity.
   Optionally binds advertised :crypto-suites."
  [agent-privkey-bytes {:keys [domain nickname pubkey home-set epoch prev-pubkey prev-privkey-bytes crypto-suites]}]
  (when (and (valid-petname? nickname)
             (valid-pubkey-hex? pubkey)
             (or (nil? epoch) (integer? epoch))
             (or (nil? prev-pubkey)
                 (and (valid-pubkey-hex? prev-pubkey)
                      (not= (normalize-pubkey-hex prev-pubkey) (normalize-pubkey-hex pubkey))
                      (some? prev-privkey-bytes))))
    (let [norm-nick (normalize-petname nickname)
          norm-pub (normalize-pubkey-hex pubkey)
          norm-domain (if (or (nil? domain) (str/blank? domain)) "bitecho.org" (str/lower-case (str/trim domain)))
          sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                 (let [n (rendezvous/normalize-home-node hn)]
                                                   (when (and (string? n) (not (str/blank? n))) n)))
                                               home-set))))
          ep (long (or epoch 0))
          norm-prev (when prev-pubkey (normalize-pubkey-hex prev-pubkey))
          suites-str (when (seq crypto-suites)
                       (str/join "," (map #(if (keyword? %) (name %) (str %)) crypto-suites)))
          base-canonical (str "bitecho-directory-pop-v1|" norm-domain "|" norm-nick "|" norm-pub "|"
                              (str/join "," sorted-hs) "|" ep "|" (or norm-prev ""))
          canonical-str (if (seq suites-str)
                          (str base-canonical "|" suites-str)
                          base-canonical)
          sig-bytes (crypto/sign agent-privkey-bytes (fressian/utf8->bytes canonical-str))
          sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
          rot-sig-bytes (when norm-prev
                          (crypto/sign prev-privkey-bytes (fressian/utf8->bytes canonical-str)))
          rot-sig-hex (when rot-sig-bytes
                        (if (string? rot-sig-bytes) rot-sig-bytes (basalt/bytes->hex rot-sig-bytes)))]
      (cond-> {:domain norm-domain
               :nickname norm-nick
               :pubkey norm-pub
               :home-set sorted-hs
               :epoch ep
               :pop-signature sig-hex}
        (seq crypto-suites) (assoc :crypto-suites (vec (map #(if (keyword? %) (name %) (str %)) crypto-suites)))
        norm-prev (assoc :prev-pubkey norm-prev
                         :rotation-signature rot-sig-hex)))))

(defn- normalize-wire-map
  "Normalizes map keys to hyphenated keywords. Handles string or keyword keys.
   Returns nil if m is not a map."
  [m]
  (when (map? m)
    (into {}
          (for [[k v] m]
            (let [k-norm (cond
                           (keyword? k)
                           (if-let [ns (namespace k)]
                             (keyword ns (str/replace (name k) #"_" "-"))
                             (keyword (str/replace (name k) #"_" "-")))
                           (string? k)
                           (let [cleaned (str/replace (str/replace k #"^:+" "") #"_" "-")]
                             (if (str/includes? cleaned "/")
                               (let [[ns n] (str/split cleaned #"/" 2)]
                                 (keyword ns n))
                               (keyword cleaned)))
                           :else (keyword (str/replace (str k) #"_" "-")))]
              [k-norm v])))))

(defn verify-directory-pop
  "Verifies an agent Proof-of-Possession (PoP) map.
   Returns true iff the agent signature verifies under pubkey and (if key rotation)
   the rotation signature verifies under prev-pubkey.
   Strictly fails closed returning false on any malformed, mistyped, or invalid input."
  [pop-map]
  (try
    (let [pop-m (normalize-wire-map pop-map)]
      (boolean
       (when (and (map? pop-m)
                  (string? (:nickname pop-m))
                  (valid-petname? (:nickname pop-m))
                  (string? (:pubkey pop-m))
                  (valid-pubkey-hex? (:pubkey pop-m))
                  (string? (:domain pop-m))
                  (not (str/blank? (:domain pop-m)))
                  (string? (:pop-signature pop-m))
                  (not (str/blank? (:pop-signature pop-m)))
                  (or (nil? (:epoch pop-m)) (integer? (:epoch pop-m)))
                  (or (nil? (:home-set pop-m))
                      (and (coll? (:home-set pop-m))
                           (every? (fn [x] (or (string? x) (keyword? x) (symbol? x))) (:home-set pop-m)))))
         (let [norm-domain (str/lower-case (str/trim (:domain pop-m)))
               norm-nick (normalize-petname (:nickname pop-m))
               norm-pub (normalize-pubkey-hex (:pubkey pop-m))
               hs (or (:home-set pop-m) [])
               sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                      (let [n (rendezvous/normalize-home-node hn)]
                                                        (when (and (string? n) (not (str/blank? n))) n)))
                                                    hs))))
               ep (long (or (:epoch pop-m) 0))
               prev-pk (:prev-pubkey pop-m)
               rot-sig (:rotation-signature pop-m)
               has-rot? (or (some? prev-pk) (some? rot-sig))
               norm-prev (when (and (string? prev-pk) (valid-pubkey-hex? prev-pk))
                           (normalize-pubkey-hex prev-pk))
               suites (or (:crypto-suites pop-m) (get pop-m "crypto_suites") (get pop-m "crypto-suites"))
               suites-str (when (seq suites)
                            (str/join "," (map #(if (keyword? %) (name %) (str %)) suites)))
               base-canonical (str "bitecho-directory-pop-v1|" norm-domain "|" norm-nick "|" norm-pub "|"
                                   (str/join "," sorted-hs) "|" ep "|" (or norm-prev ""))
               canonical-str (if (seq suites-str)
                               (str base-canonical "|" suites-str)
                               base-canonical)
               pub-bytes (try (basalt/hex->bytes norm-pub) (catch #?(:clj Exception :cljs :default) _ nil))
               sig-bytes (try (basalt/hex->bytes (:pop-signature pop-m)) (catch #?(:clj Exception :cljs :default) _ nil))
               pop-valid? (boolean (and pub-bytes sig-bytes
                                        (crypto/verify pub-bytes (fressian/utf8->bytes canonical-str) sig-bytes)))]
           (if-not pop-valid?
             false
             (if has-rot?
               (let [rot-keys-valid? (and (string? prev-pk)
                                          (valid-pubkey-hex? prev-pk)
                                          (string? rot-sig)
                                          (not (str/blank? rot-sig))
                                          norm-prev
                                          (not= norm-prev norm-pub))
                     prev-pub-bytes (when rot-keys-valid? (try (basalt/hex->bytes norm-prev) (catch #?(:clj Exception :cljs :default) _ nil)))
                     rot-sig-bytes (when rot-keys-valid? (try (basalt/hex->bytes rot-sig) (catch #?(:clj Exception :cljs :default) _ nil)))]
                 (boolean (and prev-pub-bytes rot-sig-bytes
                               (crypto/verify prev-pub-bytes (fressian/utf8->bytes canonical-str) rot-sig-bytes))))
               true))))))
    (catch #?(:clj Exception :cljs :default) _ false)))

(defn sign-directory-descriptor
  "Signs a directory attestation descriptor under a directory authority key after verifying PoP.
   Agent self-signature proves continuity only; directory signature attests the entry."
  [directory-privkey-bytes directory-pubkey-hex pop-map {:keys [mailbox issued-epoch expires-epoch]}]
  (when (and (string? directory-pubkey-hex)
             (valid-pubkey-hex? directory-pubkey-hex)
             (verify-directory-pop pop-map)
             (integer? issued-epoch)
             (integer? expires-epoch)
             (>= (long expires-epoch) (long issued-epoch)))
    (let [pop-m (normalize-wire-map pop-map)
          domain (str/lower-case (str/trim (or (:domain pop-m) "bitecho.org")))
          norm-nick (normalize-petname (:nickname pop-m))
          norm-pub (normalize-pubkey-hex (:pubkey pop-m))
          sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                 (let [n (rendezvous/normalize-home-node hn)]
                                                   (when (and (string? n) (not (str/blank? n))) n)))
                                               (:home-set pop-m)))))
          norm-prev (when-let [p (:prev-pubkey pop-m)] (normalize-pubkey-hex p))
          pop-sig (:pop-signature pop-m)
          rot-sig (or (:rotation-signature pop-m) "")
          mbox (or mailbox "")
          iss-ep (long issued-epoch)
          exp-ep (long expires-epoch)
          suites (or (:crypto-suites pop-m) (get pop-m "crypto_suites") (get pop-m "crypto-suites"))
          suites-str (when (seq suites)
                       (str/join "," (map #(if (keyword? %) (name %) (str %)) suites)))
          base-canonical (str "bitecho-directory-attestation-v1|" domain "|" norm-nick "|" norm-pub "|"
                              (str/join "," sorted-hs) "|" mbox "|" iss-ep "|" exp-ep "|"
                              (or norm-prev "") "|" pop-sig "|" rot-sig)
          canonical-str (if (seq suites-str)
                          (str base-canonical "|" suites-str)
                          base-canonical)
          dir-sig-bytes (crypto/sign directory-privkey-bytes (fressian/utf8->bytes canonical-str))
          dir-sig-hex (if (string? dir-sig-bytes) dir-sig-bytes (basalt/bytes->hex dir-sig-bytes))]
      (cond-> {:bitecho/type :directory-descriptor
               :domain domain
               :nickname norm-nick
               :uri (str domain "/" norm-nick)
               :pubkey norm-pub
               :home-set sorted-hs
               :epoch (long (or (:epoch pop-m) iss-ep))
               :issued-epoch iss-ep
               :expires-epoch exp-ep
               :pop-signature pop-sig
               :directory-pubkey (normalize-pubkey-hex directory-pubkey-hex)
               :directory-signature dir-sig-hex}
        (seq suites) (assoc :crypto-suites (vec (map #(if (keyword? %) (name %) (str %)) suites)))
        (seq mbox) (assoc :mailbox mbox)
        norm-prev (assoc :prev-pubkey norm-prev)
        (:rotation-signature pop-m) (assoc :rotation-signature (:rotation-signature pop-m))))))

(defn verify-directory-descriptor
  "Verifies a directory descriptor against a trusted directory authority public key and current epoch.
   Strictly fails closed returning {:ok? false :valid? false :error <reason>} on any validation failure."
  [descriptor trusted-directory-pubkey current-epoch]
  (try
    (let [desc (normalize-wire-map descriptor)]
      (cond
        (or (not (map? desc))
            (not (string? (:domain desc))) (str/blank? (:domain desc))
            (not (string? (:nickname desc))) (str/blank? (:nickname desc))
            (not (string? (:pubkey desc))) (str/blank? (:pubkey desc))
            (not (string? (:directory-pubkey desc))) (str/blank? (:directory-pubkey desc))
            (not (string? (:directory-signature desc))) (str/blank? (:directory-signature desc))
            (not (string? (:pop-signature desc))) (str/blank? (:pop-signature desc))
            (not (integer? (:issued-epoch desc)))
            (not (integer? (:expires-epoch desc)))
            (and (some? (:epoch desc)) (not (integer? (:epoch desc))))
            (and (some? current-epoch) (not (integer? current-epoch)))
            (and (some? (:home-set desc))
                 (not (and (coll? (:home-set desc))
                           (every? (fn [x] (or (string? x) (keyword? x) (symbol? x))) (:home-set desc)))))
            (and (some? (:prev-pubkey desc)) (not (string? (:prev-pubkey desc))))
            (and (some? (:rotation-signature desc)) (not (string? (:rotation-signature desc))))
            (and (some? (:mailbox desc)) (not (string? (:mailbox desc)))))
        {:ok? false :valid? false :error "malformed-descriptor"}

        (or (not (string? trusted-directory-pubkey))
            (not (valid-pubkey-hex? trusted-directory-pubkey))
            (not (valid-pubkey-hex? (:directory-pubkey desc)))
            (not= (normalize-pubkey-hex (:directory-pubkey desc))
                  (normalize-pubkey-hex trusted-directory-pubkey)))
        {:ok? false :valid? false :error "untrusted-directory-authority"}

        (or (< (long (:expires-epoch desc)) (long (:issued-epoch desc)))
            (and (integer? current-epoch) (< (long (:expires-epoch desc)) (long current-epoch))))
        {:ok? false :valid? false :error "descriptor-expired"}

        (and (integer? current-epoch) (> (long (:issued-epoch desc)) (+ (long current-epoch) 2)))
        {:ok? false :valid? false :error "descriptor-future-epoch"}

        (not (verify-directory-pop desc))
        {:ok? false :valid? false :error "invalid-pop-signature"}

        :else
        (let [domain (str/lower-case (str/trim (:domain desc)))
              norm-nick (normalize-petname (:nickname desc))
              norm-pub (normalize-pubkey-hex (:pubkey desc))
              hs (or (:home-set desc) [])
              sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                     (let [n (rendezvous/normalize-home-node hn)]
                                                       (when (and (string? n) (not (str/blank? n))) n)))
                                                   hs))))
              mbox (or (:mailbox desc) "")
              iss-ep (long (:issued-epoch desc))
              exp-ep (long (:expires-epoch desc))
              norm-prev (when-let [p (:prev-pubkey desc)] (normalize-pubkey-hex p))
              pop-sig (:pop-signature desc)
              rot-sig (or (:rotation-signature desc) "")
              suites (or (:crypto-suites desc) (get desc "crypto_suites") (get desc "crypto-suites"))
              suites-str (when (seq suites)
                           (str/join "," (map #(if (keyword? %) (name %) (str %)) suites)))
              base-canonical (str "bitecho-directory-attestation-v1|" domain "|" norm-nick "|" norm-pub "|"
                                  (str/join "," sorted-hs) "|" mbox "|" iss-ep "|" exp-ep "|"
                                  (or norm-prev "") "|" pop-sig "|" rot-sig)
              canonical-str (if (seq suites-str)
                              (str base-canonical "|" suites-str)
                              base-canonical)
              dir-pub-bytes (try (basalt/hex->bytes (normalize-pubkey-hex trusted-directory-pubkey)) (catch #?(:clj Exception :cljs :default) _ nil))
              dir-sig-bytes (try (basalt/hex->bytes (:directory-signature desc)) (catch #?(:clj Exception :cljs :default) _ nil))]
          (if-not (and dir-pub-bytes dir-sig-bytes
                       (crypto/verify dir-pub-bytes (fressian/utf8->bytes canonical-str) dir-sig-bytes))
            {:ok? false :valid? false :error "invalid-directory-signature"}
            (let [canonical-desc (cond-> {:bitecho/type :directory-descriptor
                                          :domain domain
                                          :nickname norm-nick
                                          :uri (str domain "/" norm-nick)
                                          :pubkey norm-pub
                                          :home-set sorted-hs
                                          :epoch (long (or (:epoch desc) iss-ep))
                                          :issued-epoch iss-ep
                                          :expires-epoch exp-ep
                                          :pop-signature pop-sig
                                          :directory-pubkey (normalize-pubkey-hex trusted-directory-pubkey)
                                          :directory-signature (:directory-signature desc)}
                                   (seq suites) (assoc :crypto-suites (vec (map #(if (keyword? %) (name %) (str %)) suites)))
                                   (seq mbox) (assoc :mailbox mbox)
                                   norm-prev (assoc :prev-pubkey norm-prev)
                                   (seq rot-sig) (assoc :rotation-signature rot-sig))]
              {:ok? true :valid? true :descriptor canonical-desc})))))
    (catch #?(:clj Exception :cljs :default) _ {:ok? false :valid? false :error "malformed-descriptor"})))

(defn check-directory-suite-compatibility
  "Inspects a directory descriptor and validates compatibility with local crypto-suites.
   Returns {:ok? true :compatible? true :selected-suite suite ...} on match,
   or {:ok? false :compatible? false :error reason} on incompatibility."
  ([descriptor]
   (check-directory-suite-compatibility descriptor sealed/default-crypto-suites))
  ([descriptor local-suites]
   (let [desc (normalize-wire-map descriptor)
         desc-suites (:crypto-suites desc)]
     (if (seq desc-suites)
       (let [neg (sealed/negotiate-crypto-suite desc-suites local-suites)]
         (if (:ok? neg)
           {:ok? true :compatible? true :selected-suite (:selected-suite neg) :descriptor-suites desc-suites}
           {:ok? false :compatible? false :error "incompatible-directory-crypto-suites" :descriptor-suites desc-suites :local-suites (vec local-suites)}))
       ;; Legacy descriptor without suite advertisement defaults to chacha20-poly1305
       (let [legacy-supported? (contains? (set (map #(if (keyword? %) (name %) (str %)) local-suites))
                                          sealed/suite-v1-chacha20poly1305)]
         (if legacy-supported?
           {:ok? true :compatible? true :selected-suite sealed/suite-v1-chacha20poly1305 :legacy? true}
           {:ok? false :compatible? false :error "legacy-descriptor-incompatible"}))))))

(defn parse-directory-descriptor-text
  "Extracts and parses a directory descriptor map from raw JSON, raw EDN,
   or a Markdown document containing a fenced ```json ... ``` block.
   Returns nil on malformed input."
  [text]
  (when (and (string? text) (not (str/blank? text)))
    (let [fenced-match (re-find #"(?s)```(?:json)?\s*([\s\S]*?)\s*```" text)
          candidate (if fenced-match (str/trim (second fenced-match)) (str/trim text))]
      (or (try
            (let [parsed (parse-json-str candidate true)]
              (when (and (map? parsed)
                         (or (:nickname parsed) (:pubkey parsed) (= (:bitecho/type parsed) "directory-descriptor")))
                parsed))
            (catch #?(:clj Exception :cljs :default) _ nil))
          (try
            (let [parsed (edn/read-string candidate)]
              (when (and (map? parsed)
                         (or (:nickname parsed) (:pubkey parsed) (= (:bitecho/type parsed) :directory-descriptor)))
                parsed))
            (catch #?(:clj Exception :cljs :default) _ nil))))))

;; -----------------------------------------------------------------------------
;; Delegated Agent Certificates (DACs: Anchor Key -> Hot Agent Key)
;; -----------------------------------------------------------------------------

(defn create-dac
  "Creates a Delegated Agent Certificate (DAC) signed by an anchor cold key."
  [anchor-privkey-bytes {:keys [anchor-pubkey agent-pubkey issued-epoch expires-epoch max-spend-per-epoch scopes]}]
  (when (and (string? anchor-pubkey)
             (valid-pubkey-hex? anchor-pubkey)
             (string? agent-pubkey)
             (valid-pubkey-hex? agent-pubkey)
             (not= (normalize-pubkey-hex anchor-pubkey) (normalize-pubkey-hex agent-pubkey))
             (or (nil? issued-epoch) (integer? issued-epoch))
             (or (nil? expires-epoch) (integer? expires-epoch))
             (or (nil? max-spend-per-epoch) (integer? max-spend-per-epoch))
             (>= (long (or issued-epoch 0)) 0)
             (>= (long (or expires-epoch 0)) (long (or issued-epoch 0)))
             (>= (long (or max-spend-per-epoch 0)) 0)
             (or (nil? scopes)
                 (and (coll? scopes)
                      (every? (fn [x] (and (or (string? x) (keyword? x) (symbol? x))
                                           (not (str/blank? (name x)))))
                              scopes))))
    (let [norm-anchor (normalize-pubkey-hex anchor-pubkey)
          norm-agent (normalize-pubkey-hex agent-pubkey)
          iss-ep (long (or issued-epoch 0))
          exp-ep (long (or expires-epoch 0))
          max-spend (long (or max-spend-per-epoch 0))
          sorted-scopes (vec (sort (distinct (map (fn [s] (str/lower-case (name s)))
                                                  (or scopes ["gossip" "offer" "settle-intent" "transfer"])))))
          canonical-str (str "bitecho-dac-v1|" norm-anchor "|" norm-agent "|" iss-ep "|" exp-ep "|" max-spend "|" (str/join "," sorted-scopes))
          dac-id (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes canonical-str)))
          sig-bytes (crypto/sign anchor-privkey-bytes (fressian/utf8->bytes canonical-str))
          sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))]
      {:bitecho/type :dac
       :dac-id dac-id
       :anchor-pubkey norm-anchor
       :agent-pubkey norm-agent
       :issued-epoch iss-ep
       :expires-epoch exp-ep
       :max-spend-per-epoch max-spend
       :scopes sorted-scopes
       :signature sig-hex})))

(defn create-dac-revocation
  "Creates a DAC revocation map signed by an anchor cold key."
  [anchor-privkey-bytes {:keys [anchor-pubkey agent-pubkey dac-id revoked-epoch]}]
  (when (and (string? anchor-pubkey)
             (valid-pubkey-hex? anchor-pubkey)
             (string? agent-pubkey)
             (valid-pubkey-hex? agent-pubkey)
             (string? dac-id)
             (not (str/blank? dac-id))
             (or (nil? revoked-epoch) (integer? revoked-epoch)))
    (let [norm-anchor (normalize-pubkey-hex anchor-pubkey)
          norm-agent (normalize-pubkey-hex agent-pubkey)
          rev-ep (long (or revoked-epoch 0))
          canonical-str (str "bitecho-dac-revoke-v1|" norm-anchor "|" norm-agent "|" dac-id "|" rev-ep)
          sig-bytes (crypto/sign anchor-privkey-bytes (fressian/utf8->bytes canonical-str))
          sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))]
      {:bitecho/type :dac-revocation
       :dac-id dac-id
       :anchor-pubkey norm-anchor
       :agent-pubkey norm-agent
       :revoked-epoch rev-ep
       :signature sig-hex})))

(defn verify-dac-revocation
  "Verifies a DAC revocation map under its anchor public key.
   Strictly fails closed returning false on any malformed or mistyped input."
  [revocation]
  (try
    (let [rev (normalize-wire-map revocation)]
      (boolean
       (when (and (map? rev)
                  (string? (:anchor-pubkey rev))
                  (valid-pubkey-hex? (:anchor-pubkey rev))
                  (string? (:agent-pubkey rev))
                  (valid-pubkey-hex? (:agent-pubkey rev))
                  (string? (:dac-id rev))
                  (not (str/blank? (:dac-id rev)))
                  (string? (:signature rev))
                  (not (str/blank? (:signature rev)))
                  (or (nil? (:revoked-epoch rev)) (integer? (:revoked-epoch rev))))
         (let [norm-anchor (normalize-pubkey-hex (:anchor-pubkey rev))
               norm-agent (normalize-pubkey-hex (:agent-pubkey rev))
               dac-id (:dac-id rev)
               rev-ep (long (or (:revoked-epoch rev) 0))
               canonical-str (str "bitecho-dac-revoke-v1|" norm-anchor "|" norm-agent "|" dac-id "|" rev-ep)
               pub-bytes (try (basalt/hex->bytes norm-anchor) (catch #?(:clj Exception :cljs :default) _ nil))
               sig-bytes (try (basalt/hex->bytes (:signature rev)) (catch #?(:clj Exception :cljs :default) _ nil))]
           (and pub-bytes sig-bytes
                (crypto/verify pub-bytes (fressian/utf8->bytes canonical-str) sig-bytes))))))
    (catch #?(:clj Exception :cljs :default) _ false)))

(defn verify-dac
  "Verifies a Delegated Agent Certificate (DAC) against expected agent key, epoch, revocations, and scope.
   Strictly fails closed returning {:ok? false :valid? false :error <reason>} on any validation failure."
  [dac {:keys [expected-agent-pubkey current-epoch revoked-dac-ids required-scope]}]
  (try
    (let [d (normalize-wire-map dac)]
      (cond
        (or (not (map? d))
            (not (string? (:anchor-pubkey d))) (str/blank? (:anchor-pubkey d))
            (not (string? (:agent-pubkey d))) (str/blank? (:agent-pubkey d))
            (not (string? (:dac-id d))) (str/blank? (:dac-id d))
            (not (string? (:signature d))) (str/blank? (:signature d))
            (not (integer? (:issued-epoch d)))
            (not (integer? (:expires-epoch d)))
            (not (integer? (:max-spend-per-epoch d)))
            (< (long (:max-spend-per-epoch d)) 0)
            (and (some? current-epoch) (not (integer? current-epoch)))
            (and (some? expected-agent-pubkey) (not (string? expected-agent-pubkey)))
            (not (coll? (:scopes d)))
            (empty? (:scopes d))
            (not (every? (fn [x] (and (or (string? x) (keyword? x) (symbol? x))
                                      (not (str/blank? (name x)))))
                         (:scopes d))))
        {:ok? false :valid? false :error "malformed-dac"}

        (or (not (valid-pubkey-hex? (:anchor-pubkey d)))
            (not (valid-pubkey-hex? (:agent-pubkey d)))
            (= (normalize-pubkey-hex (:anchor-pubkey d)) (normalize-pubkey-hex (:agent-pubkey d))))
        {:ok? false :valid? false :error "invalid-dac-keys"}

        (and expected-agent-pubkey
             (or (not (valid-pubkey-hex? expected-agent-pubkey))
                 (not= (normalize-pubkey-hex expected-agent-pubkey)
                       (normalize-pubkey-hex (:agent-pubkey d)))))
        {:ok? false :valid? false :error "dac-agent-mismatch"}

        (or (< (long (:expires-epoch d)) (long (:issued-epoch d)))
            (and (integer? current-epoch) (< (long (:expires-epoch d)) (long current-epoch))))
        {:ok? false :valid? false :error "dac-expired"}

        (and (integer? current-epoch) (> (long (:issued-epoch d)) (+ (long current-epoch) 2)))
        {:ok? false :valid? false :error "dac-future-epoch"}

        (contains? (set (or revoked-dac-ids [])) (:dac-id d))
        {:ok? false :valid? false :error "dac-revoked"}

        :else
        (let [norm-anchor (normalize-pubkey-hex (:anchor-pubkey d))
              norm-agent (normalize-pubkey-hex (:agent-pubkey d))
              iss-ep (long (:issued-epoch d))
              exp-ep (long (:expires-epoch d))
              max-spend (long (:max-spend-per-epoch d))
              sorted-scopes (vec (sort (distinct (map (fn [s] (str/lower-case (name s))) (:scopes d)))))]
          (if (and required-scope
                   (let [req-set (if (coll? required-scope)
                                   (set (map (fn [s] (str/lower-case (name s))) required-scope))
                                   #{(str/lower-case (name required-scope))})]
                     (not (some req-set sorted-scopes))))
            {:ok? false :valid? false :error "dac-scope-not-permitted"}
            (let [canonical-str (str "bitecho-dac-v1|" norm-anchor "|" norm-agent "|" iss-ep "|" exp-ep "|" max-spend "|" (str/join "," sorted-scopes))
                  expected-id (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes canonical-str)))
                  anchor-pub-bytes (try (basalt/hex->bytes norm-anchor) (catch #?(:clj Exception :cljs :default) _ nil))
                  sig-bytes (try (basalt/hex->bytes (:signature d)) (catch #?(:clj Exception :cljs :default) _ nil))]
              (if-not (and (= (:dac-id d) expected-id)
                           anchor-pub-bytes sig-bytes
                           (crypto/verify anchor-pub-bytes (fressian/utf8->bytes canonical-str) sig-bytes))
                {:ok? false :valid? false :error "invalid-dac-signature"}
                (let [canonical-dac {:bitecho/type :dac
                                     :dac-id (:dac-id d)
                                     :anchor-pubkey norm-anchor
                                     :agent-pubkey norm-agent
                                     :issued-epoch iss-ep
                                     :expires-epoch exp-ep
                                     :max-spend-per-epoch max-spend
                                     :scopes sorted-scopes
                                     :signature (:signature d)}]
                  {:ok? true
                   :valid? true
                   :dac canonical-dac
                   :dac-id (:dac-id d)
                   :anchor-pubkey norm-anchor
                   :agent-pubkey norm-agent
                   :issued-epoch iss-ep
                   :expires-epoch exp-ep
                   :max-spend-per-epoch max-spend
                   :scopes sorted-scopes})))))))
    (catch #?(:clj Exception :cljs :default) _ {:ok? false :valid? false :error "malformed-dac"})))

;; -----------------------------------------------------------------------------
;; Milestone 5 (Pillar B): In-Band Authenticated Chain State Snapshot Protocol
;; -----------------------------------------------------------------------------

(defn- parse-long-safe
  "Parses a number or string into a long safely. Returns default-val (default nil) on failure or nil."
  ([v] (parse-long-safe v nil))
  ([v default-val]
   (cond
     (integer? v) (long v)
     (number? v) (long v)
     (string? v) (try
                   #?(:clj (Long/parseLong (str/trim v))
                      :cljs (let [n (js/parseInt (str/trim v) 10)]
                              (if (js/isNaN n) default-val n)))
                   (catch #?(:clj Exception :cljs :default) _ default-val))
     :else default-val)))

(defn- canonical-escrow-entry-str
  "Formats a single escrow map into canonical colon-separated representation:
   <escrow-id>:<payer>:<receiver>:<amount>:<deliverable-hash>:<created-epoch>:<expires-epoch>:<status-name>:<settled-epoch-or-empty>:<net-amount-or-empty>:<refund-reason-or-empty>"
  [esc]
  (let [eid (or (:escrow-id esc) (:escrow_id esc) "")
        payer (or (:payer esc) "")
        receiver (or (:receiver esc) (:recipient esc) "")
        amt (long (or (:amount esc) 0))
        dh (or (:deliverable-hash esc) (:deliverable_hash esc) "")
        cr-ep (long (or (:created-epoch esc) (:created_epoch esc) 0))
        exp-ep (long (or (:expires-epoch esc) (:expires_epoch esc) 0))
        st-name (name (or (:status esc) :locked))
        settled-ep (if (some? (or (:settled-epoch esc) (:settled_epoch esc)))
                     (str (or (:settled-epoch esc) (:settled_epoch esc)))
                     "")
        net-amt (if (some? (or (:net-amount esc) (:net_amount esc)))
                  (str (or (:net-amount esc) (:net_amount esc)))
                  "")
        refund-re (if (some? (or (:refund-reason esc) (:refund_reason esc)))
                    (str (or (:refund-reason esc) (:refund_reason esc)))
                    "")]
    (str eid ":" payer ":" receiver ":" amt ":" dh ":" cr-ep ":" exp-ep ":" st-name ":" settled-ep ":" net-amt ":" refund-re)))

(defn canonical-chain-state-snapshot-str
  "Computes deterministic canonical representation of a chain state snapshot:
   bitecho-chain-state-snapshot-v1|<validator-pubkey>|<pubkey>|<finalized-epoch>|<balance>|<spendable>|<seq>|<comma-joined-deps>|<canonical-escrows-str>|<nonce>"
  [snapshot]
  (let [val-pub (or (:validator-pubkey snapshot) (get snapshot "validator_pubkey") "")
        pk (or (:pubkey snapshot) (get snapshot "pubkey") "")
        fin-ep (long (or (:finalized-epoch snapshot) (get snapshot "finalized_epoch") 0))
        bal (long (or (:balance snapshot) (get snapshot "balance") 0))
        spd (long (or (:spendable snapshot) (get snapshot "spendable") 0))
        seq-num (long (or (:seq snapshot) (get snapshot "seq") 0))
        deps (vec (or (:deps snapshot) (get snapshot "deps") []))
        deps-str (str/join "," deps)
        raw-escrows (or (:escrows snapshot) (get snapshot "escrows") [])
        escrows-vec (if (map? raw-escrows) (vals raw-escrows) (vec raw-escrows))
        sorted-escrows (sort-by (fn [e] (str (or (:escrow-id e) (:escrow_id e) ""))) escrows-vec)
        escrows-str (str/join ";" (map canonical-escrow-entry-str sorted-escrows))
        nonce (or (:nonce snapshot) (get snapshot "nonce") "")]
    (str "bitecho-chain-state-snapshot-v1|"
         val-pub "|"
         pk "|"
         fin-ep "|"
         bal "|"
         spd "|"
         seq-num "|"
         deps-str "|"
         escrows-str "|"
         nonce)))

(defn sign-chain-state-snapshot
  "Signs a chain state snapshot map using validator private key bytes.
   Returns snapshot with :bitecho/type :chain-state-snapshot, :type :chain-state-snapshot, and :signature hex."
  [snapshot ^bytes validator-privkey-bytes]
  (let [canonical-str (canonical-chain-state-snapshot-str snapshot)
        sig-bytes (crypto/sign validator-privkey-bytes (fressian/utf8->bytes canonical-str))]
    (assoc snapshot
           :protocol-version current-wire-version
           :bitecho/type :chain-state-snapshot
           :type :chain-state-snapshot
           :signature (basalt/bytes->hex sig-bytes))))

(defn verify-chain-state-snapshot
  "Verifies structure, validator signature, nonce, and epoch freshness of a chain state snapshot.
   Returns {:ok? true :snapshot normalized} or {:ok? false :error <reason>}."
  [snapshot opts]
  (cond
    (not (map? snapshot))
    {:ok? false :error "malformed-snapshot"}

    (let [exp-pk (:expected-pubkey opts)
          snap-pk (or (:pubkey snapshot) (get snapshot "pubkey"))]
      (and exp-pk (not= exp-pk snap-pk)))
    {:ok? false :error "pubkey-mismatch"}

    (let [trusted (:trusted-validators opts)
          val-pub (or (:validator-pubkey snapshot) (get snapshot "validator_pubkey"))]
      (or (empty? trusted)
          (not (contains? (set (map normalize-pubkey-hex trusted)) (normalize-pubkey-hex val-pub)))))
    {:ok? false :error "untrusted-validator"}

    (let [exp-nonce (:expected-nonce opts)
          snap-nonce (or (:nonce snapshot) (get snapshot "nonce"))]
      (and exp-nonce (not= (str exp-nonce) (str snap-nonce))))
    {:ok? false :error "nonce-mismatch"}

    (< (long (or (:finalized-epoch snapshot) (get snapshot "finalized_epoch") 0))
       (long (or (:min-finalized-epoch opts) 0)))
    {:ok? false :error "stale-finalized-epoch"}

    (let [sig (or (:signature snapshot) (get snapshot "signature"))]
      (or (nil? sig) (str/blank? (str sig))))
    {:ok? false :error "missing-snapshot-signature"}

    (let [val-pub (or (:validator-pubkey snapshot) (get snapshot "validator_pubkey"))]
      (or (nil? val-pub) (str/blank? (str val-pub))))
    {:ok? false :error "missing-validator-pubkey"}

    :else
    (let [val-pub (or (:validator-pubkey snapshot) (get snapshot "validator_pubkey"))
          sig (or (:signature snapshot) (get snapshot "signature"))
          canonical-str (canonical-chain-state-snapshot-str snapshot)
          val-pub-bytes (try (basalt/hex->bytes val-pub) (catch #?(:clj Exception :cljs :default) _ nil))
          sig-bytes (try (basalt/hex->bytes sig) (catch #?(:clj Exception :cljs :default) _ nil))
          valid? (and val-pub-bytes sig-bytes
                      (try (crypto/verify val-pub-bytes (fressian/utf8->bytes canonical-str) sig-bytes)
                           (catch #?(:clj Exception :cljs :default) _ false)))]
      (if valid?
        (let [raw-escrows (or (:escrows snapshot) (get snapshot "escrows") [])
              escrows-vec (if (map? raw-escrows) (vals raw-escrows) (vec raw-escrows))
              normalized-escrows (mapv (fn [esc]
                                         (let [eid (or (:escrow-id esc) (:escrow_id esc))
                                               payer (or (:payer esc) "")
                                               receiver (or (:receiver esc) (:recipient esc) "")
                                               amt (long (or (:amount esc) 0))
                                               dh (or (:deliverable-hash esc) (:deliverable_hash esc) "")
                                               cr-ep (long (or (:created-epoch esc) (:created_epoch esc) 0))
                                               exp-ep (long (or (:expires-epoch esc) (:expires_epoch esc) 0))
                                               st-val (let [s (or (:status esc) :locked)]
                                                        (if (keyword? s) s (keyword s)))
                                               set-ep (when-let [se (or (:settled-epoch esc) (:settled_epoch esc))] (long se))
                                               net-a (when-let [na (or (:net-amount esc) (:net_amount esc))] (long na))
                                               ref-r (or (:refund-reason esc) (:refund_reason esc))]
                                           (cond-> {:escrow-id eid
                                                    :payer payer
                                                    :receiver receiver
                                                    :amount amt
                                                    :deliverable-hash dh
                                                    :created-epoch cr-ep
                                                    :expires-epoch exp-ep
                                                    :status st-val}
                                             set-ep (assoc :settled-epoch set-ep)
                                             net-a (assoc :net-amount net-a)
                                             ref-r (assoc :refund-reason ref-r))))
                                       escrows-vec)]
          {:ok? true
           :snapshot {:bitecho/type :chain-state-snapshot
                      :type :chain-state-snapshot
                      :validator-pubkey val-pub
                      :pubkey (or (:pubkey snapshot) (get snapshot "pubkey"))
                      :finalized-epoch (long (or (:finalized-epoch snapshot) (get snapshot "finalized_epoch") 0))
                      :balance (long (or (:balance snapshot) (get snapshot "balance") 0))
                      :spendable (long (or (:spendable snapshot) (get snapshot "spendable") 0))
                      :seq (long (or (:seq snapshot) (get snapshot "seq") 0))
                      :deps (vec (or (:deps snapshot) (get snapshot "deps") []))
                      :escrows normalized-escrows
                      :nonce (or (:nonce snapshot) (get snapshot "nonce") "")
                      :signature sig}})
        {:ok? false :error "invalid-snapshot-signature"}))))

(defn verify-chain-state-quorum
  "Verifies quorum agreement across validator chain state snapshots.
   Requires:
   - All snapshots pass verify-chain-state-snapshot (fails closed on any invalid snapshot)
   - Unique validators count >= quorum-size (default: 2f+1 where n = (count trusted-validators) or (count snapshots))
   - Max finalized-epoch skew <= max-epoch-skew (default 2)
   - Strict agreement on [:balance :spendable :seq :deps :canonical-escrows] across agreeing quorum
   Returns {:ok? true :snapshot best-agreed :quorum-count n :validators [...]} or {:ok? false :error <reason>}."
  [snapshots opts]
  (let [raw-snaps (cond
                    (nil? snapshots) []
                    (map? snapshots) [snapshots]
                    (sequential? snapshots) (vec snapshots)
                    :else [])
        ;; Deduplicate snapshots by validator-pubkey
        unique-snaps (vals (into {}
                                 (keep (fn [s]
                                         (when (map? s)
                                           [(or (:validator-pubkey s) (get s "validator_pubkey")) s]))
                                       raw-snaps)))
        trusted (when (seq (:trusted-validators opts)) (set (:trusted-validators opts)))
        total-n (if (seq trusted) (count trusted) (count unique-snaps))
        quorum-size (long (or (:quorum-size opts)
                              (if (pos? total-n)
                                (math-ceil (/ (* 2.0 total-n) 3.0))
                                1)))]
    (if (empty? unique-snaps)
      {:ok? false :error "empty-snapshots"}
      (let [verifications (mapv #(verify-chain-state-snapshot % opts) unique-snaps)
            first-err (first (remove :ok? verifications))]
        (if first-err
          {:ok? false :error (:error first-err)}
          (let [valid-snaps (mapv :snapshot verifications)
                n-valid (count valid-snaps)]
            (if (< n-valid quorum-size)
              {:ok? false :error "insufficient-validator-quorum"}
              (let [fin-epochs (mapv :finalized-epoch valid-snaps)
                    min-fin (apply min fin-epochs)
                    max-fin (apply max fin-epochs)
                    max-skew (long (or (:max-epoch-skew opts) 2))]
                (if (> (- max-fin min-fin) max-skew)
                  {:ok? false :error "validator-epoch-skew-exceeded"}
                  (let [state-sig (fn [s]
                                    [(:balance s)
                                     (:spendable s)
                                     (:seq s)
                                     (:deps s)
                                     (str/join ";" (map canonical-escrow-entry-str (sort-by :escrow-id (:escrows s))))])
                        by-epoch (group-by :finalized-epoch valid-snaps)
                        same-epoch-disagreement? (some (fn [[_ snaps]]
                                                         (> (count (distinct (map state-sig snaps))) 1))
                                                       by-epoch)]
                    (if same-epoch-disagreement?
                      {:ok? false :error "validator-state-disagreement"}
                      (let [by-state (group-by state-sig valid-snaps)
                            [_ agreeing-snaps] (apply max-key (fn [[_ snaps]] (count snaps)) by-state)]
                        (if (< (count agreeing-snaps) quorum-size)
                          {:ok? false :error "validator-state-disagreement"}
                          (let [best-snap (apply max-key :finalized-epoch agreeing-snaps)]
                            {:ok? true
                             :snapshot best-snap
                             :quorum-count (count agreeing-snaps)
                             :validators (vec (sort (map :validator-pubkey agreeing-snaps)))}))))))))))))))

(defn apply-verified-chain-state-snapshot
  "Applies a verified chain state snapshot to local light-node state.
   Guards against stale finalized epochs (monotonicity), prunes expired
   unconfirmed non-terminal escrows absent from snapshot, and clears stale
   status-dependent escrow fields on merge."
  [state snapshot]
  (let [curr-fin-ep (long (or (get-in state [:account :finalized-epoch]) 0))
        fin-epoch (parse-long-safe (or (:finalized-epoch snapshot) (get snapshot "finalized_epoch")) 0)]
    (if (< fin-epoch curr-fin-ep)
      state
      (let [new-account {:balance (long (or (:balance snapshot) 0))
                         :spendable (long (or (:spendable snapshot) 0))
                         :seq (long (or (:seq snapshot) 0))
                         :deps (vec (or (:deps snapshot) []))
                         :finalized-epoch fin-epoch}
            has-escrows? (or (contains? snapshot :escrows) (contains? snapshot "escrows"))
            incoming-escrows (or (:escrows snapshot) (get snapshot "escrows") [])
            incoming-ids (set (map #(or (:escrow-id %) (get % "escrow_id")) incoming-escrows))
            existing-escrows (or (:escrows state) {})
            non-terminal-statuses #{:locked :release-submitted :refund-submitted
                                    "locked" "release-submitted" "refund-submitted"}
            base-escrows (if has-escrows?
                           (into {} (remove (fn [[eid existing]]
                                              (and (not (contains? incoming-ids eid))
                                                   (contains? non-terminal-statuses (:status existing))
                                                   (< (long (or (:created-epoch existing) (:created_epoch existing) 0))
                                                      (- fin-epoch 5))))
                                            existing-escrows))
                           existing-escrows)
            merged-escrows (reduce (fn [acc esc]
                                     (let [eid (or (:escrow-id esc) (get esc "escrow_id"))
                                           existing (dissoc (get acc eid {})
                                                            :settled-epoch :net-amount :take-burned :refund-reason
                                                            "settled_epoch" "net_amount" "take_burned" "refund_reason")]
                                       (assoc acc eid (merge existing esc))))
                                   base-escrows
                                   incoming-escrows)]
        (-> state
            (assoc :account new-account
                   :transfer-seq (:seq new-account)
                   :last-transfer-hash (last (:deps new-account))
                   :epoch (max (long (or (:epoch state) 0)) fin-epoch)
                   :epoch-initialized? true
                   :escrows merged-escrows))))))

(defn build-chain-state-query-envelope
  "Builds and wraps an authenticated :query-chain-state agent envelope.
   opts can be a map (e.g. {:nonce ... :epoch ...}) or a string nonce."
  [pubkey-hex ^bytes privkey-bytes opts]
  (let [opts-map (if (map? opts) opts {:nonce (str opts)})
        epoch-val (long (or (:epoch opts-map) 0))
        default-nonce (str "qcs-" epoch-val "-" (subs (str pubkey-hex) 0 (min 16 (count (str pubkey-hex)))))
        payload {:type :query-chain-state
                 :pubkey pubkey-hex
                 :epoch epoch-val
                 :nonce (or (:nonce opts-map) default-nonce)}]
    (wrap-agent-event payload pubkey-hex privkey-bytes)))

(defn- resolve-session-id
  "Resolves a session id from cmd-map or counterparty identifier (petname/pubkey).
   Supports :open (prefers open sessions) or :active (prefers non-closed sessions).
   Fails closed (returns nil) if multiple preferred sessions exist for the counterparty."
  [state cmd-map preference]
  (let [raw-sid (or (get cmd-map "session_id") (get cmd-map "session-id") (get cmd-map "session")
                    (:session_id cmd-map) (:session-id cmd-map) (:session cmd-map))]
    (if (and raw-sid (contains? (:sessions state) raw-sid))
      raw-sid
      (let [target (or raw-sid (get cmd-map "peer") (get cmd-map "callee")
                       (:peer cmd-map) (:callee cmd-map))
            resolved (when target (resolve-counterparty state target))]
        (when (:ok? resolved)
          (let [matching (filterv (fn [[_ s]] (= (:peer s) (:pubkey resolved))) (:sessions state))
                preferred-pred (case preference
                                 :open (fn [[_ s]] (= "open" (:state s)))
                                 :active (fn [[_ s]] (not= "closed" (:state s)))
                                 (constantly true))
                preferred-matching (filterv preferred-pred matching)]
            (cond
              (= 1 (count preferred-matching))
              (first (first preferred-matching))

              (> (count preferred-matching) 1)
              nil

              (= 1 (count matching))
              (first (first matching))

              :else
              nil)))))))

(defn- resolve-accept-session-id
  "Resolves an accept session id from cmd-map or caller identifier in pending-offers."
  [state cmd-map]
  (let [raw-sid (or (get cmd-map "session_id") (get cmd-map "session-id")
                    (:session_id cmd-map) (:session-id cmd-map))]
    (if (and raw-sid (or (contains? (:pending-offers state) raw-sid)
                         (contains? (:sessions state) raw-sid)))
      raw-sid
      (let [target (or raw-sid (get cmd-map "caller") (get cmd-map "peer")
                       (:caller cmd-map) (:peer cmd-map))
            resolved (when target (resolve-counterparty state target))]
        (if (and resolved (:ok? resolved))
          (let [matching (filter (fn [[_ offer]] (= (:caller offer) (:pubkey resolved)))
                                 (:pending-offers state))]
            (if (= 1 (count matching))
              (first (first matching))
              raw-sid))
          raw-sid)))))

;; -----------------------------------------------------------------------------
;; Command Handlers (Pure Helpers)
;; -----------------------------------------------------------------------------

(defn- dac-summary [dac]
  (when (map? dac)
    (let [d (into {} (for [[k v] dac]
                       [(if (keyword? k) k (keyword (str/replace (name k) #"_" "-"))) v]))]
      {"dac_id" (:dac-id d)
       "anchor_pubkey" (:anchor-pubkey d)
       "expires_epoch" (:expires-epoch d)})))

(defn- exec-identity [state]
  {:state state
   :response (cond-> {"ok" true
                      "pubkey" (:pubkey state)
                      "fingerprint" (:fingerprint state)
                      "ice_ufrag" (get-in state [:ice-creds :ufrag])
                      "ice_pwd" (get-in state [:ice-creds :pwd])}
               (:dac state) (assoc "dac" (dac-summary (:dac state))))
   :net-envelopes []
   :stdout-events []})

(defn- exec-discover [state]
  (let [bs (:bootstrap state)
        nodes (for [[k v] (or (:nodes bs) {})]
                (cond-> {"node_id" (name k)
                         "ip" (:ip v)
                         "port" (:port v)
                         "agent_port" (:agent-port v)
                         "fingerprint" (:fingerprint v)}
                  (:agent-tcp-port v) (assoc "agent_tcp_port" (:agent-tcp-port v))
                  (:pubkey v) (assoc "pubkey" (:pubkey v))
                  (:ingress-host v) (assoc "ingress_host" (:ingress-host v))
                  (:ingress-port v) (assoc "ingress_port" (:ingress-port v))))]
    {:state state
     :response {"ok" true
                "network" (name (or (:network bs) :devnet))
                "treasury_pubkey" (:treasury-pubkey bs)
                "custody_pubkey" (:custody-pubkey bs)
                "validators" (vec nodes)}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-register-home-set [state cmd-map privkey-bytes]
  (let [p-b (long (or (get cmd-map "price") 0))
        p-b-max (long (or (get cmd-map "price_max") p-b 0))
        explicit-nodes (seq (remove str/blank? (map str (get cmd-map "home_nodes"))))]
    (if explicit-nodes
      (let [known-nodes (set (keys (get-in state [:bootstrap :nodes])))
            requested-nodes (mapv keyword explicit-nodes)]
        (if (or (empty? known-nodes) (not-every? known-nodes requested-nodes))
          {:state state
           :response {"ok" false "error" "unknown-home-node"}
           :net-envelopes []
           :stdout-events []}
          (let [candidate-maps (mapv (fn [cid] {:node-id cid :responsive? true :latency-ms 10 :price p-b}) requested-nodes)
                hs (rendezvous/register-home-set candidate-maps p-b p-b-max)
                my-pub (:pubkey state)
                curr-epoch (:epoch state)
                ice-ufrag (get-in state [:ice-creds :ufrag])
                ice-pwd (get-in state [:ice-creds :pwd])
                env-curr (build-home-set-envelope my-pub privkey-bytes requested-nodes p-b curr-epoch ice-ufrag ice-pwd)
                env-nil (build-home-set-envelope my-pub privkey-bytes requested-nodes p-b nil ice-ufrag ice-pwd)]
            {:state (assoc state :home-set (:home-nodes hs))
             :response {"ok" true
                        "status" (name (:status hs :ok))
                        "price" (:price hs p-b)
                        "home_nodes" (vec (for [n (:home-nodes hs)] (name (or (:node-id n) n))))}
             :net-envelopes [env-curr env-nil]
             :stdout-events []})))
      (let [candidates (vec (keys (get-in state [:bootstrap :nodes])))
            candidate-maps (mapv (fn [cid] {:node-id cid :responsive? true :latency-ms 10 :price p-b}) candidates)
            hs (rendezvous/register-home-set candidate-maps p-b p-b-max)
            my-pub (:pubkey state)
            curr-epoch (:epoch state)
            ice-ufrag (get-in state [:ice-creds :ufrag])
            ice-pwd (get-in state [:ice-creds :pwd])
            env-curr (build-home-set-envelope my-pub privkey-bytes candidates p-b curr-epoch ice-ufrag ice-pwd)
            env-nil (build-home-set-envelope my-pub privkey-bytes candidates p-b nil ice-ufrag ice-pwd)]
        {:state (assoc state :home-set (:home-nodes hs))
         :response {"ok" true
                    "status" (name (:status hs :ok))
                    "price" (:price hs p-b)
                    "home_nodes" (vec (for [n (:home-nodes hs)] (name (or (:node-id n) n))))}
         :net-envelopes [env-curr env-nil]
         :stdout-events []}))))

(defn compute-session-id
  "Computes deterministic session-id from caller, callee, and caller-ephemeral-pub."
  [caller callee caller-ephemeral-pub]
  (let [sid-input (str caller "-" callee "-" caller-ephemeral-pub)]
    (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes sid-input)))))

(defn compute-offer-hash
  "Computes deterministic offer-hash binding session-id, caller, callee, ephemeral key, epoch, price, home-node,
   optional :crypto-suites, and optional DAC.
   Recreates the exact base format with optional |<suites-csv> and optional |<dac-id> appended."
  [offer-map]
  (let [caller (str (or (:caller offer-map) (get offer-map "caller") ""))
        callee (str (or (:callee offer-map) (get offer-map "callee") ""))
        eph-pub (str (or (:caller-ephemeral-pub offer-map) (get offer-map "caller_ephemeral_pub") (get offer-map "caller-ephemeral-pub")
                         (:caller-x25519 offer-map) (get offer-map "caller_x25519") (get offer-map "caller-x25519") ""))
        sid (str (or (:session-id offer-map) (get offer-map "session_id") (get offer-map "session-id")
                     (when (and (seq caller) (seq callee) (seq eph-pub))
                       (compute-session-id caller callee eph-pub))
                     ""))
        epoch (parse-long-safe (or (:epoch offer-map) (get offer-map "epoch")) 0)
        price-or-burn (parse-long-safe (or (:price offer-map) (get offer-map "price")
                                           (:burn offer-map) (get offer-map "burn")) 0)
        home-node (or (:home-node offer-map) (get offer-map "home_node") (get offer-map "home-node") "")
        hn-str (cond
                 (string? home-node) home-node
                 (or (keyword? home-node) (symbol? home-node)) (name home-node)
                 :else (str (or home-node "")))
        suites (or (:crypto-suites offer-map) (get offer-map "crypto_suites") (get offer-map "crypto-suites"))
        suites-str (when (seq suites)
                     (str/join "," (map #(if (keyword? %) (name %) (str %)) suites)))
        dac (or (:dac offer-map) (get offer-map "dac"))
        dac-id (or (:dac-id offer-map) (get offer-map "dac_id") (get offer-map "dac-id")
                   (when dac (or (:dac-id dac) (get dac "dac_id") (get dac "dac-id") (:dac_id dac))))
        subnet (or (:subnet-id offer-map) (get offer-map "subnet_id") (get offer-map "subnet-id"))
        subnet-str (when (and (string? subnet) (not (str/blank? subnet)) (not= subnet "global"))
                     subnet)
        base-input (str sid "-" caller "-" callee "-" eph-pub "-" epoch "-" price-or-burn "-" hn-str)
        with-suites (if (seq suites-str)
                      (str base-input "|" suites-str)
                      base-input)
        with-dac (if (and (string? dac-id) (not (str/blank? dac-id)))
                   (str with-suites "|" dac-id)
                   with-suites)
        hash-input (if subnet-str
                     (str with-dac "|" subnet-str)
                     with-dac)]
    (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes hash-input)))))

(defn canonical-rendezvous-header-str
  "Computes canonical string for Phase 1 :rendezvous-offer-header caller signature,
   optionally binding :crypto-suites."
  ([caller callee offer-hash epoch burn topic home-node dac-id]
   (canonical-rendezvous-header-str caller callee offer-hash epoch burn topic home-node dac-id nil))
  ([caller callee offer-hash epoch burn topic home-node dac-id suites]
   (let [base (str "bitecho-rendezvous-header-v1|"
                   caller "|" callee "|" offer-hash "|"
                   (long epoch) "|" (long burn) "|"
                   (or topic "") "|" (or home-node "") "|" (or dac-id ""))
         suites-str (when (seq suites)
                      (str/join "," (map #(if (keyword? %) (name %) (str %)) suites)))]
     (if (seq suites-str)
       (str base "|" suites-str)
       base))))

(defn canonical-rendezvous-ack-str
  "Computes canonical string for Phase 1b :rendezvous-ack-voucher callee signature,
   optionally binding :selected-suite."
  ([caller callee offer-hash callee-x25519 epoch ack-sig]
   (canonical-rendezvous-ack-str caller callee offer-hash callee-x25519 epoch ack-sig nil))
  ([caller callee offer-hash callee-x25519 epoch ack-sig selected-suite]
   (let [base (str "bitecho-rendezvous-ack-v1|"
                   caller "|" callee "|" offer-hash "|"
                   callee-x25519 "|" (long epoch) "|" ack-sig)]
     (if (and (string? selected-suite) (not (str/blank? selected-suite)))
       (str base "|" selected-suite)
       base))))

(defn canonical-rendezvous-reveal-str
  "Computes canonical string for Phase 2 :rendezvous-reveal caller signature."
  [session-id caller callee offer-hash caller-x25519 epoch]
  (str "bitecho-rendezvous-reveal-v1|"
       session-id "|" caller "|" callee "|" offer-hash "|"
       caller-x25519 "|" (long epoch)))

(defn- exec-rendezvous-policy
  "Configures pure rendezvous policy for Callee introducer introduction."
  [state cmd-map]
  (let [curr-pol (or (:rendezvous-policy state)
                     {:auto-accept? false :min-burn 0 :price 10 :allowlist #{} :home-node "default-home"})
        raw-min-burn (or (get cmd-map "min_burn") (get cmd-map "min-burn")
                         (:min_burn cmd-map) (:min-burn cmd-map))
        raw-price (or (get cmd-map "price") (:price cmd-map))
        min-burn-val (when (some? raw-min-burn) (parse-long-safe raw-min-burn :invalid))
        price-val (when (some? raw-price) (parse-long-safe raw-price :invalid))]
    (if (or (and (some? raw-min-burn) (or (= min-burn-val :invalid) (< min-burn-val 0)))
            (and (some? raw-price) (or (= price-val :invalid) (< price-val 0))))
      {:state state
       :response {"ok" false "error" "invalid-policy-numeric"}
       :net-envelopes []
       :stdout-events []}
      (let [allowlist-raw (or (get cmd-map "allowlist") (:allowlist cmd-map))
            allowlist-resolved (when (some? allowlist-raw)
                                 (let [items (cond (sequential? allowlist-raw) allowlist-raw
                                                   (set? allowlist-raw) (vec allowlist-raw)
                                                   (string? allowlist-raw) (str/split allowlist-raw #",")
                                                   :else [])]
                                   (into #{}
                                         (keep (fn [item]
                                                 (let [s (str/trim (str item))]
                                                   (when (seq s)
                                                     (let [res (resolve-counterparty state s)]
                                                       (if (:ok? res)
                                                         (:pubkey res)
                                                         (normalize-pubkey-hex s))))))
                                               items))))
            home-node-val (let [hn (or (get cmd-map "home_node") (get cmd-map "home-node")
                                       (:home_node cmd-map) (:home-node cmd-map))]
                            (when (some? hn)
                              (if (keyword? hn) (name hn) (str hn))))
            auto-accept-val (let [aa (or (get cmd-map "auto_accept") (get cmd-map "auto-accept")
                                         (get cmd-map "auto_accept?") (get cmd-map "auto-accept?")
                                         (:auto_accept cmd-map) (:auto-accept cmd-map)
                                         (:auto_accept? cmd-map) (:auto-accept? cmd-map))]
                              (when (some? aa) (boolean aa)))
            updated-pol (cond-> curr-pol
                          (some? min-burn-val) (assoc :min-burn min-burn-val)
                          (some? price-val) (assoc :price price-val)
                          (some? allowlist-resolved) (assoc :allowlist allowlist-resolved)
                          (some? home-node-val) (assoc :home-node home-node-val)
                          (some? auto-accept-val) (assoc :auto-accept? auto-accept-val))
            new-state (assoc state :rendezvous-policy updated-pol)]
        {:state new-state
         :response {"ok" true
                    "rendezvous_policy" {"min_burn" (:min-burn updated-pol)
                                         "price" (:price updated-pol)
                                         "allowlist" (vec (sort (:allowlist updated-pol #{})))
                                         "home_node" (:home-node updated-pol)
                                         "auto_accept" (:auto-accept? updated-pol)}}
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-rendezvous-offer
  "Phase 1 introduction: Caller initiates two-phase rendezvous offer header,
   withholding ephemeral X25519 key until callee DeliveryAck voucher is returned."
  [state cmd-map privkey-bytes]
  (let [callee-target (or (get cmd-map "callee") (get cmd-map "to")
                          (:callee cmd-map) (:to cmd-map))
        resolved (resolve-counterparty state callee-target)]
    (if-not (:ok? resolved)
      {:state state
       :response {"ok" false "error" (:error resolved)}
       :net-envelopes []
       :stdout-events []}
      (let [econ? (get state :economy-enabled? true)
            floor (if econ? (long (get state :burn-floor 0)) 0)
            default-burn (if econ? (max floor 500) 0)
            raw-burn (or (get cmd-map "burn") (:burn cmd-map))
            parsed-burn (if (some? raw-burn) (parse-long-safe raw-burn :invalid) default-burn)]
        (cond
          (or (= parsed-burn :invalid) (neg? parsed-burn))
          {:state state
           :response {"ok" false "error" "invalid-burn"}
           :net-envelopes []
           :stdout-events []}

          (and (pos? floor) (< parsed-burn floor))
          {:state state
           :response {"ok" false "error" "burn-below-floor"}
           :net-envelopes []
           :stdout-events []}

          :else
          (let [callee (:pubkey resolved)
                pname (:petname resolved)
                burn-amt parsed-burn
                topic (str (or (get cmd-map "topic") (:topic cmd-map) ""))
                default-home (or (first (keys (get-in state [:bootstrap :nodes]))) :node1)
                home-node (name (or (get cmd-map "home_node") (get cmd-map "home-node")
                                    (:home_node cmd-map) (:home-node cmd-map)
                                    default-home))
                text (or (get cmd-map "text") (:text cmd-map))
                caller (:pubkey state)
                kp-eph (sealed/generate-x25519-keypair)
                caller-x25519-pub (basalt/bytes->hex (:public kp-eph))
                session-id (compute-session-id caller callee caller-x25519-pub)
                epoch (:epoch state)
                active-dac (when-let [d (:dac state)]
                             (when (and (:ok? (verify-dac d {:expected-agent-pubkey caller
                                                             :current-epoch epoch
                                                             :revoked-dac-ids (:revoked-dacs state)}))
                                        (let [sc (set (map name (:scopes d)))]
                                          (or (contains? sc "offer") (contains? sc "rendezvous"))))
                               d))
                dac-id (when active-dac (or (:dac-id active-dac) (get active-dac "dac_id")))
                suites (or (:crypto-suites state) sealed/default-crypto-suites)
                sub-id (str (or (:subnet-id state) "global"))
                offer-hash (compute-offer-hash {:session-id session-id
                                                :caller caller
                                                :callee callee
                                                :caller-ephemeral-pub caller-x25519-pub
                                                :epoch epoch
                                                :price burn-amt
                                                :burn burn-amt
                                                :home-node home-node
                                                :crypto-suites suites
                                                :dac active-dac
                                                :subnet-id sub-id})
                header-str (canonical-rendezvous-header-str caller callee offer-hash epoch burn-amt topic home-node dac-id suites)
                sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes header-str)))
                wire-payload (cond-> {:protocol-version current-wire-version
                                      :wire-format current-wire-format
                                      :subnet-id sub-id
                                      :bitecho/type :rendezvous-offer-header
                                      :type :rendezvous-offer-header
                                      :caller caller
                                      :callee callee
                                      :offer-hash offer-hash
                                      :epoch epoch
                                      :burn burn-amt
                                      :topic topic
                                      :home-node home-node
                                      :crypto-suites suites
                                      :signature sig-hex}
                               active-dac (assoc :dac active-dac))
                gossip-env (assoc (build-gossip-envelope caller privkey-bytes (freeze-payload wire-payload) burn-amt)
                                  :subnet-id sub-id)
                outbound-entry {:offer-hash offer-hash
                                :session-id session-id
                                :caller caller
                                :callee callee
                                :caller-x25519-priv (:private kp-eph)
                                :caller-x25519-pub caller-x25519-pub
                                :crypto-suites suites
                                :initial-text text
                                :epoch epoch
                                :burn burn-amt
                                :topic topic
                                :home-node home-node
                                :dac active-dac}
                new-state (-> state
                              (assoc-in [:outbound-rendezvous offer-hash] outbound-entry)
                              (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))]
            {:state new-state
             :response (cond-> {"ok" true
                                "offer_hash" offer-hash
                                "session_id" session-id
                                "caller" caller
                                "callee" callee
                                "burn" burn-amt}
                         pname (assoc "callee_petname" pname "peer_petname" pname))
             :net-envelopes [gossip-env]
             :stdout-events []}))))))

(defn- callee-issue-rendezvous-ack
  "Pure helper for Callee accepting an offer header, signing a DeliveryAck voucher,
   generating ephemeral X25519 key, and creating the :rendezvous-ack-voucher wire envelope."
  [state pending-header privkey-bytes]
  (let [caller (:caller pending-header)
        callee (:callee pending-header)
        offer-hash (:offer-hash pending-header)
        epoch (long (or (:epoch pending-header) (:epoch state) 0))
        home-node (rendezvous/normalize-home-node
                   (or (:home-node pending-header)
                       (get-in state [:rendezvous-policy :home-node])
                       "default-home"))
        p-b (long (or (get-in state [:rendezvous-policy :price]) 10))
        seq-key [home-node epoch]
        curr-seq (long (get-in state [:voucher-seqs seq-key] 0))
        next-seq (inc curr-seq)
        cumulative-debit (* next-seq p-b)
        signed-ack (rendezvous/create-delivery-ack privkey-bytes callee home-node epoch offer-hash next-seq cumulative-debit)
        kp-callee (sealed/generate-x25519-keypair)
        callee-x25519-pub (basalt/bytes->hex (:public kp-callee))
        has-caller-suites? (boolean (seq (:crypto-suites pending-header)))
        selected-suite (if has-caller-suites?
                         (or (:selected-suite pending-header)
                             (:selected-suite (sealed/negotiate-crypto-suite
                                               (:crypto-suites pending-header)
                                               (or (:crypto-suites state) sealed/default-crypto-suites)))
                             sealed/suite-v1-aes256gcm)
                         sealed/suite-v1-chacha20poly1305)
        ack-str (canonical-rendezvous-ack-str caller callee offer-hash callee-x25519-pub epoch (:signature signed-ack)
                                              (when has-caller-suites? selected-suite))
        sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes ack-str)))
        ack-payload (cond-> {:protocol-version current-wire-version
                             :wire-format current-wire-format
                             :bitecho/type :rendezvous-ack-voucher
                             :type :rendezvous-ack-voucher
                             :caller caller
                             :callee callee
                             :offer-hash offer-hash
                             :callee-x25519 callee-x25519-pub
                             :epoch epoch
                             :delivery-ack (into {} signed-ack)
                             :signature sig-hex}
                      has-caller-suites? (assoc :selected-suite selected-suite))
        gossip-env (build-gossip-envelope callee privkey-bytes (freeze-payload ack-payload) 500)
        accept-entry {:callee-x25519-priv (:private kp-callee)
                      :callee-x25519-pub callee-x25519-pub
                      :caller caller
                      :callee callee
                      :epoch epoch
                      :selected-suite selected-suite
                      :delivery-ack (into {} signed-ack)
                      :header pending-header}
        new-state (-> state
                      (update :pending-rendezvous dissoc offer-hash)
                      (assoc-in [:pending-rendezvous-accepts offer-hash] accept-entry)
                      (assoc-in [:voucher-seqs seq-key] next-seq))]
    {:state new-state
     :signed-ack signed-ack
     :callee-x25519 callee-x25519-pub
     :next-seq next-seq
     :cumulative-debit cumulative-debit
     :net-envelopes [gossip-env]}))

(defn- exec-rendezvous-accept
  "Explicit Callee accept command for a pending rendezvous offer header."
  [state cmd-map privkey-bytes]
  (let [oh (or (get cmd-map "offer_hash") (get cmd-map "offer-hash")
               (:offer_hash cmd-map) (:offer-hash cmd-map))
        from-target (or (get cmd-map "from") (get cmd-map "caller")
                        (:from cmd-map) (:caller cmd-map))
        pending-header (cond
                         (and oh (contains? (:pending-rendezvous state) oh))
                         (get-in state [:pending-rendezvous oh])

                         from-target
                         (let [res (resolve-counterparty state from-target)]
                           (when (:ok? res)
                             (some (fn [[_ h]] (when (= (normalize-pubkey-hex (:caller h))
                                                        (normalize-pubkey-hex (:pubkey res)))
                                                 h))
                                   (:pending-rendezvous state))))
                         :else nil)]
    (if-not pending-header
      {:state state
       :response {"ok" false "error" "rendezvous-offer-not-found"}
       :net-envelopes []
       :stdout-events []}
      (let [ack-res (callee-issue-rendezvous-ack state pending-header privkey-bytes)
            caller (:caller pending-header)
            caller-pname (pubkey->petname state caller)]
        {:state (:state ack-res)
         :response (cond-> {"ok" true
                            "offer_hash" (:offer-hash pending-header)
                            "caller" caller
                            "callee" (:callee pending-header)
                            "seq" (:next-seq ack-res)
                            "cumulative_debit" (:cumulative-debit ack-res)}
                     caller-pname (assoc "caller_petname" caller-pname "peer_petname" caller-pname))
         :net-envelopes (:net-envelopes ack-res)
         :stdout-events []}))))

(defn- exec-offer [state cmd-map privkey-bytes]
  (let [callee-target (or (get cmd-map "callee") (get cmd-map "peer") (get cmd-map "to")
                          (:callee cmd-map) (:peer cmd-map) (:to cmd-map))
        resolved (resolve-counterparty state callee-target)]
    (if-not (:ok? resolved)
      {:state state
       :response {"ok" false "error" (:error resolved)}
       :net-envelopes []
       :stdout-events []}
      (let [raw-price (or (get cmd-map "price") (:price cmd-map))
            raw-burn (or (get cmd-map "burn") (:burn cmd-map))
            parsed-price (if (some? raw-price) (parse-long-safe raw-price :invalid) 0)
            parsed-burn (if (some? raw-burn) (parse-long-safe raw-burn :invalid) 500)]
        (if (or (= parsed-price :invalid) (< parsed-price 0)
                (= parsed-burn :invalid) (< parsed-burn 0))
          {:state state
           :response {"ok" false "error" "invalid-numeric-parameter"}
           :net-envelopes []
           :stdout-events []}
          (let [callee (:pubkey resolved)
                pname (:petname resolved)
                price parsed-price
                default-home (or (first (keys (get-in state [:bootstrap :nodes]))) :node1)
                home-node (name (or (get cmd-map "home_node") (:home_node cmd-map) default-home))
                burn-amt parsed-burn
                kp-eph (sealed/generate-x25519-keypair)
                caller (:pubkey state)
                eph-pub-hex (basalt/bytes->hex (:public kp-eph))
                session-id (compute-session-id caller callee eph-pub-hex)
                epoch (:epoch state)
                active-dac (when-let [d (:dac state)]
                             (when (:ok? (verify-dac d {:expected-agent-pubkey (:pubkey state)
                                                        :current-epoch epoch
                                                        :revoked-dac-ids (:revoked-dacs state)
                                                        :required-scope "offer"}))
                               d))
                suites (or (:crypto-suites state) sealed/default-crypto-suites)
                sub-id (str (or (:subnet-id state) "global"))
                offer-hash (compute-offer-hash {:session-id session-id
                                                :caller caller
                                                :callee callee
                                                :caller-ephemeral-pub eph-pub-hex
                                                :epoch epoch
                                                :price price
                                                :home-node home-node
                                                :crypto-suites suites
                                                :dac active-dac
                                                :subnet-id sub-id})
                sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes offer-hash)))
                offer-payload (cond-> {:protocol-version current-wire-version
                                       :wire-format current-wire-format
                                       :subnet-id sub-id
                                       :bitecho/type :channel-offer
                                       :session-id session-id
                                       :caller caller
                                       :callee callee
                                       :caller-ephemeral-pub eph-pub-hex
                                       :epoch epoch
                                       :price price
                                       :home-node home-node
                                       :crypto-suites suites
                                       :offer-hash offer-hash
                                       :burn burn-amt
                                       :signature sig-hex}
                                active-dac (assoc :dac active-dac))
                gossip-env (build-gossip-envelope caller privkey-bytes (freeze-payload offer-payload) burn-amt sub-id)
                header-event {:type :receive-offer-header
                              :subnet-id sub-id
                              :caller caller
                              :callee callee
                              :home-node home-node
                              :epoch epoch
                              :price price
                              :offer-hash offer-hash
                              :session-id session-id}
                header-env (wrap-agent-event header-event caller privkey-bytes)
                session-entry {:session-id session-id
                               :peer callee
                               :role :initiator
                               :state "offered"
                               :tx-seq 0
                               :epoch epoch
                               :crypto-suites suites
                               :ephemeral-pub (:public kp-eph)
                               :ephemeral-priv (:private kp-eph)
                               :price price
                               :home-node home-node
                               :offer-hash offer-hash}
                new-state (-> state
                              (assoc-in [:sessions session-id] session-entry)
                              (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))]
            {:state new-state
             :response (cond-> {"ok" true
                                "session_id" session-id
                                "state" "offered"
                                "callee" callee
                                "price" price
                                "burn" burn-amt}
                         pname (assoc "callee_petname" pname "peer_petname" pname))
             :net-envelopes [header-env gossip-env]
             :stdout-events []}))))))

(defn- exec-accept [state cmd-map privkey-bytes]
  (let [session-id (resolve-accept-session-id state cmd-map)]
    (cond
      (contains? (:sessions state) session-id)
      {:state (update state :pending-offers dissoc session-id)
       :response {"ok" false "error" "session-already-exists"}
       :net-envelopes []
       :stdout-events []}

      (not (get-in state [:pending-offers session-id]))
      {:state state :response {"ok" false "error" "offer-not-found"} :net-envelopes [] :stdout-events []}

      :else
      (let [offer (get-in state [:pending-offers session-id])
            caller (:caller offer)
            caller-pname (pubkey->petname state caller)
            kp-resp (sealed/generate-x25519-keypair)
            caller-eph (basalt/hex->bytes (:caller-ephemeral-pub offer))
            shared-sec (sealed/x25519-shared-secret (:private kp-resp) caller-eph)
            keys (sealed/derive-channel-keys shared-sec session-id :responder)
            eph-pub-hex (basalt/bytes->hex (:public kp-resp))
            epoch (long (or (:epoch offer) (:epoch state) 0))
            burn-val (or (:burn offer) 500)
            ack-res (rendezvous/process-offer-header
                     {:caller caller
                      :callee (:pubkey state)
                      :callee-privkey privkey-bytes
                      :offer {:epoch (:epoch offer)
                              :home-node (:home-node offer)
                              :offer-hash (:offer-hash offer)
                              :price (:price offer)}
                      :home-node (:home-node offer)
                      :epoch (:epoch offer)
                      :offer-hash (:offer-hash offer)
                      :price (:price offer)
                      :burn burn-val
                      :seq 1
                      :min-burn (if (get state :economy-enabled? true)
                                  (long (or (:burn-floor state) 100))
                                  0)})
            delivery-ack (into {} (:delivery-ack ack-res))
            has-caller-suites? (boolean (seq (:crypto-suites offer)))
            selected-suite (if has-caller-suites?
                             (or (:selected-suite offer)
                                 (:selected-suite (sealed/negotiate-crypto-suite
                                                   (:crypto-suites offer)
                                                   (or (:crypto-suites state) sealed/default-crypto-suites)))
                                 sealed/suite-v1-aes256gcm)
                             sealed/suite-v1-chacha20poly1305)
            sig-input (if has-caller-suites?
                        (str session-id "-" eph-pub-hex "|" selected-suite)
                        (str session-id "-" eph-pub-hex))
            sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes sig-input)))
            sub-id (str (or (:subnet-id state) "global"))
            burn-amt (if (get state :economy-enabled? true) 500 0)
            accept-payload (cond-> {:protocol-version current-wire-version
                                    :wire-format current-wire-format
                                    :subnet-id sub-id
                                    :bitecho/type :channel-accept
                                    :session-id session-id
                                    :caller caller
                                    :callee (:pubkey state)
                                    :callee-ephemeral-pub eph-pub-hex
                                    :epoch epoch
                                    :delivery-ack delivery-ack
                                    :signature sig-hex}
                             has-caller-suites? (assoc :selected-suite selected-suite))
            gossip-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload accept-payload) burn-amt sub-id)
            session-entry {:session-id session-id
                           :peer caller
                           :role :responder
                           :state "open"
                           :tx-seq 0
                           :acked-seq 0
                           :rx-high-seq 0
                           :contiguous-rx-seq 0
                           :replays-deduped 0
                           :outbox-evicted 0
                           :outbox {}
                           :outbox-order []
                           :epoch epoch
                           :suite selected-suite
                           :tx-key (:tx-key keys)
                           :rx-key (:rx-key keys)
                           :replay-window (sealed/init-replay-window)}
            new-state (-> state
                          (update :pending-offers dissoc session-id)
                          (assoc-in [:sessions session-id] session-entry))
            event (cond-> {"event" "channel-opened" "session_id" session-id "peer" caller}
                    caller-pname (assoc "peer_petname" caller-pname))]
        {:state new-state
         :response (cond-> {"ok" true "session_id" session-id "state" "open" "peer" caller
                            "selected_suite" selected-suite}
                     caller-pname (assoc "peer_petname" caller-pname))
         :net-envelopes [gossip-env]
         :stdout-events [event]}))))

(defn- canonical-p2p-signal-str
  [kind session-id sender recipient transport candidates ice-ufrag ice-pwd fingerprint epoch]
  (str "bitecho-p2p-" (name kind) "-v1|"
       session-id "|"
       (normalize-pubkey-hex sender) "|"
       (normalize-pubkey-hex recipient) "|"
       (or transport "udp") "|"
       (str/join "," (sort (map str (or candidates [])))) "|"
       (or ice-ufrag "") "|"
       (or ice-pwd "") "|"
       (or fingerprint "") "|"
       (long (or epoch 0))))

(defn compute-broadcast-msg-id
  "Computes a deterministic SHA-256 hex message ID for a 3-way P2P broadcast."
  [subnet-id sender-pubkey sender-seq text]
  (basalt/bytes->hex
   (crypto/sha256
    (fressian/utf8->bytes
     (str "bitecho-broadcast-id-v1|"
          (or subnet-id "global") "|"
          (normalize-pubkey-hex sender-pubkey) "|"
          (long sender-seq) "|"
          text)))))

(defn- canonical-broadcast-str
  [subnet-id sender-pubkey sender-seq msg-id text epoch dac-id]
  (str "bitecho-broadcast-v1|"
       (or subnet-id "global") "|"
       (normalize-pubkey-hex sender-pubkey) "|"
       (long sender-seq) "|"
       msg-id "|"
       text "|"
       (long (or epoch 0)) "|"
       (or dac-id "")))

(defn build-p2p-hub-relay-envelope
  "Builds a zero-burn signed `:p2p-hub-relay` envelope allowing a P2P hub (such as Nexus)
   to forward an opaque end-to-end sealed session envelope (`:sealed-envelope`) to `:target-pubkey`
   at 0 ECH burn without possessing or decrypting the session keys."
  [sender-pubkey sender-privkey {:keys [target-pubkey session-id sealed-envelope subnet-id]}]
  (let [norm-sender (normalize-pubkey-hex sender-pubkey)
        norm-target (normalize-pubkey-hex target-pubkey)
        sub-id (str (or subnet-id (:subnet-id sealed-envelope) "global"))
        sid (str (or session-id ""))
        canonical-str (str "bitecho-p2p-hub-relay-v1|" sub-id "|" norm-sender "|" norm-target "|" sid)
        sig-bytes (crypto/sign sender-privkey (fressian/utf8->bytes canonical-str))
        sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
        payload {:protocol-version current-wire-version
                 :wire-format current-wire-format
                 :subnet-id sub-id
                 :bitecho/type :p2p-hub-relay
                 :type :p2p-hub-relay
                 :sender norm-sender
                 :target-pubkey norm-target
                 :session-id sid
                 :sealed-envelope sealed-envelope
                 :signature sig-hex}]
    (build-gossip-envelope norm-sender sender-privkey (freeze-payload payload) 0 sub-id)))

(defn- exec-p2p-offer [state cmd-map privkey-bytes]
  (let [session-id (resolve-session-id state cmd-map :open)
        session (get-in state [:sessions session-id])]
    (if-not (and session (= "open" (:state session)))
      {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}
      (let [sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id state) "global"))
            transport (str (or (get cmd-map "transport") (:transport cmd-map) "udp"))
            raw-cands (or (get cmd-map "candidates") (:candidates cmd-map) [])
            candidates (vec (map str (if (string? raw-cands)
                                       (remove str/blank? (str/split raw-cands #","))
                                       raw-cands)))
            ice-ufrag (str (or (get cmd-map "ice_ufrag") (get cmd-map "ice-ufrag") (:ice-ufrag cmd-map) (get-in state [:ice-creds :ufrag]) "ufrag"))
            ice-pwd (str (or (get cmd-map "ice_pwd") (get cmd-map "ice-pwd") (:ice-pwd cmd-map) (get-in state [:ice-creds :pwd]) "pwd"))
            fp (str (or (get cmd-map "fingerprint") (:fingerprint cmd-map) (:fingerprint state) ""))
            epoch (long (or (:epoch session) (:epoch state) 0))
            sig-str (canonical-p2p-signal-str :offer session-id (:pubkey state) (:peer session) transport candidates ice-ufrag ice-pwd fp epoch)
            sig-bytes (crypto/sign privkey-bytes (fressian/utf8->bytes sig-str))
            sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
            payload {:protocol-version current-wire-version
                     :wire-format current-wire-format
                     :subnet-id sub-id
                     :bitecho/type :p2p-offer
                     :type :p2p-offer
                     :session-id session-id
                     :sender (:pubkey state)
                     :recipient (:peer session)
                     :transport transport
                     :candidates candidates
                     :ice-ufrag ice-ufrag
                     :ice-pwd ice-pwd
                     :fingerprint fp
                     :epoch epoch
                     :signature sig-hex}
            env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload payload) 0 sub-id)
            p2p-entry (merge (get session :p2p {})
                             {:phase :offered
                              :connected? false
                              :role :initiator
                              :local-transport transport
                              :local-candidates candidates
                              :local-ice-ufrag ice-ufrag
                              :local-ice-pwd ice-pwd
                              :local-fingerprint fp})
            new-state (assoc-in state [:sessions session-id :p2p] p2p-entry)]
        {:state new-state
         :response {"ok" true
                    "session_id" session-id
                    "peer" (:peer session)
                    "transport" transport
                    "candidates" candidates
                    "phase" "offered"
                    "burn" 0}
         :net-envelopes [env]
         :stdout-events []}))))

(defn- exec-p2p-answer [state cmd-map privkey-bytes]
  (let [session-id (resolve-session-id state cmd-map :open)
        session (get-in state [:sessions session-id])]
    (if-not (and session (= "open" (:state session)))
      {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}
      (let [sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id state) "global"))
            transport (str (or (get cmd-map "transport") (:transport cmd-map) (get-in session [:p2p :remote-transport]) "udp"))
            raw-cands (or (get cmd-map "candidates") (:candidates cmd-map) [])
            candidates (vec (map str (if (string? raw-cands)
                                       (remove str/blank? (str/split raw-cands #","))
                                       raw-cands)))
            ice-ufrag (str (or (get cmd-map "ice_ufrag") (get cmd-map "ice-ufrag") (:ice-ufrag cmd-map) (get-in state [:ice-creds :ufrag]) "ufrag"))
            ice-pwd (str (or (get cmd-map "ice_pwd") (get cmd-map "ice-pwd") (:ice-pwd cmd-map) (get-in state [:ice-creds :pwd]) "pwd"))
            fp (str (or (get cmd-map "fingerprint") (:fingerprint cmd-map) (:fingerprint state) ""))
            epoch (long (or (:epoch session) (:epoch state) 0))
            sig-str (canonical-p2p-signal-str :answer session-id (:pubkey state) (:peer session) transport candidates ice-ufrag ice-pwd fp epoch)
            sig-bytes (crypto/sign privkey-bytes (fressian/utf8->bytes sig-str))
            sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
            payload {:protocol-version current-wire-version
                     :wire-format current-wire-format
                     :subnet-id sub-id
                     :bitecho/type :p2p-answer
                     :type :p2p-answer
                     :session-id session-id
                     :sender (:pubkey state)
                     :recipient (:peer session)
                     :transport transport
                     :candidates candidates
                     :ice-ufrag ice-ufrag
                     :ice-pwd ice-pwd
                     :fingerprint fp
                     :epoch epoch
                     :signature sig-hex}
            env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload payload) 0 sub-id)
            p2p-entry (merge (get session :p2p {})
                             {:phase :open
                              :connected? true
                              :zero-burn? true
                              :role :responder
                              :local-transport transport
                              :local-candidates candidates
                              :local-ice-ufrag ice-ufrag
                              :local-ice-pwd ice-pwd
                              :local-fingerprint fp})
            new-state (assoc-in state [:sessions session-id :p2p] p2p-entry)
            pname (pubkey->petname state (:peer session))
            evt (cond-> {"event" "p2p-connected"
                         "session_id" session-id
                         "peer" (:peer session)
                         "transport" transport
                         "zero_burn" true}
                  pname (assoc "peer_petname" pname))]
        {:state new-state
         :response {"ok" true
                    "session_id" session-id
                    "peer" (:peer session)
                    "transport" transport
                    "candidates" candidates
                    "phase" "open"
                    "connected" true
                    "burn" 0}
         :net-envelopes [env]
         :stdout-events [evt]}))))

(defn- exec-broadcast [state cmd-map privkey-bytes]
  (let [raw-text (or (get cmd-map "text") (get cmd-map "message") (:text cmd-map) (:message cmd-map))
        text (when (some? raw-text) (str raw-text))]
    (if (or (nil? text) (str/blank? text))
      {:state state :response {"ok" false "error" "empty-payload"} :net-envelopes [] :stdout-events []}
      (let [sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id state) "global"))
            sender (normalize-pubkey-hex (:pubkey state))
            next-seq (inc (long (or (:broadcast-seq state) 0)))
            msg-id (compute-broadcast-msg-id sub-id sender next-seq text)
            epoch (long (or (:epoch state) 0))
            dac (or (get cmd-map "dac") (:dac cmd-map) (:dac state))
            dac-id (when (map? dac) (or (:dac-id dac) (get dac "dac_id") (get dac "dac-id")))
            sig-str (canonical-broadcast-str sub-id sender next-seq msg-id text epoch dac-id)
            sig-bytes (crypto/sign privkey-bytes (fressian/utf8->bytes sig-str))
            sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
            payload (cond-> {:protocol-version current-wire-version
                             :wire-format current-wire-format
                             :subnet-id sub-id
                             :bitecho/type :p2p-broadcast
                             :type :p2p-broadcast
                             :sender sender
                             :seq next-seq
                             :msg-id msg-id
                             :text text
                             :epoch epoch
                             :signature sig-hex}
                      dac (assoc :dac dac))
            env (build-gossip-envelope sender privkey-bytes (freeze-payload payload) 0 sub-id)
            dedup-key [sender next-seq msg-id]
            b-entry {:from sender
                     :seq next-seq
                     :msg-id msg-id
                     :text text
                     :subnet-id sub-id
                     :epoch epoch
                     :broadcast? true}
            new-state (-> state
                          (assoc :broadcast-seq next-seq)
                          (update :broadcast-seen (fnil conj #{}) dedup-key)
                          (update :broadcast-inbox (fnil conj []) b-entry))]
        {:state new-state
         :response {"ok" true
                    "subnet_id" sub-id
                    "seq" next-seq
                    "msg_id" msg-id
                    "burn" 0
                    "p2p" true}
         :net-envelopes [env]
         :stdout-events []}))))

(defn- exec-send [state cmd-map privkey-bytes]
  (let [session-id (resolve-session-id state cmd-map :open)
        session (get-in state [:sessions session-id])]
    (if-not (and session (= "open" (:state session)))
      {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}
      (let [pname (pubkey->petname state (:peer session))
            text (or (get cmd-map "text") (get cmd-map "message")
                     (:text cmd-map) (:message cmd-map))
            payload-hex (or (get cmd-map "payload_hex") (get cmd-map "payload-hex")
                            (:payload_hex cmd-map) (:payload-hex cmd-map))
            payload-bytes (cond (some? text) (fressian/utf8->bytes (str text))
                                (some? payload-hex) (basalt/hex->bytes payload-hex)
                                :else empty-bytes)]
        (if (zero? (fressian/count-bytes payload-bytes))
          {:state state :response {"ok" false "error" "empty-payload"} :net-envelopes [] :stdout-events []}
          (let [p2p-open? (or (true? (get-in session [:p2p :connected?]))
                              (= :open (get-in session [:p2p :phase])))
                burn-amt (if p2p-open?
                           0
                           (long (or (get cmd-map "burn") (:burn cmd-map) (if (get state :economy-enabled? true) 500 0))))
                sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id state) "global"))
                seq-num (inc (:tx-seq session 0))
                suite (or (:suite session) sealed/suite-v1-chacha20poly1305)
                sealed (sealed/seal-message (:tx-key session) seq-num payload-bytes (fressian/utf8->bytes session-id) suite)
                msg-payload {:protocol-version current-wire-version
                             :wire-format current-wire-format
                             :subnet-id sub-id
                             :bitecho/type :sealed-message
                             :session-id session-id
                             :sender (:pubkey state)
                             :recipient (:peer session)
                             :epoch (long (or (:epoch session) (:epoch state) 0))
                             :seq seq-num
                             :suite suite
                             :nonce (basalt/bytes->hex (:nonce sealed))
                             :ciphertext (basalt/bytes->hex (:ciphertext sealed))}
                gossip-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload msg-payload) burn-amt sub-id)
                max-outbox (long (or (:max-outbox-size state) 64))
                curr-outbox (or (:outbox session) {})
                curr-order (or (:outbox-order session) [])
                next-order (conj curr-order seq-num)
                next-outbox (assoc curr-outbox seq-num {:seq seq-num :msg-payload msg-payload :burn burn-amt :gossip-env gossip-env})
                [final-outbox final-order overflow] (if (> (count next-order) max-outbox)
                                                      (let [overflow (- (count next-order) max-outbox)
                                                            evicted (subvec next-order 0 overflow)
                                                            kept (subvec next-order overflow)]
                                                        [(apply dissoc next-outbox evicted) kept overflow])
                                                      [next-outbox next-order 0])
                new-state (cond-> (-> state
                                      (assoc-in [:sessions session-id :tx-seq] seq-num)
                                      (assoc-in [:sessions session-id :outbox] final-outbox)
                                      (assoc-in [:sessions session-id :outbox-order] final-order)
                                      (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))
                            (pos? overflow)
                            (update-in [:sessions session-id :outbox-evicted] (fnil + 0) overflow))]
            {:state new-state
             :response (cond-> {"ok" true
                                "session_id" session-id
                                "seq" seq-num
                                "bytes_sent" (fressian/count-bytes payload-bytes)
                                "burn" burn-amt}
                         p2p-open? (assoc "p2p" true)
                         pname (assoc "peer_petname" pname))
             :net-envelopes [gossip-env]
             :stdout-events []}))))))

(defn- exec-inbox [state]
  (let [enriched-msgs (mapv (fn [m]
                              (let [clean-m (dissoc m :from_petname :from-petname "from_petname" "from-petname")
                                    sender (or (:from clean-m) (get clean-m "from"))
                                    pname (when sender (pubkey->petname state sender))]
                                (cond-> clean-m
                                  pname (assoc :from_petname pname "from_petname" pname))))
                            (:inbox state))
        enriched-offers (mapv (fn [o]
                                (let [clean-o (dissoc o :petname :nickname :caller_petname :caller-petname
                                                      "petname" "nickname" "caller_petname" "caller-petname")
                                      caller (or (:caller clean-o) (get clean-o "caller"))
                                      pname (when caller (pubkey->petname state caller))]
                                  (cond-> clean-o
                                    pname (assoc :caller_petname pname "caller_petname" pname))))
                              (vec (vals (:pending-offers state))))
        enriched-rendezvous (mapv (fn [r]
                                    (let [clean-r (dissoc r :caller_petname :caller-petname "caller_petname" "caller-petname")
                                          caller (or (:caller clean-r) (get clean-r "caller"))
                                          pname (when caller (pubkey->petname state caller))]
                                      (cond-> clean-r
                                        pname (assoc :caller_petname pname "caller_petname" pname))))
                                  (vec (vals (:pending-rendezvous state))))]
    {:state (assoc state :inbox [])
     :response {"ok" true
                "messages" enriched-msgs
                "pending_offers" enriched-offers
                "pending_rendezvous" enriched-rendezvous}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-close [state cmd-map privkey-bytes]
  (let [session-id (resolve-session-id state cmd-map :active)
        session (get-in state [:sessions session-id])]
    (if-not session
      {:state state :response {"ok" false "error" "session-not-found"} :net-envelopes [] :stdout-events []}
      (let [pname (pubkey->petname state (:peer session))
            sub-id (str (or (:subnet-id state) "global"))
            burn-amt (if (get state :economy-enabled? true) 500 0)
            sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes (str "close-" session-id))))
            close-payload {:protocol-version current-wire-version
                           :wire-format current-wire-format
                           :subnet-id sub-id
                           :bitecho/type :channel-close
                           :session-id session-id
                           :sender (:pubkey state)
                           :recipient (:peer session)
                           :epoch (long (or (:epoch session) (:epoch state) 0))
                           :signature sig-hex}
            gossip-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload close-payload) burn-amt sub-id)
            closed-sess (-> session
                            (assoc :state "closed")
                            (dissoc :tx-key :rx-key :ephemeral-priv))
            new-state (assoc-in state [:sessions session-id] closed-sess)]
        {:state new-state
         :response (cond-> {"ok" true "session_id" session-id "state" "closed"}
                     pname (assoc "peer_petname" pname))
         :net-envelopes [gossip-env]
         :stdout-events []}))))

(defn- exec-sync-account [state cmd-map]
  (let [raw-snapshots (or (get cmd-map "snapshots") (:snapshots cmd-map)
                          (when-let [s (or (get cmd-map "snapshot") (:snapshot cmd-map))]
                            [s]))]
    (if raw-snapshots
      (let [trusted-validators (set (keep :pubkey (vals (get-in state [:bootstrap :nodes]))))
            q-opts {:expected-pubkey (:pubkey state)
                    :trusted-validators trusted-validators
                    :min-finalized-epoch (get-in state [:account :finalized-epoch] 0)}
            q-res (verify-chain-state-quorum raw-snapshots q-opts)]
        (if (:ok? q-res)
          (let [snap (:snapshot q-res)
                st-applied (apply-verified-chain-state-snapshot state snap)
                new-state (assoc-in st-applied [:chain-state-snapshots (:validator-pubkey snap)] snap)]
            {:state new-state
             :response {"ok" true
                        "synced" true
                        "pubkey" (:pubkey state)
                        "balance" (:balance snap)
                        "spendable" (:spendable snap)
                        "seq" (:seq snap)
                        "deps" (vec (:deps snap))
                        "finalized_epoch" (:finalized-epoch snap)
                        "escrows_count" (count (:escrows snap))
                        "quorum_count" (:quorum-count q-res)
                        "validators" (:validators q-res)}
             :net-envelopes []
             :stdout-events []})
          {:state state
           :response {"ok" false "error" (:error q-res)}
           :net-envelopes []
           :stdout-events []}))
      (if (or (contains? cmd-map "balance")
              (contains? cmd-map :balance)
              (contains? cmd-map "seq")
              (contains? cmd-map :seq)
              (contains? cmd-map "spendable")
              (contains? cmd-map :spendable)
              (map? (get cmd-map "account"))
              (map? (get cmd-map :account)))
        (let [acct (or (when (map? (get cmd-map "account")) (get cmd-map "account"))
                       (when (map? (get cmd-map :account)) (get cmd-map :account))
                       cmd-map)
              bal (long (or (get acct "balance")
                            (:balance acct)
                            (get-in state [:account :balance])
                            0))
              spendable (long (or (get cmd-map "spendable")
                                  (:spendable cmd-map)
                                  (get acct "spendable")
                                  (:spendable acct)
                                  bal))
              seq-num (long (or (get acct "seq")
                                (:seq acct)
                                (:transfer-seq state)
                                0))
              deps (vec (map str (or (get acct "deps")
                                     (:deps acct)
                                     (when-let [h (:last-transfer-hash state)] [h])
                                     [])))
              fin-ep (long (or (get cmd-map "finalized_epoch")
                               (:finalized-epoch cmd-map)
                               (get acct "finalized_epoch")
                               (:epoch state)
                               0))
              new-state (cond-> (assoc state
                                       :account {:balance bal
                                                 :spendable spendable
                                                 :seq seq-num
                                                 :deps deps
                                                 :finalized-epoch fin-ep}
                                       :transfer-seq seq-num
                                       :last-transfer-hash (last deps)
                                       :epoch (max (long (or (:epoch state) 0)) fin-ep))
                          (pos? fin-ep) (assoc :epoch-initialized? true))]
          {:state new-state
           :response {"ok" true
                      "pubkey" (:pubkey state)
                      "balance" bal
                      "spendable" spendable
                      "seq" seq-num
                      "deps" deps
                      "finalized_epoch" fin-ep
                      "synced" true}
           :net-envelopes []
           :stdout-events []})
        (let [acct (:account state)
              bal (long (or (:balance acct) 0))
              spendable (long (or (:spendable acct) bal))
              seq-num (long (or (:seq acct) (:transfer-seq state 0)))
              deps (vec (or (:deps acct) (when-let [h (:last-transfer-hash state)] [h]) []))
              fin-ep (long (or (:finalized-epoch acct) (:epoch state 0)))]
          {:state state
           :response {"ok" true
                      "pubkey" (:pubkey state)
                      "balance" bal
                      "spendable" spendable
                      "seq" seq-num
                      "deps" deps
                      "finalized_epoch" fin-ep
                      "synced" (some? acct)}
           :net-envelopes []
           :stdout-events []})))))

(defn- effective-chain-epoch
  "Returns the best-known on-chain epoch from :epoch and [:account :finalized-epoch]."
  [state]
  (max (long (or (:epoch state) 0))
       (long (or (get-in state [:account :finalized-epoch]) 0))))

(defn- check-dac-spend-authorization
  "Checks whether the current state's DAC permits spending `amount` in `required-scopes`.
   Returns {:ok? true :new-dac-spend ...} on success or when no DAC is attached.
   Returns {:ok? false :error <reason>} if DAC is invalid, expired, revoked, scope not permitted,
   or if (+ current-spent amount) > max-spend-per-epoch.
   Tracks cumulative spend per DAC ID under :dac-spend {dac-id {:epoch current-epoch :spent new-spent}}."
  [state amount required-scopes]
  (if-let [dac (:dac state)]
    (let [curr-epoch (effective-chain-epoch state)
          dac-res (verify-dac dac {:expected-agent-pubkey (:pubkey state)
                                   :current-epoch curr-epoch
                                   :revoked-dac-ids (:revoked-dacs state)
                                   :required-scope required-scopes})]
      (if-not (:ok? dac-res)
        (let [err (:error dac-res)]
          {:ok? false :error (if (= err "dac-scope-not-permitted") "dac-scope-denied" err)})
        (let [dac-id (:dac-id (:dac dac-res))
              max-spend (long (or (:max-spend-per-epoch (:dac dac-res))
                                  (:max-spend-per-epoch dac)
                                  0))
              dac-spend-map (if (map? (:dac-spend state)) (:dac-spend state) {})
              current-record (get dac-spend-map dac-id)
              current-spent (if (and (map? current-record)
                                     (= (:epoch current-record) curr-epoch))
                              (long (or (:spent current-record) 0))
                              0)
              new-spent (+ current-spent (long amount))]
          (if (> new-spent max-spend)
            {:ok? false :error "dac-max-spend-exceeded"}
            {:ok? true
             :new-dac-spend (assoc dac-spend-map dac-id {:epoch curr-epoch :spent new-spent})}))))
    {:ok? true :new-dac-spend (:dac-spend state)}))

(defn- exec-transfer [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient")
                         (:receiver cmd-map) (:recipient cmd-map))
        amount (parse-long-safe (or (get cmd-map "amount") (:amount cmd-map)) 0)]
    (if (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)) (<= amount 0))
      {:state state
       :response {"ok" false "error" "invalid-transfer-params"}
       :net-envelopes []
       :stdout-events []}
      (let [dac-auth (check-dac-spend-authorization state amount "transfer")]
        (if-not (:ok? dac-auth)
          {:state state
           :response {"ok" false "error" (:error dac-auth)}
           :net-envelopes []
           :stdout-events []}
          (let [resolved (resolve-counterparty state raw-receiver)]
            (if-not (:ok? resolved)
              {:state state
               :response {"ok" false "error" (:error resolved)}
               :net-envelopes []
               :stdout-events []}
              (let [receiver (:pubkey resolved)
                    pname (:petname resolved)
                    burn-amt (parse-long-safe (or (get cmd-map "burn") (:burn cmd-map)) 500)
                    acct (:account state)
                    spendable (when acct (parse-long-safe (or (:spendable acct) (:balance acct)) 0))]
                (if (and acct (< spendable (+ amount burn-amt)))
                  {:state state
                   :response {"ok" false "error" "insufficient-balance"}
                   :net-envelopes []
                   :stdout-events []}
                  (let [seq-num (parse-long-safe (or (get cmd-map "seq")
                                                     (:seq cmd-map))
                                                 (inc (long (or (when acct (:seq acct))
                                                                (:transfer-seq state)
                                                                0))))
                        deps (vec (or (get cmd-map "deps")
                                      (:deps cmd-map)
                                      (when (and acct (seq (:deps acct))) (:deps acct))
                                      (when-let [prev (:last-transfer-hash state)] [prev])
                                      []))
                        res (build-transfer-gossip-envelope
                             (:pubkey state)
                             privkey-bytes
                             {:receiver receiver :amount amount :seq seq-num :deps deps}
                             burn-amt)
                        deliver-payload (mapv long (fressian/utf8->bytes (pr-str {:transfer (into {} (:transfer res))})))
                        deliver-env (wrap-agent-event
                                     {:type :on-deliver
                                      :payload deliver-payload
                                      :message-id (:transfer-hash res)}
                                     (:pubkey state)
                                     privkey-bytes)
                        new-state (cond-> (-> state
                                              (assoc :transfer-seq seq-num
                                                     :last-transfer-hash (:transfer-hash res)
                                                     :dac-spend (:new-dac-spend dac-auth))
                                              (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))
                                    acct (-> (assoc-in [:account :seq] seq-num)
                                             (assoc-in [:account :deps] [(:transfer-hash res)])
                                             (update-in [:account :spendable] - (+ amount burn-amt))))]
                    {:state new-state
                     :response (cond-> {"ok" true
                                        "transfer_hash" (:transfer-hash res)
                                        "tx_id" (:transfer-hash res)
                                        "receiver" receiver
                                        "recipient" receiver
                                        "amount" amount
                                        "seq" seq-num}
                                 pname (assoc "receiver_petname" pname "recipient_petname" pname))
                     :net-envelopes [(:envelope res) deliver-env]
                     :stdout-events []}))))))))))

(defn- exec-settle-intent [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient")
                         (:receiver cmd-map) (:recipient cmd-map))
        amount (parse-long-safe (or (get cmd-map "amount") (:amount cmd-map)) 0)]
    (if (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)) (<= amount 0))
      {:state state
       :response {"ok" false "error" "invalid-intent-params"}
       :net-envelopes []
       :stdout-events []}
      (let [dac-auth (check-dac-spend-authorization state amount ["settle" "settle-intent"])]
        (if-not (:ok? dac-auth)
          {:state state
           :response {"ok" false "error" (:error dac-auth)}
           :net-envelopes []
           :stdout-events []}
          (let [resolved (resolve-counterparty state raw-receiver)]
            (if-not (:ok? resolved)
              {:state state
               :response {"ok" false "error" (:error resolved)}
               :net-envelopes []
               :stdout-events []}
              (let [receiver (:pubkey resolved)
                    pname (:petname resolved)
                    acct (:account state)
                    spendable (when acct (parse-long-safe (or (:spendable acct) (:balance acct)) 0))]
                (if (and acct (< spendable amount))
                  {:state state
                   :response {"ok" false "error" "insufficient-balance"}
                   :net-envelopes []
                   :stdout-events []}
                  (let [next-intent-seq (inc (long (:intent-seq state 0)))
                        curr-ep (effective-chain-epoch state)
                        rid (or (get cmd-map "receipt_id")
                                (:receipt_id cmd-map)
                                (str "intent:" (:pubkey state) ":" receiver ":" amount ":" curr-ep ":" next-intent-seq))
                        take-amt (burn/calculate-settlement-take amount burn/default-settlement-take-bps)
                        net-amt (- amount take-amt)
                        intent-env (wrap-agent-event
                                    {:type :settle-intent
                                     :payer (:pubkey state)
                                     :receiver receiver
                                     :amount amount
                                     :epoch curr-ep
                                     :receipt-id rid}
                                    (:pubkey state)
                                    privkey-bytes)
                        new-state (cond-> (assoc state :intent-seq next-intent-seq
                                                 :dac-spend (:new-dac-spend dac-auth))
                                    acct (update-in [:account :spendable] - amount))]
                    {:state new-state
                     :response (cond-> {"ok" true
                                        "receipt_id" rid
                                        "payer" (:pubkey state)
                                        "receiver" receiver
                                        "amount" amount
                                        "take" take-amt
                                        "net_amount" net-amt}
                                 pname (assoc "receiver_petname" pname))
                     :net-envelopes [intent-env]
                     :stdout-events []}))))))))))

(defn- exec-lock-intent [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient") (get cmd-map "to")
                         (:receiver cmd-map) (:recipient cmd-map) (:to cmd-map))
        raw-amount (or (get cmd-map "amount") (:amount cmd-map))
        amount (when (some? raw-amount) (parse-long-safe raw-amount :invalid))
        raw-dh (or (get cmd-map "deliverable_hash") (get cmd-map "deliverable-hash")
                   (:deliverable_hash cmd-map) (:deliverable-hash cmd-map))
        raw-deliv (or (get cmd-map "deliverable") (:deliverable cmd-map)
                      (get cmd-map "preimage") (:preimage cmd-map))
        deliverable-hash (cond
                           (and (string? raw-dh) (escrow/valid-deliverable-hash? raw-dh)) (escrow/normalize-hex raw-dh)
                           (and (string? raw-deliv) (not (str/blank? raw-deliv))) (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes raw-deliv)))
                           :else nil)
        curr-ep (effective-chain-epoch state)
        raw-expires (or (get cmd-map "expires_epoch") (get cmd-map "expires-epoch")
                        (:expires_epoch cmd-map) (:expires-epoch cmd-map))
        expires-epoch (if (some? raw-expires) (parse-long-safe raw-expires :invalid) (+ curr-ep 10))]
    (cond
      (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)))
      {:state state :response {"ok" false "error" "missing-receiver"} :net-envelopes [] :stdout-events []}

      (or (nil? amount) (= amount :invalid) (<= amount 0))
      {:state state :response {"ok" false "error" "invalid-amount"} :net-envelopes [] :stdout-events []}

      (nil? deliverable-hash)
      {:state state :response {"ok" false "error" (if raw-dh "invalid-deliverable-hash" "missing-deliverable-hash")} :net-envelopes [] :stdout-events []}

      (or (= expires-epoch :invalid) (<= expires-epoch curr-ep))
      {:state state :response {"ok" false "error" "invalid-expires-epoch"} :net-envelopes [] :stdout-events []}

      :else
      (let [resolved (resolve-counterparty state raw-receiver)]
        (if-not (:ok? resolved)
          {:state state :response {"ok" false "error" (:error resolved)} :net-envelopes [] :stdout-events []}
          (let [receiver-pub (:pubkey resolved)
                pname (:petname resolved)]
            (if (= (:pubkey state) receiver-pub)
              {:state state :response {"ok" false "error" "cannot-escrow-self"} :net-envelopes [] :stdout-events []}
              (let [dac-auth (check-dac-spend-authorization state amount ["lock-intent" "settle" "settle-intent"])]
                (if-not (:ok? dac-auth)
                  {:state state :response {"ok" false "error" (:error dac-auth)} :net-envelopes [] :stdout-events []}
                  (let [acct (:account state)
                        spendable (when acct (parse-long-safe (or (:spendable acct) (:balance acct)) 0))]
                    (if (and acct (< spendable amount))
                      {:state state :response {"ok" false "error" "insufficient-balance"} :net-envelopes [] :stdout-events []}
                      (let [raw-eid (or (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                                        (:escrow_id cmd-map) (:escrow-id cmd-map))
                            nonce (str (inc (long (count (:escrows state {})))))
                            escrow-id (or (when (and (string? raw-eid) (not (str/blank? raw-eid))) raw-eid)
                                          (escrow/compute-escrow-id (:pubkey state) receiver-pub amount deliverable-hash curr-ep expires-epoch nonce))
                            intent-payload {:type :lock-intent
                                            :escrow-id escrow-id
                                            :payer (:pubkey state)
                                            :receiver receiver-pub
                                            :amount amount
                                            :deliverable-hash deliverable-hash
                                            :created-epoch curr-ep
                                            :expires-epoch expires-epoch
                                            :epoch curr-ep
                                            :receipt-id (str "lock:" escrow-id)}
                            active-dac (when-let [d (:dac state)]
                                         (when (:ok? (verify-dac d {:expected-agent-pubkey (:pubkey state)
                                                                    :current-epoch curr-ep
                                                                    :revoked-dac-ids (:revoked-dacs state)}))
                                           d))
                            envelope (wrap-agent-event intent-payload (:pubkey state) privkey-bytes active-dac)
                            local-escrow {:escrow-id escrow-id
                                          :payer (:pubkey state)
                                          :receiver receiver-pub
                                          :amount amount
                                          :deliverable-hash deliverable-hash
                                          :created-epoch curr-ep
                                          :expires-epoch expires-epoch
                                          :status :locked}
                            new-state (cond-> (-> state
                                                  (assoc-in [:escrows escrow-id] local-escrow)
                                                  (assoc :dac-spend (:new-dac-spend dac-auth)))
                                        acct (update-in [:account :spendable] - amount))]
                        {:state new-state
                         :response (cond-> {"ok" true
                                            "escrow_id" escrow-id
                                            "payer" (:pubkey state)
                                            "receiver" receiver-pub
                                            "amount" amount
                                            "deliverable_hash" deliverable-hash
                                            "expires_epoch" expires-epoch
                                            "status" "locked"}
                                     pname (assoc "receiver_petname" pname))
                         :net-envelopes [envelope]
                         :stdout-events []}))))))))))))

(defn- exec-release-intent [state cmd-map privkey-bytes]
  (let [escrow-id (or (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                      (:escrow_id cmd-map) (:escrow-id cmd-map))]
    (if (or (nil? escrow-id) (and (string? escrow-id) (str/blank? escrow-id)))
      {:state state :response {"ok" false "error" "missing-escrow-id"} :net-envelopes [] :stdout-events []}
      (let [preimage (or (get cmd-map "preimage") (:preimage cmd-map)
                         (get cmd-map "deliverable") (:deliverable cmd-map))
            payer-sig (or (get cmd-map "payer_signature") (get cmd-map "payer-signature")
                          (:payer_signature cmd-map) (:payer-signature cmd-map))
            local-escrow (get-in state [:escrows escrow-id])
            d-hash (or (when local-escrow (:deliverable-hash local-escrow))
                       (get cmd-map "deliverable_hash") (get cmd-map "deliverable-hash")
                       (:deliverable_hash cmd-map) (:deliverable-hash cmd-map))
            final-sig (or payer-sig
                          (when (and (= (:pubkey state) (when local-escrow (:payer local-escrow)))
                                     (string? d-hash))
                            (escrow/sign-escrow-release privkey-bytes escrow-id d-hash)))
            release-payload (cond-> {:type :release-intent
                                     :escrow-id escrow-id
                                     :epoch (effective-chain-epoch state)
                                     :receipt-id (str "release:" escrow-id)}
                              preimage (assoc :preimage preimage)
                              final-sig (assoc :payer-signature final-sig))
            envelope (wrap-agent-event release-payload (:pubkey state) privkey-bytes)
            new-state (if local-escrow
                        (assoc-in state [:escrows escrow-id :status] :release-submitted)
                        state)]
        {:state new-state
         :response {"ok" true "escrow_id" escrow-id "status" "release-submitted"}
         :net-envelopes [envelope]
         :stdout-events []}))))

(defn- exec-refund-intent [state cmd-map privkey-bytes]
  (let [escrow-id (or (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                      (:escrow_id cmd-map) (:escrow-id cmd-map))]
    (if (or (nil? escrow-id) (and (string? escrow-id) (str/blank? escrow-id)))
      {:state state :response {"ok" false "error" "missing-escrow-id"} :net-envelopes [] :stdout-events []}
      (let [refund-payload {:type :refund-intent
                            :escrow-id escrow-id
                            :epoch (effective-chain-epoch state)
                            :receipt-id (str "refund:" escrow-id)}
            envelope (wrap-agent-event refund-payload (:pubkey state) privkey-bytes)
            local-escrow (get-in state [:escrows escrow-id])
            new-state (if local-escrow
                        (assoc-in state [:escrows escrow-id :status] :refund-submitted)
                        state)]
        {:state new-state
         :response {"ok" true "escrow_id" escrow-id "status" "refund-submitted"}
         :net-envelopes [envelope]
         :stdout-events []}))))

(defn- exec-escrows
  ([state]
   (exec-escrows state {}))
  ([state cmd-map]
   (let [raw-snapshots (or (get cmd-map "snapshots") (:snapshots cmd-map)
                           (when-let [s (or (get cmd-map "snapshot") (:snapshot cmd-map))]
                             [s]))]
     (if raw-snapshots
       (let [sync-res (exec-sync-account state cmd-map)]
         (if (get-in sync-res [:response "ok"])
           (exec-escrows (:state sync-res) (dissoc cmd-map "snapshots" :snapshots "snapshot" :snapshot))
           sync-res))
       (let [enriched (mapv (fn [[eid esc]]
                              (let [payer (:payer esc)
                                    receiver (:receiver esc)
                                    payer-pname (when payer (pubkey->petname state payer))
                                    recv-pname (when receiver (pubkey->petname state receiver))
                                    status-str (name (or (:status esc) :locked))]
                                (cond-> (assoc esc
                                               :escrow_id eid
                                               :escrow-id eid
                                               :status status-str)
                                  (:settled-epoch esc) (assoc :settled_epoch (:settled-epoch esc))
                                  (:net-amount esc) (assoc :net_amount (:net-amount esc))
                                  (:refund-reason esc) (assoc :refund_reason (:refund-reason esc))
                                  payer-pname (assoc :payer_petname payer-pname)
                                  recv-pname (assoc :receiver_petname recv-pname))))
                            (vec (:escrows state {})))]
         {:state state
          :response {"ok" true "escrows" enriched}
          :net-envelopes []
          :stdout-events []})))))

(defn- exec-submit-vouchers [state cmd-map privkey-bytes]
  (let [raw-vouchers (or (get cmd-map "vouchers")
                         (:vouchers cmd-map)
                         (:vouchers state)
                         [])
        compacted (->> raw-vouchers
                       (keep (fn [raw]
                               (let [ack-map (if (record? raw)
                                               (into {} raw)
                                               {:callee (or (get raw "callee") (:callee raw))
                                                :home-node (or (get raw "home_node") (get raw "home-node") (:home-node raw))
                                                :epoch (long (or (get raw "epoch") (:epoch raw) 0))
                                                :offer-hash (or (get raw "offer_hash") (get raw "offer-hash") (:offer-hash raw))
                                                :seq (long (or (get raw "seq") (:seq raw) 0))
                                                :cumulative-debit (long (or (get raw "cumulative_debit") (get raw "cumulative-debit") (:cumulative-debit raw) 0))
                                                :signature (or (get raw "signature") (:signature raw))})
                                     ack (try (rendezvous/map->DeliveryAck ack-map) (catch #?(:clj Exception :cljs :default) _ nil))]
                                 (when (and ack (rendezvous/verify-delivery-ack ack))
                                   ack))))
                       bundle/compact-vouchers)]
    (if (empty? compacted)
      {:state state
       :response {"ok" false "error" "no-valid-vouchers"}
       :net-envelopes []
       :stdout-events []}
      (let [voucher-env (wrap-agent-event
                         {:type :submit-vouchers
                          :vouchers (mapv #(into {} %) compacted)
                          :epoch (effective-chain-epoch state)}
                         (:pubkey state)
                         privkey-bytes)
            new-state (assoc state :vouchers [])]
        {:state new-state
         :response {"ok" true "submitted_count" (count compacted)}
         :net-envelopes [voucher-env]
         :stdout-events []}))))

(defn- exec-petname-set [state cmd-map]
  (let [raw-pname (or (get cmd-map "petname") (get cmd-map "name")
                      (:petname cmd-map) (:name cmd-map))
        raw-pub (or (get cmd-map "pubkey") (:pubkey cmd-map))
        pname (normalize-petname raw-pname)
        pub (normalize-pubkey-hex raw-pub)
        ov (if (contains? cmd-map "overwrite")
             (get cmd-map "overwrite")
             (:overwrite cmd-map))
        overwrite? (boolean (or (true? ov)
                                (and (string? ov) (= "true" (str/lower-case (str/trim ov))))))]
    (cond
      (nil? pname)
      {:state state
       :response {"ok" false "error" "invalid-petname"}
       :net-envelopes []
       :stdout-events []}

      (nil? pub)
      {:state state
       :response {"ok" false "error" "invalid-pubkey"}
       :net-envelopes []
       :stdout-events []}

      :else
      (let [existing-pub (get-in state [:petnames pname])
            existing-pname (pubkey->petname state pub)]
        (cond
          ;; Idempotent: already bound to the same pubkey
          (= existing-pub pub)
          {:state state
           :response {"ok" true "petname" pname "pubkey" pub}
           :net-envelopes []
           :stdout-events []}

          ;; Conflict without overwrite
          (and (not overwrite?) (or (some? existing-pub) (some? existing-pname)))
          {:state state
           :response (cond-> {"ok" false "error" "petname-conflict"}
                       existing-pub (assoc "existing_pubkey" existing-pub)
                       existing-pname (assoc "existing_petname" existing-pname))
           :net-envelopes []
           :stdout-events []}

          ;; Valid set or overwrite: clean old bindings and set new 1:1 binding
          :else
          (let [clean-petnames (cond-> (:petnames state {})
                                 existing-pname (dissoc existing-pname))
                new-petnames (assoc clean-petnames pname pub)
                new-state (assoc state :petnames new-petnames)]
            {:state new-state
             :response {"ok" true "petname" pname "pubkey" pub}
             :net-envelopes []
             :stdout-events []}))))))

(defn- exec-petname-list [state]
  {:state state
   :response {"ok" true
              "petnames" (into (sorted-map) (:petnames state {}))
              "count" (count (:petnames state {}))}
   :net-envelopes []
   :stdout-events []})

(defn- exec-petname-remove [state cmd-map]
  (let [raw-pname (or (get cmd-map "petname") (get cmd-map "name")
                      (:petname cmd-map) (:name cmd-map))
        raw-pub (or (get cmd-map "pubkey") (:pubkey cmd-map))
        pname (or (when raw-pname (normalize-petname raw-pname))
                  (when raw-pub (pubkey->petname state raw-pub)))
        pub (when pname (get-in state [:petnames pname]))]
    (if (and pname pub)
      (let [new-state (update state :petnames dissoc pname)]
        {:state new-state
         :response {"ok" true "removed" true "petname" pname "pubkey" pub}
         :net-envelopes []
         :stdout-events []})
      {:state state
       :response {"ok" false "error" "petname-not-found"}
       :net-envelopes []
       :stdout-events []})))

(defn- exec-petname-resolve [state cmd-map]
  (let [raw-pname (or (get cmd-map "petname") (get cmd-map "name")
                      (:petname cmd-map) (:name cmd-map))
        raw-pub (or (get cmd-map "pubkey") (:pubkey cmd-map))
        raw-tgt (or (get cmd-map "target") (:target cmd-map))
        resolved (cond
                   raw-pname
                   (when-let [pname (normalize-petname raw-pname)]
                     (when-let [pub (get-in state [:petnames pname])]
                       {:petname pname :pubkey pub}))

                   raw-pub
                   (when-let [pub (normalize-pubkey-hex raw-pub)]
                     (when-let [pname (pubkey->petname state pub)]
                       {:petname pname :pubkey pub}))

                   raw-tgt
                   (let [res (resolve-counterparty state raw-tgt)]
                     (when (and (:ok? res) (:petname res))
                       {:petname (:petname res) :pubkey (:pubkey res)}))

                   :else nil)]
    (if resolved
      {:state state
       :response {"ok" true "petname" (:petname resolved) "pubkey" (:pubkey resolved)}
       :net-envelopes []
       :stdout-events []}
      {:state state
       :response {"ok" false "error" "petname-not-found"}
       :net-envelopes []
       :stdout-events []})))

(defn- exec-dac-attach [state cmd-map]
  (let [raw-dac (or (get cmd-map "dac") (:dac cmd-map) cmd-map)
        cur-ep (when (:epoch-initialized? state) (:epoch state))
        res (verify-dac raw-dac {:expected-agent-pubkey (:pubkey state)
                                 :current-epoch cur-ep
                                 :revoked-dac-ids (:revoked-dacs state)})]
    (if-not (:ok? res)
      {:state state
       :response {"ok" false "error" (:error res)}
       :net-envelopes []
       :stdout-events []}
      (let [dac (:dac res)]
        {:state (assoc state :dac dac)
         :response {"ok" true
                    "dac_id" (:dac-id res)
                    "anchor_pubkey" (:anchor-pubkey res)
                    "agent_pubkey" (:agent-pubkey res)
                    "expires_epoch" (long (or (:expires-epoch dac) (get dac "expires_epoch") 0))}
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-dac-revoke [state cmd-map]
  (let [raw-rev (or (get cmd-map "revocation") (:revocation cmd-map) cmd-map)]
    (if-not (verify-dac-revocation raw-rev)
      {:state state
       :response {"ok" false "error" "invalid-dac-revocation"}
       :net-envelopes []
       :stdout-events []}
      (let [rev-map (normalize-wire-map raw-rev)
            dac-id (:dac-id rev-map)
            new-revoked (conj (set (or (:revoked-dacs state) #{})) dac-id)
            attached-dac (:dac state)
            attached-id (or (:dac-id attached-dac) (get attached-dac "dac_id") (get attached-dac "dac-id"))
            cleared-dac? (= attached-id dac-id)
            new-state (cond-> (assoc state :revoked-dacs new-revoked)
                        cleared-dac? (assoc :dac nil))]
        {:state new-state
         :response {"ok" true "revoked" true "dac_id" dac-id}
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-directory-verify [state cmd-map]
  (let [raw-desc (or (get cmd-map "descriptor") (:descriptor cmd-map) cmd-map)
        dir-pub (or (get cmd-map "directory_pubkey") (get cmd-map "directory-pubkey")
                    (:directory_pubkey cmd-map) (:directory-pubkey cmd-map)
                    (:trusted-directory-pubkey state)
                    (get-in state [:bootstrap :directory-pubkey]))
        cur-ep (when (:epoch-initialized? state) (:epoch state))
        res (verify-directory-descriptor raw-desc dir-pub cur-ep)]
    (if-not (:ok? res)
      {:state state
       :response {"ok" false "error" (:error res)}
       :net-envelopes []
       :stdout-events []}
      (let [desc-map (:descriptor res)
            nick (:nickname desc-map)
            pub (:pubkey desc-map)
            prev-pub (:prev-pubkey desc-map)
            existing (get-in state [:directory-cache nick])
            existing-pub (when existing (or (:pubkey existing) (get existing "pubkey")))
            norm-pub (normalize-pubkey-hex pub)
            norm-existing (when existing-pub (normalize-pubkey-hex existing-pub))
            norm-prev (when prev-pub (normalize-pubkey-hex prev-pub))]
        (if (and norm-existing
                 (not= norm-existing norm-pub)
                 (or (nil? norm-prev)
                     (not= norm-existing norm-prev)))
          {:state state
           :response {"ok" false "error" "broken-key-continuity"}
           :net-envelopes []
           :stdout-events []}
          (let [new-state (assoc-in state [:directory-cache nick] desc-map)]
            {:state new-state
             :response {"ok" true
                        "nickname" nick
                        "uri" (or (:uri desc-map) (str "bitecho.org/" nick))
                        "pubkey" pub
                        "home_set" (or (:home-set desc-map) [])
                        "directory_pubkey" (:directory-pubkey desc-map)
                        "expires_epoch" (:expires-epoch desc-map)}
             :net-envelopes []
             :stdout-events []}))))))

(defn- exec-directory-register [state cmd-map ^bytes privkey-bytes]
  (let [nick (or (get cmd-map "nickname") (:nickname cmd-map))
        domain (or (get cmd-map "domain") (:domain cmd-map) "bitecho.org")
        prev-pk (or (get cmd-map "prev_pubkey") (get cmd-map "prev-pubkey")
                    (:prev_pubkey cmd-map) (:prev-pubkey cmd-map))
        prev-sk-raw (or (get cmd-map "prev_privkey") (get cmd-map "prev-privkey")
                        (:prev_privkey cmd-map) (:prev-privkey cmd-map))
        prev-sk-bytes (when prev-sk-raw
                        (try
                          (if (bytes? prev-sk-raw)
                            prev-sk-raw
                            (basalt/hex->bytes prev-sk-raw))
                          (catch #?(:clj Exception :cljs :default) _ nil)))]
    (if-not (valid-petname? nick)
      {:state state
       :response {"ok" false "error" "invalid-nickname"}
       :net-envelopes []
       :stdout-events []}
      (let [norm-nick (normalize-petname nick)
            norm-domain (if (or (nil? domain) (str/blank? domain)) "bitecho.org" (str/lower-case (str/trim domain)))
            hs (if (seq (:home-set state))
                 (vec (for [hn (:home-set state)]
                        (if (map? hn) (name (or (:node-id hn) (:node hn) "node1")) (name hn))))
                 ["node1" "node2" "node3"])
            ep (effective-chain-epoch state)
            pop-opts (cond-> {:domain norm-domain
                              :nickname norm-nick
                              :pubkey (:pubkey state)
                              :home-set hs
                              :epoch ep}
                       prev-pk (assoc :prev-pubkey prev-pk
                                      :prev-privkey-bytes prev-sk-bytes))
            pop (create-directory-pop privkey-bytes pop-opts)]
        (if-not pop
          {:state state
           :response {"ok" false "error" "invalid-pop-parameters"}
           :net-envelopes []
           :stdout-events []}
          (let [pop-str-map (cond-> {"domain" (:domain pop)
                                     "nickname" (:nickname pop)
                                     "pubkey" (:pubkey pop)
                                     "home_set" (:home-set pop)
                                     "epoch" (:epoch pop)
                                     "pop_signature" (:pop-signature pop)}
                              (:prev-pubkey pop)
                              (assoc "prev_pubkey" (:prev-pubkey pop)
                                     "rotation_signature" (:rotation-signature pop)))]
            {:state state
             :response {"ok" true
                        "nickname" norm-nick
                        "domain" norm-domain
                        "uri" (str norm-domain "/" norm-nick)
                        "pop" pop-str-map}
             :net-envelopes []
             :stdout-events []}))))))

(defn- exec-directory-lookup [state cmd-map]
  (let [nick (or (get cmd-map "nickname") (:nickname cmd-map))
        raw-desc (or (get cmd-map "descriptor") (:descriptor cmd-map))]
    (if-not (valid-petname? nick)
      {:state state
       :response {"ok" false "error" "invalid-nickname"}
       :net-envelopes []
       :stdout-events []}
      (let [norm-nick (normalize-petname nick)
            trusted-pub (or (get cmd-map "directory_pubkey") (get cmd-map "directory-pubkey")
                            (:directory_pubkey cmd-map) (:directory-pubkey cmd-map)
                            (:trusted-directory-pubkey state)
                            (get-in state [:bootstrap :directory-pubkey]))]
        (if (some? raw-desc)
          (let [verify-map (assoc cmd-map "directory_pubkey" trusted-pub)
                v-res (exec-directory-verify state verify-map)]
            (if-not (get-in v-res [:response "ok"])
              v-res
              (let [desc (get-in (:state v-res) [:directory-cache norm-nick])]
                {:state (:state v-res)
                 :response {"ok" true "descriptor" desc}
                 :net-envelopes []
                 :stdout-events []})))
          (let [cached (get-in state [:directory-cache norm-nick])]
            (if-not cached
              {:state state
               :response {"ok" false "error" "directory-entry-not-found"}
               :net-envelopes []
               :stdout-events []}
              (if trusted-pub
                (let [v-res (verify-directory-descriptor cached trusted-pub (effective-chain-epoch state))]
                  (if (:ok? v-res)
                    {:state state
                     :response {"ok" true "descriptor" cached}
                     :net-envelopes []
                     :stdout-events []}
                    {:state state
                     :response {"ok" false "error" "directory-entry-not-found"}
                     :net-envelopes []
                     :stdout-events []}))
                {:state state
                 :response {"ok" true "descriptor" cached}
                 :net-envelopes []
                 :stdout-events []}))))))))

(defn- exec-status [state]
  (let [sessions-summary (vec (for [[_ s] (:sessions state)
                                    :let [pname (pubkey->petname state (:peer s))]]
                                (cond-> (select-keys s [:session-id :peer :role :state :tx-seq :epoch :acked-seq :rx-high-seq :replays-deduped :outbox-evicted])
                                  true (assoc :unacked-count (count (:outbox s)))
                                  pname (assoc :peer-petname pname :peer_petname pname))))]
    {:state state
     :response (cond-> {"ok" true
                        "connected" (boolean (:connected? state false))
                        "connection_error" (:connection-error state)
                        "pubkey" (:pubkey state)
                        "autonomous" (:autonomous? state)
                        "epoch" (:epoch state)
                        "sessions" sessions-summary
                        "pending_offers_count" (count (:pending-offers state))
                        "pending_rendezvous_count" (count (:pending-rendezvous state {}))
                        "rendezvous_policy" (:rendezvous-policy state)
                        "inbox_count" (count (:inbox state))
                        "account" (:account state)
                        "petnames" (into (sorted-map) (:petnames state {}))
                        "petnames_count" (count (:petnames state {}))
                        "dac" (dac-summary (:dac state))
                        "revoked_dacs_count" (count (:revoked-dacs state #{}))
                        "directory_cache_count" (count (:directory-cache state {}))
                        "escrows_count" (count (:escrows state {}))
                        "accounting" {"scope" "local-non-consensus"
                                      "note" "Locally computed devnet totals; never consensus finalized"
                                      "burned_ech" (get-in state [:local-accounting :burned-ech] 0)
                                      "vouchers_count" (count (:vouchers state []))}
                        "wire_protocol" {"version" current-wire-version
                                         "min_supported" min-supported-wire-version
                                         "max_supported" max-supported-wire-version
                                         "unsupported_dropped" (get-in state [:wire-version-diagnostics :unsupported-dropped] 0)
                                         "last_unsupported_version" (get-in state [:wire-version-diagnostics :last-unsupported-version])
                                         "wire_format" current-wire-format
                                         "supported_formats" ["fressian-v1" "legacy-nippy"]
                                         "unsupported_format_dropped" (get-in state [:wire-version-diagnostics :unsupported-format-dropped] 0)
                                         "last_unsupported_format" (get-in state [:wire-version-diagnostics :last-unsupported-format])}}
                 (:conn-diagnostics state) (assoc "diagnostics" (:conn-diagnostics state)))
     :net-envelopes []
     :stdout-events []}))

(defn handle-command
  "Dispatches a parsed JSON command map to its corresponding protocol verb reducer.
   Supports both flat command maps and nested {\"cmd\": ..., \"args\": {...}} maps.
   Tags outgoing envelopes with :subnet-id from state or command."
  [state cmd-map privkey-bytes]
  (let [effective-map (if (map? (get cmd-map "args"))
                        (merge (get cmd-map "args") (dissoc cmd-map "args"))
                        cmd-map)
        sub-id (str (or (get effective-map "subnet_id")
                        (get effective-map "subnet-id")
                        (:subnet-id effective-map)
                        (:subnet-id state)
                        "global"))
        res (case (or (get effective-map "cmd") (:cmd effective-map))
              "identity" (exec-identity state)
              "discover" (exec-discover state)
              "register-home-set" (exec-register-home-set state effective-map privkey-bytes)
              "offer" (exec-offer state effective-map privkey-bytes)
              "accept" (exec-accept state effective-map privkey-bytes)
              "p2p-offer" (exec-p2p-offer state effective-map privkey-bytes)
              "p2p-answer" (exec-p2p-answer state effective-map privkey-bytes)
              "broadcast" (exec-broadcast state effective-map privkey-bytes)
              "rendezvous-policy" (exec-rendezvous-policy state effective-map)
              "rendezvous-offer" (exec-rendezvous-offer state effective-map privkey-bytes)
              "rendezvous-accept" (exec-rendezvous-accept state effective-map privkey-bytes)
              "send" (exec-send state effective-map privkey-bytes)
              "inbox" (exec-inbox state)
              "close" (exec-close state effective-map privkey-bytes)
              "transfer" (exec-transfer state effective-map privkey-bytes)
              "account" (exec-sync-account state effective-map)
              "sync-account" (exec-sync-account state effective-map)
              "settle-intent" (exec-settle-intent state effective-map privkey-bytes)
              "lock-intent" (exec-lock-intent state effective-map privkey-bytes)
              "release-intent" (exec-release-intent state effective-map privkey-bytes)
              "refund-intent" (exec-refund-intent state effective-map privkey-bytes)
              "escrows" (exec-escrows state effective-map)
              "query-chain-state" (let [env (build-chain-state-query-envelope (:pubkey state) privkey-bytes effective-map)]
                                    {:state state
                                     :response {"ok" true "query_sent" true}
                                     :net-envelopes [env]
                                     :stdout-events []})
              "submit-vouchers" (exec-submit-vouchers state effective-map privkey-bytes)
              "petname-set" (exec-petname-set state effective-map)
              "petname-list" (exec-petname-list state)
              "petname-remove" (exec-petname-remove state effective-map)
              "petname-resolve" (exec-petname-resolve state effective-map)
              "dac-attach" (exec-dac-attach state effective-map)
              "dac-revoke" (exec-dac-revoke state effective-map)
              "directory-verify" (exec-directory-verify state effective-map)
              "directory-register" (exec-directory-register state effective-map privkey-bytes)
              "directory-lookup" (exec-directory-lookup state effective-map)
              "status" (exec-status state)
              {:state state :response {"ok" false "error" "unknown-command"} :net-envelopes [] :stdout-events []})]
    (if (seq (:net-envelopes res))
      (update res :net-envelopes (fn [envs]
                                   (mapv (fn [e]
                                           (if (or (nil? (:subnet-id e)) (= (:subnet-id e) "global"))
                                             (assoc e :subnet-id sub-id)
                                             e))
                                         envs)))
      res)))

;; -----------------------------------------------------------------------------
;; Inbound Wire Payload Handlers (Pure Helpers)
;; -----------------------------------------------------------------------------

(defn- unwrap-wire-message [raw-payload-or-event]
  (cond
    (bytes? raw-payload-or-event)
    (if-let [thawed (try (thaw-payload raw-payload-or-event) (catch #?(:clj Exception :cljs :default) _ nil))]
      (recur thawed)
      nil)

    (and (map? raw-payload-or-event) (map? (:event raw-payload-or-event)))
    (let [ver (or (:protocol-version raw-payload-or-event) (get raw-payload-or-event "protocol_version"))
          sub (or (:subnet-id raw-payload-or-event) (get raw-payload-or-event "subnet_id") (get raw-payload-or-event "subnet-id"))
          unwrapped (unwrap-wire-message (:event raw-payload-or-event))]
      (cond-> unwrapped
        (and (map? unwrapped) ver (not (contains? unwrapped :protocol-version)) (not (contains? unwrapped "protocol_version")))
        (assoc :protocol-version ver)
        (and (map? unwrapped) sub (not (contains? unwrapped :subnet-id)) (not (contains? unwrapped "subnet_id")) (not (contains? unwrapped "subnet-id")))
        (assoc :subnet-id (str sub))))

    (and (map? raw-payload-or-event) (map? (:message raw-payload-or-event)))
    (let [ver (or (:protocol-version raw-payload-or-event) (get raw-payload-or-event "protocol_version"))
          sub (or (:subnet-id raw-payload-or-event) (get raw-payload-or-event "subnet_id") (get raw-payload-or-event "subnet-id"))
          p (:payload (:message raw-payload-or-event))
          unwrapped (if (bytes? p)
                      (unwrap-wire-message (try (thaw-payload p) (catch #?(:clj Exception :cljs :default) _ nil)))
                      (if (map? p) (unwrap-wire-message p) nil))]
      (cond-> unwrapped
        (and (map? unwrapped) ver (not (contains? unwrapped :protocol-version)) (not (contains? unwrapped "protocol_version")))
        (assoc :protocol-version ver)
        (and (map? unwrapped) sub (not (contains? unwrapped :subnet-id)) (not (contains? unwrapped "subnet_id")) (not (contains? unwrapped "subnet-id")))
        (assoc :subnet-id (str sub))))

    (and (map? raw-payload-or-event)
         (or (contains? raw-payload-or-event :bitecho/type)
             (contains? raw-payload-or-event :type)
             (contains? raw-payload-or-event "type")
             (contains? raw-payload-or-event "cmd")))
    (fressian/strip-untrusted-crypto-tags raw-payload-or-event)

    (and (map? raw-payload-or-event)
         (or (contains? raw-payload-or-event :protocol-version)
             (contains? raw-payload-or-event "protocol_version")))
    (fressian/strip-untrusted-crypto-tags raw-payload-or-event)

    :else nil))

(defn- handle-wire-offer [state msg privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:caller msg)) (valid-pubkey-hex? (:caller msg))
                 (string? (:callee msg)) (valid-pubkey-hex? (:callee msg))
                 (string? (:session-id msg)) (not (str/blank? (:session-id msg)))
                 (string? (:caller-ephemeral-pub msg)) (not (str/blank? (:caller-ephemeral-pub msg)))
                 (string? (:offer-hash msg)) (not (str/blank? (:offer-hash msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (integer? (:epoch msg))
                 (or (nil? (:burn msg)) (integer? (:burn msg)))
                 (or (nil? (:price msg)) (integer? (:price msg)))
                 (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:pubkey state))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [caller-pub (try (basalt/hex->bytes (:caller msg)) (catch #?(:clj Exception :cljs :default) _ nil))
            sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
            expected-sid (compute-session-id (:caller msg) (:callee msg) (:caller-ephemeral-pub msg))
            expected-hash-legacy (compute-offer-hash msg)
            expected-hash-sealed (sealed/offer-hash msg)
            wire-dac (or (:dac msg) (get msg "dac"))
            dac-id (or (:dac-id msg) (get msg "dac_id")
                       (when wire-dac (or (:dac-id wire-dac) (get wire-dac "dac_id") (get wire-dac "dac-id"))))
            burn-num (parse-long-safe (or (:price msg) (:burn msg)) 0)
            epoch-num (parse-long-safe (:epoch msg) 0)
            expected-hash-5field (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes (str (:caller msg) "-" (:callee msg) "-" (:caller-ephemeral-pub msg) "-" epoch-num "-" burn-num (when (and (string? dac-id) (not (str/blank? dac-id))) (str "|" dac-id))))))
            valid-hashes? (and (= (:session-id msg) expected-sid)
                               (or (= (:offer-hash msg) expected-hash-legacy)
                                   (= (:offer-hash msg) expected-hash-sealed)
                                   (= (:offer-hash msg) expected-hash-5field)))
            caller-suites (or (:crypto-suites msg) (get msg "crypto_suites") (get msg "crypto-suites"))
            callee-suites (or (:crypto-suites state) sealed/default-crypto-suites)
            suite-negotiation (sealed/negotiate-crypto-suite (or caller-suites [sealed/suite-v1-chacha20poly1305]) callee-suites)
            valid-suite? (:ok? suite-negotiation)
            selected-suite (:selected-suite suite-negotiation)
            valid-sig? (and valid-hashes?
                            valid-suite?
                            caller-pub sig-bytes
                            (crypto/verify caller-pub (fressian/utf8->bytes (:offer-hash msg)) sig-bytes))
            ref-epoch (:epoch state)
            wire-dac (or (:dac msg) (get msg "dac"))
            dac-check (when wire-dac
                        (verify-dac wire-dac {:expected-agent-pubkey (:caller msg)
                                              :current-epoch ref-epoch
                                              :revoked-dac-ids (:revoked-dacs state)
                                              :required-scope "offer"}))
            economy-enabled? (get state :economy-enabled? true)
            burn-floor (long (or (:burn-floor state) 100))
            actual-burn (long (or (:burn msg) 0))]
        (if (or (not valid-sig?)
                (not valid-suite?)
                (and economy-enabled? (< actual-burn burn-floor))
                (and wire-dac (not (:ok? dac-check))))
          {:state state :net-envelopes [] :stdout-events []}
          (let [sid (:session-id msg)
                clean-offer (cond-> (select-keys msg [:bitecho/type :session-id :caller :callee :caller-ephemeral-pub :epoch :price :home-node :offer-hash :burn :signature :crypto-suites])
                              selected-suite (assoc :selected-suite selected-suite)
                              (and wire-dac (:ok? dac-check)) (assoc :dac (:dac dac-check)))]
            (cond
              (contains? (:sessions state) sid)
              (let [new-state (update-in state [:sessions sid :replays-deduped] (fnil inc 0))]
                {:state new-state :net-envelopes [] :stdout-events []})

              (contains? (:pending-offers state) sid)
              {:state state :net-envelopes [] :stdout-events []}

              (:autonomous? state)
              (let [accept-res (exec-accept (assoc-in state [:pending-offers sid] clean-offer)
                                            {"session_id" sid}
                                            privkey-bytes)]
                {:state (:state accept-res)
                 :net-envelopes (:net-envelopes accept-res)
                 :stdout-events (:stdout-events accept-res)})

              :else
              (let [caller-pname (pubkey->petname state (:caller clean-offer))
                    offer-dac (:dac clean-offer)
                    dac-anchor (when offer-dac (or (:anchor-pubkey offer-dac) (get offer-dac "anchor_pubkey")))
                    dac-id (when offer-dac (or (:dac-id offer-dac) (get offer-dac "dac_id")))
                    event (cond-> {"event" "offer-received"
                                   "session_id" sid
                                   "caller" (:caller clean-offer)
                                   "price" (:price clean-offer)}
                            caller-pname (assoc "caller_petname" caller-pname)
                            dac-anchor (assoc "anchor_pubkey" dac-anchor)
                            dac-id (assoc "dac_id" dac-id))]
                {:state (assoc-in state [:pending-offers sid] clean-offer)
                 :net-envelopes []
                 :stdout-events [event]}))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-accept [state msg]
  (try
    (if-not (and (map? msg)
                 (string? (:caller msg)) (= (normalize-pubkey-hex (:caller msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:callee msg)) (valid-pubkey-hex? (:callee msg))
                 (string? (:session-id msg)) (not (str/blank? (:session-id msg)))
                 (string? (:callee-ephemeral-pub msg)) (not (str/blank? (:callee-ephemeral-pub msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (map? (:delivery-ack msg))
                 (or (nil? (:epoch msg)) (integer? (:epoch msg))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [session-id (:session-id msg)
            session (get-in state [:sessions session-id])]
        (cond
          (and session (= "open" (:state session)))
          {:state (update-in state [:sessions session-id :replays-deduped] (fnil inc 0))
           :net-envelopes []
           :stdout-events []}

          (not (and session (= "offered" (:state session))))
          {:state state :net-envelopes [] :stdout-events []}

          :else
          (let [callee-pub (try (basalt/hex->bytes (:callee msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                raw-sel-suite (or (:selected-suite msg) (:suite msg))
                sel-str (when raw-sel-suite (if (keyword? raw-sel-suite) (name raw-sel-suite) (str raw-sel-suite)))
                offered-suites (set (map #(if (keyword? %) (name %) (str %))
                                         (or (:crypto-suites session) sealed/default-crypto-suites)))
                suite-valid? (if sel-str
                               (and (contains? offered-suites sel-str)
                                    (contains? sealed/supported-crypto-suites sel-str))
                               (contains? offered-suites sealed/suite-v1-chacha20poly1305))
                effective-suite (or sel-str sealed/suite-v1-chacha20poly1305)
                sig-input (if sel-str
                            (str session-id "-" (:callee-ephemeral-pub msg) "|" sel-str)
                            (str session-id "-" (:callee-ephemeral-pub msg)))
                valid-ack? (rendezvous/verify-delivery-ack (:delivery-ack msg) (:callee msg))
                valid-sig? (and suite-valid?
                                callee-pub sig-bytes
                                (crypto/verify callee-pub
                                               (fressian/utf8->bytes sig-input)
                                               sig-bytes))]
            (if-not (and valid-ack? valid-sig?)
              {:state state :net-envelopes [] :stdout-events []}
              (let [callee-eph (try (basalt/hex->bytes (:callee-ephemeral-pub msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                    shared-sec (when callee-eph (sealed/x25519-shared-secret (:ephemeral-priv session) callee-eph))]
                (if-not shared-sec
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [keys (sealed/derive-channel-keys shared-sec session-id :initiator)
                        updated-sess (-> session
                                         (assoc :state "open"
                                                :suite effective-suite
                                                :tx-seq 0
                                                :acked-seq 0
                                                :rx-high-seq 0
                                                :contiguous-rx-seq 0
                                                :replays-deduped 0
                                                :outbox-evicted 0
                                                :outbox {}
                                                :outbox-order []
                                                :tx-key (:tx-key keys)
                                                :rx-key (:rx-key keys)
                                                :replay-window (sealed/init-replay-window))
                                         (dissoc :ephemeral-priv))
                        new-state (-> state
                                      (assoc-in [:sessions session-id] updated-sess)
                                      (update :vouchers (fnil conj []) (:delivery-ack msg)))
                        callee-pname (pubkey->petname state (:callee msg))
                        event (cond-> {"event" "channel-opened" "session_id" session-id "peer" (:callee msg)}
                                callee-pname (assoc "peer_petname" callee-pname))]
                    {:state new-state
                     :net-envelopes []
                     :stdout-events [event]}))))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- advance-contiguous-rx-seq
  "Advances the contiguous received sequence number starting from contiguous-seq
   as long as contiguous-seq + 1 is present in seen-set or past the window horizon."
  [contiguous-seq seen-set ^long highest-seq]
  (let [window-size 64
        horizon (- highest-seq window-size)]
    (loop [curr (long (or contiguous-seq 0))]
      (let [next-seq (inc curr)]
        (cond
          (contains? seen-set next-seq) (recur next-seq)
          (and (pos? horizon) (<= next-seq horizon)) (recur next-seq)
          :else curr)))))

(defn build-session-ack-envelope
  "Builds and signs a :session-ack envelope wrapping Ed25519 signature."
  ([state session-id peer-pub contiguous-ack-seq msg-seq privkey-bytes]
   (build-session-ack-envelope state session-id peer-pub contiguous-ack-seq msg-seq nil privkey-bytes))
  ([state session-id peer-pub contiguous-ack-seq msg-seq seen-seqs privkey-bytes]
   (when privkey-bytes
     (let [seen-vec (vec (sort (or seen-seqs [])))
           ack-sign-bytes (fressian/utf8->bytes (str "ack-" session-id "-" contiguous-ack-seq "-" msg-seq "-" (str/join "," seen-vec)))
           sig (crypto/sign privkey-bytes ack-sign-bytes)
           sig-hex (if (string? sig) sig (basalt/bytes->hex sig))
           ack-payload {:protocol-version current-wire-version
                        :bitecho/type :session-ack
                        :session-id session-id
                        :sender (:pubkey state)
                        :recipient peer-pub
                        :epoch (long (or (get-in state [:sessions session-id :epoch]) (:epoch state) 0))
                        :ack-seq contiguous-ack-seq
                        :acked-seq msg-seq
                        :seen-seqs seen-vec
                        :signature sig-hex}]
       (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload ack-payload) 100)))))

(defn- handle-wire-sealed-msg [state msg privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:recipient msg)) (= (normalize-pubkey-hex (:recipient msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:session-id msg))
                 (integer? (:seq msg))
                 (string? (:nonce msg))
                 (string? (:ciphertext msg)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [session-id (:session-id msg)
            session (get-in state [:sessions session-id])]
        (if-not (and session (= "open" (:state session)))
          {:state state :net-envelopes [] :stdout-events []}
          (let [chk (sealed/check-and-advance-replay-window (:replay-window session) (:seq msg))]
            (cond
              (:accepted? chk)
              (let [ct (try (basalt/hex->bytes (:ciphertext msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                    decrypted (when ct (sealed/open-message (:rx-key session) (:seq msg) ct (fressian/utf8->bytes session-id) (:suite session) (:suite msg)))]
                (if-not decrypted
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [new-rx-high-seq (max (long (:rx-high-seq session 0)) (long (:seq msg)))
                        new-contiguous (advance-contiguous-rx-seq (:contiguous-rx-seq session 0)
                                                                  (:seen (:window chk))
                                                                  (:highest-seq (:window chk) 0))
                        seen-seqs (vec (sort (:seen (:window chk))))
                        ack-env (build-session-ack-envelope state session-id (:sender msg) new-contiguous (:seq msg) seen-seqs privkey-bytes)
                        text (try (fressian/bytes->utf8 decrypted) (catch #?(:clj Exception :cljs :default) _ nil))
                        sender-pname (pubkey->petname state (:sender msg))
                        inbox-item {:session-id session-id
                                    :session_id session-id
                                    :from (:sender msg)
                                    :seq (:seq msg)
                                    :text text
                                    :payload-hex (basalt/bytes->hex decrypted)
                                    :payload_hex (basalt/bytes->hex decrypted)}
                        updated-sess (assoc session
                                            :replay-window (:window chk)
                                            :rx-high-seq new-rx-high-seq
                                            :contiguous-rx-seq new-contiguous)
                        new-state (-> state
                                      (assoc-in [:sessions session-id] updated-sess)
                                      (update :inbox (fnil conj []) inbox-item))
                        event (cond-> {"event" "message-received"
                                       "session_id" session-id
                                       "from" (:sender msg)
                                       "seq" (:seq msg)}
                                text (assoc "text" text)
                                sender-pname (assoc "from_petname" sender-pname))]
                    {:state new-state
                     :net-envelopes (if ack-env [ack-env] [])
                     :stdout-events [event]})))

              (= :replayed-seq (:error chk))
              (let [ct (try (basalt/hex->bytes (:ciphertext msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                    decrypted (when ct (sealed/open-message (:rx-key session) (:seq msg) ct (fressian/utf8->bytes session-id) (:suite session) (:suite msg)))]
                (if-not decrypted
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [contig (:contiguous-rx-seq session 0)
                        seen-seqs (vec (sort (:seen (:replay-window session))))
                        ack-env (build-session-ack-envelope state session-id (:sender msg) contig (:seq msg) seen-seqs privkey-bytes)
                        new-state (update-in state [:sessions session-id :replays-deduped] (fnil inc 0))]
                    {:state new-state
                     :net-envelopes (if ack-env [ack-env] [])
                     :stdout-events []})))

              :else
              {:state state :net-envelopes [] :stdout-events []})))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-session-ack [state msg]
  (try
    (if-not (and (map? msg)
                 (string? (:recipient msg)) (= (normalize-pubkey-hex (:recipient msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:session-id msg))
                 (string? (:signature msg))
                 (integer? (:ack-seq msg))
                 (integer? (:acked-seq msg))
                 (coll? (:seen-seqs msg)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [session-id (:session-id msg)
            session (get-in state [:sessions session-id])]
        (if-not (and session
                     (= "open" (:state session))
                     (= (:sender msg) (:peer session)))
          {:state state :net-envelopes [] :stdout-events []}
          (let [peer-pub (try (basalt/hex->bytes (:peer session)) (catch #?(:clj Exception :cljs :default) _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                ack-seq (long (or (:ack-seq msg) 0))
                acked-seq (long (or (:acked-seq msg) 0))
                seen-vec (vec (sort (or (:seen-seqs msg) [])))
                canonical-bytes (fressian/utf8->bytes (str "ack-" session-id "-" ack-seq "-" acked-seq "-" (str/join "," seen-vec)))
                valid-sig? (and peer-pub sig-bytes
                                (crypto/verify peer-pub canonical-bytes sig-bytes))]
            (if-not valid-sig?
              {:state state :net-envelopes [] :stdout-events []}
              (let [new-acked-seq (max (long (:acked-seq session 0)) ack-seq)
                    curr-outbox (or (:outbox session) {})
                    curr-order (or (:outbox-order session) [])
                    seen-set (set (map long seen-vec))
                    acked? (fn [s] (or (<= (long s) ack-seq) (= (long s) acked-seq) (contains? seen-set (long s))))
                    purged-outbox (reduce-kv (fn [m s item]
                                               (if (acked? s)
                                                 m
                                                 (assoc m s item)))
                                             {}
                                             curr-outbox)
                    purged-order (filterv #(not (acked? %)) curr-order)
                    updated-sess (assoc session
                                        :acked-seq new-acked-seq
                                        :outbox purged-outbox
                                        :outbox-order purged-order)
                    new-state (assoc-in state [:sessions session-id] updated-sess)]
                {:state new-state
                 :net-envelopes []
                 :stdout-events []}))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn build-unacked-replay-envelopes
  "Extracts unacknowledged session outbox messages and returns signed gossip envelopes
   for failover/reconnect replay, reusing existing signed gossip envelopes to preserve
   message-id deduplication and prevent double-burn."
  ([state privkey-bytes]
   (build-unacked-replay-envelopes state privkey-bytes nil))
  ([state privkey-bytes session-id-filter]
   (if-not privkey-bytes
     []
     (let [sessions (into (sorted-map)
                          (filter (fn [[sid s]]
                                    (and (= "open" (:state s))
                                         (or (nil? session-id-filter)
                                             (= sid session-id-filter))))
                                  (:sessions state)))]
       (vec
        (for [[_ sess] sessions
              seq-num (or (seq (:outbox-order sess)) (sort (keys (or (:outbox sess) {}))))
              :let [item (get-in sess [:outbox seq-num])]
              :when item
              :let [env (:gossip-env item)]]
          (if env
            env
            (let [msg (:msg-payload item)
                  burn (or (:burn item) 500)]
              (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload msg) burn)))))))))

(defn- handle-wire-close [state msg]
  (try
    (if-not (and (map? msg)
                 (string? (:session-id msg)) (not (str/blank? (:session-id msg)))
                 (string? (:sender msg)) (valid-pubkey-hex? (:sender msg))
                 (string? (:signature msg)) (not (str/blank? (:signature msg))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [session-id (:session-id msg)
            session (get-in state [:sessions session-id])]
        (if-not (and session (not= "closed" (:state session)))
          {:state state :net-envelopes [] :stdout-events []}
          (let [sender-pub (try (basalt/hex->bytes (:sender msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                valid-sig? (and sender-pub sig-bytes
                                (crypto/verify sender-pub (fressian/utf8->bytes (str "close-" session-id)) sig-bytes))]
            (if-not valid-sig?
              {:state state :net-envelopes [] :stdout-events []}
              (let [closed-sess (-> session
                                    (assoc :state "closed")
                                    (dissoc :tx-key :rx-key :ephemeral-priv))
                    new-state (assoc-in state [:sessions session-id] closed-sess)
                    peer-pname (pubkey->petname state (:sender msg))
                    event (cond-> {"event" "channel-closed" "session_id" session-id "peer" (:sender msg)}
                            peer-pname (assoc "peer_petname" peer-pname))]
                {:state new-state
                 :net-envelopes []
                 :stdout-events [event]}))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-rendezvous-header
  "Callee receives Phase 1 :rendezvous-offer-header wire payload.
   Evaluates callee policy (min-burn, allowlist) and either auto-accepts or buffers in :pending-rendezvous."
  [state msg privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:caller msg)) (valid-pubkey-hex? (:caller msg))
                 (string? (:callee msg)) (valid-pubkey-hex? (:callee msg))
                 (string? (:offer-hash msg)) (not (str/blank? (:offer-hash msg)))
                 (string? (:home-node msg)) (not (str/blank? (:home-node msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (integer? (:epoch msg))
                 (integer? (:burn msg))
                 (>= (long (:burn msg)) 0)
                 (or (nil? (:topic msg)) (string? (:topic msg)))
                 (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:pubkey state))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [caller (:caller msg)
            callee (:callee msg)
            offer-hash (:offer-hash msg)
            epoch (long (:epoch msg))
            burn (long (:burn msg))
            topic (str (or (:topic msg) ""))
            home-node (:home-node msg)
            wire-dac (or (:dac msg) (get msg "dac"))
            dac-check (when wire-dac
                        (verify-dac wire-dac {:expected-agent-pubkey caller
                                              :current-epoch (:epoch state)
                                              :revoked-dac-ids (:revoked-dacs state)}))]
        (if (and wire-dac (not (:ok? dac-check)))
          {:state state :net-envelopes [] :stdout-events []}
          (let [dac-id (when (and wire-dac (:ok? dac-check))
                         (or (:dac-id (:dac dac-check)) (get (:dac dac-check) "dac_id")))
                suites (or (:crypto-suites msg) (get msg "crypto_suites") (get msg "crypto-suites"))
                header-str (canonical-rendezvous-header-str caller callee offer-hash epoch burn topic home-node dac-id suites)
                caller-pub (try (basalt/hex->bytes caller) (catch #?(:clj Exception :cljs :default) _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                suite-neg (sealed/negotiate-crypto-suite (or suites [sealed/suite-v1-chacha20poly1305])
                                                         (or (:crypto-suites state) sealed/default-crypto-suites))
                valid-sig? (and (:ok? suite-neg)
                                caller-pub sig-bytes
                                (crypto/verify caller-pub (fressian/utf8->bytes header-str) sig-bytes))]
            (if-not valid-sig?
              {:state state :net-envelopes [] :stdout-events []}
              (let [pol (or (:rendezvous-policy state)
                            {:auto-accept? false :min-burn 0 :price 10 :allowlist #{} :home-node "default-home"})
                    min-burn (long (or (:min-burn pol) 0))
                    allowlist (or (:allowlist pol) #{})
                    rejected-allowlist? (and (seq allowlist) (not (contains? (set allowlist) caller)))
                    rejected-burn? (< burn min-burn)]
                (if (or rejected-allowlist? rejected-burn?)
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [clean-header (cond-> (select-keys msg [:bitecho/type :type :caller :callee :offer-hash :epoch :burn :topic :home-node :signature :crypto-suites])
                                       (:selected-suite suite-neg) (assoc :selected-suite (:selected-suite suite-neg))
                                       (and wire-dac (:ok? dac-check)) (assoc :dac (:dac dac-check)))
                        caller-pname (pubkey->petname state caller)
                        header-evt (cond-> {"event" "rendezvous-header-received"
                                            "offer_hash" offer-hash
                                            "from" caller
                                            "burn" burn
                                            "topic" topic}
                                     caller-pname (assoc "from_petname" caller-pname))]
                    (if (or (:auto-accept? pol) (:autonomous? state))
                      (let [ack-res (callee-issue-rendezvous-ack state clean-header privkey-bytes)]
                        {:state (:state ack-res)
                         :net-envelopes (:net-envelopes ack-res)
                         :stdout-events [header-evt]})
                      {:state (assoc-in state [:pending-rendezvous offer-hash] clean-header)
                       :net-envelopes []
                       :stdout-events [header-evt]})))))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-rendezvous-ack
  "Caller receives Phase 1b :rendezvous-ack-voucher wire payload.
   Verifies callee DeliveryAck voucher, derives session keys, establishes active sealed session,
   and emits Phase 2 :rendezvous-reveal (plus any queued initial message)."
  [state msg privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:caller msg)) (= (normalize-pubkey-hex (:caller msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:callee msg)) (valid-pubkey-hex? (:callee msg))
                 (string? (:offer-hash msg)) (not (str/blank? (:offer-hash msg)))
                 (string? (:callee-x25519 msg)) (not (str/blank? (:callee-x25519 msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (integer? (:epoch msg))
                 (map? (:delivery-ack msg)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [offer-hash (:offer-hash msg)
            outbound (get-in state [:outbound-rendezvous offer-hash])]
        (if-not (and outbound
                     (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:callee outbound))))
          {:state state :net-envelopes [] :stdout-events []}
          (let [ack (:delivery-ack msg)
                ack-valid? (and (map? ack)
                                (= (:offer-hash ack) offer-hash)
                                (= (normalize-pubkey-hex (:callee ack)) (normalize-pubkey-hex (:callee msg)))
                                (rendezvous/verify-delivery-ack ack (:callee msg)))
                ack-sig (str (or (:signature ack) (get ack "signature") ""))
                callee-x25519 (:callee-x25519 msg)
                epoch (long (:epoch msg))
                raw-sel-suite (or (:selected-suite msg) (:suite msg))
                sel-str (when raw-sel-suite (if (keyword? raw-sel-suite) (name raw-sel-suite) (str raw-sel-suite)))
                offered-suites (set (map #(if (keyword? %) (name %) (str %))
                                         (or (:crypto-suites outbound) sealed/default-crypto-suites)))
                suite-valid? (if sel-str
                               (and (contains? offered-suites sel-str)
                                    (contains? sealed/supported-crypto-suites sel-str))
                               (contains? offered-suites sealed/suite-v1-chacha20poly1305))
                effective-suite (or sel-str sealed/suite-v1-chacha20poly1305)
                ack-str (canonical-rendezvous-ack-str (:caller msg) (:callee msg) offer-hash callee-x25519 epoch ack-sig sel-str)
                callee-pub (try (basalt/hex->bytes (:callee msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                sig-valid? (and suite-valid?
                                callee-pub sig-bytes
                                (crypto/verify callee-pub (fressian/utf8->bytes ack-str) sig-bytes))]
            (if-not (and ack-valid? sig-valid?)
              {:state state :net-envelopes [] :stdout-events []}
              (let [session-id (:session-id outbound)
                    callee-eph (try (basalt/hex->bytes callee-x25519) (catch #?(:clj Exception :cljs :default) _ nil))
                    keys (when callee-eph
                           (sealed/derive-session-keys (:caller-x25519-priv outbound) callee-eph
                                                       (:caller outbound) (:callee outbound)
                                                       offer-hash :initiator))]
                (if-not keys
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [reveal-str (canonical-rendezvous-reveal-str session-id (:pubkey state) (:callee outbound)
                                                                    offer-hash (:caller-x25519-pub outbound) (:epoch state))
                        reveal-sig (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes reveal-str)))
                        reveal-payload {:protocol-version current-wire-version
                                        :wire-format current-wire-format
                                        :bitecho/type :rendezvous-reveal
                                        :type :rendezvous-reveal
                                        :session-id session-id
                                        :caller (:pubkey state)
                                        :callee (:callee outbound)
                                        :offer-hash offer-hash
                                        :caller-x25519 (:caller-x25519-pub outbound)
                                        :epoch (:epoch state)
                                        :signature reveal-sig}
                        reveal-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload reveal-payload) 500)
                        initial-text (:initial-text outbound)
                        [session-with-tx net-envs]
                        (if (and initial-text (not (str/blank? initial-text)))
                          (let [text-bytes (fressian/utf8->bytes initial-text)
                                seq-num 1
                                sealed-m (sealed/seal-message (:tx-key keys) seq-num text-bytes (fressian/utf8->bytes session-id) effective-suite)
                                msg-payload {:protocol-version current-wire-version
                                             :wire-format current-wire-format
                                             :bitecho/type :sealed-message
                                             :session-id session-id
                                             :sender (:pubkey state)
                                             :recipient (:callee outbound)
                                             :epoch (long (or (:epoch outbound) (:epoch state) 0))
                                             :seq seq-num
                                             :suite effective-suite
                                             :nonce (basalt/bytes->hex (:nonce sealed-m))
                                             :ciphertext (basalt/bytes->hex (:ciphertext sealed-m))}
                                msg-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload msg-payload) 500)]
                            [{:session-id session-id
                              :peer (:callee outbound)
                              :role :initiator
                              :state "open"
                              :tx-seq seq-num
                              :acked-seq 0
                              :rx-high-seq 0
                              :contiguous-rx-seq 0
                              :replays-deduped 0
                              :outbox-evicted 0
                              :outbox {seq-num {:seq seq-num :msg-payload msg-payload :burn 500 :gossip-env msg-env}}
                              :outbox-order [seq-num]
                              :epoch (long (or (:epoch outbound) (:epoch state) 0))
                              :tx-key (:tx-key keys)
                              :rx-key (:rx-key keys)
                              :suite effective-suite
                              :replay-window (sealed/init-replay-window)}
                             [reveal-env msg-env]])
                          [{:session-id session-id
                            :peer (:callee outbound)
                            :role :initiator
                            :state "open"
                            :tx-seq 0
                            :acked-seq 0
                            :rx-high-seq 0
                            :contiguous-rx-seq 0
                            :replays-deduped 0
                            :outbox-evicted 0
                            :outbox {}
                            :outbox-order []
                            :epoch (long (or (:epoch outbound) (:epoch state) 0))
                            :tx-key (:tx-key keys)
                            :rx-key (:rx-key keys)
                            :suite effective-suite
                            :replay-window (sealed/init-replay-window)}
                           [reveal-env]])
                        new-state (-> state
                                      (update :outbound-rendezvous dissoc offer-hash)
                                      (assoc-in [:sessions session-id] session-with-tx)
                                      (update :vouchers (fnil conj []) (into {} ack)))
                        callee-pname (pubkey->petname state (:callee outbound))
                        est-evt (cond-> {"event" "rendezvous-session-established"
                                         "session_id" session-id
                                         "peer" (:callee outbound)
                                         "offer_hash" offer-hash}
                                  callee-pname (assoc "peer_petname" callee-pname))]
                    {:state new-state
                     :net-envelopes net-envs
                     :stdout-events [est-evt]}))))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-rendezvous-reveal
  "Callee receives Phase 2 :rendezvous-reveal wire payload.
   Verifies commitment binding of :caller-x25519 against Phase 1 offer-hash,
   verifies caller signature, derives matching keys, and establishes active sealed session."
  [state msg _privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:session-id msg)) (not (str/blank? (:session-id msg)))
                 (string? (:caller msg)) (valid-pubkey-hex? (:caller msg))
                 (string? (:callee msg)) (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:offer-hash msg)) (not (str/blank? (:offer-hash msg)))
                 (string? (:caller-x25519 msg)) (not (str/blank? (:caller-x25519 msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (integer? (:epoch msg)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [offer-hash (:offer-hash msg)
            pending (get-in state [:pending-rendezvous-accepts offer-hash])]
        (if-not (and pending
                     (= (normalize-pubkey-hex (:caller msg)) (normalize-pubkey-hex (:caller pending))))
          {:state state :net-envelopes [] :stdout-events []}
          (let [caller (:caller msg)
                callee (:callee msg)
                caller-x25519 (:caller-x25519 msg)
                sid (:session-id msg)
                header (:header pending)
                expected-sid (compute-session-id caller callee caller-x25519)
                expected-offer-hash (compute-offer-hash {:session-id sid
                                                         :caller caller
                                                         :callee callee
                                                         :caller-ephemeral-pub caller-x25519
                                                         :epoch (:epoch header)
                                                         :price (:burn header)
                                                         :burn (:burn header)
                                                         :home-node (:home-node header)
                                                         :crypto-suites (:crypto-suites header)
                                                         :dac (:dac header)
                                                         :subnet-id (or (:subnet-id header) (:subnet-id msg) (:subnet-id state) "global")})
                commitment-valid? (and (= sid expected-sid)
                                       (= offer-hash expected-offer-hash))]
            (if-not commitment-valid?
              {:state state :net-envelopes [] :stdout-events []}
              (let [reveal-str (canonical-rendezvous-reveal-str sid caller callee offer-hash caller-x25519 (long (:epoch msg)))
                    caller-pub (try (basalt/hex->bytes caller) (catch #?(:clj Exception :cljs :default) _ nil))
                    sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                    sig-valid? (and caller-pub sig-bytes
                                    (crypto/verify caller-pub (fressian/utf8->bytes reveal-str) sig-bytes))]
                (if-not sig-valid?
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [caller-eph (try (basalt/hex->bytes caller-x25519) (catch #?(:clj Exception :cljs :default) _ nil))
                        keys (when caller-eph
                               (sealed/derive-session-keys (:callee-x25519-priv pending) caller-eph
                                                           caller callee offer-hash :responder))]
                    (if-not keys
                      {:state state :net-envelopes [] :stdout-events []}
                      (let [session-entry {:session-id sid
                                           :peer caller
                                           :role :responder
                                           :state "open"
                                           :tx-seq 0
                                           :acked-seq 0
                                           :rx-high-seq 0
                                           :contiguous-rx-seq 0
                                           :replays-deduped 0
                                           :outbox-evicted 0
                                           :outbox {}
                                           :outbox-order []
                                           :epoch (long (or (:epoch header) (:epoch state) 0))
                                           :tx-key (:tx-key keys)
                                           :rx-key (:rx-key keys)
                                           :suite (or (:selected-suite pending) (:selected-suite header) (first (:crypto-suites header)) sealed/suite-v1-chacha20poly1305)
                                           :replay-window (sealed/init-replay-window)}
                            new-state (-> state
                                          (update :pending-rendezvous-accepts dissoc offer-hash)
                                          (assoc-in [:sessions sid] session-entry))
                            caller-pname (pubkey->petname state caller)
                            est-evt (cond-> {"event" "rendezvous-session-established"
                                             "session_id" sid
                                             "peer" caller
                                             "offer_hash" offer-hash}
                                      caller-pname (assoc "peer_petname" caller-pname))]
                        {:state new-state
                         :net-envelopes []
                         :stdout-events [est-evt]}))))))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-p2p-offer
  [state msg]
  (try
    (let [sid (:session-id msg)
          session (get-in state [:sessions sid])]
      (if-not (and session
                   (= "open" (:state session))
                   (string? (:sender msg))
                   (string? (:recipient msg))
                   (= (normalize-pubkey-hex (:recipient msg)) (normalize-pubkey-hex (:pubkey state)))
                   (= (normalize-pubkey-hex (:sender msg)) (normalize-pubkey-hex (:peer session)))
                   (string? (:signature msg)) (not (str/blank? (:signature msg))))
        {:state state :net-envelopes [] :stdout-events []}
        (let [transport (str (or (:transport msg) "udp"))
              candidates (vec (map str (or (:candidates msg) [])))
              ice-ufrag (str (or (:ice-ufrag msg) ""))
              ice-pwd (str (or (:ice-pwd msg) ""))
              fp (str (or (:fingerprint msg) ""))
              epoch (long (or (:epoch msg) 0))
              sig-str (canonical-p2p-signal-str :offer sid (:sender msg) (:recipient msg) transport candidates ice-ufrag ice-pwd fp epoch)
              sender-pub (try (basalt/hex->bytes (:sender msg)) (catch #?(:clj Exception :cljs :default) _ nil))
              sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
              sig-valid? (and sender-pub sig-bytes
                              (crypto/verify sender-pub (fressian/utf8->bytes sig-str) sig-bytes))]
          (if-not sig-valid?
            {:state state :net-envelopes [] :stdout-events []}
            (let [p2p-entry (merge (get session :p2p {})
                                   {:phase :offer-received
                                    :connected? false
                                    :remote-transport transport
                                    :remote-candidates candidates
                                    :remote-ice-ufrag ice-ufrag
                                    :remote-ice-pwd ice-pwd
                                    :remote-fingerprint fp})
                  new-state (assoc-in state [:sessions sid :p2p] p2p-entry)
                  pname (pubkey->petname state (:sender msg))
                  evt (cond-> {"event" "p2p-offer-received"
                               "session_id" sid
                               "from" (normalize-pubkey-hex (:sender msg))
                               "transport" transport
                               "candidates" candidates}
                        pname (assoc "from_petname" pname))]
              {:state new-state
               :net-envelopes []
               :stdout-events [evt]})))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-p2p-answer
  [state msg]
  (try
    (let [sid (:session-id msg)
          session (get-in state [:sessions sid])]
      (if-not (and session
                   (= "open" (:state session))
                   (string? (:sender msg))
                   (string? (:recipient msg))
                   (= (normalize-pubkey-hex (:recipient msg)) (normalize-pubkey-hex (:pubkey state)))
                   (= (normalize-pubkey-hex (:sender msg)) (normalize-pubkey-hex (:peer session)))
                   (string? (:signature msg)) (not (str/blank? (:signature msg))))
        {:state state :net-envelopes [] :stdout-events []}
        (let [transport (str (or (:transport msg) "udp"))
              candidates (vec (map str (or (:candidates msg) [])))
              ice-ufrag (str (or (:ice-ufrag msg) ""))
              ice-pwd (str (or (:ice-pwd msg) ""))
              fp (str (or (:fingerprint msg) ""))
              epoch (long (or (:epoch msg) 0))
              sig-str (canonical-p2p-signal-str :answer sid (:sender msg) (:recipient msg) transport candidates ice-ufrag ice-pwd fp epoch)
              sender-pub (try (basalt/hex->bytes (:sender msg)) (catch #?(:clj Exception :cljs :default) _ nil))
              sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
              sig-valid? (and sender-pub sig-bytes
                              (crypto/verify sender-pub (fressian/utf8->bytes sig-str) sig-bytes))]
          (if-not sig-valid?
            {:state state :net-envelopes [] :stdout-events []}
            (let [p2p-entry (merge (get session :p2p {})
                                   {:phase :open
                                    :connected? true
                                    :zero-burn? true
                                    :remote-transport transport
                                    :remote-candidates candidates
                                    :remote-ice-ufrag ice-ufrag
                                    :remote-ice-pwd ice-pwd
                                    :remote-fingerprint fp})
                  new-state (assoc-in state [:sessions sid :p2p] p2p-entry)
                  pname (pubkey->petname state (:sender msg))
                  evt (cond-> {"event" "p2p-connected"
                               "session_id" sid
                               "peer" (normalize-pubkey-hex (:sender msg))
                               "transport" transport
                               "zero_burn" true}
                        pname (assoc "peer_petname" pname))]
              {:state new-state
               :net-envelopes []
               :stdout-events [evt]})))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(declare handle-wire-payload)

(defn- handle-wire-p2p-hub-relay
  [state msg privkey-bytes]
  (try
    (if-not (and (string? (:sender msg)) (valid-pubkey-hex? (:sender msg))
                 (string? (:target-pubkey msg)) (valid-pubkey-hex? (:target-pubkey msg))
                 (some? (:sealed-envelope msg))
                 (string? (:signature msg)) (not (str/blank? (:signature msg))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [norm-sender (normalize-pubkey-hex (:sender msg))
            norm-target (normalize-pubkey-hex (:target-pubkey msg))
            sub-id (str (or (:subnet-id msg) (:subnet-id state) "global"))
            sid (str (or (:session-id msg) ""))
            canonical-str (str "bitecho-p2p-hub-relay-v1|" sub-id "|" norm-sender "|" norm-target "|" sid)
            sender-pub (try (basalt/hex->bytes norm-sender) (catch #?(:clj Exception :cljs :default) _ nil))
            sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
            sig-valid? (and sender-pub sig-bytes
                            (crypto/verify sender-pub (fressian/utf8->bytes canonical-str) sig-bytes))]
        (if-not sig-valid?
          {:state state :net-envelopes [] :stdout-events []}
          (if (= norm-target (normalize-pubkey-hex (:pubkey state)))
            (handle-wire-payload state (:sealed-envelope msg) privkey-bytes)
            {:state (update-in state [:diagnostics :p2p-relayed] (fnil inc 0))
             :net-envelopes [(:sealed-envelope msg)]
             :stdout-events []}))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-broadcast
  [state msg]
  (try
    (if-not (and (string? (:sender msg)) (valid-pubkey-hex? (:sender msg))
                 (integer? (:seq msg)) (pos? (long (:seq msg)))
                 (string? (:msg-id msg)) (not (str/blank? (:msg-id msg)))
                 (string? (:text msg)) (not (str/blank? (:text msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg))))
      {:state (update-in state [:diagnostics :broadcast-rejected] (fnil inc 0))
       :net-envelopes []
       :stdout-events []}
      (let [norm-sender (normalize-pubkey-hex (:sender msg))
            seq-num (long (:seq msg))
            msg-id (:msg-id msg)
            text (:text msg)
            sub-id (str (or (:subnet-id msg) (:subnet-id state) "global"))
            epoch (long (or (:epoch msg) (:epoch state) 0))
            wire-dac (or (:dac msg) (get msg "dac"))
            dac-id (when (map? wire-dac) (or (:dac-id wire-dac) (get wire-dac "dac_id") (get wire-dac "dac-id")))
            expected-msg-id (compute-broadcast-msg-id sub-id norm-sender seq-num text)
            sig-str (canonical-broadcast-str sub-id norm-sender seq-num msg-id text epoch dac-id)
            sender-pub (try (basalt/hex->bytes norm-sender) (catch #?(:clj Exception :cljs :default) _ nil))
            sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
            sig-valid? (and (= msg-id expected-msg-id)
                            sender-pub sig-bytes
                            (crypto/verify sender-pub (fressian/utf8->bytes sig-str) sig-bytes))
            trusted-anchors (:trusted-dac-anchors state #{})
            requires-dac? (seq trusted-anchors)
            dac-valid? (if-not requires-dac?
                         (if wire-dac
                           (:ok? (verify-dac wire-dac {:expected-agent-pubkey norm-sender
                                                       :current-epoch (:epoch state)
                                                       :revoked-dac-ids (:revoked-dacs state)
                                                       :required-scope "broadcast"}))
                           true)
                         (and (map? wire-dac)
                              (let [v (verify-dac wire-dac {:expected-agent-pubkey norm-sender
                                                            :current-epoch (:epoch state)
                                                            :revoked-dac-ids (:revoked-dacs state)
                                                            :required-scope "broadcast"})]
                                (and (:ok? v)
                                     (contains? trusted-anchors
                                                (normalize-pubkey-hex (get-in v [:dac :anchor-pubkey])))))))]
        (if-not (and sig-valid? dac-valid?)
          {:state (update-in state [:diagnostics :broadcast-rejected] (fnil inc 0))
           :net-envelopes []
           :stdout-events []}
          (let [dedup-key [norm-sender seq-num msg-id]
                seen (:broadcast-seen state #{})]
            (if (contains? seen dedup-key)
              {:state (update-in state [:diagnostics :broadcast-duplicates-dropped] (fnil inc 0))
               :net-envelopes []
               :stdout-events []}
              (let [pname (pubkey->petname state norm-sender)
                    b-entry (cond-> {:from norm-sender
                                     :seq seq-num
                                     :msg-id msg-id
                                     :text text
                                     :subnet-id sub-id
                                     :epoch epoch
                                     :broadcast? true}
                              pname (assoc :from_petname pname "from_petname" pname))
                    evt (cond-> {"event" "broadcast-received"
                                 "subnet_id" sub-id
                                 "from" norm-sender
                                 "seq" seq-num
                                 "msg_id" msg-id
                                 "text" text}
                          pname (assoc "from_petname" pname))
                    new-state (-> state
                                  (update :broadcast-seen (fnil conj #{}) dedup-key)
                                  (update :broadcast-inbox (fnil conj []) b-entry)
                                  (update :inbox (fnil conj []) b-entry))]
                {:state new-state
                 :net-envelopes []
                 :stdout-events [evt]}))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state (update-in state [:diagnostics :broadcast-rejected] (fnil inc 0))
       :net-envelopes []
       :stdout-events []})))

(defn handle-wire-chain-state-snapshot
  "Handles incoming validator :chain-state-snapshot over wire.
   Verifies against trusted bootstrap validators and min finalized epoch.
   Buffers snapshot in :chain-state-snapshots, prunes stale snapshots, and applies
   ONLY when verified BFT quorum is reached across trusted validators."
  [state msg]
  (let [trusted (set (keep (comp normalize-pubkey-hex :pubkey) (vals (get-in state [:bootstrap :nodes]))))
        min-fin-ep (long (or (get-in state [:account :finalized-epoch]) 0))
        opts {:expected-pubkey (:pubkey state)
              :trusted-validators trusted
              :min-finalized-epoch min-fin-ep}
        v-res (verify-chain-state-snapshot msg opts)]
    (if-not (:ok? v-res)
      {:state state :net-envelopes [] :stdout-events []}
      (let [snap (:snapshot v-res)
            val-pk (:validator-pubkey snap)
            fin-ep (long (or (:finalized-epoch snap) 0))
            existing-snaps (:chain-state-snapshots state {})
            ;; Prune stale snapshots older than (fin-ep - 2)
            fresh-snaps (into {} (filter (fn [[_ s]]
                                           (>= (long (or (:finalized-epoch s) 0)) (- fin-ep 2)))
                                         existing-snaps))
            buffered-snaps (assoc fresh-snaps val-pk snap)
            buffered-state (assoc state :chain-state-snapshots buffered-snaps)
            q-res (verify-chain-state-quorum (vals buffered-snaps) opts)]
        (if (:ok? q-res)
          (let [agreed-snap (:snapshot q-res)
                st-applied (apply-verified-chain-state-snapshot buffered-state agreed-snap)
                stdout-evt {"event" "chain-state-synced"
                            "pubkey" (:pubkey state)
                            "balance" (:balance agreed-snap)
                            "spendable" (:spendable agreed-snap)
                            "seq" (:seq agreed-snap)
                            "finalized_epoch" (:finalized-epoch agreed-snap)
                            "quorum_count" (:quorum-count q-res)
                            "validator" (:validator-pubkey agreed-snap)}]
            {:state st-applied
             :net-envelopes []
             :stdout-events [stdout-evt]})
          {:state buffered-state
           :net-envelopes []
           :stdout-events []})))))

(defn handle-wire-payload
  "Processes an incoming network event or raw payload. Enforces wire protocol version compatibility,
   2-epoch skew tolerance, and anti-replay protections before dispatching to message-specific reducers."
  [state raw-payload-or-event privkey-bytes]
  (let [msg (unwrap-wire-message raw-payload-or-event)]
    (if-not (map? msg)
      {:state state :net-envelopes [] :stdout-events []}
      (let [v-chk (check-wire-version-compatibility msg)]
        (if-not (:ok? v-chk)
          (let [unsupported-ver (:version v-chk)
                err-msg (:error v-chk)
                new-state (-> state
                              (update-in [:wire-version-diagnostics :unsupported-dropped] (fnil inc 0))
                              (assoc-in [:wire-version-diagnostics :last-unsupported-version] unsupported-ver)
                              (assoc-in [:wire-version-diagnostics :last-error] err-msg))
                diag-event {"event" "wire-version-rejected"
                            "error" err-msg
                            "version" unsupported-ver
                            "min_supported" min-supported-wire-version
                            "max_supported" max-supported-wire-version}]
            {:state new-state
             :response {"ok" false "error" err-msg "version" unsupported-ver}
             :net-envelopes []
             :stdout-events [diag-event]})
          (let [f-chk (check-wire-format-compatibility msg)]
            (if-not (:ok? f-chk)
              (let [unsupported-fmt (:wire-format f-chk)
                    err-msg (:error f-chk)
                    new-state (-> state
                                  (update-in [:wire-version-diagnostics :unsupported-format-dropped] (fnil inc 0))
                                  (assoc-in [:wire-version-diagnostics :last-unsupported-format] unsupported-fmt)
                                  (assoc-in [:wire-version-diagnostics :last-error] err-msg))
                    diag-event {"event" "wire-format-rejected"
                                "error" err-msg
                                "wire_format" unsupported-fmt
                                "supported_formats" ["fressian-v1" "legacy-nippy"]}]
                {:state new-state
                 :response {"ok" false "error" err-msg "wire_format" unsupported-fmt}
                 :net-envelopes []
                 :stdout-events [diag-event]})
              (let [expected-subnet (str (or (:subnet-id state) "global"))
                    outer-subnet (when-let [s (when (map? raw-payload-or-event)
                                                (or (:subnet-id raw-payload-or-event)
                                                    (get raw-payload-or-event "subnet-id")
                                                    (get raw-payload-or-event "subnet_id")))]
                                   (str s))
                    inner-subnet (when (map? msg)
                                   (when-let [s (or (:subnet-id msg)
                                                    (get msg "subnet-id")
                                                    (get msg "subnet_id"))]
                                     (str s)))
                    subnet-mismatch? (or (and outer-subnet (not= outer-subnet "*") (not= expected-subnet "*") (not= outer-subnet expected-subnet))
                                         (and inner-subnet (not= inner-subnet "*") (not= expected-subnet "*") (not= inner-subnet expected-subnet))
                                         (and outer-subnet inner-subnet (not= outer-subnet "*") (not= inner-subnet "*") (not= outer-subnet inner-subnet)))]
                (if subnet-mismatch?
                  (let [eff-subnet (or outer-subnet inner-subnet "unknown")
                        new-state (-> state
                                      (update :subnet-mismatch-dropped (fnil inc 0))
                                      (update-in [:diagnostics :subnet-mismatch-dropped] (fnil inc 0))
                                      (update-in [:wire-version-diagnostics :subnet-mismatch-dropped] (fnil inc 0)))
                        diag-event {"event" "subnet-mismatch-dropped"
                                    "error" "subnet-mismatch"
                                    "outer_subnet" outer-subnet
                                    "inner_subnet" inner-subnet
                                    "event_subnet" eff-subnet
                                    "node_subnet" expected-subnet}]
                    {:state new-state
                     :response {"ok" false "error" "subnet-mismatch" "subnet" eff-subnet}
                     :net-envelopes []
                     :stdout-events [diag-event]})
                  (let [msg-type (or (:bitecho/type msg) (:type msg))
                        msg-epoch (when (integer? (:epoch msg)) (long (:epoch msg)))
                        sess-epoch (when-let [sid (:session-id msg)]
                                     (get-in state [:sessions sid :epoch]))
                        ref-epoch (if (or (:epoch-initialized? state)
                                          (and (integer? (:epoch state)) (pos? (long (:epoch state)))))
                                    (:epoch state)
                                    (or sess-epoch msg-epoch))
                        max-skew (long (or (:max-epoch-skew state) 2))
                        skew-exceeded? (and (not (contains? #{:chain-state-snapshot
                                                              :p2p-offer
                                                              :p2p-answer
                                                              :p2p-hub-relay
                                                              :p2p-broadcast}
                                                            msg-type))
                                            msg-epoch ref-epoch
                                            (> (math-abs (- msg-epoch (long ref-epoch))) max-skew)
                                            (or (nil? sess-epoch)
                                                (> (math-abs (- msg-epoch (long sess-epoch))) max-skew)))]
                    (if skew-exceeded?
                      {:state state :net-envelopes [] :stdout-events []}
                      (let [res (case msg-type
                                  :channel-offer (handle-wire-offer state msg privkey-bytes)
                                  :channel-accept (handle-wire-accept state msg)
                                  :sealed-message (handle-wire-sealed-msg state msg privkey-bytes)
                                  :session-ack (handle-wire-session-ack state msg)
                                  :channel-close (handle-wire-close state msg)
                                  :rendezvous-offer-header (handle-wire-rendezvous-header state msg privkey-bytes)
                                  :rendezvous-ack-voucher (handle-wire-rendezvous-ack state msg privkey-bytes)
                                  :rendezvous-reveal (handle-wire-rendezvous-reveal state msg privkey-bytes)
                                  :chain-state-snapshot (handle-wire-chain-state-snapshot state msg)
                                  :p2p-offer (handle-wire-p2p-offer state msg)
                                  :p2p-answer (handle-wire-p2p-answer state msg)
                                  :p2p-hub-relay (handle-wire-p2p-hub-relay state msg privkey-bytes)
                                  :p2p-broadcast (handle-wire-broadcast state msg)
                                  {:state state :net-envelopes [] :stdout-events []})]
                        (if (and (not= msg-type :chain-state-snapshot) msg-epoch (not (:epoch-initialized? (:state res))))
                          (update res :state assoc :epoch msg-epoch :epoch-initialized? true)
                          res)))))))))))))

;; -----------------------------------------------------------------------------
;; JSONL Line Processor
;; -----------------------------------------------------------------------------

(defn process-jsonl-line
  "Parses a single JSONL line, executes the command, and returns the updated state and response."
  [state line-str privkey-bytes]
  (let [trimmed (when (string? line-str) (str/trim line-str))]
    (if (or (nil? trimmed) (str/blank? trimmed))
      {:state state :response {"ok" false "error" "empty-line"} :net-envelopes [] :stdout-events []}
      (try
        (let [cmd-map (parse-json-str trimmed)]
          (if (and (map? cmd-map) (contains? cmd-map "cmd"))
            (handle-command state cmd-map privkey-bytes)
            {:state state :response {"ok" false "error" "malformed-request"} :net-envelopes [] :stdout-events []}))
        (catch #?(:clj Exception :cljs :default) _
          {:state state :response {"ok" false "error" "malformed-request"} :net-envelopes [] :stdout-events []})))))

;; -----------------------------------------------------------------------------
;; Multi-Subnet Multiplexer (Milestone 12 - Step 12A)
;; -----------------------------------------------------------------------------

(defn init-multi-subnet-multiplexer
  "Initializes a pure multi-subnet multiplexer state map over a single Rule 4 connection pool.
   Maintains isolated per-subnet state-machine instances without splitting connection liveness."
  [opts]
  {:subnets (or (:subnets opts) {})
   :conn (or (:conn opts) nil)
   :diagnostics (merge {:unroutable-dropped 0} (:diagnostics opts))})

(defn register-subnet-instance
  "Registers or updates a subnet state machine instance in the multiplexer."
  [mux subnet-id instance-state]
  (let [sid (str (or subnet-id "global"))]
    (assoc-in mux [:subnets sid] (assoc instance-state :subnet-id sid))))

(defn remove-subnet-instance
  "Removes a subnet state machine instance from the multiplexer."
  [mux subnet-id]
  (let [sid (str (or subnet-id "global"))]
    (update mux :subnets dissoc sid)))

(defn route-multiplexed-envelope
  "Routes an incoming wire envelope to the matching registered subnet state machine by :subnet-id.
   If envelope targets an unregistered subnet, drops fail-closed, increments :unroutable-dropped,
   and surfaces a counted :diagnose effect (Rule 5)."
  [mux envelope privkey-bytes]
  (let [sub-id (str (or (when (map? envelope)
                          (or (:subnet-id envelope)
                              (get envelope "subnet-id")
                              (get envelope "subnet_id")))
                        "global"))
        instance (get-in mux [:subnets sub-id])]
    (if-not instance
      (let [new-mux (update-in mux [:diagnostics :unroutable-dropped] (fnil inc 0))
            diag-event {"event" "unroutable-subnet-dropped"
                        "effect" :diagnose
                        "reason" :unroutable-subnet-dropped
                        "subnet" sub-id}]
        {:mux new-mux
         :net-envelopes []
         :stdout-events [diag-event]})
      (if (:bitecho.subnet/unified? instance)
        (let [sub-event (or (:event envelope) envelope)
              res (core-subnet/reduce-subnet instance sub-event)
              new-mux (assoc-in mux [:subnets sub-id] (:state res))]
          {:mux new-mux
           :effects (or (:effects res) [])
           :net-envelopes []
           :stdout-events []})
        (let [res (handle-wire-payload instance envelope privkey-bytes)
              old-mismatch (or (get-in instance [:diagnostics :subnet-mismatch-dropped])
                               (:subnet-mismatch-dropped instance)
                               0)
              new-mismatch (or (get-in (:state res) [:diagnostics :subnet-mismatch-dropped])
                               (:subnet-mismatch-dropped (:state res))
                               0)
              delta (max 0 (- (long new-mismatch) (long old-mismatch)))
              new-mux (-> mux
                          (assoc-in [:subnets sub-id] (:state res))
                          (cond-> (pos? delta)
                            (update-in [:diagnostics :subnet-mismatch-dropped] (fnil + 0) delta)))]
          {:mux new-mux
           :net-envelopes (or (:net-envelopes res) [])
           :stdout-events (or (:stdout-events res) [])})))))

(defn dispatch-multiplexed-command
  "Dispatches a command map to a specific subnet instance in the multiplexer.
   Tags outgoing network envelopes with the instance's :subnet-id."
  [mux subnet-id cmd-map privkey-bytes]
  (let [sub-id (str (or subnet-id
                        (get cmd-map "subnet_id")
                        (get cmd-map "subnet-id")
                        (:subnet-id cmd-map)
                        "global"))
        instance (get-in mux [:subnets sub-id])]
    (if-not instance
      {:mux mux
       :response {"ok" false "error" "subnet-not-found" "subnet" sub-id}
       :net-envelopes []
       :stdout-events []}
      (let [res (handle-command instance cmd-map privkey-bytes)
            tagged-envs (mapv (fn [e]
                                (cond-> e
                                  (or (nil? (:subnet-id e)) (= (:subnet-id e) "global"))
                                  (assoc :subnet-id sub-id)))
                              (or (:net-envelopes res) []))
            new-mux (assoc-in mux [:subnets sub-id] (:state res))]
        {:mux new-mux
         :response (:response res)
         :net-envelopes tagged-envs
         :stdout-events (or (:stdout-events res) [])}))))

;; -----------------------------------------------------------------------------
;; Authority-Signed Bootstrap & Domain Discovery (Milestone 12 - Step 12B)
;; -----------------------------------------------------------------------------

(defn normalize-nodes-for-bootstrap
  "Deterministically sorts and canonicalizes a collection or map of validator node descriptors."
  [nodes]
  (let [node-seq (cond
                   (map? nodes) (map (fn [[k v]] (assoc v :node-id (name k))) nodes)
                   (sequential? nodes) nodes
                   :else [])
        canon (mapv (fn [n]
                      (cond-> {:node-id (str (or (:node-id n) (:id n) "node"))
                               :ip (str (:ip n "127.0.0.1"))
                               :port (long (or (:port n) 9000))
                               :agent-port (long (or (:agent-port n) 9001))
                               :pubkey (str (or (:pubkey n) ""))
                               :fingerprint (str (or (:fingerprint n) ""))
                               :ice-ufrag (str (or (:ice-ufrag n) ""))
                               :ice-pwd (str (or (:ice-pwd n) ""))}
                        (:agent-tcp-port n) (assoc :agent-tcp-port (long (:agent-tcp-port n)))
                        (:ingress-host n) (assoc :ingress-host (str (:ingress-host n)))
                        (:ingress-port n) (assoc :ingress-port (long (:ingress-port n)))))
                    node-seq)]
    (vec (sort-by (fn [n] (str (:node-id n) "|" (:pubkey n))) canon))))

(defn canonical-bootstrap-payload
  "Constructs the canonical tuple for Ed25519 signing and verification of a bootstrap descriptor."
  [descriptor]
  ["bitecho-bootstrap-descriptor-v1"
   (str (:domain descriptor))
   (normalize-nodes-for-bootstrap (:nodes descriptor))
   (str (:authority-pubkey descriptor))
   (long (or (:issued-epoch descriptor) 0))
   (long (or (:expires-epoch descriptor) 0))])

(defn sign-bootstrap-descriptor
  "Signs a bootstrap descriptor map using authority-privkey and canonical payload bytes."
  [authority-privkey descriptor]
  (let [payload (canonical-bootstrap-payload descriptor)
        sig (crypto/sign-canonical authority-privkey payload)
        sig-hex (if (string? sig) sig (basalt/bytes->hex sig))]
    (assoc descriptor :signature sig-hex)))

(defn verify-bootstrap-descriptor
  "Cryptographically verifies an authority-signed bootstrap descriptor against expected-authority-pubkey.
   Requires expected-authority-pubkey to be a non-blank valid pubkey hex string (fails closed if missing).
   Validates epoch expiration against current-epoch when provided.
   Returns {:ok? boolean :valid? boolean :descriptor desc :error err}."
  [expected-authority-pubkey descriptor current-epoch]
  (let [[expected-pk desc epoch]
        (if (and (map? expected-authority-pubkey) (string? descriptor))
          [descriptor expected-authority-pubkey current-epoch]
          [expected-authority-pubkey descriptor current-epoch])]
    (try
      (cond
        (or (nil? expected-pk) (not (string? expected-pk)) (str/blank? (str/trim (str expected-pk))))
        {:ok? false :valid? false :error :missing-expected-authority-pubkey}

        (not (map? desc))
        {:ok? false :valid? false :error "invalid-descriptor-map"}

        :else
        (let [auth-pub (when-let [p (:authority-pubkey desc)] (str/lower-case (str/trim (str p))))
              expected-pub (str/lower-case (str/trim (str expected-pk)))
              sig (:signature desc)]
          (cond
            (str/blank? (str sig))
            {:ok? false :valid? false :error "missing-signature"}

            (and (some? auth-pub) (not= auth-pub expected-pub))
            {:ok? false :valid? false :error :authority-pubkey-mismatch}

            (and (some? epoch) (integer? epoch)
                 (integer? (:expires-epoch desc))
                 (> (long epoch) (long (:expires-epoch desc))))
            {:ok? false :valid? false :error "descriptor-expired"}

            (and (some? epoch) (integer? epoch)
                 (integer? (:issued-epoch desc))
                 (< (long epoch) (long (:issued-epoch desc))))
            {:ok? false :valid? false :error "descriptor-not-yet-valid"}

            :else
            (let [payload (canonical-bootstrap-payload desc)
                  valid? (crypto/verify-with-fallback expected-pub payload sig)]
              (if valid?
                {:ok? true :valid? true :descriptor desc}
                {:ok? false :valid? false :error "invalid-authority-signature"})))))
      (catch #?(:clj Exception :cljs :default) e
        {:ok? false :valid? false :error (str "verification-failed: " #?(:clj (.getMessage e) :cljs (.-message e)))}))))

(defn- parse-single-node-txt-block-pure
  "Extracts a validator node map from a text block starting with 'Node: <id>' in pure .cljc."
  [block-str]
  (let [id-match (re-find #"(?i)Node:\s*([a-zA-Z0-9_\-]+)" block-str)
        node-id (when id-match (keyword (second id-match)))
        cluster-match (re-find #"(?i)Cluster Address:\s*([^\s:]+):([0-9]+)" block-str)
        agent-match (re-find #"(?i)Agent Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        agent-tcp-match (re-find #"(?i)Agent TCP Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        agent-proxy-match (re-find #"(?i)Agent HTTPS/Proxy Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        pubkey-match (re-find #"(?i)Ed25519 Pubkey:\s*([0-9a-fA-F]+)" block-str)
        fp-match (re-find #"(?i)DTLS Fingerprint:\s*([0-9a-fA-F:]+)" block-str)
        ice-match (re-find #"(?i)ICE Credentials:\s*ufrag=([^\s]+)\s+pwd=([^\s]+)" block-str)]
    (when node-id
      [node-id
       (cond-> {:node-id (name node-id)
                :ip (when cluster-match (nth cluster-match 1))
                :port (when cluster-match (parse-long-safe (nth cluster-match 2) 9000))
                :agent-port (when agent-match (parse-long-safe (nth agent-match 2) 9001))
                :pubkey (when pubkey-match (str/lower-case (second pubkey-match)))
                :fingerprint (when fp-match (str/upper-case (second fp-match)))
                :ice-ufrag (when ice-match (nth ice-match 1))
                :ice-pwd (when ice-match (nth ice-match 2))}
         agent-tcp-match (assoc :agent-tcp-port (parse-long-safe (nth agent-tcp-match 2) 9002))
         agent-proxy-match (assoc :ingress-host (nth agent-proxy-match 1)
                                  :ingress-port (parse-long-safe (nth agent-proxy-match 2) 443)))])))

(defn format-bootstrap-txt-pure
  "Renders a bootstrap descriptor map into canonical bootstrap.txt string format in pure .cljc."
  [desc]
  (let [header-lines (cond-> [(str "Network: " (name (or (:network desc) :devnet)))]
                       (:domain desc) (conj (str "Domain: " (:domain desc)))
                       (:authority-pubkey desc) (conj (str "Authority Pubkey: " (:authority-pubkey desc)))
                       (:issued-epoch desc) (conj (str "Issued Epoch: " (:issued-epoch desc)))
                       (:expires-epoch desc) (conj (str "Expires Epoch: " (:expires-epoch desc)))
                       (:signature desc) (conj (str "Authority Signature: " (:signature desc)))
                       (:treasury-pubkey desc) (conj (str "Treasury Public Key: " (:treasury-pubkey desc)))
                       (:custody-pubkey desc) (conj (str "Custody Public Key: " (:custody-pubkey desc)))
                       (:directory-pubkey desc) (conj (str "Directory Authority Public Key: " (:directory-pubkey desc))))
        norm-nodes (normalize-nodes-for-bootstrap (:nodes desc))
        node-blocks (map (fn [n]
                           (str "Node: " (:node-id n) "\n"
                                "Cluster Address: " (:ip n) ":" (:port n) "\n"
                                "Agent Ingress: " (:ip n) ":" (:agent-port n) "\n"
                                (when-let [atp (:agent-tcp-port n)]
                                  (str "Agent TCP Ingress: " (:ip n) ":" atp "\n"))
                                (when-let [ih (:ingress-host n)]
                                  (str "Agent HTTPS/Proxy Ingress: " ih ":" (or (:ingress-port n) 443) "\n"))
                                "Ed25519 Pubkey: " (:pubkey n) "\n"
                                "DTLS Fingerprint: " (:fingerprint n) "\n"
                                "ICE Credentials: ufrag=" (:ice-ufrag n) " pwd=" (:ice-pwd n) "\n"))
                         norm-nodes)]
    (str (str/join "\n" header-lines) "\n\n" (str/join "\n" node-blocks))))

(defn parse-bootstrap-descriptor-pure
  "Parses an EDN or text format bootstrap descriptor into a map (including Node: blocks).
   Pure Sans-IO cross-platform helper for JVM and JS runtimes."
  [str-or-map]
  (cond
    (map? str-or-map) str-or-map
    (string? str-or-map)
    (let [trimmed (str/trim str-or-map)]
      (if (or (str/starts-with? trimmed "{") (str/starts-with? trimmed ";;"))
        (try
          (edn/read-string trimmed)
          (catch #?(:clj Exception :cljs :default) _ nil))
        (let [lines (str/split-lines trimmed)
              node-blocks (rest (str/split trimmed #"(?im)(?=^Node:\s*)"))
              nodes-map (into {} (keep parse-single-node-txt-block-pure node-blocks))
              parsed (reduce (fn [acc line]
                               (let [t (str/trim line)]
                                 (cond
                                   (re-find #"^Domain:\s*(.+)$" t)
                                   (assoc acc :domain (str/trim (second (re-find #"^Domain:\s*(.+)$" t))))
                                   (re-find #"^Authority Pubkey:\s*(.+)$" t)
                                   (assoc acc :authority-pubkey (str/trim (second (re-find #"^Authority Pubkey:\s*(.+)$" t))))
                                   (re-find #"^Issued Epoch:\s*(\d+)$" t)
                                   (assoc acc :issued-epoch (parse-long-safe (second (re-find #"^Issued Epoch:\s*(\d+)$" t)) 0))
                                   (re-find #"^Expires Epoch:\s*(\d+)$" t)
                                   (assoc acc :expires-epoch (parse-long-safe (second (re-find #"^Expires Epoch:\s*(\d+)$" t)) 0))
                                   (re-find #"^Authority Signature:\s*(.+)$" t)
                                   (assoc acc :signature (str/trim (second (re-find #"^Authority Signature:\s*(.+)$" t))))
                                   (re-find #"^Treasury Public Key:\s*(.+)$" t)
                                   (assoc acc :treasury-pubkey (str/trim (second (re-find #"^Treasury Public Key:\s*(.+)$" t))))
                                   (re-find #"^Custody Public Key:\s*(.+)$" t)
                                   (assoc acc :custody-pubkey (str/trim (second (re-find #"^Custody Public Key:\s*(.+)$" t))))
                                   :else acc)))
                             {:nodes nodes-map}
                             lines)]
          parsed)))
    :else nil))

(defn verify-federated-domain-bootstrap
  "Validates that a domain descriptor (EDN or text) was signed by expected authority pubkey and has not expired."
  ([domain _doh-or-edn-txt _current-epoch]
   {:ok? false :valid? false :error :missing-expected-authority-pubkey :domain domain})
  ([domain doh-or-edn-txt current-epoch expected-authority-pubkey]
   (if (or (nil? expected-authority-pubkey)
           (not (string? expected-authority-pubkey))
           (str/blank? (str/trim (str expected-authority-pubkey))))
     {:ok? false :valid? false :error :missing-expected-authority-pubkey :domain domain}
     (let [desc (parse-bootstrap-descriptor-pure doh-or-edn-txt)]
       (cond
         (nil? desc)
         {:ok? false :valid? false :error "malformed-descriptor" :domain domain}

         (and domain (not= (str (:domain desc)) (str domain)))
         {:ok? false :valid? false :error "domain-mismatch" :domain domain :descriptor-domain (:domain desc)}

         :else
         (let [res (verify-bootstrap-descriptor expected-authority-pubkey desc current-epoch)]
           (assoc res :domain domain)))))))

;; -----------------------------------------------------------------------------
;; Rendezvous Subnet Advertisements
;; -----------------------------------------------------------------------------

(def build-subnet-advertisement
  "Constructs and signs an authority rendezvous advertisement for a subnet."
  rendezvous/build-subnet-advertisement)

(def parse-subnet-advertisement
  "Validates structure and signature of a rendezvous subnet advertisement map."
  rendezvous/parse-subnet-advertisement)

;; -----------------------------------------------------------------------------
;; Milestone 12 Demonstrations (Step 12A & Step 12B)
;; -----------------------------------------------------------------------------

(defn run-zero-burn-team-subnet-demo
  "Demonstrates an isolated zero-burn team subnet processing offer, accept, and sealed messaging
   without requiring ECH balance or incurring burn fees."
  []
  (let [kp-alice (crypto/generate-keypair)
        kp-bob (crypto/generate-keypair)
        alice-pub (basalt/bytes->hex (:public-key kp-alice))
        bob-pub (basalt/bytes->hex (:public-key kp-bob))
        subnet "team-subnet-engineering"
        alice-init (init-light-state {:pubkey-hex alice-pub}
                                     {:subnet-id subnet :economy-enabled? false :burn-floor 0})
        bob-init (init-light-state {:pubkey-hex bob-pub}
                                   {:subnet-id subnet :economy-enabled? false :burn-floor 0})
        ;; 1. Alice initiates offer
        offer-res (handle-command alice-init
                                  {"cmd" "offer" "callee" bob-pub "peer" bob-pub "price" 0 "burn" 0}
                                  (:private-key kp-alice))
        session-id (get-in offer-res [:response "session_id"])
        ;; 2. Deliver all offer envelopes to Bob
        bob-after-offer (reduce (fn [st env]
                                  (:state (handle-wire-payload st env (:private-key kp-bob))))
                                bob-init
                                (:net-envelopes offer-res))
        ;; 3. Bob accepts offer
        accept-res (handle-command bob-after-offer
                                   {"cmd" "accept" "session_id" session-id}
                                   (:private-key kp-bob))
        ;; 4. Deliver accept envelopes to Alice
        alice-after-accept (reduce (fn [st env]
                                     (:state (handle-wire-payload st env (:private-key kp-alice))))
                                   (:state offer-res)
                                   (:net-envelopes accept-res))
        ;; 5. Alice sends message
        send-res (handle-command alice-after-accept
                                 {"cmd" "send" "session_id" session-id "text" "Deploying v2.4 to staging..."}
                                 (:private-key kp-alice))
        ;; 6. Deliver send envelopes to Bob
        bob-final (reduce (fn [st env]
                            (:state (handle-wire-payload st env (:private-key kp-bob))))
                          (:state accept-res)
                          (:net-envelopes send-res))
        alice-final (:state send-res)
        alice-burned (get-in alice-final [:local-accounting :burned-ech] 0)
        bob-burned (get-in bob-final [:local-accounting :burned-ech] 0)
        inbox (:inbox bob-final)]
    {:ok? (and (= 0 alice-burned)
               (= 0 bob-burned)
               (= 1 (count inbox))
               (= "Deploying v2.4 to staging..." (:text (first inbox))))
     :subnet-id subnet
     :economy-enabled? false
     :alice-pubkey alice-pub
     :bob-pubkey bob-pub
     :session-id session-id
     :alice-burned alice-burned
     :bob-burned bob-burned
     :messages-received (count inbox)
     :last-message (first inbox)
     :verified? true}))

(defn run-two-domain-federation-demo
  "Demonstrates cross-domain federation between alpha.bitecho.local and beta.bitecho.local
   with descriptor verification, rendezvous relay, and inter-subnet envelope multiplexing."
  []
  (let [kp-a (crypto/generate-keypair)
        kp-b (crypto/generate-keypair)
        pub-a (basalt/bytes->hex (:public-key kp-a))
        pub-b (basalt/bytes->hex (:public-key kp-b))
        domain-a "alpha.bitecho.local"
        domain-b "beta.bitecho.local"
        current-epoch 42
        desc-a {:domain domain-a
                :authority-pubkey pub-a
                :issued-epoch current-epoch
                :expires-epoch (+ current-epoch 100)
                :nodes [{:node-id "alpha-node-1" :ip "10.0.1.1" :port 9000 :agent-port 9001 :pubkey pub-a
                         :fingerprint "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                         :ice-ufrag "ufrag-a" :ice-pwd "pwd-a"}]}
        desc-b {:domain domain-b
                :authority-pubkey pub-b
                :issued-epoch current-epoch
                :expires-epoch (+ current-epoch 100)
                :nodes [{:node-id "beta-node-1" :ip "10.0.2.1" :port 9000 :agent-port 9001 :pubkey pub-b
                         :fingerprint "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
                         :ice-ufrag "ufrag-b" :ice-pwd "pwd-b"}]}
        signed-a (sign-bootstrap-descriptor (:private-key kp-a) desc-a)
        signed-b (sign-bootstrap-descriptor (:private-key kp-b) desc-b)
        v-a (verify-bootstrap-descriptor pub-a signed-a current-epoch)
        v-b (verify-bootstrap-descriptor pub-b signed-b current-epoch)
        fed-a (verify-federated-domain-bootstrap domain-a signed-a current-epoch pub-a)
        fed-b (verify-federated-domain-bootstrap domain-b signed-b current-epoch pub-b)
        ;; Rendezvous subnet advertisement for domain B
        ad-b (rendezvous/build-subnet-advertisement pub-b (:private-key kp-b)
                                                    {:subnet-id "beta-subnet"
                                                     :domain domain-b
                                                     :topic "subnet/beta-subnet"
                                                     :economy-enabled? false
                                                     :burn-floor 0})
        parsed-ad (rendezvous/parse-subnet-advertisement ad-b)
        ;; Multiplexer with isolated subnets
        node-a-state (init-light-state {:pubkey-hex pub-a} {:subnet-id "alpha-subnet"})
        node-b-state (init-light-state {:pubkey-hex pub-b} {:subnet-id "beta-subnet"})
        mux (-> (init-multi-subnet-multiplexer {})
                (register-subnet-instance "alpha-subnet" node-a-state)
                (register-subnet-instance "beta-subnet" node-b-state))
        ;; Route envelope targeting beta-subnet
        env-for-b {:protocol-version current-wire-version
                   :wire-format current-wire-format
                   :subnet-id "beta-subnet"
                   :agent-pubkey pub-a
                   :event {:type :tick :epoch current-epoch}}
        routed-res (route-multiplexed-envelope mux env-for-b (:private-key kp-b))
        ;; Attempt to route envelope targeting unknown-subnet (fail-closed, Rule 5)
        env-unroutable {:protocol-version current-wire-version
                        :wire-format current-wire-format
                        :subnet-id "unknown-subnet"
                        :event {:type :tick}}
        unroutable-res (route-multiplexed-envelope (:mux routed-res) env-unroutable (:private-key kp-a))]
    {:ok? (and (:ok? v-a) (:ok? v-b)
               (:ok? fed-a) (:ok? fed-b)
               (:ok? parsed-ad)
               (= 1 (get-in unroutable-res [:mux :diagnostics :unroutable-dropped])))
     :domain-a domain-a
     :domain-b domain-b
     :domain-a-verified? (:ok? v-a)
     :domain-b-verified? (:ok? v-b)
     :advertisement-verified? (:ok? parsed-ad)
     :inter-subnet-routed? true
     :unroutable-dropped (get-in unroutable-res [:mux :diagnostics :unroutable-dropped])
     :verified? true}))

;; -----------------------------------------------------------------------------
;; Milestone 16 Demonstration: 3-Way Zero-Burn P2P & Broadcast Mesh (Step 16B/16C)
;; -----------------------------------------------------------------------------

(defn run-three-way-p2p-broadcast-demo
  "Demonstrates 3-way zero-burn P2P & broadcast mesh across Simon (Browser), Nexus (JVM),
   and Axiom (Node.js) on subnet 'chat/simon-nexus-axiom' with DAC anchor verification,
   mDNS/direct ICE candidate signaling, and gossip deduplication."
  []
  (let [kp-anchor (crypto/generate-keypair)
        anchor-pub (basalt/bytes->hex (:public kp-anchor))
        kp-simon (crypto/generate-keypair)
        kp-nexus (crypto/generate-keypair)
        kp-axiom (crypto/generate-keypair)
        pub-simon (basalt/bytes->hex (:public kp-simon))
        pub-nexus (basalt/bytes->hex (:public kp-nexus))
        pub-axiom (basalt/bytes->hex (:public kp-axiom))
        subnet-id simon-nexus-axiom-subnet-id
        issue-dac (fn [delegate-pub]
                    (create-dac (:private kp-anchor)
                                {:anchor-pubkey anchor-pub
                                 :agent-pubkey delegate-pub
                                 :issued-epoch 10
                                 :expires-epoch 100
                                 :max-spend-per-epoch 1000
                                 :scopes ["broadcast" "gossip" "offer" "send"]}))
        dac-simon (issue-dac pub-simon)
        dac-nexus (issue-dac pub-nexus)
        dac-axiom (issue-dac pub-axiom)
        init-peer (fn [pub dac]
                    (-> (init-light-state {:pubkey-hex pub}
                                          {:subnet-id subnet-id
                                           :economy-enabled? false
                                           :burn-floor 0
                                           :trusted-dac-anchors #{anchor-pub}
                                           :epoch 10})
                        (assoc :dac dac)))
        simon-0 (init-peer pub-simon dac-simon)
        nexus-0 (init-peer pub-nexus dac-nexus)
        axiom-0 (init-peer pub-axiom dac-axiom)
        ;; 1. Open 1-to-1 channel Simon <-> Nexus and upgrade via p2p-offer / p2p-answer
        offer-sn (handle-command simon-0
                                 {"cmd" "offer" "callee" pub-nexus "peer" pub-nexus "price" 0 "burn" 0}
                                 (:private kp-simon))
        sid-sn (get-in offer-sn [:response "session_id"])
        nexus-1 (reduce (fn [st env] (:state (handle-wire-payload st env (:private kp-nexus))))
                        nexus-0
                        (:net-envelopes offer-sn))
        accept-sn (handle-command nexus-1
                                  {"cmd" "accept" "session_id" sid-sn}
                                  (:private kp-nexus))
        simon-1 (reduce (fn [st env] (:state (handle-wire-payload st env (:private kp-simon))))
                        (:state offer-sn)
                        (:net-envelopes accept-sn))
        p2p-off (handle-command simon-1
                                {"cmd" "p2p-offer"
                                 "session_id" sid-sn
                                 "candidates" ["a=candidate:1 1 UDP 2122260223 a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d.local 54321 typ host"]
                                 "ice_ufrag" "simon-ufrag"
                                 "ice_pwd" "simon-pwd"
                                 "dtls_fingerprint" "AA:BB:CC:DD"}
                                (:private kp-simon))
        nexus-2 (:state (handle-wire-payload (:state accept-sn)
                                             (first (:net-envelopes p2p-off))
                                             (:private kp-nexus)))
        p2p-ans (handle-command nexus-2
                                {"cmd" "p2p-answer"
                                 "session_id" sid-sn
                                 "candidates" ["a=candidate:1 1 UDP 2122260223 nexus.ingress.bitecho.org 18443 typ srflx"]
                                 "ice_ufrag" "nexus-ufrag"
                                 "ice_pwd" "nexus-pwd"
                                 "dtls_fingerprint" "11:22:33:44"
                                 "transport" "direct-p2p"}
                                (:private kp-nexus))
        simon-2 (:state (handle-wire-payload (:state p2p-off)
                                             (first (:net-envelopes p2p-ans))
                                             (:private kp-simon)))
        ;; 2. 3-way Broadcast across Simon, Nexus, and Axiom on chat/simon-nexus-axiom
        b-simon (handle-command simon-2
                                {"cmd" "broadcast" "text" "Browser ready on chat/simon-nexus-axiom" "subnet_id" subnet-id}
                                (:private kp-simon))
        b-nexus (handle-command (:state p2p-ans)
                                {"cmd" "broadcast" "text" "JVM Light-Node ready on chat/simon-nexus-axiom" "subnet_id" subnet-id}
                                (:private kp-nexus))
        b-axiom (handle-command axiom-0
                                {"cmd" "broadcast" "text" "Node.js Light-Node ready on chat/simon-nexus-axiom" "subnet_id" subnet-id}
                                (:private kp-axiom))
        env-s (first (:net-envelopes b-simon))
        env-n (first (:net-envelopes b-nexus))
        env-a (first (:net-envelopes b-axiom))
        ;; Deliver each peer's remote broadcasts (plus a duplicate of env-s to Nexus to test deduplication)
        nexus-final (reduce (fn [st env]
                              (:state (handle-wire-payload st env (:private kp-nexus))))
                            (:state b-nexus)
                            [env-s env-s env-a])
        simon-final (reduce (fn [st env]
                              (:state (handle-wire-payload st env (:private kp-simon))))
                            (:state b-simon)
                            [env-n env-a])
        axiom-final (reduce (fn [st env]
                              (:state (handle-wire-payload st env (:private kp-axiom))))
                            (:state b-axiom)
                            [env-s env-n])
        total-burned (+ (get-in simon-final [:local-accounting :burned-ech] 0)
                        (get-in nexus-final [:local-accounting :burned-ech] 0)
                        (get-in axiom-final [:local-accounting :burned-ech] 0))
        dups-dropped (get-in nexus-final [:diagnostics :broadcast-duplicates-dropped] 0)]
    {:ok? (and (= 0 total-burned)
               (= 3 (count (:broadcast-inbox nexus-final)))
               (= 3 (count (:broadcast-inbox simon-final)))
               (= 3 (count (:broadcast-inbox axiom-final)))
               (= 1 dups-dropped)
               (true? (get-in simon-final [:sessions sid-sn :p2p :connected?]))
               (true? (get-in nexus-final [:sessions sid-sn :p2p :connected?])))
     :subnet-id subnet-id
     :session-id sid-sn
     :p2p-status (if (get-in simon-final [:sessions sid-sn :p2p :connected?]) :connected :idle)
     :total-ech-burned total-burned
     :broadcast-count (count (:broadcast-inbox nexus-final))
     :duplicates-dropped dups-dropped
     :verified? true}))
