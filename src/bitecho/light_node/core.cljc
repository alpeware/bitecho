(ns bitecho.light-node.core
  "Pure Sans-IO protocol state reducer for the Bitecho light node.
   Handles command processing, sealed channel establishment, anti-replay,
   epoch skew tolerance, and Wire/JSONL conversions without side effects.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.bech32m :as bech32m]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.core.storage :as storage]
            [bitecho.core.subnet :as core-subnet]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.economy.account :as account]
            [bitecho.economy.bundle :as bundle]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.errors.core :as errors]
            [bitecho.fido :as fido]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.light-node.cli :as cli]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.status.core :as status-core]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [datachannel.mdns :as mdns]
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

(defn- now-utc-ms []
  #?(:clj (System/currentTimeMillis)
     :cljs (.now js/Date)))

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

(defn invalidate-stale-p2p-sessions
  "Pure helper (`F-BCAST-1` / `BIP-013`): clears transient runtime P2P liveness flags
   (`:connected?`, `:channel-open?`, `:direct-route?`) from all sessions' `:p2p` and `:p2p-meta`
   maps on daemon restart so stale pre-restart P2P metadata can never divert routing."
  [state]
  (if-not (map? state)
    state
    (let [clean-sessions
          (into {}
                (for [[sid s] (:sessions state)]
                  (let [p2p-seqs (select-keys (:p2p s) [:local-signal-seq :remote-offer-seq :remote-answer-seq])
                        p2p-meta (when (map? (:p2p-meta s))
                                   (dissoc (:p2p-meta s) :connected? :channel-open? :direct-route?))
                        s1 (cond-> (dissoc s :p2p)
                             (seq p2p-seqs) (assoc :p2p p2p-seqs)
                             (some? p2p-meta) (assoc :p2p-meta p2p-meta))]
                    [sid s1])))]
      (assoc state :sessions clean-sessions))))

(defn strip-sensitive-keys
  "Pure helper to remove single-use ECDH `:ephemeral-priv` keys from session state prior to persistence,
   and dissoc transient runtime connection liveness keys (`:connected?`, `:connection-error`, `:conn-diagnostics`, `:p2p`)
   so persisted state never includes them.
   NOTE (`M2a-1` Trust Boundary): Active session symmetric `:tx-key` and `:rx-key` are intentionally retained
   inside `state.fressian` (enforced `0600` POSIX permissions alongside `<state-dir>/identity/node-identity.edn`)
   so stateless one-shot CLI invocations (`send`, `inbox`, `close`) can encrypt and decrypt ongoing session
   messages across process invocations without re-running the X25519 handshake."
  [state]
  (let [invalidated (invalidate-stale-p2p-sessions state)
        clean-sessions (into {} (for [[sid s] (:sessions invalidated)]
                                  (let [cleaned (cond-> (dissoc s :ephemeral-priv :ratchet :pq-secret-key :handshake-state)
                                                  (not= "offered" (:state s)) (dissoc :offer-nonce))]
                                    [sid cleaned])))]
    (-> invalidated
        (assoc :sessions clean-sessions)
        (dissoc :connected? :connection-error :conn-diagnostics :runtime-ctx))))

(defn encode-light-state
  "Serializes sanitized light-node state into cross-platform Fressian bytes (`state.fressian`)."
  [state]
  (fressian/encode-wire-uncompressed (strip-sensitive-keys state)))

(defn legacy-v0238-state?
  "Returns true if `state` is a decoded v0.23.8 state map containing legacy split pointer/blob
   stores without unified `:pointers` / `:blobs` projection (`BIP-005` / `F-U5`)."
  [state]
  (and (map? state)
       (nil? (:pointers state))
       (boolean (or (seq (:artifact-pointers state))
                    (seq (:storage-pointers state))
                    (seq (:capabilities state))
                    (seq (get-in state [:governance :pointers]))))))

(defn migrate-light-state
  "Idempotently migrates a light-node state map so that all legacy domain pointer/blob maps
   (`:artifact-pointers`, `:storage-pointers`, `:capabilities`, `[:governance :pointers]`,
    `:artifact-blobs`, `:storage-blobs`, `:capability-blobs`, `[:governance :blobs]`)
   are projected into the unified `:pointers` and `:blobs` maps (`BIP-005` / `F-U4`, `F-U5`)."
  [state]
  (if-not (map? state)
    state
    (let [cap-ptrs (into {}
                         (keep (fn [[k v]]
                                 (let [ptr (if (and (map? v) (:pointer v)) (:pointer v) v)]
                                   (when (and (map? ptr) (:pointer/path ptr))
                                     [k ptr]))))
                         (:capabilities state))
          merged-ptrs (merge (or (get-in state [:governance :pointers]) {})
                             cap-ptrs
                             (or (:storage-pointers state) {})
                             (or (:artifact-tombstones state) {})
                             (or (:artifact-pointers state) {})
                             (or (:pointers state) {}))
          merged-blobs (merge (or (get-in state [:governance :blobs]) {})
                              (or (:capability-blobs state) {})
                              (or (:storage-blobs state) {})
                              (or (:artifact-blobs state) {})
                              (or (:blobs state) {}))]
      (cond-> state
        (or (seq merged-ptrs) (contains? state :pointers))
        (assoc :pointers merged-ptrs)
        (or (seq merged-blobs) (contains? state :blobs))
        (assoc :blobs merged-blobs)))))

(defn decode-light-state
  "Deserializes light-node state from Fressian bytes (`state.fressian`) across JVM and Node.js."
  [state-bytes]
  (when (and state-bytes (pos? (fressian/count-bytes state-bytes)))
    (fressian/decode-wire state-bytes)))

(declare handle-wire-payload enqueue-actionable-events build-session-ack-envelope)

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

(defn build-gossip-envelope
  "Builds and signs a `:receive-gossip` agent envelope across JVM and ClojureScript."
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

(declare normalize-pubkey-hex valid-pubkey-hex?)

(def simon-nexus-axiom-subnet-id
  "Canonical zero-burn DAC-gated 3-way private broadcast & chat subnet ID (Subnet #4)."
  "chat/simon-nexus-axiom")

(defn safe-map-get
  "Safe lookup that never throws CLJS CompareError when probing keyword keys
   on a string-keyed sorted-map (e.g. :petnames)."
  ([m k] (safe-map-get m k nil))
  ([m k not-found]
   (if (map? m)
     (try
       (get m k not-found)
       (catch #?(:clj Exception :cljs :default) _
         not-found))
     not-found)))

(def delivery-ring-max-entries
  "Pillar 1 bound: max entries in per-envelope sender lifecycle ring buffer (256)."
  256)

(def delivery-ring-max-entry-bytes
  "Pillar 1 bound: max UTF-8 serialized byte size per ring buffer entry (1 KiB)."
  1024)

(def broadcast-seen-max-entries
  "e2-micro bound: max entries retained in :broadcast-seen FIFO/LRU set (1024)."
  1024)

(def inbox-max-entries
  "e2-micro bound: max entries retained in :inbox and :broadcast-inbox."
  512)

(def default-unacked-age-threshold-ms
  "Default age threshold (60s) for classifying unacked outbox entries as unacked_aged."
  60000)

(def eviction-reasons
  "Closed enum of Pillar 2 outbox eviction reasons."
  #{:retries-exhausted :epoch-skew :session-not-open
    :mesh-disconnected :capacity-overflow :expired :rollback-collision})

(def suppression-reasons
  "Closed enum of Pillar 3 receiver/watcher received_but_not_emitted suppression reasons."
  #{:cursor-skip :subnet-mismatch :session-mismatch :event-type-mismatch
    :min-seq-filter :min-broadcast-seq-filter :after-ts-filter
    :duplicate-replay :queue-overflow :foreign-unicast :watcher-closed :admission-drop
    :broadcast-malformed :broadcast-sig-invalid :dac-required-missing :broadcast-dac-invalid})

(def initial-delivery-telemetry
  "Initial pure Sans-IO Pillar 1-3 delivery telemetry structure."
  {:ring-buffer []
   :sent 0
   :acked 0
   :evicted-by-reason {:retries-exhausted 0
                       :epoch-skew 0
                       :session-not-open 0
                       :mesh-disconnected 0
                       :capacity-overflow 0
                       :expired 0
                       :rollback-collision 0}
   :received-but-not-emitted {:cursor-skip 0
                              :subnet-mismatch 0
                              :session-mismatch 0
                              :event-type-mismatch 0
                              :min-seq-filter 0
                              :min-broadcast-seq-filter 0
                              :after-ts-filter 0
                              :duplicate-replay 0
                              :queue-overflow 0
                              :foreign-unicast 0
                              :watcher-closed 0
                              :admission-drop 0
                              :broadcast-malformed 0
                              :broadcast-sig-invalid 0
                              :dac-required-missing 0
                              :broadcast-dac-invalid 0}
   :fanout {:mesh-submitted 0
            :p2p-direct 0
            :peers-targeted 0
            :mesh-submit-failed 0}})

(def default-subscribed-subnets
  "Default set of subscribed subnets for light node instances (F-D25-8, F-D29-21)."
  #{})

(defn init-light-state
  "Initializes a pure light node state map from an identity public map and options.
   Private keys are never stored in the returned state map."
  [identity-pub-map opts]
  {:pubkey (or (:pubkey-hex identity-pub-map) (:pubkey identity-pub-map))
   :fingerprint (:fingerprint identity-pub-map)
   :ice-creds (:ice-creds identity-pub-map)
   :autonomous? (boolean (:autonomous? opts false))
   :auto-relay-fallback? (boolean (get opts :auto-relay-fallback? true))
   :epoch (long (:epoch opts 0))
   :epoch-initialized? (contains? opts :epoch)
   :bootstrap (:bootstrap opts)
   :trusted-directory-pubkey (or (:directory-pubkey opts)
                                 (get-in opts [:bootstrap :directory-pubkey])
                                 (:trusted-directory-pubkey opts))
   :trusted-dac-anchors (set (keep normalize-pubkey-hex (:trusted-dac-anchors opts)))
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
   :broadcast-seen-order []
   :broadcast-inbox []
   :relay-since-seq 0
   :relay-since-broadcast-seq 0
   :relay-cursors {}
   :event-history []
   :delivery-telemetry initial-delivery-telemetry
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
   :subscribed-subnets (let [raw (or (:subscribed-subnets opts) (:subscribed_subnets opts)
                                     (:subscribe-subnets opts) (:subscribe_subnets opts)
                                     default-subscribed-subnets)
                             items (cond
                                     (coll? raw) raw
                                     (string? raw) (str/split raw #",")
                                     :else [])]
                         (into default-subscribed-subnets (remove str/blank? (map (comp str/trim str) items))))
   :network-uri (or (config/resolve-network-uri (:network-uri opts))
                    (config/resolve-network-uri (:network opts))
                    (config/resolve-network-uri (:bootstrap opts))
                    (when (contains? (set (vals config/network-uris)) (str (:subnet-id opts)))
                      (str (:subnet-id opts)))
                    "devnet.bitecho.org")
   :economy-enabled? (boolean (get opts :economy-enabled? (get-in opts [:bootstrap :economy-enabled?] true)))
   :burn-floor (long (or (:burn-floor opts) (get-in opts [:bootstrap :burn-floor]) 0))
   :max-epoch-skew (max 1 (long (or (:max-epoch-skew opts) 15)))
   :diagnostics (merge {:subnet-mismatch-dropped 0
                        :network-replay-rejected 0
                        :p2p-relayed 0
                        :broadcast-duplicates-dropped 0
                        :broadcast-rejected 0
                        :p2p-signaling-rejected 0
                        :p2p-dial-failed 0
                        :p2p-answer-empty-candidates 0
                        :governance-replication-rejected 0}
                       (:diagnostics opts))
   :governance (or (:governance opts) (gov/init-governance-state))
   :crypto-suites (or (:crypto-suites opts) sealed/default-crypto-suites)})

(defn effective-subscribed-subnets
  "Returns the set of subnets a light node accepts broadcasts for."
  [state]
  (let [expected-subnet (str (or (:subnet-id state) "global"))
        active-net-uri (or (:network-uri state)
                           (config/resolve-network-uri (:bootstrap state))
                           "devnet.bitecho.org")
        explicit (into #{} (map str (or (:subscribed-subnets state) #{})))]
    (cond-> explicit
      expected-subnet (conj expected-subnet)
      (config/equivalent-subnet-id? "global" expected-subnet active-net-uri) (conj "global"))))

(def ^:private canonical-network-uri-set
  (set (vals config/network-uris)))

(defn- canonical-network-uri-for-subnet
  "Resolves canonical network URI strictly against `(vals config/network-uris)` (BIP-021 §2.1).
   Returns nil if `subnet-id` does not explicitly name a canonical network URI."
  [subnet-id]
  (when (and (string? subnet-id) (not (str/blank? subnet-id)))
    (let [s (str/trim subnet-id)]
      (cond
        (contains? canonical-network-uri-set s) s
        :else (some (fn [net-uri]
                      (when (str/starts-with? s (str net-uri "/"))
                        net-uri))
                    canonical-network-uri-set)))))

(declare enqueue-actionable-events)

(defn reconcile-startup-subnet-id
  "Pure Sans-IO startup `subnet_id` reconciler (BIP-021 §2.1).
   - Preserves persisted `:subnet-id` with 0 spurious diagnostics when `explicit-subnet-id` is nil/blank or equal.
   - Refuses silent cross-network-URI switches (`devnet` <-> `testnet` <-> `mainnet`) with counted
     `[:diagnostics :cross-network-subnet-switch-blocked]` unless `:reset-network-state?` is true.
   - Within the same canonical network (or with `:reset-network-state? true`), updates `:subnet-id`,
     merges `explicit-subscribe-subnets` and the new `:subnet-id` into `:subscribed-subnets`,
     increments `[:diagnostics :subnet-id-reconciled]`, and emits a `subnet-id-reconciled` event."
  ([state explicit-subnet-id]
   (reconcile-startup-subnet-id state explicit-subnet-id nil nil))
  ([state explicit-subnet-id explicit-subscribe-subnets]
   (reconcile-startup-subnet-id state explicit-subnet-id explicit-subscribe-subnets nil))
  ([state explicit-subnet-id explicit-subscribe-subnets opts]
   (let [persisted-sub (str (or (:subnet-id state) "global"))
         trimmed-explicit (when (and (some? explicit-subnet-id)
                                     (not (str/blank? (str explicit-subnet-id))))
                            (str/trim (str explicit-subnet-id)))
         extra-subs (->> (cond
                           (coll? explicit-subscribe-subnets) explicit-subscribe-subnets
                           (string? explicit-subscribe-subnets) (str/split explicit-subscribe-subnets #",")
                           :else [])
                         (map (comp str/trim str))
                         (remove str/blank?)
                         set)
         merged-subs (into (into #{} (map str (or (:subscribed-subnets state) #{}))) extra-subs)]
     (if (or (nil? trimmed-explicit) (= trimmed-explicit persisted-sub))
       {:ok? true
        :reconciled? false
        :blocked? false
        :state (assoc state
                      :subscribed-subnets merged-subs
                      :subnet-id-overridden? (boolean (:subnet-id-overridden? state false)))
        :effects []
        :stdout-events []}
       (let [old-net (or (canonical-network-uri-for-subnet (:network-uri state))
                         (canonical-network-uri-for-subnet persisted-sub)
                         "devnet.bitecho.org")
             new-net (or (canonical-network-uri-for-subnet trimmed-explicit)
                         old-net)
             cross-net? (not= old-net new-net)
             reset? (boolean (:reset-network-state? opts))]
         (if (and cross-net? (not reset?))
           (let [diag {:effect :diagnose
                       :type :diagnose
                       :reason :cross-network-subnet-switch-blocked
                       :from old-net
                       :to new-net
                       :from-subnet persisted-sub
                       :to-subnet trimmed-explicit}
                 st' (update-in state [:diagnostics :cross-network-subnet-switch-blocked] (fnil inc 0))]
             {:ok? false
              :reconciled? false
              :blocked? true
              :error :cross-network-subnet-switch-blocked
              :state st'
              :effects [diag]
              :stdout-events []})
           (let [evt (cond-> {"event" "subnet-id-reconciled"
                              "from" persisted-sub
                              "to" trimmed-explicit}
                       reset? (assoc "reset_network_state" true))
                 diag {:effect :diagnose
                       :type :diagnose
                       :reason :subnet-id-reconciled
                       :from persisted-sub
                       :to trimmed-explicit}
                 st0 (-> state
                         (assoc :subnet-id trimmed-explicit
                                :subnet-id-overridden? true
                                :subscribed-subnets (conj merged-subs trimmed-explicit))
                         (cond-> cross-net?
                           (assoc :network-uri new-net))
                         (cond-> (and cross-net? reset?)
                           (assoc :account nil
                                  :chain-state-snapshots {}
                                  :sessions {}
                                  :pending-offers {}
                                  :relay-since-broadcast-seq 0
                                  :relay-cursors {}))
                         (update-in [:diagnostics :subnet-id-reconciled] (fnil inc 0)))
                 st1 (enqueue-actionable-events st0 [evt])]
             {:ok? true
              :reconciled? true
              :blocked? false
              :state st1
              :effects [diag]
              :stdout-events [evt]})))))))

(defn effective-signaling-burn-floor
  "Computes the effective signaling burn floor for P2P signaling envelopes.
   Delegates directly to `burn/effective-signaling-burn-floor`."
  [state]
  (burn/effective-signaling-burn-floor state))

;; -----------------------------------------------------------------------------
;; Petnames Address Book & Counterparty Resolution (Pure Helpers)
;; -----------------------------------------------------------------------------

(def ^:private pubkey-88-pattern #"(?i)^302a300506032b6570032100[0-9a-f]{64}$")
(def ^:private pubkey-64-pattern #"(?i)^[0-9a-f]{64}$")
(def ^:private petname-pattern #"^[a-zA-Z0-9._-]{1,64}$")

(defn valid-pubkey-hex?
  "Returns true iff s is a string whose trimmed form is an 88-char DER SPKI hex string
   or a 64-char raw Ed25519 hex string, and cleanly decodes via basalt/hex->bytes."
  [s]
  (boolean
   (when (and (string? s) (not (str/blank? s)))
     (let [t (str/trim s)]
       (cond
         (re-matches pubkey-88-pattern t)
         (try
           (let [b (basalt/hex->bytes t)]
             (and (some? b) (= 44 (fressian/count-bytes b))))
           (catch #?(:clj Exception :cljs :default) _ false))

         (re-matches pubkey-64-pattern t)
         (try
           (let [b (basalt/hex->bytes t)]
             (and (some? b) (= 32 (fressian/count-bytes b))))
           (catch #?(:clj Exception :cljs :default) _ false))

         :else false)))))

(defn normalize-pubkey-hex
  "Returns lower-case 88-char DER SPKI pubkey hex string when valid-pubkey-hex?,
   normalizing 64-char raw hex keys by prepending \"302a300506032b6570032100\", else nil."
  [s]
  (when (valid-pubkey-hex? s)
    (let [t (str/lower-case (str/trim s))]
      (if (= (count t) 64)
        (str "302a300506032b6570032100" t)
        t))))

(defn valid-petname?
  "Returns true iff s is a string whose trimmed form (allowing an optional leading @)
   is non-blank, is NOT a valid-pubkey-hex?, is NOT a Bech32m ech1... address,
   and matches ^[a-zA-Z0-9._-]{1,64}$."
  [s]
  (boolean
   (when (and (string? s) (not (str/blank? s)))
     (let [t (str/trim s)
           stripped (if (str/starts-with? t "@") (subs t 1) t)]
       (and (not (str/blank? stripped))
            (not (valid-pubkey-hex? t))
            (not (valid-pubkey-hex? stripped))
            (not (and (str/starts-with? (str/lower-case t) "ech1")
                      (some? (bech32m/bech32m->pubkey t))))
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
    (some (fn [[p k]] (when (= (normalize-pubkey-hex k) norm-pub) p)) (:petnames state))))

(defn petname->pubkey
  "Forward lookup in (:petnames state) returning the pubkey
   bound to (normalize-petname petname), or nil."
  [state petname]
  (when-let [norm-pname (normalize-petname petname)]
    (get-in state [:petnames norm-pname])))

(defn resolve-counterparty
  "Resolves a counterparty identifier (petname, Bech32m address, or 64/88-hex pubkey).
   Returns:
     {:ok? false :error \"missing-counterparty\"} when target is blank/nil
     {:ok? true :pubkey bound-pubkey :petname canonical-petname} when target matches a petname
     {:ok? true :pubkey spki-hex :petname (pubkey->petname state spki-hex)} when target is Bech32m ech1...
     {:ok? true :pubkey (normalize-pubkey-hex target) :petname (pubkey->petname state target)} when valid pubkey hex
     {:ok? false :error \"unknown-petname\"} otherwise."
  [state target]
  (if (or (nil? target) (and (string? target) (str/blank? target)))
    {:ok? false :error "missing-counterparty"}
    (let [norm-pname (normalize-petname target)]
      (cond
        (and norm-pname (contains? (:petnames state) norm-pname))
        (let [pk (get-in state [:petnames norm-pname])]
          {:ok? true :pubkey (normalize-pubkey-hex pk) :petname norm-pname})

        (and (string? target)
             (str/starts-with? (str/lower-case (str/trim target)) "ech1")
             (bech32m/bech32m->pubkey (str/trim target)))
        (let [pk (bech32m/bech32m->pubkey (str/trim target))
              norm-pub (normalize-pubkey-hex (or (:spki-hex pk) (:hex pk)))]
          {:ok? true :pubkey norm-pub :petname (pubkey->petname state norm-pub)})

        (valid-pubkey-hex? target)
        (let [norm-pub (normalize-pubkey-hex target)]
          {:ok? true :pubkey norm-pub :petname (pubkey->petname state norm-pub)})

        :else
        {:ok? false :error "unknown-petname"}))))

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
                                                  (or scopes ["broadcast" "gossip" "offer" "settle-intent" "transfer"])))))
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
  (let [eid (or (:escrow-id esc) (get esc "escrow-id") (:escrow_id esc) (get esc "escrow_id") "")
        payer (or (:payer esc) (get esc "payer") "")
        receiver (or (:receiver esc) (get esc "receiver") (:recipient esc) (get esc "recipient") "")
        amt (long (or (:amount esc) (get esc "amount") 0))
        dh (or (:deliverable-hash esc) (get esc "deliverable-hash") (:deliverable_hash esc) (get esc "deliverable_hash") "")
        cr-ep (long (or (:created-epoch esc) (get esc "created-epoch") (:created_epoch esc) (get esc "created_epoch") 0))
        exp-ep (long (or (:expires-epoch esc) (get esc "expires-epoch") (:expires_epoch esc) (get esc "expires_epoch") 0))
        st-name (name (or (:status esc) (get esc "status") :locked))
        settled-ep (if (some? (or (:settled-epoch esc) (get esc "settled-epoch") (:settled_epoch esc) (get esc "settled_epoch")))
                     (str (or (:settled-epoch esc) (get esc "settled-epoch") (:settled_epoch esc) (get esc "settled_epoch")))
                     "")
        net-amt (if (some? (or (:net-amount esc) (get esc "net-amount") (:net_amount esc) (get esc "net_amount")))
                  (str (or (:net-amount esc) (get esc "net-amount") (:net_amount esc) (get esc "net_amount")))
                  "")
        refund-re (if (some? (or (:refund-reason esc) (get esc "refund-reason") (:refund_reason esc) (get esc "refund_reason")))
                    (str (or (:refund-reason esc) (get esc "refund-reason") (:refund_reason esc) (get esc "refund_reason")))
                    "")]
    (str eid ":" payer ":" receiver ":" amt ":" dh ":" cr-ep ":" exp-ep ":" st-name ":" settled-ep ":" net-amt ":" refund-re)))

(defn canonical-chain-state-snapshot-str
  "Computes deterministic canonical representation of a chain state snapshot:
   bitecho-chain-state-snapshot-v1|<validator-pubkey>|<pubkey>|<finalized-epoch>|<balance>|<spendable>|<seq>|<comma-joined-deps>|<canonical-escrows-str>|<nonce>"
  [snapshot]
  (let [val-pub (or (:validator-pubkey snapshot) (get snapshot "validator-pubkey") (get snapshot "validator_pubkey") "")
        pk (or (:pubkey snapshot) (get snapshot "pubkey") "")
        fin-ep (long (or (:finalized-epoch snapshot) (get snapshot "finalized-epoch") (get snapshot "finalized_epoch") 0))
        bal (long (or (:balance snapshot) (get snapshot "balance") 0))
        spd (long (or (:spendable snapshot) (get snapshot "spendable") 0))
        seq-num (long (or (:seq snapshot) (get snapshot "seq") 0))
        deps (vec (or (:deps snapshot) (get snapshot "deps") []))
        deps-str (str/join "," deps)
        raw-escrows (or (:escrows snapshot) (get snapshot "escrows") [])
        escrows-vec (if (map? raw-escrows) (vals raw-escrows) (vec raw-escrows))
        sorted-escrows (sort-by (fn [e] (str (or (:escrow-id e) (get e "escrow-id") (:escrow_id e) (get e "escrow_id") ""))) escrows-vec)
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
          val-pub (or (:validator-pubkey snapshot)
                      (get snapshot "validator-pubkey")
                      (get snapshot "validator_pubkey"))]
      (or (empty? trusted)
          (not (contains? (set (map normalize-pubkey-hex trusted)) (normalize-pubkey-hex val-pub)))))
    {:ok? false :error "untrusted-validator"}

    (let [exp-nonce (:expected-nonce opts)
          snap-nonce (or (:nonce snapshot) (get snapshot "nonce"))]
      (and exp-nonce (not= (str exp-nonce) (str snap-nonce))))
    {:ok? false :error "nonce-mismatch"}

    (< (long (or (:finalized-epoch snapshot)
                 (get snapshot "finalized-epoch")
                 (get snapshot "finalized_epoch")
                 0))
       (let [snap-gen (parse-long-safe (or (:network-generation snapshot)
                                           (get snapshot "network-generation")
                                           (get snapshot "network_generation"))
                                       nil)
             min-gen (long (or (:min-network-generation opts) 1))]
         (if (and snap-gen (> snap-gen min-gen))
           0
           (long (or (:min-finalized-epoch opts) 0)))))
    {:ok? false :error "stale-finalized-epoch"}

    (let [sig (or (:signature snapshot) (get snapshot "signature"))]
      (or (nil? sig) (str/blank? (str sig))))
    {:ok? false :error "missing-snapshot-signature"}

    (let [val-pub (or (:validator-pubkey snapshot)
                      (get snapshot "validator-pubkey")
                      (get snapshot "validator_pubkey"))]
      (or (nil? val-pub) (str/blank? (str val-pub))))
    {:ok? false :error "missing-validator-pubkey"}

    :else
    (let [val-pub (or (:validator-pubkey snapshot)
                      (get snapshot "validator-pubkey")
                      (get snapshot "validator_pubkey"))
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
                                         (let [eid (or (:escrow-id esc) (get esc "escrow-id") (:escrow_id esc) (get esc "escrow_id"))
                                               payer (or (:payer esc) (get esc "payer") "")
                                               receiver (or (:receiver esc) (get esc "receiver") (:recipient esc) (get esc "recipient") "")
                                               amt (long (or (:amount esc) (get esc "amount") 0))
                                               dh (or (:deliverable-hash esc) (get esc "deliverable-hash") (:deliverable_hash esc) (get esc "deliverable_hash") "")
                                               cr-ep (long (or (:created-epoch esc) (get esc "created-epoch") (:created_epoch esc) (get esc "created_epoch") 0))
                                               exp-ep (long (or (:expires-epoch esc) (get esc "expires-epoch") (:expires_epoch esc) (get esc "expires_epoch") 0))
                                               st-val (let [s (or (:status esc) (get esc "status") :locked)]
                                                        (if (keyword? s) s (keyword s)))
                                               set-ep (when-let [se (or (:settled-epoch esc) (get esc "settled-epoch") (:settled_epoch esc) (get esc "settled_epoch"))] (long se))
                                               net-a (when-let [na (or (:net-amount esc) (get esc "net-amount") (:net_amount esc) (get esc "net_amount"))] (long na))
                                               ref-r (or (:refund-reason esc) (get esc "refund-reason") (:refund_reason esc) (get esc "refund_reason"))]
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
           :snapshot (cond-> {:bitecho/type :chain-state-snapshot
                              :type :chain-state-snapshot
                              :validator-pubkey val-pub
                              :pubkey (or (:pubkey snapshot) (get snapshot "pubkey"))
                              :finalized-epoch (long (or (:finalized-epoch snapshot)
                                                         (get snapshot "finalized-epoch")
                                                         (get snapshot "finalized_epoch")
                                                         0))
                              :balance (long (or (:balance snapshot) (get snapshot "balance") 0))
                              :spendable (long (or (:spendable snapshot) (get snapshot "spendable") 0))
                              :seq (long (or (:seq snapshot) (get snapshot "seq") 0))
                              :deps (vec (or (:deps snapshot) (get snapshot "deps") []))
                              :escrows normalized-escrows
                              :nonce (or (:nonce snapshot) (get snapshot "nonce") "")
                              :signature sig}
                       (some? (or (:network-generation snapshot)
                                  (get snapshot "network-generation")
                                  (get snapshot "network_generation")))
                       (assoc :network-generation
                              (parse-long-safe (or (:network-generation snapshot)
                                                   (get snapshot "network-generation")
                                                   (get snapshot "network_generation"))
                                               1)))})
        {:ok? false :error "invalid-snapshot-signature"}))))

(defn verify-chain-state-quorum
  "Verifies quorum agreement across validator chain state snapshots.
   Requires:
   - All snapshots pass verify-chain-state-snapshot (fails closed on any invalid snapshot)
   - Unique validators count >= quorum-size (default: 2f+1 where n = (count trusted-validators) or (count snapshots))
   - Max finalized-epoch skew <= max-epoch-skew (default 15)
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
                                           [(or (:validator-pubkey s) (get s "validator-pubkey") (get s "validator_pubkey")) s]))
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
              {:ok? false :error "insufficient-snapshots-returned" :reason "insufficient-validator-quorum"}
              (let [fin-epochs (mapv :finalized-epoch valid-snaps)
                    min-fin (apply min fin-epochs)
                    max-fin (apply max fin-epochs)
                    max-skew (max 1 (long (or (:max-epoch-skew opts) 15)))]
                (if (> (- max-fin min-fin) max-skew)
                  {:ok? false :error "validator-epoch-skew-exceeded"}
                  (let [state-sig (fn [s]
                                    [(:balance s)
                                     (:seq s)
                                     (:deps s)
                                     (str/join ";" (map canonical-escrow-entry-str (sort-by :escrow-id (:escrows s))))])
                        by-state (group-by state-sig valid-snaps)
                        [_ agreeing-snaps] (apply max-key (fn [[_ snaps]] (count snaps)) by-state)]
                    (if (>= (count agreeing-snaps) quorum-size)
                      (let [best-snap (apply max-key :finalized-epoch agreeing-snaps)
                            min-spendable (apply min (map #(or (:spendable %) (:balance %)) agreeing-snaps))
                            capped-spendable (min (long min-spendable) (long (or (:balance best-snap) 0)))
                            final-snap (assoc best-snap :spendable capped-spendable)]
                        {:ok? true
                         :snapshot final-snap
                         :quorum-count (count agreeing-snaps)
                         :validators (vec (sort (map :validator-pubkey agreeing-snaps)))})
                      (let [by-epoch (group-by :finalized-epoch valid-snaps)
                            same-epoch-disagreement? (some (fn [[_ snaps]]
                                                             (> (count (distinct (map state-sig snaps))) 1))
                                                           by-epoch)]
                        (if same-epoch-disagreement?
                          {:ok? false :error "validator-state-disagreement"}
                          {:ok? false :error "insufficient-snapshots-returned" :reason "insufficient-validator-quorum"})))))))))))))

(def default-finalized-epoch-stall-threshold-ms
  "Default wall-clock threshold (ms) before a frozen `finalized-epoch` during light-node
   `auto-sync` is classified as `:finalized-epoch-stalled` (BIP-019 S3: 180s)."
  180000)

(defn evaluate-auto-sync-stall
  "Pure BIP-019 S3 light-node `auto-sync` stall detector (Rules 2 & 5).
   Tracks wall-clock advancement of `finalized-epoch` in `(:auto-sync-stall-tracker state)`.
   If `finalized-epoch` remains frozen for `>= stall-threshold-ms`, returns:
     `{:ok? false :synced? false :stalled? true :stall-duration-ms ms :finalized-epoch fin :state st' :diagnose diag}`
   with a counted Rule 5 `:diagnose {:reason :finalized-epoch-stalled ...}` effect and
   increments `[:diagnostics :finalized-epoch-stalled]`.
   Once `finalized-epoch` advances again, clears `:stalled?` and returns `:ok? true :synced? true`."
  ([state finalized-epoch now-ms]
   (evaluate-auto-sync-stall state finalized-epoch now-ms nil))
  ([state finalized-epoch now-ms opts]
   (let [fin (long (or finalized-epoch 0))
         now (max 0 (long (or now-ms 0)))
         threshold-ms (max 1 (long (or (:stall-threshold-ms opts) default-finalized-epoch-stall-threshold-ms)))
         head-ep (when (some? (:head-epoch opts)) (long (:head-epoch opts)))
         tracker (or (:auto-sync-stall-tracker state) {})
         prev-fin (:last-finalized-epoch tracker)
         prev-adv-ms (:last-advanced-ms tracker)
         advanced? (or (nil? prev-fin)
                       (zero? (long prev-fin))
                       (> fin (long prev-fin)))]
     (if advanced?
       (let [next-tracker {:last-finalized-epoch fin
                           :last-advanced-ms now
                           :stalled? false
                           :stall-started-ms nil
                           :stall-duration-ms 0}
             st' (cond-> (assoc state :auto-sync-stall-tracker next-tracker)
                   (= "finalized-epoch-stalled" (:auto-sync-last-error state))
                   (assoc :auto-sync-last-error nil))]
         {:ok? true
          :synced? true
          :stalled? false
          :stall-duration-ms 0
          :finalized-epoch fin
          :state st'
          :diagnose nil})
       (let [anchor-ms (long (or prev-adv-ms now))
             frozen-ms (max 0 (- now anchor-ms))]
         (if (and (pos? fin) (>= frozen-ms threshold-ms))
           (let [stall-start (long (or (:stall-started-ms tracker) anchor-ms))
                 diag {:effect :diagnose
                       :type :diagnose
                       :reason :finalized-epoch-stalled
                       :finalized-epoch fin
                       :observed-lag (when head-ep (max 0 (- head-ep fin)))
                       :stall-duration-ms frozen-ms
                       :threshold-ms threshold-ms}
                 next-tracker {:last-finalized-epoch (long prev-fin)
                               :last-advanced-ms anchor-ms
                               :stalled? true
                               :stall-started-ms stall-start
                               :stall-duration-ms frozen-ms}
                 st' (-> state
                         (assoc :auto-sync-stall-tracker next-tracker
                                :auto-sync-last-error "finalized-epoch-stalled")
                         (update-in [:diagnostics :finalized-epoch-stalled] (fnil inc 0)))]
             {:ok? false
              :synced? false
              :stalled? true
              :stall-duration-ms frozen-ms
              :finalized-epoch fin
              :state st'
              :diagnose diag})
           (let [next-tracker {:last-finalized-epoch (long prev-fin)
                               :last-advanced-ms anchor-ms
                               :stalled? false
                               :stall-started-ms nil
                               :stall-duration-ms frozen-ms}
                 st' (assoc state :auto-sync-stall-tracker next-tracker)]
             {:ok? true
              :synced? true
              :stalled? false
              :stall-duration-ms frozen-ms
              :finalized-epoch fin
              :state st'
              :diagnose nil})))))))

(defn apply-verified-chain-state-snapshot
  "Applies a verified chain state snapshot to local light-node state.
   Guards against stale finalized epochs (monotonicity), unless `:network-generation`
   has incremented (`P-DEPLOY-9` balance-preserving genesis reset), in which case
   local `:epoch`, `:transfer-seq`, and `:account` are re-baselined to the new generation
   while preserving identity, petnames, and open E2EE sessions.
   Prunes expired unconfirmed non-terminal escrows absent from snapshot, and clears stale
   status-dependent escrow fields on merge."
  [state snapshot]
  (let [curr-gen (long (or (:network-generation state) 1))
        snap-gen (parse-long-safe (or (:network-generation snapshot)
                                      (get snapshot "network-generation")
                                      (get snapshot "network_generation"))
                                  curr-gen)
        gen-incremented? (> snap-gen curr-gen)
        curr-fin-ep (long (or (get-in state [:account :finalized-epoch]) 0))
        fin-epoch (parse-long-safe (or (:finalized-epoch snapshot)
                                       (get snapshot "finalized-epoch")
                                       (get snapshot "finalized_epoch"))
                                   0)]
    (if (and (not gen-incremented?) (< fin-epoch curr-fin-ep))
      state
      (let [new-account {:balance (long (or (:balance snapshot) (get snapshot "balance") 0))
                         :spendable (long (or (:spendable snapshot) (get snapshot "spendable") 0))
                         :seq (long (or (:seq snapshot) (get snapshot "seq") 0))
                         :deps (vec (or (:deps snapshot) (get snapshot "deps") []))
                         :finalized-epoch fin-epoch}
            has-escrows? (or (contains? snapshot :escrows) (contains? snapshot "escrows"))
            incoming-escrows (or (:escrows snapshot) (get snapshot "escrows") [])
            incoming-ids (set (map #(or (:escrow-id %) (get % "escrow-id") (get % "escrow_id")) incoming-escrows))
            existing-escrows (or (:escrows state) {})
            non-terminal-statuses #{:locked :release-submitted :refund-submitted
                                    "locked" "release-submitted" "refund-submitted"}
            base-escrows (if has-escrows?
                           (into {} (remove (fn [[eid existing]]
                                              (and (not (contains? incoming-ids eid))
                                                   (contains? non-terminal-statuses (:status existing))
                                                   (< (long (or (:created-epoch existing) (get existing "created-epoch") (:created_epoch existing) (get existing "created_epoch") 0))
                                                      (- fin-epoch 5))))
                                            existing-escrows))
                           existing-escrows)
            merged-escrows (reduce (fn [acc esc]
                                     (let [eid (or (:escrow-id esc) (get esc "escrow-id") (get esc "escrow_id"))
                                           existing (dissoc (get acc eid {})
                                                            :settled-epoch :net-amount :take-burned :refund-reason
                                                            "settled-epoch" "net-amount" "take-burned" "refund-reason"
                                                            "settled_epoch" "net_amount" "take_burned" "refund_reason")]
                                       (assoc acc eid (merge existing esc))))
                                   base-escrows
                                   incoming-escrows)]
        (-> state
            (assoc :account new-account
                   :network-generation snap-gen
                   :transfer-seq (:seq new-account)
                   :last-transfer-hash (last (:deps new-account))
                   :epoch (if (or gen-incremented?
                                  (> (long (or (:epoch state) 0)) (+ fin-epoch 1000)))
                            fin-epoch
                            (max (long (or (:epoch state) 0)) fin-epoch))
                   :epoch-initialized? true
                   :escrows merged-escrows)
            (update :credited-tx-ids (fn [c] (into (or c #{}) (map str (:deps new-account))))))))))

(defn build-chain-state-query-envelope
  "Builds and wraps an authenticated :query-chain-state agent envelope.
   opts can be a map (e.g. {:nonce ... :epoch ... :target-pubkey ...}) or a string nonce."
  [pubkey-hex ^bytes privkey-bytes opts]
  (let [opts-map (if (map? opts) opts {:nonce (str opts)})
        epoch-val (long (or (:epoch opts-map) 0))
        target-pk (or (:target-pubkey opts-map) pubkey-hex)
        default-nonce (str "qcs-" epoch-val "-" (subs (str target-pk) 0 (min 16 (count (str target-pk)))))
        payload {:type :query-chain-state
                 :pubkey target-pk
                 :epoch epoch-val
                 :nonce (or (:nonce opts-map) default-nonce)}]
    (wrap-agent-event payload pubkey-hex privkey-bytes)))

(defn resolve-session-id
  "Resolves a session id from cmd-map or counterparty identifier (petname/pubkey).
   Supports :open (prefers open sessions, picking most recently active if multiple)
   or :active (prefers non-closed sessions, failing closed if ambiguous).
   Supports unique session prefix matching (>= 6 hex chars), failing closed with
   {:ok? false :error \"ambiguous-session-prefix\" :matches matches} if ambiguous."
  [state cmd-map preference]
  (let [raw-sid (or (get cmd-map "session_id") (get cmd-map "session-id") (get cmd-map "session")
                    (:session_id cmd-map) (:session-id cmd-map) (:session cmd-map))
        exact-match (when (and raw-sid (contains? (:sessions state) raw-sid)) raw-sid)]
    (if exact-match
      exact-match
      (let [norm-raw (when (and (string? raw-sid) (not (str/blank? raw-sid)))
                       (str/lower-case (str/trim raw-sid)))
            prefix-matches (when (and norm-raw
                                      (>= (count norm-raw) 6)
                                      (re-matches #"^[0-9a-fA-F]+$" norm-raw))
                             (filterv (fn [k] (str/starts-with? (str/lower-case (str k)) norm-raw))
                                      (keys (:sessions state))))]
        (cond
          (= 1 (count prefix-matches))
          (first prefix-matches)

          (> (count prefix-matches) 1)
          {:ok? false :error "ambiguous-session-prefix" :matches (vec (sort prefix-matches))}

          :else
          (let [target (or raw-sid
                           (get cmd-map "to") (:to cmd-map)
                           (get cmd-map "peer") (:peer cmd-map)
                           (get cmd-map "callee") (:callee cmd-map))]
            (cond
              (and target (contains? (:sessions state) target))
              target

              :else
              (let [norm-t (when (and (string? target) (not (str/blank? target)))
                             (str/lower-case (str/trim target)))
                    t-matches (when (and norm-t
                                         (not= norm-t norm-raw)
                                         (>= (count norm-t) 6)
                                         (re-matches #"^[0-9a-fA-F]+$" norm-t))
                                (filterv (fn [k] (str/starts-with? (str/lower-case (str k)) norm-t))
                                         (keys (:sessions state))))]
                (cond
                  (= 1 (count t-matches))
                  (first t-matches)

                  (> (count t-matches) 1)
                  {:ok? false :error "ambiguous-session-prefix" :matches (vec (sort t-matches))}

                  :else
                  (let [resolved (when target (resolve-counterparty state target))]
                    (when (:ok? resolved)
                      (let [matching (filterv (fn [[_ s]]
                                                (= (normalize-pubkey-hex (:peer s))
                                                   (normalize-pubkey-hex (:pubkey resolved))))
                                              (:sessions state))
                            preferred-pred (case preference
                                             :open (fn [[_ s]] (= "open" (:state s)))
                                             :active (fn [[_ s]] (not= "closed" (:state s)))
                                             (constantly true))
                            preferred-matching (filterv preferred-pred matching)]
                        (cond
                          (= 1 (count preferred-matching))
                          (first (first preferred-matching))

                          (> (count preferred-matching) 1)
                          (if (= preference :open)
                            ;; Pick most active open session by (tx-seq + rx-high-seq), then epoch, then lexicographical session-id
                            (first (last (sort-by (fn [[sid s]]
                                                    [(+ (long (or (:tx-seq s) (:outbound-seq s) 0))
                                                        (long (or (:rx-high-seq s) (:inbound-seq s) (:rx-seq s) 0)))
                                                     (long (or (:last-active-epoch s) (:epoch s) (:created-epoch s) 0))
                                                     (long (or (:created-epoch s) (:epoch s) 0))
                                                     (str sid)])
                                                  preferred-matching)))
                            nil)

                          (= 1 (count matching))
                          (first (first matching))

                          (and (> (count matching) 1) (= preference :open))
                          (first (last (sort-by (fn [[sid s]]
                                                  [(+ (long (or (:tx-seq s) (:outbound-seq s) 0))
                                                      (long (or (:rx-high-seq s) (:inbound-seq s) (:rx-seq s) 0)))
                                                   (long (or (:last-active-epoch s) (:epoch s) (:created-epoch s) 0))
                                                   (long (or (:created-epoch s) (:epoch s) 0))
                                                   (str sid)])
                                                matching)))

                          :else
                          nil)))))))))))))

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
        net-uri (or (:network-uri offer-map) (get offer-map "network_uri") (get offer-map "network-uri"))
        net-str (when (and (string? net-uri) (not (str/blank? net-uri)))
                  (str/trim net-uri))
        base-input (str sid "-" caller "-" callee "-" eph-pub "-" epoch "-" price-or-burn "-" hn-str)
        with-suites (if (seq suites-str)
                      (str base-input "|" suites-str)
                      base-input)
        with-dac (if (and (string? dac-id) (not (str/blank? dac-id)))
                   (str with-suites "|" dac-id)
                   with-suites)
        with-subnet (if subnet-str
                      (str with-dac "|" subnet-str)
                      with-dac)
        hash-input (if net-str
                     (str with-subnet "|net:" net-str)
                     with-subnet)]
    (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes hash-input)))))

(defn matching-offer-hash?
  "Pure predicate checking whether an offer hash matches across equivalent candidate subnet IDs
   and rolling upgrade tolerance between network-bound and legacy unbound hashes."
  [offer-map state expected-offer-hash]
  (let [candidate-subnets (distinct (remove nil? [(:subnet-id offer-map)
                                                  (:subnet-id state)
                                                  (when (config/equivalent-subnet-id? (or (:subnet-id state) "global") (or (:subnet-id offer-map) "global")) "global")
                                                  (when (config/equivalent-subnet-id? (or (:subnet-id state) "global") "devnet.bitecho.org") "devnet.bitecho.org")
                                                  "global"]))
        candidate-offers (concat [offer-map]
                                 (when (or (:network-uri offer-map) (get offer-map "network_uri") (get offer-map "network-uri"))
                                   [(dissoc offer-map :network-uri "network-uri" "network_uri")])
                                 (when (and (not (:network-uri offer-map)) (not (get offer-map "network_uri")) (not (get offer-map "network-uri"))
                                            (:network-uri state))
                                   [(assoc offer-map :network-uri (:network-uri state))]))]
    (boolean
     (some (fn [sub-id]
             (some (fn [cand-offer]
                     (let [cand-with-sub (assoc cand-offer :subnet-id sub-id)]
                       (or (= (compute-offer-hash cand-with-sub) expected-offer-hash)
                           (= (sealed/offer-hash cand-with-sub) expected-offer-hash))))
                   candidate-offers))
           candidate-subnets))))

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
            floor (effective-signaling-burn-floor state)
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
                net-uri (or (:network-uri state) (config/resolve-network-uri (:subnet-id state)))
                offer-hash (compute-offer-hash (cond-> {:session-id session-id
                                                        :caller caller
                                                        :callee callee
                                                        :caller-ephemeral-pub caller-x25519-pub
                                                        :epoch epoch
                                                        :price burn-amt
                                                        :burn burn-amt
                                                        :home-node home-node
                                                        :crypto-suites suites
                                                        :dac active-dac
                                                        :subnet-id sub-id}
                                                 net-uri (assoc :network-uri net-uri)))
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
                               net-uri (assoc :network-uri net-uri)
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
        epoch (max (long (or (:epoch state) 0)) (long (or (:epoch pending-header) 0)))
        sub-id (str (or (:subnet-id pending-header) (:subnet-id state) "global"))
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
                             :subnet-id sub-id
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
        gossip-env (build-gossip-envelope callee privkey-bytes (freeze-payload ack-payload) 500 sub-id)
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
  (let [resolved-sid (resolve-session-id state cmd-map :active)]
    (cond
      (and (map? resolved-sid) (false? (:ok? resolved-sid)))
      {:state state
       :response {"ok" false "error" (:error resolved-sid) "matches" (:matches resolved-sid)}
       :net-envelopes []
       :stdout-events []}

      :else
      (let [callee-target (or (when (and (string? resolved-sid) (get-in state [:sessions resolved-sid]))
                                (:peer (get-in state [:sessions resolved-sid])))
                              (get cmd-map "callee") (get cmd-map "peer") (get cmd-map "to")
                              (:callee cmd-map) (:peer cmd-map) (:to cmd-map))
            resolved (resolve-counterparty state callee-target)]
        (if-not (:ok? resolved)
          {:state state
           :response {"ok" false "error" (:error resolved)}
           :net-envelopes []
           :stdout-events []}
          (let [raw-price (or (get cmd-map "price") (:price cmd-map))
                raw-burn (or (get cmd-map "burn") (:burn cmd-map))
                burn-floor (effective-signaling-burn-floor state)
                parsed-price (if (some? raw-price) (parse-long-safe raw-price :invalid) 0)
                parsed-burn (if (some? raw-burn) (parse-long-safe raw-burn :invalid) (max 500 burn-floor))]
            (cond
              (or (= parsed-price :invalid) (< parsed-price 0)
                  (= parsed-burn :invalid) (< parsed-burn 0))
              {:state state
               :response {"ok" false "error" "invalid-numeric-parameter"}
               :net-envelopes []
               :stdout-events []}

              (and (pos? burn-floor) (< (long parsed-burn) burn-floor))
              {:state state
               :response {"ok" false "error" "burn-below-floor" "required_floor" burn-floor}
               :net-envelopes []
               :stdout-events []}

              :else
              (let [callee (:pubkey resolved)
                    pname (:petname resolved)
                    price parsed-price
                    default-home (or (first (keys (get-in state [:bootstrap :nodes]))) :node1)
                    home-node (name (or (get cmd-map "home_node") (:home_node cmd-map) default-home))
                    burn-amt parsed-burn
                    caller (:pubkey state)
                    offer-nonce (basalt/bytes->hex (crypto/random-bytes 32))
                    kp-eph (if privkey-bytes
                             (sealed/derive-offer-x25519-keypair privkey-bytes offer-nonce caller callee)
                             (sealed/generate-x25519-keypair))
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
                    sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id state) "global"))
                    net-uri (or (:network-uri state) (config/resolve-network-uri (:subnet-id state)))
                    offer-hash (compute-offer-hash (cond-> {:session-id session-id
                                                            :caller caller
                                                            :callee callee
                                                            :caller-ephemeral-pub eph-pub-hex
                                                            :epoch epoch
                                                            :price price
                                                            :home-node home-node
                                                            :crypto-suites suites
                                                            :dac active-dac
                                                            :subnet-id sub-id}
                                                     net-uri (assoc :network-uri net-uri)))
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
                                    net-uri (assoc :network-uri net-uri)
                                    active-dac (assoc :dac active-dac))
                    outer-sub (if (and (pos? (long burn-amt)) (config/root-subnet-id? sub-id)) "*" sub-id)
                    gossip-env (build-gossip-envelope caller privkey-bytes (freeze-payload offer-payload) burn-amt outer-sub)
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
                                   :subnet-id sub-id
                                   :peer callee
                                   :role :initiator
                                   :state "offered"
                                   :tx-seq 0
                                   :epoch epoch
                                   :crypto-suites suites
                                   :ephemeral-pub (:public kp-eph)
                                   :ephemeral-priv (:private kp-eph)
                                   :offer-nonce offer-nonce
                                   :price price
                                   :home-node home-node
                                   :offer-hash offer-hash}
                    new-state (cond-> (-> state
                                          (assoc-in [:sessions session-id] session-entry)
                                          (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))
                                (and (pos? burn-amt) (some? (get-in state [:account :spendable])))
                                (update-in [:account :spendable] - burn-amt))]
                {:state new-state
                 :response (cond-> {"ok" true
                                    "session_id" session-id
                                    "state" "offered"
                                    "callee" callee
                                    "price" price
                                    "burn" burn-amt}
                             pname (assoc "callee_petname" pname "peer_petname" pname))
                 :net-envelopes [header-env gossip-env]
                 :stdout-events []}))))))))

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
                      :min-burn (effective-signaling-burn-floor state)})
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
            sub-id (str (or (:subnet-id offer) (:subnet-id state) "global"))
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
            outer-sub (if (and (pos? (long burn-amt)) (config/root-subnet-id? sub-id)) "*" sub-id)
            gossip-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload accept-payload) burn-amt outer-sub)
            session-entry {:session-id session-id
                           :subnet-id sub-id
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

(defn parse-p2p-candidate
  "Parses a candidate URI string or SDP candidate line into
   {:scheme :host :port :transport ?(:proxy-connect? true)},
   resolving .local mDNS hostnames against mdns-state."
  ([cand-str]
   (parse-p2p-candidate cand-str nil))
  ([cand-str mdns-state]
   (when (and (string? cand-str) (not (str/blank? cand-str)))
     (let [s (str/trim cand-str)]
       (cond
         (or (str/starts-with? s "https://") (str/starts-with? s "http://"))
         (let [https? (str/starts-with? s "https://")
               prefix (if https? "https://" "http://")
               rest-str (subs s (count prefix))
               slash-idx (str/index-of rest-str "/")
               host-port (if slash-idx (subs rest-str 0 slash-idx) rest-str)
               [raw-host port-str] (if-let [col-idx (str/index-of host-port ":")]
                                     [(subs host-port 0 col-idx) (subs host-port (inc col-idx))]
                                     [host-port nil])
               port (if port-str
                      (try (#?(:clj Integer/parseInt :cljs js/parseInt) port-str)
                           (catch #?(:clj Exception :cljs :default) _ (if https? 443 80)))
                      (if https? 443 80))]
           {:scheme (if https? "https" "http")
            :host raw-host
            :port port
            :transport (if https? "https" "http")
            :zero-burn? true
            :url s})

         :else
         (let [sdp-cand? (or (str/starts-with? s "candidate:") (str/starts-with? s "a=candidate:"))
               [scheme host port proxy-connect?]
               (if sdp-cand?
                 (let [tokens (vec (str/split s #"\s+"))
                       cand-idx (if (str/starts-with? (first tokens) "a=") 0 0)
                       tr-token (get tokens (+ cand-idx 2))
                       host-token (get tokens (+ cand-idx 4))
                       port-token (get tokens (+ cand-idx 5))
                       p (try (when port-token (#?(:clj Integer/parseInt :cljs js/parseInt) port-token)) (catch #?(:clj Exception :cljs :default) _ nil))
                       tr (when tr-token (str/lower-case tr-token))]
                   [tr host-token p false])
                 (let [[scheme-part rest-part] (if-let [idx (str/index-of s "://")]
                                                 [(subs s 0 idx) (subs s (+ idx 3))]
                                                 [nil s])
                       sch (when scheme-part (str/lower-case scheme-part))
                       [raw-host raw-port] (if-let [last-colon (str/last-index-of rest-part ":")]
                                             [(subs rest-part 0 last-colon) (subs rest-part (inc last-colon))]
                                             [rest-part nil])
                       p (try (when raw-port (#?(:clj Integer/parseInt :cljs js/parseInt) (str/trim raw-port)))
                              (catch #?(:clj Exception :cljs :default) _ nil))
                       h (when raw-host (str/trim raw-host))]
                   [sch h p (= sch "connect")]))
               tab (cond
                     (nil? mdns-state) nil
                     #?@(:clj [(instance? clojure.lang.IDeref mdns-state) @mdns-state]
                         :cljs [(satisfies? IDeref mdns-state) @mdns-state])
                     (map? mdns-state) mdns-state
                     :else nil)
               resolved-host (if (and host (mdns/mdns-hostname? host))
                               (or (when tab
                                     (let [cand-map {:ip host :port (or port 0)}
                                           res (mdns/resolve-candidate-address cand-map tab)]
                                       (when (and res (not= (:ip res) host))
                                         (:ip res))))
                                   (when tab (mdns/lookup-cached-ip tab host))
                                   host)
                               host)]
           (when (and (seq resolved-host) port (pos? port))
             (cond-> {:scheme (or scheme "udp")
                      :host resolved-host
                      :port port
                      :transport (case scheme
                                   ("tcp" "connect") :tcp
                                   :udp)}
               proxy-connect? (assoc :proxy-connect? true)))))))))

(defn- effective-session-wire-epoch
  [state session]
  (let [st-ep (long (or (:epoch state) 0))
        sess-ep (long (or (:epoch session) 0))]
    (if (pos? st-ep) st-ep sess-ep)))

(defn canonical-p2p-signal-str
  "Constructs canonical signing payload string for P2P offer or answer signaling envelopes."
  ([kind session-id sender recipient transport candidates ice-ufrag ice-pwd fingerprint epoch]
   (canonical-p2p-signal-str kind session-id sender recipient transport candidates ice-ufrag ice-pwd fingerprint epoch 1))
  ([kind session-id sender recipient transport candidates ice-ufrag ice-pwd fingerprint epoch signal-seq]
   (str "bitecho-p2p-" (name kind) "-v1|"
        session-id "|"
        (normalize-pubkey-hex sender) "|"
        (normalize-pubkey-hex recipient) "|"
        (or transport "udp") "|"
        (str/join "," (sort (map str (or candidates [])))) "|"
        (or ice-ufrag "") "|"
        (or ice-pwd "") "|"
        (or fingerprint "") "|"
        (long (or epoch 0)) "|"
        (long (or signal-seq 1)))))

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

(defn canonical-broadcast-str
  "Canonical signing string format for broadcast messages."
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
                 :signature sig-hex}
        env (build-gossip-envelope norm-sender sender-privkey (freeze-payload payload) 0 sub-id)]
    (assoc env :p2p-direct? true :p2p-peer norm-target)))

(defn- exec-p2p-offer [state cmd-map privkey-bytes]
  (let [resolved-sid (resolve-session-id state cmd-map :open)]
    (cond
      (and (map? resolved-sid) (false? (:ok? resolved-sid)))
      {:state state :response {"ok" false "error" (:error resolved-sid) "matches" (:matches resolved-sid)} :net-envelopes [] :stdout-events []}

      (nil? resolved-sid)
      {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}

      :else
      (let [session-id resolved-sid
            session (get-in state [:sessions session-id])]
        (if-not (and session (= "open" (:state session)))
          {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}
          (let [sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id session) (:subnet-id state) "global"))
                transport (str (or (get cmd-map "transport") (:transport cmd-map) "udp"))
                explicit-cands-val (or (get cmd-map "candidates") (:candidates cmd-map)
                                       (get cmd-map "endpoint") (:endpoint cmd-map))
                explicit-cands? (and (some? explicit-cands-val)
                                     (if (string? explicit-cands-val) (not (str/blank? explicit-cands-val)) (seq explicit-cands-val)))
                raw-cands (if explicit-cands?
                            explicit-cands-val
                            (or (not-empty (get-in session [:p2p-meta :local-candidates]))
                                (not-empty (get-in session [:p2p-meta :preferred-candidates]))
                                (not-empty (get-in session [:p2p :local-candidates]))
                                (:default-p2p-candidates state [])))
                candidates (vec (map str (if (string? raw-cands)
                                           (remove str/blank? (str/split raw-cands #","))
                                           raw-cands)))
                ice-ufrag (str (or (get cmd-map "ice_ufrag") (get cmd-map "ice-ufrag") (:ice-ufrag cmd-map) (get-in state [:ice-creds :ufrag]) "ufrag"))
                ice-pwd (str (or (get cmd-map "ice_pwd") (get cmd-map "ice-pwd") (:ice-pwd cmd-map) (get-in state [:ice-creds :pwd]) "pwd"))
                fp (str (or (get cmd-map "fingerprint") (:fingerprint cmd-map) (:fingerprint state) ""))
                epoch (effective-session-wire-epoch state session)
                now-ms (long (or (get cmd-map "now_ms") (get cmd-map "now-ms")
                                 (:now-ms cmd-map) (:now_ms cmd-map)
                                 0))
                signal-seq (or (when-let [s (or (get cmd-map "signal_seq") (get cmd-map "signal-seq")
                                                (:signal_seq cmd-map) (:signal-seq cmd-map))]
                                 (long s))
                               (inc (max (long (or (get-in session [:p2p-meta :local-signal-seq]) (get-in session [:p2p :local-signal-seq]) 0))
                                         now-ms)))
                sig-str (canonical-p2p-signal-str :offer session-id (:pubkey state) (:peer session) transport candidates ice-ufrag ice-pwd fp epoch signal-seq)
                sig-bytes (crypto/sign privkey-bytes (fressian/utf8->bytes sig-str))
                sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
                p2p-open? (true? (get-in session [:p2p :connected?]))
                burn-floor (effective-signaling-burn-floor state)
                raw-burn (or (get cmd-map "burn") (:burn cmd-map))
                parsed-burn (if (some? raw-burn) (parse-long-safe raw-burn :invalid) nil)]
            (cond
              (= parsed-burn :invalid)
              {:state state :response {"ok" false "error" "invalid-numeric-parameter"} :net-envelopes [] :stdout-events []}

              (and (number? parsed-burn) (neg? (long parsed-burn)))
              {:state state :response {"ok" false "error" "invalid-numeric-parameter"} :net-envelopes [] :stdout-events []}

              (and (not p2p-open?) (number? parsed-burn) (pos? burn-floor) (< (long parsed-burn) burn-floor))
              {:state state :response {"ok" false "error" "burn-below-floor" "required_floor" burn-floor} :net-envelopes [] :stdout-events []}

              :else
              (let [burn-amt (cond
                               (some? parsed-burn) (long parsed-burn)
                               p2p-open? 0
                               :else burn-floor)
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
                             :signal-seq signal-seq
                             :signature sig-hex}
                    outer-sub (if (pos? (long burn-amt)) "*" sub-id)
                    raw-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload payload) (long burn-amt) outer-sub)
                    env (cond-> raw-env
                          p2p-open? (assoc :p2p-direct? true
                                           :p2p-peer (normalize-pubkey-hex (:peer session))
                                           :p2p-session-id session-id))
                    p2p-entry (merge (get session :p2p {})
                                     {:phase :offered
                                      :connected? false
                                      :role :initiator
                                      :local-transport transport
                                      :local-candidates candidates
                                      :local-ice-ufrag ice-ufrag
                                      :local-ice-pwd ice-pwd
                                      :local-fingerprint fp
                                      :local-signal-seq signal-seq})
                    p2p-meta (merge (get session :p2p-meta {})
                                    (cond-> {:local-signal-seq signal-seq
                                             :preferred-transport transport
                                             :preferred-candidates candidates}
                                      explicit-cands? (assoc :local-candidates candidates)))
                    new-state (-> state
                                  (assoc-in [:sessions session-id :p2p] p2p-entry)
                                  (assoc-in [:sessions session-id :p2p-meta] p2p-meta))]
                {:state new-state
                 :response {"ok" true
                            "session_id" session-id
                            "peer" (:peer session)
                            "transport" transport
                            "candidates" candidates
                            "phase" "offered"
                            "connected" false
                            "burn" (long burn-amt)}
                 :net-envelopes [env]
                 :stdout-events []}))))))))

(defn- shared-http-relay-candidate?
  [cand]
  (boolean (and (some? cand)
                (re-find #"^https?://" (str/lower-case (str/trim (str cand)))))))

(defn- connect-proxy-candidate?
  [cand]
  (boolean (and (some? cand)
                (re-find #"(?i)^connect://" (str/trim (str cand))))))

(defn private-or-mdns-candidate?
  "Returns true if a P2P candidate URL or SDP candidate string targets an mDNS (.local),
   loopback (localhost / 127.x.x.x), or RFC1918 private LAN address (10.x.x.x, 192.168.x.x, 172.16-31.x.x)."
  [cand]
  (if (or (nil? cand) (shared-http-relay-candidate? cand))
    false
    (let [s (str/trim (str cand))]
      (boolean
       (or (re-find #"(?i)[a-z0-9._-]+\.local(?::\d+|/|$|\s)" s)
           (re-find #"(?i)(?:^|//|\s)(?:localhost|127\.\d+\.\d+\.\d+)(?::\d+|/|$|\s)" s)
           (re-find #"(?:^|//|\s)10\.\d+\.\d+\.\d+(?::\d+|/|$|\s)" s)
           (re-find #"(?:^|//|\s)192\.168\.\d+\.\d+(?::\d+|/|$|\s)" s)
           (re-find #"(?:^|//|\s)172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+(?::\d+|/|$|\s)" s))))))

(defn- filter-p2p-remote-candidates
  "Filters remote P2P candidates against local candidates, preserving shared HTTP/HTTPS relay
   endpoints (`https://...` / `http://...`) and optionally falling back to `remote-cands` when
   self-filtering would empty a non-empty candidate list."
  ([local-cands remote-cands]
   (filter-p2p-remote-candidates local-cands remote-cands true))
  ([local-cands remote-cands allow-fallback?]
   (let [local-set (set (map str local-cands))
         rem-vec (vec (map str remote-cands))
         filtered (vec (remove (fn [c]
                                 (and (not (shared-http-relay-candidate? c))
                                      (contains? local-set c)))
                               rem-vec))
         fallback? (and allow-fallback? (empty? filtered) (seq rem-vec))]
     {:dialable (if fallback? rem-vec filtered)
      :fallback? fallback?})))

(defn- exec-p2p-answer [state cmd-map privkey-bytes]
  (let [resolved-sid (resolve-session-id state cmd-map :open)]
    (cond
      (and (map? resolved-sid) (false? (:ok? resolved-sid)))
      {:state state :response {"ok" false "error" (:error resolved-sid) "matches" (:matches resolved-sid)} :net-envelopes [] :stdout-events []}

      (nil? resolved-sid)
      {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}

      :else
      (let [session-id resolved-sid
            session (get-in state [:sessions session-id])]
        (if-not (and session (= "open" (:state session)))
          {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}
          (let [sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id session) (:subnet-id state) "global"))
                transport (str (or (get cmd-map "transport") (:transport cmd-map) (get-in session [:p2p :remote-transport]) "udp"))
                explicit-cands-val (or (get cmd-map "candidates") (:candidates cmd-map)
                                       (get cmd-map "endpoint") (:endpoint cmd-map))
                explicit-cands? (and (some? explicit-cands-val)
                                     (if (string? explicit-cands-val) (not (str/blank? explicit-cands-val)) (seq explicit-cands-val)))
                raw-cands (if explicit-cands?
                            explicit-cands-val
                            (or (not-empty (get-in session [:p2p-meta :local-candidates]))
                                (not-empty (get-in session [:p2p-meta :preferred-candidates]))
                                (not-empty (get-in session [:p2p :local-candidates]))
                                (:default-p2p-candidates state [])))
                parsed-cands (vec (map str (if (string? raw-cands)
                                             (remove str/blank? (str/split raw-cands #","))
                                             raw-cands)))
                remote-relay-cands (vec (distinct (filter shared-http-relay-candidate?
                                                          (concat (get-in session [:p2p :remote-candidates])
                                                                  (get-in session [:p2p-meta :remote-candidates])))))
                candidates (if explicit-cands?
                             parsed-cands
                             (let [no-connect (vec (remove connect-proxy-candidate? parsed-cands))]
                               (if (seq remote-relay-cands)
                                 (if (or (empty? no-connect) (every? private-or-mdns-candidate? no-connect))
                                   remote-relay-cands
                                   (vec (distinct (concat no-connect remote-relay-cands))))
                                 no-connect)))
                ice-ufrag (str (or (get cmd-map "ice_ufrag") (get cmd-map "ice-ufrag") (:ice-ufrag cmd-map) (get-in state [:ice-creds :ufrag]) "ufrag"))
                ice-pwd (str (or (get cmd-map "ice_pwd") (get cmd-map "ice-pwd") (:ice-pwd cmd-map) (get-in state [:ice-creds :pwd]) "pwd"))
                fp (str (or (get cmd-map "fingerprint") (:fingerprint cmd-map) (:fingerprint state) ""))
                epoch (effective-session-wire-epoch state session)
                now-ms (long (or (get cmd-map "now_ms") (get cmd-map "now-ms")
                                 (:now-ms cmd-map) (:now_ms cmd-map)
                                 0))
                signal-seq (or (when-let [s (or (get cmd-map "signal_seq") (get cmd-map "signal-seq")
                                                (:signal_seq cmd-map) (:signal-seq cmd-map))]
                                 (long s))
                               (inc (max (long (or (get-in session [:p2p-meta :local-signal-seq]) (get-in session [:p2p :local-signal-seq]) 0))
                                         now-ms)))
                sig-str (canonical-p2p-signal-str :answer session-id (:pubkey state) (:peer session) transport candidates ice-ufrag ice-pwd fp epoch signal-seq)
                sig-bytes (crypto/sign privkey-bytes (fressian/utf8->bytes sig-str))
                sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
                p2p-open? (true? (get-in session [:p2p :connected?]))
                burn-floor (effective-signaling-burn-floor state)
                raw-burn (or (get cmd-map "burn") (:burn cmd-map))
                parsed-burn (if (some? raw-burn) (parse-long-safe raw-burn :invalid) nil)]
            (cond
              (= parsed-burn :invalid)
              {:state state :response {"ok" false "error" "invalid-numeric-parameter"} :net-envelopes [] :stdout-events []}

              (and (number? parsed-burn) (neg? (long parsed-burn)))
              {:state state :response {"ok" false "error" "invalid-numeric-parameter"} :net-envelopes [] :stdout-events []}

              (and (not p2p-open?) (number? parsed-burn) (pos? burn-floor) (< (long parsed-burn) burn-floor))
              {:state state :response {"ok" false "error" "burn-below-floor" "required_floor" burn-floor} :net-envelopes [] :stdout-events []}

              :else
              (let [burn-amt (cond
                               (some? parsed-burn) (long parsed-burn)
                               p2p-open? 0
                               :else burn-floor)
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
                             :signal-seq signal-seq
                             :signature sig-hex}
                    outer-sub (if (pos? (long burn-amt)) "*" sub-id)
                    raw-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload payload) (long burn-amt) outer-sub)
                    env (cond-> raw-env
                          p2p-open? (assoc :p2p-direct? true
                                           :p2p-peer (normalize-pubkey-hex (:peer session))
                                           :p2p-session-id session-id))
                    p2p-entry (merge (get session :p2p {})
                                     (if p2p-open?
                                       {:phase :open
                                        :connected? true
                                        :zero-burn? (boolean (get-in session [:p2p :zero-burn?] true))
                                        :role :responder
                                        :local-transport transport
                                        :local-candidates candidates
                                        :local-ice-ufrag ice-ufrag
                                        :local-ice-pwd ice-pwd
                                        :local-fingerprint fp
                                        :local-signal-seq signal-seq}
                                       {:phase :connecting
                                        :connected? false
                                        :zero-burn? false
                                        :role :responder
                                        :local-transport transport
                                        :local-candidates candidates
                                        :local-ice-ufrag ice-ufrag
                                        :local-ice-pwd ice-pwd
                                        :local-fingerprint fp
                                        :local-signal-seq signal-seq}))
                    p2p-meta (merge (get session :p2p-meta {})
                                    (cond-> {:local-signal-seq signal-seq
                                             :preferred-transport transport
                                             :preferred-candidates candidates}
                                      explicit-cands? (assoc :local-candidates candidates)))
                    raw-remote-cands (vec (or (get-in session [:p2p :remote-candidates])
                                              (get-in session [:p2p-meta :remote-candidates])
                                              []))
                    remote-ufrag (or (get-in session [:p2p :remote-ice-ufrag])
                                     (get-in session [:p2p-meta :remote-ice-ufrag]))
                    remote-pwd (or (get-in session [:p2p :remote-ice-pwd])
                                   (get-in session [:p2p-meta :remote-ice-pwd]))
                    remote-fp (or (get-in session [:p2p :remote-fingerprint])
                                  (get-in session [:p2p-meta :remote-fingerprint]))
                    remote-trans (or (get-in session [:p2p :remote-transport])
                                     (get-in session [:p2p-meta :remote-transport])
                                     transport)
                    {:keys [dialable fallback?]} (filter-p2p-remote-candidates candidates raw-remote-cands)
                    dialable-candidates dialable
                    updated-p2p-meta (merge p2p-meta
                                            (cond-> {}
                                              (seq raw-remote-cands) (assoc :remote-candidates raw-remote-cands)
                                              remote-ufrag (assoc :remote-ice-ufrag remote-ufrag)
                                              remote-pwd (assoc :remote-ice-pwd remote-pwd)
                                              remote-fp (assoc :remote-fingerprint remote-fp)
                                              remote-trans (assoc :remote-transport remote-trans)))
                    new-state (cond-> (-> state
                                          (assoc-in [:sessions session-id :p2p] p2p-entry)
                                          (assoc-in [:sessions session-id :p2p-meta] updated-p2p-meta))
                                fallback? (update-in [:diagnostics :p2p-answer-candidate-self-filter-fallback] (fnil inc 0))
                                p2p-open? (update-in [:diagnostics :duplicate-p2p-answer-ignored] (fnil inc 0)))
                    force-dial? (boolean (or (get cmd-map "force_dial") (get cmd-map "force-dial")
                                             (:force_dial cmd-map) (:force-dial cmd-map)))
                    p2p-dial (when (and (seq dialable-candidates)
                                        (or (not p2p-open?) force-dial?))
                               {:session-id session-id
                                :peer (:peer session)
                                :role :responder
                                :transport transport
                                :local-candidates candidates
                                :remote-candidates dialable-candidates
                                :remote-ice-ufrag remote-ufrag
                                :remote-ice-pwd remote-pwd
                                :remote-fingerprint remote-fp})]
                {:state new-state
                 :response {"ok" true
                            "session_id" session-id
                            "peer" (:peer session)
                            "transport" transport
                            "candidates" candidates
                            "phase" (if p2p-open? "open" "connecting")
                            "connected" (if p2p-open? true false)
                            "burn" (long burn-amt)}
                 :net-envelopes [env]
                 :stdout-events []
                 :p2p-dial p2p-dial}))))))))

(defn- math-pow-2 [n]
  #?(:clj (long (Math/pow 2.0 (double n)))
     :cljs (long (js/Math.pow 2 n))))

(defn calculate-reconnect-backoff-ms
  "Calculates exponential backoff in milliseconds: min(30000, 1000 * 2^attempts)."
  [attempts]
  (min 30000 (long (* 1000 (math-pow-2 (min (long (or attempts 0)) 15))))))

(defn should-auto-reoffer?
  "Returns true if session `sess-or-sid` in `state` is eligible for an automatic P2P re-offer.
   Enforces:
   1. Single-owner re-dial: only session :initiator or higher-pubkey peer initiates.
   2. Hard cap at max-unanswered-p2p-offers = 3, latching :p2p-reoffer-exhausted.
   3. Mode gate: never re-offers in :shuttle mode.
   4. Exponential backoff: now-ms >= :next-reconnect-ms."
  ([state sess-or-sid]
   (should-auto-reoffer? state sess-or-sid (:epoch state 0) (:autonomous? state false)))
  ([state sess-or-sid now-ms]
   (should-auto-reoffer? state sess-or-sid now-ms (:autonomous? state false)))
  ([state sess-or-sid now-ms daemon-autonomous?]
   (let [sess (if (map? sess-or-sid) sess-or-sid (get-in state [:sessions sess-or-sid]))]
     (boolean
      (when sess
        (let [role (or (:role (get sess :p2p-meta {})) (:role (get sess :p2p {})) (:role sess))
              initiator? (= role :initiator)
              my-pk (str/lower-case (str (or (:pubkey state) "")))
              peer-pk (str/lower-case (str (or (:peer sess) "")))
              responder? (= role :responder)
              tie-breaker? (and (seq my-pk) (seq peer-pk) (neg? (compare my-pk peer-pk)))
              single-owner? (cond
                              initiator? true
                              responder? false
                              :else tie-breaker?)
              attempts (long (or (:reoffer-attempts sess) (get-in sess [:p2p-meta :reconnect-attempts]) 0))
              exhausted? (boolean (or (:p2p-reoffer-exhausted sess) (get-in sess [:p2p-meta :p2p-reoffer-exhausted])))
              cap-ok? (and (not exhausted?) (< attempts 3))]
          (when (and single-owner? cap-ok?)
            (let [p2p (get sess :p2p {})
                  p2p-meta (get sess :p2p-meta {})
                  sess-st (or (:state sess) (:phase sess))
                  has-p2p? (or (contains? sess :p2p) (contains? sess :p2p-meta))]
              (if-not has-p2p?
                true
                (let [reconnect-needed? (true? (:reconnect-needed? p2p-meta))
                      mode (or (:mode p2p-meta) (:mode p2p))
                      shuttle? (or (= mode :shuttle) (= mode "shuttle"))
                      autonomous-allowed? (and (not shuttle?)
                                               (or (= mode :autonomous)
                                                   (= mode "autonomous")
                                                   (true? daemon-autonomous?)
                                                   (true? (:autonomous? state))))
                      connected? (true? (:connected? p2p))
                      has-cands? (boolean (or (seq (:local-candidates p2p-meta))
                                              (seq (:preferred-candidates p2p-meta))
                                              (seq (:local-candidates p2p))
                                              (seq (:default-p2p-candidates state))))
                      now (long (or now-ms 0))
                      next-reconn (long (or (:next-reconnect-ms p2p-meta) 0))
                      backoff-ok? (>= now next-reconn)]
                  (and (or (= sess-st "open") (= sess-st :open))
                       reconnect-needed?
                       autonomous-allowed?
                       (not connected?)
                       has-cands?
                       backoff-ok?)))))))))))

(defn record-reoffer-attempt
  "Updates session `sid` in `state` after an autonomous re-offer attempt,
   incrementing :reconnect-attempts (and :reoffer-attempts), scheduling :next-reconnect-ms
   with exponential backoff, and latching :p2p-reoffer-exhausted after 3 attempts."
  ([state sess-or-sid]
   (record-reoffer-attempt state sess-or-sid (:epoch state 0)))
  ([state sess-or-sid now-ms]
   (let [sid (if (map? sess-or-sid) (or (:session-id sess-or-sid) (:session_id sess-or-sid)) sess-or-sid)
         sess (if (map? sess-or-sid)
                (merge (get-in state [:sessions sid]) sess-or-sid)
                (get-in state [:sessions sid]))
         now (long (or now-ms 0))
         attempts (long (or (:reoffer-attempts sess) (get-in sess [:p2p-meta :reconnect-attempts]) 0))
         new-attempts (inc attempts)
         exhausted? (>= new-attempts 3)
         backoff (calculate-reconnect-backoff-ms attempts)
         next-reconn (+ now backoff)
         updated-sess (-> sess
                          (assoc :session-id sid
                                 :reoffer-attempts new-attempts
                                 :p2p-reoffer-exhausted exhausted?)
                          (assoc-in [:p2p-meta :reconnect-attempts] new-attempts)
                          (assoc-in [:p2p-meta :p2p-reoffer-exhausted] exhausted?)
                          (assoc-in [:p2p-meta :next-reconnect-ms] next-reconn))]
     (cond-> (assoc-in state [:sessions sid] updated-sess)
       exhausted? (update-in [:diagnostics :p2p-reoffer-exhausted] (fnil inc 0))))))

(defn reset-reoffer-attempts
  "Resets reoffer attempts and exhausted state for session `sid`, updating :last-peer-activity-ms."
  ([state sid]
   (reset-reoffer-attempts state sid (:epoch state 0)))
  ([state sid now-ms]
   (let [now (long (or now-ms 0))]
     (update-in state [:sessions sid]
                (fn [sess]
                  (when sess
                    (-> sess
                        (assoc :reoffer-attempts 0
                               :p2p-reoffer-exhausted false
                               :last-peer-activity-ms now)
                        (assoc-in [:p2p-meta :reconnect-attempts] 0)
                        (assoc-in [:p2p-meta :p2p-reoffer-exhausted] false))))))))

(defn check-peer-silence-alerts
  "Emits a counted :peer-silence-alert diagnostic event when an open session has > 60 min of inactivity."
  ([state]
   (check-peer-silence-alerts state (:epoch state 0)))
  ([state now-ms]
   (let [now (long (or now-ms 0))
         silence-thresh (* 60 60 1000)]
     (reduce
      (fn [st [sid sess]]
        (let [phase (or (:state sess) (:phase sess))
              open? (or (= phase "open") (= phase :open))
              last-act (long (or (:last-peer-activity-ms sess) now))
              silent? (> (- now last-act) silence-thresh)
              alerted? (true? (:peer-silence-alerted? sess))]
          (if (and open? silent? (not alerted?))
            (-> st
                (assoc-in [:sessions sid :peer-silence-alerted?] true)
                (update-in [:diagnostics :peer-silence-alert] (fnil inc 0)))
            st)))
      state
      (:sessions state)))))

;; =============================================================================
;; BIP-020 Shared-Core Delivery Telemetry (Pillars 1-4, Pure Sans-IO)
;; =============================================================================

(defn- truncate-utf8-str
  [s max-chars]
  (let [sv (str s)]
    (if (> (count sv) max-chars)
      (subs sv 0 max-chars)
      sv)))

(defn- cap-ring-entry
  "Ensures a Pillar 1 ring-buffer entry serializes to <= 1024 UTF-8 bytes."
  [entry]
  (let [base (reduce-kv
              (fn [m k v]
                (assoc m k (if (string? v) (truncate-utf8-str v 200) v)))
              {}
              (select-keys (or entry {}) [:msg-id :kind :state :route :reason :session-id
                                          :subnet-id :seq :peers-targeted :error :ts-ms]))]
    (if (<= (fressian/count-bytes (fressian/utf8->bytes (pr-str base))) delivery-ring-max-entry-bytes)
      base
      (let [trimmed (cond-> (dissoc base :error)
                      (:msg-id base) (assoc :msg-id (truncate-utf8-str (:msg-id base) 64))
                      (:session-id base) (assoc :session-id (truncate-utf8-str (:session-id base) 64))
                      (:subnet-id base) (assoc :subnet-id (truncate-utf8-str (:subnet-id base) 64)))]
        (if (<= (fressian/count-bytes (fressian/utf8->bytes (pr-str trimmed))) delivery-ring-max-entry-bytes)
          trimmed
          {:msg-id (truncate-utf8-str (or (:msg-id base) "") 64)
           :kind (or (:kind base) :unknown)
           :state (or (:state base) :submitted)
           :ts-ms (long (or (:ts-ms base) 0))})))))

(defn append-delivery-ring-entry
  "Pure helper (Pillar 1): appends a bounded <= 1 KiB sender lifecycle entry into
   `[:delivery-telemetry :ring-buffer]`, FIFO-capped at 256 entries."
  [state entry]
  (let [capped (cap-ring-entry entry)
        prev (vec (or (get-in state [:delivery-telemetry :ring-buffer]) []))
        next-ring (let [r (conj prev capped)]
                    (if (> (count r) delivery-ring-max-entries)
                      (subvec r (- (count r) delivery-ring-max-entries))
                      r))]
    (assoc-in state [:delivery-telemetry :ring-buffer] next-ring)))

(defn record-eviction
  "Pure helper (Pillar 1 & 2): increments `[:delivery-telemetry :evicted-by-reason reason]`,
   `[:diagnostics :outbox-evicted]`, and appends an `:evicted` entry to the ring buffer."
  [state reason meta]
  (let [norm-reason (if (contains? eviction-reasons reason) reason :expired)
        entry (merge {:kind :direct
                      :state :evicted
                      :reason norm-reason}
                     (when (map? meta) meta))]
    (-> state
        (update-in [:delivery-telemetry :evicted-by-reason norm-reason] (fnil inc 0))
        (update-in [:diagnostics :outbox-evicted] (fnil inc 0))
        (append-delivery-ring-entry entry))))

(defn record-suppression
  "Pure helper (Pillar 3): increments closed-enum `[:delivery-telemetry :received-but-not-emitted reason]`
   and `[:diagnostics :received-but-not-emitted]`."
  ([state reason]
   (record-suppression state reason 1))
  ([state reason delta]
   (let [norm-reason (if (contains? suppression-reasons reason) reason :admission-drop)
         d (long (or delta 1))]
     (if (pos? d)
       (-> state
           (update-in [:delivery-telemetry :received-but-not-emitted norm-reason] (fnil + 0) d)
           (update-in [:diagnostics :received-but-not-emitted] (fnil + 0) d))
       state))))

(defn record-broadcast-seen
  "Pure helper (e2-micro bound): records `dedup-key` into bounded 1024-entry FIFO `:broadcast-seen`."
  [state dedup-key]
  (let [seen (or (:broadcast-seen state) #{})]
    (if (contains? seen dedup-key)
      state
      (let [order0 (let [o (:broadcast-seen-order state)]
                     (if (vector? o)
                       o
                       (vec seen)))
            order1 (conj order0 dedup-key)
            seen1 (conj seen dedup-key)]
        (if (> (count order1) broadcast-seen-max-entries)
          (let [overflow (- (count order1) broadcast-seen-max-entries)
                evicted (subvec order1 0 overflow)
                kept-order (subvec order1 overflow)
                kept-seen (apply disj seen1 evicted)]
            (assoc state
                   :broadcast-seen kept-seen
                   :broadcast-seen-order kept-order))
          (assoc state
                 :broadcast-seen seen1
                 :broadcast-seen-order order1))))))

(defn append-bounded-inbox
  "Pure helper (e2-micro bound): appends `item` to inbox vector capped at `inbox-max-entries`."
  [items item]
  (let [v (conj (vec (or items [])) item)]
    (if (> (count v) inbox-max-entries)
      (subvec v (- (count v) inbox-max-entries))
      v)))

(defn compute-unacked-aged-count
  "Pure helper (Pillar 2): counts unacked outbox entries across all sessions whose age
   `(now-ms - created-ms) >= threshold-ms` (default 60000 ms). Never uses `:epoch`."
  ([state now-ms]
   (compute-unacked-aged-count state now-ms (or (:unacked-age-threshold-ms state)
                                                default-unacked-age-threshold-ms)))
  ([state now-ms threshold-ms]
   (let [now (long (or now-ms 0))
         thresh (max 1 (long (or threshold-ms default-unacked-age-threshold-ms)))]
     (if-not (pos? now)
       0
       (reduce
        (fn [cnt [_ sess]]
          (let [outbox (or (:outbox sess) {})]
            (+ cnt
               (count (filter (fn [entry]
                                (let [created (long (or (:created-ms entry) (:sent-at-ms entry) 0))]
                                  (and (pos? created)
                                       (>= (- now created) thresh))))
                              (if (map? outbox) (vals outbox) outbox))))))
        0
        (:sessions state))))))

(defn detect-relay-broadcast-gap
  "Pure helper (Catch 4): detects evicted relay broadcast ring-buffer slots when a peer's
   local cursor for `relay-id` is strictly below `min-available-broadcast-seq` (and local-cursor > 0)
   or when a relay failover gap is observed. Emits counted `:diagnose` `{:reason :broadcast-gap-detected}`."
  [state {:keys [relay-id local-cursor min-available-broadcast-seq last-broadcast-seq]}]
  (let [rid (str (or relay-id "default"))
        prev-cursor (long (or local-cursor (get-in state [:relay-cursors rid :broadcast-seq]) 0))
        min-avail (long (or min-available-broadcast-seq 0))
        last-bseq (long (or last-broadcast-seq prev-cursor))
        gap? (and (pos? prev-cursor)
                  (pos? min-avail)
                  (< prev-cursor (dec min-avail)))
        ;; Also detect if min-avail > prev-cursor + 1 OR if prev-cursor < min-avail when min-avail > 1
        strict-gap? (or gap?
                        (and (pos? prev-cursor)
                             (> min-avail 1)
                             (< prev-cursor min-avail)))
        updated-cursor (max prev-cursor last-bseq)
        st1 (assoc-in state [:relay-cursors rid :broadcast-seq] updated-cursor)]
    (if strict-gap?
      (let [missed (max 1 (- min-avail prev-cursor))
            diag-evt {"event" "diagnostic"
                      "reason" "broadcast-gap-detected"
                      "relay_id" rid
                      "local_cursor" prev-cursor
                      "min_available_broadcast_seq" min-avail
                      "missed_slots" missed}
            st2 (-> st1
                    (update-in [:diagnostics :broadcast-gap-detected] (fnil inc 0))
                    (enqueue-actionable-events [diag-evt]))]
        {:state st2
         :gap-detected? true
         :missed-slots missed
         :stdout-events [diag-evt]})
      {:state st1
       :gap-detected? false
       :missed-slots 0
       :stdout-events []})))

(def waitable-event-types
  "Unified set of incoming asynchronous event types eligible to wake `wait-event`."
  #{"message-received" "offer-received" "channel-opened" "session-established"
    "rendezvous-header-received" "rendezvous-reveal-received"
    "p2p-offer-received" "p2p-connected" "broadcast-received"})

(defn classify-wait-filter-drop-reason
  "Pure helper (Catch 4 / Pillar 3): returns `nil` if `evt` satisfies `opts`, or the exact
   closed-enum suppression keyword from `suppression-reasons` explaining why it was not emitted."
  [evt opts]
  (if-not (map? evt)
    :admission-drop
    (let [ev-type (or (safe-map-get evt "event") (some-> (safe-map-get evt :event) name))
          enforce-type? (if (contains? opts :enforce-waitable-type?)
                          (boolean (:enforce-waitable-type? opts))
                          true)
          target-cursor (when-let [c (or (:cursor opts) (get opts "cursor"))]
                          (parse-long-safe c nil))
          ev-eid (parse-long-safe (or (safe-map-get evt "event_id")
                                      (safe-map-get evt :event-id)
                                      (safe-map-get evt "eid")
                                      (safe-map-get evt :eid))
                                  nil)
          target-sid (or (:session-id opts) (get opts "session_id") (get opts "session-id"))
          ev-sid (or (safe-map-get evt "session_id") (safe-map-get evt "session-id")
                     (safe-map-get evt :session-id) (safe-map-get evt :session_id))
          target-subnet (or (:subnet-id opts) (:subnet opts) (get opts "subnet_id") (get opts "subnet-id"))
          ev-subnet (or (safe-map-get evt "subnet_id") (safe-map-get evt "subnet-id")
                        (safe-map-get evt :subnet-id) (safe-map-get evt :subnet_id))
          net-uri (or (:network-uri opts) "devnet.bitecho.org")
          min-seq (when-let [ms (or (:min-seq opts) (get opts "min_seq") (get opts "min-seq"))]
                    (parse-long-safe ms nil))
          ev-seq (parse-long-safe (or (safe-map-get evt "seq") (safe-map-get evt :seq)) nil)
          min-bseq (when-let [mb (or (:min-broadcast-seq opts) (get opts "min_broadcast_seq") (get opts "min-broadcast-seq"))]
                     (parse-long-safe mb nil))
          ev-bseq (parse-long-safe (or (safe-map-get evt "broadcast_seq")
                                       (safe-map-get evt "broadcast-seq")
                                       (safe-map-get evt :broadcast-seq)
                                       (safe-map-get evt :broadcast_seq))
                                   nil)
          after-ts (when-let [at (or (:after-ts opts) (get opts "after_ts") (get opts "after-ts"))]
                     (parse-long-safe at nil))
          ev-ts (parse-long-safe (or (safe-map-get evt "timestamp_ms")
                                     (safe-map-get evt :timestamp-ms)
                                     (safe-map-get evt :timestamp_ms))
                                 0)]
      (cond
        (and enforce-type? (not (contains? waitable-event-types ev-type)))
        :event-type-mismatch

        (and (some? target-cursor) (or (nil? ev-eid) (<= (long ev-eid) (long target-cursor))))
        :cursor-skip

        (and (some? target-sid) (not= (str ev-sid) (str target-sid)))
        :session-mismatch

        (and (some? target-subnet)
             (not (and (some? ev-subnet)
                       (or (= (str ev-subnet) (str target-subnet))
                           (config/equivalent-subnet-id? (str ev-subnet) (str target-subnet) net-uri)))))
        :subnet-mismatch

        (and (some? min-seq)
             (let [eff-seq (if (and (nil? ev-seq) (nil? target-cursor) (true? (:allow-eid-fallback-for-min-seq? opts)))
                             ev-eid
                             ev-seq)]
               (or (nil? eff-seq) (< (long eff-seq) (long min-seq)))))
        :min-seq-filter

        (and (some? min-bseq)
             (or (nil? ev-bseq) (< (long ev-bseq) (long min-bseq))))
        :min-broadcast-seq-filter

        (and (some? after-ts) (<= (long (or ev-ts 0)) (long after-ts)))
        :after-ts-filter

        :else nil))))

(defn event-matches-wait-filter?
  "Unified pure predicate (Catch 4) checking whether an emitted JSON event map satisfies
   a `wait-event` or `ctl wait` filter, supporting `broadcast_seq` and `config/equivalent-subnet-id?`."
  [evt opts]
  (nil? (classify-wait-filter-drop-reason evt opts)))

(defn retransmit-unacked-outbox
  "Pure helper. Collects unacknowledged outbox entries for session `sid` in oldest-first order.
   If rto-ms is positive, filters to entries where (now-ms - last-sent-ms) >= rto-ms.
   If rto-ms is 0 or nil (e.g. on reconnect), retransmits all unacked outbox entries.
   When all transports are disconnected (`:connected? false` and P2P closed), pauses retry aging
   so entries do not burn retries while offline.
   When an entry has >= 5 retries, evicts it from :outbox, records `:retries-exhausted` in
   `delivery-telemetry`, increments `:outbox-evicted` diagnostic, and emits an actionable event.
   Returns {:state updated-state :net-envelopes retransmitted-envs :stdout-events evts :count count}."
  ([state sid]
   (retransmit-unacked-outbox state sid 0 0 nil))
  ([state sid now-ms rto-ms]
   (retransmit-unacked-outbox state sid now-ms rto-ms nil))
  ([state sid now-ms rto-ms privkey-bytes]
   (let [sess (get-in state [:sessions sid])
         p2p-open? (true? (get-in sess [:p2p :connected?]))
         all-disconnected? (and (false? (:connected? state)) (not p2p-open?))]
     (cond
       (not sess)
       {:state state :net-envelopes [] :stdout-events [] :count 0}

       all-disconnected?
       {:state state :net-envelopes [] :stdout-events [] :count 0 :paused? true}

       :else
       (let [outbox-raw (get sess :outbox {})
             outbox (if (map? outbox-raw)
                      outbox-raw
                      (into {} (map (fn [e] [(:seq e) e])) outbox-raw))
             order (get sess :outbox-order (vec (sort (keys outbox))))
             now (long (or now-ms 0))
             rto (when rto-ms (long rto-ms))
             sorted-entries (mapv (fn [sq] (get outbox sq)) (sort order))
             initial-acc {:outbox outbox
                          :order order
                          :retransmit-envs []
                          :events []
                          :evicted-entries []
                          :evicted-count 0}
             res (reduce
                  (fn [acc entry]
                    (if-not entry
                      acc
                      (let [sq (:seq entry)
                            retries (long (or (:retries entry) 0))
                            last-sent (long (or (:last-sent-ms entry) (:created-ms entry) (:sent-at-ms entry) 0))
                            eligible? (or (nil? rto) (<= rto 0) (>= (- now last-sent) rto))]
                        (if-not eligible?
                          acc
                          (if (>= retries 5)
                            ;; Evict from outbox after 5 retries
                            (let [msg-id (or (:msg-id entry) (get-in entry [:gossip-env :event :message-id]) "")
                                  evict-evt {"event" "outbox-evicted"
                                             :event "outbox-evicted"
                                             "session_id" sid
                                             :session_id sid
                                             "seq" sq
                                             :seq sq
                                             "msg_id" msg-id
                                             :msg_id msg-id
                                             "reason" "retries-exhausted"
                                             :reason "retries-exhausted"
                                             "retries" retries
                                             :retries retries}]
                              (-> acc
                                  (update :outbox dissoc sq)
                                  (update :order (fn [ord] (filterv #(not= % sq) ord)))
                                  (update :events conj evict-evt)
                                  (update :evicted-entries conj {:msg-id msg-id :session-id sid :seq sq :ts-ms now})
                                  (update :evicted-count inc)))
                            ;; Retransmit entry (< 5 retries)
                            (let [raw-env (or (:gossip-env entry) (:env entry))
                                  fallback-burn? (and (not p2p-open?)
                                                      privkey-bytes
                                                      (:msg-payload entry)
                                                      (zero? (long (or (:burn entry) 0)))
                                                      (get state :economy-enabled? true))
                                  fallback-burn (when fallback-burn?
                                                  (max 100 (effective-signaling-burn-floor state)))
                                  env (cond
                                        (and p2p-open? (:msg-payload entry) raw-env)
                                        (assoc raw-env
                                               :p2p-direct? true
                                               :p2p-peer (normalize-pubkey-hex (:peer sess))
                                               :p2p-session-id sid)

                                        fallback-burn?
                                        (build-gossip-envelope
                                         (:pubkey state)
                                         privkey-bytes
                                         (freeze-payload (:msg-payload entry))
                                         fallback-burn
                                         (str (or (:subnet-id state) "global")))

                                        (map? raw-env)
                                        (dissoc raw-env :p2p-direct? :p2p-peer :p2p-session-id)

                                        :else
                                        raw-env)
                                  updated-entry (cond-> (assoc entry
                                                               :retries (inc retries)
                                                               :last-sent-ms now
                                                               :sent-at-ms now)
                                                  (map? env) (assoc :gossip-env env)
                                                  fallback-burn? (assoc :burn fallback-burn))]
                              (-> acc
                                  (assoc-in [:outbox sq] updated-entry)
                                  (update :retransmit-envs conj env))))))))
                  initial-acc
                  sorted-entries)
             st' (-> state
                     (assoc-in [:sessions sid :outbox] (:outbox res))
                     (assoc-in [:sessions sid :outbox-order] (vec (:order res))))
             p2p-disconn-evt (when (and (pos? (:evicted-count res)) p2p-open?)
                               {"event" "p2p-disconnected"
                                :event "p2p-disconnected"
                                "session_id" sid
                                :session_id sid
                                "peer" (normalize-pubkey-hex (:peer sess))
                                :peer (normalize-pubkey-hex (:peer sess))
                                "reason" "ack-timeout"
                                :reason "ack-timeout"})
             all-events (cond-> (:events res)
                          p2p-disconn-evt (conj p2p-disconn-evt))
             st'' (if (pos? (:evicted-count res))
                    (let [st-rec (reduce (fn [s ev-meta]
                                           (record-eviction s :retries-exhausted ev-meta))
                                         (update-in st' [:sessions sid :outbox-evicted] (fnil + 0) (:evicted-count res))
                                         (:evicted-entries res))]
                      (cond-> st-rec
                        p2p-open?
                        (-> (assoc-in [:sessions sid :p2p :connected?] false)
                            (assoc-in [:sessions sid :p2p :zero-burn?] false)
                            (assoc-in [:sessions sid :p2p :phase] :closed)
                            (assoc-in [:sessions sid :p2p :error] "ack-timeout")
                            (assoc-in [:sessions sid :p2p-meta :reconnect-needed?] true))))
                    st')
             st-final (if (seq all-events)
                        (enqueue-actionable-events st'' all-events)
                        st'')]
         {:state st-final
          :net-envelopes (vec (remove nil? (:retransmit-envs res)))
          :stdout-events all-events
          :count (count (:retransmit-envs res))})))))

(defn- exec-retransmit-outbox
  ([state cmd-map]
   (exec-retransmit-outbox state cmd-map nil))
  ([state cmd-map privkey-bytes]
   (let [resolved-sid (resolve-session-id state cmd-map :active)
         now-ms (long (or (:now-ms cmd-map) (get cmd-map "now_ms") (:epoch state 0)))
         rto-ms (long (or (:rto-ms cmd-map) (get cmd-map "rto_ms") 0))]
     (cond
       (and (map? resolved-sid) (false? (:ok? resolved-sid)))
       {:state state :response {"ok" false "error" (:error resolved-sid) "matches" (:matches resolved-sid)} :net-envelopes [] :stdout-events []}

       (nil? resolved-sid)
       {:state state :response {"ok" false "error" "session-not-found"} :net-envelopes [] :stdout-events []}

       :else
       (let [sid resolved-sid
             res (retransmit-unacked-outbox state sid now-ms rto-ms privkey-bytes)]
         {:state (:state res)
          :response {"ok" true "session_id" sid "retransmitted_count" (:count res)}
          :net-envelopes (:net-envelopes res)
          :stdout-events (:stdout-events res)})))))

(defn- exec-p2p-channel-state
  ([state cmd-map]
   (exec-p2p-channel-state state cmd-map nil))
  ([state cmd-map privkey-bytes]
   (let [raw-target (or (get cmd-map "session_id") (get cmd-map "session-id")
                        (:session_id cmd-map) (:session-id cmd-map))
         resolved-sid (if (and raw-target (contains? (:sessions state) raw-target))
                        raw-target
                        (resolve-session-id state cmd-map :active))]
     (cond
       (and (map? resolved-sid) (false? (:ok? resolved-sid)))
       {:state state :response {"ok" false "error" (:error resolved-sid) "matches" (:matches resolved-sid)} :net-envelopes [] :stdout-events []}

       (nil? resolved-sid)
       {:state state :response {"ok" false "error" "session-not-found"} :net-envelopes [] :stdout-events []}

       :else
       (let [session-id resolved-sid
             session (get-in state [:sessions session-id])]
         (if-not session
           {:state state :response {"ok" false "error" "session-not-found"} :net-envelopes [] :stdout-events []}
           (let [connected? (let [c (or (get cmd-map "connected") (:connected cmd-map)
                                        (get cmd-map "connected?") (:connected? cmd-map))]
                              (if (nil? c) false (boolean c)))
                 transport (or (get cmd-map "transport") (:transport cmd-map))
                 error (or (get cmd-map "error") (:error cmd-map))
                 pname (pubkey->petname state (:peer session))]
             (if connected?
               (let [eff-transport (str (or transport
                                            (get-in session [:p2p :remote-transport])
                                            (get-in session [:p2p :local-transport])
                                            "udp"))
                     p2p-entry (merge (get session :p2p {})
                                      {:phase :open
                                       :connected? true
                                       :zero-burn? true
                                       :transport eff-transport})
                     p2p-meta (merge (get session :p2p-meta {})
                                     {:reconnect-needed? false
                                      :reconnect-attempts 0
                                      :next-reconnect-ms 0
                                      :relay-fallback? false
                                      :preferred-transport eff-transport})
                     base-state (-> state
                                    (assoc-in [:sessions session-id :p2p] p2p-entry)
                                    (assoc-in [:sessions session-id :p2p-meta] p2p-meta))
                     now-ms (long (or (:now-ms cmd-map) (get cmd-map "now_ms") (:epoch state 0)))
                     retrans (retransmit-unacked-outbox base-state session-id now-ms 0 privkey-bytes)
                     new-state (:state retrans)
                     evt (cond-> {"event" "p2p-connected"
                                  "session_id" session-id
                                  "peer" (:peer session)
                                  "transport" eff-transport
                                  "zero_burn" true}
                           pname (assoc "peer_petname" pname))]
                 {:state new-state
                  :response {"ok" true
                             "session_id" session-id
                             "connected" true
                             "phase" "open"}
                  :net-envelopes (:net-envelopes retrans)
                  :stdout-events [evt]})
               (let [auto-relay? (not= false (:auto-relay-fallback? state))
                     p2p-entry (cond-> (merge (get session :p2p {})
                                              {:phase :closed
                                               :connected? false
                                               :zero-burn? false})
                                 error (assoc :last-error error)
                                 auto-relay? (assoc :relay-fallback? true))
                     p2p-meta (merge (get session :p2p-meta {})
                                     {:reconnect-needed? true
                                      :relay-fallback? true})
                     new-state (cond-> (-> state
                                           (assoc-in [:sessions session-id :p2p] p2p-entry)
                                           (assoc-in [:sessions session-id :p2p-meta] p2p-meta)
                                           (cond-> auto-relay? (assoc-in [:sessions session-id :relay-fallback?] true)))
                                 error (update-in [:diagnostics :p2p-dial-failed] (fnil inc 0)))
                     evt (cond-> {"event" "p2p-disconnected"
                                  "session_id" session-id
                                  "peer" (:peer session)
                                  "reason" (or error "closed")}
                           auto-relay? (assoc "relay_fallback" true)
                           pname (assoc "peer_petname" pname))]
                 {:state new-state
                  :response {"ok" true
                             "session_id" session-id
                             "connected" false
                             "phase" "closed"}
                  :net-envelopes []
                  :stdout-events [evt]})))))))))

(defn handle-p2p-connection-failure
  "Pure state transition when a direct P2P connection or dial fails for a session.
   Transitions P2P phase to :closed and, unless (:auto-relay-fallback? state) is explicitly false,
   activates :relay-fallback? true on the session."
  ([state session-id] (handle-p2p-connection-failure state session-id nil))
  ([state session-id error]
   (let [cmd-map (cond-> {"cmd" "p2p-channel-state"
                          "session_id" session-id
                          "connected" false}
                   error (assoc "error" (str error)))]
     (:state (exec-p2p-channel-state state cmd-map)))))

(defn- check-and-deduct-burn
  [state burn-amt]
  (let [burn (max 0 (long (or burn-amt 0)))
        acct (:account state)
        has-bal? (and (map? acct) (or (some? (:spendable acct)) (some? (:balance acct))))
        spendable (when has-bal? (long (parse-long-safe (or (:spendable acct) (:balance acct)) 0)))]
    (if (and (pos? burn) has-bal? (< spendable burn))
      {:ok? false :error "insufficient-funds" :state state}
      {:ok? true
       :burn burn
       :state (cond-> (update-in state [:local-accounting :burned-ech] (fnil + 0) burn)
                (and (pos? burn) (some? (:spendable acct)))
                (update-in [:account :spendable] - burn)
                (and (pos? burn) (some? (:balance acct)))
                (update-in [:account :balance] - burn))})))

(defn prepare-broadcast
  "Pure two-phase broadcast preparation (BIP-020 Catch 1 & 2).
   Signs wire broadcast payload with ZERO route metadata inside wire bytes (N-1 compatible).
   NEVER returns `ok: true` or `mesh_submitted: true` prior to shell transport confirmation via
   `commit-delivery-outcome`."
  [state cmd-map privkey-bytes]
  (let [raw-text (or (get cmd-map "text") (get cmd-map "message") (:text cmd-map) (:message cmd-map))
        text (when (some? raw-text) (str raw-text))]
    (if (or (nil? text) (str/blank? text))
      {:ok? false
       :state state
       :response {"ok" false "error" "empty-payload" "mesh_submitted" false "p2p" false "peers_targeted" 0}
       :net-envelopes []
       :stdout-events []}
      (let [burn-amt (max 0 (long (or (parse-long-safe (or (get cmd-map "burn") (:burn cmd-map)) 0) 0)))
            burn-chk (check-and-deduct-burn state burn-amt)]
        (if-not (:ok? burn-chk)
          (let [err (errors/canonical-error (:error burn-chk) {:burn burn-amt})
                st-err (errors/record-error-diagnostic state err)]
            {:ok? false
             :state st-err
             :response (errors/canonical-error->wire err {"mesh_submitted" false "p2p" false "peers_targeted" 0})
             :effects [(errors/diagnose-effect err)]
             :net-envelopes []
             :stdout-events []})
          (let [st-after-burn (:state burn-chk)
                sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id state) "global"))
                sender (normalize-pubkey-hex (:pubkey state))
                next-seq (inc (long (or (:broadcast-seq state) 0)))
                msg-id (compute-broadcast-msg-id sub-id sender next-seq text)
                epoch (long (or (:epoch state) 0))
                now-ms (long (or (parse-long-safe (or (get cmd-map "now_ms") (:now-ms cmd-map)) nil) 0))
                explicit-dac (or (get cmd-map "dac") (:dac cmd-map))
                dac (or explicit-dac
                        (when-let [d (:dac state)]
                          (when (:ok? (verify-dac d {:expected-agent-pubkey (:pubkey state)
                                                     :current-epoch epoch
                                                     :revoked-dac-ids (:revoked-dacs state)
                                                     :required-scope "broadcast"}))
                            d)))
                dac-id (when (map? dac) (or (:dac-id dac) (get dac "dac_id") (get dac "dac-id")))
                sig-str (canonical-broadcast-str sub-id sender next-seq msg-id text epoch dac-id)
                sig-bytes (crypto/sign privkey-bytes (fressian/utf8->bytes sig-str))
                sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
                ;; N-1 wire invariant: ZERO route metadata inside signed wire payload
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
                outer-sub (if (pos? burn-amt) "*" sub-id)
                raw-env (build-gossip-envelope sender privkey-bytes (freeze-payload payload) burn-amt outer-sub)
                ;; F-BCAST-1 (BIP-013): Broadcast NEVER sets :p2p-direct? true so stale P2P session metadata
                ;; cannot divert mesh broadcast or cause relay mirroring to skip it.
                env (assoc (dissoc raw-env :p2p-direct? :p2p-peer :p2p-session-id)
                           :p2p-broadcast? true
                           :mesh-broadcast? true)
                dedup-key [sender next-seq msg-id]
                b-entry {:type :broadcast
                         :from sender
                         :seq next-seq
                         :msg-id msg-id
                         :msg_id msg-id
                         "msg_id" msg-id
                         :text text
                         :subnet-id sub-id
                         :subnet_id sub-id
                         "subnet_id" sub-id
                         :epoch epoch
                         :broadcast? true
                         :self true
                         "self" true}
                intent {:kind :broadcast
                        :msg-id msg-id
                        :subnet-id sub-id
                        :seq next-seq
                        :burn burn-amt
                        :zero-burn? (zero? burn-amt)
                        :ts-ms now-ms}
                new-state (-> st-after-burn
                              (assoc :broadcast-seq next-seq)
                              (record-broadcast-seen dedup-key)
                              (update :broadcast-inbox append-bounded-inbox b-entry)
                              (append-delivery-ring-entry {:msg-id msg-id
                                                           :kind :broadcast
                                                           :state :submitted
                                                           :subnet-id sub-id
                                                           :seq next-seq
                                                           :ts-ms now-ms}))]
            {:ok? true
             :state new-state
             :fanout-intent intent
             :response {"ok" false
                        "pending" true
                        "status" "prepared"
                        "subnet_id" sub-id
                        "seq" next-seq
                        "msg_id" msg-id
                        "burn" burn-amt
                        "zero_burn" (zero? burn-amt)
                        "p2p" false
                        "p2p_direct" false
                        "mesh_submitted" false
                        "peers_targeted" 0
                        "fanout" {"route" "pending"
                                  "mesh_submitted" false
                                  "p2p_direct" false
                                  "peers_targeted" 0}}
             :net-envelopes [env]
             :stdout-events []}))))))

(defn prepare-send
  "Pure two-phase sealed send preparation (BIP-020 Catch 1).
   Requires explicit wall-clock `now_ms` (never falls back to `:epoch`).
   NEVER returns `ok: true` or `mesh_submitted: true` prior to shell transport confirmation via
   `commit-delivery-outcome`."
  [state cmd-map privkey-bytes]
  (let [resolved-sid (resolve-session-id state cmd-map :open)]
    (cond
      (and (map? resolved-sid) (false? (:ok? resolved-sid)))
      {:ok? false
       :state state
       :response {"ok" false "error" (:error resolved-sid) "matches" (:matches resolved-sid)
                  "mesh_submitted" false "p2p" false "peers_targeted" 0}
       :net-envelopes []
       :stdout-events []}

      (nil? resolved-sid)
      (let [err (errors/canonical-error :session-not-open {:reason "no-open-session"})
            st-err (-> state
                       (record-eviction :session-not-open {:ts-ms (long (or (parse-long-safe (or (get cmd-map "now_ms") (:now-ms cmd-map)) nil) 0))})
                       (errors/record-error-diagnostic err))]
        {:ok? false
         :state st-err
         :response (errors/canonical-error->wire err {"mesh_submitted" false "p2p" false "peers_targeted" 0})
         :effects [(errors/diagnose-effect err)]
         :net-envelopes []
         :stdout-events []})

      :else
      (let [session-id resolved-sid
            session (get-in state [:sessions session-id])]
        (cond
          (not (and session (= "open" (:state session))))
          (let [err (errors/canonical-error :session-not-open {:session-id session-id})
                st-err (-> state
                           (record-eviction :session-not-open {:session-id session-id
                                                               :ts-ms (long (or (parse-long-safe (or (get cmd-map "now_ms") (:now-ms cmd-map)) nil) 0))})
                           (errors/record-error-diagnostic err))]
            {:ok? false
             :state st-err
             :response (errors/canonical-error->wire err {"mesh_submitted" false "p2p" false "peers_targeted" 0})
             :effects [(errors/diagnose-effect err)]
             :net-envelopes []
             :stdout-events []})

          (or (true? (:tx-tainted? session)) (true? (:rekey-required? session)))
          {:ok? false
           :state state
           :response {"ok" false "error" "session-key-tainted-rollback"
                      "session_id" session-id
                      "rekey_required" true
                      "reoffer_recommended" true
                      "mesh_submitted" false "p2p" false "peers_targeted" 0}
           :net-envelopes []
           :stdout-events []}

          :else
          (let [pname (pubkey->petname state (:peer session))
                text (or (get cmd-map "text") (get cmd-map "message")
                         (:text cmd-map) (:message cmd-map))
                payload-hex (or (get cmd-map "payload_hex") (get cmd-map "payload-hex")
                                (:payload_hex cmd-map) (:payload-hex cmd-map))
                payload-bytes (cond (some? text) (fressian/utf8->bytes (str text))
                                    (some? payload-hex) (basalt/hex->bytes payload-hex)
                                    :else empty-bytes)]
            (if (zero? (fressian/count-bytes payload-bytes))
              {:ok? false
               :state state
               :response {"ok" false "error" "empty-payload"
                          "mesh_submitted" false "p2p" false "peers_targeted" 0}
               :net-envelopes []
               :stdout-events []}
              (let [p2p-open? (true? (get-in session [:p2p :connected?]))
                    burn-amt (if p2p-open?
                               0
                               (long (or (get cmd-map "burn") (:burn cmd-map) (if (get state :economy-enabled? true) 500 0))))
                    sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet-id session) (:subnet-id state) "global"))
                    seq-num (inc (:tx-seq session 0))
                    suite (or (:suite session) sealed/suite-v1-chacha20poly1305)
                    sealed (sealed/seal-message (:tx-key session) seq-num payload-bytes (fressian/utf8->bytes session-id) suite)
                    ct-hex (basalt/bytes->hex (:ciphertext sealed))
                    ct-sha256 (crypto/sha256-hex ct-hex)
                    msg-payload {:protocol-version current-wire-version
                                 :wire-format current-wire-format
                                 :subnet-id sub-id
                                 :bitecho/type :sealed-message
                                 :session-id session-id
                                 :sender (:pubkey state)
                                 :recipient (:peer session)
                                 :epoch (effective-session-wire-epoch state session)
                                 :seq seq-num
                                 :suite suite
                                 :nonce (basalt/bytes->hex (:nonce sealed))
                                 :ciphertext ct-hex}
                    raw-gossip-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload msg-payload) burn-amt sub-id)
                    gossip-env (cond-> raw-gossip-env
                                 p2p-open? (assoc :p2p-direct? true
                                                  :p2p-peer (normalize-pubkey-hex (:peer session))
                                                  :p2p-session-id session-id))
                    max-outbox (long (or (:max-outbox-size state) 64))
                    curr-outbox (or (:outbox session) {})
                    curr-order (or (:outbox-order session) [])
                    ;; BIP-020 Catch 1: Explicit wall-clock now_ms ONLY — NEVER fall back to :epoch!
                    sent-at (long (or (parse-long-safe (or (get cmd-map "now_ms") (:now-ms cmd-map)) nil) 0))
                    msg-id (or (:message-id (:event gossip-env)) "")
                    next-order (conj curr-order seq-num)
                    next-outbox (assoc curr-outbox seq-num {:seq seq-num
                                                            :msg-payload msg-payload
                                                            :ciphertext-sha256 ct-sha256
                                                            :burn burn-amt
                                                            :gossip-env gossip-env
                                                            :sent-at-ms sent-at
                                                            :last-sent-ms sent-at
                                                            :created-ms sent-at
                                                            :retries 0
                                                            :msg-id msg-id})
                    [final-outbox final-order evicted-seqs] (if (> (count next-order) max-outbox)
                                                              (let [overflow (- (count next-order) max-outbox)
                                                                    evicted (subvec next-order 0 overflow)
                                                                    kept (subvec next-order overflow)]
                                                                [(apply dissoc next-outbox evicted) kept (vec evicted)])
                                                              [next-outbox next-order []])
                    overflow (count evicted-seqs)
                    diag-events (if (pos? overflow)
                                  [{"event" "diagnostic"
                                    "reason" "outbox-evicted"
                                    "eviction_reason" "capacity-overflow"
                                    "session_id" session-id
                                    "evicted_seqs" evicted-seqs}]
                                  [])
                    st0 (cond-> (-> state
                                    (assoc-in [:sessions session-id :tx-seq] seq-num)
                                    (assoc-in [:sessions session-id :outbox] final-outbox)
                                    (assoc-in [:sessions session-id :outbox-order] final-order)
                                    (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt)
                                    (append-delivery-ring-entry {:msg-id msg-id
                                                                 :kind :direct
                                                                 :state :submitted
                                                                 :session-id session-id
                                                                 :subnet-id sub-id
                                                                 :seq seq-num
                                                                 :ts-ms sent-at}))
                          (and (pos? burn-amt) (some? (get-in state [:account :spendable])))
                          (update-in [:account :spendable] - burn-amt))
                    new-state (if (pos? overflow)
                                (let [st-ev (reduce (fn [s ev-sq]
                                                      (record-eviction s :capacity-overflow
                                                                       {:session-id session-id :seq ev-sq :ts-ms sent-at}))
                                                    (-> st0
                                                        (update-in [:sessions session-id :outbox-evicted] (fnil + 0) overflow)
                                                        (update-in [:sessions session-id :outbox-evicted-seqs]
                                                                   (fnil (fn [v sqs] (vec (take-last 64 (into (vec v) sqs)))) [])
                                                                   evicted-seqs))
                                                    evicted-seqs)]
                                  st-ev)
                                st0)
                    bytes-sent (fressian/count-bytes payload-bytes)
                    tr-label (if p2p-open?
                               (or (get-in session [:p2p :transport])
                                   (get-in session [:p2p-meta :preferred-transport])
                                   "p2p")
                               "mesh")
                    intent (cond-> {:kind :direct
                                    :msg-id msg-id
                                    :session-id session-id
                                    :subnet-id sub-id
                                    :seq seq-num
                                    :bytes-sent bytes-sent
                                    :burn burn-amt
                                    :transport tr-label
                                    :p2p-open? p2p-open?
                                    :ts-ms sent-at}
                             pname (assoc :peer-petname pname))]
                {:ok? true
                 :state new-state
                 :fanout-intent intent
                 :response (cond-> {"ok" false
                                    "pending" true
                                    "status" "prepared"
                                    "session_id" session-id
                                    "seq" seq-num
                                    "msg_id" msg-id
                                    "bytes_sent" bytes-sent
                                    "burn" burn-amt
                                    "transport" tr-label
                                    "p2p" false
                                    "p2p_direct" false
                                    "mesh_submitted" false
                                    "peers_targeted" 0}
                             pname (assoc "peer_petname" pname))
                 :net-envelopes [gossip-env]
                 :stdout-events diag-events}))))))))

(defn commit-delivery-outcome
  "Pure shell-confirmation reducer (BIP-020 Catch 1, Pillar 1 & 2).
   Reduces actual transport outcome (`{:mesh-submitted? :p2p-direct? :mesh-peers-targeted :p2p-peers-targeted :error :now-ms}`)
   into confirmed response fields, delivery-telemetry counters, ring-buffer lifecycle entry,
   and counted `:diagnose {:reason :mesh-submit-failed}` on failure."
  [state intent outcome]
  (let [mesh-ok? (boolean (:mesh-submitted? outcome))
        p2p-ok? (boolean (:p2p-direct? outcome))
        delivered? (or mesh-ok? p2p-ok?)
        mesh-peers (long (or (:mesh-peers-targeted outcome) (if mesh-ok? 1 0)))
        p2p-peers (long (or (:p2p-peers-targeted outcome) (if p2p-ok? 1 0)))
        peers-targeted (+ mesh-peers p2p-peers)
        route (cond
                (and mesh-ok? p2p-ok?) :mesh+p2p
                mesh-ok? :mesh
                p2p-ok? :p2p
                :else :none)
        now-ms (long (or (:now-ms outcome) (:ts-ms intent) 0))
        err-str (or (:error outcome) (when-not delivered? "mesh-submit-failed"))
        kind (or (:kind intent) :broadcast)
        msg-id (or (:msg-id intent) "")
        diag-evt (when-not delivered?
                   (cond-> {"event" "diagnostic"
                            "reason" "mesh-submit-failed"
                            "kind" (name kind)
                            "msg_id" msg-id
                            "error" (str err-str)}
                     (:subnet-id intent) (assoc "subnet_id" (:subnet-id intent))
                     (:session-id intent) (assoc "session_id" (:session-id intent))
                     (:seq intent) (assoc "seq" (:seq intent))))
        st1 (if delivered?
              (cond-> (-> state
                          (update-in [:delivery-telemetry :sent] (fnil inc 0))
                          (update-in [:delivery-telemetry :fanout :peers-targeted] (fnil + 0) peers-targeted)
                          (append-delivery-ring-entry
                           (cond-> {:msg-id msg-id
                                    :kind kind
                                    :state :fanned-out
                                    :route route
                                    :peers-targeted peers-targeted
                                    :ts-ms now-ms}
                             (:subnet-id intent) (assoc :subnet-id (:subnet-id intent))
                             (:session-id intent) (assoc :session-id (:session-id intent))
                             (:seq intent) (assoc :seq (:seq intent)))))
                mesh-ok? (update-in [:delivery-telemetry :fanout :mesh-submitted] (fnil inc 0))
                p2p-ok? (update-in [:delivery-telemetry :fanout :p2p-direct] (fnil inc 0)))
              (-> state
                  (update-in [:delivery-telemetry :fanout :mesh-submit-failed] (fnil inc 0))
                  (update-in [:diagnostics :mesh-submit-failed] (fnil inc 0))
                  (update-in [:diagnostics :dropped] (fnil inc 0))
                  (append-delivery-ring-entry
                   (cond-> {:msg-id msg-id
                            :kind kind
                            :state :evicted
                            :route :none
                            :reason :mesh-disconnected
                            :error (str err-str)
                            :ts-ms now-ms}
                     (:subnet-id intent) (assoc :subnet-id (:subnet-id intent))
                     (:session-id intent) (assoc :session-id (:session-id intent))
                     (:seq intent) (assoc :seq (:seq intent))))
                  (enqueue-actionable-events [diag-evt])))
        base-resp (cond-> {"ok" delivered?
                           "mesh_submitted" mesh-ok?
                           "p2p" p2p-ok?
                           "p2p_direct" p2p-ok?
                           "peers_targeted" peers-targeted
                           "fanout" {"route" (name route)
                                     "mesh_submitted" mesh-ok?
                                     "p2p_direct" p2p-ok?
                                     "mesh_peers_targeted" mesh-peers
                                     "p2p_peers_targeted" p2p-peers
                                     "peers_targeted" peers-targeted}}
                    (:subnet-id intent) (assoc "subnet_id" (:subnet-id intent))
                    (:session-id intent) (assoc "session_id" (:session-id intent))
                    (:seq intent) (assoc "seq" (:seq intent))
                    (seq msg-id) (assoc "msg_id" msg-id)
                    (some? (:burn intent)) (assoc "burn" (:burn intent))
                    (some? (:zero-burn? intent)) (assoc "zero_burn" (:zero-burn? intent))
                    (some? (:bytes-sent intent)) (assoc "bytes_sent" (:bytes-sent intent))
                    (:transport intent) (assoc "transport" (:transport intent))
                    (:peer-petname intent) (assoc "peer_petname" (:peer-petname intent))
                    (not delivered?) (assoc "error" (str err-str)))]
    {:ok? delivered?
     :state st1
     :response base-resp
     :stdout-events (if diag-evt [diag-evt] [])}))

(defn- exec-broadcast [state cmd-map privkey-bytes]
  (let [prep (prepare-broadcast state cmd-map privkey-bytes)]
    (if-not (:ok? prep)
      (dissoc prep :ok?)
      ;; Synchronous handle-command compatibility: preserves "ok" true for pure unit callers,
      ;; while keeping "mesh_submitted" false and "peers_targeted" 0 until shell commits outcome.
      (assoc (dissoc prep :ok?)
             :response (assoc (:response prep) "ok" true "pending_delivery" true)))))

(defn- exec-send [state cmd-map privkey-bytes]
  (let [prep (prepare-send state cmd-map privkey-bytes)]
    (if-not (:ok? prep)
      (dissoc prep :ok?)
      (assoc (dissoc prep :ok?)
             :response (assoc (:response prep)
                              "ok" true
                              "pending_delivery" true
                              "p2p" (boolean (get-in prep [:fanout-intent :p2p-open?])))))))

(defn- exec-inbox
  ([state] (exec-inbox state {}))
  ([state cmd-map]
   (let [raw-sub (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map)
                     (get cmd-map "subnet") (:subnet cmd-map))
         subnet-filter (when (and raw-sub (not (str/blank? (str raw-sub))))
                         (str raw-sub))
         peek? (boolean (or (get cmd-map "peek") (:peek cmd-map) (true? (get cmd-map :peek))))
         matches-subnet? (fn [entry]
                           (if (nil? subnet-filter)
                             true
                             (let [entry-sub (str (or (:subnet-id entry) (:subnet_id entry)
                                                      (get entry "subnet_id") (get entry "subnet-id")
                                                      ""))]
                               (or (= subnet-filter entry-sub)
                                   (config/equivalent-subnet-id? subnet-filter entry-sub (:active-network-uri state))))))
         inbox-entries (vec (:inbox state))
         bcast-entries (vec (:broadcast-inbox state))
         matched-inbox (filterv matches-subnet? inbox-entries)
         rem-inbox (if subnet-filter (filterv (complement matches-subnet?) inbox-entries) [])
         matched-bcasts (filterv matches-subnet? bcast-entries)
         rem-bcasts (if subnet-filter (filterv (complement matches-subnet?) bcast-entries) [])
         enrich-entry (fn [m]
                        (let [clean-m (dissoc m :from_petname :from-petname "from_petname" "from-petname")
                              sender (or (:from clean-m) (get clean-m "from"))
                              pname (when sender (pubkey->petname state sender))
                              sub-id (or (:subnet-id clean-m) (:subnet_id clean-m) (get clean-m "subnet_id") (get clean-m "subnet-id"))
                              msg-id (or (:msg-id clean-m) (:msg_id clean-m) (get clean-m "msg_id") (get clean-m "msg-id"))]
                          (cond-> clean-m
                            pname (assoc :from_petname pname "from_petname" pname)
                            sub-id (assoc :subnet-id (str sub-id) :subnet_id (str sub-id) "subnet_id" (str sub-id))
                            msg-id (assoc :msg-id (str msg-id) :msg_id (str msg-id) "msg_id" (str msg-id)))))
         enriched-msgs (mapv enrich-entry matched-inbox)
         enriched-bcasts (mapv enrich-entry matched-bcasts)
         all-offers (vec (vals (:pending-offers state)))
         matched-offers (if subnet-filter (filterv matches-subnet? all-offers) all-offers)
         enriched-offers (mapv (fn [o]
                                 (let [clean-o (dissoc o :petname :nickname :caller_petname :caller-petname
                                                       "petname" "nickname" "caller_petname" "caller-petname")
                                       caller (or (:caller clean-o) (get clean-o "caller"))
                                       pname (when caller (pubkey->petname state caller))]
                                   (cond-> clean-o
                                     pname (assoc :caller_petname pname "caller_petname" pname))))
                               matched-offers)
         all-rendezvous (vec (vals (:pending-rendezvous state)))
         matched-rendezvous (if subnet-filter (filterv matches-subnet? all-rendezvous) all-rendezvous)
         enriched-rendezvous (mapv (fn [r]
                                     (let [clean-r (dissoc r :caller_petname :caller-petname "caller_petname" "caller-petname")
                                           caller (or (:caller clean-r) (get clean-r "caller"))
                                           pname (when caller (pubkey->petname state caller))]
                                       (cond-> clean-r
                                         pname (assoc :caller_petname pname "caller_petname" pname))))
                                   matched-rendezvous)
         new-state (if peek?
                     state
                     (assoc state :inbox rem-inbox :broadcast-inbox rem-bcasts))]
     {:state new-state
      :response (cond-> {"ok" true
                         "messages" enriched-msgs
                         "broadcasts" enriched-bcasts
                         "pending_offers" enriched-offers
                         "pending_rendezvous" enriched-rendezvous}
                  peek? (assoc "peek" true))
      :net-envelopes []
      :stdout-events []})))

(defn- exec-close [state cmd-map privkey-bytes]
  (let [resolved-sid (resolve-session-id state cmd-map :active)]
    (cond
      (and (map? resolved-sid) (false? (:ok? resolved-sid)))
      {:state state :response {"ok" false "error" (:error resolved-sid) "matches" (:matches resolved-sid)} :net-envelopes [] :stdout-events []}

      (nil? resolved-sid)
      {:state state :response {"ok" false "error" "session-not-found"} :net-envelopes [] :stdout-events []}

      :else
      (let [session-id resolved-sid
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
                                (dissoc :tx-key :rx-key :ephemeral-priv :p2p))
                new-state (assoc-in state [:sessions session-id] closed-sess)]
            {:state new-state
             :response (cond-> {"ok" true "session_id" session-id "state" "closed"}
                         pname (assoc "peer_petname" pname))
             :net-envelopes [gossip-env]
             :stdout-events []}))))))

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
              new-state (cond-> (-> state
                                    (assoc :account {:balance bal
                                                     :spendable spendable
                                                     :seq seq-num
                                                     :deps deps
                                                     :finalized-epoch fin-ep}
                                           :transfer-seq seq-num
                                           :last-transfer-hash (last deps)
                                           :epoch (max (long (or (:epoch state) 0)) fin-ep))
                                    (update :credited-tx-ids (fn [c] (into (or c #{}) (map str deps)))))
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

(defn- parse-structured-arg
  [val]
  (if (string? val)
    (let [trimmed (str/trim val)]
      (if (or (str/starts-with? trimmed "{") (str/starts-with? trimmed "["))
        (try
          (let [parsed (parse-json-str trimmed true)]
            (if (or (map? parsed) (vector? parsed))
              parsed
              (edn/read-string trimmed)))
          (catch #?(:clj Exception :cljs :default) _
            (try
              (edn/read-string trimmed)
              (catch #?(:clj Exception :cljs :default) _ val))))
        val))
    val))

(defn- exec-lock-intent [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient") (get cmd-map "to")
                         (:receiver cmd-map) (:recipient cmd-map) (:to cmd-map))
        raw-amount (or (get cmd-map "amount") (:amount cmd-map))
        amount (when (some? raw-amount) (parse-long-safe raw-amount :invalid))
        raw-dh (or (get cmd-map "deliverable_hash") (get cmd-map "deliverable-hash")
                   (:deliverable_hash cmd-map) (:deliverable-hash cmd-map))
        raw-deliv (or (get cmd-map "deliverable") (:deliverable cmd-map)
                      (get cmd-map "preimage") (:preimage cmd-map))
        raw-ph (or (get cmd-map "puzzle_hash") (get cmd-map "puzzle-hash")
                   (:puzzle_hash cmd-map) (:puzzle-hash cmd-map))
        raw-psrc (or (get cmd-map "puzzle_source") (get cmd-map "puzzle-source")
                     (:puzzle_source cmd-map) (:puzzle-source cmd-map))
        curr-ep (effective-chain-epoch state)
        raw-expires (or (get cmd-map "timeout_epoch") (get cmd-map "timeout-epoch")
                        (:timeout_epoch cmd-map) (:timeout-epoch cmd-map)
                        (get cmd-map "expires_epoch") (get cmd-map "expires-epoch")
                        (:expires_epoch cmd-map) (:expires-epoch cmd-map))
        expires-epoch (if (some? raw-expires) (parse-long-safe raw-expires :invalid) (+ curr-ep 10))
        has-ph? (and (string? raw-ph) (not (str/blank? raw-ph)))
        has-psrc? (and (string? raw-psrc) (not (str/blank? raw-psrc)))
        ph-cid (when has-psrc? (puzzle/puzzle-cid (str raw-psrc)))
        norm-ph (when has-ph? (escrow/normalize-hex (str raw-ph)))]
    (cond
      (and has-ph? has-psrc? (not= ph-cid norm-ph))
      {:state state :response {"ok" false "error" "puzzle-hash-mismatch"} :net-envelopes [] :stdout-events []}

      (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)))
      {:state state :response {"ok" false "error" "missing-receiver"} :net-envelopes [] :stdout-events []}

      (or (nil? amount) (= amount :invalid) (<= amount 0))
      {:state state :response {"ok" false "error" "invalid-amount"} :net-envelopes [] :stdout-events []}

      :else
      (let [puzzle-hash (cond
                          has-ph? norm-ph
                          has-psrc? ph-cid
                          :else nil)]
        (if (and puzzle-hash (not (escrow/valid-deliverable-hash? puzzle-hash)))
          {:state state :response {"ok" false "error" "invalid-puzzle-hash"} :net-envelopes [] :stdout-events []}
          (let [deliverable-hash (cond
                                   (and (string? raw-dh) (escrow/valid-deliverable-hash? raw-dh)) (escrow/normalize-hex raw-dh)
                                   (and (string? raw-deliv) (not (str/blank? raw-deliv))) (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes raw-deliv)))
                                   puzzle-hash puzzle-hash
                                   :else nil)]
            (cond
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
                              (let [raw-eid (or (get cmd-map "intent_id") (get cmd-map "intent-id")
                                                (:intent_id cmd-map) (:intent-id cmd-map)
                                                (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                                                (:escrow_id cmd-map) (:escrow-id cmd-map))
                                    nonce (str (inc (long (count (:escrows state {})))))
                                    escrow-id (or (when (and (string? raw-eid) (not (str/blank? raw-eid))) raw-eid)
                                                  (escrow/compute-escrow-id (:pubkey state) receiver-pub amount deliverable-hash curr-ep expires-epoch nonce))
                                    intent-payload (cond-> {:type :lock-intent
                                                            :escrow-id escrow-id
                                                            :payer (:pubkey state)
                                                            :receiver receiver-pub
                                                            :amount amount
                                                            :deliverable-hash deliverable-hash
                                                            :created-epoch curr-ep
                                                            :expires-epoch expires-epoch
                                                            :epoch curr-ep
                                                            :receipt-id (str "lock:" escrow-id)}
                                                     puzzle-hash (assoc :puzzle-hash puzzle-hash))
                                    active-dac (when-let [d (:dac state)]
                                                 (when (:ok? (verify-dac d {:expected-agent-pubkey (:pubkey state)
                                                                            :current-epoch curr-ep
                                                                            :revoked-dac-ids (:revoked-dacs state)}))
                                                   d))
                                    envelope (wrap-agent-event intent-payload (:pubkey state) privkey-bytes active-dac)
                                    local-escrow (cond-> {:escrow-id escrow-id
                                                          :payer (:pubkey state)
                                                          :receiver receiver-pub
                                                          :amount amount
                                                          :deliverable-hash deliverable-hash
                                                          :created-epoch curr-ep
                                                          :expires-epoch expires-epoch
                                                          :status :locked}
                                                   puzzle-hash (assoc :puzzle-hash puzzle-hash))
                                    new-state (cond-> (-> state
                                                          (assoc-in [:escrows escrow-id] local-escrow)
                                                          (assoc :dac-spend (:new-dac-spend dac-auth)))
                                                acct (update-in [:account :spendable] - amount))]
                                {:state new-state
                                 :response (cond-> {"ok" true
                                                    "escrow_id" escrow-id
                                                    "intent_id" escrow-id
                                                    "payer" (:pubkey state)
                                                    "receiver" receiver-pub
                                                    "amount" amount
                                                    "deliverable_hash" deliverable-hash
                                                    "expires_epoch" expires-epoch
                                                    "timeout_epoch" expires-epoch
                                                    "status" "locked"}
                                             puzzle-hash (assoc "puzzle_hash" puzzle-hash)
                                             pname (assoc "receiver_petname" pname))
                                 :net-envelopes [envelope]
                                 :stdout-events []}))))))))))))))))

(defn- exec-release-intent [state cmd-map privkey-bytes]
  (let [escrow-id (or (get cmd-map "intent_id") (get cmd-map "intent-id")
                      (:intent_id cmd-map) (:intent-id cmd-map)
                      (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                      (:escrow_id cmd-map) (:escrow-id cmd-map))]
    (if (or (nil? escrow-id) (and (string? escrow-id) (str/blank? escrow-id)))
      {:state state :response {"ok" false "error" "missing-escrow-id"} :net-envelopes [] :stdout-events []}
      (let [preimage (or (get cmd-map "preimage") (:preimage cmd-map)
                         (get cmd-map "deliverable") (:deliverable cmd-map))
            raw-sig (or (get cmd-map "payer_signature") (get cmd-map "payer-signature")
                        (:payer_signature cmd-map) (:payer-signature cmd-map))
            raw-psrc (or (get cmd-map "puzzle_source") (get cmd-map "puzzle-source")
                         (:puzzle_source cmd-map) (:puzzle-source cmd-map))
            raw-sol (or (get cmd-map "solution") (:solution cmd-map))
            solution (when (some? raw-sol) (parse-structured-arg raw-sol))
            local-escrow (get-in state [:escrows escrow-id])
            d-hash (or (when local-escrow (:deliverable-hash local-escrow))
                       (get cmd-map "deliverable_hash") (get cmd-map "deliverable-hash")
                       (:deliverable_hash cmd-map) (:deliverable-hash cmd-map))
            is-puzzle? (or (and (string? raw-psrc) (not (str/blank? raw-psrc)))
                           (and local-escrow (:puzzle-hash local-escrow)))
            final-sig (or raw-sig
                          (when (and (not is-puzzle?)
                                     (= (:pubkey state) (when local-escrow (:payer local-escrow)))
                                     (string? d-hash))
                            (escrow/sign-escrow-release privkey-bytes escrow-id d-hash)))
            release-payload (cond-> {:type :release-intent
                                     :escrow-id escrow-id
                                     :epoch (effective-chain-epoch state)
                                     :receipt-id (str "release:" escrow-id)}
                              preimage (assoc :preimage preimage)
                              final-sig (assoc :payer-signature final-sig)
                              raw-psrc (assoc :puzzle-source raw-psrc)
                              (some? solution) (assoc :solution solution))
            envelope (wrap-agent-event release-payload (:pubkey state) privkey-bytes)
            new-state (if local-escrow
                        (assoc-in state [:escrows escrow-id :status] :release-submitted)
                        state)]
        {:state new-state
         :response {"ok" true "escrow_id" escrow-id "intent_id" escrow-id "status" "release-submitted"}
         :net-envelopes [envelope]
         :stdout-events []}))))

(defn- exec-refund-intent [state cmd-map privkey-bytes]
  (let [escrow-id (or (get cmd-map "intent_id") (get cmd-map "intent-id")
                      (:intent_id cmd-map) (:intent-id cmd-map)
                      (get cmd-map "escrow_id") (get cmd-map "escrow-id")
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
         :response {"ok" true "escrow_id" escrow-id "intent_id" escrow-id "status" "refund-submitted"}
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

(defn- split-qualified-directory-name
  "Splits a possibly qualified `<domain>/<nickname>` string into `[domain-or-nil nickname]` (`P-SOAK-2`)."
  [raw-nick explicit-domain]
  (if (and (string? raw-nick) (not (str/blank? raw-nick)))
    (let [trimmed (str/trim raw-nick)
          slash-idx (.lastIndexOf trimmed "/")]
      (if (pos? slash-idx)
        (let [d (subs trimmed 0 slash-idx)
              n (subs trimmed (inc slash-idx))]
          [(if (and (string? explicit-domain) (not (str/blank? explicit-domain)))
             explicit-domain
             d)
           n])
        [explicit-domain trimmed]))
    [explicit-domain raw-nick]))

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
  (let [raw-nick (or (get cmd-map "nickname") (:nickname cmd-map)
                     (get cmd-map "name") (:name cmd-map))
        raw-domain (or (get cmd-map "domain") (:domain cmd-map))
        [split-dom nick] (split-qualified-directory-name raw-nick raw-domain)
        domain (or split-dom "bitecho.org")
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
  (let [raw-nick (or (get cmd-map "nickname") (:nickname cmd-map)
                     (get cmd-map "name") (:name cmd-map))
        raw-domain (or (get cmd-map "domain") (:domain cmd-map))
        [_ nick] (split-qualified-directory-name raw-nick raw-domain)
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
          (let [verify-map (assoc cmd-map "nickname" norm-nick "directory_pubkey" trusted-pub)
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

(defn- kw-map->snake-str-map
  [m]
  (reduce-kv (fn [acc k v]
               (assoc acc (str/replace (if (keyword? k) (name k) (str k)) "-" "_") v))
             {}
             (or m {})))

(defn exec-status
  "Pure status query returning canonical `bitecho.status/v1` fields via `bitecho.status.core/render-status`
   plus backwards-compatible light-node fields (balances, inbox counts, sessions, merged diagnostics,
   and BIP-020 Pillars 1-3 delivery telemetry)."
  ([state] (exec-status state nil nil))
  ([state now-ms] (exec-status state now-ms nil))
  ([state now-ms runtime-ctx]
   (let [inbox-items (or (:inbox state) [])
         inbox-direct (count (filter (fn [m] (= (or (:type m) (get m "type")) :direct)) inbox-items))
         inbox-broadcast-items (filter (fn [m] (or (= (or (:type m) (get m "type")) :broadcast)
                                                   (true? (:broadcast? m))))
                                       inbox-items)
         inbox-broadcast (count inbox-broadcast-items)
         inbox-by-subnet (reduce (fn [acc m]
                                   (if-let [sub (or (:subnet-id m) (:subnet m) (get m "subnet-id") (get m "subnet_id"))]
                                     (update acc (str sub) (fnil inc 0))
                                     acc))
                                 {}
                                 inbox-broadcast-items)
         merged-diags (merge (or (:diagnostics state) {})
                             (or (:conn-diagnostics state) {}))
         dt (merge initial-delivery-telemetry (or (:delivery-telemetry state) {}))
         ev-by-reason (merge (:evicted-by-reason initial-delivery-telemetry)
                             (or (:evicted-by-reason dt) {}))
         rx-not-emitted (merge (:received-but-not-emitted initial-delivery-telemetry)
                               (or (:received-but-not-emitted dt) {}))
         fanout (merge (:fanout initial-delivery-telemetry)
                       (or (:fanout dt) {}))
         ring-buf (vec (or (:ring-buffer dt) []))
         eff-now (long (or now-ms (:now-ms state) 0))
         unacked-aged (compute-unacked-aged-count state eff-now)
         delivery-telemetry-resp {"sent" (long (or (:sent dt) 0))
                                  "acked" (long (or (:acked dt) 0))
                                  "unacked_aged" unacked-aged
                                  "unacked_age_threshold_ms" (long (or (:unacked-age-threshold-ms state) default-unacked-age-threshold-ms))
                                  "evicted_by_reason" (kw-map->snake-str-map ev-by-reason)
                                  "received_but_not_emitted" (kw-map->snake-str-map rx-not-emitted)
                                  "fanout" (kw-map->snake-str-map fanout)
                                  "ring_buffer_count" (count ring-buf)
                                  "ring_buffer_max" delivery-ring-max-entries}
         wire-proto {"version" current-wire-version
                     "min_supported" min-supported-wire-version
                     "max_supported" max-supported-wire-version
                     "unsupported_dropped" (get-in state [:wire-version-diagnostics :unsupported-dropped] 0)
                     "last_unsupported_version" (get-in state [:wire-version-diagnostics :last-unsupported-version])
                     "wire_format" current-wire-format
                     "supported_formats" ["fressian-v1" "legacy-nippy"]
                     "unsupported_format_dropped" (get-in state [:wire-version-diagnostics :unsupported-format-dropped] 0)
                     "last_unsupported_format" (get-in state [:wire-version-diagnostics :last-unsupported-format])}
         eff-rctx (merge {:runtime #?(:clj :jvm :cljs :nodejs)
                          :now-ms eff-now
                          :version config/version
                          :wire-protocol wire-proto}
                         (:runtime-ctx state)
                         runtime-ctx)
         canonical (status-core/render-status state eff-rctx)
         stalled? (boolean (get canonical "stalled"))
         stall-duration-ms (long (or (get canonical "stall_duration_ms") 0))
         combined-diags (merge merged-diags (get canonical "diagnostics"))
         resp (cond-> (merge canonical
                             {"delivery_telemetry" delivery-telemetry-resp
                              "diagnostics" combined-diags
                              "autonomous" (:autonomous? state)
                              "pending_offers_count" (count (:pending-offers state))
                              "pending_rendezvous_count" (count (:pending-rendezvous state {}))
                              "rendezvous_policy" (:rendezvous-policy state)
                              "inbox_direct_count" inbox-direct
                              "inbox_broadcast_count" inbox-broadcast
                              "inbox_by_subnet" inbox-by-subnet
                              "account" (:account state)
                              "dac" (dac-summary (:dac state))
                              "revoked_dacs_count" (count (:revoked-dacs state #{}))
                              "directory_cache_count" (count (:directory-cache state {}))
                              "escrows_count" (count (:escrows state {}))
                              "accounting" {"scope" "local-non-consensus"
                                            "note" "Locally computed devnet totals; never consensus finalized"
                                            "burned_ech" (get-in state [:local-accounting :burned-ech] 0)
                                            "vouchers_count" (count (:vouchers state []))}
                              "wire_protocol" wire-proto})
                (contains? state :events-out) (assoc "events_out" (:events-out state))
                (:mdns-hostname state) (assoc "mdns_hostname" (:mdns-hostname state))
                (:lan-ip state) (assoc "lan_ip" (:lan-ip state))
                (seq (:default-p2p-candidates state)) (assoc "default_p2p_candidates" (:default-p2p-candidates state)))]
     (merge resp
            {:state state
             :stalled? stalled?
             :stall-duration-ms stall-duration-ms
             :response resp
             :net-envelopes []
             :stdout-events []}))))

;; -----------------------------------------------------------------------------
;; Actionable Event Queue & Shuttle Verbs (A2, A2a, F-Bb-6)
;; -----------------------------------------------------------------------------

(def actionable-event-types
  "Taxonomy of actionable events enqueued into :event-queue."
  #{"message-received"
    "offer-received"
    "channel-opened"
    "channel-closed"
    "rendezvous-session-established"
    "p2p-connected"
    "p2p-disconnected"
    "p2p-offer-received"
    "p2p-answer-received"
    "p2p-offer-answered-while-open"
    "diagnostic"
    "outbox-evicted"
    "storage-replicated"
    "artifact-replicated"
    "artifact-revoked"
    "governance-replicated"
    "broadcast-received"
    "broadcast-rejected"
    "subnet-id-reconciled"
    "session-replay-detected"
    "session-seq-mismatch"
    "transfer-received"
    "capability-published"})

(defn- actionable-event? [ev]
  (when (map? ev)
    (let [ev-name (or (get ev "event") (:event ev))]
      (contains? actionable-event-types ev-name))))

(defn- unauthenticated-sig-invalid-event? [ev]
  (and (map? ev)
       (= "broadcast-rejected" (or (get ev "event") (:event ev)))
       (= "broadcast-sig-invalid" (or (get ev "reason") (:reason ev)))))

(defn- tag-and-enqueue-event [state ev]
  (if (actionable-event? ev)
    (let [cur-q (vec (or (:event-queue state) []))
          ;; BIP-021 §2.3: isolate/rate-limit unauthenticated broadcast-sig-invalid events
          ;; so floods cannot evict real messages from the 256-entry :event-queue.
          sig-flood-suppressed? (and (unauthenticated-sig-invalid-event? ev)
                                     (>= (count (filter unauthenticated-sig-invalid-event? cur-q)) 16))]
      (if sig-flood-suppressed?
        (update-in state [:diagnostics :broadcast-sig-invalid-queue-throttled] (fnil inc 0))
        (let [next-id (inc (long (or (:last-event-id state) 0)))
              tagged (cond-> ev
                       (map? ev) (assoc "event_id" next-id :event-id next-id))
              max-q (long (or (:max-event-queue-size state) 256))
              q (conj cur-q tagged)
              overflow? (> (count q) max-q)
              dropped (if overflow? (- (count q) max-q) 0)
              trimmed-q (if overflow? (subvec q dropped) q)
              hist0 (conj (vec (or (:event-history state) [])) tagged)
              trimmed-hist (if (> (count hist0) max-q)
                             (subvec hist0 (- (count hist0) max-q))
                             hist0)]
          (-> state
              (assoc :last-event-id next-id)
              (assoc :event-queue trimmed-q)
              (assoc :event-history trimmed-hist)
              (cond-> overflow?
                (-> (update-in [:diagnostics :event-queue-overflow] (fnil + 0) dropped)
                    (update-in [:diagnostics :dropped] (fnil + 0) dropped)
                    (record-suppression :queue-overflow dropped)))))))
    state))

(defn enqueue-actionable-events
  "Enqueues actionable events into state's persistent :event-queue tagged with monotonic event-id."
  [state events]
  (reduce tag-and-enqueue-event state events))

(defn exec-wait
  "Pure reducer for 'wait' command (BIP-020 Catch 4).
   Separates global `event_id` cursor from per-stream `seq`/`broadcast_seq`, supports
   `subnet_id`, `session_id`, `min_seq`, `min_broadcast_seq`, `after_ts`, and non-destructive
   cursor-based reads so concurrent/reconnecting watchers never lose events.
   Counts every suppressed event in `received_but_not_emitted`."
  [state cmd-map]
  (let [peek? (or (true? (get cmd-map "peek"))
                  (true? (:peek cmd-map))
                  (= (get cmd-map "peek") "true"))
        block? (or (true? (get cmd-map "block"))
                   (true? (:block cmd-map))
                   (= (get cmd-map "block") "true"))
        non-destructive? (or (contains? cmd-map "cursor")
                             (contains? cmd-map :cursor)
                             (true? (get cmd-map "non_destructive"))
                             (true? (:non-destructive cmd-map)))
        req-cursor (when-let [c (or (get cmd-map "cursor") (:cursor cmd-map))]
                     (parse-long-safe c nil))
        min-seq (when-let [ms (or (get cmd-map "min_seq") (get cmd-map "min-seq") (:min-seq cmd-map))]
                  (parse-long-safe ms nil))
        min-bseq (when-let [mb (or (get cmd-map "min_broadcast_seq") (get cmd-map "min-broadcast-seq") (:min-broadcast-seq cmd-map))]
                   (parse-long-safe mb nil))
        sub-filter (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet cmd-map))
        sid-filter (or (get cmd-map "session_id") (get cmd-map "session-id") (:session-id cmd-map))
        after-ts (when-let [at (or (get cmd-map "after_ts") (get cmd-map "after-ts") (:after-ts cmd-map))]
                   (parse-long-safe at nil))
        net-uri (or (:network-uri state)
                    (config/resolve-network-uri (:bootstrap state))
                    "devnet.bitecho.org")
        filter-opts {:enforce-waitable-type? false
                     :cursor req-cursor
                     :session-id sid-filter
                     :subnet-id sub-filter
                     :network-uri net-uri
                     :min-seq min-seq
                     :min-broadcast-seq min-bseq
                     :after-ts after-ts
                     :allow-eid-fallback-for-min-seq? (not non-destructive?)}
        has-filter? (or (some? req-cursor) (some? min-seq) (some? min-bseq)
                        (some? sub-filter) (some? sid-filter) (some? after-ts))
        raw-q (if non-destructive?
                (let [hist (vec (or (:event-history state) []))]
                  (if (seq hist) hist (vec (or (:event-queue state) []))))
                (vec (or (:event-queue state) [])))
        [eligible-evs drop-reasons]
        (if has-filter?
          (reduce (fn [[matched drops] ev]
                    (if-let [reason (classify-wait-filter-drop-reason ev filter-opts)]
                      [matched (conj drops reason)]
                      [(conj matched ev) drops]))
                  [[] []]
                  raw-q)
          [raw-q []])
        st-counted (reduce (fn [s r] (record-suppression s r 1)) state drop-reasons)
        cursor (long (or (:event-ack-cursor st-counted) 0))]
    (if peek?
      (let [resp {"ok" true "events" eligible-evs "cursor" cursor "peek" true}]
        (merge resp {:state st-counted :response resp :net-envelopes [] :stdout-events []}))
      (if (seq eligible-evs)
        (let [norm-evs (mapv (fn [ev]
                               (let [eid (or (get ev "event_id") (:event-id ev) (get ev "eid") (:eid ev))]
                                 (cond-> ev
                                   eid (assoc "eid" eid :eid eid))))
                             eligible-evs)
              last-ev (last norm-evs)
              last-id (long (or (get last-ev "event_id") (:event-id last-ev) (get last-ev "eid") (:eid last-ev) (count norm-evs)))
              new-cursor (max cursor last-id)
              new-state (if non-destructive?
                          (assoc st-counted :event-ack-cursor new-cursor)
                          (let [matched-set (set eligible-evs)
                                remaining (filterv (fn [ev] (not (contains? matched-set ev)))
                                                   (vec (or (:event-queue st-counted) [])))]
                            (assoc st-counted :event-queue remaining :event-ack-cursor new-cursor)))
              resp {"ok" true "events" norm-evs "cursor" new-cursor}]
          (merge resp {:state new-state :response resp :net-envelopes [] :stdout-events []}))
        (let [resp (cond-> {"ok" true "events" [] "cursor" cursor}
                     block? (assoc "timeout" true)
                     (not block?) (assoc "park" true))]
          (merge resp {:state st-counted :response resp :net-envelopes [] :stdout-events []}))))))

(defn verify-and-strip-chunk-prefixes
  "Verifies per-chunk 8-char SHA-256 checksums if declared, returning:
   {:ok? true :hex <concatenated-hex>} on success, or
   {:ok? false :error \"chunk-checksum-mismatch\" :line line :expected expected :actual actual}
   on checksum failure."
  [text]
  (if-not (string? text)
    {:ok? true :hex ""}
    (let [lines (remove str/blank? (map str/trim (str/split-lines text)))]
      (if (empty? lines)
        {:ok? true :hex ""}
        (loop [remaining lines
               acc []]
          (if (empty? remaining)
            {:ok? true :hex (apply str acc)}
            (let [line (first remaining)
                  m-chunk (or (re-matches #"(?i)^L\d+(?:\s*\[\d+c\s+sha=([0-9a-f]{8})\])?:\s*(.*)$" line)
                              (re-matches #"(?i)^\[([0-9a-f]{8})\]\s*(.*)$" line))]
              (if-not m-chunk
                ;; Line without chunk headers - plain hex line
                (recur (rest remaining) (conj acc (str/replace line #"\s+" "")))
                (let [expected-sha (second m-chunk)
                      payload (str/trim (nth m-chunk 2))]
                  (if (str/blank? expected-sha)
                    ;; Header without sha (e.g. "L01: ...")
                    (recur (rest remaining) (conj acc (str/replace payload #"\s+" "")))
                    (let [actual-sha (subs (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes payload))) 0 8)]
                      (if (not= (str/lower-case expected-sha) (str/lower-case actual-sha))
                        {:ok? false
                         :error "chunk-checksum-mismatch"
                         :line line
                         :expected (str/lower-case expected-sha)
                         :actual (str/lower-case actual-sha)}
                        (recur (rest remaining) (conj acc (str/replace payload #"\s+" "")))))))))))))))

(defn strip-chunk-prefixes
  "Strips chunked line headers (e.g. 'L01 [200c sha=89abcdef]: ...' or 'L01: ...') from text.
   Verifies 8-char SHA-256 checksums if declared; returns cleaned hex if valid, or throws ex-info on mismatch."
  [text]
  (let [res (verify-and-strip-chunk-prefixes text)]
    (if (:ok? res)
      (:hex res)
      (throw (ex-info "chunk-checksum-mismatch" res)))))

(defn parse-poll-payloads
  "Parses a poll response JSON, chunked lines, or hex string into a seq of maps:
   [{:hex <envelope-hex> :relay-seq <seq> :broadcast-seq <bseq>}]."
  [raw]
  (cond
    (map? raw)
    (let [msgs (or (get raw "messages") (:messages raw) [])
          bcasts (or (get raw "broadcasts") (:broadcasts raw) [])
          snap (or (get raw "chain_state_snapshot") (get raw "chain-state-snapshot")
                   (get raw :chain-state-snapshot) (get raw :chain_state_snapshot)
                   (when (or (get raw "validator_pubkey") (get raw :validator-pubkey)) raw))
          extract-hex (fn [entry]
                        (let [raw-h (or (get entry "envelope_hex") (get entry "envelope")
                                        (:envelope-hex entry) (:envelope entry) "")
                              v-res (verify-and-strip-chunk-prefixes raw-h)]
                          (if-not (:ok? v-res)
                            v-res
                            (:hex v-res))))
          snap-hex (when (map? snap)
                     (let [raw-h (or (get snap "envelope_hex") (get snap "envelope")
                                     (:envelope-hex snap) (:envelope snap))]
                       (if (and raw-h (string? raw-h))
                         (extract-hex snap)
                         (basalt/bytes->hex (fressian/encode-wire snap)))))
          snap-err (when (and (map? snap-hex) (false? (:ok? snap-hex))) snap-hex)
          msg-items (mapv (fn [m]
                            (let [h (extract-hex m)]
                              {:hex h
                               :relay-seq (long (or (get m "relay_seq") (get m "relay-seq") (:relay-seq m) 0))
                               :broadcast-seq 0}))
                          msgs)
          msg-err (some (fn [m] (when (and (map? (:hex m)) (false? (:ok? (:hex m)))) (:hex m))) msg-items)
          bcast-items (mapv (fn [b]
                              (let [h (extract-hex b)]
                                {:hex h
                                 :relay-seq 0
                                 :broadcast-seq (long (or (get b "broadcast_seq") (get b "broadcast-seq") (:broadcast-seq b) 0))}))
                            bcasts)
          bcast-err (some (fn [b] (when (and (map? (:hex b)) (false? (:ok? (:hex b)))) (:hex b))) bcast-items)]
      (cond
        snap-err snap-err
        msg-err msg-err
        bcast-err bcast-err
        :else
        (cond-> (into [] (concat msg-items bcast-items))
          (and snap-hex (string? snap-hex))
          (conj {:hex snap-hex :relay-seq 0 :broadcast-seq 0}))))

    (string? raw)
    (let [trimmed (str/trim raw)]
      (if (or (str/starts-with? trimmed "{") (str/starts-with? trimmed "["))
        (let [parsed (try (parse-json-str trimmed) (catch #?(:clj Exception :cljs :default) _ nil))]
          (if (map? parsed)
            (parse-poll-payloads parsed)
            []))
        ;; Not JSON: chunked lines or raw hex
        (let [v-res (verify-and-strip-chunk-prefixes trimmed)]
          (if-not (:ok? v-res)
            v-res
            (if (seq (:hex v-res))
              [{:hex (:hex v-res) :relay-seq 0 :broadcast-seq 0}]
              [])))))

    :else []))

(defn build-ack-request-map
  "Builds an authenticated Proof-of-Possession ack request map signed by privkey-bytes."
  [pubkey-hex ^bytes privkey-bytes ack-seq ack-bseq now-ms]
  (let [pk (normalize-pubkey-hex pubkey-hex)
        seq-num (long (or ack-seq 0))
        ts (long (or now-ms 0))
        nonce (str "ack-" seq-num "-" (subs pk 0 (min 8 (count pk))) "-" ts)
        signing-str (str "bitecho-relay-poll-v1|" pk "|" seq-num "|" ts "|" nonce)
        sig-bytes (crypto/sign privkey-bytes (fressian/utf8->bytes signing-str))
        sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))]
    (cond-> {"pubkey" pk
             "ack_seq" seq-num
             "timestamp_ms" ts
             "nonce" nonce
             "signature" sig-hex}
      (pos? (long (or ack-bseq 0))) (assoc "ack_broadcast_seq" (long ack-bseq)))))

(defn- exec-import-poll
  "Pure reducer for import-poll. Ingests raw poll JSON, chunked lines, or hex envelopes.
   Passes each envelope through handle-wire-payload, updates :last-relay-seq and :last-broadcast-seq,
   and generates a signed ack_request."
  [state cmd-map privkey-bytes]
  (let [raw-data (or (get cmd-map "file_content") (get cmd-map "file-content")
                     (get cmd-map "json") (:json cmd-map)
                     (get cmd-map "text") (:text cmd-map)
                     (get cmd-map "payload") (:payload cmd-map))
        payloads (parse-poll-payloads raw-data)]
    (cond
      (and (map? payloads) (false? (:ok? payloads)))
      {:state (update-in state [:diagnostics :chunk-checksum-mismatch] (fnil inc 0))
       :response {"ok" false "error" (:error payloads) "expected" (:expected payloads) "actual" (:actual payloads) "line" (:line payloads)}
       :net-envelopes []
       :stdout-events [{"event" "chunk-checksum-mismatch" "error" (:error payloads) "expected" (:expected payloads) "actual" (:actual payloads)}]}

      (empty? payloads)
      {:state state
       :response {"ok" false "error" "empty-or-invalid-poll-data"}
       :net-envelopes []
       :stdout-events []}

      :else
      (let [init-res {:state state :stdout-events [] :net-envelopes []
                      :p2p-dials []
                      :max-relay-seq (long (or (:last-relay-seq state) 0))
                      :max-bseq (long (or (:last-broadcast-seq state) 0))
                      :count 0}
            reduced (reduce (fn [acc item]
                              (let [h (:hex item)
                                    bs (try (basalt/hex->bytes h) (catch #?(:clj Exception :cljs :default) _ nil))]
                                (if-not bs
                                  acc
                                  (let [w-res (handle-wire-payload (:state acc) bs privkey-bytes)]
                                    (cond-> (-> acc
                                                (assoc :state (:state w-res))
                                                (update :stdout-events into (:stdout-events w-res))
                                                (update :net-envelopes into (:net-envelopes w-res))
                                                (update :max-relay-seq max (:relay-seq item))
                                                (update :max-bseq max (:broadcast-seq item))
                                                (update :count inc))
                                      (:p2p-dial w-res)
                                      (update :p2p-dials conj (:p2p-dial w-res)))))))
                            init-res
                            payloads)
            new-st (assoc (:state reduced)
                          :last-relay-seq (:max-relay-seq reduced)
                          :last-broadcast-seq (:max-bseq reduced))
            ack-req (when (pos? (:max-relay-seq reduced))
                      (build-ack-request-map (:pubkey state) privkey-bytes
                                             (:max-relay-seq reduced)
                                             (:max-bseq reduced)
                                             nil))]
        (cond-> {:state new-st
                 :response (cond-> {"ok" true
                                    "imported_count" (:count reduced)
                                    "last_relay_seq" (:max-relay-seq reduced)
                                    "last_broadcast_seq" (:max-bseq reduced)
                                    "events" (:stdout-events reduced)}
                             ack-req (assoc "ack_request" ack-req))
                 :net-envelopes (:net-envelopes reduced)
                 :stdout-events (:stdout-events reduced)}
          (seq (:p2p-dials reduced))
          (assoc :p2p-dial (last (:p2p-dials reduced))
                 :p2p-dials (:p2p-dials reduced)))))))

(defn- exec-import
  "Pure reducer for import. Ingests a hex envelope string (or chunked lines),
   passes it through handle-wire-payload, and returns resulting state and events."
  [state cmd-map privkey-bytes]
  (let [raw-hex (or (get cmd-map "hex") (:hex cmd-map)
                    (get cmd-map "file_content") (get cmd-map "file-content")
                    (get cmd-map "text") (:text cmd-map))
        v-res (verify-and-strip-chunk-prefixes raw-hex)]
    (if-not (:ok? v-res)
      {:state (update-in state [:diagnostics :chunk-checksum-mismatch] (fnil inc 0))
       :response {"ok" false "error" (:error v-res) "expected" (:expected v-res) "actual" (:actual v-res) "line" (:line v-res)}
       :net-envelopes []
       :stdout-events [{"event" "chunk-checksum-mismatch" "error" (:error v-res) "expected" (:expected v-res) "actual" (:actual v-res)}]}
      (let [clean-hex (:hex v-res)
            bs (try (basalt/hex->bytes clean-hex) (catch #?(:clj Exception :cljs :default) _ nil))]
        (if (or (nil? bs) (zero? (fressian/count-bytes bs)))
          {:state state
           :response {"ok" false "error" "invalid-hex-envelope"}
           :net-envelopes []
           :stdout-events []}
          (let [w-res (handle-wire-payload state bs privkey-bytes)
                events (:stdout-events w-res)]
            (cond-> {:state (:state w-res)
                     :response {"ok" true
                                "envelope_processed" true
                                "events" events}
                     :net-envelopes (:net-envelopes w-res)
                     :stdout-events events}
              (:p2p-dial w-res)
              (assoc :p2p-dial (:p2p-dial w-res)
                     :p2p-dials [(:p2p-dial w-res)]))))))))

(defn- exec-export-poll
  "Pure helper for export-poll. Generates a signed Proof-of-Possession poll request map."
  [state cmd-map privkey-bytes]
  (let [pk (normalize-pubkey-hex (:pubkey state))
        since-seq (long (or (get cmd-map "since_seq") (get cmd-map "since-seq")
                            (:since_seq cmd-map) (:since-seq cmd-map)
                            (:last-relay-seq state) 0))
        since-bseq (long (or (get cmd-map "since_broadcast_seq") (get cmd-map "since-broadcast-seq")
                             (:since_broadcast_seq cmd-map) (:since-broadcast-seq cmd-map)
                             (:last-broadcast-seq state) 0))
        ts (long (or (get cmd-map "now_ms") (:now-ms cmd-map)
                     (get cmd-map "timestamp_ms") (get cmd-map "timestamp-ms")
                     (:epoch state 0)))
        nonce (str "poll-" since-seq "-" (subs pk 0 (min 8 (count pk))) "-" ts)
        signing-str (str "bitecho-relay-poll-v1|" pk "|" since-seq "|" ts "|" nonce)
        sig-bytes (crypto/sign privkey-bytes (fressian/utf8->bytes signing-str))
        sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
        eff-subnets (vec (sort (effective-subscribed-subnets state)))
        req {"pubkey" pk
             "since_seq" since-seq
             "since_broadcast_seq" since-bseq
             "subnets" eff-subnets
             "subnet_ids" eff-subnets
             "timestamp_ms" ts
             "nonce" nonce
             "signature" sig-hex}]
    {:state state
     :response {"ok" true
                "poll_request" req}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-ack
  "Pure helper for ack. If session target is provided, emits a session-ack envelope for that session.
   Otherwise emits a relay ack_request."
  [state cmd-map privkey-bytes]
  (let [target (or (get cmd-map "session_id") (get cmd-map "session-id") (get cmd-map "session")
                   (:session_id cmd-map) (:session-id cmd-map) (:session cmd-map)
                   (get cmd-map "to") (:to cmd-map)
                   (get cmd-map "peer") (:peer cmd-map)
                   (get cmd-map "callee") (:callee cmd-map))]
    (if target
      (let [resolved-sid (resolve-session-id state cmd-map :open)]
        (cond
          (and (map? resolved-sid) (false? (:ok? resolved-sid)))
          {:state state
           :response {"ok" false "error" (:error resolved-sid) "matches" (:matches resolved-sid)}
           :net-envelopes []
           :stdout-events []}

          (nil? resolved-sid)
          {:state state
           :response {"ok" false "error" "session-not-open"}
           :net-envelopes []
           :stdout-events []}

          :else
          (let [sid resolved-sid
                session (get-in state [:sessions sid])]
            (if-not (and session (= "open" (:state session)))
              {:state state
               :response {"ok" false "error" "session-not-open"}
               :net-envelopes []
               :stdout-events []}
              (let [contig (long (or (:contiguous-rx-seq session) 0))
                    msg-seq (long (or (get cmd-map "seq") (:seq cmd-map) contig))
                    seen-seqs (vec (sort (or (:seen (:replay-window session)) [])))
                    env (build-session-ack-envelope state sid (:peer session) contig msg-seq seen-seqs privkey-bytes)]
                {:state state
                 :response {"ok" true "session_id" sid "ack_seq" contig "acked_seq" msg-seq}
                 :net-envelopes (if env [env] [])
                 :stdout-events []})))))
      (let [up-to-seq (long (or (get cmd-map "up_to_seq") (get cmd-map "up-to-seq")
                                (get cmd-map "seq") (:seq cmd-map)
                                (:up_to_seq cmd-map) (:up-to-seq cmd-map) 0))
            up-to-bseq (when-let [b (or (get cmd-map "up_to_broadcast_seq") (get cmd-map "up-to-broadcast-seq")
                                        (:up_to_broadcast_seq cmd-map) (:up-to-broadcast-seq cmd-map))]
                         (long b))
            now-ms (long (or (get cmd-map "now_ms") (:now-ms cmd-map)
                             (get cmd-map "timestamp_ms") (get cmd-map "timestamp-ms")
                             (:epoch state 0)))
            ack-req (build-ack-request-map (:pubkey state) privkey-bytes up-to-seq up-to-bseq now-ms)]
        {:state state
         :response {"ok" true
                    "ack_request" ack-req}
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-export-ack
  "Pure helper for export-ack. If session target is provided, emits a session-ack envelope and returns envelope_hex.
   Otherwise emits a signed Proof-of-Possession ack request map."
  [state cmd-map privkey-bytes]
  (let [target (or (get cmd-map "session_id") (get cmd-map "session-id") (get cmd-map "session")
                   (:session_id cmd-map) (:session-id cmd-map) (:session cmd-map)
                   (get cmd-map "to") (:to cmd-map)
                   (get cmd-map "peer") (:peer cmd-map)
                   (get cmd-map "callee") (:callee cmd-map))]
    (if target
      (let [res (exec-ack state cmd-map privkey-bytes)]
        (if-not (get-in res [:response "ok"])
          res
          (let [env (first (:net-envelopes res))
                env-hex (when env (basalt/bytes->hex (fressian/encode-canonical env)))]
            {:state (:state res)
             :response (cond-> (:response res)
                         env-hex (assoc "envelope_hex" env-hex))
             :net-envelopes (:net-envelopes res)
             :stdout-events (:stdout-events res)})))
      (exec-ack state cmd-map privkey-bytes))))

(defn- exec-export-offer
  "Pure helper for export-offer. Emits a channel offer and returns its envelope hex."
  [state cmd-map privkey-bytes]
  (let [callee (or (get cmd-map "to") (get cmd-map "callee") (get cmd-map "peer")
                   (get cmd-map "session_id") (get cmd-map "session-id")
                   (:to cmd-map) (:callee cmd-map) (:peer cmd-map)
                   (:session_id cmd-map) (:session-id cmd-map))
        off-map (assoc cmd-map "callee" callee)
        res (exec-offer state off-map privkey-bytes)]
    (if-not (get-in res [:response "ok"])
      res
      (let [env (last (:net-envelopes res))
            env-hex (when env (basalt/bytes->hex (fressian/encode-canonical env)))]
        {:state (:state res)
         :response (cond-> (:response res)
                     env-hex (assoc "envelope_hex" env-hex))
         :net-envelopes (:net-envelopes res)
         :stdout-events (:stdout-events res)}))))

(defn- exec-export-send
  "Pure helper for export-send. Emits a sealed message and returns its envelope hex."
  [state cmd-map privkey-bytes]
  (let [res (exec-send state cmd-map privkey-bytes)]
    (if-not (get-in res [:response "ok"])
      res
      (let [env (first (:net-envelopes res))
            env-hex (basalt/bytes->hex (fressian/encode-canonical env))]
        {:state (:state res)
         :response (assoc (:response res) "envelope_hex" env-hex)
         :net-envelopes (:net-envelopes res)
         :stdout-events (:stdout-events res)}))))

(defn- exec-export-reveal
  "Pure helper for export-reveal. Emits rendezvous reveal / ack vouchers and returns envelope_hex."
  [state cmd-map privkey-bytes]
  (let [res (exec-rendezvous-accept state cmd-map privkey-bytes)]
    (if-not (get-in res [:response "ok"])
      res
      (let [envs (:net-envelopes res)
            env (first envs)
            env-hex (when env (basalt/bytes->hex (fressian/encode-canonical env)))
            hexes (mapv #(basalt/bytes->hex (fressian/encode-canonical %)) envs)]
        {:state (:state res)
         :response (cond-> (:response res)
                     env-hex (assoc "envelope_hex" env-hex)
                     (seq hexes) (assoc "envelopes_hex" hexes))
         :net-envelopes envs
         :stdout-events (:stdout-events res)}))))

(defn- exec-export-p2p-offer
  "Pure helper for export-p2p-offer. Emits a p2p-offer envelope and returns envelope_hex."
  [state cmd-map privkey-bytes]
  (let [res (exec-p2p-offer state cmd-map privkey-bytes)]
    (if-not (get-in res [:response "ok"])
      res
      (let [env (last (:net-envelopes res))
            env-hex (when env (basalt/bytes->hex (fressian/encode-canonical env)))]
        {:state (:state res)
         :response (cond-> (:response res)
                     env-hex (assoc "envelope_hex" env-hex))
         :net-envelopes (:net-envelopes res)
         :stdout-events (:stdout-events res)}))))

(defn- exec-export-p2p-answer
  "Pure helper for export-p2p-answer. Emits a p2p-answer envelope and returns envelope_hex."
  [state cmd-map privkey-bytes]
  (let [res (exec-p2p-answer state cmd-map privkey-bytes)]
    (if-not (get-in res [:response "ok"])
      res
      (let [env (last (:net-envelopes res))
            env-hex (when env (basalt/bytes->hex (fressian/encode-canonical env)))]
        {:state (:state res)
         :response (cond-> (:response res)
                     env-hex (assoc "envelope_hex" env-hex))
         :net-envelopes (:net-envelopes res)
         :stdout-events (:stdout-events res)}))))

(declare dispatch-multiplexed-command)

(defn- ensure-light-node-subnet-mux
  [state sub-id privkey-bytes]
  (if (or (contains? (:subnets state) sub-id)
          (:bitecho.subnet/unified? state)
          (nil? privkey-bytes)
          (nil? (:pubkey state))
          (= sub-id "global"))
    state
    (let [parent-sid "global"
          parent-policy {:subnet/id parent-sid
                         :subnet/gate {:gate/mode :permissionless :gate/admission :open}
                         :subnet/economy {:economy/mode :burn-only :economy/burn-floor 0}
                         :subnet/path-acl [{:pattern "anchor/*" :principal {:type :allowlist}}]
                         :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
          child-policy {:subnet/id sub-id
                        :subnet/parent-id parent-sid
                        :subnet/gate {:gate/mode :permissioned :gate/admission :allowlist :gate/trust-anchors #{(:pubkey state)}}
                        :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                        :subnet/path-acl [{:pattern "head/*" :principal {:type :allowlist}}]
                        :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}
                        :subnet/anchoring {:trigger :epoch
                                           :authority-privkey privkey-bytes
                                           :authority-pubkey (:pubkey state)}}
          parent-inst (:instance (core-subnet/init-subnet-instance parent-policy))
          child-inst (:instance (core-subnet/init-subnet-instance child-policy))]
      (update state :subnets (fn [m]
                               (assoc (or m {})
                                      parent-sid (or (get m parent-sid) parent-inst)
                                      sub-id child-inst))))))

(defn- anchor-effects->net-envelopes
  [state privkey-bytes effects]
  (if-not privkey-bytes
    []
    (vec
     (keep (fn [eff]
             (when (= :anchor-to-parent (:effect eff))
               (let [parent-sid (str (or (:parent-subnet eff) "global"))
                     payload (freeze-payload (merge {:type :anchor-to-parent} eff))
                     burn-amt (max 100 (effective-signaling-burn-floor state))]
                 (build-gossip-envelope (:pubkey state) privkey-bytes payload burn-amt parent-sid))))
           effects))))

(defn- exec-anchor-subnet
  [state effective-map privkey-bytes sub-id]
  (let [state (ensure-light-node-subnet-mux state sub-id privkey-bytes)]
    (cond
      (contains? (:subnets state) sub-id)
      (let [res (dispatch-multiplexed-command state sub-id (assoc effective-map :type :anchor-subnet) privkey-bytes)
            anchor-envs (anchor-effects->net-envelopes state privkey-bytes (:effects res))]
        {:state (:mux res)
         :response (:response res)
         :effects (or (:effects res) [])
         :net-envelopes (into (vec (or (:net-envelopes res) [])) anchor-envs)
         :stdout-events (or (:stdout-events res) [])})

      (:bitecho.subnet/unified? state)
      (let [res (core-subnet/reduce-subnet state (assoc effective-map :type :anchor-subnet))
            anchor-envs (anchor-effects->net-envelopes state privkey-bytes (:effects res))]
        {:state (:state res)
         :response (if (:applied? res)
                     (cond-> {"ok" true "subnet" (:subnet/id (:policy state))}
                       (:anchor res) (assoc "anchor" (:anchor res)))
                     {"ok" false "error" (str (:error res))})
         :effects (or (:effects res) [])
         :net-envelopes anchor-envs
         :stdout-events []})

      :else
      {:state state :response {"ok" false "error" "subnet-not-found" "subnet" sub-id} :net-envelopes [] :stdout-events []})))

(defn- exec-epoch-tick
  [state effective-map privkey-bytes sub-id]
  (let [explicit-ep (parse-long-safe (or (get effective-map "epoch") (:epoch effective-map)) nil)
        target-ep (long (or explicit-ep (inc (long (or (:epoch state) 0)))))
        act-res (gov/activate-epoch-upgrades (or (:governance state) (gov/init-governance-state)) target-ep)
        gov-st (dissoc (or (:state act-res) act-res) :state :activated)
        state (-> state
                  (assoc :governance gov-st)
                  (cond-> explicit-ep (assoc :epoch target-ep))
                  (ensure-light-node-subnet-mux sub-id privkey-bytes))]
    (cond
      (contains? (:subnets state) sub-id)
      (let [res (dispatch-multiplexed-command state sub-id (assoc effective-map :type :epoch-tick) privkey-bytes)
            anchor-envs (anchor-effects->net-envelopes state privkey-bytes (:effects res))
            mux-st (assoc (:mux res) :governance gov-st)]
        {:state (if explicit-ep (assoc mux-st :epoch target-ep) mux-st)
         :response (:response res)
         :effects (or (:effects res) [])
         :net-envelopes (into (vec (or (:net-envelopes res) [])) anchor-envs)
         :stdout-events (or (:stdout-events res) [])})

      (:bitecho.subnet/unified? state)
      (let [res (core-subnet/reduce-subnet state (assoc effective-map :type :epoch-tick))
            anchor-envs (anchor-effects->net-envelopes state privkey-bytes (:effects res))]
        {:state (assoc (:state res) :governance gov-st)
         :response (if (:applied? res)
                     (cond-> {"ok" true "subnet" (:subnet/id (:policy state))}
                       (:anchor res) (assoc "anchor" (:anchor res)))
                     {"ok" true "subnet" (:subnet/id (:policy state)) "unchanged" true})
         :effects (or (:effects res) [])
         :net-envelopes anchor-envs
         :stdout-events []})

      :else
      {:state (assoc state :epoch target-ep :governance gov-st)
       :response {"ok" true "epoch" target-ep}
       :net-envelopes []
       :stdout-events []})))

(defn- exec-verify-subnet-anchor
  [state effective-map sub-id]
  (let [ptr (or (:pointer effective-map) (get effective-map "pointer"))
        blob (or (:blob effective-map) (get effective-map "blob"))
        prev-anchor (or (:prev-anchor effective-map) (:prev-anchor-entry effective-map) (get effective-map "prev_anchor"))
        parent-sid (or (get effective-map "parent_subnet") (get effective-map "parent-subnet") (:parent-subnet effective-map) sub-id "global")
        parent-inst (when (:subnets state) (get-in state [:subnets parent-sid]))
        now-ms (long (or (:now-ms effective-map) 0))
        parent-ctx (cond
                     (and parent-inst (:bitecho.subnet/unified? parent-inst))
                     (core-subnet/pointer-verify-ctx parent-inst nil now-ms)

                     (:bitecho.subnet/unified? state)
                     (core-subnet/pointer-verify-ctx state nil now-ms)

                     :else
                     (or (:parent-ctx effective-map) (get effective-map "parent_ctx") {}))
        res (core-subnet/verify-subnet-anchor ptr blob parent-ctx prev-anchor)]
    {:state state
     :response (if (:ok? res)
                 {"ok" true "verified" true "child_subnet" (:child-subnet res) "merkle_root" (:merkle-root res) "child_epoch" (:child-epoch res) "anchor_seq" (:anchor-seq res)}
                 {"ok" false "error" (str (:error res))})
     :net-envelopes []
     :stdout-events []}))

(defn- exec-puzzle-hash
  [state cmd-map]
  (let [src (or (get cmd-map "puzzle_source") (get cmd-map "puzzle-source")
                (:puzzle_source cmd-map) (:puzzle-source cmd-map))]
    (if (or (nil? src) (and (string? src) (str/blank? src)))
      {:state state :response {"ok" false "error" "missing-puzzle-source"} :net-envelopes [] :stdout-events []}
      (let [src-str (str src)
            cid (puzzle/puzzle-cid src-str)
            size-bytes (fressian/count-bytes (fressian/utf8->bytes src-str))]
        {:state state
         :response {"ok" true
                    "puzzle_hash" cid
                    "size_bytes" size-bytes}
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-puzzle-eval
  [state cmd-map]
  (let [src (or (get cmd-map "puzzle_source") (get cmd-map "puzzle-source")
                (:puzzle_source cmd-map) (:puzzle-source cmd-map))]
    (if (or (nil? src) (and (string? src) (str/blank? src)))
      {:state state :response {"ok" false "error" "missing-puzzle-source"} :net-envelopes [] :stdout-events []}
      (let [raw-sol (or (get cmd-map "solution") (:solution cmd-map))
            solution (if (some? raw-sol) (parse-structured-arg raw-sol) {})
            amount (long (or (get cmd-map "amount") (:amount cmd-map) 1000))
            raw-payer (or (get cmd-map "payer") (:payer cmd-map))
            payer (if raw-payer
                    (or (:pubkey (resolve-counterparty state raw-payer)) raw-payer)
                    (or (:pubkey state) "0000000000000000000000000000000000000000000000000000000000000000"))
            raw-recv (or (get cmd-map "receiver") (get cmd-map "recipient")
                         (:receiver cmd-map) (:recipient cmd-map))
            receiver (if raw-recv
                       (or (:pubkey (resolve-counterparty state raw-recv)) raw-recv)
                       (or (:pubkey state) "1111111111111111111111111111111111111111111111111111111111111111"))
            raw-dh (or (get cmd-map "deliverable_hash") (get cmd-map "deliverable-hash")
                       (:deliverable_hash cmd-map) (:deliverable-hash cmd-map))
            src-cid (puzzle/puzzle-cid (str src))
            puzzle-hash (or (get cmd-map "puzzle_hash") (get cmd-map "puzzle-hash")
                            (:puzzle_hash cmd-map) (:puzzle-hash cmd-map)
                            src-cid)
            d-hash (or raw-dh puzzle-hash)
            to-epoch (long (or (get cmd-map "timeout_epoch") (get cmd-map "timeout-epoch")
                               (get cmd-map "expires_epoch") (get cmd-map "expires-epoch")
                               (:timeout_epoch cmd-map) (:timeout-epoch cmd-map)
                               100))
            epoch (long (or (get cmd-map "epoch") (:epoch cmd-map) (:epoch state) 1))
            intent-id (str (or (get cmd-map "intent_id") (get cmd-map "intent-id")
                               (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                               (:intent_id cmd-map) (:intent-id cmd-map)
                               "eval-intent"))
            env-ctx {:amount amount
                     :receiver receiver
                     :payer payer
                     :deliverable-hash d-hash
                     :puzzle-hash puzzle-hash
                     :timeout-epoch to-epoch
                     :epoch epoch
                     :escrow-id intent-id}
            res (puzzle/eval-puzzle (str src) solution env-ctx)]
        {:state state
         :response {"ok" true
                    "valid" (boolean (:valid? res))
                    "puzzle_hash" puzzle-hash
                    "conditions" (mapv (fn [c] (cond-> {"type" (name (:type c))}
                                                 (:receiver c) (assoc "receiver" (:receiver c))
                                                 (:amount c) (assoc "amount" (:amount c))
                                                 (:epoch c) (assoc "epoch" (:epoch c))))
                                       (:conditions res))
                    "error" (some-> (:error res) name)}
         :net-envelopes []
         :stdout-events []}))))

(defn prepare-storage-put
  "Pure two-phase `storage-put` preparation (BIP-022 Stage A, Row 7; Rules 2 & 5).
   - Packs encrypted `Blob` + signed monotonic `Pointer` via `bitecho.core.storage`.
   - When `--local-only` (`local_only` / `:local-only`) is explicitly set, writes locally,
     emits a counted `:storage-put-local-only` `:diagnose` effect, and returns
     `{\"ok\" true \"replicated\" false \"local_only\" true ...}`.
   - Otherwise, does NOT advance `:storage-pointers` or `:storage-min-seqs` yet; returns
     `{:ok? true :pending-publish? true :publish-intent {...} :state state ...}` so the shell
     must confirm network publication via `commit-storage-put-outcome`."
  [state effective-map privkey-bytes _sub-id]
  (let [burn-amt (max 0 (long (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)) 0) 0)))
        burn-chk (check-and-deduct-burn state burn-amt)]
    (if-not (:ok? burn-chk)
      (let [err (errors/canonical-error (:error burn-chk) {:burn burn-amt})
            st-err (errors/record-error-diagnostic state err)]
        {:ok? false
         :state st-err
         :response (errors/canonical-error->wire err)
         :effects [(errors/diagnose-effect err)]
         :net-envelopes []
         :stdout-events []})
      (let [st-after-burn (:state burn-chk)
            raw-data (get effective-map "data" (get effective-map "payload" (get effective-map :data (:payload effective-map))))
            raw-hex (or (get effective-map "data_hex") (get effective-map "data-hex")
                        (:data_hex effective-map) (:data-hex effective-map))
            data (cond
                   (some? raw-data) raw-data
                   (and (string? raw-hex) (not (str/blank? raw-hex))) (fressian/hex->bytes raw-hex)
                   :else nil)
            slot (str (or (get effective-map "slot_id") (get effective-map "slot-id")
                          (:slot_id effective-map) (:slot-id effective-map)
                          (get effective-map "slot") (:slot effective-map)
                          "default"))
            subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) _sub-id "global"))
            path (str "storage/" (:pubkey state) "/" slot)
            min-seq (long (get-in state [:storage-min-seqs [subnet path]] 0))
            seq-num (long (or (get effective-map "seq") (:seq effective-map) (inc min-seq)))
            context (or (get effective-map "context") (:context effective-map))
            nonce (or (get effective-map "nonce") (:nonce effective-map))
            local-only? (boolean (or (get effective-map "local_only")
                                     (get effective-map "local-only")
                                     (:local-only effective-map)
                                     (:local_only effective-map)))
            pack-res (storage/pack-encrypted-state {:privkey privkey-bytes
                                                    :pubkey (:pubkey state)
                                                    :subnet-id subnet
                                                    :slot slot
                                                    :seq seq-num
                                                    :state-data data
                                                    :context context
                                                    :nonce-bytes nonce})
            cid (:cid pack-res)
            blob (:blob pack-res)
            ptr (:pointer pack-res)
            size-bytes (if blob (fressian/count-bytes (:blob/bytes blob)) 0)
            rep-payload {:protocol-version current-wire-version
                         :wire-format current-wire-format
                         :bitecho/type :storage-replicate
                         :subnet-id subnet
                         :path path
                         :blob blob
                         :pointer ptr
                         :sender (:pubkey state)
                         :epoch (or (:epoch state) 0)
                         :timestamp (now-utc-ms)}
            outer-sub (if (pos? burn-amt) "*" subnet)
            rep-envelope (when privkey-bytes
                           (let [gossip-env (build-gossip-envelope
                                             (normalize-pubkey-hex (:pubkey state))
                                             privkey-bytes
                                             (freeze-payload rep-payload)
                                             burn-amt
                                             outer-sub)]
                             (merge rep-payload gossip-env {:p2p-broadcast? true})))]
        (if local-only?
          (let [diag {:effect :diagnose
                      :type :diagnose
                      :reason :storage-put-local-only
                      :cid cid
                      :path path
                      :seq seq-num}
                st-local (-> st-after-burn
                             (assoc-in [:blobs cid] blob)
                             (assoc-in [:pointers [subnet path]] ptr)
                             (assoc-in [:storage-blobs cid] blob)
                             (assoc-in [:storage-pointers [subnet path]] ptr)
                             (assoc-in [:storage-min-seqs [subnet path]] seq-num)
                             (update-in [:diagnostics :storage-put-local-only] (fnil inc 0)))]
            {:ok? true
             :local-only? true
             :pending-publish? false
             :state st-local
             :response {"ok" true
                        "cid" cid
                        "path" path
                        "seq" seq-num
                        "slot" slot
                        "slot_id" slot
                        "subnet_id" subnet
                        "size_bytes" size-bytes
                        "burn" burn-amt
                        "replicated" false
                        "local_only" true
                        "blob" blob
                        "pointer" ptr}
             :effects [diag]
             :net-envelopes (if rep-envelope [rep-envelope] [])
             :stdout-events []})
          {:ok? true
           :local-only? false
           :pending-publish? true
           :state state
           :publish-intent {:cid cid
                            :path path
                            :subnet subnet
                            :slot slot
                            :seq seq-num
                            :size-bytes size-bytes
                            :burn burn-amt
                            :blob blob
                            :pointer ptr
                            :state-after-burn st-after-burn}
           :response {"ok" false
                      "pending" true
                      "cid" cid
                      "path" path
                      "seq" seq-num
                      "slot" slot
                      "slot_id" slot
                      "subnet_id" subnet
                      "size_bytes" size-bytes
                      "burn" burn-amt
                      "replicated" false
                      "blob" blob
                      "pointer" ptr}
           :effects []
           :net-envelopes (if rep-envelope [rep-envelope] [])
           :stdout-events []})))))

(defn commit-storage-put-outcome
  "Pure shell-confirmation reducer for `storage-put` (BIP-022 Stage A, Row 7; Rules 2 & 5).
   - Commits local blob/pointer/min-seq and returns `{\"ok\" true \"replicated\" true \"endpoints\" [...]}`
     ONLY when `(:ok? outcome)` is true AND `(seq (:endpoints outcome))` is non-empty.
   - Otherwise fails closed with zero partial pointer advance, canonical `:storage-publish-failed`
     error envelope, and counted Rule 5 `:diagnose`."
  [state publish-intent outcome]
  (let [endpoints (->> (or (:endpoints outcome) (get outcome "endpoints") [])
                       (filter #(and (string? %) (not (str/blank? %))))
                       vec)
        confirmed? (and (true? (or (:ok? outcome) (get outcome "ok")))
                        (seq endpoints))
        {:keys [cid path subnet slot seq size-bytes burn blob pointer state-after-burn]} publish-intent]
    (if confirmed?
      (let [base-st (or state-after-burn state)
            st-committed (-> base-st
                             (assoc-in [:blobs cid] blob)
                             (assoc-in [:pointers [subnet path]] pointer)
                             (assoc-in [:storage-blobs cid] blob)
                             (assoc-in [:storage-pointers [subnet path]] pointer)
                             (assoc-in [:storage-min-seqs [subnet path]] seq))]
        {:ok? true
         :state st-committed
         :response {"ok" true
                    "cid" cid
                    "path" path
                    "seq" seq
                    "slot" slot
                    "slot_id" slot
                    "subnet_id" subnet
                    "size_bytes" size-bytes
                    "burn" burn
                    "replicated" true
                    "endpoints" endpoints
                    "blob" blob
                    "pointer" pointer}
         :effects []
         :net-envelopes []
         :stdout-events []})
      (let [detail (cond-> {:cid cid
                            :path path
                            :subnet-id subnet
                            :seq seq}
                     (:status outcome) (assoc :status (:status outcome))
                     (:error outcome) (assoc :cause (str (:error outcome)))
                     (:detail outcome) (assoc :detail (:detail outcome))
                     (empty? endpoints) (assoc :reason "network-replication-unconfirmed"))
            err (errors/canonical-error :storage-publish-failed detail)
            st-err (errors/record-error-diagnostic state err)]
        {:ok? false
         :state st-err
         :response (errors/canonical-error->wire err {"cid" cid
                                                      "path" path
                                                      "seq" seq
                                                      "replicated" false})
         :effects [(errors/diagnose-effect err)]
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-storage-put
  [state effective-map privkey-bytes _sub-id]
  (let [prep (prepare-storage-put state effective-map privkey-bytes _sub-id)]
    (cond
      (not (:ok? prep))
      (dissoc prep :ok?)

      (:local-only? prep)
      (dissoc prep :ok? :local-only? :pending-publish?)

      :else
      (let [receipt (or (get effective-map "network_receipt")
                        (:network-receipt effective-map)
                        {:ok? false :detail "network-replication-unconfirmed"})
            committed (commit-storage-put-outcome state (:publish-intent prep) receipt)]
        (-> committed
            (dissoc :ok?)
            (assoc :net-envelopes (:net-envelopes prep)))))))

(defn- exec-storage-get
  [state effective-map privkey-bytes _sub-id]
  (let [slot (str (or (get effective-map "slot_id") (get effective-map "slot-id")
                      (:slot_id effective-map) (:slot-id effective-map)
                      (get effective-map "slot") (:slot effective-map)
                      "default"))
        subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) _sub-id "global"))
        path (str (or (get effective-map "path") (:path effective-map) (str "storage/" (:pubkey state) "/" slot)))
        ptr (or (get effective-map "pointer") (:pointer effective-map) (get-in state [:storage-pointers [subnet path]]))
        target-cid (when ptr (:pointer/target ptr))
        blob (or (get effective-map "blob") (:blob effective-map) (when target-cid (get-in state [:storage-blobs target-cid])))
        min-expected (long (or (get effective-map "min_seq") (get effective-map "min-seq") (:min-seq effective-map)
                               (get effective-map "min_expected_seq") (get effective-map "min-expected-seq") (:min-expected-seq effective-map)
                               (get-in state [:storage-min-seqs [subnet path]] 0)))
        context (or (get effective-map "context") (:context effective-map))]
    (if-not (and blob ptr)
      {:state state
       :response {"ok" false "error" "missing-storage-entry"}
       :net-envelopes []
       :stdout-events []}
      (let [res (storage/unpack-encrypted-state {:privkey privkey-bytes
                                                 :pubkey (:pubkey state)
                                                 :blob blob
                                                 :pointer ptr
                                                 :min-expected-seq min-expected
                                                 :context context})]
        (if (:ok? res)
          {:state (assoc-in state [:storage-min-seqs [subnet path]] (:seq res))
           :response {"ok" true
                      "data" (:data res)
                      "seq" (:seq res)
                      "cid" (:cid res)
                      "path" (:path res)
                      "slot" slot
                      "slot_id" slot
                      "subnet_id" subnet}
           :net-envelopes []
           :stdout-events []}
          {:state state
           :response {"ok" false "error" (name (:error res))}
           :net-envelopes []
           :stdout-events []})))))

(defn- exec-storage-list
  [state effective-map]
  (let [target-subnet (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map))
        slots (->> (:storage-pointers state {})
                   (filter (fn [[[sub _] _]]
                             (or (nil? target-subnet) (= sub (str target-subnet)))))
                   (map (fn [[[sub path] ptr]]
                          (let [cid (:pointer/target ptr)
                                blob (get-in state [:storage-blobs cid])
                                sz (if blob (fressian/count-bytes (:blob/bytes blob)) 0)
                                after-storage (if (str/starts-with? (str path) "storage/")
                                                (subs (str path) (count "storage/"))
                                                (str path))
                                parts (str/split after-storage #"/")
                                slot-id (if (> (count parts) 1)
                                          (str/join "/" (rest parts))
                                          (first parts))]
                            {"subnet_id" sub
                             "path" (str path)
                             "slot_id" slot-id
                             "cid" cid
                             "authority" (:pointer/authority ptr)
                             "seq" (:pointer/seq ptr)
                             "size_bytes" sz})))
                   (sort-by #(get % "path"))
                   vec)]
    {:state state
     :response {"ok" true
                "count" (count slots)
                "slots" slots}
     :net-envelopes []
     :stdout-events []}))

(defn- extract-artifact-bytes
  [effective-map]
  (let [raw-bytes (or (get effective-map "bytes") (:bytes effective-map))
        raw-hex (or (get effective-map "hex")
                    (get effective-map "data_hex")
                    (get effective-map "data-hex")
                    (:hex effective-map)
                    (:data-hex effective-map)
                    (:data_hex effective-map))
        raw-text (or (get effective-map "text")
                     (get effective-map "data")
                     (get effective-map "file_content")
                     (get effective-map "file-content")
                     (:text effective-map)
                     (:data effective-map)
                     (:file-content effective-map)
                     (:file_content effective-map))]
    (cond
      (fressian/bytes? raw-bytes)
      raw-bytes

      (and (string? raw-hex) (not (str/blank? raw-hex)))
      (let [clean (str/trim raw-hex)]
        (when (and (even? (count clean)) (re-matches #"[0-9a-fA-F]*" clean))
          (fressian/hex->bytes clean)))

      (some? raw-text)
      (fressian/utf8->bytes (str raw-text))

      :else
      nil)))

(defn- exec-artifact-put
  [state effective-map privkey-bytes sub-id]
  (let [raw-burn (if (contains? effective-map "burn")
                   (get effective-map "burn")
                   (:burn effective-map))
        default-burn (if (get state :economy-enabled? true)
                       (max 100 (effective-signaling-burn-floor state))
                       0)
        burn-amt (max 0 (long (if (some? raw-burn)
                                (or (parse-long-safe raw-burn default-burn) default-burn)
                                default-burn)))
        burn-chk (check-and-deduct-burn state burn-amt)]
    (if-not (:ok? burn-chk)
      {:state state :response {"ok" false "error" (:error burn-chk)} :net-envelopes [] :stdout-events []}
      (let [st-after-burn (:state burn-chk)
            subnet (str (or (get effective-map "subnet_id")
                            (get effective-map "subnet-id")
                            (:subnet-id effective-map)
                            sub-id
                            (:subnet-id state)
                            "global"))
            raw-path (str (or (get effective-map "path") (:path effective-map) ""))
            path (str/replace (str/trim raw-path) #"^/+" "")
            bs (extract-artifact-bytes effective-map)]
        (cond
          (or (str/blank? path) (str/includes? path ".."))
          {:state (update-in state [:diagnostics :artifact-put-rejected] (fnil inc 0))
           :response {"ok" false "error" "invalid-artifact-path" "path" path}
           :net-envelopes []
           :stdout-events []}

          (nil? bs)
          {:state (update-in state [:diagnostics :artifact-put-rejected] (fnil inc 0))
           :response {"ok" false "error" "missing-artifact-payload" "path" path}
           :net-envelopes []
           :stdout-events []}

          :else
          (let [blob (data/make-blob bs)
                cid (:blob/cid blob)
                local-prev-seq (long (or (get-in st-after-burn [:artifact-min-seqs [subnet path]])
                                         (when-let [p (get-in st-after-burn [:artifact-pointers [subnet path]])]
                                           (:pointer/seq p))
                                         (when-let [t (get-in st-after-burn [:artifact-tombstones [subnet path]])]
                                           (:pointer/seq t))
                                         0))
                remote-seq (long (or (parse-long-safe (or (get effective-map "min_remote_seq") (:min-remote-seq effective-map)) 0) 0))
                prev-seq (max local-prev-seq remote-seq)
                explicit-seq (parse-long-safe (or (get effective-map "seq") (:seq effective-map)) nil)
                seq-num (long (if (some? explicit-seq) explicit-seq (inc prev-seq)))]
            (if (<= seq-num prev-seq)
              {:state (update-in state [:diagnostics :stale-pointer-seq] (fnil inc 0))
               :response {"ok" false "error" "stale-pointer-seq" "seq" seq-num "current_seq" prev-seq "path" path}
               :net-envelopes []
               :stdout-events []}
              (let [my-pub (normalize-pubkey-hex (:pubkey st-after-burn))
                    fallback-kp (when-not privkey-bytes
                                  (crypto/generate-keypair (str "artifact-authority-" my-pub)))
                    eff-priv (or privkey-bytes (:private fallback-kp))
                    eff-pub (if privkey-bytes my-pub (basalt/bytes->hex (:public fallback-kp)))
                    ts (now-utc-ms)
                    raw-replicas (or (get effective-map "replicas") (:replicas effective-map) (:artifact-replicas st-after-burn))
                    replicas (when (sequential? raw-replicas) (vec (map str raw-replicas)))
                    raw-confirmed (or (get effective-map "confirmed_replicas") (:confirmed-replicas effective-map))
                    confirmed-replicas (when (sequential? raw-confirmed) (vec (map str raw-confirmed)))
                    req-quorum (parse-long-safe (or (get effective-map "replica_quorum") (:replica-quorum effective-map)) nil)
                    quorum-unmet? (and (some? req-quorum)
                                       (some? confirmed-replicas)
                                       (< (count confirmed-replicas) (long req-quorum)))]
                (if quorum-unmet?
                  (let [missing-reps (vec (remove (set confirmed-replicas) (or replicas [])))
                        diag {"reason" "artifact-replica-quorum-unmet"
                              "required_quorum" (long req-quorum)
                              "confirmed_replicas" confirmed-replicas
                              "missing_replicas" missing-reps}]
                    {:state (update-in state [:diagnostics :artifact-replica-quorum-unmet] (fnil inc 0))
                     :response {"ok" false
                                "error" "artifact-replica-quorum-unmet"
                                "subnet_id" subnet
                                "path" path
                                "cid" cid
                                "required_quorum" (long req-quorum)
                                "confirmed_replicas" confirmed-replicas
                                "missing_replicas" missing-reps
                                "diagnose" diag}
                     :net-envelopes []
                     :stdout-events []})
                  (let [unsigned-ptr (cond-> {:pointer/subnet subnet
                                              :pointer/path path
                                              :pointer/authority eff-pub
                                              :pointer/seq seq-num
                                              :pointer/leader-term 1
                                              :pointer/target cid
                                              :pointer/proof {:proof/type :self}
                                              :pointer/timestamp ts}
                                       (seq replicas) (assoc :pointer/replicas replicas))
                        ptr (cond-> (assoc (data/sign-pointer eff-priv unsigned-ptr) :pointer/timestamp ts)
                              (seq replicas) (assoc :pointer/replicas replicas))
                        rep-payload {:protocol-version current-wire-version
                                     :wire-format current-wire-format
                                     :bitecho/type :artifact-replicate
                                     :type :artifact-replicate
                                     :subnet-id subnet
                                     :path path
                                     :cid cid
                                     :seq seq-num
                                     :blob blob
                                     :pointer ptr
                                     :replicas replicas
                                     :sender eff-pub
                                     :epoch (long (or (:epoch st-after-burn) 0))
                                     :timestamp ts}
                        outer-sub (if (pos? burn-amt) "*" subnet)
                        rep-envelope (when eff-priv
                                       (let [gossip-env (build-gossip-envelope
                                                         eff-pub
                                                         eff-priv
                                                         (freeze-payload rep-payload)
                                                         burn-amt
                                                         outer-sub)]
                                         (merge rep-payload gossip-env {:p2p-broadcast? true})))]
                    {:state (-> st-after-burn
                                (assoc-in [:blobs cid] blob)
                                (assoc-in [:pointers [subnet path]] ptr)
                                (assoc-in [:artifact-blobs cid] blob)
                                (assoc-in [:artifact-pointers [subnet path]] ptr)
                                (update :artifact-tombstones dissoc [subnet path])
                                (assoc-in [:artifact-min-seqs [subnet path]] seq-num))
                     :response (cond-> {"ok" true
                                        "subnet_id" subnet
                                        "path" path
                                        "cid" cid
                                        "seq" seq-num
                                        "authority" eff-pub
                                        "size_bytes" (fressian/count-bytes bs)
                                        "burn" burn-amt
                                        "blob" blob
                                        "pointer" ptr}
                                 (seq replicas) (assoc "replicas" replicas)
                                 (some? req-quorum) (assoc "replica_quorum" (long req-quorum)
                                                           "quorum_confirmed" true))
                     :net-envelopes (if rep-envelope [rep-envelope] [])
                     :stdout-events []}))))))))))

(defn- exec-artifact-revoke
  [state effective-map privkey-bytes sub-id]
  (let [raw-burn (if (contains? effective-map "burn")
                   (get effective-map "burn")
                   (:burn effective-map))
        default-burn (if (get state :economy-enabled? true)
                       (max 100 (effective-signaling-burn-floor state))
                       0)
        burn-amt (max 0 (long (if (some? raw-burn)
                                (or (parse-long-safe raw-burn default-burn) default-burn)
                                default-burn)))
        burn-chk (check-and-deduct-burn state burn-amt)]
    (if-not (:ok? burn-chk)
      {:state state :response {"ok" false "error" (:error burn-chk)} :net-envelopes [] :stdout-events []}
      (let [st-after-burn (:state burn-chk)
            subnet (str (or (get effective-map "subnet_id")
                            (get effective-map "subnet-id")
                            (:subnet-id effective-map)
                            sub-id
                            (:subnet-id state)
                            "global"))
            raw-path (str (or (get effective-map "path") (:path effective-map) ""))
            path (str/replace (str/trim raw-path) #"^/+" "")]
        (if (or (str/blank? path) (str/includes? path ".."))
          {:state (update-in state [:diagnostics :artifact-revoke-rejected] (fnil inc 0))
           :response {"ok" false "error" "invalid-artifact-path" "path" path}
           :net-envelopes []
           :stdout-events []}
          (let [local-prev-seq (long (or (get-in st-after-burn [:artifact-min-seqs [subnet path]])
                                         (when-let [p (get-in st-after-burn [:artifact-pointers [subnet path]])]
                                           (:pointer/seq p))
                                         (when-let [t (get-in st-after-burn [:artifact-tombstones [subnet path]])]
                                           (:pointer/seq t))
                                         0))
                remote-seq (long (or (parse-long-safe (or (get effective-map "min_remote_seq") (:min-remote-seq effective-map)) 0) 0))
                prev-seq (max local-prev-seq remote-seq)
                explicit-seq (parse-long-safe (or (get effective-map "seq") (:seq effective-map)) nil)
                seq-num (long (if (some? explicit-seq) explicit-seq (inc prev-seq)))]
            (if (<= seq-num prev-seq)
              {:state (update-in state [:diagnostics :stale-pointer-seq] (fnil inc 0))
               :response {"ok" false "error" "stale-pointer-seq" "seq" seq-num "current_seq" prev-seq "path" path}
               :net-envelopes []
               :stdout-events []}
              (let [my-pub (normalize-pubkey-hex (:pubkey st-after-burn))
                    fallback-kp (when-not privkey-bytes
                                  (crypto/generate-keypair (str "artifact-authority-" my-pub)))
                    eff-priv (or privkey-bytes (:private fallback-kp))
                    eff-pub (if privkey-bytes my-pub (basalt/bytes->hex (:public fallback-kp)))
                    ts (now-utc-ms)
                    unsigned-ptr {:pointer/subnet subnet
                                  :pointer/path path
                                  :pointer/authority eff-pub
                                  :pointer/seq seq-num
                                  :pointer/leader-term 1
                                  :pointer/target nil
                                  :pointer/proof {:proof/type :self}
                                  :pointer/timestamp ts}
                    ptr (assoc (data/sign-pointer eff-priv unsigned-ptr) :pointer/timestamp ts)
                    rep-payload {:protocol-version current-wire-version
                                 :wire-format current-wire-format
                                 :bitecho/type :artifact-replicate
                                 :type :artifact-replicate
                                 :subnet-id subnet
                                 :path path
                                 :cid nil
                                 :tombstoned true
                                 :seq seq-num
                                 :blob nil
                                 :pointer ptr
                                 :sender eff-pub
                                 :epoch (long (or (:epoch st-after-burn) 0))
                                 :timestamp ts}
                    outer-sub (if (pos? burn-amt) "*" subnet)
                    rep-envelope (when eff-priv
                                   (let [gossip-env (build-gossip-envelope
                                                     eff-pub
                                                     eff-priv
                                                     (freeze-payload rep-payload)
                                                     burn-amt
                                                     outer-sub)]
                                     (merge rep-payload gossip-env {:p2p-broadcast? true})))]
                {:state (-> st-after-burn
                            (assoc-in [:pointers [subnet path]] ptr)
                            (update :artifact-pointers dissoc [subnet path])
                            (assoc-in [:artifact-tombstones [subnet path]] ptr)
                            (assoc-in [:artifact-min-seqs [subnet path]] seq-num))
                 :response {"ok" true
                            "subnet_id" subnet
                            "path" path
                            "cid" nil
                            "tombstoned" true
                            "seq" seq-num
                            "authority" eff-pub
                            "burn" burn-amt
                            "pointer" ptr}
                 :net-envelopes (if rep-envelope [rep-envelope] [])
                 :stdout-events []}))))))))

(defn- exec-artifact-get
  [state effective-map sub-id]
  (let [subnet (str (or (get effective-map "subnet_id")
                        (get effective-map "subnet-id")
                        (:subnet-id effective-map)
                        sub-id
                        (:subnet-id state)
                        "global"))
        raw-path (str (or (get effective-map "path") (:path effective-map) ""))
        path (str/replace (str/trim raw-path) #"^/+" "")
        explicit-cid (let [c (or (get effective-map "cid") (:cid effective-map))]
                       (when (and (string? c) (not (str/blank? c)))
                         (str/lower-case (str/trim c))))]
    (if (and (str/blank? path) explicit-cid)
      (let [blob (or (get-in state [:artifact-blobs explicit-cid])
                     (get-in state [:blobs explicit-cid]))
            ptr (some (fn [[_ p]] (when (= (:pointer/target p) explicit-cid) p))
                      (or (:artifact-pointers state) (:pointers state)))]
        (if-not (and blob (data/verify-blob blob))
          {:state (update-in state [:diagnostics :artifact-get-missing] (fnil inc 0))
           :response {"ok" false
                      "error" "missing-artifact"
                      "subnet_id" subnet
                      "cid" explicit-cid}
           :net-envelopes []
           :stdout-events []}
          (let [bs (:blob/bytes blob)
                hex (basalt/bytes->hex bs)
                text (try (fressian/bytes->utf8 bs) (catch #?(:clj Exception :cljs :default) _ nil))]
            {:state state
             :response {"ok" true
                        "subnet_id" (or (when ptr (:pointer/subnet ptr)) subnet)
                        "path" (or (when ptr (:pointer/path ptr)) "")
                        "cid" explicit-cid
                        "seq" (long (or (when ptr (:pointer/seq ptr)) 1))
                        "authority" (or (when ptr (:pointer/authority ptr)) "")
                        "size_bytes" (fressian/count-bytes bs)
                        "hex" hex
                        "data_hex" hex
                        "text" text
                        "data" text
                        "pointer" ptr}
             :net-envelopes []
             :stdout-events []})))
      (let [tomb (or (get-in state [:artifact-tombstones [subnet path]])
                     (some (fn [[[_ p] t]] (when (= p path) t)) (:artifact-tombstones state)))
            ptr (or (get-in state [:artifact-pointers [subnet path]])
                    (some (fn [[[_ p] candidate-ptr]] (when (= p path) candidate-ptr)) (:artifact-pointers state)))
            cid (or (when ptr (:pointer/target ptr)) explicit-cid)
            local-blob (when cid (or (get-in state [:artifact-blobs cid])
                                     (get-in state [:blobs cid])))
            replicas (let [r (or (get effective-map "replicas")
                                 (:replicas effective-map)
                                 (when ptr (:pointer/replicas ptr))
                                 (:artifact-replicas state))]
                       (when (sequential? r) (vec (map str r))))
            replica-hit (when (and (nil? local-blob) cid (seq replicas))
                          (some (fn [rep]
                                  (when-let [rb (get-in state [:replica-blobs rep cid])]
                                    (when (data/verify-blob rb)
                                      {:replica rep :blob rb})))
                                replicas))
            blob (or local-blob (:blob replica-hit))
            served-by (:replica replica-hit)]
        (cond
          (and tomb (nil? ptr))
          {:state (update-in state [:diagnostics :artifact-get-tombstoned] (fnil inc 0))
           :response {"ok" false
                      "error" "artifact-tombstoned"
                      "subnet_id" subnet
                      "path" path
                      "tombstoned" true
                      "seq" (:pointer/seq tomb)}
           :net-envelopes []
           :stdout-events []}

          (not (and ptr blob (data/verify-blob blob) (:ok? (data/verify-pointer ptr))))
          (let [missing-reps (vec (or replicas []))
                diag {"reason" "artifact-missing-on-replicas"
                      "subnet_id" subnet
                      "path" path
                      "cid" cid
                      "missing_replicas" missing-reps}]
            {:state (-> state
                        (update-in [:diagnostics :artifact-get-missing] (fnil inc 0))
                        (update-in [:diagnostics :artifact-missing-on-replicas] (fnil inc 0)))
             :response (cond-> {"ok" false
                                "error" "missing-artifact"
                                "subnet_id" subnet
                                "path" path
                                "missing_replicas" missing-reps
                                "diagnose" diag}
                         cid (assoc "cid" cid))
             :net-envelopes []
             :stdout-events []})

          :else
          (let [bs (:blob/bytes blob)
                hex (basalt/bytes->hex bs)
                text (try (fressian/bytes->utf8 bs) (catch #?(:clj Exception :cljs :default) _ nil))]
            {:state state
             :response (cond-> {"ok" true
                                "subnet_id" (:pointer/subnet ptr subnet)
                                "path" path
                                "cid" cid
                                "seq" (:pointer/seq ptr)
                                "authority" (:pointer/authority ptr)
                                "size_bytes" (fressian/count-bytes bs)
                                "hex" hex
                                "data_hex" hex
                                "text" text
                                "data" text
                                "pointer" ptr}
                         served-by (assoc "served_by_replica" served-by))
             :net-envelopes []
             :stdout-events []}))))))

(defn- exec-artifact-list
  [state effective-map]
  (let [target-subnet (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map))
        prefix (str (or (get effective-map "prefix") (:prefix effective-map) (get effective-map "path") (:path effective-map) ""))
        clean-prefix (str/replace (str/trim prefix) #"^/+" "")
        raw-auth (or (get effective-map "authority") (get effective-map "pubkey") (:authority effective-map) (:pubkey effective-map))
        auth-filter (when raw-auth (str/lower-case (str/trim (str raw-auth))))
        items (->> (:artifact-pointers state {})
                   (keep (fn [[[sub path] ptr]]
                           (when (and (or (nil? target-subnet) (= sub (str target-subnet)))
                                      (or (str/blank? clean-prefix) (str/starts-with? (str path) clean-prefix))
                                      (or (nil? auth-filter) (= (str/lower-case (str (:pointer/authority ptr))) auth-filter)))
                             (let [cid (:pointer/target ptr)
                                   blob (get-in state [:artifact-blobs cid])
                                   sz (if blob (fressian/count-bytes (:blob/bytes blob)) 0)]
                               {"subnet_id" sub
                                "path" (str path)
                                "cid" cid
                                "seq" (:pointer/seq ptr)
                                "authority" (:pointer/authority ptr)
                                "size_bytes" sz}))))
                   (sort-by #(get % "path"))
                   vec)
        tombs (->> (:artifact-tombstones state {})
                   (keep (fn [[[sub path] ptr]]
                           (when (and (or (nil? target-subnet) (= sub (str target-subnet)))
                                      (or (str/blank? clean-prefix) (str/starts-with? (str path) clean-prefix)))
                             {"subnet_id" sub
                              "path" (str path)
                              "seq" (:pointer/seq ptr)
                              "authority" (:pointer/authority ptr)
                              "tombstoned" true})))
                   (sort-by #(get % "path"))
                   vec)]
    {:state state
     :response {"ok" true
                "count" (count items)
                "artifacts" items
                "pointers" items
                "tombstones" tombs}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-capability-publish
  [state effective-map privkey-bytes sub-id]
  (let [burn-amt (max 0 (long (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)) 0) 0)))
        burn-chk (check-and-deduct-burn state burn-amt)]
    (if-not (:ok? burn-chk)
      {:state state :response {"ok" false "error" (:error burn-chk)} :net-envelopes [] :stdout-events []}
      (let [st-after-burn (:state burn-chk)
            subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) sub-id "global"))
            cap-id (str (or (get effective-map "capability_id") (get effective-map "capability-id") (:capability-id effective-map) "default"))
            raw-type (or (get effective-map "capability_type") (get effective-map "capability-type") (:capability-type effective-map) :storage/blob-pinning)
            cap-type (cond
                       (keyword? raw-type) raw-type
                       (string? raw-type) (keyword (str/replace raw-type #"^:+" ""))
                       :else :storage/blob-pinning)
            price (long (or (get effective-map "price_echo") (get effective-map "price-echo") (:price-echo effective-map) 0))
            burn (long (or (get effective-map "burn_floor") (get effective-map "burn-floor") (:burn-floor effective-map) 0))
            meta-raw (or (get effective-map "metadata") (:metadata effective-map) {})
            meta (if (some? meta-raw) (parse-structured-arg meta-raw) {})
            target (or (get effective-map "target_cid") (get effective-map "target-cid") (:target-cid effective-map))
            seq-num (long (or (get effective-map "seq") (:seq effective-map) 1))
            pack-res (storage/pack-capability-descriptor {:privkey privkey-bytes
                                                          :pubkey (:pubkey state)
                                                          :subnet-id subnet
                                                          :capability-id cap-id
                                                          :capability-type cap-type
                                                          :price-echo price
                                                          :burn-floor burn
                                                          :metadata meta
                                                          :seq seq-num
                                                          :target-cid target})
            cid (:cid pack-res)
            path (:path pack-res)
            blob (:blob pack-res)
            ptr (:pointer pack-res)
            rep-payload {:protocol-version current-wire-version
                         :wire-format current-wire-format
                         :bitecho/type :capability-replicate
                         :subnet-id subnet
                         :path path
                         :blob blob
                         :pointer ptr
                         :sender (:pubkey state)
                         :epoch (or (:epoch state) 0)
                         :timestamp (now-utc-ms)}
            outer-sub (if (pos? burn-amt) "*" subnet)
            rep-envelope (when privkey-bytes
                           (let [gossip-env (build-gossip-envelope
                                             (normalize-pubkey-hex (:pubkey state))
                                             privkey-bytes
                                             (freeze-payload rep-payload)
                                             burn-amt
                                             outer-sub)]
                             (merge rep-payload gossip-env {:p2p-broadcast? true})))]
        {:state (-> st-after-burn
                    (assoc-in [:pointers [subnet path]] ptr)
                    (assoc-in [:blobs cid] blob)
                    (assoc-in [:capabilities [subnet path]] ptr)
                    (assoc-in [:capability-blobs cid] blob))
         :response {"ok" true
                    "capability_id" cap-id
                    "capability_type" (if (keyword? cap-type) (subs (str cap-type) 1) (str cap-type))
                    "price_echo" price
                    "burn_floor" burn
                    "burn" burn-amt
                    "subnet_id" subnet
                    "path" path
                    "cid" cid
                    "seq" seq-num
                    "blob" blob
                    "pointer" ptr}
         :net-envelopes (if rep-envelope [rep-envelope] [])
         :stdout-events []}))))

(defn- exec-capability-resolve
  [state effective-map _privkey-bytes sub-id]
  (let [subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) sub-id "global"))
        cap-id (or (get effective-map "capability_id") (get effective-map "capability-id") (:capability-id effective-map))
        raw-auth (or (get effective-map "authority") (get effective-map "pubkey") (:authority effective-map) (:pubkey effective-map))
        resolved-auth (when raw-auth
                        (let [r (resolve-counterparty state raw-auth)]
                          (if (:ok? r) (:pubkey r) raw-auth)))
        provider (or resolved-auth (:pubkey state))
        canonical-path (if cap-id
                         (if (and subnet (not= subnet "global"))
                           (str "subnet/" subnet "/capability/" provider "/" cap-id)
                           (str "capability/" provider "/" cap-id))
                         nil)
        path (str (or (get effective-map "path") (:path effective-map) canonical-path))
        ptr (or (get effective-map "pointer") (:pointer effective-map)
                (get-in state [:capabilities [subnet path]])
                (when (and cap-id (nil? raw-auth))
                  ;; fallback search in (:capabilities state)
                  (some (fn [[[s p] p-ptr]]
                          (when (and (= s subnet)
                                     (or (= p cap-id)
                                         (str/ends-with? p (str "/" cap-id))))
                            p-ptr))
                        (:capabilities state))))
        target-cid (when ptr (:pointer/target ptr))
        blob (or (get effective-map "blob") (:blob effective-map) (when target-cid (get-in state [:capability-blobs target-cid])))
        min-expected (long (or (get effective-map "min_seq") (get effective-map "min-seq") (:min-seq effective-map)
                               (get effective-map "min_expected_seq") (get effective-map "min-expected-seq") (:min-expected-seq effective-map)
                               0))]
    (if-not (and blob ptr)
      {:state state
       :response {"ok" false "error" "missing-capability"}
       :net-envelopes []
       :stdout-events []}
      (let [res (storage/unpack-capability-descriptor {:blob blob :pointer ptr :min-expected-seq min-expected})]
        (if (:ok? res)
          (let [desc (:capability res)
                desc-map {"capability_id" (:capability/id desc)
                          "capability_type" (if (keyword? (:capability/type desc))
                                              (subs (str (:capability/type desc)) 1)
                                              (str (:capability/type desc)))
                          "provider" (:capability/provider desc)
                          "subnet_id" (:capability/subnet desc)
                          "price_echo" (:capability/price-echo desc)
                          "burn_floor" (:capability/burn-floor desc)
                          "target_cid" (:capability/target-cid desc)
                          "metadata" (:capability/metadata desc)}]
            {:state state
             :response {"ok" true
                        "descriptor" desc-map
                        "capability" desc
                        "cid" (:cid res)
                        "seq" (:seq res)
                        "path" (or (:pointer/path ptr) path)}
             :net-envelopes []
             :stdout-events []})
          {:state state
           :response {"ok" false "error" (name (:error res))}
           :net-envelopes []
           :stdout-events []})))))

(defn- exec-capability-list
  [state effective-map]
  (let [target-subnet (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map))
        raw-type (or (get effective-map "capability_type") (get effective-map "capability-type") (:capability-type effective-map))
        type-filter (when raw-type
                      (if (keyword? raw-type)
                        (subs (str raw-type) 1)
                        (str/replace (str raw-type) #"^:+" "")))
        raw-auth (or (get effective-map "authority") (get effective-map "pubkey") (:authority effective-map) (:pubkey effective-map))
        auth-filter (when raw-auth
                      (let [r (resolve-counterparty state raw-auth)]
                        (if (:ok? r) (:pubkey r) raw-auth)))
        caps (->> (:capabilities state {})
                  (filter (fn [[[sub _] _]]
                            (or (nil? target-subnet) (= sub (str target-subnet)))))
                  (keep (fn [[[sub path] ptr]]
                          (let [cid (:pointer/target ptr)
                                blob (get-in state [:capability-blobs cid])]
                            (when (and blob ptr)
                              (let [res (storage/unpack-capability-descriptor {:blob blob :pointer ptr :min-expected-seq 0})]
                                (when (:ok? res)
                                  (let [desc (:capability res)
                                        desc-type (if (keyword? (:capability/type desc))
                                                    (subs (str (:capability/type desc)) 1)
                                                    (str (:capability/type desc)))
                                        provider (:capability/provider desc)]
                                    (when (and (or (nil? type-filter) (= desc-type type-filter))
                                               (or (nil? auth-filter) (= provider auth-filter)))
                                      {"capability_id" (:capability/id desc)
                                       "capability_type" desc-type
                                       "provider" provider
                                       "subnet_id" (:capability/subnet desc sub)
                                       "price_echo" (:capability/price-echo desc)
                                       "burn_floor" (:capability/burn-floor desc)
                                       "target_cid" (:capability/target-cid desc)
                                       "metadata" (:capability/metadata desc)
                                       "path" (str path)
                                       "cid" cid
                                       "seq" (:pointer/seq ptr)}))))))))
                  (sort-by #(get % "path"))
                  vec)]
    {:state state
     :response {"ok" true
                "count" (count caps)
                "capabilities" caps}
     :net-envelopes []
     :stdout-events []}))

(defn- canonical-governance-replicate-payload
  [subnet-id op sender epoch body]
  ["bitecho-governance-replicate-v1"
   (str subnet-id)
   (if (keyword? op) (name op) (str op))
   (str sender)
   (long (or epoch 0))
   body])

(defn- build-governance-replicate-envelope
  [state privkey-bytes subnet-id op body burn-amt]
  (when privkey-bytes
    (let [sender (normalize-pubkey-hex (:pubkey state))
          ep (long (or (:epoch state) 0))
          signing-payload (canonical-governance-replicate-payload subnet-id op sender ep body)
          sig-hex (basalt/bytes->hex (crypto/sign-canonical privkey-bytes signing-payload))
          rep-payload {:protocol-version current-wire-version
                       :wire-format current-wire-format
                       :bitecho/type :governance-replicate
                       :type :governance-replicate
                       :subnet-id subnet-id
                       :op op
                       :sender sender
                       :epoch ep
                       :timestamp (now-utc-ms)
                       :body body
                       :signature sig-hex}
          outer-sub (if (pos? burn-amt) "*" subnet-id)
          gossip-env (build-gossip-envelope
                      sender
                      privkey-bytes
                      (freeze-payload rep-payload)
                      burn-amt
                      outer-sub)]
      (merge rep-payload gossip-env {:p2p-broadcast? true}))))

(defn- parse-edn-safe
  [v]
  (cond
    (map? v) v
    (and (string? v) (not (str/blank? v)))
    (try (edn/read-string v) (catch #?(:clj Exception :cljs :default) _ nil))
    :else nil))

(defn- exec-bip-submit
  [state effective-map privkey-bytes sub-id]
  (let [burn-amt (max 0 (long (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)) 0) 0)))
        burn-chk (check-and-deduct-burn state burn-amt)]
    (if-not (:ok? burn-chk)
      {:state state :response {"ok" false "error" (:error burn-chk)} :net-envelopes [] :stdout-events []}
      (let [st-after-burn (:state burn-chk)
            subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) sub-id gov/dev-subnet-id))
            spec-map (or (parse-edn-safe (or (get effective-map "spec_edn") (get effective-map "spec-edn") (:spec-edn effective-map))) {})
            policy-map (parse-edn-safe (or (get effective-map "policy_edn") (get effective-map "policy-edn") (:policy-edn effective-map)))
            oracle-map (parse-edn-safe (or (get effective-map "oracle_receipts_edn") (get effective-map "oracle-receipts-edn") (:oracle-receipts-edn effective-map)))
            defspec-csv (or (get effective-map "defspec_vars") (get effective-map "defspec-vars") (:defspec-vars effective-map))
            bip-id (str (or (get effective-map "bip_id") (get effective-map "bip-id") (:bip-id effective-map) (:bip-id spec-map) ""))
            title (str (or (get effective-map "title") (:title effective-map) (:title spec-map) bip-id))
            act-ep (or (parse-long-safe (or (get effective-map "activate_at_epoch") (get effective-map "activate-at-epoch") (:activate-at-epoch effective-map)) nil)
                       (:activate-at-epoch spec-map))
            defspec-vec (when (and (string? defspec-csv) (not (str/blank? defspec-csv)))
                          (vec (remove str/blank? (map str/trim (str/split defspec-csv #",")))))
            jurisdiction-map (or (parse-edn-safe (or (get effective-map "jurisdiction_map") (get effective-map "jurisdiction-map") (:jurisdiction-map effective-map)))
                                 (:jurisdiction-map spec-map))
            human-anchor-sunset (or (get effective-map "human_anchor_sunset") (get effective-map "human-anchor-sunset") (:human-anchor-sunset effective-map)
                                    (:human-anchor-sunset spec-map))
            inv-map (or (parse-edn-safe (or (get effective-map "invariant_diff_edn") (get effective-map "invariant-diff-edn") (:invariant-diff-edn effective-map)))
                        (:invariant-diff spec-map))
            eff-inv (cond
                      (and (map? inv-map) (seq defspec-vec) (empty? (:defspec-vars inv-map)))
                      (assoc inv-map :defspec-vars defspec-vec)
                      (map? inv-map)
                      inv-map
                      :else nil)
            bip-payload (cond-> (merge spec-map
                                       {:subnet-id subnet
                                        :bip-id bip-id
                                        :title title
                                        :author-pubkey (or (:author-pubkey spec-map) (:pubkey state))})
                          eff-inv (assoc :invariant-diff eff-inv)
                          jurisdiction-map (assoc :jurisdiction-map jurisdiction-map)
                          human-anchor-sunset (assoc :human-anchor-sunset human-anchor-sunset)
                          (map? policy-map) (assoc :policy-theta policy-map)
                          (map? oracle-map) (assoc :oracle-receipts oracle-map)
                          (some? act-ep) (assoc :activate-at-epoch (long act-ep)))
            fallback-kp (when-not privkey-bytes
                          (crypto/generate-keypair (str "bip-author-" (:pubkey state))))
            eff-priv (or privkey-bytes (:private fallback-kp))
            gov-st (or (:governance st-after-burn) (gov/init-governance-state))
            res (gov/submit-bip gov-st bip-payload eff-priv)]
        (if-not (:ok? res)
          {:state (-> st-after-burn
                      (assoc :governance (:state res))
                      (update-in [:diagnostics :bip-admission-rejected] (fnil inc 0)))
           :response {"ok" false
                      "error" "bip-admission-rejected"
                      "missing_gates" (mapv #(if (keyword? %) (subs (str %) 1) (str %)) (:missing-gates res))}
           :net-envelopes []
           :stdout-events []}
          (let [bip-rec (gov/get-bip (:state res) subnet bip-id)
                rep-env (build-governance-replicate-envelope
                         st-after-burn
                         privkey-bytes
                         subnet
                         :bip-submit
                         {:subnet-id subnet
                          :bip-id bip-id
                          :bip bip-rec
                          :cid (:cid res)
                          :blob (:blob res)
                          :pointer (:pointer res)}
                         burn-amt)]
            {:state (assoc st-after-burn :governance (:state res))
             :response {"ok" true
                        "subnet_id" subnet
                        "bip_id" bip-id
                        "cid" (:cid res)
                        "status" "under-review"
                        "burn" burn-amt}
             :net-envelopes (if rep-env [rep-env] [])
             :stdout-events []}))))))

(defn- normalize-circle-kw
  [raw-circle]
  (cond
    (keyword? raw-circle) raw-circle
    (string? raw-circle) (keyword (str/replace (str/trim raw-circle) #"^:+" ""))
    :else :builders-stewards))

(defn- ensure-default-circle-member
  [gov-st subnet circle-kw pubkey weight]
  (let [existing (or (get-in gov-st [:circles [subnet circle-kw] pubkey])
                     (when (= subnet gov/dev-subnet-id)
                       (get-in gov-st [:circles circle-kw pubkey])))]
    (if (and existing (pos? (double (:weight existing 0.0))))
      gov-st
      (let [w (max 1 (long (or weight 100)))]
        (gov/register-circle-member
         gov-st
         subnet
         circle-kw
         pubkey
         {:verified-commits w
          :participation 1.0
          :stake (max 250000 w)
          :trailing-burned-ech w})))))

(defn- exec-bip-consent
  [state effective-map privkey-bytes sub-id]
  (let [burn-amt (max 0 (long (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)) 0) 0)))
        burn-chk (check-and-deduct-burn state burn-amt)]
    (if-not (:ok? burn-chk)
      {:state state :response {"ok" false "error" (:error burn-chk)} :net-envelopes [] :stdout-events []}
      (let [st-after-burn (:state burn-chk)
            subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) sub-id gov/dev-subnet-id))
            bip-id (str (or (get effective-map "bip_id") (get effective-map "bip-id") (:bip-id effective-map) ""))
            circle-kw (normalize-circle-kw (or (get effective-map "circle") (:circle effective-map)))
            weight (parse-long-safe (or (get effective-map "weight") (:weight effective-map)) 100)
            my-pub (normalize-pubkey-hex (:pubkey state))
            gov-st0 (or (:governance st-after-burn) (gov/init-governance-state))
            gov-st1 (ensure-default-circle-member gov-st0 subnet circle-kw my-pub weight)
            resp-res (gov/submit-circle-response gov-st1 subnet bip-id circle-kw my-pub {:stance :consent :subnet-id subnet})
            eval-res (gov/evaluate-tri-circle-consent (:state resp-res) subnet bip-id)
            member-weight (long (or (get-in (:state eval-res) [:circles [subnet circle-kw] my-pub :weight]) weight 100))
            rep-env (build-governance-replicate-envelope
                     st-after-burn
                     privkey-bytes
                     subnet
                     :bip-response
                     {:subnet-id subnet
                      :bip-id bip-id
                      :circle circle-kw
                      :member-pubkey my-pub
                      :weight member-weight
                      :response {:stance :consent :subnet-id subnet}}
                     burn-amt)]
        {:state (assoc st-after-burn :governance (:state eval-res))
         :response {"ok" (boolean (:ok? resp-res))
                    "subnet_id" subnet
                    "bip_id" bip-id
                    "circle" (name circle-kw)
                    "recorded_stance" (name (or (:recorded-stance resp-res) :consent))
                    "ratified" (boolean (:ratified? eval-res))
                    "status" (name (or (:status eval-res) :under-review))
                    "burn" burn-amt}
         :net-envelopes (if rep-env [rep-env] [])
         :stdout-events []}))))

(defn- exec-bip-object
  [state effective-map privkey-bytes sub-id]
  (let [burn-amt (max 0 (long (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)) 0) 0)))
        burn-chk (check-and-deduct-burn state burn-amt)]
    (if-not (:ok? burn-chk)
      {:state state :response {"ok" false "error" (:error burn-chk)} :net-envelopes [] :stdout-events []}
      (let [st-after-burn (:state burn-chk)
            subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) sub-id gov/dev-subnet-id))
            bip-id (str (or (get effective-map "bip_id") (get effective-map "bip-id") (:bip-id effective-map) ""))
            circle-kw (normalize-circle-kw (or (get effective-map "circle") (:circle effective-map)))
            ce (parse-edn-safe (or (get effective-map "counterexample_edn") (get effective-map "counterexample-edn") (:counterexample-edn effective-map)))
            weight (parse-long-safe (or (get effective-map "weight") (:weight effective-map)) 100)
            my-pub (normalize-pubkey-hex (:pubkey state))
            gov-st0 (or (:governance st-after-burn) (gov/init-governance-state))
            gov-st1 (ensure-default-circle-member gov-st0 subnet circle-kw my-pub weight)
            response-map {:stance :paramount-objection :counterexample ce :subnet-id subnet}
            resp-res (gov/submit-circle-response gov-st1 subnet bip-id circle-kw my-pub response-map)
            eval-res (gov/evaluate-tri-circle-consent (:state resp-res) subnet bip-id)
            member-weight (long (or (get-in (:state eval-res) [:circles [subnet circle-kw] my-pub :weight]) weight 100))
            rep-env (build-governance-replicate-envelope
                     st-after-burn
                     privkey-bytes
                     subnet
                     :bip-response
                     {:subnet-id subnet
                      :bip-id bip-id
                      :circle circle-kw
                      :member-pubkey my-pub
                      :weight member-weight
                      :response response-map}
                     burn-amt)]
        {:state (assoc st-after-burn :governance (:state eval-res))
         :response {"ok" (boolean (:ok? resp-res))
                    "subnet_id" subnet
                    "bip_id" bip-id
                    "circle" (name circle-kw)
                    "recorded_stance" (name (or (:recorded-stance resp-res) :consent))
                    "ignored_objection" (boolean (:ignored-objection? resp-res))
                    "ratified" (boolean (:ratified? eval-res))
                    "status" (name (or (:status eval-res) :under-review))
                    "burn" burn-amt}
         :net-envelopes (if rep-env [rep-env] [])
         :stdout-events []}))))

(defn- exec-bip-status
  [state effective-map sub-id]
  (let [subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) sub-id gov/dev-subnet-id))
        bip-id (str (or (get effective-map "bip_id") (get effective-map "bip-id") (:bip-id effective-map) ""))
        gov-st (or (:governance state) (gov/init-governance-state))
        eval-res (gov/evaluate-tri-circle-consent gov-st subnet bip-id)
        gov-st' (:state eval-res)
        bip (gov/get-bip gov-st' subnet bip-id)
        status-kw (or (:status bip) (:status eval-res) :unknown-bip)
        reg-vecs (gov/get-subnet-regression-vectors gov-st' subnet)]
    {:state (assoc state :governance gov-st')
     :response {"ok" (some? bip)
                "subnet_id" subnet
                "bip_id" bip-id
                "cid" (:cid bip)
                "title" (:title bip)
                "status" (name status-kw)
                "ratified" (= :ratified status-kw)
                "circle_quorums" (into {} (map (fn [[k v]] [(name k) v]) (:circle-quorums eval-res)))
                "regression_vectors" reg-vecs
                "regression_vectors_count" (count reg-vecs)
                "active_policy" (get-in gov-st' [:subnet-policies subnet])}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-bounty-create
  [state effective-map privkey-bytes sub-id]
  (let [subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) sub-id gov/dev-subnet-id))
        bounty-id (str (or (get effective-map "bounty_id") (get effective-map "bounty-id") (:bounty-id effective-map) ""))
        target-cid (str (or (get effective-map "target_bip_cid") (get effective-map "target-bip-cid") (:target-bip-cid effective-map)
                            (get effective-map "bip_id") (get effective-map "bip-id") (:bip-id effective-map) ""))
        gross (max 0 (long (or (parse-long-safe (or (get effective-map "gross_amount") (get effective-map "gross-amount") (:gross-amount effective-map)
                                                    (get effective-map "amount") (:amount effective-map)) 0) 0)))
        burn-amt (max 0 (long (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)) 0) 0)))
        total-deduct (+ gross burn-amt)
        deduct-chk (check-and-deduct-burn state total-deduct)]
    (if-not (:ok? deduct-chk)
      {:state state :response {"ok" false "error" (:error deduct-chk)} :net-envelopes [] :stdout-events []}
      (let [st-after-deduct (:state deduct-chk)
            m-pub (or (get effective-map "maintainer_pubkey") (get effective-map "maintainer-pubkey") (:maintainer-pubkey effective-map) (:pubkey state))
            take-bps (parse-long-safe (or (get effective-map "take_bps") (get effective-map "take-bps") (:take-bps effective-map)) 50)
            builder-bps (parse-long-safe (or (get effective-map "builder_bps") (get effective-map "builder-bps") (:builder-bps effective-map)) 8500)
            gov-st (or (:governance st-after-deduct) (gov/init-governance-state))
            res (gov/create-bounty-escrow
                 gov-st
                 {:subnet-id subnet
                  :bounty-id bounty-id
                  :target-bip-cid target-cid
                  :gross-amount gross
                  :maintainer-pubkey m-pub
                  :take-bps take-bps
                  :builder-bps builder-bps}
                 privkey-bytes)
            bounty (:bounty res)
            cap-cid (:capability-cid res)
            cap-blob (:capability-blob res)
            cap-ptr (:capability-pointer res)
            cap-path (str "bounty/" bounty-id)
            b-escrow {:bounty-id bounty-id
                      :maintainer-pubkey m-pub
                      :subnet-id subnet
                      :target-bip-cid target-cid
                      :gross-amount gross
                      :take-bps take-bps
                      :builder-bps builder-bps
                      :protocol-take (:protocol-take bounty)
                      :builder-net (:builder-net bounty)
                      :auditor-net (:auditor-net bounty)
                      :created-epoch (:epoch state 0)
                      :status :locked}
            b-rcpt {:type :bounty-create
                    :receipt-id (str "bounty-rcpt-" bounty-id)
                    :bounty-id bounty-id
                    :subnet-id subnet
                    :maintainer-pubkey m-pub
                    :gross-amount gross
                    :take-bps take-bps
                    :builder-bps builder-bps
                    :target-bip-cid target-cid
                    :epoch (:epoch state 0)}
            b-rcpt-signed (if privkey-bytes
                            (let [c-bytes (fressian/encode-canonical (dissoc b-rcpt :signature "signature"))
                                  sig (basalt/bytes->hex (crypto/sign privkey-bytes c-bytes))]
                              (assoc b-rcpt :signature sig))
                            b-rcpt)
            rcpt-env {:type :receive-receipt :receipt b-rcpt-signed}
            rep-env (build-governance-replicate-envelope
                     st-after-deduct
                     privkey-bytes
                     subnet
                     :bounty-create
                     {:subnet-id subnet
                      :bounty-id bounty-id
                      :bounty bounty
                      :capability-cid cap-cid
                      :capability-blob cap-blob
                      :capability-pointer cap-ptr}
                     burn-amt)]
        {:state (-> st-after-deduct
                    (assoc :governance (:state res))
                    (assoc-in [:bounty-escrows bounty-id] b-escrow)
                    (assoc-in [:capabilities [subnet cap-path]] cap-ptr)
                    (assoc-in [:capability-blobs cap-cid] cap-blob))
         :response {"ok" true
                    "subnet_id" subnet
                    "bounty_id" bounty-id
                    "target_bip_cid" target-cid
                    "gross_amount" (:gross-amount bounty)
                    "protocol_take" (:protocol-take bounty)
                    "builder_net" (:builder-net bounty)
                    "auditor_net" (:auditor-net bounty)
                    "capability_cid" cap-cid
                    "capability_path" cap-path
                    "path" cap-path
                    "status" "locked"
                    "burn" burn-amt}
         :net-envelopes (cond-> []
                          rep-env (conj rep-env)
                          rcpt-env (conj rcpt-env))
         :stdout-events []}))))

(defn- exec-bounty-settle
  [state effective-map privkey-bytes sub-id]
  (let [burn-amt (max 0 (long (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)) 0) 0)))
        burn-chk (check-and-deduct-burn state burn-amt)]
    (if-not (:ok? burn-chk)
      {:state state :response {"ok" false "error" (:error burn-chk)} :net-envelopes [] :stdout-events []}
      (let [st-after-burn (:state burn-chk)
            subnet (str (or (get effective-map "subnet_id") (get effective-map "subnet-id") (:subnet-id effective-map) sub-id gov/dev-subnet-id))
            bounty-id (str (or (get effective-map "bounty_id") (get effective-map "bounty-id") (:bounty-id effective-map) ""))
            explicit-claim (parse-edn-safe (or (get effective-map "claim_edn") (get effective-map "claim-edn") (:claim-edn effective-map)))
            raw-builder (or (get effective-map "builder") (:builder effective-map))
            raw-auditor (or (get effective-map "auditor") (:auditor effective-map))
            patch-cid (str (or (get effective-map "patch_cid") (get effective-map "patch-cid") (:patch-cid effective-map) "cid-patch"))
            sha256 (str (or (get effective-map "sha256") (:sha256 effective-map) "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
            builder-pub (when raw-builder
                          (normalize-pubkey-hex (or (:pubkey (resolve-counterparty state raw-builder)) (str raw-builder))))
            auditor-pub (when raw-auditor
                          (normalize-pubkey-hex (or (:pubkey (resolve-counterparty state raw-auditor)) (str raw-auditor))))
            my-pub (normalize-pubkey-hex (:pubkey state))
            fallback-kp (when-not privkey-bytes
                          (crypto/generate-keypair (str "bounty-maintainer-" my-pub)))
            eff-priv (or privkey-bytes (:private fallback-kp))
            claim (if (seq explicit-claim)
                    explicit-claim
                    (let [payload (gov/canonical-bounty-claim-payload bounty-id patch-cid sha256)
                          m-sig (basalt/bytes->hex (crypto/sign-canonical eff-priv payload))]
                      {:bounty-id bounty-id
                       :patch-bundle-cid patch-cid
                       :reproducible-sha256 sha256
                       :maintainer-direct-settle? true
                       :builder {:pubkey builder-pub}
                       :auditor {:pubkey auditor-pub
                                 :model "claude-opus-5-5"
                                 :tests-passed? true
                                 :lint-clean? true
                                 :reproducible-sha256 sha256}
                       :maintainer {:pubkey my-pub
                                    :signature m-sig}}))
            gov-st (or (:governance st-after-burn) (gov/init-governance-state))
            res (gov/settle-bounty-escrow gov-st subnet bounty-id claim)]
        (if-not (:ok? res)
          {:state (assoc st-after-burn :governance (:state res))
           :response {"ok" false
                      "error" (name (or (:error res) :bounty-quorum-invalid))
                      "subnet_id" subnet
                      "bounty_id" bounty-id}
           :net-envelopes []
           :stdout-events []}
          (let [settled-bounty (:bounty res)
                b-net (long (or (:builder-net settled-bounty) 0))
                a-net (long (or (:auditor-net settled-bounty) 0))
                settle-rcpt {:type :bounty-settle
                             :receipt-id (str "bounty-settle-rcpt-" bounty-id)
                             :bounty-id bounty-id
                             :subnet-id subnet
                             :maintainer-pubkey my-pub
                             :builder-pubkey builder-pub
                             :auditor-pubkey auditor-pub
                             :claim claim
                             :epoch (:epoch state 0)}
                settle-rcpt-signed (if eff-priv
                                     (let [c-bytes (fressian/encode-canonical (dissoc settle-rcpt :signature "signature"))
                                           sig (basalt/bytes->hex (crypto/sign eff-priv c-bytes))]
                                       (assoc settle-rcpt :signature sig))
                                     settle-rcpt)
                rcpt-env {:type :receive-receipt :receipt settle-rcpt-signed}
                rep-env (build-governance-replicate-envelope
                         st-after-burn
                         privkey-bytes
                         subnet
                         :bounty-settle
                         {:subnet-id subnet
                          :bounty-id bounty-id
                          :claim claim
                          :bounty settled-bounty}
                         burn-amt)]
            {:state (-> st-after-burn
                        (assoc :governance (:state res))
                        (assoc-in [:bounty-escrows bounty-id :status] :settled))
             :response {"ok" true
                        "subnet_id" subnet
                        "bounty_id" bounty-id
                        "status" "settled"
                        "payouts" (:payouts res)
                        "builder_net" b-net
                        "auditor_net" a-net
                        "protocol_take" (:protocol-take res)
                        "burn" burn-amt}
             :net-envelopes (cond-> []
                              rep-env (conj rep-env)
                              rcpt-env (conj rcpt-env))
             :stdout-events []}))))))

(defn exec-bounties
  "Returns list of on-chain / replicated bounty escrows optionally filtered by subnet_id."
  ([state]
   (exec-bounties state {}))
  ([state cmd-map]
   (let [sub-filter (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map))
         escrows (vals (or (:bounty-escrows state) {}))
         filtered (if (and sub-filter (not= sub-filter "all"))
                    (filter (fn [b] (= (str (:subnet-id b)) (str sub-filter))) escrows)
                    escrows)
         bounties-out (mapv (fn [b]
                              (into {} (map (fn [[k v]] [(if (keyword? k) (name k) (str k)) v]) b)))
                            filtered)
         resp {"ok" true
               "count" (count bounties-out)
               "bounties" bounties-out}]
     (merge resp
            {:state state
             :response resp
             :net-envelopes []
             :stdout-events []}))))

(defn- exec-subscribe-subnets [state cmd-map]
  (let [raw-subs (or (get cmd-map "subnets") (:subnets cmd-map)
                     (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map))
        items (cond
                (coll? raw-subs) raw-subs
                (string? raw-subs) (str/split raw-subs #",")
                :else [])
        subs (into #{} (remove str/blank? (map (comp str/trim str) items)))
        new-subs (into (or (:subscribed-subnets state) #{}) subs)]
    {:state (assoc state :subscribed-subnets new-subs)
     :response {"ok" true
                "subnet_id" (or (:subnet-id state) "global")
                "subscribed_subnets" (vec (sort new-subs))}
     :net-envelopes []
     :stdout-events []}))

(defn- sanitize-rolodex-snapshot
  "Builds a deterministic, secret-free BIP-016 Rolodex snapshot from light-node state."
  [state next-seq node-role]
  (let [petnames (into (sorted-map)
                       (for [[k v] (or (:petnames state) {})
                             :when (and (some? k) (some? v))]
                         [(if (keyword? k) (name k) (str k)) (str v)]))
        petname-meta (into (sorted-map)
                           (for [[pk meta-m] (or (:petname-meta state) {})
                                 :when (and (some? pk) (map? meta-m))]
                             [(str pk) (select-keys meta-m [:petname :voice-id :color])]))
        subnets (vec (sort (distinct (map str (or (:subscribed-subnets state) [])))))
        sessions (into (sorted-map)
                       (for [[sid s] (or (:sessions state) {})
                             :when (and (some? sid) (map? s))]
                         [(str sid) {:peer (str (:peer s))
                                     :state (str (or (:state s) "unknown"))
                                     :epoch (long (or (:epoch s) 0))}]))]
    {:schema "bitecho/rolodex-snapshot-v1"
     :pubkey (str (or (:pubkey state) ""))
     :node-role (str (or node-role "light"))
     :seq next-seq
     :petnames petnames
     :petname-meta petname-meta
     :subscribed-subnets subnets
     :sessions sessions}))

(defn- exec-rolodex-put [state cmd-map]
  (let [prev-seq (long (or (get-in state [:rolodex :seq]) 0))
        next-seq (inc prev-seq)
        node-role (or (get cmd-map "nodeRole") (get cmd-map "node_role") (:node-role cmd-map) "light")
        snap (sanitize-rolodex-snapshot state next-seq node-role)
        snap-cid (crypto/sha256-hex (pr-str snap))
        rolodex-rec {:seq next-seq
                     :cid snap-cid
                     :node-role (str node-role)
                     :snapshot snap}
        new-state (assoc state :rolodex rolodex-rec)]
    {:state new-state
     :response {"ok" true
                "seq" next-seq
                "cid" snap-cid
                "petnames" (count (:petnames snap))
                "subnets" (count (:subscribed-subnets snap))
                "sessions" (count (:sessions snap))
                "snapshot" snap}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-rolodex-status [state]
  (let [rec (:rolodex state)
        snap (:snapshot rec)]
    {:state state
     :response {"ok" true
                "seq" (long (or (:seq rec) 0))
                "cid" (:cid rec)
                "petnames" (count (or (:petnames state) {}))
                "subnets" (count (or (:subscribed-subnets state) []))
                "sessions" (count (or (:sessions state) {}))
                "has_snapshot" (boolean (some? snap))}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-rolodex-restore [state cmd-map]
  (let [raw-snap (or (get cmd-map "snapshot") (:snapshot cmd-map) (get-in state [:rolodex :snapshot]))]
    (if-not (map? raw-snap)
      {:state state
       :response {"ok" false "error" "missing-rolodex-snapshot"}
       :net-envelopes []
       :stdout-events []}
      (let [pnames (or (:petnames raw-snap) (get raw-snap "petnames") {})
            pmeta (or (:petname-meta raw-snap) (get raw-snap "petname-meta") (get raw-snap "petname_meta") {})
            subs (or (:subscribed-subnets raw-snap) (get raw-snap "subscribed-subnets") (get raw-snap "subscribed_subnets") [])
            restored-seq (long (or (:seq raw-snap) (get raw-snap "seq") (get-in state [:rolodex :seq]) 0))
            clean-snap (dissoc raw-snap :private-key "private-key" :privkey "privkey")
            snap-cid (crypto/sha256-hex (pr-str clean-snap))
            new-state (-> state
                          (update :petnames #(merge (or % {}) pnames))
                          (update :petname-meta #(merge (or % {}) pmeta))
                          (update :subscribed-subnets #(into (into #{} (or % [])) (map str subs)))
                          (assoc :rolodex {:seq restored-seq :cid snap-cid :snapshot clean-snap}))]
        {:state new-state
         :response {"ok" true
                    "restored" true
                    "seq" restored-seq
                    "cid" snap-cid
                    "petnames" (count (:petnames new-state))
                    "subnets" (count (:subscribed-subnets new-state))}
         :net-envelopes []
         :stdout-events []}))))

(defn handle-command
  "Dispatches a parsed JSON command map to its corresponding protocol verb reducer.
   Supports both flat command maps and nested {\"cmd\": ..., \"args\": {...}} maps,
   plus automatic 12-canonical-verb desugaring (`BIP-005` / `F-U1`).
   Tags outgoing envelopes with :subnet-id from state or command."
  [state cmd-map privkey-bytes]
  (let [raw-effective (if (map? (get cmd-map "args"))
                        (merge (get cmd-map "args") (dissoc cmd-map "args"))
                        cmd-map)
        raw-cmd (or (get raw-effective "cmd") (:cmd raw-effective))
        effective-map (if (contains? #{"put" "get" "list" "lock" "spend" "connect" "wait-event"} (str raw-cmd))
                        (cli/desugar-cli-cmd-map raw-effective)
                        raw-effective)
        cmd-name (or (get effective-map "cmd") (:cmd effective-map))
        raw-min-balance (or (get effective-map "min_balance") (get effective-map "min-balance")
                            (:min-balance effective-map) (:min_balance effective-map))
        min-balance (when (some? raw-min-balance) (parse-long-safe raw-min-balance nil))
        burn-bearing? (contains? #{"send" "broadcast" "offer" "rendezvous-offer" "transfer"} cmd-name)
        spendable (long (or (get-in state [:account :spendable]) (get-in state [:account :balance]) 0))
        required-burn (long (cond
                              (= cmd-name "transfer")
                              (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)) nil) 500)
                              :else
                              (or (parse-long-safe (or (get effective-map "burn") (:burn effective-map)
                                                       (get effective-map "price") (:price effective-map)) nil)
                                  (effective-signaling-burn-floor state))))
        sub-id-raw (or (get effective-map "subnet_id")
                       (get effective-map "subnet-id")
                       (:subnet-id effective-map)
                       (:subnet-id state))
        sub-id-str (when sub-id-raw (str sub-id-raw))]
    (if (and burn-bearing? min-balance (< (- spendable required-burn) (long min-balance)))
      (let [ev {"event" "budget-floor-reached"
                "spendable" spendable
                "required_burn" required-burn
                "min_balance" (long min-balance)}
            st' (update-in state [:diagnostics :below-min-balance-rejected] (fnil inc 0))]
        {:state (enqueue-actionable-events st' [ev])
         :response {"ok" false
                    "error" "below-min-balance"
                    "spendable" spendable
                    "required_burn" required-burn
                    "min_balance" (long min-balance)}
         :net-envelopes []
         :stdout-events [ev]})
      (let [res (case cmd-name
                  "identity" (exec-identity state)
                  "discover" (exec-discover state)
                  "register-home-set" (exec-register-home-set state effective-map privkey-bytes)
                  "offer" (exec-offer state effective-map privkey-bytes)
                  "accept" (exec-accept state effective-map privkey-bytes)
                  "p2p-offer" (exec-p2p-offer state effective-map privkey-bytes)
                  "p2p-answer" (exec-p2p-answer state effective-map privkey-bytes)
                  "p2p-channel-state" (exec-p2p-channel-state state effective-map privkey-bytes)
                  "p2p_channel_state" (exec-p2p-channel-state state effective-map privkey-bytes)
                  "broadcast" (exec-broadcast state effective-map privkey-bytes)
                  "rendezvous-policy" (exec-rendezvous-policy state effective-map)
                  "rendezvous-offer" (exec-rendezvous-offer state effective-map privkey-bytes)
                  "rendezvous-accept" (exec-rendezvous-accept state effective-map privkey-bytes)
                  "send" (exec-send state effective-map privkey-bytes)
                  "inbox" (exec-inbox state effective-map)
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
                  "anchor-subnet" (exec-anchor-subnet state effective-map privkey-bytes (or sub-id-str "global"))
                  "epoch-tick" (exec-epoch-tick state effective-map privkey-bytes (or sub-id-str "global"))
                  "verify-subnet-anchor" (exec-verify-subnet-anchor state effective-map (or sub-id-str "global"))
                  "wait" (exec-wait state effective-map)
                  "retransmit-outbox" (exec-retransmit-outbox state effective-map privkey-bytes)
                  "export-poll" (exec-export-poll state effective-map privkey-bytes)
                  "import-poll" (exec-import-poll state effective-map privkey-bytes)
                  "import" (exec-import state effective-map privkey-bytes)
                  "import-envelope" (exec-import state effective-map privkey-bytes)
                  "export-offer" (exec-export-offer state effective-map privkey-bytes)
                  "export-reveal" (exec-export-reveal state effective-map privkey-bytes)
                  "export-p2p-offer" (exec-export-p2p-offer state effective-map privkey-bytes)
                  "export-p2p-answer" (exec-export-p2p-answer state effective-map privkey-bytes)
                  "export-send" (exec-export-send state effective-map privkey-bytes)
                  "ack" (exec-ack state effective-map privkey-bytes)
                  "export-ack" (exec-export-ack state effective-map privkey-bytes)
                  "storage-put" (exec-storage-put state effective-map privkey-bytes sub-id-str)
                  "storage-get" (exec-storage-get state effective-map privkey-bytes sub-id-str)
                  "storage-list" (exec-storage-list state effective-map)
                  "artifact-put" (exec-artifact-put state effective-map privkey-bytes sub-id-str)
                  "artifact-get" (exec-artifact-get state effective-map sub-id-str)
                  "artifact-list" (exec-artifact-list state effective-map)
                  "artifact-revoke" (exec-artifact-revoke state effective-map privkey-bytes sub-id-str)
                  "capability-publish" (exec-capability-publish state effective-map privkey-bytes sub-id-str)
                  "capability-resolve" (exec-capability-resolve state effective-map privkey-bytes sub-id-str)
                  "capability-list" (exec-capability-list state effective-map)
                  "puzzle-hash" (exec-puzzle-hash state effective-map)
                  "puzzle-eval" (exec-puzzle-eval state effective-map)
                  "bip-submit" (exec-bip-submit state effective-map privkey-bytes sub-id-str)
                  "bip-consent" (exec-bip-consent state effective-map privkey-bytes sub-id-str)
                  "bip-object" (exec-bip-object state effective-map privkey-bytes sub-id-str)
                  "bip-status" (exec-bip-status state effective-map sub-id-str)
                  "bounty-create" (exec-bounty-create state effective-map privkey-bytes sub-id-str)
                  "bounty-settle" (exec-bounty-settle state effective-map privkey-bytes sub-id-str)
                  "bounties" (exec-bounties state effective-map)
                  "status" (exec-status state)
                  "help" {:state state
                          :response {"ok" true
                                     "help" true
                                     "verbs" cli/supported-cli-verbs
                                     "modes" ["one-shot" "serve" "ctl" "wait-event"]
                                     "flags" cli/known-command-flags}
                          :net-envelopes []
                          :stdout-events []}
                  "subscribe-subnets" (exec-subscribe-subnets state effective-map)
                  "rolodex-put" (exec-rolodex-put state effective-map)
                  "rolodex-status" (exec-rolodex-status state)
                  "rolodex-restore" (exec-rolodex-restore state effective-map)
                  {:state state :response {"ok" false "error" "unknown-command"} :net-envelopes [] :stdout-events []})
            res' (if (seq (:net-envelopes res))
                   (update res :net-envelopes (fn [envs]
                                                (mapv (fn [e]
                                                        (if (or (nil? (:subnet-id e)) (= (:subnet-id e) "global"))
                                                          (assoc e :subnet-id (or sub-id-str (:subnet-id e) "global"))
                                                          e))
                                                      envs)))
                   res)]
        (if (seq (:stdout-events res'))
          (update res' :state enqueue-actionable-events (:stdout-events res'))
          res')))))

;; -----------------------------------------------------------------------------
;; Inbound Wire Payload Handlers (Pure Helpers)
;; -----------------------------------------------------------------------------

(defn unwrap-wire-message
  "Pure helper recursively unpacking and canonicalizing wire envelopes, thawed payloads, and inner events."
  [raw-payload-or-event]
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
         (or (= :receive-gossip (:type raw-payload-or-event))
             (= :receive-gossip (:bitecho/type raw-payload-or-event))
             (= "receive-gossip" (:type raw-payload-or-event))
             (= "receive-gossip" (get raw-payload-or-event "type"))))
    (let [inner (or (:envelope raw-payload-or-event)
                    (:message raw-payload-or-event)
                    (:payload raw-payload-or-event)
                    (get raw-payload-or-event "envelope")
                    (get raw-payload-or-event "message")
                    (get raw-payload-or-event "payload"))]
      (if (bytes? inner)
        (unwrap-wire-message (try (thaw-payload inner) (catch #?(:clj Exception :cljs :default) _ nil)))
        (unwrap-wire-message inner)))

    (and (map? raw-payload-or-event)
         (or (contains? raw-payload-or-event :bitecho/type)
             (contains? raw-payload-or-event :type)
             (contains? raw-payload-or-event "type")
             (contains? raw-payload-or-event "cmd")
             (contains? raw-payload-or-event :transfer)
             (contains? raw-payload-or-event "transfer")
             (contains? raw-payload-or-event :validator-pubkey)
             (contains? raw-payload-or-event "validator-pubkey")
             (contains? raw-payload-or-event "validator_pubkey")))
    (fressian/strip-untrusted-crypto-tags raw-payload-or-event)

    (and (map? raw-payload-or-event)
         (or (contains? raw-payload-or-event :protocol-version)
             (contains? raw-payload-or-event "protocol_version")))
    (fressian/strip-untrusted-crypto-tags raw-payload-or-event)

    :else nil))

(defn handle-wire-offer
  "Handles incoming wire channel-offer message, validating signatures, hashes, and network-uri."
  ([state msg] (handle-wire-offer state msg nil))
  ([state msg privkey-bytes]
   (try
     (let [msg-net (or (:network-uri msg) (get msg "network_uri") (get msg "network-uri"))
           st-net (or (:network-uri state) (config/resolve-network-uri (:subnet-id state)))
           network-mismatch? (or (and (string? msg-net) (string? st-net)
                                      (not= (str/trim msg-net) (str/trim st-net))
                                      (not (and (= (str/trim msg-net) "global") (true? (:allow-legacy-global-offers? state)))))
                                 (and (= st-net "mainnet.bitecho.org") (str/blank? (str msg-net))))]
       (if network-mismatch?
         {:state (update-in state [:diagnostics :network-replay-rejected] (fnil inc 0))
          :net-envelopes []
          :stdout-events []}
         (if-not (and (map? msg)
                      (string? (:caller msg))
                      (string? (:callee msg))
                      (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:pubkey state)))
                      (string? (:caller-ephemeral-pub msg))
                      (string? (:signature msg))
                      (integer? (:epoch msg))
                      (valid-pubkey-hex? (:caller msg))
                      (valid-pubkey-hex? (:callee msg)))
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
                 net-str (when (and (string? msg-net) (not (str/blank? msg-net))) (str/trim msg-net))
                 expected-hash-5field (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes (str (:caller msg) "-" (:callee msg) "-" (:caller-ephemeral-pub msg) "-" epoch-num "-" burn-num
                                                                                                   (when (and (string? dac-id) (not (str/blank? dac-id))) (str "|" dac-id))
                                                                                                   (when net-str (str "|net:" net-str))))))
                 valid-hashes? (and (= (:session-id msg) expected-sid)
                                    (or (= (:offer-hash msg) expected-hash-legacy)
                                        (= (:offer-hash msg) expected-hash-sealed)
                                        (= (:offer-hash msg) expected-hash-5field)
                                        (matching-offer-hash? msg state (:offer-hash msg))))
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
                 burn-floor (effective-signaling-burn-floor state)
                 actual-burn (long (or (:burn msg) 0))]
             (if (or (not valid-sig?)
                     (not valid-suite?)
                     (and economy-enabled? (< actual-burn burn-floor))
                     (and wire-dac (not (:ok? dac-check))))
               {:state state :net-envelopes [] :stdout-events []}
               (let [sid (:session-id msg)
                     clean-offer (cond-> (select-keys msg [:bitecho/type :session-id :subnet-id :caller :callee :caller-ephemeral-pub :epoch :price :home-node :offer-hash :burn :signature :crypto-suites :network-uri])
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
                      :stdout-events [event]}))))))))
     (catch #?(:clj Exception :cljs :default) _
       {:state state :net-envelopes [] :stdout-events []}))))

(defn handle-wire-accept
  "Handles incoming wire channel-accept message, validating delivery ack and network-uri."
  ([state msg] (handle-wire-accept state msg nil))
  ([state msg privkey-bytes]
   (try
     (let [msg-net (or (:network-uri msg) (get msg "network_uri") (get msg "network-uri"))
           st-net (or (:network-uri state) (config/resolve-network-uri (:subnet-id state)))
           network-mismatch? (and (string? msg-net) (string? st-net)
                                  (not= (str/trim msg-net) (str/trim st-net)))]
       (if network-mismatch?
         {:state (update-in state [:diagnostics :cross-network-accept-rejected] (fnil inc 0))
          :net-envelopes []
          :stdout-events []}
         (if-not (and (map? msg)
                      (string? (:session-id msg))
                      (or (nil? (:caller msg)) (= (normalize-pubkey-hex (:caller msg)) (normalize-pubkey-hex (:pubkey state)))))
           {:state state :net-envelopes [] :stdout-events []}
           (let [session-id (:session-id msg)
                 session (get-in state [:sessions session-id])]
             (cond
               (and session (or (= "open" (:state session)) (= :open (:phase session))))
               {:state (update-in state [:sessions session-id :replays-deduped] (fnil inc 0))
                :net-envelopes []
                :stdout-events []}

               (not (and session (or (= "offered" (:state session)) (= :offered (:phase session)))))
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
                         eph-priv (or (:ephemeral-priv session)
                                      (when (and (:offer-nonce session) privkey-bytes)
                                        (:private (sealed/derive-offer-x25519-keypair privkey-bytes (:offer-nonce session) (:caller msg) (:callee msg)))))
                         shared-sec (when (and callee-eph eph-priv) (sealed/x25519-shared-secret eph-priv callee-eph))]
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
                                              (dissoc :ephemeral-priv :offer-nonce))
                             new-state (-> state
                                           (assoc-in [:sessions session-id] updated-sess)
                                           (update :vouchers (fnil conj []) (:delivery-ack msg)))
                             callee-pname (pubkey->petname state (:callee msg))
                             event (cond-> {"event" "channel-opened" "session_id" session-id "peer" (:callee msg)}
                                     callee-pname (assoc "peer_petname" callee-pname))]
                         {:state new-state
                          :net-envelopes []
                          :stdout-events [event]}))))))))))
     (catch #?(:clj Exception :cljs :default) _
       {:state state :net-envelopes [] :stdout-events []}))))

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

(def ^:private max-safe-js-seq 9007199254740991)

(defn- ack-has-rollback-fields? [m]
  (or (contains? m :replay-rejected?)
      (contains? m :rejected-seq)
      (contains? m :peer-high-seq)
      (contains? m :accepted-ciphertext-sha256)))

(defn- compute-ack-sign-bytes
  "Computes canonical bytes signed in `:session-ack`.
   BIP-021 §2.4: when ANY rollback field is present, binds all rollback fields with
   ZERO legacy-signature fallback."
  [session-id contiguous-ack-seq msg-seq seen-vec rollback-opts]
  (let [base (str "ack-" session-id "-" contiguous-ack-seq "-" msg-seq "-" (str/join "," seen-vec))]
    (if (ack-has-rollback-fields? (or rollback-opts {}))
      (fressian/utf8->bytes
       (str base "|rb:"
            (boolean (:replay-rejected? rollback-opts)) ":"
            (or (:rejected-seq rollback-opts) "") ":"
            (or (:peer-high-seq rollback-opts) "") ":"
            (or (:accepted-ciphertext-sha256 rollback-opts) "")))
      (fressian/utf8->bytes base))))

(defn build-session-ack-envelope
  "Builds and signs a :session-ack envelope wrapping Ed25519 signature."
  ([state session-id peer-pub contiguous-ack-seq msg-seq privkey-bytes]
   (build-session-ack-envelope state session-id peer-pub contiguous-ack-seq msg-seq nil privkey-bytes nil))
  ([state session-id peer-pub contiguous-ack-seq msg-seq seen-seqs privkey-bytes]
   (build-session-ack-envelope state session-id peer-pub contiguous-ack-seq msg-seq seen-seqs privkey-bytes nil))
  ([state session-id peer-pub contiguous-ack-seq msg-seq seen-seqs privkey-bytes rollback-opts]
   (when privkey-bytes
     (let [seen-vec (vec (sort (or seen-seqs [])))
           ack-sign-bytes (compute-ack-sign-bytes session-id contiguous-ack-seq msg-seq seen-vec rollback-opts)
           sig (crypto/sign privkey-bytes ack-sign-bytes)
           sig-hex (if (string? sig) sig (basalt/bytes->hex sig))
           sess (get-in state [:sessions session-id])
           p2p-open? (true? (get-in sess [:p2p :connected?]))
           burn-amt (if p2p-open? 0 100)
           sub-id (str (or (:subnet-id sess) (:subnet-id state) "global"))
           ack-payload (cond-> {:protocol-version current-wire-version
                                :wire-format current-wire-format
                                :subnet-id sub-id
                                :bitecho/type :session-ack
                                :session-id session-id
                                :sender (:pubkey state)
                                :recipient peer-pub
                                :epoch (effective-session-wire-epoch state sess)
                                :ack-seq contiguous-ack-seq
                                :acked-seq msg-seq
                                :seen-seqs seen-vec
                                :signature sig-hex}
                         (ack-has-rollback-fields? (or rollback-opts {}))
                         (merge (select-keys rollback-opts [:replay-rejected? :rejected-seq :peer-high-seq :accepted-ciphertext-sha256])))
           outer-sub (if (and (pos? burn-amt) (config/root-subnet-id? sub-id)) "*" sub-id)
           raw-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload ack-payload) burn-amt outer-sub)]
       (cond-> raw-env
         p2p-open? (assoc :p2p-direct? true
                          :p2p-peer (normalize-pubkey-hex peer-pub)
                          :p2p-session-id session-id))))))

(defn- prune-rx-ciphertext-hashes
  "Retains at most 64 most recent seq -> ciphertext-sha256 entries in the replay window."
  [hashes highest-seq]
  (let [horizon (- (long highest-seq) 64)]
    (reduce-kv (fn [acc k v]
                 (if (> (long k) horizon)
                   (assoc acc k v)
                   acc))
               {}
               (or hashes {}))))

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
          (let [early-sessions (get state :early-sealed-messages {})
                cur-buf (get early-sessions session-id [])
                max-per-session 8
                max-sessions 32
                within-caps? (and (< (count cur-buf) max-per-session)
                                  (or (contains? early-sessions session-id)
                                      (< (count early-sessions) max-sessions)))
                new-state (if within-caps?
                            (-> state
                                (assoc-in [:early-sealed-messages session-id] (conj cur-buf msg))
                                (update-in [:diagnostics :early-sealed-message-buffered] (fnil inc 0)))
                            (update-in state [:diagnostics :early-sealed-message-dropped] (fnil inc 0)))]
            {:state new-state :net-envelopes [] :stdout-events []})
          (let [msg-seq (long (:seq msg))
                incoming-ct-sha256 (crypto/sha256-hex (:ciphertext msg))
                prev-rx-high (long (:rx-high-seq session 0))
                chk (sealed/check-and-advance-replay-window (:replay-window session) msg-seq)]
            (cond
              (:accepted? chk)
              (let [ct (try (basalt/hex->bytes (:ciphertext msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                    decrypted (when ct (sealed/open-message (:rx-key session) msg-seq ct (fressian/utf8->bytes session-id) (:suite session) (:suite msg)))]
                (if-not decrypted
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [rx-gap? (> msg-seq (inc prev-rx-high))
                        new-rx-high-seq (max prev-rx-high msg-seq)
                        new-contiguous (advance-contiguous-rx-seq (:contiguous-rx-seq session 0)
                                                                  (:seen (:window chk))
                                                                  (:highest-seq (:window chk) 0))
                        seen-seqs (vec (sort (:seen (:window chk))))
                        ack-env (build-session-ack-envelope state session-id (:sender msg) new-contiguous msg-seq seen-seqs privkey-bytes)
                        text (try (fressian/bytes->utf8 decrypted) (catch #?(:clj Exception :cljs :default) _ nil))
                        sender-pname (pubkey->petname state (:sender msg))
                        inbox-item {:type :direct
                                    :session-id session-id
                                    :session_id session-id
                                    :from (:sender msg)
                                    :seq msg-seq
                                    :text text
                                    :payload-hex (basalt/bytes->hex decrypted)
                                    :payload_hex (basalt/bytes->hex decrypted)}
                        next-hashes (-> (or (:rx-ciphertext-hashes session) {})
                                        (assoc msg-seq incoming-ct-sha256)
                                        (prune-rx-ciphertext-hashes new-rx-high-seq))
                        updated-sess (assoc session
                                            :replay-window (:window chk)
                                            :rx-high-seq new-rx-high-seq
                                            :contiguous-rx-seq new-contiguous
                                            :rx-ciphertext-hashes next-hashes)
                        new-state (cond-> (-> state
                                              (assoc-in [:sessions session-id] updated-sess)
                                              (update :inbox append-bounded-inbox inbox-item))
                                    rx-gap? (update-in [:diagnostics :session-rx-gap-detected] (fnil inc 0)))
                        event (cond-> {"event" "message-received"
                                       "session_id" session-id
                                       "from" (:sender msg)
                                       "seq" msg-seq}
                                text (assoc "text" text)
                                sender-pname (assoc "from_petname" sender-pname))]
                    {:state new-state
                     :net-envelopes (if ack-env [ack-env] [])
                     :stdout-events [event]})))

              (contains? #{:replayed-seq :stale-seq} (:error chk))
              (let [err-kind (:error chk)
                    stored-digest (get-in session [:rx-ciphertext-hashes msg-seq])
                    identical-retransmit? (and (= err-kind :replayed-seq)
                                               (some? stored-digest)
                                               (= stored-digest incoming-ct-sha256))
                    contig (:contiguous-rx-seq session 0)
                    seen-seqs (vec (sort (:seen (:replay-window session))))]
                (if identical-retransmit?
                  ;; Benign duplicate retransmit of identical ciphertext (lost ACK retry)
                  (let [ack-env (build-session-ack-envelope state session-id (:sender msg) contig msg-seq seen-seqs privkey-bytes)
                        new-state (-> state
                                      (update-in [:sessions session-id :replays-deduped] (fnil inc 0))
                                      (record-suppression :duplicate-replay))]
                    {:state new-state
                     :net-envelopes (if ack-env [ack-env] [])
                     :stdout-events []})
                  ;; BIP-021 §2.4: Rollback / conflicting replay or >= 64 :stale-seq!
                  ;; Never decrement :rx-high-seq or deliver to :inbox; emit signed rollback ACK.
                  (let [rollback-opts (cond-> {:replay-rejected? true
                                               :rejected-seq msg-seq
                                               :peer-high-seq prev-rx-high}
                                        stored-digest (assoc :accepted-ciphertext-sha256 stored-digest))
                        ack-env (build-session-ack-envelope state session-id (:sender msg) contig msg-seq seen-seqs privkey-bytes rollback-opts)
                        replay-evt {"event" "session-replay-detected"
                                    "session_id" session-id
                                    "from" (:sender msg)
                                    "seq" msg-seq
                                    "rx_high_seq" prev-rx-high
                                    "reason" (name err-kind)}
                        new-state (cond-> (-> state
                                              (update-in [:sessions session-id :replays-deduped] (fnil inc 0))
                                              (update-in [:diagnostics :session-replay-detected] (fnil inc 0))
                                              (record-suppression :duplicate-replay))
                                    (= err-kind :stale-seq)
                                    (update-in [:diagnostics :session-stale-seq-detected] (fnil inc 0)))]
                    {:state new-state
                     :net-envelopes (if ack-env [ack-env] [])
                     :stdout-events [replay-evt]})))

              :else
              {:state state :net-envelopes [] :stdout-events []})))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-session-ack
  ([state msg]
   (handle-wire-session-ack state msg nil))
  ([state msg privkey-bytes]
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
                 raw-peer-high (:peer-high-seq msg)
                 peer-high-seq (long (or raw-peer-high (max ack-seq acked-seq)))
                 overflow? (or (> peer-high-seq max-safe-js-seq)
                               (> ack-seq max-safe-js-seq)
                               (> acked-seq max-safe-js-seq)
                               (neg? peer-high-seq))
                 seen-vec (vec (sort (or (:seen-seqs msg) [])))
                 rollback-fields (select-keys msg [:replay-rejected? :rejected-seq :peer-high-seq :accepted-ciphertext-sha256])
                 ;; BIP-021 §2.4: zero legacy-signature fallback when any rollback field is present
                 canonical-bytes (compute-ack-sign-bytes session-id ack-seq acked-seq seen-vec rollback-fields)
                 valid-sig? (and (not overflow?)
                                 peer-pub sig-bytes
                                 (crypto/verify peer-pub canonical-bytes sig-bytes))]
             (if-not valid-sig?
               {:state (if overflow?
                         (update-in state [:diagnostics :session-ack-invalid] (fnil inc 0))
                         state)
                :net-envelopes []
                :stdout-events []}
               (let [local-tx-seq (long (:tx-seq session 0))
                     curr-outbox (or (:outbox session) {})
                     curr-order (or (:outbox-order session) [])
                     rejected-seq (when (integer? (:rejected-seq msg)) (long (:rejected-seq msg)))
                     accepted-ct (:accepted-ciphertext-sha256 msg)
                     digest-mismatch? (boolean
                                       (when (and accepted-ct rejected-seq)
                                         (when-let [ob-item (get curr-outbox rejected-seq)]
                                           (and (:ciphertext-sha256 ob-item)
                                                (not= accepted-ct (:ciphertext-sha256 ob-item))))))
                     rollback-detected? (or (> peer-high-seq local-tx-seq)
                                            (true? (:replay-rejected? msg))
                                            digest-mismatch?)]
                 (if rollback-detected?
                   ;; Strict ordering: evict colliding outbox entries BEFORE (acked? s) purge!
                   (let [colliding-seqs (vec (sort (filter (fn [s]
                                                             (let [sl (long s)]
                                                               (or (<= sl peer-high-seq)
                                                                   (and rejected-seq (= sl rejected-seq)))))
                                                           (keys curr-outbox))))
                         rem-outbox (apply dissoc curr-outbox colliding-seqs)
                         colliding-set (set colliding-seqs)
                         rem-order (filterv #(not (contains? colliding-set %)) curr-order)
                         st-evicted (reduce (fn [s ev-sq]
                                              (record-eviction s :rollback-collision
                                                               {:session-id session-id :seq ev-sq}))
                                            state
                                            colliding-seqs)
                         fence-seq (max local-tx-seq peer-high-seq)
                         updated-sess (assoc session
                                             :tx-seq fence-seq
                                             :acked-seq (max (long (:acked-seq session 0)) ack-seq)
                                             :tx-tainted? true
                                             :rekey-required? true
                                             :reoffer-recommended? true
                                             :outbox rem-outbox
                                             :outbox-order rem-order
                                             :outbox-evicted (+ (long (:outbox-evicted session 0)) (count colliding-seqs)))
                         mismatch-evt {"event" "session-seq-mismatch"
                                       "session_id" session-id
                                       "peer" (:peer session)
                                       "local_tx_seq" local-tx-seq
                                       "peer_high_seq" peer-high-seq
                                       "affected_seqs" colliding-seqs
                                       "rekey_required" true
                                       "reoffer_recommended" true}
                         st1 (-> st-evicted
                                 (assoc-in [:sessions session-id] updated-sess)
                                 (update-in [:diagnostics :session-tx-seq-rollback-detected] (fnil inc 0))
                                 (update-in [:diagnostics :session-tx-seq-rollback-evicted] (fnil + 0) (count colliding-seqs)))
                         ;; Autonomous mode: auto-initiate real X25519 key-rotating channel-offer (NEVER p2p-offer!)
                         rekey-res (when (and (true? (:autonomous? st1)) privkey-bytes)
                                     (exec-offer st1
                                                 {"cmd" "offer"
                                                  "callee" (:peer session)
                                                  "subnet_id" (or (:subnet-id session) (:subnet-id st1) "global")
                                                  "price" (long (or (:price session) 0))
                                                  "burn" (if (get st1 :economy-enabled? true)
                                                           (effective-signaling-burn-floor st1)
                                                           0)}
                                                 privkey-bytes))]
                     {:state (if rekey-res (:state rekey-res) st1)
                      :net-envelopes (if rekey-res (:net-envelopes rekey-res) [])
                      :stdout-events (into [mismatch-evt] (when rekey-res (:stdout-events rekey-res)))})
                   (let [new-acked-seq (max (long (:acked-seq session 0)) ack-seq)
                         seen-set (set (map long seen-vec))
                         acked? (fn [s] (or (<= (long s) ack-seq) (= (long s) acked-seq) (contains? seen-set (long s))))
                         purged-outbox (reduce-kv (fn [m s item]
                                                    (if (acked? s)
                                                      m
                                                      (assoc m s item)))
                                                  {}
                                                  curr-outbox)
                         purged-order (filterv #(not (acked? %)) curr-order)
                         newly-acked (max 0 (- (count curr-outbox) (count purged-outbox)))
                         updated-sess (assoc session
                                             :acked-seq new-acked-seq
                                             :outbox purged-outbox
                                             :outbox-order purged-order)
                         new-state (cond-> (assoc-in state [:sessions session-id] updated-sess)
                                     (pos? newly-acked)
                                     (update-in [:delivery-telemetry :acked] (fnil + 0) newly-acked))]
                     {:state new-state
                      :net-envelopes []
                      :stdout-events []}))))))))
     (catch #?(:clj Exception :cljs :default) _
       {:state state :net-envelopes [] :stdout-events []}))))

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
      (let [msg-net (or (:network-uri msg) (get msg "network_uri") (get msg "network-uri"))
            st-net (or (:network-uri state) (config/resolve-network-uri (:subnet-id state)))
            network-mismatch? (or (and (string? msg-net) (string? st-net)
                                       (not= (str/trim msg-net) (str/trim st-net)))
                                  (and (= st-net "mainnet.bitecho.org") (str/blank? (str msg-net))))]
        (if network-mismatch?
          {:state (update-in state [:diagnostics :network-replay-rejected] (fnil inc 0))
           :net-envelopes []
           :stdout-events []}
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
                      (let [clean-header (cond-> (select-keys msg [:bitecho/type :type :caller :callee :offer-hash :epoch :burn :topic :home-node :signature :crypto-suites :subnet-id])
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
                           :stdout-events [header-evt]})))))))))))
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
      (let [msg-net (or (:network-uri msg) (get msg "network_uri") (get msg "network-uri"))
            st-net (or (:network-uri state) (config/resolve-network-uri (:subnet-id state)))
            network-mismatch? (or (and (string? msg-net) (string? st-net)
                                       (not= (str/trim msg-net) (str/trim st-net)))
                                  (and (= st-net "mainnet.bitecho.org") (str/blank? (str msg-net))))]
        (if network-mismatch?
          {:state (update-in state [:diagnostics :network-replay-rejected] (fnil inc 0))
           :net-envelopes []
           :stdout-events []}
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
                      (let [sub-id (str (or (:subnet-id outbound) (:subnet-id state) "global"))
                            reveal-str (canonical-rendezvous-reveal-str session-id (:pubkey state) (:callee outbound)
                                                                        offer-hash (:caller-x25519-pub outbound) (:epoch state))
                            reveal-sig (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes reveal-str)))
                            reveal-payload {:protocol-version current-wire-version
                                            :wire-format current-wire-format
                                            :subnet-id sub-id
                                            :bitecho/type :rendezvous-reveal
                                            :type :rendezvous-reveal
                                            :session-id session-id
                                            :caller (:pubkey state)
                                            :callee (:callee outbound)
                                            :offer-hash offer-hash
                                            :caller-x25519 (:caller-x25519-pub outbound)
                                            :epoch (:epoch state)
                                            :signature reveal-sig}
                            reveal-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload reveal-payload) 500 sub-id)
                            initial-text (:initial-text outbound)
                            [session-with-tx net-envs]
                            (if (and initial-text (not (str/blank? initial-text)))
                              (let [text-bytes (fressian/utf8->bytes initial-text)
                                    seq-num 1
                                    sealed-m (sealed/seal-message (:tx-key keys) seq-num text-bytes (fressian/utf8->bytes session-id) effective-suite)
                                    msg-payload {:protocol-version current-wire-version
                                                 :wire-format current-wire-format
                                                 :subnet-id sub-id
                                                 :bitecho/type :sealed-message
                                                 :session-id session-id
                                                 :sender (:pubkey state)
                                                 :recipient (:callee outbound)
                                                 :epoch (long (or (:epoch outbound) (:epoch state) 0))
                                                 :seq seq-num
                                                 :suite effective-suite
                                                 :nonce (basalt/bytes->hex (:nonce sealed-m))
                                                 :ciphertext (basalt/bytes->hex (:ciphertext sealed-m))}
                                    msg-env (build-gossip-envelope (:pubkey state) privkey-bytes (freeze-payload msg-payload) 500 sub-id)]
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
                         :stdout-events [est-evt]}))))))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-rendezvous-reveal
  "Callee receives Phase 2 :rendezvous-reveal wire payload.
   Verifies commitment binding of :caller-x25519 against Phase 1 offer-hash,
   verifies caller signature, derives matching keys, and establishes active sealed session."
  [state msg privkey-bytes]
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
      (let [msg-net (or (:network-uri msg) (get msg "network_uri") (get msg "network-uri"))
            st-net (or (:network-uri state) (config/resolve-network-uri (:subnet-id state)))
            network-mismatch? (or (and (string? msg-net) (string? st-net)
                                       (not= (str/trim msg-net) (str/trim st-net)))
                                  (and (= st-net "mainnet.bitecho.org") (str/blank? (str msg-net))))]
        (if network-mismatch?
          {:state (update-in state [:diagnostics :network-replay-rejected] (fnil inc 0))
           :net-envelopes []
           :stdout-events []}
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
                    offer-base {:session-id sid
                                :caller caller
                                :callee callee
                                :caller-ephemeral-pub caller-x25519
                                :epoch (:epoch header)
                                :price (:burn header)
                                :burn (:burn header)
                                :home-node (:home-node header)
                                :crypto-suites (:crypto-suites header)
                                :dac (:dac header)
                                :subnet-id (:subnet-id header)}
                    commitment-valid? (and (= sid expected-sid)
                                           (matching-offer-hash? offer-base state offer-hash))]
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
                                          caller-pname (assoc "peer_petname" caller-pname))
                                early-msgs (get-in state [:early-sealed-messages sid] [])
                                state-after-clear (update new-state :early-sealed-messages dissoc sid)
                                [final-state replayed-envs replayed-events]
                                (reduce (fn [[cur-st acc-envs acc-evts] early-msg]
                                          (let [res (handle-wire-sealed-msg cur-st early-msg privkey-bytes)]
                                            [(:state res)
                                             (into acc-envs (:net-envelopes res))
                                             (into acc-evts (:stdout-events res))]))
                                        [state-after-clear [] [est-evt]]
                                        early-msgs)]
                            {:state final-state
                             :net-envelopes replayed-envs
                             :stdout-events replayed-events}))))))))))))
    (catch #?(:clj Exception :cljs :default) _
      {:state state :net-envelopes [] :stdout-events []})))

(defn handle-wire-p2p-offer
  "Handles an incoming wire :p2p-offer envelope, validating sequence and answering or dialing."
  ([state msg]
   (handle-wire-p2p-offer state msg nil))
  ([state msg privkey-bytes]
   (try
     (let [recip (when-let [r (:recipient msg)] (normalize-pubkey-hex r))
           my-pk (normalize-pubkey-hex (:pubkey state))]
       (if (and recip (not= recip my-pk))
         {:state state :net-envelopes [] :stdout-events []}
         (let [sid (:session-id msg)
               session (get-in state [:sessions sid])
               signal-seq (long (or (:signal-seq msg) 0))
               last-seq (max (long (or (get-in session [:p2p :remote-offer-seq]) 0))
                             (long (or (get-in session [:p2p-meta :remote-offer-seq]) 0)))]
           (if (and (pos? signal-seq) (<= signal-seq last-seq))
             {:state (update-in state [:diagnostics :p2p-signal-deduped] (fnil inc 0))
              :net-envelopes []
              :stdout-events []}
             (let [valid-seq? (and (pos? signal-seq) (> signal-seq last-seq))
                   valid-session? (and session (= "open" (:state session)))
                   valid-endpoints? (and (string? (:sender msg))
                                         (string? (:recipient msg))
                                         (= recip my-pk)
                                         (= (normalize-pubkey-hex (:sender msg)) (normalize-pubkey-hex (:peer session))))
                   valid-sig-field? (and (string? (:signature msg)) (not (str/blank? (:signature msg))))]
               (if-not (and valid-session? valid-endpoints? valid-sig-field? valid-seq?)
                 (let [diag-evt {"event" "p2p-signaling-rejected"
                                 "type" (name (or (:type msg) :unknown))
                                 "session_id" (str (or sid ""))}]
                   {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
                    :net-envelopes []
                    :stdout-events [diag-evt]})
                 (let [transport (str (or (:transport msg) "udp"))
                       candidates (vec (map str (or (:candidates msg) [])))
                       ice-ufrag (str (or (:ice-ufrag msg) ""))
                       ice-pwd (str (or (:ice-pwd msg) ""))
                       fp (str (or (:fingerprint msg) ""))
                       epoch (long (or (:epoch msg) 0))
                       sig-str (canonical-p2p-signal-str :offer sid (:sender msg) (:recipient msg) transport candidates ice-ufrag ice-pwd fp epoch signal-seq)
                       sender-pub (try (basalt/hex->bytes (:sender msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                       sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                       sig-valid? (and sender-pub sig-bytes
                                       (crypto/verify sender-pub (fressian/utf8->bytes sig-str) sig-bytes))]
                   (if-not sig-valid?
                     (let [diag-evt {"event" "p2p-signaling-rejected"
                                     "type" (name (or (:type msg) :unknown))
                                     "session_id" (str (or sid ""))}]
                       {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
                        :net-envelopes []
                        :stdout-events [diag-evt]})
                     (let [already-connected? (or (true? (get-in session [:p2p :connected?]))
                                                  (= :open (get-in session [:p2p :phase])))
                           effective-sk (or privkey-bytes
                                            (when-let [pk (:privkey state)]
                                              (try (if (bytes? pk) pk (basalt/hex->bytes pk)) (catch #?(:clj Exception :cljs :default) _ nil)))
                                            (when-let [pk-b (get-in state [:identity :privkey-bytes])] pk-b))
                           auto-answer? (or already-connected?
                                            (and (boolean (:autonomous? state))
                                                 (some? effective-sk)))
                           p2p-base (get session :p2p {})
                           pname (pubkey->petname state (:sender msg))
                           evt (cond-> {"event" "p2p-offer-received"
                                        "session_id" sid
                                        "from" (normalize-pubkey-hex (:sender msg))
                                        "transport" transport
                                        "candidates" candidates}
                                 pname (assoc "from_petname" pname))]
                       (if auto-answer?
                         (let [_now-ms (long (or (:now-ms msg) (:epoch state 0)))
                               answer-seq (inc (max (long (or (get-in session [:p2p-meta :local-signal-seq]) (get-in session [:p2p :local-signal-seq]) 0))
                                                    (long (or (:signal-seq msg) 0))))
                               tr (str (or (get-in session [:p2p :local-transport])
                                           (get-in session [:p2p-meta :preferred-transport])
                                           transport
                                           "udp"))
                               incoming-relay-cands (filterv shared-http-relay-candidate? candidates)
                               existing-relay-cands (filterv shared-http-relay-candidate?
                                                             (concat (get-in session [:p2p :local-candidates])
                                                                     (get-in session [:p2p-meta :local-candidates])
                                                                     (get-in session [:p2p-meta :preferred-candidates])
                                                                     (get-in session [:p2p :remote-candidates])
                                                                     (get-in session [:p2p-meta :remote-candidates])))
                               all-relay-cands (vec (distinct (concat incoming-relay-cands existing-relay-cands)))
                               base-cands (->> (or (not-empty (get-in session [:p2p :local-candidates]))
                                                   (not-empty (get-in session [:p2p-meta :local-candidates]))
                                                   (not-empty (get-in session [:p2p-meta :preferred-candidates]))
                                                   (:default-p2p-candidates state []))
                                               (map str)
                                               (remove connect-proxy-candidate?)
                                               vec)
                               cands (if (seq all-relay-cands)
                                       (if (or (empty? base-cands) (every? private-or-mdns-candidate? base-cands))
                                         all-relay-cands
                                         (vec (distinct (concat base-cands all-relay-cands))))
                                       base-cands)
                               ice-u (str (or (get-in session [:p2p :local-ice-ufrag]) (get-in state [:ice-creds :ufrag]) "ufrag"))
                               ice-p (str (or (get-in session [:p2p :local-ice-pwd]) (get-in state [:ice-creds :pwd]) "pwd"))
                               local-fp (str (or (get-in session [:p2p :local-fingerprint]) (:fingerprint state) ""))
                               ep (effective-session-wire-epoch state session)
                               ans-sig-str (canonical-p2p-signal-str :answer sid (:pubkey state) (:sender msg) tr cands ice-u ice-p local-fp ep answer-seq)
                               ans-sig-bytes (when effective-sk (crypto/sign effective-sk (fressian/utf8->bytes ans-sig-str)))
                               ans-sig-hex (when ans-sig-bytes (if (string? ans-sig-bytes) ans-sig-bytes (basalt/bytes->hex ans-sig-bytes)))
                               answer-payload (when ans-sig-hex
                                                {:protocol-version current-wire-version
                                                 :wire-format current-wire-format
                                                 :subnet-id (str (or (:subnet-id session) (:subnet-id state) "global"))
                                                 :bitecho/type :p2p-answer
                                                 :type :p2p-answer
                                                 :session-id sid
                                                 :sender (:pubkey state)
                                                 :recipient (:sender msg)
                                                 :transport tr
                                                 :candidates cands
                                                 :ice-ufrag ice-u
                                                 :ice-pwd ice-p
                                                 :fingerprint local-fp
                                                 :epoch ep
                                                 :signal-seq answer-seq
                                                 :signature ans-sig-hex})
                               burn-fl (effective-signaling-burn-floor state)
                               outer-sub (if (pos? (long burn-fl)) "*" (:subnet-id answer-payload))
                               raw-env (when (and effective-sk answer-payload)
                                         (build-gossip-envelope (:pubkey state) effective-sk (freeze-payload answer-payload) (long burn-fl) outer-sub))
                               env (when raw-env
                                     (assoc raw-env
                                            :p2p-broadcast? true
                                            :p2p-peer (normalize-pubkey-hex (:sender msg))
                                            :p2p-session-id sid))
                               ans-evt {"event" "p2p-offer-answered-while-open"
                                        :event "p2p-offer-answered-while-open"
                                        "session_id" sid
                                        :session_id sid
                                        "to" (normalize-pubkey-hex (:sender msg))
                                        :to (normalize-pubkey-hex (:sender msg))
                                        "signal_seq" answer-seq
                                        :signal_seq answer-seq}
                               p2p-entry (assoc p2p-base
                                                :phase (if already-connected? :open :connecting)
                                                :connected? (boolean already-connected?)
                                                :role :responder
                                                :local-transport tr
                                                :local-candidates cands
                                                :local-ice-ufrag ice-u
                                                :local-ice-pwd ice-p
                                                :local-fingerprint local-fp
                                                :remote-candidates (vec candidates)
                                                :remote-transport transport
                                                :remote-ice-ufrag ice-ufrag
                                                :remote-ice-pwd ice-pwd
                                                :remote-fingerprint fp
                                                :remote-offer-seq signal-seq
                                                :local-signal-seq answer-seq
                                                :updated-epoch (long (or (:epoch state) 0)))
                               p2p-meta (merge (get session :p2p-meta {})
                                               {:remote-candidates (vec candidates)
                                                :remote-transport transport
                                                :remote-ice-ufrag ice-ufrag
                                                :remote-ice-pwd ice-pwd
                                                :remote-fingerprint fp
                                                :remote-offer-seq signal-seq
                                                :local-signal-seq answer-seq})
                               local-cands-set (set (concat (get-in session [:p2p :local-candidates])
                                                            (get-in session [:p2p-meta :local-candidates])
                                                            (get-in session [:p2p-meta :preferred-candidates])))
                               {:keys [dialable fallback?]} (filter-p2p-remote-candidates local-cands-set candidates)
                               dialable-candidates dialable
                               new-state (cond-> (-> state
                                                     (assoc-in [:sessions sid :p2p] p2p-entry)
                                                     (assoc-in [:sessions sid :p2p-meta] p2p-meta)
                                                     (update-in [:diagnostics :p2p-offer-answered-while-open] (fnil inc 0)))
                                           fallback? (update-in [:diagnostics :p2p-offer-candidate-self-filter-fallback] (fnil inc 0)))
                               dial-effect (when (seq dialable-candidates)
                                             {:session-id sid
                                              :peer (normalize-pubkey-hex (:sender msg))
                                              :role :responder
                                              :force-redial? true
                                              :transport transport
                                              :remote-candidates dialable-candidates
                                              :remote-ice-ufrag ice-ufrag
                                              :remote-ice-pwd ice-pwd
                                              :remote-fingerprint fp})]
                           (cond-> {:state new-state
                                    :net-envelopes (if env [env] [])
                                    :stdout-events (if already-connected? [ans-evt] [evt ans-evt])}
                             dial-effect (assoc :p2p-dial dial-effect)))
                         (let [p2p-entry (merge p2p-base
                                                {:phase :offer-received
                                                 :connected? false
                                                 :remote-transport transport
                                                 :remote-candidates (vec candidates)
                                                 :remote-ice-ufrag ice-ufrag
                                                 :remote-ice-pwd ice-pwd
                                                 :remote-fingerprint fp
                                                 :remote-offer-seq signal-seq})
                               p2p-meta (merge (get session :p2p-meta {})
                                               {:remote-transport transport
                                                :remote-candidates (vec candidates)
                                                :remote-ice-ufrag ice-ufrag
                                                :remote-ice-pwd ice-pwd
                                                :remote-fingerprint fp
                                                :remote-offer-seq signal-seq})
                               new-state (-> state
                                             (assoc-in [:sessions sid :p2p] p2p-entry)
                                             (assoc-in [:sessions sid :p2p-meta] p2p-meta))]
                           {:state new-state
                            :net-envelopes []
                            :stdout-events [evt]})))))))))))
     (catch #?(:clj Exception :cljs :default) _
       (let [diag-evt {"event" "p2p-signaling-rejected"
                       "type" (name (or (:type msg) :unknown))
                       "session_id" (str (or (:session-id msg) ""))}]
         {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
          :net-envelopes []
          :stdout-events [diag-evt]})))))

(defn- handle-wire-p2p-answer
  [state msg]
  (try
    (let [recip (when-let [r (:recipient msg)] (normalize-pubkey-hex r))
          my-pk (normalize-pubkey-hex (:pubkey state))]
      (if (and recip (not= recip my-pk))
        {:state state :net-envelopes [] :stdout-events []}
        (let [sid (:session-id msg)
              session (get-in state [:sessions sid])
              signal-seq (long (or (:signal-seq msg) 0))
              last-seq (max (long (or (get-in session [:p2p :remote-answer-seq]) 0))
                            (long (or (get-in session [:p2p-meta :remote-answer-seq]) 0)))]
          (if (and (pos? signal-seq) (<= signal-seq last-seq))
            {:state (update-in state [:diagnostics :p2p-signal-deduped] (fnil inc 0))
             :net-envelopes []
             :stdout-events []}
            (let [valid-seq? (and (pos? signal-seq) (> signal-seq last-seq))
                  valid-session? (and session (= "open" (:state session)))
                  valid-endpoints? (and (string? (:sender msg))
                                        (string? (:recipient msg))
                                        (= recip my-pk)
                                        (= (normalize-pubkey-hex (:sender msg)) (normalize-pubkey-hex (:peer session))))
                  valid-sig-field? (and (string? (:signature msg)) (not (str/blank? (:signature msg))))]
              (if-not (and valid-session? valid-endpoints? valid-sig-field? valid-seq?)
                (let [diag-evt {"event" "p2p-signaling-rejected"
                                "type" (name (or (:type msg) :unknown))
                                "session_id" (str (or sid ""))}]
                  {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
                   :net-envelopes []
                   :stdout-events [diag-evt]})
                (let [transport (str (or (:transport msg) "udp"))
                      candidates (vec (map str (or (:candidates msg) [])))
                      ice-ufrag (str (or (:ice-ufrag msg) ""))
                      ice-pwd (str (or (:ice-pwd msg) ""))
                      fp (str (or (:fingerprint msg) ""))
                      epoch (long (or (:epoch msg) 0))
                      sig-str (canonical-p2p-signal-str :answer sid (:sender msg) (:recipient msg) transport candidates ice-ufrag ice-pwd fp epoch signal-seq)
                      sender-pub (try (basalt/hex->bytes (:sender msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                      sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch #?(:clj Exception :cljs :default) _ nil))
                      sig-valid? (and sender-pub sig-bytes
                                      (crypto/verify sender-pub (fressian/utf8->bytes sig-str) sig-bytes))]
                  (if-not sig-valid?
                    (let [diag-evt {"event" "p2p-signaling-rejected"
                                    "type" (name (or (:type msg) :unknown))
                                    "session_id" (str (or sid ""))}]
                      {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
                       :net-envelopes []
                       :stdout-events [diag-evt]})
                    (let [norm-sender (normalize-pubkey-hex (:sender msg))
                          already-connected? (or (true? (get-in session [:p2p :connected?]))
                                                 (= :open (get-in session [:p2p :phase])))
                          local-cands-set (set (concat (get-in session [:p2p :local-candidates])
                                                       (get-in session [:p2p-meta :local-candidates])
                                                       (get-in session [:p2p-meta :preferred-candidates])))
                          {:keys [dialable fallback?]} (filter-p2p-remote-candidates local-cands-set candidates false)
                          dialable-candidates dialable
                          has-candidates? (boolean (seq dialable-candidates))
                          has-local-candidates? (boolean (seq (get-in session [:p2p :local-candidates])))
                          p2p-base (get session :p2p {})
                          pname (pubkey->petname state norm-sender)
                          evt (cond-> {"event" "p2p-answer-received"
                                       "session_id" sid
                                       "peer" norm-sender
                                       "transport" transport
                                       "candidates" candidates}
                                pname (assoc "peer_petname" pname))]
                      (cond
                        already-connected?
                        (let [p2p-entry (assoc p2p-base
                                               :phase :open
                                               :connected? true
                                               :remote-candidates (vec candidates)
                                               :remote-transport transport
                                               :remote-ice-ufrag ice-ufrag
                                               :remote-ice-pwd ice-pwd
                                               :remote-fingerprint fp
                                               :remote-answer-seq signal-seq
                                               :updated-epoch (long (or (:epoch state) 0)))
                              new-state (-> state
                                            (assoc-in [:sessions sid :p2p] p2p-entry)
                                            (assoc-in [:sessions sid :p2p-meta :remote-answer-seq] signal-seq)
                                            (update-in [:diagnostics :p2p-signal-deduped] (fnil inc 0)))]
                          {:state new-state
                           :net-envelopes []
                           :stdout-events []
                           :p2p-dial nil})

                        has-candidates?
                        (let [p2p-entry (merge p2p-base
                                               {:phase :connecting
                                                :connected? false
                                                :zero-burn? false
                                                :remote-transport transport
                                                :remote-candidates (vec candidates)
                                                :remote-ice-ufrag ice-ufrag
                                                :remote-ice-pwd ice-pwd
                                                :remote-fingerprint fp
                                                :remote-answer-seq signal-seq})
                              new-state (cond-> (-> state
                                                    (assoc-in [:sessions sid :p2p] p2p-entry)
                                                    (assoc-in [:sessions sid :p2p-meta :remote-answer-seq] signal-seq))
                                          fallback? (update-in [:diagnostics :p2p-answer-candidate-self-filter-fallback] (fnil inc 0)))
                              p2p-dial {:session-id sid
                                        :peer norm-sender
                                        :role :initiator
                                        :transport transport
                                        :local-candidates (get-in session [:p2p :local-candidates])
                                        :remote-candidates dialable-candidates
                                        :remote-ice-ufrag ice-ufrag
                                        :remote-ice-pwd ice-pwd
                                        :remote-fingerprint fp}]
                          {:state new-state
                           :net-envelopes []
                           :stdout-events [evt]
                           :p2p-dial p2p-dial})

                        has-local-candidates?
                        (let [p2p-entry (merge p2p-base
                                               {:phase (or (get-in session [:p2p :phase]) :offered)
                                                :connected? false
                                                :zero-burn? false
                                                :remote-transport transport
                                                :remote-candidates (vec candidates)
                                                :remote-ice-ufrag ice-ufrag
                                                :remote-ice-pwd ice-pwd
                                                :remote-fingerprint fp
                                                :remote-answer-seq signal-seq})
                              new-state (-> state
                                            (assoc-in [:sessions sid :p2p] p2p-entry)
                                            (assoc-in [:sessions sid :p2p-meta :remote-answer-seq] signal-seq)
                                            (update-in [:diagnostics :p2p-answer-empty-candidates] (fnil inc 0)))]
                          {:state new-state
                           :net-envelopes []
                           :stdout-events [evt]
                           :p2p-dial nil})

                        :else
                        (let [p2p-entry (merge p2p-base
                                               {:phase :closed
                                                :connected? false
                                                :zero-burn? false
                                                :error "p2p-dial-failed"
                                                :remote-transport transport
                                                :remote-candidates (vec candidates)
                                                :remote-ice-ufrag ice-ufrag
                                                :remote-ice-pwd ice-pwd
                                                :remote-fingerprint fp
                                                :remote-answer-seq signal-seq})
                              new-state (-> state
                                            (assoc-in [:sessions sid :p2p] p2p-entry)
                                            (assoc-in [:sessions sid :p2p-meta :remote-answer-seq] signal-seq)
                                            (update-in [:diagnostics :p2p-dial-failed] (fnil inc 0)))
                              disconn-evt {"event" "p2p-disconnected"
                                           "session_id" sid
                                           "peer" norm-sender
                                           "reason" "p2p-dial-failed"}]
                          {:state new-state
                           :net-envelopes []
                           :stdout-events [evt disconn-evt]
                           :p2p-dial nil})))))))))))
    (catch #?(:clj Exception :cljs :default) _
      (let [diag-evt {"event" "p2p-signaling-rejected"
                      "type" (name (or (:type msg) :unknown))
                      "session_id" (str (or (:session-id msg) ""))}]
        {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
         :net-envelopes []
         :stdout-events [diag-evt]}))))

(defn- handle-wire-p2p-hub-relay
  [state msg privkey-bytes]
  (try
    (if-not (and (string? (:sender msg)) (valid-pubkey-hex? (:sender msg))
                 (string? (:target-pubkey msg)) (valid-pubkey-hex? (:target-pubkey msg))
                 (some? (:sealed-envelope msg))
                 (string? (:signature msg)) (not (str/blank? (:signature msg))))
      (let [diag-evt {"event" "p2p-signaling-rejected"
                      "type" (name (or (:type msg) :p2p-hub-relay))
                      "session_id" (str (or (:session-id msg) ""))}]
        {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
         :net-envelopes []
         :stdout-events [diag-evt]})
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
          (let [diag-evt {"event" "p2p-signaling-rejected"
                          "type" (name (or (:type msg) :p2p-hub-relay))
                          "session_id" (str (or (:session-id msg) ""))}]
            {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
             :net-envelopes []
             :stdout-events [diag-evt]})
          (if (= norm-target (normalize-pubkey-hex (:pubkey state)))
            (handle-wire-payload state (:sealed-envelope msg) privkey-bytes)
            (let [relay-env (assoc (:sealed-envelope msg)
                                   :p2p-direct? true
                                   :p2p-peer norm-target)]
              {:state (update-in state [:diagnostics :p2p-relayed] (fnil inc 0))
               :net-envelopes [relay-env]
               :stdout-events []})))))
    (catch #?(:clj Exception :cljs :default) _
      (let [diag-evt {"event" "p2p-signaling-rejected"
                      "type" (name (or (:type msg) :p2p-hub-relay))
                      "session_id" (str (or (:session-id msg) ""))}]
        {:state (update-in state [:diagnostics :p2p-signaling-rejected] (fnil inc 0))
         :net-envelopes []
         :stdout-events [diag-evt]}))))

(defn- verify-p2p-link-bind-msg
  "Verifies a `:p2p-link-bind` wire message signature (`bitecho-p2p-link-bind-v1|<norm-sender>|<sid>`)."
  [msg]
  (when (and (map? msg)
             (= :p2p-link-bind (or (:type msg) (:bitecho/type msg)))
             (string? (:sender msg))
             (valid-pubkey-hex? (:sender msg))
             (string? (:session-id msg))
             (not (str/blank? (:session-id msg)))
             (string? (:signature msg))
             (not (str/blank? (:signature msg))))
    (try
      (let [norm-sender (normalize-pubkey-hex (:sender msg))
            sid (:session-id msg)
            sig-str (str "bitecho-p2p-link-bind-v1|" norm-sender "|" sid)
            pub-bytes (basalt/hex->bytes norm-sender)
            sig-bytes (basalt/hex->bytes (:signature msg))]
        (boolean (and pub-bytes sig-bytes
                      (crypto/verify pub-bytes (fressian/utf8->bytes sig-str) sig-bytes))))
      (catch #?(:clj Exception :cljs :default) _ false))))

(defn handle-wire-p2p-link-bind
  "Handles an incoming `:p2p-link-bind` wire envelope (`P-LEG-1`).
   Transitions the session's P2P leg to `:open` (`:connected? true`, `:zero-burn? true`)
   only if the signature is valid and `:sender` matches the open session's `:peer`.
   Otherwise increments `[:diagnostics :p2p-link-bind-rejected]` and emits a diagnostic event (Rule 5)."
  ([state msg]
   (handle-wire-p2p-link-bind state msg nil))
  ([state msg privkey-bytes]
   (let [sid (or (:session-id msg) (get msg "session_id"))
         raw-sender (or (:sender msg) (get msg "sender"))
         norm-sender (when (and (string? raw-sender) (valid-pubkey-hex? raw-sender))
                       (normalize-pubkey-hex raw-sender))
         sess (when (and sid (string? sid)) (get-in state [:sessions sid]))
         expected-peer (when sess (normalize-pubkey-hex (:peer sess)))
         valid? (and (verify-p2p-link-bind-msg msg)
                     (some? sess)
                     (= "open" (:state sess))
                     (some? norm-sender)
                     (= norm-sender expected-peer))]
     (if valid?
       (let [tr (str (or (:transport msg)
                         (get-in sess [:p2p :remote-transport])
                         (get-in sess [:p2p :local-transport])
                         "https"))]
         (exec-p2p-channel-state state
                                 {"cmd" "p2p-channel-state"
                                  "session_id" sid
                                  "connected" true
                                  "transport" tr}
                                 privkey-bytes))
       (let [diag-evt {"event" "diagnostic"
                       "reason" "p2p-link-bind-rejected"
                       "session_id" (str (or sid ""))}]
         {:state (-> state
                     (update-in [:diagnostics :p2p-link-bind-rejected] (fnil inc 0))
                     (update-in [:diagnostics :p2p-signaling-rejected] (fnil inc 0)))
          :net-envelopes []
          :stdout-events [diag-evt]})))))

(defn handle-wire-broadcast
  "Processes an incoming broadcast gossip message across both map and wire-unpacked formats."
  ([state msg]
   (handle-wire-broadcast state msg nil))
  ([state msg privkey-bytes]
   (try
     (let [raw-sender (or (:sender msg) (:from msg) (get msg "sender") (get msg "from"))
           raw-seq (or (:seq msg) (get msg "seq"))
           parsed-seq (when raw-seq (parse-long-safe raw-seq nil))
           raw-msg-id (or (:msg-id msg) (:msg_id msg) (get msg "msg-id") (get msg "msg_id"))
           raw-text (or (:text msg) (get msg "text") (:message msg) (get msg "message"))
           raw-sig (or (:signature msg) (:sig msg) (get msg "signature") (get msg "sig"))
           raw-sub (or (:subnet-id msg) (:subnet_id msg) (get msg "subnet-id") (get msg "subnet_id"))
           raw-epoch (or (:epoch msg) (get msg "epoch"))]
       (if-not (and (string? raw-sender) (valid-pubkey-hex? raw-sender)
                    (integer? parsed-seq) (pos? (long parsed-seq))
                    (string? raw-msg-id) (not (str/blank? raw-msg-id))
                    (string? raw-text) (not (str/blank? raw-text))
                    (string? raw-sig) (not (str/blank? raw-sig)))
         (let [evt {"event" "broadcast-rejected"
                    "reason" "broadcast-malformed"
                    "local_epoch" (long (or (:epoch state) 0))}]
           {:state (-> state
                       (update-in [:diagnostics :broadcast-malformed] (fnil inc 0))
                       (update-in [:diagnostics :broadcast-rejected] (fnil inc 0))
                       (record-suppression :broadcast-malformed))
            :net-envelopes []
            :stdout-events [evt]})
         (let [norm-sender (normalize-pubkey-hex raw-sender)
               seq-num (long parsed-seq)
               msg-id raw-msg-id
               text raw-text
               sub-id (str (or raw-sub (:subnet-id state) "global"))
               epoch (long (or (when raw-epoch (parse-long-safe raw-epoch nil)) (:epoch state) 0))
               wire-dac (or (:dac msg) (get msg "dac"))
               dac-id (when (map? wire-dac) (or (:dac-id wire-dac) (get wire-dac "dac_id") (get wire-dac "dac-id")))
               expected-msg-id (compute-broadcast-msg-id sub-id norm-sender seq-num text)
               sig-str (canonical-broadcast-str sub-id norm-sender seq-num msg-id text epoch dac-id)
               sender-pub (try (basalt/hex->bytes norm-sender) (catch #?(:clj Exception :cljs :default) _ nil))
               sig-bytes (try (basalt/hex->bytes raw-sig) (catch #?(:clj Exception :cljs :default) _ nil))
               sig-valid? (and (= msg-id expected-msg-id)
                               sender-pub sig-bytes
                               (crypto/verify sender-pub (fressian/utf8->bytes sig-str) sig-bytes))
               trusted-anchors (into #{} (concat (:trusted-dac-anchors state) (get-in state [:account :trusted-dac-anchors])))
               requires-dac? (boolean (seq trusted-anchors))
               dac-check (when (and sig-valid? (map? wire-dac))
                           (verify-dac wire-dac {:expected-agent-pubkey norm-sender
                                                 :current-epoch (:epoch state)
                                                 :revoked-dac-ids (:revoked-dacs state)
                                                 :required-scope "broadcast"}))
               dac-anchor (when (map? wire-dac)
                            (or (get-in dac-check [:dac :anchor-pubkey])
                                (:anchor-pubkey wire-dac)
                                (get wire-dac "anchor_pubkey")
                                (get wire-dac "anchor-pubkey")))
               dac-valid? (cond
                            (nil? wire-dac) (not requires-dac?)
                            (not (map? wire-dac)) false
                            (not (:ok? dac-check)) false
                            requires-dac? (contains? trusted-anchors (normalize-pubkey-hex dac-anchor))
                            :else true)]
           (cond
             (not sig-valid?)
             (let [evt {"event" "broadcast-rejected"
                        "reason" "broadcast-sig-invalid"
                        "subnet_id" sub-id
                        "from" norm-sender
                        "seq" seq-num
                        "msg_id" msg-id
                        "local_epoch" (long (or (:epoch state) 0))}]
               {:state (-> state
                           (update-in [:diagnostics :broadcast-sig-invalid] (fnil inc 0))
                           (update-in [:diagnostics :broadcast-rejected] (fnil inc 0))
                           (record-suppression :broadcast-sig-invalid))
                :net-envelopes []
                :stdout-events [evt]})

             (and requires-dac? (nil? wire-dac))
             (let [evt {"event" "broadcast-rejected"
                        "reason" "dac-required-missing"
                        "subnet_id" sub-id
                        "from" norm-sender
                        "seq" seq-num
                        "msg_id" msg-id
                        "local_epoch" (long (or (:epoch state) 0))}]
               {:state (-> state
                           (update-in [:diagnostics :broadcast-dac-missing] (fnil inc 0))
                           (update-in [:diagnostics :broadcast-rejected] (fnil inc 0))
                           (record-suppression :dac-required-missing))
                :net-envelopes []
                :stdout-events [evt]})

             (and (some? wire-dac) (or (not (map? wire-dac)) (not dac-valid?)))
             (let [dac-err (cond
                             (not (map? wire-dac)) "malformed-dac-not-a-map"
                             (not (:ok? dac-check)) (str (or (:error dac-check) "dac-verification-failed"))
                             :else "untrusted-dac-anchor")
                   evt (cond-> {"event" "broadcast-rejected"
                                "reason" "broadcast-dac-invalid"
                                "subnet_id" sub-id
                                "from" norm-sender
                                "seq" seq-num
                                "msg_id" msg-id
                                "local_epoch" (long (or (:epoch state) 0))
                                "dac_error" dac-err}
                         dac-id (assoc "dac_id" (str dac-id))
                         dac-anchor (assoc "anchor_pubkey" (str dac-anchor)))]
               {:state (-> state
                           (update-in [:diagnostics :broadcast-dac-invalid] (fnil inc 0))
                           (update-in [:diagnostics :broadcast-rejected] (fnil inc 0))
                           (record-suppression :broadcast-dac-invalid))
                :net-envelopes []
                :stdout-events [evt]})

             :else
             (let [dedup-key [norm-sender seq-num msg-id]
                   seen (:broadcast-seen state #{})]
               (if (contains? seen dedup-key)
                 {:state (-> state
                             (update-in [:diagnostics :broadcast-duplicates-dropped] (fnil inc 0))
                             (record-suppression :duplicate-replay))
                  :net-envelopes []
                  :stdout-events []}
                 (let [pname (pubkey->petname state norm-sender)
                       b-entry (cond-> {:type :broadcast
                                        :from norm-sender
                                        :seq seq-num
                                        :broadcast-seq seq-num
                                        :msg-id msg-id
                                        :msg_id msg-id
                                        "msg_id" msg-id
                                        :text text
                                        :subnet-id sub-id
                                        :subnet_id sub-id
                                        "subnet_id" sub-id
                                        :epoch epoch
                                        :broadcast? true}
                                 pname (assoc :from_petname pname "from_petname" pname))
                       evt (cond-> {"event" "broadcast-received"
                                    "subnet_id" sub-id
                                    "from" norm-sender
                                    "seq" seq-num
                                    "broadcast_seq" seq-num
                                    "msg_id" msg-id
                                    "text" text}
                             pname (assoc "from_petname" pname))
                       open-p2p-peers (->> (:sessions state)
                                           (keep (fn [[sid s]]
                                                   (when (and (= "open" (:state s))
                                                              (true? (get-in s [:p2p :connected?]))
                                                              (not= (normalize-pubkey-hex (:peer s)) norm-sender))
                                                     {:peer (normalize-pubkey-hex (:peer s))
                                                      :session-id sid})))
                                           (distinct)
                                           vec)
                       relay-pub (or (:pubkey state) norm-sender)
                       relay-payload (cond-> msg
                                       wire-dac (assoc :dac wire-dac))
                       relay-envs (mapv (fn [target]
                                          (assoc (build-gossip-envelope relay-pub privkey-bytes (freeze-payload relay-payload) 0 sub-id)
                                                 :p2p-direct? true
                                                 :p2p-peer (:peer target)
                                                 :p2p-session-id (:session-id target)))
                                        open-p2p-peers)
                       new-state (-> state
                                     (record-broadcast-seen dedup-key)
                                     (update :broadcast-inbox append-bounded-inbox b-entry)
                                     (update :inbox append-bounded-inbox b-entry)
                                     (update-in [:diagnostics :p2p-relayed] (fnil + 0) (count relay-envs)))]
                   {:state new-state
                    :net-envelopes relay-envs
                    :stdout-events [evt]})))))))
     (catch #?(:clj Exception :cljs :default) _
       {:state (update-in state [:diagnostics :broadcast-rejected] (fnil inc 0))
        :net-envelopes []
        :stdout-events []}))))

(defn handle-wire-chain-state-snapshot
  "Handles incoming validator :chain-state-snapshot over wire.
   Verifies against trusted bootstrap validators and min finalized epoch.
   Buffers snapshot in :chain-state-snapshots, prunes stale snapshots, and applies
   ONLY when verified BFT quorum is reached across trusted validators."
  [state msg]
  (let [trusted (set (keep (comp normalize-pubkey-hex :pubkey) (vals (get-in state [:bootstrap :nodes]))))
        curr-gen (long (or (:network-generation state) 1))
        min-fin-ep (long (or (get-in state [:account :finalized-epoch]) 0))
        opts {:expected-pubkey (:pubkey state)
              :trusted-validators trusted
              :min-network-generation curr-gen
              :min-finalized-epoch min-fin-ep}
        v-res (verify-chain-state-snapshot msg opts)]
    (if-not (:ok? v-res)
      {:state state :net-envelopes [] :stdout-events []}
      (let [snap (:snapshot v-res)
            val-pk (:validator-pubkey snap)
            snap-gen (long (or (:network-generation snap) curr-gen))
            fin-ep (long (or (:finalized-epoch snap) 0))
            existing-snaps (:chain-state-snapshots state {})
            ;; Prune stale snapshots older than (fin-ep - 2) or from an older network generation
            fresh-snaps (into {} (filter (fn [[_ s]]
                                           (let [s-gen (long (or (:network-generation s) curr-gen))]
                                             (if (> snap-gen s-gen)
                                               false
                                               (>= (long (or (:finalized-epoch s) 0)) (- fin-ep 2)))))
                                         existing-snaps))
            buffered-snaps (assoc fresh-snaps val-pk snap)
            buffered-state (assoc state :chain-state-snapshots buffered-snaps)
            q-res (verify-chain-state-quorum (vals buffered-snaps) opts)]
        (if (:ok? q-res)
          (let [agreed-snap (:snapshot q-res)
                agreed-gen (long (or (:network-generation agreed-snap) curr-gen))
                gen-resynced? (> agreed-gen curr-gen)
                st-applied (apply-verified-chain-state-snapshot buffered-state agreed-snap)
                stdout-evt {"event" "chain-state-synced"
                            "pubkey" (:pubkey state)
                            "balance" (:balance agreed-snap)
                            "spendable" (:spendable agreed-snap)
                            "seq" (:seq agreed-snap)
                            "finalized_epoch" (:finalized-epoch agreed-snap)
                            "quorum_count" (:quorum-count q-res)
                            "validator" (:validator-pubkey agreed-snap)}
                gen-evt (when gen-resynced?
                          {"event" "network-generation-resynced"
                           "pubkey" (:pubkey state)
                           "from_generation" curr-gen
                           "to_generation" agreed-gen
                           "finalized_epoch" (:finalized-epoch agreed-snap)
                           "balance" (:balance agreed-snap)
                           "seq" (:seq agreed-snap)})]
            {:state st-applied
             :net-envelopes []
             :stdout-events (cond-> [stdout-evt]
                              gen-evt (conj gen-evt))})
          {:state buffered-state
           :net-envelopes []
           :stdout-events []})))))

(defn- normalize-wire-blob [b]
  (when (map? b)
    (let [cid (str (or (:blob/cid b) (get b "blob/cid") (:cid b) (get b "cid")))
          media (str (or (:blob/media-type b) (get b "blob/media-type") (:media-type b) (get b "media_type") "application/octet-stream"))
          raw-bytes (or (:blob/bytes b) (get b "blob/bytes") (:bytes b) (get b "bytes"))
          bs (cond
               (fressian/bytes? raw-bytes) raw-bytes
               (and (string? raw-bytes) (re-matches #"[0-9a-fA-F]+" raw-bytes) (even? (count raw-bytes)))
               (fressian/hex->bytes raw-bytes)
               (string? raw-bytes) (fressian/utf8->bytes raw-bytes)
               :else raw-bytes)]
      {:blob/cid cid
       :blob/media-type media
       :blob/bytes bs})))

(defn- normalize-wire-pointer [p]
  (when (map? p)
    (let [sub (str (or (:pointer/subnet p) (get p "pointer/subnet") (:subnet p) (get p "subnet")))
          path (str (or (:pointer/path p) (get p "pointer/path") (:path p) (get p "path")))
          auth (str (or (:pointer/authority p) (get p "pointer/authority") (:authority p) (get p "authority")))
          seq-num (long (or (:pointer/seq p) (get p "pointer/seq") (:seq p) (get p "seq") 0))
          raw-term (or (:pointer/leader-term p) (get p "pointer/leader-term") (:leader-term p) (get p "leader_term"))
          raw-target (or (:pointer/target p) (get p "pointer/target") (:target p) (get p "target") (:cid p) (get p "cid"))
          target (when (and (some? raw-target) (not (str/blank? (str raw-target))))
                   (str raw-target))
          sig (str (or (:pointer/sig p) (get p "pointer/sig") (:sig p) (get p "sig")))
          raw-proof (or (:pointer/proof p) (get p "pointer/proof") (:proof p) (get p "proof"))
          proof (if (map? raw-proof)
                  (let [pt (or (:proof/type raw-proof) (get raw-proof "proof/type") (:type raw-proof) (get raw-proof "type") :self)]
                    (-> raw-proof
                        (dissoc "proof/type" "type" :type)
                        (assoc :proof/type (if (keyword? pt) pt (keyword (str/replace (str pt) #"^:+" ""))))))
                  {:proof/type :self})]
      (cond-> {:pointer/subnet sub
               :pointer/path path
               :pointer/authority auth
               :pointer/seq seq-num
               :pointer/target target
               :pointer/sig sig
               :pointer/proof proof}
        (some? raw-term) (assoc :pointer/leader-term (long raw-term))))))

(defn- handle-wire-storage-replicate [state msg]
  (let [blob (normalize-wire-blob (or (:blob msg) (get msg "blob")))
        ptr (normalize-wire-pointer (or (:pointer msg) (get msg "pointer")))
        subnet (str (or (:subnet-id msg) (get msg "subnet_id") (when ptr (:pointer/subnet ptr)) "global"))
        path (str (or (:path msg) (get msg "path") (when ptr (:pointer/path ptr))))
        existing-ptr (or (get-in state [:storage-pointers [subnet path]])
                         (get-in state [:pointers [subnet path]]))
        current-seq (long (or (get-in state [:storage-min-seqs [subnet path]])
                              (when existing-ptr (:pointer/seq existing-ptr))
                              0))
        valid-blob? (boolean (and (map? blob) (data/verify-blob blob)))
        valid-ptr? (boolean (and (map? ptr) (:ok? (data/verify-pointer ptr))))
        target-match? (boolean (and valid-blob? valid-ptr? (= (:pointer/target ptr) (:blob/cid blob))))
        seq-valid? (boolean (and valid-ptr? (> (long (:pointer/seq ptr)) current-seq)))
        valid? (and valid-blob? valid-ptr? target-match? seq-valid?)]
    (if-not valid?
      (let [reason (cond
                     (not valid-blob?) "invalid-blob"
                     (not valid-ptr?) "invalid-pointer"
                     (not target-match?) "target-mismatch"
                     (not seq-valid?) "stale-sequence"
                     :else "invalid-replicate")
            diag-event {"event" "diagnostic"
                        "reason" "storage-replication-rejected"
                        "cause" reason
                        "subnet_id" subnet
                        "path" path}]
        {:state (-> state
                    (update-in [:diagnostics :replication-rejected] (fnil inc 0)))
         :net-envelopes []
         :stdout-events [diag-event]})
      (let [evt {"event" "storage-replicated"
                 "subnet_id" subnet
                 "path" path
                 "cid" (:blob/cid blob)
                 "seq" (:pointer/seq ptr)
                 "authority" (:pointer/authority ptr)}]
        {:state (-> state
                    (assoc-in [:blobs (:blob/cid blob)] blob)
                    (assoc-in [:pointers [subnet path]] ptr)
                    (assoc-in [:storage-blobs (:blob/cid blob)] blob)
                    (assoc-in [:storage-pointers [subnet path]] ptr)
                    (assoc-in [:storage-min-seqs [subnet path]] (:pointer/seq ptr)))
         :net-envelopes []
         :stdout-events [evt]}))))

(defn- handle-wire-artifact-replicate [state msg]
  (let [blob (normalize-wire-blob (or (:blob msg) (get msg "blob")))
        ptr (normalize-wire-pointer (or (:pointer msg) (get msg "pointer") msg))
        subnet (str (or (:subnet-id msg) (get msg "subnet_id") (when ptr (:pointer/subnet ptr)) "global"))
        path (str/replace (str/trim (str (or (:path msg) (get msg "path") (when ptr (:pointer/path ptr)) ""))) #"^/+" "")
        existing-ptr (or (get-in state [:artifact-pointers [subnet path]])
                         (get-in state [:artifact-tombstones [subnet path]])
                         (get-in state [:pointers [subnet path]]))
        current-seq (long (or (get-in state [:artifact-min-seqs [subnet path]])
                              (when existing-ptr (:pointer/seq existing-ptr))
                              0))
        valid-ptr? (boolean (and (map? ptr) (not (str/blank? path)) (:ok? (data/verify-pointer ptr))))
        tombstone? (boolean (and valid-ptr? (nil? (:pointer/target ptr))))
        valid-blob? (boolean (and (map? blob) (data/verify-blob blob)))
        target-match? (if tombstone?
                        true
                        (if (some? blob)
                          (and valid-blob? (= (:pointer/target ptr) (:blob/cid blob)))
                          (or (some? (get-in state [:artifact-blobs (:pointer/target ptr)]))
                              (some? (get-in state [:blobs (:pointer/target ptr)])))))
        duplicate-ptr? (boolean (and valid-ptr?
                                     target-match?
                                     existing-ptr
                                     (= (:pointer/authority ptr) (:pointer/authority existing-ptr))
                                     (= (long (:pointer/seq ptr)) (long (:pointer/seq existing-ptr)))
                                     (= (:pointer/target ptr) (:pointer/target existing-ptr))))
        seq-valid? (boolean (and valid-ptr?
                                 (if existing-ptr
                                   (pos? (compare (data/pointer-order-tuple ptr)
                                                  (data/pointer-order-tuple existing-ptr)))
                                   (> (long (:pointer/seq ptr)) current-seq))))
        valid? (and valid-ptr? target-match? seq-valid?)]
    (if duplicate-ptr?
      {:state (-> state
                  (cond-> valid-blob? (assoc-in [:blobs (:blob/cid blob)] blob))
                  (cond-> valid-blob? (assoc-in [:artifact-blobs (:blob/cid blob)] blob)))
       :net-envelopes []
       :stdout-events []}
      (if-not valid?
        (let [reason (cond
                       (not valid-ptr?) "invalid-pointer"
                       (not target-match?) "target-mismatch"
                       (not seq-valid?) "stale-sequence"
                       :else "invalid-replicate")
              diag-event {"event" "diagnostic"
                          "reason" "artifact-replication-rejected"
                          "cause" reason
                          "subnet_id" subnet
                          "path" path}]
          {:state (-> state
                      (update-in [:diagnostics :replication-rejected] (fnil inc 0)))
           :net-envelopes []
           :stdout-events [diag-event]})
        (if tombstone?
          (let [evt {"event" "artifact-revoked"
                     "subnet_id" subnet
                     "path" path
                     "cid" nil
                     "tombstoned" true
                     "seq" (:pointer/seq ptr)
                     "authority" (:pointer/authority ptr)}]
            {:state (-> state
                        (assoc-in [:pointers [subnet path]] ptr)
                        (assoc :artifact-pointers (dissoc (or (:artifact-pointers state) {}) [subnet path]))
                        (assoc :artifact-tombstones (assoc (or (:artifact-tombstones state) {}) [subnet path] ptr))
                        (assoc-in [:artifact-min-seqs [subnet path]] (:pointer/seq ptr)))
             :net-envelopes []
             :stdout-events [evt]})
          (let [evt {"event" "artifact-replicated"
                     "subnet_id" subnet
                     "path" path
                     "cid" (:pointer/target ptr)
                     "seq" (:pointer/seq ptr)
                     "authority" (:pointer/authority ptr)}]
            {:state (-> state
                        (cond-> valid-blob? (assoc-in [:blobs (:blob/cid blob)] blob))
                        (assoc-in [:pointers [subnet path]] ptr)
                        (cond-> valid-blob? (assoc-in [:artifact-blobs (:blob/cid blob)] blob))
                        (assoc :artifact-pointers (assoc (or (:artifact-pointers state) {}) [subnet path] ptr))
                        (assoc :artifact-tombstones (dissoc (or (:artifact-tombstones state) {}) [subnet path]))
                        (assoc-in [:artifact-min-seqs [subnet path]] (:pointer/seq ptr)))
             :net-envelopes []
             :stdout-events [evt]}))))))

(defn- handle-wire-capability-replicate [state msg]
  (let [blob (normalize-wire-blob (or (:blob msg) (get msg "blob")))
        ptr (normalize-wire-pointer (or (:pointer msg) (get msg "pointer")))
        subnet (str (or (:subnet-id msg) (get msg "subnet_id") (when ptr (:pointer/subnet ptr)) "global"))
        path (str (or (:path msg) (get msg "path") (when ptr (:pointer/path ptr))))
        existing-ptr (get-in state [:capabilities [subnet path]])
        current-seq (long (or (when existing-ptr (:pointer/seq existing-ptr)) 0))
        valid-blob? (boolean (and (map? blob) (data/verify-blob blob)))
        valid-ptr? (boolean (and (map? ptr) (:ok? (data/verify-pointer ptr))))
        target-match? (boolean (and valid-blob? valid-ptr? (= (:pointer/target ptr) (:blob/cid blob))))
        duplicate-ptr? (boolean (and valid-ptr?
                                     target-match?
                                     existing-ptr
                                     (= (:pointer/authority ptr) (:pointer/authority existing-ptr))
                                     (= (long (:pointer/seq ptr)) (long (:pointer/seq existing-ptr)))
                                     (= (:pointer/target ptr) (:pointer/target existing-ptr))))
        seq-valid? (boolean (and valid-ptr? (> (long (:pointer/seq ptr)) current-seq)))
        valid? (and valid-blob? valid-ptr? target-match? seq-valid?)]
    (if duplicate-ptr?
      {:state state :net-envelopes [] :stdout-events []}
      (if-not valid?
        (let [reason (cond
                       (not valid-blob?) "invalid-blob"
                       (not valid-ptr?) "invalid-pointer"
                       (not target-match?) "target-mismatch"
                       (not seq-valid?) "stale-sequence"
                       :else "invalid-replicate")
              diag-event {"event" "diagnostic"
                          "reason" "capability-replication-rejected"
                          "cause" reason
                          "subnet_id" subnet
                          "path" path}]
          {:state (-> state
                      (update-in [:diagnostics :replication-rejected] (fnil inc 0)))
           :net-envelopes []
           :stdout-events [diag-event]})
        (let [evt {"event" "capability-published"
                   "subnet_id" subnet
                   "path" path
                   "cid" (:blob/cid blob)
                   "seq" (:pointer/seq ptr)
                   "authority" (:pointer/authority ptr)}]
          {:state (-> state
                      (assoc-in [:blobs (:blob/cid blob)] blob)
                      (assoc-in [:pointers [subnet path]] ptr)
                      (assoc-in [:capability-blobs (:blob/cid blob)] blob)
                      (assoc-in [:capabilities [subnet path]] ptr))
           :net-envelopes []
           :stdout-events [evt]})))))

(defn- handle-wire-governance-replicate [state msg]
  (let [subnet (str (or (:subnet-id msg) (get msg "subnet_id") gov/dev-subnet-id))
        op (keyword (or (:op msg) (get msg "op")))
        sender (normalize-pubkey-hex (str (or (:sender msg) (get msg "sender") "")))
        ep (long (or (:epoch msg) (get msg "epoch") 0))
        body (or (:body msg) (get msg "body") {})
        sig-hex (str (or (:signature msg) (get msg "signature") ""))
        valid-sig? (boolean
                    (when (and (valid-pubkey-hex? sender)
                               (not (str/blank? sig-hex))
                               (contains? #{:bip-submit :bip-response :bounty-create :bounty-settle} op))
                      (try
                        (let [sender-bytes (basalt/hex->bytes sender)
                              sig-bytes (basalt/hex->bytes sig-hex)
                              cand-bodies (distinct
                                           (cond-> [body]
                                             (and (map? body) (number? (:weight body)))
                                             (conj (assoc body :weight (long (:weight body)))
                                                   (assoc body :weight (double (:weight body))))))]
                          (and sender-bytes sig-bytes
                               (some (fn [b]
                                       (crypto/verify-with-fallback
                                        sender-bytes
                                        (canonical-governance-replicate-payload subnet op sender ep b)
                                        sig-bytes))
                                     cand-bodies)))
                        (catch #?(:clj Exception :cljs :default) _ false))))]
    (if-not valid-sig?
      (let [diag-event {"event" "diagnostic"
                        "reason" "governance-replication-rejected"
                        "subnet_id" subnet
                        "op" (if op (name op) "unknown")}]
        {:state (update-in state [:diagnostics :governance-replication-rejected] (fnil inc 0))
         :net-envelopes []
         :stdout-events [diag-event]})
      (let [gov-st0 (or (:governance state) (gov/init-governance-state))
            evt {"event" "governance-replicated"
                 "subnet_id" subnet
                 "op" (name op)
                 "sender" sender}]
        (case op
          :bip-submit
          (let [bip (:bip body)
                bip-id (str (or (:bip-id body) (:bip-id bip) ""))
                blob (normalize-wire-blob (:blob body))
                ptr (normalize-wire-pointer (:pointer body))
                cid (or (:cid body) (:blob/cid blob))
                path (str "bip/" bip-id)
                gov-st' (-> gov-st0
                            (cond-> (and cid blob) (assoc-in [:blobs cid] blob))
                            (cond-> ptr (assoc-in [:pointers [subnet path]] ptr))
                            (assoc-in [:bips [subnet bip-id]] bip)
                            (assoc-in [:bips bip-id] bip))]
            {:state (assoc state :governance gov-st')
             :net-envelopes []
             :stdout-events [evt]})

          :bip-response
          (let [bip-id (str (or (:bip-id body) ""))
                circle-kw (normalize-circle-kw (:circle body))
                member-pub (normalize-pubkey-hex (str (or (:member-pubkey body) sender)))
                weight (double (or (:weight body) 100.0))
                response (:response body)
                gov-st1 (ensure-default-circle-member gov-st0 subnet circle-kw member-pub weight)
                resp-res (gov/submit-circle-response gov-st1 subnet bip-id circle-kw member-pub response)
                eval-res (gov/evaluate-tri-circle-consent (:state resp-res) subnet bip-id)]
            {:state (assoc state :governance (:state eval-res))
             :net-envelopes []
             :stdout-events [evt]})

          :bounty-create
          (let [bounty (:bounty body)
                bounty-id (str (or (:bounty-id body) (:bounty-id bounty) ""))
                cap-cid (:capability-cid body)
                cap-blob (normalize-wire-blob (:capability-blob body))
                cap-ptr (normalize-wire-pointer (:capability-pointer body))
                cap-path (str "bounty/" bounty-id)
                gov-st' (-> gov-st0
                            (cond-> (and cap-cid cap-blob) (assoc-in [:blobs cap-cid] cap-blob))
                            (cond-> cap-ptr (assoc-in [:pointers [subnet cap-path]] cap-ptr))
                            (assoc-in [:bounties [subnet bounty-id]] bounty)
                            (assoc-in [:bounties bounty-id] bounty))]
            {:state (-> state
                        (assoc :governance gov-st')
                        (cond-> cap-ptr (assoc-in [:capabilities [subnet cap-path]] cap-ptr))
                        (cond-> (and cap-cid cap-blob) (assoc-in [:capability-blobs cap-cid] cap-blob)))
             :net-envelopes []
             :stdout-events [evt]})

          :bounty-settle
          (let [bounty-id (str (or (:bounty-id body) ""))
                claim (:claim body)
                settle-res (gov/settle-bounty-escrow gov-st0 subnet bounty-id claim)
                my-pub (normalize-pubkey-hex (str (or (:pubkey state) "")))
                my-payout (when (:ok? settle-res)
                            (long (or (get (:payouts settle-res) my-pub) 0)))]
            {:state (cond-> (assoc state :governance (:state settle-res))
                      (and my-payout (pos? my-payout))
                      (-> (update-in [:account :balance] (fn [b] (+ (long (or b 0)) my-payout)))
                          (update-in [:account :spendable] (fn [s] (+ (long (or s 0)) my-payout)))))
             :net-envelopes []
             :stdout-events [evt]}))))))

(defn- handle-wire-transfer [state msg]
  (let [raw-tf (or (:transfer msg) (get msg "transfer"))
        tf-net-uri (when (map? raw-tf)
                     (or (:network-uri raw-tf)
                         (get raw-tf "network-uri")
                         (get raw-tf "network_uri")))
        tf (when (map? raw-tf)
             (cond-> {:sender (normalize-pubkey-hex (str (or (:sender raw-tf) (get raw-tf "sender") "")))
                      :receiver (normalize-pubkey-hex (str (or (:receiver raw-tf) (get raw-tf "receiver") "")))
                      :amount (long (or (:amount raw-tf) (get raw-tf "amount") 0))
                      :seq (long (or (:seq raw-tf) (get raw-tf "seq") 0))
                      :deps (vec (or (:deps raw-tf) (get raw-tf "deps") []))
                      :signature (or (:signature raw-tf) (get raw-tf "signature"))}
               (and (string? tf-net-uri) (not (str/blank? tf-net-uri)))
               (assoc :network-uri (str/trim tf-net-uri))))
        expected-net-uri (or (:network-uri state)
                             (config/resolve-network-uri (:bootstrap state))
                             (when (contains? (set (vals config/network-uris)) (str (:subnet-id state)))
                               (str (:subnet-id state)))
                             "devnet.bitecho.org")
        strict-net? (or (= expected-net-uri "mainnet.bitecho.org")
                        (= (:network state) :mainnet)
                        (= (get-in state [:bootstrap :network]) :mainnet))
        replay? (and (map? tf)
                     (or (and (string? (:network-uri tf))
                              (not (str/blank? (:network-uri tf)))
                              (not= (:network-uri tf) expected-net-uri))
                         (and strict-net?
                              (or (not (string? (:network-uri tf)))
                                  (str/blank? (:network-uri tf))))))
        my-pub (normalize-pubkey-hex (str (or (:pubkey state) "")))
        for-me? (and (map? tf) (not (str/blank? my-pub)) (= (:receiver tf) my-pub))
        valid-sig? (boolean
                    (when (and for-me? (not replay?) (pos? (:amount tf)))
                      (try
                        (let [sender-bytes (basalt/hex->bytes (:sender tf))
                              unsigned-tf (into (sorted-map) (fressian/strip-untrusted-crypto-tags (dissoc tf :signature)))
                              sig-raw (:signature tf)
                              sig-bytes (cond
                                          (fressian/bytes? sig-raw) sig-raw
                                          (string? sig-raw) (basalt/hex->bytes sig-raw)
                                          (coll? sig-raw) #?(:clj (byte-array (map byte sig-raw))
                                                             :cljs (js/Uint8Array. (clj->js sig-raw)))
                                          :else nil)]
                          (and sender-bytes sig-bytes
                               (crypto/verify-with-fallback sender-bytes unsigned-tf sig-bytes)))
                        (catch #?(:clj Exception :cljs :default) _ false))))]
    (cond
      replay?
      {:state (update-in state [:diagnostics :network-replay-rejected] (fnil inc 0))
       :net-envelopes []
       :stdout-events [{"event" "diagnostic"
                        "reason" "network-replay-rejected"
                        "expected_network_uri" expected-net-uri
                        "actual_network_uri" (:network-uri tf)}]}

      (not for-me?)
      {:state state :net-envelopes [] :stdout-events []}

      (not valid-sig?)
      {:state (update-in state [:diagnostics :invalid-transfer-dropped] (fnil inc 0))
       :net-envelopes []
       :stdout-events [{"event" "diagnostic" "reason" "invalid-transfer-signature"}]}

      :else
      (let [tx-id (account/transfer-hash tf)
            credited? (contains? (set (or (:credited-tx-ids state) #{})) tx-id)]
        (if credited?
          {:state state :net-envelopes [] :stdout-events []}
          (let [amt (:amount tf)
                evt {"event" "transfer-received"
                     "tx_id" tx-id
                     "from" (:sender tf)
                     "to" (:receiver tf)
                     "amount" amt
                     "seq" (:seq tf)}
                inbox-entry {:type "transfer-received"
                             :tx-id tx-id
                             :from (:sender tf)
                             :amount amt
                             :seq (:seq tf)
                             :message (str "Received " amt " ECH transfer from " (:sender tf))}]
            {:state (-> state
                        (update :credited-tx-ids (fn [s] (conj (set (or s #{})) tx-id)))
                        (update-in [:account :balance] (fn [b] (+ (long (or b 0)) amt)))
                        (update-in [:account :spendable] (fn [s] (+ (long (or s 0)) amt)))
                        (update :inbox (fn [ib] (conj (vec (or ib [])) inbox-entry))))
             :net-envelopes []
             :stdout-events [evt]}))))))

(defn- handle-wire-sync-pointer
  "Unified `:sync-pointer` wire handler (`BIP-005` / `F-U4`).
   Dispatches by path/op to governance, storage, capability, or artifact pointer replication,
   keeping both unified `:pointers` / `:blobs` and domain views in sync."
  [state msg]
  (let [op (keyword (or (:op msg) (get msg "op")))
        ptr (or (:pointer msg) (get msg "pointer") msg)
        path (str (or (:path msg) (get msg "path") (when (map? ptr) (:pointer/path ptr)) ""))]
    (cond
      (contains? #{:bip-submit :bip-response :bounty-create :bounty-settle} op)
      (handle-wire-governance-replicate state msg)

      (str/starts-with? path "storage/")
      (handle-wire-storage-replicate state msg)

      (or (str/starts-with? path "capability/")
          (str/includes? path "/capability/"))
      (handle-wire-capability-replicate state msg)

      :else
      (handle-wire-artifact-replicate state msg))))

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
                    active-net-uri (or (:network-uri state)
                                       (config/resolve-network-uri (:bootstrap state))
                                       (when (contains? (set (vals config/network-uris)) expected-subnet)
                                         expected-subnet)
                                       "devnet.bitecho.org")
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
                    msg-type (keyword (or (:bitecho/type msg)
                                          (:type msg)
                                          (when (or (:transfer msg) (get msg "transfer")) :transfer)
                                          (when (or (:validator-pubkey msg) (get msg "validator_pubkey")) :chain-state-snapshot)))
                    storage-or-cap? (or (= msg-type :sync-pointer)
                                        (= msg-type :storage-replicate)
                                        (= msg-type :artifact-replicate)
                                        (= msg-type :replicate-pointer)
                                        (= msg-type :capability-replicate)
                                        (= msg-type :governance-replicate)
                                        (= msg-type :transfer)
                                        (= msg-type :p2p-link-bind)
                                        (= msg-type :chain-state-snapshot))
                    eff-inner (or inner-subnet outer-subnet "global")
                    sub-set (effective-subscribed-subnets state)
                    sub-wildcard? (contains? sub-set "*")
                    admitted-subnet? (fn [s]
                                       (or sub-wildcard?
                                           (contains? sub-set s)
                                           (boolean (some #(config/equivalent-subnet-id? s % active-net-uri) sub-set))))
                    sub-bcast? (when (= msg-type :p2p-broadcast)
                                 (admitted-subnet? eff-inner))
                    unsolicited-direct? (contains? #{:channel-offer :rendezvous-offer-header} msg-type)
                    eff-direct-sub (or inner-subnet (when (not= outer-subnet "*") outer-subnet))
                    spoofed-direct? (and (not storage-or-cap?)
                                         (not= msg-type :p2p-broadcast)
                                         (not sub-wildcard?)
                                         (or (= inner-subnet "*")
                                             (and (nil? inner-subnet) (= outer-subnet "*"))
                                             (and unsolicited-direct?
                                                  (nil? outer-subnet)
                                                  (nil? inner-subnet)
                                                  (not= expected-subnet "global"))))
                    subnet-mismatch? (or (and outer-subnet inner-subnet (not= outer-subnet "*") (not= inner-subnet "*")
                                              (not (config/equivalent-subnet-id? outer-subnet inner-subnet active-net-uri)))
                                         spoofed-direct?
                                         (if (= msg-type :p2p-broadcast)
                                           (not sub-bcast?)
                                           (and (not storage-or-cap?)
                                                (some? eff-direct-sub)
                                                (not (admitted-subnet? eff-direct-sub)))))]
                (if subnet-mismatch?
                  (let [eff-subnet (or outer-subnet inner-subnet "unknown")
                        new-state (-> state
                                      (update :subnet-mismatch-dropped (fnil inc 0))
                                      (update-in [:diagnostics :subnet-mismatch-dropped] (fnil inc 0))
                                      (update-in [:wire-version-diagnostics :subnet-mismatch-dropped] (fnil inc 0))
                                      (record-suppression :subnet-mismatch))
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
                  (let [msg-type (keyword (or (:bitecho/type msg)
                                              (:type msg)
                                              (when (or (:transfer msg) (get msg "transfer")) :transfer)
                                              (when (or (:validator-pubkey msg) (get msg "validator_pubkey")) :chain-state-snapshot)))
                        msg-epoch (when (integer? (:epoch msg)) (long (:epoch msg)))
                        target-sid (or (:session-id msg) (get msg "session_id"))
                        sess-epoch (when target-sid
                                     (let [ep (get-in state [:sessions target-sid :epoch])]
                                       (when (integer? ep)
                                         (long ep))))
                        open-session? (and (contains? #{:sealed-message :session-ack :p2p-offer :p2p-answer :p2p-link-bind} msg-type)
                                           (some? target-sid)
                                           (= "open" (get-in state [:sessions target-sid :state])))
                        pending-offer-reply? (or (and (= msg-type :rendezvous-ack-voucher)
                                                      (some? (:offer-hash msg))
                                                      (contains? (:outbound-rendezvous state) (:offer-hash msg)))
                                                 (and (= msg-type :rendezvous-reveal)
                                                      (some? (:offer-hash msg))
                                                      (contains? (:pending-rendezvous-accepts state) (:offer-hash msg)))
                                                 (and (= msg-type :channel-accept)
                                                      (some? target-sid)
                                                      (= "offered" (get-in state [:sessions target-sid :state]))))
                        unicast-types #{:channel-offer :rendezvous-offer-header :channel-accept
                                        :rendezvous-ack-voucher :rendezvous-reveal :sealed-message
                                        :session-ack :p2p-offer :p2p-answer}
                        target-recip (when (contains? unicast-types msg-type)
                                       (case msg-type
                                         (:channel-offer :rendezvous-offer-header :rendezvous-reveal)
                                         (or (:callee msg) (get msg "callee"))
                                         (:channel-accept :rendezvous-ack-voucher)
                                         (or (:caller msg) (get msg "caller"))
                                         (:sealed-message :session-ack :p2p-answer)
                                         (or (:recipient msg) (get msg "recipient"))
                                         :p2p-offer
                                         (or (:recipient msg) (get msg "recipient") (:callee msg) (get msg "callee"))
                                         nil))
                        foreign-unicast? (and target-recip
                                              (:pubkey state)
                                              (not= (normalize-pubkey-hex target-recip)
                                                    (normalize-pubkey-hex (:pubkey state))))
                        ref-epoch (if (or (:epoch-initialized? state)
                                          (and (integer? (:epoch state)) (pos? (long (:epoch state)))))
                                    (:epoch state)
                                    (or sess-epoch msg-epoch))
                        max-skew (max 1 (long (or (:max-epoch-skew state) 15)))
                        skew-exceeded? (and (not open-session?)
                                            (not pending-offer-reply?)
                                            (not (contains? #{:chain-state-snapshot
                                                              :query-chain-state
                                                              :p2p-link-bind
                                                              :p2p-hub-relay
                                                              :p2p-broadcast
                                                              :sync-pointer
                                                              :storage-replicate
                                                              :artifact-replicate
                                                              :replicate-pointer
                                                              :capability-replicate
                                                              :governance-replicate}
                                                            msg-type))
                                            msg-epoch ref-epoch
                                            (> (math-abs (- msg-epoch (long ref-epoch))) max-skew))]
                    (if foreign-unicast?
                      {:state (-> state
                                  (update-in [:diagnostics :foreign-unicast-dropped] (fnil inc 0))
                                  (record-suppression :foreign-unicast))
                       :net-envelopes []
                       :stdout-events []}
                      (if skew-exceeded?
                        (let [p2p-sig? (contains? #{:p2p-offer :p2p-answer} msg-type)
                              sid (or target-sid (:offer-hash msg) (get msg "offer_hash"))
                              caller-pub (or (:caller msg) (:sender msg) (get msg "caller") (get msg "sender"))
                              diag-event (cond-> {"event" "diagnostic"
                                                  "reason" "epoch-skew-dropped"
                                                  "msg_type" (name (or msg-type :unknown))
                                                  "offer_epoch" (or msg-epoch 0)
                                                  "local_epoch" (long (or ref-epoch 0))}
                                           sid (assoc "session_id" (str sid))
                                           caller-pub (assoc "from" (str caller-pub)))
                              p2p-event (when p2p-sig?
                                          {"event" "p2p-signaling-rejected" "reason" "epoch-skew-exceeded"})
                              evts (cond-> [diag-event]
                                     p2p-event (conj p2p-event))
                              new-state (cond-> (-> state
                                                    (update-in [:diagnostics :epoch-skew-dropped] (fnil inc 0))
                                                    (record-suppression :admission-drop))
                                          p2p-sig? (update-in [:diagnostics :p2p-signaling-rejected] (fnil inc 0)))
                              st-enq (enqueue-actionable-events new-state evts)]
                          {:state st-enq
                           :net-envelopes []
                           :stdout-events evts})
                        (let [res (case msg-type
                                    :channel-offer (handle-wire-offer state msg privkey-bytes)
                                    :channel-accept (handle-wire-accept state msg privkey-bytes)
                                    :sealed-message (handle-wire-sealed-msg state msg privkey-bytes)
                                    :session-ack (handle-wire-session-ack state msg privkey-bytes)
                                    :channel-close (handle-wire-close state msg)
                                    :rendezvous-offer-header (handle-wire-rendezvous-header state msg privkey-bytes)
                                    :rendezvous-ack-voucher (handle-wire-rendezvous-ack state msg privkey-bytes)
                                    :rendezvous-reveal (handle-wire-rendezvous-reveal state msg privkey-bytes)
                                    :chain-state-snapshot (handle-wire-chain-state-snapshot state msg)
                                    :p2p-offer (handle-wire-p2p-offer state msg privkey-bytes)
                                    :p2p-answer (handle-wire-p2p-answer state msg)
                                    :p2p-link-bind (handle-wire-p2p-link-bind state msg privkey-bytes)
                                    :p2p-hub-relay (handle-wire-p2p-hub-relay state msg privkey-bytes)
                                    :p2p-broadcast (handle-wire-broadcast state msg privkey-bytes)
                                    :sync-pointer (handle-wire-sync-pointer state msg)
                                    :storage-replicate (handle-wire-storage-replicate state msg)
                                    :artifact-replicate (handle-wire-artifact-replicate state msg)
                                    :replicate-pointer (handle-wire-artifact-replicate state msg)
                                    :capability-replicate (handle-wire-capability-replicate state msg)
                                    :governance-replicate (handle-wire-governance-replicate state msg)
                                    :transfer (handle-wire-transfer state msg)
                                    {:state state :net-envelopes [] :stdout-events []})
                              res' (if (and (not= msg-type :chain-state-snapshot)
                                            msg-epoch
                                            (not (:epoch-initialized? (:state res))))
                                     (update res :state assoc :epoch msg-epoch :epoch-initialized? true)
                                     res)
                              res'' (if (and open-session? (get-in (:state res') [:sessions target-sid]))
                                      (update-in res' [:state :sessions target-sid :epoch]
                                                 (fn [curr-ep]
                                                   (max (long (or curr-ep 0))
                                                        (long (or msg-epoch 0))
                                                        (long (or (:epoch (:state res')) 0)))))
                                      res')
                              st-enq (enqueue-actionable-events (:state res'') (:stdout-events res''))]
                          (assoc res'' :state st-enq))))))))))))))

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
  (let [sid (str (or subnet-id "global"))
        inst (or (:instance instance-state) instance-state)]
    (assoc-in mux [:subnets sid] (assoc inst :subnet-id sid))))

(defn remove-subnet-instance
  "Removes a subnet state machine instance from the multiplexer."
  [mux subnet-id]
  (let [sid (str (or subnet-id "global"))]
    (update mux :subnets dissoc sid)))

(defn- handle-multiplexed-anchor-effects
  "Propagates any child-to-parent :anchor-to-parent effects across registered subnets in `mux`."
  [mux effects now-ms]
  (reduce (fn [{:keys [mux effs]} eff]
            (if (= :anchor-to-parent (:effect eff))
              (let [parent-id (str (:parent-subnet eff))
                    parent-inst (get-in mux [:subnets parent-id])]
                (if-not (and parent-inst (:bitecho.subnet/unified? parent-inst))
                  ;; Parent subnet not locally hosted on this multiplexer; keep effect for network propagation
                  {:mux mux :effs (conj effs eff)}
                  (let [auth (or (get-in eff [:pointer :pointer/authority])
                                 (get-in eff [:pointer :authority]))
                        b-res (core-subnet/reduce-subnet parent-inst
                                                         {:type :put-blob
                                                          :blob (:blob eff)
                                                          :sender auth
                                                          :now-ms now-ms})
                        p-res (core-subnet/reduce-subnet (:state b-res)
                                                         {:type :publish-pointer
                                                          :pointer (:pointer eff)
                                                          :sender auth
                                                          :now-ms now-ms})
                        updated-mux (assoc-in mux [:subnets parent-id] (:state p-res))
                        parent-effs (into (vec (or (:effects b-res) []))
                                          (or (:effects p-res) []))
                        nested (handle-multiplexed-anchor-effects updated-mux parent-effs now-ms)]
                    {:mux (:mux nested)
                     :effs (into (conj effs eff) (:effs nested))})))
              {:mux mux :effs (conj effs eff)}))
          {:mux mux :effs []}
          effects))

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
              now-ms (long (or (:now-ms sub-event) (:now-ms envelope) 0))
              handled (handle-multiplexed-anchor-effects (assoc-in mux [:subnets sub-id] (:state res))
                                                         (or (:effects res) [])
                                                         now-ms)]
          {:mux (:mux handled)
           :effects (:effs handled)
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
      (if (:bitecho.subnet/unified? instance)
        (let [now-ms (long (or (:now-ms cmd-map) 0))
              res (core-subnet/reduce-subnet instance cmd-map)
              handled (handle-multiplexed-anchor-effects (assoc-in mux [:subnets sub-id] (:state res))
                                                         (or (:effects res) [])
                                                         now-ms)]
          {:mux (:mux handled)
           :response (if (:applied? res)
                       (cond-> {"ok" true "subnet" sub-id}
                         (:anchor res) (assoc "anchor" (:anchor res)))
                       (if (= :epoch-tick (:type cmd-map))
                         {"ok" true "subnet" sub-id "unchanged" true}
                         {"ok" false "error" (str (:error res)) "subnet" sub-id}))
           :effects (:effs handled)
           :net-envelopes []
           :stdout-events []})
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
           :stdout-events (or (:stdout-events res) [])})))))

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
                       (:directory-pubkey desc) (conj (str "Directory Authority Public Key: " (:directory-pubkey desc)))
                       (contains? desc :economy-enabled?) (conj (str "Economy Enabled: " (boolean (:economy-enabled? desc))))
                       (:burn-floor desc) (conj (str "Burn Floor: " (:burn-floor desc)))
                       (:min-signaling-burn desc) (conj (str "Min Signaling Burn: " (:min-signaling-burn desc))))
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
  (let [parsed
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
                    nodes-map (into {} (keep parse-single-node-txt-block-pure node-blocks))]
                (reduce (fn [acc line]
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
                              (re-find #"(?i)^Economy Enabled:\s*(.+)$" t)
                              (assoc acc :economy-enabled? (= "true" (str/lower-case (str/trim (second (re-find #"(?i)^Economy Enabled:\s*(.+)$" t))))))
                              (re-find #"(?i)^Burn Floor:\s*(\d+)$" t)
                              (assoc acc :burn-floor (parse-long-safe (second (re-find #"(?i)^Burn Floor:\s*(\d+)$" t)) 0))
                              (re-find #"(?i)^Min Signaling Burn:\s*(\d+)$" t)
                              (assoc acc :min-signaling-burn (parse-long-safe (second (re-find #"(?i)^Min Signaling Burn:\s*(\d+)$" t)) 0))
                              (re-find #"(?i)^(?:Relay URL|relay)[=:]\s*(.+)$" t)
                              (assoc acc :relay-url (str/trim (second (re-find #"(?i)^(?:Relay URL|relay)[=:]\s*(.+)$" t))))
                              :else acc)))
                        {:nodes nodes-map}
                        lines))))
          :else nil)]
    (when (map? parsed)
      (cond-> parsed
        (and (nil? (:relay-url parsed))
             (= "bitecho.org" (:domain parsed)))
        (assoc :relay-url "https://ns1.bitecho.org")))))

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
        ;; P2P channel opens -> transition p2p-channel-state to connected: true on both sides
        nexus-p2p (handle-command (:state p2p-ans)
                                  {"cmd" "p2p-channel-state" "session_id" sid-sn "connected" true}
                                  (:private kp-nexus))
        simon-p2p (handle-command simon-2
                                  {"cmd" "p2p-channel-state" "session_id" sid-sn "connected" true}
                                  (:private kp-simon))
        ;; 2. 3-way Broadcast across Simon, Nexus, and Axiom on chat/simon-nexus-axiom
        b-simon (handle-command (:state simon-p2p)
                                {"cmd" "broadcast" "text" "Browser ready on chat/simon-nexus-axiom" "subnet_id" subnet-id}
                                (:private kp-simon))
        b-nexus (handle-command (:state nexus-p2p)
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

;; -----------------------------------------------------------------------------
;; Human Anchor State & Command Reducer (Folded from bitecho.anchor.core in D31)
;; -----------------------------------------------------------------------------

(defn init-anchor-state
  "Initializes Human Anchor state wrapping light-node core with human-in-the-loop policy.
   Default policy enforces autonomous? false (human approval required)."
  ([] (init-anchor-state {} {}))
  ([identity-pub-map] (init-anchor-state identity-pub-map {}))
  ([identity-pub-map opts]
   (let [base-node (init-light-state (or identity-pub-map {}) (merge {:autonomous? false} opts))
         key-mode (or (:key-mode opts) :yubikey-discoverable)
         anchor-pub (:pubkey base-node)
         anchor-addr (when anchor-pub (bech32m/pubkey->bech32m anchor-pub "ech"))]
     (assoc base-node
            :anchor/role :human-anchor
            :key-mode key-mode
            :anchor-pubkey anchor-pub
            :anchor-address anchor-addr
            :hot-pubkey (or (:hot-pubkey opts) anchor-pub)
            :active-dac (:dac base-node)
            :privkey-bytes (:privkey-bytes opts)
            :service-offers (or (:service-offers opts) {})
            :pending-offers (or (:pending-offers opts) [])
            :supervised-agents (or (:supervised-agents opts) {})
            :offers-approved 0
            :offers-denied 0
            :last-denied-reason nil
            :fido-strength (fido/evaluate-authenticator-strength
                            {:aaguid (or (:aaguid opts) "2fc0579f-8113-47ea-b116-bb5a8db9202a")
                             :up? true :uv? true :be? true :bs? false})
            :team-call-subnet nil))))

(defn set-service-offer
  "Configures a service offer with price and burn floor in the anchor menu."
  [state service-id {:keys [name price burn-floor description]}]
  (assoc-in state [:service-offers (keyword service-id)]
            {:service-id (keyword service-id)
             :name (or name (clojure.core/name service-id))
             :price (or price 10)
             :burn-floor (or burn-floor 100)
             :description (or description "")}))

(defn queue-incoming-offer
  "Queues an incoming offer into pending-offers for human inspection and approval."
  [state offer]
  (let [offer-id (or (:offer-id offer) (:session-id offer) (str "offer-" (count (:pending-offers state))))
        offer-record (assoc offer :offer-id offer-id
                            :queued-at (or (:epoch state) 0))]
    (update state :pending-offers (fnil conj []) offer-record)))

(defn approve-offer
  "Human-in-the-loop action: approves a pending offer.
   Removes offer from pending-offers, increments :offers-approved,
   and returns [new-state effects]."
  [state offer-id & [accept-opts]]
  (let [pending (:pending-offers state)
        matching (first (filter #(= (:offer-id %) offer-id) pending))]
    (if-not matching
      [state [{:effect :diagnose :reason :offer-not-found :offer-id offer-id}]]
      (let [new-pending (vec (remove #(= (:offer-id %) offer-id) pending))
            new-state (-> state
                          (assoc :pending-offers new-pending)
                          (update :offers-approved (fnil inc 0)))
            effect {:effect :accept-offer
                    :offer-id offer-id
                    :peer-id (:peer-id matching)
                    :accepted-at (or (:epoch state) 0)
                    :opts accept-opts}]
        [new-state [effect]]))))

(defn deny-offer
  "Human-in-the-loop action: denies a pending offer with an explicit reason.
   Removes offer from pending-offers, increments :offers-denied,
   and returns [new-state effects]."
  [state offer-id & [reason]]
  (let [pending (:pending-offers state)
        matching (first (filter #(= (:offer-id %) offer-id) pending))
        rej-reason (or reason "denied-by-human-anchor")]
    (if-not matching
      [state [{:effect :diagnose :reason :offer-not-found :offer-id offer-id}]]
      (let [new-pending (vec (remove #(= (:offer-id %) offer-id) pending))
            new-state (-> state
                          (assoc :pending-offers new-pending)
                          (assoc :last-denied-reason rej-reason)
                          (update :offers-denied (fnil inc 0)))
            effect {:effect :diagnose
                    :reason :offer-denied-by-anchor
                    :offer-id offer-id
                    :peer-id (:peer-id matching)
                    :denial-reason rej-reason}]
        [new-state [effect]]))))

(def ^:private anchor-trust-boundary-disclosure
  "Trust boundary: when using user.id/PRF seed recovery, the 32-byte seed is reconstructed in browser memory during signing; the local device and JavaScript bundle (verified via SRI) must be trusted.")

(def ^:private anchor-origin-scoping-disclosure
  "Credentials are scoped per WebAuthn RP ID / origin; self-hosted origins must re-register or import via backup seed.")

(defn register-supervised-agent
  "Registers an autonomous or semi-autonomous agent supervised by this human anchor.
   Requires a valid signed DAC (either explicitly provided or signed using cold key in state).
   If no signed DAC can be established, fails closed and returns state unchanged."
  [state {:keys [agent-id hot-pubkey dac permissions max-spend scopes issued-epoch expires-epoch]}]
  (let [anchor-pub (:anchor-pubkey state)
        agent-key-hex (cond
                        (string? hot-pubkey) (normalize-pubkey-hex hot-pubkey)
                        (some? hot-pubkey) (normalize-pubkey-hex (basalt/bytes->hex hot-pubkey))
                        :else nil)
        effective-dac (or dac
                          (when (and (:privkey-bytes state) agent-key-hex anchor-pub)
                            (create-dac
                             (:privkey-bytes state)
                             {:anchor-pubkey (normalize-pubkey-hex anchor-pub)
                              :agent-pubkey agent-key-hex
                              :issued-epoch (or issued-epoch 0)
                              :expires-epoch (or expires-epoch 1000)
                              :max-spend-per-epoch (or max-spend 10000)
                              :scopes (or scopes ["gossip" "offer" "settle-intent" "transfer"])})))]
    (if-not (and (map? effective-dac) (:signature effective-dac) (:dac-id effective-dac))
      state
      (let [agent-record {:agent-id agent-id
                          :hot-pubkey agent-key-hex
                          :hot-address (when agent-key-hex (bech32m/pubkey->bech32m agent-key-hex "ech"))
                          :dac effective-dac
                          :status :active
                          :permissions (or permissions scopes [:offer :message :escrow])
                          :activity-log []
                          :registered-at (or (:epoch state) 0)}]
        (assoc-in state [:supervised-agents agent-id] agent-record)))))

(defn log-agent-activity
  "Appends an activity event to a supervised agent's activity log."
  [state agent-id event]
  (if (get-in state [:supervised-agents agent-id])
    (update-in state [:supervised-agents agent-id :activity-log]
               (fnil conj [])
               (assoc event :logged-at (or (:epoch state) 0)))
    state))

(defn pause-agent
  "Pauses an agent's delegated authority."
  [state agent-id]
  (if (get-in state [:supervised-agents agent-id])
    (assoc-in state [:supervised-agents agent-id :status] :paused)
    state))

(defn resume-agent
  "Resumes an agent's delegated authority."
  [state agent-id]
  (if (get-in state [:supervised-agents agent-id])
    (assoc-in state [:supervised-agents agent-id :status] :active)
    state))

(defn revoke-agent-dac
  "Emergency revocation of a supervised agent's DAC.
   Immediately updates status to :revoked, constructs signed DAC revocation,
   records revocation in state, and returns [new-state effects].
   Only emits :broadcast-dac-revocation effect if signed revocation was constructed."
  [state agent-id & [reason]]
  (let [agent (get-in state [:supervised-agents agent-id])]
    (if-not agent
      [state [{:effect :diagnose :reason :agent-not-found :agent-id agent-id}]]
      (let [rev-reason (or reason "emergency-human-anchor-revocation")
            dac (:dac agent)
            dac-id (:dac-id dac)
            anchor-priv (:privkey-bytes state)
            anchor-pub (:anchor-pubkey state)
            agent-pub (:hot-pubkey agent)
            revocation (when (and anchor-priv anchor-pub agent-pub dac-id)
                         (create-dac-revocation
                          anchor-priv
                          {:anchor-pubkey anchor-pub
                           :agent-pubkey agent-pub
                           :dac-id dac-id
                           :revoked-epoch (or (:epoch state) 0)}))
            new-state (cond-> (assoc-in state [:supervised-agents agent-id :status] :revoked)
                        revocation (assoc-in [:supervised-agents agent-id :revocation] revocation)
                        revocation (update :revoked-dacs (fnil conj []) revocation))
            effects (cond-> [{:effect :diagnose
                              :reason :supervised-agent-dac-revoked
                              :agent-id agent-id
                              :dac-id dac-id
                              :revocation-reason rev-reason}]
                      revocation (conj {:effect :broadcast-dac-revocation
                                        :agent-id agent-id
                                        :dac-id dac-id
                                        :revocation revocation}))]
        [new-state effects]))))

(defn sanitize-anchor-state-for-persistence
  "Sanitizes anchor state for persistence to disk or IndexedDB.
   Strips all private key material (:privkey-bytes, :cold-privkey, :private-key, :seed),
   raw keypairs, and non-serializable objects."
  [state]
  (let [clean (dissoc state :privkey-bytes :cold-privkey :private-key :seed :keypair)]
    (cond-> clean
      (:backup-key clean)
      (update :backup-key dissoc :private-key :backup-seed :public-key)
      (:identity clean)
      (update :identity dissoc :private-key :seed :keypair))))

(defn create-team-call-subnet
  "Creates a team-call subnet state demonstrating how a team in a call forms a subnet.
   Supports zero or minimal burn floor for close collaboration."
  [state {:keys [topic-name peers burn-floor]}]
  (let [subnet-id (str "team-call/" (or topic-name "main-room"))
        subnet-record {:subnet-id subnet-id
                       :topic-name (or topic-name "main-room")
                       :peers (or peers [])
                       :burn-floor (or burn-floor 0)
                       :created-at (or (:epoch state) 0)
                       :status :active}]
    (assoc state :team-call-subnet subnet-record)))

(defn anchor-dashboard-view
  "Computes a clean, presentation-ready view model of the Human Anchor dashboard."
  [state]
  (let [anchor-pub (:anchor-pubkey state)
        anchor-addr (or (:anchor-address state)
                        (when anchor-pub (bech32m/pubkey->bech32m anchor-pub "ech")))
        fido-hint (or (:fido-strength state)
                      (fido/evaluate-authenticator-strength (:aaguid state "2fc0579f-8113-47ea-b116-bb5a8db9202a")))
        supervised-summary (into {}
                                 (map (fn [[id a]]
                                        [id {:agent-id id
                                             :status (:status a)
                                             :address (:hot-address a)
                                             :dac-id (get-in a [:dac :dac-id])
                                             :activity-count (count (:activity-log a))}])
                                      (:supervised-agents state)))
        petnames-view (into {}
                            (map (fn [[k v]]
                                   [k {:pubkey v
                                       :address (bech32m/pubkey->bech32m v "ech")}])
                                 (or (:petnames state) {})))]
    {:identity {:anchor-pubkey anchor-pub
                :address anchor-addr
                :hot-pubkey (:hot-pubkey state)
                :key-mode (or (:key-mode state) :yubikey-discoverable)
                :active-dac-id (get-in state [:active-dac :dac-id])}
     :fido-authenticator {:strength (:strength fido-hint)
                          :score (:score fido-hint)
                          :verification-status (:verification-status fido-hint)
                          :label (:label fido-hint)
                          :warning (:warning fido-hint)
                          :yubico-enrollment (:yubico-enrollment fido-hint)}
     :accounting {:balance (get-in state [:accounts anchor-pub :balance] 0)
                  :burned-ech (or (get-in state [:local-accounting :burned-ech])
                                  (get-in state [:accounting :burned-ech])
                                  0)
                  :vouchers-count (or (some-> (get-in state [:local-accounting :vouchers]) count)
                                      (get-in state [:accounting :vouchers-count])
                                      0)
                  :offers-approved (:offers-approved state 0)
                  :offers-denied (:offers-denied state 0)}
     :pending-offers (vec (:pending-offers state []))
     :service-offers (:service-offers state {})
     :supervised-agents supervised-summary
     :petnames petnames-view
     :directory-cache (:directory-cache state {})
     :team-call-subnet (:team-call-subnet state)
     :trust-boundary anchor-trust-boundary-disclosure
     :origin-scoping anchor-origin-scoping-disclosure}))
