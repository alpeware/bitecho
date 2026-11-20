(ns bitecho.core.mesh
  "Pure Sans-IO `.cljc` Validator Mesh & State Snapshot Persistence logic shared across JVM (`bitecho.shell.mesh`,
   `bitecho.shell.persistence`, `bitecho.shell.identity`) and Node.js (`bitecho.full-node-main`):
   - Snapshot serialization sanitization & record reconstitution (`strip-unserializable-state`, `restore-unserializable-state`)
   - Validator node initial state construction & snapshot rebinding (`build-initial-node-state`, `rebind-restored-state`)
   - DTLS SHA-256 fingerprint normalization & deterministic ICE credentials (`normalize-fingerprint`, `verify-peer-fingerprint?`, `deterministic-ice-creds`)
   - Authenticated agent ingress envelope wrapping & unwrapping (`wrap-agent-event`, `unwrap-authenticated-agent-event`)
   - Signed validator `:chain-state-snapshot` construction (`build-validator-chain-state-snapshot`)
   - Single-authority generation-tagged mesh connection lifecycle reducer (`transition-mesh-conn`, Rules 4 & 5)
   - Validator `/statusz` rendering & parsing (`render-statusz`, `parse-statusz-line`, `mesh-conn-diagnostics-summary`)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.treasury :as treasury]
            [bitecho.fressian :as fressian]
            #?(:cljs [bitecho.light-node.core :as light-core])
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            #?(:clj [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            [clojure.string :as str]))

(def ^:private bytes? fressian/bytes?)

(defn- now-ms-default []
  #?(:clj (System/currentTimeMillis)
     :cljs (long (.now js/Date))))

(defn- derefable? [x]
  #?(:clj (instance? clojure.lang.IDeref x)
     :cljs (satisfies? IDeref x)))

;; =============================================================================
;; 1. DTLS Fingerprints & ICE Credentials
;; =============================================================================

(def ^:private fingerprint-pattern
  #"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")

(defn normalize-fingerprint
  "Normalizes a SHA-256 DTLS fingerprint string to 32 uppercase colon-separated hex pairs.
   Strips optional case-insensitive 'SHA-256:' prefix and surrounding whitespace.
   Throws ex-info if input is nil, blank, or does not match the 32-byte hex pattern."
  [fp]
  (when (or (nil? fp) (str/blank? (str fp)))
    (throw (ex-info "Invalid fingerprint: cannot be nil or blank" {:fingerprint fp})))
  (let [trimmed (str/trim (str fp))
        stripped (if (str/starts-with? (str/lower-case trimmed) "sha-256:")
                   (str/trim (subs trimmed 8))
                   trimmed)
        upper (str/upper-case stripped)]
    (if (re-matches fingerprint-pattern upper)
      upper
      (throw (ex-info "Invalid fingerprint format" {:fingerprint fp :normalized upper})))))

(defn verify-peer-fingerprint?
  "Verifies actual DTLS peer fingerprint against expected fingerprint.
   Strictly fail-closed: returns false if either is nil, blank, or invalid."
  [expected actual]
  (if (or (nil? expected) (nil? actual)
          (str/blank? (str expected)) (str/blank? (str actual)))
    false
    (try
      (= (normalize-fingerprint expected) (normalize-fingerprint actual))
      (catch #?(:clj Exception :cljs :default) _
        false))))

(defn deterministic-ice-creds
  "Derives deterministic ICE ufrag (8 chars) and pwd (24 chars) credentials
   from node-id and optional peer/cert fingerprint."
  ([node-id]
   (deterministic-ice-creds node-id nil))
  ([node-id fingerprint]
   (let [name-str (name (or node-id :node))
         seed-str (if (and (string? fingerprint) (not (str/blank? fingerprint)))
                    (str name-str "-" (normalize-fingerprint fingerprint))
                    name-str)
         ufrag (subs (crypto/sha256-hex (fressian/utf8->bytes (str "ufrag-" seed-str))) 0 8)
         pwd (subs (crypto/sha256-hex (fressian/utf8->bytes (str "pwd-" seed-str))) 0 24)]
     {:ufrag ufrag :pwd pwd})))

;; =============================================================================
;; 2. Snapshot Serialization Sanitization & Reconstitution (Rule 2)
;; =============================================================================

(def ^:private ephemeral-snapshot-keys
  "Derived duplicate sets (reconstructed from `*-order` on load) and ephemeral Bracha/Sieve
   gossip delivery caches that never need to be serialized into validator snapshots."
  [:known-receipt-ids
   :executed-receipt-ids
   :received-readies
   :received-echoes
   :echo-vote-counts
   :ready-vote-counts
   :delivery-vote-counts
   :local-ready-set
   :sieve-delivered-set
   :delivered-set])

(defn- unserializable-val?
  [x]
  (or (satisfies? crypto/IRandom x)
      #?@(:clj
          [(instance? java.util.Random x)
           (and (some? x) (= "clojure.core.async.impl.channels.ManyToManyChannel" (.getName (class x))))])))

(def ^:private bulk-pure-snapshot-keys
  "Large pure-data validator state collections that never contain PRNGs or channels;
   skipping recursive walk over these keys avoids O(100k)-node deep copies on every snapshot."
  #{:blocks :pending-receipts :known-receipt-order :executed-receipt-order
    :ledger :genesis-ledger :block-vote-proofs :block-votes :future-votes
    :future-blocks :epoch-voters :expired-gossip-ids :expired-gossip-order
    :epoch-to-message-roles :notarized-blocks :finalized-blocks
    :executed-finalized-blocks :executed-finalized-blocks-order :block-depths
    :mempool :home-sets :basalt-view :voted-epochs :epoch-unclaimed-mint
    :epoch-mint-dust :frozen-epoch-message-roles :frozen-epoch-messages})

(defn- scrub-unserializable-val
  [x]
  (cond
    (unserializable-val? x) nil
    (map? x) (reduce-kv (fn [acc k v]
                          (let [v' (scrub-unserializable-val v)]
                            (if (identical? v v') acc (assoc acc k v'))))
                        x
                        x)
    (vector? x) (mapv scrub-unserializable-val x)
    (set? x) (into #{} (map scrub-unserializable-val) x)
    :else x))

(defn- scrub-top-level-unserializable
  [m]
  (if-not (map? m)
    m
    (reduce-kv (fn [acc k v]
                 (if (contains? bulk-pure-snapshot-keys k)
                   acc
                   (let [v' (scrub-unserializable-val v)]
                     (if (identical? v v') acc (assoc acc k v')))))
               m
               m)))

(defn strip-unserializable-state
  "Transforms the pure state map into a compact, serializable format without deep-walking
   10,000+ pure receipt/block entries (`D39` V8 hot-path fix).
   Strips private key material, nested PRNG/channel instances, duplicate derived sets
   (`:known-receipt-ids`, `:executed-receipt-ids` — reconstructed from `*-order` on load),
   ephemeral Bracha/Sieve gossip caches, and converts `:murmur-cache :queue` into a vector."
  [state]
  (if-not (map? state)
    state
    (let [queue-handled (if (get-in state [:murmur-cache :queue])
                          (update-in state [:murmur-cache :queue] vec)
                          state)
          secrets-and-ephemeral-stripped
          (-> (apply dissoc queue-handled
                     :keypair :keys :node-private-key :treasury-privkey :custody-privkey
                     ephemeral-snapshot-keys)
              (cond-> (map? (:config queue-handled))
                (update :config dissoc :keypair :keys :node-private-key :treasury-privkey :custody-privkey)))]
      (scrub-top-level-unserializable secrets-and-ephemeral-stripped))))

(def set-typed-state-keys
  "Root state keys that must be reconstituted as Clojure sets after Fressian deserialization."
  [:notarized-blocks
   :finalized-blocks
   :executed-finalized-blocks
   :minted-epochs
   :contagion-known-ids
   :known-receipt-ids
   :executed-receipt-ids
   :settled-escrow-ids
   :voted-epochs
   :equivocated-voters
   :global-echo-sample
   :global-ready-sample
   :global-delivery-sample
   :echo-subscribers
   :ready-subscribers
   :delivery-subscribers
   :sieve-delivered-set
   :local-ready-set
   :delivered-set
   :settled-transcript-pairs
   :settled-voucher-tuples])

(defn- restore-basalt-view
  [bv]
  (cond
    (set? bv)
    (into #{}
          (map (fn [item]
                 (if (and (map? item) (not (record? item)) (or (contains? item :ip) (contains? item :id)) (contains? item :pubkey))
                   (basalt/map->Peer item)
                   item))
               bv))

    (sequential? bv)
    (mapv (fn [slot]
            (cond
              (and (map? slot) (map? (:peer slot)))
              (update slot :peer #(if (record? %) % (basalt/map->Peer %)))

              (and (map? slot) (not (record? slot)) (or (contains? slot :ip) (contains? slot :id)) (contains? slot :pubkey))
              (basalt/map->Peer slot)

              :else slot))
          bv)

    :else bv))

(defn restore-unserializable-state
  "Reconstitutes a Fressian-serialized state map back into its fully functional form.
   Restores domain defrecords (AccountState, Block, Vote, DeliveryAck, Peer),
   set-typed state fields, and converts the :murmur-cache :queue vector back into a PersistentQueue."
  [state]
  (when (map? state)
    (let [s (reduce (fn [acc k]
                      (if (contains? acc k)
                        (update acc k #(when (some? %) (set %)))
                        acc))
                    state
                    set-typed-state-keys)
          s (cond-> s
              (and (not (contains? s :known-receipt-ids)) (coll? (:known-receipt-order s)))
              (assoc :known-receipt-ids (set (:known-receipt-order s)))

              (and (not (contains? s :executed-receipt-ids)) (coll? (:executed-receipt-order s)))
              (assoc :executed-receipt-ids (set (:executed-receipt-order s))))
          empty-q #?(:clj clojure.lang.PersistentQueue/EMPTY :cljs #queue [])]
      (cond-> s
        (get-in s [:murmur-cache :queue])
        (update-in [:murmur-cache :queue] #(into empty-q %))

        (get-in s [:murmur-cache :set])
        (update-in [:murmur-cache :set] set)

        (get-in s [:murmur-cache :seen])
        (update-in [:murmur-cache :seen] set)

        (map? (:ledger s))
        (update :ledger
                #(into {}
                       (map (fn [[k v]]
                              [k (if (map? v)
                                   (account/map->AccountState
                                    (cond-> v
                                      (contains? v :deps) (update :deps vec)))
                                   v)])
                            %)))

        (map? (:blocks s))
        (update :blocks
                #(into {}
                       (map (fn [[k v]]
                              [k (if (map? v)
                                   (streamlet/map->Block
                                    (cond-> v
                                      (contains? v :txs) (update :txs vec)))
                                   v)])
                            %)))

        (map? (:block-votes s))
        (update :block-votes
                #(into {}
                       (map (fn [[k v]]
                              [k (set v)])
                            %)))

        (map? (:block-vote-proofs s))
        (update :block-vote-proofs
                #(into {}
                       (map (fn [[bhash voter-map]]
                              [bhash (if (map? voter-map)
                                       (into {}
                                             (map (fn [[voter v]]
                                                    [voter (if (map? v)
                                                             (streamlet/map->Vote v)
                                                             v)])
                                                  voter-map))
                                       voter-map)])
                            %)))

        (contains? s :pending-vouchers)
        (update :pending-vouchers
                #(when (some? %)
                   (mapv (fn [v]
                           (if (map? v)
                             (rendezvous/map->DeliveryAck v)
                             v))
                         %)))

        (contains? s :basalt-view)
        (update :basalt-view restore-basalt-view)))))

(defn encode-snapshot-bytes
  "Pure helper: strips unserializable state, normalizes for wire, and encodes into Fressian bytes."
  [state]
  (let [safe-state (strip-unserializable-state state)]
    (fressian/write-standard-fressian (fressian/normalize-for-wire safe-state))))

(defn decode-snapshot-bytes
  "Pure helper: decodes Fressian snapshot bytes (standard or canonical/wire), rejecting Nippy fail-closed,
   and restores records, sets, and queues."
  [raw-bytes]
  (when (and (bytes? raw-bytes)
             (pos? (fressian/count-bytes raw-bytes))
             (not (fressian/nippy-payload? raw-bytes)))
    (when-let [raw-state (or (try (fressian/decode raw-bytes)
                                  (catch #?(:clj Exception :cljs :default) _ nil))
                             (try (fressian/decode-wire raw-bytes)
                                  (catch #?(:clj Exception :cljs :default) _ nil)))]
      (restore-unserializable-state raw-state))))

;; =============================================================================
;; 3. Pure Network Command Translation & Agent Ingress Authentication
;; =============================================================================

(defn command->network-event
  "Translates an outgoing :net-out command to a peer's incoming network event."
  [cmd sender-pubkey-hex]
  (let [t (:type cmd)
        name-str (name t)
        receive-type (if (str/starts-with? name-str "send-")
                       (keyword (str "receive-" (subs name-str 5)))
                       t)]
    (-> cmd
        (assoc :type receive-type
               :sender sender-pubkey-hex)
        (dissoc :targets :target))))

(defn extract-command-target-hexes
  "Extracts a vector of distinct target peer pubkey hex strings from a network command."
  [cmd]
  (let [raw-targets (cond
                      (contains? cmd :targets) (:targets cmd)
                      (contains? cmd :target) [(:target cmd)]
                      :else [])
        resolve-hex (fn [t]
                      (cond
                        (string? t) t
                        (map? t) (let [pk (:pubkey t)]
                                   (cond
                                     (string? pk) pk
                                     (bytes? pk) (basalt/bytes->hex pk)
                                     :else nil))
                        :else nil))]
    (vec (distinct (keep resolve-hex raw-targets)))))

(def allowed-agent-events
  "Set of event types permitted from external agent connections on the agent ingress port."
  #{:receive-gossip
    :receive-summary
    :receive-pull-request
    :register-home-set
    :receive-offer-header
    :on-deliver
    :submit-vouchers
    :signaling-burn
    :settle-intent
    :lock-intent
    :release-intent
    :refund-intent
    :reconfigure-membership
    :query-chain-state})

(defn canonicalize-for-signing
  "Recursively converts a data structure into a content-deterministic
   canonical form for pr-str signing (converting byte arrays to [:bytes hex]
   and sorting maps and sets deterministically)."
  [x]
  (cond
    (bytes? x)
    [:bytes (basalt/bytes->hex x)]

    (map? x)
    (into (sorted-map-by (fn [a b] (compare (pr-str a) (pr-str b))))
          (map (fn [[k v]] [(canonicalize-for-signing k) (canonicalize-for-signing v)]) x))

    (set? x)
    (vec (sort-by pr-str (map canonicalize-for-signing x)))

    (sequential? x)
    (mapv canonicalize-for-signing x)

    :else x))

(defn agent-event-signing-bytes
  "Serializes agent public key and event map into deterministic byte array for Ed25519 signing.
   Uses v2 canonical Fressian signing bytes."
  [agent-pubkey-hex event]
  (let [clean (dissoc event :sender :sender-pubkey-bytes :rng)]
    (crypto/canonical-signing-bytes [(or agent-pubkey-hex "") (canonicalize-for-signing clean)])))

(def current-wire-version
  "Current Bitecho mesh wire protocol envelope version."
  1)

(def min-supported-wire-version
  "Minimum supported wire protocol version for rolling-upgrade compatibility (N-1/N)."
  1)

(def max-supported-wire-version
  "Maximum supported wire protocol version for forward rolling-upgrade compatibility (N+1)."
  2)

(defn rolling-upgrade-compatible?
  "Pure helper checking whether two wire protocol versions are within the rolling-upgrade compatibility window (<= 1 step difference) and supported."
  [v1 v2]
  (and (integer? v1)
       (integer? v2)
       (<= min-supported-wire-version (long v1) max-supported-wire-version)
       (<= min-supported-wire-version (long v2) max-supported-wire-version)
       (<= (let [d (- (long v1) (long v2))] (if (neg? d) (- d) d)) 1)))

(defn valid-agent-envelope-version?
  "Pure helper verifying agent wire protocol envelope version compatibility.
   Returns true if :protocol-version is absent/nil (legacy unversioned N-1) or in [min-supported-wire-version, max-supported-wire-version]."
  [msg]
  (if-not (map? msg)
    false
    (let [v (if (contains? msg :protocol-version)
              (:protocol-version msg)
              (when (contains? msg "protocol_version")
                (get msg "protocol_version")))]
      (or (nil? v)
          (and (integer? v)
               (<= min-supported-wire-version (long v) max-supported-wire-version))))))

(def ^{:doc "Default wire format identifier for agent mesh envelopes."}
  current-wire-format "fressian-v1")

(def ^{:doc "Set of supported wire encoding formats."}
  supported-wire-formats #{"fressian-v1" "legacy-nippy" :fressian-v1 :legacy-nippy})

(def ^{:doc "Set of reserved wire formats for future milestones."}
  reserved-wire-formats #{"transit-json" "transit-msgpack" :transit-json :transit-msgpack})

(defn valid-agent-envelope-format?
  "Pure helper verifying agent wire protocol envelope format compatibility.
   Returns true if :wire-format is absent/nil (legacy unversioned N-1) or in supported-wire-formats."
  [msg]
  (if-not (map? msg)
    false
    (let [fmt (or (:wire-format msg) (get msg "wire_format") (get msg "wire-format"))]
      (or (nil? fmt)
          (contains? supported-wire-formats fmt)))))

(defn wrap-agent-event
  "Wraps an agent event into an envelope signed with agent-privkey-bytes.
   Optionally attaches a DAC to the envelope if provided.
   Includes :protocol-version current-wire-version and :wire-format for rolling upgrade compatibility."
  ([event agent-pubkey-hex agent-privkey-bytes]
   (wrap-agent-event event agent-pubkey-hex agent-privkey-bytes nil))
  ([event agent-pubkey-hex agent-privkey-bytes dac]
   (let [clean-event (dissoc event :sender :sender-pubkey-bytes :rng)
         sub-id (str (or (:subnet-id event) "global"))
         sb (agent-event-signing-bytes agent-pubkey-hex clean-event)
         sig (crypto/sign agent-privkey-bytes sb)
         sig-hex (if (string? sig) sig (basalt/bytes->hex sig))
         effective-dac (or dac (:dac event))]
     (cond-> {:protocol-version current-wire-version
              :wire-format current-wire-format
              :subnet-id sub-id
              :agent-pubkey agent-pubkey-hex
              :event clean-event
              :signature sig-hex}
       effective-dac (assoc :dac effective-dac)))))

(defn- verify-mesh-agent-dac
  "Pure helper. Verifies DAC on incoming agent envelope if present."
  [dac agent-pub-hex epoch opts]
  #?(:clj
     (if-let [v-fn (try (requiring-resolve 'bitecho.light-node.core/verify-dac) (catch Exception _ nil))]
       (let [res (v-fn dac {:expected-agent-pubkey agent-pub-hex
                            :current-epoch epoch
                            :required-scope (:required-scope opts)
                            :revoked-dac-ids (:revoked-dacs opts)})]
         (boolean (:ok? res)))
       false)
     :cljs
     (let [res (light-core/verify-dac dac {:expected-agent-pubkey agent-pub-hex
                                           :current-epoch epoch
                                           :required-scope (:required-scope opts)
                                           :revoked-dac-ids (:revoked-dacs opts)})]
       (boolean (:ok? res)))))

(defonce ^:private mesh-crypto-boundary (crypto/make-crypto-boundary))

(defn- make-event-rng []
  #?(:clj (java.util.Random.)
     :cljs (crypto/make-random)))

(defn- seq->bytes [coll]
  #?(:clj (byte-array (map unchecked-byte coll))
     :cljs (let [v (vec coll)
                 n (count v)
                 u8 (js/Uint8Array. n)]
             (dotimes [i n]
               (aset u8 i (bit-and (int (nth v i)) 0xff)))
             u8)))

(defn unwrap-authenticated-agent-event
  "Unwraps and verifies an authenticated agent envelope.
   Returns sanitized event with bound :sender and :sender-pubkey-bytes if valid, or nil.
   Accepts optional opts map supplying :current-epoch, :required-scope, and :revoked-dacs."
  ([raw-msg]
   (unwrap-authenticated-agent-event raw-msg nil))
  ([raw-msg opts]
   (try
     (let [raw-unwrapped (if (bytes? raw-msg)
                           (fressian/decode-wire raw-msg)
                           raw-msg)
           msg (when raw-unwrapped (fressian/strip-untrusted-crypto-tags raw-unwrapped))]
       (when (and (map? msg)
                  (valid-agent-envelope-version? msg)
                  (valid-agent-envelope-format? msg)
                  (string? (:agent-pubkey msg))
                  (map? (:event msg))
                  (contains? allowed-agent-events (:type (:event msg)))
                  (or (string? (:signature msg)) (bytes? (:signature msg))))
         (let [pre-verified (crypto/pre-verify-envelope mesh-crypto-boundary msg)]
           (when (:crypto/verified? pre-verified)
             (let [agent-pub-hex (:agent-pubkey msg)
                   agent-pub-bytes (basalt/hex->bytes agent-pub-hex)
                   event (:event msg)
                   envelope-dac (or (:dac msg) (:dac event))
                   effective-epoch (or (:current-epoch opts) (:epoch event))]
               (when (or (nil? envelope-dac)
                         (and (integer? effective-epoch)
                              (verify-mesh-agent-dac envelope-dac agent-pub-hex effective-epoch opts)))
                 (let [ev-type (:type event)
                       protocol-ver (long (or (:protocol-version msg)
                                              (get msg "protocol_version")
                                              current-wire-version))
                       base-event (cond-> event
                                    envelope-dac (assoc :dac envelope-dac)
                                    true (assoc :protocol-version protocol-ver))]
                   (case ev-type
                     :settle-intent
                     (let [payer (:payer base-event)
                           receiver (:receiver base-event)
                           amount (:amount base-event)]
                       (when (and (or (nil? payer) (= payer agent-pub-hex))
                                  (string? receiver)
                                  (not (str/blank? receiver))
                                  (integer? amount)
                                  (pos? amount))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :payer agent-pub-hex
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (make-event-rng)))))

                     :signaling-burn
                     (let [sender (:sender base-event)
                           amt (or (:burn base-event) (:burn-amount base-event))]
                       (when (and (or (nil? sender) (= sender agent-pub-hex))
                                  (or (nil? amt) (and (integer? amt) (pos? amt))))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (make-event-rng)))))

                     :reconfigure-membership
                     (let [raw-rcpt (or (:receipt base-event) base-event)
                           vals-coll (:validators raw-rcpt)
                           mesh-coll (:mesh-nodes raw-rcpt)
                           sig (:signature raw-rcpt)]
                       (when (and (coll? vals-coll)
                                  (seq vals-coll)
                                  (some? mesh-coll)
                                  (string? sig)
                                  (not (str/blank? sig)))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (make-event-rng)))))

                     :lock-intent
                     (let [payer (:payer base-event)
                           receiver (:receiver base-event)
                           amount (:amount base-event)
                           deliverable-hash (or (:deliverable-hash base-event) (:puzzle-hash base-event))
                           expires-epoch (:expires-epoch base-event)
                           created-epoch (or (:created-epoch base-event) (:epoch base-event))]
                       (when (and (or (nil? payer) (= payer agent-pub-hex))
                                  (string? receiver)
                                  (not (str/blank? receiver))
                                  (not= agent-pub-hex receiver)
                                  (integer? amount)
                                  (pos? amount)
                                  (string? deliverable-hash)
                                  (escrow/valid-deliverable-hash? deliverable-hash)
                                  (integer? expires-epoch)
                                  (if (some? created-epoch)
                                    (and (integer? created-epoch) (> expires-epoch created-epoch))
                                    (pos? expires-epoch)))
                         (cond-> (-> base-event
                                     (dissoc :sender :sender-pubkey-bytes :rng)
                                     (assoc :sender agent-pub-hex
                                            :payer agent-pub-hex
                                            :sender-pubkey-bytes agent-pub-bytes
                                            :rng (make-event-rng)))
                           (some? created-epoch)
                           (assoc :created-epoch created-epoch))))

                     :release-intent
                     (let [escrow-id (:escrow-id base-event)
                           preimage (:preimage base-event)
                           payer-sig (:payer-signature base-event)]
                       (when (and (string? escrow-id)
                                  (not (str/blank? escrow-id))
                                  (or (nil? preimage) (string? preimage))
                                  (or (nil? payer-sig) (string? payer-sig)))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (make-event-rng)))))

                     :refund-intent
                     (let [escrow-id (:escrow-id base-event)]
                       (when (and (string? escrow-id)
                                  (not (str/blank? escrow-id)))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (make-event-rng)))))

                     :query-chain-state
                     (let [q-pk (or (:pubkey base-event) agent-pub-hex)]
                       (when (and (string? q-pk)
                                  (re-matches #"^(?:302a300506032b6570032100)?[0-9a-fA-F]{64}$" (str/trim q-pk)))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :pubkey (str/lower-case (str/trim q-pk))
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (make-event-rng)))))

                     :register-home-set
                     (let [callee (:callee base-event)
                           raw-candidates (or (:candidates base-event) [])
                           candidates (mapv (fn [c]
                                              (if (contains? c :node-id)
                                                (assoc c :node-id (rendezvous/normalize-home-node (:node-id c)))
                                                c))
                                            raw-candidates)]
                       (when (or (nil? callee) (= callee agent-pub-hex))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :callee agent-pub-hex
                                    :candidates candidates
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (make-event-rng)))))

                     :on-deliver
                     (let [p (:payload base-event)
                           p-bytes (cond
                                     (bytes? p) p
                                     (sequential? p) (seq->bytes p)
                                     :else nil)]
                       (when p-bytes
                         (let [p-data (or (try (let [v (fressian/decode p-bytes)]
                                                 (when (or (map? v) (record? v)) v))
                                               (catch #?(:clj Exception :cljs :default) _ nil))
                                          (try (when-let [p-str (try (fressian/bytes->utf8 p-bytes)
                                                                     (catch #?(:clj Exception :cljs :default) _ nil))]
                                                 (edn/read-string {:default tagged-literal
                                                                   :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                                             'bitecho.economy.account.AccountState account/map->AccountState}}
                                                                  p-str))
                                               (catch #?(:clj Exception :cljs :default) _ nil)))
                               raw-transfer (when (and (map? p-data) (:transfer p-data))
                                              (:transfer p-data))
                               transfer-map (when raw-transfer
                                              (if (tagged-literal? raw-transfer)
                                                (:form raw-transfer)
                                                (into {} raw-transfer)))
                               sig (:signature transfer-map)
                               tx-sig-bytes (cond
                                              (bytes? sig) sig
                                              (and (sequential? sig) (seq sig)) (seq->bytes sig)
                                              (and (string? sig) (not (str/blank? sig)))
                                              (if (re-matches #"^[0-9a-fA-F]+$" sig)
                                                (basalt/hex->bytes sig)
                                                (fressian/utf8->bytes sig))
                                              :else nil)
                               unsigned-tx (when (map? transfer-map)
                                             (into (sorted-map) (dissoc transfer-map :signature)))]
                           (when (and (map? transfer-map)
                                      (= (:sender transfer-map) agent-pub-hex)
                                      (some? tx-sig-bytes)
                                      (some? unsigned-tx)
                                      (crypto/verify-with-fallback agent-pub-bytes unsigned-tx tx-sig-bytes))
                             (-> base-event
                                 (dissoc :sender :sender-pubkey-bytes :rng)
                                 (assoc :sender agent-pub-hex
                                        :payload p-bytes
                                        :sender-pubkey-bytes agent-pub-bytes
                                        :rng (make-event-rng)))))))

                     :submit-vouchers
                     (let [vouchers (:vouchers base-event)
                           norm-vouchers (when (and (sequential? vouchers) (seq vouchers))
                                           (mapv (fn [v]
                                                   (let [hn (rendezvous/normalize-home-node (:home-node v))]
                                                     (when (and (string? hn) (not (str/blank? hn)))
                                                       (assoc v :home-node hn))))
                                                 vouchers))]
                       (when (and (sequential? norm-vouchers)
                                  (seq norm-vouchers)
                                  (every? some? norm-vouchers)
                                  (every? (fn [v]
                                            (let [ack (if (record? v)
                                                        v
                                                        (try (rendezvous/map->DeliveryAck v)
                                                             (catch #?(:clj Exception :cljs :default) _ nil)))]
                                              (and ack (rendezvous/verify-delivery-ack ack))))
                                          norm-vouchers))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :vouchers norm-vouchers
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (make-event-rng)))))

                     :receive-offer-header
                     (if (contains? base-event :home-node)
                       (let [hn (rendezvous/normalize-home-node (:home-node base-event))]
                         (when (and (string? hn) (not (str/blank? hn)))
                           (-> base-event
                               (dissoc :sender :sender-pubkey-bytes :rng)
                               (assoc :sender agent-pub-hex
                                      :home-node hn
                                      :sender-pubkey-bytes agent-pub-bytes
                                      :rng (make-event-rng)))))
                       (-> base-event
                           (dissoc :sender :sender-pubkey-bytes :rng)
                           (assoc :sender agent-pub-hex
                                  :sender-pubkey-bytes agent-pub-bytes
                                  :rng (make-event-rng))))

                     ;; Default for other allowed events: :receive-gossip, :receive-summary, :receive-pull-request
                     (-> base-event
                         (dissoc :sender :sender-pubkey-bytes :rng)
                         (assoc :sender agent-pub-hex
                                :sender-pubkey-bytes agent-pub-bytes
                                :rng (make-event-rng)))))))))))
     (catch #?(:clj Exception :cljs :default) _ nil))))

;; =============================================================================
;; 4. Pure State Initialization & Snapshot Rebinding
;; =============================================================================

(defn resolve-pubkey-bytes
  "Converts a hex string or byte array into a byte array."
  [pk]
  (cond
    (bytes? pk) pk
    (string? pk) (try (basalt/hex->bytes pk) (catch #?(:clj Exception :cljs :default) _ nil))
    :else nil))

(defn- extract-top-level-overrides
  "Extracts and normalizes treasury, custody, and ledger overrides from config."
  [cfg cluster-cfg]
  (let [resolve-opt-bytes (fn [v] (when v (resolve-pubkey-bytes v)))
        tp-raw (or (:treasury-privkey cfg)
                   (get-in cfg [:protocol :treasury-privkey])
                   (get-in cluster-cfg [:treasury-privkey]))
        cp-raw (or (:custody-privkey cfg)
                   (get-in cfg [:protocol :custody-privkey])
                   (get-in cluster-cfg [:custody-privkey]))]
    (cond-> {}
      (or (:genesis-ledger cfg) (get-in cluster-cfg [:genesis-ledger]))
      (assoc :genesis-ledger (or (:genesis-ledger cfg) (get-in cluster-cfg [:genesis-ledger])))

      (or (:treasury-pubkey cfg) (get-in cluster-cfg [:treasury-pubkey]))
      (assoc :treasury-pubkey (or (:treasury-pubkey cfg) (get-in cluster-cfg [:treasury-pubkey])))

      tp-raw (assoc :treasury-privkey (resolve-opt-bytes tp-raw))

      (or (:custody-pubkey cfg) (get-in cluster-cfg [:custody-pubkey]))
      (assoc :custody-pubkey (or (:custody-pubkey cfg) (get-in cluster-cfg [:custody-pubkey])))

      cp-raw (assoc :custody-privkey (resolve-opt-bytes cp-raw))

      (or (:custody-allocations cfg) (get-in cluster-cfg [:custody-allocations]))
      (assoc :custody-allocations (or (:custody-allocations cfg) (get-in cluster-cfg [:custody-allocations])))

      (or (:bootstrap-sunset-epoch cfg) (get-in cluster-cfg [:bootstrap-sunset-epoch]))
      (assoc :bootstrap-sunset-epoch (or (:bootstrap-sunset-epoch cfg) (get-in cluster-cfg [:bootstrap-sunset-epoch]))))))

(declare rebind-restored-state)

(defn build-initial-node-state
  "Constructs initial Bitecho state from cluster config and node identity
   (or rebinds `loaded-state` when provided as 3rd argument)."
  ([cfg identity]
   (let [node-id (or (:node/id cfg) (:node-id cfg) (:node-id identity))
         pubkey-hex (:pubkey-hex identity)
         pubkey-bytes (resolve-pubkey-bytes (or (get-in identity [:keypair :public])
                                                (:pubkey-bytes identity)
                                                pubkey-hex))
         privkey-bytes (resolve-pubkey-bytes (or (get-in identity [:keypair :private])
                                                 (:privkey-bytes identity)
                                                 (:privkey-hex identity)))
         cluster-cfg (get cfg :cluster {})
         nodes-cfg (get cluster-cfg :nodes {})
         raw-validators (or (:validators cluster-cfg) (keys nodes-cfg))
         validators (vec (sort (keep (fn [v] (if (keyword? v) (get-in nodes-cfg [v :pubkey]) v)) raw-validators)))
         raw-mesh (:mesh-nodes cluster-cfg)
         mesh-nodes (cond
                      (map? raw-mesh)
                      (into {} (keep (fn [[k w]]
                                       (let [pk (if (keyword? k) (get-in nodes-cfg [k :pubkey]) k)]
                                         (when pk [pk (double (or w 1.0))])))
                                     raw-mesh))
                      (coll? raw-mesh)
                      (into {} (keep (fn [v]
                                       (let [pk (if (keyword? v) (get-in nodes-cfg [v :pubkey]) v)]
                                         (when pk [pk 1.0])))
                                     raw-mesh))
                      :else
                      (into {} (map (fn [pk] [pk 1.0]) validators)))
         peer-entries (for [[_ ninfo] nodes-cfg
                            :let [pk (:pubkey ninfo)
                                  pk-bytes (resolve-pubkey-bytes pk)]
                            :when (some? pk-bytes)]
                        [(if (string? pk) pk (basalt/bytes->hex pk-bytes))
                         pk-bytes])
         peers-map (into {pubkey-hex pubkey-bytes} peer-entries)
         initial-peers (vec (for [[nid ninfo] nodes-cfg
                                  :when (not= nid node-id)
                                  :let [pk (:pubkey ninfo)
                                        pk-bytes (resolve-pubkey-bytes pk)]
                                  :when (some? pk-bytes)]
                              (basalt/make-peer (or (:ip ninfo) (:ip4 ninfo) "127.0.0.1")
                                                (or (:port ninfo) 8000)
                                                pk-bytes)))
         overrides (extract-top-level-overrides cfg cluster-cfg)
         explicit-network (or (:network cfg) (get-in cfg [:cluster :network]))
         configured-validator-count (max (count nodes-cfg) (count validators))
         base-proto-cfg (case explicit-network
                          :devnet (if (>= configured-validator-count 6)
                                    (config/devnet-6-config)
                                    config/devnet-config)
                          :testnet config/testnet-config
                          :mainnet config/mainnet-config
                          config/default-config)
         net-uri (or (config/resolve-network-uri cfg)
                     (:network-uri base-proto-cfg)
                     "devnet.bitecho.org")
         proto-cfg (merge base-proto-cfg
                          (get cfg :protocol {})
                          (get cluster-cfg :protocol {})
                          overrides
                          {:network-uri net-uri
                           :validators validators
                           :mesh-nodes mesh-nodes})
         base-state (sm/init-state initial-peers pubkey-hex proto-cfg)]
     (merge base-state
            overrides
            {:node-id node-id
             :node-pubkey pubkey-hex
             :node-private-key privkey-bytes
             :keypair (or (:keypair identity) {:public pubkey-bytes :private privkey-bytes})
             :validators validators
             :peers-map peers-map
             :mesh-nodes mesh-nodes})))
  ([cfg identity loaded-state]
   (if loaded-state
     (rebind-restored-state loaded-state cfg identity)
     (build-initial-node-state cfg identity))))

(defn rebind-restored-state
  "Rebinds node private keys, credentials, and configuration overrides to a deserialized snapshot state."
  [loaded-state config identity]
  (let [cluster-cfg (get config :cluster {})
        overrides (extract-top-level-overrides config cluster-cfg)
        privkey-bytes (resolve-pubkey-bytes (or (get-in identity [:keypair :private])
                                                (:privkey-bytes identity)
                                                (:privkey-hex identity)))
        pubkey-hex (:pubkey-hex identity)
        genesis-ledger (or (:genesis-ledger overrides)
                           (get-in cluster-cfg [:genesis-ledger])
                           (:genesis-ledger config))
        custody-pk (or (:custody-pubkey overrides)
                       (get-in cluster-cfg [:custody-pubkey])
                       (:custody-pubkey config)
                       (:custody-pubkey loaded-state))
        loaded-ledger (or (:ledger loaded-state) {})
        has-existing-custody? (and custody-pk (contains? loaded-ledger custody-pk))
        merged-ledger (if (map? genesis-ledger)
                        (reduce-kv (fn [m pk acct]
                                     (if (contains? m pk)
                                       m
                                       (let [acct-rec (if (record? acct)
                                                        acct
                                                        (account/map->AccountState acct))
                                             amt (long (or (:balance acct-rec) 0))
                                             m-with-acct (assoc m pk acct-rec)]
                                         (if (and has-existing-custody?
                                                  (not= pk custody-pk)
                                                  (pos? amt)
                                                  (>= (long (or (get-in m-with-acct [custody-pk :balance]) 0)) amt))
                                           (update-in m-with-acct [custody-pk :balance] - amt)
                                           m-with-acct))))
                                   loaded-ledger
                                   genesis-ledger)
                        loaded-ledger)
        pubkey-bytes (resolve-pubkey-bytes (or (get-in identity [:keypair :public])
                                               (:pubkey-bytes identity)
                                               pubkey-hex))
        nodes-cfg (get cluster-cfg :nodes {})
        raw-validators (or (:validators cluster-cfg) (keys nodes-cfg))
        cfg-validators (vec (sort (keep (fn [v] (if (keyword? v) (get-in nodes-cfg [v :pubkey]) v)) raw-validators)))
        effective-validators (cond
                               (:force-config-validators? cluster-cfg)
                               cfg-validators

                               (seq (:validators loaded-state))
                               (vec (sort (distinct (into (vec (:validators loaded-state)) cfg-validators))))

                               (seq cfg-validators)
                               cfg-validators

                               :else
                               (:validators loaded-state))
        raw-mesh (:mesh-nodes cluster-cfg)
        cfg-mesh-nodes (cond
                         (map? raw-mesh)
                         (into {} (keep (fn [[k w]]
                                          (let [pk (if (keyword? k) (get-in nodes-cfg [k :pubkey]) k)]
                                            (when pk [pk (double (or w 1.0))])))
                                        raw-mesh))
                         (coll? raw-mesh)
                         (into {} (keep (fn [v]
                                          (let [pk (if (keyword? v) (get-in nodes-cfg [v :pubkey]) v)]
                                            (when pk [pk 1.0])))
                                        raw-mesh))
                         :else nil)
        loaded-mesh (when (map? (:mesh-nodes loaded-state)) (:mesh-nodes loaded-state))
        base-validator-mesh (when (seq effective-validators)
                              (into {} (map (fn [pk] [pk 1.0]) effective-validators)))
        effective-mesh-nodes (if (:force-config-validators? cluster-cfg)
                               (or (when (seq cfg-mesh-nodes) cfg-mesh-nodes)
                                   base-validator-mesh
                                   loaded-mesh)
                               (let [merged-mesh (merge base-validator-mesh loaded-mesh cfg-mesh-nodes)]
                                 (when (seq merged-mesh) merged-mesh)))
        peer-entries (for [[_ ninfo] nodes-cfg
                           :let [pk (:pubkey ninfo)
                                 pk-bytes (resolve-pubkey-bytes pk)]
                           :when (some? pk-bytes)]
                       [(if (string? pk) pk (basalt/bytes->hex pk-bytes))
                        pk-bytes])
        effective-peers-map (into (or (:peers-map loaded-state) {})
                                  (cond-> peer-entries
                                    pubkey-bytes (conj [pubkey-hex pubkey-bytes])))
        exec-receipt-ids (or (:executed-receipt-ids loaded-state) #{})
        cleaned-pending-receipts (if (seq (:pending-receipts loaded-state))
                                   (filterv #(not (contains? exec-receipt-ids (:receipt-id %)))
                                            (:pending-receipts loaded-state))
                                   (or (:pending-receipts loaded-state) []))
        explicit-network (or (:network config) (get-in config [:cluster :network]))
        configured-validator-count (max (count nodes-cfg) (count effective-validators))
        upgrade-devnet-6? (and (= explicit-network :devnet)
                               (>= configured-validator-count 6)
                               (= 2 (:echo-sample-size (:config loaded-state))))
        base-loaded-config (cond-> (or (:config loaded-state) {})
                             upgrade-devnet-6?
                             (merge (select-keys (config/devnet-6-config)
                                                 [:murmur-k :echo-sample-size :echo-threshold
                                                  :ready-sample-size :ready-threshold
                                                  :delivery-sample-size :delivery-threshold])))
        merged-config (cond-> (merge base-loaded-config
                                     (get config :protocol {})
                                     (get cluster-cfg :protocol {})
                                     overrides)
                        (seq effective-validators) (assoc :validators effective-validators)
                        (seq effective-mesh-nodes) (assoc :mesh-nodes effective-mesh-nodes))]
    (merge loaded-state
           overrides
           (cond-> {:config merged-config
                    :node-pubkey pubkey-hex
                    :node-private-key privkey-bytes
                    :keypair (or (:keypair identity) {:public pubkey-bytes :private privkey-bytes})
                    :last-executed-finalized-epoch (long (or (:last-executed-finalized-epoch loaded-state)
                                                             (:epoch loaded-state)
                                                             0))
                    :executed-finalized-blocks (or (:executed-finalized-blocks loaded-state)
                                                   (:finalized-blocks loaded-state)
                                                   #{})
                    :pending-receipts cleaned-pending-receipts
                    :ledger merged-ledger}
             (seq effective-validators) (assoc :validators effective-validators)
             (seq effective-mesh-nodes) (assoc :mesh-nodes effective-mesh-nodes)
             (seq effective-peers-map) (assoc :peers-map effective-peers-map)))))

(defn- validate-peer-node-entry
  "Validates a single peer node entry in cluster config.
   Returns nil if valid, or an error string."
  [pid pcfg]
  (let [peer-ip (or (:ip pcfg) (:ip4 pcfg))]
    (cond
      (not (map? pcfg))
      (str "Peer " pid " configuration must be a map")

      (or (not (string? peer-ip)) (str/blank? peer-ip))
      (str "Peer " pid " missing or invalid :ip")

      (or (not (integer? (:port pcfg))) (not (pos? (:port pcfg))))
      (str "Peer " pid " missing or invalid :port")

      (let [pk (:pubkey pcfg)]
        (not (and (string? pk) (= 88 (count pk)) (re-matches #"^[0-9a-fA-F]{88}$" pk))))
      (str "Peer " pid " has invalid :pubkey (must be 88-char hex)")

      (not (verify-peer-fingerprint? (:fingerprint pcfg) (:fingerprint pcfg)))
      (str "Peer " pid " has invalid DTLS :fingerprint")

      (or (not (string? (:ice-ufrag pcfg))) (str/blank? (:ice-ufrag pcfg)))
      (str "Peer " pid " missing or invalid :ice-ufrag")

      (or (not (string? (:ice-pwd pcfg))) (str/blank? (:ice-pwd pcfg)))
      (str "Peer " pid " missing or invalid :ice-pwd")

      :else nil)))

(defn validate-contagion-config
  "Validates Contagion sample sizes and thresholds against the configured validator count (`P-CONTAG-3`)."
  ([proto-cfg]
   (validate-contagion-config proto-cfg (or (:validators proto-cfg) (:nodes proto-cfg) [])))
  ([proto-cfg validators-or-count]
   (let [n (long (cond
                   (number? validators-or-count) validators-or-count
                   (coll? validators-or-count) (count validators-or-count)
                   :else (or (:validator-count proto-cfg) 0)))
         v (max 0 (dec n))
         d-size (long (or (:delivery-sample-size proto-cfg) 10))
         d-hat (long (or (:delivery-threshold proto-cfg) 8))
         eff-d (sm/effective-sample-threshold d-size d-hat v)
         clamped? (and (pos? v) (> d-hat v))
         diags (if clamped?
                 [{:effect :diagnose
                   :reason :contagion-threshold-clamped-to-active-view
                   :validator-count n
                   :active-peer-count v
                   :configured-delivery-threshold d-hat
                   :effective-delivery-threshold eff-d}]
                 [])]
     {:valid? (or (zero? v) (<= eff-d v))
      :clamped? clamped?
      :validator-count n
      :active-peer-count v
      :configured-delivery-threshold d-hat
      :effective-delivery-threshold eff-d
      :diagnostics diags})))

(defn validate-node-config
  "Validates a Bitecho node configuration map fail-closed:
   checks map structure, node-id keyword, non-blank state-dir, cluster peer fields,
   and verifies that initial node state construction succeeds.
   Returns {:valid? true} or {:valid? false :error <string>}."
  [cfg]
  (cond
    (not (map? cfg))
    {:valid? false :error "Config must be a map"}

    (not (keyword? (or (:node/id cfg) (:node-id cfg))))
    {:valid? false :error "Config missing valid :node/id or :node-id keyword"}

    (let [sd (:state-dir cfg)]
      (or (not (string? sd)) (str/blank? sd)))
    {:valid? false :error "Config missing or invalid :state-dir"}

    (and (contains? cfg :cluster) (not (map? (:cluster cfg))))
    {:valid? false :error "Cluster configuration must be a map"}

    (and (contains? cfg :cluster)
         (contains? (:cluster cfg) :nodes)
         (not (map? (get-in cfg [:cluster :nodes]))))
    {:valid? false :error "[:cluster :nodes] must be a map"}

    (and (or (= (:network cfg) :mainnet)
             (= (get-in cfg [:cluster :network]) :mainnet)
             (= (config/resolve-network-uri cfg) "mainnet.bitecho.org"))
         (some? (or (:custody-privkey cfg)
                    (get-in cfg [:protocol :custody-privkey])
                    (get-in cfg [:cluster :custody-privkey]))))
    {:valid? false :error "Mainnet configuration must not contain hot :custody-privkey (A-D23-4)"}

    :else
    (let [node-id (or (:node/id cfg) (:node-id cfg))
          nodes (get-in cfg [:cluster :nodes])
          peer-errs (when (map? nodes)
                      (keep (fn [[pid pcfg]]
                              (when (not= pid node-id)
                                (validate-peer-node-entry pid pcfg)))
                            nodes))]
      (if (seq peer-errs)
        {:valid? false :error (first peer-errs)}
        (try
          (let [synth-id {:node-id node-id
                          :pubkey-hex (apply str (repeat 88 "a"))
                          :keypair (crypto/generate-keypair "validate-config-synth")}]
            (build-initial-node-state cfg synth-id)
            {:valid? true})
          (catch #?(:clj Exception :cljs :default) e
            {:valid? false :error (str "State initialization failed: " (ex-message e))}))))))

;; =============================================================================
;; 5. Single-Authority Mesh Connection State Machine (Rules 4 & 5)
;; =============================================================================

(defn conn-channel-id
  "Extracts channel-id from a connection map, unwrapping IDeref atoms if present for backward compatibility."
  [conn]
  (let [cid (:channel-id conn)]
    (if (derefable? cid) @cid cid)))

(defn conn-last-rx-at
  "Extracts last-rx-at from a connection map, unwrapping IDeref atoms if present for backward compatibility."
  [conn]
  (let [rx (:last-rx-at conn)]
    (if (derefable? rx) @rx rx)))

(defn conn-sent-msg-ids
  "Extracts sent-msg-ids set from a connection map, unwrapping IDeref atoms if present for backward compatibility."
  [conn]
  (let [s (:sent-msg-ids conn)]
    (if (derefable? s) @s (or s #{}))))

(defn init-mesh-conn-state
  "Initializes a pure single-authority connection lifecycle state map for a mesh peer or agent."
  ([] (init-mesh-conn-state {}))
  ([opts]
   (let [now-ms (long (or (:now-ms opts) 0))]
     {:generation (long (or (:generation opts) 0))
      :phase :down
      :ok? false
      :node nil
      :channel-id nil
      :created-at now-ms
      :last-rx-at now-ms
      :sent-msg-ids #{}
      :sent-msg-order []
      :error nil
      :last-error nil
      :dropped 0
      :ignored-stale 0
      :diagnostics []})))

(defn anon-conn-key?
  "Returns true if k represents an unauthenticated anonymous agent connection (Gap F-D29-16)."
  [k]
  (and (vector? k) (= :anon (first k))))

(defn push-mesh-diagnostic
  "Appends an effect to the connection diagnostics ring-buffer (capped at 64 entries) and updates :last-diagnostic."
  [conn eff]
  (-> conn
      (assoc :last-diagnostic eff)
      (update :diagnostics (fn [ds] (vec (take-last 64 (conj (vec (or ds [])) eff)))))))

(defn transition-mesh-conn
  "Pure reducer transitioning mesh connection lifecycle state and returning [new-conn effects].
   Phases: :down, :dialing, :open, :failed.
   Ignores stale generation callbacks (< (:generation event) (:generation conn)) or superseded nodes
   without mutating connection phase, liveness, active channel, or resources, incrementing only :ignored-stale."
  [conn event]
  (let [init-st (init-mesh-conn-state {:now-ms (or (:now-ms event) 0)})
        conn (if (nil? conn)
               init-st
               (let [base (merge init-st conn)]
                 (assoc base
                        :channel-id (conn-channel-id conn)
                        :last-rx-at (or (conn-last-rx-at conn) (:last-rx-at base) 0)
                        :sent-msg-ids (conn-sent-msg-ids conn)
                        :sent-msg-order (or (:sent-msg-order conn) (vec (conn-sent-msg-ids conn))))))
        stale-gen? (and (some? (:generation event))
                        (< (long (:generation event)) (long (:generation conn 0))))
        superseded-node? (and (not (#{:dial-started :accept-started} (:type event)))
                              (some? (:node event))
                              (not= (:node event) (:node conn)))]
    (if (or stale-gen? superseded-node?)
      (let [eff (cond-> {:effect :ignore-stale :generation (or (:generation event) (:generation conn 0))}
                  (:peer event) (assoc :peer (:peer event)))]
        [(-> conn
             (update :ignored-stale (fnil inc 0))
             (push-mesh-diagnostic eff))
         [eff]])
      (case (:type event)
        (:dial-started :accept-started)
        (let [next-gen (long (or (:generation event) (inc (long (:generation conn 0)))))
              now-ms (long (or (:now-ms event) (now-ms-default)))
              old-node (:node conn)
              new-node (:node event)
              effects (if (and old-node (not= old-node new-node))
                        [{:effect :close-node :node old-node :generation (:generation conn 0)}]
                        [])
              cid (:channel-id event)
              phase (if (= (:type event) :accept-started)
                      (if (some? cid) :open :dialing)
                      :dialing)
              new-conn (assoc conn
                              :generation next-gen
                              :phase phase
                              :ok? (= phase :open)
                              :node new-node
                              :channel-id cid
                              :created-at now-ms
                              :last-rx-at now-ms
                              :sent-msg-ids (or (:sent-msg-ids event) #{})
                              :sent-msg-order (or (:sent-msg-order event) (vec (or (:sent-msg-ids event) [])))
                              :error nil)]
          [new-conn effects])

        (:on-open :on-data-channel)
        (let [target-gen (long (or (:generation event) (:generation conn 0)))
              now-ms (long (or (:now-ms event) (now-ms-default)))
              old-node (:node conn)
              new-node (or (:node event) old-node)
              cid (if (contains? event :channel-id) (:channel-id event) (:channel-id conn))
              effects (if (and old-node new-node (not= old-node new-node))
                        [{:effect :close-node :node old-node :generation (:generation conn 0)}]
                        [])
              open? (some? cid)
              new-conn (assoc conn
                              :generation target-gen
                              :phase (if open? :open :dialing)
                              :ok? open?
                              :node new-node
                              :channel-id cid
                              :last-rx-at now-ms
                              :error nil)]
          [new-conn effects])

        :on-message
        (let [now-ms (long (or (:now-ms event) (now-ms-default)))
              cid (if (and (contains? event :channel-id) (some? (:channel-id event)))
                    (:channel-id event)
                    (:channel-id conn))
              open? (some? cid)
              new-conn (assoc conn
                              :phase (if open? :open (:phase conn))
                              :ok? (if open? true (:ok? conn))
                              :channel-id cid
                              :last-rx-at now-ms)]
          [new-conn []])

        :record-sent-msg
        (let [mid (:msg-id event)
              curr-set (set (conn-sent-msg-ids conn))
              curr-order (or (:sent-msg-order conn) (vec curr-set))]
          (if (or (nil? mid) (contains? curr-set mid))
            [conn []]
            (let [overflow? (>= (count curr-set) 1024)
                  evicted (when overflow? (first curr-order))
                  next-set (cond-> curr-set
                             evicted (disj evicted)
                             true (conj mid))
                  next-order (cond-> (if overflow? (subvec curr-order 1) curr-order)
                               true (conj mid))]
              [(assoc conn :sent-msg-ids next-set :sent-msg-order next-order) []])))

        (:send-failed :invalid-frame)
        (let [err (or (:error event) (name (:type event)))
              diag-eff (cond-> {:effect :diagnose :reason (:type event) :error err}
                         (:peer event) (assoc :peer (:peer event)))
              new-conn (-> conn
                           (assoc :last-error err
                                  :dropped (inc (long (:dropped conn 0))))
                           (push-mesh-diagnostic diag-eff))]
          [new-conn [diag-eff]])

        :dial-failed
        (let [err (or (:error event) "dial-failed")
              node-to-close (:node conn)
              diag-eff (cond-> {:effect :diagnose :reason :dial-failed :error err}
                         (:peer event) (assoc :peer (:peer event)))
              effects (cond-> []
                        node-to-close (conj {:effect :close-node :node node-to-close :generation (:generation conn 0)})
                        true (conj diag-eff))
              new-conn (-> conn
                           (assoc :phase :failed
                                  :ok? false
                                  :node nil
                                  :channel-id nil
                                  :error err
                                  :last-error err
                                  :dropped (inc (long (:dropped conn 0))))
                           (push-mesh-diagnostic diag-eff))]
          [new-conn effects])

        :on-close
        (let [err (or (:error event) "connection-closed")
              node-to-close (:node conn)
              diag-eff (cond-> {:effect :diagnose :reason :on-close :error err}
                         (:peer event) (assoc :peer (:peer event)))
              effects (cond-> []
                        node-to-close (conj {:effect :close-node :node node-to-close :generation (:generation conn 0)})
                        true (conj diag-eff))
              new-conn (-> conn
                           (assoc :phase :failed
                                  :ok? false
                                  :node nil
                                  :channel-id nil
                                  :error err
                                  :last-error err)
                           (push-mesh-diagnostic diag-eff))]
          [new-conn effects])

        (:shutdown :reap)
        (let [node-to-close (:node conn)
              effects (if node-to-close
                        [{:effect :close-node :node node-to-close :generation (:generation conn 0)}]
                        [])
              new-conn (assoc conn
                              :phase :down
                              :ok? false
                              :node nil
                              :channel-id nil
                              :error nil)]
          [new-conn effects])

        [conn []]))))

(defn prune-closed-conn-tombstones
  "Pure helper. Limits closed or failed connection tombstones in conns-map to max-tombstones (default 64).
   Evicts the oldest closed/failed entries by :last-rx-at / :created-at, rolling their :dropped and
   :ignored-stale counts into the newest remaining closed entry so cumulative diagnostics totals are preserved."
  ([conns-map]
   (prune-closed-conn-tombstones conns-map 64))
  ([conns-map max-tombstones]
   (if (empty? conns-map)
     conns-map
     (let [closed-entries (filter (fn [[_ c]] (#{:down :failed} (:phase c))) conns-map)
           excess (- (count closed-entries) (long max-tombstones))]
       (if (<= excess 0)
         conns-map
         (let [sorted-closed (vec (sort-by (fn [[_ c]]
                                             [(long (or (:last-rx-at c) (:created-at c) 0))
                                              (long (or (:created-at c) 0))])
                                           closed-entries))
               to-evict (subvec sorted-closed 0 excess)
               remaining-closed (subvec sorted-closed excess)
               evicted-dropped (reduce + 0 (map (fn [[_ c]] (long (or (:dropped c) 0))) to-evict))
               evicted-stale (reduce + 0 (map (fn [[_ c]] (long (or (:ignored-stale c) 0))) to-evict))
               to-evict-keys (set (map first to-evict))]
           (if (seq remaining-closed)
             (let [[newest-k newest-c] (last remaining-closed)
                   updated-newest-c (assoc newest-c
                                           :dropped (+ (long (or (:dropped newest-c) 0)) evicted-dropped)
                                           :ignored-stale (+ (long (or (:ignored-stale newest-c) 0)) evicted-stale))]
               (-> (apply dissoc conns-map to-evict-keys)
                   (assoc newest-k updated-newest-c)))
             (apply dissoc conns-map to-evict-keys))))))))

(defn rebind-agent-conn-sender
  "Pure helper. Moves connection entry from anon-key to sender-hex when an agent authenticates.
   If anon-key is already closed/failed or missing a node, treats the rebind as stale without
   overwriting sender-hex. If sender-hex already exists with a different node, closes the existing
   node, advances generation, and preserves cumulative drop/stale counters. Returns [new-conns-map effects]."
  [conns-map anon-key sender-hex cid now-ms]
  (let [anon-conn (get conns-map anon-key)
        existing (get conns-map sender-hex)]
    (if (or (nil? anon-conn)
            (nil? (:node anon-conn))
            (#{:down :failed} (:phase anon-conn)))
      (let [eff {:effect :ignore-stale :generation (long (or (:generation anon-conn) 0))}
            anon-dropped (long (or (:dropped anon-conn) 0))
            anon-stale (long (or (:ignored-stale anon-conn) 0))
            new-map (if existing
                      (-> (dissoc conns-map anon-key)
                          (assoc sender-hex (-> existing
                                                (update :dropped (fn [d] (+ (long (or d 0)) anon-dropped)))
                                                (update :ignored-stale (fn [s] (+ (long (or s 0)) anon-stale 1)))
                                                (push-mesh-diagnostic eff))))
                      (if anon-conn
                        (assoc conns-map anon-key (-> anon-conn
                                                      (update :ignored-stale (fnil inc 0))
                                                      (push-mesh-diagnostic eff)))
                        conns-map))]
        [new-map [eff]])
      (let [superseded? (and existing
                             (or (nil? (:node existing))
                                 (not= (:node existing) (:node anon-conn))))
            effects (if (and superseded? (:node existing))
                      [{:effect :close-node :node (:node existing) :generation (:generation existing 0)}]
                      [])
            next-gen (inc (max (long (or (:generation anon-conn) 0))
                               (long (or (:generation existing) 0))))
            cumulative-dropped (+ (long (or (:dropped anon-conn) 0))
                                  (long (or (:dropped existing) 0)))
            cumulative-stale (+ (long (or (:ignored-stale anon-conn) 0))
                                (long (or (:ignored-stale existing) 0)))
            existing-order (when-not superseded?
                             (or (:sent-msg-order existing) (vec (conn-sent-msg-ids existing))))
            anon-order (or (:sent-msg-order anon-conn) (vec (conn-sent-msg-ids anon-conn)))
            merged-sent-order (if superseded?
                                (vec (distinct anon-order))
                                (vec (distinct (into (or existing-order []) anon-order))))
            capped-order (if (> (count merged-sent-order) 1024)
                           (subvec merged-sent-order (- (count merged-sent-order) 1024))
                           merged-sent-order)
            capped-ids (set capped-order)
            rebound-conn (assoc anon-conn
                                :generation next-gen
                                :phase (if (some? cid) :open (:phase anon-conn))
                                :ok? (if (some? cid) true (:ok? anon-conn))
                                :channel-id (or cid (:channel-id anon-conn))
                                :last-rx-at (or now-ms (:last-rx-at anon-conn))
                                :dropped cumulative-dropped
                                :ignored-stale cumulative-stale
                                :sent-msg-ids capped-ids
                                :sent-msg-order capped-order)
            new-map (-> conns-map
                        (dissoc anon-key)
                        (assoc sender-hex rebound-conn))]
        [new-map effects]))))

(defn mesh-conn-diagnostics-summary
  "Computes aggregate and per-connection diagnostics for peer and agent connections."
  ([peer-conns-map]
   (mesh-conn-diagnostics-summary peer-conns-map {}))
  ([peer-conns-map agent-conns-map]
   (let [peers (or peer-conns-map {})
         agents (or agent-conns-map {})
         all-conns (concat (vals peers) (vals agents))
         total-dropped (reduce + 0 (map #(long (or (:dropped %) 0)) all-conns))
         total-stale (reduce + 0 (map #(long (or (:ignored-stale %) 0)) all-conns))
         summarize (fn [conn]
                     (let [diag-count (count (or (:diagnostics conn) []))]
                       (cond-> {:phase (name (or (:phase conn) :down))
                                :generation (long (or (:generation conn) 0))
                                :ok? (boolean (:ok? conn))
                                :last_error (:last-error conn)
                                :dropped (long (or (:dropped conn) 0))
                                :ignored_stale (long (or (:ignored-stale conn) 0))
                                :diagnostics_buffered (long diag-count)}
                         (:last-diagnostic conn) (assoc :last_diagnostic (:last-diagnostic conn)))))
         peers-summary (into {} (map (fn [[k c]] [k (summarize c)]) peers))
         agents-summary (into {} (map (fn [[k c]] [(if (keyword? k) (name k) (str k)) (summarize c)]) agents))]
     {:protocol_version current-wire-version
      :conn_dropped total-dropped
      :conn_stale total-stale
      :peers peers-summary
      :agents agents-summary})))

;; =============================================================================
;; 6. Pure Statusz Rendering & Signed Validator Chain-State Snapshots
;; =============================================================================

(defn render-statusz
  "Renders single-line diagnostic statusz string.
   Supports 3-arity (defaults conn_dropped=0 conn_stale=0) and 4-arity with conn-diag-summary."
  ([state connected-count total-peers]
   (render-statusz state connected-count total-peers {:conn_dropped 0 :conn_stale 0}))
  ([state connected-count total-peers conn-diag-summary]
   (let [vals-set (set (or (:validators state) (get-in state [:config :validators])))
         role (if (contains? vals-set (:node-pubkey state))
                "validator"
                "mesh")
         epoch (long (or (:epoch state) 0))
         head (str (or (:head-hash state) "genesis"))
         notarized (+ (long (or (:pruned-notarized-count state) 0)) (long (count (or (:notarized-blocks state) #{}))))
         finalized (+ (long (or (:pruned-finalized-count state) 0)) (long (count (or (:finalized-blocks state) #{}))))
         ledger (or (:ledger state) {})
         supply (long (reduce + 0 (map (fn [v] (if (map? v) (or (:balance v) 0) (or v 0))) (vals ledger))))
         minted (long (or (:total-minted state) 0))
         burns (long (reduce + 0 (vals (or (:epoch-burns state) {}))))
         finalized-epoch (long (or (:last-executed-finalized-epoch state) 0))
         burn-digest (sm/compute-burn-map-digest state)
         pending-receipts (long (count (or (:pending-receipts state) [])))
         failed-receipts (long (or (:failed-receipts-count state) 0))
         conn-dropped (long (or (:conn_dropped conn-diag-summary) 0))
         conn-stale (long (or (:conn_stale conn-diag-summary) 0))
         k-bps (long (or (:k-bps state) (get-in state [:config :treasury-k-bps]) (get-in state [:config :k-bps]) treasury/default-k-bps))]
     (str "role=" role
          " epoch=" epoch
          " head=" head
          " notarized=" notarized
          " finalized=" finalized
          " peers=" (long connected-count) "/" (long total-peers)
          " supply=" supply
          " minted=" minted
          " burns=" burns
          " finalized_epoch=" finalized-epoch
          " burn_digest=" burn-digest
          " pending_receipts=" pending-receipts
          " failed_receipts=" failed-receipts
          " conn_dropped=" conn-dropped
          " conn_stale=" conn-stale
          " k_bps=" k-bps
          "\n"))))

(defn- parse-long-or-zero [s]
  (try
    #?(:clj (Long/parseLong s)
       :cljs (let [n (js/parseInt s 10)] (if (js/isNaN n) 0 (long n))))
    (catch #?(:clj Exception :cljs :default) _ 0)))

(defn parse-statusz-line
  "Parses a statusz line string into a keyword map with numeric fields parsed as longs."
  [line]
  (when (and (string? line) (not (str/blank? line)))
    (let [kvs (str/split (str/trim line) #"\s+")
          numeric-keys #{:epoch :notarized :finalized :supply :minted :burns
                         :finalized_epoch :pending_receipts :failed_receipts
                         :conn_dropped :conn_stale :k_bps}]
      (reduce
       (fn [m kv]
         (let [[k-str v-str] (str/split kv #"=" 2)]
           (if (and k-str v-str)
             (let [k (keyword k-str)
                   v (if (contains? numeric-keys k)
                       (parse-long-or-zero v-str)
                       v-str)]
               (assoc m k v))
             m)))
       {}
       kvs))))

(defn build-validator-chain-state-snapshot
  "Pure helper. Builds and signs a :chain-state-snapshot from validator state."
  [st validator-identity pubkey nonce]
  (let [acc (get (:ledger st) pubkey)
        balance (long (or (:balance acc) 0))
        spendable (long (or (:spendable acc) (sm/spendable-balance st pubkey) balance))
        seq-num (long (or (:seq acc) 0))
        deps (vec (or (:deps acc) []))
        fin-epoch (long (or (:last-executed-finalized-epoch st) 0))
        matching-escrows (vec (sort-by :escrow-id
                                       (filter (fn [esc]
                                                 (or (= (:payer esc) pubkey)
                                                     (= (:receiver esc) pubkey)))
                                               (vals (or (:escrows st) {})))))
        val-pub (or (:node-pubkey st)
                    (:pubkey-hex validator-identity)
                    (when-let [pk (get-in st [:keypair :public])]
                      (if (string? pk) pk (basalt/bytes->hex pk))))
        val-priv (or (:node-private-key st)
                     (get-in st [:keypair :private])
                     (get-in validator-identity [:keypair :private])
                     (:privkey-bytes validator-identity)
                     (when-let [pk-hex (:privkey-hex validator-identity)]
                       (basalt/hex->bytes pk-hex)))
        base-snap {:bitecho/type :chain-state-snapshot
                   :type :chain-state-snapshot
                   :validator-pubkey val-pub
                   :pubkey pubkey
                   :finalized-epoch fin-epoch
                   :balance balance
                   :spendable spendable
                   :seq seq-num
                   :deps deps
                   :escrows matching-escrows
                   :nonce (or nonce "")}]
    (when (and val-pub val-priv)
      (let [canonical-str (relay/canonical-chain-state-snapshot-str base-snap)
            sig (crypto/sign val-priv (fressian/utf8->bytes canonical-str))
            sig-hex (if (string? sig) sig (basalt/bytes->hex sig))
            signed (assoc base-snap :signature sig-hex)]
        (when (and (map? signed) (string? (:signature signed)) (not (str/blank? (:signature signed))))
          signed)))))

(defn extract-gossip-msg-id
  "Extracts or computes a deterministic message ID from a frozen or thawed gossip event/envelope."
  [evt-or-bytes]
  (let [thawed (cond
                 (bytes? evt-or-bytes) (fressian/decode-wire evt-or-bytes)
                 (map? evt-or-bytes) evt-or-bytes
                 :else nil)
        msg (cond
              (map? (:message thawed)) (:message thawed)
              (and (map? (:event thawed)) (map? (:message (:event thawed)))) (:message (:event thawed))
              :else nil)]
    (or (:message-id msg)
        (:message_id msg)
        (when-let [p (:payload msg)]
          (let [b (cond
                    (bytes? p) p
                    (string? p) (fressian/utf8->bytes p)
                    :else (try (fressian/encode-wire p) (catch #?(:clj Exception :cljs :default) _ nil)))]
            (when b
              (basalt/bytes->hex (crypto/sha256 b)))))
        (when (bytes? evt-or-bytes)
          (basalt/bytes->hex (crypto/sha256 evt-or-bytes))))))

(defn ensure-fressian-wire-bytes
  "Ensures outbound agent wire payload is valid Fressian-encoded map,
   re-encoding if given a map or a legacy Nippy byte array.
   Strictly validates non-Nippy byte arrays via fressian/decode-wire,
   returning nil for non-map or malformed/garbage bytes."
  [evt-or-bytes]
  (cond
    (map? evt-or-bytes)
    (fressian/encode-wire evt-or-bytes)

    (bytes? evt-or-bytes)
    (if (fressian/nippy-payload? evt-or-bytes)
      (when-let [decoded (try (fressian/decode-wire evt-or-bytes) (catch #?(:clj Exception :cljs :default) _ nil))]
        (when (map? decoded)
          (fressian/encode-wire decoded)))
      (when-let [decoded (try (fressian/decode-wire evt-or-bytes) (catch #?(:clj Exception :cljs :default) _ nil))]
        (when (map? decoded)
          evt-or-bytes)))

    :else nil))

(defn is-network-command?
  "Determines if a given command map is meant for external network peers."
  [cmd]
  (let [t (:type cmd)]
    (or (= :network-out t)
        (and (keyword? t) (str/starts-with? (name t) "send-")))))

(def allowed-network-events
  "Set of event types permitted on the peer-to-peer validator network channel."
  #{:receive-push-view
    :receive-summary
    :receive-pull-request
    :receive-gossip
    :receive-sieve-echo
    :receive-contagion-ready
    :receive-subscribe
    :receive-propose
    :receive-vote
    :register-home-set
    :receive-offer-header
    :on-deliver
    :submit-vouchers
    :signaling-burn
    :settle-intent
    :lock-intent
    :release-intent
    :refund-intent
    :reconfigure-membership
    :receive-receipt
    :request-checkpoint
    :receive-request-checkpoint
    :receive-checkpoint
    :query-chain-state
    :submit-transcript
    :receive-transcript-sig})

(defn valid-network-event?
  "Validates if an incoming event map from the external network is in the whitelist."
  [event]
  (contains? allowed-network-events (:type event)))
