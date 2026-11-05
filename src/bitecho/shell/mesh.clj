(ns bitecho.shell.mesh
  "DataChannel mesh and boundary layer for Bitecho nodes.
   Provides WebRTC DataChannel full-mesh networking, mutual DTLS fingerprint
   authentication, transparent in-memory and datachannel transports,
   embedded HTTP /healthz & /statusz diagnostics, and node lifecycle management."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.treasury :as treasury]
            [bitecho.fressian :as fressian]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.core :as core]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.persistence :as persistence]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datachannel.api :as api])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.net InetSocketAddress]
           [java.nio.charset StandardCharsets]
           [java.util.concurrent Executors TimeUnit]))

(defn log-mesh-error
  "Logs an error message and exception with context for mesh operations."
  [context ^Throwable e]
  (binding [*out* *err*]
    (println (format "[mesh-error] %s: %s" context (or (when e (.getMessage e)) "unknown")))))

;; ---------------------------------------------------------------------------
;; Shared In-Memory Bus for Fast Test Transport
;; ---------------------------------------------------------------------------

(defonce ^:private in-memory-bus (atom {}))

;; ---------------------------------------------------------------------------
;; Pure Network Command & Event Translation
;; ---------------------------------------------------------------------------

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

;; ---------------------------------------------------------------------------
;; Pure Agent Ingress Envelope & Authentication
;; ---------------------------------------------------------------------------

(def allowed-agent-events
  "Set of event types permitted from external agent connections on the agent ingress port."
  #{:receive-gossip
    :receive-summary
    :receive-pull-request
    :register-home-set
    :receive-offer-header
    :on-deliver
    :submit-vouchers
    :settle-intent
    :lock-intent
    :release-intent
    :refund-intent
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
       (<= (Math/abs (- (long v1) (long v2))) 1)))

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
  ([event agent-pubkey-hex ^bytes agent-privkey-bytes]
   (wrap-agent-event event agent-pubkey-hex agent-privkey-bytes nil))
  ([event agent-pubkey-hex ^bytes agent-privkey-bytes dac]
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
  (if-let [v-fn (try (requiring-resolve 'bitecho.light-node.core/verify-dac) (catch Exception _ nil))]
    (let [res (v-fn dac {:expected-agent-pubkey agent-pub-hex
                         :current-epoch epoch
                         :required-scope (:required-scope opts)
                         :revoked-dac-ids (:revoked-dacs opts)})]
      (:ok? res))
    false))

(defonce ^:private mesh-crypto-boundary (crypto/make-crypto-boundary))

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
                                    :rng (java.util.Random.)))))

                     :lock-intent
                     (let [payer (:payer base-event)
                           receiver (:receiver base-event)
                           amount (:amount base-event)
                           deliverable-hash (:deliverable-hash base-event)
                           expires-epoch (:expires-epoch base-event)
                           created-epoch (or (:created-epoch base-event) (:epoch base-event) 0)]
                       (when (and (or (nil? payer) (= payer agent-pub-hex))
                                  (string? receiver)
                                  (not (str/blank? receiver))
                                  (not= agent-pub-hex receiver)
                                  (integer? amount)
                                  (pos? amount)
                                  (string? deliverable-hash)
                                  (escrow/valid-deliverable-hash? deliverable-hash)
                                  (integer? expires-epoch)
                                  (integer? created-epoch)
                                  (> expires-epoch created-epoch))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :payer agent-pub-hex
                                    :created-epoch created-epoch
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (java.util.Random.)))))

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
                                    :rng (java.util.Random.)))))

                     :refund-intent
                     (let [escrow-id (:escrow-id base-event)]
                       (when (and (string? escrow-id)
                                  (not (str/blank? escrow-id)))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (java.util.Random.)))))

                     :query-chain-state
                     (when (or (nil? (:pubkey base-event)) (= (:pubkey base-event) agent-pub-hex))
                       (-> base-event
                           (dissoc :sender :sender-pubkey-bytes :rng)
                           (assoc :sender agent-pub-hex
                                  :pubkey agent-pub-hex
                                  :sender-pubkey-bytes agent-pub-bytes
                                  :rng (java.util.Random.))))

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
                                    :rng (java.util.Random.)))))

                     :on-deliver
                     (let [p (:payload base-event)
                           p-bytes (cond
                                     (bytes? p) p
                                     (sequential? p) (byte-array (map byte p))
                                     :else nil)]
                       (when p-bytes
                         (let [p-data (or (try (let [v (fressian/decode p-bytes)]
                                                 (when (or (map? v) (record? v)) v))
                                               (catch Exception _ nil))
                                          (try (when-let [p-str (try (String. ^bytes p-bytes StandardCharsets/UTF_8) (catch Exception _ nil))]
                                                 (edn/read-string {:default tagged-literal
                                                                   :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                                             'bitecho.economy.account.AccountState account/map->AccountState}}
                                                                  p-str))
                                               (catch Exception _ nil)))
                               raw-transfer (when (and (map? p-data) (:transfer p-data))
                                              (:transfer p-data))
                               transfer-map (when raw-transfer
                                              (if (instance? clojure.lang.TaggedLiteral raw-transfer)
                                                (:form raw-transfer)
                                                (into {} raw-transfer)))
                               sig (:signature transfer-map)
                               tx-sig-bytes (cond
                                              (bytes? sig) sig
                                              (and (sequential? sig) (seq sig)) (byte-array (map byte sig))
                                              (and (string? sig) (not (str/blank? sig)))
                                              (if (re-matches #"^[0-9a-fA-F]+$" sig)
                                                (basalt/hex->bytes sig)
                                                (.getBytes ^String sig StandardCharsets/UTF_8))
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
                                        :rng (java.util.Random.)))))))

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
                                            (let [ack (if (instance? bitecho.rendezvous.core.DeliveryAck v)
                                                        v
                                                        (try (rendezvous/map->DeliveryAck v) (catch Exception _ nil)))]
                                              (and ack (rendezvous/verify-delivery-ack ack))))
                                          norm-vouchers))
                         (-> base-event
                             (dissoc :sender :sender-pubkey-bytes :rng)
                             (assoc :sender agent-pub-hex
                                    :vouchers norm-vouchers
                                    :sender-pubkey-bytes agent-pub-bytes
                                    :rng (java.util.Random.)))))

                     :receive-offer-header
                     (if (contains? base-event :home-node)
                       (let [hn (rendezvous/normalize-home-node (:home-node base-event))]
                         (when (and (string? hn) (not (str/blank? hn)))
                           (-> base-event
                               (dissoc :sender :sender-pubkey-bytes :rng)
                               (assoc :sender agent-pub-hex
                                      :home-node hn
                                      :sender-pubkey-bytes agent-pub-bytes
                                      :rng (java.util.Random.)))))
                       (-> base-event
                           (dissoc :sender :sender-pubkey-bytes :rng)
                           (assoc :sender agent-pub-hex
                                  :sender-pubkey-bytes agent-pub-bytes
                                  :rng (java.util.Random.))))

                ;; Default for other allowed events: :receive-gossip, :receive-summary, :receive-pull-request
                     (-> base-event
                         (dissoc :sender :sender-pubkey-bytes :rng)
                         (assoc :sender agent-pub-hex
                                :sender-pubkey-bytes agent-pub-bytes
                                :rng (java.util.Random.)))))))))))
     (catch Exception _ nil))))

;; ---------------------------------------------------------------------------
;; Pure State Initialization & Status Rendering
;; ---------------------------------------------------------------------------

(defn- resolve-pubkey-bytes
  "Converts a hex string or byte array into a byte array."
  [pk]
  (cond
    (bytes? pk) pk
    (string? pk) (try (basalt/hex->bytes pk) (catch Exception _ nil))
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

(defn build-initial-node-state
  "Constructs initial Bitecho state from cluster config and node identity."
  [cfg identity]
  (let [node-id (or (:node/id cfg) (:node-id cfg) (:node-id identity))
        pubkey-hex (:pubkey-hex identity)
        pubkey-bytes (resolve-pubkey-bytes (get-in identity [:keypair :public]))
        privkey-bytes (resolve-pubkey-bytes (get-in identity [:keypair :private]))
        cluster-cfg (get cfg :cluster {})
        nodes-cfg (get cluster-cfg :nodes {})
        raw-validators (or (:validators cluster-cfg) (keys nodes-cfg))
        validators (vec (sort (keep (fn [v] (if (keyword? v) (get-in nodes-cfg [v :pubkey]) v)) raw-validators)))
        mesh-nodes (or (:mesh-nodes cluster-cfg)
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
                             (basalt/make-peer (or (:ip ninfo) "127.0.0.1")
                                               (or (:port ninfo) 8000)
                                               pk-bytes)))
        overrides (extract-top-level-overrides cfg cluster-cfg)
        network (or (:network cfg) (get-in cfg [:cluster :network]) :mainnet)
        base-proto-cfg (if (= network :devnet)
                         config/devnet-config
                         config/default-config)
        proto-cfg (merge base-proto-cfg
                         (get cfg :protocol {})
                         (get cluster-cfg :protocol {})
                         overrides
                         {:validators validators
                          :mesh-nodes mesh-nodes})
        base-state (sm/init-state initial-peers pubkey-hex proto-cfg)]
    (merge base-state
           overrides
           {:node-id node-id
            :node-pubkey pubkey-hex
            :node-private-key privkey-bytes
            :keypair (:keypair identity)
            :validators validators
            :peers-map peers-map
            :mesh-nodes mesh-nodes})))

(defn rebind-restored-state
  "Rebinds node private keys, credentials, and configuration overrides to a deserialized snapshot state."
  [loaded-state config identity]
  (let [cluster-cfg (get config :cluster {})
        overrides (extract-top-level-overrides config cluster-cfg)
        privkey-bytes (resolve-pubkey-bytes (get-in identity [:keypair :private]))
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
                                       (let [acct-rec (if (instance? bitecho.economy.account.AccountState acct)
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
                        loaded-ledger)]
    (merge loaded-state
           overrides
           {:node-pubkey pubkey-hex
            :node-private-key privkey-bytes
            :keypair (:keypair identity)
            :last-executed-finalized-epoch (long (or (:last-executed-finalized-epoch loaded-state)
                                                     (:epoch loaded-state)
                                                     0))
            :executed-finalized-blocks (or (:executed-finalized-blocks loaded-state)
                                           (:finalized-blocks loaded-state)
                                           #{})
            :ledger merged-ledger})))

(defn- validate-peer-node-entry
  "Validates a single peer node entry in cluster config.
   Returns nil if valid, or an error string."
  [pid pcfg]
  (cond
    (not (map? pcfg))
    (format "Peer %s configuration must be a map" pid)

    (or (not (string? (:ip pcfg))) (str/blank? (:ip pcfg)))
    (format "Peer %s missing or invalid :ip" pid)

    (or (not (integer? (:port pcfg))) (not (pos? (:port pcfg))))
    (format "Peer %s missing or invalid :port" pid)

    (let [pk (:pubkey pcfg)]
      (not (and (string? pk) (= 88 (count pk)) (re-matches #"^[0-9a-fA-F]{88}$" pk))))
    (format "Peer %s has invalid :pubkey (must be 88-char hex)" pid)

    (not (identity/verify-peer-fingerprint? (:fingerprint pcfg) (:fingerprint pcfg)))
    (format "Peer %s has invalid DTLS :fingerprint" pid)

    (or (not (string? (:ice-ufrag pcfg))) (str/blank? (:ice-ufrag pcfg)))
    (format "Peer %s missing or invalid :ice-ufrag" pid)

    (or (not (string? (:ice-pwd pcfg))) (str/blank? (:ice-pwd pcfg)))
    (format "Peer %s missing or invalid :ice-pwd" pid)

    :else nil))

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
                          :keypair (crypto/generate-keypair)}]
            (build-initial-node-state cfg synth-id)
            {:valid? true})
          (catch Exception e
            {:valid? false :error (str "State initialization failed: " (.getMessage e))}))))))

;; ---------------------------------------------------------------------------
;; Single-Authority Mesh Connection State Machine (Rules 4 & 5)
;; ---------------------------------------------------------------------------

(defn conn-channel-id
  "Extracts channel-id from a connection map, unwrapping IDeref atoms if present for backward compatibility."
  [conn]
  (let [cid (:channel-id conn)]
    (if (instance? clojure.lang.IDeref cid) @cid cid)))

(defn conn-last-rx-at
  "Extracts last-rx-at from a connection map, unwrapping IDeref atoms if present for backward compatibility."
  [conn]
  (let [rx (:last-rx-at conn)]
    (if (instance? clojure.lang.IDeref rx) @rx rx)))

(defn conn-sent-msg-ids
  "Extracts sent-msg-ids set from a connection map, unwrapping IDeref atoms if present for backward compatibility."
  [conn]
  (let [s (:sent-msg-ids conn)]
    (if (instance? clojure.lang.IDeref s) @s (or s #{}))))

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
              now-ms (long (or (:now-ms event) (System/currentTimeMillis)))
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
              now-ms (long (or (:now-ms event) (System/currentTimeMillis)))
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
        (let [now-ms (long (or (:now-ms event) (System/currentTimeMillis)))
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

        :shutdown
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

(defn execute-mesh-conn-effects!
  "Executes boundary side-effects resulting from mesh connection state transitions.
   Handles :close-node, :diagnose, and :ignore-stale effects."
  ([effects]
   (execute-mesh-conn-effects! effects nil))
  ([effects opts]
   (doseq [eff effects]
     (case (:effect eff)
       :close-node
       (when-let [n (:node eff)]
         (try (api/close! n) (catch Exception _ nil)))

       (:diagnose :ignore-stale)
       (do
         (when-let [dfn (:diagnose-fn opts)]
           (when (fn? dfn)
             (try (dfn eff) (catch Exception _ nil))))
         (when-let [datom (:diagnostics-atom opts)]
           (when (instance? clojure.lang.IAtom datom)
             (swap! datom (fn [curr] (vec (take-last 64 (conj (vec curr) eff))))))))

       nil))))

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

(defn apply-mesh-conn-event!
  "Atomically transitions an entry in a connections atom (peer-conns or agent-conns)
   via transition-mesh-conn, executes effects outside the swap!, and returns the updated connection map."
  ([conns-atom key event]
   (apply-mesh-conn-event! conns-atom key event nil))
  ([conns-atom key event opts]
   (let [effects-ref (atom [])]
     (swap! conns-atom
            (fn [conns]
              (let [conn (get conns key)
                    [new-conn effects] (transition-mesh-conn conn event)
                    updated (assoc conns key new-conn)]
                (reset! effects-ref effects)
                (prune-closed-conn-tombstones updated))))
     (execute-mesh-conn-effects! @effects-ref opts)
     (get @conns-atom key))))

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
                             (:node existing)
                             (not= (:node existing) (:node anon-conn)))
            effects (if superseded?
                      [{:effect :close-node :node (:node existing) :generation (:generation existing 0)}]
                      [])
            next-gen (inc (max (long (or (:generation anon-conn) 0))
                               (long (or (:generation existing) 0))))
            cumulative-dropped (+ (long (or (:dropped anon-conn) 0))
                                  (long (or (:dropped existing) 0)))
            cumulative-stale (+ (long (or (:ignored-stale anon-conn) 0))
                                (long (or (:ignored-stale existing) 0)))
            existing-order (or (:sent-msg-order existing) (vec (conn-sent-msg-ids existing)))
            anon-order (or (:sent-msg-order anon-conn) (vec (conn-sent-msg-ids anon-conn)))
            merged-sent-order (vec (distinct (into existing-order anon-order)))
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

(defn apply-agent-sender-rebind!
  "Atomically moves an agent connection from anon-key to sender-hex,
   executing any close-node effects outside swap!."
  ([agent-conns anon-key sender-hex cid now-ms]
   (apply-agent-sender-rebind! agent-conns anon-key sender-hex cid now-ms nil))
  ([agent-conns anon-key sender-hex cid now-ms opts]
   (let [effects-ref (atom [])]
     (swap! agent-conns
            (fn [conns]
              (let [[new-conns effects] (rebind-agent-conn-sender conns anon-key sender-hex cid now-ms)]
                (reset! effects-ref effects)
                (prune-closed-conn-tombstones new-conns))))
     (execute-mesh-conn-effects! @effects-ref opts)
     (get @agent-conns sender-hex))))

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
     (format "role=%s epoch=%d head=%s notarized=%d finalized=%d peers=%d/%d supply=%d minted=%d burns=%d finalized_epoch=%d burn_digest=%s pending_receipts=%d failed_receipts=%d conn_dropped=%d conn_stale=%d k_bps=%d\n"
             role epoch head notarized finalized (long connected-count) (long total-peers) supply minted burns finalized-epoch burn-digest pending-receipts failed-receipts conn-dropped conn-stale k-bps))))

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
                       (try (Long/parseLong v-str) (catch Exception _ 0))
                       v-str)]
               (assoc m k v))
             m)))
       {}
       kvs))))

(defn evaluate-cluster-convergence
  "Pure function evaluating consensus, burn window, and soak convergence across cluster node snapshots.
   Takes {node-id {:statusz <map-or-str> :burnsz {:anchor-epoch ... :window [[ep burn take] ...]} ...}}
   and optional opts map {:min-validators N :k-bps N :quorum-size N}, returning structured convergence telemetry."
  [node-snapshots & [opts]]
  (if (empty? node-snapshots)
    {:common-finalized-epoch 0
     :finalized-epoch-skew 0
     :epoch-mismatches []
     :window-burns-converged? true
     :minted-values {}
     :minted-skew 0
     :burn-digest-converged? true
     :accountz-converged? true
     :wire-version-status :converged
     :wire-version-converged? true
     :treasury-sla {:sla-healthy? true}
     :soak-summary {:max_failed_receipts 0
                    :total_conn_dropped 0
                    :total_conn_stale 0
                    :finality_healthy? true}
     :converged? true}
    (let [parsed-snapshots
          (into {}
                (map (fn [[nid snap]]
                       (let [raw-st (:statusz snap)
                             st-map (if (string? raw-st)
                                      (parse-statusz-line raw-st)
                                      (or raw-st {}))
                             fin-epoch (long (or (:finalized_epoch st-map)
                                                 (get-in snap [:burnsz :anchor-epoch])
                                                 0))
                             minted (long (or (:minted st-map) 0))
                             burn-digest (:burn_digest st-map)
                             failed-rcpts (long (or (:failed_receipts st-map) 0))
                             conn-drop (long (or (get-in snap [:connz :conn_dropped])
                                                 (:conn_dropped st-map)
                                                 0))
                             conn-stale (long (or (get-in snap [:connz :conn_stale])
                                                  (:conn_stale st-map)
                                                  0))]
                         [nid {:statusz st-map
                               :burnsz (:burnsz snap)
                               :accountz (:accountz snap)
                               :connz (:connz snap)
                               :fin-epoch fin-epoch
                               :minted minted
                               :burn-digest burn-digest
                               :failed-rcpts failed-rcpts
                               :conn-drop conn-drop
                               :conn-stale conn-stale}]))
                     node-snapshots))
          fin-epochs (mapv :fin-epoch (vals parsed-snapshots))
          common-fin-epoch (if (seq fin-epochs) (apply min fin-epochs) 0)
          max-fin-epoch (if (seq fin-epochs) (apply max fin-epochs) 0)
          fin-epoch-skew (- max-fin-epoch common-fin-epoch)

          ;; Extract node windows and check per-epoch convergence for ep <= common-finalized-epoch
          node-ep-maps (into {}
                             (map (fn [[nid snap]]
                                    [nid (into {}
                                               (map (fn [[ep b t]]
                                                      [(long ep) [(long (or b 0)) (long (or t 0))]]))
                                               (get-in snap [:burnsz :window]))])
                                  parsed-snapshots))
          candidate-epochs (into (sorted-set)
                                 (filter #(<= (long %) common-fin-epoch)
                                         (mapcat keys (vals node-ep-maps))))
          epoch-mismatches (vec (sort (filter (fn [ep]
                                                (let [vals (keep #(get % ep) (vals node-ep-maps))]
                                                  (if (>= (count parsed-snapshots) 2)
                                                    (or (< (count vals) (count parsed-snapshots))
                                                        (not (apply = vals)))
                                                    (and (>= (count vals) 2)
                                                         (not (apply = vals))))))
                                              candidate-epochs)))
          window-burns-converged? (empty? epoch-mismatches)

          minted-values (into {} (map (fn [[nid p]] [nid (:minted p)]) parsed-snapshots))
          minted-skew (if (seq (vals minted-values))
                        (- (apply max (vals minted-values)) (apply min (vals minted-values)))
                        0)

          ;; Check burn digest convergence across nodes at the same finalized-epoch
          nodes-by-fin-epoch (group-by :fin-epoch (vals parsed-snapshots))
          burn-digest-converged? (every? (fn [[_ nodes]]
                                           (let [digests (distinct (keep :burn-digest nodes))]
                                             (<= (count digests) 1)))
                                         nodes-by-fin-epoch)

          ;; Check ledger /accountz parity across all nodes when fin-epoch-skew == 0
          has-accountz? (boolean (some (fn [[_ snap]] (some? (:accountz snap))) parsed-snapshots))
          accountz-maps (when has-accountz?
                          (into {}
                                (keep (fn [[nid snap]]
                                        (let [raw-ac (:accountz snap)
                                              ac-map (cond
                                                       (string? raw-ac) (try (edn/read-string raw-ac) (catch Exception _ nil))
                                                       (map? raw-ac) raw-ac
                                                       :else nil)
                                              accounts (when (map? ac-map)
                                                         (or (:accounts ac-map) ac-map))]
                                          (when (map? accounts)
                                            [nid (into {}
                                                       (map (fn [[k v]] [k (if (map? v) (into {} v) v)]))
                                                       accounts)])))
                                      parsed-snapshots)))
          accountz-converged? (if has-accountz?
                                (let [parse-failed? (< (count accountz-maps) (count parsed-snapshots))
                                      empty-mismatch? (and (some empty? (vals accountz-maps))
                                                           (some seq (vals accountz-maps)))]
                                  (cond
                                    parse-failed? false
                                    empty-mismatch? false
                                    (zero? fin-epoch-skew) (<= (count (distinct (vals accountz-maps))) 1)
                                    :else true))
                                true)

          max-failed (if (seq (vals parsed-snapshots))
                       (apply max (map :failed-rcpts (vals parsed-snapshots)))
                       0)
          total-dropped (reduce + 0 (map :conn-drop (vals parsed-snapshots)))
          total-stale (reduce + 0 (map :conn-stale (vals parsed-snapshots)))
          finality-healthy? (<= fin-epoch-skew 2)

          ;; Wire protocol version convergence check (rolling upgrade window <= 1)
          wire-versions (vec (keep (fn [[_ snap]]
                                     (or (get-in snap [:connz :protocol_version])
                                         (get-in snap [:connz "protocol_version"])))
                                   parsed-snapshots))
          has-connz? (boolean (some (fn [[_ snap]] (some? (:connz snap))) parsed-snapshots))
          require-wire-ver? (or has-connz? (true? (:require-wire-version? opts)))

          [wire-version-status wire-version-converged?]
          (if require-wire-ver?
            (if (< (count wire-versions) (count parsed-snapshots))
              [:unknown false]
              (let [all-compatible? (every? true?
                                            (for [v1 wire-versions
                                                  v2 wire-versions]
                                              (rolling-upgrade-compatible? v1 v2)))]
                (if all-compatible?
                  [:converged true]
                  [:diverged false])))
            [:unknown true])

          ;; Treasury SLA evaluation across validator snapshots
          min-vals (long (or (:min-validators opts) (min 3 (count parsed-snapshots))))
          treasury-sla (treasury/evaluate-treasury-sla parsed-snapshots (assoc (or opts {}) :min-validators min-vals))

          soak-summary {:max_failed_receipts max-failed
                        :total_conn_dropped total-dropped
                        :total_conn_stale total-stale
                        :finality_healthy? finality-healthy?}

          converged? (and window-burns-converged?
                          burn-digest-converged?
                          finality-healthy?
                          (zero? max-failed)
                          accountz-converged?
                          wire-version-converged?
                          (:sla-healthy? treasury-sla))]
      {:common-finalized-epoch common-fin-epoch
       :finalized-epoch-skew fin-epoch-skew
       :epoch-mismatches epoch-mismatches
       :window-burns-converged? window-burns-converged?
       :minted-values minted-values
       :minted-skew minted-skew
       :burn-digest-converged? burn-digest-converged?
       :accountz-converged? accountz-converged?
       :wire-version-status wire-version-status
       :wire-version-converged? wire-version-converged?
       :treasury-sla treasury-sla
       :soak-summary soak-summary
       :converged? converged?})))

;; ---------------------------------------------------------------------------
;; Embedded HTTP Server (/healthz & /statusz)
;; ---------------------------------------------------------------------------

(defn- query-node-state
  "Queries the active shell node for its current internal state with timeout.
   Reads :state-atom directly in O(1) if present, falling back to channel query."
  [shell-node timeout-ms]
  (if-let [st-atom (or (:state-atom shell-node)
                       (get-in shell-node [:shell-node :state-atom]))]
    (when (instance? clojure.lang.IDeref st-atom)
      @st-atom)
    (let [sh (if (:shell-node shell-node) (:shell-node shell-node) shell-node)
          reply-ch (async/promise-chan)]
      (async/put! (:events-in sh) {:type :query-state :reply-chan reply-ch})
      (let [[val _] (async/alts!! [reply-ch (async/timeout timeout-ms)])]
        val))))

(defn- make-http-handler
  "Creates an HttpHandler for healthz, statusz, connz, burnsz, and accountz endpoints."
  [ctx total-peers fallback-state]
  (let [{:keys [shell-node peer-conns agent-conns transport in-mem-bus]} ctx]
    (reify HttpHandler
      (handle [_ exchange]
        (let [path (.getPath (.getRequestURI ^HttpExchange exchange))
              [status body] (cond
                              (= path "/healthz")
                              [200 "ok\n"]

                              (= path "/statusz")
                              (let [st (or (query-node-state shell-node 500) fallback-state)
                                    connected (if (= transport :in-memory)
                                                (max 0 (dec (count @in-mem-bus)))
                                                (count (filter (fn [[_ c]] (some? (conn-channel-id c))) (when peer-conns @peer-conns))))
                                    conn-diag (mesh-conn-diagnostics-summary (when peer-conns @peer-conns)
                                                                             (when agent-conns @agent-conns))]
                                [200 (render-statusz st connected total-peers conn-diag)])

                              (= path "/connz")
                              (let [conn-diag (mesh-conn-diagnostics-summary (when peer-conns @peer-conns)
                                                                             (when agent-conns @agent-conns))]
                                [200 (str (pr-str conn-diag) "\n")])

                              (= path "/burnsz")
                              (let [st (or (query-node-state shell-node 500) fallback-state)]
                                [200 (str (pr-str (sm/extract-burn-window st)) "\n")])

                              (= path "/accountz")
                              (let [st (or (query-node-state shell-node 500) fallback-state)
                                    query (.getQuery (.getRequestURI ^HttpExchange exchange))
                                    pubkey (when query
                                             (second (re-find #"(?:^|&)pubkey=([^&]+)" query)))
                                    resp (if pubkey
                                           {:pubkey pubkey
                                            :account (when-let [a (get (:ledger st) pubkey)] (into {} a))
                                            :spendable (sm/spendable-balance st pubkey)
                                            :finalized-epoch (long (or (:last-executed-finalized-epoch st) 0))}
                                           {:accounts (into {} (map (fn [[k v]] [k (into {} v)]) (:ledger st)))
                                            :finalized-epoch (long (or (:last-executed-finalized-epoch st) 0))})]
                                [200 (str (pr-str resp) "\n")])

                              :else
                              [404 "not found\n"])
              resp-bytes (.getBytes ^String body StandardCharsets/UTF_8)]
          (.getResponseHeaders ^HttpExchange exchange)
          (.set (.getResponseHeaders ^HttpExchange exchange) "Content-Type" "text/plain; charset=utf-8")
          (.sendResponseHeaders ^HttpExchange exchange status (alength resp-bytes))
          (with-open [os (.getResponseBody ^HttpExchange exchange)]
            (.write os resp-bytes)))))))

(defn- start-http-server!
  "Starts embedded HTTP server if enabled."
  [http-cfg ctx total-peers fallback-state]
  (when (get http-cfg :enabled? true)
    (let [port (int (get http-cfg :port 8080))
          host (str (get http-cfg :host "127.0.0.1"))
          server (HttpServer/create (InetSocketAddress. ^String host port) 0)
          handler (make-http-handler ctx total-peers fallback-state)]
      (.createContext server "/healthz" handler)
      (.createContext server "/statusz" handler)
      (.createContext server "/connz" handler)
      (.createContext server "/burnsz" handler)
      (.createContext server "/accountz" handler)
      (.setExecutor server (Executors/newVirtualThreadPerTaskExecutor))
      (.start server)
      server)))

;; ---------------------------------------------------------------------------
;; Mesh Transports & Lifecycle
;; ---------------------------------------------------------------------------

(declare init-datachannel-peer!)

(defn create-peer-datachannel-node
  "Constructs a DataChannel node map using persistent DTLS cert-data and deterministic ICE credentials,
   avoiding runtime throwaway certificate generation."
  ([local-port setup cert-data local-ice local-fp]
   (create-peer-datachannel-node local-port setup cert-data local-ice local-fp nil))
  ([local-port setup cert-data local-ice local-fp turn-config]
   (let [opts (cond-> {:port local-port :setup setup}
                turn-config (assoc :turn-config turn-config
                                   :use-turn-relay? (boolean (:force-relay? turn-config))))
         local-sdp-params {:port local-port
                           :ice-ufrag (:ufrag local-ice)
                           :ice-pwd (:pwd local-ice)
                           :fingerprint local-fp
                           :setup setup}]
     {:opts opts
      :cert-data cert-data
      :ice-creds local-ice
      :local-sdp-params local-sdp-params
      :running (atom false)
      :state-atom (atom nil)
      :channel (atom nil)
      :selector (atom nil)
      :loop-future (atom nil)
      :remote-addr (atom nil)
      :shared-channel? false
      :callbacks (atom nil)})))

(defn send-peer-keepalives!
  "Sends a keepalive frame to each connected peer DataChannel."
  [peer-conns]
  (when peer-conns
    (let [keepalive-bytes (fressian/encode-wire {:type :keepalive})]
      (doseq [[peer-hex conn] @peer-conns
              :let [cid (conn-channel-id conn)]
              :when (some? cid)]
        (try
          (when-let [node (:node conn)]
            (api/send! node keepalive-bytes cid))
          (catch Exception e
            (apply-mesh-conn-event! peer-conns peer-hex
                                    {:type :send-failed :peer peer-hex :error (or (.getMessage e) "send-failed")})
            (log-mesh-error "Failed to send keepalive" e)))))))

(defn check-and-reconnect-peers!
  "Checks peer datachannel health and attempts reconnect if closed, stalled during handshake, or quiet past timeout-ms."
  ([ctx]
   (check-and-reconnect-peers! ctx 20000 (System/currentTimeMillis)))
  ([ctx timeout-ms]
   (check-and-reconnect-peers! ctx timeout-ms (System/currentTimeMillis)))
  ([ctx timeout-ms now-ms]
   (let [{:keys [nodes-cfg node-id peer-conns]} ctx]
     (doseq [[pid pcfg] nodes-cfg
             :when (not= pid node-id)
             :let [peer-hex (:pubkey pcfg)
                   conn (get @peer-conns peer-hex)
                   node (:node conn)
                   st (when node (try (api/get-state node) (catch Exception _ :closed)))
                   cid (when conn (conn-channel-id conn))
                   created-at (long (get conn :created-at 0))
                   last-rx (long (or (when conn (conn-last-rx-at conn)) now-ms))
                   stalled-unconnected? (and (nil? cid) (> (- (long now-ms) created-at) 12000))
                   timed-out-connected? (and (some? cid) (> (- (long now-ms) last-rx) (long timeout-ms)))]]
       (when (or (nil? conn)
                 (= st :closed)
                 stalled-unconnected?
                 timed-out-connected?)
         (try
           (init-datachannel-peer! ctx pid pcfg)
           (catch Exception e
             (log-mesh-error (str "Peer reconnect error for " pid) e))))))))

(defn- start-ticker!
  "Starts the periodic virtual-thread timer pushing :tick events, sending peer keepalives, and auto-reconnecting."
  [ctx tick-interval-ms]
  (let [{:keys [shell-node transport]} ctx
        timeout-ms (max 20000 (* 2 (long tick-interval-ms)))
        executor (Executors/newSingleThreadScheduledExecutor)
        initial-delay (let [t (long tick-interval-ms)
                            rem-ms (mod (System/currentTimeMillis) t)]
                        (if (zero? rem-ms) t (- t rem-ms)))]
    (.scheduleAtFixedRate executor
                          (fn []
                            (try
                              (async/put! (:events-in shell-node)
                                          {:type :tick :rng (java.util.Random.)})
                              (when (= transport :datachannel)
                                (send-peer-keepalives! (:peer-conns ctx))
                                (check-and-reconnect-peers! ctx timeout-ms))
                              (catch Exception e
                                (log-mesh-error "Ticker loop error" e))))
                          initial-delay
                          tick-interval-ms
                          TimeUnit/MILLISECONDS)
    executor))

(defn- extract-gossip-msg-id
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
                    (string? p) (.getBytes ^String p StandardCharsets/UTF_8)
                    :else (try (fressian/encode-wire p) (catch Exception _ nil)))]
            (when b
              (basalt/bytes->hex (crypto/sha256 b)))))
        (when (bytes? evt-or-bytes)
          (basalt/bytes->hex (crypto/sha256 evt-or-bytes))))))

(defn- ensure-fressian-wire-bytes
  "Ensures outbound agent wire payload is Fressian-encoded,
   re-encoding if given a map or a legacy Nippy byte array."
  [evt-or-bytes]
  (cond
    (and (bytes? evt-or-bytes) (not (fressian/nippy-payload? evt-or-bytes)))
    evt-or-bytes

    (bytes? evt-or-bytes)
    (when-let [decoded (fressian/decode-wire evt-or-bytes)]
      (fressian/encode-wire decoded))

    (map? evt-or-bytes)
    (fressian/encode-wire evt-or-bytes)

    :else nil))

(defn- forward-gossip-to-agents!
  "Forwards a frozen gossip network event to all connected agent DataChannels, optionally excluding a sender.
   Deduplicates messages per agent connection using :sent-msg-ids and enforces Fressian wire encoding."
  [agent-conns frozen-evt exclude-sender]
  (when agent-conns
    (when-let [wire-bytes (ensure-fressian-wire-bytes frozen-evt)]
      (let [msg-id (extract-gossip-msg-id wire-bytes)]
        (doseq [[pk conn] @agent-conns
                :when (not= pk exclude-sender)]
          (let [sent-ids (conn-sent-msg-ids conn)]
            (when-not (and msg-id (contains? sent-ids msg-id))
              (when-let [cid (or (conn-channel-id conn) 0)]
                (when-let [node (:node conn)]
                  (try
                    (api/send! node wire-bytes cid)
                    (when msg-id
                      (if (instance? clojure.lang.IAtom (:sent-msg-ids conn))
                        (swap! (:sent-msg-ids conn) conj msg-id)
                        (apply-mesh-conn-event! agent-conns pk {:type :record-sent-msg :msg-id msg-id})))
                    (catch Exception e
                      (apply-mesh-conn-event! agent-conns pk
                                              {:type :send-failed :error (or (.getMessage e) "send-failed")})
                      nil)))))))))))

(defn- start-net-out-loop!
  "Consumes net-out commands, transforms them to peer events, and delivers to targets."
  [ctx]
  (let [{:keys [shell-node identity transport peer-conns in-mem-bus agent-conns]} ctx]
    (async/go-loop []
      (when-let [cmd (async/<! (:net-out shell-node))]
        (try
          (let [targets (extract-command-target-hexes cmd)
                sender-hex (:pubkey-hex identity)
                evt (command->network-event cmd sender-hex)
                frozen (fressian/encode-wire evt)]
            (doseq [target targets]
              (if (= transport :in-memory)
                (when-let [peer-entry (get @in-mem-bus target)]
                  (let [thawed (assoc (fressian/decode-wire frozen)
                                      :sender sender-hex
                                      :sender-pubkey-bytes (get-in identity [:keypair :public])
                                      :rng (java.util.Random.))]
                    (async/put! (:network-in peer-entry) thawed)))
                (when-let [conn (or (get @peer-conns target)
                                    (when agent-conns (get @agent-conns target)))]
                  (when-let [cid (conn-channel-id conn)]
                    (try
                      (when-let [node (:node conn)]
                        (api/send! node frozen cid))
                      (catch Exception e
                        (let [target-conns (if (get @peer-conns target) peer-conns agent-conns)]
                          (when target-conns
                            (apply-mesh-conn-event! target-conns target
                                                    {:type :send-failed :peer target :error (or (.getMessage e) "send-failed")})))
                        nil))))))
            (when (and (or (= (:type cmd) :send-gossip)
                           (= (:type evt) :receive-gossip))
                       agent-conns)
              (forward-gossip-to-agents! agent-conns frozen nil)))
          (catch Exception e
            (log-mesh-error "Net-out loop error" e)))
        (recur)))))

(defn- init-datachannel-peer!
  "Establishes a single peer DataChannel connection using single-authority lifecycle state machine."
  [ctx pid peer-cfg]
  (try
    (let [peer-hex (:pubkey peer-cfg)
          raw-fp (:fingerprint peer-cfg)
          peer-fp (when (identity/verify-peer-fingerprint? raw-fp raw-fp)
                    (identity/normalize-fingerprint raw-fp))
          {:keys [node-id identity node-idx nodes-cfg shell-node peer-conns agent-conns]} ctx
          local-fp (:fingerprint identity)
          local-ice (or (:ice-creds identity)
                        (when (and (:ice-ufrag identity) (:ice-pwd identity))
                          {:ufrag (:ice-ufrag identity) :pwd (:ice-pwd identity)}))
          remote-ice (or (:ice-creds peer-cfg)
                         (when (and (:ice-ufrag peer-cfg) (:ice-pwd peer-cfg))
                           {:ufrag (:ice-ufrag peer-cfg) :pwd (:ice-pwd peer-cfg)}))]
      (cond
        (not peer-fp)
        (do
          (when peer-hex
            (apply-mesh-conn-event! (:peer-conns ctx) peer-hex
                                    {:type :dial-failed :peer pid :error "invalid-peer-fingerprint"}))
          (log-mesh-error (format "Invalid peer fingerprint for %s" pid)
                          (ex-info "Invalid peer fingerprint" {:peer pid :fingerprint raw-fp})))

        (or (nil? (:ufrag local-ice)) (nil? (:pwd local-ice))
            (nil? (:ufrag remote-ice)) (nil? (:pwd remote-ice)))
        (do
          (when peer-hex
            (apply-mesh-conn-event! (:peer-conns ctx) peer-hex
                                    {:type :dial-failed :peer pid :error "missing-ice-credentials"}))
          (log-mesh-error (format "Missing ICE credentials for peer %s" pid)
                          (ex-info "Missing ICE credentials" {:peer pid :local-ice local-ice :remote-ice remote-ice})))

        :else
        (let [next-gen (inc (long (get-in @peer-conns [peer-hex :generation] 0)))
              peer-ip (or (:ip peer-cfg) "127.0.0.1")
              base-peer-port (int (or (:port peer-cfg) 5000))
              peer-port (+ base-peer-port (int (get node-idx node-id 0)))
              base-local-port (int (or (get-in nodes-cfg [node-id :port]) 5000))
              local-port (+ base-local-port (int (get node-idx pid 0)))
              setup (if (neg? (compare (name node-id) (name pid))) "active" "passive")
              turn-cfg (or (:turn-config peer-cfg) (get-in ctx [:config :cluster :turn-config]))
              node (create-peer-datachannel-node local-port setup (:cert-data identity) local-ice local-fp turn-cfg)
              _ (apply-mesh-conn-event! peer-conns peer-hex
                                        {:type :dial-started :generation next-gen :node node :peer pid})
              remote-sdp {:ip peer-ip
                          :port peer-port
                          :fingerprint peer-fp
                          :remote-ice-ufrag (:ufrag remote-ice)
                          :remote-ice-pwd (:pwd remote-ice)}
              callbacks {:on-open
                         (fn [evt]
                           (let [curr-conn (get @peer-conns peer-hex)]
                             (if (or (< next-gen (long (:generation curr-conn 0)))
                                     (not= node (:node curr-conn)))
                               (apply-mesh-conn-event! peer-conns peer-hex
                                                       {:type :on-open :generation next-gen :node node :peer pid})
                               (let [cid (or (:channel-id evt)
                                             (try (api/create-data-channel! node "bitecho" {:ordered true})
                                                  (catch Exception _ 0)))]
                                 (apply-mesh-conn-event! peer-conns peer-hex
                                                         {:type :on-open :generation next-gen :node node :channel-id cid :peer pid})))))
                         :on-message
                         (fn [evt]
                           (let [updated (apply-mesh-conn-event!
                                          peer-conns peer-hex
                                          (cond-> {:type :on-message :generation next-gen :node node :peer pid}
                                            (:channel-id evt) (assoc :channel-id (:channel-id evt))))]
                             (when (= node (:node updated))
                               (let [msg (fressian/decode-wire (:payload evt))]
                                 (if-not (map? msg)
                                   (apply-mesh-conn-event! peer-conns peer-hex
                                                           {:type :invalid-frame :generation next-gen :node node :peer pid :error "malformed-peer-frame"})
                                   (when-not (= :keepalive (:type msg))
                                     (let [event (assoc msg
                                                        :sender peer-hex
                                                        :sender-pubkey-bytes (basalt/hex->bytes peer-hex)
                                                        :rng (java.util.Random.))]
                                       (async/put! (:network-in shell-node) event)
                                       (when (= :receive-gossip (:type msg))
                                         (forward-gossip-to-agents! agent-conns (fressian/encode-wire msg) nil)))))))))
                         :on-close
                         (fn [_]
                           (apply-mesh-conn-event! peer-conns peer-hex
                                                   {:type :on-close :generation next-gen :node node :peer pid}))}]
          (try
            (api/start! node remote-sdp callbacks)
            (catch Exception e
              (apply-mesh-conn-event! peer-conns peer-hex
                                      {:type :dial-failed :generation next-gen :node node :peer pid :error (or (.getMessage e) "start-failed")})
              (throw e))))))
    (catch Exception e
      (log-mesh-error (format "Failed to connect to peer %s" pid) e)
      nil)))

(defn- replay-cached-gossip-to-agent!
  "Replays all cached epoch gossip messages to a newly connected or identified agent DataChannel,
   deduplicating per agent connection via :sent-msg-ids."
  [shell-node agent-conns conn-key]
  (when-let [st (query-node-state shell-node 200)]
    (let [messages-map (or (:messages st) {})
          epochs-map (or (:message-epochs st) {})
          sorted-msgs (sort-by (fn [[mid _]] [(long (get epochs-map mid 0)) (str mid)]) messages-map)]
      (doseq [[mid message] sorted-msgs]
        (let [conn (when agent-conns (get @agent-conns conn-key))]
          (when-let [node (:node conn)]
            (let [sent-ids (conn-sent-msg-ids conn)]
              (when-not (contains? sent-ids mid)
                (let [cid (or (conn-channel-id conn) 0)
                      frozen (fressian/encode-wire {:type :receive-gossip :message message})]
                  (try
                    (api/send! node frozen cid)
                    (if (instance? clojure.lang.IAtom (:sent-msg-ids conn))
                      (swap! (:sent-msg-ids conn) conj mid)
                      (apply-mesh-conn-event! agent-conns conn-key {:type :record-sent-msg :msg-id mid}))
                    (catch Exception e
                      (when agent-conns
                        (apply-mesh-conn-event! agent-conns conn-key
                                                {:type :send-failed :error (or (.getMessage e) "send-failed")}))
                      nil)))))))))))

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
                      (basalt/bytes->hex pk)))
        val-priv (or (:node-private-key st)
                     (get-in st [:keypair :private])
                     (get-in validator-identity [:keypair :private])
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
                   :nonce (or nonce "")}
        sign-fn (try (requiring-resolve 'bitecho.light-node.core/sign-chain-state-snapshot) (catch Exception _ nil))]
    (if (and sign-fn val-priv)
      (let [signed (sign-fn base-snap val-priv)]
        (if (and (map? signed) (string? (:signature signed)) (not (str/blank? (:signature signed))))
          signed
          (do
            (log-mesh-error "build-validator-chain-state-snapshot: invalid signature produced"
                            (ex-info "Invalid signature" {:signed signed}))
            nil)))
      (do
        (log-mesh-error "build-validator-chain-state-snapshot: missing sign-fn or val-priv"
                        (ex-info "Cannot sign snapshot" {:has-sign-fn? (boolean sign-fn) :has-priv? (boolean val-priv)}))
        nil))))

(defn make-agent-connection-handler
  "Returns a connection handler function for an incoming agent node.
   Works identically for UDP and TCP agent connections using single-authority lifecycle state."
  ([shell-node agent-conns]
   (make-agent-connection-handler shell-node agent-conns nil nil))
  ([shell-node agent-conns peer-ice-pwds]
   (make-agent-connection-handler shell-node agent-conns peer-ice-pwds nil))
  ([shell-node agent-conns peer-ice-pwds validator-identity]
   (fn [agent-node]
     (let [conn-key (atom [:anon (System/identityHashCode agent-node)])
           init-gen (inc (long (reduce max 0 (map #(long (or (:generation %) 0)) (vals (or (when agent-conns (deref agent-conns)) {}))))))
           node-gen (atom init-gen)]
       (when agent-conns
         (apply-mesh-conn-event! agent-conns @conn-key
                                 {:type :accept-started :generation @node-gen :node agent-node :channel-id 0}))
       (api/set-callbacks!
        agent-node
        {:on-open (fn [evt]
                    (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)
                          updated (when agent-conns
                                    (apply-mesh-conn-event! agent-conns @conn-key
                                                            {:type :on-open :generation @node-gen :node agent-node :channel-id cid}))]
                      (when (or (nil? agent-conns) (= agent-node (:node updated)))
                        (replay-cached-gossip-to-agent! shell-node agent-conns @conn-key))))
         :on-data-channel (fn [evt]
                            (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)
                                  updated (when agent-conns
                                            (apply-mesh-conn-event! agent-conns @conn-key
                                                                    {:type :on-data-channel :generation @node-gen :node agent-node :channel-id cid}))]
                              (when (or (nil? agent-conns) (= agent-node (:node updated)))
                                (replay-cached-gossip-to-agent! shell-node agent-conns @conn-key))))
         :on-message
         (fn [evt]
           (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)
                 active? (or (nil? agent-conns)
                             (= agent-node (:node (get @agent-conns @conn-key))))]
             (if-not active?
               (when agent-conns
                 (apply-mesh-conn-event! agent-conns @conn-key
                                         {:type :on-message :generation @node-gen :node agent-node :channel-id cid}))
               (let [unwrapped (unwrap-authenticated-agent-event (:payload evt))]
                 (if-not unwrapped
                   (when agent-conns
                     (apply-mesh-conn-event! agent-conns @conn-key
                                             {:type :invalid-frame :generation @node-gen :node agent-node :error "invalid-agent-envelope"}))
                   (do
                     (when (and (= :register-home-set (:type unwrapped))
                                (:ice-ufrag unwrapped)
                                (:ice-pwd unwrapped))
                       (let [ufrag (:ice-ufrag unwrapped)
                             pwd (:ice-pwd unwrapped)
                             sender (:sender unwrapped)
                             node-ufrag (when-let [sa (:state-atom agent-node)] (:remote-ice-ufrag @sa))
                             can-set? (and (or (nil? node-ufrag) (= node-ufrag ufrag))
                                           (or (nil? peer-ice-pwds)
                                               (not (instance? clojure.lang.Atom peer-ice-pwds))
                                               (let [curr-pwds @peer-ice-pwds
                                                     owner (get curr-pwds [:owner ufrag])]
                                                 (or (nil? owner) (= owner sender)))))]
                         (when can-set?
                           (when (instance? clojure.lang.Atom peer-ice-pwds)
                             (swap! peer-ice-pwds (fn [m]
                                                    (-> (assoc m ufrag pwd)
                                                        (assoc [:owner ufrag] sender)))))
                           (try
                             (api/set-remote-ice-credentials! agent-node ufrag pwd)
                             (catch Exception _
                               (when-let [st-atom (:state-atom agent-node)]
                                 (swap! st-atom assoc
                                        :remote-ice-ufrag ufrag
                                        :remote-ice-pwd pwd)))))))
                     (let [sender (:sender unwrapped)
                           query-only? (= (:type unwrapped) :query-chain-state)]
                       (when (and sender (not query-only?) (not= sender @conn-key))
                         (let [old-key @conn-key]
                           (if agent-conns
                             (let [rebound (apply-agent-sender-rebind! agent-conns old-key sender cid (System/currentTimeMillis))]
                               (when (= agent-node (:node rebound))
                                 (reset! conn-key sender)
                                 (reset! node-gen (long (or (:generation rebound) @node-gen)))
                                 (replay-cached-gossip-to-agent! shell-node agent-conns sender)))
                             (reset! conn-key sender))))
                       (let [updated (when (and agent-conns (not query-only?))
                                       (apply-mesh-conn-event! agent-conns @conn-key
                                                               {:type :on-message :generation @node-gen :node agent-node :channel-id cid}))]
                         (when (or (nil? agent-conns) query-only? (= agent-node (:node updated)))
                           (if query-only?
                             (let [st (or (when shell-node (query-node-state shell-node 500)) {})
                                   v-id (or validator-identity (:identity shell-node))
                                   snapshot (build-validator-chain-state-snapshot st v-id (:pubkey unwrapped) (:nonce unwrapped))]
                               (when (and (map? snapshot) (string? (:signature snapshot)) (not (str/blank? (:signature snapshot))))
                                 (try
                                   (api/send! agent-node (fressian/encode-wire snapshot) cid)
                                   (catch Exception e
                                     (log-mesh-error "Failed to send chain-state-snapshot to agent" e)))))
                             (do
                               (async/put! (:network-in shell-node) unwrapped)
                               (when (and (= (:type unwrapped) :receive-gossip) agent-conns)
                                 (let [fressian-payload (if (and (bytes? (:payload evt)) (fressian/nippy-payload? (:payload evt)))
                                                          (fressian/encode-wire {:type :receive-gossip :message (:message unwrapped)})
                                                          (:payload evt))]
                                   (forward-gossip-to-agents! agent-conns fressian-payload (:sender unwrapped)))))))))))))))
         :on-close (fn [_]
                     (when agent-conns
                       (apply-mesh-conn-event! agent-conns @conn-key
                                               {:type :on-close :generation @node-gen :node agent-node})))})))))

(defn- init-agent-listener!
  "Starts agent ingress listener when enabled.
   Sanitizes incoming agent messages using unwrap-authenticated-agent-event."
  [config identity shell-node transport agent-conns]
  (when (and (= transport :datachannel)
             (get-in config [:cluster :listen-agents?] false))
    (let [port (int (get-in config [:cluster :agent-port] 5010))
          peer-ice-pwds (atom {})
          listen-opts {:port port
                       :cert-data (:cert-data identity)
                       :ice-creds (:ice-creds identity)
                       :peer-ice-pwds peer-ice-pwds}]
      (api/listen! listen-opts
                   {:on-connection (make-agent-connection-handler shell-node agent-conns peer-ice-pwds identity)}))))

(defn- init-agent-tcp-listener!
  "Starts TCP agent ingress listener when enabled (RFC 4571 framing)."
  [config identity shell-node transport agent-conns]
  (when (and (= transport :datachannel)
             (get-in config [:cluster :listen-agents?] false))
    (let [port (int (or (get-in config [:cluster :agent-tcp-port])
                        (get-in config [:cluster :agent-port])
                        5010))
          peer-ice-pwds (atom {})
          listen-opts {:port port
                       :cert-data (:cert-data identity)
                       :ice-creds (:ice-creds identity)
                       :peer-ice-pwds peer-ice-pwds}]
      (api/listen-tcp! listen-opts
                       {:on-connection (make-agent-connection-handler shell-node agent-conns peer-ice-pwds identity)}))))

(defn stop-mesh-node!
  "Stops all running resources of a mesh node cleanly."
  [mesh-node]
  (when-let [srv (:http-server mesh-node)]
    (try (.stop ^HttpServer srv 0) (catch Exception _ nil)))
  (when-let [exec (:ticker-executor mesh-node)]
    (try (.shutdownNow ^java.util.concurrent.ExecutorService exec) (catch Exception _ nil)))
  (when-let [al (:agent-listener mesh-node)]
    (try (api/close! al) (catch Exception _ nil)))
  (when-let [atl (:agent-tcp-listener mesh-node)]
    (try (api/close! atl) (catch Exception _ nil)))
  (when-let [pcs (:peer-conns mesh-node)]
    (doseq [[peer-hex _] @pcs]
      (apply-mesh-conn-event! pcs peer-hex {:type :shutdown})))
  (when-let [acs (:agent-conns mesh-node)]
    (doseq [[k _] @acs]
      (apply-mesh-conn-event! acs k {:type :shutdown})))
  (when (= (:transport mesh-node) :in-memory)
    (swap! in-memory-bus dissoc (get-in mesh-node [:identity :pubkey-hex])))
  (when-let [sh (:shell-node mesh-node)]
    (try (core/stop-node sh) (catch Exception _ nil)))
  true)

(defn start-mesh-node!
  "Starts a full Bitecho mesh node."
  ([config]
   (start-mesh-node! config {}))
  ([config opts]
   (let [node-id (or (:node/id config) (:node-id config) :node-1)
         state-dir (or (:state-dir config) "data")
         identity (or (:identity opts) (identity/load-or-create-node-identity! state-dir node-id))
         transport (or (:transport opts) (:transport config) :datachannel)
         snapshot-file (str (io/file state-dir "state" (str "snapshot-" (name node-id) ".edn")))
         loaded-state (or (when-let [f (:snapshot-file opts)] (persistence/load-state-from-disk f))
                          (when (.exists (io/file snapshot-file)) (persistence/load-state-from-disk snapshot-file)))
         initial-state (if loaded-state
                         (rebind-restored-state loaded-state config identity)
                         (build-initial-node-state config identity))
         shell-node (core/start-node initial-state snapshot-file {:persist? (get opts :persist? true)})
         peer-conns (atom {})
         agent-conns (atom {})
         cluster-cfg (get config :cluster {})
         nodes-cfg (get cluster-cfg :nodes {})
         sorted-ids (vec (sort-by name (keys nodes-cfg)))
         node-idx (into {} (map-indexed (fn [i k] [k i]) sorted-ids))
         ctx {:node-id node-id
              :identity identity
              :transport transport
              :shell-node shell-node
              :peer-conns peer-conns
              :agent-conns agent-conns
              :in-mem-bus in-memory-bus
              :node-idx node-idx
              :nodes-cfg nodes-cfg}]
     (if (= transport :in-memory)
       (swap! in-memory-bus assoc (:pubkey-hex identity) {:node-id node-id :network-in (:network-in shell-node)})
       (doseq [[pid pcfg] nodes-cfg :when (not= pid node-id)]
         (try
           (init-datachannel-peer! ctx pid pcfg)
           (catch Exception e
             (log-mesh-error (str "Failed to initialize peer " pid) e)))))
     (start-net-out-loop! ctx)
     (let [tick-interval (or (get-in config [:protocol :tick-interval-ms])
                             (get-in initial-state [:config :tick-interval-ms])
                             (:tick-interval-ms config/devnet-config)
                             10000)
           ticker (start-ticker! ctx tick-interval)
           agent-listener (init-agent-listener! config identity shell-node transport agent-conns)
           agent-tcp-listener (init-agent-tcp-listener! config identity shell-node transport agent-conns)
           http-server (start-http-server! (get config :http {})
                                           ctx
                                           (count (disj (set (keys nodes-cfg)) node-id))
                                           initial-state)
           node-map {:node-id node-id
                     :identity identity
                     :transport transport
                     :shell-node shell-node
                     :state-atom (:state-atom shell-node)
                     :peer-conns peer-conns
                     :agent-conns agent-conns
                     :http-server http-server
                     :ticker-executor ticker
                     :agent-listener agent-listener
                     :agent-tcp-listener agent-tcp-listener
                     :config config}]
       (assoc node-map :stop! #(stop-mesh-node! node-map))))))
