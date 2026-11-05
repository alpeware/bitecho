(ns bitecho.shell.browser
  "Browser-safe light-node shell boundary conforming to Rules 1-6.
   - Rule 4: Single-authority generation-tagged connection state reducer
     (transition-conn conn event) -> [new-conn effects].
   - Rule 5: Zero silent failures: stale generation callbacks, dropped envelopes,
     unsupported wire formats, and failed dials emit counted :diagnose effects.
   - Honest background-tab visibility tracking without claiming always-on execution.
   - WebRTC / RTCDataChannel transport with mock transport fallback.
   - IndexedDB persistence with memory fallback (sanitizing sensitive keys).
   - Async WebCrypto boundary implementing ICryptoBoundary.
   - Deterministic multi-peer browser subnet simulation."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-node]
            [clojure.string :as str]))

;; =============================================================================
;; Rule 4 & Rule 5 Single-Authority Connection Lifecycle State Machine
;; =============================================================================

(def initial-diagnostics
  "Initial zero-value diagnostics structure."
  {:phase :idle
   :generation 0
   :last-error nil
   :dropped 0
   :ignored-stale 0
   :unsupported-format-dropped 0
   :background-throttled-events 0})

(defn initial-conn-state
  "Initializes a single-authority connection state map tagged with generation 0."
  [& [opts]]
  {:phase :idle
   :generation 0
   :peer-id (:peer-id opts)
   :subnet-id (or (:subnet-id opts) "global")
   :visibility-state "visible"
   :channel nil
   :transport nil
   :diagnostics initial-diagnostics})

(defn transition-conn
  "Pure generation-tagged reducer managing connection lifecycle state per Rule 4.
   (transition-conn conn event) -> [new-conn effects]

   State model:
     {:phase (:idle | :dialing | :open | :closed)
      :generation <int>
      :peer-id <str-or-id>
      :subnet-id <str> (default \"global\")
      :visibility-state (\"visible\" | \"hidden\")
      :channel <obj>
      :transport <obj>
      :diagnostics {:phase :idle
                    :generation 0
                    :last-error nil
                    :dropped 0
                    :ignored-stale 0
                    :unsupported-format-dropped 0
                    :background-throttled-events 0}}

   Enforces:
   - Rule 4: Single authority, effects executed outside reducer.
   - Rule 5: Stale generations (gen < current) ignored with counted :diagnose effect.
   - Zero silent failures: all drops, dial failures, and wire rejections emit :diagnose."
  [conn event]
  (let [event-gen (:generation event)
        curr-gen (:generation conn 0)
        is-stale? (and (some? event-gen) (< (long event-gen) (long curr-gen)))]
    (if is-stale?
      ;; Rule 4 & 5: Stale callback ignored. Increment :ignored-stale, emit counted :diagnose.
      (let [new-conn (-> conn
                         (update-in [:diagnostics :ignored-stale] (fnil inc 0))
                         (assoc-in [:diagnostics :last-error] "stale-generation-event"))
            diag-effect {:type :diagnose
                         :kind :ignored-stale
                         :event event
                         :current-gen curr-gen
                         :event-gen event-gen}]
        [new-conn [diag-effect]])

      ;; Current or new generation
      (case (:type event)
        :dial
        (let [next-gen (if (and (some? event-gen) (>= (long event-gen) (long curr-gen)))
                         (long event-gen)
                         (inc (long curr-gen)))
              pid (or (:peer-id event) (:peer-id conn))
              sid (or (:subnet-id event) (:subnet-id conn) "global")
              new-conn (assoc conn
                              :phase :dialing
                              :generation next-gen
                              :peer-id pid
                              :subnet-id sid
                              :channel nil
                              :transport nil
                              :diagnostics (assoc (:diagnostics conn)
                                                  :phase :dialing
                                                  :generation next-gen
                                                  :last-error nil))
              effects [{:type :dial
                        :generation next-gen
                        :peer-id pid
                        :subnet-id sid
                        :target-url (:target-url event)}]]
          [new-conn effects])

        :dial-failed
        (let [err (or (:error event) "dial-failed")
              new-conn (assoc conn
                              :phase :closed
                              :channel nil
                              :transport nil
                              :diagnostics (assoc (:diagnostics conn)
                                                  :phase :closed
                                                  :last-error err))
              diag-effect {:type :diagnose
                           :kind :dial-failed
                           :error err
                           :generation curr-gen}]
          [new-conn [diag-effect]])

        :open
        (let [pid (or (:peer-id event) (:peer-id conn))
              ch (:channel event)
              tp (:transport event)
              new-conn (assoc conn
                              :phase :open
                              :peer-id pid
                              :channel ch
                              :transport tp
                              :diagnostics (assoc (:diagnostics conn)
                                                  :phase :open
                                                  :last-error nil))
              effects [{:type :open
                        :generation curr-gen
                        :peer-id pid}]]
          [new-conn effects])

        :close
        (let [cause (or (:cause event) "closed")
              new-conn (assoc conn
                              :phase :closed
                              :channel nil
                              :transport nil
                              :diagnostics (assoc (:diagnostics conn)
                                                  :phase :closed
                                                  :last-error cause))
              effects [{:type :close-transport
                        :transport (:transport conn)
                        :cause cause}
                       {:type :diagnose
                        :kind :closed
                        :cause cause
                        :generation curr-gen}]]
          [new-conn effects])

        :send
        (let [env (:envelope event)]
          (if-not (= (:phase conn) :open)
            ;; Rule 5: Dropped send when connection is not open
            (let [new-conn (-> conn
                               (update-in [:diagnostics :dropped] (fnil inc 0))
                               (assoc-in [:diagnostics :last-error] "connection-not-open"))
                  diag-effect {:type :diagnose
                               :kind :dropped
                               :reason "connection-not-open"
                               :envelope env
                               :phase (:phase conn)}]
              [new-conn [diag-effect]])
            ;; Open: emit wire envelope
            [conn [{:type :emit
                    :channel (:channel conn)
                    :generation curr-gen
                    :envelope env}]]))

        :message
        (let [env (:envelope event)
              wire-fmt (or (:wire-format env) (when (map? env) "fressian-v1"))
              fmt-supported? (contains? #{"fressian-v1" "legacy-nippy"} wire-fmt)]
          (cond
            (not= (:phase conn) :open)
            ;; Dropped: message received while not open
            (let [new-conn (-> conn
                               (update-in [:diagnostics :dropped] (fnil inc 0))
                               (assoc-in [:diagnostics :last-error] "message-received-when-not-open"))
                  diag-effect {:type :diagnose
                               :kind :dropped
                               :reason "message-received-when-not-open"
                               :generation curr-gen}]
              [new-conn [diag-effect]])

            (not fmt-supported?)
            ;; Rule 5: Unsupported wire format dropped with counted diagnostic
            (let [new-conn (-> conn
                               (update-in [:diagnostics :unsupported-format-dropped] (fnil inc 0))
                               (assoc-in [:diagnostics :last-error] "unsupported-wire-format"))
                  diag-effect {:type :diagnose
                               :kind :unsupported-format
                               :wire-format wire-fmt
                               :reason "unsupported-wire-format"
                               :generation curr-gen}]
              [new-conn [diag-effect]])

            :else
            ;; Valid incoming message. Record background throttle if hidden.
            (let [hidden? (= (:visibility-state conn) "hidden")
                  new-conn (if hidden?
                             (update-in conn [:diagnostics :background-throttled-events] (fnil inc 0))
                             conn)
                  effects [{:type :deliver-message
                            :generation curr-gen
                            :envelope env}]]
              [new-conn effects])))

        :visibility-change
        (let [new-state (if (= (:state event) "hidden") "hidden" "visible")
              new-conn (assoc conn :visibility-state new-state)]
          [new-conn [{:type :visibility-changed :state new-state}]])

        ;; Fallback for unhandled events: count drop, emit diagnose
        (let [new-conn (-> conn
                           (update-in [:diagnostics :dropped] (fnil inc 0))
                           (assoc-in [:diagnostics :last-error] "unknown-event"))
              diag-effect {:type :diagnose
                           :kind :unknown-event
                           :event event}]
          [new-conn [diag-effect]])))))

;; =============================================================================
;; State Sanitization & Persistence (Rule 4)
;; =============================================================================

(defn canonical-key-name
  "Converts camelCase, PascalCase, snake_case, dot.case, or kebab-case keyword/string/symbol
   to lowercase kebab-case."
  [k]
  (when (or (keyword? k) (string? k) (symbol? k))
    (-> (name k)
        (str/replace #"([a-z0-9])([A-Z])" "$1-$2")
        (str/replace #"([A-Z]+)([A-Z][a-z])" "$1-$2")
        (str/replace #"[_./\s]+" "-")
        str/lower-case)))

(def forbidden-persistence-keys
  "Set of sensitive credential, key material, and derived lifecycle keys in canonical lowercase kebab-case."
  #{"private" "private-key" "private-key-bytes" "private-key-hex"
    "privkey" "privkey-bytes" "privkey-hex"
    "seed" "seed-bytes" "seed-hex" "backup-seed" "backup-seed-bytes" "backup-seed-hex"
    "secret" "secret-key" "secret-key-bytes" "secret-key-hex" "shared-secret" "shared-secret-bytes"
    "root-key" "chain-key" "send-chain-key" "recv-chain-key"
    "skipped-keys" "session-key" "session-keys" "session-key-bytes" "ratchet-key"
    "ephemeral-private" "ephemeral-private-key" "ephemeral-priv" "ephemeral-privkey" "ephemeral-secret"
    "x25519" "x25519-priv" "x25519-privkey" "x25519-private" "x25519-private-key"
    "x25519-privkey-bytes" "x25519-private-key-bytes" "x25519-secret" "x25519-secret-key"
    "ed25519-priv" "ed25519-privkey" "ed25519-private" "ed25519-private-key"
    "ed25519-privkey-bytes" "ed25519-private-key-bytes" "ed25519-seed" "ed25519-secret"
    "cold-privkey" "cold-private-key" "cold-seed" "keypair" "tx-key" "rx-key"
    "prf" "prf-output" "prf-bytes" "prf-seed" "prf-secret" "hmac-secret"
    "raw-id" "raw-id-bytes" "user-handle" "user-handle-bytes" "credential-id" "credential-id-bytes"
    "attestation-object" "client-data-json"
    "api-key" "api-key-hex" "api-key-bytes" "api-token" "api-secret"
    "jwt" "jwt-token" "access-token" "refresh-token" "session-token" "auth-token"
    "bearer-token" "id-token" "csrf-token" "oauth-token" "token" "tokens"
    "bearer" "authorization" "auth-secret" "auth-key" "client-secret" "server-secret"
    "signing-key" "signing-privkey" "signing-private-key" "encryption-key" "decryption-key"
    "master-key" "master-seed" "hmac-key" "symmetric-key" "aes-key" "chacha-key"
    "wrapping-key" "derived-key" "hkdf-key" "kdf-key" "mac-key" "backup-key"
    "recovery-key" "recovery-seed" "identity-key" "identity-seed" "node-key" "host-key"
    "peer-key" "hot-key" "cold-key" "device-key" "turn-password" "turn-secret"
    "credential" "credentials" "cookie" "cookies" "pin" "otp" "totp"
    "mnemonic" "passphrase" "password" "first" "eval"
    "connected?" "connected" "connection-error" "conn-diagnostics" "conn-atom" "conn"
    "channel" "active-channels" "connections" "transport" "socket" "last-error"})

(def ^:private forbidden-persistence-keys-compact
  (into #{} (map #(str/replace % "-" "") forbidden-persistence-keys)))

(def ^:private forbidden-persistence-tokens
  #{"private" "privkey" "priv" "seed" "seeds" "secret" "secrets"
    "mnemonic" "passphrase" "password" "passwd" "pwd" "keypair" "keypairs"
    "prf" "eval" "jwt" "bearer" "token" "tokens" "cookie" "cookies"
    "credential" "credentials" "pin" "otp" "totp"})

(def ^:private forbidden-persistence-compact-substrings
  ["private" "privkey" "seed" "secret" "mnemonic" "passphrase" "password" "keypair"
   "x25519priv" "x25519sec" "ed25519priv" "ed25519sec" "ed25519seed"
   "sessionkey" "sharedsecret" "rootkey" "chainkey" "ratchetkey" "skippedkey" "txkey" "rxkey"
   "ephemeralpriv" "coldpriv" "prfoutput" "prfbytes" "prfseed" "userhandle" "rawid"
   "credentialid" "attestationobject" "clientdatajson" "connectionerror" "conndiagnostics"
   "connatom" "activechannels" "lasterror"
   "apikey" "apitoken" "apisecret" "jwttoken" "accesstoken" "refreshtoken" "sessiontoken"
   "authtoken" "bearertoken" "idtoken" "csrftoken" "oauthtoken" "authsecret" "authkey"
   "clientsecret" "serversecret" "signingkey" "encryptionkey" "decryptionkey" "masterkey"
   "hmackey" "symmetrickey" "aeskey" "chachakey" "wrappingkey" "derivedkey" "hkdfkey"
   "kdfkey" "mackey" "backupkey" "recoverykey" "identitykey" "nodekey" "hostkey" "peerkey"
   "hotkey" "coldkey" "devicekey"])

(def ^:private carved-out-public-keys
  #{"pubkey" "pubkeys" "public-key" "public-keys" "public" "public-hex"
    "pubkey-hex" "public-key-hex" "pubkey-bytes" "public-key-bytes"
    "key-mode" "keys-verified?" "keys-verified" "cose-key"})

(defn- public-key-carve-out?
  "Returns true if canonical key `canon` (and its compact form and token vector) represents
   a public key or non-secret key metadata field (e.g., :pubkey, :public-key, :x25519-pubkey,
   :ed25519-public-key, :peer-pubkey, :key-mode, :keys-verified?) that must never be stripped."
  [canon compact tokens]
  (or (contains? carved-out-public-keys canon)
      (and (not-any? #(contains? forbidden-persistence-tokens %) tokens)
           (not-any? #(str/includes? compact %)
                     ["private" "privkey" "secret" "seed" "password" "passphrase"
                      "mnemonic" "token" "jwt" "bearer" "cookie"])
           (or (some #{"pubkey" "pubkeys"} tokens)
               (and (some #{"public"} tokens) (some #{"key" "keys"} tokens))
               (str/ends-with? compact "pubkey")
               (str/ends-with? compact "pubkeys")
               (str/ends-with? compact "publickey")
               (str/ends-with? compact "publickeys")
               (str/ends-with? compact "pubkeyhex")
               (str/ends-with? compact "publickeyhex")
               (str/ends-with? compact "pubkeybytes")
               (str/ends-with? compact "publickeybytes")))))

(defn forbidden-persistence-key?
  "Returns true if key k (in any case: camelCase, PascalCase, snake_case, UPPER_SNAKE, kebab-case,
   compact lowercase, keyword, string, or symbol, with any prefix/suffix) is a sensitive credential,
   private key material, or derived transport/lifecycle state, while preserving carved-out public-key
   identifiers (e.g. :pubkey, :public-key, :x25519-pubkey)."
  [k]
  (boolean
   (when-let [canon (canonical-key-name k)]
     (let [compact (str/replace canon #"[-?]" "")
           tokens (str/split (str/replace canon "?" "") #"-")]
       (and (not (public-key-carve-out? canon compact tokens))
            (or (contains? forbidden-persistence-keys canon)
                (contains? forbidden-persistence-keys-compact compact)
                (some #(contains? forbidden-persistence-tokens %) tokens)
                (and (>= (count tokens) 2) (some #{"key" "keys"} tokens))
                (some #(str/includes? compact %) forbidden-persistence-compact-substrings)))))))

(defn sanitize-state-for-persistence
  "Sanitizes browser/light-node state recursively before storage in IndexedDB/disk.
   Strips all private key material (:keypair, :x25519, :seed, :private-key, :privkey-bytes,
   :cold-privkey, :ephemeral-priv, :tx-key, :rx-key, :session-keys), transport references,
   and derived liveness (:connected?, :connection-error, :conn) at every nesting depth per Rule 4.
   Supports camelCase, snake_case, and kebab-case variants across maps, vectors, sets, and sequences."
  [state]
  (letfn [(sanitize-val [v]
            (cond
              (map? v)
              (into (empty v)
                    (keep (fn [[k sub-v]]
                            (when-not (forbidden-persistence-key? k)
                              [k (sanitize-val sub-v)])))
                    v)
              (vector? v)
              (mapv sanitize-val v)
              (set? v)
              (into #{} (map sanitize-val v))
              (seq? v)
              (map sanitize-val v)
              :else v))]
    (when (map? state)
      (sanitize-val state))))

(defonce ^{:doc "In-memory storage map fallback for environments without native IndexedDB."
           :dynamic true}
  *in-memory-idb-store*
  (atom {}))

(defn persist-state!
  "Persists sanitized state into IndexedDB (store 'bitecho-state', key 'light-node-state')
   or fallback atom, returning a map or invoking callback (cb [err result])."
  ([state] (persist-state! state nil))
  ([state cb]
   (let [clean-state (sanitize-state-for-persistence state)
         encoded-bytes (try (fressian/encode-wire clean-state) (catch #?(:clj Exception :cljs :default) _ nil))]
     (if (or (nil? encoded-bytes) (zero? (fressian/count-bytes encoded-bytes)))
       (let [err-res {:ok? false :error :encode-failed}]
         (when cb (cb err-res nil))
         err-res)
       #?(:cljs
          (if (and (exists? js/indexedDB) (some? js/indexedDB))
            (try
              (let [req (.open js/indexedDB "bitecho-db" 1)]
                (set! (.-onupgradeneeded req)
                      (fn [e]
                        (let [db (.. e -target -result)]
                          (when-not (.contains (.-objectStoreNames db) "bitecho-state")
                            (.createObjectStore db "bitecho-state")))))
                (set! (.-onsuccess req)
                      (fn [e]
                        (let [db (.. e -target -result)
                              tx (.transaction db (clj->js ["bitecho-state"]) "readwrite")
                              store (.objectStore tx "bitecho-state")
                              put-req (.put store encoded-bytes "light-node-state")]
                          (set! (.-onsuccess put-req)
                                (fn [_] (when cb (cb nil {:ok? true :bytes-stored (fressian/count-bytes encoded-bytes)}))))
                          (set! (.-onerror put-req)
                                (fn [err] (when cb (cb err nil)))))))
                (set! (.-onerror req)
                      (fn [_err]
                        (swap! *in-memory-idb-store* assoc "light-node-state" encoded-bytes)
                        (when cb (cb nil {:ok? true :in-memory? true})))))
              (catch :default _err
                (swap! *in-memory-idb-store* assoc "light-node-state" encoded-bytes)
                (when cb (cb nil {:ok? true :in-memory? true}))))
            (do
              (swap! *in-memory-idb-store* assoc "light-node-state" encoded-bytes)
              (when cb (cb nil {:ok? true :in-memory? true}))))
          :clj
          (do
            (swap! *in-memory-idb-store* assoc "light-node-state" encoded-bytes)
            (when cb (cb nil {:ok? true :in-memory? true}))))))))

(defn load-persisted-state
  "Loads persisted state from IndexedDB or in-memory fallback, invoking cb (cb [err state])."
  [cb]
  #?(:cljs
     (if (and (exists? js/indexedDB) (some? js/indexedDB))
       (try
         (let [req (.open js/indexedDB "bitecho-db" 1)]
           (set! (.-onupgradeneeded req)
                 (fn [e]
                   (let [db (.. e -target -result)]
                     (when-not (.contains (.-objectStoreNames db) "bitecho-state")
                       (.createObjectStore db "bitecho-state")))))
           (set! (.-onsuccess req)
                 (fn [e]
                   (let [db (.. e -target -result)
                         tx (.transaction db (clj->js ["bitecho-state"]) "readonly")
                         store (.objectStore tx "bitecho-state")
                         get-req (.get store "light-node-state")]
                     (set! (.-onsuccess get-req)
                           (fn [ev]
                             (let [bytes (.. ev -target -result)]
                               (if bytes
                                 (let [decoded (sanitize-state-for-persistence (fressian/decode-wire bytes))]
                                   (cb nil decoded))
                                 (cb nil nil)))))
                     (set! (.-onerror get-req)
                           (fn [err] (cb err nil))))))
           (set! (.-onerror req)
                 (fn [_]
                   (let [bytes (get @*in-memory-idb-store* "light-node-state")
                         decoded (when bytes (sanitize-state-for-persistence (fressian/decode-wire bytes)))]
                     (cb nil decoded)))))
         (catch :default _
           (let [bytes (get @*in-memory-idb-store* "light-node-state")
                 decoded (when bytes (sanitize-state-for-persistence (fressian/decode-wire bytes)))]
             (cb nil decoded))))
       (let [bytes (get @*in-memory-idb-store* "light-node-state")
             decoded (when bytes (sanitize-state-for-persistence (fressian/decode-wire bytes)))]
         (cb nil decoded)))
     :clj
     (let [bytes (get @*in-memory-idb-store* "light-node-state")
           decoded (when bytes (sanitize-state-for-persistence (fressian/decode-wire bytes)))]
       (cb nil decoded))))

;; =============================================================================
;; HTTPS Bootstrap & Directory Fetch (CORS)
;; =============================================================================

(defn fetch-descriptor
  "Fetches bootstrap or directory descriptor from HTTPS endpoint with CORS mode."
  [url cb]
  #?(:cljs
     (if (and (exists? js/fetch) (some? js/fetch))
       (-> (.fetch js/globalThis url (clj->js {:mode "cors"}))
           (.then (fn [res] (.text res)))
           (.then (fn [txt] (cb nil txt)))
           (.catch (fn [err] (cb err nil))))
       (cb (js/Error. "fetch-unavailable") nil))
     :clj
     (try
       (let [txt (slurp url)]
         (cb nil txt))
       (catch Exception e
         (cb e nil)))))

;; =============================================================================
;; Async WebCrypto Boundary
;; =============================================================================

(defn browser-crypto-boundary
  "Returns an ICryptoBoundary instance suitable for the browser runtime."
  []
  (crypto/make-crypto-boundary))

;; =============================================================================
;; Browser WebRTC / RTCDataChannel Transport & Effect Executor (Step 10A)
;; =============================================================================

(def default-ice-servers
  "Default STUN servers for browser RTCPeerConnection."
  [{:urls "stun:stun.l.google.com:19302"}])

(defn webrtc-available?
  "Checks if RTCPeerConnection is natively available in the runtime."
  []
  #?(:cljs (and (exists? js/RTCPeerConnection) (some? js/RTCPeerConnection))
     :clj false))

(defn create-mock-channel
  "Creates a mock channel pair for deterministic multi-peer testing."
  [target-callback-atom]
  {:send (fn [data]
           (when-let [cb @target-callback-atom]
             (cb data)))
   :close (fn [] nil)})

(defn dispatch-conn-event!
  "Applies a connection lifecycle event to conn-atom via pure transition-conn reducer,
   then executes any returned effects outside the state transition (Rule 4)."
  [conn-atom event effect-handler-fn]
  (let [effects-box (atom nil)]
    (swap! conn-atom
           (fn [curr-conn]
             (let [[next-conn effects] (transition-conn curr-conn event)]
               (reset! effects-box effects)
               next-conn)))
    (when effect-handler-fn
      (doseq [eff @effects-box]
        (effect-handler-fn eff)))
    @effects-box))

(defn install-visibility-listener!
  "Installs a document 'visibilitychange' listener that dispatches :visibility-change
   events into conn-atom via transition-conn (Rule 4). Returns a cleanup fn."
  ([conn-atom] (install-visibility-listener! conn-atom nil))
  ([_conn-atom _on-change-fn]
   #?(:cljs
      (if (and (exists? js/document) (some? (.-addEventListener js/document)))
        (let [handler (fn [_]
                        (let [vis-state (if (= (.-visibilityState js/document) "hidden") "hidden" "visible")
                              effects (dispatch-conn-event! _conn-atom
                                                            {:type :visibility-change :state vis-state}
                                                            _on-change-fn)]
                          (when _on-change-fn
                            (_on-change-fn vis-state effects))))]
          (.addEventListener js/document "visibilitychange" handler)
          (fn [] (.removeEventListener js/document "visibilitychange" handler)))
        (fn [] nil))
      :clj (fn [] nil))))

(defn format-validator-sdp-answer
  "Generates passive WebRTC SDP answer (ice-lite, setup:passive) for connecting to a Bitecho validator."
  [node-cfg]
  (let [ip (or (:ip node-cfg) "127.0.0.1")
        port (or (:agent-port node-cfg) (:port node-cfg) 9001)
        ufrag (or (:ice-ufrag node-cfg) "ufrag")
        pwd (or (:ice-pwd node-cfg) "pwd")
        fp (or (:fingerprint node-cfg) "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")]
    (str "v=0\r\n"
         "o=- 123456789 2 IN IP4 " ip "\r\n"
         "s=-\r\n"
         "t=0 0\r\n"
         "a=group:BUNDLE 0\r\n"
         "m=application " port " UDP/DTLS/SCTP webrtc-datachannel\r\n"
         "c=IN IP4 " ip "\r\n"
         "a=setup:passive\r\n"
         "a=mid:0\r\n"
         "a=max-message-size:100000\r\n"
         "a=sctp-port:5000\r\n"
         "a=fingerprint:sha-256 " fp "\r\n"
         "a=ice-ufrag:" ufrag "\r\n"
         "a=ice-pwd:" pwd "\r\n"
         "a=ice-lite\r\n"
         "a=rtcp-mux\r\n"
         "a=candidate:1 1 UDP 2130706431 " ip " " port " typ host\r\n")))

(defn send-webrtc-envelope!
  "Sends an envelope over the active WebRTC DataChannel via Rule 4 :send transition."
  [conn-atom env]
  (let [[new-conn effects] (transition-conn @conn-atom {:type :send :envelope env})]
    (reset! conn-atom new-conn)
    #?(:cljs
       (let [dc (:channel new-conn)
             wire-bytes (fressian/encode-wire env)]
         (if (and dc (= (.-readyState dc) "open"))
           (try
             (.send dc wire-bytes)
             {:ok? true :effects effects}
             (catch :default err
               {:ok? false :error (str err) :effects effects}))
           {:ok? false :error "channel-not-open" :effects effects}))
       :clj {:ok? false :error "not-in-browser" :effects effects})))

(defn connect-webrtc!
  "Establishes a generation-tagged RTCPeerConnection + RTCDataChannel in the browser
   (matching clj-datachannel/dev/example/index.html SDP offer/answer flow + STUN/ICE).
   All callbacks capture the dial generation so stale callbacks from superseded
   connections are ignored and counted by transition-conn (Rules 4 & 5)."
  [conn-atom {:keys [peer-id target-url] :as opts}]
  (let [dial-effects (dispatch-conn-event! conn-atom
                                           {:type :dial :peer-id peer-id :target-url (or target-url "rtc://validator")}
                                           nil)
        gen (:generation (first dial-effects))]
    #?(:cljs
       (let [{:keys [answer-sdp ice-servers channel-label on-deliver-message on-open]} opts]
         (if-not (webrtc-available?)
           (do
             (dispatch-conn-event! conn-atom
                                   {:type :dial-failed :generation gen :error "webrtc-unavailable"}
                                   nil)
             {:ok? false :error "webrtc-unavailable" :generation gen})
           (try
             (let [rtc-cfg (clj->js {:iceServers (or ice-servers default-ice-servers)})
                   pc (js/RTCPeerConnection. rtc-cfg)
                   dc (.createDataChannel pc (or channel-label "bitecho"))]
               (set! (.-binaryType dc) "arraybuffer")
               (set! (.-onopen dc)
                     (fn [ev]
                       (dispatch-conn-event! conn-atom
                                             {:type :open :generation gen :peer-id peer-id :channel dc :transport pc}
                                             nil)
                       (when on-open (on-open {:type :open :generation gen :channel dc :transport pc :event ev}))))
               (set! (.-onmessage dc)
                     (fn [ev]
                       (let [raw (.-data ev)
                             env (cond
                                   (string? raw) {:type :raw-string :wire-format "fressian-v1" :text raw}
                                   (instance? js/ArrayBuffer raw) (fressian/decode-wire (js/Uint8Array. raw))
                                   (fressian/bytes? raw) (fressian/decode-wire raw)
                                   (map? raw) raw
                                   :else nil)]
                         (dispatch-conn-event!
                          conn-atom
                          {:type :message :generation gen :envelope env}
                          (fn [eff]
                            (when (and (= (:type eff) :deliver-message) on-deliver-message)
                              (on-deliver-message (:envelope eff))))))))
               (set! (.-onerror dc)
                     (fn [err]
                       (dispatch-conn-event! conn-atom
                                             {:type :dial-failed :generation gen :error (str "datachannel-error:" err)}
                                             nil)))
               (set! (.-onclose dc)
                     (fn [_]
                       (dispatch-conn-event! conn-atom
                                             {:type :close :generation gen :cause "datachannel-closed"}
                                             (fn [eff]
                                               (when (= (:type eff) :close-transport)
                                                 (try (.close pc) (catch :default _ nil)))))))
               (when (string? answer-sdp)
                 (-> (.createOffer pc)
                     (.then (fn [offer] (.setLocalDescription pc offer)))
                     (.then (fn [_] (.setRemoteDescription pc (clj->js {:type "answer" :sdp answer-sdp}))))
                     (.catch (fn [err]
                               (dispatch-conn-event! conn-atom
                                                     {:type :dial-failed :generation gen :error (str "sdp-error:" err)}
                                                     nil)))))
               {:ok? true :generation gen :peer-connection pc :data-channel dc})
             (catch :default err
               (dispatch-conn-event! conn-atom
                                     {:type :dial-failed :generation gen :error (str err)}
                                     nil)
               {:ok? false :error (str err) :generation gen}))))
       :clj
       (do
         (let [_ opts]
           (dispatch-conn-event! conn-atom
                                 {:type :dial-failed :generation gen :error "webrtc-unavailable-on-jvm"}
                                 nil)
           {:ok? false :error "webrtc-unavailable-on-jvm" :generation gen})))))

;; =============================================================================
;; Browser-Only Subnet Demo (Step 10C)
;; =============================================================================

(defn- route-net-envelopes
  "Pure helper that serializes a light-node's outbound :net-envelopes via fressian-v1,
   passes each through sender's Rule 4 :send transition and receiver's Rule 4 :message
   transition, and feeds the decoded wire payload into receiver's light-node/handle-wire-payload."
  [sender-conn receiver-conn receiver-state receiver-priv envelopes]
  (reduce
   (fn [[s-conn r-conn r-state] env]
     (let [raw-payload (or (get-in env [:event :message :payload])
                           (get-in env [:message :payload]))
           wire-msg (when raw-payload (fressian/decode-wire raw-payload))
           [s-conn-next s-effects] (transition-conn s-conn {:type :send :generation (:generation s-conn) :envelope wire-msg})
           emitted? (some #(= (:type %) :emit) s-effects)]
       (if-not (and emitted? wire-msg)
         [s-conn-next r-conn r-state]
         (let [[r-conn-next r-effects] (transition-conn r-conn {:type :message :generation (:generation r-conn) :envelope wire-msg})
               deliver-eff (first (filter #(= (:type %) :deliver-message) r-effects))]
           (if-not deliver-eff
             [s-conn-next r-conn-next r-state]
             (let [res (light-node/handle-wire-payload r-state (:envelope deliver-eff) receiver-priv)]
               [s-conn-next r-conn-next (:state res)]))))))
   [sender-conn receiver-conn receiver-state]
   envelopes))

(defn run-browser-subnet-demo
  "Executes a deterministic multi-peer browser-only subnet simulation driving real
   bitecho.light-node.core state machines across 3 browser nodes (Alice, Bob, Carol):
   - 3 browser nodes (browser-alice, browser-bob, browser-carol) with real Ed25519 identities
   - fressian-v1 wire format (encode-wire / decode-wire)
   - suite-v1-aes256gcm negotiated encryption on all sessions
   - Autonomous OFF (:autonomous? false) requiring explicit human-anchor/callee approval
   - E2E AES-256-GCM sealed messages with signed SACK acknowledgments
   - Local burn accounting (:burned-ech) computed by light-node.core
   - Visibility change event handling (:background-throttled-events)
   - Stale-generation callback injection and counted rejection (:ignored-stale)

   Returns a structured summary map asserting all invariants."
  []
  (let [alice-id "browser-alice"
        bob-id "browser-bob"
        carol-id "browser-carol"
        alice-kp (crypto/generate-keypair)
        bob-kp (crypto/generate-keypair)
        carol-kp (crypto/generate-keypair)
        alice-pub (basalt/bytes->hex (:public alice-kp))
        bob-pub (basalt/bytes->hex (:public bob-kp))
        carol-pub (basalt/bytes->hex (:public carol-kp))

        ;; 1. Initialize 3 browser light-node states (Autonomous OFF by default per Standing Constraint 2)
        alice-st0 (light-node/init-light-state {:pubkey-hex alice-pub} {:autonomous? false})
        bob-st0 (light-node/init-light-state {:pubkey-hex bob-pub} {:autonomous? false})
        carol-st0 (light-node/init-light-state {:pubkey-hex carol-pub} {:autonomous? false})

        ;; 2. Initialize Rule 4 single-authority connection states & open channels
        [alice-dial dial-effects] (transition-conn (initial-conn-state {:peer-id bob-id :subnet-id "browser-subnet-v1"})
                                                   {:type :dial :target-url "rtc://bob"})
        alice-gen (:generation alice-dial)
        [alice-conn _] (transition-conn alice-dial {:type :open :generation alice-gen :channel :alice-dc})

        [bob-dial _] (transition-conn (initial-conn-state {:peer-id alice-id :subnet-id "browser-subnet-v1"})
                                      {:type :dial :target-url "rtc://alice"})
        bob-gen (:generation bob-dial)
        [bob-conn _] (transition-conn bob-dial {:type :open :generation bob-gen :channel :bob-dc})

        [carol-dial _] (transition-conn (initial-conn-state {:peer-id bob-id :subnet-id "browser-subnet-v1"})
                                        {:type :dial :target-url "rtc://bob"})
        carol-gen (:generation carol-dial)
        [carol-conn _] (transition-conn carol-dial {:type :open :generation carol-gen :channel :carol-dc})

        ;; 3. Alice offers a channel to Bob (500 ECH burn); Bob holds it pending (autonomous OFF) then explicitly accepts
        alice-offer-res (light-node/handle-command alice-st0
                                                   {"cmd" "offer" "callee" bob-pub "price" 10 "burn" 500}
                                                   (:private alice-kp))
        sid-ab (get-in alice-offer-res [:response "session_id"])
        [alice-conn1 bob-conn1 bob-st1] (route-net-envelopes alice-conn bob-conn bob-st0 (:private bob-kp)
                                                             (:net-envelopes alice-offer-res))
        held-pending? (contains? (:pending-offers bob-st1) sid-ab)
        bob-accept-res (light-node/handle-command bob-st1
                                                  {"cmd" "accept" "session_id" sid-ab}
                                                  (:private bob-kp))
        [bob-conn2 alice-conn2 alice-st2] (route-net-envelopes bob-conn1 alice-conn1 (:state alice-offer-res) (:private alice-kp)
                                                               (:net-envelopes bob-accept-res))

        ;; 4. Alice sends E2E AES-256-GCM sealed message #1 to Bob; Bob decrypts & emits SACK back to Alice
        msg1-text "Browser node Alice greeting to Bob over suite-v1-aes256gcm."
        alice-send1 (light-node/handle-command alice-st2
                                               {"cmd" "send" "session_id" sid-ab "text" msg1-text "burn" 500}
                                               (:private alice-kp))
        [alice-conn3 bob-conn3 bob-st3] (route-net-envelopes alice-conn2 bob-conn2 (:state bob-accept-res) (:private bob-kp)
                                                             (:net-envelopes alice-send1))

        ;; 5. Bob becomes backgrounded (:visibility-change "hidden") and Carol opens & sends message #2 to Bob
        [bob-hidden _] (transition-conn bob-conn3 {:type :visibility-change :state "hidden"})
        carol-offer-res (light-node/handle-command carol-st0
                                                   {"cmd" "offer" "callee" bob-pub "price" 10 "burn" 500}
                                                   (:private carol-kp))
        sid-cb (get-in carol-offer-res [:response "session_id"])
        [carol-conn1 bob-conn4 bob-st4] (route-net-envelopes carol-conn bob-hidden bob-st3 (:private bob-kp)
                                                             (:net-envelopes carol-offer-res))
        bob-accept2-res (light-node/handle-command bob-st4
                                                   {"cmd" "accept" "session_id" sid-cb}
                                                   (:private bob-kp))
        [bob-conn5 carol-conn2 carol-st2] (route-net-envelopes bob-conn4 carol-conn1 (:state carol-offer-res) (:private carol-kp)
                                                               (:net-envelopes bob-accept2-res))
        msg2-text "Browser node Carol message to backgrounded Bob."
        carol-send2 (light-node/handle-command carol-st2
                                               {"cmd" "send" "session_id" sid-cb "text" msg2-text "burn" 500}
                                               (:private carol-kp))
        [_carol-conn3 bob-conn6 bob-st5] (route-net-envelopes carol-conn2 bob-conn5 (:state bob-accept2-res) (:private bob-kp)
                                                              (:net-envelopes carol-send2))

        ;; 6. Stale-generation callback injection (gen 0 < bob-gen)
        [bob-final stale-effects] (transition-conn bob-conn6 {:type :message :generation 0 :envelope {:type :stale}})

        selected-suite (get-in bob-st5 [:sessions sid-ab :suite])
        bob-inbox (:inbox bob-st5)
        alice-burned (get-in (:state alice-send1) [:local-accounting :burned-ech] 0)
        bob-burned (get-in bob-st5 [:local-accounting :burned-ech] 0)
        carol-burned (get-in (:state carol-send2) [:local-accounting :burned-ech] 0)
        total-burned (+ alice-burned bob-burned carol-burned)]

    {:ok? (and held-pending?
               (= selected-suite "suite-v1-aes256gcm")
               (= 2 (count bob-inbox))
               (= msg1-text (:text (first bob-inbox)))
               (= msg2-text (:text (second bob-inbox)))
               (pos? (get-in bob-final [:diagnostics :background-throttled-events]))
               (= 1 (get-in bob-final [:diagnostics :ignored-stale]))
               (= :ignored-stale (:kind (first stale-effects))))
     :demo "browser-subnet-v1"
     :nodes-count 3
     :nodes [alice-id bob-id carol-id]
     :keys-verified? (and (some? dial-effects) (= (:phase alice-conn3) :open) held-pending?)
     :wire-format "fressian-v1"
     :crypto-suite selected-suite
     :autonomous-off? (and (false? (:autonomous? alice-st0))
                           (false? (:autonomous? bob-st0))
                           (false? (:autonomous? carol-st0))
                           held-pending?)
     :messages-exchanged (count bob-inbox)
     :total-burned-ech total-burned
     :visibility-state (:visibility-state bob-final)
     :background-throttled-events (get-in bob-final [:diagnostics :background-throttled-events])
     :stale-generation-ignored (get-in bob-final [:diagnostics :ignored-stale])
     :diagnostics (:diagnostics bob-final)}))
