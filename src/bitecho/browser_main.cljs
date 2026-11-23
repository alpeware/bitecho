(ns bitecho.browser-main
  "Bitecho Browser Node static bundle entry point.
   Exposes high-level browser API on js/globalThis.BitechoBrowser and unified CLI parity API
   on js/globalThis.BitechoLightNode conforming to Rules 1-6."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.bech32m :as bech32m]
            [bitecho.browser-cli :as browser-cli]
            [bitecho.config :as config]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.deploy.core :as deploy]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.net.relay-pool :as relay-pool]
            [bitecho.shell.browser :as browser]
            [bitecho.storage.chunk-constants :as chunk-const]
            [bitecho.storage.chunk-fetch :as chunk-fetch]
            [bitecho.webauthn :as webauthn]
            [cljs.reader :as edn]
            [clojure.string :as str]
            [goog.object :as gobj]))

(defonce
  ^{:doc "Global atom holding active Human Anchor state for browser UI."}
  anchor-state-atom
  (atom nil))

(defonce
  ^{:doc "Atom holding reference to the most recently created light node atom."}
  active-node-atom
  (atom nil))

(def default-authority-pubkey
  "Pinned Directory Authority public key for bitecho.org devnet."
  "302a300506032b657003210056b505baa32c3b99663d163d6ee00b5018a26e182405f5ec4d5062f12f633ce9")

(def default-bootstrap-nodes
  "Default bootstrap devnet validator nodes for browser WebRTC connection."
  {:node1 {:node-id "node1" :ip "35.212.129.138" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :ingress-host "node1.ingress.bitecho.org" :ingress-port 443 :pubkey "302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086" :fingerprint "95:09:40:3B:04:A0:B3:F5:88:26:51:CE:C9:A9:8E:0C:A1:15:92:8F:D5:7D:4A:11:A2:6C:3C:B0:0B:AB:0C:3B" :ice-ufrag "1ec0ae74" :ice-pwd "d928f1aac56a0d6e6fdda551"}
   :node2 {:node-id "node2" :ip "35.206.120.143" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :ingress-host "node2.ingress.bitecho.org" :ingress-port 443 :pubkey "302a300506032b6570032100592ab794dea07da278ef3853e8cc2d2f6ac5e3417eac80d93ab01e1fc61653ba" :fingerprint "F8:73:94:91:1D:7B:CA:66:D9:67:9E:4B:72:B0:D0:8D:5F:5C:37:0F:FE:04:2E:ED:86:E6:8D:79:B8:07:43:78" :ice-ufrag "18388497" :ice-pwd "20540a60217702b8869d7bf5"}
   :node3 {:node-id "node3" :ip "35.211.71.139" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :ingress-host "node3.ingress.bitecho.org" :ingress-port 443 :pubkey "302a300506032b65700321007b7f58652a2c26b4180aeee45ff12f927a45d92e00fc3462c5d854f6203351f1" :fingerprint "38:2B:18:4B:23:E8:F4:32:D7:08:5A:2A:A4:45:4F:EE:12:D4:51:B1:9B:2D:66:7C:2E:E1:2A:3E:7C:B3:60:40" :ice-ufrag "4b1d8fc5" :ice-pwd "47e794a9ed5ef04cc0ebbe7f"}
   :ns1 {:node-id "ns1" :ip "35.212.172.159" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :ingress-host "ns1.bitecho.org" :ingress-port 443 :pubkey "302a300506032b6570032100cd5be4b2c2f08ac78178db2e8f7d57ea3e01b09373a18a15c17f64294033ce3a" :fingerprint "3E:28:4A:2F:34:F4:4F:F2:18:3A:23:3C:9B:31:87:84:2C:C3:67:AF:B6:97:6A:32:1F:A5:0C:8B:96:EA:41:3B" :ice-ufrag "a1e0a80d" :ice-pwd "e9580acf2174e43d4d3535a6"}
   :ns2 {:node-id "ns2" :ip "35.209.253.119" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :ingress-host "ns2.bitecho.org" :ingress-port 443 :pubkey "302a300506032b6570032100e4e5921c1b4bd6444da44493d2e63fcb916b91dad7ad32f10e92d850c8ba501c" :fingerprint "BC:4A:35:74:3F:36:D1:7A:6F:84:23:E4:6E:82:7E:19:C2:88:4D:38:A1:A5:58:8E:F6:57:1D:D9:C8:1C:2B:63" :ice-ufrag "eb999287" :ice-pwd "0b041a7ac128edba260627d0"}
   :ns3 {:node-id "ns3" :ip "35.211.30.106" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :ingress-host "ns3.bitecho.org" :ingress-port 443 :pubkey "302a300506032b6570032100c9cee982d272e9761035aea742378daebf06e20bf1edead46254c8c8b0c90013" :fingerprint "08:7D:65:5E:C1:4E:43:B8:6A:B8:2B:61:36:DE:55:24:C6:23:0F:37:F1:CB:54:51:CD:E2:CC:58:92:39:E6:D2" :ice-ufrag "10b7e089" :ice-pwd "095767ea310990ef2c76e691"}})

(def default-bootstrap-descriptor
  "Signed devnet bootstrap descriptor verified against default-authority-pubkey."
  {:network :devnet
   :network-uri "devnet.bitecho.org"
   :domain "bitecho.org"
   :authority-pubkey default-authority-pubkey
   :issued-epoch 0
   :expires-epoch 1000000000
   :signature "0c7a1caa76a6def0a39b81d3dd7996aec71a06aa258364a04ef328ff5621eff67704d1e4a5daa7fee02d0646ea6f7171e2e6fdbbb5ebfb70d735a1a1ce1b7a0c"
   :treasury-pubkey "302a300506032b65700321007c2b695b77904a19a630b75ce53889a53963c0f85aa69e5276bb988a183b91b8"
   :custody-pubkey "302a300506032b6570032100e476d77ef34962d09baee0062b4c03be832a1ccc2d691623a8cb39e356793f2b"
   :directory-pubkey default-authority-pubkey
   :nodes default-bootstrap-nodes})

(def default-petnames
  "Default well-known petnames for devnet authorities and key peers."
  {"axiom" "302a300506032b6570032100b53afd55492fe17fca9d0ef0e07b367bf8333490e43b4ecd3610c12c8e6a79f8"
   "nexus" "302a300506032b65700321009b33a9ebd1866d6db419edabe2de9ee74c884dc86b4214f60e3a26f04cbd9cfc"})

(defonce ^:private ui-listeners-atom (atom []))

(defonce ^:private event-listeners-atom (atom {}))
(defonce ^:private event-listener-next-id-atom (atom 0))
(defonce ^:private event-seq-atom (atom 0))

(declare get-status fetch-relay-chain-state!)

(defn emit-browser-event!
  "Emits a normalized v1.0.0 event to all `BitechoLightNode.onEvent` subscribers.
   If a subscriber callback throws, catches the error, increments the counted
   `:event-listener-errors` diagnostic, emits a `:diagnose` event (`:event-listener-error`),
   and continues delivering to all remaining subscribers (Rules 4 & 5)."
  [node-atom raw-event]
  (let [state (if (and node-atom @node-atom) @node-atom {})
        ev-with-meta (cond-> (if (map? raw-event) raw-event {})
                       (nil? (or (:timestamp-ms raw-event) (:timestampMs raw-event)))
                       (assoc :timestamp-ms (.now js/Date))
                       (nil? (or (:event-id raw-event) (:eventId raw-event)))
                       (assoc :event-id (str "ev-" (swap! event-seq-atom inc))))
        norm-ev (browser-cli/normalize-browser-event state ev-with-meta)
        js-ev (clj->js (browser-cli/event->js-map norm-ev))
        listeners @event-listeners-atom
        listener-errors (atom [])]
    (doseq [[_id cb] listeners]
      (try
        (cb js-ev)
        (catch :default err
          (let [err-msg (str (or (when err (.-message err)) err "listener-error"))]
            (swap! listener-errors conj err-msg)
            (when (and node-atom @node-atom)
              (swap! node-atom
                     (fn [curr]
                       (-> curr
                           (update-in [:conn :diagnostics :event-listener-errors] (fnil inc 0))
                           (assoc-in [:conn :diagnostics :last-error] (str "event-listener-error:" err-msg))))))))))
    (when (and (seq @listener-errors) (not= "diagnose" (:type norm-ev)))
      (doseq [err-msg @listener-errors]
        (emit-browser-event! node-atom
                             {:type "diagnose"
                              :kind :event-listener-error
                              :reason (str "event-listener-error:" err-msg)
                              :timestamp-ms (.now js/Date)})))
    js-ev))

(defn on-event
  "Subscribes `cb` to normalized `BitechoLightNode` v1.0.0 events.
   Returns an `unsubscribeFn` closure."
  [cb]
  (if-not (fn? cb)
    (fn [] nil)
    (let [id (swap! event-listener-next-id-atom inc)]
      (swap! event-listeners-atom assoc id cb)
      (fn []
        (swap! event-listeners-atom dissoc id)
        nil))))

(defn- notify-ui-listeners! []
  (when-let [na @active-node-atom]
    (let [st (get-status na)]
      (doseq [cb @ui-listeners-atom]
        (try (cb st) (catch :default _ nil))))))

(defn on-state-change
  "Registers a UI listener callback called whenever node connection, session, or chat state updates."
  [cb]
  (when (fn? cb)
    (swap! ui-listeners-atom conj cb)
    (when @active-node-atom
      (cb (get-status @active-node-atom)))))

(def redacted-js-key?
  "Canonical forbidden key predicate aliased from bitecho.shell.browser."
  browser/forbidden-persistence-key?)

(defn redact-for-js
  "Recursively redacts private key material and credentials before converting to JS.
   Handles maps, vectors, sets, and sequences at any nesting depth."
  [x]
  (cond
    (map? x)
    (into (empty x)
          (keep (fn [[k v]]
                  (when-not (redacted-js-key? k)
                    [k (redact-for-js v)])))
          x)
    (vector? x) (mapv redact-for-js x)
    (set? x) (into #{} (map redact-for-js x))
    (seq? x) (mapv redact-for-js x)
    :else x))

(declare send-to-all-channels! send-chain-state-query! set-p2p-channel-state dial-browser-p2p-peer! handle-inbound-wire-envelope! route-browser-envelope! poll-relay-envelopes! ack-relay-envelopes! submit-relay-envelope! fetch-relay-chain-state!)

(defn- prune-ghost-sessions
  "Removes restored sessions whose ephemeral/session keys (:tx-key, :ephemeral-priv)
   were stripped during IndexedDB persistence sanitization, and strips transient :p2p liveness per Rule 4."
  [sessions]
  (if-not (map? sessions)
    {}
    (into {}
          (keep (fn [[sid s]]
                  (let [st (or (:state s) (when (:status s) (name (:status s))))
                        survives? (cond
                                    (= st "open") (or (some? (:tx-key s)) (some? (:session-keys s)))
                                    (= st "offered") (some? (:ephemeral-priv s))
                                    :else false)]
                    (when survives?
                      [sid (dissoc s :p2p)]))))
          sessions)))

(defn- apply-hardware-identity!
  "Applies a recovered hardware identity map to anchor-state-atom and active-node-atom,
   normalizing to canonical 88-char SPKI :public-hex and 44-byte SPKI :public-key (BIP-010 P-WEB-1),
   and persists the sanitized public state to IndexedDB for refresh continuity (H-5, A-5)."
  [raw-recovered]
  (let [recovered (webauthn/normalize-recovered-identity raw-recovered)]
    (when (and (map? recovered) (:public-hex recovered))
      (when @anchor-state-atom
        (swap! anchor-state-atom
               (fn [st]
                 (cond-> (-> st
                             (assoc-in [:identity :anchor-pubkey] (:public-hex recovered))
                             (assoc-in [:identity :address] (:address recovered))
                             (assoc :anchor-pubkey (:public-hex recovered))
                             (assoc :anchor-address (:address recovered))
                             (assoc :hot-pubkey (:public-hex recovered))
                             (assoc :key-mode :yubikey-discoverable))
                   (:private-key recovered)
                   (assoc :privkey-bytes (:private-key recovered))))))
      (when (and @active-node-atom (:public-key recovered))
        (let [na @active-node-atom
              prev-pub (webauthn/normalize-spki-pubkey-hex (get-in @na [:light-state :pubkey]))
              new-pub (:public-hex recovered)
              pub-changed? (and (some? prev-pub) (not= prev-pub new-pub))
              existing-priv (get-in @na [:keypair :private-key])
              eff-priv (or (:private-key recovered)
                           (when (not pub-changed?) existing-priv))]
          (when eff-priv
            (swap! na
                   (fn [node]
                     (cond-> (-> node
                                 (assoc :keypair {:public-key (:public-key recovered)
                                                  :private-key eff-priv})
                                 (assoc-in [:light-state :pubkey] new-pub))
                       pub-changed?
                       (-> (assoc-in [:light-state :chain-state-snapshots] {})
                           (assoc-in [:light-state :account] {:balance 0 :spendable 0 :seq 0 :deps []})))))
            ;; If already connected to mesh DataChannels, re-register home-set and query chain state for unlocked identity
            (let [channels (:active-channels @na)
                  open-dcs (keep (fn [[_id dc]] (when (and dc (= (.-readyState dc) "open")) dc)) channels)]
              (when (seq open-dcs)
                (let [reg-res (light-core/handle-command (:light-state @na)
                                                         {"cmd" "register-home-set" "price" 10 "nodes" ["node1" "node2" "node3"]}
                                                         eff-priv)]
                  (swap! na assoc :light-state (:state reg-res))
                  (doseq [env (:net-envelopes reg-res)]
                    (send-to-all-channels! na env)))
                (doseq [dc open-dcs]
                  (send-chain-state-query! na dc))))
            (browser/persist-state! (browser/sanitize-state-for-persistence @na)))))
      (notify-ui-listeners!)
      recovered)))

(defn apply-restored-state!
  "Applies sanitized persisted state loaded from IndexedDB to node-atom and anchor-state-atom.
   Preserves public identity (pubkey + ech1 address) across browser refresh without generating
   a conflicting random keypair (avoiding Frankenstein state). Private key remains nil until
   unlocked via hardware recovery (H-5, A-5).
   Returns enriched restored state map with top-level :pubkey, :address, and :hardwareLocked."
  [node-atom loaded]
  (when (and node-atom (map? loaded))
    (let [saved-pub (or (get-in loaded [:light-state :pubkey])
                        (:pubkey loaded))]
      (if (and (string? saved-pub) (not (str/blank? saved-pub)))
        (let [saved-addr (bech32m/pubkey->bech32m saved-pub "ech")
              pub-bytes (basalt/hex->bytes saved-pub)
              clean-loaded (-> loaded
                               (dissoc :conn :mesh-conns :keypair :x25519 :active-channels)
                               (update :sessions prune-ghost-sessions)
                               (update-in [:light-state :sessions] prune-ghost-sessions)
                               (update :chat-history #(vec (or % [])))
                               (update-in [:light-state :inbox] #(vec (or % [])))
                               (assoc-in [:light-state :bootstrap] default-bootstrap-descriptor)
                               (assoc-in [:light-state :max-epoch-skew]
                                         (or (get-in loaded [:light-state :max-epoch-skew]) 15))
                               (update :light-state
                                       browser/normalize-restored-light-state
                                       #{"bitecho.org/dev" "bitecho.org/team" "bitecho.org/infra"
                                         "chat/simon-nexus-axiom" "devnet.bitecho.org" "global"}))]
          (let [reconciled? (atom false)]
            (swap! node-atom
                   (fn [curr]
                     (let [curr-kp (:keypair curr)
                           curr-pub (when (and curr-kp (:public-key curr-kp))
                                      (fressian/bytes->hex (:public-key curr-kp)))
                           same-pub? (= curr-pub saved-pub)
                           explicit-sub (:explicit-subnet-id curr)
                           base-light (assoc (:light-state clean-loaded) :pubkey saved-pub)
                           rec (light-core/reconcile-startup-subnet-id base-light explicit-sub)
                           final-light (:state rec)
                           final-sub (or (:subnet-id final-light) (:subnet-id curr) "global")]
                       (when (:reconciled? rec)
                         (reset! reconciled? true))
                       (-> curr
                           (merge clean-loaded)
                           (assoc :subnet-id final-sub)
                           (assoc-in [:conn :subnet-id] final-sub)
                           (assoc :light-state final-light)
                           (assoc :keypair (if same-pub?
                                             curr-kp
                                             {:public-key pub-bytes
                                              :private-key nil}))
                           (assoc :x25519 (when same-pub? (:x25519 curr)))))))
            (when @reconciled?
              (browser/persist-state! (browser/sanitize-state-for-persistence @node-atom))))
          (if @anchor-state-atom
            (swap! anchor-state-atom
                   (fn [st]
                     (-> st
                         (assoc-in [:identity :anchor-pubkey] saved-pub)
                         (assoc-in [:identity :address] saved-addr)
                         (assoc :anchor-pubkey saved-pub)
                         (assoc :anchor-address saved-addr)
                         (assoc :hot-pubkey saved-pub)
                         (dissoc :privkey-bytes))))
            (reset! anchor-state-atom
                    (light-core/init-anchor-state {:pubkey saved-pub} {})))
          (notify-ui-listeners!)
          (let [hw-locked? (nil? (get-in @node-atom [:keypair :private-key]))]
            (-> clean-loaded
                (assoc :pubkey saved-pub
                       :address saved-addr
                       :hardwareLocked hw-locked?))))
        loaded))))

(defn init-anchor
  "Initializes or resets the global Human Anchor state atom."
  ([] (init-anchor nil))
  ([opts]
   (let [opts-map (or (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true))) {})
         fallback-kp (or (when-let [na @active-node-atom] (:keypair @na))
                         (crypto/generate-keypair))
         pubkey-hex (or (:pubkey opts-map)
                        (:pubkey-hex opts-map)
                        (when-let [na @active-node-atom] (get-in @na [:light-state :pubkey]))
                        (when fallback-kp (fressian/bytes->hex (:public-key fallback-kp))))
         privkey-bytes (or (:privkey-bytes opts-map)
                           (:cold-privkey opts-map)
                           (when fallback-kp (:private-key fallback-kp)))
         st (light-core/init-anchor-state (assoc opts-map :pubkey pubkey-hex)
                                          (cond-> opts-map
                                            privkey-bytes (assoc :privkey-bytes privkey-bytes)))]
     (reset! anchor-state-atom st)
     (clj->js (redact-for-js (light-core/anchor-dashboard-view st))))))

(defn get-anchor-dashboard
  "Returns the Human Anchor dashboard view as a JavaScript object, syncing live balance, burn metrics, and pending offers from active-node-atom."
  []
  (when-not @anchor-state-atom
    (init-anchor nil))
  (when-let [na @active-node-atom]
    (let [node @na
          light-st (:light-state node)
          pub (or (:anchor-pubkey @anchor-state-atom) (:pubkey light-st))
          light-bal (or (get-in light-st [:account :balance]) (:balance light-st))
          light-burned (or (get-in light-st [:local-accounting :burned-ech]) (:burned-ech node))
          pending-offers (or (:pending-offers light-st) {})
          open-sessions (or (:sessions light-st) {})]
      (swap! anchor-state-atom
             (fn [st]
               (let [existing-ids (set (keep #(or (:offer-id %) (:session-id %)) (:pending-offers st)))
                     st1 (cond-> st
                           (and pub (number? light-bal))
                           (assoc-in [:accounts pub :balance] light-bal)
                           (number? light-burned)
                           (assoc-in [:local-accounting :burned-ech] light-burned))]
                 (reduce-kv
                  (fn [acc sid offer]
                    (if (or (contains? existing-ids sid)
                            (contains? open-sessions sid))
                      acc
                      (light-core/queue-incoming-offer
                       acc
                       {:offer-id sid
                        :session-id sid
                        :peer-id (:caller offer)
                        :caller-pubkey (:caller offer)
                        :callee-pubkey (:callee offer)
                        :price (or (:price offer) 10)
                        :burn (or (:burn offer) 100)
                        :epoch (or (:epoch offer) 0)})))
                  st1
                  pending-offers))))))
  (let [hw-locked? (if-let [na @active-node-atom]
                     (nil? (get-in @na [:keypair :private-key]))
                     (nil? (:privkey-bytes @anchor-state-atom)))
        view (-> (light-core/anchor-dashboard-view @anchor-state-atom)
                 (assoc :hardware-locked hw-locked?)
                 (assoc-in [:identity :hardware-locked] hw-locked?))]
    (clj->js (redact-for-js view))))

(defn register-yubikey
  "Configures YubiKey discoverable credential options and updates anchor key-mode."
  ([] (register-yubikey nil))
  ([opts]
   (let [opts-map (if (map? opts) opts (when opts (js->clj opts :keywordize-keys true)))
         reg-opts (webauthn/build-registration-options opts-map)]
     (when @anchor-state-atom
       (swap! anchor-state-atom assoc :key-mode :yubikey-discoverable))
     (clj->js (redact-for-js reg-opts)))))

(defn recover-from-yubikey
  "Recovers identity from WebAuthn assertion/userHandle without generating silent random identity.
   Recognizes both top-level {:public-hex ...} and nested {:identity {:public-hex ...}} redacted shapes,
   normalizes to canonical 88-char SPKI :public-hex, and never overwrites an already-unlocked
   active-node-atom :private-key with nil (BIP-010 P-WEB-1).
   Fails closed with {:ok false :error 'recovery-failed'} if recovery input is missing or invalid."
  [seed-or-opts]
  (let [raw-bytes? (or (instance? js/Uint8Array seed-or-opts)
                       (and (exists? js/ArrayBuffer)
                            (or (instance? js/ArrayBuffer seed-or-opts)
                                (.isView js/ArrayBuffer seed-or-opts))))
        opts-map (cond
                   raw-bytes? {:user-handle seed-or-opts}
                   (map? seed-or-opts) seed-or-opts
                   (some? seed-or-opts) (js->clj seed-or-opts :keywordize-keys true)
                   :else nil)
        existing-ident (or (when (map? opts-map)
                             (when (map? (:identity opts-map)) (:identity opts-map)))
                           (when (and (map? opts-map) (:public-hex opts-map)) opts-map))
        prf-out (or (when (and (some? seed-or-opts) (= "object" (js* "typeof ~{}" seed-or-opts)) (not (map? seed-or-opts)))
                      (or (gobj/get seed-or-opts "prfOutput")
                          (gobj/get seed-or-opts "prf_output")
                          (gobj/get seed-or-opts "prf-output")
                          (when-let [cer (or (gobj/get seed-or-opts "clientExtensionResults")
                                             (gobj/get seed-or-opts "client_extension_results")
                                             (gobj/get seed-or-opts "extensions")
                                             (when-let [f (gobj/get seed-or-opts "getClientExtensionResults")]
                                               (when (fn? f) (.call f seed-or-opts))))]
                            (when-let [prf (or (gobj/get cer "prf") cer)]
                              (or (gobj/get prf "first")
                                  (when-let [r (gobj/get prf "results")]
                                    (gobj/get r "first")))))
                          (when-let [prf (gobj/get seed-or-opts "prf")]
                            (or (gobj/get prf "first")
                                (when-let [r (gobj/get prf "results")]
                                  (gobj/get r "first"))))
                          (when-let [r (gobj/get seed-or-opts "results")]
                            (gobj/get r "first"))))
                    (when (map? opts-map)
                      (or (:prf-output opts-map)
                          (:prfOutput opts-map)
                          (:prf_output opts-map)
                          (get-in opts-map [:results :first])
                          (get-in opts-map [:prf :results :first])
                          (get-in opts-map [:extensions :prf :results :first])
                          (get-in opts-map [:clientExtensionResults :prf :results :first])
                          (get-in opts-map [:client-extension-results :prf :results :first]))))
        user-handle (or (when raw-bytes? seed-or-opts)
                        (when (and (some? seed-or-opts) (= "object" (js* "typeof ~{}" seed-or-opts)) (not (map? seed-or-opts)))
                          (or (gobj/get seed-or-opts "userHandle")
                              (gobj/get seed-or-opts "user_handle")
                              (when-let [r (gobj/get seed-or-opts "response")]
                                (or (gobj/get r "userHandle")
                                    (gobj/get r "user_handle")))))
                        (when existing-ident (or (:user-handle existing-ident) (:seed existing-ident)))
                        (when (map? opts-map)
                          (or (:user-handle opts-map)
                              (:userHandle opts-map)
                              (:user_handle opts-map)
                              (get-in opts-map [:response :userHandle])
                              (get-in opts-map [:response :user-handle])
                              (get-in opts-map [:response :user_handle])
                              (:seed-bytes opts-map)
                              (:seedBytes opts-map)
                              (:seed_bytes opts-map)))
                        (when (string? seed-or-opts) seed-or-opts)
                        (when (sequential? seed-or-opts) seed-or-opts))
        stage1-diag (when (map? opts-map) (:diagnostics opts-map))
        stage1-failed? (and (map? opts-map) (false? (:ok opts-map)))
        input-shape (cond
                      (nil? seed-or-opts) "nil"
                      stage1-failed? "stage1-failed-result"
                      raw-bytes? "raw-bytes"
                      (some? user-handle) "assertion-or-user-handle"
                      (some? prf-out) "prf-output"
                      (and existing-ident (:public-hex existing-ident)) "redacted-identity-double-recovery"
                      (map? opts-map) (str "map-keys:" (str/join "," (sort (map name (keys opts-map)))))
                      :else "other")
        raw-recovered (cond
                        stage1-failed? nil

                        (some? user-handle)
                        (webauthn/recover-seed-from-assertion
                         (if (map? opts-map)
                           (assoc opts-map :user-handle user-handle)
                           {:user-handle user-handle}))

                        (some? prf-out)
                        (webauthn/derive-identity-from-prf prf-out)

                        (and existing-ident (:public-hex existing-ident))
                        existing-ident

                        :else nil)
        recovered (when raw-recovered
                    (webauthn/normalize-recovered-identity raw-recovered))
        rec-pk (when (map? recovered) (:public-hex recovered))
        rec-pk-len (if (string? rec-pk) (count rec-pk) 0)
        rec-pk-fmt (cond (= rec-pk-len 88) "88-char-spki-hex"
                         (= rec-pk-len 64) "64-char-raw-hex"
                         :else "none")
        merged-diag (merge (or stage1-diag (webauthn/inspect-assertion-diagnostics seed-or-opts))
                           {:second-call-ran true
                            :second-call-input-shape input-shape
                            :recovered-key-length rec-pk-len
                            :recovered-key-format rec-pk-fmt})]
    (if-not recovered
      (let [fail-stage (or (when stage1-failed? (:failure-stage opts-map))
                           (if raw-recovered "normalize-recovered-identity" "recover-from-yubikey"))
            fail-reason (or (when stage1-failed? (:failure-reason opts-map))
                            (cond
                              (nil? seed-or-opts) "nil-input-to-recover-from-yubikey"
                              (and (nil? user-handle) (nil? prf-out) (nil? existing-ident))
                              (str "no-user-handle-prf-or-public-hex-in-input (" input-shape ")")
                              (nil? raw-recovered) (str "seed-derivation-returned-nil (" input-shape ")")
                              :else (str "normalize-recovered-identity-returned-nil (raw-public-hex-len="
                                         (count (str (:public-hex raw-recovered))) ")")))]
        (clj->js {:ok false
                  :error "recovery-failed"
                  :failure-stage fail-stage
                  :failure-reason fail-reason
                  :diagnostics (assoc merged-diag
                                      :failure-stage fail-stage
                                      :failure-reason fail-reason)}))
      (let [applied (or (apply-hardware-identity! recovered) recovered)]
        (clj->js (assoc (redact-for-js applied)
                        :ok true
                        :diagnostics merged-diag))))))

(defn generate-non-extractable-key
  "Generates and returns non-extractable WebCrypto key spec and metadata."
  ([] (generate-non-extractable-key nil))
  ([opts]
   (let [opts-map (if (map? opts) opts (when opts (js->clj opts :keywordize-keys true)))
         spec (webauthn/generate-non-extractable-keypair-spec opts-map)]
     (when @anchor-state-atom
       (swap! anchor-state-atom assoc :key-mode :webcrypto-non-extractable))
     (clj->js spec))))

(declare accept-channel-offer)

(defn approve-offer-cmd
  "Approves a pending offer in the Human Anchor queue and accepts any matching live channel offer."
  [offer-id & [opts]]
  (let [id (str offer-id)
        opts-map (when opts (js->clj opts :keywordize-keys true))
        na @active-node-atom
        live-offer? (and na (some? (get-in @na [:light-state :pending-offers id])))
        hw-locked? (and na (nil? (get-in @na [:keypair :private-key])))]
    (if (and live-offer? hw-locked?)
      (clj->js {:ok false
                :error "hardware-unlock-required"
                :dashboard (redact-for-js (light-core/anchor-dashboard-view (or @anchor-state-atom (light-core/init-anchor-state))))})
      (let [[new-state effects] (light-core/approve-offer (or @anchor-state-atom (light-core/init-anchor-state)) id opts-map)]
        (reset! anchor-state-atom new-state)
        (when live-offer?
          (accept-channel-offer na id))
        (clj->js {:ok true :effects effects :dashboard (redact-for-js (light-core/anchor-dashboard-view new-state))})))))

(defn deny-offer-cmd
  "Denies a pending offer in the Human Anchor queue with an explicit reason."
  [offer-id & [reason]]
  (let [id (str offer-id)
        rej-reason (or reason "denied-by-human-anchor")
        [new-state effects] (light-core/deny-offer (or @anchor-state-atom (light-core/init-anchor-state)) id rej-reason)]
    (reset! anchor-state-atom new-state)
    (when-let [na @active-node-atom]
      (swap! na update-in [:light-state :pending-offers] dissoc id))
    (clj->js {:ok true :effects effects :dashboard (redact-for-js (light-core/anchor-dashboard-view new-state))})))

(defn supervise-agent-cmd
  "Registers an autonomous agent under human anchor supervision with an issued DAC."
  [agent-id hot-pubkey & [perms]]
  (let [aid (str agent-id)
        pub-str (str hot-pubkey)
        perms-vec (when perms (js->clj perms :keywordize-keys true))
        new-state (light-core/register-supervised-agent (or @anchor-state-atom (light-core/init-anchor-state))
                                                        {:agent-id aid
                                                         :hot-pubkey pub-str
                                                         :permissions perms-vec})]
    (reset! anchor-state-atom new-state)
    (clj->js {:ok true :agentId aid :dashboard (redact-for-js (light-core/anchor-dashboard-view new-state))})))

(defn revoke-agent-dac-cmd
  "Emergency revocation of a supervised agent's DAC."
  [agent-id & [reason]]
  (let [aid (str agent-id)
        rej-reason (or reason "emergency-human-anchor-revocation")
        [new-state effects] (light-core/revoke-agent-dac (or @anchor-state-atom (light-core/init-anchor-state)) aid rej-reason)]
    (reset! anchor-state-atom new-state)
    (clj->js {:ok true :effects effects :dashboard (redact-for-js (light-core/anchor-dashboard-view new-state))})))

(defn encode-bech32m-cmd
  "Encodes raw bytes or hex into a Bech32m address."
  [bytes-or-hex & [hrp]]
  (bech32m/pubkey->bech32m bytes-or-hex (or hrp "ech")))

(defn decode-bech32m-cmd
  "Decodes a Bech32m address into a JavaScript object."
  [bech-str]
  (clj->js (bech32m/decode-address bech-str)))

(defn run-anchor-end-to-end-demo
  "Executes a complete self-contained Human Anchor lifecycle demo and returns results."
  [& _args]
  (let [seed (crypto/random-bytes 32)
        recovered (webauthn/recover-seed-from-assertion {:user-handle seed})
        anchor-pub (:public-hex recovered)
        anchor-addr (:address recovered)
        st0 (light-core/init-anchor-state {:pubkey anchor-pub}
                                          {:privkey-bytes (:private-key recovered)
                                           :key-mode :yubikey-discoverable})
        st1 (light-core/set-service-offer st0 :ai-inference {:price 100 :burn-floor 100})
        st2 (light-core/queue-incoming-offer st1 {:offer-id "off-demo-1" :peer-id "worker-node-1" :burn 100})
        [st3 _app-effects] (light-core/approve-offer st2 "off-demo-1")
        hot-kp (crypto/generate-keypair)
        hot-pub (fressian/bytes->hex (:public-key hot-kp))
        st4 (light-core/register-supervised-agent st3 {:agent-id "sub-agent-alpha"
                                                       :hot-pubkey hot-pub
                                                       :max-spend 5000})
        st5 (light-core/log-agent-activity st4 "sub-agent-alpha" {:type :offer-accepted :offer-id "off-demo-1"})
        [st6 _rev-effects] (light-core/revoke-agent-dac st5 "sub-agent-alpha" "routine-rotation")
        st7 (light-core/create-team-call-subnet st6 {:topic-name "core-devs" :peers ["worker-node-1"]})
        dashboard (redact-for-js (light-core/anchor-dashboard-view st7))]
    (reset! anchor-state-atom st7)
    (clj->js {:ok true
              :anchorAddress anchor-addr
              :anchorPubkey anchor-pub
              :keyMode :yubikey-discoverable
              :fidoSecurity (get-in dashboard [:fido-authenticator])
              :offersApproved (:offers-approved st7)
              :supervisedAgentsCount (count (:supervised-agents st7))
              :supervisedAgentRevoked (= :revoked (get-in st7 [:supervised-agents "sub-agent-alpha" :status]))
              :teamCallSubnet (get-in dashboard [:team-call-subnet :subnet-id])
              :dashboard dashboard})))

(defn init-node
  "Initializes a new browser light-node state atom and records it in active-node-atom."
  ([] (init-node nil))
  ([opts]
   (let [opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
         node-id (or (:peer-id opts-map) (:peerId opts-map)
                     (str "browser-" (fressian/bytes->hex (crypto/random-bytes 4))))
         explicit-subnet-id (or (:explicit-subnet-id opts-map) (:explicitSubnetId opts-map)
                                (:subnet-id opts-map) (:subnetId opts-map))
         subnet-id (or explicit-subnet-id "global")
         relay-url (or (:relay-url opts-map) (:relayUrl opts-map)
                       (when (and (exists? js/window) (exists? js/URLSearchParams) (some? (.-location js/window)))
                         (try
                           (let [params (js/URLSearchParams. (.-search (.-location js/window)))]
                             (or (.get params "relay-url") (.get params "relayUrl")))
                           (catch :default _ nil))))
         keypair (crypto/generate-keypair)
         x25519 (sealed/generate-x25519-keypair)
         pubkey-hex (fressian/bytes->hex (:public-key keypair))
         init-light (light-core/init-light-state {:pubkey-hex pubkey-hex}
                                                 {:subnet-id subnet-id
                                                  :bootstrap default-bootstrap-descriptor
                                                  :economy-enabled? true
                                                  :burn-floor 100
                                                  :autonomous? false})
         light-st (cond-> (assoc init-light :petnames default-petnames :petname-meta {} :max-epoch-skew 15)
                    relay-url (assoc :relay-url relay-url))
         conn-state (browser/initial-conn-state {:peer-id node-id :subnet-id subnet-id})
         mesh-conns (browser/initial-mesh-conns-state)
         node-atom (atom {:peer-id node-id
                          :subnet-id subnet-id
                          :explicit-subnet-id explicit-subnet-id
                          :relay-url relay-url
                          :keypair keypair
                          :x25519 x25519
                          :conn conn-state
                          :mesh-conns mesh-conns
                          :light-state light-st
                          :petnames default-petnames
                          :petname-meta {}
                          :chat-history []
                          :active-channels {}
                          :p2p-channels {}
                          :sessions {}
                          :inbox []
                          :outbox []
                          :burned-ech 0
                          :autonomous? false})]
     (reset! active-node-atom node-atom)
     (when (:persist? opts-map)
       (browser/persist-state! (browser/sanitize-state-for-persistence @node-atom)))
     (when relay-url
       (fetch-relay-chain-state! relay-url {:node-atom node-atom})
       (let [saved-mseq (or (get-in @node-atom [:light-state :relay-since-seq])
                            (when (exists? js/localStorage)
                              (try (js/parseInt (.getItem js/localStorage "relay-since-seq")) (catch :default _ nil)))
                            0)
             saved-bseq (or (get-in @node-atom [:light-state :relay-since-broadcast-seq])
                            (when (exists? js/localStorage)
                              (try (js/parseInt (.getItem js/localStorage "relay-since-broadcast-seq")) (catch :default _ nil)))
                            0)
             since-mseq (atom (long (if (and saved-mseq (not (js/isNaN saved-mseq))) saved-mseq 0)))
             since-bseq (atom (long (if (and saved-bseq (not (js/isNaN saved-bseq))) saved-bseq 0)))
             polling? (atom false)
             poll-tick!
             (fn poll-tick! []
               (when (compare-and-set! polling? false true)
                 (let [st (:light-state @node-atom)
                       pk-hex (or (:pubkey st) pubkey-hex)
                       privkey (:private-key (:keypair @node-atom))]
                   (-> (poll-relay-envelopes!
                        relay-url pk-hex privkey
                        {:since-seq @since-mseq
                         :since-broadcast-seq @since-bseq
                         :timeout-ms 2000})
                       (.then (fn [poll-res]
                                (try
                                  (let [msgs (or (:messages poll-res) [])
                                        bcasts (or (:broadcasts poll-res) [])
                                        all-items (concat msgs bcasts)]
                                    (when (seq msgs)
                                      (let [last-m (last msgs)
                                            mseq (or (:relay_seq last-m) (:relay-seq last-m))]
                                        (when mseq (reset! since-mseq (long mseq)))))
                                    (when (seq bcasts)
                                      (let [last-b (last bcasts)
                                            bseq (or (:broadcast_seq last-b) (:broadcast-seq last-b))]
                                        (when bseq (reset! since-bseq (long bseq)))))
                                    (swap! node-atom (fn [n]
                                                       (-> n
                                                           (assoc-in [:light-state :relay-since-seq] @since-mseq)
                                                           (assoc-in [:light-state :relay-since-broadcast-seq] @since-bseq))))
                                    (when (or (seq msgs) (seq bcasts))
                                      (browser/persist-state! (browser/sanitize-state-for-persistence @node-atom))
                                      (when (exists? js/localStorage)
                                        (try
                                          (.setItem js/localStorage "relay-since-seq" (str @since-mseq))
                                          (.setItem js/localStorage "relay-since-broadcast-seq" (str @since-bseq))
                                          (catch :default _ nil))))
                                    (doseq [item all-items]
                                      (let [env-raw (or (:envelope_hex item) (:envelope item))
                                            wire-bytes (when env-raw
                                                         (try (basalt/hex->bytes (str env-raw)) (catch :default _ nil)))]
                                        (when wire-bytes
                                          (handle-inbound-wire-envelope! node-atom wire-bytes))))
                                    (when (seq msgs)
                                      (ack-relay-envelopes! relay-url pk-hex privkey @since-mseq {:ack-broadcast-seq @since-bseq})))
                                  (finally
                                    (reset! polling? false)))))
                       (.catch (fn [_]
                                 (reset! polling? false)))))))]
         (poll-tick!)
         (js/setInterval poll-tick! 1000)))
     (notify-ui-listeners!)
     node-atom)))

(defn- kw-or-str->name
  [v default-str]
  (if (or (keyword? v) (symbol? v) (string? v))
    (name v)
    default-str))

(defn- format-peer-diagnostics-js
  [peer-map]
  (into {}
        (map (fn [[pid p]]
               [pid {:peerId pid
                     :phase (kw-or-str->name (:phase p) "idle")
                     :generation (long (or (:generation p) 0))
                     :lastError (:last-error p)
                     :dropped (long (or (:dropped p) 0))
                     :ignoredStale (long (or (:ignored-stale p) 0))
                     :unsupportedFormatDropped (long (or (:unsupported-format-dropped p) 0))
                     :backgroundThrottledEvents (long (or (:background-throttled-events p) 0))
                     :iceDisconnects (long (or (:ice-disconnects p) 0))
                     :iceReconnects (long (or (:ice-reconnects p) 0))
                     :closeCount (long (or (:close-count p) 0))
                     :dialFailures (long (or (:dial-failures p) 0))
                     :lastIceState (:last-ice-state p)
                     :lastConnectionState (:last-connection-state p)
                     :recentEvents (mapv (fn [e]
                                           (cond-> {:seq (:seq e)
                                                    :kind (kw-or-str->name (:kind e) "unknown")
                                                    :peerId (:peer-id e)
                                                    :generation (long (or (:generation e) 0))
                                                    :phase (kw-or-str->name (:phase e) "idle")
                                                    :reason (:reason e)}
                                             (:ice-state e) (assoc :iceState (:ice-state e))
                                             (:connection-state e) (assoc :connectionState (:connection-state e))
                                             (:event-gen e) (assoc :eventGen (:event-gen e))
                                             (:timestamp-ms e) (assoc :timestampMs (:timestamp-ms e))))
                                         (or (:recent-events p) []))}]))
        (or peer-map {})))

(defn- format-recent-events-js
  [events]
  (mapv (fn [e]
          (cond-> {:seq (:seq e)
                   :peerId (:peer-id e)
                   :kind (kw-or-str->name (:kind e) "unknown")
                   :generation (long (or (:generation e) 0))
                   :phase (kw-or-str->name (:phase e) "idle")
                   :reason (:reason e)}
            (:ice-state e) (assoc :iceState (:ice-state e))
            (:connection-state e) (assoc :connectionState (:connection-state e))
            (:event-gen e) (assoc :eventGen (:event-gen e))
            (:timestamp-ms e) (assoc :timestampMs (:timestamp-ms e))))
        (or events [])))

(defn get-status
  "Returns Rule 4 & Rule 5 status and single-authority multi-peer diagnostics map as a JavaScript object."
  ([] (get-status @active-node-atom))
  ([node-atom]
   (when node-atom
     (let [node @node-atom
           conn (:conn node)
           diag (:diagnostics conn)
           mesh-conns (:mesh-conns node)
           has-mesh-peers? (pos? (count (:peers mesh-conns)))
           mesh-summary (when has-mesh-peers?
                          (browser/summarize-mesh-diagnostics mesh-conns))
           light-st (:light-state node)
           channels (:active-channels node)
           open-channels (into [] (keep (fn [[k dc]]
                                          (let [pid (if (or (keyword? k) (symbol? k)) (name k) (str k))
                                                peer-phase (get-in mesh-conns [:peers pid :phase])]
                                            (when (and dc
                                                       (= (.-readyState dc) "open")
                                                       (or (nil? peer-phase) (= :open peer-phase)))
                                              pid)))
                                        channels))
           connected-nodes (if has-mesh-peers?
                             (if (seq open-channels)
                               (filterv (set (or (:open-peers mesh-summary) [])) open-channels)
                               (or (:open-peers mesh-summary) []))
                             open-channels)
           relay-fallback-active? (and (empty? connected-nodes)
                                       (boolean (or (:relay-url node) (:relay-fallback-active? node))))
           core-diags (or (:diagnostics light-st) {})
           dt (merge light-core/initial-delivery-telemetry (or (:delivery-telemetry light-st) {}))
           unacked-aged (light-core/compute-unacked-aged-count light-st (.now js/Date))
           closed-nodes (or (:closed-peers mesh-summary) [])
           dialing-nodes (or (:dialing-peers mesh-summary) [])
           degraded? (boolean (:degraded? mesh-summary))
           tr-val (:transport conn)
           tr-str (cond
                    (:relay-url node) "http-relay"
                    (or (keyword? tr-val) (symbol? tr-val) (string? tr-val)) (name tr-val)
                    :else "webrtc")
           phase-val (if has-mesh-peers? (:phase mesh-summary) (:phase conn))
           phase-str (kw-or-str->name phase-val "idle")
           diag-phase-str (kw-or-str->name (if has-mesh-peers? (:phase mesh-summary) (:phase diag)) "idle")
           eff-gen (if has-mesh-peers? (long (or (:generation mesh-summary) 0)) (long (or (:generation conn) 0)))
           eff-last-err (if has-mesh-peers? (:last-error mesh-summary) (:last-error diag))
           eff-dropped (if has-mesh-peers? (:dropped mesh-summary) (or (:dropped diag) 0))
           eff-stale (if has-mesh-peers? (:ignored-stale mesh-summary) (or (:ignored-stale diag) 0))
           eff-unsup (if has-mesh-peers? (:unsupported-format-dropped mesh-summary) (or (:unsupported-format-dropped diag) 0))
           eff-bg (if has-mesh-peers? (:background-throttled-events mesh-summary) (or (:background-throttled-events diag) 0))
           eff-ice-disc (if has-mesh-peers? (:ice-disconnects mesh-summary) (or (:ice-disconnects diag) 0))
           eff-ice-reconn (if has-mesh-peers? (:ice-reconnects mesh-summary) (or (:ice-reconnects diag) 0))
           eff-close-cnt (if has-mesh-peers? (:close-count mesh-summary) (or (:close-count diag) 0))
           eff-dial-fail (if has-mesh-peers? (:dial-failures mesh-summary) (or (:dial-failures diag) 0))
           eff-last-ice (if has-mesh-peers? (:last-ice-state mesh-summary) (:last-ice-state diag))
           eff-last-cs (if has-mesh-peers? (:last-connection-state mesh-summary) (:last-connection-state diag))
           eff-recent (if has-mesh-peers?
                        (format-recent-events-js (:recent-events mesh-summary))
                        (format-recent-events-js (:recent-events diag)))
           eff-peers (if has-mesh-peers?
                       (format-peer-diagnostics-js (:peers mesh-summary))
                       {})
           pubkey-hex (or (get-in light-st [:pubkey])
                          (when-let [kp (:keypair node)]
                            (when (:public-key kp)
                              (fressian/bytes->hex (:public-key kp)))))]
       (clj->js {:peerId (:peer-id node)
                 :subnetId (:subnet-id node)
                 :pubkey pubkey-hex
                 :address (when pubkey-hex (bech32m/pubkey->bech32m pubkey-hex "ech"))
                 :hardwareLocked (nil? (get-in node [:keypair :private-key]))
                 :epoch (or (:epoch light-st) 0)
                 :balance (or (get-in light-st [:account :balance]) (:balance light-st) 0)
                 :spendable (or (get-in light-st [:account :spendable]) (:spendable light-st) 0)
                 :transport tr-str
                 :phase phase-str
                 :generation eff-gen
                 :visibilityState (or (:visibility-state mesh-summary) (:visibility-state conn) "visible")
                 :burnedEch (or (:burned-ech node) 0)
                 :meshConnected (boolean (seq connected-nodes))
                 :relayFallbackActive relay-fallback-active?
                 :connectedNodes connected-nodes
                 :closedNodes closed-nodes
                 :dialingNodes dialing-nodes
                 :degraded degraded?
                 :deliveryTelemetry {:sent (long (or (:sent dt) 0))
                                     :acked (long (or (:acked dt) 0))
                                     :unackedAged unacked-aged
                                     :evictedByReason (:evicted-by-reason dt)
                                     :receivedButNotEmitted (:received-but-not-emitted dt)
                                     :fanout (:fanout dt)
                                     :ringBufferCount (count (or (:ring-buffer dt) []))}
                 :sessions (redact-for-js (or (:sessions light-st) {}))
                 :pendingOffers (redact-for-js (or (:pending-offers light-st) {}))
                 :broadcastInbox (redact-for-js (or (:broadcast-inbox light-st) []))
                 :chatHistory (or (:chat-history node) [])
                 :petnames (or (:petnames node) default-petnames)
                 :diagnostics (merge
                               core-diags
                               {:phase diag-phase-str
                                :generation eff-gen
                                :lastError eff-last-err
                                :dropped (+ (long (or eff-dropped 0)) (long (or (:dropped core-diags) 0)))
                                :ignoredStale eff-stale
                                :unsupportedFormatDropped eff-unsup
                                :backgroundThrottledEvents eff-bg
                                :iceDisconnects eff-ice-disc
                                :iceReconnects eff-ice-reconn
                                :closeCount eff-close-cnt
                                :dialFailures eff-dial-fail
                                :eventListenerErrors (long (or (:event-listener-errors diag) 0))
                                :cidMismatch (long (or (:cid-mismatch diag) 0))
                                :lastIceState eff-last-ice
                                :lastConnectionState eff-last-cs
                                :totalPeers (long (or (:total-peers mesh-summary) 0))
                                :openPeers connected-nodes
                                :dialingPeers dialing-nodes
                                :closedPeers closed-nodes
                                :degraded degraded?
                                :peers eff-peers
                                :recentEvents eff-recent})})))))

(defn build-p2p-link-bind-envelope
  "Builds and signs a :p2p-link-bind envelope proving peer pubkey and session identity."
  [sender-pub sender-priv sid]
  (let [norm-sender (light-core/normalize-pubkey-hex sender-pub)
        sig-str (str "bitecho-p2p-link-bind-v1|" norm-sender "|" sid)
        sig-bytes (crypto/sign sender-priv (fressian/utf8->bytes sig-str))]
    {:bitecho/type :p2p-link-bind
     :type :p2p-link-bind
     :sender norm-sender
     :session-id sid
     :signature (fressian/bytes->hex sig-bytes)}))

(defn verify-p2p-link-bind
  "Verifies a :p2p-link-bind message signature."
  [msg]
  (when (and (map? msg) (= :p2p-link-bind (or (:type msg) (:bitecho/type msg))))
    (let [sender (light-core/normalize-pubkey-hex (:sender msg))
          sid (:session-id msg)
          sig-hex (:signature msg)]
      (when (and sender sid sig-hex)
        (let [pub-bytes (try (basalt/hex->bytes sender) (catch :default _ nil))
              sig-bytes (try (basalt/hex->bytes sig-hex) (catch :default _ nil))
              sig-str (str "bitecho-p2p-link-bind-v1|" sender "|" sid)]
          (boolean
           (and pub-bytes sig-bytes
                (crypto/verify pub-bytes (fressian/utf8->bytes sig-str) sig-bytes))))))))

(defn- dispatch-mesh-peer-event!
  "Single-authority Rule 4/5 dispatcher updating `[:mesh-conns]` inside `node-atom` via pure
   `browser/transition-mesh-peer`, syncing `[:conn]` to the primary/aggregate peer view,
   executing effects outside `swap!`, and notifying UI listeners on lifecycle/diagnostic changes."
  [node-atom peer-id event effect-handler-fn]
  (when node-atom
    (let [effects-box (atom nil)]
      (swap! node-atom
             (fn [curr]
               (let [mesh0 (or (:mesh-conns curr) (browser/initial-mesh-conns-state))
                     [mesh1 effs] (browser/transition-mesh-peer mesh0 peer-id event)
                     primary-conn (or (get-in mesh1 [:peers "node1"])
                                      (get-in mesh1 [:peers (str peer-id)])
                                      (:conn curr))]
                 (reset! effects-box effs)
                 (cond-> (assoc curr :mesh-conns mesh1)
                   primary-conn (assoc :conn primary-conn)))))
      (let [effs @effects-box]
        (when effect-handler-fn
          (doseq [eff effs]
            (effect-handler-fn eff)))
        (doseq [eff effs]
          (when (= :diagnose (:type eff))
            (emit-browser-event! node-atom
                                 {:type "diagnose"
                                  :kind (:kind eff)
                                  :reason (or (:reason eff) (:error eff))
                                  :from (or (:peer-id eff) peer-id)
                                  :generation (:generation eff)
                                  :timestamp-ms (or (:timestamp-ms event) (.now js/Date))})))
        (when (contains? #{:open :close :dial-failed :ice-state-change :connection-state-change} (:type event))
          (let [peer-st (get-in @node-atom [:mesh-conns :peers peer-id])]
            (emit-browser-event! node-atom
                                 {:type "status"
                                  :phase (:phase peer-st)
                                  :generation (:generation peer-st)
                                  :from peer-id
                                  :text (name (:type event))
                                  :timestamp-ms (or (:timestamp-ms event) (.now js/Date))})))
        (when (or (contains? #{:open :close :dial-failed :ice-state-change :connection-state-change} (:type event))
                  (some #(= :diagnose (:type %)) effs))
          (notify-ui-listeners!))
        effs))))

(defn- send-to-all-channels!
  "Sends wire envelope to all healthy open validator DataChannels or falls back to HTTPS relay.
   Returns `{:mesh-submitted? bool :mesh-peers-targeted int :error str-or-nil}` (BIP-020 Catch 1/2)."
  [node-atom env]
  (let [node @node-atom
        channels (:active-channels node)
        mesh-peers (get-in node [:mesh-conns :peers] {})
        wire-bytes (fressian/encode-wire env)
        open-dcs (filter (fn [[nid dc]]
                           (let [pid (if (or (keyword? nid) (symbol? nid)) (name nid) (str nid))
                                 p-phase (get-in mesh-peers [pid :phase])]
                             (and dc
                                  (= (.-readyState dc) "open")
                                  (or (nil? p-phase) (= :open p-phase)))))
                         channels)]
    (if (seq open-dcs)
      (let [sent-cnt (reduce
                      (fn [acc [nid dc]]
                        (try
                          (.send dc wire-bytes)
                          (inc acc)
                          (catch :default err
                            (let [cur-gen (long (or (get-in @node-atom [:mesh-conns :peers nid :generation]) 0))]
                              (dispatch-mesh-peer-event!
                               node-atom
                               nid
                               {:type :dial-failed
                                :generation cur-gen
                                :error (str "send-failed:" err)
                                :timestamp-ms (.now js/Date)}
                               nil))
                            acc)))
                      0
                      open-dcs)]
        (if (pos? sent-cnt)
          {:mesh-submitted? true :mesh-peers-targeted sent-cnt :error nil}
          {:mesh-submitted? false :mesh-peers-targeted 0 :error "all-mesh-channel-sends-failed"}))
      (if-let [relay-url (:relay-url node)]
        (do
          (submit-relay-envelope! relay-url env nil)
          {:mesh-submitted? true :mesh-peers-targeted 1 :error nil})
        ;; Rule 5: Never drop outbound envelopes silently when no channels or relay are open
        (let [target-pid (if (contains? (get-in @node-atom [:mesh-conns :peers]) "node1") "node1" "mesh")
              cur-gen (long (or (get-in @node-atom [:mesh-conns :peers target-pid :generation]) 0))]
          (dispatch-mesh-peer-event!
           node-atom
           target-pid
           {:type :send
            :generation cur-gen
            :envelope env
            :timestamp-ms (.now js/Date)}
           nil)
          {:mesh-submitted? false :mesh-peers-targeted 0 :error "no-open-mesh-channels"})))))

(defn route-browser-envelope!
  "Routes an outgoing envelope with unconditional dual-fanout for broadcasts (BIP-020 Catch 2)
   and zero silent `.send` catch blocks (Rule 5).
   Returns `{:mesh-submitted? :p2p-direct? :mesh-peers-targeted :p2p-peers-targeted :error}`."
  [node-atom env]
  (cond
    (:p2p-broadcast? env)
    (let [p2p-chans (vals (or (:p2p-channels @node-atom) {}))
          open-chans (into [] (keep (fn [entry]
                                      (let [dc (:channel entry)]
                                        (when (and dc (= (.-readyState dc) "open")) dc)))
                                    p2p-chans))
          wire-bytes (fressian/encode-wire env)
          p2p-sent (reduce
                    (fn [acc dc]
                      (try
                        (.send dc wire-bytes)
                        (inc acc)
                        (catch :default err
                          (swap! node-atom update-in [:light-state :diagnostics :p2p-send-failed] (fnil inc 0))
                          (emit-browser-event! node-atom {:type "diagnose"
                                                          :kind :p2p-send-failed
                                                          :reason (str "p2p-broadcast-send-failed:" err)
                                                          :timestamp-ms (.now js/Date)})
                          acc)))
                    0
                    open-chans)
          ;; BIP-020 Catch 2: ALWAYS fan out unconditionally to validator mesh/relay as well
          mesh-res (send-to-all-channels! node-atom env)]
      {:mesh-submitted? (boolean (:mesh-submitted? mesh-res))
       :p2p-direct? (pos? p2p-sent)
       :mesh-peers-targeted (long (or (:mesh-peers-targeted mesh-res) 0))
       :p2p-peers-targeted p2p-sent
       :error (when-not (or (:mesh-submitted? mesh-res) (pos? p2p-sent))
                (or (:error mesh-res) "broadcast-fanout-failed"))})

    (:p2p-direct? env)
    (let [peer-pk (light-core/normalize-pubkey-hex (:p2p-peer env))
          entry (get-in @node-atom [:p2p-channels peer-pk])
          dc (:channel entry)]
      (if (and dc (= (.-readyState dc) "open"))
        (let [wire-bytes (fressian/encode-wire env)
              p2p-ok? (try
                        (.send dc wire-bytes)
                        true
                        (catch :default err
                          (swap! node-atom update-in [:light-state :diagnostics :p2p-send-failed] (fnil inc 0))
                          (emit-browser-event! node-atom {:type "diagnose"
                                                          :kind :p2p-send-failed
                                                          :peer-id peer-pk
                                                          :reason (str "p2p-direct-send-failed:" err)
                                                          :timestamp-ms (.now js/Date)})
                          false))]
          (if p2p-ok?
            {:mesh-submitted? false :p2p-direct? true :mesh-peers-targeted 0 :p2p-peers-targeted 1 :error nil}
            (let [mesh-res (send-to-all-channels! node-atom env)]
              (assoc mesh-res :p2p-direct? false :p2p-peers-targeted 0))))
        (do
          (when (:p2p-session-id env)
            (set-p2p-channel-state node-atom (:p2p-session-id env) false {:error "no-direct-route"}))
          (let [mesh-res (send-to-all-channels! node-atom env)]
            (assoc mesh-res :p2p-direct? false :p2p-peers-targeted 0)))))

    :else
    (let [mesh-res (send-to-all-channels! node-atom env)]
      (assoc mesh-res :p2p-direct? false :p2p-peers-targeted 0))))

(defn dial-browser-p2p-peer!
  "Dials a remote P2P candidate peer via WebRTC DataChannel in the browser per Rule 4."
  [node-atom dial-info]
  (when (and node-atom dial-info)
    (let [peer-pk (light-core/normalize-pubkey-hex (:peer dial-info))
          sid (:session-id dial-info)
          existing-entry (get-in @node-atom [:p2p-channels peer-pk])
          existing-dc (:channel existing-entry)]
      (if (and existing-dc (= (.-readyState existing-dc) "open"))
        (set-p2p-channel-state node-atom sid true nil)
        (let [candidates (or (:remote-candidates dial-info) [])
              parsed-candidates (keep #(light-core/parse-p2p-candidate % nil) candidates)
              udp-candidates (vec (filter #(= :udp (or (:transport %) :udp)) parsed-candidates))
              cand (first udp-candidates)]
          (if-not cand
            (set-p2p-channel-state node-atom sid false {:error "no-valid-candidates"})
            (let [p2p-conn-atom (atom (browser/initial-conn-state {:peer-id peer-pk :subnet-id (:subnet-id @node-atom)}))
                  tr-name (name (or (:transport cand) :udp))
                  target-url (str tr-name "://" (:host cand) ":" (:port cand))
                  answer-sdp (browser/format-p2p-sdp-answer dial-info udp-candidates)
                  res (browser/connect-webrtc!
                       p2p-conn-atom
                       {:peer-id peer-pk
                        :target-url target-url
                        :answer-sdp answer-sdp
                        :channel-label "bitecho-p2p"
                        :on-open
                        (fn [{:keys [channel]}]
                          (let [my-gen (inc (long (or (get-in @node-atom [:p2p-channels peer-pk :generation]) 0)))]
                            (swap! node-atom assoc-in [:p2p-channels peer-pk]
                                   {:channel channel
                                    :conn-atom p2p-conn-atom
                                    :session-id sid
                                    :generation my-gen})
                            (try
                              (.addEventListener channel "close"
                                                 (fn [_]
                                                   (let [cur-gen (long (or (get-in @node-atom [:p2p-channels peer-pk :generation]) 0))]
                                                     (if (and (pos? cur-gen) (< my-gen cur-gen))
                                                       (swap! node-atom update-in [:light-state :diagnostics :ignored-stale] (fnil inc 0))
                                                       (do
                                                         (swap! node-atom update :p2p-channels dissoc peer-pk)
                                                         (set-p2p-channel-state node-atom sid false {:error "channel-closed"}))))))
                              (catch :default _ nil)))
                          (let [local-pub (get-in @node-atom [:light-state :pubkey])
                                local-priv (get-in @node-atom [:keypair :private-key])
                                bind-env (build-p2p-link-bind-envelope local-pub local-priv sid)
                                wire-bytes (fressian/encode-wire bind-env)]
                            (try (.send channel wire-bytes) (catch :default _ nil)))
                          (set-p2p-channel-state node-atom sid true {:transport tr-name}))
                        :on-deliver-message
                        (fn [env]
                          (handle-inbound-wire-envelope! node-atom env))})]
              (when-not (:ok? res)
                (set-p2p-channel-state node-atom sid false {:error (or (:error res) "p2p-dial-failed")}))
              res)))))))

(defn handle-inbound-wire-envelope!
  "Processes an incoming wire envelope, updates light state, handles decrypted messages,
   and replies over the WebRTC mesh DataChannel."
  [node-atom env]
  (when (and node-atom env)
    (if (and (map? env) (= :p2p-link-bind (or (:type env) (:bitecho/type env))))
      (let [sender-pk (light-core/normalize-pubkey-hex (:sender env))
            sid (:session-id env)
            sess (get-in @node-atom [:light-state :sessions sid])
            expected-peer (when sess (light-core/normalize-pubkey-hex (:peer sess)))
            p2p-phase (when sess (get-in sess [:p2p :phase]))]
        (if (and (verify-p2p-link-bind env)
                 (some? sess)
                 (= "open" (:state sess))
                 (= sender-pk expected-peer)
                 (contains? #{:offered :offer-received :connecting :open :closed nil} p2p-phase))
          (set-p2p-channel-state node-atom sid true nil)
          (swap! node-atom update-in [:light-state :diagnostics :p2p-signaling-rejected] (fnil inc 0))))
      (let [node @node-atom
            privkey (:private-key (:keypair node))
            st (:light-state node)
            prev-offers (or (:pending-offers st) {})
            prev-sessions (or (:sessions st) {})
            prev-inbox (vec (get-in st [:inbox] []))
            prev-bcasts (vec (get-in st [:broadcast-inbox] []))
            res (light-core/handle-wire-payload st env privkey)
            new-st (:state res)
            curr-inbox (vec (get-in new-st [:inbox] []))
            curr-bcasts (vec (get-in new-st [:broadcast-inbox] []))
            new-direct-msgs (subvec curr-inbox (min (count prev-inbox) (count curr-inbox)))
            new-bcast-msgs (subvec curr-bcasts (min (count prev-bcasts) (count curr-bcasts)))
            new-msgs (into new-direct-msgs new-bcast-msgs)
            curr-offers (or (:pending-offers new-st) {})
            curr-sessions (or (:sessions new-st) {})]
        (swap! node-atom (fn [curr]
                           (-> curr
                               (assoc :light-state (update new-st :inbox #(vec (or % []))))
                               (assoc :sessions (:sessions new-st))
                               (update :chat-history
                                       (fn [hist]
                                         (let [base-hist (vec (or hist []))
                                               seen-keys (into #{}
                                                               (keep (fn [e]
                                                                       (when (and (= (:direction e) :incoming)
                                                                                  (:sessionId e)
                                                                                  (:seq e))
                                                                         [(:sessionId e) (:seq e)])))
                                                               base-hist)
                                               pnames (or (:petnames curr) (:petnames new-st) default-petnames)]
                                           (reduce
                                            (fn [acc m]
                                              (let [sid (or (:session-id m) (:session_id m))
                                                    m-seq (:seq m)
                                                    sender-hex (or (:sender m) (:from m) (:peer-id m))
                                                    pname (some (fn [[k v]]
                                                                  (when (= v sender-hex)
                                                                    (if (keyword? k) (name k) (str k))))
                                                                pnames)
                                                    entry (cond-> {:timestamp (.toISOString (js/Date.))
                                                                   :direction :incoming
                                                                   :peer (or (:from_petname m) (:from-petname m) pname sender-hex "peer")
                                                                   :text (or (:text m) (:message m) (str m))
                                                                   :status :received}
                                                            sid (assoc :sessionId sid)
                                                            (some? m-seq) (assoc :seq m-seq))]
                                                (if (and sid (some? m-seq) (contains? seen-keys [sid m-seq]))
                                                  acc
                                                  (conj acc entry))))
                                            base-hist
                                            new-msgs)))))))
      ;; Surface any new live incoming channel offers into the Human Anchor queue
        (doseq [[sid offer] curr-offers]
          (when-not (contains? prev-offers sid)
            (when-not @anchor-state-atom
              (init-anchor nil))
            (swap! anchor-state-atom light-core/queue-incoming-offer
                   {:offer-id sid
                    :session-id sid
                    :peer-id (:caller offer)
                    :caller-pubkey (:caller offer)
                    :callee-pubkey (:callee offer)
                    :price (or (:price offer) 10)
                    :burn (or (:burn offer) 100)
                    :epoch (or (:epoch offer) 0)})
            (emit-browser-event! node-atom
                                 {:type "offer-received"
                                  :session-id sid
                                  :from (:caller offer)
                                  :price (or (:price offer) 10)
                                  :burn (or (:burn offer) 100)
                                  :epoch (or (:epoch offer) 0)
                                  :timestamp-ms (.now js/Date)})))
        (doseq [[sid sess] curr-sessions]
          (when (not= (:state (get prev-sessions sid)) (:state sess))
            (emit-browser-event! node-atom
                                 {:type "session-updated"
                                  :session-id sid
                                  :from (:peer sess)
                                  :phase (:state sess)
                                  :text (str "session-" (or (:state sess) "updated"))
                                  :timestamp-ms (.now js/Date)})))
        (doseq [reply-env (:net-envelopes res)]
          (route-browser-envelope! node-atom reply-env))
        (when-let [dial-info (:p2p-dial res)]
          (dial-browser-p2p-peer! node-atom dial-info))
        (doseq [m new-direct-msgs]
          (emit-browser-event! node-atom
                               {:type "message-received"
                                :session-id (or (:session-id m) (:session_id m))
                                :subnet-id (or (:subnet-id m) (:subnet_id m))
                                :from (or (:sender m) (:from m) (:peer-id m))
                                :from-petname (or (:from-petname m) (:from_petname m))
                                :seq (:seq m)
                                :text (or (:text m) (:message m))
                                :timestamp-ms (or (:timestamp-ms m) (:timestamp_ms m) (.now js/Date))}))
        (doseq [b new-bcast-msgs]
          (emit-browser-event! node-atom
                               {:type "broadcast-received"
                                :session-id (or (:session-id b) (:session_id b))
                                :subnet-id (or (:subnet-id b) (:subnet_id b) (:subnet b))
                                :from (or (:sender b) (:from b) (:peer-id b))
                                :from-petname (or (:from-petname b) (:from_petname b))
                                :seq (:seq b)
                                :text (or (:text b) (:message b))
                                :timestamp-ms (or (:timestamp-ms b) (:timestamp_ms b) (.now js/Date))}))
        (browser/persist-state! (browser/sanitize-state-for-persistence @node-atom))
        (notify-ui-listeners!)))))

(defn- send-chain-state-query!
  "Sends a signed :query-chain-state envelope on the given DataChannel."
  [node-atom dc]
  (when (and node-atom dc (= (.-readyState dc) "open"))
    (let [node @node-atom
          pubkey (get-in node [:light-state :pubkey])
          privkey (:private-key (:keypair node))]
      (when (and pubkey privkey)
        (let [nonce (str "csq-" (fressian/bytes->hex (crypto/random-bytes 4)))
              q-env (light-core/build-chain-state-query-envelope pubkey privkey {:nonce nonce})]
          (try (.send dc (fressian/encode-wire q-env)) (catch :default _ nil)))))))

(defonce ^:private keepalive-timers-atom (atom {}))
(defonce ^:private redial-timer-atom (atom nil))

(defn- dispatch-redial-event!
  [node-atom ev dial-validator-fn]
  (let [effs-box (atom [])]
    (swap! node-atom
           (fn [st]
             (let [r0 (or (:redial-state st)
                          (browser/initial-redial-state {:peers ["node1" "node2" "node3" "ns1" "ns2" "ns3"]}))
                   [r1 effs] (browser/transition-redial r0 ev)]
               (reset! effs-box effs)
               (assoc st :redial-state r1))))
    (doseq [eff @effs-box]
      (case (:type eff)
        :start-dial
        (when-let [ncfg (get default-bootstrap-nodes (keyword (:peer-id eff)))]
          (when dial-validator-fn
            (dial-validator-fn (:peer-id eff) ncfg)))

        :diagnose
        (emit-browser-event! node-atom (assoc eff :type "diagnose" :timestamp-ms (.now js/Date)))

        nil))))

(defn- on-validator-channel-open!
  "Handles validator DataChannel open: records channel, registers home set, queries chain state, and starts keepalive."
  [node-atom nid dc gen]
  (swap! node-atom assoc-in [:active-channels nid] dc)
  ;; Register home set with devnet nodes when signing key is unlocked
  (when-let [privkey (:private-key (:keypair @node-atom))]
    (let [reg-res (light-core/handle-command (:light-state @node-atom)
                                             {"cmd" "register-home-set" "price" 10 "nodes" ["node1" "node2" "node3" "ns1" "ns2" "ns3"]}
                                             privkey)]
      (swap! node-atom assoc :light-state (:state reg-res))
      (doseq [env (:net-envelopes reg-res)]
        (try (.send dc (fressian/encode-wire env)) (catch :default _ nil)))))
  ;; Fast-path 4-of-6 HTTPS relay chain-state quorum sync (BIP-007)
  (when (= nid "node1")
    (try
      (fetch-relay-chain-state! (or (when (and (exists? js/window) (.-location js/window) (.-origin (.-location js/window)))
                                      (let [o (str (.-origin (.-location js/window)))]
                                        (if (str/starts-with? o "http") o "https://ns1.bitecho.org")))
                                    "https://ns1.bitecho.org")
                                {:node-atom node-atom})
      (catch :default _ nil)))
  ;; Query chain state from validator so 4-of-6 BFT quorum syncs epoch and account
  (send-chain-state-query! node-atom dc)
  ;; Keepalive + epoch/balance sync every 5s (clear any previous interval for nid first)
  (when-let [old-timer (get @keepalive-timers-atom nid)]
    (try (js/clearInterval old-timer) (catch :default _ nil)))
  (let [timer-id (js/setInterval (fn []
                                   (if (and dc (= (.-readyState dc) "open"))
                                     (send-chain-state-query! node-atom dc)
                                     (do
                                       (when-let [tid (get @keepalive-timers-atom nid)]
                                         (try (js/clearInterval tid) (catch :default _ nil))
                                         (swap! keepalive-timers-atom dissoc nid))
                                       ;; Rule 5: If browser DC closed without onclose transitioning peer, record it loudly
                                       (let [peer-st (get-in @node-atom [:mesh-conns :peers nid])]
                                         (when (and peer-st (= :open (:phase peer-st)))
                                           (dispatch-mesh-peer-event!
                                            node-atom
                                            nid
                                            {:type :close
                                             :generation (long (or gen (:generation peer-st) 0))
                                             :cause "keepalive-detected-closed"
                                             :timestamp-ms (.now js/Date)}
                                            nil)))
                                       (notify-ui-listeners!))))
                                 5000)]
    (swap! keepalive-timers-atom assoc nid timer-id))
  (notify-ui-listeners!))

(defn connect-mesh
  "Connects live browser light-node to Bitecho devnet mesh via WebRTC DataChannels.
   Routes all 6 validator connections through single-authority `[:mesh-conns]` inside `node-atom`
   so every ICE disconnect, failure, error, or close is tracked with zero silent losses (Rules 4 & 5)."
  ([] (connect-mesh nil))
  ([opts]
   (if-not (:ok? (light-core/verify-bootstrap-descriptor default-authority-pubkey default-bootstrap-descriptor 0))
     (clj->js {:ok false :error "untrusted-bootstrap-descriptor"})
     (let [node-atom (or @active-node-atom (init-node nil))
           _opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
           _ (try
               (fetch-relay-chain-state! (or (when (and (exists? js/window) (.-location js/window) (.-origin (.-location js/window)))
                                               (let [o (str (.-origin (.-location js/window)))]
                                                 (if (str/starts-with? o "http") o "https://ns1.bitecho.org")))
                                             "https://ns1.bitecho.org")
                                         {:node-atom node-atom})
               (catch :default _ nil))
           _ (doseq [[_nid tid] @keepalive-timers-atom]
               (try (js/clearInterval tid) (catch :default _ nil)))
           _ (reset! keepalive-timers-atom {})
           _ (doseq [[_nid old-dc] (:active-channels @node-atom)]
               (when old-dc
                 (try (.close old-dc) (catch :default _ nil))))
           _ (when-let [old-rt @redial-timer-atom]
               (try (js/clearInterval old-rt) (catch :default _ nil))
               (reset! redial-timer-atom nil))
           _ (swap! node-atom assoc
                    :active-channels {}
                    :redial-state (browser/initial-redial-state {:peers ["node1" "node2" "node3" "ns1" "ns2" "ns3"]}))
           node1 (get default-bootstrap-nodes :node1)
           dial-validator!
           (fn dial-validator! [nid-str ncfg]
             (let [sdp (browser/format-validator-sdp-answer ncfg)
                   target-url (str "rtc://" (:ip ncfg) ":" (:agent-port ncfg))]
               (browser/connect-webrtc!
                nil
                {:peer-id nid-str
                 :target-url target-url
                 :answer-sdp sdp
                 :channel-label "bitecho"
                 :dispatch! (fn [ev eff-handler]
                              (dispatch-mesh-peer-event! node-atom nid-str ev eff-handler))
                 :on-open (fn [open-info]
                            (dispatch-redial-event!
                             node-atom
                             {:type :peer-open :peer-id nid-str :generation (:generation open-info) :now-ms (.now js/Date)}
                             dial-validator!)
                            (on-validator-channel-open! node-atom nid-str (:channel open-info) (:generation open-info)))
                 :on-close (fn [_close-info]
                             (when-let [tid (get @keepalive-timers-atom nid-str)]
                               (try (js/clearInterval tid) (catch :default _ nil))
                               (swap! keepalive-timers-atom dissoc nid-str))
                             (dispatch-redial-event!
                              node-atom
                              {:type :peer-down :peer-id nid-str :now-ms (.now js/Date)}
                              dial-validator!)
                             (notify-ui-listeners!))
                 :on-diagnose (fn [diag-eff]
                                (when (contains? #{:ice-disconnected :ice-failed :ice-closed :dial-failed} (:kind diag-eff))
                                  (dispatch-redial-event!
                                   node-atom
                                   {:type (if (= :dial-failed (:kind diag-eff)) :dial-failed :peer-down)
                                    :peer-id nid-str
                                    :generation (:generation diag-eff)
                                    :now-ms (.now js/Date)}
                                   dial-validator!))
                                (notify-ui-listeners!))
                 :on-deliver-message (fn [env]
                                       (handle-inbound-wire-envelope! node-atom env))})))
           relay-origin (or (when (and (exists? js/window) (.-location js/window) (.-origin (.-location js/window)))
                              (let [o (str (.-origin (.-location js/window)))]
                                (if (str/starts-with? o "http") o "https://ns1.bitecho.org")))
                            "https://ns1.bitecho.org")]
       ;; Dial all 6 validators (node1..ns3) through single-authority mesh-conns for 4-of-6 BFT quorum
       (doseq [nid [:node1 :node2 :node3 :ns1 :ns2 :ns3]]
         (when-let [ncfg (get default-bootstrap-nodes nid)]
           (dial-validator! (name nid) ncfg)))
       ;; Bounded auto-redial tick + HTTPS relay fallback when 0/6 mesh peers are open (BIP-020 Catch 2 & 3)
       (reset! redial-timer-atom
               (js/setInterval
                (fn []
                  (when-let [st @node-atom]
                    (let [now-ms (.now js/Date)
                          mesh-summary (browser/summarize-mesh-diagnostics (:mesh-conns st))
                          zero-open? (empty? (:open-peers mesh-summary))]
                      (dispatch-redial-event! node-atom {:type :tick :now-ms now-ms} dial-validator!)
                      (swap! node-atom assoc :relay-fallback-active? zero-open?)
                      (when zero-open?
                        (try
                          (fetch-relay-chain-state! relay-origin {:node-atom node-atom})
                          (catch :default err
                            (swap! node-atom update-in [:light-state :diagnostics :relay-fallback-error] (fnil inc 0))
                            (emit-browser-event! node-atom {:type "diagnose"
                                                            :kind :relay-fallback-error
                                                            :reason (str err)
                                                            :timestamp-ms now-ms})))))))
                2000))
       (notify-ui-listeners!)
       (clj->js {:ok true
                 :connected false
                 :dialing true
                 :status "connecting"
                 :targetNode "node1"
                 :targetNodes ["node1" "node2" "node3" "ns1" "ns2" "ns3"]
                 :ip (:ip node1)
                 :port (:agent-port node1)})))))

(defn- resolve-peer-target
  "Resolves peer identifier or petname against :petnames, default-petnames,
   and anchor-state-atom :supervised-agents, returning hex public key string.
   Uses safe-map-get so populated string-keyed sorted-maps never throw CLJS CompareError."
  [node peer-or-petname]
  (let [target (if (keyword? peer-or-petname) (name peer-or-petname) (str peer-or-petname))
        kw-target (keyword target)
        pnames (:petnames node)
        agents (when-let [st @anchor-state-atom] (:supervised-agents st))
        agent-entry (when (map? agents)
                      (or (light-core/safe-map-get agents target)
                          (light-core/safe-map-get agents kw-target)))]
    (or (light-core/safe-map-get pnames target)
        (light-core/safe-map-get pnames kw-target)
        (light-core/safe-map-get default-petnames target)
        (light-core/safe-map-get default-petnames kw-target)
        (when (map? agent-entry)
          (or (light-core/safe-map-get agent-entry :agent-pubkey)
              (light-core/safe-map-get agent-entry "agent-pubkey")
              (light-core/safe-map-get agent-entry :pubkey)
              (light-core/safe-map-get agent-entry "pubkey")))
        target)))

(defn open-channel
  "Initiates a cryptographically signed channel offer to callee over the live mesh DataChannel.
   Returns {:ok false :error 'not-connected'} if no channels are open and phase is not :open."
  ([callee] (open-channel @active-node-atom callee 10 500))
  ([arg1 arg2]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (open-channel arg1 arg2 10 500)
     (open-channel @active-node-atom arg1 arg2 500)))
  ([arg1 arg2 arg3]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (open-channel arg1 arg2 arg3 500)
     (open-channel @active-node-atom arg1 arg2 arg3)))
  ([node-atom callee price burn]
   (let [na (or node-atom @active-node-atom)]
     (if-not na
       (clj->js {:ok false :error "not-connected"})
       (let [node @na
             channels (or (:active-channels node) {})
             phase (get-in node [:conn :phase])]
         (if (and (empty? channels) (not= phase :open))
           (clj->js {:ok false :error "not-connected"})
           (if-not (:private-key (:keypair node))
             (clj->js {:ok false :error "hardware-unlock-required"})
             (let [target-pub (resolve-peer-target node callee)
                   privkey (:private-key (:keypair node))
                   cmd-res (light-core/handle-command (:light-state node)
                                                      {"cmd" "offer"
                                                       "callee" target-pub
                                                       "price" (or price 10)
                                                       "burn" (or burn 500)}
                                                      privkey)
                   new-st (:state cmd-res)
                   out-envs (:net-envelopes cmd-res)
                   resp (:response cmd-res)
                   cmd-ok? (boolean (get resp "ok" true))]
               (swap! na (fn [curr]
                           (-> curr
                               (assoc :light-state new-st)
                               (assoc :sessions (:sessions new-st)))))
               (doseq [env out-envs]
                 (send-to-all-channels! na env))
               (browser/persist-state! (browser/sanitize-state-for-persistence @na))
               (notify-ui-listeners!)
               (clj->js (cond-> {:ok cmd-ok?
                                 :callee callee
                                 :sessionId (get resp "session_id")
                                 :envelopesSent (count out-envs)
                                 :response resp}
                          (not cmd-ok?) (assoc :error (get resp "error"))))))))))))

(defn accept-channel-offer
  "Accepts a pending session offer by session-id over the live mesh DataChannel."
  ([session-id] (accept-channel-offer @active-node-atom session-id))
  ([node-atom session-id]
   (let [na (or node-atom @active-node-atom)
         node @na
         privkey (:private-key (:keypair node))]
     (if-not privkey
       (clj->js {:ok false :error "hardware-unlock-required"})
       (let [cmd-res (light-core/handle-command (:light-state node)
                                                {"cmd" "accept" "session_id" session-id}
                                                privkey)
             new-st (:state cmd-res)
             out-envs (:net-envelopes cmd-res)
             resp (:response cmd-res)
             cmd-ok? (boolean (get resp "ok" true))]
         (swap! na (fn [curr]
                     (-> curr
                         (assoc :light-state new-st)
                         (assoc :sessions (:sessions new-st)))))
         (doseq [env out-envs]
           (route-browser-envelope! na env))
         (browser/persist-state! (browser/sanitize-state-for-persistence @na))
         (notify-ui-listeners!)
         (clj->js (cond-> {:ok cmd-ok?
                           :sessionId session-id
                           :response resp}
                    (not cmd-ok?) (assoc :error (get resp "error")))))))))

(defn- resolve-best-open-session-id
  "Resolves the newest usable 'open' session-id (with :tx-key present) for target-pub,
   or explicit-sid if provided."
  [sessions target-pub explicit-sid]
  (cond
    (and (string? explicit-sid) (contains? sessions explicit-sid))
    explicit-sid

    (and (string? target-pub) (contains? sessions target-pub))
    target-pub

    :else
    (let [open-candidates (->> sessions
                               (filter (fn [[_sid s]]
                                         (and (= (:peer s) target-pub)
                                              (= (:state s) "open")
                                              (some? (:tx-key s)))))
                               (sort-by (fn [[sid s]]
                                          [(long (or (:epoch s) 0))
                                           (long (or (:tx-seq s) 0))
                                           (str sid)])))]
      (first (last open-candidates)))))

(defn send-message
  "Sends a cryptographically sealed message to a peer or explicit session-id over the live mesh DataChannel."
  ([peer-id text] (send-message @active-node-atom peer-id text nil))
  ([arg1 arg2 arg3]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (send-message arg1 arg2 arg3 nil)
     (send-message @active-node-atom arg1 arg2 arg3)))
  ([node-atom peer-id text explicit-session-id]
   (let [na (or node-atom @active-node-atom)
         node @na
         sessions (or (get-in node [:light-state :sessions]) {})
         direct-sess (get sessions peer-id)
         target-pub (if direct-sess
                      (:peer direct-sess)
                      (or (get (:petnames node) peer-id)
                          (get default-petnames peer-id)
                          peer-id))
         resolved-sid (resolve-best-open-session-id sessions target-pub (or explicit-session-id (when direct-sess peer-id)))
         resolved-sess (when resolved-sid (get sessions resolved-sid))
         actual-peer-pub (or (:peer resolved-sess) target-pub)
         pnames (or (:petnames node) (get-in node [:light-state :petnames]) default-petnames)
         resolved-peer-label (or (some (fn [[k v]]
                                         (when (= v actual-peer-pub)
                                           (if (keyword? k) (name k) (str k))))
                                       pnames)
                                 (when (and (not direct-sess) (not explicit-session-id)) peer-id)
                                 actual-peer-pub)
         privkey (:private-key (:keypair node))]
     (if-not privkey
       (clj->js {:ok false :error "hardware-unlock-required"})
       (let [cmd-map (cond-> {"cmd" "send"
                              "peer" actual-peer-pub
                              "text" (str text)
                              "message" (str text)}
                       resolved-sid (assoc "session_id" resolved-sid))
             cmd-res (light-core/handle-command (:light-state node)
                                                cmd-map
                                                privkey)
             new-st (:state cmd-res)
             out-envs (:net-envelopes cmd-res)
             resp (:response cmd-res)
             cmd-ok? (and (boolean (get resp "ok" true))
                          (pos? (count out-envs)))]
         (swap! na (fn [curr]
                     (cond-> (-> curr
                                 (assoc :light-state new-st)
                                 (assoc :sessions (:sessions new-st)))
                       cmd-ok?
                       (update :chat-history
                               (fn [h]
                                 (conj (vec (or h []))
                                       {:timestamp (.toISOString (js/Date.))
                                        :direction :outgoing
                                        :peer resolved-peer-label
                                        :sessionId resolved-sid
                                        :text text
                                        :status :sent}))))))
         (doseq [env out-envs]
           (route-browser-envelope! na env))
         (browser/persist-state! (browser/sanitize-state-for-persistence @na))
         (notify-ui-listeners!)
         (clj->js (cond-> {:ok cmd-ok?
                           :peer resolved-peer-label
                           :sessionId resolved-sid
                           :text text
                           :envelopesSent (count out-envs)
                           :response resp}
                    (not cmd-ok?) (assoc :error (or (get resp "error") "no-open-session-for-peer")))))))))

(defn close-session
  "Removes or closes a session by session-id from the browser light-node state."
  ([session-id] (close-session @active-node-atom session-id))
  ([node-atom session-id]
   (let [na (or node-atom @active-node-atom)
         sid (str session-id)]
     (when na
       (swap! na (fn [curr]
                   (-> curr
                       (update-in [:light-state :sessions] dissoc sid)
                       (update :sessions dissoc sid))))
       (browser/persist-state! (browser/sanitize-state-for-persistence @na))
       (notify-ui-listeners!))
     (clj->js {:ok true :closedSessionId sid}))))

(defn get-chat-history
  "Returns the vector of chat messages exchanged with peers."
  ([] (get-chat-history @active-node-atom))
  ([node-atom]
   (clj->js (or (:chat-history @(or node-atom @active-node-atom)) []))))

(defn get-sessions
  "Returns active and pending sessions map."
  ([] (get-sessions @active-node-atom))
  ([node-atom]
   (let [node @(or node-atom @active-node-atom)
         st (:light-state node)
         sessions (or (:sessions st) {})]
     (clj->js (into {} (map (fn [[k v]] [(str k) (redact-for-js v)]) sessions))))))

(defn resolve-peer
  "Resolves a petname or handle ('axiom', 'nexus') to public key."
  [handle]
  (let [h (str handle)
        known (or (get default-petnames h)
                  (when @active-node-atom (get (:petnames @active-node-atom) h)))]
    (if known
      (js/Promise.resolve #js {:handle h :pubkey known :cached true})
      (if (exists? js/fetch)
        (-> (.fetch js/globalThis (str "/" h "/agent.json"))
            (.then (fn [res] (if (.-ok res) (.json res) (throw (js/Error. (str "HTTP " (.-status res)))))))
            (.then (fn [data] #js {:handle h :pubkey (or (aget data "pubkey") (aget data "pubkey_hex")) :remote true}))
            (.catch (fn [_] #js {:handle h :pubkey h :raw true})))
        (js/Promise.resolve #js {:handle h :pubkey h})))))

(defn handle-visibility-change!
  "Dispatches visibility change ('visible' | 'hidden') into active node's connection state and mesh-conns."
  ([vis-state] (handle-visibility-change! @active-node-atom vis-state))
  ([node-atom vis-state]
   (when node-atom
     (let [state-str (if (= (str vis-state) "hidden") "hidden" "visible")
           [new-conn effects] (browser/transition-conn (:conn @node-atom)
                                                       {:type :visibility-change :state state-str})
           [new-mesh _mesh-effs] (browser/transition-mesh-visibility (:mesh-conns @node-atom) state-str)]
       (swap! node-atom assoc :conn new-conn :mesh-conns new-mesh)
       (clj->js {:visibilityState (:visibility-state new-conn)
                 :effects effects})))))

(defn save-state-to-indexed-db
  "Persists current sanitized node state into IndexedDB. Returns a Promise."
  ([] (save-state-to-indexed-db @active-node-atom))
  ([node-atom]
   (js/Promise.
    (fn [resolve reject]
      (if-not node-atom
        (reject (js/Error. "no-active-node"))
        (let [clean (browser/sanitize-state-for-persistence @node-atom)]
          (browser/persist-state!
           clean
           (fn [err res]
             (if err
               (reject (js/Error. (str (or (:error err) err))))
               (resolve (clj->js (redact-for-js (or res {:ok true})))))))))))))

(defn restore-from-indexed-db!
  "Loads persisted sanitized state from IndexedDB and applies it to node-atom and anchor-state-atom.
   Invokes optional callback (cb [err restored-map])."
  ([] (restore-from-indexed-db! @active-node-atom nil))
  ([node-atom] (restore-from-indexed-db! node-atom nil))
  ([node-atom cb]
   (let [na (or node-atom @active-node-atom)]
     (browser/load-persisted-state
      (fn [err loaded]
        (let [restored (if (and (nil? err) na (map? loaded))
                         (apply-restored-state! na loaded)
                         loaded)]
          (when cb
            (cb err restored))))))))

(defn load-state-from-indexed-db
  "Loads persisted sanitized state from IndexedDB and restores public identity continuity. Returns a Promise."
  ([] (load-state-from-indexed-db @active-node-atom))
  ([node-atom]
   (js/Promise.
    (fn [resolve reject]
      (restore-from-indexed-db!
       node-atom
       (fn [err restored]
         (if err
           (reject (js/Error. (str err)))
           (resolve (clj->js (redact-for-js (or restored {})))))))))))

(defn connect
  "Initiates dialing transition on the node's connection state and executes effects.
   When called with 0 arguments or an options object (without node-atom), delegates to connect-mesh."
  ([] (connect-mesh nil))
  ([arg1]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (connect arg1 nil)
     (connect-mesh arg1)))
  ([node-atom opts]
   (let [na (or node-atom @active-node-atom)
         opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
         target-url (or (:target-url opts-map) (:targetUrl opts-map) "rtc://default")
         [new-conn effects] (browser/transition-conn (:conn @na)
                                                     {:type :dial :target-url target-url})]
     (swap! na assoc :conn new-conn)
     (doseq [eff effects]
       (case (:type eff)
         :diagnose nil
         :close-transport (when-let [t (:transport eff)] (try (.close t) (catch :default _ nil)))
         nil))
     (clj->js {:conn (get-status na)
               :effects effects}))))

(defn create-offer
  "Creates a cryptographically signed rendezvous/channel offer descriptor conforming to Phase 1 wire format.
   Supports:
     (create-offer peer-or-petname)
     (create-offer peer-or-petname amount)
     (create-offer peer-or-petname amount memo)
     (create-offer node-atom peer-id & [opts])
   Resolves peer-or-petname against (:petnames node), default-petnames, and (:supervised-agents @anchor-state-atom)."
  ([arg1]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (create-offer arg1 nil nil)
     (create-offer @active-node-atom arg1 nil)))
  ([arg1 arg2]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (create-offer arg1 arg2 nil)
     (create-offer @active-node-atom arg1 (if (map? arg2) arg2 {:burn arg2 :price arg2}))))
  ([arg1 arg2 arg3]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (let [node-atom arg1
           peer-id arg2
           opts arg3
           node @node-atom
           opts-map (cond
                      (map? opts) opts
                      (some? opts) (js->clj opts :keywordize-keys true)
                      :else {})
           x25519 (:x25519 node)
           keypair (:keypair node)
           caller-pub (fressian/bytes->hex (:public-key keypair))
           caller-eph (fressian/bytes->hex (:public-key x25519))
           raw-callee (or peer-id (:callee opts-map) (:callee-pubkey opts-map))
           callee-pub (resolve-peer-target node raw-callee)
           epoch (or (:epoch opts-map) 1)
           burn (or (:burn opts-map) (:burn-amount opts-map) 100)
           price (or (:price opts-map) burn)
           memo (or (:memo opts-map) "")
           sub-id (or (:subnet-id node) "global")
           net-uri (or (:network-uri node) (config/resolve-network-uri (:subnet-id node)))
           suites (or (:crypto-suites opts-map) ["suite-v1-aes256gcm"])
           sid (light-core/compute-session-id caller-pub callee-pub caller-eph)
           offer-hash (light-core/compute-offer-hash (cond-> {:session-id sid
                                                              :caller caller-pub
                                                              :callee callee-pub
                                                              :caller-ephemeral-pub caller-eph
                                                              :epoch epoch
                                                              :price price
                                                              :burn burn
                                                              :home-node ""
                                                              :crypto-suites suites
                                                              :subnet-id sub-id}
                                                       net-uri (assoc :network-uri net-uri)))
           privkey-bytes (:private-key keypair)
           sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes offer-hash)))
           offer (cond-> {:type :rendezvous-offer
                          :bitecho/type :channel-offer
                          :protocol-version 1
                          :wire-format "fressian-v1"
                          :subnet-id sub-id
                          :session-id sid
                          :caller caller-pub
                          :caller-pubkey caller-pub
                          :callee callee-pub
                          :callee-pubkey callee-pub
                          :caller-ephemeral-pub caller-eph
                          :caller-x25519 caller-eph
                          :crypto-suites suites
                          :epoch epoch
                          :price price
                          :burn burn
                          :burn-amount burn
                          :offer-hash offer-hash
                          :signature sig-hex}
                   net-uri (assoc :network-uri net-uri)
                   (and (string? memo) (seq memo)) (assoc :memo memo))]
       (swap! node-atom update :burned-ech (fnil + 0) burn)
       (clj->js offer))
     (let [peer-id arg1
           amount arg2
           memo arg3]
       (create-offer @active-node-atom peer-id (cond-> {:burn (or amount 100)
                                                        :price (or amount 100)}
                                                 memo (assoc :memo memo)))))))

(defn accept-offer
  "Explicitly accepts an incoming offer after validating its cryptographic signature."
  ([offer]
   (if (nil? offer)
     (clj->js {:ok false :accepted false :error "invalid-offer"})
     (if-let [na @active-node-atom]
       (accept-offer na offer)
       (clj->js {:ok false :accepted false :error "no-active-node"}))))
  ([node-atom offer]
   (if (nil? offer)
     (clj->js {:ok false :accepted false :error "invalid-offer"})
     (let [na (or (when (or (satisfies? IAtom node-atom)
                            (and (some? node-atom) (fn? (.-deref node-atom))))
                    node-atom)
                  @active-node-atom)]
       (if (nil? na)
         (clj->js {:ok false :accepted false :error "no-active-node"})
         (let [offer-clj (cond
                           (string? offer) offer
                           (map? offer) offer
                           :else (js->clj offer :keywordize-keys true))
               pending-offers (or (get-in @na [:light-state :pending-offers]) {})
               classified (browser/classify-accept-offer-target offer-clj pending-offers)]
           (case (:mode classified)
             :mesh-channel
             (let [sid (:session-id classified)]
               (when @anchor-state-atom
                 (let [[new-anchor _] (light-core/approve-offer @anchor-state-atom sid nil)]
                   (reset! anchor-state-atom new-anchor)))
               (accept-channel-offer na sid))

             :invalid
             (clj->js (cond-> {:ok false
                               :accepted false
                               :error (or (:error classified) "invalid-offer")}
                        (:session-id classified) (assoc :sessionId (:session-id classified))))

             :p2p-direct
             (let [offer-map (:offer classified)
                   caller-pub (or (:caller-pubkey offer-map) (:caller offer-map))
                   caller-x25519 (when-let [x (:caller-x25519 classified)]
                                   (fressian/hex->bytes x))
                   offer-hash (or (:offer-hash offer-map) (:offerHash offer-map))
                   sig-hex (:signature offer-map)
                   sig-valid? (and (string? caller-pub) (string? offer-hash) (string? sig-hex)
                                   (crypto/verify (basalt/hex->bytes caller-pub)
                                                  (fressian/utf8->bytes offer-hash)
                                                  (basalt/hex->bytes sig-hex)))
                   my-x25519 (:x25519 @na)]
               (cond
                 (not sig-valid?)
                 (clj->js {:ok false :accepted false :error "invalid-offer-signature"})

                 (or (nil? caller-x25519) (nil? (:private-key my-x25519)))
                 (clj->js {:ok false :accepted false :error "missing-x25519-key"})

                 :else
                 (let [shared-secret (sealed/x25519-shared-secret (:private-key my-x25519) caller-x25519)
                       session-keys (sealed/derive-channel-keys shared-secret "bitecho-browser-session-salt" :responder)
                       burn (long (or (:burn offer-map) (:burn-amount offer-map) 50))]
                   (swap! na (fn [st]
                               (-> st
                                   (assoc-in [:sessions caller-pub] {:session-keys session-keys
                                                                     :suite "suite-v1-aes256gcm"
                                                                     :seq 0})
                                   (update :burned-ech (fnil + 0) burn))))
                   (clj->js {:ok true
                             :accepted true
                             :peerId caller-pub
                             :suite "suite-v1-aes256gcm"})))))))))))

(defn send-sealed-message
  "Seals and sends a message to an active peer session."
  ([peer-id]
   (send-sealed-message nil peer-id nil))
  ([peer-id text]
   (cond
     (or (nil? peer-id) (and (string? peer-id) (str/blank? peer-id)))
     (clj->js {:ok false :sent false :error "invalid-peer"})

     (nil? text)
     (clj->js {:ok false :sent false :error "invalid-message"})

     :else
     (if-let [na @active-node-atom]
       (send-sealed-message na peer-id text)
       (clj->js {:ok false :sent false :error "no-active-node"}))))
  ([node-atom peer-id text]
   (cond
     (or (nil? peer-id) (and (string? peer-id) (str/blank? peer-id)))
     (clj->js {:ok false :sent false :error "invalid-peer"})

     (nil? text)
     (clj->js {:ok false :sent false :error "invalid-message"})

     :else
     (let [na (or (when (or (satisfies? IAtom node-atom)
                            (and (some? node-atom) (fn? (.-deref node-atom))))
                    node-atom)
                  @active-node-atom)]
       (if-not na
         (clj->js {:ok false :sent false :error "no-active-node"})
         (let [node @na
               resolved-peer (resolve-peer-target node peer-id)
               session (or (get-in node [:sessions resolved-peer])
                           (get-in node [:sessions peer-id]))
               eff-peer (if (get-in node [:sessions resolved-peer]) resolved-peer peer-id)
               session-keys (:session-keys session)]
           (if-not session-keys
             (clj->js {:ok false :sent false :error "no-open-session"})
             (let [seq-num (inc (or (:seq session) 0))
                   plaintext (fressian/utf8->bytes (str text))
                   sealed-frame (sealed/seal-message session-keys seq-num plaintext "suite-v1-aes256gcm")
                   env {:type :sealed-message
                        :protocol-version 1
                        :wire-format "fressian-v1"
                        :sender (fressian/bytes->hex (:public-key (:keypair node)))
                        :recipient eff-peer
                        :sealed-frame sealed-frame}
                   route-res (route-browser-envelope! na env)
                   delivered? (boolean (or (:mesh-submitted? route-res) (:p2p-direct? route-res)))]
               (swap! na (fn [st]
                           (-> st
                               (assoc-in [:sessions eff-peer :seq] seq-num)
                               (update :outbox conj env))))
               (clj->js {:ok (and (some? sealed-frame) delivered?)
                         :sent (and (some? sealed-frame) delivered?)
                         :meshSubmitted (boolean (:mesh-submitted? route-res))
                         :p2pDirect (boolean (:p2p-direct? route-res))
                         :error (when-not delivered? (:error route-res))
                         :seq seq-num})))))))))

(defn run-subnet-demo
  "Runs the browser-only subnet demo and returns a JavaScript summary object."
  [& _args]
  (clj->js (browser/run-browser-subnet-demo)))

(defn run-zero-burn-subnet-demo
  "Runs the zero-burn team subnet demo and returns a JavaScript summary object."
  [& _args]
  (clj->js (light-core/run-zero-burn-team-subnet-demo)))

(defn run-federation-demo
  "Runs the two-domain federation demo and returns a JavaScript summary object."
  [& _args]
  (clj->js (light-core/run-two-domain-federation-demo)))

(defn run-three-way-p2p-broadcast-demo
  "Runs the Milestone 16 (M4) three-way direct P2P ICE + mDNS handshake and zero-burn broadcast demo."
  [& _args]
  (clj->js (light-core/run-three-way-p2p-broadcast-demo)))

(defn p2p-offer
  "Initiates a direct P2P ICE + mDNS offer over an existing sealed session."
  ([session-id] (p2p-offer @active-node-atom session-id nil))
  ([arg1 arg2]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (p2p-offer arg1 arg2 nil)
     (p2p-offer @active-node-atom arg1 arg2)))
  ([node-atom session-id opts]
   (let [na (or node-atom @active-node-atom)]
     (if-not na
       (clj->js {:ok false :error "no-active-node"})
       (let [node @na
             privkey (:private-key (:keypair node))
             opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
             candidates (or (:candidates opts-map) [])]
         (if-not privkey
           (clj->js {:ok false :error "hardware-unlock-required"})
           (let [cmd-res (light-core/handle-command (:light-state node)
                                                    (cond-> {"cmd" "p2p-offer"
                                                             "session_id" (str session-id)}
                                                      (seq candidates) (assoc "candidates" candidates))
                                                    privkey)
                 new-st (:state cmd-res)
                 out-envs (:net-envelopes cmd-res)
                 resp (:response cmd-res)
                 cmd-ok? (boolean (get resp "ok" true))]
             (swap! na (fn [curr]
                         (-> curr
                             (assoc :light-state new-st)
                             (assoc :sessions (:sessions new-st)))))
             (doseq [env out-envs]
               (route-browser-envelope! na env))
             (when-let [dial-info (:p2p-dial cmd-res)]
               (dial-browser-p2p-peer! na dial-info))
             (browser/persist-state! (browser/sanitize-state-for-persistence @na))
             (notify-ui-listeners!)
             (clj->js (cond-> {:ok cmd-ok?
                               :sessionId (str session-id)
                               :envelopesSent (count out-envs)
                               :response resp}
                        (not cmd-ok?) (assoc :error (get resp "error")))))))))))

(defn p2p-answer
  "Answers a pending direct P2P ICE + mDNS offer over an existing sealed session."
  ([session-id] (p2p-answer @active-node-atom session-id nil))
  ([arg1 arg2]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (p2p-answer arg1 arg2 nil)
     (p2p-answer @active-node-atom arg1 arg2)))
  ([node-atom session-id opts]
   (let [na (or node-atom @active-node-atom)]
     (if-not na
       (clj->js {:ok false :error "no-active-node"})
       (let [node @na
             privkey (:private-key (:keypair node))
             opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
             candidates (or (:candidates opts-map) [])]
         (if-not privkey
           (clj->js {:ok false :error "hardware-unlock-required"})
           (let [cmd-res (light-core/handle-command (:light-state node)
                                                    (cond-> {"cmd" "p2p-answer"
                                                             "session_id" (str session-id)}
                                                      (seq candidates) (assoc "candidates" candidates))
                                                    privkey)
                 new-st (:state cmd-res)
                 out-envs (:net-envelopes cmd-res)
                 resp (:response cmd-res)
                 cmd-ok? (boolean (get resp "ok" true))]
             (swap! na (fn [curr]
                         (-> curr
                             (assoc :light-state new-st)
                             (assoc :sessions (:sessions new-st)))))
             (doseq [env out-envs]
               (route-browser-envelope! na env))
             (when-let [dial-info (:p2p-dial cmd-res)]
               (dial-browser-p2p-peer! na dial-info))
             (browser/persist-state! (browser/sanitize-state-for-persistence @na))
             (notify-ui-listeners!)
             (clj->js (cond-> {:ok cmd-ok?
                               :sessionId (str session-id)
                               :envelopesSent (count out-envs)
                               :response resp}
                        (not cmd-ok?) (assoc :error (get resp "error")))))))))))

(defn set-p2p-channel-state
  "Sets the direct P2P transport connectivity status for a session per Rule 4."
  ([session-id connected?]
   (set-p2p-channel-state @active-node-atom session-id connected? nil))
  ([arg1 arg2 arg3]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (set-p2p-channel-state arg1 arg2 arg3 nil)
     (set-p2p-channel-state @active-node-atom arg1 arg2 arg3)))
  ([node-atom session-id connected? opts]
   (let [na (or (when (or (satisfies? IAtom node-atom)
                          (and (some? node-atom) (fn? (.-deref node-atom))))
                  node-atom)
                @active-node-atom)]
     (if-not na
       (clj->js {:ok false :error "no-active-node"})
       (let [node @na
             privkey (:private-key (:keypair node))
             opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
             transport (:transport opts-map)
             err-val (or (:error opts-map) (:reason opts-map))
             cmd-map (cond-> {"cmd" "p2p-channel-state"
                              "session_id" (str session-id)
                              "connected" (boolean connected?)}
                       transport (assoc "transport" (str transport))
                       err-val (assoc "error" (str err-val)))
             cmd-res (light-core/handle-command (:light-state node) cmd-map privkey)
             new-st (:state cmd-res)
             resp (:response cmd-res)
             cmd-ok? (boolean (get resp "ok" true))]
         (swap! na (fn [curr]
                     (-> curr
                         (assoc :light-state new-st)
                         (assoc :sessions (:sessions new-st)))))
         (browser/persist-state! (browser/sanitize-state-for-persistence @na))
         (notify-ui-listeners!)
         (clj->js (cond-> {:ok cmd-ok?
                           :sessionId (str session-id)
                           :connected (boolean connected?)
                           :response resp}
                    (not cmd-ok?) (assoc :error (get resp "error")))))))))

(defn broadcast-message
  "Broadcasts a zero-burn message across the 3-way mesh subnet (default node's subnet, 'chat/simon-nexus-axiom', or 'global')."
  ([text] (broadcast-message @active-node-atom text nil))
  ([arg1 arg2]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (broadcast-message arg1 arg2 nil)
     (broadcast-message @active-node-atom arg1 arg2)))
  ([node-atom text subnet-id]
   (let [na (or node-atom @active-node-atom)]
     (if-not na
       (clj->js {:ok false :error "no-active-node"})
       (let [node @na
             privkey (:private-key (:keypair node))
             eff-subnet (or (when (and (string? subnet-id) (not (str/blank? subnet-id))) subnet-id)
                            (:subnet-id node)
                            (get-in node [:light-state :subnet-id])
                            light-core/simon-nexus-axiom-subnet-id
                            "global")]
         (if-not privkey
           (clj->js {:ok false :error "hardware-unlock-required"})
           (let [cmd-res (light-core/handle-command (:light-state node)
                                                    {"cmd" "broadcast"
                                                     "text" (str text)
                                                     "message" (str text)
                                                     "subnet_id" (str eff-subnet)}
                                                    privkey)
                 new-st (:state cmd-res)
                 out-envs (:net-envelopes cmd-res)
                 resp (:response cmd-res)
                 cmd-ok? (boolean (get resp "ok" true))]
             (swap! na (fn [curr]
                         (cond-> (-> curr
                                     (assoc :light-state new-st)
                                     (assoc :sessions (:sessions new-st)))
                           cmd-ok?
                           (update :chat-history
                                   (fn [h]
                                     (conj (vec (or h []))
                                           {:timestamp (.toISOString (js/Date.))
                                            :direction :outgoing
                                            :peer eff-subnet
                                            :sessionId eff-subnet
                                            :text (str text)
                                            :status :sent}))))))
             (doseq [env out-envs]
               (route-browser-envelope! na env))
             (when-let [dial-info (:p2p-dial cmd-res)]
               (dial-browser-p2p-peer! na dial-info))
             (browser/persist-state! (browser/sanitize-state-for-persistence @na))
             (notify-ui-listeners!)
             (clj->js (cond-> {:ok cmd-ok?
                               :subnetId eff-subnet
                               :text (str text)
                               :envelopesSent (count out-envs)
                               :response resp}
                        (not cmd-ok?) (assoc :error (get resp "error")))))))))))

(defn queue-offer
  "Queues a simulated incoming offer on the active Human Anchor state atom.
   Returns the updated dashboard view as a JavaScript object."
  ([] (queue-offer nil))
  ([offer-map]
   (when-not @anchor-state-atom
     (init-anchor nil))
   (let [callee (get-in @anchor-state-atom [:identity :anchor-pubkey])
         rand-num (rand-int 9000)
         off (merge {:offer-id (str "off-" (+ 1000 rand-num))
                     :caller-pubkey (basalt/bytes->hex (:public-key (crypto/generate-keypair)))
                     :callee-pubkey callee
                     :price 10
                     :burn 500
                     :epoch 1}
                    (when offer-map (js->clj offer-map :keywordize-keys true)))
         new-st (light-core/queue-incoming-offer @anchor-state-atom off)]
     (reset! anchor-state-atom new-st)
     (clj->js (redact-for-js (light-core/anchor-dashboard-view new-st))))))

(defn create-discoverable-credential
  "Invokes WebAuthn navigator.credentials.create with discoverable resident key
   and PRF extension for hardware seed generation. Returns a Promise."
  ([] (create-discoverable-credential nil))
  ([opts]
   (let [rp-id (or (when opts (aget opts "rpId"))
                   (if (exists? js/window) js/window.location.hostname "bitecho.org"))
         user-name (or (when opts (aget opts "userName")) "human-anchor@bitecho.org")]
     (js/Promise.
      (fn [resolve reject]
        (webauthn/create-discoverable-credential!
         {:rp-id rp-id :user-name user-name}
         (fn [err res]
           (if err
             (reject (js/Error. (or (:error err) "credential-creation-failed")))
             (do
               (apply-hardware-identity! res)
               (let [safe (redact-for-js res)
                       ;; Preserve privacy-safe Stage 1 diagnostic fields that are outside the
                       ;; IndexedDB persistence allowlist (BIP-010 P-WEB-1, Rule 5).
                     with-diag (cond-> safe
                                 (:error res) (assoc :error (:error res))
                                 (:failure-stage res) (assoc :failure-stage (:failure-stage res))
                                 (:failure-reason res) (assoc :failure-reason (:failure-reason res))
                                 (:diagnostics res) (assoc :diagnostics (:diagnostics res)))]
                 (resolve (clj->js with-diag))))))))))))

(defn get-discoverable-credential
  "Invokes WebAuthn navigator.credentials.get to recover discoverable credential seed. Returns a Promise."
  ([] (get-discoverable-credential nil))
  ([opts]
   (let [rp-id (or (when opts (aget opts "rpId"))
                   (if (exists? js/window) js/window.location.hostname "bitecho.org"))]
     (js/Promise.
      (fn [resolve reject]
        (webauthn/get-discoverable-credential!
         {:rp-id rp-id}
         (fn [err res]
           (if err
             (reject (js/Error. (or (:error err) "credential-get-failed")))
             (do
               (apply-hardware-identity! res)
               (let [safe (redact-for-js res)
                       ;; Preserve privacy-safe Stage 1 diagnostic fields that are outside the
                       ;; IndexedDB persistence allowlist (BIP-010 P-WEB-1, Rule 5).
                     with-diag (cond-> safe
                                 (:error res) (assoc :error (:error res))
                                 (:failure-stage res) (assoc :failure-stage (:failure-stage res))
                                 (:failure-reason res) (assoc :failure-reason (:failure-reason res))
                                 (:diagnostics res) (assoc :diagnostics (:diagnostics res)))]
                 (resolve (clj->js with-diag))))))))))))

;; =============================================================================
;; HTTP Gateway Relay Client Helpers (/relay/v1/*)
;; =============================================================================

(defn submit-relay-envelope!
  "Submits an envelope (hex string, bytes, or map) to HTTP relay at `relay-url` via fetch. Returns a Promise."
  ([relay-url envelope] (submit-relay-envelope! relay-url envelope nil))
  ([relay-url envelope _opts]
   (js/Promise.
    (fn [resolve _]
      (let [url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/send")
            env-hex (cond
                      (fressian/bytes? envelope) (fressian/bytes->hex envelope)
                      (string? envelope) envelope
                      (map? envelope) (try (fressian/bytes->hex (fressian/encode-canonical envelope)) (catch :default _ nil))
                      :else (str envelope))
            body-str (js/JSON.stringify #js {:envelope_hex env-hex})]
        (-> (js/fetch url #js {:method "POST"
                               :headers #js {"Content-Type" "application/json"}
                               :body body-str})
            (.then (fn [res] (.json res)))
            (.then (fn [data] (resolve (js->clj data :keywordize-keys true))))
            (.catch (fn [err] (resolve {:ok false :error (.-message err)})))))))))

(defn poll-relay-envelopes!
  "Polls HTTP relay at `relay-url` for envelopes addressed to `pubkey`. Returns a Promise."
  ([relay-url pubkey privkey] (poll-relay-envelopes! relay-url pubkey privkey nil))
  ([relay-url pubkey privkey opts]
   (js/Promise.
    (fn [resolve _]
      (let [now-ms (.now js/Date)
            pk-hex (if (fressian/bytes? pubkey) (fressian/bytes->hex pubkey) (str pubkey))
            since-seq (long (or (:since-seq opts) (:seq-gte opts) 0))
            bseq (long (or (:since-broadcast-seq opts) 0))
            nonce (or (:nonce opts) (fressian/bytes->hex (crypto/random-bytes 16)))
            sig (relay/sign-poll-request privkey {:pubkey pk-hex
                                                  :since-seq since-seq
                                                  :timestamp-ms now-ms
                                                  :nonce nonce})
            params (cond-> {"pubkey" pk-hex
                            "since_seq" (str since-seq)}
                     (:since-broadcast-seq opts) (assoc "since_broadcast_seq" (str (:since-broadcast-seq opts)))
                     (:limit opts) (assoc "limit" (str (:limit opts)))
                     (:timeout-ms opts) (assoc "timeout_ms" (str (:timeout-ms opts))))
            q-str (str/join "&" (map (fn [[k v]] (str (js/encodeURIComponent (name k)) "=" (js/encodeURIComponent (str v)))) params))
            base-url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/poll")
            url (str base-url "?" q-str)
            headers (cond-> {"X-Bitecho-Pubkey" pk-hex
                             "X-Bitecho-Since-Seq" (str since-seq)
                             "X-Bitecho-Since-Broadcast-Seq" (str bseq)
                             "X-Bitecho-Timestamp-Ms" (str now-ms)
                             "X-Bitecho-Nonce" nonce
                             "X-Bitecho-Signature" sig}
                      (:timeout-ms opts) (assoc "X-Bitecho-Wait-Ms" (str (:timeout-ms opts))))]
        (-> (js/fetch url #js {:method "GET"
                               :headers (clj->js headers)})
            (.then (fn [res] (.json res)))
            (.then (fn [data] (resolve (js->clj data :keywordize-keys true))))
            (.catch (fn [err] (resolve {:ok false :error (.-message err)})))))))))

(defn ack-relay-envelopes!
  "Acknowledges envelopes processed up to `up-to-seq` at `relay-url`. Returns a Promise."
  ([relay-url pubkey privkey up-to-seq] (ack-relay-envelopes! relay-url pubkey privkey up-to-seq nil))
  ([relay-url pubkey privkey up-to-seq opts]
   (js/Promise.
    (fn [resolve _]
      (let [now-ms (.now js/Date)
            pk-hex (if (fressian/bytes? pubkey) (fressian/bytes->hex pubkey) (str pubkey))
            ack-seq (long (or up-to-seq 0))
            ack-bseq (or (:ack-broadcast-seq opts) (:ack_broadcast_seq opts))
            nonce (or (:nonce opts) (fressian/bytes->hex (crypto/random-bytes 16)))
            sig (relay/sign-poll-request privkey {:pubkey pk-hex
                                                  :since-seq ack-seq
                                                  :timestamp-ms now-ms
                                                  :nonce nonce})
            url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/ack")
            payload-map (cond-> {"pubkey" pk-hex
                                 "sig" sig
                                 "signature" sig
                                 "ts" now-ms
                                 "timestamp_ms" now-ms
                                 "nonce" nonce
                                 "ack_seq" ack-seq
                                 "up_to_seq" ack-seq}
                          ack-bseq (assoc "ack_broadcast_seq" (long ack-bseq)
                                          "ack-broadcast-seq" (long ack-bseq)))
            payload (js/JSON.stringify (clj->js payload-map))
            headers (cond-> {"Content-Type" "application/json"
                             "X-Bitecho-Pubkey" pk-hex
                             "X-Bitecho-Ack-Seq" (str ack-seq)
                             "X-Bitecho-Timestamp-Ms" (str now-ms)
                             "X-Bitecho-Nonce" nonce
                             "X-Bitecho-Signature" sig}
                      ack-bseq (assoc "X-Bitecho-Ack-Broadcast-Seq" (str ack-bseq)))]
        (-> (js/fetch url #js {:method "POST"
                               :headers (clj->js headers)
                               :body payload})
            (.then (fn [res] (.json res)))
            (.then (fn [data] (resolve (js->clj data :keywordize-keys true))))
            (.catch (fn [err] (resolve {:ok false :error (.-message err)})))))))))

(defn fetch-relay-chain-state!
  "Fetches chain-state and bootstrap info from `relay-url`.
   When `node-atom` is provided (or in `opts`), verifies 2f+1 quorum signatures fail-closed
   via `light-core/verify-chain-state-quorum` and updates `node-atom`'s `:light-state`
   via `light-core/apply-verified-chain-state-snapshot`. Returns a Promise."
  ([relay-url] (fetch-relay-chain-state! relay-url nil))
  ([relay-url opts]
   (js/Promise.
    (fn [resolve _]
      (let [clean (relay/normalize-relay-base-url relay-url)
            base-url (str clean "/relay/v1/chain-state")
            node-atom (if (map? opts) (or (:node-atom opts) @active-node-atom) (or opts @active-node-atom))
            pk (when node-atom (or (get-in @node-atom [:light-state :pubkey])
                                   (when-let [kp (:keypair @node-atom)]
                                     (fressian/bytes->hex (:public-key kp)))))
            nonce (or (:nonce opts) (str (.now js/Date) "-" (fressian/bytes->hex (crypto/random-bytes 8))))
            q-parts (cond-> []
                      pk (conj (str "pubkey=" (js/encodeURIComponent (str pk))))
                      nonce (conj (str "nonce=" (js/encodeURIComponent (str nonce)))))
            url (if (seq q-parts) (str base-url "?" (str/join "&" q-parts)) base-url)]
        (-> (js/fetch url #js {:method "GET"})
            (.then (fn [res] (.json res)))
            (.then (fn [data]
                     (let [resp (js->clj data :keywordize-keys true)
                           raw-snaps (or (:snapshots resp) [])
                           signed-snaps (filterv #(or (:signature %) (:sig %)) raw-snaps)]
                       (if (and node-atom (seq signed-snaps))
                         (let [bootstrap (or (get-in @node-atom [:light-state :bootstrap]) default-bootstrap-descriptor)
                               trusted (set (keep :pubkey (vals (:nodes bootstrap))))
                               verify-opts {:expected-pubkey pk
                                            :expected-nonce nonce
                                            :trusted-validators trusted
                                            :min-finalized-epoch (long (or (:min-finalized-epoch opts) 0))}
                               q-res (light-core/verify-chain-state-quorum signed-snaps verify-opts)]
                           (if (:ok? q-res)
                             (let [snap (:snapshot q-res)
                                   fin-ep (long (or (:finalized-epoch snap) 0))]
                               (swap! node-atom update :light-state
                                      (fn [st]
                                        (-> (light-core/apply-verified-chain-state-snapshot st snap)
                                            (assoc :epoch fin-ep :epoch-initialized? true))))
                               (notify-ui-listeners!)
                               (resolve (assoc resp :ok true :quorum-verified true :quorum-result q-res)))
                             (resolve {:ok false :error (:error q-res)})))
                         (if (seq signed-snaps)
                           (resolve resp)
                           (if node-atom
                             (resolve {:ok false :error "no-verified-relay-snapshots"})
                             (resolve resp)))))))
            (.catch (fn [err] (resolve {:ok false :error (.-message err)})))))))))

(defn get-supported-verbs
  "Returns JavaScript array of all canonical supported CLI verbs (Priority 4)."
  []
  (clj->js cli/supported-cli-verbs))

(defn get-state
  "Returns current sanitized browser node state as a JavaScript object (Priority 4)."
  [& [node-atom]]
  (let [na (or node-atom @active-node-atom)]
    (if (and na @na)
      (clj->js (redact-for-js @na))
      nil)))

(defn stop-node
  "Stops active browser node, closing all WebRTC data channels and clearing state (Priority 4)."
  [& [node-atom]]
  (let [na (or node-atom @active-node-atom)]
    (when (and na @na)
      (let [channels (:active-channels @na)]
        (doseq [[_id dc] channels]
          (when dc
            (try (.close dc) (catch :default _ nil)))))
      (reset! na nil)
      (when (= na @active-node-atom)
        (reset! active-node-atom nil))
      (notify-ui-listeners!)
      #js {:ok true :stopped true})))

(defn ctl
  "Executes a CLI command string, token vector, or map against the browser node.
   Returns a Promise resolving to the JSON response map (Priority 4)."
  [cmd-or-args & [opts]]
  (js/Promise.
   (fn [resolve _reject]
     (let [opts-clj (if (map? opts) opts (if opts (js->clj opts :keywordize-keys true) {}))
           node-atom (or (:node-atom opts-clj) @active-node-atom)]
       (if-not (and node-atom @node-atom)
         (resolve #js {:ok false :error "node-not-initialized"})
         (let [priv (or (get-in @node-atom [:keypair :private-key])
                        (:privkey-bytes @anchor-state-atom))
               input-clj (cond
                           (string? cmd-or-args) cmd-or-args
                           (vector? cmd-or-args) cmd-or-args
                           (sequential? cmd-or-args) (vec cmd-or-args)
                           (map? cmd-or-args) cmd-or-args
                           :else (js->clj cmd-or-args))
               exec-res (browser/exec-browser-cli @node-atom input-clj priv)
               resp (:response exec-res)]
           (when (:state exec-res)
             (reset! node-atom (:state exec-res))
             (when (seq (:net-envelopes exec-res))
               (doseq [env (:net-envelopes exec-res)]
                 (route-browser-envelope! node-atom env)))
             (when-let [dial-info (:p2p-dial exec-res)]
               (dial-browser-p2p-peer! node-atom dial-info))
             (browser/persist-state! (browser/sanitize-state-for-persistence @node-atom))
             (notify-ui-listeners!))
           (resolve (clj->js resp))))))))

(defn- run-browser-governance-cmd!
  [cmd-map]
  (let [na @active-node-atom]
    (if-not (and na @na)
      (clj->js {:ok false :error "no-active-node"})
      (let [node @na
            privkey (or (get-in node [:keypair :private-key])
                        (when @anchor-state-atom (:privkey-bytes @anchor-state-atom)))]
        (if-not privkey
          (clj->js {:ok false :error "hardware-unlock-required"})
          (let [cmd-res (light-core/handle-command (:light-state node) cmd-map privkey)
                new-st (:state cmd-res)
                out-envs (:net-envelopes cmd-res)
                resp (:response cmd-res)]
            (swap! na assoc :light-state new-st)
            (doseq [env out-envs]
              (route-browser-envelope! na env))
            (browser/persist-state! (browser/sanitize-state-for-persistence @na))
            (notify-ui-listeners!)
            (clj->js resp)))))))

(defn submit-bip-cmd
  "Submits a Sociocratic BIP proposal from the browser light-node (BIP-006 Part 2)."
  ([bip-id title]
   (submit-bip-cmd bip-id title nil nil))
  ([bip-id title spec-edn]
   (submit-bip-cmd bip-id title spec-edn nil))
  ([bip-id title spec-edn subnet-id]
   (let [default-spec (pr-str
                       {:human-anchor-sunset "2027-06-30"
                        :jurisdiction-map {:machine-enforced [:invariant-diff-4-fields :oracle-receipts-4-gates :tri-circle-quorum :counterexample-veto :scheduled-epoch-activation]
                                           :review-loop-enforced [:architectural-simplicity :sans-io-boundary-discipline :cross-network-reset-hygiene :outsider-circle-admission]
                                           :foundation-legal-seat "Zug, Switzerland"
                                           :dispute-resolution "Sociocratic Circle Double-Linked Consent"}
                        :invariant-diff {:defspec-vars ["prop-mcp-jsonrpc-framing-and-9-tool-dispatch"]
                                         :seed 1794853200
                                         :sans-io-pure? true
                                         :diagnose-coverage? true
                                         :co-committed-spec-and-flags? true}
                        :oracle-receipts {:four-way-golden-oracle {:passed? true :seed 1794853200 :tests 700 :assertions 6500 :executed-at 1794853200000}
                                          :vopr-jepsen-non-vacuity {:passed? true :seed 1794853200 :scenarios-passed 29 :executed-at 1794853200000}
                                          :deterministic-bundle-sha256 "2c8d97181c6c98edae9defc47a64ede4b9ee6a2212913aca6cff7edad7bba62c"
                                          :bwrap-civilization-regression {:passed? true
                                                                          :browser-bundle-sha256 "99005965d85d07d3e125405ce93fc6c25c64cae0b908d58c5288a421c50e13b0"
                                                                          :executed-at 1794853200000}}})
         eff-spec (if (and (string? spec-edn) (not (str/blank? spec-edn)))
                    spec-edn
                    default-spec)]
     (run-browser-governance-cmd!
      {"cmd" "bip-submit"
       "bip_id" (str (or bip-id "BIP-006"))
       "title" (str (or title bip-id "BIP-006"))
       "spec_edn" eff-spec
       "subnet_id" (str (or (when (and (string? subnet-id) (not (str/blank? subnet-id))) subnet-id)
                            "bitecho.org/dev"))}))))

(defn consent-bip-cmd
  "Signs and broadcasts a Tri-Circle Sociocratic consent response for a BIP from the browser light-node (BIP-006 Part 2)."
  ([bip-id]
   (consent-bip-cmd bip-id "anchor-agent-users" nil nil))
  ([bip-id circle]
   (consent-bip-cmd bip-id circle nil nil))
  ([bip-id circle subnet-id]
   (consent-bip-cmd bip-id circle subnet-id nil))
  ([bip-id circle subnet-id comment]
   (run-browser-governance-cmd!
    (cond-> {"cmd" "bip-consent"
             "bip_id" (str (or bip-id "BIP-006"))
             "circle" (str (or circle "anchor-agent-users"))
             "subnet_id" (str (or (when (and (string? subnet-id) (not (str/blank? subnet-id))) subnet-id)
                                  "bitecho.org/dev"))}
      (and (string? comment) (not (str/blank? comment)))
      (assoc "comment" comment)))))

(defn object-bip-cmd
  "Signs and broadcasts a reproducible counterexample objection for a BIP from the browser light-node (BIP-006 Part 2)."
  ([bip-id circle counterexample-edn]
   (object-bip-cmd bip-id circle counterexample-edn nil))
  ([bip-id circle counterexample-edn subnet-id]
   (run-browser-governance-cmd!
    {"cmd" "bip-object"
     "bip_id" (str (or bip-id "BIP-006"))
     "circle" (str (or circle "anchor-agent-users"))
     "counterexample_edn" (str (or counterexample-edn "{:type :vopr-seed :seed 1 :failing-invariant :INV-1}"))
     "subnet_id" (str (or (when (and (string? subnet-id) (not (str/blank? subnet-id))) subnet-id)
                          "bitecho.org/dev"))})))

(defn get-bip-status-cmd
  "Queries local Tri-Circle ratification status for a BIP in the browser light-node (BIP-006 Part 2)."
  ([bip-id]
   (get-bip-status-cmd bip-id nil))
  ([bip-id subnet-id]
   (let [na @active-node-atom]
     (if-not (and na @na)
       (clj->js {:ok false :error "no-active-node"})
       (let [node @na
             privkey (get-in node [:keypair :private-key])
             cmd-res (light-core/handle-command
                      (:light-state node)
                      {"cmd" "bip-status"
                       "bip_id" (str (or bip-id "BIP-006"))
                       "subnet_id" (str (or (when (and (string? subnet-id) (not (str/blank? subnet-id))) subnet-id)
                                            "bitecho.org/dev"))}
                      privkey)]
         (clj->js (:response cmd-res)))))))

(defn claim-hardware-key-faucet!
  "Requests a WebAuthn challenge from `/faucet/v1/challenge` and submits a Hardware-Key Sponsored
   Faucet claim (`1,000,000 ECH` drip) to `/faucet/v1/claim` (BIP-006 Part 2 & Part 3).
   Returns a Promise resolving to the claim response object."
  ([] (claim-hardware-key-faucet! nil))
  ([opts]
   (js/Promise.
    (fn [resolve _reject]
      (let [opts-map (if (map? opts) opts (if opts (js->clj opts :keywordize-keys true) {}))
            na @active-node-atom
            local-pk (or (when na (get-in @na [:light-state :pubkey]))
                         (when @anchor-state-atom (:anchor-pubkey @anchor-state-atom)))
            claimant-pk (let [raw (or (:claimant-pubkey opts-map)
                                      (:claimantPubkey opts-map)
                                      (:claimant_pubkey opts-map)
                                      (:pubkey opts-map)
                                      local-pk)]
                          (when (and (string? raw) (not (str/blank? raw)))
                            (or (when na (get-in @na [:light-state :petnames (str/trim raw)]))
                                (get default-petnames (str/lower-case (str/trim raw)))
                                (str/lower-case (str/trim raw)))))
            cred-seed (or (:credential-id-hash opts-map)
                          (:credentialIdHash opts-map)
                          (:credential_id_hash opts-map)
                          (when local-pk
                            (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes (str "webauthn-yubikey-" local-pk))))))
            net-uri (or (:network-uri opts-map)
                        (:networkUri opts-map)
                        (when na (get-in @na [:light-state :network-uri]))
                        "devnet.bitecho.org")
            raw-base (or (:faucet-url opts-map)
                         (:faucetUrl opts-map)
                         (:relay-url opts-map)
                         (:relayUrl opts-map)
                         "")
            base-url (if (str/blank? (str raw-base))
                       ""
                       (str/replace (str/trim (str raw-base)) #"/+$" ""))]
        (if (or (str/blank? (str claimant-pk)) (str/blank? (str cred-seed)))
          (resolve #js {:ok false :error "missing-claimant-or-credential"})
          (-> (js/fetch (str base-url "/faucet/v1/challenge?network_uri=" (js/encodeURIComponent net-uri))
                        #js {:method "GET"})
              (.then (fn [res] (.json res)))
              (.then (fn [ch-data]
                       (let [ch-map (js->clj ch-data :keywordize-keys true)
                             nonce (get-in ch-map [:challenge :nonce])]
                         (if-not (and (string? nonce) (not (str/blank? nonce)))
                           (resolve (clj->js {:ok false :error "challenge-fetch-failed" :response ch-map}))
                           (let [claim-payload #js {:nonce nonce
                                                    :credential_id_hash cred-seed
                                                    :claimant_pubkey claimant-pk
                                                    :network_uri net-uri
                                                    :authenticator_verified true}]
                             (-> (js/fetch (str base-url "/faucet/v1/claim")
                                           #js {:method "POST"
                                                :headers #js {"Content-Type" "application/json"}
                                                :body (js/JSON.stringify claim-payload)})
                                 (.then (fn [res] (.json res)))
                                 (.then (fn [claim-data]
                                          (let [c-map (js->clj claim-data :keywordize-keys true)
                                                amt (long (or (get-in c-map [:transfer_intent :amount]) 1000000))]
                                            (when (and (:ok c-map) na (= claimant-pk local-pk))
                                              (swap! na (fn [curr]
                                                          (-> curr
                                                              (update-in [:light-state :account :balance] (fn [b] (+ (long (or b 0)) amt)))
                                                              (update-in [:light-state :account :spendable] (fn [s] (+ (long (or s 0)) amt))))))
                                              (browser/persist-state! (browser/sanitize-state-for-persistence @na))
                                              (notify-ui-listeners!))
                                            (resolve (clj->js c-map)))))))))))
              (.catch (fn [err]
                        (resolve #js {:ok false :error (or (.-message err) "faucet-request-failed")}))))))))))

(defn exec-command
  "JS-friendly alias for ctl (Priority 4)."
  [cmd-or-args & [opts]]
  (ctl cmd-or-args opts))

(defonce
  ^{:doc "Single-authority generation-tagged browser P-UPD-1 auto-updater state atom."}
  browser-updater-atom
  (atom nil))

(defn start-browser-auto-updater!
  "P-UPD-1 / D40.2: Starts a browser pointer-driven self-update watcher backed by pure
   `deploy/reduce-light-update-tick` (`:artifact-role :browser`). Verifies pointer authority,
   monotonic version, and SHA-256 == CID via async `js/fetch`, invoking `onUpdateReady` and
   optionally reloading the window when `autoReload` is true."
  [js-opts]
  (let [opts (js->clj js-opts :keywordize-keys true)
        pointer-url (:pointerUrl opts)
        poll-ms (max 5000 (long (or (:pollIntervalMs opts) 60000)))
        on-ready (when (and js-opts (fn? (.-onUpdateReady js-opts))) (.-onUpdateReady js-opts))
        auto-reload? (boolean (:autoReload opts))
        st0 (deploy/init-light-updater-state
             {:node-id "browser"
              :artifact-role :browser
              :current-version "0.23.22"
              :current-cid (:currentCid opts)
              :pinned-version (:pinVersion opts)
              :trusted-deploy-authorities (:trustedAuthorities opts)
              :poll-interval-ms poll-ms})
        _ (reset! browser-updater-atom st0)
        dispatch!
        (fn dispatch! [ev]
          (let [effs-box (atom [])]
            (swap! browser-updater-atom
                   (fn [st]
                     (let [[st' effs] (deploy/reduce-light-update-tick st ev)]
                       (reset! effs-box effs)
                       st')))
            (doseq [eff @effs-box]
              (case (:effect eff)
                :fetch-pointer
                (let [gen (:generation eff)]
                  (when (and pointer-url (exists? js/fetch))
                    (-> (js/fetch pointer-url #js {:cache "no-store"})
                        (.then (fn [resp] (when (.-ok resp) (.text resp))))
                        (.then (fn [txt]
                                 (when txt
                                   (let [ptr (try (edn/read-string txt) (catch :default _ nil))]
                                     (when (map? ptr)
                                       (dispatch! {:type :pointer-seen :pointer ptr :generation gen}))))))
                        (.catch (fn [_] nil)))))

                :fetch-bundle-blob
                (let [gen (:generation eff)
                      cid (:cid eff)
                      blob-url (deploy/build-blob-fetch-url pointer-url cid)]
                  (when (and blob-url (exists? js/fetch))
                    (-> (js/fetch blob-url #js {:cache "no-store"})
                        (.then (fn [resp] (when (.-ok resp) (.arrayBuffer resp))))
                        (.then (fn [ab]
                                 (when ab
                                   (dispatch! {:type :blob-fetched
                                               :cid cid
                                               :bytes (js/Uint8Array. ab)
                                               :generation gen}))))
                        (.catch (fn [_] nil)))))

                :atomic-swap-and-restart-light-node
                (let [cid (:cid eff)
                      pending (:pending-update @browser-updater-atom)]
                  (when on-ready
                    (try (on-ready (clj->js {:version (:target-version pending) :cid cid})) (catch :default _ nil)))
                  (when (and auto-reload? (exists? js/window) (.-location js/window))
                    (.reload (.-location js/window))))

                nil))))
        t0 (js/setTimeout #(dispatch! {:type :poll-tick}) 5000)
        iv (js/setInterval #(dispatch! {:type :poll-tick}) poll-ms)]
    (fn []
      (js/clearTimeout t0)
      (js/clearInterval iv))))

(def api
  "Global BitechoBrowser API object with Closure :advanced-safe string property exports (Priority 4 & BIP-006 Part 2)."
  #js {"initNode" init-node
       "ctl" ctl
       "execCommand" exec-command
       "getSupportedVerbs" get-supported-verbs
       "getState" get-state
       "getStatus" get-status
       "stopNode" stop-node
       "connect" connect
       "connectMesh" connect-mesh
       "openChannel" open-channel
       "acceptChannelOffer" accept-channel-offer
       "p2pOffer" p2p-offer
       "p2pAnswer" p2p-answer
       "setP2pChannelState" set-p2p-channel-state
       "broadcastMessage" broadcast-message
       "sendMessage" send-message
       "closeSession" close-session
       "getChatHistory" get-chat-history
       "getSessions" get-sessions
       "resolvePeer" resolve-peer
       "onStateChange" on-state-change
       "handleVisibilityChange" handle-visibility-change!
       "saveStateToIndexedDB" save-state-to-indexed-db
       "loadStateFromIndexedDB" load-state-from-indexed-db
       "loadStateFromIndexedDb" load-state-from-indexed-db
       "restoreFromIndexedDB" restore-from-indexed-db!
       "restoreFromIndexedDb" restore-from-indexed-db!
       "createOffer" create-offer
       "acceptOffer" accept-offer
       "sendSealedMessage" send-sealed-message
       "runSubnetDemo" run-subnet-demo
       "runZeroBurnSubnetDemo" run-zero-burn-subnet-demo
       "runFederationDemo" run-federation-demo
       "runThreeWayP2pBroadcastDemo" run-three-way-p2p-broadcast-demo
       "initAnchor" init-anchor
       "getAnchorDashboard" get-anchor-dashboard
       "registerYubiKey" register-yubikey
       "recoverFromYubiKey" recover-from-yubikey
       "createDiscoverableCredential" create-discoverable-credential
       "getDiscoverableCredential" get-discoverable-credential
       "queueOffer" queue-offer
       "generateNonExtractableKey" generate-non-extractable-key
       "approveOffer" approve-offer-cmd
       "denyOffer" deny-offer-cmd
       "superviseAgent" supervise-agent-cmd
       "revokeAgentDac" revoke-agent-dac-cmd
       "encodeBech32m" encode-bech32m-cmd
       "decodeBech32m" decode-bech32m-cmd
       "runAnchorEndToEndDemo" run-anchor-end-to-end-demo
       "submitBip" submit-bip-cmd
       "consentBip" consent-bip-cmd
       "objectBip" object-bip-cmd
       "getBipStatus" get-bip-status-cmd
       "claimHardwareKeyFaucet" claim-hardware-key-faucet!
       "submitRelayEnvelope" submit-relay-envelope!
       "pollRelayEnvelopes" poll-relay-envelopes!
       "ackRelayEnvelopes" ack-relay-envelopes!
       "fetchRelayChainState" fetch-relay-chain-state!
       "checkBundleFreshness" (fn [remote-ver]
                                (let [na @active-node-atom
                                      st (if na @na {:diagnostics {}})
                                      res (browser/check-browser-bundle-freshness st "0.23.22" remote-ver)]
                                  (when (and na (not (:fresh? res)))
                                    (swap! na update-in [:conn :diagnostics :stale-browser-bundle] (fnil inc 0)))
                                  (clj->js res)))
       "startAutoUpdater" start-browser-auto-updater!
       "getAutoUpdaterStatus" (fn [] (clj->js (or @browser-updater-atom {})))
       "version" "0.23.22"})

(defn- js-params->clj-map
  "Safely converts a JS object (including null-prototype or cross-realm objects) or CLJ map
   into a Clojure map for browser CLI verb dispatch."
  [params]
  (cond
    (nil? params) {}
    (map? params) params
    (string? params) {"topic" params "verb" params}
    (= "object" (js* "typeof ~{}" params))
    (let [ks (js/Object.keys params)]
      (reduce (fn [acc k]
                (let [v (gobj/get params k)]
                  (assoc acc k (if (and (some? v) (= "object" (js* "typeof ~{}" v)))
                                 (if (js/Array.isArray v)
                                   (vec (map #(if (and (some? %) (= "object" (js* "typeof ~{}" %)))
                                                (js-params->clj-map %)
                                                %)
                                             (array-seq v)))
                                   (js-params->clj-map v))
                                 v))))
              {}
              (array-seq ks)))
    :else {}))

(defn exec-light-node-verb
  "Executes a single CLI verb (kebab-case or camelCase) with optional JS/CLJ params object
   against the active browser light node. Always returns a JS Promise resolving to a clean
   plain JS object matching Node/JVM light-node JSON output semantics (Rules 2, 5, 6)."
  ([verb] (exec-light-node-verb verb nil nil))
  ([verb params] (exec-light-node-verb verb params nil))
  ([verb params opts]
   (js/Promise.
    (fn [resolve _reject]
      (let [norm-verb (browser-cli/js-method-name->verb (str (or verb "")))
            params-clj (js-params->clj-map params)
            opts-clj (cond
                       (nil? opts) {}
                       (map? opts) opts
                       :else (let [c (js->clj opts :keywordize-keys true)]
                               (if (map? c) c {})))
            node-atom (or (:node-atom opts-clj) @active-node-atom)]
        (cond
          (= norm-verb "help")
          (let [topic (or (when (string? params) params)
                          (get params-clj "verb")
                          (:verb params-clj)
                          (get params-clj "topic")
                          (:topic params-clj))]
            (resolve (clj->js (browser-cli/build-browser-help topic))))

          (contains? browser-cli/browser-unsupported-verbs norm-verb)
          (let [norm (browser-cli/normalize-cli-invocation norm-verb params-clj)]
            (when (and node-atom @node-atom)
              (dispatch-mesh-peer-event!
               node-atom
               "cli"
               {:type :unknown-event
                :error "unsupported-in-browser"
                :verb norm-verb
                :timestamp-ms (.now js/Date)}
               nil))
            (resolve (clj->js (:response norm))))

          (not (and node-atom @node-atom))
          (resolve #js {:ok false :error "node-not-initialized" :verb norm-verb})

          :else
          (let [priv (or (get-in @node-atom [:keypair :private-key])
                         (:privkey-bytes @anchor-state-atom))
                exec-res (browser-cli/dispatch-browser-cli @node-atom norm-verb params-clj priv)
                resp (:response exec-res)]
            (when (:state exec-res)
              (reset! node-atom (:state exec-res))
              (when (seq (:net-envelopes exec-res))
                (doseq [env (:net-envelopes exec-res)]
                  (route-browser-envelope! node-atom env)))
              (when-let [dial-info (:p2p-dial exec-res)]
                (dial-browser-p2p-peer! node-atom dial-info))
              (browser/persist-state! (browser/sanitize-state-for-persistence @node-atom))
              (notify-ui-listeners!))
            (resolve (clj->js resp)))))))))

(defn exec-light-node-cli
  "Executes a CLI string (e.g. \"p2p-channel-state --session-id s1 --connected true\")
   or argv array against the active browser light node, returning a JS Promise."
  ([argv-or-str] (exec-light-node-cli argv-or-str nil))
  ([argv-or-str opts]
   (let [input-clj (cond
                     (string? argv-or-str) argv-or-str
                     (vector? argv-or-str) argv-or-str
                     (sequential? argv-or-str) (vec argv-or-str)
                     (map? argv-or-str) argv-or-str
                     (nil? argv-or-str) "status"
                     :else (js->clj argv-or-str))
         parsed (cli/parse-cli-command input-clj)]
     (cond
       (and (:ok? parsed) (contains? browser-cli/browser-unsupported-verbs (:verb parsed)))
       (exec-light-node-verb (:verb parsed) (:opts parsed) opts)

       (and (:ok? parsed) (= "help" (:verb parsed)))
       (exec-light-node-verb "help" (first (:args parsed)) opts)

       :else
       (ctl input-clj opts)))))

(defn get-peers-status
  "Returns a JS Promise resolving to the full validator mesh + P2P peer diagnostics object."
  ([] (get-peers-status @active-node-atom))
  ([node-atom]
   (let [na (or node-atom @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {:ok false :error "node-not-initialized"})
       (let [node @na
             summary (browser/summarize-mesh-diagnostics (:mesh-conns node))
             p2p-peers (into {}
                             (map (fn [[pk entry]]
                                    [pk {:peerId pk
                                         :sessionId (:session-id entry)
                                         :generation (long (or (:generation entry) 0))
                                         :readyState (when-let [dc (:channel entry)]
                                                       (.-readyState dc))}]))
                             (or (:p2p-channels node) {}))]
         (js/Promise.resolve
          (clj->js {:ok true
                    :totalPeers (:total-peers summary)
                    :openPeers (:open-peers summary)
                    :dialingPeers (:dialing-peers summary)
                    :closedPeers (:closed-peers summary)
                    :degraded (:degraded? summary)
                    :lastError (:last-error summary)
                    :iceDisconnects (:ice-disconnects summary)
                    :iceReconnects (:ice-reconnects summary)
                    :closeCount (:close-count summary)
                    :dialFailures (:dial-failures summary)
                    :peers (format-peer-diagnostics-js (:peers summary))
                    :p2pPeers p2p-peers
                    :recentEvents (format-recent-events-js (:recent-events summary))})))))))

(defn get-light-node-status
  "D40.4 v1.0.0: Returns a Promise resolving to `{ ok, apiVersion, phase, generation, pubkey,
   finalizedEpoch, balance, spendable, lastError, dropped, diagnostics, ... }`."
  ([] (get-light-node-status @active-node-atom))
  ([node-atom]
   (let [na (or (when (or (satisfies? IAtom node-atom)
                          (and (some? node-atom) (fn? (.-deref node-atom))))
                  node-atom)
                @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false
                                "apiVersion" browser-cli/api-version
                                "error" "node-not-initialized"})
       (let [st-js (get-status na)
             node @na
             light-st (:light-state node)
             diag-js (gobj/get st-js "diagnostics")
             fin-epoch (long (or (:finalized-epoch light-st) (:epoch light-st) 0))]
         (gobj/set st-js "ok" true)
         (gobj/set st-js "apiVersion" browser-cli/api-version)
         (gobj/set st-js "finalizedEpoch" fin-epoch)
         (gobj/set st-js "lastError" (when diag-js (gobj/get diag-js "lastError")))
         (gobj/set st-js "dropped" (if diag-js (gobj/get diag-js "dropped") 0))
         (gobj/set st-js "pendingOffers" (clj->js (redact-for-js (or (:pending-offers light-st) {}))))
         (js/Promise.resolve st-js))))))

(defn list-petnames-v1
  "D40.4 v1.0.0: Returns a Promise resolving to `{ ok: true, petnames: [{ pubkey, petname, voiceId, color }] }`."
  ([] (list-petnames-v1 nil))
  ([opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false "error" "node-not-initialized" "petnames" #js []})
       (let [entries (browser-cli/list-petname-entries @na)
             js-entries (clj->js (mapv (fn [e]
                                         {"pubkey" (:pubkey e)
                                          "petname" (:petname e)
                                          "voiceId" (:voice-id e)
                                          "color" (:color e)})
                                       entries))]
         (js/Promise.resolve #js {"ok" true "petnames" js-entries}))))))

(defn set-petname-v1
  "D40.4 v1.0.0: Sets `{ petname, voiceId, color }` for `pubkey` in local Rolodex state,
   preserving 100% compatibility with existing `:petnames` and persisting to IndexedDB."
  ([pubkey meta-opts] (set-petname-v1 pubkey meta-opts nil))
  ([pubkey meta-opts opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false "error" "node-not-initialized"})
       (let [meta-clj (if (string? meta-opts)
                        {:petname meta-opts}
                        (js-params->clj-map meta-opts))
             res (browser-cli/merge-petname-entry @na pubkey meta-clj)]
         (if-not (:ok? res)
           (do
             (when-let [diag (:diagnose res)]
               (emit-browser-event! na (assoc diag :type "diagnose" :timestamp-ms (.now js/Date))))
             (js/Promise.resolve #js {"ok" false "error" (name (:error res))}))
           (let [entry (:entry res)]
             (reset! na (:state res))
             (browser/persist-state! (browser/sanitize-state-for-persistence @na))
             (notify-ui-listeners!)
             (js/Promise.resolve #js {"ok" true
                                      "pubkey" (:pubkey entry)
                                      "petname" (:petname entry)
                                      "voiceId" (:voice-id entry)
                                      "color" (:color entry)}))))))))

(defn list-sessions-v1
  "D40.4 v1.0.0: Returns a Promise resolving to `{ ok: true, sessions: [...] }`."
  ([] (list-sessions-v1 nil))
  ([opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false "error" "node-not-initialized" "sessions" #js []})
       (let [node @na
             sessions (or (get-in node [:light-state :sessions]) (:sessions node) {})
             items (mapv (fn [[sid s]]
                           (let [peer-pk (:peer s)
                                 rolodex (browser-cli/resolve-petname-entry node peer-pk)
                                 safe-s (redact-for-js s)]
                             {"sessionId" (str sid)
                              "peer" peer-pk
                              "peerPetname" (:petname rolodex)
                              "voiceId" (:voice-id rolodex)
                              "color" (:color rolodex)
                              "state" (or (:state safe-s) (when (:status safe-s) (name (:status safe-s))) "unknown")
                              "epoch" (long (or (:epoch safe-s) 0))
                              "txSeq" (long (or (:tx-seq safe-s) 0))
                              "rxHighSeq" (long (or (:rx-high-seq safe-s) 0))}))
                         (sort-by first sessions))]
         (js/Promise.resolve #js {"ok" true
                                  "sessions" (clj->js items)
                                  "sessionsMap" (get-sessions na)}))))))

(defn list-subnets-v1
  "D40.4 v1.0.0: Returns a Promise resolving to `{ ok: true, subnets: [...] }`."
  ([] (list-subnets-v1 nil))
  ([opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false "error" "node-not-initialized" "subnets" #js []})
       (let [node @na
             light-st (:light-state node)
             raw-subs (or (:subscribed-subnets light-st) (:subnets light-st))
             eff-subs (vec (distinct (concat (when-let [s (:subnet-id node)] [s])
                                             (when-let [s (:subnet-id light-st)] [s])
                                             (map str (or raw-subs [])))))]
         (js/Promise.resolve #js {"ok" true
                                  "subnetId" (or (:subnet-id node) (:subnet-id light-st) "global")
                                  "subnets" (clj->js eff-subs)}))))))

(defn send-message-v1
  "D40.4 v1.0.0: Multi-line UTF-8 safe sealed message sender accepting either
   `(sessionId, text)` positional or `({sessionId, text})` object.
   Returns a Promise resolving to `{ ok, sessionId, seq, burn, error }`."
  ([arg1] (send-message-v1 arg1 nil nil))
  ([arg1 arg2] (send-message-v1 arg1 arg2 nil))
  ([arg1 arg2 opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)
         norm-arg1 (if (and (some? arg1) (= "object" (js* "typeof ~{}" arg1)) (not (map? arg1)))
                     (js-params->clj-map arg1)
                     arg1)
         parsed (browser-cli/normalize-send-message-args norm-arg1 arg2)]
     (cond
       (not (:ok? parsed))
       (js/Promise.resolve #js {"ok" false
                                "sessionId" nil
                                "seq" nil
                                "burn" 0
                                "error" (name (:error parsed))})

       (not (and na @na))
       (js/Promise.resolve #js {"ok" false
                                "sessionId" (:session-id parsed)
                                "seq" nil
                                "burn" 0
                                "error" "node-not-initialized"})

       :else
       (let [node @na
             privkey (or (get-in node [:keypair :private-key])
                         (when @anchor-state-atom (:privkey-bytes @anchor-state-atom)))
             sid (:session-id parsed)
             text (:text parsed)]
         (if-not privkey
           (js/Promise.resolve #js {"ok" false
                                    "sessionId" sid
                                    "seq" nil
                                    "burn" 0
                                    "error" "hardware-unlock-required"})
           (let [sessions (or (get-in node [:light-state :sessions]) {})
                 direct-sess (get sessions sid)
                 target-pub (if direct-sess
                              (:peer direct-sess)
                              (resolve-peer-target node sid))
                 resolved-sid (resolve-best-open-session-id sessions target-pub (when direct-sess sid))
                 resolved-sess (when resolved-sid (get sessions resolved-sid))
                 actual-peer-pub (or (:peer resolved-sess) target-pub)
                 now-ms (.now js/Date)
                 cmd-map (cond-> {"cmd" "send"
                                  "peer" actual-peer-pub
                                  "text" text
                                  "message" text
                                  "now_ms" now-ms}
                           resolved-sid (assoc "session_id" resolved-sid))
                 prep-res (light-core/prepare-send (:light-state node) cmd-map privkey)
                 out-envs (:net-envelopes prep-res)
                 intent (:fanout-intent prep-res)]
             (if-not (and (:ok? prep-res) (seq out-envs))
               (do
                 (swap! na assoc :light-state (:state prep-res))
                 (notify-ui-listeners!)
                 (js/Promise.resolve #js {"ok" false
                                          "sessionId" (or resolved-sid sid)
                                          "seq" nil
                                          "burn" 0
                                          "meshSubmitted" false
                                          "p2pDirect" false
                                          "peersTargeted" 0
                                          "error" (or (get-in prep-res [:response "error"]) "no-open-session-for-peer")}))
               (let [route-outcomes (mapv #(route-browser-envelope! na %) out-envs)
                     mesh-ok? (boolean (some :mesh-submitted? route-outcomes))
                     p2p-ok? (boolean (some :p2p-direct? route-outcomes))
                     mesh-peers (reduce + 0 (map #(long (or (:mesh-peers-targeted %) 0)) route-outcomes))
                     p2p-peers (reduce + 0 (map #(long (or (:p2p-peers-targeted %) 0)) route-outcomes))
                     first-err (some :error route-outcomes)
                     committed (light-core/commit-delivery-outcome
                                (:state prep-res)
                                intent
                                {:mesh-submitted? mesh-ok?
                                 :p2p-direct? p2p-ok?
                                 :mesh-peers-targeted mesh-peers
                                 :p2p-peers-targeted p2p-peers
                                 :error first-err
                                 :now-ms (.now js/Date)})
                     new-st (:state committed)
                     resp (:response committed)
                     cmd-ok? (boolean (:ok? committed))
                     out-sid (or (get resp "session_id") resolved-sid sid)
                     out-seq (get resp "seq")
                     out-burn (long (or (get resp "burn") 0))]
                 (swap! na (fn [curr]
                             (-> curr
                                 (assoc :light-state new-st)
                                 (assoc :sessions (:sessions new-st))
                                 (update :chat-history
                                         (fn [h]
                                           (conj (vec (or h []))
                                                 {:timestamp (.toISOString (js/Date.))
                                                  :direction :outgoing
                                                  :peer (or (:petname (browser-cli/resolve-petname-entry curr actual-peer-pub))
                                                            actual-peer-pub)
                                                  :sessionId out-sid
                                                  :seq out-seq
                                                  :text text
                                                  :status (if cmd-ok? :sent :failed)
                                                  :error (when-not cmd-ok? (get resp "error"))}))))))
                 (doseq [diag-ev (:stdout-events committed)]
                   (emit-browser-event! na (assoc diag-ev :type "diagnose" :timestamp-ms (.now js/Date))))
                 (browser/persist-state! (browser/sanitize-state-for-persistence @na))
                 (notify-ui-listeners!)
                 (js/Promise.resolve #js {"ok" cmd-ok?
                                          "sessionId" out-sid
                                          "seq" out-seq
                                          "burn" out-burn
                                          "meshSubmitted" mesh-ok?
                                          "p2pDirect" p2p-ok?
                                          "peersTargeted" (+ mesh-peers p2p-peers)
                                          "error" (when-not cmd-ok?
                                                    (or (get resp "error") "mesh-submit-failed"))}))))))))))

(defn send-broadcast-v1
  "D40.4 v1.0.0: Multi-line UTF-8 safe subnet broadcast sender accepting either
   `(subnetId, text)` positional or `({subnetId, text})` object.
   Returns a Promise resolving to `{ ok, subnetId, seq, burn, error }`."
  ([arg1] (send-broadcast-v1 arg1 nil nil))
  ([arg1 arg2] (send-broadcast-v1 arg1 arg2 nil))
  ([arg1 arg2 opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)
         norm-arg1 (if (and (some? arg1) (= "object" (js* "typeof ~{}" arg1)) (not (map? arg1)))
                     (js-params->clj-map arg1)
                     arg1)
         parsed (browser-cli/normalize-send-broadcast-args norm-arg1 arg2)]
     (cond
       (not (:ok? parsed))
       (js/Promise.resolve #js {"ok" false
                                "subnetId" nil
                                "seq" nil
                                "burn" 0
                                "error" (name (:error parsed))})

       (not (and na @na))
       (js/Promise.resolve #js {"ok" false
                                "subnetId" (:subnet-id parsed)
                                "seq" nil
                                "burn" 0
                                "error" "node-not-initialized"})

       :else
       (let [node @na
             privkey (or (get-in node [:keypair :private-key])
                         (when @anchor-state-atom (:privkey-bytes @anchor-state-atom)))
             sub-id (:subnet-id parsed)
             text (:text parsed)]
         (if-not privkey
           (js/Promise.resolve #js {"ok" false
                                    "subnetId" sub-id
                                    "seq" nil
                                    "burn" 0
                                    "error" "hardware-unlock-required"})
           (let [now-ms (.now js/Date)
                 prep-res (light-core/prepare-broadcast (:light-state node)
                                                        {"subnet_id" sub-id
                                                         "text" text
                                                         "message" text
                                                         "now_ms" now-ms}
                                                        privkey)
                 out-envs (:net-envelopes prep-res)
                 intent (:fanout-intent prep-res)]
             (if-not (and (:ok? prep-res) (seq out-envs))
               (do
                 (swap! na assoc :light-state (:state prep-res))
                 (notify-ui-listeners!)
                 (js/Promise.resolve #js {"ok" false
                                          "subnetId" sub-id
                                          "seq" nil
                                          "burn" 0
                                          "meshSubmitted" false
                                          "p2pDirect" false
                                          "peersTargeted" 0
                                          "error" (or (get-in prep-res [:response "error"]) "broadcast-prepare-failed")}))
               (let [route-outcomes (mapv #(route-browser-envelope! na %) out-envs)
                     mesh-ok? (boolean (some :mesh-submitted? route-outcomes))
                     p2p-ok? (boolean (some :p2p-direct? route-outcomes))
                     mesh-peers (reduce + 0 (map #(long (or (:mesh-peers-targeted %) 0)) route-outcomes))
                     p2p-peers (reduce + 0 (map #(long (or (:p2p-peers-targeted %) 0)) route-outcomes))
                     first-err (some :error route-outcomes)
                     committed (light-core/commit-delivery-outcome
                                (:state prep-res)
                                intent
                                {:mesh-submitted? mesh-ok?
                                 :p2p-direct? p2p-ok?
                                 :mesh-peers-targeted mesh-peers
                                 :p2p-peers-targeted p2p-peers
                                 :error first-err
                                 :now-ms (.now js/Date)})
                     new-st (:state committed)
                     resp (:response committed)
                     cmd-ok? (boolean (:ok? committed))
                     out-sub (or (get resp "subnet_id") sub-id)
                     out-seq (get resp "seq")
                     out-burn (long (or (get resp "burn") 0))]
                 (swap! na (fn [curr]
                             (-> curr
                                 (assoc :light-state new-st)
                                 (assoc :sessions (:sessions new-st))
                                 (update :chat-history
                                         (fn [h]
                                           (conj (vec (or h []))
                                                 {:timestamp (.toISOString (js/Date.))
                                                  :direction :outgoing
                                                  :peer out-sub
                                                  :sessionId out-sub
                                                  :seq out-seq
                                                  :text text
                                                  :status (if cmd-ok? :sent :failed)
                                                  :error (when-not cmd-ok? (get resp "error"))}))))))
                 (doseq [diag-ev (:stdout-events committed)]
                   (emit-browser-event! na (assoc diag-ev :type "diagnose" :timestamp-ms (.now js/Date))))
                 (browser/persist-state! (browser/sanitize-state-for-persistence @na))
                 (notify-ui-listeners!)
                 (js/Promise.resolve #js {"ok" cmd-ok?
                                          "subnetId" out-sub
                                          "seq" out-seq
                                          "burn" out-burn
                                          "meshSubmitted" mesh-ok?
                                          "p2pDirect" p2p-ok?
                                          "peersTargeted" (+ mesh-peers p2p-peers)
                                          "error" (when-not cmd-ok? (get resp "error"))}))))))))))

(defn get-artifact-v1
  "D40.4 v1.0.0: Fetches an artifact by `{ cid }` or `{ subnet, path }` (plus optional `{ baseUrl }`),
   verifies SHA-256 == `cid` fail-closed with counted `:diagnose` on mismatch, and returns
   `Promise<{ ok, cid, bytes: Uint8Array, contentType, error }>`."
  [opts]
  (let [opts-clj (js-params->clj-map opts)
        na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)
        plan (browser-cli/build-artifact-fetch-plan opts-clj)]
    (cond
      (not (:ok? plan))
      (do
        (when-let [diag (:diagnose plan)]
          (emit-browser-event! na (assoc diag :type "diagnose" :timestamp-ms (.now js/Date))))
        (js/Promise.resolve #js {"ok" false
                                 "cid" nil
                                 "bytes" nil
                                 "contentType" nil
                                 "error" (name (:error plan))
                                 "reason" (:reason plan)}))

      (not (exists? js/fetch))
      (do
        (emit-browser-event! na {:type "diagnose"
                                 :kind :fetch-unavailable
                                 :reason "global-fetch-unavailable"
                                 :timestamp-ms (.now js/Date)})
        (js/Promise.resolve #js {"ok" false
                                 "cid" (:cid plan)
                                 "bytes" nil
                                 "contentType" nil
                                 "error" "fetch-unavailable"}))

      :else
      (js/Promise.
       (fn [resolve _reject]
         (let [urls (:urls plan)
               expected-cid (:cid plan)
               try-url!
               (fn try-url! [idx last-err]
                 (if (>= idx (count urls))
                   (do
                     (emit-browser-event! na {:type "diagnose"
                                              :kind :artifact-fetch-failed
                                              :reason (or last-err "artifact-fetch-failed")
                                              :timestamp-ms (.now js/Date)})
                     (resolve #js {"ok" false
                                   "cid" expected-cid
                                   "bytes" nil
                                   "contentType" nil
                                   "error" "artifact-fetch-failed"
                                   "reason" (or last-err "artifact-fetch-failed")}))
                   (let [u (nth urls idx)]
                     (-> (js/fetch u #js {"method" "GET"})
                         (.then (fn [resp]
                                  (if-not (and resp (.-ok resp))
                                    (try-url! (inc idx) (str "http-" (when resp (.-status resp))))
                                    (let [ct (or (when-let [hdrs (.-headers resp)]
                                                   (.get hdrs "content-type"))
                                                 "application/octet-stream")]
                                      (-> (.arrayBuffer resp)
                                          (.then (fn [ab]
                                                   (let [u8 (js/Uint8Array. ab)
                                                         vres (browser-cli/verify-artifact-bytes expected-cid u8)]
                                                     (if (:ok? vres)
                                                       (resolve #js {"ok" true
                                                                     "cid" (:cid vres)
                                                                     "bytes" u8
                                                                     "contentType" ct
                                                                     "error" nil})
                                                       (do
                                                         (when (and na @na)
                                                           (swap! na
                                                                  (fn [curr]
                                                                    (-> curr
                                                                        (update-in [:conn :diagnostics :cid-mismatch] (fnil inc 0))
                                                                        (assoc-in [:conn :diagnostics :last-error] (get-in vres [:diagnose :reason]))))))
                                                         (when-let [diag (:diagnose vres)]
                                                           (emit-browser-event! na (assoc diag :type "diagnose" :timestamp-ms (.now js/Date))))
                                                         (resolve #js {"ok" false
                                                                       "cid" (:actual-cid vres)
                                                                       "expectedCid" (:expected-cid vres)
                                                                       "bytes" nil
                                                                       "contentType" ct
                                                                       "error" (:error vres)})))))))))))
                         (.catch (fn [err]
                                   (try-url! (inc idx) (str (or (when err (.-message err)) err "fetch-error")))))))))]
           (try-url! 0 nil)))))))

(defn list-pending-offers-v11
  "BIP-017a v1.1.0: Returns a Promise resolving to `{ ok: true, pendingOffers: [...] }`."
  ([] (list-pending-offers-v11 nil))
  ([opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false "error" "node-not-initialized" "pendingOffers" #js []})
       (let [pending (or (get-in @na [:light-state :pending-offers]) {})
             entries (mapv (fn [[k v]]
                             (let [m (if (map? v) v {:offer v})]
                               (assoc m :offerId (str (or (:offer-id m) (:session-id m) k)))))
                           pending)]
         (js/Promise.resolve #js {"ok" true
                                  "pendingOffers" (clj->js (redact-for-js entries))}))))))

(defn open-channel-v11
  "BIP-017a v1.1.0: Opens a payment/messaging channel to `callee` and returns a Promise."
  ([callee] (open-channel-v11 callee nil))
  ([callee opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)
         price (long (or (:price opts-clj) (get opts-clj "price") 10))
         deposit (long (or (:deposit opts-clj) (get opts-clj "deposit") 500))]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false "error" "node-not-initialized"})
       (js/Promise.resolve (open-channel na callee price deposit))))))

(defn open-session-v11
  "BIP-017a v1.1.0: Opens an encrypted session/channel with `peer` and returns a Promise."
  ([peer] (open-session-v11 peer nil))
  ([peer opts]
   (open-channel-v11 peer opts)))

(defn accept-offer-v11
  "BIP-017a v1.1.0: Accepts an inbound channel offer and returns a Promise."
  ([offer] (accept-offer-v11 offer nil))
  ([offer opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false "error" "node-not-initialized"})
       (js/Promise.resolve (accept-offer na offer))))))

(defn approve-offer-v11
  "BIP-017a v1.1.0: Approves a pending offer by `offerId` and returns a Promise."
  ([offer-id] (approve-offer-v11 offer-id nil))
  ([offer-id opts]
   (js/Promise.resolve (approve-offer-cmd offer-id opts))))

(defn deny-offer-v11
  "BIP-017a v1.1.0: Denies a pending offer by `offerId` with optional `reason` and returns a Promise."
  ([offer-id] (deny-offer-v11 offer-id "user-denied"))
  ([offer-id reason]
   (js/Promise.resolve (deny-offer-cmd offer-id reason))))

(defn register-yubikey-v11
  "BIP-017a v1.1.0: Registers a WebAuthn / YubiKey hardware anchor and returns a Promise."
  ([] (register-yubikey-v11 nil))
  ([opts]
   (js/Promise.resolve (register-yubikey opts))))

(defn recover-yubikey-v11
  "BIP-017a v1.1.0: Recovers identity from a WebAuthn / YubiKey hardware anchor and returns a Promise."
  ([] (recover-yubikey-v11 nil))
  ([opts]
   (js/Promise.resolve (recover-from-yubikey opts))))

(defn save-identity-v11
  "BIP-017a v1.1.0: Explicitly persists sanitized active node identity & state to IndexedDB."
  ([] (save-identity-v11 nil))
  ([opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)]
     (if-not (and na @na)
       (js/Promise.resolve #js {"ok" false "error" "node-not-initialized"})
       (let [node @na
             pk (get-in node [:light-state :pubkey])]
         (browser/persist-state! (browser/sanitize-state-for-persistence node))
         (js/Promise.resolve #js {"ok" true "pubkey" pk}))))))

(defn- concat-uint8-arrays
  "Concatenates a vector of Uint8Arrays into a single Uint8Array."
  [chunks-vec total-bytes]
  (let [out (js/Uint8Array. (long total-bytes))]
    (loop [idx 0
           offset 0]
      (if (< idx (count chunks-vec))
        (let [^js/Uint8Array arr (nth chunks-vec idx)]
          (.set out arr offset)
          (recur (inc idx) (+ offset (.-length arr))))
        out))))

(defn get-chunked-artifact-v11
  "BIP-017a v1.1.0: Fetches, verifies per-chunk SHA-256, and streams incremental SHA-256
   for a chunked large artifact identified by `manifestCid` using the pure Sans-IO
   `bitecho.storage.chunk-fetch` state machine.
   Supports `opts`:
   - `mirrors` / `baseUrls` (default `browser-cli/default-artifact-base-urls`)
   - `concurrency` (clamped to `chunk-const/max-fetch-concurrency-940mb`)
   - `maxBytes` (optional hard total-bytes cap)
   - `manifest` (optional pre-fetched manifest map/object)
   - `envelope` (optional detached owner envelope for signature verification)
   - `fetchFn` (optional custom `(fn [url] -> Promise<Response>)` for testing)."
  ([manifest-cid] (get-chunked-artifact-v11 manifest-cid nil))
  ([manifest-cid opts]
   (let [opts-clj (js-params->clj-map opts)
         na (or (:node-atom opts-clj) (get opts-clj "nodeAtom") @active-node-atom)
         raw-cid (str/lower-case (str/trim (str (or manifest-cid ""))))
         mirrors (vec (or (:relay-urls opts-clj)
                          (get opts-clj "relayUrls")
                          (get opts-clj "relay_urls")
                          (:mirrors opts-clj)
                          (get opts-clj "mirrors")
                          (:base-urls opts-clj)
                          (get opts-clj "baseUrls")
                          browser-cli/default-artifact-base-urls))
         fetch-fn (or (:fetch-fn opts-clj)
                      (get opts-clj "fetchFn")
                      (when (exists? js/fetch) js/fetch))
         concurrency (long (or (:concurrency opts-clj)
                               (get opts-clj "concurrency")
                               chunk-const/default-fetch-concurrency))
         max-bytes (or (:max-bytes opts-clj) (get opts-clj "maxBytes"))
         pre-manifest (or (:manifest opts-clj) (get opts-clj "manifest"))
         envelope (or (:envelope opts-clj) (get opts-clj "envelope"))
         emit-diag! (fn [d]
                      (when (and na @na)
                        (emit-browser-event! na (assoc d :type "diagnose" :timestamp-ms (.now js/Date)))))]
     (if-not (re-matches #"^[0-9a-f]{64}$" raw-cid)
       (do
         (emit-diag! {:kind :invalid-cid :reason (str "invalid-manifest-cid:" raw-cid)})
         (js/Promise.resolve #js {"ok" false "error" "invalid-cid" "manifestCid" raw-cid}))
       (let [load-manifest-promise
             (if (some? pre-manifest)
               (js/Promise.resolve {:ok? true :manifest (if (map? pre-manifest) pre-manifest (js->clj pre-manifest))})
               (if-not fetch-fn
                 (js/Promise.resolve {:ok? false :error "fetch-unavailable"})
                 (js/Promise.
                  (fn [resolve _reject]
                    (letfn [(try-m [idx last-err]
                              (if (>= idx (count mirrors))
                                (resolve {:ok? false :error (or last-err "manifest-fetch-failed")})
                                (let [url (str (str/replace (nth mirrors idx) #"/+$" "") "/artifact/v1/blob/" raw-cid)]
                                  (-> (fetch-fn url)
                                      (.then (fn [resp]
                                               (if (and resp (.-ok resp))
                                                 (-> (.json resp)
                                                     (.then (fn [j] (resolve {:ok? true :manifest (js->clj j)})))
                                                     (.catch (fn [e] (try-m (inc idx) (str e)))))
                                                 (try-m (inc idx) (str "http-" (when resp (.-status resp)))))))
                                      (.catch (fn [e] (try-m (inc idx) (str e))))))))]
                      (try-m 0 nil))))))]
         (.then
          load-manifest-promise
          (fn [mres]
            (if-not (:ok? mres)
              (js/Promise.resolve #js {"ok" false "error" (str (:error mres)) "manifestCid" raw-cid})
              (let [manifest (:manifest mres)
                    val-res (chunk-const/validate-manifest manifest (cond-> {} (some? max-bytes) (assoc :max-bytes max-bytes)))
                    env-res (when (and (:ok? val-res) (some? envelope))
                              (chunk-const/verify-detached-owner-envelope (:manifest val-res)
                                                                          (if (map? envelope) envelope (js->clj envelope :keywordize-keys true))))]
                (cond
                  (not (:ok? val-res))
                  (do
                    (doseq [e (:effects val-res)] (emit-diag! e))
                    (js/Promise.resolve #js {"ok" false
                                             "error" (name (:error val-res))
                                             "manifestCid" raw-cid}))

                  (not= raw-cid (:manifest-cid val-res))
                  (do
                    (emit-diag! {:kind :manifest-cid-mismatch :expected raw-cid :actual (:manifest-cid val-res)})
                    (js/Promise.resolve #js {"ok" false
                                             "error" "manifest-cid-mismatch"
                                             "manifestCid" raw-cid
                                             "actualCid" (:manifest-cid val-res)}))

                  (and (some? env-res) (not (:ok? env-res)))
                  (do
                    (doseq [e (:effects env-res)] (emit-diag! e))
                    (js/Promise.resolve #js {"ok" false
                                             "error" (name (:error env-res))
                                             "manifestCid" raw-cid}))

                  (nil? fetch-fn)
                  (js/Promise.resolve #js {"ok" false "error" "fetch-unavailable" "manifestCid" raw-cid})

                  :else
                  (let [init-res (chunk-fetch/init-fetch-state {:manifest (:manifest val-res)
                                                                :mirrors mirrors
                                                                :concurrency concurrency
                                                                :max-bytes max-bytes})]
                    (if-not (:ok? init-res)
                      (js/Promise.resolve #js {"ok" false "error" (name (:error init-res)) "manifestCid" raw-cid})
                      (js/Promise.
                       (fn [resolve _reject]
                         (let [st-atom (atom (:state init-res))
                               pool-atom (atom (relay-pool/init-relay-pool mirrors {:generation 1}))
                               staged-bytes-atom (atom {})
                               ordered-chunks-atom (atom [])
                               done-atom (atom false)]
                           (letfn [(finish! [res-obj]
                                     (when-not @done-atom
                                       (reset! done-atom true)
                                       (resolve res-obj)))
                                   (record-pool-event! [ev]
                                     (let [effs-box (atom [])]
                                       (swap! pool-atom
                                              (fn [p]
                                                (let [[p' effs] (relay-pool/transition p ev)]
                                                  (reset! effs-box effs)
                                                  p')))
                                       (doseq [d @effs-box]
                                         (emit-diag! d))))
                                   (run-effects! [effs]
                                     (doseq [eff effs]
                                       (when-not @done-atom
                                         (case (:type eff)
                                           :diagnose
                                           (emit-diag! eff)

                                           :emit
                                           (cond
                                             (= :chunked-artifact-complete (:event eff))
                                             (let [st @st-atom
                                                   assembled (concat-uint8-arrays @ordered-chunks-atom (:total-bytes st))]
                                               (finish! #js {"ok" true
                                                             "manifestCid" (:manifest-cid st)
                                                             "totalSha256" (:total-sha256 st)
                                                             "totalBytes" (:total-bytes st)
                                                             "bytes" assembled
                                                             "diagnostics" (clj->js (:diagnostics st))
                                                             "relayPoolDiagnostics" (clj->js (:diagnostics @pool-atom))}))

                                             (= :chunked-artifact-failed (:event eff))
                                             (let [st @st-atom]
                                               (finish! #js {"ok" false
                                                             "error" (name (or (:reason eff) :chunked-artifact-failed))
                                                             "manifestCid" (:manifest-cid st)
                                                             "diagnostics" (clj->js (:diagnostics st))
                                                             "relayPoolDiagnostics" (clj->js (:diagnostics @pool-atom))})))

                                           :fetch-chunk
                                           (let [idx (:index eff)
                                                 cid (:cid eff)
                                                 now-ms (.now js/Date)
                                                 mirror (or (relay-pool/select-healthy-relay @pool-atom now-ms #{})
                                                            (:mirror eff))
                                                 gen (:generation eff)
                                                 pool-gen (:generation @pool-atom)
                                                 url (str (str/replace mirror #"/+$" "") "/artifact/v1/blob/" cid)]
                                             (-> (fetch-fn url)
                                                 (.then (fn [resp]
                                                          (if (and resp (.-ok resp))
                                                            (-> (.arrayBuffer resp)
                                                                (.then (fn [ab]
                                                                         (let [u8 (js/Uint8Array. ab)
                                                                               actual-cid (crypto/sha256-hex u8)
                                                                               done-ms (.now js/Date)]
                                                                           (record-pool-event! {:type :request-ok
                                                                                                :url mirror
                                                                                                :rtt-ms (max 0 (- done-ms now-ms))
                                                                                                :generation pool-gen
                                                                                                :now-ms done-ms})
                                                                           (swap! staged-bytes-atom assoc idx u8)
                                                                           (let [[ns next-effs]
                                                                                 (chunk-fetch/transition @st-atom
                                                                                                         {:type :chunk-fetched
                                                                                                          :generation gen
                                                                                                          :index idx
                                                                                                          :mirror mirror
                                                                                                          :cid actual-cid
                                                                                                          :size (.-length u8)})]
                                                                             (reset! st-atom ns)
                                                                             (run-effects! next-effs))))))
                                                            (let [status (if resp (.-status resp) 0)
                                                                  reason (str "http-" status)
                                                                  fail-ms (.now js/Date)]
                                                              (record-pool-event! {:type :request-failed
                                                                                   :url mirror
                                                                                   :status status
                                                                                   :error reason
                                                                                   :chunk-idx idx
                                                                                   :generation pool-gen
                                                                                   :now-ms fail-ms})
                                                              (let [[ns next-effs]
                                                                    (chunk-fetch/transition @st-atom
                                                                                            {:type :chunk-http-error
                                                                                             :generation gen
                                                                                             :index idx
                                                                                             :mirror mirror
                                                                                             :status status
                                                                                             :reason reason})]
                                                                (reset! st-atom ns)
                                                                (run-effects! next-effs))))))
                                                 (.catch (fn [err]
                                                           (let [reason (str (or (when err (.-message err)) err "fetch-error"))
                                                                 fail-ms (.now js/Date)]
                                                             (record-pool-event! {:type :request-failed
                                                                                  :url mirror
                                                                                  :status 0
                                                                                  :error reason
                                                                                  :chunk-idx idx
                                                                                  :generation pool-gen
                                                                                  :now-ms fail-ms})
                                                             (let [[ns next-effs]
                                                                   (chunk-fetch/transition @st-atom
                                                                                           {:type :chunk-http-error
                                                                                            :generation gen
                                                                                            :index idx
                                                                                            :mirror mirror
                                                                                            :status 0
                                                                                            :reason reason})]
                                                               (reset! st-atom ns)
                                                               (run-effects! next-effs)))))))

                                           :digest-chunk
                                           (let [idx (:index eff)
                                                 gen (:generation eff)
                                                 u8 (get @staged-bytes-atom idx)]
                                             (if (and u8 (= (crypto/sha256-hex u8) (:cid eff)))
                                               (do
                                                 (swap! ordered-chunks-atom conj u8)
                                                 (swap! staged-bytes-atom dissoc idx)
                                                 (let [[ns next-effs]
                                                       (chunk-fetch/transition @st-atom
                                                                               {:type :digest-result
                                                                                :generation gen
                                                                                :index idx
                                                                                :ok? true})]
                                                   (reset! st-atom ns)
                                                   (run-effects! next-effs)))
                                               (let [[ns next-effs]
                                                     (chunk-fetch/transition @st-atom
                                                                             {:type :digest-result
                                                                              :generation gen
                                                                              :index idx
                                                                              :ok? false
                                                                              :reason "staged-chunk-missing-or-corrupt"})]
                                                 (reset! st-atom ns)
                                                 (run-effects! next-effs))))

                                           :digest-final
                                           (let [gen (:generation eff)
                                                 st @st-atom
                                                 assembled (concat-uint8-arrays @ordered-chunks-atom (:total-bytes st))
                                                 actual-total-sha (crypto/sha256-hex assembled)
                                                 [ns next-effs]
                                                 (chunk-fetch/transition @st-atom
                                                                         {:type :digest-final
                                                                          :generation gen
                                                                          :sha256 actual-total-sha})]
                                             (reset! st-atom ns)
                                             (run-effects! next-effs))

                                           nil))))]
                             (let [[st1 start-effs] (chunk-fetch/transition @st-atom {:type :start :generation 1})]
                               (reset! st-atom st1)
                               (run-effects! (into (:effects init-res) start-effs)))))))))))))))))))

(defn build-light-node-api
  "Constructs the unified `BitechoLightNode` browser console CLI & v1.1.0 Headless API object
   exposing EVERY Node/JVM CLI verb from `browser-cli/browser-cli-verb-inventory` as a camelCase
   Promise-returning method, plus the additive D40.4 v1.0.0 contract (`apiVersion`, `getStatus`,
   `onEvent`, `listPetnames`, `setPetname`, `listSessions`, `listSubnets`, `sendMessage`,
   `sendBroadcast`, `getArtifact`), BIP-017a v1.1.0 additive facade (`openChannel`, `openSession`,
   `acceptOffer`, `approveOffer`, `denyOffer`, `listPendingOffers`, `registerYubiKey`,
   `recoverYubiKey`, `saveIdentity`, `getChunkedArtifact`), `exec`, `cli`, `help`, `verbs`,
   `peers`, `reconnect`, and `autoUpdaterStatus`."
  []
  (let [obj #js {"apiVersion" browser-cli/api-version
                 "exec" exec-light-node-verb
                 "cli" exec-light-node-cli
                 "verbs" (fn [] (js/Promise.resolve (clj->js browser-cli/browser-cli-verb-inventory)))
                 "peers" (fn [] (get-peers-status @active-node-atom))
                 "reconnect" (fn [& [opts]] (js/Promise.resolve (connect-mesh opts)))
                 "autoUpdaterStatus" (fn [] (js/Promise.resolve (clj->js (or @browser-updater-atom {:status "not-started"}))))
                 "initNode" init-node
                 "stopNode" stop-node
                 "getState" get-state
                 "getStatus" get-light-node-status
                 "onEvent" on-event
                 "listPetnames" list-petnames-v1
                 "setPetname" set-petname-v1
                 "listSessions" list-sessions-v1
                 "listSubnets" list-subnets-v1
                 "sendMessage" send-message-v1
                 "sendBroadcast" send-broadcast-v1
                 "getArtifact" get-artifact-v1
                 "version" "0.23.22"}]
    ;; Attach every recognized CLI verb as a Closure :advanced-safe camelCase JS method
    (doseq [[verb {:keys [js-method]}] browser-cli/browser-cli-verb-inventory]
      (gobj/set obj js-method
                (fn [& [params opts]]
                  (exec-light-node-verb verb params opts))))
    ;; Attach additive BIP-017a v1.1.0 top-level camelCase facade methods (preserving all v1.0.0 methods)
    (gobj/set obj "openChannel" open-channel-v11)
    (gobj/set obj "openSession" open-session-v11)
    (gobj/set obj "acceptOffer" accept-offer-v11)
    (gobj/set obj "approveOffer" approve-offer-v11)
    (gobj/set obj "denyOffer" deny-offer-v11)
    (gobj/set obj "listPendingOffers" list-pending-offers-v11)
    (gobj/set obj "registerYubiKey" register-yubikey-v11)
    (gobj/set obj "recoverYubiKey" recover-yubikey-v11)
    (gobj/set obj "saveIdentity" save-identity-v11)
    (gobj/set obj "getChunkedArtifact" get-chunked-artifact-v11)
    obj))

(def light-node-api
  "Global BitechoLightNode console CLI parity API object (Rule 6)."
  (build-light-node-api))

(gobj/set api "lightNode" light-node-api)
(gobj/set api "exec" exec-light-node-verb)
(gobj/set api "cli" exec-light-node-cli)
(gobj/set api "verbs" (fn [] (js/Promise.resolve (clj->js browser-cli/browser-cli-verb-inventory))))
(gobj/set api "peers" (fn [] (get-peers-status @active-node-atom)))
(gobj/set api "reconnect" (fn [& [opts]] (js/Promise.resolve (connect-mesh opts))))

(when (exists? js/goog)
  (.exportSymbol js/goog "BitechoBrowser" api)
  (.exportSymbol js/goog "BitechoLightNode" light-node-api))
(when (exists? js/globalThis)
  (gobj/set js/globalThis "BitechoBrowser" api)
  (gobj/set js/globalThis "BitechoLightNode" light-node-api))
(when (exists? js/window)
  (gobj/set js/window "BitechoBrowser" api)
  (gobj/set js/window "BitechoLightNode" light-node-api))

;; Wire document visibilitychange listener
(when (and (exists? js/document) (some? (.-addEventListener js/document)))
  (.addEventListener js/document "visibilitychange"
                     (fn [_]
                       (when-let [na @active-node-atom]
                         (let [state (if (= (.-visibilityState js/document) "hidden") "hidden" "visible")]
                           (handle-visibility-change! na state))))))
