(ns bitecho.browser-main
  "Bitecho Browser Node static bundle entry point.
   Exposes high-level browser API on js/globalThis.BitechoBrowser conforming to Rules 1-6."
  (:require [bitecho.anchor.core :as anchor]
            [bitecho.basalt.core :as basalt]
            [bitecho.bech32m :as bech32m]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.browser :as browser]
            [bitecho.webauthn :as webauthn]))

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
   :node3 {:node-id "node3" :ip "35.211.71.139" :port 5000 :agent-port 5010 :agent-tcp-port 5010 :ingress-host "node3.ingress.bitecho.org" :ingress-port 443 :pubkey "302a300506032b65700321007b7f58652a2c26b4180aeee45ff12f927a45d92e00fc3462c5d854f6203351f1" :fingerprint "38:2B:18:4B:23:E8:F4:32:D7:08:5A:2A:A4:45:4F:EE:12:D4:51:B1:9B:2D:66:7C:2E:E1:2A:3E:7C:B3:60:40" :ice-ufrag "4b1d8fc5" :ice-pwd "47e794a9ed5ef04cc0ebbe7f"}})

(def default-bootstrap-descriptor
  "Signed devnet bootstrap descriptor verified against default-authority-pubkey."
  {:network :devnet
   :domain "bitecho.org"
   :authority-pubkey default-authority-pubkey
   :issued-epoch 0
   :expires-epoch 1000000000
   :signature "fb6cbfaf65fde5e05eacda10b88dbb1bb0d5e3c955b7941e71b201769f1c25acd3df6fa5130a7316cf89260549de9888b3f35d352dbde62098820232a4b2f701"
   :treasury-pubkey "302a300506032b65700321007c2b695b77904a19a630b75ce53889a53963c0f85aa69e5276bb988a183b91b8"
   :custody-pubkey "302a300506032b6570032100e476d77ef34962d09baee0062b4c03be832a1ccc2d691623a8cb39e356793f2b"
   :directory-pubkey default-authority-pubkey
   :nodes default-bootstrap-nodes})

(def default-petnames
  "Default well-known petnames for devnet authorities and key peers."
  {"axiom" "302a300506032b6570032100b53afd55492fe17fca9d0ef0e07b367bf8333490e43b4ecd3610c12c8e6a79f8"
   "nexus" "302a300506032b65700321009b33a9ebd1866d6db419edabe2de9ee74c884dc86b4214f60e3a26f04cbd9cfc"})

(defonce ^:private ui-listeners-atom (atom []))

(declare get-status)

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

(def ^:private redacted-js-keys
  #{:privkey-bytes :cold-privkey :private-key :privkey :privkey-hex :seed :seed-bytes
    :keypair :x25519 :ephemeral-priv :ephemeral-privkey :tx-key :rx-key :session-keys
    :shared-secret :user-handle :raw-id :prf-output :backup-seed
    :private_key :privkey_bytes :cold_privkey :seed_bytes :user_handle :raw_id
    :ephemeral_priv :tx_key :rx_key :session_keys :shared_secret :prf_output :backup_seed
    :privateKey :privkeyBytes :coldPrivkey :seedBytes :userHandle :rawId
    :ephemeralPriv :txKey :rxKey :sessionKeys :sharedSecret :prfOutput :backupSeed})

(defn- redacted-js-key? [k]
  (or (contains? redacted-js-keys k)
      (and (or (keyword? k) (string? k))
           (contains? redacted-js-keys (keyword (name k))))))

(defn- redact-for-js
  "Recursively redacts private key material and credentials before converting to JS."
  [x]
  (cond
    (map? x)
    (into {}
          (keep (fn [[k v]]
                  (when-not (redacted-js-key? k)
                    [k (redact-for-js v)])))
          x)
    (vector? x) (mapv redact-for-js x)
    (seq? x) (map redact-for-js x)
    :else x))

(defn- apply-hardware-identity!
  "Applies a recovered hardware identity map to anchor-state-atom and active-node-atom."
  [recovered]
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
    (when (and @active-node-atom (:private-key recovered) (:public-key recovered))
      (swap! @active-node-atom
             (fn [node]
               (-> node
                   (assoc :keypair {:public-key (:public-key recovered)
                                    :private-key (:private-key recovered)})
                   (assoc-in [:light-state :pubkey] (:public-hex recovered))))))))

(defn init-anchor
  "Initializes or resets the global Human Anchor state atom."
  ([] (init-anchor nil))
  ([opts]
   (let [opts-map (or (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true))) {})
         fallback-kp (or (when-let [na @active-node-atom] (:keypair @na))
                         (crypto/generate-keypair))
         pubkey-hex (or (:pubkey opts-map)
                        (:pubkey-hex opts-map)
                        (when fallback-kp (fressian/bytes->hex (:public-key fallback-kp))))
         privkey-bytes (or (:privkey-bytes opts-map)
                           (:cold-privkey opts-map)
                           (when fallback-kp (:private-key fallback-kp)))
         st (anchor/init-anchor-state (assoc opts-map :pubkey pubkey-hex)
                                      (cond-> opts-map
                                        privkey-bytes (assoc :privkey-bytes privkey-bytes)))]
     (reset! anchor-state-atom st)
     (clj->js (redact-for-js (anchor/anchor-dashboard-view st))))))

(defn get-anchor-dashboard
  "Returns the Human Anchor dashboard view as a JavaScript object."
  []
  (when-not @anchor-state-atom
    (init-anchor nil))
  (clj->js (redact-for-js (anchor/anchor-dashboard-view @anchor-state-atom))))

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
        existing-ident (or (when (map? opts-map) (:identity opts-map))
                           (when (and (map? opts-map) (:public-hex opts-map)) opts-map))
        user-handle (or (when raw-bytes? seed-or-opts)
                        (when (and (some? seed-or-opts) (object? seed-or-opts))
                          (or (unchecked-get seed-or-opts "userHandle")
                              (unchecked-get seed-or-opts "user_handle")
                              (when-let [r (unchecked-get seed-or-opts "response")]
                                (or (unchecked-get r "userHandle")
                                    (unchecked-get r "user_handle")))))
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
                              (:seed_bytes opts-map)
                              (:prf-output opts-map)
                              (:prfOutput opts-map)
                              (:prf_output opts-map)))
                        (when (string? seed-or-opts) seed-or-opts)
                        (when (sequential? seed-or-opts) seed-or-opts))
        recovered (cond
                    (some? user-handle)
                    (webauthn/recover-seed-from-assertion
                     (if (map? opts-map)
                       (assoc opts-map :user-handle user-handle)
                       {:user-handle user-handle}))

                    (and existing-ident (:public-hex existing-ident) (:address existing-ident))
                    existing-ident

                    :else nil)]
    (if-not recovered
      (clj->js {:ok false :error "recovery-failed"})
      (do
        (apply-hardware-identity! recovered)
        (clj->js (assoc (redact-for-js recovered) :ok true))))))

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
        [new-state effects] (anchor/approve-offer (or @anchor-state-atom (anchor/init-anchor-state)) id opts-map)]
    (reset! anchor-state-atom new-state)
    (when-let [na @active-node-atom]
      (when (get-in @na [:light-state :pending-offers id])
        (accept-channel-offer na id)))
    (clj->js {:ok true :effects effects :dashboard (redact-for-js (anchor/anchor-dashboard-view new-state))})))

(defn deny-offer-cmd
  "Denies a pending offer in the Human Anchor queue with an explicit reason."
  [offer-id & [reason]]
  (let [id (str offer-id)
        rej-reason (or reason "denied-by-human-anchor")
        [new-state effects] (anchor/deny-offer (or @anchor-state-atom (anchor/init-anchor-state)) id rej-reason)]
    (reset! anchor-state-atom new-state)
    (clj->js {:ok true :effects effects :dashboard (redact-for-js (anchor/anchor-dashboard-view new-state))})))

(defn supervise-agent-cmd
  "Registers an autonomous agent under human anchor supervision with an issued DAC."
  [agent-id hot-pubkey & [perms]]
  (let [aid (str agent-id)
        pub-str (str hot-pubkey)
        perms-vec (when perms (js->clj perms :keywordize-keys true))
        new-state (anchor/register-supervised-agent (or @anchor-state-atom (anchor/init-anchor-state))
                                                    {:agent-id aid
                                                     :hot-pubkey pub-str
                                                     :permissions perms-vec})]
    (reset! anchor-state-atom new-state)
    (clj->js {:ok true :agentId aid :dashboard (redact-for-js (anchor/anchor-dashboard-view new-state))})))

(defn revoke-agent-dac-cmd
  "Emergency revocation of a supervised agent's DAC."
  [agent-id & [reason]]
  (let [aid (str agent-id)
        rej-reason (or reason "emergency-human-anchor-revocation")
        [new-state effects] (anchor/revoke-agent-dac (or @anchor-state-atom (anchor/init-anchor-state)) aid rej-reason)]
    (reset! anchor-state-atom new-state)
    (clj->js {:ok true :effects effects :dashboard (redact-for-js (anchor/anchor-dashboard-view new-state))})))

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
        st0 (anchor/init-anchor-state {:pubkey anchor-pub}
                                      {:privkey-bytes (:private-key recovered)
                                       :key-mode :yubikey-discoverable})
        st1 (anchor/set-service-offer st0 :ai-inference {:price 100 :burn-floor 100})
        st2 (anchor/queue-incoming-offer st1 {:offer-id "off-demo-1" :peer-id "worker-node-1" :burn 100})
        [st3 _app-effects] (anchor/approve-offer st2 "off-demo-1")
        hot-kp (crypto/generate-keypair)
        hot-pub (fressian/bytes->hex (:public-key hot-kp))
        st4 (anchor/register-supervised-agent st3 {:agent-id "sub-agent-alpha"
                                                   :hot-pubkey hot-pub
                                                   :max-spend 5000})
        st5 (anchor/log-agent-activity st4 "sub-agent-alpha" {:type :offer-accepted :offer-id "off-demo-1"})
        [st6 _rev-effects] (anchor/revoke-agent-dac st5 "sub-agent-alpha" "routine-rotation")
        st7 (anchor/create-team-call-subnet st6 {:topic-name "core-devs" :peers ["worker-node-1"]})
        dashboard (redact-for-js (anchor/anchor-dashboard-view st7))]
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
         subnet-id (or (:subnet-id opts-map) (:subnetId opts-map)
                       "global")
         keypair (crypto/generate-keypair)
         x25519 (sealed/generate-x25519-keypair)
         pubkey-hex (fressian/bytes->hex (:public-key keypair))
         init-light (light-core/init-light-state {:pubkey-hex pubkey-hex}
                                                 {:subnet-id subnet-id
                                                  :bootstrap default-bootstrap-descriptor
                                                  :economy-enabled? true
                                                  :burn-floor 100
                                                  :autonomous? false})
         light-st (assoc init-light :petnames default-petnames)
         conn-state (browser/initial-conn-state {:peer-id node-id :subnet-id subnet-id})
         node-atom (atom {:peer-id node-id
                          :subnet-id subnet-id
                          :keypair keypair
                          :x25519 x25519
                          :conn conn-state
                          :light-state light-st
                          :petnames default-petnames
                          :chat-history []
                          :active-channels {}
                          :sessions {}
                          :inbox []
                          :outbox []
                          :burned-ech 0
                          :autonomous? false})]
     (reset! active-node-atom node-atom)
     (when (:persist? opts-map)
       (browser/persist-state! (browser/sanitize-state-for-persistence @node-atom)))
     (notify-ui-listeners!)
     node-atom)))

(defn get-status
  "Returns Rule 4 status and diagnostics map as a JavaScript object."
  ([] (get-status @active-node-atom))
  ([node-atom]
   (when node-atom
     (let [node @node-atom
           conn (:conn node)
           diag (:diagnostics conn)
           light-st (:light-state node)
           channels (:active-channels node)
           open-channels (into [] (keep (fn [[k dc]]
                                          (when (and dc (= (.-readyState dc) "open")) (name k)))
                                        channels))]
       (clj->js {:peerId (:peer-id node)
                 :subnetId (:subnet-id node)
                 :pubkey (when-let [kp (:keypair node)] (fressian/bytes->hex (:public-key kp)))
                 :epoch (or (:epoch light-st) 0)
                 :phase (name (or (:phase conn) :idle))
                 :generation (or (:generation conn) 0)
                 :visibilityState (or (:visibility-state conn) "visible")
                 :burnedEch (or (:burned-ech node) 0)
                 :meshConnected (boolean (seq open-channels))
                 :connectedNodes open-channels
                 :sessions (redact-for-js (or (:sessions light-st) {}))
                 :pendingOffers (redact-for-js (or (:pending-offers light-st) {}))
                 :chatHistory (or (:chat-history node) [])
                 :petnames (or (:petnames node) default-petnames)
                 :diagnostics {:phase (name (or (:phase diag) :idle))
                               :generation (or (:generation diag) 0)
                               :lastError (:last-error diag)
                               :dropped (or (:dropped diag) 0)
                               :ignoredStale (or (:ignored-stale diag) 0)
                               :unsupportedFormatDropped (or (:unsupported-format-dropped diag) 0)
                               :backgroundThrottledEvents (or (:background-throttled-events diag) 0)}})))))

(defn- send-to-all-channels!
  [node-atom env]
  (let [channels (:active-channels @node-atom)
        wire-bytes (fressian/encode-wire env)]
    (doseq [[_id dc] channels]
      (when (and dc (= (.-readyState dc) "open"))
        (try (.send dc wire-bytes) (catch :default _ nil))))))

(defn handle-inbound-wire-envelope!
  "Processes an incoming wire envelope, updates light state, handles decrypted messages,
   and replies over the WebRTC mesh DataChannel."
  [node-atom env]
  (when (and node-atom env)
    (let [node @node-atom
          privkey (:private-key (:keypair node))
          st (:light-state node)
          prev-offers (or (:pending-offers st) {})
          res (light-core/handle-wire-payload st env privkey)
          new-st (:state res)
          curr-offers (or (:pending-offers new-st) {})]
      (swap! node-atom (fn [curr]
                         (let [prev-inbox (get-in curr [:light-state :inbox] [])
                               curr-inbox (get-in new-st [:inbox] [])
                               new-msgs (subvec curr-inbox (count prev-inbox))]
                           (-> curr
                               (assoc :light-state new-st)
                               (assoc :sessions (:sessions new-st))
                               (update :chat-history (fn [hist]
                                                       (into (or hist [])
                                                             (map (fn [m]
                                                                    {:timestamp (.toISOString (js/Date.))
                                                                     :direction :incoming
                                                                     :peer (or (:sender m) (:peer-id m) "peer")
                                                                     :text (or (:text m) (:message m) (str m))
                                                                     :status :received}))
                                                             new-msgs)))))))
      ;; Surface any new live incoming channel offers into the Human Anchor queue
      (doseq [[sid offer] curr-offers]
        (when-not (contains? prev-offers sid)
          (when-not @anchor-state-atom
            (init-anchor nil))
          (swap! anchor-state-atom anchor/queue-incoming-offer
                 {:offer-id sid
                  :session-id sid
                  :peer-id (:caller offer)
                  :caller-pubkey (:caller offer)
                  :callee-pubkey (:callee offer)
                  :price (or (:price offer) 10)
                  :burn (or (:burn offer) 100)
                  :epoch (or (:epoch offer) 0)})))
      (doseq [reply-env (:net-envelopes res)]
        (send-to-all-channels! node-atom reply-env))
      (browser/persist-state! (browser/sanitize-state-for-persistence @node-atom))
      (notify-ui-listeners!))))

(defn- send-chain-state-query!
  "Sends a signed :query-chain-state envelope on the given DataChannel."
  [node-atom dc]
  (when (and node-atom dc (= (.-readyState dc) "open"))
    (let [node @node-atom
          pubkey (get-in node [:light-state :pubkey])
          privkey (:private-key (:keypair node))
          nonce (str "csq-" (fressian/bytes->hex (crypto/random-bytes 4)))
          q-env (light-core/build-chain-state-query-envelope pubkey privkey {:nonce nonce})]
      (try (.send dc (fressian/encode-wire q-env)) (catch :default _ nil)))))

(defn- on-validator-channel-open!
  "Handles validator DataChannel open: records channel, registers home set, queries chain state, and starts keepalive."
  [node-atom nid dc conn-atom]
  (swap! node-atom (fn [st]
                     (cond-> (assoc-in st [:active-channels nid] dc)
                       (= nid "node1") (assoc :conn @conn-atom))))
  ;; Register home set with devnet nodes
  (let [reg-res (light-core/handle-command (:light-state @node-atom)
                                           {"cmd" "register-home-set" "price" 10 "nodes" ["node1" "node2" "node3"]}
                                           (:private-key (:keypair @node-atom)))]
    (swap! node-atom assoc :light-state (:state reg-res))
    (doseq [env (:net-envelopes reg-res)]
      (try (.send dc (fressian/encode-wire env)) (catch :default _ nil))))
  ;; Query chain state from validator so 2-of-3 BFT quorum syncs epoch and account
  (send-chain-state-query! node-atom dc)
  ;; Keepalive + epoch sync every 25s
  (js/setInterval (fn []
                    (when (and dc (= (.-readyState dc) "open"))
                      (send-chain-state-query! node-atom dc)))
                  25000)
  (notify-ui-listeners!))

(defn connect-mesh
  "Connects live browser light-node to Bitecho devnet mesh via WebRTC DataChannels."
  ([] (connect-mesh nil))
  ([opts]
   (if-not (:ok? (light-core/verify-bootstrap-descriptor default-authority-pubkey default-bootstrap-descriptor 0))
     (clj->js {:ok false :error "untrusted-bootstrap-descriptor"})
     (let [node-atom (or @active-node-atom (init-node nil))
           _opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
           node1 (get default-bootstrap-nodes :node1)
           sdp1 (browser/format-validator-sdp-answer node1)
           target-url (str "rtc://" (:ip node1) ":" (:agent-port node1))
           conn-atom (atom (:conn @node-atom))]
       (browser/connect-webrtc!
        conn-atom
        {:peer-id "node1"
         :target-url target-url
         :answer-sdp sdp1
         :channel-label "bitecho"
         :on-open (fn [open-info]
                    (on-validator-channel-open! node-atom "node1" (:channel open-info) conn-atom))
         :on-deliver-message (fn [env]
                               (handle-inbound-wire-envelope! node-atom env))})
       ;; Auxiliary DataChannels to node2 and node3
       (doseq [[nid ncfg] (select-keys default-bootstrap-nodes [:node2 :node3])]
         (let [nid-str (name nid)
               aux-sdp (browser/format-validator-sdp-answer ncfg)
               aux-conn-atom (atom (browser/initial-conn-state {:peer-id nid-str}))]
           (browser/connect-webrtc!
            aux-conn-atom
            {:peer-id nid-str
             :target-url (str "rtc://" (:ip ncfg) ":" (:agent-port ncfg))
             :answer-sdp aux-sdp
             :channel-label "bitecho"
             :on-open (fn [aux-open]
                        (on-validator-channel-open! node-atom nid-str (:channel aux-open) aux-conn-atom))
             :on-deliver-message (fn [env]
                                   (handle-inbound-wire-envelope! node-atom env))})))
       (notify-ui-listeners!)
       (clj->js {:ok true
                 :status "connecting"
                 :targetNode "node1"
                 :ip (:ip node1)
                 :port (:agent-port node1)})))))

(defn open-channel
  "Initiates a cryptographically signed channel offer to callee over the live mesh DataChannel."
  ([callee] (open-channel @active-node-atom callee 10 500))
  ([node-atom callee & [price burn]]
   (let [na (or node-atom @active-node-atom)
         node @na
         target-pub (or (get (:petnames node) callee)
                        (get default-petnames callee)
                        callee)
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
                (not cmd-ok?) (assoc :error (get resp "error")))))))

(defn accept-channel-offer
  "Accepts a pending session offer by session-id over the live mesh DataChannel."
  ([session-id] (accept-channel-offer @active-node-atom session-id))
  ([node-atom session-id]
   (let [na (or node-atom @active-node-atom)
         node @na
         privkey (:private-key (:keypair node))
         cmd-res (light-core/handle-command (:light-state node)
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
       (send-to-all-channels! na env))
     (browser/persist-state! (browser/sanitize-state-for-persistence @na))
     (notify-ui-listeners!)
     (clj->js (cond-> {:ok cmd-ok?
                       :sessionId session-id
                       :response resp}
                (not cmd-ok?) (assoc :error (get resp "error")))))))

(defn send-message
  "Sends a cryptographically sealed message to a peer over the live mesh DataChannel."
  ([peer-id text] (send-message @active-node-atom peer-id text))
  ([node-atom peer-id text]
   (let [na (or node-atom @active-node-atom)
         node @na
         target-pub (or (get (:petnames node) peer-id)
                        (get default-petnames peer-id)
                        peer-id)
         privkey (:private-key (:keypair node))
         cmd-res (light-core/handle-command (:light-state node)
                                            {"cmd" "send"
                                             "peer" target-pub
                                             "text" (str text)
                                             "message" (str text)}
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
                   (update :chat-history conj {:timestamp (.toISOString (js/Date.))
                                               :direction :outgoing
                                               :peer peer-id
                                               :text text
                                               :status :sent}))))
     (doseq [env out-envs]
       (send-to-all-channels! na env))
     (browser/persist-state! (browser/sanitize-state-for-persistence @na))
     (notify-ui-listeners!)
     (clj->js (cond-> {:ok cmd-ok?
                       :peer peer-id
                       :text text
                       :envelopesSent (count out-envs)
                       :response resp}
                (not cmd-ok?) (assoc :error (or (get resp "error") "no-open-session-for-peer")))))))

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
  "Dispatches visibility change ('visible' | 'hidden') into active node's connection state."
  ([vis-state] (handle-visibility-change! @active-node-atom vis-state))
  ([node-atom vis-state]
   (when node-atom
     (let [state-str (if (= (str vis-state) "hidden") "hidden" "visible")
           [new-conn effects] (browser/transition-conn (:conn @node-atom)
                                                       {:type :visibility-change :state state-str})]
       (swap! node-atom assoc :conn new-conn)
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

(defn load-state-from-indexed-db
  "Loads persisted sanitized state from IndexedDB. Returns a Promise."
  ([] (load-state-from-indexed-db @active-node-atom))
  ([node-atom]
   (js/Promise.
    (fn [resolve reject]
      (browser/load-persisted-state
       (fn [err loaded]
         (if err
           (reject (js/Error. (str err)))
           (do
             (when (and node-atom loaded)
               (swap! node-atom merge (dissoc loaded :conn :keypair :x25519)))
             (resolve (clj->js (redact-for-js (or loaded {}))))))))))))

(defn connect
  "Initiates dialing transition on the node's connection state and executes effects."
  [node-atom opts]
  (let [opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
        target-url (or (:target-url opts-map) (:targetUrl opts-map) "rtc://default")
        [new-conn effects] (browser/transition-conn (:conn @node-atom)
                                                    {:type :dial :target-url target-url})]
    (swap! node-atom assoc :conn new-conn)
    (doseq [eff effects]
      (case (:type eff)
        :diagnose nil
        :close-transport (when-let [t (:transport eff)] (try (.close t) (catch :default _ nil)))
        nil))
    (clj->js {:conn (get-status node-atom)
              :effects effects})))

(defn create-offer
  "Creates a cryptographically signed rendezvous/channel offer descriptor conforming to Phase 1 wire format."
  [node-atom peer-id & [opts]]
  (let [node @node-atom
        opts-map (when opts (js->clj opts :keywordize-keys true))
        x25519 (:x25519 node)
        keypair (:keypair node)
        caller-pub (fressian/bytes->hex (:public-key keypair))
        caller-eph (fressian/bytes->hex (:public-key x25519))
        callee-pub (str peer-id)
        epoch (or (:epoch opts-map) 1)
        burn (or (:burn opts-map) (:burn-amount opts-map) 100)
        price (or (:price opts-map) burn)
        sub-id (or (:subnet-id node) "global")
        suites (or (:crypto-suites opts-map) ["suite-v1-aes256gcm"])
        sid (light-core/compute-session-id caller-pub callee-pub caller-eph)
        offer-hash (light-core/compute-offer-hash {:session-id sid
                                                   :caller caller-pub
                                                   :callee callee-pub
                                                   :caller-ephemeral-pub caller-eph
                                                   :epoch epoch
                                                   :price price
                                                   :burn burn
                                                   :home-node ""
                                                   :crypto-suites suites
                                                   :subnet-id sub-id})
        privkey-bytes (:private-key keypair)
        sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (fressian/utf8->bytes offer-hash)))
        offer {:type :rendezvous-offer
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
               :signature sig-hex}]
    (swap! node-atom update :burned-ech (fnil + 0) burn)
    (clj->js offer)))

(defn accept-offer
  "Explicitly accepts an incoming offer after validating its cryptographic signature."
  [node-atom offer]
  (let [offer-map (if (map? offer) offer (js->clj offer :keywordize-keys true))
        caller-pub (or (:caller-pubkey offer-map) (:caller offer-map))
        caller-x25519 (or (when-let [x (:caller-x25519 offer-map)] (fressian/hex->bytes x))
                          (when-let [x (:caller-ephemeral-pub offer-map)] (fressian/hex->bytes x)))
        offer-hash (:offer-hash offer-map)
        sig-hex (:signature offer-map)
        sig-valid? (and (string? caller-pub) (string? offer-hash) (string? sig-hex)
                        (crypto/verify (basalt/hex->bytes caller-pub)
                                       (fressian/utf8->bytes offer-hash)
                                       (basalt/hex->bytes sig-hex)))]
    (if-not sig-valid?
      (clj->js {:accepted false :error "invalid-offer-signature"})
      (let [my-x25519 (:x25519 @node-atom)
            shared-secret (sealed/x25519-shared-secret (:private-key my-x25519) caller-x25519)
            session-keys (sealed/derive-channel-keys shared-secret "bitecho-browser-session-salt" :responder)
            burn (long (or (:burn offer-map) (:burn-amount offer-map) 50))]
        (swap! node-atom (fn [st]
                           (-> st
                               (assoc-in [:sessions caller-pub] {:session-keys session-keys
                                                                 :suite "suite-v1-aes256gcm"
                                                                 :seq 0})
                               (update :burned-ech (fnil + 0) burn))))
        (clj->js {:accepted true
                  :peerId caller-pub
                  :suite "suite-v1-aes256gcm"})))))

(defn send-sealed-message
  "Seals and sends a message to an active peer session."
  [node-atom peer-id text]
  (let [node @node-atom
        session (get-in node [:sessions peer-id])
        session-keys (:session-keys session)
        seq-num (inc (or (:seq session) 0))
        plaintext (fressian/utf8->bytes text)
        sealed-frame (when session-keys
                       (sealed/seal-message session-keys seq-num plaintext "suite-v1-aes256gcm"))
        env {:type :sealed-message
             :protocol-version 1
             :wire-format "fressian-v1"
             :sender (fressian/bytes->hex (:public-key (:keypair node)))
             :recipient peer-id
             :sealed-frame sealed-frame}
        [new-conn effects] (browser/transition-conn (:conn node)
                                                    {:type :send :envelope env})]
    (swap! node-atom (fn [st]
                       (-> st
                           (assoc :conn new-conn)
                           (assoc-in [:sessions peer-id :seq] seq-num)
                           (update :outbox conj env))))
    (clj->js {:sent (some? sealed-frame)
              :seq seq-num
              :effects effects})))

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
         new-st (anchor/queue-incoming-offer @anchor-state-atom off)]
     (reset! anchor-state-atom new-st)
     (clj->js (redact-for-js (anchor/anchor-dashboard-view new-st))))))

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
               (resolve (clj->js (redact-for-js res))))))))))))

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
               (resolve (clj->js (redact-for-js res))))))))))))

(def api
  "Global BitechoBrowser API object."
  #js {:initNode init-node
       :getStatus get-status
       :connect connect
       :connectMesh connect-mesh
       :openChannel open-channel
       :acceptChannelOffer accept-channel-offer
       :sendMessage send-message
       :getChatHistory get-chat-history
       :getSessions get-sessions
       :resolvePeer resolve-peer
       :onStateChange on-state-change
       :handleVisibilityChange handle-visibility-change!
       :saveStateToIndexedDB save-state-to-indexed-db
       :loadStateFromIndexedDB load-state-from-indexed-db
       :createOffer create-offer
       :acceptOffer accept-offer
       :sendSealedMessage send-sealed-message
       :runSubnetDemo run-subnet-demo
       :runZeroBurnSubnetDemo run-zero-burn-subnet-demo
       :runFederationDemo run-federation-demo
       :initAnchor init-anchor
       :getAnchorDashboard get-anchor-dashboard
       :registerYubiKey register-yubikey
       :recoverFromYubiKey recover-from-yubikey
       :createDiscoverableCredential create-discoverable-credential
       :getDiscoverableCredential get-discoverable-credential
       :queueOffer queue-offer
       :generateNonExtractableKey generate-non-extractable-key
       :approveOffer approve-offer-cmd
       :denyOffer deny-offer-cmd
       :superviseAgent supervise-agent-cmd
       :revokeAgentDac revoke-agent-dac-cmd
       :encodeBech32m encode-bech32m-cmd
       :decodeBech32m decode-bech32m-cmd
       :runAnchorEndToEndDemo run-anchor-end-to-end-demo
       :version "1.0.0-m12"})

(when (exists? js/globalThis)
  (set! (.-BitechoBrowser js/globalThis) api))

;; Wire document visibilitychange listener
(when (and (exists? js/document) (some? (.-addEventListener js/document)))
  (.addEventListener js/document "visibilitychange"
                     (fn [_]
                       (when-let [na @active-node-atom]
                         (let [state (if (= (.-visibilityState js/document) "hidden") "hidden" "visible")]
                           (handle-visibility-change! na state))))))
