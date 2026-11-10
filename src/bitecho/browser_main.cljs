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
            [bitecho.webauthn :as webauthn]
            [clojure.string :as str]))

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

(declare send-to-all-channels! send-chain-state-query!)

(defn- prune-ghost-sessions
  "Removes restored sessions whose ephemeral/session keys (:tx-key, :ephemeral-priv)
   were stripped during IndexedDB persistence sanitization."
  [sessions]
  (if-not (map? sessions)
    {}
    (into {}
          (filter (fn [[_sid s]]
                    (let [st (or (:state s) (when (:status s) (name (:status s))))]
                      (cond
                        (= st "open") (or (some? (:tx-key s)) (some? (:session-keys s)))
                        (= st "offered") (some? (:ephemeral-priv s))
                        :else false))))
          sessions)))

(defn- apply-hardware-identity!
  "Applies a recovered hardware identity map to anchor-state-atom and active-node-atom,
   and persists the sanitized public state to IndexedDB for refresh continuity (H-5, A-5)."
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
      (let [na @active-node-atom
            prev-pub (get-in @na [:light-state :pubkey])
            new-pub (:public-hex recovered)
            pub-changed? (not= prev-pub new-pub)]
        (swap! na
               (fn [node]
                 (cond-> (-> node
                             (assoc :keypair {:public-key (:public-key recovered)
                                              :private-key (:private-key recovered)})
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
                                                     (:private-key recovered))]
              (swap! na assoc :light-state (:state reg-res))
              (doseq [env (:net-envelopes reg-res)]
                (send-to-all-channels! na env)))
            (doseq [dc open-dcs]
              (send-chain-state-query! na dc))))
        (browser/persist-state! (browser/sanitize-state-for-persistence @na))))
    (notify-ui-listeners!)))

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
                               (dissoc :conn :keypair :x25519 :active-channels)
                               (update :sessions prune-ghost-sessions)
                               (update-in [:light-state :sessions] prune-ghost-sessions)
                               (update :chat-history #(vec (or % [])))
                               (update-in [:light-state :inbox] #(vec (or % [])))
                               (assoc-in [:light-state :max-epoch-skew]
                                         (or (get-in loaded [:light-state :max-epoch-skew]) 15)))]
          (swap! node-atom
                 (fn [curr]
                   (let [curr-kp (:keypair curr)
                         curr-pub (when (and curr-kp (:public-key curr-kp))
                                    (fressian/bytes->hex (:public-key curr-kp)))
                         same-pub? (= curr-pub saved-pub)]
                     (-> curr
                         (merge clean-loaded)
                         (assoc-in [:light-state :pubkey] saved-pub)
                         (assoc :keypair (if same-pub?
                                           curr-kp
                                           {:public-key pub-bytes
                                            :private-key nil}))
                         (assoc :x25519 (when same-pub? (:x25519 curr)))))))
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
                    (anchor/init-anchor-state {:pubkey saved-pub} {})))
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
         st (anchor/init-anchor-state (assoc opts-map :pubkey pubkey-hex)
                                      (cond-> opts-map
                                        privkey-bytes (assoc :privkey-bytes privkey-bytes)))]
     (reset! anchor-state-atom st)
     (clj->js (redact-for-js (anchor/anchor-dashboard-view st))))))

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
                      (anchor/queue-incoming-offer
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
        view (-> (anchor/anchor-dashboard-view @anchor-state-atom)
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
        prf-out (or (when (and (some? seed-or-opts) (object? seed-or-opts))
                      (or (unchecked-get seed-or-opts "prfOutput")
                          (unchecked-get seed-or-opts "prf_output")
                          (unchecked-get seed-or-opts "prf-output")
                          (when-let [cer (or (unchecked-get seed-or-opts "clientExtensionResults")
                                             (unchecked-get seed-or-opts "client_extension_results")
                                             (unchecked-get seed-or-opts "extensions")
                                             (when (fn? (.-getClientExtensionResults seed-or-opts))
                                               (.getClientExtensionResults seed-or-opts)))]
                            (when-let [prf (or (unchecked-get cer "prf") cer)]
                              (or (unchecked-get prf "first")
                                  (when-let [r (unchecked-get prf "results")]
                                    (unchecked-get r "first")))))
                          (when-let [prf (unchecked-get seed-or-opts "prf")]
                            (or (unchecked-get prf "first")
                                (when-let [r (unchecked-get prf "results")]
                                  (unchecked-get r "first"))))
                          (when-let [r (unchecked-get seed-or-opts "results")]
                            (unchecked-get r "first"))))
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
                              (:seed_bytes opts-map)))
                        (when (string? seed-or-opts) seed-or-opts)
                        (when (sequential? seed-or-opts) seed-or-opts))
        recovered (cond
                    (some? user-handle)
                    (webauthn/recover-seed-from-assertion
                     (if (map? opts-map)
                       (assoc opts-map :user-handle user-handle)
                       {:user-handle user-handle}))

                    (some? prf-out)
                    (webauthn/derive-identity-from-prf prf-out)

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
        na @active-node-atom
        live-offer? (and na (some? (get-in @na [:light-state :pending-offers id])))
        hw-locked? (and na (nil? (get-in @na [:keypair :private-key])))]
    (if (and live-offer? hw-locked?)
      (clj->js {:ok false
                :error "hardware-unlock-required"
                :dashboard (redact-for-js (anchor/anchor-dashboard-view (or @anchor-state-atom (anchor/init-anchor-state))))})
      (let [[new-state effects] (anchor/approve-offer (or @anchor-state-atom (anchor/init-anchor-state)) id opts-map)]
        (reset! anchor-state-atom new-state)
        (when live-offer?
          (accept-channel-offer na id))
        (clj->js {:ok true :effects effects :dashboard (redact-for-js (anchor/anchor-dashboard-view new-state))})))))

(defn deny-offer-cmd
  "Denies a pending offer in the Human Anchor queue with an explicit reason."
  [offer-id & [reason]]
  (let [id (str offer-id)
        rej-reason (or reason "denied-by-human-anchor")
        [new-state effects] (anchor/deny-offer (or @anchor-state-atom (anchor/init-anchor-state)) id rej-reason)]
    (reset! anchor-state-atom new-state)
    (when-let [na @active-node-atom]
      (swap! na update-in [:light-state :pending-offers] dissoc id))
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
         light-st (assoc init-light :petnames default-petnames :max-epoch-skew 15)
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
                                        channels))
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
                 :phase (name (or (:phase conn) :idle))
                 :generation (or (:generation conn) 0)
                 :visibilityState (or (:visibility-state conn) "visible")
                 :burnedEch (or (:burned-ech node) 0)
                 :meshConnected (boolean (seq open-channels))
                 :connectedNodes open-channels
                 :sessions (redact-for-js (or (:sessions light-st) {}))
                 :pendingOffers (redact-for-js (or (:pending-offers light-st) {}))
                 :broadcastInbox (redact-for-js (or (:broadcast-inbox light-st) []))
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
          prev-inbox (vec (get-in st [:inbox] []))
          prev-bcasts (vec (get-in st [:broadcast-inbox] []))
          res (light-core/handle-wire-payload st env privkey)
          new-st (:state res)
          curr-inbox (vec (get-in new-st [:inbox] []))
          curr-bcasts (vec (get-in new-st [:broadcast-inbox] []))
          new-msgs (into (subvec curr-inbox (min (count prev-inbox) (count curr-inbox)))
                         (subvec curr-bcasts (min (count prev-bcasts) (count curr-bcasts))))
          curr-offers (or (:pending-offers new-st) {})]
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
          privkey (:private-key (:keypair node))]
      (when (and pubkey privkey)
        (let [nonce (str "csq-" (fressian/bytes->hex (crypto/random-bytes 4)))
              q-env (light-core/build-chain-state-query-envelope pubkey privkey {:nonce nonce})]
          (try (.send dc (fressian/encode-wire q-env)) (catch :default _ nil)))))))

(defonce ^:private keepalive-timers-atom (atom {}))

(defn- on-validator-channel-open!
  "Handles validator DataChannel open: records channel, registers home set, queries chain state, and starts keepalive."
  [node-atom nid dc conn-atom]
  (swap! node-atom (fn [st]
                     (cond-> (assoc-in st [:active-channels nid] dc)
                       (= nid "node1") (assoc :conn @conn-atom))))
  ;; Register home set with devnet nodes when signing key is unlocked
  (when-let [privkey (:private-key (:keypair @node-atom))]
    (let [reg-res (light-core/handle-command (:light-state @node-atom)
                                             {"cmd" "register-home-set" "price" 10 "nodes" ["node1" "node2" "node3"]}
                                             privkey)]
      (swap! node-atom assoc :light-state (:state reg-res))
      (doseq [env (:net-envelopes reg-res)]
        (try (.send dc (fressian/encode-wire env)) (catch :default _ nil)))))
  ;; Query chain state from validator so 2-of-3 BFT quorum syncs epoch and account
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
                                       (notify-ui-listeners!))))
                                 5000)]
    (swap! keepalive-timers-atom assoc nid timer-id))
  (notify-ui-listeners!))

(defn connect-mesh
  "Connects live browser light-node to Bitecho devnet mesh via WebRTC DataChannels."
  ([] (connect-mesh nil))
  ([opts]
   (if-not (:ok? (light-core/verify-bootstrap-descriptor default-authority-pubkey default-bootstrap-descriptor 0))
     (clj->js {:ok false :error "untrusted-bootstrap-descriptor"})
     (let [node-atom (or @active-node-atom (init-node nil))
           _opts-map (when opts (if (map? opts) opts (js->clj opts :keywordize-keys true)))
           _ (doseq [[_nid tid] @keepalive-timers-atom]
               (try (js/clearInterval tid) (catch :default _ nil)))
           _ (reset! keepalive-timers-atom {})
           _ (doseq [[_nid old-dc] (:active-channels @node-atom)]
               (when old-dc
                 (try (.close old-dc) (catch :default _ nil))))
           _ (swap! node-atom assoc :active-channels {})
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
                 :connected false
                 :dialing true
                 :status "connecting"
                 :targetNode "node1"
                 :ip (:ip node1)
                 :port (:agent-port node1)})))))

(defn- resolve-peer-target
  "Resolves peer identifier or petname against :petnames, default-petnames,
   and anchor-state-atom :supervised-agents, returning hex public key string."
  [node peer-or-petname]
  (let [target (if (keyword? peer-or-petname) (name peer-or-petname) (str peer-or-petname))
        agents (when-let [st @anchor-state-atom] (:supervised-agents st))]
    (or (get (:petnames node) target)
        (get (:petnames node) (keyword target))
        (get default-petnames target)
        (get default-petnames (keyword target))
        (when (map? agents)
          (or (get-in agents [target :agent-pubkey])
              (get-in agents [(keyword target) :agent-pubkey])
              (get-in agents [target "agent-pubkey"])
              (get-in agents [target :pubkey])
              (get-in agents [target "pubkey"])))
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
           (send-to-all-channels! na env))
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
           (send-to-all-channels! na env))
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
             (clj->js {:ok false :accepted false :error "invalid-offer-signature"})
             (let [my-x25519 (:x25519 @na)
                   shared-secret (sealed/x25519-shared-secret (:private-key my-x25519) caller-x25519)
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
                         :suite "suite-v1-aes256gcm"})))))))))

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
                   [new-conn effects] (browser/transition-conn (:conn node)
                                                               {:type :send :envelope env})]
               (swap! na (fn [st]
                           (-> st
                               (assoc :conn new-conn)
                               (assoc-in [:sessions eff-peer :seq] seq-num)
                               (update :outbox conj env))))
               (clj->js {:ok (some? sealed-frame)
                         :sent (some? sealed-frame)
                         :seq seq-num
                         :effects effects})))))))))

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
               (send-to-all-channels! na env))
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
               (send-to-all-channels! na env))
             (browser/persist-state! (browser/sanitize-state-for-persistence @na))
             (notify-ui-listeners!)
             (clj->js (cond-> {:ok cmd-ok?
                               :sessionId (str session-id)
                               :envelopesSent (count out-envs)
                               :response resp}
                        (not cmd-ok?) (assoc :error (get resp "error")))))))))))

(defn broadcast-message
  "Broadcasts a zero-burn message across the 3-way mesh subnet (default 'chat/simon-nexus-axiom')."
  ([text] (broadcast-message @active-node-atom text light-core/simon-nexus-axiom-subnet-id))
  ([arg1 arg2]
   (if (or (satisfies? IAtom arg1)
           (and (some? arg1) (fn? (.-deref arg1))))
     (broadcast-message arg1 arg2 light-core/simon-nexus-axiom-subnet-id)
     (broadcast-message @active-node-atom arg1 arg2)))
  ([node-atom text subnet-id]
   (let [na (or node-atom @active-node-atom)]
     (if-not na
       (clj->js {:ok false :error "no-active-node"})
       (let [node @na
             privkey (:private-key (:keypair node))
             eff-subnet (or subnet-id light-core/simon-nexus-axiom-subnet-id)]
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
               (send-to-all-channels! na env))
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
       :p2pOffer p2p-offer
       :p2pAnswer p2p-answer
       :broadcastMessage broadcast-message
       :sendMessage send-message
       :closeSession close-session
       :getChatHistory get-chat-history
       :getSessions get-sessions
       :resolvePeer resolve-peer
       :onStateChange on-state-change
       :handleVisibilityChange handle-visibility-change!
       :saveStateToIndexedDB save-state-to-indexed-db
       :loadStateFromIndexedDB load-state-from-indexed-db
       :loadStateFromIndexedDb load-state-from-indexed-db
       :restoreFromIndexedDB restore-from-indexed-db!
       :restoreFromIndexedDb restore-from-indexed-db!
       :createOffer create-offer
       :acceptOffer accept-offer
       :sendSealedMessage send-sealed-message
       :runSubnetDemo run-subnet-demo
       :runZeroBurnSubnetDemo run-zero-burn-subnet-demo
       :runFederationDemo run-federation-demo
       :runThreeWayP2pBroadcastDemo run-three-way-p2p-broadcast-demo
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
       :version "1.0.0-m16"})

(when (exists? js/globalThis)
  (set! (.-BitechoBrowser js/globalThis) api))

;; Wire document visibilitychange listener
(when (and (exists? js/document) (some? (.-addEventListener js/document)))
  (.addEventListener js/document "visibilitychange"
                     (fn [_]
                       (when-let [na @active-node-atom]
                         (let [state (if (= (.-visibilityState js/document) "hidden") "hidden" "visible")]
                           (handle-visibility-change! na state))))))
