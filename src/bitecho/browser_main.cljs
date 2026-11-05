(ns bitecho.browser-main
  "Bitecho Browser Node static bundle entry point.
   Exposes high-level browser API on js/globalThis.BitechoBrowser conforming to Rules 1-6."
  (:require [bitecho.anchor.core :as anchor]
            [bitecho.bech32m :as bech32m]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.shell.browser :as browser]
            [bitecho.webauthn :as webauthn]))

(defonce
  ^{:doc "Global atom holding active Human Anchor state for browser UI."}
  anchor-state-atom
  (atom nil))

(defn init-anchor
  "Initializes or resets the global Human Anchor state atom."
  ([] (init-anchor nil))
  ([opts]
   (let [st (anchor/init-anchor-state (or (when opts (js->clj opts :keywordize-keys true)) {}))]
     (reset! anchor-state-atom st)
     (clj->js (anchor/anchor-dashboard-view st)))))

(defn get-anchor-dashboard
  "Returns the Human Anchor dashboard view as a JavaScript object."
  []
  (when-not @anchor-state-atom
    (init-anchor nil))
  (clj->js (anchor/anchor-dashboard-view @anchor-state-atom)))

(defn register-yubikey
  "Configures YubiKey discoverable credential options and updates anchor key-mode."
  ([] (register-yubikey nil))
  ([opts]
   (let [opts-map (if (map? opts) opts (when opts (js->clj opts :keywordize-keys true)))
         reg-opts (webauthn/build-registration-options opts-map)]
     (when @anchor-state-atom
       (swap! anchor-state-atom assoc :key-mode :yubikey-discoverable))
     (clj->js reg-opts))))

(defn recover-from-yubikey
  "Simulates or executes WebAuthn userHandle seed recovery, updating anchor identity."
  [seed-or-opts]
  (let [opts-map (if (map? seed-or-opts) seed-or-opts (when seed-or-opts (js->clj seed-or-opts :keywordize-keys true)))
        user-handle (or (:user-handle opts-map) (:seed-bytes opts-map) seed-or-opts (crypto/random-bytes 32))
        recovered (webauthn/recover-seed-from-assertion {:user-handle user-handle})]
    (when (and @anchor-state-atom recovered)
      (swap! anchor-state-atom (fn [st]
                                 (-> st
                                     (assoc :anchor-pubkey (:public-hex recovered))
                                     (assoc :anchor-address (:address recovered))
                                     (assoc :privkey-bytes (:private-key recovered))
                                     (assoc :hot-pubkey (:public-hex recovered))))))
    (clj->js recovered)))

(defn generate-non-extractable-key
  "Generates and returns non-extractable WebCrypto key spec and metadata."
  ([] (generate-non-extractable-key nil))
  ([opts]
   (let [opts-map (if (map? opts) opts (when opts (js->clj opts :keywordize-keys true)))
         spec (webauthn/generate-non-extractable-keypair-spec opts-map)]
     (when @anchor-state-atom
       (swap! anchor-state-atom assoc :key-mode :webcrypto-non-extractable))
     (clj->js spec))))

(defn approve-offer-cmd
  "Approves a pending offer in the Human Anchor queue."
  [offer-id & [opts]]
  (let [id (str offer-id)
        opts-map (when opts (js->clj opts :keywordize-keys true))
        [new-state effects] (anchor/approve-offer (or @anchor-state-atom (anchor/init-anchor-state)) id opts-map)]
    (reset! anchor-state-atom new-state)
    (clj->js {:ok true :effects effects :dashboard (anchor/anchor-dashboard-view new-state)})))

(defn deny-offer-cmd
  "Denies a pending offer in the Human Anchor queue with an explicit reason."
  [offer-id & [reason]]
  (let [id (str offer-id)
        rej-reason (or reason "denied-by-human-anchor")
        [new-state effects] (anchor/deny-offer (or @anchor-state-atom (anchor/init-anchor-state)) id rej-reason)]
    (reset! anchor-state-atom new-state)
    (clj->js {:ok true :effects effects :dashboard (anchor/anchor-dashboard-view new-state)})))

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
    (clj->js {:ok true :agentId aid :dashboard (anchor/anchor-dashboard-view new-state)})))

(defn revoke-agent-dac-cmd
  "Emergency revocation of a supervised agent's DAC."
  [agent-id & [reason]]
  (let [aid (str agent-id)
        rej-reason (or reason "emergency-human-anchor-revocation")
        [new-state effects] (anchor/revoke-agent-dac (or @anchor-state-atom (anchor/init-anchor-state)) aid rej-reason)]
    (reset! anchor-state-atom new-state)
    (clj->js {:ok true :effects effects :dashboard (anchor/anchor-dashboard-view new-state)})))

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
        dashboard (anchor/anchor-dashboard-view st7)]
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
  "Initializes a new browser light-node state atom."
  ([] (init-node nil))
  ([opts]
   (let [node-id (or (when (map? opts) (or (:peer-id opts) (get opts "peerId")))
                     (str "browser-" (fressian/bytes->hex (crypto/random-bytes 4))))
         subnet-id (or (when (map? opts) (or (:subnet-id opts) (get opts "subnetId")))
                       "global")
         keypair (crypto/generate-keypair)
         x25519 (sealed/generate-x25519-keypair)
         conn-state (browser/initial-conn-state {:peer-id node-id :subnet-id subnet-id})]
     (atom {:peer-id node-id
            :subnet-id subnet-id
            :keypair keypair
            :x25519 x25519
            :conn conn-state
            :sessions {}
            :inbox []
            :outbox []
            :burned-ech 0
            :autonomous? false}))))

(defn get-status
  "Returns Rule 4 status and diagnostics map as a JavaScript object."
  [node-atom]
  (let [node @node-atom
        conn (:conn node)
        diag (:diagnostics conn)]
    (clj->js {:peerId (:peer-id node)
              :subnetId (:subnet-id node)
              :phase (name (:phase conn))
              :generation (:generation conn)
              :visibilityState (:visibility-state conn)
              :burnedEch (:burned-ech node)
              :autonomous (:autonomous? node)
              :diagnostics {:phase (name (:phase diag))
                            :generation (:generation diag)
                            :lastError (:last-error diag)
                            :dropped (:dropped diag)
                            :ignoredStale (:ignored-stale diag)
                            :unsupportedFormatDropped (:unsupported-format-dropped diag)
                            :backgroundThrottledEvents (:background-throttled-events diag)}})))

(defn connect
  "Initiates dialing transition on the node's connection state."
  [node-atom opts]
  (let [target-url (or (when (map? opts) (or (:target-url opts) (get opts "targetUrl")))
                       "rtc://default")
        [new-conn effects] (browser/transition-conn (:conn @node-atom)
                                                    {:type :dial :target-url target-url})]
    (swap! node-atom assoc :conn new-conn)
    (clj->js {:conn (get-status node-atom)
              :effects effects})))

(defn create-offer
  "Creates a rendezvous/channel offer descriptor."
  [node-atom peer-id & [_opts]]
  (let [node @node-atom
        x25519 (:x25519 node)
        keypair (:keypair node)
        offer {:type :rendezvous-offer
               :caller-pubkey (fressian/bytes->hex (:public-key keypair))
               :callee-pubkey peer-id
               :caller-x25519 (fressian/bytes->hex (:public-key x25519))
               :crypto-suites ["suite-v1-aes256gcm"]
               :wire-format "fressian-v1"
               :burn-amount 50}]
    (swap! node-atom update :burned-ech + 50)
    (clj->js offer)))

(defn accept-offer
  "Explicitly accepts an offer (since :autonomous? is false)."
  [node-atom offer]
  (let [offer-map (if (map? offer) offer (js->clj offer :keywordize-keys true))
        caller-pub (:caller-pubkey offer-map)
        caller-x25519 (fressian/hex->bytes (:caller-x25519 offer-map))
        my-x25519 (:x25519 @node-atom)
        shared-secret (sealed/x25519-shared-secret (:private-key my-x25519) caller-x25519)
        session-keys (sealed/derive-channel-keys shared-secret "bitecho-browser-session-salt" :responder)]
    (swap! node-atom (fn [st]
                       (-> st
                           (assoc-in [:sessions caller-pub] {:session-keys session-keys
                                                             :suite "suite-v1-aes256gcm"
                                                             :seq 0})
                           (update :burned-ech + 50))))
    (clj->js {:accepted true
              :peerId caller-pub
              :suite "suite-v1-aes256gcm"})))

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

(def api
  "Global BitechoBrowser API object."
  #js {:initNode init-node
       :getStatus get-status
       :connect connect
       :createOffer create-offer
       :acceptOffer accept-offer
       :sendSealedMessage send-sealed-message
       :runSubnetDemo run-subnet-demo
       :initAnchor init-anchor
       :getAnchorDashboard get-anchor-dashboard
       :registerYubiKey register-yubikey
       :recoverFromYubiKey recover-from-yubikey
       :generateNonExtractableKey generate-non-extractable-key
       :approveOffer approve-offer-cmd
       :denyOffer deny-offer-cmd
       :superviseAgent supervise-agent-cmd
       :revokeAgentDac revoke-agent-dac-cmd
       :encodeBech32m encode-bech32m-cmd
       :decodeBech32m decode-bech32m-cmd
       :runAnchorEndToEndDemo run-anchor-end-to-end-demo
       :version "1.0.0-m11"})

(when (exists? js/globalThis)
  (set! (.-BitechoBrowser js/globalThis) api))
