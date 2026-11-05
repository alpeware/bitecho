(ns bitecho.browser-main
  "Bitecho Browser Node static bundle entry point.
   Exposes high-level browser API on js/globalThis.BitechoBrowser conforming to Rules 1-6."
  (:require [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.shell.browser :as browser]))

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
       :version "1.0.0-m10"})

(when (exists? js/globalThis)
  (set! (.-BitechoBrowser js/globalThis) api))
