(ns bitecho.light-node.core
  "Pure Sans-IO protocol state reducer for the Bitecho light node.
   Handles command processing, sealed channel establishment, anti-replay,
   epoch skew tolerance, and Wire/JSONL conversions without side effects."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.agent-sim :as agent-sim]
            [bitecho.shell.mesh :as mesh]
            [clojure.data.json :as json]
            [clojure.string :as str]
            [taoensso.nippy :as nippy]))

;; -----------------------------------------------------------------------------
;; State Initialization
;; -----------------------------------------------------------------------------

(defn init-light-state
  "Initializes a pure light node state map from an identity public map and options.
   Private keys are never stored in the returned state map."
  [identity-pub-map opts]
  {:pubkey (or (:pubkey-hex identity-pub-map) (:pubkey identity-pub-map))
   :fingerprint (:fingerprint identity-pub-map)
   :ice-creds (:ice-creds identity-pub-map)
   :autonomous? (boolean (:autonomous? opts false))
   :epoch (long (:epoch opts 0))
   :bootstrap (:bootstrap opts)
   :home-set []
   :sessions {}
   :pending-offers {}
   :inbox []
   :local-accounting {:burned-ech 0}
   :vouchers []})

;; -----------------------------------------------------------------------------
;; Command Handlers (Pure Helpers)
;; -----------------------------------------------------------------------------

(defn- exec-identity [state]
  {:state state
   :response {"ok" true
              "pubkey" (:pubkey state)
              "fingerprint" (:fingerprint state)
              "ice_ufrag" (get-in state [:ice-creds :ufrag])
              "ice_pwd" (get-in state [:ice-creds :pwd])}
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
                  (:agent-tcp-port v) (assoc "agent_tcp_port" (:agent-tcp-port v))))]
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
        candidates (vec (keys (get-in state [:bootstrap :nodes])))
        candidate-maps (mapv (fn [cid] {:node-id cid :responsive? true :latency-ms 10 :price p-b}) candidates)
        hs (rendezvous/register-home-set candidate-maps p-b p-b-max)
        my-pub (:pubkey state)
        curr-epoch (:epoch state)
        env-curr (agent-sim/build-home-set-envelope my-pub privkey-bytes candidates p-b curr-epoch)
        env-nil (agent-sim/build-home-set-envelope my-pub privkey-bytes candidates p-b nil)]
    {:state (assoc state :home-set (:home-nodes hs))
     :response {"ok" true
                "status" (name (:status hs :ok))
                "price" (:price hs p-b)
                "home_nodes" (vec (for [n (:home-nodes hs)] (name (or (:node-id n) n))))}
     :net-envelopes [env-curr env-nil]
     :stdout-events []}))

(defn- exec-offer [state cmd-map privkey-bytes]
  (let [callee (get cmd-map "callee")
        price (long (or (get cmd-map "price") 0))
        default-home (or (first (keys (get-in state [:bootstrap :nodes]))) :node1)
        home-node (name (or (get cmd-map "home_node") default-home))
        burn-amt (long (or (get cmd-map "burn") 500))
        kp-eph (sealed/generate-x25519-keypair)
        caller (:pubkey state)
        eph-pub-hex (basalt/bytes->hex (:public kp-eph))
        sid-input (str caller "-" callee "-" eph-pub-hex)
        session-id (basalt/bytes->hex (crypto/sha256 (.getBytes sid-input "UTF-8")))
        epoch (:epoch state)
        hash-input (str session-id "-" caller "-" callee "-" eph-pub-hex "-" epoch "-" price "-" home-node)
        offer-hash (basalt/bytes->hex (crypto/sha256 (.getBytes hash-input "UTF-8")))
        sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes offer-hash "UTF-8")))
        offer-payload {:bitecho/type :channel-offer
                       :session-id session-id
                       :caller caller
                       :callee callee
                       :caller-ephemeral-pub eph-pub-hex
                       :epoch epoch
                       :price price
                       :home-node home-node
                       :offer-hash offer-hash
                       :burn burn-amt
                       :signature sig-hex}
        gossip-env (agent-sim/build-gossip-envelope caller privkey-bytes (nippy/freeze offer-payload) burn-amt)
        header-event {:type :receive-offer-header
                      :caller caller
                      :callee callee
                      :home-node home-node
                      :epoch epoch
                      :price price
                      :offer-hash offer-hash
                      :session-id session-id}
        header-env (mesh/wrap-agent-event header-event caller privkey-bytes)
        session-entry {:session-id session-id
                       :peer callee
                       :role :initiator
                       :state "offered"
                       :tx-seq 0
                       :epoch epoch
                       :ephemeral-pub (:public kp-eph)
                       :ephemeral-priv (:private kp-eph)
                       :price price
                       :home-node home-node
                       :offer-hash offer-hash}
        new-state (-> state
                      (assoc-in [:sessions session-id] session-entry)
                      (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))]
    {:state new-state
     :response {"ok" true
                "session_id" session-id
                "state" "offered"
                "callee" callee
                "price" price
                "burn" burn-amt}
     :net-envelopes [header-env gossip-env]
     :stdout-events []}))

(defn- exec-accept [state cmd-map privkey-bytes]
  (let [session-id (get cmd-map "session_id")
        offer (get-in state [:pending-offers session-id])]
    (if-not offer
      {:state state :response {"ok" false "error" "offer-not-found"} :net-envelopes [] :stdout-events []}
      (let [caller (:caller offer)
            kp-resp (sealed/generate-x25519-keypair)
            caller-eph (basalt/hex->bytes (:caller-ephemeral-pub offer))
            shared-sec (sealed/x25519-shared-secret (:private kp-resp) caller-eph)
            keys (sealed/derive-channel-keys shared-sec session-id :responder)
            eph-pub-hex (basalt/bytes->hex (:public kp-resp))
            epoch (:epoch state)
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
                      :min-burn 100})
            delivery-ack (into {} (:delivery-ack ack-res))
            sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes (str session-id "-" eph-pub-hex) "UTF-8")))
            accept-payload {:bitecho/type :channel-accept
                            :session-id session-id
                            :caller caller
                            :callee (:pubkey state)
                            :callee-ephemeral-pub eph-pub-hex
                            :epoch epoch
                            :delivery-ack delivery-ack
                            :signature sig-hex}
            gossip-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze accept-payload) 500)
            session-entry {:session-id session-id
                           :peer caller
                           :role :responder
                           :state "open"
                           :tx-seq 0
                           :epoch epoch
                           :tx-key (:tx-key keys)
                           :rx-key (:rx-key keys)
                           :replay-window (sealed/init-replay-window)}
            new-state (-> state
                          (update :pending-offers dissoc session-id)
                          (assoc-in [:sessions session-id] session-entry))
            event {"event" "channel-opened" "session_id" session-id "peer" caller}]
        {:state new-state
         :response {"ok" true "session_id" session-id "state" "open" "peer" caller}
         :net-envelopes [gossip-env]
         :stdout-events [event]}))))

(defn- exec-send [state cmd-map privkey-bytes]
  (let [session-id (get cmd-map "session_id")
        session (get-in state [:sessions session-id])]
    (if-not (and session (= "open" (:state session)))
      {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}
      (let [text (get cmd-map "text")
            payload-hex (get cmd-map "payload_hex")
            payload-bytes (cond (some? text) (.getBytes ^String text "UTF-8")
                                (some? payload-hex) (basalt/hex->bytes payload-hex)
                                :else (byte-array 0))
            burn-amt (long (or (get cmd-map "burn") 500))
            seq-num (inc (:tx-seq session 0))
            sealed (sealed/seal-message (:tx-key session) seq-num payload-bytes (.getBytes session-id "UTF-8"))
            msg-payload {:bitecho/type :sealed-message
                         :session-id session-id
                         :sender (:pubkey state)
                         :recipient (:peer session)
                         :epoch (:epoch state)
                         :seq seq-num
                         :nonce (basalt/bytes->hex (:nonce sealed))
                         :ciphertext (basalt/bytes->hex (:ciphertext sealed))}
            gossip-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze msg-payload) burn-amt)
            new-state (-> state
                          (assoc-in [:sessions session-id :tx-seq] seq-num)
                          (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))]
        {:state new-state
         :response {"ok" true
                    "session_id" session-id
                    "seq" seq-num
                    "bytes_sent" (alength payload-bytes)
                    "burn" burn-amt}
         :net-envelopes [gossip-env]
         :stdout-events []}))))

(defn- exec-inbox [state]
  {:state (assoc state :inbox [])
   :response {"ok" true
              "messages" (:inbox state)
              "pending_offers" (vec (vals (:pending-offers state)))}
   :net-envelopes []
   :stdout-events []})

(defn- exec-close [state cmd-map privkey-bytes]
  (let [session-id (get cmd-map "session_id")
        session (get-in state [:sessions session-id])]
    (if-not session
      {:state state :response {"ok" false "error" "session-not-found"} :net-envelopes [] :stdout-events []}
      (let [sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes (str "close-" session-id) "UTF-8")))
            close-payload {:bitecho/type :channel-close
                           :session-id session-id
                           :sender (:pubkey state)
                           :recipient (:peer session)
                           :epoch (:epoch state)
                           :signature sig-hex}
            gossip-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze close-payload) 500)
            closed-sess (-> session
                            (assoc :state "closed")
                            (dissoc :tx-key :rx-key :ephemeral-priv))
            new-state (assoc-in state [:sessions session-id] closed-sess)]
        {:state new-state
         :response {"ok" true "session_id" session-id "state" "closed"}
         :net-envelopes [gossip-env]
         :stdout-events []}))))

(defn- exec-transfer [state cmd-map privkey-bytes]
  (let [receiver (get cmd-map "receiver")
        amount (long (or (get cmd-map "amount") 0))
        seq-num (long (or (get cmd-map "seq") 1))
        burn-amt (long (or (get cmd-map "burn") 500))
        res (agent-sim/build-transfer-gossip-envelope
             (:pubkey state)
             privkey-bytes
             {:receiver receiver :amount amount :seq seq-num :deps []}
             burn-amt)
        new-state (update-in state [:local-accounting :burned-ech] (fnil + 0) burn-amt)]
    {:state new-state
     :response {"ok" true
                "transfer_hash" (:transfer-hash res)
                "receiver" receiver
                "amount" amount}
     :net-envelopes [(:envelope res)]
     :stdout-events []}))

(defn- exec-status [state]
  (let [sessions-summary (vec (for [[_ s] (:sessions state)]
                                (select-keys s [:session-id :peer :role :state :tx-seq :epoch])))]
    {:state state
     :response {"ok" true
                "pubkey" (:pubkey state)
                "autonomous" (:autonomous? state)
                "epoch" (:epoch state)
                "sessions" sessions-summary
                "pending_offers_count" (count (:pending-offers state))
                "inbox_count" (count (:inbox state))
                "accounting" {"scope" "local-non-consensus"
                              "note" "Locally computed devnet totals; never consensus finalized"
                              "burned_ech" (get-in state [:local-accounting :burned-ech] 0)
                              "vouchers_count" (count (:vouchers state []))}}
     :net-envelopes []
     :stdout-events []}))

(defn handle-command
  "Dispatches a parsed JSON command map to its corresponding protocol verb reducer.
   Supports both flat command maps and nested {\"cmd\": ..., \"args\": {...}} maps."
  [state cmd-map privkey-bytes]
  (let [effective-map (if (map? (get cmd-map "args"))
                        (merge (get cmd-map "args") (dissoc cmd-map "args"))
                        cmd-map)]
    (case (get effective-map "cmd")
      "identity" (exec-identity state)
      "discover" (exec-discover state)
      "register-home-set" (exec-register-home-set state effective-map privkey-bytes)
      "offer" (exec-offer state effective-map privkey-bytes)
      "accept" (exec-accept state effective-map privkey-bytes)
      "send" (exec-send state effective-map privkey-bytes)
      "inbox" (exec-inbox state)
      "close" (exec-close state effective-map privkey-bytes)
      "transfer" (exec-transfer state effective-map privkey-bytes)
      "status" (exec-status state)
      {:state state :response {"ok" false "error" "unknown-command"} :net-envelopes [] :stdout-events []})))

;; -----------------------------------------------------------------------------
;; Inbound Wire Payload Handlers (Pure Helpers)
;; -----------------------------------------------------------------------------

(defn- unwrap-wire-message [raw-payload-or-event]
  (cond
    (bytes? raw-payload-or-event)
    (if-let [thawed (try (nippy/thaw raw-payload-or-event) (catch Exception _ nil))]
      (recur thawed)
      nil)

    (and (map? raw-payload-or-event) (contains? raw-payload-or-event :bitecho/type))
    raw-payload-or-event

    (and (map? raw-payload-or-event) (map? (:event raw-payload-or-event)))
    (recur (:event raw-payload-or-event))

    (and (map? raw-payload-or-event) (map? (:message raw-payload-or-event)))
    (let [p (:payload (:message raw-payload-or-event))]
      (if (bytes? p)
        (recur (try (nippy/thaw p) (catch Exception _ nil)))
        (if (map? p) (recur p) nil)))

    :else nil))

(defn- handle-wire-offer [state msg privkey-bytes]
  (if-not (= (:callee msg) (:pubkey state))
    {:state state :net-envelopes [] :stdout-events []}
    (let [caller-pub (try (basalt/hex->bytes (:caller msg)) (catch Exception _ nil))
          sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
          valid-sig? (and caller-pub sig-bytes
                          (crypto/verify caller-pub (.getBytes ^String (:offer-hash msg) "UTF-8") sig-bytes))]
      (if-not valid-sig?
        {:state state :net-envelopes [] :stdout-events []}
        (if (:autonomous? state)
          (let [accept-res (exec-accept (assoc-in state [:pending-offers (:session-id msg)] msg)
                                        {"session_id" (:session-id msg)}
                                        privkey-bytes)]
            {:state (:state accept-res)
             :net-envelopes (:net-envelopes accept-res)
             :stdout-events (:stdout-events accept-res)})
          (let [event {"event" "offer-received"
                       "session_id" (:session-id msg)
                       "caller" (:caller msg)
                       "price" (:price msg)}]
            {:state (assoc-in state [:pending-offers (:session-id msg)] msg)
             :net-envelopes []
             :stdout-events [event]}))))))

(defn- handle-wire-accept [state msg]
  (if-not (= (:caller msg) (:pubkey state))
    {:state state :net-envelopes [] :stdout-events []}
    (let [session-id (:session-id msg)
          session (get-in state [:sessions session-id])]
      (if-not (and session (= "offered" (:state session)))
        {:state state :net-envelopes [] :stdout-events []}
        (let [callee-pub (try (basalt/hex->bytes (:callee msg)) (catch Exception _ nil))
              sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
              valid-ack? (rendezvous/verify-delivery-ack (:delivery-ack msg) (:callee msg))
              valid-sig? (and callee-pub sig-bytes
                              (crypto/verify callee-pub
                                             (.getBytes (str session-id "-" (:callee-ephemeral-pub msg)) "UTF-8")
                                             sig-bytes))]
          (if-not (and valid-ack? valid-sig?)
            {:state state :net-envelopes [] :stdout-events []}
            (let [callee-eph (basalt/hex->bytes (:callee-ephemeral-pub msg))
                  shared-sec (sealed/x25519-shared-secret (:ephemeral-priv session) callee-eph)
                  keys (sealed/derive-channel-keys shared-sec session-id :initiator)
                  updated-sess (-> session
                                   (assoc :state "open"
                                          :tx-key (:tx-key keys)
                                          :rx-key (:rx-key keys)
                                          :replay-window (sealed/init-replay-window))
                                   (dissoc :ephemeral-priv))
                  new-state (-> state
                                (assoc-in [:sessions session-id] updated-sess)
                                (update :vouchers (fnil conj []) (:delivery-ack msg)))
                  event {"event" "channel-opened" "session_id" session-id "peer" (:callee msg)}]
              {:state new-state
               :net-envelopes []
               :stdout-events [event]})))))))

(defn- handle-wire-sealed-msg [state msg]
  (if-not (= (:recipient msg) (:pubkey state))
    {:state state :net-envelopes [] :stdout-events []}
    (let [session-id (:session-id msg)
          session (get-in state [:sessions session-id])]
      (if-not (and session (= "open" (:state session)))
        {:state state :net-envelopes [] :stdout-events []}
        (let [chk (sealed/check-and-advance-replay-window (:replay-window session) (:seq msg))]
          (if-not (:accepted? chk)
            {:state state :net-envelopes [] :stdout-events []}
            (let [ct (try (basalt/hex->bytes (:ciphertext msg)) (catch Exception _ nil))
                  decrypted (when ct (sealed/open-message (:rx-key session) (:seq msg) ct (.getBytes session-id "UTF-8")))]
              (if-not decrypted
                {:state state :net-envelopes [] :stdout-events []}
                (let [text (try (String. ^bytes decrypted "UTF-8") (catch Exception _ nil))
                      inbox-item {:session-id session-id
                                  :from (:sender msg)
                                  :seq (:seq msg)
                                  :text text
                                  :payload-hex (basalt/bytes->hex decrypted)}
                      updated-sess (assoc session :replay-window (:window chk))
                      new-state (-> state
                                    (assoc-in [:sessions session-id] updated-sess)
                                    (update :inbox (fnil conj []) inbox-item))
                      event (cond-> {"event" "message-received"
                                     "session_id" session-id
                                     "from" (:sender msg)
                                     "seq" (:seq msg)}
                              text (assoc "text" text))]
                  {:state new-state
                   :net-envelopes []
                   :stdout-events [event]})))))))))

(defn- handle-wire-close [state msg]
  (let [session-id (:session-id msg)
        session (get-in state [:sessions session-id])]
    (if-not (and session (not= "closed" (:state session)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [sender-pub (try (basalt/hex->bytes (:sender msg)) (catch Exception _ nil))
            sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
            valid-sig? (and sender-pub sig-bytes
                            (crypto/verify sender-pub (.getBytes (str "close-" session-id) "UTF-8") sig-bytes))]
        (if-not valid-sig?
          {:state state :net-envelopes [] :stdout-events []}
          (let [closed-sess (-> session
                                (assoc :state "closed")
                                (dissoc :tx-key :rx-key :ephemeral-priv))
                new-state (assoc-in state [:sessions session-id] closed-sess)
                event {"event" "channel-closed" "session_id" session-id "peer" (:sender msg)}]
            {:state new-state
             :net-envelopes []
             :stdout-events [event]}))))))

(defn handle-wire-payload
  "Processes an incoming network event or raw payload. Enforces 2-epoch skew tolerance
   and anti-replay protections before dispatching to message-specific reducers."
  [state raw-payload-or-event privkey-bytes]
  (let [msg (unwrap-wire-message raw-payload-or-event)]
    (if-not (map? msg)
      {:state state :net-envelopes [] :stdout-events []}
      (let [msg-epoch (:epoch msg)
            st-epoch (:epoch state)
            skew-exceeded? (and (integer? msg-epoch) (integer? st-epoch)
                                (pos? msg-epoch) (pos? st-epoch)
                                (> (Math/abs (long (- msg-epoch st-epoch))) 2))]
        (if skew-exceeded?
          {:state state :net-envelopes [] :stdout-events []}
          (case (:bitecho/type msg)
            :channel-offer (handle-wire-offer state msg privkey-bytes)
            :channel-accept (handle-wire-accept state msg)
            :sealed-message (handle-wire-sealed-msg state msg)
            :channel-close (handle-wire-close state msg)
            {:state state :net-envelopes [] :stdout-events []}))))))

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
        (let [cmd-map (json/read-str trimmed)]
          (if (and (map? cmd-map) (contains? cmd-map "cmd"))
            (handle-command state cmd-map privkey-bytes)
            {:state state :response {"ok" false "error" "malformed-request"} :net-envelopes [] :stdout-events []}))
        (catch Exception _
          {:state state :response {"ok" false "error" "malformed-request"} :net-envelopes [] :stdout-events []})))))
