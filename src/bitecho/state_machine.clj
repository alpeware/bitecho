(ns bitecho.state-machine
  "The pure root reducer that integrates Basalt, Murmur, Sieve, and Contagion.
   Accepts `state` and `event` inputs and emits a map of `{:state new-state :commands [...]}`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.channels.core :as channels]
            [bitecho.contagion.core :as contagion]
            [bitecho.economy.difficulty :as difficulty]
            [bitecho.economy.ledger :as ledger]
            [bitecho.murmur.core :as murmur]
            [bitecho.routing.ingress :as ingress]
            [bitecho.routing.weighted :as weighted]
            [bitecho.services.turn :as turn]
            [bitecho.sieve.core :as sieve]
            [clojure.set :as set]))

(def murmur-k
  "Number of peers to forward gossip messages to."
  3)

(def murmur-max-cache-size
  "Maximum number of seen message IDs to keep in the cache."
  1000)

(def basalt-max-view-size
  "Maximum number of peers to keep in the Basalt view."
  50)

(def gossip-ttl-epochs
  "Maximum number of epochs to keep a gossip message in the cache."
  10)

(defn init-state
  "Initializes the pure Bitecho state map.
   node-pubkey should be the hex-encoded public key of this node."
  [initial-peers node-pubkey]
  {:node-pubkey node-pubkey
   :epoch 0
   :basalt-view (basalt/init-view initial-peers)
   :murmur-cache {:set #{} :queue clojure.lang.PersistentQueue/EMPTY}
   :sieve-history {}
   :contagion-known-ids #{}
   :messages {}
   :message-epochs {}
   :ledger (ledger/init-ledger)
   :channels {}})

(defn- handle-tick
  "Handles a periodic tick event to drive Basalt age updates, views, and Contagion anti-entropy."
  [state event]
  (let [new-epoch (inc (or (:epoch state) 0))
        view (:basalt-view state)
        new-view (basalt/increment-ages view)
        rng (:rng event)
        push-targets (basalt/select-peers rng new-view 1)
        push-command (when (seq push-targets)
                       {:type :send-push-view
                        :targets push-targets
                        :view new-view})
        summary (contagion/generate-summary rng new-view (:contagion-known-ids state))
        summary-command (when summary
                          {:type :send-summary
                           :target (:target summary)
                           :summary (:summary summary)})
        commands (filterv some? [push-command summary-command])
        ;; Prune gossip caches based on TTL
        cutoff-epoch (- new-epoch gossip-ttl-epochs)
        expired-ids (set (keep (fn [[msg-id epoch]]
                                 (when (< epoch cutoff-epoch) msg-id))
                               (or (:message-epochs state) {})))
        pruned-epochs (apply dissoc (or (:message-epochs state) {}) expired-ids)
        pruned-messages (apply dissoc (:messages state) expired-ids)
        pruned-known-ids (set/difference (:contagion-known-ids state) expired-ids)
        pruned-ledger (ledger/prune-claimed-tickets (:ledger state) new-epoch)]
    {:state (assoc state
                   :epoch new-epoch
                   :basalt-view new-view
                   :contagion-known-ids pruned-known-ids
                   :messages pruned-messages
                   :message-epochs pruned-epochs
                   :ledger pruned-ledger)
     :commands commands}))

(defn- handle-broadcast
  "Handles an internal request to broadcast a payload."
  [state event]
  (let [payload (:payload event)
        rng (:rng event)
        sieve-message (if (and (:private-key event) (:public-key event))
                        (sieve/wrap-message payload (:private-key event) (:public-key event))
                        {:payload payload :sender "local" :signature (byte-array 0)})
        ;; For debugging, make sure there are targets and commands are emitted.
        ;; When the test fails, print out the targets.
        broadcast-result (murmur/initiate-broadcast payload rng (:basalt-view state) murmur-k)
        message-id (:message-id broadcast-result)
        message (assoc sieve-message :message-id message-id)
        commands (if (seq (:targets broadcast-result))
                   [{:type :send-gossip
                     :targets (:targets broadcast-result)
                     :message message}]
                   [])
        _ (when (empty? (:targets broadcast-result)) (println "WARNING: broadcast had no targets! View size:" (count (:basalt-view state))))
        ;; We implicitly add our own broadcasts to the known ids and cache
        new-cache-set (conj (:set (:murmur-cache state)) message-id)
        new-cache-queue (conj (:queue (:murmur-cache state)) message-id)
        new-cache-queue-evicted (if (> (count new-cache-queue) murmur-max-cache-size)
                                  (pop new-cache-queue)
                                  new-cache-queue)
        new-cache-set-evicted (if (> (count new-cache-queue) murmur-max-cache-size)
                                (disj new-cache-set (peek new-cache-queue))
                                new-cache-set)
        new-cache {:set new-cache-set-evicted :queue new-cache-queue-evicted}
        new-known-ids (conj (:contagion-known-ids state) message-id)
        new-messages (assoc (:messages state) message-id message)
        new-epochs (assoc (or (:message-epochs state) {}) message-id (or (:epoch state) 0))]
    {:state (assoc state
                   :murmur-cache new-cache
                   :contagion-known-ids new-known-ids
                   :messages new-messages
                   :message-epochs new-epochs)
     :commands commands}))

(defn- handle-receive-push-view
  "Handles an incoming Basalt view exchange."
  [state event]
  (let [received-view (:view event)
        new-view (basalt/merge-views (:basalt-view state) received-view basalt-max-view-size)]
    {:state (assoc state :basalt-view new-view)
     :commands []}))

(defn- handle-receive-summary
  "Handles an incoming Contagion anti-entropy summary."
  [state event]
  (let [remote-summary (:summary event)
        missing-ids (contagion/lazy-pull (:contagion-known-ids state) remote-summary)
        commands (if (seq missing-ids)
                   [{:type :send-pull-request
                     :target (:sender event)
                     :missing-ids missing-ids}]
                   [])]
    {:state state
     :commands commands}))

(defn- handle-receive-pull-request
  "Handles an incoming Contagion lazy pull request.
   Looks up requested IDs in the local message store and returns
   individual :send-gossip commands targeting the requester for each found message."
  [state event]
  (let [missing-ids (:missing-ids event)
        requester (:sender event)
        messages-map (:messages state)
        found-messages (keep #(get messages-map %) missing-ids)
        commands (map (fn [msg]
                        {:type :send-gossip
                         :target requester
                         :message msg})
                      found-messages)]
    {:state state
     :commands (vec commands)}))

(defn- handle-receive-gossip
  "Handles an incoming Murmur gossip message.
   Validates the Sieve signature before accepting into the cache."
  [state event]
  (let [message (:message event)
        rng (:rng event)
        valid-signature? (sieve/validate-message message)]
    (if valid-signature?
      (let [gossip-result (murmur/receive-gossip (:murmur-cache state) message rng (:basalt-view state) murmur-k murmur-max-cache-size)
            commands (if (seq (:forward-targets gossip-result))
                       [{:type :send-gossip
                         :targets (:forward-targets gossip-result)
                         :message (:message gossip-result)}]
                       [])
            new-message? (some? (:message gossip-result))
            new-known-ids (if new-message?
                            (conj (:contagion-known-ids state) (:message-id message))
                            (:contagion-known-ids state))
            new-messages (if new-message?
                           (assoc (:messages state) (:message-id message) message)
                           (:messages state))
            new-epochs (if new-message?
                         (assoc (or (:message-epochs state) {}) (:message-id message) (or (:epoch state) 0))
                         (:message-epochs state))]
        {:state (assoc state
                       :murmur-cache (:cache gossip-result)
                       :contagion-known-ids new-known-ids
                       :messages new-messages
                       :message-epochs new-epochs)
         :commands commands})
      {:state state :commands []})))

(defn- calculate-network-scale
  "Estimates network scale by summing the Active Network Stake (Echo balances) of all peers
   currently observed in the basalt-view or contagion caches. Ensures new/stakeless networks
   default to a scale of 1."
  [state]
  (let [utxos (:utxos (:ledger state))
        ;; Extract known pubkeys from basalt-view
        view-pubkeys (map :pubkey (:basalt-view state))
        ;; Extract known pubkeys from contagion messages
        message-senders (map :sender (vals (:messages state)))
        ;; Distinct set of all known pubkeys in hex format
        all-hex-pubkeys (set (concat
                              (map #(if (string? %) % (basalt/bytes->hex %)) view-pubkeys)
                              message-senders))
        ;; Map each hex pubkey to its expected puzzle hash
        expected-hashes (set (map ledger/standard-puzzle-hash all-hex-pubkeys))
        ;; Sum the balances of UTXOs matching these puzzle hashes
        total-stake (reduce + (map :amount (filter #(contains? expected-hashes (:puzzle-hash %)) (vals utxos))))]
    (max 1 total-stake)))

(defn- handle-route-directed-message
  "Handles routing of a directed message. Validates the attached lottery ticket,
   claims the fee if it wins, and forwards the envelope via stake-weighted routing.
   If the node itself is the destination, it emits an :app-event instead.
   Applies stake-weighted ingress to drop unstaked messages 95% of the time."
  [state event]
  (let [envelope (:envelope event)
        destination (:destination envelope)
        claimer-pubkey (:node-pubkey state)
        ticket (:lottery-ticket envelope)
        sender-pubkey (:public-key ticket)
        utxos (:utxos (:ledger state))
        rng (:rng event)]
    (if (ingress/admit-message? rng sender-pubkey utxos)
      (if (= destination claimer-pubkey)
        {:state state
         :commands [{:type :app-event
                     :event-name :on-direct-message
                     :envelope envelope}]}
        (let [payout-amount (:payout-amount event)
              network-scale (calculate-network-scale state)
              difficulty-hex (difficulty/calculate-difficulty murmur-k network-scale)
              current-epoch (or (:epoch state) 0)
              new-ledger (ledger/claim-ticket (:ledger state) ticket difficulty-hex claimer-pubkey payout-amount current-epoch)
              next-hop (weighted/select-next-hop rng (:basalt-view state) (:balances new-ledger))
              commands (if next-hop
                         [{:type :send-directed-message
                           :target next-hop
                           :envelope envelope}]
                         [])]
          {:state (assoc state :ledger new-ledger)
           :commands commands}))
      ;; Message dropped via ingress filter
      {:state state :commands []})))

(defn- handle-open-channel
  "Handles a channel open event by storing the initial multisig state and emitting an :app-event."
  [state event]
  (let [channel-id (:channel-id event)
        initial-state (channels/create-initial-state channel-id
                                                     (:pubkey-a event)
                                                     (:pubkey-b event)
                                                     (:amount-a event)
                                                     (:amount-b event))]
    {:state (assoc-in state [:channels channel-id] initial-state)
     :commands [{:type :app-event
                 :event-name :on-channel-opened
                 :channel-id channel-id}]}))

(defn- handle-update-channel
  "Handles off-chain channel updates by validating mutual signatures."
  [state event]
  (let [channel-id (:channel-id event)
        current-state (get-in state [:channels channel-id])]
    (if current-state
      (let [new-state (channels/mutually-sign-update current-state (:update event) (:sig-a event) (:sig-b event))]
        {:state (assoc-in state [:channels channel-id] new-state)
         :commands []})
      {:state state :commands []})))

(defn- handle-settle-channel
  "Handles settling a channel by submitting the final state to the sci-ledger."
  [state event]
  (let [new-ledger (ledger/process-transaction (:ledger state) (:tx event))]
    (if (not= new-ledger (:ledger state))
      {:state (-> state
                  (assoc :ledger new-ledger)
                  (update :channels dissoc (:channel-id event)))
       :commands []}
      {:state state :commands []})))

(defn- handle-turn-allocate-request
  "Handles a request for TURN relay allocation, responding with granted status and pricing."
  [state event]
  (let [client-pubkey (:client-pubkey event)
        req {:type :turn-allocate-request :client-pubkey client-pubkey}
        ;; In a real deployment, server-pubkey and price would come from config/state.
        ;; For the state machine abstraction, we stub the response generation.
        res (turn/handle-allocation-request req "server-pubkey-stub" 1)]
    {:state state
     :commands [{:type :network-out
                 :target client-pubkey
                 :payload res}]}))

(defn- handle-turn-relay-request
  "Handles incoming TURN relay payload wrapped in a micro-payment channel update."
  [state event]
  (let [channel-id (:channel-id event)
        current-state (get-in state [:channels channel-id])]
    (if current-state
      (let [res (turn/handle-relay-request (:req event) current-state (:price event) (:server-priv event))]
        (if (:valid? res)
          {:state (assoc-in state [:channels channel-id] (:new-state res))
           :commands [{:type :network-out
                       ;; Target is the client or a proxy. For TURN relay, we'll
                       ;; assume the target is the client for now. Let's use pubkey-a.
                       :target (:pubkey-a current-state)
                       :payload (:command res)}]}
          {:state state :commands []}))
      {:state state :commands []})))

(defn handle-event
  "Pure root reducer. Takes the current state and an event,
   returns a map with :state (new state) and :commands (side-effects to perform)."
  [state event]
  (case (:type event)
    :tick (handle-tick state event)
    :broadcast (handle-broadcast state event)
    :receive-push-view (handle-receive-push-view state event)
    :receive-summary (handle-receive-summary state event)
    :receive-pull-request (handle-receive-pull-request state event)
    :receive-gossip (handle-receive-gossip state event)
    :route-directed-message (handle-route-directed-message state event)
    :open-channel (handle-open-channel state event)
    :update-channel (handle-update-channel state event)
    :settle-channel (handle-settle-channel state event)
    :turn-allocate-request (handle-turn-allocate-request state event)
    :turn-relay-request (handle-turn-relay-request state event)
    {:state state :commands []}))
