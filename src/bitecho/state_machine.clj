(ns bitecho.state-machine
  "The pure root reducer that integrates Basalt, Murmur, Sieve, and Contagion.
   Accepts `state` and `event` inputs and emits a map of `{:state new-state :commands [...]}`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.channels.core :as channels]
            [bitecho.contagion.core :as contagion]
            [bitecho.economy.difficulty :as difficulty]
            [bitecho.economy.ledger :as ledger]
            [bitecho.murmur.core :as murmur]
            [bitecho.peer-review.core :as peer-review]
            [bitecho.routing.ingress :as ingress]
            [bitecho.routing.weighted :as weighted]
            [bitecho.services.turn :as turn]
            [bitecho.sieve.core :as sieve]
            [clojure.set :as set]))

(def murmur-k
  "Number of peers to forward gossip messages to."
  5)

(def murmur-max-cache-size
  "Maximum number of seen message IDs to keep in the cache."
  1000)

(def basalt-max-view-size
  "Maximum number of peers to keep in the Basalt view."
  20)

(def gossip-ttl-epochs
  "Maximum number of epochs to keep a gossip message in the cache."
  10)

(def pending-circuit-ttl
  "Maximum number of local epochs to track a pending circuit before garbage collecting."
  50)

(defn init-state
  "Initializes the pure Bitecho state map.
   node-pubkey should be the hex-encoded public key of this node."
  [initial-peers node-pubkey]
  {:node-pubkey node-pubkey
   :epoch 0
   :basalt-index 0
   :basalt-view (basalt/init-view initial-peers basalt-max-view-size (java.util.Random.))
   :murmur-cache {:set #{} :queue clojure.lang.PersistentQueue/EMPTY}
   :sieve-history {}
   :contagion-known-ids #{}
   :messages {}
   :message-epochs {}
   :ledger (ledger/init-ledger)
   :channels {}
   :pending-circuits {}})

(defn- handle-tick
  "Handles a periodic tick event to drive Basalt reseeding and Contagion anti-entropy."
  [state event]
  (let [new-epoch (inc (or (:epoch state) 0))
        view (:basalt-view state)
        rng (:rng event)
        reset-result (basalt/reset-slots view rng (:basalt-index state) 1)
        new-view (:view reset-result)
        new-index (:next-r reset-result)
        extracted-peers (basalt/extract-peers new-view)
        push-targets (basalt/select-peers rng new-view 1)
        push-command (when (seq push-targets)
                       {:type :send-push-view
                        :targets push-targets
                        :view extracted-peers})
        summary (contagion/generate-summary rng extracted-peers (:contagion-known-ids state))
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
        pruned-murmur-cache-set (set/difference (:set (:murmur-cache state)) expired-ids)
        pruned-murmur-cache-queue (into clojure.lang.PersistentQueue/EMPTY (remove expired-ids (:queue (:murmur-cache state))))
        pruned-murmur-cache {:set pruned-murmur-cache-set :queue pruned-murmur-cache-queue}
        ;; Prune pending circuits
        circuit-cutoff-epoch (- new-epoch pending-circuit-ttl)
        pruned-pending-circuits (into {} (remove (fn [[_ pending]] (< (:epoch pending) circuit-cutoff-epoch)) (or (:pending-circuits state) {})))]
    {:state (assoc state
                   :epoch new-epoch
                   :basalt-view new-view
                   :basalt-index new-index
                   :murmur-cache pruned-murmur-cache
                   :contagion-known-ids pruned-known-ids
                   :messages pruned-messages
                   :message-epochs pruned-epochs
                   :pending-circuits pruned-pending-circuits)
     :commands commands}))

(defn- handle-broadcast
  "Handles an internal request to broadcast a payload."
  [state event]
  (let [payload (:payload event)
        rng (:rng event)
        extracted-peers (basalt/extract-peers (:basalt-view state))
        sieve-message (if (and (:private-key event) (:public-key event))
                        (sieve/wrap-message payload (:private-key event) (:public-key event))
                        {:payload payload :sender "local" :signature (byte-array 0)})
        ;; For debugging, make sure there are targets and commands are emitted.
        ;; When the test fails, print out the targets.
        broadcast-result (murmur/initiate-broadcast payload rng extracted-peers murmur-k)
        message-id (:message-id broadcast-result)
        message (assoc sieve-message :message-id message-id)
        commands (if (seq (:targets broadcast-result))
                   [{:type :send-gossip
                     :targets (:targets broadcast-result)
                     :message message}]
                   [])
        _ (when (empty? (:targets broadcast-result)) (println "WARNING: broadcast had no targets! View size:" (count extracted-peers)))
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

(defn- handle-contagion-broadcast
  "Handles an internal request to broadcast a payload, specifically emitting :on-deliver for simulator E2E."
  [state event]
  (let [{new-state :state commands :commands} (handle-broadcast state (assoc event :type :broadcast))]
    {:state new-state
     :commands (conj commands {:type :app-event :event-name :on-deliver :payload (:payload event)})}))

(defn- handle-receive-push-view
  "Handles an incoming Basalt view exchange."
  [state event]
  (let [received-peers (:view event)
        new-view (basalt/update-view (:basalt-view state) received-peers)]
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
      (let [extracted-peers (basalt/extract-peers (:basalt-view state))
            gossip-result (murmur/receive-gossip (:murmur-cache state) message rng extracted-peers murmur-k murmur-max-cache-size)
            commands (if (seq (:forward-targets gossip-result))
                       [{:type :send-gossip
                         :targets (:forward-targets gossip-result)
                         :message (:message gossip-result)}]
                       [])
            new-message? (some? (:message gossip-result))
            commands (if new-message?
                       (conj commands {:type :app-event :event-name :on-deliver :payload (:payload message)})
                       commands)
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
        view-pubkeys (map :pubkey (basalt/extract-peers (:basalt-view state)))
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
  "Handles the forward pass of a directed message along a locked circuit.
   Validates the attached lottery ticket and proof of relay.
   Requires strict source routing via :forward-circuit.
   If this node is the destination, emits :on-direct-message and
   turns the message around to return via :route-directed-ack."
  [state event]
  (let [envelope (:envelope event)
        claimer-pubkey (:node-pubkey state)
        ticket (:lottery-ticket envelope)
        proof-of-relay (:proof-of-relay envelope)
        sender-pubkey (:public-key ticket)
        utxos (:utxos (:ledger state))
        rng (:rng event)
        forward-circuit (or (:forward-circuit envelope) [])
        return-circuit (or (:return-circuit envelope) [])]
    (if (and (ingress/admit-message? rng sender-pubkey utxos)
             (peer-review/validate-proof-of-relay ticket proof-of-relay)
             (= claimer-pubkey (first forward-circuit)))
      (let [new-forward (rest forward-circuit)
            new-return (cons claimer-pubkey return-circuit)]
        (if (empty? new-forward)
          ;; We are the destination (Node B). Turnaround.
          {:state state
           :commands [{:type :app-event
                       :event-name :on-direct-message
                       :envelope envelope}
                      {:type :sign-and-forward
                       :target (first return-circuit)
                       :out-type :send-directed-ack
                       :payout-amount (:payout-amount event)
                       :envelope (assoc envelope
                                        :forward-circuit return-circuit
                                        :return-circuit (list claimer-pubkey))}]}
          ;; We are a forward router. Pop and push, then forward.
          {:state state
           :commands [{:type :sign-and-forward
                       :target (first new-forward)
                       :out-type :send-directed-message
                       :payout-amount (:payout-amount event)
                       :envelope (assoc envelope
                                        :forward-circuit new-forward
                                        :return-circuit new-return)}]}))
      ;; Message dropped (invalid ingress, invalid proof, or not in circuit)
      {:state state :commands []})))

(defn- attempt-claim-ticket
  "Attempts to claim a ticket in the local ledger, returning the new ledger."
  [state ticket claimer-pubkey payout-amount]
  (let [network-scale (calculate-network-scale state)
        difficulty-hex (difficulty/calculate-difficulty murmur-k network-scale)]
    (ledger/claim-ticket (:ledger state) ticket difficulty-hex claimer-pubkey payout-amount)))

(defn- handle-route-directed-ack
  "Handles the return pass of a directed message along a locked circuit.
   Validates the proof of relay. Edge routers claim the lottery ticket here.
   If this node is the origin, emits :on-proof-of-relay-complete.
   If a Mint Ticket is claimed successfully, initiates Quorum Settlement."
  [state event]
  (let [envelope (:envelope event)
        claimer-pubkey (:node-pubkey state)
        ticket (:lottery-ticket envelope)
        proof-of-relay (:proof-of-relay envelope)
        forward-circuit (or (:forward-circuit envelope) [])
        return-circuit (or (:return-circuit envelope) [])]
    (if (and (peer-review/validate-proof-of-relay ticket proof-of-relay)
             (= claimer-pubkey (first forward-circuit)))
      (let [new-forward (rest forward-circuit)
            new-return (cons claimer-pubkey return-circuit)]
        (if (empty? new-forward)
          ;; We are the origin (Node A). Proof complete.
          {:state state
           :commands [{:type :app-event
                       :event-name :on-proof-of-relay-complete
                       :envelope envelope}]}
          ;; We are an edge router on the return path. Claim ticket and forward.
          (let [payout-amount (:payout-amount event)
                new-ledger (attempt-claim-ticket state ticket claimer-pubkey payout-amount)
                ;; Check if we successfully claimed a :mint ticket
                ticket-claimed? (not= (:ledger state) new-ledger)
                mint-ticket? (= :mint (:ticket-type ticket))
                _ (when ticket-claimed?
                    (println "WINNING TICKET REGISTERED! Node:" claimer-pubkey))
                rng (:rng event)
                utxos (:utxos new-ledger)
                ;; If we won a mint ticket, we must initiate quorum settlement
                quorum-target (when (and ticket-claimed? mint-ticket?)
                                (weighted/select-next-hop rng (basalt/extract-peers (:basalt-view state)) utxos))
                forward-command {:type :sign-and-forward
                                 :target (first new-forward)
                                 :out-type :send-directed-ack
                                 :payout-amount (:payout-amount event)
                                 :envelope (assoc envelope
                                                  :forward-circuit new-forward
                                                  :return-circuit new-return)}
                quorum-command (when quorum-target
                                 (let [target-pubkey (if (string? (:pubkey quorum-target)) (:pubkey quorum-target) (basalt/bytes->hex (:pubkey quorum-target)))]
                                   {:type :send-quorum-settlement
                                    :target target-pubkey
                                    :ticket ticket
                                    :proof-of-relay proof-of-relay
                                    :claimer-pubkey claimer-pubkey
                                    :payout-amount payout-amount}))
                commands (filterv some? [forward-command quorum-command])]
            {:state (assoc state :ledger new-ledger)
             :commands commands})))
      ;; Message dropped (invalid proof, or not in circuit)
      {:state state :commands []})))

(defn- handle-receive-quorum-settlement
  "Handles an incoming Quorum Settlement message.
   Validates the proof of relay and attempts to claim the Mint Ticket
   on behalf of the winning router (claimer-pubkey).
   If accepted into the local ledger, forwards it to the next hop."
  [state event]
  (let [ticket (:ticket event)
        proof-of-relay (:proof-of-relay event)
        claimer-pubkey (:claimer-pubkey event)
        payout-amount (:payout-amount event)]
    (if (and (= :mint (:ticket-type ticket))
             (peer-review/validate-proof-of-relay ticket proof-of-relay))
      (let [new-ledger (attempt-claim-ticket state ticket claimer-pubkey payout-amount)]
        (if (not= (:ledger state) new-ledger)
          ;; Successfully accepted into ledger. Forward to continue quorum building.
          (let [rng (:rng event)
                utxos (:utxos new-ledger)
                next-hop (weighted/select-next-hop rng (basalt/extract-peers (:basalt-view state)) utxos)]
            (if next-hop
              (let [target-pubkey (if (string? (:pubkey next-hop)) (:pubkey next-hop) (basalt/bytes->hex (:pubkey next-hop)))]
                {:state (assoc state :ledger new-ledger)
                 :commands [{:type :send-quorum-settlement
                             :target target-pubkey
                             :ticket ticket
                             :proof-of-relay proof-of-relay
                             :claimer-pubkey claimer-pubkey
                             :payout-amount payout-amount}]})
              {:state (assoc state :ledger new-ledger) :commands []}))
          ;; Already known/invalid, do not forward
          {:state state :commands []}))
      ;; Invalid ticket or proof
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

(defn- handle-ping-peer
  "Handles a circuit discovery ping request.
   If this node is the destination, emit a pong command targeting the last hop in the path.
   If not, route it forward appending this node to the path."
  [state event]
  (let [dest (:destination event)
        path (or (:path event) [])]
    (if (= dest (:node-pubkey state))
      ;; Target reached. Send pong back to the last node.
      (if (seq path)
        (let [last-hop (peek path)
              new-path (pop path)]
          {:state state
           :commands [{:type :pong-peer
                       :target last-hop
                       :path new-path
                       :ping-id (:ping-id event)}]})
        ;; This shouldn't happen unless origin pinged itself, but handle safely
        {:state state
         :commands [{:type :app-event
                     :event-name :on-circuit-locked
                     :ping-id (:ping-id event)}]})
      ;; Forward ping towards destination
      (let [rng (:rng event)
            utxos (:utxos (:ledger state))
            view-peers (basalt/extract-peers (:basalt-view state))
            ;; First check if the destination is already in our view
            direct-peer (some #(when (= dest (if (string? (:pubkey %)) (:pubkey %) (basalt/bytes->hex (:pubkey %)))) %) view-peers)
            next-hop (or direct-peer (weighted/select-next-hop rng view-peers utxos))
            new-state (if (empty? path)
                        (assoc-in state [:pending-circuits dest] {:epoch (or (:epoch state) 0)})
                        state)]
        (if next-hop
          (let [next-hop-pubkey (if (string? (:pubkey next-hop)) (:pubkey next-hop) (basalt/bytes->hex (:pubkey next-hop)))
                new-path (conj (vec path) (:node-pubkey state))]
            {:state new-state
             :commands [{:type :ping-peer
                         :target next-hop-pubkey
                         :destination dest
                         :path new-path
                         :ping-id (:ping-id event)
                         :rng rng}]})
          {:state new-state :commands []})))))

(defn- handle-pong-peer
  "Handles a returning circuit discovery pong request.
   If path is empty, this node is the origin and the circuit is locked.
   Otherwise, pop the last node from the path and forward the pong."
  [state event]
  (let [path (:path event)]
    (if (empty? path)
      ;; Origin reached. Circuit locked.
      {:state state
       :commands [{:type :app-event
                   :event-name :on-circuit-locked
                   :ping-id (:ping-id event)}]}
      ;; Forward pong to previous hop
      (let [last-hop (peek path)
            new-path (pop path)]
        {:state state
         :commands [{:type :pong-peer
                     :target last-hop
                     :path new-path
                     :ping-id (:ping-id event)}]}))))

(defn handle-event
  "Pure root reducer. Takes the current state and an event,
   returns a map with :state (new state) and :commands (side-effects to perform)."
  [state event]
  (case (:type event)
    :contagion-broadcast (handle-contagion-broadcast state event)
    :ping-peer (handle-ping-peer state event)
    :pong-peer (handle-pong-peer state event)
    :tick (handle-tick state event)
    :broadcast (handle-broadcast state event)
    :receive-push-view (handle-receive-push-view state event)
    :receive-summary (handle-receive-summary state event)
    :receive-pull-request (handle-receive-pull-request state event)
    :receive-gossip (handle-receive-gossip state event)
    :route-directed-message (handle-route-directed-message state event)
    :receive-directed-message (handle-route-directed-message state event)
    :route-directed-ack (handle-route-directed-ack state event)
    :receive-directed-ack (handle-route-directed-ack state event)
    :receive-ping (handle-ping-peer state event)
    :receive-pong (handle-pong-peer state event)
    :receive-quorum-settlement (handle-receive-quorum-settlement state event)
    :open-channel (handle-open-channel state event)
    :update-channel (handle-update-channel state event)
    :settle-channel (handle-settle-channel state event)
    :turn-allocate-request (handle-turn-allocate-request state event)
    :turn-relay-request (handle-turn-relay-request state event)
    {:state state :commands []}))