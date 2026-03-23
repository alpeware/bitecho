(ns bitecho.state-machine
  "The pure root reducer that integrates Basalt, Murmur, Sieve, and Contagion.
   Accepts `state` and `event` inputs and emits a map of `{:state new-state :commands [...]}`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.contagion.core :as contagion]
            [bitecho.murmur.core :as murmur]
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

(def E-size "Sieve echo sample size" 10)
(def E-hat "Sieve echo delivery threshold" 7)
(def R-size "Contagion ready sample size" 10)
(def R-hat "Contagion ready threshold" 3)
(def D-size "Contagion delivery sample size" 10)
(def D-hat "Contagion final delivery threshold" 8)

(defn init-state
  "Initializes the pure Bitecho state map.
   node-pubkey should be the hex-encoded public key of this node."
  [initial-peers node-pubkey]
  {:node-pubkey node-pubkey
   :epoch 0
   :basalt-index 0
   :basalt-view (basalt/init-view initial-peers basalt-max-view-size (java.util.Random.))
   :murmur-cache {:set #{} :queue clojure.lang.PersistentQueue/EMPTY}
   :contagion-known-ids #{}
   :messages {}
   :message-epochs {}
   :global-echo-sample #{}
   :global-ready-sample #{}
   :global-delivery-sample #{}
   :echo-subscribers #{}
   :ready-subscribers #{}
   :delivery-subscribers #{}
   :received-echoes {}
   :received-readies {}
   :sieve-delivered-set #{}
   :local-ready-set #{}
   :delivered-set #{}})

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

        ;; Background Sampling
        my-pubkey (:node-pubkey state)

        needed-echo (max 0 (- E-size (count (:global-echo-sample state))))
        needed-ready (max 0 (- R-size (count (:global-ready-sample state))))
        needed-delivery (max 0 (- D-size (count (:global-delivery-sample state))))

        exclude-fn (fn [sample-set peer]
                     (let [p-hex (if (string? (:pubkey peer)) (:pubkey peer) (basalt/bytes->hex (:pubkey peer)))]
                       (or (= p-hex my-pubkey) (contains? sample-set p-hex))))

        available-for-echo (filter #(not (exclude-fn (:global-echo-sample state) %)) extracted-peers)
        new-echo-peers (basalt/select-peers rng available-for-echo needed-echo)
        new-echo-hexes (set (map #(if (string? (:pubkey %)) (:pubkey %) (basalt/bytes->hex (:pubkey %))) new-echo-peers))

        available-for-ready (filter #(not (exclude-fn (:global-ready-sample state) %)) extracted-peers)
        new-ready-peers (basalt/select-peers rng available-for-ready needed-ready)
        new-ready-hexes (set (map #(if (string? (:pubkey %)) (:pubkey %) (basalt/bytes->hex (:pubkey %))) new-ready-peers))

        available-for-delivery (filter #(not (exclude-fn (:global-delivery-sample state) %)) extracted-peers)
        new-delivery-peers (basalt/select-peers rng available-for-delivery needed-delivery)
        new-delivery-hexes (set (map #(if (string? (:pubkey %)) (:pubkey %) (basalt/bytes->hex (:pubkey %))) new-delivery-peers))

        updated-echo-sample (set/union (:global-echo-sample state) new-echo-hexes)
        updated-ready-sample (set/union (:global-ready-sample state) new-ready-hexes)
        updated-delivery-sample (set/union (:global-delivery-sample state) new-delivery-hexes)

        ;; Collect all newly added peers and their roles
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :echo)) {} new-echo-hexes)
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :ready)) new-roles-by-peer new-ready-hexes)
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :delivery)) new-roles-by-peer new-delivery-hexes)

        subscribe-commands (mapv (fn [[peer roles]]
                                   {:type :send-subscribe
                                    :target peer
                                    :roles roles})
                                 new-roles-by-peer)

        commands (filterv some? (concat [push-command summary-command] subscribe-commands))

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

        pruned-received-echoes (apply dissoc (or (:received-echoes state) {}) expired-ids)
        pruned-received-readies (apply dissoc (or (:received-readies state) {}) expired-ids)
        pruned-sieve-delivered-set (set/difference (:sieve-delivered-set state) expired-ids)
        pruned-local-ready-set (set/difference (:local-ready-set state) expired-ids)
        pruned-delivered-set (set/difference (:delivered-set state) expired-ids)]
    {:state (assoc state
                   :epoch new-epoch
                   :basalt-view new-view
                   :basalt-index new-index
                   :murmur-cache pruned-murmur-cache
                   :contagion-known-ids pruned-known-ids
                   :messages pruned-messages
                   :message-epochs pruned-epochs
                   :global-echo-sample updated-echo-sample
                   :global-ready-sample updated-ready-sample
                   :global-delivery-sample updated-delivery-sample
                   :received-echoes pruned-received-echoes
                   :received-readies pruned-received-readies
                   :sieve-delivered-set pruned-sieve-delivered-set
                   :local-ready-set pruned-local-ready-set
                   :delivered-set pruned-delivered-set)
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

(defn- handle-receive-subscribe
  "Handles an incoming subscription request from a peer.
   Adds the peer to the corresponding subscriber sets."
  [state event]
  (let [sender (:sender event)
        roles (:roles event)
        new-echo-subscribers (if (contains? roles :echo)
                               (conj (:echo-subscribers state) sender)
                               (:echo-subscribers state))
        new-ready-subscribers (if (contains? roles :ready)
                                (conj (:ready-subscribers state) sender)
                                (:ready-subscribers state))
        new-delivery-subscribers (if (contains? roles :delivery)
                                   (conj (:delivery-subscribers state) sender)
                                   (:delivery-subscribers state))]
    {:state (assoc state
                   :echo-subscribers new-echo-subscribers
                   :ready-subscribers new-ready-subscribers
                   :delivery-subscribers new-delivery-subscribers)
     :commands []}))

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
   Validates the Sieve signature before accepting into the cache.
   If new, initializes Sieve and Contagion sampling."
  [state event]
  (let [message (:message event)
        rng (:rng event)
        valid-signature? (sieve/validate-message message)]
    (if valid-signature?
      (let [extracted-peers (basalt/extract-peers (:basalt-view state))
            gossip-result (murmur/receive-gossip (:murmur-cache state) message rng extracted-peers murmur-k murmur-max-cache-size)
            gossip-commands (if (seq (:forward-targets gossip-result))
                              [{:type :send-gossip
                                :targets (:forward-targets gossip-result)
                                :message (:message gossip-result)}]
                              [])
            new-message? (some? (:message gossip-result))
            message-id (:message-id message)

            ;; If new message, send Sieve Echo to our echo subscribers
            sieve-targets (:echo-subscribers state)
            sieve-echo-command (when (and new-message? (seq sieve-targets))
                                 {:type :send-sieve-echo
                                  :targets sieve-targets
                                  :message-id message-id})

            commands (if new-message?
                       (filterv some? (into gossip-commands [sieve-echo-command]))
                       gossip-commands)

            new-known-ids (if new-message?
                            (conj (:contagion-known-ids state) message-id)
                            (:contagion-known-ids state))
            new-messages (if new-message?
                           (assoc (:messages state) message-id message)
                           (:messages state))
            new-epochs (if new-message?
                         (assoc (or (:message-epochs state) {}) message-id (or (:epoch state) 0))
                         (:message-epochs state))]
        {:state (assoc state
                       :murmur-cache (:cache gossip-result)
                       :contagion-known-ids new-known-ids
                       :messages new-messages
                       :message-epochs new-epochs)
         :commands commands})
      {:state state :commands []})))

(defn- handle-receive-sieve-echo
  "Handles an incoming Sieve Echo message.
   Records the vote if the sender is in the global-echo-sample.
   If E-hat is reached, transitions to Sieve-Delivered and broadcasts Contagion Ready."
  [state event]
  (let [sender (:sender event)
        message-id (:message-id event)
        echo-sample (:global-echo-sample state)
        received-echoes (get (:received-echoes state) message-id #{})
        sieve-delivered-set (:sieve-delivered-set state)]
    (if (and (contains? echo-sample sender)
             (not (contains? received-echoes sender)))
      (let [new-received-echoes (conj received-echoes sender)
            state-with-echo (assoc-in state [:received-echoes message-id] new-received-echoes)
            current-E-hat E-hat]
        (if (and (>= (count new-received-echoes) current-E-hat)
                 (not (contains? sieve-delivered-set message-id)))
          ;; Threshold reached, transition to Sieve-Delivered
          (let [state-sieve-delivered (update state-with-echo :sieve-delivered-set conj message-id)
                ;; Rule 1 (Becoming Ready): we are Sieve-Delivered, so we become Ready.
                local-ready-set (:local-ready-set state-sieve-delivered)]
            (if (not (contains? local-ready-set message-id))
              (let [state-ready (update state-sieve-delivered :local-ready-set conj message-id)
                    ;; Broadcast Ready to union of ready and delivery subscribers
                    ready-targets (set/union (:ready-subscribers state) (:delivery-subscribers state))
                    ready-command (when (seq ready-targets)
                                    {:type :send-contagion-ready
                                     :targets ready-targets
                                     :message-id message-id})]
                {:state state-ready :commands (filterv some? [ready-command])})
              {:state state-sieve-delivered :commands []}))
          {:state state-with-echo :commands []}))
      {:state state :commands []})))

(defn- handle-receive-contagion-ready
  "Handles an incoming Contagion Ready message.
   Records the vote if the sender is in the global-ready-sample or global-delivery-sample.
   If R-hat is reached, transitions to Ready and broadcasts Contagion Ready.
   If D-hat is reached, transitions to Delivered and emits :on-deliver."
  [state event]
  (let [sender (:sender event)
        message-id (:message-id event)
        ready-sample (:global-ready-sample state)
        delivery-sample (:global-delivery-sample state)
        received-readies (get (:received-readies state) message-id #{})]
    (if (and (not (contains? received-readies sender))
             (or (contains? ready-sample sender)
                 (contains? delivery-sample sender)))
      (let [new-received-readies (conj received-readies sender)
            state-with-ready (assoc-in state [:received-readies message-id] new-received-readies)

            ;; Check R-hat for Ready transition
            current-R-hat R-hat
            ready-votes (count (clojure.set/intersection new-received-readies ready-sample))
            state-checked-ready (if (and (>= ready-votes current-R-hat)
                                         (not (contains? (:local-ready-set state-with-ready) message-id)))
                                  (update state-with-ready :local-ready-set conj message-id)
                                  state-with-ready)
            ready-commands (if (and (>= ready-votes current-R-hat)
                                    (not (contains? (:local-ready-set state-with-ready) message-id)))
                             (let [ready-targets (set/union (:ready-subscribers state) (:delivery-subscribers state))]
                               (if (seq ready-targets)
                                 [{:type :send-contagion-ready
                                   :targets ready-targets
                                   :message-id message-id}]
                                 []))
                             [])

            ;; Check D-hat for Final Delivery transition
            current-D-hat D-hat
            delivery-votes (count (clojure.set/intersection new-received-readies delivery-sample))
            state-checked-delivery (if (and (>= delivery-votes current-D-hat)
                                            (not (contains? (:delivered-set state-checked-ready) message-id)))
                                     (update state-checked-ready :delivered-set conj message-id)
                                     state-checked-ready)

            delivery-commands (if (and (>= delivery-votes current-D-hat)
                                       (not (contains? (:delivered-set state-checked-ready) message-id)))
                                (let [message (get (:messages state) message-id)]
                                  (if message
                                    [{:type :app-event :event-name :on-deliver :payload (:payload message)}]
                                    []))
                                [])
            commands (into ready-commands delivery-commands)]
        {:state state-checked-delivery :commands commands})
      {:state state :commands []})))

(defn handle-event
  "Pure root reducer. Takes the current state and an event,
   returns a map with :state (new state) and :commands (side-effects to perform)."
  [state event]
  (case (:type event)
    :contagion-broadcast (handle-contagion-broadcast state event)
    :tick (handle-tick state event)
    :broadcast (handle-broadcast state event)
    :receive-push-view (handle-receive-push-view state event)
    :receive-summary (handle-receive-summary state event)
    :receive-subscribe (handle-receive-subscribe state event)
    :receive-pull-request (handle-receive-pull-request state event)
    :receive-gossip (handle-receive-gossip state event)
    :receive-sieve-echo (handle-receive-sieve-echo state event)
    :receive-contagion-ready (handle-receive-contagion-ready state event)
    {:state state :commands []}))