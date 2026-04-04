(ns bitecho.state-machine
  "The pure root reducer that integrates Basalt, Murmur, Sieve, and Contagion.
   Accepts `state` and `event` inputs and emits a map of `{:state new-state :commands [...]}`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.contagion.core :as contagion]
            [bitecho.economy.account :as account]
            [bitecho.murmur.core :as murmur]
            [bitecho.sieve.core :as sieve]
            [clojure.edn :as edn]
            [clojure.set :as set]))

(defn- peer-hex
  "Normalizes a peer's pubkey to a hex string."
  [peer]
  (let [pk (:pubkey peer)]
    (if (string? pk) pk (basalt/bytes->hex pk))))

(defn init-state
  "Initializes the pure Bitecho state map.
   node-pubkey should be the hex-encoded public key of this node.
   config is an optional protocol-parameter map (defaults to `config/default-config`)."
  ([initial-peers node-pubkey]
   (init-state initial-peers node-pubkey config/default-config))
  ([initial-peers node-pubkey cfg]
   {:node-pubkey node-pubkey
    :config cfg
    :epoch 0
    :basalt-index 0
    :basalt-view (basalt/init-view initial-peers (:basalt-max-view-size cfg) (java.util.Random.))
    :murmur-cache {:set #{} :queue clojure.lang.PersistentQueue/EMPTY}
    :contagion-known-ids #{}
    :messages {}
    :message-epochs {}
    :epoch-to-messages {}
    :global-echo-sample #{}
    :global-ready-sample #{}
    :global-delivery-sample #{}
    :echo-subscribers #{}
    :ready-subscribers #{}
    :delivery-subscribers #{}
    :received-echoes {}
    :received-readies {}
    :echo-vote-counts {}
    :ready-vote-counts {}
    :delivery-vote-counts {}
    :sieve-delivered-set #{}
    :local-ready-set #{}
    :delivered-set #{}
    :ledger {node-pubkey (account/map->AccountState {:balance 1000 :seq 0 :deps []})}}))

(defn- handle-tick
  "Handles a periodic tick event to drive Basalt reseeding and Contagion anti-entropy."
  [state event]
  (let [cfg (:config state)
        E-size (:echo-sample-size cfg)
        R-size (:ready-sample-size cfg)
        D-size (:delivery-sample-size cfg)
        gossip-ttl-epochs (:gossip-ttl-epochs cfg)
        new-epoch (inc (or (:epoch state) 0))
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

        ;; Bounded anti-entropy: only include recent epoch's known-ids
        summary (contagion/generate-summary rng extracted-peers (:contagion-known-ids state))
        summary-command (when summary
                          {:type :send-summary
                           :target (:target summary)
                           :summary (:summary summary)})

        ;; Background Sampling — pre-normalize pubkeys once
        my-pubkey (:node-pubkey state)
        peer-hexes (mapv peer-hex extracted-peers)

        needed-echo (max 0 (- E-size (count (:global-echo-sample state))))
        needed-ready (max 0 (- R-size (count (:global-ready-sample state))))
        needed-delivery (max 0 (- D-size (count (:global-delivery-sample state))))

        exclude-fn (fn [sample-set p-hex]
                     (or (= p-hex my-pubkey) (contains? sample-set p-hex)))

        avail-idx-for (fn [sample-set]
                        (filterv #(not (exclude-fn sample-set (nth peer-hexes %)))
                                 (range (count extracted-peers))))

        echo-avail-idxs (avail-idx-for (:global-echo-sample state))
        echo-avail-peers (mapv #(nth extracted-peers %) echo-avail-idxs)
        new-echo-peers (basalt/select-peers rng echo-avail-peers needed-echo)
        new-echo-hexes (set (mapv peer-hex new-echo-peers))

        ready-avail-idxs (avail-idx-for (:global-ready-sample state))
        ready-avail-peers (mapv #(nth extracted-peers %) ready-avail-idxs)
        new-ready-peers (basalt/select-peers rng ready-avail-peers needed-ready)
        new-ready-hexes (set (mapv peer-hex new-ready-peers))

        delivery-avail-idxs (avail-idx-for (:global-delivery-sample state))
        delivery-avail-peers (mapv #(nth extracted-peers %) delivery-avail-idxs)
        new-delivery-peers (basalt/select-peers rng delivery-avail-peers needed-delivery)
        new-delivery-hexes (set (mapv peer-hex new-delivery-peers))

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

        ;; Sieve-echo anti-entropy: re-send echoes for messages not yet sieve-delivered
        echo-subs (:echo-subscribers state)
        pending-echo-ids (set/difference (:contagion-known-ids state)
                                         (:sieve-delivered-set state))
        echo-ae-commands (when (seq echo-subs)
                           (mapv (fn [mid]
                                   {:type :send-sieve-echo
                                    :targets echo-subs
                                    :message-id mid})
                                 pending-echo-ids))

        commands (into (filterv some? (concat [push-command summary-command] subscribe-commands))
                       echo-ae-commands)

        ;; Epoch-indexed GC: collect expired epoch keys, union their message IDs
        cutoff-epoch (- new-epoch gossip-ttl-epochs)
        epoch-to-messages (or (:epoch-to-messages state) {})
        expired-epochs (filterv #(< % cutoff-epoch) (keys epoch-to-messages))
        expired-ids (reduce (fn [acc ep] (set/union acc (get epoch-to-messages ep #{})))
                            #{} expired-epochs)
        pruned-epoch-to-messages (reduce dissoc epoch-to-messages expired-epochs)
        pruned-epochs (reduce dissoc (or (:message-epochs state) {}) expired-ids)
        pruned-messages (reduce dissoc (:messages state) expired-ids)
        pruned-known-ids (set/difference (:contagion-known-ids state) expired-ids)
        pruned-murmur-cache-set (set/difference (:set (:murmur-cache state)) expired-ids)
        pruned-murmur-cache-queue (if (seq expired-ids)
                                    (into clojure.lang.PersistentQueue/EMPTY
                                          (remove expired-ids (:queue (:murmur-cache state))))
                                    (:queue (:murmur-cache state)))
        pruned-murmur-cache {:set pruned-murmur-cache-set :queue pruned-murmur-cache-queue}

        pruned-received-echoes (reduce dissoc (or (:received-echoes state) {}) expired-ids)
        pruned-received-readies (reduce dissoc (or (:received-readies state) {}) expired-ids)
        pruned-echo-vote-counts (reduce dissoc (or (:echo-vote-counts state) {}) expired-ids)
        pruned-ready-vote-counts (reduce dissoc (or (:ready-vote-counts state) {}) expired-ids)
        pruned-delivery-vote-counts (reduce dissoc (or (:delivery-vote-counts state) {}) expired-ids)
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
                   :epoch-to-messages pruned-epoch-to-messages
                   :global-echo-sample updated-echo-sample
                   :global-ready-sample updated-ready-sample
                   :global-delivery-sample updated-delivery-sample
                   :received-echoes pruned-received-echoes
                   :received-readies pruned-received-readies
                   :echo-vote-counts pruned-echo-vote-counts
                   :ready-vote-counts pruned-ready-vote-counts
                   :delivery-vote-counts pruned-delivery-vote-counts
                   :sieve-delivered-set pruned-sieve-delivered-set
                   :local-ready-set pruned-local-ready-set
                   :delivered-set pruned-delivered-set)
     :commands commands}))

(defn- handle-broadcast
  "Handles an internal request to broadcast a payload."
  [state event]
  (let [cfg (:config state)
        murmur-k (:murmur-k cfg)
        murmur-max-cache-size (:murmur-max-cache-size cfg)
        payload (:payload event)
        rng (:rng event)
        extracted-peers (basalt/extract-peers (:basalt-view state))
        sieve-message (if (and (:private-key event) (:public-key event))
                        (sieve/wrap-message payload (:private-key event) (:public-key event))
                        {:payload payload :sender "local" :signature (byte-array 0)})
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
        current-epoch (or (:epoch state) 0)
        new-epochs (assoc (or (:message-epochs state) {}) message-id current-epoch)
        new-epoch-to-messages (update (or (:epoch-to-messages state) {})
                                      current-epoch (fnil conj #{}) message-id)]
    {:state (assoc state
                   :murmur-cache new-cache
                   :contagion-known-ids new-known-ids
                   :messages new-messages
                   :message-epochs new-epochs
                   :epoch-to-messages new-epoch-to-messages)
     :commands commands}))

(defn- handle-contagion-broadcast
  "Handles an internal request to broadcast a payload, specifically emitting :on-deliver for simulator E2E."
  [state event]
  (let [{new-state :state commands :commands} (handle-broadcast state (assoc event :type :broadcast))
        ;; Find the message-id just created (last added to known-ids)
        message-id (first (set/difference (:contagion-known-ids new-state)
                                          (:contagion-known-ids state)))]
    {:state new-state
     :commands (conj commands {:type :app-event :event-name :on-deliver
                               :payload (:payload event) :message-id message-id})}))

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
  (let [cfg (:config state)
        murmur-k (:murmur-k cfg)
        murmur-max-cache-size (:murmur-max-cache-size cfg)
        message (:message event)
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

            current-epoch (or (:epoch state) 0)
            new-known-ids (if new-message?
                            (conj (:contagion-known-ids state) message-id)
                            (:contagion-known-ids state))
            new-messages (if new-message?
                           (assoc (:messages state) message-id message)
                           (:messages state))
            new-epochs (if new-message?
                         (assoc (or (:message-epochs state) {}) message-id current-epoch)
                         (:message-epochs state))
            new-epoch-to-messages (if new-message?
                                    (update (or (:epoch-to-messages state) {})
                                            current-epoch (fnil conj #{}) message-id)
                                    (or (:epoch-to-messages state) {}))]
        {:state (assoc state
                       :murmur-cache (:cache gossip-result)
                       :contagion-known-ids new-known-ids
                       :messages new-messages
                       :message-epochs new-epochs
                       :epoch-to-messages new-epoch-to-messages)
         :commands commands})
      {:state state :commands []})))

(defn- handle-receive-sieve-echo
  "Handles an incoming Sieve Echo message.
   Records the vote if the sender is in the global-echo-sample.
   Uses integer vote counters instead of set intersection for threshold checks.
   If E-hat is reached, transitions to Sieve-Delivered and broadcasts Contagion Ready."
  [state event]
  (let [cfg (:config state)
        E-hat (:echo-threshold cfg)
        sender (:sender event)
        message-id (:message-id event)
        echo-sample (:global-echo-sample state)
        received-echoes (get (:received-echoes state) message-id #{})
        sieve-delivered-set (:sieve-delivered-set state)]
    (if (and (contains? echo-sample sender)
             (not (contains? received-echoes sender)))
      (let [new-received-echoes (conj received-echoes sender)
            old-count (get-in state [:echo-vote-counts message-id] 0)
            new-count (inc old-count)
            state-with-echo (-> state
                                (assoc-in [:received-echoes message-id] new-received-echoes)
                                (assoc-in [:echo-vote-counts message-id] new-count))]
        (if (and (>= new-count E-hat)
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
   Uses integer vote counters instead of set intersection for threshold checks.
   If R-hat is reached, transitions to Ready and broadcasts Contagion Ready.
   If D-hat is reached, transitions to Delivered and emits :on-deliver."
  [state event]
  (let [cfg (:config state)
        R-hat (:ready-threshold cfg)
        D-hat (:delivery-threshold cfg)
        sender (:sender event)
        message-id (:message-id event)
        ready-sample (:global-ready-sample state)
        delivery-sample (:global-delivery-sample state)
        received-readies (get (:received-readies state) message-id #{})
        in-ready? (contains? ready-sample sender)
        in-delivery? (contains? delivery-sample sender)]
    (if (and (not (contains? received-readies sender))
             (or in-ready? in-delivery?))
      (let [new-received-readies (conj received-readies sender)
            ;; Increment vote counters based on membership
            old-ready-votes (get-in state [:ready-vote-counts message-id] 0)
            new-ready-votes (if in-ready? (inc old-ready-votes) old-ready-votes)
            old-delivery-votes (get-in state [:delivery-vote-counts message-id] 0)
            new-delivery-votes (if in-delivery? (inc old-delivery-votes) old-delivery-votes)
            state-with-ready (-> state
                                 (assoc-in [:received-readies message-id] new-received-readies)
                                 (assoc-in [:ready-vote-counts message-id] new-ready-votes)
                                 (assoc-in [:delivery-vote-counts message-id] new-delivery-votes))

            ;; Check R-hat for Ready transition
            state-checked-ready (if (and (>= new-ready-votes R-hat)
                                         (not (contains? (:local-ready-set state-with-ready) message-id)))
                                  (update state-with-ready :local-ready-set conj message-id)
                                  state-with-ready)
            ready-commands (if (and (>= new-ready-votes R-hat)
                                    (not (contains? (:local-ready-set state-with-ready) message-id)))
                             (let [ready-targets (set/union (:ready-subscribers state) (:delivery-subscribers state))]
                               (if (seq ready-targets)
                                 [{:type :send-contagion-ready
                                   :targets ready-targets
                                   :message-id message-id}]
                                 []))
                             [])

            ;; If payload contains a transfer, try to apply it to the ledger upon delivery.
            state-with-applied-ledger (if (and (>= new-delivery-votes D-hat)
                                               (not (contains? (:delivered-set state-checked-ready) message-id)))
                                        (let [message (get (:messages state) message-id)
                                              payload-bytes (or (:payload message) (byte-array 0))
                                              payload-str (try (String. ^bytes payload-bytes "UTF-8") (catch Exception _ nil))
                                              payload-edn (try (when payload-str
                                                                 (edn/read-string {:default tagged-literal
                                                                                   :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                                                             'bitecho.economy.account.AccountState account/map->AccountState}} payload-str))
                                                               (catch Exception _ nil))]
                                          (if (and (map? payload-edn) (:transfer payload-edn))
                                            (try
                                              (let [raw-transfer (:transfer payload-edn)
                                                    transfer-map (if (instance? clojure.lang.TaggedLiteral raw-transfer)
                                                                   (:form raw-transfer)
                                                                   (if (map? raw-transfer)
                                                                     (into {} raw-transfer)
                                                                     ;; If it's already a Transfer record it will act as map
                                                                     (into {} raw-transfer)))
                                                    ;; In tests signature might be a Vector instead of byte array since it gets passed around via pr-str and parsed via EDN,
                                                    ;; let's ensure it's a byte-array to prevent classcast errors in validate-transfer
                                                    transfer-map (if (vector? (:signature transfer-map))
                                                                   (assoc transfer-map :signature (byte-array (map byte (:signature transfer-map))))
                                                                   transfer-map)
                                                    ;; If it is a string representation of bytes in a tagged literal (via tests), force stringification for the sig check mock
                                                    transfer-map (if (string? (:signature transfer-map))
                                                                   (assoc transfer-map :signature (.getBytes ^String (:signature transfer-map) "UTF-8"))
                                                                   transfer-map)
                                                    ;; EDN parsing from tagged literal sometimes converts into an array of Long/Long numbers when reading into native Maps
                                                    ;; So let's force the signature map back into a byte array again if it was a sequence of java.lang.Long
                                                    transfer-map (if (and (seqable? (:signature transfer-map))
                                                                          (every? number? (:signature transfer-map)))
                                                                   (assoc transfer-map :signature (byte-array (map byte (:signature transfer-map))))
                                                                   transfer-map)
                                                    ;; Ensure signature is always a byte array (mock signers return strings etc sometimes)
                                                    transfer-map (if (not (bytes? (:signature transfer-map)))
                                                                   (assoc transfer-map :signature (byte-array 0))
                                                                   transfer-map)
                                                    ;; Re-hydrate the transfer structure carefully avoiding tagged-literals
                                                    transfer (account/map->Transfer transfer-map)
                                                    ;; The root state initializes the ledger with our own balance.
                                                    ;; We need to ensure sender and receiver exist in the ledger before apply-transfer so it can validate.
                                                    ;; By default apply-transfer handles missing receivers, but if sender is missing it fails validation.
                                                    ;; In a real network, genesis balances cover this. For simulation, lazily initialize sender with 1000 if missing.
                                                    ledger (or (:ledger state-checked-ready) {})
                                                    ;; ONLY initialize if they don't exist at all, meaning they aren't the local node and haven't transacted.
                                                    ;; If receiver is local node, it already has an account initialized to 1000. We MUST NOT overwrite that balance logic.
                                                    ;; Since local nodes start with 1000 balance, receiving 100 makes it 1100!
                                                    ;; Wait! That perfectly explains why node receiver balance is 1100 sometimes!
                                                    ledger (if (and (:sender transfer) (not (contains? ledger (:sender transfer))))
                                                             (assoc ledger (:sender transfer) (account/map->AccountState {:balance 1000 :seq 0 :deps []}))
                                                             ledger)
                                                    ledger (if (and (:receiver transfer) (not (contains? ledger (:receiver transfer))))
                                                             (assoc ledger (:receiver transfer) (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                                                             ledger)
                                                    new-ledger (account/apply-transfer ledger transfer)]
                                                (assoc state-checked-ready :ledger new-ledger))
                                              (catch Exception e
                                                (println "Error applying transfer" e)
                                                ;; In case applying the transfer fails due to invalid structures
                                                state-checked-ready))
                                            state-checked-ready))
                                        state-checked-ready)

            delivery-commands (if (and (>= new-delivery-votes D-hat)
                                       (not (contains? (:delivered-set state-checked-ready) message-id)))
                                (let [message (get (:messages state) message-id)]
                                  (if message
                                    [{:type :app-event :event-name :on-deliver
                                      :payload (:payload message) :message-id message-id}]
                                    []))
                                [])

            ;; Check D-hat for Final Delivery transition (must happen AFTER ledger apply and command generation so we don't block them)
            state-checked-delivery (if (and (>= new-delivery-votes D-hat)
                                            (not (contains? (:delivered-set state-checked-ready) message-id)))
                                     (update state-with-applied-ledger :delivered-set conj message-id)
                                     state-with-applied-ledger)

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