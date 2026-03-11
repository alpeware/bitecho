(ns bitecho.state-machine
  "The pure root reducer that integrates Basalt, Murmur, Sieve, and Contagion.
   Accepts `state` and `event` inputs and emits a map of `{:state new-state :commands [...]}`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.contagion.core :as contagion]
            [bitecho.murmur.core :as murmur]
            [bitecho.sieve.core :as sieve]))

(def murmur-k
  "Number of peers to forward gossip messages to."
  3)

(def murmur-max-cache-size
  "Maximum number of seen message IDs to keep in the cache."
  1000)

(def basalt-max-view-size
  "Maximum number of peers to keep in the Basalt view."
  50)

(defn init-state
  "Initializes the pure Bitecho state map."
  [initial-peers]
  {:basalt-view (basalt/init-view initial-peers)
   :murmur-cache {:set #{} :queue []}
   :sieve-history {}
   :contagion-known-ids #{}
   :messages {}})

(defn- handle-tick
  "Handles a periodic tick event to drive Basalt age updates, views, and Contagion anti-entropy."
  [state event]
  (let [view (:basalt-view state)
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
        commands (filterv some? [push-command summary-command])]
    {:state (assoc state :basalt-view new-view)
     :commands commands}))

(defn- handle-broadcast
  "Handles an internal request to broadcast a payload."
  [state event]
  (let [payload (:payload event)
        rng (:rng event)
        sieve-message (if (and (:private-key event) (:public-key event))
                        (sieve/wrap-message payload (:private-key event) (:public-key event))
                        {:payload payload :sender "local" :signature (byte-array 0)})
        broadcast-result (murmur/initiate-broadcast payload rng (:basalt-view state) murmur-k)
        message-id (:message-id broadcast-result)
        message (assoc sieve-message :message-id message-id)
        commands (if (seq (:targets broadcast-result))
                   [{:type :send-gossip
                     :targets (:targets broadcast-result)
                     :message message}]
                   [])
        ;; We implicitly add our own broadcasts to the known ids and cache
        new-cache-set (conj (:set (:murmur-cache state)) message-id)
        new-cache-queue (conj (:queue (:murmur-cache state)) message-id)
        new-cache {:set new-cache-set :queue new-cache-queue}
        new-known-ids (conj (:contagion-known-ids state) message-id)
        new-messages (assoc (:messages state) message-id message)]
    {:state (assoc state
                   :murmur-cache new-cache
                   :contagion-known-ids new-known-ids
                   :messages new-messages)
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
  "Handles an incoming Murmur gossip message."
  [state event]
  (let [message (:message event)
        rng (:rng event)
        gossip-result (murmur/receive-gossip (:murmur-cache state) message rng (:basalt-view state) murmur-k murmur-max-cache-size)
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
                       (:messages state))]
    {:state (assoc state
                   :murmur-cache (:cache gossip-result)
                   :contagion-known-ids new-known-ids
                   :messages new-messages)
     :commands commands}))

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
    {:state state :commands []}))
