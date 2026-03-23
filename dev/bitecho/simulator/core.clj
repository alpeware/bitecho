(ns bitecho.simulator.core
  "The network orchestrator for the Chaos Mesh Simulator."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.shell.agent :as agent-shell]
            [bitecho.shell.bootstrap :as boot-shell]
            [bitecho.shell.core :as shell-core]
            [clojure.core.async :as async]))

(defn- create-bootstrap-node
  [i]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        node (boot-shell/init-node pubkey-hex)
        peer {:ip "127.0.0.1"
              :port (+ 8000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}]
    {:type :bootstrap
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :node node
     :events-in (:events-in node)
     :network-in (:network-in node)
     :net-out (:net-out node)
     :app-out (:app-out node)}))

(defn- create-agent-node
  [i bootstraps]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        ;; Pick a random bootstrap to connect to
        boot-peer (:peer (rand-nth bootstraps))
        node (agent-shell/init-node boot-peer pubkey-hex)
        peer {:ip "127.0.0.1"
              :port (+ 9000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}]
    {:type :agent
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :node node
     :events-in (:events-in node)
     :network-in (:network-in node)
     :net-out (:net-out node)
     :app-out (:app-out node)}))

(defn- route-message-to-target
  "Translates a network-out command to a network-in event for the target node."
  [nodes target-hex cmd sender-hex]
  (when-let [target-node (get nodes target-hex)]
    (case (:type cmd)
      :send-push-view
      (async/put! (:network-in target-node) {:type :receive-push-view :view (:view cmd)})
      :send-summary
      (async/put! (:network-in target-node) {:type :receive-summary
                                             :sender sender-hex
                                             :summary (:summary cmd)})
      :send-pull-request
      (async/put! (:network-in target-node) {:type :receive-pull-request
                                             :sender sender-hex
                                             :missing-ids (:missing-ids cmd)})
      :send-gossip
      (async/put! (:network-in target-node) {:type :receive-gossip
                                             :message (:message cmd)
                                             :rng (java.util.Random.)})
      :send-sieve-echo
      (async/put! (:network-in target-node) {:type :receive-sieve-echo
                                             :sender sender-hex
                                             :message-id (:message-id cmd)
                                             :rng (java.util.Random.)})
      :send-contagion-ready
      (async/put! (:network-in target-node) {:type :receive-contagion-ready
                                             :sender sender-hex
                                             :message-id (:message-id cmd)
                                             :rng (java.util.Random.)})
      nil)))

(defn- create-multiplexer
  "Spawns a go-loop that listens to all node net-out channels and routes them to targets."
  [nodes stop-ch]
  (let [out-channels (mapv :net-out (vals nodes))]
    (async/go-loop []
      (let [[val port] (async/alts! (conj out-channels stop-ch))]
        (if (= port stop-ch)
          nil ;; stop multiplexer
          (do
            (when (map? val)
              (let [cmd val
                    targets (or (:targets cmd) (when (:target cmd) [(:target cmd)]) (when (:destination cmd) [(:destination cmd)]) (when (:next-hop cmd) [(:next-hop cmd)]))
                    sender-hex (some (fn [[k v]] (when (= (:net-out v) port) k)) nodes)]
                (doseq [t targets]
                  (let [target-hex (if (string? t) t (:pubkey t))]
                    (route-message-to-target nodes target-hex cmd sender-hex)))))
            (recur)))))))

(defn- create-metronome
  "Spawns a go-loop that pushes :tick events to all nodes periodically."
  [nodes stop-ch interval-ms]
  (async/go-loop []
    (let [[_ port] (async/alts! [(async/timeout interval-ms) stop-ch])]
      (when (not= port stop-ch)
        (doseq [node (vals nodes)]
          (when (:events-in node)
            (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)})))
        (recur)))))

(defn start-network
  "Initializes the network orchestrator based on the given config.
   Returns a map with :nodes, :stop-ch, :multiplexer and :metronome."
  [config]
  (let [num-bootstraps (:bootstraps config 1)
        num-agents (:agents config 0)

        bootstraps (mapv create-bootstrap-node (range num-bootstraps))
        agents (mapv #(create-agent-node % bootstraps) (range num-agents))

        all-nodes (concat bootstraps agents)
        nodes-map (into {} (map (juxt :pubkey-hex identity) all-nodes))
        stop-ch (async/chan)
        multiplexer (create-multiplexer nodes-map stop-ch)
        tick-interval (:tick-interval-ms config 100)
        metronome (create-metronome nodes-map stop-ch tick-interval)
        all-peers (mapv :peer (concat bootstraps agents))]

    (doseq [agent agents]
      (async/put! (:events-in agent) {:type :receive-push-view
                                      :view all-peers}))

    {:nodes nodes-map
     :stop-ch stop-ch
     :multiplexer multiplexer
     :metronome metronome}))

(defn stop-network
  "Gracefully stops the simulator network."
  [network]
  (when-let [stop-ch (:stop-ch network)]
    (async/put! stop-ch true)
    (async/close! stop-ch))
  (doseq [node (vals (:nodes network))]
    (shell-core/stop-node (:node node))))
