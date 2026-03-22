(ns bitecho.simulator.contagion-e2e
  "Isolated integration test proving that a pure Contagion broadcast reliably reaches all honest nodes in the presence of Byzantine actors."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.shell.core :as shell-core]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]))

;; Configuration
(def total-nodes 100)
(def byzantine-nodes 10)
(def honest-nodes (- total-nodes byzantine-nodes))
(def tick-interval-ms 100)

;; Metrics
(def broadcasts-initiated (atom 0))
(def broadcasts-delivered (atom 0))
(def broadcast-start-times (atom {}))
(def total-consensus-time (atom 0))

(defn- create-honest-node
  [i]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        initial-state (sm/init-state [] pubkey-hex)
        snapshot-filename (str "/tmp/snapshot-" pubkey-hex ".bin")
        node (shell-core/start-node initial-state (:private keys) snapshot-filename)
        peer {:ip "127.0.0.1"
              :port (+ 8000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}]
    {:type :honest
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :node node
     :events-in (:events-in node)
     :network-in (:network-in node)
     :net-out (:net-out node)
     :app-out (:app-out node)}))

(defn- start-byzantine-spammer
  "Starts a simple loop that consumes net-out messages but drops them (black hole)."
  [net-out-ch stop-ch]
  (async/go-loop []
    (let [[val port] (async/alts! [net-out-ch stop-ch])]
      (when (not= port stop-ch)
        ;; Black hole: drops packet silently
        (recur)))))

(defn- create-byzantine-node
  [i]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        peer {:ip "127.0.0.1"
              :port (+ 9000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}
        net-out-ch (async/chan 1024)
        stop-ch (async/chan)]
    (start-byzantine-spammer net-out-ch stop-ch)
    {:type :byzantine
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :node {:stop-ch stop-ch} ;; Mock node map for stop
     :events-in nil
     :network-in nil
     :net-out net-out-ch
     :app-out nil}))

(defn- route-message-to-target
  "Translates a network-out command to a network-in event for the target node."
  [nodes target-hex cmd sender-hex]
  (when-let [target-node (get nodes target-hex)]
    (when (:network-in target-node)
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
        nil))))

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
                    targets (or (:targets cmd) (when (:target cmd) [(:target cmd)]))
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

(defn- start-network
  []
  (let [h-nodes (mapv create-honest-node (range honest-nodes))
        b-nodes (mapv create-byzantine-node (range byzantine-nodes))

        all-nodes (concat h-nodes b-nodes)
        nodes-map (into {} (map (juxt :pubkey-hex identity) all-nodes))
        stop-ch (async/chan)
        multiplexer (create-multiplexer nodes-map stop-ch)
        metronome (create-metronome nodes-map stop-ch tick-interval-ms)
        all-peers (mapv :peer all-nodes)]

    ;; Push an omniscient view to all honest nodes
    (doseq [node h-nodes]
      (async/put! (:events-in node) {:type :receive-push-view
                                     :view (take 20 (shuffle all-peers))}))

    {:nodes nodes-map
     :h-nodes h-nodes
     :stop-ch stop-ch
     :multiplexer multiplexer
     :metronome metronome}))

(defn- stop-network
  [network]
  (when-let [stop-ch (:stop-ch network)]
    (async/put! stop-ch true)
    (async/close! stop-ch))
  (doseq [node (vals (:nodes network))]
    (if (= (:type node) :byzantine)
      (do
        (async/put! (:stop-ch (:node node)) true)
        (async/close! (:stop-ch (:node node))))
      (shell-core/stop-node (:node node)))))

(defn -main []
  (println "Starting Contagion E2E Simulator...")
  (println (format "Network Topology: %d total nodes (%d honest, %d byzantine)" total-nodes honest-nodes byzantine-nodes))
  (let [network (start-network)
        app-out-channels (mapv :app-out (:h-nodes network))
        delivery-tracker (atom {})
        done-ch (async/chan)]

    ;; Telemetry Sink
    (async/go-loop []
      (let [[val port] (async/alts! (conj app-out-channels done-ch))]
        (if (= port done-ch)
          nil
          (do
            (when (and (map? val) (= (:event-name val) :on-deliver))
              (let [payload-str (String. ^bytes (:payload val) "UTF-8")
                    payload-map (clojure.edn/read-string payload-str)
                    broadcast-id (:id payload-map)
                    pubkey (some (fn [[k v]] (when (= (:app-out v) port) k)) (:nodes network))]
                (let [tracker @delivery-tracker
                      already-delivered? (contains? (get tracker broadcast-id #{}) pubkey)]
                  (swap! delivery-tracker update broadcast-id (fnil conj #{}) pubkey)
                  (let [current-deliveries (count (get @delivery-tracker broadcast-id))]
                    (when (and (not already-delivered?) (zero? (mod current-deliveries 10)))
                      (println (format "Broadcast %s reached %d nodes" broadcast-id current-deliveries)))
                    (when (and (= current-deliveries honest-nodes) (not already-delivered?))
                      (swap! broadcasts-delivered inc)
                      (let [end-time (System/currentTimeMillis)
                            start-time (get @broadcast-start-times broadcast-id)
                            duration (- end-time start-time)]
                        (swap! total-consensus-time + duration)
                        (println (format "✅ Broadcast %s delivered to ALL %d honest nodes in %d ms" broadcast-id honest-nodes duration))
                        (when (>= @broadcasts-delivered 10)
                          (async/put! done-ch true))))))))
            (recur)))))

    ;; Scenario Loop
    (async/go-loop [iteration 1]
      (when (< @broadcasts-initiated 10)
        (let [initiator (rand-nth (:h-nodes network))
              broadcast-id (str (java.util.UUID/randomUUID))
              payload-str (pr-str {:id broadcast-id :data (str "test-payload-" iteration)})
              payload-bytes (.getBytes ^String payload-str "UTF-8")]
          (swap! broadcasts-initiated inc)
          (swap! broadcast-start-times assoc broadcast-id (System/currentTimeMillis))
          (println (format "Injecting broadcast %s via honest node %s..." broadcast-id (subs (:pubkey-hex initiator) 0 8)))
          (async/put! (:events-in initiator) {:type :contagion-broadcast
                                              :payload payload-bytes
                                              :rng (java.util.Random.)
                                              :private-key (:private (:keys initiator))
                                              :public-key (:public (:keys initiator))}))
        (async/<! (async/timeout 3000))
        (recur (inc iteration))))

    ;; Wait for completion
    (async/<!! done-ch)
    (println "\n========================================")
    (println "SIMULATION COMPLETE")
    (println "========================================")
    (println "Broadcasts Initiated:               " @broadcasts-initiated)
    (println "Broadcasts Delivered to ALL Honest: " @broadcasts-delivered)
    (println "Average Time to Global Consensus:   " (int (/ @total-consensus-time @broadcasts-delivered)) "ms")
    (println "========================================")

    (stop-network network)
    (System/exit 0)))
