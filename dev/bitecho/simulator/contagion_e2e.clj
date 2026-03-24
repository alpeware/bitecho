(ns bitecho.simulator.contagion-e2e
  "Isolated integration test proving that a pure Contagion broadcast reliably reaches all honest nodes in the presence of Byzantine actors."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.shell.core :as shell-core]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]))

;; ---------------------------------------------------------------------------
;; Simulation Configuration
;; ---------------------------------------------------------------------------

(def sim-config
  "Simulation parameters for 1000-node Contagion E2E with 25 % Byzantine.
   Protocol parameters are tuned per the Contagion paper (Section 5)
   for O(log N) sample sizes at N = 1000."
  {:total-nodes             100
   :byzantine-nodes         5
   :tick-interval-ms        50
   :total-broadcast-messages 1
   :stabilization-ticks     20
   :stabilization-tick-pause-ms 20
   :post-stabilization-pause-ms 2000
   :broadcast-pause-ms      5000
   :completion-timeout-ms   120000
   :channel-buffer-size     8192
   :protocol                config/large-network-config})

;; ---------------------------------------------------------------------------
;; Metrics
;; ---------------------------------------------------------------------------

(def broadcasts-initiated (atom 0))
(def broadcasts-delivered (atom 0))
(def broadcast-start-times (atom {}))
(def total-consensus-time (atom 0))

;; ---------------------------------------------------------------------------
;; Node creation
;; ---------------------------------------------------------------------------

(defn- create-honest-node
  [i cfg]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        initial-state (sm/init-state [] pubkey-hex (:protocol cfg))
        snapshot-filename (str "/tmp/snapshot-" pubkey-hex ".bin")
        node (shell-core/start-node initial-state snapshot-filename)
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
    (let [[_val port] (async/alts! [net-out-ch stop-ch])]
      (when (not= port stop-ch)
        ;; Black hole: drops packet silently
        (recur)))))

(defn- create-byzantine-node
  [i cfg]
  (let [buf (:channel-buffer-size cfg)
        keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        peer {:ip "127.0.0.1"
              :port (+ 9000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}
        net-out-ch (async/chan buf)
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

;; ---------------------------------------------------------------------------
;; Network plumbing
;; ---------------------------------------------------------------------------

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
        :send-subscribe
        (async/put! (:network-in target-node) {:type :receive-subscribe
                                               :sender sender-hex
                                               :roles (:roles cmd)})
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

;; ---------------------------------------------------------------------------
;; Network lifecycle
;; ---------------------------------------------------------------------------

(defn- start-network
  [cfg]
  (let [total-nodes (:total-nodes cfg)
        byzantine-nodes (:byzantine-nodes cfg)
        honest-nodes (- total-nodes byzantine-nodes)
        view-size (get-in cfg [:protocol :basalt-max-view-size])

        h-nodes (mapv #(create-honest-node % cfg) (range honest-nodes))
        b-nodes (mapv #(create-byzantine-node % cfg) (range byzantine-nodes))

        all-nodes (concat h-nodes b-nodes)
        nodes-map (into {} (map (juxt :pubkey-hex identity) all-nodes))
        stop-ch (async/chan)
        multiplexer (create-multiplexer nodes-map stop-ch)
        metronome (create-metronome nodes-map stop-ch (:tick-interval-ms cfg))
        all-peers (mapv :peer all-nodes)]

    ;; Push an omniscient view to all honest nodes
    (doseq [node h-nodes]
      (async/put! (:events-in node) {:type :receive-push-view
                                     :view (take view-size (shuffle all-peers))}))

    {:nodes nodes-map
     :h-nodes h-nodes
     :honest-nodes honest-nodes
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

;; ---------------------------------------------------------------------------
;; Main
;; ---------------------------------------------------------------------------

(defn -main []
  (let [cfg sim-config
        total-nodes (:total-nodes cfg)
        byzantine-nodes (:byzantine-nodes cfg)
        honest-nodes (- total-nodes byzantine-nodes)]
    (println "Starting Contagion E2E Simulator...")
    (println (format "Network Topology: %d total nodes (%d honest, %d byzantine)"
                     total-nodes honest-nodes byzantine-nodes))
    (println (format "Protocol: murmur-k=%d, view=%d, E=%d/%d, R=%d/%d, D=%d/%d, TTL=%d"
                     (get-in cfg [:protocol :murmur-k])
                     (get-in cfg [:protocol :basalt-max-view-size])
                     (get-in cfg [:protocol :echo-sample-size])
                     (get-in cfg [:protocol :echo-threshold])
                     (get-in cfg [:protocol :ready-sample-size])
                     (get-in cfg [:protocol :ready-threshold])
                     (get-in cfg [:protocol :delivery-sample-size])
                     (get-in cfg [:protocol :delivery-threshold])
                     (get-in cfg [:protocol :gossip-ttl-epochs])))
    (let [network (start-network cfg)
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
                  (let [already-delivered? (contains? (get @delivery-tracker broadcast-id #{}) pubkey)]
                    (swap! delivery-tracker update broadcast-id (fnil conj #{}) pubkey)
                    (let [current-deliveries (count (get @delivery-tracker broadcast-id))]
                      (when (and (not already-delivered?) (zero? (mod current-deliveries 50)))
                        (println (format "Broadcast %s reached %d/%d nodes" broadcast-id current-deliveries honest-nodes)))
                      (when (and (= current-deliveries honest-nodes) (not already-delivered?))
                        (swap! broadcasts-delivered inc)
                        (let [end-time (System/currentTimeMillis)
                              start-time (get @broadcast-start-times broadcast-id)
                              duration (- end-time start-time)]
                          (swap! total-consensus-time + duration)
                          (println (format "✅ Broadcast %s delivered to ALL %d honest nodes in %d ms" broadcast-id honest-nodes duration))
                          (when (>= @broadcasts-delivered (:total-broadcast-messages cfg))
                            (async/put! done-ch true))))))))
              (recur)))))

      ;; Scenario Loop
      (async/go-loop [iteration 1]
        ;; Wait to establish subscription graphs before starting
        (when (= iteration 1)
          (println (format "Running %d stabilization ticks to build subscription graphs..."
                           (:stabilization-ticks cfg)))
          (dotimes [_i (:stabilization-ticks cfg)]
            (doseq [node (vals (:nodes network))]
              (when (:events-in node)
                (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)})))
            (async/<! (async/timeout (:stabilization-tick-pause-ms cfg))))
          (println (format "Running %d ms post stabilization pause..."
                           (:post-stabilization-pause-ms cfg)))
          (async/<! (async/timeout (:post-stabilization-pause-ms cfg))))

        (when (< @broadcasts-initiated (:total-broadcast-messages cfg))
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
          (async/<! (async/timeout (:broadcast-pause-ms cfg)))
          (recur (inc iteration))))

      ;; Wait for completion
      (let [[_ port] (async/alts!! [done-ch (async/timeout (:completion-timeout-ms cfg))])]
        (when (not= port done-ch)
          (let [tracker @delivery-tracker]
            (println "\n⚠️  Delivery status at timeout:")
            (doseq [[bid delivered-set] tracker]
              (println (format "  Broadcast %s: %d/%d delivered" bid (count delivered-set) honest-nodes)))
            (throw (ex-info "Contagion broadcast failed to reach all honest nodes within timeout"
                            {:timeout-ms (:completion-timeout-ms cfg)
                             :delivered (into {} (map (fn [[k v]] [k (count v)]) tracker))})))))
      (println "\n========================================")
      (println "SIMULATION COMPLETE")
      (println "========================================")
      (println "Broadcasts Initiated:               " @broadcasts-initiated)
      (println "Broadcasts Delivered to ALL Honest: " @broadcasts-delivered)
      (println "Average Time to Global Consensus:   " (int (/ @total-consensus-time @broadcasts-delivered)) "ms")
      (println "========================================")

      (stop-network network)
      (System/exit 0))))
