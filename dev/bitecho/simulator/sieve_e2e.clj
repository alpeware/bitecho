(ns bitecho.simulator.sieve-e2e
  "Isolated integration test proving that Sieve echoes correctly track E-hat thresholds and emit :send-contagion-ready."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]))

(def sim-config
  "Simulation parameters for the Sieve E2E test."
  {:total-nodes 15
   :protocol    config/default-config})

(defn- create-node
  [i cfg]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        initial-state (sm/init-state [] pubkey-hex (:protocol cfg))
        peer {:ip "127.0.0.1"
              :port (+ 8000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}]
    {:pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :state (atom initial-state)
     :in-ch (async/chan 1024)
     :out-ch (async/chan 1024)}))

(defn- route-events
  [nodes stop-ch]
  (let [out-channels (mapv :out-ch (vals nodes))]
    (async/go-loop []
      (let [[val port] (async/alts! (conj out-channels stop-ch))]
        (if (= port stop-ch)
          nil
          (do
            (when (map? val)
              (let [cmd val
                    targets (or (:targets cmd) (when (:target cmd) [(:target cmd)]))
                    sender-hex (some (fn [[k v]] (when (= (:out-ch v) port) k)) nodes)]
                (doseq [t targets]
                  (let [target-hex (if (string? t) t (:pubkey t))
                        target-node (get nodes target-hex)]
                    (when target-node
                      (case (:type cmd)
                        :send-push-view
                        (async/put! (:in-ch target-node) {:type :receive-push-view :view (:view cmd)})
                        :send-gossip
                        (async/put! (:in-ch target-node) {:type :receive-gossip
                                                          :message (:message cmd)
                                                          :rng (java.util.Random.)})
                        :send-subscribe
                        (async/put! (:in-ch target-node) {:type :receive-subscribe
                                                          :sender sender-hex
                                                          :roles (:roles cmd)})
                        :send-sieve-echo
                        (async/put! (:in-ch target-node) {:type :receive-sieve-echo
                                                          :sender sender-hex
                                                          :message-id (:message-id cmd)
                                                          :rng (java.util.Random.)})
                        :send-contagion-ready
                        (async/put! (:in-ch target-node) {:type :receive-contagion-ready
                                                          :sender sender-hex
                                                          :message-id (:message-id cmd)
                                                          :rng (java.util.Random.)})
                        nil))))))
            (recur)))))))

(defn- run-node-loop
  [node stop-ch nodes-ready]
  (async/go-loop []
    (let [[val port] (async/alts! [(:in-ch node) stop-ch])]
      (when (not= port stop-ch)
        (let [event val
              {new-state :state commands :commands} (sm/handle-event @(:state node) event)]
          (reset! (:state node) new-state)
          (doseq [cmd commands]
            (case (:type cmd)
              :send-push-view (async/put! (:out-ch node) cmd)
              :send-gossip (async/put! (:out-ch node) cmd)
              :send-subscribe (async/put! (:out-ch node) cmd)
              :send-sieve-echo (async/put! (:out-ch node) cmd)
              :send-contagion-ready
              (do
                (async/put! (:out-ch node) cmd)
                (swap! nodes-ready conj (:pubkey-hex node)))
              nil)))
        (recur)))))

(defn -main
  "Starts the isolated Sieve simulation, verifying E-hat thresholds are met."
  []
  (let [cfg sim-config
        total-nodes (:total-nodes cfg)
        view-size (get-in cfg [:protocol :basalt-max-view-size])]
    (println "Starting Sieve E2E Simulator...")
    (println (format "Config: %d nodes, E-size=%d, E-hat=%d"
                     total-nodes
                     (get-in cfg [:protocol :echo-sample-size])
                     (get-in cfg [:protocol :echo-threshold])))
    (let [nodes (mapv #(create-node % cfg) (range total-nodes))
          nodes-map (into {} (map (juxt :pubkey-hex identity) nodes))
          stop-ch (async/chan)
          _router (route-events nodes-map stop-ch)
          all-peers (mapv :peer nodes)
          nodes-ready (atom #{})
          payload-bytes (.getBytes "test-sieve-payload" "UTF-8")]

      ;; Run node loops
      (doseq [node nodes]
        (run-node-loop node stop-ch nodes-ready))

      ;; Bootstrap: push omniscient view
      (doseq [node nodes]
        (let [initial-view (take view-size (shuffle all-peers))]
          (async/put! (:in-ch node) {:type :receive-push-view :view initial-view})))

      ;; Wait for initial views to process
      (async/<!! (async/timeout 100))

      ;; Network Stabilization: Ticks for subscription building
      (println "Running stabilization ticks to build subscription graphs...")
      (dotimes [_i 100]
        (doseq [node nodes]
          (async/put! (:in-ch node) {:type :tick :rng (java.util.Random.)}))
        (async/<!! (async/timeout 100)))

      ;; Inject Sieve Broadcast
      (let [initiator (rand-nth nodes)]
        (println (format "Injecting Sieve :contagion-broadcast via node %s..." (subs (:pubkey-hex initiator) 0 8)))
        (async/put! (:in-ch initiator) {:type :contagion-broadcast
                                        :payload payload-bytes
                                        :rng (java.util.Random.)
                                        :private-key (:private (:keys initiator))
                                        :public-key (:public (:keys initiator))}))

      ;; Wait for Sieve echoes and ready transitions
      (println "Waiting for Sieve echoes to propagate and reach E-hat thresholds...")
      (async/<!! (async/timeout 3000))

      ;; Stop network
      (async/close! stop-ch)

      ;; Analyze Sieve reach
      (let [ready-count (count @nodes-ready)
            majority (Math/ceil (/ total-nodes 2.0))]
        (println (format "Nodes emitting :send-contagion-ready: %d/%d (majority threshold: %d)" ready-count total-nodes (int majority)))
        (if (>= ready-count majority)
          (do
            (println "✅ Sieve correctly tracked E-hat thresholds and emitted ready.")
            (System/exit 0))
          (do
            (println "❌ Sieve echoes failed to reach E-hat or failed to emit ready!")
            (throw (ex-info "Sieve threshold tracking failed"
                            {:ready-count ready-count
                             :majority majority}))
            (System/exit 1)))))))
