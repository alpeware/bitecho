(ns bitecho.simulator.murmur-e2e
  "Isolated integration test proving that pure Murmur gossip probabilistically reaches a majority of the network before the cache evicts it."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]))

(def total-nodes
  "Total nodes in the isolated Murmur network"
  15)

(def tick-interval-ms
  "Tick interval, though not used heavily in this pure Murmur test"
  100)

(defn- create-node
  [i]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        initial-state (sm/init-state [] pubkey-hex)
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
              (case (:type val)
                :send-push-view
                (doseq [t (:targets val)]
                  (let [target-hex (if (string? t) t (:pubkey t))
                        target-node (get nodes target-hex)]
                    (when target-node
                      (async/put! (:in-ch target-node) {:type :receive-push-view :view (:view val)}))))

                :send-gossip
                (doseq [t (:targets val)]
                  (let [target-hex (if (string? t) t (:pubkey t))
                        target-node (get nodes target-hex)]
                    (when target-node
                      (async/put! (:in-ch target-node) {:type :receive-gossip
                                                        :message (:message val)
                                                        :rng (java.util.Random.)}))))
                nil))
            (recur)))))))

(defn- run-node-loop
  [node stop-ch nodes-received broadcast-id]
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
              nil))

          ;; Track received gossip
          (when (and (= (:type event) :receive-gossip)
                     (= (:message-id (:message event)) broadcast-id))
            (swap! nodes-received conj (:pubkey-hex node))))
        (recur)))))

(defn -main
  "Starts the isolated Murmur simulation, injecting a single broadcast and verifying majority reach."
  []
  (with-redefs [sieve/validate-message identity]
    (println "Starting Murmur E2E Simulator...")
    (let [nodes (mapv create-node (range total-nodes))
          nodes-map (into {} (map (juxt :pubkey-hex identity) nodes))
          stop-ch (async/chan)
          _router (route-events nodes-map stop-ch)
          all-peers (mapv :peer nodes)
          nodes-received (atom #{})
          broadcast-id (basalt/bytes->hex (crypto/sha256 (.getBytes "test-payload" "UTF-8")))]

      ;; Run node loops
      (doseq [node nodes]
        (run-node-loop node stop-ch nodes-received broadcast-id))

      ;; Bootstrap: push omniscient view
      (doseq [node nodes]
        (let [initial-view (take 20 (shuffle all-peers))]
          (async/put! (:in-ch node) {:type :receive-push-view :view initial-view})))

      ;; Wait for initial views to process
      (async/<!! (async/timeout 100))

      ;; Inject a broadcast into a random node
      (let [initiator (rand-nth nodes)
            payload-bytes (.getBytes "test-payload" "UTF-8")]
        (println (format "Injecting raw :broadcast via node %s..." (subs (:pubkey-hex initiator) 0 8)))
        (async/put! (:in-ch initiator) {:type :broadcast
                                        :payload payload-bytes
                                        :rng (java.util.Random.)
                                        :private-key (:private (:keys initiator))
                                        :public-key (:public (:keys initiator))}))

      ;; Wait for the gossip storm to settle
      (println "Waiting for gossip to propagate...")
      (async/<!! (async/timeout 3000))

      ;; Stop network
      (async/close! stop-ch)

      ;; Analyze gossip reach
      (let [reached-count (count @nodes-received)
            majority (Math/ceil (/ total-nodes 2.0))]
        (println (format "Broadcast reached %d/%d nodes (majority threshold: %d)" reached-count total-nodes (int majority)))
        (if (>= reached-count majority)
          (do
            (println "✅ Murmur gossip successfully reached a majority of the network.")
            (System/exit 0))
          (do
            (println "❌ Murmur gossip failed to reach a majority!")
            (throw (ex-info "Murmur gossip failed to reach majority before dying out"
                            {:reached reached-count
                             :majority majority}))
            (System/exit 1)))))))
