(ns bitecho.simulator.basalt-e2e
  "Isolated integration test proving that Basalt peer sampling converges."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]))

(def total-nodes 15)
(def tick-interval-ms 100)
(def total-ticks 50)

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
            (when (and (map? val) (= (:type val) :send-push-view))
              (doseq [t (:targets val)]
                (let [target-hex (if (string? t) t (:pubkey t))
                      target-node (get nodes target-hex)]
                  (when target-node
                    (async/put! (:in-ch target-node) {:type :receive-push-view :view (:view val)})))))
            (recur)))))))

(defn- run-node-loop
  [node stop-ch]
  (async/go-loop []
    (let [[val port] (async/alts! [(:in-ch node) stop-ch])]
      (when (not= port stop-ch)
        (let [event val
              {new-state :state commands :commands} (sm/handle-event @(:state node) event)]
          (reset! (:state node) new-state)
          (doseq [cmd commands]
            (when (= (:type cmd) :send-push-view)
              (async/put! (:out-ch node) cmd))))
        (recur)))))

(defn -main []
  (println "Starting Basalt E2E Simulator...")
  (let [nodes (mapv create-node (range total-nodes))
        nodes-map (into {} (map (juxt :pubkey-hex identity) nodes))
        stop-ch (async/chan)
        router (route-events nodes-map stop-ch)
        node-loops (mapv #(run-node-loop % stop-ch) nodes)
        all-peers (mapv :peer nodes)]

    ;; Bootstrap: push omniscient view
    (doseq [node nodes]
      (let [initial-view (take 20 (shuffle all-peers))]
        (async/put! (:in-ch node) {:type :receive-push-view :view initial-view})))

    ;; Wait for initial views to process
    (async/<!! (async/timeout 100))

    ;; Tick loop
    (dotimes [i total-ticks]
      (doseq [node nodes]
        (async/put! (:in-ch node) {:type :tick :rng (java.util.Random.)}))
      (async/<!! (async/timeout tick-interval-ms)))

    ;; Wait a bit for final events
    (println "Waiting for events to drain...")
    (async/<!! (async/timeout 3000))

    ;; Stop network
    (async/put! stop-ch true)

    ;; Analyze topology
    (let [view-sizes (map #(count (basalt/extract-peers (:basalt-view @(:state %)))) nodes)
          min-view (apply min view-sizes)
          max-view (apply max view-sizes)
          avg-view (float (/ (reduce + view-sizes) total-nodes))]
      (println (format "View sizes: min=%d, max=%d, avg=%.2f" min-view max-view avg-view))
      (if (>= min-view 10)
        (do
          (println "✅ Basalt topology converged successfully.")
          (System/exit 0))
        (do
          (println "❌ Basalt topology failed to converge! Views are too small.")
          (System/exit 1))))))
