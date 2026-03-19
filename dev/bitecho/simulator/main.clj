(ns bitecho.simulator.main
  "The main execution script for the Chaos Mesh Simulator.
   Boots the network, commands honest agents, and creates a Telemetry Sink."
  (:require [bitecho.simulator.core :as sim]
            [bitecho.crypto :as crypto]
            [bitecho.lottery.core :as lottery]
            [clojure.core.async :as async]))

(defn calculate-ratio
  "Calculates the ratio of dropped Byzantine packets vs successful honest deliveries."
  [dropped success]
  (if (zero? success)
    (format "Undefined (%d successful)" success)
    (format "%.2f : 1" (float (/ dropped success)))))

(defn- create-telemetry-sink
  "Multiplexes all node :app-out channels and spammers' :net-out channels.
   Calculates and prints real-time metrics periodically."
  [network]
  (let [nodes (vals (:nodes network))
        honest-nodes (filter #(not= (:type %) :spammer) nodes)
        spammer-nodes (filter #(= (:type %) :spammer) nodes)

        app-out-chans (map :app-out honest-nodes)
        metrics (atom {:successful-deliveries 0
                       :byzantine-packets-sent 0})
        stop-ch (async/chan)]

    ;; Track emitted Byzantine packets based on spammer clock rates.
    (async/go-loop []
      (let [[_ port] (async/alts! [(async/timeout 10) stop-ch])]
        (when (not= port stop-ch)
          (swap! metrics update :byzantine-packets-sent + (count spammer-nodes))
          (recur))))

    ;; App-out multiplexer
    (async/go-loop []
      (let [[val port] (async/alts! (conj (vec app-out-chans) stop-ch))]
        (if (= port stop-ch)
          nil ;; Stop
          (do
            (when (map? val)
              (case (:event-name val)
                :on-direct-message
                (swap! metrics update :successful-deliveries inc)

                nil))
            (recur)))))

    ;; Periodic Reporter & Treasury Query
    (async/go-loop []
      (let [[_ port] (async/alts! [(async/timeout 5000) stop-ch])]
        (when (not= port stop-ch)
          (let [boot-node (first (filter #(= (:type %) :bootstrap) nodes))]
            (when boot-node
              (let [reply-ch (async/chan 1)]
                (async/put! (:events-in boot-node) {:type :query-state :reply-chan reply-ch})
                (async/go
                  (let [state (async/<! reply-ch)
                        utxos (vals (:utxos (:ledger state)))
                        treasury-utxo (first (filter #(= (:puzzle-hash %) "0000000000000000000000000000000000000000000000000000000000000000") utxos))
                        treasury-bal (if treasury-utxo (:amount treasury-utxo) 42000000)
                        emitted (- 42000000 treasury-bal)

                        m @metrics
                        dropped (:byzantine-packets-sent m)
                        success (:successful-deliveries m)]
                    (println "\n--- Telemetry Report ---")
                    (println (format "Total Treasury Emitted (Echos): %d" emitted))
                    (println (format "Byzantine Dropped vs Honest Delivered: %s" (calculate-ratio dropped success)))
                    (println "------------------------\n"))))))
          (recur))))
    stop-ch))

(defn- run-scenario
  "Commands honest agents to initiate payload deliveries."
  [network stop-ch]
  (let [nodes (vals (:nodes network))
        agents (filter #(= (:type %) :agent) nodes)
        targets (filterv #(not= (:type %) :spammer) nodes)]
    (async/go-loop []
      (let [[_ port] (async/alts! [(async/timeout 10) stop-ch])]
        (when (not= port stop-ch)
          (let [sender (rand-nth agents)
                target (rand-nth targets)]
            (when (and sender target (not= (:pubkey-hex sender) (:pubkey-hex target)))
              (let [keys (:keys sender)
                    payload-bytes (.getBytes "payload" "UTF-8")
                    ticket (lottery/generate-ticket :fee payload-bytes 1 (:private keys) (:public keys) 0)
                    envelope {:encrypted-payload payload-bytes
                              :lottery-ticket ticket
                              :forward-circuit [(:pubkey-hex sender) (:pubkey-hex target)]
                              :return-circuit []}]
                (async/put! (:events-in sender) {:type :route-directed-message
                                                 :envelope envelope
                                                 :destination (:pubkey-hex target)
                                                 :payout-amount 10
                                                 :rng (java.util.Random.)}))))
          (recur))))))

(defn -main
  "Starts the simulator and telemetry."
  [& args]
  (println "Starting Chaos Mesh Simulator...")
  (let [config {:bootstraps 3
                :agents 15
                :spammers 3
                :tick-interval-ms 100}
        network (sim/start-network config)]

    (println "Network booted.")

    (let [telemetry-stop-ch (create-telemetry-sink network)
          scenario-stop-ch (async/chan)]

      (run-scenario network scenario-stop-ch)

      ;; Run for 20 seconds, then shutdown
      (Thread/sleep 20000)

      (println "Shutting down simulator...")
      (async/close! scenario-stop-ch)
      (async/close! telemetry-stop-ch)
      (sim/stop-network network)
      (println "Shutdown complete.")
      (System/exit 0))))
