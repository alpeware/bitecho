(ns bitecho.shell.agent
  "Entry point for the Bitecho agent node.
   Connects to a bootstrap node and initializes its flow network."
  (:require [bitecho.shell.flow :as flow]
            [clojure.core.async :as async]))

(defn init-node
  "Purely initializes the agent flow topology given a bootstrap peer,
   returning it without starting IO sinks."
  [bootstrap-peer]
  (let [net-in (async/chan 100)
        events-in (async/chan 100)
        net-out (async/chan 100)
        events-out (async/chan 100)
        initial-peers [bootstrap-peer]
        topology (flow/create-topology initial-peers net-in events-in net-out events-out)]
    topology))

(defn -main
  "Main executable entry point for the agent node.
   Takes an optional bootstrap IP/port argument."
  [& _args]
  (println "Starting Bitecho Agent Node...")
  (let [;; In a real implementation we'd parse this from CLI or config.
        default-bootstrap {:pubkey "0000" :ip "127.0.0.1" :port 8000 :age 0 :hash "1234"}
        topology (init-node default-bootstrap)]
    (println "Agent Flow topology created using bootstrap peer:")
    (println default-bootstrap)
    (println "Topology keys:" (keys topology))
    (println "Agent initialization complete (IO sinks stubbed).")))
