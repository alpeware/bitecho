(ns bitecho.shell.agent
  "Entry point for the Bitecho agent node.
   Connects to a bootstrap node and initializes its flow network."
  (:require [bitecho.shell.core :as core]))

(defn init-node
  "Initializes the agent shell given a bootstrap peer."
  [bootstrap-peer]
  (let [initial-peers [bootstrap-peer]]
    (core/start-node initial-peers)))

(defn -main
  "Main executable entry point for the agent node.
   Takes an optional bootstrap IP/port argument."
  [& _args]
  (println "Starting Bitecho Agent Node...")
  (let [;; In a real implementation we'd parse this from CLI or config.
        default-bootstrap {:pubkey "0000" :ip "127.0.0.1" :port 8000 :age 0 :hash "1234"}
        node (init-node default-bootstrap)]
    (println "Agent shell created using bootstrap peer:")
    (println default-bootstrap)
    (println "Node channels:" (keys node))
    (println "Agent initialization complete (IO sinks stubbed).")))
