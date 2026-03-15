(ns bitecho.shell.agent
  "Entry point for the Bitecho agent node.
   Connects to a bootstrap node and initializes its flow network."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.shell.core :as core]
            [bitecho.shell.persistence :as persistence]
            [bitecho.state-machine :as sm]))

(defn init-node
  "Initializes the agent shell given a bootstrap peer."
  [bootstrap-peer node-pubkey]
  (let [initial-peers [bootstrap-peer]
        snapshot-filename (str "snapshot-" node-pubkey ".edn")
        initial-state (or (persistence/load-state-from-disk snapshot-filename)
                          (sm/init-state initial-peers node-pubkey))]
    (core/start-node initial-state snapshot-filename)))

(defn -main
  "Main executable entry point for the agent node.
   Takes an optional bootstrap IP/port argument."
  [& _args]
  (println "Starting Bitecho Agent Node...")
  (let [;; Generate a node key for this instance.
        node-keys (crypto/generate-keypair)
        node-pubkey (basalt/bytes->hex (:public node-keys))
        ;; In a real implementation we'd parse this from CLI or config.
        default-bootstrap {:pubkey "0000" :ip "127.0.0.1" :port 8000 :age 0 :hash "1234"}
        node (init-node default-bootstrap node-pubkey)]
    (println "Agent shell created using bootstrap peer:")
    (println default-bootstrap)
    (println "Node channels:" (keys node))
    (println "Agent initialization complete (IO sinks stubbed).")))
