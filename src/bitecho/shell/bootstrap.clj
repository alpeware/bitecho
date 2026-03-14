(ns bitecho.shell.bootstrap
  "Entry point for the Bitecho bootstrap node.
   Initializes the core.async shell and the Genesis state."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.shell.core :as core]))

(defn init-node
  "Initializes the bootstrap shell."
  [node-pubkey]
  (let [;; Genesis peer is typically itself or hardcoded network starts.
        ;; For bootstrap, we might start with an empty list or known peers.
        initial-peers []]
    (core/start-node initial-peers node-pubkey)))

(defn -main
  "Main executable entry point for the bootstrap node.
   Stubs the datachannel/IO sinks and focuses purely on initializing
   the go-loop shell and the Genesis state."
  [& _args]
  (println "Starting Bitecho Bootstrap Node...")
  (let [;; Generate a node key for this instance.
        node-keys (crypto/generate-keypair)
        node-pubkey (basalt/bytes->hex (:public node-keys))
        node (init-node node-pubkey)]
    (println "Bootstrap shell created:")
    (println (keys node))
    (println "Bootstrap initialization complete (IO sinks stubbed).")))
