(ns bitecho.shell.bootstrap
  "Entry point for the Bitecho bootstrap node.
   Initializes the core.async shell and the Genesis state."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.shell.core :as core]
            [bitecho.shell.persistence :as persistence]
            [bitecho.state-machine :as sm]))

(defn init-node
  "Initializes the bootstrap shell."
  [node-pubkey private-key]
  (let [snapshot-filename (str "snapshot-" node-pubkey ".edn")
        ;; Load state from disk if available, otherwise init genesis state
        initial-state (or (persistence/load-state-from-disk snapshot-filename)
                          (sm/init-state [] node-pubkey))]
    (core/start-node initial-state private-key snapshot-filename)))

(defn -main
  "Main executable entry point for the bootstrap node.
   Stubs the datachannel/IO sinks and focuses purely on initializing
   the go-loop shell and the Genesis state."
  [& _args]
  (println "Starting Bitecho Bootstrap Node...")
  (let [;; Generate a node key for this instance.
        node-keys (crypto/generate-keypair)
        node-pubkey (basalt/bytes->hex (:public node-keys))
        node (init-node node-pubkey (:private node-keys))]
    (println "Bootstrap shell created:")
    (println (keys node))
    (println "Bootstrap initialization complete (IO sinks stubbed).")))
