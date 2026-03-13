(ns bitecho.shell.bootstrap
  "Entry point for the Bitecho bootstrap node.
   Initializes the core.async.flow network and the Genesis state."
  (:require [bitecho.shell.flow :as flow]
            [clojure.core.async :as async]))

(defn init-node
  "Purely initializes the node flow topology, returning it without starting
   blocking IO. Used for testing and setup."
  []
  (let [net-in (async/chan 100)
        events-in (async/chan 100)
        net-out (async/chan 100)
        events-out (async/chan 100)
        ;; Genesis peer is typically itself or hardcoded network starts.
        ;; For bootstrap, we might start with an empty list or known peers.
        initial-peers []
        topology (flow/create-topology initial-peers net-in events-in net-out events-out)]
    topology))

(defn -main
  "Main executable entry point for the bootstrap node.
   Stubs the datachannel/IO sinks and focuses purely on initializing
   the flow network and the Genesis state."
  [& _args]
  (println "Starting Bitecho Bootstrap Node...")
  (let [topology (init-node)]
    (println "Flow topology created:")
    (println (keys topology))
    (println "Bootstrap initialization complete (IO sinks stubbed).")))
