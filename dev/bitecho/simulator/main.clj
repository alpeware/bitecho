(ns bitecho.simulator.main
  "The main execution script for the Chaos Mesh Simulator.
   Boots the network and executes the pure gossip contagion E2E."
  (:require [bitecho.simulator.contagion-e2e :as e2e]))

(defn -main
  "Starts the simulator."
  [& _args]
  (e2e/-main))
