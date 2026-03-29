(ns bitecho.simulator.main
  "The main execution script for the Chaos Mesh Simulator.
   Boots the network and executes the pure gossip contagion E2E."
  (:require [bitecho.simulator.contagion-e2e :as e2e]))

(defn -main
  "Starts the simulator."
  [& _args]
  (e2e/-main))

(defn calculate-ratio
  "Calculates ratio of dropped Byzantine packets vs successful honest deliveries."
  [dropped successful]
  (if (zero? successful)
    (str "Undefined (" successful " successful)")
    (format "%.2f : 1" (float (/ dropped successful)))))

(defn calculate-circuit-lock-time
  "Measures time-to-circuit-lock."
  [start end]
  (- end start))
