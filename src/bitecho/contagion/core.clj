(ns bitecho.contagion.core
  "Core logic for Contagion reliable broadcast protocol."
  (:require [bitecho.basalt.core :as basalt]))

(defn generate-summary
  "Generates an anti-entropy summary by targeting a random peer from the Basalt view.
   Takes an RNG instance, the local Basalt view, and a set of known message IDs.
   Returns a map with :target and :summary, or nil if the view is empty."
  [^java.util.Random rng view known-ids]
  (let [targets (basalt/select-peers rng view 1)
        target (first targets)]
    (if target
      {:target target
       :summary known-ids}
      nil)))
