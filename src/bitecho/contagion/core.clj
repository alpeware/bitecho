(ns bitecho.contagion.core
  "Core logic for Contagion reliable broadcast protocol."
  (:require [bitecho.basalt.core :as basalt]
            [clojure.set :as set]))

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

(defn lazy-pull
  "Processes an incoming anti-entropy summary.
   Takes the set of locally known message IDs and the remote summary (set of message IDs).
   Returns the set of message IDs that are present in the remote summary but missing locally.
   These are the IDs that should be requested via lazy pull."
  [local-known-ids remote-summary]
  (set/difference remote-summary local-known-ids))
