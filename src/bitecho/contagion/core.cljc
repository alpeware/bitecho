(ns bitecho.contagion.core
  "Core logic for Contagion reliable broadcast protocol."
  (:require [bitecho.basalt.core :as basalt]
            [clojure.set :as set]))

(defn generate-summary
  "Generates an anti-entropy summary by targeting a random peer from the Basalt view.
   Takes an RNG instance, the local Basalt view, a set of known message IDs,
   and an optional 4th argument `max-ids-or-filter` (either an integer max ID count
   or a set/predicate filtering eligible trailing-epoch message IDs).
   Returns a map with :target and :summary, or nil if the view is empty."
  ([rng view known-ids]
   (generate-summary rng view known-ids nil))
  ([rng view known-ids max-ids-or-filter]
   (let [targets (basalt/select-peers rng view 1)
         target (first targets)]
     (if target
       (let [bounded-ids (cond
                           (nil? max-ids-or-filter)
                           known-ids

                           (set? max-ids-or-filter)
                           (set/intersection (set known-ids) max-ids-or-filter)

                           (and (integer? max-ids-or-filter)
                                (pos? (long max-ids-or-filter))
                                (> (count known-ids) (long max-ids-or-filter)))
                           (into #{} (take (long max-ids-or-filter) (sort known-ids)))

                           (fn? max-ids-or-filter)
                           (into #{} (filter max-ids-or-filter known-ids))

                           :else
                           known-ids)]
         {:target target
          :summary bounded-ids})
       nil))))

(defn lazy-pull
  "Processes an incoming anti-entropy summary.
   Takes the set of locally known message IDs and the remote summary (set of message IDs).
   Returns the set of message IDs that are present in the remote summary but missing locally.
   These are the IDs that should be requested via lazy pull."
  [local-known-ids remote-summary]
  (set/difference remote-summary local-known-ids))
