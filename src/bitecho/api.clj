(ns bitecho.api
  "Public Application API for the Bitecho agent.
   Provides command injection functions to act as the interface for the intelligence layer."
  (:require [clojure.core.async :as async]))

(defn send-direct-message
  "Injects a command to route a directed message to the network.
   Pushes a :route-directed-message event to the shell's :events-in channel."
  [node destination-pubkey encrypted-payload lottery-ticket payout-amount rng]
  (let [envelope {:destination destination-pubkey
                  :encrypted-payload encrypted-payload
                  :lottery-ticket lottery-ticket}
        event {:type :route-directed-message
               :envelope envelope
               :payout-amount payout-amount
               :rng rng}]
    (async/put! (:events-in node) event)))
