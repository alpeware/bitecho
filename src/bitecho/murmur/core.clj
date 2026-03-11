(ns bitecho.murmur.core
  "Core logic for Murmur probabilistic broadcast protocol."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defn initiate-broadcast
  "Initiates a broadcast by generating a deterministic message ID from the payload,
   and selecting up to k random peers from the provided view.
   Returns a map with :message-id, :payload, and :targets."
  [^bytes payload ^java.util.Random rng view k]
  (let [message-id (basalt/bytes->hex (crypto/sha256 payload))
        targets (basalt/select-peers rng view k)]
    {:message-id message-id
     :payload payload
     :targets targets}))
