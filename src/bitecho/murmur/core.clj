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

(defn- update-cache
  "Adds a message-id to the cache and evicts the oldest if max-size is exceeded.
   Returns the updated cache map."
  [cache message-id max-size]
  (let [current-set (:set cache)
        current-queue (:queue cache)
        new-queue (conj current-queue message-id)
        new-set (conj current-set message-id)]
    (if (> (count new-queue) max-size)
      (let [oldest (peek new-queue)]
        {:set (disj new-set oldest)
         :queue (pop new-queue)})
      {:set new-set
       :queue new-queue})))

(defn receive-gossip
  "Processes an incoming gossip message.
   If the message ID is in the cache, drops it and returns the unmodified cache.
   If unseen, updates the cache, returns the message, and selects k random forward targets.
   Returns a map with :cache, :forward-targets, and :message."
  [seen-cache message ^java.util.Random rng view k max-cache-size]
  (let [message-id (:message-id message)]
    (if (contains? (:set seen-cache) message-id)
      {:cache seen-cache
       :forward-targets ()
       :message nil}
      (let [new-cache (update-cache seen-cache message-id max-cache-size)
            targets (basalt/select-peers rng view k)]
        {:cache new-cache
         :forward-targets targets
         :message message}))))
