(ns bitecho.economy.receipt
  "Probabilistic cryptographic Proof of Delivery receipt generation."
  (:require [bitecho.crypto :as crypto]))

(defrecord Receipt [agent node payload-id signature])

(defn create-receipt
  "Creates a cryptographic 'Proof of Delivery' receipt.
   The receipt contains the agent's public key, the routing node's public key,
   the payload-id of the routed data, and a signature from the agent over
   these properties."
  [^bytes agent-pub ^bytes agent-priv ^bytes node-pub ^String payload-id]
  (let [unsigned-receipt (into (sorted-map)
                               {:agent (vec agent-pub)
                                :node (vec node-pub)
                                :payload-id payload-id})
        payload-bytes (.getBytes (pr-str unsigned-receipt) "UTF-8")
        sig (crypto/sign agent-priv payload-bytes)]
    (map->Receipt (assoc unsigned-receipt :signature (vec sig)))))
