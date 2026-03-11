(ns bitecho.sieve.core
  "Core logic for Sieve consistent broadcast validation."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defn wrap-message
  "Wraps a payload with an Ed25519 signature and the sender's public key hex.
   Returns a map with :payload, :sender, and :signature."
  [^bytes payload ^bytes private-key ^bytes public-key]
  (let [signature (crypto/sign private-key payload)]
    {:payload payload
     :sender (basalt/bytes->hex public-key)
     :signature signature}))

(defn validate-message
  "Validates a signed message.
   Takes a message containing :payload, :sender (hex), and :signature.
   Returns the message if the signature is valid, nil otherwise."
  [message]
  (try
    (let [payload (:payload message)
          sender-pub-key (basalt/hex->bytes ^String (:sender message))
          signature (:signature message)]
      (if (crypto/verify sender-pub-key payload signature)
        message
        nil))
    (catch Exception _
      nil)))
