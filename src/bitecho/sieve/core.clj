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

(defn check-equivocation
  "Checks if a message is an equivocation based on the sender's history.
   Returns a map with :equivocation? (boolean) and :history (updated history).
   History is a map of [sender (hex) message-id] to signature (hex)."
  [history message]
  (let [sender (:sender message)
        message-id (:message-id message)
        sender-msg-key [sender message-id]
        sig-hex (basalt/bytes->hex (:signature message))
        existing-sig-hex (get history sender-msg-key)]
    (if existing-sig-hex
      (if (= existing-sig-hex sig-hex)
        {:equivocation? false :history history}
        {:equivocation? true :history history})
      {:equivocation? false :history (assoc history sender-msg-key sig-hex)})))
