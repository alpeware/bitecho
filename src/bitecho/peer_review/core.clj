(ns bitecho.peer-review.core
  "Core logic for Peer Review Protocol. Validates a Proof of Relay
   which is a sequence of transmission events, verifying signatures
   at each hop."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defn- validate-receipt
  "Validates a single receipt against the previous signature.
   Returns the new signature if valid, nil otherwise."
  [prev-sig receipt]
  (let [node-pubkey-hex (:node receipt)
        node-sig (:signature receipt)]
    (try
      (let [pub-key (basalt/hex->bytes ^String node-pubkey-hex)]
        (if (crypto/verify pub-key prev-sig node-sig)
          node-sig
          nil))
      (catch Exception _
        nil))))

(defn validate-proof-of-relay
  "Validates a Proof of Relay sequence.
   The proof is a sequence of receipts. Each receipt is a map with
   :node (hex string) and :signature (byte array). The first receipt
   signs the original message's signature.
   Returns true if the sequence is valid, false otherwise."
  [original-message proof-sequence]
  (if (empty? proof-sequence)
    true
    (let [initial-sig (if (string? (:signature original-message))
                        (basalt/hex->bytes ^String (:signature original-message))
                        (:signature original-message))]
      (loop [receipts proof-sequence
             prev-sig initial-sig]
        (if (empty? receipts)
          true
          (let [receipt (first receipts)
                valid-sig (validate-receipt prev-sig receipt)]
            (if valid-sig
              (recur (rest receipts) valid-sig)
              false)))))))
