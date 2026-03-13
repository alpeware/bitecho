(ns bitecho.crypto.delegation
  "Pure functions for generating and verifying Delegated Agent Certificates (DACs)
   linking a temporary Node Key to a Parent Key."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]))

(defn- canonicalize-dac
  "Canonicalizes the payload of a DAC for signing or verification.
   Returns a string representation of the data to be signed."
  [parent-pubkey node-pubkey]
  (pr-str (into (sorted-map)
                {:parent-pubkey parent-pubkey
                 :node-pubkey node-pubkey})))

(defn generate-dac
  "Generates a Delegated Agent Certificate (DAC).
   The signature is created using the parent's private key over the
   canonicalized map of the parent and node public keys.
   Returns a map representing the DAC."
  [^String parent-pubkey ^bytes parent-privkey ^String node-pubkey]
  (let [payload (canonicalize-dac parent-pubkey node-pubkey)
        payload-bytes (.getBytes payload "UTF-8")
        signature-bytes (crypto/sign parent-privkey payload-bytes)]
    {:parent-pubkey parent-pubkey
     :node-pubkey node-pubkey
     :signature (basalt/bytes->hex signature-bytes)}))

(defn verify-dac
  "Verifies a Delegated Agent Certificate (DAC).
   Returns true if the signature is valid according to the parent-pubkey
   and matches the canonicalized payload, false otherwise."
  [{:keys [parent-pubkey node-pubkey signature] :as _dac}]
  (try
    (let [payload (canonicalize-dac parent-pubkey node-pubkey)
          payload-bytes (.getBytes payload "UTF-8")
          pubkey-bytes (basalt/hex->bytes parent-pubkey)
          signature-bytes (basalt/hex->bytes signature)]
      (crypto/verify pubkey-bytes payload-bytes signature-bytes))
    (catch Exception _
      false)))
