(ns bitecho.message.envelope
  "Pure spec and wrapping logic for a directed message envelope."
  (:require [clojure.spec.alpha :as s]))

;; Specification

(s/def ::destination string?)
(s/def ::encrypted-payload bytes?)

(s/def ::payload-hash string?)
(s/def ::nonce int?)
(s/def ::public-key string?)
(s/def ::signature string?)

(s/def ::lottery-ticket
  (s/keys :req-un [::payload-hash ::nonce ::public-key ::signature]))

(s/def ::envelope
  (s/keys :req-un [::destination ::encrypted-payload ::lottery-ticket]))

;; Logic

(defn wrap-envelope
  "Wraps a destination pubkey, encrypted payload, and lottery ticket into an envelope map."
  [^String destination-pubkey ^bytes encrypted-payload ticket]
  {:destination destination-pubkey
   :encrypted-payload encrypted-payload
   :lottery-ticket ticket})
