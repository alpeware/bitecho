(ns bitecho.basalt.core
  "Core logic for Basalt peer sampling protocol."
  (:require [bitecho.crypto :as crypto]))

(defrecord Peer [ip port pubkey age hash])

(defn bytes->hex
  "Converts a byte array to a hex string."
  [^bytes ba]
  (apply str (map #(format "%02x" %) ba)))

(defn make-peer
  "Creates a Peer record given IP, port, and a public key byte array.
   Calculates the deterministic SHA-256 hash of IP:PORT:PUBKEY to uniquely identify the peer.
   Age defaults to 0."
  [^String ip ^long port ^bytes pubkey]
  (let [ip-bytes (.getBytes ip)
        port-str (str port)
        port-bytes (.getBytes port-str)
        hash-input (byte-array (+ (count ip-bytes)
                                  (count port-bytes)
                                  (count pubkey)))
        bb (java.nio.ByteBuffer/wrap hash-input)]
    (.put bb ip-bytes)
    (.put bb port-bytes)
    (.put bb pubkey)
    (->Peer ip port (bytes->hex pubkey) 0 (bytes->hex (crypto/sha256 hash-input)))))

(defn init-view
  "Initializes a new Basalt view (a set of peers) from an initial collection of peer records.
   Removes duplicate peers based on hash."
  [initial-peers]
  (reduce (fn [view peer]
            (if (some #(= (:hash %) (:hash peer)) view)
              view
              (conj view peer)))
          #{}
          initial-peers))
