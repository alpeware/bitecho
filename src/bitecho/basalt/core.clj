(ns bitecho.basalt.core
  "Core logic for Basalt peer sampling protocol."
  (:require [bitecho.crypto :as crypto]))

(defrecord Peer [ip port pubkey age hash])

(defn bytes->hex
  "Converts a byte array to a hex string."
  [^bytes ba]
  (apply str (map #(format "%02x" %) ba)))

(defn hex->bytes
  "Converts a hex string to a byte array."
  [^String s]
  (let [len (.length s)
        data (byte-array (quot len 2))]
    (loop [i 0]
      (if (< i len)
        (do
          (aset data (quot i 2)
                (unchecked-byte (+ (bit-shift-left (Character/digit (.charAt s i) 16) 4)
                                   (Character/digit (.charAt s (inc i)) 16))))
          (recur (+ i 2)))
        data))))

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

(defn increment-ages
  "Increments the age of all peers in the view by 1."
  [view]
  (set (map #(update % :age inc) view)))

(defn select-peers
  "Selects up to k random peers from the view for exchange.
   To ensure determinism and purity in tests, it accepts a java.util.Random instance
   and uses it to shuffle the view before taking the first k elements."
  [^java.util.Random rng view k]
  (let [view-seq (vec view)
        size (count view-seq)]
    (if (zero? size)
      ()
      (let [shuffled (java.util.ArrayList. view-seq)]
        (java.util.Collections/shuffle shuffled rng)
        (take k shuffled)))))

(defn- dedup-peers
  "Deduplicates a collection of peers by hash, keeping the peer with the minimum age."
  [peers]
  (vals (reduce (fn [acc peer]
                  (let [existing (get acc (:hash peer))]
                    (if (or (nil? existing) (< (:age peer) (:age existing)))
                      (assoc acc (:hash peer) peer)
                      acc)))
                {}
                peers)))

(defn merge-views
  "Merges the local view and received view. Removes duplicates by keeping the youngest.
   Sorts by age and hash, and keeps up to max-size elements."
  [local-view received-view max-size]
  (let [all-peers (concat local-view received-view)
        deduped (dedup-peers all-peers)
        sorted (sort-by (juxt :age :hash) deduped)
        selected (take max-size sorted)]
    (set selected)))
