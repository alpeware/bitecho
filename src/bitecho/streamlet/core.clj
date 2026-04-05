(ns bitecho.streamlet.core
  "Streamlet core data structures and pure functions."
  (:require [bitecho.crypto :as crypto]))

(defrecord Block [epoch parent-hash payload proposer])

(defrecord Vote [block-hash epoch voter-signature])

(defn hex->bytes
  "Converts a hex string to a byte array."
  [^String s]
  (let [len (.length s)
        data (byte-array (/ len 2))]
    (loop [i 0]
      (when (< i len)
        (aset data (/ i 2)
              (unchecked-byte
               (+ (bit-shift-left (Character/digit (.charAt s i) 16) 4)
                  (Character/digit (.charAt s (inc i)) 16))))
        (recur (+ i 2))))
    data))

(defn- bytes->hex
  "Converts a byte array to a hex string."
  [^bytes ba]
  (apply str (map #(format "%02x" %) ba)))

(defn hash-block
  "Serializes a block to a string, hashes it via SHA-256, and returns a hex string."
  [block]
  (bytes->hex (crypto/sha256 (.getBytes (pr-str block) "UTF-8"))))

(defn propose-block
  "Proposes a block for a given epoch.
   Uses :node-pubkey for the proposer, :head-hash (defaulting to 'genesis') for parent-hash,
   and :mempool (defaulting to []) for payload."
  [state epoch]
  (->Block epoch
           (get state :head-hash "genesis")
           (get state :mempool [])
           (get state :node-pubkey)))

(defn cast-vote
  "Casts a vote on a block if the state has not already voted in this epoch.
   Returns a Vote record with a valid signature, or nil if already voted."
  [state block]
  (let [epoch (:epoch block)
        voted (get state :voted-epochs #{})]
    (when-not (contains? voted epoch)
      (let [b-hash (hash-block block)
            private-key (get-in state [:keypair :private])
            sig-bytes (crypto/sign private-key (.getBytes ^String b-hash "UTF-8"))]
        (->Vote b-hash epoch (bytes->hex sig-bytes))))))
