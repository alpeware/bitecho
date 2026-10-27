(ns bitecho.basalt.core
  "Core logic for Basalt peer sampling protocol."
  (:require [bitecho.crypto :as crypto]))

(defrecord Peer [ip port pubkey hash])

(declare extract-peers)

(defn bytes->hex
  "Converts a byte array to a hex string."
  [^bytes ba]
  (apply str (map #(format "%02x" %) ba)))

(defn hex->bytes
  "Converts a hex string to a byte array. Throws IllegalArgumentException on invalid input."
  [^String s]
  (let [len (.length s)]
    (if (odd? len)
      (throw (IllegalArgumentException. "Hex string must have an even length"))
      (let [data (byte-array (quot len 2))]
        (loop [i 0]
          (if (< i len)
            (let [high (Character/digit (.charAt s i) 16)
                  low  (Character/digit (.charAt s (inc i)) 16)]
              (if (or (= high -1) (= low -1))
                (throw (IllegalArgumentException. "Invalid hex character"))
                (do
                  (aset data (quot i 2)
                        (unchecked-byte (+ (bit-shift-left high 4) low)))
                  (recur (+ i 2)))))
            data))))))

(defn make-peer
  "Creates a Peer record given IP, port, and a public key byte array.
   Calculates the deterministic SHA-256 hash of IP:PORT:PUBKEY to uniquely identify the peer.
   Age defaults to 0."
  [^String ip ^long port ^bytes pubkey]
  (let [ip-bytes (.getBytes ip)
        port-str (str port)
        port-bytes (.getBytes port-str)
        hash-input (byte-array (+ (count ip-bytes)
                                  1
                                  (count port-bytes)
                                  1
                                  (count pubkey)))
        bb (java.nio.ByteBuffer/wrap hash-input)]
    (.put bb ip-bytes)
    (.put bb (byte 124))
    (.put bb port-bytes)
    (.put bb (byte 124))
    (.put bb pubkey)
    (->Peer ip port (bytes->hex pubkey) (bytes->hex (crypto/sha256 hash-input)))))

(defn derive-slot-seed
  "Deterministically computes SHA-256(epoch-entropy || node-pubkey || slot-idx).
   Returns the 64-character lowercase hex string representation.
   Supports epoch-entropy and node-pubkey as either string or byte array."
  [epoch-entropy node-pubkey slot-idx]
  (let [e-bytes (if (bytes? epoch-entropy) epoch-entropy (.getBytes ^String (str epoch-entropy) "UTF-8"))
        p-bytes (if (bytes? node-pubkey) node-pubkey (.getBytes ^String (str node-pubkey) "UTF-8"))
        s-bytes (.getBytes ^String (str slot-idx) "UTF-8")
        total-len (+ (count e-bytes) (count p-bytes) (count s-bytes))
        bb (java.nio.ByteBuffer/wrap (byte-array total-len))]
    (.put bb ^bytes e-bytes)
    (.put bb ^bytes p-bytes)
    (.put bb ^bytes s-bytes)
    (bytes->hex (crypto/sha256 (.array bb)))))

(defn rank
  "Calculates the cryptographic rank of a peer for a given slot seed.
   Concatenates the slot seed and the peer's hash, computes SHA-256,
   and returns the hex string representation.
   Supports slot seed and peer-hash as either string or byte array."
  [seed peer-hash]
  (let [seed-bytes (if (bytes? seed) seed (.getBytes ^String (str seed) "UTF-8"))
        hash-bytes (if (bytes? peer-hash) peer-hash (.getBytes ^String (str peer-hash) "UTF-8"))
        input (byte-array (+ (count seed-bytes) (count hash-bytes)))
        bb (java.nio.ByteBuffer/wrap input)]
    (.put bb ^bytes seed-bytes)
    (.put bb ^bytes hash-bytes)
    (bytes->hex (crypto/sha256 input))))

(defn update-view
  "Performs greedy optimization on the view without allowing duplicates.
   Extracts all unique peers from the current view and the received peers,
   then assigns each to at most one slot where it minimizes the cryptographic rank,
   ensuring the view is populated with as many distinct optimal peers as possible."
  [view received-peers]
  (let [initial-candidates (vals (reduce #(assoc %1 (:hash %2) %2) {}
                                         (concat (extract-peers view)
                                                 received-peers)))]
    (loop [v []
           remaining-slots view
           candidates initial-candidates
           used-hashes #{}]
      (if (empty? remaining-slots)
        v
        (let [slot (first remaining-slots)
              avail (remove #(contains? used-hashes (:hash %)) candidates)
              best-candidate (when (seq avail)
                               (reduce (fn [best peer]
                                         (if (neg? (compare (rank (:seed slot) (:hash peer))
                                                            (rank (:seed slot) (:hash best))))
                                           peer
                                           best))
                                       (first avail) (rest avail)))]
          (recur (conj v (assoc slot :peer best-candidate))
                 (rest remaining-slots)
                 candidates
                 (if best-candidate
                   (conj used-hashes (:hash best-candidate))
                   used-hashes)))))))

(defn init-view
  "Initializes a new Basalt view (a vector of view-size slots) from initial peers.
   Accepts an explicit java.util.Random instance:
     (init-view initial-peers view-size ^java.util.Random rng)
   Or deterministic epoch-entropy and node-pubkey:
     (init-view initial-peers view-size epoch-entropy node-pubkey)"
  ([initial-peers view-size ^java.util.Random rng]
   (let [slots (vec (repeatedly view-size
                                #(let [seed-bytes (byte-array 32)]
                                   (.nextBytes rng seed-bytes)
                                   {:seed (bytes->hex seed-bytes) :peer nil})))]
     (if (empty? initial-peers)
       slots
       (update-view slots initial-peers))))
  ([initial-peers view-size epoch-entropy node-pubkey]
   (let [slots (vec (map-indexed
                     (fn [idx _]
                       {:seed (derive-slot-seed epoch-entropy node-pubkey idx)
                        :peer nil})
                     (range view-size)))]
     (if (empty? initial-peers)
       slots
       (update-view slots initial-peers)))))

(defn extract-peers
  "Extracts all distinct, non-nil peers currently held in the view's slots."
  [view]
  (let [peers (remove nil? (map :peer view))]
    (loop [result [] seen #{} remaining peers]
      (if-let [p (first remaining)]
        (let [h (:hash p)]
          (if (contains? seen h)
            (recur result seen (rest remaining))
            (recur (conj result p) (conj seen h) (rest remaining))))
        result))))

(defn reset-slots-rng
  "Resets k slots starting at index r (with wrap-around) using explicit java.util.Random.
   Yields previous peers, generates new random 32-byte seeds via rng,
   and repopulates slots using remaining and sampled peers.
   Returns {:view updated-view :samples samples :next-r new-r}."
  [view ^java.util.Random rng r k]
  (let [size (count view)
        indices (map #(mod (+ r %) size) (range k))
        samples (keep :peer (map #(get view %) indices))
        cleared-view (reduce (fn [v idx]
                               (let [seed-bytes (byte-array 32)]
                                 (.nextBytes rng seed-bytes)
                                 (assoc v idx {:seed (bytes->hex seed-bytes) :peer nil})))
                             view
                             indices)
        remaining-peers (extract-peers cleared-view)
        all-peers (reduce (fn [acc peer]
                            (if (some #(= (:hash %) (:hash peer)) acc)
                              acc
                              (conj acc peer)))
                          remaining-peers
                          samples)
        updated-view (update-view cleared-view all-peers)]
    {:view updated-view
     :samples samples
     :next-r (mod (+ r k) size)}))

(defn reset-slots-deterministic
  "Resets k slots starting at index r (with wrap-around) deterministically using epoch-entropy and node-pubkey.
   Yields previous peers, generates deterministic slot seeds via derive-slot-seed,
   and repopulates slots using remaining and sampled peers.
   Returns {:view updated-view :samples samples :next-r new-r}."
  [view epoch-entropy node-pubkey r k]
  (let [size (count view)
        indices (map #(mod (+ r %) size) (range k))
        samples (keep :peer (map #(get view %) indices))
        cleared-view (reduce (fn [v idx]
                               (let [seed (derive-slot-seed epoch-entropy node-pubkey idx)]
                                 (assoc v idx {:seed seed :peer nil})))
                             view
                             indices)
        remaining-peers (extract-peers cleared-view)
        all-peers (reduce (fn [acc peer]
                            (if (some #(= (:hash %) (:hash peer)) acc)
                              acc
                              (conj acc peer)))
                          remaining-peers
                          samples)
        updated-view (update-view cleared-view all-peers)]
    {:view updated-view
     :samples samples
     :next-r (mod (+ r k) size)}))

(defn reset-slots
  "Resets k slots starting at index r (with wrap-around).
   Delegates to reset-slots-rng when passed an explicit java.util.Random instance:
     (reset-slots view rng r k)
   Delegates to reset-slots-deterministic when passed epoch-entropy and node-pubkey:
     (reset-slots view epoch-entropy node-pubkey r k)
   Returns {:view updated-view :samples samples :next-r new-r}."
  ([view ^java.util.Random rng r k]
   (reset-slots-rng view rng r k))
  ([view epoch-entropy node-pubkey r k]
   (reset-slots-deterministic view epoch-entropy node-pubkey r k)))

(defn select-peers-deterministic
  "Selects up to k peers from the view deterministically using cryptographic ranking.
   Derives a selection seed from epoch-entropy and node-pubkey, calculates the rank
   for each distinct peer, and returns the top k peers sorted by rank."
  [epoch-entropy node-pubkey view k]
  (let [peers (if (and (vector? view) (some #(contains? % :seed) view))
                (extract-peers view)
                (distinct (remove nil? view)))
        seed (derive-slot-seed epoch-entropy node-pubkey "select")]
    (take k (sort-by #(rank seed (:hash %)) peers))))

(defn select-peers
  "Selects up to k peers from the view for exchange.
   Supports explicit RNG-based shuffling when passed a java.util.Random instance:
     (select-peers ^java.util.Random rng view k)
   Supports deterministic rank-based selection when passed epoch-entropy and node-pubkey:
     (select-peers epoch-entropy node-pubkey view k)
   Or when passed a string/bytes seed as the first argument:
     (select-peers seed view k)"
  ([^java.util.Random rng view k]
   (if (instance? java.util.Random rng)
     (let [peers (if (and (vector? view) (some #(contains? % :seed) view))
                   (extract-peers view)
                   (seq view))
           size (count peers)]
       (if (zero? size)
         ()
         (let [shuffled (java.util.ArrayList. peers)]
           (java.util.Collections/shuffle shuffled rng)
           (take k shuffled))))
     (select-peers-deterministic rng "select" view k)))
  ([epoch-entropy node-pubkey view k]
   (select-peers-deterministic epoch-entropy node-pubkey view k)))