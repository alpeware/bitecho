(ns bitecho.basalt.core
  "Core logic for Basalt peer sampling protocol.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]))

(defrecord ^{:doc "Represents a sampled network peer."} Peer [ip port pubkey hash])

(declare extract-peers)

;; Re-export portable byte helpers for backward compatibility
(def ^{:doc "Returns true if x is a raw byte array (byte[] on JVM, Uint8Array on JS)."} bytes? fressian/bytes?)
(def ^{:doc "Returns the length in bytes of x."} count-bytes fressian/count-bytes)
(def ^{:doc "Encodes a string to UTF-8 bytes."} utf8->bytes fressian/utf8->bytes)
(def ^{:doc "Decodes UTF-8 bytes to a string."} bytes->utf8 fressian/bytes->utf8)
(def ^{:doc "Converts a byte array / Uint8Array to a lowercase hex string."} bytes->hex fressian/bytes->hex)
(def ^{:doc "Converts a hex string to a byte array / Uint8Array."} hex->bytes fressian/hex->bytes)
(def ^{:doc "Checks byte equality between two byte arrays."} byte-array-equals? fressian/byte-array-equals?)
(def ^{:doc "Lexicographical unsigned comparison of two byte arrays."} byte-array-compare fressian/byte-array-compare)

(defn concat-bytes
  "Concatenates two byte arrays."
  [a b]
  (let [len-a (count-bytes a)
        len-b (count-bytes b)
        total-len (+ len-a len-b)]
    #?(:clj
       (let [res (byte-array total-len)]
         (System/arraycopy ^bytes a 0 res 0 len-a)
         (System/arraycopy ^bytes b 0 res len-a len-b)
         res)
       :cljs
       (let [res (js/Uint8Array. total-len)]
         (.set res a 0)
         (.set res b len-a)
         res))))

(defn make-peer
  "Creates a Peer record given IP, port, and a public key byte array.
   Calculates the deterministic SHA-256 hash of IP:PORT:PUBKEY to uniquely identify the peer.
   Age defaults to 0."
  [ip port pubkey]
  (let [ip-bytes (utf8->bytes (str ip))
        port-bytes (utf8->bytes (str port))
        pub-bytes (if (string? pubkey) (hex->bytes pubkey) pubkey)
        sep (utf8->bytes "|")
        hash-input (concat-bytes (concat-bytes (concat-bytes (concat-bytes ip-bytes sep) port-bytes) sep) pub-bytes)]
    (->Peer ip port (bytes->hex pub-bytes) (bytes->hex (crypto/sha256 hash-input)))))

(defn derive-slot-seed
  "Deterministically computes SHA-256(epoch-entropy || node-pubkey || slot-idx).
   Returns the 64-character lowercase hex string representation.
   Supports epoch-entropy and node-pubkey as either string or byte array."
  [epoch-entropy node-pubkey slot-idx]
  (let [e-bytes (if (bytes? epoch-entropy) epoch-entropy (utf8->bytes (str epoch-entropy)))
        p-bytes (if (bytes? node-pubkey) node-pubkey (utf8->bytes (str node-pubkey)))
        s-bytes (utf8->bytes (str slot-idx))
        input (concat-bytes (concat-bytes e-bytes p-bytes) s-bytes)]
    (bytes->hex (crypto/sha256 input))))

(defn rank
  "Calculates the cryptographic rank of a peer for a given slot seed.
   Concatenates the slot seed and the peer's hash, computes SHA-256,
   and returns the hex string representation.
   Supports slot seed and peer-hash as either string or byte array."
  [seed peer-hash]
  (let [seed-bytes (if (bytes? seed) seed (utf8->bytes (str seed)))
        hash-bytes (if (bytes? peer-hash) peer-hash (utf8->bytes (str peer-hash)))
        input (concat-bytes seed-bytes hash-bytes)]
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
   Accepts an explicit RNG / crypto.IRandom instance:
     (init-view initial-peers view-size rng)
   Or deterministic epoch-entropy and node-pubkey:
     (init-view initial-peers view-size epoch-entropy node-pubkey)"
  ([initial-peers view-size rng]
   (let [slots (vec (repeatedly view-size
                                #(let [seed-bytes #?(:clj (byte-array 32) :cljs (js/Uint8Array. 32))]
                                   (crypto/next-bytes rng seed-bytes)
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
  "Resets k slots starting at index r (with wrap-around) using explicit IRandom/RNG.
   Yields previous peers, generates new random 32-byte seeds via rng,
   and repopulates slots using remaining and sampled peers.
   Returns {:view updated-view :samples samples :next-r new-r}."
  [view rng r k]
  (let [size (count view)
        indices (map #(mod (+ r %) size) (range k))
        samples (keep :peer (map #(get view %) indices))
        cleared-view (reduce (fn [v idx]
                               (let [seed-bytes #?(:clj (byte-array 32) :cljs (js/Uint8Array. 32))]
                                 (crypto/next-bytes rng seed-bytes)
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
   Delegates to reset-slots-rng when passed an explicit IRandom/Random instance:
     (reset-slots view rng r k)
   Delegates to reset-slots-deterministic when passed epoch-entropy and node-pubkey:
     (reset-slots view epoch-entropy node-pubkey r k)
   Returns {:view updated-view :samples samples :next-r new-r}."
  ([view rng r k]
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

(defn- shuffle-with-rng
  [coll rng]
  (let [v (vec coll)
        n (count v)]
    (loop [i (dec n)
           res (transient v)]
      (if (pos? i)
        (let [j (crypto/next-int rng (inc i))
              tmp (get res i)
              res' (-> res (assoc! i (get res j)) (assoc! j tmp))]
          (recur (dec i) res'))
        (persistent! res)))))

(defn select-peers
  "Selects up to k peers from the view for exchange.
   Supports explicit RNG-based shuffling when passed an IRandom / java.util.Random instance:
     (select-peers rng view k)
   Supports deterministic rank-based selection when passed epoch-entropy and node-pubkey:
     (select-peers epoch-entropy node-pubkey view k)
   Or when passed a string/bytes seed as the first argument:
     (select-peers seed view k)"
  ([rng-or-entropy view k]
   (if (satisfies? crypto/IRandom rng-or-entropy)
     (let [peers (if (and (vector? view) (some #(contains? % :seed) view))
                   (extract-peers view)
                   (distinct (remove nil? view)))
           size (count peers)]
       (if (zero? size)
         ()
         (take k (shuffle-with-rng peers rng-or-entropy))))
     (select-peers-deterministic rng-or-entropy "select" view k)))
  ([epoch-entropy node-pubkey view k]
   (select-peers-deterministic epoch-entropy node-pubkey view k)))
