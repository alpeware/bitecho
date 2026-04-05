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

(defn quorum-threshold
  "Calculates the 2n/3 quorum threshold for a network of size n."
  [n]
  (int (Math/ceil (/ (* 2.0 n) 3))))

(defn accumulate-vote
  "Validates a vote and accumulates it into the block's vote set.
   If the accumulated valid votes reach the 2n/3 threshold, adds the block to the :notarized-blocks set."
  [state vote voter-pubkey-bytes n]
  (let [{:keys [block-hash voter-signature]} vote]
    (if (crypto/verify voter-pubkey-bytes
                       (.getBytes ^String block-hash "UTF-8")
                       (hex->bytes voter-signature))
      (let [pubkey-hex (bytes->hex voter-pubkey-bytes)
            current-votes (get-in state [:block-votes block-hash] #{})
            new-votes (conj current-votes pubkey-hex)
            state-with-vote (assoc-in state [:block-votes block-hash] new-votes)]
        (if (>= (count new-votes) (quorum-threshold n))
          (update state-with-vote :notarized-blocks (fnil conj #{}) block-hash)
          state-with-vote))
      state)))

(defn- get-ancestors
  "Recursively retrieves the sequence of ancestors for a given block hash."
  [blocks block-hash]
  (loop [curr-hash block-hash
         acc []]
    (let [block (get blocks curr-hash)]
      (if (or (nil? block) (= "genesis" (:parent-hash block)))
        acc
        (recur (:parent-hash block) (conj acc (:parent-hash block)))))))

(defn- find-consecutive-epoch-head
  "Finds the middle block's hash of any 3 consecutive notarized blocks.
   Returns a sequence of such hashes."
  [notarized-blocks blocks]
  (let [notarized-block-maps (keep #(when-let [b (get blocks %)] (assoc b :hash %)) notarized-blocks)
        ;; For each notarized block, trace back its ancestors to see if we have 3 consecutive epochs
        consecutive-heads
        (keep (fn [{:keys [epoch parent-hash]}]
                (let [parent-block (get blocks parent-hash)
                      parent-epoch (:epoch parent-block)]
                  (when (and parent-block
                             (contains? notarized-blocks parent-hash)
                             (= epoch (inc parent-epoch)))
                    (let [grandparent-hash (:parent-hash parent-block)
                          grandparent-block (get blocks grandparent-hash)
                          grandparent-epoch (:epoch grandparent-block)]
                      (when (and grandparent-block
                                 (contains? notarized-blocks grandparent-hash)
                                 (= parent-epoch (inc grandparent-epoch)))
                        parent-hash)))))
              notarized-block-maps)]
    consecutive-heads))

(defn finalize-prefix
  "Scans the notarized chain. If three adjacent blocks have consecutive epoch numbers,
   finalizes the prefix of blocks starting from the middle block."
  [state]
  (let [blocks (get state :blocks {})
        notarized-blocks (get state :notarized-blocks #{})
        heads (find-consecutive-epoch-head notarized-blocks blocks)
        new-finalized (reduce (fn [acc head-hash]
                                (let [ancestors (get-ancestors blocks head-hash)]
                                  (into acc (conj ancestors head-hash))))
                              #{}
                              heads)]
    (update state :finalized-blocks (fnil into #{}) new-finalized)))
