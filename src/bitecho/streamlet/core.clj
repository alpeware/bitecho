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

(defn bytes->hex
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

(defn chain-length
  "Calculates the length of the chain ending at block-hash.
   Guards against cycles using a visited set: returns -1 if a cycle is detected,
   indicating an invalid cyclic chain."
  [blocks block-hash]
  (loop [curr block-hash
         visited #{}
         len 0]
    (cond
      (= curr "genesis") len
      (contains? visited curr) -1
      :else (if-let [block (get blocks curr)]
              (recur (:parent-hash block) (conj visited curr) (inc len))
              len))))

(defn longest-notarized-parent?
  "Returns true if parent-hash extends one of the longest notarized chains in state.
   If no blocks are notarized yet, only 'genesis' is valid.
   If notarized blocks exist, parent-hash must be a notarized block with maximal chain length.
   Returns false if parent-hash or any notarized ancestor is cyclic."
  [state parent-hash]
  (let [notarized (get state :notarized-blocks #{})
        blocks (get state :blocks {})]
    (if (empty? notarized)
      (= parent-hash "genesis")
      (let [parent-len (chain-length blocks parent-hash)
            valid-lens (filterv pos? (map #(chain-length blocks %) notarized))]
        (boolean
         (and (pos? parent-len)
              (contains? notarized parent-hash)
              (seq valid-lens)
              (= parent-len (reduce max 0 valid-lens))))))))

(defn cast-vote
  "Casts a vote on a block if the state has not already voted in this epoch
   and the block's parent-hash extends one of the longest notarized chains.
   Returns a Vote record with a valid signature, or nil if already voted or invalid parent."
  [state block]
  (let [epoch (:epoch block)
        parent-hash (:parent-hash block)
        voted (get state :voted-epochs #{})]
    (when (and (not (contains? voted epoch))
               (longest-notarized-parent? state parent-hash))
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

(defn get-ancestors
  "Recursively retrieves the sequence of ancestors for a given block hash.
   Guards against cycles using a visited set: terminates traversal if a cycle is detected."
  [blocks block-hash]
  (loop [curr-hash block-hash
         visited #{block-hash}
         acc []]
    (let [block (get blocks curr-hash)
          parent-hash (:parent-hash block)]
      (if (or (nil? block)
              (= "genesis" parent-hash)
              (contains? visited parent-hash))
        acc
        (recur parent-hash (conj visited parent-hash) (conj acc parent-hash))))))

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

(defn- peer->hex
  "Normalizes a peer representation (string or map) to a public key hex string."
  [peer]
  (cond
    (string? peer) peer
    (map? peer) (or (:pubkey-hex peer) (:pubkey peer) (:node-pubkey peer))
    :else nil))

(defn- extract-peer-hexes
  "Extracts a sorted vector of peer public key hex strings from state."
  [state]
  (cond
    (seq (:peers-map state))
    (vec (sort (keys (:peers-map state))))

    (seq (:registry-map state))
    (vec (sort (keys (:registry-map state))))

    (seq (:peers state))
    (vec (sort (keep peer->hex (:peers state))))

    (:node-pubkey state)
    [(:node-pubkey state)]

    :else
    []))

(defn- total-node-count
  "Determines the total network size from state or peer set."
  [state peer-hexes]
  (or (:total-nodes state)
      (when (seq peer-hexes) (count peer-hexes))
      1))

(defn- extract-targets
  "Determines target destinations for outgoing network commands."
  [state]
  (cond
    (:targets state) (:targets state)
    (:registry-map state) (vals (:registry-map state))
    (:peers-map state) (keys (:peers-map state))
    (:peers state) (:peers state)
    :else []))

(defn- extract-local-pubkey-bytes
  "Extracts the local node's public key as a byte array."
  [state]
  (or (get-in state [:keypair :public])
      (get-in state [:keys :public])
      (when-let [hex (:node-pubkey state)]
        (try (hex->bytes hex) (catch Exception _ nil)))))

(defn- extract-sender-pubkey-bytes
  "Resolves the sender's public key bytes from event or state registries."
  [state event]
  (or (:sender-pubkey-bytes event)
      (when-let [sender (:sender event)]
        (cond
          (bytes? sender)
          sender

          (contains? (:peers-map state) sender)
          (let [entry (get-in state [:peers-map sender])]
            (if (bytes? entry)
              entry
              (or (:public (:keys entry)) (:public entry) (:pubkey entry))))

          (contains? (:registry-map state) sender)
          (let [node (get-in state [:registry-map sender])]
            (or (:public (:keys node)) (:public node)))

          (string? sender)
          (try (hex->bytes sender) (catch Exception _ nil))

          :else
          nil))))

(defn- update-head-hash
  "Updates :head-hash in state to the maximal length notarized chain head.
   Guards against cyclic chains by ignoring cyclic notarized heads and falling back to genesis."
  [state]
  (let [notarized (:notarized-blocks state)
        blocks (:blocks state)
        valid-heads (filterv #(pos? (chain-length blocks %)) notarized)
        head-hash (if (empty? valid-heads)
                    "genesis"
                    (apply max-key (fn [h] [(chain-length blocks h) (get-in blocks [h :epoch] -1)]) valid-heads))]
    (assoc state :head-hash head-hash)))

(defn- apply-future-votes
  "Applies any votes buffered in :future-votes for block-hash."
  [state block-hash total-nodes]
  (let [future-votes (get-in state [:future-votes block-hash] [])
        state-with-votes (reduce (fn [s {:keys [vote sender-pubkey-bytes]}]
                                   (accumulate-vote s vote sender-pubkey-bytes total-nodes))
                                 state
                                 future-votes)]
    (if (contains? state-with-votes :future-votes)
      (update state-with-votes :future-votes dissoc block-hash)
      state-with-votes)))

(defn- buffer-future-vote
  "Buffers a vote whose block is not yet known in state."
  [state vote sender-pubkey-bytes]
  (let [b-hash (:block-hash vote)
        future-votes (get-in state [:future-votes b-hash] [])
        sig (:voter-signature vote)
        already? (some (fn [v] (= (:voter-signature (:vote v)) sig)) future-votes)]
    (if (or already? (nil? sender-pubkey-bytes))
      state
      (assoc-in state [:future-votes b-hash]
                (conj future-votes {:vote vote :sender-pubkey-bytes sender-pubkey-bytes})))))

(defn- handle-tick-event
  "Handles a :tick event: advances epoch, elects proposer, and proposes if local node."
  [state]
  (let [new-epoch (inc (get state :epoch 0))
        state (-> state
                  (assoc :epoch new-epoch)
                  update-head-hash)
        peer-hexes (extract-peer-hexes state)
        total-nodes (total-node-count state peer-hexes)
        proposer-idx (mod new-epoch total-nodes)
        proposer-hex (when (seq peer-hexes) (nth peer-hexes proposer-idx))
        is-proposer? (= proposer-hex (:node-pubkey state))]
    (if is-proposer?
      (let [block (propose-block state new-epoch)
            b-hash (hash-block block)
            state (assoc-in state [:blocks b-hash] block)
            vote (cast-vote state block)
            local-pk (extract-local-pubkey-bytes state)
            state (if vote
                    (-> state
                        (update :voted-epochs (fnil conj #{}) (:epoch block))
                        (accumulate-vote vote local-pk total-nodes))
                    state)
            state (apply-future-votes state b-hash total-nodes)
            state (finalize-prefix state)
            targets (extract-targets state)
            commands (if vote
                       [{:type :send-propose :targets targets :block block}
                        {:type :send-vote :targets targets :vote vote}]
                       [{:type :send-propose :targets targets :block block}])]
        {:state state :commands commands})
      {:state state :commands []})))

(defn- handle-propose-event
  "Handles a :receive-propose event: records block and votes if parent is known."
  [state event]
  (let [block (:block event)
        b-hash (hash-block block)
        state (assoc-in state [:blocks b-hash] block)
        parent-hash (:parent-hash block)
        known-parent? (or (= parent-hash "genesis") (contains? (:blocks state) parent-hash))]
    (if known-parent?
      (let [peer-hexes (extract-peer-hexes state)
            total-nodes (total-node-count state peer-hexes)
            vote (cast-vote state block)
            local-pk (extract-local-pubkey-bytes state)
            state (if vote
                    (-> state
                        (update :voted-epochs (fnil conj #{}) (:epoch block))
                        (accumulate-vote vote local-pk total-nodes))
                    state)
            state (apply-future-votes state b-hash total-nodes)
            state (finalize-prefix state)
            targets (extract-targets state)
            commands (if vote
                       [{:type :send-vote :targets targets :vote vote}]
                       [])]
        {:state state :commands commands})
      (let [future-blocks (get state :future-blocks [])
            state (assoc state :future-blocks (conj future-blocks event))]
        {:state state :commands []}))))

(defn- drain-future-blocks
  "Re-evaluates buffered future block proposals whose parents may now be known."
  [state]
  (let [future-blocks (get state :future-blocks [])]
    (if (empty? future-blocks)
      {:state state :commands []}
      (loop [remaining future-blocks
             curr-state (assoc state :future-blocks [])
             acc-cmds []
             unresolved []]
        (if (empty? remaining)
          {:state (assoc curr-state :future-blocks unresolved)
           :commands acc-cmds}
          (let [event (first remaining)
                block (:block event)
                parent-hash (:parent-hash block)
                known? (or (= parent-hash "genesis")
                           (contains? (:blocks curr-state) parent-hash))]
            (if known?
              (let [{s :state cmds :commands} (handle-propose-event curr-state event)]
                (recur (rest remaining) s (into acc-cmds cmds) unresolved))
              (recur (rest remaining) curr-state acc-cmds (conj unresolved event)))))))))

(defn- handle-vote-event
  "Handles a :receive-vote event: accumulates vote if block is known, or buffers it."
  [state event]
  (let [vote (:vote event)
        sender-pk (extract-sender-pubkey-bytes state event)
        b-hash (:block-hash vote)
        known-block? (contains? (:blocks state) b-hash)]
    (if known-block?
      (let [peer-hexes (extract-peer-hexes state)
            total-nodes (total-node-count state peer-hexes)
            state (if sender-pk
                    (accumulate-vote state vote sender-pk total-nodes)
                    state)
            {state :state cmds :commands} (drain-future-blocks state)
            state (finalize-prefix state)]
        {:state state :commands cmds})
      (let [state (buffer-future-vote state vote sender-pk)]
        {:state state :commands []}))))

(defn handle-streamlet-event
  "Pure state machine reducer for Streamlet BFT nodes.
   Accepts a node state map and an event map, returning:
   {:state new-state :commands [...]}"
  [state event]
  (case (:type event)
    :tick (handle-tick-event state)
    :receive-propose (handle-propose-event state event)
    :receive-vote (handle-vote-event state event)
    {:state state :commands []}))
