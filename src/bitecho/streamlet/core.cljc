(ns bitecho.streamlet.core
  "Streamlet core data structures and pure functions.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.set :as set]))

(defrecord ^{:doc "Streamlet consensus block record."} Block [epoch parent-hash payload proposer signature])

#_{:clj-kondo/ignore [:redefined-var]}
(defn ->Block
  "Constructs a Block record.
   Supports 4-arity (signature defaults to nil) and 5-arity."
  ([epoch parent-hash payload proposer]
   (Block. epoch parent-hash payload proposer nil))
  ([epoch parent-hash payload proposer signature]
   (Block. epoch parent-hash payload proposer signature)))

(defrecord ^{:doc "Streamlet vote record."} Vote [block-hash epoch voter-signature])

(def max-epoch-catchup-delta
  "Maximum allowed forward epoch jump from a single message or ancestor step."
  64)

(def ^{:doc "Portable byte array predicate."} bytes? fressian/bytes?)
(def ^{:doc "Converts hex string to byte array."} hex->bytes basalt/hex->bytes)
(def ^{:doc "Converts byte array to hex string."} bytes->hex basalt/bytes->hex)

(defn valid-hex-string?
  "Returns true if s is a non-empty, even-length hex string."
  [s]
  (boolean (and (string? s)
                (pos? (count s))
                (even? (count s))
                (re-matches #"[0-9a-fA-F]+" s))))

(defn block-signing-bytes
  "Serializes block contents excluding signature for Ed25519 signing."
  [block]
  (crypto/canonical-signing-bytes [(:epoch block) (:parent-hash block) (:payload block) (:proposer block)]))

(defn sign-block
  "Signs a block with proposer's private key bytes, attaching the hex signature."
  [block private-key]
  (let [sig-bytes (crypto/sign-canonical private-key [(:epoch block) (:parent-hash block) (:payload block) (:proposer block)])]
    (assoc block :signature (bytes->hex sig-bytes))))

(defn verify-block-signature
  "Verifies the Ed25519 signature of a block against the proposer's public key bytes.
   Supports N/N-1 rolling verification."
  [block proposer-pubkey-bytes]
  (boolean
   (when (and (map? block)
              (valid-hex-string? (:signature block))
              (bytes? proposer-pubkey-bytes))
     (try
       (crypto/verify-with-fallback proposer-pubkey-bytes
                                    [(:epoch block) (:parent-hash block) (:payload block) (:proposer block)]
                                    (hex->bytes (:signature block)))
       (catch #?(:clj Exception :cljs :default) _ false)))))

(defn verify-vote-signature
  "Verifies the Ed25519 signature of a vote against voter-pubkey-bytes.
   Supports N/N-1 rolling verification.
   Returns false on any non-string field, malformed hex, or verification error."
  [vote voter-pubkey-bytes]
  (boolean
   (when (and (map? vote)
              (string? (:block-hash vote))
              (valid-hex-string? (:voter-signature vote)))
     (let [pk-bytes (if (string? voter-pubkey-bytes)
                      (hex->bytes voter-pubkey-bytes)
                      voter-pubkey-bytes)]
       (when (bytes? pk-bytes)
         (try
           (let [sig-bytes (hex->bytes (:voter-signature vote))
                 msg-bytes (fressian/utf8->bytes (:block-hash vote))]
             (or (crypto/verify pk-bytes msg-bytes sig-bytes)
                 (crypto/verify-with-fallback pk-bytes (:block-hash vote) sig-bytes)))
           (catch #?(:clj Exception :cljs :default) _ false)))))))

(defn hash-block
  "Serializes a block to canonical bytes, hashes via SHA-256, and returns a hex string."
  [block]
  (bytes->hex (crypto/sha256 (fressian/encode-canonical (into {} block)))))

(defn propose-block
  "Proposes a block for a given epoch.
   Uses :node-pubkey for the proposer, :head-hash (defaulting to 'genesis') for parent-hash,
   and :mempool (defaulting to []) for payload.
   Signs the block if a private key is present in state."
  [state epoch]
  (let [raw-block (->Block epoch
                           (get state :head-hash "genesis")
                           (get state :mempool [])
                           (get state :node-pubkey))
        priv-key (or (get-in state [:keypair :private])
                     (get-in state [:keys :private])
                     (:node-private-key state))]
    (if priv-key
      (sign-block raw-block priv-key)
      raw-block)))

(defn chain-length
  "Calculates the length of the chain ending at block-hash.
   Guards against cycles using a visited set: returns -1 if a cycle is detected,
   indicating an invalid cyclic chain.
   Returns -1 if chain terminates at an unknown/unrooted parent (orphan fragment).
   Optional 3-arity accepts block-depths map for O(1) cached lookups."
  ([blocks block-hash]
   (chain-length blocks block-hash nil))
  ([blocks block-hash block-depths]
   (loop [curr block-hash
          visited #{}
          len 0]
     (cond
       (= curr "genesis") len
       (contains? visited curr) -1
       (and (map? block-depths) (contains? block-depths curr))
       (let [d (long (get block-depths curr -1))]
         (if (>= d 0) (+ d len) -1))
       :else (if-let [block (get blocks curr)]
               (recur (:parent-hash block) (conj visited curr) (inc len))
               -1)))))

(defn- lookup-known-depth
  "Looks up a positive topological depth for `h`, consulting cached `:block-depths`
   first and immutable `:executed-root-depths` second. Returns nil if unknown."
  [depths exec-root-depths h]
  (let [d1 (long (or (get depths h) 0))
        d2 (long (or (get exec-root-depths h) 0))]
    (cond
      (pos? d1) d1
      (pos? d2) d2
      :else nil)))

(defn record-executed-root-depths
  "Immutably records true positive topological depths of `hashes` into `:executed-root-depths`.
   Never overwrites an existing positive entry in `:executed-root-depths`."
  [state hashes]
  (let [depths (or (:block-depths state) {})
        existing (or (:executed-root-depths state) {})
        updated (reduce (fn [acc h]
                          (if (pos? (long (or (get acc h) 0)))
                            acc
                            (let [d (long (or (get depths h) 0))]
                              (if (pos? d)
                                (assoc acc h d)
                                acc))))
                        existing
                        hashes)]
    (if (identical? updated existing)
      state
      (assoc state :executed-root-depths updated))))

(defn record-block-depth
  "Records the chain depth of block-hash in (:block-depths state) if it roots to genesis or an executed root.
   Always consults `:block-depths` then immutable `:executed-root-depths` before any fallback.
   NEVER seeds depth from `:epoch` or `:last-executed-finalized-epoch`.
   Does not cache depths for unrooted orphan chains or cyclic chains."
  [state block-hash]
  (let [blocks (:blocks state)
        depths (get state :block-depths {})
        exec-root-depths (get state :executed-root-depths {})
        executed-roots (or (:executed-finalized-blocks state) #{})]
    (cond
      (or (nil? block-hash) (= block-hash "genesis") (contains? depths block-hash))
      state

      :else
      (if-let [block (get blocks block-hash)]
        (let [p-hash (:parent-hash block)]
          (cond
            (= p-hash "genesis")
            (assoc-in state [:block-depths block-hash] 1)

            (lookup-known-depth depths exec-root-depths p-hash)
            (let [d (lookup-known-depth depths exec-root-depths p-hash)]
              (-> state
                  (assoc-in [:block-depths p-hash] d)
                  (assoc-in [:block-depths block-hash] (inc d))))

            (and (contains? executed-roots p-hash) (not (contains? blocks p-hash)))
            (-> state
                (assoc-in [:block-depths p-hash] 1)
                (assoc-in [:block-depths block-hash] 2))

            :else
            (loop [curr p-hash
                   path [block-hash]
                   visited #{block-hash}]
              (cond
                (= curr "genesis")
                (let [path-rev (vec (rseq path))
                      new-depths (into {} (map-indexed (fn [idx h] [h (inc idx)]) path-rev))]
                  (update state :block-depths (fnil merge {}) new-depths))

                (contains? visited curr)
                state

                (lookup-known-depth depths exec-root-depths curr)
                (let [d (lookup-known-depth depths exec-root-depths curr)
                      path-rev (vec (rseq path))
                      new-depths (into {curr d} (map-indexed (fn [idx h] [h (+ d (inc idx))]) path-rev))]
                  (update state :block-depths (fnil merge {}) new-depths))

                (and (contains? executed-roots curr) (not (contains? blocks curr)))
                (let [path-rev (vec (rseq path))
                      new-depths (into {curr 1} (map-indexed (fn [idx h] [h (+ 1 (inc idx))]) path-rev))]
                  (update state :block-depths (fnil merge {}) new-depths))

                :else
                (if-let [curr-blk (get blocks curr)]
                  (recur (:parent-hash curr-blk) (conj path curr) (conj visited curr))
                  state)))))
        state))))

(defn repair-corrupt-block-depths
  "Self-heals any mathematically impossible cached `:block-depths` entries where
   `depth > (:epoch block)` OR where a cached `:block-depths` entry contradicts
   the immutable `:executed-root-depths` truth. Strips poisoned entries, restores
   `:executed-root-depths` truth, recomputes affected blocks in ascending `:epoch` order,
   and records a counted Rule 5 `:corrupt-block-depth-repaired` diagnostic counter & event."
  [state]
  (let [blocks (:blocks state)
        depths (:block-depths state)
        exec-root-depths (or (:executed-root-depths state) {})
        corrupt-roots (when (and (map? depths) (map? exec-root-depths))
                        (into []
                              (keep (fn [[h d]]
                                      (let [true-d (get exec-root-depths h)]
                                        (when (and (some? true-d)
                                                   (pos? (long true-d))
                                                   (not= (long (or d 0)) (long true-d)))
                                          [h (long true-d)]))))
                              depths))
        corrupt-blocks (when (and (map? blocks) (map? depths))
                         (into []
                               (keep (fn [[h d]]
                                       (when-let [blk (get blocks h)]
                                         (let [ep (long (or (:epoch blk) 0))]
                                           (when (and (pos? ep) (> (long (or d 0)) ep))
                                             [ep h])))))
                               depths))]
    (if (and (empty? corrupt-roots) (empty? corrupt-blocks))
      state
      (let [root-hashes (mapv first corrupt-roots)
            sorted-block-hashes (mapv second (sort-by first corrupt-blocks))
            all-repaired-hashes (vec (distinct (concat root-hashes sorted-block-hashes)))
            repaired-count (count all-repaired-hashes)
            diag-ev {:effect :diagnose
                     :type :diagnose
                     :reason :corrupt-block-depth-repaired
                     :count repaired-count
                     :hashes all-repaired-hashes}
            cleaned-blocks (update state :block-depths #(apply dissoc % sorted-block-hashes))
            restored-roots (reduce (fn [st [h true-d]]
                                     (assoc-in st [:block-depths h] true-d))
                                   cleaned-blocks
                                   corrupt-roots)
            rebuilt (reduce record-block-depth restored-roots sorted-block-hashes)]
        (-> rebuilt
            (update-in [:diagnostics :corrupt-block-depth-repaired] (fnil + 0) repaired-count)
            (update-in [:diagnostics :corrupt-block-depth-repaired-events]
                       (fn [evs]
                         (let [v (conj (vec (or evs [])) diag-ev)]
                           (if (> (count v) 64)
                             (subvec v (- (count v) 64))
                             v)))))))))

(defn longest-notarized-parent?
  "Returns true if parent-hash extends one of the longest notarized chains in state.
   If no blocks are notarized yet, only 'genesis' is valid.
   If notarized blocks exist, parent-hash must be a notarized block with maximal chain length.
   When child-epoch is provided, requires child-epoch > parent-epoch when parent-hash is not 'genesis'.
   Returns false if parent-hash or any notarized ancestor is cyclic."
  ([state parent-hash]
   (longest-notarized-parent? state parent-hash nil))
  ([state parent-hash child-epoch]
   (let [notarized (get state :notarized-blocks #{})
         blocks (get state :blocks {})
         depths (:block-depths state)]
     (if (empty? notarized)
       (= parent-hash "genesis")
       (let [parent-len (chain-length blocks parent-hash depths)
             valid-lens (filterv pos? (map #(chain-length blocks % depths) notarized))
             epoch-monotonic? (or (nil? child-epoch)
                                  (= parent-hash "genesis")
                                  (> (long child-epoch) (long (get-in blocks [parent-hash :epoch] 0))))]
         (boolean
          (and (pos? parent-len)
               (contains? notarized parent-hash)
               epoch-monotonic?
               (seq valid-lens)
               (= parent-len (reduce max 0 valid-lens)))))))))

(defn cast-vote
  "Casts a vote on a block if the state has not already voted in this epoch
   and the block's parent-hash extends one of the longest notarized chains.
   Returns a Vote record with a valid signature, or nil if already voted or invalid parent."
  [state block]
  (let [epoch (:epoch block)
        parent-hash (:parent-hash block)
        voted (get state :voted-epochs #{})]
    (when (and (not (contains? voted epoch))
               (longest-notarized-parent? state parent-hash epoch))
      (let [b-hash (hash-block block)
            private-key (get-in state [:keypair :private])
            sig-bytes (crypto/sign private-key (fressian/utf8->bytes b-hash))]
        (->Vote b-hash epoch (bytes->hex sig-bytes))))))

(defn quorum-threshold
  "Calculates the 2n/3 quorum threshold for a network of size n."
  [n]
  (int #?(:clj (Math/ceil (/ (* 2.0 n) 3)) :cljs (js/Math.ceil (/ (* 2.0 n) 3)))))

(defn accumulate-vote
  "Validates a vote and accumulates it into the block's vote set.
   Rejects Byzantine vote equivocations where a validator votes for two distinct blocks in the same epoch.
   If the accumulated valid votes reach the 2n/3 threshold, adds the block to the :notarized-blocks set."
  [state vote voter-pubkey-bytes n]
  (let [b-hash (when (map? vote) (:block-hash vote))]
    (if (and b-hash (verify-vote-signature vote voter-pubkey-bytes))
      (let [pubkey-hex (bytes->hex voter-pubkey-bytes)
            v-epoch (or (:epoch vote) (get-in state [:blocks b-hash :epoch]))
            prev-b-hash (when v-epoch (get-in state [:epoch-voters v-epoch pubkey-hex]))]
        (if (and prev-b-hash (not= prev-b-hash b-hash))
          ;; JEP-01: Reject Byzantine vote equivocation fail-closed
          (-> state
              (update-in [:diagnostics :vote-equivocations] (fnil inc 0))
              (update :equivocated-voters (fnil conj #{}) pubkey-hex))
          (let [current-votes (get-in state [:block-votes b-hash] #{})
                new-votes (conj current-votes pubkey-hex)
                state-with-voter (if v-epoch
                                   (assoc-in state [:epoch-voters v-epoch pubkey-hex] b-hash)
                                   state)
                state-with-vote (-> state-with-voter
                                    (assoc-in [:block-votes b-hash] new-votes)
                                    (assoc-in [:block-vote-proofs b-hash pubkey-hex] vote))]
            (if (>= (count new-votes) (quorum-threshold n))
              (update state-with-vote :notarized-blocks (fnil conj #{}) b-hash)
              state-with-vote))))
      state)))

(defn get-ancestors
  "Recursively retrieves the sequence of ancestors for a given block hash.
   Guards against cycles using a visited set: terminates traversal if a cycle is detected.
   Optional 3-arity terminates walk early if parent-hash is in existing-finalized or not in blocks."
  ([blocks block-hash]
   (get-ancestors blocks block-hash nil))
  ([blocks block-hash existing-finalized]
   (loop [curr-hash block-hash
          visited #{block-hash}
          acc []]
     (let [block (get blocks curr-hash)
           parent-hash (:parent-hash block)]
       (if (if existing-finalized
             (or (nil? block)
                 (= "genesis" parent-hash)
                 (not (contains? blocks parent-hash))
                 (contains? existing-finalized parent-hash)
                 (contains? visited parent-hash))
             (or (nil? block)
                 (= "genesis" parent-hash)
                 (contains? visited parent-hash)))
         acc
         (recur parent-hash (conj visited parent-hash) (conj acc parent-hash)))))))

(defn find-consecutive-epoch-head
  "Finds the middle block's hash of any 3 consecutive notarized blocks.
   Returns a sequence of such hashes.
   When existing-finalized is provided, skips candidate if parent-hash is already finalized."
  ([notarized-blocks blocks]
   (find-consecutive-epoch-head notarized-blocks blocks nil))
  ([notarized-blocks blocks existing-finalized]
   (let [notarized-block-maps (keep #(when-let [b (get blocks %)] (assoc b :hash %)) notarized-blocks)
         consecutive-heads
         (keep (fn [{:keys [epoch parent-hash]}]
                 (when-not (and existing-finalized (contains? existing-finalized parent-hash))
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
                           parent-hash))))))
               notarized-block-maps)]
     consecutive-heads)))

(defn finalize-prefix
  "Scans the notarized chain. If three adjacent blocks have consecutive epoch numbers,
   finalizes the prefix of blocks starting from the middle block.
   Terminates ancestor walks incrementally at existing finalized blocks.
   Updates :latest-finalized-block-hash to the finalized block hash with highest epoch."
  [state]
  (let [blocks (get state :blocks {})
        notarized-blocks (get state :notarized-blocks #{})
        existing-finalized (get state :finalized-blocks #{})
        heads (find-consecutive-epoch-head notarized-blocks blocks existing-finalized)
        new-finalized (reduce (fn [acc head-hash]
                                (if (contains? existing-finalized head-hash)
                                  acc
                                  (let [ancestors (get-ancestors blocks head-hash existing-finalized)]
                                    (into (conj acc head-hash) ancestors))))
                              #{}
                              heads)]
    (if (empty? new-finalized)
      state
      (let [updated-finalized (into existing-finalized new-finalized)
            candidates (if-let [curr (:latest-finalized-block-hash state)]
                         (conj new-finalized curr)
                         new-finalized)
            new-latest (last (sort-by #(get-in blocks [% :epoch] -1) candidates))
            st-with-depths (reduce record-block-depth state new-finalized)]
        (-> st-with-depths
            (record-executed-root-depths new-finalized)
            (assoc :finalized-blocks updated-finalized
                   :latest-finalized-block-hash new-latest))))))

(def default-streamlet-retention-epochs
  "Default number of historical epochs to retain before pruning state."
  256)

(def default-max-ancestor-sync-depth
  "Default maximum number of notarized ancestors bundled in a :send-propose command."
  16)

(def default-max-propose-wire-bytes
  "Default maximum encoded wire byte budget (32 KiB) for a :send-propose command."
  32768)

(defn protected-ancestor-chain-hashes
  "When state tracks :executed-finalized-blocks or :last-executed-finalized-epoch,
   returns the set of block hashes along the ancestor chain from :head-hash,
   :latest-finalized-block-hash, and any unexecuted :finalized-blocks back to
   (and including) the root anchor in :executed-finalized-blocks.
   Ensures unexecuted canonical ancestors are never orphaned by pruning during long stalls."
  [state]
  (if-not (or (contains? state :executed-finalized-blocks)
              (contains? state :last-executed-finalized-epoch))
    #{}
    (let [blocks (or (:blocks state) {})
          executed (or (:executed-finalized-blocks state) #{})
          finalized (or (:finalized-blocks state) #{})
          unexecuted-fin (set/difference finalized executed)
          roots (into (cond-> #{}
                        (:head-hash state) (conj (:head-hash state))
                        (:latest-finalized-block-hash state) (conj (:latest-finalized-block-hash state)))
                      unexecuted-fin)]
      (reduce (fn [protected start-hash]
                (loop [curr start-hash
                       visited #{}
                       acc protected]
                  (cond
                    (or (nil? curr)
                        (= curr "genesis")
                        (= curr "0000000000000000000000000000000000000000000000000000000000000000")
                        (contains? visited curr))
                    acc

                    (contains? executed curr)
                    (conj acc curr)

                    (contains? acc curr)
                    acc

                    :else
                    (if-let [b (get blocks curr)]
                      (recur (:parent-hash b)
                             (conj visited curr)
                             (conj acc curr))
                      acc))))
              #{}
              roots))))

(defn prune-streamlet-state
  "Prunes Streamlet state beyond retention epoch threshold to bound memory.
   Retains :head-hash, :latest-finalized-block-hash, and any unexecuted ancestor chain
   back to the executed root regardless of epoch.
   Updates cumulative :pruned-notarized-count and :pruned-finalized-count."
  [state]
  (let [retention (or (get-in state [:config :streamlet-retention-epochs])
                      (:streamlet-retention-epochs state)
                      default-streamlet-retention-epochs)
        current-epoch (or (:epoch state) 0)
        cutoff (- current-epoch (long retention))
        head-hash (get state :head-hash "genesis")]
    (if (or (<= cutoff 0) (= head-hash "genesis"))
      state
      (let [blocks (:blocks state)
            state-with-depths (-> (reduce record-block-depth state (keys blocks))
                                  (record-executed-root-depths
                                   (set/union (or (:executed-finalized-blocks state) #{})
                                              (or (:finalized-blocks state) #{}))))
            latest-finalized (:latest-finalized-block-hash state-with-depths)
            protected-hashes (protected-ancestor-chain-hashes state-with-depths)
            expired-hashes (into #{}
                                 (keep (fn [[h b]]
                                         (when (and (< (long (or (:epoch b) 0)) cutoff)
                                                    (not= h head-hash)
                                                    (not= h latest-finalized)
                                                    (not (contains? protected-hashes h)))
                                           h)))
                                 blocks)
            voted-epochs (into #{} (filter #(>= (long %) cutoff)) (get state-with-depths :voted-epochs #{}))
            epoch-voters (into {} (filter (fn [[ep _]] (>= (long ep) cutoff))) (get state-with-depths :epoch-voters {}))
            retained-blocks (reduce dissoc blocks expired-hashes)
            parent-boundary-hashes (set (keep :parent-hash (vals retained-blocks)))
            allowed-depth-hashes (set/union (set (keys retained-blocks))
                                            parent-boundary-hashes
                                            protected-hashes
                                            (disj (hash-set head-hash latest-finalized "genesis") nil))
            bounded-depths (select-keys (:block-depths state-with-depths {}) allowed-depth-hashes)]
        (if (empty? expired-hashes)
          (assoc state-with-depths
                 :block-depths bounded-depths
                 :voted-epochs voted-epochs
                 :epoch-voters epoch-voters)
          (let [notarized (get state-with-depths :notarized-blocks #{})
                finalized (get state-with-depths :finalized-blocks #{})
                pruned-notarized (count (set/intersection notarized expired-hashes))
                pruned-finalized (count (set/intersection finalized expired-hashes))
                cum-pruned-notarized (+ (long (or (:pruned-notarized-count state-with-depths) 0)) pruned-notarized)
                cum-pruned-finalized (+ (long (or (:pruned-finalized-count state-with-depths) 0)) pruned-finalized)]
            (-> state-with-depths
                (update :blocks #(reduce dissoc (or % {}) expired-hashes))
                (update :notarized-blocks #(set/difference (or % #{}) expired-hashes))
                (update :finalized-blocks #(set/difference (or % #{}) expired-hashes))
                (update :block-votes #(reduce dissoc (or % {}) expired-hashes))
                (update :block-vote-proofs #(reduce dissoc (or % {}) expired-hashes))
                (assoc :block-depths bounded-depths
                       :voted-epochs voted-epochs
                       :epoch-voters epoch-voters
                       :pruned-notarized-count cum-pruned-notarized
                       :pruned-finalized-count cum-pruned-finalized))))))))

(defn extract-peer-hexes
  "Extracts a sorted vector of peer public key hex strings from state."
  [state]
  (cond
    (seq (:peers-map state))
    (vec (sort (keys (:peers-map state))))

    (and (contains? state :peers-map) (empty? (:peers-map state)))
    []

    (:node-pubkey state)
    [(:node-pubkey state)]

    :else
    []))

(defn extract-validator-hexes
  "Extracts a sorted vector of Streamlet BFT committee validator public key hex strings from state.
   When :validators (or [:config :validators]) is non-empty, returns sorted vector of :validators;
   otherwise falls back to extract-peer-hexes."
  [state]
  (let [vals-coll (or (when (seq (:validators state)) (:validators state))
                      (when (seq (get-in state [:config :validators])) (get-in state [:config :validators])))]
    (if (seq vals-coll)
      (vec (sort (if (map? vals-coll) (keys vals-coll) vals-coll)))
      (extract-peer-hexes state))))

(defn- total-node-count
  "Determines the Streamlet BFT committee size from state or validator set."
  [state validator-hexes]
  (if (or (seq (:validators state)) (seq (get-in state [:config :validators])))
    (max 1 (count validator-hexes))
    (or (:total-nodes state)
        (when (seq validator-hexes) (count validator-hexes))
        1)))

(defn resolve-peer-pubkey-bytes
  "Resolves the peer's public key byte array strictly from :peers-map in state.
   Returns nil if peer-hex is not present in :peers-map."
  [state peer-hex]
  (when (and (map? (:peers-map state)) (contains? (:peers-map state) peer-hex))
    (let [entry (get-in state [:peers-map peer-hex])]
      (cond
        (bytes? entry) entry
        (string? entry) (try (hex->bytes entry) (catch #?(:clj Exception :cljs :default) _ nil))
        :else nil))))

(defn valid-block-proposal?
  "Validates a block proposal event against state:
   - event and block must be maps
   - :peers-map must be non-empty
   - epoch must be a positive integer
   - proposer must be a string, in :peers-map, and in the active Streamlet BFT :validators committee
   - proposer must match expected round-robin leader for epoch
   - if :sender is present on event, must equal (:proposer block)
   - proposer signature must be valid Ed25519 signature verified by proposer's pubkey bytes"
  [state event]
  (boolean
   (when (and (map? state) (map? event) (map? (:block event)))
     (let [block (:block event)
           validator-hexes (extract-validator-hexes state)
           validator-set (set validator-hexes)
           total-nodes (total-node-count state validator-hexes)
           epoch (:epoch block)
           proposer (:proposer block)
           sender (:sender event)
           sender-hex (cond
                        (string? sender) sender
                        (bytes? sender) (bytes->hex sender)
                        :else nil)]
       (when (and (seq (:peers-map state))
                  (seq validator-hexes)
                  (integer? epoch)
                  (pos? epoch)
                  (string? proposer)
                  (contains? validator-set proposer)
                  (pos? total-nodes)
                  (or (nil? sender) (= sender-hex proposer)))
         (let [expected-leader (nth validator-hexes (mod epoch total-nodes))
               proposer-pk (resolve-peer-pubkey-bytes state proposer)]
           (and expected-leader
                (= proposer expected-leader)
                proposer-pk
                (verify-block-signature block proposer-pk))))))))

(defn- extract-targets
  "Determines target destinations for outgoing network commands.
   Prefers explicit :targets override, otherwise falls back to keys of :peers-map."
  [state]
  (cond
    (:targets state) (:targets state)
    (:peers-map state) (keys (:peers-map state))
    :else []))

(defn- extract-local-pubkey-bytes
  "Extracts the local node's public key as a byte array."
  [state]
  (or (get-in state [:keypair :public])
      (get-in state [:keys :public])
      (when-let [hex (:node-pubkey state)]
        (try (hex->bytes hex) (catch #?(:clj Exception :cljs :default) _ nil)))))

(defn- extract-sender-pubkey-bytes
  "Resolves the sender's public key bytes strictly from :peers-map in state.
   Returns nil if sender is absent from :peers-map or sender-hex is nil."
  [state event]
  (let [sender (:sender event)
        sender-hex (cond
                     (string? sender) sender
                     (bytes? sender) (bytes->hex sender)
                     (bytes? (:sender-pubkey-bytes event)) (bytes->hex (:sender-pubkey-bytes event))
                     :else nil)]
    (when sender-hex
      (resolve-peer-pubkey-bytes state sender-hex))))

(defn- update-head-hash
  "Updates :head-hash in state to the maximal length notarized chain head.
   Guards against cyclic chains by ignoring cyclic notarized heads and falling back to genesis."
  [state]
  (let [state (repair-corrupt-block-depths state)
        notarized (:notarized-blocks state)
        blocks (:blocks state)
        depths (:block-depths state)
        candidates (keep (fn [h]
                           (let [len (chain-length blocks h depths)]
                             (when (pos? len)
                               {:hash h
                                :len len
                                :epoch (get-in blocks [h :epoch] -1)})))
                         notarized)
        head-hash (if (empty? candidates)
                    "genesis"
                    (:hash (last (sort-by (juxt :len :epoch) candidates))))]
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

(defn extract-notarized-ancestors
  "Extracts a vector of up to max-depth notarized ancestor blocks walking back from parent-hash in state.
   Bundles each notarized ancestor as {:block block :votes vote-proofs} with verified quorum vote proofs.
   Guards against cycles using a visited set."
  [state parent-hash max-depth]
  (let [blocks (get state :blocks {})
        notarized (get state :notarized-blocks #{})
        validator-hexes (extract-validator-hexes state)
        total-nodes (total-node-count state validator-hexes)
        threshold (quorum-threshold total-nodes)]
    (loop [curr-hash parent-hash
           depth 0
           visited #{parent-hash}
           acc []]
      (if (or (>= depth max-depth)
              (= "genesis" curr-hash)
              (not (contains? notarized curr-hash)))
        acc
        (if-let [block (get blocks curr-hash)]
          (let [p-hash (:parent-hash block)
                vote-proofs (get-in state [:block-vote-proofs curr-hash] {})
                bundled-entry (when (>= (count vote-proofs) threshold)
                                {:block block :votes vote-proofs})
                next-acc (if bundled-entry (conj acc bundled-entry) acc)]
            (if (contains? visited p-hash)
              next-acc
              (recur p-hash (inc depth) (conj visited p-hash) next-acc)))
          acc)))))

(defn verify-ancestor-quorum
  "Verifies that an ancestor entry contains a valid block proposal within max-epoch-catchup-delta
   and a quorum of validly signed votes from Streamlet BFT committee members."
  [state ancestor-entry]
  (if-not (and (map? ancestor-entry)
               (map? (:block ancestor-entry))
               (map? (:votes ancestor-entry)))
    {:valid? false}
    (let [block (:block ancestor-entry)
          votes-map (:votes ancestor-entry)
          curr-ep (or (:epoch state) 0)
          max-d (or (:max-epoch-catchup-delta state) max-epoch-catchup-delta)
          epoch-ok? (and (integer? (:epoch block))
                         (<= (long (:epoch block)) (+ curr-ep max-d)))
          proposal-ok? (and epoch-ok? (valid-block-proposal? state {:block block}))]
      (if-not proposal-ok?
        {:valid? false}
        (let [b-hash (hash-block block)
              validator-hexes (extract-validator-hexes state)
              validator-set (set validator-hexes)
              total-nodes (total-node-count state validator-hexes)
              threshold (quorum-threshold total-nodes)
              verified-votes
              (into {}
                    (filter (fn [[voter-hex vote]]
                              (when (and (string? voter-hex)
                                         (contains? validator-set voter-hex)
                                         (map? vote)
                                         (= (:block-hash vote) b-hash))
                                (when-let [voter-pk (resolve-peer-pubkey-bytes state voter-hex)]
                                  (verify-vote-signature vote voter-pk))))
                            votes-map))]
          {:valid? (>= (count verified-votes) threshold)
           :b-hash b-hash
           :block block
           :voter-set (set (keys verified-votes))
           :vote-proofs verified-votes})))))

(defn ingest-verified-ancestors
  "Ingests verified notarized ancestor blocks into state if they have valid quorum vote proofs
   and do not exceed max-epoch-catchup-delta. Ancestors are processed in ascending epoch order."
  [state ancestors]
  (let [sorted-ancestors (sort-by (fn [entry] (or (get-in entry [:block :epoch]) 0)) ancestors)]
    (reduce (fn [s entry]
              (let [res (verify-ancestor-quorum s entry)]
                (if (:valid? res)
                  (let [b-hash (:b-hash res)
                        block (:block res)
                        s-with-depth (-> s
                                         (assoc-in [:blocks b-hash] block)
                                         (record-block-depth b-hash))
                        ;; Never seed depth from :epoch or :last-executed-finalized-epoch when
                        ;; parent is unknown; anchor at minimal topological depth (<= epoch).
                        s-anchored (if (not (contains? (:block-depths s-with-depth) b-hash))
                                     (let [ep (long (or (:epoch block) 1))]
                                       (if (> ep 1)
                                         (-> s-with-depth
                                             (assoc-in [:block-depths (:parent-hash block)] 1)
                                             (assoc-in [:block-depths b-hash] 2))
                                         (assoc-in s-with-depth [:block-depths b-hash] 1)))
                                     s-with-depth)]
                    (-> s-anchored
                        (update-in [:block-votes b-hash] (fnil into #{}) (:voter-set res))
                        (update-in [:block-vote-proofs b-hash] merge (:vote-proofs res))
                        (update :notarized-blocks (fnil conj #{}) b-hash)
                        (update :epoch (fn [e] (max (or e 0) (long (:epoch block)))))))
                  s)))
            state
            sorted-ancestors)))

(defn truncate-ancestors-to-wire-budget
  "Truncates a newest-first vector of notarized ancestor entries to the longest contiguous prefix
   whose encoded :send-propose wire representation does not exceed max-wire-bytes."
  [base-propose-cmd ancestors max-wire-bytes]
  (let [budget (long (or max-wire-bytes default-max-propose-wire-bytes))
        base-bytes (fressian/count-bytes (fressian/encode-wire base-propose-cmd))]
    (loop [remaining ancestors
           kept []
           acc-bytes base-bytes]
      (if (empty? remaining)
        kept
        (let [anc (first remaining)
              anc-bytes (+ 8 (fressian/count-bytes (fressian/encode-wire anc)))
              next-bytes (+ acc-bytes anc-bytes)]
          (if (<= next-bytes budget)
            (recur (rest remaining) (conj kept anc) next-bytes)
            kept))))))

(defn- handle-tick-event
  "Handles a :tick event: advances epoch, elects proposer from Streamlet BFT :validators committee, and proposes if local node."
  [state]
  (let [new-epoch (inc (get state :epoch 0))
        state (-> state
                  (assoc :epoch new-epoch)
                  update-head-hash)
        validator-hexes (extract-validator-hexes state)]
    (if (empty? validator-hexes)
      {:state (prune-streamlet-state state) :commands []}
      (let [total-nodes (total-node-count state validator-hexes)
            proposer-idx (mod new-epoch total-nodes)
            proposer-hex (nth validator-hexes proposer-idx)
            is-proposer? (= proposer-hex (:node-pubkey state))]
        (if is-proposer?
          (let [block (propose-block state new-epoch)
                b-hash (hash-block block)
                state (-> state
                          (assoc-in [:blocks b-hash] block)
                          (record-block-depth b-hash))
                vote (cast-vote state block)
                local-pk (extract-local-pubkey-bytes state)
                state (if vote
                        (-> state
                            (update :voted-epochs (fnil conj #{}) (:epoch block))
                            (accumulate-vote vote local-pk total-nodes))
                        state)
                state (apply-future-votes state b-hash total-nodes)
                state (-> state
                          update-head-hash
                          finalize-prefix)
                targets (extract-targets state)
                ancestor-depth (long (or (get-in state [:config :max-ancestor-sync-depth])
                                         (:max-ancestor-sync-depth state)
                                         default-max-ancestor-sync-depth))
                wire-budget (long (or (get-in state [:config :max-propose-wire-bytes])
                                      (:max-propose-wire-bytes state)
                                      default-max-propose-wire-bytes))
                raw-ancestors (extract-notarized-ancestors state (:parent-hash block) ancestor-depth)
                base-propose {:type :send-propose :targets targets :block block :ancestors []}
                ancestors (truncate-ancestors-to-wire-budget base-propose raw-ancestors wire-budget)
                propose-cmd (assoc base-propose :ancestors ancestors)
                commands (if vote
                           [propose-cmd
                            {:type :send-vote :targets targets :vote vote}]
                           [propose-cmd])]
            {:state (prune-streamlet-state state) :commands commands})
          {:state (prune-streamlet-state state) :commands []})))))

(defn- catchup-corroboration-threshold
  "Minimum distinct verified committee validators required to corroborate an out-of-horizon
   epoch jump (`F-EPOCH-1` / `BIP-013`): `f + 1` (at least 2 for N >= 3) so a single Byzantine
   peer can never jump a node's epoch past `max-epoch-catchup-delta`."
  [total-nodes]
  (let [n (max 1 (long total-nodes))
        f (quot (max 0 (dec n)) 3)]
    (if (<= n 1) 1 (max 2 (inc f)))))

(defn- valid-quorum-ancestor-epoch
  "Returns the maximum epoch of any quorum-certified ancestor entry in `ancestors` (verified
   against the committee validator set), or nil if none has a valid quorum certificate."
  [state ancestors]
  (when (seq ancestors)
    (let [validator-hexes (extract-validator-hexes state)
          validator-set (set validator-hexes)
          total-nodes (total-node-count state validator-hexes)
          q (quorum-threshold total-nodes)]
      (reduce (fn [best entry]
                (let [b (:block entry)
                      votes (or (:votes entry) [])
                      ep (when (and (map? b) (integer? (:epoch b))) (long (:epoch b)))]
                  (if (and ep (pos? ep) (>= (count votes) q))
                    (let [b-hash (hash-block b)
                          valid-voters
                          (reduce (fn [acc v]
                                    (let [vhex (or (:voter-pubkey v) (:voter v))]
                                      (if (and (string? vhex)
                                               (contains? validator-set vhex)
                                               (= b-hash (:block-hash v))
                                               (= ep (:epoch v))
                                               (valid-hex-string? (:voter-signature v))
                                               (verify-vote-signature v (hex->bytes vhex)))
                                        (conj acc vhex)
                                        acc)))
                                  #{}
                                  votes)]
                      (if (>= (count valid-voters) q)
                        (max (or best 0) ep)
                        best))
                    best)))
              nil
              ancestors))))

(defn- record-out-of-horizon-witness
  "Pure F-EPOCH-1 helper: records a verified committee sender's out-of-horizon epoch witness and
   returns `{:jump-to-epoch E-or-nil :state st' :diagnose diag-cmd}`.
   Uses the `(f+1)`-th highest witnessed epoch so a single Byzantine peer cannot pull `:epoch`
   ahead of honest validators."
  [state sender-hex observed-epoch curr-epoch max-delta reason-on-drop ancestors]
  (let [validator-hexes (extract-validator-hexes state)
        total-nodes (total-node-count state validator-hexes)
        threshold (catchup-corroboration-threshold total-nodes)
        horizon (+ (long curr-epoch) (long max-delta))
        qc-epoch (valid-quorum-ancestor-epoch state ancestors)
        prev-witnesses (or (:epoch-catchup-witnesses state) {})
        validator-set (set validator-hexes)
        witnesses (if (and sender-hex (contains? validator-set sender-hex))
                    (assoc prev-witnesses sender-hex (max (long observed-epoch)
                                                          (long (get prev-witnesses sender-hex 0))))
                    prev-witnesses)
        above-horizon (into {} (filter (fn [[_ ep]] (> (long ep) horizon)) witnesses))
        quorum-epoch (cond
                       (and qc-epoch (> qc-epoch horizon))
                       qc-epoch

                       (>= (count above-horizon) threshold)
                       (let [sorted-desc (vec (sort > (vals above-horizon)))]
                         (long (nth sorted-desc (dec threshold))))

                       :else nil)]
    (if quorum-epoch
      (let [diag {:type :diagnose
                  :effect :diagnose
                  :reason :quorum-epoch-catchup
                  :from-epoch (long curr-epoch)
                  :to-epoch (long quorum-epoch)
                  :witness-count (count above-horizon)
                  :threshold threshold
                  :qc-backed? (boolean (and qc-epoch (> qc-epoch horizon)))}
            st' (-> state
                    (assoc :epoch (max (long curr-epoch) (long quorum-epoch))
                           :epoch-catchup-witnesses {})
                    (update-in [:diagnostics :quorum-epoch-catchup] (fnil inc 0)))]
        {:jump-to-epoch (long quorum-epoch)
         :state st'
         :diagnose diag})
      (let [diag {:type :diagnose
                  :effect :diagnose
                  :reason reason-on-drop
                  :from-epoch (long curr-epoch)
                  :observed-epoch (long observed-epoch)
                  :max-delta (long max-delta)
                  :witness-count (count above-horizon)
                  :threshold threshold}
            st' (-> state
                    (assoc :epoch-catchup-witnesses above-horizon)
                    (update-in [:diagnostics reason-on-drop] (fnil inc 0)))]
        {:jump-to-epoch nil
         :state st'
         :diagnose diag}))))

(defn- process-in-horizon-propose
  [state event extra-cmds]
  (let [block (:block event)
        state-with-ancestors (if (seq (:ancestors event))
                               (ingest-verified-ancestors state (:ancestors event))
                               state)
        state (update state-with-ancestors :epoch (fn [e] (max (or e 0) (long (:epoch block)))))
        b-hash (hash-block block)
        state (-> state
                  (assoc-in [:blocks b-hash] block)
                  (record-block-depth b-hash))
        parent-hash (:parent-hash block)
        known-parent? (or (= parent-hash "genesis") (contains? (:blocks state) parent-hash))]
    (if known-parent?
      (let [validator-hexes (extract-validator-hexes state)
            validator-set (set validator-hexes)
            total-nodes (total-node-count state validator-hexes)
            eligible-voter? (contains? validator-set (:node-pubkey state))
            vote (when eligible-voter? (cast-vote state block))
            local-pk (extract-local-pubkey-bytes state)
            state (if vote
                    (-> state
                        (update :voted-epochs (fnil conj #{}) (:epoch block))
                        (accumulate-vote vote local-pk total-nodes))
                    state)
            state (apply-future-votes state b-hash total-nodes)
            state (-> state
                      update-head-hash
                      finalize-prefix)
            targets (extract-targets state)
            commands (cond-> (vec extra-cmds)
                       vote (conj {:type :send-vote :targets targets :vote vote}))]
        {:state state :commands commands})
      (let [future-blocks (get state :future-blocks [])
            state (-> state
                      (assoc :future-blocks (conj future-blocks event))
                      update-head-hash
                      finalize-prefix)]
        {:state state :commands (vec extra-cmds)}))))

(defn- handle-propose-event
  "Handles a :receive-propose event: validates proposal fail-closed,
   enforces epoch bounds with F-EPOCH-1 self-healing quorum epoch catch-up,
   ingests verified quorum ancestors, records block and votes (if in :validators committee)."
  [state event]
  (if-not (valid-block-proposal? state event)
    {:state state :commands []}
    (let [block (:block event)
          curr-epoch (long (or (:epoch state) 0))
          max-delta (long (or (:max-epoch-catchup-delta state) max-epoch-catchup-delta))]
      (if (> (long (:epoch block)) (+ curr-epoch max-delta))
        (let [sender-pk (extract-sender-pubkey-bytes state event)
              sender-hex (when sender-pk (bytes->hex sender-pk))
              {:keys [jump-to-epoch state diagnose]}
              (record-out-of-horizon-witness state sender-hex (:epoch block) curr-epoch max-delta
                                             :proposal-exceeds-catchup-delta (:ancestors event))]
          (if (and jump-to-epoch (<= (long (:epoch block)) (+ jump-to-epoch max-delta)))
            (process-in-horizon-propose state event [diagnose])
            {:state state :commands [diagnose]}))
        (process-in-horizon-propose state event [])))))

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
  "Handles a :receive-vote event: rejects non-committee/Sybil senders, malformed votes, or far-future epochs fail-closed,
   accumulates vote if block is known, or buffers into :future-votes."
  [state event]
  (let [vote (:vote event)
        sender-pk (extract-sender-pubkey-bytes state event)
        sender-hex (when sender-pk (bytes->hex sender-pk))
        validator-hexes (extract-validator-hexes state)
        validator-set (set validator-hexes)
        b-hash (when (map? vote) (:block-hash vote))
        sig (when (map? vote) (:voter-signature vote))
        epoch (when (map? vote) (:epoch vote))
        curr-epoch (or (:epoch state) 0)
        max-delta (or (:max-epoch-catchup-delta state) max-epoch-catchup-delta)]
    (if (or (nil? sender-pk)
            (not (contains? validator-set sender-hex))
            (not (string? b-hash))
            (not (valid-hex-string? sig))
            (not (integer? epoch))
            (not (pos? epoch))
            (not (verify-vote-signature vote sender-pk)))
      {:state state :commands []}
      (if (> (long epoch) (+ (long curr-epoch) (long max-delta)))
        (let [{:keys [jump-to-epoch state diagnose]}
              (record-out-of-horizon-witness state sender-hex epoch curr-epoch max-delta
                                             :vote-exceeds-catchup-delta nil)]
          (if (and jump-to-epoch (<= (long epoch) (+ jump-to-epoch (long max-delta))))
            (let [state (update state :epoch (fn [e] (max (or e 0) (long epoch))))]
              (if (contains? (:blocks state) b-hash)
                (let [total-nodes (total-node-count state validator-hexes)
                      state (accumulate-vote state vote sender-pk total-nodes)
                      {state :state cmds :commands} (drain-future-blocks state)
                      state (-> state
                                update-head-hash
                                finalize-prefix)]
                  {:state state :commands (into [diagnose] cmds)})
                (let [state (-> (buffer-future-vote state vote sender-pk)
                                update-head-hash
                                finalize-prefix)]
                  {:state state :commands [diagnose]})))
            {:state state :commands [diagnose]}))
        (let [state (update state :epoch (fn [e] (max (or e 0) (long epoch))))]
          (if (contains? (:blocks state) b-hash)
            (let [total-nodes (total-node-count state validator-hexes)
                  state (accumulate-vote state vote sender-pk total-nodes)
                  {state :state cmds :commands} (drain-future-blocks state)
                  state (-> state
                            update-head-hash
                            finalize-prefix)]
              {:state state :commands cmds})
            (let [state (-> (buffer-future-vote state vote sender-pk)
                            update-head-hash
                            finalize-prefix)]
              {:state state :commands []})))))))

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
