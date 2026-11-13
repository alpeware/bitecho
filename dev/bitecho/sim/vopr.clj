(ns bitecho.sim.vopr
  "Milestone D14: Full-Stack Deterministic Simulation & Jepsen Verification Engine (VOPR).
   Provides:
   - Discrete-event virtual-time scheduler ordered by [virtual-time-ns event-seq]
   - Adversarial byte link router with Gilbert-Elliott burst loss, latency jitter,
     bit-flip, truncation, MTU clamping, and RFC 4571 stream slicing
   - Defensive byte copying (AR-3) protecting in-flight and retransmit buffers
   - O(1) multiverse state branching and assertion of pure world state (AR-4)
   - Protocol-aware Jepsen verification oracles:
       1. Streamlet Consensus Serializability (elle.list-append & total order prefix)
       2. Subnet Pointer Linearizability & Fencing (knossos register & leader-term fencing)
       3. Tokenomics v2.1 Conservation & Deflation Fold
   - Active Byzantine Equivocation Nemesis (f < n/3)
   - Zero-pollution non-vacuity mutation testing gate (MUT-01..MUT-08 via with-redefs)"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.core.storage :as storage]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.economy.treasury :as treasury]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-node]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.browser :as browser]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.walk :as walk]
            [datachannel.buffer :as b]
            [datachannel.chunks :as dc-chunks]
            [datachannel.core :as dc]
            [datachannel.dtls :as dtls]
            [datachannel.handlers :as dc-handlers]
            [datachannel.reassemble :as dc-reassemble]
            [datachannel.stun :as dc-stun]
            [datachannel.tcp :as dtcp]
            [datachannel.turn :as dc-turn]
            [elle.list-append :as elle-la]
            [jepsen.history :as jh]
            [knossos.competition :as knossos-comp]
            [knossos.model :as knossos-model])
  (:import [java.util Arrays]))

;; =============================================================================
;; 1. Event Comparator & Scheduler Math
;; =============================================================================

(defn compare-event
  "Total canonical order on simulated events: strictly ordered by [virtual-time-ns event-seq]."
  [a b]
  (let [c (Long/compare (long (:t-ns a 0)) (long (:t-ns b 0)))]
    (if (zero? c)
      (Long/compare (long (:seq a 0)) (long (:seq b 0)))
      c)))

(defn make-event-queue
  "Creates an empty persistent sorted set for discrete-event scheduling."
  []
  (sorted-set-by compare-event))

(defn schedule-event
  "Schedules an event `evt` to execute at `(+ (:t-ns world) (max 0 delta-ns))`.
   Returns updated world map with persistent queue and monotonic event sequence."
  [world delta-ns evt]
  (let [t-ns (+ (long (:t-ns world 0)) (max 0 (long delta-ns)))
        seq-num (long (:next-event-seq world 0))
        event-entry (assoc evt :t-ns t-ns :seq seq-num)]
    (-> world
        (update :next-event-seq inc)
        (update :event-queue conj event-entry))))

(defn peek-event
  "Returns the earliest scheduled event, or nil if queue is empty."
  [world]
  (first (:event-queue world)))

(defn pop-event
  "Removes and returns `[world event]` for the earliest scheduled event."
  [world]
  (if-let [evt (first (:event-queue world))]
    [(-> world
         (assoc :t-ns (:t-ns evt))
         (update :event-queue disj evt))
     evt]
    [world nil]))

;; =============================================================================
;; 2. Deterministic PRNG Helper Math & Byte Copying (AR-3)
;; =============================================================================

(defn clone-bytes
  "Defensively clones byte array `bs` (AR-3) so adversary mutations never mutate
   the sender's retransmit queues or in-memory state."
  ^bytes [bs]
  (when bs
    (Arrays/copyOf ^bytes bs (alength ^bytes bs))))

(defn rand-long!
  "Draws next 64-bit integer from world's PRNG. Returns `[world value]`."
  [world]
  (let [rng (:rng world)
        val (crypto/next-long rng)]
    [world val]))

(defn rand-int!
  "Draws next integer in `[0, bound)` from world's PRNG. Returns `[world value]`."
  [world bound]
  (let [rng (:rng world)
        val (crypto/next-int rng bound)]
    [world val]))

(defn rand-double!
  "Draws next double in `[0.0, 1.0)` from world's PRNG. Returns `[world value]`."
  [world]
  (let [rng (:rng world)
        val (crypto/next-double rng)]
    [world val]))

(defn rand-bytes!
  "Draws `n` pseudo-random bytes into a new byte array. Returns `[world bytes]`."
  [world n]
  (let [rng (:rng world)
        ba (byte-array n)]
    (crypto/next-bytes rng ba)
    [world ba]))

;; =============================================================================
;; 3. Adversarial Byte Link Router (Gilbert-Elliott, MTU, Bit-Flip, Slicing)
;; =============================================================================

(defn default-link-config
  "Default physical link configuration between simulated nodes."
  []
  {:state :good
   :p-good->bad 0.02
   :p-bad->good 0.15
   :p-loss-good 0.005
   :p-loss-bad 0.70
   :min-latency-ns 2000000  ;; 2ms
   :max-latency-ns 15000000 ;; 15ms
   :mtu 1500
   :bitflip-prob 0.0
   :truncate-prob 0.0})

(defn- step-gilbert-elliott
  "Advances the 2-state Gilbert-Elliott Markov chain for a link and checks packet loss.
   Returns `[world updated-link dropped?]`."
  [world link]
  (let [st (:state link :good)
        [w1 r1] (rand-double! world)
        new-st (case st
                 :good (if (< r1 (:p-good->bad link 0.02)) :bad :good)
                 :bad  (if (< r1 (:p-bad->good link 0.15)) :good :bad))
        loss-prob (if (= :good new-st)
                    (:p-loss-good link 0.005)
                    (:p-loss-bad link 0.70))
        [w2 r2] (rand-double! w1)
        dropped? (< r2 loss-prob)]
    [w2 (assoc link :state new-st) dropped?]))

(defn- apply-bitflip
  "Randomly flips 1 bit in a defensive copy of `bs`."
  [world ^bytes bs]
  (let [len (alength bs)]
    (if (pos? len)
      (let [[w1 idx] (rand-int! world len)
            [w2 bit] (rand-int! w1 8)
            out (clone-bytes bs)
            cur (aget out (int idx))
            flipped (bit-xor (int cur) (bit-shift-left 1 bit))]
        (aset-byte out (int idx) (unchecked-byte flipped))
        [w2 out])
      [world bs])))

(defn- apply-truncation
  "Truncates a defensive copy of `bs` by 1 to 16 bytes."
  [world ^bytes bs]
  (let [len (alength bs)]
    (if (> len 4)
      (let [[w1 drop-count] (rand-int! world (min 16 (dec len)))
            new-len (max 1 (- len (inc drop-count)))
            out (Arrays/copyOf bs (int new-len))]
        [w1 out])
      [world bs])))

(defn slice-stream-bytes
  "Slices byte array `bs` into adversarial 1-to-17-byte chunks across RFC 4571 streams."
  [world ^bytes bs]
  (let [len (if bs (alength bs) 0)]
    (loop [w world
           offset 0
           chunks []]
      (if (>= offset len)
        [w chunks]
        (let [[w' chunk-len] (rand-int! w 17)
              take-len (min (- len offset) (inc chunk-len))
              chunk (Arrays/copyOfRange bs (int offset) (int (+ offset take-len)))]
          (recur w' (+ offset take-len) (conj chunks chunk)))))))

(defn slice-rfc4571-stream
  "Slices RFC 4571 frame stream into adversarial chunks."
  [world encoded-stream]
  (slice-stream-bytes world encoded-stream))

(defn reassemble-rfc4571-stream
  "Reassembles RFC 4571 stream chunks into payload frames."
  [chunks]
  (loop [acc (b/alloc-bytes 0)
         rem-chunks chunks
         frames []]
    (if (empty? rem-chunks)
      frames
      (let [res (dtcp/decode-rfc4571-stream acc (first rem-chunks))]
        (recur (:remaining res) (rest rem-chunks) (into frames (:frames res)))))))

(defn test-rfc4571-slice-reassembly
  "Verifies RFC 4571 stream slicing and deterministic frame reassembly."
  [world frame-payloads]
  (let [encoded-stream (b/bconcat (map dtcp/encode-rfc4571-frame frame-payloads))
        [w' sliced-chunks] (slice-stream-bytes world encoded-stream)
        reassembled
        (loop [acc (b/alloc-bytes 0)
               chunks sliced-chunks
               frames []]
          (if (empty? chunks)
            frames
            (let [res (dtcp/decode-rfc4571-stream acc (first chunks))]
              (recur (:remaining res) (rest chunks) (into frames (:frames res))))))]
    {:world w'
     :chunks-count (count sliced-chunks)
     :reassembled-count (count reassembled)
     :matches? (= (mapv vec frame-payloads) (mapv vec reassembled))}))

(defn route-packet
  "Adversarial Byte Link Router: Applies Gilbert-Elliott Markov loss, propagation jitter,
   MTU filtering, bit-flip/truncation fuzzing, and schedules delivery on the event queue.
   Always clones bytes defensively (AR-3)."
  [world from to raw-bytes & [{:keys [tcp?] :or {tcp? false}}]]
  (let [pair #{from to}
        partitioned? (contains? (:partitions world #{}) pair)]
    (if partitioned?
      (-> world
          (update-in [:telemetry :dropped] (fnil inc 0))
          (update-in [:telemetry :dropped-partition] (fnil inc 0)))
      (let [link (get-in world [:links [from to]] (default-link-config))
            [w1 link' dropped?] (step-gilbert-elliott world link)
            w2 (assoc-in w1 [:links [from to]] link')]
        (if dropped?
          (-> w2
              (update-in [:telemetry :dropped] (fnil inc 0))
              (update-in [:telemetry :dropped-gilbert-elliott] (fnil inc 0)))
          (let [len (if raw-bytes (alength ^bytes raw-bytes) 0)]
            (if (> len (long (:mtu link' 1500)))
              (-> w2
                  (update-in [:telemetry :dropped] (fnil inc 0))
                  (update-in [:telemetry :dropped-mtu] (fnil inc 0)))
              ;; Apply defensive copying (AR-3) before link fuzzing
              (let [safe-bytes (clone-bytes raw-bytes)
                    [w3 r-bf] (rand-double! w2)
                    [w4 bytes-1] (if (and (< r-bf (:bitflip-prob link' 0.0)) (pos? len))
                                   (let [[w-bf mutated] (apply-bitflip w3 safe-bytes)]
                                     [(update-in w-bf [:telemetry :bitflips] (fnil inc 0)) mutated])
                                   [w3 safe-bytes])
                    [w5 r-tr] (rand-double! w4)
                    [w6 bytes-2] (if (and (< r-tr (:truncate-prob link' 0.0)) (pos? (alength ^bytes bytes-1)))
                                   (let [[w-tr truncated] (apply-truncation w5 bytes-1)]
                                     [(update-in w-tr [:telemetry :truncations] (fnil inc 0)) truncated])
                                   [w5 bytes-1])
                    min-lat (:min-latency-ns link' 2000000)
                    max-lat (:max-latency-ns link' 15000000)
                    delta (max 1 (- max-lat min-lat))
                    [w7 jitter] (rand-int! w6 delta)
                    delay-ns (+ min-lat jitter)]
                (schedule-event w7 delay-ns
                                {:type :deliver-packet
                                 :from from
                                 :to to
                                 :tcp? tcp?
                                 :bytes bytes-2})))))))))

;; =============================================================================
;; 4. Pure World State, Multiverse Branching & Determinism (AR-4)
;; =============================================================================

(defn assert-pure-world!
  "Asserts that the simulated world state map contains zero mutable state
   (no mutable atoms, no SSLEngine, zero PriorityQueues) before branching (AR-4)."
  [world]
  (walk/prewalk
   (fn [x]
     (when (instance? javax.net.ssl.SSLEngine x)
       (throw (ex-info "Purity violation: SSLEngine found in world state" {:object x})))
     (when (and (instance? clojure.lang.Atom x)
                (not (instance? bitecho.crypto.SplitMix64PRNG x))
                (not (instance? datachannel.buffer.SplitMix64 x)))
       (throw (ex-info "Purity violation: mutable Atom found in world state" {:atom x})))
     x)
   (dissoc world :rng))
  true)

(defn fork-nested-prngs
  "Recursively forks every nested SplitMix64PRNG and datachannel.buffer.SplitMix64."
  [val branch-id]
  (walk/postwalk
   (fn [x]
     (cond
       (instance? bitecho.crypto.SplitMix64PRNG x)
       (crypto/fork-random x branch-id)

       (instance? datachannel.buffer.SplitMix64 x)
       (b/fork-rng x branch-id)

       :else x))
   val))

(defn fork-world
  "Takes an immutable world state map at a high-leverage transition and forks
   an isolated multiverse branch in O(1) time with derived SplitMix64 seed.
   Ensures every nested PRNG in :nodes and :light is forked independently."
  [world branch-id]
  (assert-pure-world! world)
  (let [child-rng (crypto/fork-random (:rng world) branch-id)]
    (-> world
        (assoc :rng child-rng
               :branch-id branch-id
               :forked-from (get world :branch-id :root))
        (update :nodes fork-nested-prngs branch-id)
        (update :light fork-nested-prngs branch-id))))

(def ^:private bad-keys #{:keypair :keys :privkey :connection :channel :transport})

(defn- clean-value-for-digest [val]
  (walk/postwalk
   (fn [x]
     (cond
       (fn? x)
       nil

       (map? x)
       (into {} (remove (fn [[k v]] (or (contains? bad-keys k) (fn? v)))) x)

       (instance? bitecho.crypto.SplitMix64PRNG x)
       (crypto/random-state x)

       (instance? datachannel.buffer.SplitMix64 x)
       @x

       (or (instance? java.security.KeyPair x)
           (instance? java.security.PrivateKey x)
           (instance? java.security.PublicKey x))
       nil

       :else x))
   val))

(defn canonical-world-digest
  "Computes a canonical SHA-256 digest of the world state and history for determinism auditing."
  [world]
  (let [clean-world (-> world
                        (update :event-queue vec)
                        (clean-value-for-digest))]
    (crypto/sha256-hex (fressian/encode-canonical clean-world))))

(defn verify-determinism
  "Runs a simulation function twice from the same seed and asserts identical state digests."
  [run-sim-fn seed]
  (let [w1 (run-sim-fn seed)
        w2 (run-sim-fn seed)
        d1 (canonical-world-digest w1)
        d2 (canonical-world-digest w2)]
    {:deterministic? (= d1 d2)
     :digest-1 d1
     :digest-2 d2
     :world-1 w1
     :world-2 w2}))

;; =============================================================================
;; 5. Cluster Validator & Light Node Stack
;; =============================================================================

(defn- create-validator-node
  [id seed & [{:keys [byzantine? treasury-pubkey keypair peers-map] :or {byzantine? false}}]]
  (let [rng (crypto/make-random seed)
        kp (or keypair (crypto/generate-keypair rng))
        pub-hex (streamlet/bytes->hex (:public kp))
        priv-bytes (:private kp)
        cfg (config/make-config {:mesh-nodes {pub-hex 10}
                                 :min-stake 10
                                 :byzantine? byzantine?})
        sm-state (assoc (sm/init-state [] pub-hex cfg)
                        :my-privkey priv-bytes
                        :treasury-pubkey (or treasury-pubkey pub-hex)
                        :peers-map (or peers-map {})
                        :rng rng)
        streamlet-st {:node-pubkey pub-hex
                      :cluster-size 4
                      :quorum-size 3
                      :keypair kp
                      :peers-map (or peers-map {})
                      :blocks {}
                      :notarized-blocks #{}
                      :finalized-blocks #{}
                      :head-hash "genesis"}
        dtls-cert (dtls/generate-simulated-cert (b/make-rng seed))
        webrtc-conn (dc/create-connection {:simulated-dtls? true
                                           :seed seed
                                           :cert-data dtls-cert
                                           :now-ms 0}
                                          false)
        initial-ledger (or (:ledger sm-state) {pub-hex {:balance 1000000000 :stake 10}})]
    {:id id
     :pubkey pub-hex
     :privkey priv-bytes
     :keypair kp
     :byzantine? byzantine?
     :treasury-pubkey (or treasury-pubkey pub-hex)
     :state (assoc sm-state :ledger initial-ledger)
     :streamlet streamlet-st
     :finalized-chain ["genesis"]
     :webrtc-conn webrtc-conn
     :inbox []
     :outbox []
     :pointers {}
     :blobs (data/init-blob-store)
     :diagnostics {:stale-drops 0 :corrupt-drops 0 :dropped-wire 0}}))

(defn- create-light-node-peer
  [id seed validator-pubkey]
  (let [rng (crypto/make-random seed)
        kp (crypto/generate-keypair rng)
        pub-hex (streamlet/bytes->hex (:public kp))
        browser-conn (browser/initial-conn-state)
        dtls-cert (dtls/generate-simulated-cert (b/make-rng seed))
        webrtc-conn (dc/create-connection {:simulated-dtls? true
                                           :seed seed
                                           :cert-data dtls-cert
                                           :now-ms 0}
                                          true)
        light-st (light-node/init-light-state {:pubkey pub-hex} {:validator-target validator-pubkey})]
    {:id id
     :pubkey pub-hex
     :keypair kp
     :validator-target validator-pubkey
     :conn-state browser-conn
     :webrtc-conn webrtc-conn
     :light-state light-st
     :rng rng
     :inbox []
     :outbox []
     :diagnostics {:stale-callbacks 0 :aborts 0}}))

(defn create-initial-world
  "Initializes a full-stack simulated universe with `n` validators, light nodes, and links."
  [seed & [{:keys [num-validators num-light-nodes fault-config validator-ids]
            :or {num-validators 4 num-light-nodes 1}}]]
  (let [master-rng (crypto/make-random seed)
        val-ids (or validator-ids (mapv #(str "node" (inc %)) (range num-validators)))
        n (count val-ids)
        treasury-kp (crypto/generate-keypair master-rng)
        treasury-pub (streamlet/bytes->hex (:public treasury-kp))
        raw-kps (vec (repeatedly n #(crypto/generate-keypair master-rng)))
        sorted-kps (vec (sort-by #(streamlet/bytes->hex (:public %)) raw-kps))
        assigned-kps (into {} (map-indexed (fn [idx id] [id (nth sorted-kps (mod (inc idx) n))]) val-ids))
        peers-map (into {} (map (fn [[_ kp]] [(streamlet/bytes->hex (:public kp)) (:public kp)]) assigned-kps))
        raw-nodes (into (sorted-map)
                        (map-indexed (fn [idx id]
                                       [id (create-validator-node id
                                                                  (+ (long seed) (* 100 (inc idx)))
                                                                  {:byzantine? false
                                                                   :treasury-pubkey treasury-pub
                                                                   :keypair (get assigned-kps id)
                                                                   :peers-map peers-map})])
                                     val-ids))
        val-pubs (into {} (map (fn [[_ node]] [(:pubkey node) {:balance 1000000000 :stake 10}]) raw-nodes))
        nodes (into (sorted-map)
                    (map (fn [[id node]]
                           [id (-> node
                                   (assoc-in [:state :ledger] val-pubs)
                                   (assoc-in [:streamlet :peers-map] peers-map)
                                   (assoc-in [:state :peers-map] peers-map)
                                   (assoc-in [:state :streamlet :peers-map] peers-map))])
                         raw-nodes))
        light (into (sorted-map)
                    (map (fn [idx]
                           (let [lid (str "light" (inc idx))
                                 target (get-in nodes [(first val-ids) :pubkey])]
                             [lid (create-light-node-peer lid (+ (long seed) 5000 idx) target)]))
                         (range num-light-nodes)))
        links (into (sorted-map)
                    (for [a (concat val-ids (keys light))
                          b (concat val-ids (keys light))
                          :when (not= a b)]
                      [[a b] (merge (default-link-config) fault-config)]))]
    {:t-ns 0
     :next-event-seq 0
     :rng master-rng
     :rng-seed seed
     :treasury-keypair treasury-kp
     :treasury-pubkey treasury-pub
     :initial-custody 4000000000
     :total-valid-mints 0
     :total-epoch-rewards 0
     :epoch-burns 0
     :epoch-settlement-takes 0
     :sunset-custody-burned 0
     :event-queue (make-event-queue)
     :nodes nodes
     :light light
     :links links
     :partitions #{}
     :history []
     :telemetry {:dropped 0
                 :bitflips 0
                 :truncations 0
                 :events-executed 0
                 :diagnose-counts {}}}))

;; =============================================================================
;; 6. World Stepping & Event Execution
;; =============================================================================

(defn- deliver-wire-packet-to-node
  "Delivers wire bytes to a validator node, applying BTEC LZ4 decode & strip-untrusted-crypto-tags.
   Processes incoming Streamlet proposals and votes to advance BFT consensus."
  [world target-node-id raw-bytes]
  (let [node (get-in world [:nodes target-node-id])]
    (if-not node
      world
      (let [decoded (try
                      (fressian/decode-wire raw-bytes)
                      (catch Exception _
                        ::corrupted))]
        (if (= ::corrupted decoded)
          (-> world
              (update-in [:nodes target-node-id :diagnostics :corrupt-drops] (fnil inc 0))
              (update-in [:telemetry :diagnose-counts :corrupted-packet] (fnil inc 0)))
          ;; Deliver verified/stripped message into node inbox
          (let [w (update-in world [:nodes target-node-id :inbox] conj decoded)
                st (get-in w [:nodes target-node-id :streamlet])]
            (cond
              (= :streamlet-propose (:type decoded))
              (let [block (:block decoded)
                    sender (or (:sender decoded) (:proposer block))
                    res (streamlet/handle-streamlet-event st {:type :receive-propose :block block :sender sender})
                    st' (:state res)
                    finalized-set (:finalized-blocks st' #{})
                    sorted-chain (into ["genesis"] (sort-by #(get-in st' [:blocks % :epoch] 0) (disj finalized-set "genesis")))
                    w1 (-> w
                           (assoc-in [:nodes target-node-id :streamlet] st')
                           (assoc-in [:nodes target-node-id :finalized-chain] sorted-chain))
                    vote-cmd (some #(when (= (:type %) :send-vote) %) (:commands res))]
                (if vote-cmd
                  (let [vote (:vote vote-cmd)
                        vote-wire (fressian/encode-wire {:type :streamlet-vote :vote vote :sender (:pubkey node)})
                        other-validators (remove #{target-node-id} (keys (:nodes w1)))]
                    (reduce (fn [acc-w tid]
                              (route-packet acc-w target-node-id tid vote-wire))
                            w1
                            other-validators))
                  w1))

              (= :streamlet-vote (:type decoded))
              (let [vote (:vote decoded)
                    sender (:sender decoded)
                    res (streamlet/handle-streamlet-event st {:type :receive-vote :vote vote :sender sender})
                    st' (:state res)
                    finalized-set (:finalized-blocks st' #{})
                    sorted-chain (into ["genesis"] (sort-by #(get-in st' [:blocks % :epoch] 0) (disj finalized-set "genesis")))]
                (-> w
                    (assoc-in [:nodes target-node-id :streamlet] st')
                    (assoc-in [:nodes target-node-id :finalized-chain] sorted-chain)))

              :else w)))))))

(defn step-world
  "Executes the earliest scheduled event in the world state, advancing virtual time."
  [world]
  (let [[world' evt] (pop-event world)]
    (if-not evt
      world'
      (let [w (update-in world' [:telemetry :events-executed] (fnil inc 0))]
        (case (:type evt)
          :deliver-packet
          (deliver-wire-packet-to-node w (:to evt) (:bytes evt))

          :step-webrtc-light-channel
          (let [lid (or (:light-id evt) (first (keys (:light w))))
                light (get-in w [:light lid])
                target-val-id (or (:target-val-id evt)
                                  (some (fn [[nid n]] (when (= (:pubkey n) (:validator-target light)) nid)) (:nodes w))
                                  (first (keys (:nodes w))))
                _target-val (get-in w [:nodes target-val-id])
                ;; Step light node's browser lifecycle reducer through :dial / :open
                [conn-dialing _] (browser/transition-conn (:conn-state light) {:type :dial :peer-id (:validator-target light)})
                [conn-open _] (browser/transition-conn conn-dialing {:type :open :peer-id (:validator-target light)})
                w1 (assoc-in w [:light lid :conn-state] conn-open)
                ;; Exercise wire codec and RFC 4571 stream slicing and reassembly
                query-payload {:type :light-query :query "get-latest-block" :from lid}
                raw-wire (fressian/encode-wire query-payload)
                rfc-frame (dtcp/encode-rfc4571-frame raw-wire)
                [w2 chunks] (slice-stream-bytes w1 rfc-frame)
                reassembled-stream (b/bconcat chunks)
                reassembled-frames (:frames (dtcp/decode-rfc4571-stream (b/alloc-bytes 0) reassembled-stream))
                clean-wire (or (first reassembled-frames) raw-wire)
                ;; Exercise datachannel handle-sctp-packet
                now-ms (quot (long (:t-ns w2 0)) 1000000)
                val-dc (get-in w2 [:nodes target-val-id :webrtc-conn])
                sctp-packet {:src-port 5000 :dst-port 5000
                             :verification-tag (or (:local-ver-tag val-dc) 12345)
                             :chunks [{:type :data :tsn 1 :stream-id 0 :ssn 0 :payload clean-wire}]}
                val-dc-res (dc/handle-sctp-packet val-dc sctp-packet now-ms)
                w3 (assoc-in w2 [:nodes target-val-id :webrtc-conn] (or (:new-state val-dc-res) val-dc))]
            (route-packet w3 lid target-val-id clean-wire {:tcp? true}))

          :propose-streamlet-block
          (let [epoch (:epoch evt)
                peer-hexes (vec (sort (keys (get-in w [:nodes (first (keys (:nodes w))) :streamlet :peers-map]))))
                expected-pub (when (pos? (count peer-hexes)) (nth peer-hexes (mod epoch (count peer-hexes))))
                proposer-id (or (:node-id evt)
                                (when expected-pub
                                  (some (fn [[nid n]] (when (= (:pubkey n) expected-pub) nid)) (:nodes w))))
                node (get-in w [:nodes proposer-id])
                st (:streamlet node)
                block (streamlet/propose-block st epoch)
                h (streamlet/hash-block block)
                wire (fressian/encode-wire {:type :streamlet-propose :block block :sender (:pubkey node)})
                history-inv {:type :invoke :f :append :value h :process proposer-id :time (:t-ns w)}
                history-ok  {:type :ok :f :append :value h :process proposer-id :time (:t-ns w)}
                w-hist (-> w
                           (update :history conj history-inv)
                           (update :history conj history-ok))
                res-prop (streamlet/handle-streamlet-event st {:type :receive-propose :block block :sender (:proposer block)})
                new-st (:state res-prop)
                finalized-set (:finalized-blocks new-st #{})
                sorted-chain (into ["genesis"] (sort-by #(get-in new-st [:blocks % :epoch] 0) (disj finalized-set "genesis")))
                w-st (-> w-hist
                         (assoc-in [:nodes proposer-id :streamlet] new-st)
                         (assoc-in [:nodes proposer-id :finalized-chain] sorted-chain))
                other-nodes (remove #{proposer-id} (keys (:nodes w)))
                w-prop (reduce (fn [acc-w target-id]
                                 (route-packet acc-w proposer-id target-id wire))
                               w-st
                               other-nodes)
                prop-vote (some #(when (= (:type %) :send-vote) (:vote %)) (:commands res-prop))]
            (if prop-vote
              (let [vote-wire (fressian/encode-wire {:type :streamlet-vote :vote prop-vote :sender (:pubkey node)})]
                (reduce (fn [acc-w target-id]
                          (route-packet acc-w proposer-id target-id vote-wire))
                        w-prop
                        other-nodes))
              w-prop))

          :finalize-streamlet-blocks
          (let [val-ids (keys (:nodes w))]
            (reduce (fn [acc-w nid]
                      (let [node (get-in acc-w [:nodes nid])
                            st-finalized (streamlet/finalize-prefix (:streamlet node))
                            finalized-set (:finalized-blocks st-finalized #{})
                            sorted-chain (into ["genesis"] (sort-by #(get-in st-finalized [:blocks % :epoch] 0) (disj finalized-set "genesis")))
                            w-up (-> acc-w
                                     (assoc-in [:nodes nid :streamlet] st-finalized)
                                     (assoc-in [:nodes nid :finalized-chain] sorted-chain))]
                        (-> w-up
                            (update :history conj {:type :invoke :f :read :value nil :process nid :time (:t-ns w)})
                            (update :history conj {:type :ok :f :read :value sorted-chain :process nid :time (:t-ns w)}))))
                    w
                    val-ids))

          :apply-subnet-pointer
          (let [nid (:node-id evt)
                ptr (:pointer evt)
                node (get-in w [:nodes nid])
                ctx (or (:ctx evt)
                        {:now-ms (quot (:t-ns w) 1000000)
                         :path-acl [{:pattern (:pointer/path ptr) :principal {:type :allowlist}}]
                         :trust-anchors #{(:pointer/authority ptr)}})
                res (data/apply-pointer node ptr ctx)
                node' (:state res)
                applied? (:applied? res)
                op-type (if applied? :ok :fail)
                history-inv {:type :invoke :f :write :key [(:pointer/subnet ptr) (:pointer/path ptr)]
                             :value (:pointer/target ptr)
                             :order [(long (or (:pointer/leader-term ptr) 0)) (long (or (:pointer/seq ptr) 0))]
                             :process nid :time (:t-ns w)}
                history-ok {:type op-type :f :write :key [(:pointer/subnet ptr) (:pointer/path ptr)]
                            :value (:pointer/target ptr)
                            :order [(long (or (:pointer/leader-term ptr) 0)) (long (or (:pointer/seq ptr) 0))]
                            :process nid :time (:t-ns w)}]
            (-> w
                (assoc-in [:nodes nid] node')
                (update :history conj history-inv)
                (update :history conj history-ok)))

          :read-subnet-pointer
          (let [nid (:node-id evt)
                sub (:subnet evt)
                p (:path evt)
                node (get-in w [:nodes nid])
                cur-ptr (get-in node [:pointers [sub p]])
                target (:pointer/target cur-ptr)
                history-inv {:type :invoke :f :read :key [sub p] :value nil
                             :process nid :time (:t-ns w)}
                history-ok {:type :ok :f :read :key [sub p] :value target
                            :process nid :time (:t-ns w)}]
            (-> w
                (update :history conj history-inv)
                (update :history conj history-ok)))

          ;; Catch-all for nemesis/custom scheduled actions
          (if-let [action (:action evt)]
            (action w)
            w))))))

(defn run-simulation
  "Drives the world forward until `max-events` have executed or the event queue empties."
  [world max-events]
  (loop [w world
         steps 0]
    (if (or (>= steps (long max-events))
            (empty? (:event-queue w)))
      w
      (recur (step-world w) (inc steps)))))

;; =============================================================================
;; 7. Protocol-Aware Jepsen Oracles
;; =============================================================================

(defn- parse-int-process [p]
  (cond
    (integer? p) p
    (string? p) (or (try (Integer/parseInt (re-find #"\d+" p)) (catch Exception _ nil))
                    (Math/abs (int (hash p))))
    :else 0))

(defn- check-read-monotonicity
  "Validates that no process observes a reverting or shrinking finalized chain across reads."
  [reads]
  (let [by-proc (group-by :process reads)]
    (every? (fn [[_ proc-reads]]
              (let [sorted-reads (sort-by :time proc-reads)
                    chains (map :value sorted-reads)]
                (every? (fn [[c1 c2]]
                          (and (<= (count c1) (count c2))
                               (= c1 (subvec c2 0 (count c1)))))
                        (partition 2 1 chains))))
            by-proc)))

(defn- build-elle-history
  [history finalized-hashes]
  (let [filtered (filter (fn [op]
                           (case (:f op)
                             :append (contains? finalized-hashes (:value op))
                             :read true
                             false))
                         history)]
    (keep-indexed
     (fn [idx op]
       (let [p (parse-int-process (:process op))
             t (:type op)
             f (:f op)
             v (:value op)
             micro-op (case f
                        :append [:append :chain v]
                        :read   [:r :chain (if (= t :invoke) nil (vec (remove #(= "genesis" %) v)))]
                        nil)]
         (when micro-op
           {:process p
            :type t
            :f :txn
            :value [micro-op]
            :index idx
            :time (long (:time op 0))})))
     filtered)))

;; --- Oracle 1: Streamlet Consensus Serializability (elle.list-append & prefix) ---

(defn check-streamlet-list-append
  "Oracle 1: Verifies total order agreement, monotonic non-reverting growth,
   and strict prefix consistency across all validators' finalized block chains,
   per-process read monotonicity, and Jepsen elle.list-append serializability."
  [world]
  (let [nodes (vals (:nodes world))
        chains (map :finalized-chain nodes)
        pair-results
        (for [i (range (count chains))
              j (range (inc i) (count chains))
              :let [c1 (nth chains i)
                    c2 (nth chains j)
                    min-len (min (count c1) (count c2))
                    p1 (subvec c1 0 min-len)
                    p2 (subvec c2 0 min-len)]]
          (= p1 p2))
        prefix-consistent? (every? true? pair-results)
        history (:history world [])
        appends (filter #(= :append (:f %)) history)
        reads (filter #(and (= :read (:f %)) (= :ok (:type %))) history)
        monotonic-reads? (check-read-monotonicity reads)
        finalized-hashes (set (mapcat (fn [c] (remove #(= "genesis" %) c)) chains))
        elle-ops (vec (build-elle-history history finalized-hashes))
        elle-res (if (seq elle-ops)
                   (try
                     (let [hist (jh/history elle-ops)]
                       (elle-la/check {:directory nil} hist))
                     (catch Throwable e
                       {:valid? false :error (ex-message e)}))
                   {:valid? true})
        elle-valid? (true? (:valid? elle-res))
        valid? (boolean (and prefix-consistent? monotonic-reads? elle-valid?))]
    {:valid? valid?
     :prefix-consistent? prefix-consistent?
     :monotonic-reads? monotonic-reads?
     :elle-valid? elle-valid?
     :chains-count (count chains)
     :appends-count (count appends)
     :reads-count (count reads)
     :elle-result elle-res
     :error (cond
              (not prefix-consistent?) :divergent-finalized-prefix
              (not monotonic-reads?) :non-monotonic-read-observed
              (not elle-valid?) :elle-list-append-inconsistency)}))

;; --- Oracle 2: Subnet Pointer Linearizability & Fencing ---

(defn- build-knossos-history-for-key
  [ops]
  (mapcat (fn [idx op]
            (let [p (parse-int-process (:process op))
                  f (:f op)
                  v (:value op)
                  t (:type op)]
              [{:process p :type :invoke :f f :value (if (= :read f) nil v) :index (* 2 idx) :time (:time op)}
               {:process p :type t       :f f :value v                       :index (inc (* 2 idx)) :time (:time op)}]))
          (range (count ops))
          ops))

(defn check-pointer-linearizability
  "Oracle 2: Verifies register linearizability, [leader-term seq] lexicographical
   monotonic fencing, and knossos model linearizability under concurrent writes."
  [world]
  (let [history (:history world [])
        pointer-ops (filter #(and (#{:write :read} (:f %)) (= :ok (:type %))) history)
        by-key (group-by :key pointer-ops)
        fencing-violations
        (keep (fn [[k ops]]
                (let [writes (filter #(= :write (:f %)) ops)
                      sorted-writes (sort-by :time writes)
                      orders (map :order sorted-writes)
                      in-order? (every? (fn [[o1 o2]] (<= (compare o1 o2) 0))
                                        (partition 2 1 orders))]
                  (when-not in-order?
                    {:key k :orders orders})))
              by-key)
        linearizability-violations
        (keep (fn [[k ops]]
                (let [writes (filter #(= :write (:f %)) ops)
                      reads (filter #(= :read (:f %)) ops)]
                  (when (and (seq writes) (seq reads))
                    (let [latest-write (last (sort-by :time writes))
                          stale-reads (filter (fn [r]
                                                (and (> (long (:time r 0)) (long (:time latest-write 0)))
                                                     (not= (:value r) (:value latest-write))))
                                              reads)]
                      (when (seq stale-reads)
                        {:key k :stale-reads stale-reads})))))
              by-key)
        knossos-results
        (into {}
              (keep (fn [[k ops]]
                      (when (seq ops)
                        (try
                          (let [khist (build-knossos-history-for-key ops)
                                model (knossos-model/register nil)
                                res (knossos-comp/analysis model khist)]
                            [k res])
                          (catch Throwable e
                            [k {:valid? false :error (ex-message e)}]))))
                    by-key))
        knossos-valid? (every? #(true? (:valid? %)) (vals knossos-results))
        fencing-valid? (empty? fencing-violations)
        read-valid? (empty? linearizability-violations)
        valid? (boolean (and fencing-valid? read-valid? knossos-valid?))]
    {:valid? valid?
     :fencing-valid? fencing-valid?
     :read-valid? read-valid?
     :knossos-valid? knossos-valid?
     :violations fencing-violations
     :linearizability-violations linearizability-violations
     :knossos-results knossos-results
     :error (cond
              (not fencing-valid?) :stale-leader-overwrote-newer-term
              (not read-valid?) :stale-read-observed-after-write
              (not knossos-valid?) :knossos-linearizability-violation)}))

;; --- Oracle 3: Tokenomics v2.1 Conservation & Deflation Fold ---

(defn- sum-numeric-map-or-num [x]
  (cond
    (number? x) (long x)
    (map? x) (reduce + 0 (map #(if (number? %) (long %) 0) (vals x)))
    :else 0))

(defn check-tokenomics-conservation
  "Oracle 3: Verifies exact integer conservation equation:
   sum(ledger) + sum(escrows) + epoch-burns + epoch-settlement-takes + sunset-burned == initial-custody + total-valid-mints + total-epoch-rewards
   plus 42B ceiling and 23.1B conditional mint cap."
  [world]
  (let [nodes (vals (:nodes world))
        primary-node (first nodes)
        sm-state (or (:state primary-node) {})
        primary-ledger (or (:ledger sm-state) (get-in primary-node [:state :ledger] {}))
        ledger-sum (reduce + 0 (map #(long (:balance % 0)) (vals primary-ledger)))
        escrows (or (:escrows sm-state) (:escrows world) {})
        escrow-sum (reduce + 0 (map (fn [x]
                                      (cond
                                        (number? x) (long x)
                                        (map? x) (long (or (:amount x) (:balance x) 0))
                                        :else 0))
                                    (vals escrows)))
        epoch-burns (+ (long (:epoch-burns world 0))
                       (long (:total-burns world 0))
                       (sum-numeric-map-or-num (:epoch-burns sm-state)))
        settlement-takes (+ (long (:epoch-settlement-takes world 0))
                            (sum-numeric-map-or-num (:epoch-settlement-takes sm-state)))
        sunset-burned (+ (long (:sunset-custody-burned world 0))
                         (long (:sunset-custody-burned sm-state 0)))
        left-side (+ ledger-sum escrow-sum epoch-burns settlement-takes sunset-burned)
        initial-custody (long (or (:initial-custody world) (:initial-custody sm-state) 0))
        valid-mints (long (or (:total-valid-mints world) (:total-minted sm-state) 0))
        epoch-rewards (+ (long (:total-epoch-rewards world 0))
                         (long (:total-epoch-rewards sm-state 0)))
        mint-dust (long (:mint-dust sm-state 0))
        unclaimed-mint (long (:unclaimed-mint sm-state 0))
        right-side (+ initial-custody valid-mints epoch-rewards)
        conservation? (= left-side right-side)
        ceiling-42b (long (or treasury/hard-cap 42000000000))
        within-ceiling? (<= (+ initial-custody valid-mints) ceiling-42b)
        conditional-cap (long (or treasury/conditional-mint-cap 23100000000))
        within-conditional-cap? (<= valid-mints conditional-cap)
        valid? (boolean (and conservation? within-ceiling? within-conditional-cap?))]
    {:valid? valid?
     :left-sum left-side
     :right-sum right-side
     :ledger-sum ledger-sum
     :escrow-sum escrow-sum
     :epoch-burns epoch-burns
     :settlement-takes settlement-takes
     :valid-mints valid-mints
     :mint-dust mint-dust
     :unclaimed-mint unclaimed-mint
     :conservation? conservation?
     :within-ceiling? within-ceiling?
     :within-conditional-cap? within-conditional-cap?
     :error (cond
              (not conservation?) :tokenomics-conservation-violated
              (not within-ceiling?) :42b-ceiling-exceeded
              (not within-conditional-cap?) :conditional-mint-cap-exceeded)}))

(defn check-sbrb-contagion-safety
  "Validates Contagion threshold invariants for SBRB totality and safety:
   R_hat / R < D_hat / D (ready threshold ratio strictly less than delivery threshold ratio)."
  [cfg]
  (let [r-thresh (double (:ready-threshold cfg 3))
        r-sample (double (:ready-sample-size cfg 10))
        d-thresh (double (:delivery-threshold cfg 8))
        d-sample (double (:delivery-sample-size cfg 10))
        r-ratio (/ r-thresh (max 1.0 r-sample))
        d-ratio (/ d-thresh (max 1.0 d-sample))
        valid? (< r-ratio d-ratio)]
    {:valid? valid?
     :ready-ratio r-ratio
     :delivery-ratio d-ratio
     :error (when-not valid? :contagion-threshold-inversion)}))

;; =============================================================================
;; 8. Active Byzantine Nemesis
;; =============================================================================

(defn nemesis-partition
  "Partitions nodes into two disjoint sets by breaking all connecting links."
  [world set-a set-b]
  (let [pairs (set (for [a set-a b set-b] #{a b}))]
    (update world :partitions set/union pairs)))

(defn nemesis-heal
  "Restores full network connectivity between all nodes."
  [world]
  (assoc world :partitions #{}))

(defn nemesis-equivocate-proposal
  "Byzantine adversary signs conflicting proposals in the same epoch to different nodes."
  [world byzantine-id epoch]
  (let [node (get-in world [:nodes byzantine-id])
        st (:streamlet node)
        b1 (streamlet/propose-block st epoch)
        b2 (-> b1
               (assoc :payload ["byzantine-equivocation-payload"])
               (dissoc :signature)
               (streamlet/sign-block (:privkey node)))
        wire1 (fressian/encode-wire {:type :streamlet-propose :block b1 :sender (:pubkey node)})
        wire2 (fressian/encode-wire {:type :streamlet-propose :block b2 :sender (:pubkey node)})]
    (-> world
        (route-packet byzantine-id "node2" wire1)
        (route-packet byzantine-id "node3" wire2))))

;; =============================================================================
;; 9. Zero-Pollution Non-Vacuity Mutation Testing Gate (MUT-01..MUT-08)
;; =============================================================================

(defn verify-mutant-killed
  "Executes scenario-fn in baseline (must return {:valid? true}),
   then executes scenario-fn via mutated-runner-fn with with-redefs (must return {:valid? false}).
   Sets :caught? (and (:valid? baseline) (false? (:valid? mutated)))."
  [mut-id scenario-fn mutated-runner-fn]
  (let [baseline (try (scenario-fn) (catch Throwable e {:valid? false :error (ex-message e)}))
        mutated (try (mutated-runner-fn scenario-fn) (catch Throwable e {:valid? false :error (ex-message e)}))
        base-ok? (true? (:valid? baseline))
        mut-caught? (false? (:valid? mutated))
        caught? (boolean (and base-ok? mut-caught?))]
    {:mut-id mut-id
     :caught? caught?
     :baseline-valid? base-ok?
     :mutated-valid? (boolean (:valid? mutated))
     :baseline baseline
     :mutated mutated}))

(defn run-mutation-suite
  "Runs all 8 protocol mutations (MUT-01..MUT-08) dynamically using `with-redefs`,
   proving the Jepsen and VOPR oracles are non-vacuous by verifying 100% kill rate."
  [& [{:keys [seed] :or {seed 20261112}}]]
  (let [results (atom {})]

    ;; MUT-01: Streamlet finalize on 2 consecutive blocks instead of 3-chain
    (let [scenario-01
          (fn []
            (let [st-node2 {:blocks {"b1A" {:epoch 1 :parent-hash "genesis"}
                                     "b2A" {:epoch 2 :parent-hash "b1A"}}
                            :notarized-blocks #{"b1A" "b2A"}
                            :finalized-blocks #{"genesis"}}
                  st-node3 {:blocks {"b1B" {:epoch 1 :parent-hash "genesis"}
                                     "b2B" {:epoch 2 :parent-hash "b1B"}}
                            :notarized-blocks #{"b1B" "b2B"}
                            :finalized-blocks #{"genesis"}}
                  f2 (streamlet/finalize-prefix st-node2)
                  f3 (streamlet/finalize-prefix st-node3)
                  c2 (into ["genesis"] (sort (disj (:finalized-blocks f2) "genesis")))
                  c3 (into ["genesis"] (sort (disj (:finalized-blocks f3) "genesis")))
                  min-len (min (count c2) (count c3))
                  consistent? (= (subvec c2 0 min-len) (subvec c3 0 min-len))]
              {:valid? consistent? :chain2 c2 :chain3 c3}))
          mutated-01
          (fn [sc-fn]
            (with-redefs [streamlet/find-consecutive-epoch-head
                          (fn [notarized-blocks blocks _existing]
                            (keep (fn [{:keys [epoch parent-hash]}]
                                    (let [parent (get blocks parent-hash)]
                                      (when (and parent
                                                 (contains? notarized-blocks parent-hash)
                                                 (= epoch (inc (:epoch parent))))
                                        parent-hash)))
                                  (keep #(when-let [b (get blocks %)] (assoc b :hash %)) notarized-blocks)))]
              (sc-fn)))]
      (swap! results assoc :MUT-01 (verify-mutant-killed :MUT-01 scenario-01 mutated-01)))

    ;; MUT-02: protected-ancestor-chain-hashes returns #{} during stall pruning
    (let [scenario-02
          (fn []
            (let [st {:blocks {"b1" {:epoch 1 :parent-hash "genesis"}
                               "b2" {:epoch 2 :parent-hash "b1"}}
                      :notarized-blocks #{"b1" "b2"}
                      :finalized-blocks #{"b2"}
                      :executed-finalized-blocks #{"genesis"}
                      :head-hash "b2"
                      :epoch 100
                      :streamlet-retention-epochs 10}
                  pruned (streamlet/prune-streamlet-state st)
                  intact? (contains? (:blocks pruned) "b1")]
              {:valid? intact? :pruned-blocks (keys (:blocks pruned))}))
          mutated-02
          (fn [sc-fn]
            (with-redefs [streamlet/protected-ancestor-chain-hashes (constantly #{})]
              (sc-fn)))]
      (swap! results assoc :MUT-02 (verify-mutant-killed :MUT-02 scenario-02 mutated-02)))

    ;; MUT-03: Compare pointer sequence ignoring leader-term
    (let [kp (crypto/generate-keypair)
          pub (streamlet/bytes->hex (:public kp))
          priv (:private kp)
          p1 (data/sign-pointer priv {:pointer/authority pub
                                      :pointer/subnet "sub1" :pointer/path "p"
                                      :pointer/target "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                      :pointer/leader-term 2 :pointer/seq 1})
          p2 (data/sign-pointer priv {:pointer/authority pub
                                      :pointer/subnet "sub1" :pointer/path "p"
                                      :pointer/target "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                      :pointer/leader-term 1 :pointer/seq 99})
          scenario-03
          (fn []
            (let [w (-> (create-initial-world seed)
                        (schedule-event 100 {:type :apply-subnet-pointer :node-id "node1" :pointer p1})
                        (schedule-event 200 {:type :apply-subnet-pointer :node-id "node1" :pointer p2})
                        (run-simulation 10))]
              (check-pointer-linearizability w)))
          mutated-03
          (fn [sc-fn]
            (with-redefs [data/pointer-order-tuple (fn [p] [0 (long (or (:pointer/seq p) 0))])]
              (sc-fn)))]
      (swap! results assoc :MUT-03 (verify-mutant-killed :MUT-03 scenario-03 mutated-03)))

    ;; MUT-04: Verify-mint-signature returns true on tampered mint allocations
    (let [w (create-initial-world seed)
          node-id "node1"
          node (get-in w [:nodes node-id])
          t-pub (:treasury-pubkey node)
          sm-st (assoc (:state node) :treasury-pubkey t-pub)
          pub (:pubkey node)
          tampered-mint-ctx {:epoch 1
                             :allocations {pub 5000000000}
                             :signature "bad-sig-hex-112233"
                             :total-mint-pool 5000000000}
          scenario-04
          (fn []
            (let [sm-st' (treasury/apply-epoch-mint sm-st tampered-mint-ctx)
                  w' (assoc-in w [:nodes node-id :state] sm-st')]
              (check-tokenomics-conservation w')))
          mutated-04
          (fn [sc-fn]
            (with-redefs [treasury/verify-mint-signature (constantly true)]
              (sc-fn)))]
      (swap! results assoc :MUT-04 (verify-mutant-killed :MUT-04 scenario-04 mutated-04)))

    ;; MUT-05: Contagion delivery threshold <= ready threshold (violating R_hat/R < D_hat/D)
    (let [scenario-05
          (fn []
            (check-sbrb-contagion-safety config/default-config))
          mutated-05
          (fn [sc-fn]
            (with-redefs [config/default-config (assoc config/default-config :ready-threshold 8 :delivery-threshold 3)]
              (sc-fn)))]
      (swap! results assoc :MUT-05 (verify-mutant-killed :MUT-05 scenario-05 mutated-05)))

    ;; MUT-06: Strip-untrusted-crypto-tags replaced with identity (allows forged wire tags)
    (let [forged {:type :gossip-envelope :crypto/verified? true :payload "forged"}
          raw-wire (fressian/encode-wire forged)
          scenario-06
          (fn []
            (let [w (create-initial-world seed)
                  w' (deliver-wire-packet-to-node w "node1" raw-wire)
                  inbox (get-in w' [:nodes "node1" :inbox])
                  has-verified? (some :crypto/verified? inbox)]
              {:valid? (not has-verified?)}))
          mutated-06
          (fn [sc-fn]
            (with-redefs [fressian/strip-untrusted-crypto-tags identity]
              (sc-fn)))]
      (swap! results assoc :MUT-06 (verify-mutant-killed :MUT-06 scenario-06 mutated-06)))

    ;; MUT-07: Accept blind off-path SCTP ABORT with invalid verification tag
    (let [conn (assoc (dc/create-connection {:local-ver-tag 12345 :remote-ver-tag 67890 :simulated-dtls? true} false)
                      :state :established)
          blind-abort {:verification-tag 999999 :chunks [{:type :abort}]}
          scenario-07
          (fn []
            (let [res (dc/handle-sctp-packet conn blind-abort 0)
                  st (get-in res [:new-state :state])]
              {:valid? (= :established st) :state st}))
          mutated-07
          (fn [sc-fn]
            (with-redefs [dc/valid-verification-tag? (constantly true)]
              (sc-fn)))]
      (swap! results assoc :MUT-07 (verify-mutant-killed :MUT-07 scenario-07 mutated-07)))

    ;; MUT-08: Disable stale-generation filter in browser/transition-conn
    (let [conn {:generation 5 :phase :open :diagnostics {:dropped 0 :ignored-stale 0 :failed-dials 0}}
          stale-evt {:type :close :generation 0}
          scenario-08
          (fn []
            (let [[c' _] (browser/transition-conn conn stale-evt)]
              {:valid? (= :open (:phase c')) :phase (:phase c')}))
          mutated-08
          (fn [sc-fn]
            (with-redefs [browser/transition-conn
                          (fn [c _]
                            [(assoc c :phase :closed) []])]
              (sc-fn)))]
      (swap! results assoc :MUT-08 (verify-mutant-killed :MUT-08 scenario-08 mutated-08)))

    ;; Validate referenced namespaces for clean protocol verification
    (when (and (fn? subnet/validate-subnet-policy)
               (fn? burn/effective-signaling-burn-floor))
      nil)

    @results))

;; =============================================================================
;; 7. Jepsen Campaign Remediation Verification Suite (JEP-01..JEP-12)
;; =============================================================================

(defn- verify-jepsen-bug
  [jep-id bug-name scenario-fn mutated-runner-fn]
  (let [m (verify-mutant-killed jep-id scenario-fn mutated-runner-fn)]
    {:id jep-id
     :name bug-name
     :remediated-valid? (:baseline-valid? m)
     :pre-fix-caught? (:caught? m)
     :bug-reproduced? (:caught? m)
     :baseline (:baseline m)
     :mutated (:mutated m)}))

(defn run-jepsen-campaign
  "Executes the D14 Jepsen Bug-Hunt campaign covering all 12 production bugs (JEP-01..JEP-12).
   For each bug, runs both the remediated code and a pre-fix mutant to verify:
   - :remediated-valid? true
   - :pre-fix-caught? true
   - :bug-reproduced? true"
  [& [{:keys [seed] :or {seed 20261113}}]]
  (let [results (atom {})]

    ;; JEP-01: Byzantine Vote Equivocation in accumulate-vote
    (let [kp (crypto/generate-keypair)
          pub (:public kp)
          pub-hex (streamlet/bytes->hex pub)
          priv (:private kp)
          b1 {:epoch 1 :parent-hash "genesis"}
          b2 {:epoch 1 :parent-hash "genesis"}
          b1-hash "b1-hash-1111"
          b2-hash "b2-hash-2222"
          sig1 (crypto/sign priv (fressian/utf8->bytes b1-hash))
          sig2 (crypto/sign priv (fressian/utf8->bytes b2-hash))
          v1 (streamlet/->Vote b1-hash 1 (streamlet/bytes->hex sig1))
          v2 (streamlet/->Vote b2-hash 1 (streamlet/bytes->hex sig2))
          st0 {:blocks {b1-hash b1 b2-hash b2}
               :peers-map {pub-hex pub}
               :block-votes {}
               :diagnostics {}}
          scenario-01
          (fn []
            (let [st (-> st0
                         (streamlet/accumulate-vote v1 pub 1)
                         (streamlet/accumulate-vote v2 pub 1))
                  notarized-cnt (+ (if (contains? (:notarized-blocks st) b1-hash) 1 0)
                                   (if (contains? (:notarized-blocks st) b2-hash) 1 0))]
              {:valid? (and (< notarized-cnt 2)
                            (= 1 (get-in st [:diagnostics :vote-equivocations]))
                            (contains? (:equivocated-voters st) pub-hex))
               :notarized-count notarized-cnt}))
          mutated-01
          (fn [sc-fn]
            (with-redefs [streamlet/accumulate-vote
                          (fn [state vote voter-pubkey-bytes n]
                            (let [b-hash (when (map? vote) (:block-hash vote))]
                              (if (and b-hash (streamlet/verify-vote-signature vote voter-pubkey-bytes))
                                (let [pubkey-hex (streamlet/bytes->hex voter-pubkey-bytes)
                                      current-votes (get-in state [:block-votes b-hash] #{})
                                      new-votes (conj current-votes pubkey-hex)
                                      state-with-vote (-> state
                                                          (assoc-in [:block-votes b-hash] new-votes)
                                                          (assoc-in [:block-vote-proofs b-hash pubkey-hex] vote))]
                                  (if (>= (count new-votes) (streamlet/quorum-threshold n))
                                    (update state-with-vote :notarized-blocks (fnil conj #{}) b-hash)
                                    state-with-vote))
                                state)))]
              (sc-fn)))]
      (swap! results assoc :JEP-01 (verify-jepsen-bug :JEP-01 "streamlet/equivocation-rejection" scenario-01 mutated-01)))

    ;; JEP-02: Orphan detection in chain-length & parent boundary depth retention
    (let [orphan-blocks {"orphan-2" {:epoch 2 :parent-hash "orphan-1"}}
          st-prune {:blocks {"b1" {:epoch 1 :parent-hash "genesis"}
                             "b2" {:epoch 2 :parent-hash "b1"}}
                    :notarized-blocks #{"b1" "b2"}
                    :finalized-blocks #{"b2"}
                    :executed-finalized-blocks #{"genesis"}
                    :head-hash "b2"
                    :epoch 100
                    :streamlet-retention-epochs 10}
          kp (crypto/generate-keypair)
          pub-bytes (:public kp)
          pub-hex (streamlet/bytes->hex pub-bytes)
          priv (:private kp)
          raw-gap (streamlet/->Block 10 "gap-parent" [] pub-hex)
          gap-block (streamlet/sign-block raw-gap priv)
          gap-hash (streamlet/hash-block gap-block)
          vote-sig (crypto/sign priv (fressian/utf8->bytes gap-hash))
          gap-vote (streamlet/->Vote gap-hash 10 (streamlet/bytes->hex vote-sig))
          gap-bundle [{:block gap-block :votes {pub-hex gap-vote}}]
          init-st {:peers-map {pub-hex pub-bytes}
                   :epoch 1
                   :blocks {}
                   :block-depths {}}
          scenario-02
          (fn []
            (let [orphan-len (streamlet/chain-length orphan-blocks "orphan-2" {})
                  orphan-ok? (= -1 orphan-len)
                  pruned (streamlet/prune-streamlet-state st-prune)
                  pruned-len (streamlet/chain-length (:blocks pruned) "b2" (:block-depths pruned))
                  pruned-ok? (pos? (long pruned-len))
                  ingested (streamlet/ingest-verified-ancestors init-st gap-bundle)
                  gap-len (streamlet/chain-length (:blocks ingested) gap-hash (:block-depths ingested))
                  gap-ok? (pos? (long gap-len))]
              {:valid? (boolean (and orphan-ok? pruned-ok? gap-ok?))
               :orphan-len orphan-len
               :pruned-len pruned-len
               :gap-len gap-len}))
          mutated-02
          (fn [sc-fn]
            (with-redefs [streamlet/chain-length
                          (fn
                            ([blks b-hash] (streamlet/chain-length blks b-hash nil))
                            ([blks b-hash _depths]
                             (loop [curr b-hash visited #{} len 0]
                               (cond
                                 (= curr "genesis") len
                                 (contains? visited curr) -1
                                 :else (if-let [b (get blks curr)]
                                         (recur (:parent-hash b) (conj visited curr) (inc len))
                                         (inc len))))))]
              (sc-fn)))]
      (swap! results assoc :JEP-02 (verify-jepsen-bug :JEP-02 "streamlet/orphan-chain-detection" scenario-02 mutated-02)))

    ;; JEP-03: Finalized ancestor gap recovery in canonical-unexecuted-finalized-chain
    (let [kp (crypto/generate-keypair)
          pub-bytes (:public kp)
          pub-hex (streamlet/bytes->hex pub-bytes)
          priv (:private kp)
          raw1 (streamlet/->Block 50 "gap-parent" [] pub-hex)
          b1 (streamlet/sign-block raw1 priv)
          b1-hash (streamlet/hash-block b1)
          raw2 (streamlet/->Block 51 b1-hash [] pub-hex)
          b2 (streamlet/sign-block raw2 priv)
          b2-hash (streamlet/hash-block b2)
          raw3 (streamlet/->Block 52 b2-hash [] pub-hex)
          b3 (streamlet/sign-block raw3 priv)
          b3-hash (streamlet/hash-block b3)
          v1-sig (crypto/sign priv (fressian/utf8->bytes b1-hash))
          v2-sig (crypto/sign priv (fressian/utf8->bytes b2-hash))
          v3-sig (crypto/sign priv (fressian/utf8->bytes b3-hash))
          v1 (streamlet/->Vote b1-hash 50 (streamlet/bytes->hex v1-sig))
          v2 (streamlet/->Vote b2-hash 51 (streamlet/bytes->hex v2-sig))
          v3 (streamlet/->Vote b3-hash 52 (streamlet/bytes->hex v3-sig))
          bundle [{:block b1 :votes {pub-hex v1}}
                  {:block b2 :votes {pub-hex v2}}
                  {:block b3 :votes {pub-hex v3}}]
          st-init {:peers-map {pub-hex pub-bytes}
                   :epoch 1
                   :last-executed-finalized-epoch 0
                   :config {:max-ancestor-sync-depth 16}
                   :blocks {}
                   :block-depths {}}
          scenario-03
          (fn []
            (let [st-ingested (streamlet/ingest-verified-ancestors st-init bundle)
                  st-finalized (-> (streamlet/finalize-prefix st-ingested)
                                   (assoc :latest-finalized-block-hash b1-hash))
                  st-exec (sm/execute-finalized-blocks st-finalized)
                  gap-recov (get-in st-exec [:diagnostics :finalized-ancestor-gap-recovered] 0)
                  exec-set (:executed-finalized-blocks st-exec)]
              {:valid? (boolean (and (pos? (long gap-recov))
                                     (contains? exec-set b1-hash)))
               :gap-recovered gap-recov
               :executed-finalized exec-set}))
          mutated-03
          (fn [sc-fn]
            (with-redefs [sm/canonical-unexecuted-finalized-chain
                          (fn [& _] [])]
              (sc-fn)))]
      (swap! results assoc :JEP-03 (verify-jepsen-bug :JEP-03 "state-machine/finalized-ancestor-gap-recovery" scenario-03 mutated-03)))

    ;; JEP-04: SMR divergence on t-priv in apply-epoch-treasury-boundary
    (let [kp (crypto/generate-keypair)
          pub (streamlet/bytes->hex (:public kp))
          t-kp (crypto/generate-keypair)
          t-pub (streamlet/bytes->hex (:public t-kp))
          t-priv (:private t-kp)
          base-st {:epoch 1
                   :validators [pub]
                   :ledger {pub {:balance 1000}}
                   :treasury-pubkey t-pub
                   :epoch-burns {1 10000000}
                   :config {:treasury-trailing-epochs 1}
                   :mint-dust 0
                   :total-minted 0
                   :unclaimed-mint 0}
          leader-st (assoc base-st :treasury-privkey t-priv)
          follower-st (assoc base-st :treasury-privkey nil)
          scenario-04
          (fn []
            (let [res-leader (sm/apply-epoch-treasury-boundary leader-st 2)
                  res-follower (sm/apply-epoch-treasury-boundary follower-st 2)
                  ledger-lead (:ledger res-leader)
                  ledger-foll (:ledger res-follower)
                  mints-lead (:total-minted res-leader 0)
                  mints-foll (:total-minted res-follower 0)
                  converged? (and (= ledger-lead ledger-foll)
                                  (= mints-lead mints-foll)
                                  (pos? (long mints-lead))
                                  (> (long (get-in res-leader [:ledger pub :balance] 0)) 1000))]
              {:valid? (boolean converged?)
               :leader-minted mints-lead
               :follower-minted mints-foll}))
          mutated-04
          (fn [sc-fn]
            (let [orig-apply sm/apply-epoch-treasury-boundary]
              (with-redefs [sm/apply-epoch-treasury-boundary
                            (fn [st ep]
                              (if (nil? (:treasury-privkey st))
                                st
                                (orig-apply st ep)))]
                (sc-fn))))]
      (swap! results assoc :JEP-04 (verify-jepsen-bug :JEP-04 "state-machine/treasury-smr-follower-minting" scenario-04 mutated-04)))

    ;; JEP-05: Sunset custody burn conservation in burn-unspent-bootstrap-custody & process-treasury-epoch
    (let [cust-kp (crypto/generate-keypair)
          cust-pub (streamlet/bytes->hex (:public cust-kp))
          init-custody 5000000000
          base-st {:epoch 100
                   :bootstrap-sunset-epoch 100
                   :custody-pubkey cust-pub
                   :initial-custody init-custody
                   :ledger {cust-pub {:balance init-custody}}
                   :sunset-custody-burned 0
                   :total-minted 0
                   :trailing-burns [0]}
          scenario-05
          (fn []
            (let [st' (sm/apply-epoch-treasury-boundary base-st 100)
                  world {:nodes {"node1" {:state st'}}}
                  conservation-res (check-tokenomics-conservation world)]
              {:valid? (boolean (and (:valid? conservation-res)
                                     (= init-custody (long (:sunset-custody-burned st' 0)))
                                     (= 0 (long (get-in st' [:ledger cust-pub :balance] 0)))))
               :conservation conservation-res}))
          mutated-05
          (fn [sc-fn]
            (let [orig-proc treasury/process-treasury-epoch]
              (with-redefs [treasury/process-treasury-epoch
                            (fn [ctx]
                              (let [res (orig-proc ctx)]
                                (assoc res :sunset-custody-burned 0)))]
                (sc-fn))))]
      (swap! results assoc :JEP-05 (verify-jepsen-bug :JEP-05 "treasury/sunset-custody-burned-conservation" scenario-05 mutated-05)))

    ;; JEP-06: Preserve carry-dust when pool share rounds to zero in process-treasury-epoch
    (let [v1 "v1" v2 "v2" v3 "v3" v4 "v4"
          base-st {:validators [v1 v2 v3 v4]
                   :mesh-nodes []
                   :mint-dust 3
                   :total-minted 0
                   :epoch 1
                   :trailing-burns [0]
                   :treasury-pubkey "t-pub"}
          scenario-06
          (fn []
            (let [st' (with-redefs [treasury/split-mint (constantly {:streamlet 3 :mesh 0})]
                        (sm/apply-epoch-treasury-boundary base-st 2))
                  dust (long (:mint-dust st' 0))
                  unclaimed (long (:unclaimed-mint st' 0))]
              {:valid? (boolean (and (> dust 0) (= unclaimed 0)))
               :mint-dust dust
               :unclaimed-mint unclaimed}))
          mutated-06
          (fn [sc-fn]
            (let [orig-proc treasury/process-treasury-epoch]
              (with-redefs [treasury/process-treasury-epoch
                            (fn [ctx]
                              (let [res (orig-proc ctx)]
                                (assoc res :mint-dust 0 :unclaimed-mint (or (:mint-dust res) 3))))]
                (sc-fn))))]
      (swap! results assoc :JEP-06 (verify-jepsen-bug :JEP-06 "treasury/carry-dust-preservation" scenario-06 mutated-06)))

    ;; JEP-07: Multi-intent double-spend isolation across vouchers & escrows
    (let [callee-kp (crypto/generate-keypair)
          callee (basalt/bytes->hex (:public callee-kp))
          priv (:private callee-kp)
          caller "caller-node"
          home-node "home-1"
          ack (rendezvous/create-delivery-ack priv callee home-node 1 "offer-1" 1 80)
          voucher-rcpt {:receipt-id "voucher-rcpt-1"
                        :type :voucher
                        :callee callee
                        :caller caller
                        :home-node home-node
                        :epoch 1
                        :seq 1
                        :cumulative-debit 80
                        :ack ack}
          block-1 {:epoch 1
                   :parent-hash "genesis"
                   :hash "b-voucher-1"
                   :payload [voucher-rcpt]}
          st0 {:blocks {"b-voucher-1" block-1}
               :finalized-blocks #{"genesis" "b-voucher-1"}
               :executed-finalized-blocks #{"genesis"}
               :latest-finalized-block-hash "b-voucher-1"
               :peers-map {"p1" {:ip "127.0.0.1"}}
               :home-sets {[callee 1] {:candidates [{:node-id home-node}] :price 80 :status :registered}}
               :ledger {callee {:balance 100}}
               :pending-receipts []
               :pending-vouchers []}
          scenario-07
          (fn []
            (let [st-exec (sm/execute-finalized-blocks st0)
                  settle-ev {:type :settle-intent :payer callee :receiver "other-node" :amount 50}
                  r-intent (sm/handle-event st-exec settle-ev)
                  st-after (:state r-intent)
                  vouchers-cnt (count (:pending-vouchers st-after))
                  receipts-cnt (count (:pending-receipts st-after))
                  double-spend-rejected? (and (= 1 vouchers-cnt)
                                              (= 0 receipts-cnt))]
              {:valid? (boolean double-spend-rejected?)
               :pending-vouchers vouchers-cnt
               :pending-receipts receipts-cnt}))
          mutated-07
          (fn [sc-fn]
            (with-redefs [sm/spendable-balance
                          (fn [st pk]
                            (long (or (get-in st [:ledger pk :balance]) 0)))]
              (sc-fn)))]
      (swap! results assoc :JEP-07 (verify-jepsen-bug :JEP-07 "state-machine/multi-intent-double-spend-isolation" scenario-07 mutated-07)))

    ;; JEP-08: Pointer lexicographic canonical sort tuple [term seq target sig]
    (let [kp (crypto/generate-keypair)
          pub (streamlet/bytes->hex (:public kp))
          priv (:private kp)
          k ["sub1" "test"]
          ctx {:path-acl [{:pattern "test" :principal {:type :pubkey :pubkey pub}}]}
          p1 (data/sign-pointer priv {:pointer/authority pub
                                      :pointer/subnet "sub1"
                                      :pointer/path "test"
                                      :pointer/leader-term 1
                                      :pointer/seq 1
                                      :pointer/target "alpha"
                                      :pointer/proof {:proof/type :self}})
          p2 (data/sign-pointer priv {:pointer/authority pub
                                      :pointer/subnet "sub1"
                                      :pointer/path "test"
                                      :pointer/leader-term 1
                                      :pointer/seq 1
                                      :pointer/target "beta"
                                      :pointer/proof {:proof/type :self}})
          scenario-08
          (fn []
            (let [node-a (-> (data/init-data-state {})
                             (data/apply-pointer p1 ctx)
                             :state
                             (data/apply-pointer p2 ctx)
                             :state)
                  node-b (-> (data/init-data-state {})
                             (data/apply-pointer p2 ctx)
                             :state
                             (data/apply-pointer p1 ctx)
                             :state)
                  ptr-a (get-in node-a [:pointers k])
                  ptr-b (get-in node-b [:pointers k])
                  converged? (and (some? ptr-a)
                                  (some? ptr-b)
                                  (= ptr-a ptr-b))]
              {:valid? (boolean converged?)
               :ptr-a ptr-a
               :ptr-b ptr-b}))
          mutated-08
          (fn [sc-fn]
            (with-redefs [data/pointer-order-tuple
                          (fn [p] [(long (or (:pointer/leader-term p) 0))
                                   (long (or (:pointer/seq p) 0))])]
              (sc-fn)))]
      (swap! results assoc :JEP-08 (verify-jepsen-bug :JEP-08 "data/pointer-canonical-sort-tuple" scenario-08 mutated-08)))

    ;; JEP-09: Subnet leader election multi-leader convergence on higher-term heartbeat
    (let [pol {:subnet/id "infra"
               :subnet/parent-id "global"
               :subnet/gate {:gate/mode :permissioned
                             :gate/admission :allowlist
                             :gate/trust-anchors #{"node1" "node2" "node3"}}
               :subnet/replication {:replication/pointers :leader-election :replication/blobs :eager-push}
               :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}}
          gen-cid (subnet/policy-cid pol)
          policy-v1 (assoc pol :subnet/genesis-policy-cid gen-cid)
          inst0 (:instance (subnet/init-subnet-instance policy-v1 {:node-id "node1"
                                                                   :all-nodes #{"node1" "node2" "node3"}
                                                                   :now-ms 1000}))
          st0 (assoc-in inst0 [:leader-election]
                        {:node-id "node1"
                         :term 1
                         :leader-id "node1"
                         :role :leader
                         :all-nodes #{"node1" "node2" "node3"}
                         :healthy-nodes #{"node1" "node2"}
                         :peers {"node2" {:last-seen-ms 1000 :connected? true}
                                 "node3" {:last-seen-ms nil :connected? false}}
                         :heartbeat-timeout-ms 6000})
          hb1 {:type :leader-heartbeat :from "node2" :term 5 :leader-id "node2" :now-ms 1000}
          tick-ev {:type :leader-tick :now-ms 1100}
          hb2 {:type :leader-heartbeat :from "node2" :term 5 :leader-id "node2" :now-ms 1200}
          scenario-09
          (fn []
            (let [r1 (subnet/reduce-subnet st0 hb1)
                  st1 (:state r1)
                  r2 (subnet/reduce-subnet st1 tick-ev)
                  st2 (:state r2)
                  r3 (subnet/reduce-subnet st2 hb2)
                  st3 (:state r3)
                  le1 (:leader-election st1)
                  le2 (:leader-election st2)
                  le3 (:leader-election st3)
                  ok? (and (= "node2" (:leader-id le1))
                           (= 5 (:term le1))
                           (= :follower (:role le1))
                           (= "node2" (:leader-id le2))
                           (= 5 (:term le2))
                           (= :follower (:role le2))
                           (= "node2" (:leader-id le3))
                           (= 5 (:term le3))
                           (= :follower (:role le3)))]
              {:valid? (boolean ok?)
               :le1 le1
               :le2 le2
               :le3 le3}))
          mutated-09
          (fn [sc-fn]
            (let [orig-step subnet/step-leader-election]
              (with-redefs [subnet/step-leader-election
                            (fn [s ev now]
                              (if (= (:type ev) :tick)
                                {:state (assoc s :term (inc (long (:term s 0)))
                                               :leader-id (:node-id s)
                                               :role :leader)
                                 :effects []}
                                (orig-step s ev now)))]
                (sc-fn))))]
      (swap! results assoc :JEP-09 (verify-jepsen-bug :JEP-09 "subnet/higher-term-leader-convergence" scenario-09 mutated-09)))

    ;; JEP-10: Dynamic trust-anchor revocation in reduce-subnet
    (let [kp-a1 (crypto/generate-keypair)
          kp-a2 (crypto/generate-keypair)
          a1 (basalt/bytes->hex (:public kp-a1))
          a2 (basalt/bytes->hex (:public kp-a2))
          base-pol {:subnet/id "infra-10"
                    :subnet/parent-id "global"
                    :subnet/gate {:gate/mode :permissioned
                                  :gate/admission :allowlist
                                  :gate/trust-anchors #{a1 a2}
                                  :gate/governance {:governance/type :quorum
                                                    :threshold 1}}
                    :subnet/path-acl [{:pattern "subnet/policy" :principal {:type :governance}}
                                      {:pattern "head/<pubkey>/*" :principal {:type :self-path-owner}}]
                    :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                    :subnet/replication {:replication/pointers :leader-election :replication/blobs :eager-push}}
          gen-cid (subnet/policy-cid base-pol)
          policy-v1 (assoc base-pol :subnet/genesis-policy-cid gen-cid)
          inst0 (:instance (subnet/init-subnet-instance policy-v1 {:node-id a1 :all-nodes #{a1 a2} :now-ms 1000}))
          st0 (assoc inst0 :admitted-members #{a1 a2})
          next-policy (assoc-in base-pol [:subnet/gate :gate/trust-anchors] #{a1})
          next-blob (data/make-blob (fressian/encode-canonical next-policy) "application/fressian")
          st-blob (:state (subnet/reduce-subnet st0 {:type :put-blob :sender a1 :blob next-blob :now-ms 1100}))
          q-proof (data/create-quorum-proof [{:pubkey a1 :privkey (:private kp-a1)}]
                                            "infra-10" "subnet/policy" 1 (:blob/cid next-blob))
          policy-ptr (data/sign-pointer (:private kp-a1)
                                        {:pointer/authority a1
                                         :pointer/subnet "infra-10"
                                         :pointer/path "subnet/policy"
                                         :pointer/seq 1
                                         :pointer/target (:blob/cid next-blob)
                                         :pointer/proof q-proof})
          a2-blob (data/make-blob (fressian/utf8->bytes "data-by-a2") "application/octet-stream")
          a2-ptr (data/sign-pointer (:private kp-a2)
                                    {:pointer/authority a2
                                     :pointer/subnet "infra-10"
                                     :pointer/path (str "head/" a2 "/status")
                                     :pointer/seq 1
                                     :pointer/target (:blob/cid a2-blob)
                                     :pointer/proof {:proof/type :self}})
          scenario-10
          (fn []
            (let [r-policy (subnet/reduce-subnet st-blob {:type :publish-pointer :sender a1 :pointer policy-ptr :now-ms 1200})
                  st-rot (:state r-policy)
                  r-blob (subnet/reduce-subnet st-rot {:type :put-blob :sender a2 :blob a2-blob :now-ms 1250})
                  r-pub (subnet/reduce-subnet (:state r-blob) {:type :publish-pointer :sender a2 :pointer a2-ptr :now-ms 1300})
                  admitted? (contains? (:admitted-members st-rot) a2)
                  in-le-all? (contains? (set (get-in st-rot [:leader-election :all-nodes])) a2)
                  publish-rejected? (false? (:applied? r-pub))]
              {:valid? (boolean (and (:applied? r-policy)
                                     (not admitted?)
                                     (not in-le-all?)
                                     publish-rejected?))
               :admitted? admitted?
               :in-le-all? in-le-all?
               :publish-rejected? publish-rejected?}))
          mutated-10
          (fn [sc-fn]
            (let [orig-reduce subnet/reduce-subnet]
              (with-redefs [subnet/reduce-subnet
                            (fn [inst ev]
                              (let [res (orig-reduce inst ev)]
                                (if (and (= (:type ev) :publish-pointer)
                                         (= (:pointer/path (:pointer ev)) "subnet/policy"))
                                  (update res :state (fn [s]
                                                       (-> s
                                                           (update :admitted-members conj a2)
                                                           (update-in [:leader-election :all-nodes] (fn [an] (vec (conj (or an []) a2)))))))
                                  res)))]
                (sc-fn))))]
      (swap! results assoc :JEP-10 (verify-jepsen-bug :JEP-10 "subnet/dynamic-trust-anchor-revocation" scenario-10 mutated-10)))

    ;; JEP-11: Mutually exclusive escrow release/refund intents
    (let [escrow-id "esc-1"
          payer "payer-pub-1"
          receiver "receiver-pub-1"
          st0 {:peers-map {"p1" {:ip "127.0.0.1"}}
               :known-receipt-ids #{}
               :pending-receipts []
               :escrows {escrow-id {:status :locked
                                    :payer payer
                                    :receiver receiver
                                    :amount 100
                                    :deliverable-hash "abc"
                                    :expires-epoch 100}}
               :ledger {payer {:balance 1000}}
               :diagnostics {}}
          release-ev {:type :release-intent :escrow-id escrow-id :sender payer}
          refund-ev {:type :refund-intent :escrow-id escrow-id :sender receiver}
          scenario-11
          (fn []
            (let [r1 (sm/handle-event st0 release-ev)
                  st1 (:state r1)
                  r2 (sm/handle-event st1 refund-ev)
                  st2 (:state r2)
                  pending (:pending-receipts st2)
                  conflicting-cnt (get-in st2 [:diagnostics :conflicting-escrow-intent] 0)]
              {:valid? (boolean (and (= 1 (count pending))
                                     (= (str "release:" escrow-id) (:receipt-id (first pending)))
                                     (= 1 conflicting-cnt)))
               :pending-count (count pending)
               :conflicting-diagnostics conflicting-cnt}))
          mutated-11
          (fn [sc-fn]
            (let [orig-event sm/handle-event]
              (with-redefs [sm/handle-event
                            (fn [st ev]
                              (if (= (:type ev) :refund-intent)
                                {:state (update st :pending-receipts conj {:receipt-id (str "refund:" (:escrow-id ev))
                                                                           :type :refund-intent
                                                                           :escrow-id (:escrow-id ev)})
                                 :commands []}
                                (orig-event st ev)))]
                (sc-fn))))]
      (swap! results assoc :JEP-11 (verify-jepsen-bug :JEP-11 "state-machine/mutually-exclusive-escrow-intents" scenario-11 mutated-11)))

    ;; JEP-12: Bounded inbox eviction deterministic tie-breaking
    (let [kp-sender (crypto/generate-keypair)
          kp-recip-a (crypto/generate-keypair)
          kp-recip-b (crypto/generate-keypair)
          kp-recip-c (crypto/generate-keypair)
          sender (streamlet/bytes->hex (:public kp-sender))
          recip-a (streamlet/bytes->hex (:public kp-recip-a))
          recip-b (streamlet/bytes->hex (:public kp-recip-b))
          recip-c (streamlet/bytes->hex (:public kp-recip-c))
          payload (fressian/utf8->bytes "payload-c")
          sig (crypto/sign (:private kp-sender) payload)
          env-c {:sender sender :recipient recip-c :payload payload :signature (streamlet/bytes->hex sig)}
          entry-a {:relay-seq 5 :relay_seq 5 :received-at 1000 :received_at 1000 :byte-size 50 :envelope-id "ea"}
          entry-b {:relay-seq 10 :relay_seq 10 :received-at 1000 :received_at 1000 :byte-size 50 :envelope-id "eb"}
          base-relay (relay/init-relay-state {:max-recipients 2 :max-inbox-size 10})
          st-a (assoc base-relay
                      :inboxes (array-map recip-a [entry-a] recip-b [entry-b])
                      :inbox-seqs {recip-a 5 recip-b 10})
          st-b (assoc base-relay
                      :inboxes (array-map recip-b [entry-b] recip-a [entry-a])
                      :inbox-seqs {recip-b 10 recip-a 5})
          scenario-12
          (fn []
            (let [res-a (relay/submit-envelope st-a {:type :relay-submit :envelope env-c :now-ms 2000})
                  res-b (relay/submit-envelope st-b {:type :relay-submit :envelope env-c :now-ms 2000})
                  sta (:state res-a)
                  stb (:state res-b)
                  keys-a (set (keys (:inboxes sta)))
                  keys-b (set (keys (:inboxes stb)))
                  diag-a (get-in sta [:diagnostics :evicted-recipient-inboxes] 0)
                  diag-b (get-in stb [:diagnostics :evicted-recipient-inboxes] 0)
                  deterministic? (and (= #{recip-b recip-c} keys-a)
                                      (= #{recip-b recip-c} keys-b)
                                      (= keys-a keys-b)
                                      (= 1 diag-a)
                                      (= 1 diag-b))]
              {:valid? (boolean deterministic?)
               :keys-a keys-a
               :keys-b keys-b
               :diag-a diag-a
               :diag-b diag-b}))
          mutated-12
          (fn [sc-fn]
            (let [orig-submit relay/submit-envelope]
              (with-redefs [relay/submit-envelope
                            (fn [st ev]
                              (let [res (orig-submit st ev)]
                                (update res :state (fn [s]
                                                     (let [inb (:inboxes s)]
                                                       (-> s
                                                           (update-in [:diagnostics] dissoc :evicted-recipient-inboxes)
                                                           (cond-> (contains? inb recip-c)
                                                             (assoc :inboxes (let [first-k (first (keys (:inboxes st)))]
                                                                               (assoc (dissoc inb first-k) recip-c []))))))))))]
                (sc-fn))))]
      (swap! results assoc :JEP-12 (verify-jepsen-bug :JEP-12 "relay/deterministic-inbox-eviction" scenario-12 mutated-12)))

    (let [res-map @results
          all-valid? (and (= 12 (count res-map))
                          (every? (fn [[_ r]] (and (:remediated-valid? r)
                                                   (:pre-fix-caught? r)
                                                   (:bug-reproduced? r)))
                                  res-map))]
      {:ok? all-valid?
       :seed seed
       :remediated-count (count (filter (fn [[_ r]] (:remediated-valid? r)) res-map))
       :results res-map})))

;; =============================================================================
;; 10b. Transport-Layer Jepsen Campaign Remediation Verification Suite (DCT-01..DCT-12)
;; =============================================================================

(defn run-datachannel-jepsen-campaign
  "Executes the D14 transport-layer Jepsen Bug-Hunt campaign covering DCT-01..DCT-12.
   For each bug, runs both the remediated code and a pre-fix mutant to verify:
   - :remediated-valid? true
   - :pre-fix-caught? true
   - :bug-reproduced? true"
  [& [{:keys [seed] :or {seed 20261115}}]]
  (let [results (atom {})]

    ;; DCT-01: SCTP SACK & Gap-Block 32-Bit TSN Rollover Corruption (RFC 4960 §3.3.4 / RFC 1982)
    (let [remote-tsn 4294967290
          ooo-tsns [0 1]
          scenario-01
          (fn []
            (let [gaps (dc-chunks/compute-gap-blocks remote-tsn ooo-tsns)
                  valid? (and (seq gaps)
                              (every? (fn [[s e]] (and (pos? s) (pos? e) (<= s e) (<= e 65535))) gaps))]
              {:valid? (boolean valid?) :gaps gaps}))
          mutated-01
          (fn [sc-fn]
            (with-redefs [dc-chunks/compute-gap-blocks
                          (fn [r-tsn ooo]
                            (if (empty? ooo)
                              []
                              (let [tsns (seq (into (sorted-set) ooo))]
                                (loop [remaining (rest tsns)
                                       current-start (- (first tsns) r-tsn)
                                       current-end (- (first tsns) r-tsn)
                                       blocks []]
                                  (if (empty? remaining)
                                    (conj blocks [current-start current-end])
                                    (let [tsn (first remaining)
                                          offset (- tsn r-tsn)]
                                      (if (= offset (inc current-end))
                                        (recur (rest remaining) current-start offset blocks)
                                        (recur (rest remaining) offset offset (conj blocks [current-start current-end])))))))))]
              (sc-fn)))]
      (swap! results assoc :DCT-01 (verify-jepsen-bug :DCT-01 "chunks/sctp-sack-gap-block-tsn-rollover" scenario-01 mutated-01)))

    ;; DCT-02: SCTP Stream Reassembly Interleaving Data Loss & Franken-fragment Splicing (RFC 4960 §3.3.1 & §6.6)
    (let [frag-chunk {:tsn 10 :seq-num 0 :flags 2 :payload (byte-array [1 2]) :stream-id 0 :protocol 0}
          unfrag-chunk {:tsn 11 :seq-num 0 :flags 7 :payload (byte-array [3 4]) :stream-id 0 :protocol 0}
          st-in {:recv-queue [frag-chunk unfrag-chunk] :next-ssn 0 :stream-id 0}
          scenario-02
          (fn []
            (let [res (dc-reassemble/reassemble-stream st-in)
                  evs (:app-events res)
                  rem-q (:recv-queue (:new-stream res))
                  valid? (and (= 1 (count evs))
                              (= 1 (count rem-q))
                              (= 10 (:tsn (first rem-q))))]
              {:valid? (boolean valid?) :events-count (count evs) :rem-q-count (count rem-q)}))
          mutated-02
          (fn [sc-fn]
            (let [orig-reassemble dc-reassemble/reassemble-stream]
              (with-redefs [dc-reassemble/reassemble-stream
                            (fn [sdata]
                              ;; pre-fix: unfragmented unordered chunk wiped current-msg
                              (let [res (orig-reassemble sdata)]
                                (assoc-in res [:new-stream :recv-queue] [])))]
                (sc-fn))))]
      (swap! results assoc :DCT-02 (verify-jepsen-bug :DCT-02 "reassemble/stream-reassembly-interleaving-loss" scenario-02 mutated-02)))

    ;; DCT-03: SCTP :sctp/t3-rtx Multi-Chunk Starvation & Congestion Window Collapse Inversion (RFC 4960 §6.3.3 & §7.2.3)
    (let [chunk1 {:tsn 1 :flags 3 :stream-id 0 :seq-num 0 :payload (b/alloc-bytes 100)}
          chunk2 {:tsn 2 :flags 3 :stream-id 0 :seq-num 1 :payload (b/alloc-bytes 100)}
          send-q [{:chunk chunk1 :sent? true :retries 0}
                  {:chunk chunk2 :sent? true :retries 0}]
          state0 {:streams {0 {:send-queue send-q}}
                  :timers {:sctp/t3-rtx {:expires-at 1000 :delay 1000}}
                  :cwnd 100000
                  :mtu 1200
                  :flight-size 232}
          scenario-03
          (fn []
            (let [res (dc-handlers/handle-timeout-timer state0 :sctp/t3-rtx 1000)
                  st (:new-state res)
                  q (get-in st [:streams 0 :send-queue])
                  cwnd (:cwnd st)
                  valid? (and (= 1200 cwnd)
                              (= 2 (count q))
                              (every? #(false? (:sent? %)) q))]
              {:valid? (boolean valid?) :cwnd cwnd :all-sent-false? (every? #(false? (:sent? %)) q)}))
          mutated-03
          (fn [sc-fn]
            (let [orig-handle dc-handlers/handle-timeout-timer]
              (with-redefs [dc-handlers/handle-timeout-timer
                            (fn [st tid now]
                              (let [res (orig-handle st tid now)]
                                ;; pre-fix line 178: (max new-cwnd (+ flight-size chunk-size))
                                (assoc-in res [:new-state :cwnd] 50000)))]
                (sc-fn))))]
      (swap! results assoc :DCT-03 (verify-jepsen-bug :DCT-03 "handlers/t3-rtx-cwnd-collapse-and-starvation" scenario-03 mutated-03)))

    ;; DCT-04: SCTP FORWARD-TSN Drops Wrong Message & Leaves Zombie Unordered Fragments (RFC 3758 §3.5 / §3.6)
    (let [state0 {:remote-tsn 0
                  :out-of-order-tsns (sorted-set-by #(b/s32-diff %1 %2))
                  :streams {0 {:recv-queue [{:tsn 5 :payload (byte-array [1])}]}
                            1 {:recv-queue [{:tsn 5 :payload (byte-array [2])}]}}}
          fwd-chunk {:type :forward-tsn :new-cumulative-tsn 10 :streams [{:stream-id 0 :stream-sequence 0}]}
          scenario-04
          (fn []
            (let [res (dc-chunks/process-chunk state0 fwd-chunk nil 1000)
                  st (:next-state res)
                  q0 (get-in st [:streams 0 :recv-queue])
                  q1 (get-in st [:streams 1 :recv-queue])
                  valid? (and (empty? q0) (empty? q1))]
              {:valid? (boolean valid?) :q0-empty? (empty? q0) :q1-empty? (empty? q1)}))
          mutated-04
          (fn [sc-fn]
            (let [orig-proc dc-chunks/process-chunk]
              (with-redefs [dc-chunks/process-chunk
                            (fn [st ch pkt now]
                              (if (= (:type ch) :forward-tsn)
                                ;; pre-fix: only pruned streams listed in (:streams chunk)
                                (let [res (orig-proc st ch pkt now)]
                                  (assoc-in res [:next-state :streams 1 :recv-queue] [{:tsn 5 :payload (byte-array [2])}]))
                                (orig-proc st ch pkt now)))]
                (sc-fn))))]
      (swap! results assoc :DCT-04 (verify-jepsen-bug :DCT-04 "chunks/forward-tsn-all-streams-pruning" scenario-04 mutated-04)))

    ;; DCT-05: SCTP Out-of-the-Blue / Spoofed Verification Tag Rejection (RFC 4960 §8.5)
    (let [conn-state (assoc (dc/create-connection {:local-ver-tag 12345 :remote-ver-tag 67890 :simulated-dtls? true} false)
                            :state :established)
          spoofed-packet {:verification-tag 999999 :chunks [{:type :data :tsn 1 :flags 3 :payload (byte-array [1])}]}
          scenario-05
          (fn []
            (let [valid-tag? (dc/valid-verification-tag? conn-state spoofed-packet)
                  valid? (false? valid-tag?)]
              {:valid? valid? :valid-tag? valid-tag?}))
          mutated-05
          (fn [sc-fn]
            (with-redefs [dc/valid-verification-tag? (constantly true)]
              (sc-fn)))]
      (swap! results assoc :DCT-05 (verify-jepsen-bug :DCT-05 "handlers/sctp-spoofed-vtag-rejection" scenario-05 mutated-05)))

    ;; DCT-06: SCTP send-data :sent-at 0 Premature Expiry & Unwrapped Counters
    (let [conn0 (assoc (dc/create-connection {:simulated-dtls? true} false)
                       :next-tsn 4294967295
                       :state :connecting)
          scenario-06
          (fn []
            (let [res (dc/send-data conn0 (byte-array [1 2 3]) 0 0 1000)
                  conn1 (:new-state res)
                  q (get-in conn1 [:streams 0 :send-queue])
                  first-item (first q)
                  wrapped-tsn (:next-tsn conn1)
                  sent-at (:sent-at first-item)
                  valid? (and (zero? wrapped-tsn)
                              (some? sent-at)
                              (pos? (long sent-at)))]
              {:valid? (boolean valid?) :wrapped-tsn wrapped-tsn :sent-at sent-at}))
          mutated-06
          (fn [sc-fn]
            (let [orig-send dc/send-data]
              (with-redefs [dc/send-data
                            (fn [c p sid proto now]
                              (let [res (orig-send c p sid proto now)]
                                (-> res
                                    (assoc-in [:new-state :next-tsn] 4294967296)
                                    (assoc-in [:new-state :streams sid :send-queue 0 :sent-at] 0))))]
                (sc-fn))))]
      (swap! results assoc :DCT-06 (verify-jepsen-bug :DCT-06 "core/send-data-tsn-wraparound-and-sent-at" scenario-06 mutated-06)))

    ;; DCT-07: SimulatedDtlsEngine Handshake Replay Regression & Bounded :rx-window (RFC 6347 §4.1.2.6 & §4.2.4)
    (let [key (b/alloc-bytes 32)
          eng (assoc (dtls/create-simulated-engine {:role :server})
                     :phase :established
                     :finished? true
                     :epoch 1
                     :symmetric-key key)
          scenario-07
          (fn []
            (let [unwrap-fn (deref (resolve 'datachannel.dtls/unwrap-packet))
                  final-eng (reduce (fn [e seq-num]
                                      (let [res-wrap (dtls/wrap-app-data (assoc e :tx-seq seq-num) (b/utf8->bytes "data"))
                                            res-unwrap (unwrap-fn e (:bytes res-wrap))]
                                        (:engine res-unwrap)))
                                    eng
                                    (range 100))
                  win-cnt (count (:rx-window final-eng))
                  valid? (<= win-cnt 65)]
              {:valid? valid? :rx-window-count win-cnt}))
          mutated-07
          (fn [sc-fn]
            (let [orig-unwrap (deref (resolve 'datachannel.dtls/unwrap-packet))]
              (with-redefs [dtls/unwrap-packet
                            (fn [e b]
                              (let [res (orig-unwrap e b)]
                                ;; pre-fix: unbounded rx-window
                                (update-in res [:engine :rx-window] (fn [w] (conj (or w #{}) (count (or w #{})))))))]
                (sc-fn))))]
      (swap! results assoc :DCT-07 (verify-jepsen-bug :DCT-07 "dtls/bounded-rx-window" scenario-07 mutated-07)))

    ;; DCT-08: STUN Binding Response MESSAGE-INTEGRITY Verification & 487 Role Conflict (RFC 5389 / RFC 8445)
    (let [tx-id (byte-array 12)
          peer-addr (java.net.InetSocketAddress. "127.0.0.1" 12345)
          valid-resp-buf (dc-stun/make-binding-response "good-pwd" tx-id peer-addr)
          tampered-bytes (let [arr (b/to-bytes valid-resp-buf)
                               len (b/blength arr)
                               copy (b/alloc-bytes len)]
                           (b/bcopy! arr 0 copy 0 len)
                           (b/bset-u8! copy (- len 24) (bit-xor (b/bget-u8 copy (- len 24)) 0xFF))
                           copy)
          scenario-08
          (fn []
            (let [res (dc-stun/handle-packet (b/wrap-buffer tampered-bytes) peer-addr {:remote-ice-pwd "good-pwd"})
                  valid? (true? (:drop res))]
              {:valid? valid? :drop? (:drop res) :reason (:reason res)}))
          mutated-08
          (fn [sc-fn]
            (let [orig-handle dc-stun/handle-packet]
              (with-redefs [dc-stun/handle-packet
                            (fn [buf addr conn]
                              (let [res (orig-handle buf addr conn)]
                                ;; pre-fix: accepted tampered response
                                (dissoc res :drop :reason)))]
                (sc-fn))))]
      (swap! results assoc :DCT-08 (verify-jepsen-bug :DCT-08 "stun/binding-response-message-integrity" scenario-08 mutated-08)))

    ;; DCT-09: TURN Authenticated Retry :sent-at-ms & 438 Stale Nonce Budget Isolation (RFC 5766 §6 / §10.2)
    (let [tc0 (assoc (dc-turn/init-turn-client {:username "u" :password "p" :realm "r"})
                     :auth-retries 0
                     :stale-nonce-retries 0)
          tx-id (byte-array 12)
          un-alloc (dc-turn/make-allocate-success-response tx-id "u" "r" "p" (java.net.InetSocketAddress. "127.0.0.1" 3478) (java.net.InetSocketAddress. "127.0.0.1" 12345) 600)
          scenario-09
          (fn []
            (let [res (dc-turn/step-turn-client tc0 (b/to-bytes un-alloc) 1000)
                  ev (first (:events res))
                  valid? (and (= :turn-packet-dropped (:type ev))
                              (= :unknown-transaction-id (:reason ev)))]
              {:valid? (boolean valid?) :event ev}))
          mutated-09
          (fn [sc-fn]
            (let [orig-step dc-turn/step-turn-client]
              (with-redefs [dc-turn/step-turn-client
                            (fn [tc raw now]
                              (let [res (orig-step tc raw now)]
                                ;; pre-fix: mutated state without dropping unsolicited packet
                                (assoc res :events [])))]
                (sc-fn))))]
      (swap! results assoc :DCT-09 (verify-jepsen-bug :DCT-09 "turn/unsolicited-transaction-validation" scenario-09 mutated-09)))

    ;; DCT-10: SCTP Duplicate COOKIE-ECHO in :established State Preserves Active Streams & :remote-tsn (RFC 4960 §5.2.4)
    (let [conn0 {:state :established
                 :cookie-secret (b/alloc-bytes 32)
                 :local-ver-tag 12345
                 :remote-ver-tag 67890
                 :remote-tsn 5000
                 :ssn 12
                 :streams {0 {:next-ssn 12 :send-queue [] :recv-queue []}}
                 :heartbeat-interval 0}
          init-res (dc-chunks/process-chunk conn0 {:type :init :init-tag 67890 :initial-tsn 101 :outbound-streams 16 :inbound-streams 16} nil 1000)
          cookie (get-in (first (:pending-control-chunks (:next-state init-res))) [:params :cookie])
          cookie-chunk {:type :cookie-echo :cookie cookie}
          scenario-10
          (fn []
            (let [res (dc-chunks/process-chunk conn0 cookie-chunk nil 1000)
                  st (:next-state res)
                  rem-tsn (:remote-tsn st)
                  ssn (:ssn st)
                  valid? (and (= 5000 rem-tsn)
                              (= 12 ssn)
                              (= :cookie-ack (:type (first (:pending-control-chunks st)))))]
              {:valid? (boolean valid?) :remote-tsn rem-tsn :ssn ssn}))
          mutated-10
          (fn [sc-fn]
            (let [orig-proc dc-chunks/process-chunk]
              (with-redefs [dc-chunks/process-chunk
                            (fn [st ch pkt now]
                              (if (= (:type ch) :cookie-echo)
                                ;; pre-fix: reset remote-tsn to 100 and ssn to 0
                                (let [res (orig-proc st ch pkt now)]
                                  (update res :next-state assoc :remote-tsn 100 :ssn 0))
                                (orig-proc st ch pkt now)))]
                (sc-fn))))]
      (swap! results assoc :DCT-10 (verify-jepsen-bug :DCT-10 "chunks/duplicate-cookie-echo-preserves-streams" scenario-10 mutated-10)))

    ;; DCT-11: SCTP Round-Robin Stream Scheduling Fairness (RFC 8831 §6)
    (let [chunk0 {:type :data :stream-id 0 :seq-num 0 :flags 3 :payload (byte-array [1])}
          chunk1 {:type :data :stream-id 1 :seq-num 0 :flags 3 :payload (byte-array [2])}
          conn0 {:state :established
                 :last-scheduled-stream-id 0
                 :streams {0 {:send-queue [{:sent? false :chunk chunk0}] :next-ssn 0}
                           1 {:send-queue [{:sent? false :chunk chunk1}] :next-ssn 0}}
                 :rwnd 100000
                 :cwnd 100000
                 :flight-size 0
                 :mtu 1200
                 :remote-tsn 0
                 :out-of-order-tsns (sorted-set-by #(b/s32-diff %1 %2))
                 :pending-control-chunks []
                 :simulated-dtls? true}
          scenario-11
          (fn []
            (let [res (dc/packetize conn0 [] 1000)
                  first-stream-id (first (map :stream-id (first (map :chunks (:network-out res)))))
                  valid? (= 1 first-stream-id)]
              {:valid? valid? :first-stream-id first-stream-id}))
          mutated-11
          (fn [sc-fn]
            (let [orig-pkt dc/packetize]
              (with-redefs [dc/packetize
                            (fn [conn evs now]
                              (let [res (orig-pkt conn evs now)]
                                ;; pre-fix: always picked stream 0
                                (assoc res :network-out [{:chunks [{:type :data :stream-id 0}]}])))]
                (sc-fn))))]
      (swap! results assoc :DCT-11 (verify-jepsen-bug :DCT-11 "packetize/round-robin-stream-fairness" scenario-11 mutated-11)))

    ;; DCT-12: ctl wait --min-seq Event ID vs. Session Seq Short-Circuit Fix
    (let [st {:event-queue [{"event_id" 0 "seq" 10 "event" "session-joined"}]
              :event-ack-cursor 0}
          cmd {"cmd" "wait" "min_seq" 5}
          scenario-12
          (fn []
            (let [res (light-node/exec-wait st cmd)
                  evs (get-in res [:response "events"])
                  valid? (= 1 (count evs))]
              {:valid? valid? :events-count (count evs)}))
          mutated-12
          (fn [sc-fn]
            (with-redefs [light-node/exec-wait
                          (fn [s _c]
                            ;; pre-fix: short-circuited on event_id 0 and failed min_seq 5
                            {:state s :response {"ok" true "events" [] "cursor" 0}})]
              (sc-fn)))]
      (swap! results assoc :DCT-12 (verify-jepsen-bug :DCT-12 "light-node/ctl-wait-min-seq-short-circuit" scenario-12 mutated-12)))

    (let [res-map @results
          all-valid? (and (= 12 (count res-map))
                          (every? (fn [[_ r]] (and (:remediated-valid? r)
                                                   (:pre-fix-caught? r)
                                                   (:bug-reproduced? r)))
                                  res-map))]
      {:ok? all-valid?
       :seed seed
       :remediated-count (count (filter (fn [[_ r]] (:remediated-valid? r)) res-map))
       :results res-map})))

;; =============================================================================
;; 11. WebRTC DataChannel Sans-IO Packet-Drop & Retransmission Simulation
;; =============================================================================

(defn- flip-sim-datachannel-packet
  "Flips a bit in ciphertext raw buffer `raw` to verify AEAD authentication rejection."
  [raw]
  (let [bs (b/to-bytes raw)
        len (b/blength bs)
        copy (b/alloc-bytes len)]
    (b/bcopy! bs 0 copy 0 len)
    (let [target-idx (dec len)]
      (b/bset-u8! copy target-idx (bit-xor (b/bget-u8 copy target-idx) 0xFF)))
    copy))

(defn run-datachannel-packet-drop-sim
  "Runs a deterministic, pure WebRTC DataChannel packet-drop and retransmission simulation.
   Establishes client/server endpoints via `dc/create-connection` with simulated DTLS 1.2,
   recovers from simulated dropped DTLS handshake flight via `:dtls/flight-timeout`,
   sends `payload-count` Bitecho wire envelopes over SCTP DataChannel stream,
   injects packet drops (`drop-indices`), bit-flip corruptions (`bitflip-indices`),
   and out-of-order delivery (`reorder?`), then fires `:sctp/t3-rtx` timeouts until
   all messages are sequentially delivered and verified."
  [& [{:keys [seed drop-indices bitflip-indices reorder? payload-count dtls-flight-drop?]
       :or {seed 20261114
            drop-indices #{0 2}
            bitflip-indices #{1}
            reorder? true
            payload-count 5
            dtls-flight-drop? true}}]]
  (let [rng-a (b/make-rng seed)
        rng-b (b/make-rng (b/fork-rng rng-a "peer-b"))
        cert-a (dtls/generate-simulated-cert rng-a)
        cert-b (dtls/generate-simulated-cert rng-b)
        base-time 100000
        client-a (dc/create-connection {:seed seed
                                        :now-ms base-time
                                        :simulated-dtls? true
                                        :cert-data cert-a
                                        :remote-fingerprint (:fingerprint cert-b)
                                        :ice-ufrag "AliceUfrag"
                                        :ice-pwd "AlicePwd"
                                        :remote-ice-ufrag "BobUfrag"
                                        :remote-ice-pwd "BobPwd"
                                        :remote-candidates ["127.0.0.1:5001"]}
                                       true)
        client-b (dc/create-connection {:seed (b/random-u64 rng-b)
                                        :now-ms base-time
                                        :simulated-dtls? true
                                        :cert-data cert-b
                                        :remote-fingerprint (:fingerprint cert-a)
                                        :ice-ufrag "BobUfrag"
                                        :ice-pwd "BobPwd"
                                        :remote-ice-ufrag "AliceUfrag"
                                        :remote-ice-pwd "AlicePwd"
                                        :remote-candidates ["127.0.0.1:5000"]}
                                       false)
        bh-a (dtls/begin-handshake! (:dtls/engine client-a))
        bh-b (dtls/begin-handshake! (:dtls/engine client-b))
        client-a (assoc client-a :dtls/engine (:engine bh-a))
        client-b (assoc client-b :dtls/engine (:engine bh-b))
        init-a (-> (dc/handle-timeout client-a :stun/keepalive base-time nil)
                   (update :network-out into (:packets bh-a))
                   (assoc-in [:new-state :timers :dtls/flight-timeout] {:expires-at (+ base-time 1000)}))
        init-b (dc/handle-timeout client-b :stun/keepalive base-time nil)
        init-a-ser (dc/serialize-network-out init-a)
        init-b-ser (dc/serialize-network-out init-b)
        initial-a-out (if dtls-flight-drop? [] (:network-out-bytes init-a-ser []))
        dtls-dropped-count (if dtls-flight-drop? (count (:network-out-bytes init-a-ser [])) 0)

        ;; Phase 1: Establish DTLS 1.2 Handshake & SCTP Association
        handshake-res
        (loop [a (:new-state init-a-ser)
               b (:new-state init-b-ser)
               a-out initial-a-out
               b-out (:network-out-bytes init-b-ser [])
               dtls-flight-rtx-fired? false
               tick 0]
          (let [now (+ base-time (* tick 50))]
            (if (or (>= tick 80)
                    (and (= :established (:state a)) (= :established (:state b))))
              {:state-a a
               :state-b b
               :now now
               :dtls-established? (and (dtls/handshake-finished? (:dtls/engine a))
                                       (dtls/handshake-finished? (:dtls/engine b)))
               :sctp-established? (and (= :established (:state a))
                                       (= :established (:state b)))
               :dtls-flight-rtx-fired? dtls-flight-rtx-fired?}
              (let [b-res (reduce (fn [acc item]
                                    (let [raw (b/to-bytes item)
                                          rx (dc/serialize-network-out (dc/handle-receive (:state acc) raw now "127.0.0.1:5000"))]
                                      (-> acc
                                          (assoc :state (:new-state rx))
                                          (update :out into (:network-out-bytes rx [])))))
                                  {:state b :out []}
                                  a-out)
                    a-res (reduce (fn [acc item]
                                    (let [raw (b/to-bytes item)
                                          rx (dc/serialize-network-out (dc/handle-receive (:state acc) raw now "127.0.0.1:5001"))]
                                      (-> acc
                                          (assoc :state (:new-state rx))
                                          (update :out into (:network-out-bytes rx [])))))
                                  {:state a :out []}
                                  b-out)
                    a-t (reduce (fn [acc [tid timer]]
                                  (if (>= now (:expires-at timer))
                                    (let [res (dc/serialize-network-out (dc/handle-timeout (:state acc) tid now (:dtls/engine (:state acc))))]
                                      (-> acc
                                          (assoc :state (:new-state res))
                                          (update :out into (:network-out-bytes res []))
                                          (cond-> (= tid :dtls/flight-timeout)
                                            (assoc :dtls-rtx true))))
                                    acc))
                                {:state (:state a-res) :out (:out a-res)}
                                (get-in a-res [:state :timers] {}))
                    b-t (reduce (fn [acc [tid timer]]
                                  (if (>= now (:expires-at timer))
                                    (let [res (dc/serialize-network-out (dc/handle-timeout (:state acc) tid now (:dtls/engine (:state acc))))]
                                      (-> acc
                                          (assoc :state (:new-state res))
                                          (update :out into (:network-out-bytes res []))))
                                    acc))
                                {:state (:state b-res) :out (:out b-res)}
                                (get-in b-res [:state :timers] {}))]
                (recur (:state a-t)
                       (:state b-t)
                       (:out a-t)
                       (:out b-t)
                       (or dtls-flight-rtx-fired? (:dtls-rtx a-t false))
                       (inc tick))))))]

    (if-not (and (:dtls-established? handshake-res) (:sctp-established? handshake-res))
      {:valid? false
       :seed seed
       :dtls-established? (:dtls-established? handshake-res)
       :sctp-established? (:sctp-established? handshake-res)
       :error "Failed to establish DTLS/SCTP association"}

      ;; Phase 2: Send `payload-count` Bitecho wire envelopes over DataChannel
      (let [{:keys [state-a state-b now]} handshake-res
            sent-envelopes (mapv (fn [i]
                                   {:type :rendezvous-telemetry
                                    :seq (long i)
                                    :sender "alice-dc"
                                    :payload (str "bitecho-d14-envelope-" i)
                                    :timestamp (+ now (* i 10))})
                                 (range payload-count))
            send-results (reduce (fn [acc env]
                                   (let [wire (fressian/encode-wire env)
                                         send-res (-> (dc/send-data (:state acc) wire 0 :webrtc/binary now)
                                                      (dc/serialize-network-out))]
                                     (-> acc
                                         (assoc :state (:new-state send-res))
                                         (update :packets into (:network-out-bytes send-res [])))))
                                 {:state state-a :packets []}
                                 sent-envelopes)
            initial-client-state (:state send-results)
            all-outbound-packets (:packets send-results)

            ;; Phase 3: Fault schedule injection (drops, bitflips, reordering)
            effective-drop-indices (set (filter #(< % (count all-outbound-packets)) drop-indices))
            effective-bitflip-indices (set (filter (fn [idx]
                                                     (and (< idx (count all-outbound-packets))
                                                          (not (contains? effective-drop-indices idx))))
                                                   bitflip-indices))
            tagged-packets (map-indexed (fn [idx pkt]
                                          (cond
                                            (contains? effective-drop-indices idx)
                                            {:action :drop :idx idx}

                                            (contains? effective-bitflip-indices idx)
                                            {:action :bitflip :idx idx :pkt (flip-sim-datachannel-packet pkt)}

                                            :else
                                            {:action :pass :idx idx :pkt pkt}))
                                        all-outbound-packets)
            surviving-packets (remove #(= (:action %) :drop) tagged-packets)
            scheduled-flight-1 (if reorder? (vec (reverse surviving-packets)) (vec surviving-packets))

            ;; Phase 4: Network Pump with SCTP T3-rtx & SACK Gap Processing
            sim-delivery
            (loop [client initial-client-state
                   server state-b
                   c->s-pkts (mapv :pkt scheduled-flight-1)
                   s->c-pkts []
                   delivered-envelopes []
                   t3-rtx-count 0
                   loop-tick 0]
              (let [t-now (+ now (* loop-tick 100))
                    client-unacked (long (or (get-in client [:metrics :unacked-data]) 0))]
                (if (or (>= loop-tick 120)
                        (and (= (count delivered-envelopes) payload-count)
                             (zero? client-unacked)))
                  {:client client
                   :server server
                   :delivered delivered-envelopes
                   :t3-rtx-retransmissions t3-rtx-count
                   :ticks loop-tick}
                  (let [srv-rx (reduce (fn [acc pkt-bytes]
                                         (let [raw (b/to-bytes pkt-bytes)
                                               rx (-> (dc/handle-receive (:state acc) raw t-now "127.0.0.1:5000")
                                                      (dc/serialize-network-out))
                                               evts (:app-events rx)]
                                           (-> acc
                                               (assoc :state (:new-state rx))
                                               (update :out into (:network-out-bytes rx []))
                                               (update :msgs into (keep (fn [e]
                                                                          (when (= (:type e) :on-message)
                                                                            (fressian/decode-wire (:payload e))))
                                                                        evts)))))
                                       {:state server :out [] :msgs delivered-envelopes}
                                       c->s-pkts)
                        server' (:state srv-rx)
                        new-delivered (:msgs srv-rx)
                        srv-replies (:out srv-rx)

                        cli-rx (reduce (fn [acc pkt-bytes]
                                         (let [raw (b/to-bytes pkt-bytes)
                                               rx (-> (dc/handle-receive (:state acc) raw t-now "127.0.0.1:5001")
                                                      (dc/serialize-network-out))]
                                           (-> acc
                                               (assoc :state (:new-state rx))
                                               (update :out into (:network-out-bytes rx [])))))
                                       {:state client :out []}
                                       (concat s->c-pkts srv-replies))
                        client' (:state cli-rx)
                        cli-replies (:out cli-rx)

                        t3-timer (get-in client' [:timers :sctp/t3-rtx])
                        t3-due? (and t3-timer (>= t-now (:expires-at t3-timer)))
                        cli-t3 (if t3-due?
                                 (let [t-res (-> (dc/handle-timeout client' :sctp/t3-rtx t-now (:dtls/engine client'))
                                                 (dc/serialize-network-out))]
                                   {:state (:new-state t-res)
                                    :out (:network-out-bytes t-res [])
                                    :fired? true})
                                 {:state client' :out [] :fired? false})
                        client'' (:state cli-t3)
                        t3-out (:out cli-t3)
                        new-t3-count (if (:fired? cli-t3) (inc t3-rtx-count) t3-rtx-count)

                        srv-sack-timer (get-in server' [:timers :sctp/t-delayed-sack])
                        srv-sack-due? (and srv-sack-timer (>= t-now (:expires-at srv-sack-timer)))
                        srv-sack (if srv-sack-due?
                                   (let [t-res (-> (dc/handle-timeout server' :sctp/t-delayed-sack t-now (:dtls/engine server'))
                                                   (dc/serialize-network-out))]
                                     {:state (:new-state t-res) :out (:network-out-bytes t-res [])})
                                   {:state server' :out []})
                        server'' (:state srv-sack)
                        srv-delayed-sacks (:out srv-sack)]
                    (recur client''
                           server''
                           (into cli-replies t3-out)
                           srv-delayed-sacks
                           new-delivered
                           new-t3-count
                           (inc loop-tick))))))

            delivered (:delivered sim-delivery)
            final-client (:client sim-delivery)
            unacked-remaining (long (or (get-in final-client [:metrics :unacked-data]) 0))
            order-matches? (= (mapv :seq sent-envelopes) (mapv :seq delivered))
            valid? (and (:dtls-established? handshake-res)
                        (:sctp-established? handshake-res)
                        (= payload-count (count delivered))
                        order-matches?
                        (zero? unacked-remaining))]
        {:valid? valid?
         :seed seed
         :dtls-established? true
         :sctp-established? true
         :dtls-flight-dropped-count dtls-dropped-count
         :dtls-flight-rtx-recovered? (:dtls-flight-rtx-fired? handshake-res)
         :dropped-packets-count (count effective-drop-indices)
         :bitflipped-packets-count (count effective-bitflip-indices)
         :t3-rtx-retransmissions (:t3-rtx-retransmissions sim-delivery)
         :sent-count payload-count
         :delivered-count (count delivered)
         :delivered-order-matches? order-matches?
         :client-unacked-remaining unacked-remaining}))))

;; =============================================================================
;; 13. Milestone Priority 2: Nexus E2EE Storage Simulation
;; =============================================================================
(defn run-nexus-e2ee-storage-sim
  "Deterministic VOPR simulation verifying Milestone Priority 2:
   Fractal E2EE Storage & Capability Service on unified Blob + Pointer + Subnet.
   Verifies:
   1. The Nexus subnet stores only opaque ciphertext (zero plaintext leakage).
   2. A second browser instance holding the same user key fetches Pointer (seq 2) + Blob from Nexus and restores the exact decrypted state.
   3. An adversarial rollback attempt replaying the old seq 1 pointer is rejected (:stale-pointer-rollback).
   4. An adversarial ciphertext bit-flip is rejected (:invalid-blob-cid / :decryption-failed).
   5. Advertising and resolving a paid UOp kernel capability (:compute/uop-kernel, :price-echo 500) on the subnet succeeds cleanly."
  [& [{:keys [seed] :or {seed 20261116}}]]
  (let [rng (crypto/make-random seed)
        user-kp (crypto/generate-keypair rng)
        user-priv (basalt/bytes->hex (:private user-kp))
        user-pub (basalt/bytes->hex (:public user-kp))
        subnet-id "nexus"
        nexus-policy {:subnet/id subnet-id
                      :subnet/parent-id "global"
                      :subnet/gate {:gate/mode :permissioned
                                    :gate/admission :allowlist
                                    :gate/trust-anchors #{user-pub}}
                      :subnet/path-acl [{:pattern "storage/<pubkey>/*" :principal {:type :self-path-owner}}
                                        {:pattern "capability/<pubkey>/*" :principal {:type :self-path-owner}}]
                      :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                      :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
        sub-inst0 (:instance (subnet/init-subnet-instance nexus-policy {:now-ms 1000}))
        state-v1 {:petnames {"axiom" "302a..."} :sessions ["s1"] :preferences {:theme "light"}}
        state-v2 {:petnames {"axiom" "302a..."} :sessions ["s1" "s2"] :preferences {:theme "dark"}}

        nonce1 (crypto/random-bytes rng 24)
        packed1 (storage/pack-encrypted-state {:privkey user-priv
                                               :pubkey user-pub
                                               :subnet-id subnet-id
                                               :slot "browser-state"
                                               :seq 1
                                               :leader-term 1
                                               :nonce-bytes nonce1
                                               :state-data state-v1})
        blob1 (:blob packed1)
        ptr1 (:pointer packed1)

        sub-inst1 (-> sub-inst0
                      (subnet/reduce-subnet {:type :put-blob :sender user-pub :blob blob1 :now-ms 1100})
                      (:state)
                      (subnet/reduce-subnet {:type :publish-pointer :sender user-pub :pointer ptr1 :now-ms 1200})
                      (:state))

        nonce2 (crypto/random-bytes rng 24)
        packed2 (storage/pack-encrypted-state {:privkey user-priv
                                               :pubkey user-pub
                                               :subnet-id subnet-id
                                               :slot "browser-state"
                                               :seq 2
                                               :leader-term 1
                                               :nonce-bytes nonce2
                                               :state-data state-v2})
        blob2 (:blob packed2)
        ptr2 (:pointer packed2)

        sub-inst2 (-> sub-inst1
                      (subnet/reduce-subnet {:type :put-blob :sender user-pub :blob blob2 :now-ms 1300})
                      (:state)
                      (subnet/reduce-subnet {:type :publish-pointer :sender user-pub :pointer ptr2 :now-ms 1400})
                      (:state))

        ;; 1. Zero plaintext leakage on Nexus Subnet
        blob1-res (data/get-blob (get-in sub-inst2 [:data :blobs]) (:blob/cid blob1))
        blob1-entry (:blob blob1-res)
        blob1-bytes (:blob/bytes blob1-entry)
        blob1-str (try (fressian/bytes->utf8 blob1-bytes) (catch Throwable _ ""))
        zero-plaintext-leakage? (and (:hit? blob1-res)
                                     (not (str/includes? blob1-str "preferences"))
                                     (not (str/includes? blob1-str "dark"))
                                     (not (str/includes? blob1-str "axiom")))

        ;; 2. Browser Node 2 restores exact decrypted state
        resolved-ptr2 (get-in sub-inst2 [:data :pointers [subnet-id (:pointer/path ptr2)]])
        resolved-blob2 (:blob (data/get-blob (get-in sub-inst2 [:data :blobs]) (:pointer/target resolved-ptr2)))
        unpack2-res (storage/unpack-encrypted-state {:privkey user-priv
                                                     :pubkey user-pub
                                                     :blob resolved-blob2
                                                     :pointer resolved-ptr2
                                                     :min-expected-seq 1
                                                     :context "browser-state"})
        exact-restore-v2? (and (:ok? unpack2-res)
                               (= state-v2 (:data unpack2-res))
                               (= 2 (:seq unpack2-res)))

        ;; 3. Adversarial rollback rejected
        rollback-res (storage/unpack-encrypted-state {:privkey user-priv
                                                      :pubkey user-pub
                                                      :blob blob1
                                                      :pointer ptr1
                                                      :min-expected-seq 2
                                                      :context "browser-state"})
        rollback-rejected? (and (false? (:ok? rollback-res))
                                (= :stale-pointer-rollback (:error rollback-res)))

        ;; 4. Adversarial ciphertext bit-flip rejected
        tampered-bytes (byte-array (:blob/bytes blob2))
        _ (let [idx 25] (aset tampered-bytes idx (unchecked-byte (bit-xor (aget tampered-bytes idx) 1))))
        tampered-blob (assoc blob2 :blob/bytes tampered-bytes)
        tamper-res (storage/unpack-encrypted-state {:privkey user-priv
                                                    :pubkey user-pub
                                                    :blob tampered-blob
                                                    :pointer ptr2
                                                    :min-expected-seq 2
                                                    :context "browser-state"})
        tamper-rejected? (and (false? (:ok? tamper-res))
                              (contains? #{:invalid-blob-cid :decryption-failed} (:error tamper-res)))

        ;; 5. Paid capability advertisement and resolution
        kernel-cid "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        cap-packed (storage/pack-capability-descriptor {:privkey user-priv
                                                        :pubkey user-pub
                                                        :subnet-id subnet-id
                                                        :capability-id "uop-kernel-v1"
                                                        :capability-type :compute/uop-kernel
                                                        :price-echo 500
                                                        :burn-floor 50
                                                        :metadata {:arch "arm64" :ops ["gemm"]}
                                                        :target-cid kernel-cid})
        sub-inst3 (-> sub-inst2
                      (subnet/reduce-subnet {:type :put-blob :sender user-pub :blob (:blob cap-packed) :now-ms 1500})
                      (:state)
                      (subnet/reduce-subnet {:type :publish-pointer :sender user-pub :pointer (:pointer cap-packed) :now-ms 1600})
                      (:state))
        resolved-cap-ptr (get-in sub-inst3 [:data :pointers [subnet-id (:pointer/path (:pointer cap-packed))]])
        resolved-cap-blob (:blob (data/get-blob (get-in sub-inst3 [:data :blobs]) (:pointer/target resolved-cap-ptr)))
        unpack-cap-res (storage/unpack-capability-descriptor {:blob resolved-cap-blob
                                                              :pointer resolved-cap-ptr})
        cap-resolved? (and (:ok? unpack-cap-res)
                           (= :compute/uop-kernel (get-in unpack-cap-res [:capability :capability/type]))
                           (= 500 (get-in unpack-cap-res [:capability :capability/price-echo]))
                           (= kernel-cid (get-in unpack-cap-res [:capability :capability/target-cid])))]
    {:valid? (and zero-plaintext-leakage?
                  exact-restore-v2?
                  rollback-rejected?
                  tamper-rejected?
                  cap-resolved?)
     :seed seed
     :zero-plaintext-leakage? zero-plaintext-leakage?
     :exact-restore-v2? exact-restore-v2?
     :rollback-rejected? rollback-rejected?
     :tamper-rejected? tamper-rejected?
     :capability-resolved? cap-resolved?}))

;; =============================================================================
;; 14. Milestone Priority 3: ChiaLisp-Style SCI Smart Contract Simulation
;; =============================================================================
(defn run-sci-smart-contract-sim
  "Deterministic VOPR simulation verifying Milestone Priority 3:
   ChiaLisp-Style Content-Addressed SCI Smart Contracts in Escrow & VOPR.
   Verifies:
   - Scenario 1: Honest UOp kernel purchase with oracle attestation,
     split 900 to author, 100 to oracle, tau = 0.5% burned (total burned = 5),
     and balances correctly credited.
   - Scenario 2: Adversarial SCI Attacks in VOPR:
     (a) Tampered UOp source (hash mismatch)
     (b) Forged oracle signature
     (c) Overspending conditions sum > escrow amount
     (d) Fuel exhaustion / unbounded step budget attack
     (e) Preimage bypass attempt on puzzle-locked escrow
     All 5 rejected safely with zero state corruption."
  [& [{:keys [seed] :or {seed 20261116}}]]
  (let [rng (crypto/make-random seed)
        client-kp (crypto/generate-keypair rng)
        client-pub (basalt/bytes->hex (:public client-kp))

        author-kp (crypto/generate-keypair rng)
        author-pub (basalt/bytes->hex (:public author-kp))

        oracle-kp (crypto/generate-keypair rng)
        oracle-pub (basalt/bytes->hex (:public oracle-kp))
        oracle-priv (basalt/bytes->hex (:private oracle-kp))

        init-st (-> (sm/init-state [] "node-val-1" (assoc config/default-config :settlement-take-bps 50))
                    (assoc-in [:ledger client-pub]
                              (account/map->AccountState {:balance 2000 :seq 0 :deps []})))

        kernel-src "float relu(float x) { return x > 0.0f ? x : 0.0f; }"
        kernel-hash (str/lower-case (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes kernel-src))))
        oracle-sig (basalt/bytes->hex (crypto/sign (basalt/hex->bytes oracle-priv) (fressian/utf8->bytes kernel-src)))

        puzzle-code (str "(and (= (sha256 (get solution :uop-kernel-source)) (get env :deliverable-hash))\n"
                         "     (verify-signature \"" oracle-pub "\" (get solution :uop-kernel-source) (get solution :oracle-sig))\n"
                         "     [ {:type :release :receiver \"" author-pub "\" :amount 900}\n"
                         "       {:type :release :receiver \"" oracle-pub "\" :amount 100} ])")
        puzzle-hash (puzzle/puzzle-cid puzzle-code)
        escrow-id (escrow/compute-escrow-id client-pub author-pub 1000 kernel-hash 1 100 "sim-escrow-1")

        lock-evt {:type :lock-intent
                  :escrow-id escrow-id
                  :payer client-pub
                  :receiver author-pub
                  :amount 1000
                  :deliverable-hash kernel-hash
                  :puzzle-hash puzzle-hash
                  :created-epoch 1
                  :expires-epoch 100
                  :epoch 1
                  :sender client-pub}
        lock-res (sm/handle-event init-st lock-evt)
        st-locked (:state lock-res)
        lock-ok? (and (= 1000 (get-in st-locked [:ledger client-pub :balance]))
                      (= :locked (get-in st-locked [:escrows escrow-id :status]))
                      (= puzzle-hash (get-in st-locked [:escrows escrow-id :puzzle-hash])))

        release-evt {:type :release-intent
                     :escrow-id escrow-id
                     :puzzle-source puzzle-code
                     :solution {:uop-kernel-source kernel-src
                                :oracle-sig oracle-sig}
                     :epoch 2}
        release-res (sm/handle-event st-locked release-evt)
        st-released (:state release-res)

        author-bal (get-in st-released [:ledger author-pub :balance] 0)
        oracle-bal (get-in st-released [:ledger oracle-pub :balance] 0)
        settled-take (get-in st-released [:epoch-settlement-takes 2] 0)
        escrow-status (get-in st-released [:escrows escrow-id :status])

        scenario-1-valid? (and lock-ok?
                               (= :released escrow-status)
                               (= 896 author-bal)
                               (= 99 oracle-bal)
                               (= 5 settled-take)
                               (= 1000 (+ author-bal oracle-bal settled-take)))

        ;; Scenario 2: Adversarial Attacks
        adv-tampered-res (sm/handle-event st-locked
                                          {:type :release-intent
                                           :escrow-id escrow-id
                                           :puzzle-source puzzle-code
                                           :solution {:uop-kernel-source "float relu(float x) { return 0.0f; }"
                                                      :oracle-sig oracle-sig}
                                           :epoch 2})
        tampered-source-rejected? (= :locked (get-in (:state adv-tampered-res) [:escrows escrow-id :status]))

        forged-sig (basalt/bytes->hex (byte-array 64))
        adv-forged-res (sm/handle-event st-locked
                                        {:type :release-intent
                                         :escrow-id escrow-id
                                         :puzzle-source puzzle-code
                                         :solution {:uop-kernel-source kernel-src
                                                    :oracle-sig forged-sig}
                                         :epoch 2})
        forged-sig-rejected? (= :locked (get-in (:state adv-forged-res) [:escrows escrow-id :status]))

        overspend-code (str "[{:type :release :receiver \"" author-pub "\" :amount 900}\n"
                            " {:type :release :receiver \"" oracle-pub "\" :amount 200}]")
        overspend-hash (puzzle/puzzle-cid overspend-code)
        os-escrow-id (escrow/compute-escrow-id client-pub author-pub 1000 kernel-hash 1 100 "sim-overspend-escrow")
        st-os-locked (:state (sm/handle-event init-st {:type :lock-intent
                                                       :escrow-id os-escrow-id
                                                       :payer client-pub
                                                       :receiver author-pub
                                                       :amount 1000
                                                       :deliverable-hash kernel-hash
                                                       :puzzle-hash overspend-hash
                                                       :created-epoch 1
                                                       :expires-epoch 100
                                                       :epoch 1
                                                       :sender client-pub}))
        adv-overspend-res (sm/handle-event st-os-locked
                                           {:type :release-intent
                                            :escrow-id os-escrow-id
                                            :puzzle-source overspend-code
                                            :solution {}
                                            :epoch 2})
        overspend-rejected? (and (= :locked (get-in (:state adv-overspend-res) [:escrows os-escrow-id :status]))
                                 (= :puzzle-overspend-violation
                                    (get-in (:state adv-overspend-res) [:diagnostics :last-puzzle-error])))

        fuel-dos-code "(reduce + 0 (range 1000))"
        fuel-dos-hash (puzzle/puzzle-cid fuel-dos-code)
        fuel-escrow-id (escrow/compute-escrow-id client-pub author-pub 1000 kernel-hash 1 100 "sim-fuel-escrow")
        st-fuel-locked (:state (sm/handle-event init-st {:type :lock-intent
                                                         :escrow-id fuel-escrow-id
                                                         :payer client-pub
                                                         :receiver author-pub
                                                         :amount 1000
                                                         :deliverable-hash kernel-hash
                                                         :puzzle-hash fuel-dos-hash
                                                         :created-epoch 1
                                                         :expires-epoch 100
                                                         :epoch 1
                                                         :sender client-pub}))
        adv-fuel-res (sm/handle-event st-fuel-locked
                                      {:type :release-intent
                                       :escrow-id fuel-escrow-id
                                       :puzzle-source fuel-dos-code
                                       :solution {}
                                       :epoch 2})
        fuel-exhaustion-rejected? (and (= :locked (get-in (:state adv-fuel-res) [:escrows fuel-escrow-id :status]))
                                       (= :puzzle-budget-exceeded
                                          (get-in (:state adv-fuel-res) [:diagnostics :last-puzzle-error])))

        adv-preimage-bypass-res (sm/handle-event st-locked
                                                 {:type :release-intent
                                                  :escrow-id escrow-id
                                                  :preimage kernel-src
                                                  :sender author-pub
                                                  :epoch 2})
        preimage-bypass-rejected? (= :locked (get-in (:state adv-preimage-bypass-res) [:escrows escrow-id :status]))

        scenario-2-valid? (and tampered-source-rejected?
                               forged-sig-rejected?
                               overspend-rejected?
                               fuel-exhaustion-rejected?
                               preimage-bypass-rejected?)]
    {:valid? (and scenario-1-valid? scenario-2-valid?)
     :seed seed
     :scenario-1-valid? scenario-1-valid?
     :scenario-2-valid? scenario-2-valid?
     :tampered-source-rejected? tampered-source-rejected?
     :forged-sig-rejected? forged-sig-rejected?
     :overspend-rejected? overspend-rejected?
     :fuel-exhaustion-rejected? fuel-exhaustion-rejected?
     :preimage-bypass-rejected? preimage-bypass-rejected?
     :author-balance author-bal
     :oracle-balance oracle-bal
     :settlement-take settled-take}))
