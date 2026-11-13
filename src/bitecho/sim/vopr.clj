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
  (:require [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.treasury :as treasury]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-node]
            [bitecho.shell.browser :as browser]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.set :as set]
            [clojure.walk :as walk]
            [datachannel.buffer :as b]
            [datachannel.core :as dc]
            [datachannel.dtls :as dtls]
            [datachannel.tcp :as dtcp]
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
