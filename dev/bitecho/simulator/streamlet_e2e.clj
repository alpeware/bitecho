(ns bitecho.simulator.streamlet-e2e
  "Pure Streamlet E2E simulation — bypasses core.async entirely.
   Each node is a map with a ConcurrentLinkedQueue inbox, an AtomicBoolean
   scheduler flag, and state held in a volatile!.  Events are drained in
   batches by tasks submitted to ForkJoinPool/commonPool, guaranteeing
   single-threaded execution per node while maximizing parallelism
   across the network."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.streamlet.core :as streamlet]
            [clojure.set :as set])
  (:import [java.util.concurrent ConcurrentHashMap ConcurrentLinkedQueue
            ForkJoinPool]
           [java.util.concurrent.atomic AtomicBoolean AtomicInteger AtomicLong]))

;; ---------------------------------------------------------------------------
;; Simulation Configuration
;; ---------------------------------------------------------------------------

(def total-nodes
  "Total nodes in simulation."
  100)
(def byzantine-pct
  "Percentage of byzantine nodes."
  0.0)

(defn calculate-protocol-params
  "Dynamically scales Contagion parameters based on network size.
   Mode can be :lean (fast simulations) or :secure (paper-accurate)."
  [n & {:keys [mode] :or {mode :lean}}]
  (let [ln-n (Math/log n)
        scale-factor (if (= mode :secure) 12.0 3.0)
        murmur-mult  (if (= mode :secure) 3.0 1.5)
        murmur-k    (max 5 (int (Math/ceil (* murmur-mult ln-n))))
        base-sample (int (Math/ceil (* scale-factor ln-n)))
        E base-sample
        R base-sample
        D base-sample
        E-thresh (int (Math/ceil (* 0.60 E)))
        R-thresh (int (Math/ceil (* 0.30 R)))
        D-thresh (int (Math/ceil (* 0.60 D)))
        view-size (int (Math/ceil (* 2.5 base-sample)))
        ttl-multiplier (if (= mode :secure) 10.0 3.0)
        ttl (int (Math/ceil (* ttl-multiplier ln-n)))]
    {:murmur-k murmur-k
     :basalt-max-view-size view-size
     :echo-sample-size E
     :echo-threshold E-thresh
     :ready-sample-size R
     :ready-threshold R-thresh
     :delivery-sample-size D
     :delivery-threshold D-thresh
     :gossip-ttl-epochs ttl}))

(def sim-config
  "Simulation configuration."
  {:total-nodes             total-nodes
   :byzantine-nodes         (int (* byzantine-pct total-nodes))
   :total-broadcast-messages 3
   :stabilization-ticks     20
   :max-epoch-jitter        3
   :completion-max-epochs   150
   :protocol                (merge config/default-config
                                   (calculate-protocol-params total-nodes :mode :lean))})

;; ---------------------------------------------------------------------------
;; Global pool & registry
;; ---------------------------------------------------------------------------

(def ^ForkJoinPool pool
  "ForkJoinPool for simulation."
  (ForkJoinPool/commonPool))

;; pubkey-hex -> node map.  Populated by start-network before events flow.
(def registry
  "Node registry map."
  (atom {}))

;; ---------------------------------------------------------------------------
;; Metrics (contention-free via ConcurrentHashMap/AtomicLong)
;; ---------------------------------------------------------------------------

(def ^ConcurrentHashMap cmd-counters
  "Counters for commands."
  (ConcurrentHashMap.))
(def ^AtomicLong total-routed
  "Total routed commands."
  (AtomicLong. 0))

(defn- inc-cmd-counter! [cmd-type]
  (let [^AtomicLong counter (.computeIfAbsent cmd-counters (name cmd-type)
                                              (reify java.util.function.Function
                                                (apply [_ _k] (AtomicLong. 0))))]
    (.incrementAndGet counter)))

;; Telemetry globals — reset by -main before simulation starts
(def partition-mode
  "Global flag to enable network partitions."
  (atom false))
(def ^ConcurrentHashMap delivery-chm
  "Delivery map."
  (ConcurrentHashMap.))
(def ^AtomicInteger delivery-counter
  "Delivery counter."
  (AtomicInteger. 0))
(def ^ConcurrentHashMap completed-broadcasts
  "Completed broadcasts map."
  (ConcurrentHashMap.))
(def ^AtomicLong done-flag
  "Done flag."
  (AtomicLong. 0))
(def honest-count
  "Honest node count."
  (atom 0))
(def broadcast-start-times
  "Map of broadcast start times."
  (atom {}))
(def total-consensus-time
  "Total time to consensus."
  (atom 0))
(def total-broadcast-count
  "Total broadcast count."
  (atom 1))

;; ---------------------------------------------------------------------------
;; Dummy crypto
;; ---------------------------------------------------------------------------

(defn fast-dummy-sha256
  "Replaces cryptographic SHA-256 with Clojure's fast, built-in Murmur3 hash.
   Returns a byte array to satisfy the existing bytes->hex contract."
  [^bytes b]
  ;; Converting to a vec to use Clojure's collection hashing
  (let [h (hash (vec b))]
    (.getBytes (str h) "UTF-8")))

(defn dummy-verify
  "Blindly accepts all signatures as valid during the simulation."
  [_pubkey _message _signature]
  true)

(defn dummy-sign
  "Returns an empty 64-byte array to simulate the shape of an Ed25519 signature."
  [_privkey _message]
  (byte-array 64))

;; ---------------------------------------------------------------------------
;; Forward declarations for the send→drain→route mutual recursion
;; ---------------------------------------------------------------------------

(declare send-event!)
(declare node-epoch)

;; ---------------------------------------------------------------------------
;; Batch size range for chaotic interleaving
;; ---------------------------------------------------------------------------
(def ^:private ^:const MIN-BATCH 1)
(def ^:private ^:const MAX-BATCH 64)

;; ---------------------------------------------------------------------------
;; Streamlet Reducer
;; ---------------------------------------------------------------------------

(defn- hash-to-int [hex]
  (try
    ;; Parse a short substring to avoid sign bit issues, ensuring a positive long.
    ;; The last characters of the public key are quite random.
    (Long/parseLong (subs hex (- (count hex) 8)) 16)
    (catch Exception _ 0)))

(defn- handle-streamlet-event
  "Pure state machine reducer for Streamlet BFT nodes."
  [state event]
  (case (:type event)
    :tick
    (let [new-epoch (inc (:epoch state))
          state (assoc state :epoch new-epoch)
          ;; Update head-hash to highest notarized block before proposing
          notarized-blocks (:notarized-blocks state)
          head-hash (if (empty? notarized-blocks)
                      "genesis"
                      (let [blocks (:blocks state)
                            highest-block (apply max-key #(get-in blocks [% :epoch] -1) notarized-blocks)]
                        highest-block))
          state (assoc state :head-hash head-hash)
          ;; Deterministic proposer selection for the epoch
          proposer-index (mod new-epoch (:total-nodes state))
          sorted-peers (vec (sort (keys (:registry-map state))))
          proposer-hex (nth sorted-peers proposer-index)]
      (if (= proposer-hex (:node-pubkey state))
        (let [block (streamlet/propose-block state new-epoch)
              block-hash (streamlet/hash-block block)
              state (assoc-in state [:blocks block-hash] block)
              ;; Proposer implicitly votes for their own block
              vote (streamlet/cast-vote state block)
              state (if vote (update state :voted-epochs (fnil conj #{}) (:epoch block)) state)
              ;; Accumulate local vote
              state (if vote (streamlet/accumulate-vote state vote (:public (:keypair state)) (:total-nodes state)) state)
              ;; Apply any future buffered votes for this block
              future-votes (get-in state [:future-votes block-hash] [])
              state (reduce (fn [s {:keys [vote sender-pubkey-bytes]}]
                              (streamlet/accumulate-vote s vote sender-pubkey-bytes (:total-nodes state)))
                            state future-votes)
              state (if (contains? state :future-votes) (update state :future-votes dissoc block-hash) state)
              ;; Try finalizing immediately in case n=1 threshold is met
              state (streamlet/finalize-prefix state)]
          {:state state
           :commands (if vote
                       [{:type :send-propose
                         :targets (vals (:registry-map state))
                         :block block}
                        {:type :send-vote
                         :targets (vals (:registry-map state))
                         :vote vote}]
                       [{:type :send-propose
                         :targets (vals (:registry-map state))
                         :block block}])})
        {:state state :commands []}))

    :receive-propose
    (let [block (:block event)
          block-hash (streamlet/hash-block block)
          ;; 1. Add block to DAG
          state (assoc-in state [:blocks block-hash] block)
          ;; 2. Ensure parent block is known before voting
          parent-hash (:parent-hash block)
          known-parent? (or (= parent-hash "genesis") (contains? (:blocks state) parent-hash))]
      (if known-parent?
        (let [;; 3. Cast vote if valid (streamlet/cast-vote checks if already voted for this epoch)
              vote (streamlet/cast-vote state block)
              state (if vote (update state :voted-epochs (fnil conj #{}) (:epoch block)) state)
              ;; Accumulate local vote
              state (if vote (streamlet/accumulate-vote state vote (:public (:keypair state)) (:total-nodes state)) state)
              ;; Apply any future buffered votes for this block
              future-votes (get-in state [:future-votes block-hash] [])
              state (reduce (fn [s {:keys [vote sender-pubkey-bytes]}]
                              (streamlet/accumulate-vote s vote sender-pubkey-bytes (:total-nodes state)))
                            state future-votes)
              state (if (contains? state :future-votes) (update state :future-votes dissoc block-hash) state)
              state (streamlet/finalize-prefix state)]
          (if vote
            {:state state
             :commands [{:type :send-vote
                         :targets (vals (:registry-map state))
                         ;; Important: the vote structure only contains :block-hash, :epoch, and :voter-signature
                         ;; The simulation routes to peers, but `:receive-vote` needs to know the original sender to fetch their pubkey
                         ;; So the :sender field is added to the event at `route-command!`
                         :vote vote}]}
            {:state state :commands []}))
        ;; If parent block is missing, buffer the block
        (let [future-blocks (get state :future-blocks [])
              state (assoc state :future-blocks (conj future-blocks event))]
          {:state state :commands []})))

    :receive-vote
    (let [vote (:vote event)
          sender (:sender event)
          ;; Try to resolve public key from registry map to bytes, otherwise parse from hex
          sender-node (get (:registry-map state) sender)
          sender-pubkey-bytes (if sender-node (:public (:keys sender-node)) (basalt/hex->bytes sender))
          ;; Verify vote block exists in blocks before accumulating
          known-block? (contains? (:blocks state) (:block-hash vote))]
      (if known-block?
        (let [;; accumulate-vote takes state, vote, public-key bytes, n
              state (streamlet/accumulate-vote state vote sender-pubkey-bytes (:total-nodes state))
              ;; if block was notarized by this vote, apply any future blocks that were waiting for it
              future-blocks (get state :future-blocks [])
              state (assoc state :future-blocks []) ;; clear queue so we can re-evaluate
              state (reduce (fn [s block-event]
                              ;; simplistic: just re-process them. In real app, we'd recursively call handle-event or drain them properly.
                              ;; For the simulator, buffering blocks prevents stall but recursive call here is fine because it's pure
                              (let [res (handle-streamlet-event s block-event)]
                                (:state res)))
                            state future-blocks)
              state (streamlet/finalize-prefix state)]
          {:state state :commands []})
        ;; Buffer future votes so they aren't lost if they arrive before the block proposal
        (let [future-votes (get state :future-votes {})
              block-future-votes (get future-votes (:block-hash vote) [])
              ;; Don't buffer duplicate votes from same sender!
              already-buffered? (some (fn [v] (= (:voter-signature (:vote v)) (:voter-signature vote))) block-future-votes)
              state (if already-buffered?
                      state
                      (assoc-in state [:future-votes (:block-hash vote)] (conj block-future-votes {:vote vote :sender-pubkey-bytes sender-pubkey-bytes})))]
          {:state state :commands []})))

    {:state state :commands []}))

;; ---------------------------------------------------------------------------
;; Side-effect handlers called from inside the drain loop
;; ---------------------------------------------------------------------------

(defn- is-network-command? [cmd]
  (let [t (:type cmd)]
    (and (keyword? t) (.startsWith (name t) "send-"))))

(defn- route-command!
  "Translates a network-out command to a network-in event for target node(s).
   Directly enqueues into each target's inbox via send-event!."
  [sender-node cmd]
  (let [sender-hex (:pubkey-hex sender-node)
        targets (or (:targets cmd) (when (:target cmd) [(:target cmd)]))
        sender-partition (mod (hash-to-int sender-hex) 2)]
    (doseq [t targets]
      (let [target-hex (if (string? t) t (or (:pubkey-hex t) (:pubkey t)))
            target-partition (mod (hash-to-int target-hex) 2)
            ;; Nodes partitioned into two groups: evens and odds.
            ;; But wait: if n=15, 8 nodes in group 0, 7 nodes in group 1.
            ;; Quorum threshold is 10. So neither group can reach quorum.
            drop? (and @partition-mode (not= sender-partition target-partition))]
        (when (not drop?)
          (when-let [target-node (get @registry target-hex)]
            (.incrementAndGet total-routed)
            (inc-cmd-counter! (:type cmd))
            (case (:type cmd)
              :send-propose
              (send-event! target-node {:type :receive-propose :sender sender-hex :block (:block cmd)})
              :send-vote
              (send-event! target-node {:type :receive-vote :sender sender-hex :vote (:vote cmd)})
              nil)))))))

;; ---------------------------------------------------------------------------
;; Core actor loop
;; ---------------------------------------------------------------------------

(defn- drain-node!
  "Drains a random number (1–64) of events from the node's inbox, processes each
   through the pure state machine, routes resulting commands, then re-schedules
   if the inbox is non-empty.  Decrements :pending-ticks when a :tick is consumed."
  [node]
  (let [^ConcurrentLinkedQueue inbox (:inbox node)
        ^AtomicBoolean sched (:scheduled? node)
        ^AtomicInteger pending (:pending-ticks node)
        state-vol (:state-vol node)
        batch-limit (+ MIN-BATCH (rand-int MAX-BATCH))]
    (try
      (loop [remaining batch-limit]
        (when (pos? remaining)
          (when-let [event (.poll inbox)]
            (when (= (:type event) :tick)
              (.decrementAndGet pending))
            (let [{new-state :state commands :commands}
                  (handle-streamlet-event @state-vol event)]
              (vreset! state-vol new-state)
              (doseq [cmd commands]
                (cond
                  (is-network-command? cmd)
                  (route-command! node cmd))))
            (recur (dec remaining)))))
      (finally
        ;; Reset scheduled flag and re-check inbox
        (.set sched false)
        (when (and (not (.isEmpty inbox))
                   (.compareAndSet sched false true))
          (.execute pool ^Runnable (fn [] (drain-node! node))))))))

(defn send-event!
  "Enqueues an event into the node's inbox and schedules a drain task on the
   ForkJoinPool if the node isn't already scheduled."
  [node event]
  (let [^ConcurrentLinkedQueue inbox (:inbox node)
        ^AtomicBoolean sched (:scheduled? node)
        type (:type node)]
    (when (= type :honest)
      (.add inbox event)
      (when (.compareAndSet sched false true)
        (.execute pool ^Runnable (fn [] (drain-node! node)))))))

;; ---------------------------------------------------------------------------
;; Node creation
;; ---------------------------------------------------------------------------

(defn- create-honest-node
  [i cfg]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        initial-state {:node-pubkey pubkey-hex
                       :keypair keys
                       :epoch 0
                       :blocks {}
                       :notarized-blocks #{}
                       :finalized-blocks #{}
                       :voted-epochs #{}
                       :block-votes {}
                       :total-nodes (:total-nodes cfg)}
        peer {:ip "127.0.0.1"
              :port (+ 8000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}]
    {:type :honest
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :state-vol (volatile! initial-state)
     :inbox (ConcurrentLinkedQueue.)
     :scheduled? (AtomicBoolean. false)
     :pending-ticks (AtomicInteger. 0)}))

(defn- create-byzantine-node
  [i _cfg]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        peer {:ip "127.0.0.1"
              :port (+ 9000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}]
    ;; Byzantine nodes silently drop everything — no state, drain is a no-op
    {:type :byzantine
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :state-vol (volatile! nil)
     :inbox (ConcurrentLinkedQueue.)
     :scheduled? (AtomicBoolean. false)
     :pending-ticks (AtomicInteger. 0)}))

;; ---------------------------------------------------------------------------
;; Network lifecycle
;; ---------------------------------------------------------------------------

(defn- start-network
  [cfg]
  (let [total (:total-nodes cfg)
        byz (:byzantine-nodes cfg)
        honest (- total byz)
        view-size (get-in cfg [:protocol :basalt-max-view-size])
        h-nodes (mapv #(create-honest-node % cfg) (range honest))
        b-nodes (mapv #(create-byzantine-node % cfg) (range byz))
        all-nodes (concat h-nodes b-nodes)
        nodes-map (into {} (map (juxt :pubkey-hex identity) all-nodes))
        all-peers (mapv :peer all-nodes)]

    ;; Populate the global registry so route-command! can find targets
    (reset! registry nodes-map)

    ;; Push an omniscient bootstrap view to all honest nodes
    (doseq [node h-nodes]
      (send-event! node {:type :receive-push-view
                         :view (take view-size (shuffle all-peers))}))

    {:nodes-map nodes-map
     :h-nodes h-nodes
     :honest-nodes honest}))

;; ---------------------------------------------------------------------------
;; Virtual-time tick injection
;; ---------------------------------------------------------------------------

(defn- node-epoch
  "Returns the current epoch of a node from its volatile state."
  [node]
  (or (:epoch @(:state-vol node)) 0))

(defn- min-epoch
  "Returns the minimum epoch across all honest nodes."
  [h-nodes]
  (reduce (fn [acc node] (min acc (node-epoch node))) Long/MAX_VALUE h-nodes))

(defn- inject-tick!
  "Enqueues a :tick event into a node's inbox and increments its pending-ticks."
  [node]
  (let [^AtomicInteger pending (:pending-ticks node)]
    (.incrementAndGet pending)
    (send-event! node {:type :tick :rng (java.util.concurrent.ThreadLocalRandom/current)})))

(defn- start-tick-injector!
  "Starts a daemon thread that continuously injects :tick events into nodes whose
   virtual epoch (epoch + pending-ticks) is within a random jitter of the minimum
   epoch across the network.  Returns the AtomicBoolean control flag and the Thread."
  [h-nodes max-jitter]
  (let [running (AtomicBoolean. true)
        thread (Thread.
                (fn []
                  (while (.get running)
                    (let [me (min-epoch h-nodes)]
                      (doseq [node h-nodes]
                        (let [^AtomicInteger pending (:pending-ticks node)
                              virtual-epoch (+ (node-epoch node) (.get pending))
                              jitter (+ 1 (rand-int max-jitter))]
                          (when (< virtual-epoch (+ me jitter))
                            (inject-tick! node))))))))]
    (.setDaemon thread true)
    (.start thread)
    {:running running :thread thread}))

;; ---------------------------------------------------------------------------
;; Main
;; ---------------------------------------------------------------------------

(defn- await-inboxes-empty
  "Blocks until all nodes have empty inboxes and zero pending tasks."
  [nodes]
  (loop []
    (when (some (fn [node]
                  (or (not (.isEmpty ^ConcurrentLinkedQueue (:inbox node)))
                      (.get ^AtomicBoolean (:scheduled? node))))
                nodes)
      (Thread/sleep 10)
      (recur)))
  ;; Wait an extra bit to allow ForkJoin tasks to fully clear and finalize variables
  (Thread/sleep 50))

(defn- inject-tick-to-all!
  "Injects a single tick into all nodes and waits for them to drain."
  [nodes]
  (doseq [node nodes]
    (inject-tick! node))
  (await-inboxes-empty nodes))

(defn -main
  "Main function for the Streamlet pure E2E simulator."
  []
  ;; We will use real crypto for streamlet rather than dummies, because the fast dummy sha
  ;; was causing identical hashes for block structures that serialize slightly differently.
  ;; Also the streamlet tests natively use real crypto without performance issues.
  (let [cfg (assoc sim-config :total-nodes 15 :byzantine-nodes 0) ; Run cluster of k=15 nodes
        total (:total-nodes cfg)
        byz (:byzantine-nodes cfg)
        honest (- total byz)
        start-wall-time (System/currentTimeMillis)]

      (.set total-routed 0)
      (.clear cmd-counters)
      (reset! partition-mode false)

      (println "Starting Streamlet Pure E2E Simulator (ForkJoinPool)...")
      (println (format "Network Topology: %d total nodes (%d honest, %d byzantine)"
                       total honest byz))
      (println (format "Quorum Threshold: %d" (streamlet/quorum-threshold total)))

      (let [network (start-network cfg)
            h-nodes (:h-nodes network)
            ;; Populate registry-map for all nodes to easily loop through them
            registry-map @registry]
        (doseq [node h-nodes]
          (vswap! (:state-vol node) assoc :registry-map registry-map))

        (println "\n── Phase 1: Full Synchrony (20 Epochs) ─────────────────")
        (dotimes [_ 20]
          (inject-tick-to-all! h-nodes))

        (let [finalized-sets (mapv #(count (:finalized-blocks @(:state-vol %))) h-nodes)
              max-finalized (apply max finalized-sets)]
          (println "Finalized blocks per node:" finalized-sets)
          (when (zero? max-finalized)
            (throw (ex-info "Liveness failure: No blocks finalized during synchrony" {}))))

        (println "\n── Phase 2: Extreme Network Partition (20 Epochs) ──────")
        (reset! partition-mode true)
        (let [pre-partition-finalized (apply max (mapv #(count (:finalized-blocks @(:state-vol %))) h-nodes))]
          (dotimes [_ 20]
            (inject-tick-to-all! h-nodes))
          (let [post-partition-finalized (apply max (mapv #(count (:finalized-blocks @(:state-vol %))) h-nodes))]
            (println "Finalized blocks per node before partition:" pre-partition-finalized)
            (println "Finalized blocks per node after partition:" post-partition-finalized)
            (when (> post-partition-finalized pre-partition-finalized)
              (throw (ex-info "Safety/Logic failure: Blocks finalized during strict partition without quorum" {})))))

        (println "\n── Phase 3: Partition Resolved & Anti-Entropy ──────────")
        (reset! partition-mode false)
        (let [global-blocks (apply merge (mapv #(:blocks @(:state-vol %)) h-nodes))
              global-notarized (apply set/union (mapv #(:notarized-blocks @(:state-vol %)) h-nodes))
              global-finalized (apply set/union (mapv #(:finalized-blocks @(:state-vol %)) h-nodes))]
          (doseq [node h-nodes]
            (vswap! (:state-vol node)
                    (fn [state]
                      (-> state
                          (update :blocks merge global-blocks)
                          (update :notarized-blocks set/union global-notarized)
                          (update :finalized-blocks set/union global-finalized))))))

        (println "\n── Phase 4: Restored Synchrony (20 Epochs) ─────────────")
        (let [pre-recovery-finalized (apply max (mapv #(count (:finalized-blocks @(:state-vol %))) h-nodes))]
          (dotimes [_ 20]
            (inject-tick-to-all! h-nodes))
          (let [finalized-sets (mapv #(:finalized-blocks @(:state-vol %)) h-nodes)
                post-recovery-finalized (count (first finalized-sets))]
            (println "Finalized blocks per node before recovery:" pre-recovery-finalized)
            (println "Finalized blocks per node after recovery:" (mapv count finalized-sets))
            (when-not (apply = finalized-sets)
              (throw (ex-info "Safety failure: Nodes have divergent finalized block prefixes" {})))
            (when (<= post-recovery-finalized pre-recovery-finalized)
              (throw (ex-info "Liveness failure: Nodes did not finalize new blocks after synchrony was restored" {})))))

        ;; ── Summary ──────────────────────────────────────────────────────
        (let [wall-time (- (System/currentTimeMillis) start-wall-time)
              cmd-stats (into {} (map (fn [k] [(keyword k) (.get ^AtomicLong (.get cmd-counters k))])
                                      (enumeration-seq (.keys cmd-counters))))]
          (println "\n========================================")
          (println "SIMULATION COMPLETE")
          (println "========================================")
          (println "Network commands processed          " (->> cmd-stats (sort-by second) (reverse)))
          (println "Total messages routed:              " (.get total-routed))
          (println "Epoch:                              " (min-epoch h-nodes))
          (println "Broadcasts Delivered:               " (.get delivery-counter))
          (println "Wall-clock time:                    " wall-time "ms")
          (when (pos? (.get delivery-counter))
            (println "Time to Delivery:                 "
                     (int (/ @total-consensus-time (.get delivery-counter))) "ms"))
          (println "========================================"))

        (System/exit 0))))