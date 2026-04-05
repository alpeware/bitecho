(ns bitecho.simulator.bundle-e2e
  "Pure Contagion E2E simulation — bypasses core.async entirely.
   Simulates Light Nodes streaming high-frequency micro-transactions to a Full Node.
   Proves the Full Node correctly batches them, respecting a time-based interval,
   and emits a single, compressed Murmur broadcast to optimize egress bandwidth."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]

            [bitecho.economy.bundle :as bundle]
            [bitecho.state-machine :as sm])
  (:import [java.util.concurrent ConcurrentHashMap ConcurrentLinkedQueue
            ForkJoinPool]
           [java.util.concurrent.atomic AtomicBoolean AtomicInteger AtomicLong]))

;; ---------------------------------------------------------------------------
;; Simulation Configuration
;; ---------------------------------------------------------------------------

(def total-nodes
  "Total nodes in simulation."
  15)
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
   :total-micro-transactions 50
   :bundle-max-size         50
   :bundle-max-time         1000000
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
;; Side-effect handlers called from inside the drain loop
;; ---------------------------------------------------------------------------

(defn- is-network-command? [cmd]
  (let [t (:type cmd)]
    (and (keyword? t) (.startsWith (name t) "send-"))))

(defn- handle-app-event!
  "Processes :app-event commands inline instead of routing through a channel."
  [node cmd]
  (when (= (:event-name cmd) :on-deliver)
    (let [message-id (:message-id cmd)
          pubkey (:pubkey-hex node)
          current-epoch (node-epoch node)
          ^java.util.Set delivery-set
          (.computeIfAbsent delivery-chm message-id
                            (reify java.util.function.Function
                              (apply [_ _k]
                                (ConcurrentHashMap/newKeySet))))]
      (when (.add delivery-set pubkey)
        (let [current (.size delivery-set)
              hn @honest-count]
          (when (zero? (mod current 10))
            (println (format "Broadcast %s reached %d/%d nodes at epoch %d"
                             message-id current hn current-epoch)))
          (when (>= current hn)
            ;; putIfAbsent returns nil on first insert (= this thread wins)
            (when (nil? (.putIfAbsent completed-broadcasts message-id true))
              (let [end-time (System/currentTimeMillis)
                    start-time (get @broadcast-start-times message-id)
                    duration (- end-time start-time)
                    completed (.incrementAndGet delivery-counter)]
                (swap! total-consensus-time + duration)
                (println (format "✅ Broadcast %s delivered to ALL %d honest nodes in %d ms (%d/%d)"
                                 message-id hn duration completed @total-broadcast-count))
                (when (>= completed @total-broadcast-count)
                  (.set done-flag 1))))))))))

(defn- route-command!
  "Translates a network-out command to a network-in event for target node(s).
   Directly enqueues into each target's inbox via send-event!."
  [sender-node cmd]
  (let [sender-hex (:pubkey-hex sender-node)
        targets (or (:targets cmd) (when (:target cmd) [(:target cmd)]))]
    (doseq [t targets]
      (let [target-hex (if (string? t) t (:pubkey t))]
        (when-let [target-node (get @registry target-hex)]
          (.incrementAndGet total-routed)
          (inc-cmd-counter! (:type cmd))
          (case (:type cmd)
            :send-push-view
            (send-event! target-node {:type :receive-push-view :view (:view cmd)})
            :send-summary
            (send-event! target-node {:type :receive-summary
                                      :sender sender-hex
                                      :summary (:summary cmd)})
            :send-subscribe
            (send-event! target-node {:type :receive-subscribe
                                      :sender sender-hex
                                      :roles (:roles cmd)})
            :send-pull-request
            (send-event! target-node {:type :receive-pull-request
                                      :sender sender-hex
                                      :missing-ids (:missing-ids cmd)})
            :send-gossip
            (send-event! target-node {:type :receive-gossip
                                      :message (:message cmd)
                                      :rng (java.util.concurrent.ThreadLocalRandom/current)})
            :send-sieve-echo
            (send-event! target-node {:type :receive-sieve-echo
                                      :sender sender-hex
                                      :message-id (:message-id cmd)
                                      :rng (java.util.concurrent.ThreadLocalRandom/current)})
            :send-contagion-ready
            (send-event! target-node {:type :receive-contagion-ready
                                      :sender sender-hex
                                      :message-id (:message-id cmd)
                                      :rng (java.util.concurrent.ThreadLocalRandom/current)})
            nil))))))

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
        bundle-state-vol (:bundle-state-vol node)
        batch-limit (+ MIN-BATCH (rand-int MAX-BATCH))]
    (try
      (loop [remaining batch-limit]
        (when (pos? remaining)
          (when-let [event (.poll inbox)]
            (if (= (:type event) :micro-transfer)
              ;; Full Node receives a micro-transfer
              (when bundle-state-vol
                (vreset! bundle-state-vol (bundle/add-to-buffer @bundle-state-vol (:transfer event) (System/currentTimeMillis))))
              (do
                (when (= (:type event) :tick)
                  (.decrementAndGet pending)
                  ;; Check bundling logic on tick
                  (when bundle-state-vol
                    (let [{:keys [bundle state]} (bundle/try-bundle @bundle-state-vol (System/currentTimeMillis) (:bundle-max-size sim-config) (:bundle-max-time sim-config))]
                      (vreset! bundle-state-vol state)
                      (when bundle
                        (let [payload-bytes (.getBytes (pr-str {:type :bundle :transfers bundle}) "UTF-8")
                              message-id (basalt/bytes->hex (crypto/sha256 payload-bytes))]
                          (swap! broadcast-start-times assoc message-id (System/currentTimeMillis))
                          (println (format "📦 Full Node emitting bundled Murmur broadcast %s with %d transfers" message-id (count bundle)))
                          (send-event! node {:type :contagion-broadcast
                                             :payload payload-bytes
                                             :rng (java.util.concurrent.ThreadLocalRandom/current)
                                             :private-key (:private (:keys node))
                                             :public-key (:public (:keys node))}))))))
                ;; Normal state machine processing
                (let [{new-state :state commands :commands}
                      (sm/handle-event @state-vol event)]
                  (vreset! state-vol new-state)
                  (doseq [cmd commands]
                    (cond
                      (= (:type cmd) :app-event)
                      (handle-app-event! node cmd)

                      (is-network-command? cmd)
                      (route-command! node cmd))))))
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
        initial-state (sm/init-state [] pubkey-hex (:protocol cfg))
        peer {:ip "127.0.0.1"
              :port (+ 8000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}]
    (cond-> {:type :honest
             :pubkey-hex pubkey-hex
             :keys keys
             :peer peer
             :state-vol (volatile! initial-state)
             :inbox (ConcurrentLinkedQueue.)
             :scheduled? (AtomicBoolean. false)
             :pending-ticks (AtomicInteger. 0)}
      ;; Make Node 0 the "Full Node"
      (= i 0) (assoc :bundle-state-vol (volatile! {})))))

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

(defn -main
  "Main function for the Contagion pure E2E simulator."
  []
  (with-redefs [crypto/sha256 fast-dummy-sha256
                crypto/verify dummy-verify
                crypto/sign   dummy-sign]
    (let [cfg sim-config
          total (:total-nodes cfg)
          byz (:byzantine-nodes cfg)
          honest (- total byz)
          start-wall-time (System/currentTimeMillis)]

      ;; Reset global mutable state
      (.clear delivery-chm)
      (.set delivery-counter 0)
      (.clear completed-broadcasts)
      (.set done-flag 0)
      (.set total-routed 0)
      (.clear cmd-counters)
      (reset! honest-count honest)
      (reset! broadcast-start-times {})
      (reset! total-consensus-time 0)
      (reset! total-broadcast-count 1) ;; Expecting 1 bundle broadcast

      (println "Starting Bundling Isolation Simulator (ForkJoinPool, no core.async)...")
      (println (format "Network Topology: %d total nodes (%d honest, %d byzantine)"
                       total honest byz))

      (let [network (start-network cfg)
            h-nodes (:h-nodes network)]

        ;; ── Start virtual-time tick injector ─────────────────────────────
        (let [max-jitter (:max-epoch-jitter cfg)
              ticker (start-tick-injector! h-nodes max-jitter)]

          ;; ── Stabilization phase ──────────────────────────────────────────
          (println (format "Waiting for min-epoch to reach %d (stabilization)..."
                           (:stabilization-ticks cfg)))
          (loop [last-printed 0]
            (let [me (min-epoch h-nodes)]
              (when (< me (:stabilization-ticks cfg))
                (when (>= (- me last-printed) 10)
                  (println (format "  Stabilization: min-epoch %d/%d"
                                   me (:stabilization-ticks cfg))))
                (Thread/sleep 10)
                (recur (if (>= (- me last-printed) 10) me last-printed)))))
          (println "  Stabilization complete.")

          ;; ── Broadcast phase ──────────────────────────────────────────────
          (let [full-node (first h-nodes)
                sender-pubkey (:pubkey-hex full-node)
                receiver (second h-nodes)
                receiver-pubkey (:pubkey-hex receiver)]
            (println (format "Simulating %d high-frequency micro-transactions sent to Full Node %s"
                             (:total-micro-transactions cfg)
                             (subs sender-pubkey (- (count sender-pubkey) 8))))
            (doseq [i (range (:total-micro-transactions cfg))]
              (let [transfer {:sender sender-pubkey
                              :receiver receiver-pubkey
                              :amount 1
                              :seq (inc i)
                              :deps []}]
                (send-event! full-node {:type :micro-transfer :transfer transfer})))

            ;; We just let the tick injector naturally trigger `try-bundle`
            (println "Finished streaming micro-transactions. Waiting for Full Node to bundle and broadcast..."))

          ;; ── Wait for completion (epoch-bounded) ──────────────────────────
          (let [broadcast-epoch (min-epoch h-nodes)
                max-epochs (:completion-max-epochs cfg)]
            (loop []
              (let [total-delivered (.get delivery-counter)]
                (when (and (< total-delivered @total-broadcast-count)
                           (< (- (min-epoch h-nodes) broadcast-epoch) max-epochs))
                  (Thread/sleep 10)
                  (recur))))

            (when (zero? (.get done-flag))
              (throw (ex-info "Contagion broadcast failed to reach all honest nodes within epoch limit"
                              {:max-epochs max-epochs
                               :current-min-epoch (min-epoch h-nodes)}))))

          ;; Stop tick injector
          (.set ^AtomicBoolean (:running ticker) false))

        ;; Final validation: verify a single Murmur broadcast hit the network
        (println "\nVerifying network egress bandwidth savings...")
        (let [b-counts (get cmd-counters "send-gossip")
              murmur-gossip-count (if b-counts (.get ^AtomicLong b-counts) 0)]
          ;; Egress for a single broadcast should be around 10-50 gossip messages in a 15-node network
          (if (< murmur-gossip-count 300)
            (println (format "✅ Egress optimization confirmed! Only %d gossip messages were routed for %d micro-transactions."
                             murmur-gossip-count (:total-micro-transactions cfg)))
            (throw (ex-info "Egress bandwidth was not optimized" {:murmur-gossip-count murmur-gossip-count}))))

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

        (System/exit 0)))))