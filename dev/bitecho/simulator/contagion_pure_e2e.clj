(ns bitecho.simulator.contagion-pure-e2e
  "Pure Contagion E2E simulation — bypasses core.async entirely.
   Each node is a map with a ConcurrentLinkedQueue inbox, an AtomicBoolean
   scheduler flag, and state held in a volatile!.  Events are drained in
   batches by tasks submitted to ForkJoinPool/commonPool, guaranteeing
   single-threaded execution per node while maximizing parallelism
   across the network."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.state-machine :as sm])
  (:import [java.util.concurrent ConcurrentHashMap ConcurrentLinkedQueue
            ForkJoinPool]
           [java.util.concurrent.atomic AtomicBoolean AtomicInteger AtomicLong]))

;; ---------------------------------------------------------------------------
;; Simulation Configuration
;; ---------------------------------------------------------------------------

(def total-nodes 1000)

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
        E-thresh (int (Math/ceil (* 0.70 E)))
        R-thresh (int (Math/ceil (* 0.35 R)))
        D-thresh (int (Math/ceil (* 0.80 D)))
        view-size (int (Math/ceil (* 2.5 base-sample)))
        ttl (int (Math/ceil (* 3.0 ln-n)))]
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
  {:total-nodes             total-nodes
   :byzantine-nodes         0
   :tick-interval-ms        5000
   :total-broadcast-messages 1
   :stabilization-ticks     60
   :stabilization-tick-pause-ms 500
   :post-stabilization-pause-ms 30000
   :broadcast-pause-ms      5000
   :completion-timeout-ms   (* 12 600000)
   :protocol                (merge config/default-config
                                   (calculate-protocol-params total-nodes :mode :lean))})

;; ---------------------------------------------------------------------------
;; Global pool & registry
;; ---------------------------------------------------------------------------

(def ^ForkJoinPool pool (ForkJoinPool/commonPool))

;; pubkey-hex -> node map.  Populated by start-network before events flow.
(def registry (atom {}))

;; ---------------------------------------------------------------------------
;; Metrics (contention-free via ConcurrentHashMap/AtomicLong)
;; ---------------------------------------------------------------------------

(def ^ConcurrentHashMap cmd-counters (ConcurrentHashMap.))
(def ^AtomicLong total-routed (AtomicLong. 0))

(defn- inc-cmd-counter! [cmd-type]
  (let [^AtomicLong counter (.computeIfAbsent cmd-counters (name cmd-type)
                                               (reify java.util.function.Function
                                                 (apply [_ _k] (AtomicLong. 0))))]
    (.incrementAndGet counter)))

;; Telemetry globals — reset by -main before simulation starts
(def ^ConcurrentHashMap delivery-chm (ConcurrentHashMap.))
(def ^AtomicInteger delivery-counter (AtomicInteger. 0))
(def ^AtomicLong done-flag (AtomicLong. 0))
(def honest-count (atom 0))
(def broadcast-start-times (atom {}))
(def total-consensus-time (atom 0))

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

;; ---------------------------------------------------------------------------
;; Constants
;; ---------------------------------------------------------------------------
(def ^:private ^:const BATCH-SIZE 128)

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
          ^java.util.Set delivery-set
          (.computeIfAbsent delivery-chm message-id
                            (reify java.util.function.Function
                              (apply [_ _k]
                                (ConcurrentHashMap/newKeySet))))]
      (when (.add delivery-set pubkey)
        (let [current (.size delivery-set)
              hn @honest-count]
          (when (zero? (mod current 10))
            (println (format "Broadcast %s reached %d/%d nodes"
                             message-id current hn)))
          (when (and (>= current hn)
                     (.compareAndSet delivery-counter 0 1))
            (let [end-time (System/currentTimeMillis)
                  start-time (get @broadcast-start-times message-id)
                  duration (- end-time start-time)]
              (swap! total-consensus-time + duration)
              (println (format "✅ Broadcast %s delivered to ALL %d honest nodes in %d ms"
                               message-id hn duration)))
            (.set done-flag 1)))))))

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
  "Drains up to BATCH-SIZE events from the node's inbox, processes each through
   the pure state machine, routes resulting commands, then re-schedules if the
   inbox is non-empty."
  [node]
  (let [^ConcurrentLinkedQueue inbox (:inbox node)
        ^AtomicBoolean sched (:scheduled? node)
        state-vol (:state-vol node)]
    (try
      (loop [remaining BATCH-SIZE]
        (when (pos? remaining)
          (when-let [event (.poll inbox)]
            (let [{new-state :state commands :commands}
                  (sm/handle-event @state-vol event)]
              (vreset! state-vol new-state)
              (doseq [cmd commands]
                (cond
                  (= (:type cmd) :app-event)
                  (handle-app-event! node cmd)

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
        ^AtomicBoolean sched (:scheduled? node)]
    (.add inbox event)
    (when (.compareAndSet sched false true)
      (.execute pool ^Runnable (fn [] (drain-node! node))))))

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
    {:type :honest
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :state-vol (volatile! initial-state)
     :inbox (ConcurrentLinkedQueue.)
     :scheduled? (AtomicBoolean. false)}))

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
     :scheduled? (AtomicBoolean. false)}))

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
;; Synchronous helpers
;; ---------------------------------------------------------------------------

(defn- tick-all-nodes!
  "Sends a :tick event to every honest node."
  [h-nodes]
  (doseq [node h-nodes]
    (when (= (:type node) :honest)
      (send-event! node {:type :tick :rng (java.util.concurrent.ThreadLocalRandom/current)}))))

(defn- await-quiescence!
  "Busy-waits until the ForkJoinPool has no queued/active tasks."
  []
  (loop []
    (when-not (.isQuiescent pool)
      (Thread/sleep 1)
      (recur))))

;; ---------------------------------------------------------------------------
;; Main
;; ---------------------------------------------------------------------------

(defn -main []
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
      (.set done-flag 0)
      (.set total-routed 0)
      (.clear cmd-counters)
      (reset! honest-count honest)
      (reset! broadcast-start-times {})
      (reset! total-consensus-time 0)

      (println "Starting Contagion Pure E2E Simulator (ForkJoinPool, no core.async)...")
      (println (format "Network Topology: %d total nodes (%d honest, %d byzantine)"
                       total honest byz))
      (println (format "Protocol: murmur-k=%d, view=%d, E=%d/%d, R=%d/%d, D=%d/%d, TTL=%d"
                       (get-in cfg [:protocol :murmur-k])
                       (get-in cfg [:protocol :basalt-max-view-size])
                       (get-in cfg [:protocol :echo-sample-size])
                       (get-in cfg [:protocol :echo-threshold])
                       (get-in cfg [:protocol :ready-sample-size])
                       (get-in cfg [:protocol :ready-threshold])
                       (get-in cfg [:protocol :delivery-sample-size])
                       (get-in cfg [:protocol :delivery-threshold])
                       (get-in cfg [:protocol :gossip-ttl-epochs])))
      (println (format "ForkJoinPool parallelism: %d" (.getParallelism (ForkJoinPool/commonPool))))

      (let [network (start-network cfg)
            h-nodes (:h-nodes network)]

        ;; ── Stabilization phase ──────────────────────────────────────────
        (println (format "Running %d stabilization ticks to build subscription graphs..."
                         (:stabilization-ticks cfg)))
        (dotimes [i (:stabilization-ticks cfg)]
          (tick-all-nodes! h-nodes)
          (Thread/sleep (:stabilization-tick-pause-ms cfg))
          (when (zero? (mod (inc i) 10))
            (println (format "  Stabilization tick %d/%d complete"
                             (inc i) (:stabilization-ticks cfg)))))

        ;; Let the pool drain before post-stabilization pause
        (await-quiescence!)
        (println (format "Running %d ms post-stabilization pause..."
                         (:post-stabilization-pause-ms cfg)))
        (Thread/sleep (:post-stabilization-pause-ms cfg))

        ;; ── Background ticker ────────────────────────────────────────────
        (let [tick-running (AtomicBoolean. true)
              tick-thread (Thread.
                           (fn []
                             (while (.get tick-running)
                               (tick-all-nodes! h-nodes)
                               (Thread/sleep (:tick-interval-ms cfg)))))]
          (.setDaemon tick-thread true)
          (.start tick-thread)

          ;; ── Broadcast phase ──────────────────────────────────────────────
          (dotimes [iteration (:total-broadcast-messages cfg)]
            (let [initiator (rand-nth h-nodes)
                  broadcast-id (str (java.util.UUID/randomUUID))
                  payload-str (pr-str {:id broadcast-id :data (str "test-payload-" (inc iteration))})
                  payload-bytes (.getBytes ^String payload-str "UTF-8")
                  message-id (basalt/bytes->hex (crypto/sha256 payload-bytes))]
              (swap! broadcast-start-times assoc message-id (System/currentTimeMillis))
              (println (format "Injecting broadcast %s via honest node %s..."
                               broadcast-id
                               (subs (:pubkey-hex initiator)
                                     (- (count (:pubkey-hex initiator)) 8))))
              (send-event! initiator {:type :contagion-broadcast
                                      :payload payload-bytes
                                      :rng (java.util.concurrent.ThreadLocalRandom/current)
                                      :private-key (:private (:keys initiator))
                                      :public-key (:public (:keys initiator))}))
            (Thread/sleep (:broadcast-pause-ms cfg)))

          ;; ── Wait for completion ──────────────────────────────────────────
          (let [deadline (+ (System/currentTimeMillis) (:completion-timeout-ms cfg))]
            (loop []
              (when (and (zero? (.get done-flag))
                         (< (System/currentTimeMillis) deadline))
                (Thread/sleep 500)
                (recur)))

            (when (zero? (.get done-flag))
              (println "\n⚠️  Delivery status at timeout:")
              (doseq [bid (enumeration-seq (.keys delivery-chm))]
                (let [^java.util.Set s (.get delivery-chm bid)]
                  (println (format "  Broadcast %s: %d/%d delivered" bid (.size s) honest))))

              ;; ─── Diagnostic state dump ───────────────────────────────────
              (println "\n🔍 Querying state of undelivered nodes...")
              (let [delivered-pubkeys (into #{}
                                            (mapcat (fn [bid]
                                                      (let [^java.util.Set s (.get delivery-chm bid)]
                                                        (iterator-seq (.iterator s))))
                                                    (enumeration-seq (.keys delivery-chm))))
                    undelivered (filterv #(not (contains? delivered-pubkeys (:pubkey-hex %)))
                                         h-nodes)
                    protocol-cfg (:protocol cfg)
                    E-hat (:echo-threshold protocol-cfg)
                    D-hat (:delivery-threshold protocol-cfg)
                    broadcast-ids (into #{} (enumeration-seq (.keys delivery-chm)))

                    classify-node
                    (fn [n]
                      (let [state @(:state-vol n)
                            pubkey (let [pk (:pubkey-hex n)] (subs pk (- (count pk) 8)))
                            echo-sample (:global-echo-sample state)
                            echo-subs (:echo-subscribers state)
                            ready-subs (:ready-subscribers state)
                            delivery-subs (:delivery-subscribers state)
                            bid (first broadcast-ids)
                            has-message? (and bid (contains? (:contagion-known-ids state) bid))
                            echo-votes (get-in state [:echo-vote-counts bid] 0)
                            ready-votes (get-in state [:ready-vote-counts bid] 0)
                            delivery-votes (get-in state [:delivery-vote-counts bid] 0)
                            sieve-delivered? (and bid (contains? (:sieve-delivered-set state) bid))
                            local-ready? (and bid (contains? (:local-ready-set state) bid))]
                        {:pubkey pubkey
                         :group (cond
                                  (empty? echo-sample)       :no-echo-sample
                                  (empty? echo-subs)         :no-echo-subscribers
                                  (empty? ready-subs)        :no-ready-subscribers
                                  (empty? delivery-subs)     :no-delivery-subscribers
                                  (not has-message?)         :no-message
                                  (and has-message? (not sieve-delivered?)
                                       (< echo-votes E-hat)) :awaiting-sieve-echo
                                  (and sieve-delivered? (not local-ready?))
                                  :sieve-delivered-not-ready
                                  (and local-ready?
                                       (< delivery-votes D-hat))
                                  :ready-awaiting-delivery
                                  :else                      :unknown)
                         :echo-sample-size (count echo-sample)
                         :echo-sub-count (count echo-subs)
                         :ready-sub-count (count ready-subs)
                         :delivery-sub-count (count delivery-subs)
                         :echo-votes echo-votes
                         :ready-votes ready-votes
                         :delivery-votes delivery-votes
                         :basalt-view-size (count (basalt/extract-peers (:basalt-view state)))
                         :epoch (:epoch state)
                         :has-message? has-message?
                         :sieve-delivered? sieve-delivered?
                         :local-ready? local-ready?}))

                    classified (mapv classify-node undelivered)
                    groups (group-by :group classified)]

                (println (format "\n📊 Diagnostic Summary: %d undelivered nodes"
                                 (count undelivered)))
                (println "════════════════════════════════════════════════════════════")
                (doseq [[group nodes] (sort-by (comp - count second) groups)]
                  (let [sample (first nodes)]
                    (println (format "\n  %-30s  %d nodes" (name group) (count nodes)))
                    (println (format "    Sample node:  %s" (:pubkey sample)))
                    (println (format "    Basalt view:  %d peers, epoch %d"
                                     (:basalt-view-size sample) (:epoch sample)))
                    (println (format "    Samples:      E=%d" (:echo-sample-size sample)))
                    (println (format "    Subscribers:  echo=%d  ready=%d  delivery=%d"
                                     (:echo-sub-count sample) (:ready-sub-count sample)
                                     (:delivery-sub-count sample)))
                    (println (format "    Has message:  %s  Sieve-delivered: %s  Ready: %s"
                                     (:has-message? sample) (:sieve-delivered? sample)
                                     (:local-ready? sample)))
                    (println (format "    Votes:        echo=%d/%d  ready=%d  delivery=%d/%d"
                                     (:echo-votes sample) E-hat
                                     (:ready-votes sample)
                                     (:delivery-votes sample) D-hat))))
                (println "\n════════════════════════════════════════════════════════════"))

              (throw (ex-info "Contagion broadcast failed to reach all honest nodes within timeout"
                              {:timeout-ms (:completion-timeout-ms cfg)}))))

          ;; Stop background ticker
          (.set tick-running false))

        ;; ── Summary ──────────────────────────────────────────────────────
        (let [wall-time (- (System/currentTimeMillis) start-wall-time)
              cmd-stats (into {} (map (fn [k] [(keyword k) (.get ^AtomicLong (.get cmd-counters k))])
                                      (enumeration-seq (.keys cmd-counters))))]
          (println "\n========================================")
          (println "SIMULATION COMPLETE")
          (println "========================================")
          (println "Network commands processed          " (->> cmd-stats (sort-by second) (reverse)))
          (println "Total messages routed:              " (.get total-routed))
          (println "Broadcasts Delivered:               " (.get delivery-counter))
          (println "Wall-clock time:                    " wall-time "ms")
          (when (pos? (.get delivery-counter))
            (println "Time to Delivery:                 "
                     (int (/ @total-consensus-time (.get delivery-counter))) "ms"))
          (println "========================================"))

        (System/exit 0)))))
