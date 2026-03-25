(ns bitecho.simulator.contagion-e2e
  "Isolated integration test proving that a pure Contagion broadcast reliably reaches all honest nodes in the presence of Byzantine actors."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.shell.core :as shell-core]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async])
  (:import [java.util.concurrent ConcurrentHashMap]
           [java.util.concurrent.atomic AtomicInteger AtomicLong]))

;; ---------------------------------------------------------------------------
;; Simulation Configuration
;; ---------------------------------------------------------------------------

(defn calculate-protocol-params
  "Dynamically scales Contagion parameters based on network size to maintain O(log N) guarantees.
   Mode can be :lean (fast simulations) or :secure (paper-accurate, high fault tolerance)."
  [total-nodes & {:keys [mode] :or {mode :lean}}]
  (let [ln-n (Math/log total-nodes)
        
        ;; Multipliers based on desired security margin
        scale-factor (if (= mode :secure) 12.0 3.0)
        murmur-mult  (if (= mode :secure) 3.0 1.5)
        
        ;; Logarithmic scaling
        murmur-k    (max 5 (int (Math/ceil (* murmur-mult ln-n))))
        base-sample (int (Math/ceil (* scale-factor ln-n)))
        
        ;; Sizing (Uniform sample sizes mapped to S)
        E base-sample
        R base-sample
        D base-sample
        
        ;; Thresholds (Maintaining the strict R/R < D/D invariant)
        ;; Echo: ~70%, Ready: ~35%, Delivery: ~80%
        E-thresh (int (Math/ceil (* 0.70 E)))
        R-thresh (int (Math/ceil (* 0.35 R)))
        D-thresh (int (Math/ceil (* 0.80 D)))
        
        ;; Auxiliary network params
        view-size (int (Math/ceil (* 2.5 base-sample)))
        ;; Safely over-estimating the theoretical diameter of O(log N / log log N)
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
  "Simulation parameters for 1000-node Contagion E2E.
   Protocol parameters use default-config with bumped view/TTL for N=1000."
  {:total-nodes             1000
   :byzantine-nodes         0
   :tick-interval-ms        500
   :total-broadcast-messages 1
   :stabilization-ticks     40
   :stabilization-tick-pause-ms 500
   :post-stabilization-pause-ms 15000
   :broadcast-pause-ms      5000
   :completion-timeout-ms   600000
   :channel-buffer-size     8192
   :protocol                (merge config/default-config 
                                   (calculate-protocol-params 1000 :mode :lean))
   #_(merge config/default-config
            {:murmur-k 8
             :basalt-max-view-size 40
             :gossip-ttl-epochs 200})
   #_(merge config/default-config
            {:murmur-k 12
             :basalt-max-view-size 50
             :echo-sample-size 20
             :echo-threshold 14
             :ready-sample-size 20
             :ready-threshold 7
             :delivery-sample-size 20
             :delivery-threshold 16
             :gossip-ttl-epochs 20})})

;; ---------------------------------------------------------------------------
;; Metrics (contention-free via ConcurrentHashMap/AtomicLong)
;; ---------------------------------------------------------------------------

(def broadcasts-initiated (atom 0))
(def broadcast-start-times (atom {}))
(def total-consensus-time (atom 0))

(def ^ConcurrentHashMap cmd-counters (ConcurrentHashMap.))
(def ^AtomicLong total-routed (AtomicLong. 0))

(defn- inc-cmd-counter! [cmd-type]
  (let [^AtomicLong counter (.computeIfAbsent cmd-counters (name cmd-type)
                                               (reify java.util.function.Function
                                                 (apply [_ _k] (AtomicLong. 0))))]
    (.incrementAndGet counter)))

;; ---------------------------------------------------------------------------
;; Node creation
;; ---------------------------------------------------------------------------

(defn- create-honest-node
  [i cfg]
  (let [keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        initial-state (sm/init-state [] pubkey-hex (:protocol cfg))
        snapshot-filename (str "/tmp/snapshot-" pubkey-hex ".bin")
        node (shell-core/start-node initial-state snapshot-filename {:persist? false})
        peer {:ip "127.0.0.1"
              :port (+ 8000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}]
    {:type :honest
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :node node
     :events-in (:events-in node)
     :network-in (:network-in node)
     :net-out (:net-out node)
     :app-out (:app-out node)}))

(defn- start-byzantine-spammer
  "Starts a simple loop that consumes net-out messages but drops them (black hole)."
  [net-out-ch stop-ch]
  (async/go-loop []
    (let [[_val port] (async/alts! [net-out-ch stop-ch])]
      (when (not= port stop-ch)
        (recur)))))

(defn- create-byzantine-node
  [i cfg]
  (let [buf (:channel-buffer-size cfg)
        keys (crypto/generate-keypair)
        pubkey-hex (basalt/bytes->hex (:public keys))
        peer {:ip "127.0.0.1"
              :port (+ 9000 i)
              :pubkey pubkey-hex
              :hash (basalt/bytes->hex (crypto/sha256 (:public keys)))}
        net-out-ch (async/chan buf)
        stop-ch (async/chan)]
    (start-byzantine-spammer net-out-ch stop-ch)
    {:type :byzantine
     :pubkey-hex pubkey-hex
     :keys keys
     :peer peer
     :node {:stop-ch stop-ch}
     :events-in nil
     :network-in nil
     :net-out net-out-ch
     :app-out nil}))

;; ---------------------------------------------------------------------------
;; Network plumbing (Optimized: decentralized point-to-point routing)
;; ---------------------------------------------------------------------------

(defn- route-message-to-target
  "Translates a network-out command to a network-in event for the target node.
   Uses a flat channel-registry map for O(1) direct routing."
  [registry target-hex cmd sender-hex]
  (when-let [target-ch (get registry target-hex)]
    (.incrementAndGet total-routed)
    (inc-cmd-counter! (:type cmd))
    (case (:type cmd)
      :send-push-view
      (async/put! target-ch {:type :receive-push-view :view (:view cmd)})
      :send-summary
      (async/put! target-ch {:type :receive-summary
                              :sender sender-hex
                              :summary (:summary cmd)})
      :send-subscribe
      (async/put! target-ch {:type :receive-subscribe
                              :sender sender-hex
                              :roles (:roles cmd)})
      :send-pull-request
      (async/put! target-ch {:type :receive-pull-request
                              :sender sender-hex
                              :missing-ids (:missing-ids cmd)})
      :send-gossip
      (async/put! target-ch {:type :receive-gossip
                              :message (:message cmd)
                              :rng (java.util.Random.)})
      :send-sieve-echo
      (async/put! target-ch {:type :receive-sieve-echo
                              :sender sender-hex
                              :message-id (:message-id cmd)
                              :rng (java.util.Random.)})
      :send-contagion-ready
      (async/put! target-ch {:type :receive-contagion-ready
                              :sender sender-hex
                              :message-id (:message-id cmd)
                              :rng (java.util.Random.)})
      nil)))

(defn- create-direct-routers
  "Spawns one go-loop per node to consume its net-out channel and route messages
   directly to target nodes via the channel registry. Distributes routing across
   the entire core.async thread pool."
  [nodes-map registry stop-ch]
  (doseq [[pubkey-hex node] nodes-map]
    (async/go-loop []
      (let [[val port] (async/alts! [(:net-out node) stop-ch])]
        (when (and (not= port stop-ch) (some? val))
          (let [targets (or (:targets val) (when (:target val) [(:target val)]))]
            (doseq [t targets]
              (let [target-hex (if (string? t) t (:pubkey t))]
                (route-message-to-target registry target-hex val pubkey-hex))))
          (recur))))))

;; ---------------------------------------------------------------------------
;; Network lifecycle
;; ---------------------------------------------------------------------------

(defn- start-network
  [cfg]
  (let [total-nodes (:total-nodes cfg)
        byzantine-nodes (:byzantine-nodes cfg)
        honest-nodes (- total-nodes byzantine-nodes)
        view-size (get-in cfg [:protocol :basalt-max-view-size])

        h-nodes (mapv #(create-honest-node % cfg) (range honest-nodes))
        b-nodes (mapv #(create-byzantine-node % cfg) (range byzantine-nodes))

        all-nodes (concat h-nodes b-nodes)
        nodes-map (into {} (map (juxt :pubkey-hex identity) all-nodes))
        stop-ch (async/chan)

        ;; Build channel registry: pubkey-hex -> network-in channel (O(1) lookup)
        registry (into {} (keep (fn [[k v]] (when (:network-in v) [k (:network-in v)])) nodes-map))

        ;; Decentralized routing: per-node go-loops instead of centralized mux
        _ (create-direct-routers nodes-map registry stop-ch)
        all-peers (mapv :peer all-nodes)]

    ;; Push an omniscient view to all honest nodes
    (doseq [node h-nodes]
      (async/put! (:events-in node) {:type :receive-push-view
                                     :view (take view-size (shuffle all-peers))}))

    {:nodes nodes-map
     :h-nodes h-nodes
     :honest-nodes honest-nodes
     :stop-ch stop-ch}))

(defn- stop-network
  [network]
  (when-let [stop-ch (:stop-ch network)]
    (async/put! stop-ch true)
    (async/close! stop-ch))
  (doseq [node (vals (:nodes network))]
    (if (= (:type node) :byzantine)
      (do
        (async/put! (:stop-ch (:node node)) true)
        (async/close! (:stop-ch (:node node))))
      (shell-core/stop-node (:node node)))))

;; ---------------------------------------------------------------------------
;; Main
;; ---------------------------------------------------------------------------

(defn -main []
  (let [cfg sim-config
        total-nodes (:total-nodes cfg)
        byzantine-nodes (:byzantine-nodes cfg)
        honest-nodes (- total-nodes byzantine-nodes)
        start-wall-time (System/currentTimeMillis)
        delivery-target (int (* 0.95 honest-nodes))]
    (println "Starting Contagion E2E Simulator...")
    (println (format "Network Topology: %d total nodes (%d honest, %d byzantine)"
                     total-nodes honest-nodes byzantine-nodes))
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
    (println (format "Delivery target: %d/%d" delivery-target honest-nodes))

    (let [network (start-network cfg)

          ;; Telemetry via ConcurrentHashMap — no async/merge needed
          ^ConcurrentHashMap delivery-chm (ConcurrentHashMap.)
          ^AtomicInteger delivery-counter (AtomicInteger. 0)
          done-ch (async/chan)]

      ;; Per-node telemetry consumers — each drains app-out into the shared CHM
      ;; Uses :message-id directly from the app event (no EDN parsing needed)
      (doseq [node (:h-nodes network)]
        (async/go-loop []
          (when-let [val (async/<! (:app-out node))]
            (when (and (map? val) (= (:event-name val) :on-deliver))
              (let [broadcast-id (:message-id val)
                    pubkey (:pubkey-hex node)
                    ^java.util.Set delivery-set
                    (.computeIfAbsent delivery-chm broadcast-id
                                     (reify java.util.function.Function
                                       (apply [_ _k]
                                         (java.util.concurrent.ConcurrentHashMap/newKeySet))))]
                (when (.add delivery-set pubkey)
                  (let [current-deliveries (.size delivery-set)]
                    (when (zero? (mod current-deliveries 10))
                      (println (format "Broadcast %s reached %d/%d nodes in %dms"
                                       broadcast-id current-deliveries honest-nodes
                                       (- (System/currentTimeMillis) start-wall-time))))
                    (when (and (= current-deliveries honest-nodes)
                               (zero? (.get delivery-counter)))
                      (.incrementAndGet delivery-counter)
                      (let [end-time (System/currentTimeMillis)
                            start-time (get @broadcast-start-times broadcast-id)
                            duration (- end-time start-time)]
                        (swap! total-consensus-time + duration)
                        (println (format "✅ Broadcast %s delivered to ALL %d honest nodes in %d ms"
                                         broadcast-id honest-nodes duration)))
                      (async/put! done-ch true))
                    (when (and (>= current-deliveries delivery-target)
                               (zero? (.get delivery-counter)))
                      (.incrementAndGet delivery-counter)
                      (let [end-time (System/currentTimeMillis)
                            start-time (get @broadcast-start-times broadcast-id)
                            duration (- end-time start-time)]
                        (swap! total-consensus-time + duration)
                        (println (format "✅ Broadcast %s delivered to %d/%d honest nodes in %d ms"
                                         broadcast-id current-deliveries honest-nodes duration)))
                      (async/put! done-ch true))))))
            (recur))))

      ;; Scenario Loop — stabilize then broadcast
      (let [nodes-map (:nodes network)]
        (async/go-loop [iteration 1]
          (when (= iteration 1)
            (println (format "Running %d stabilization ticks to build subscription graphs..."
                             (:stabilization-ticks cfg)))
            (dotimes [_i (:stabilization-ticks cfg)]
              (doseq [node (vals nodes-map)]
                (when (:events-in node)
                  (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)})))
              (async/<! (async/timeout (:stabilization-tick-pause-ms cfg))))
            (println (format "Running %d ms post stabilization pause..."
                             (:post-stabilization-pause-ms cfg)))
            (async/<! (async/timeout (:post-stabilization-pause-ms cfg))))

          (when (< @broadcasts-initiated (:total-broadcast-messages cfg))
            (let [initiator (rand-nth (:h-nodes network))
                  broadcast-id (str (java.util.UUID/randomUUID))
                  payload-str (pr-str {:id broadcast-id :data (str "test-payload-" iteration)})
                  payload-bytes (.getBytes ^String payload-str "UTF-8")
                  ;; Compute the message-id the same way the state machine will
                  message-id (basalt/bytes->hex (crypto/sha256 payload-bytes))]
              (swap! broadcasts-initiated inc)
              (swap! broadcast-start-times assoc message-id (System/currentTimeMillis))
              (println (format "Injecting broadcast %s via honest node %s..."
                               broadcast-id (subs (:pubkey-hex initiator) (- (count (:pubkey-hex initiator)) 8))))
              (async/put! (:events-in initiator) {:type :contagion-broadcast
                                                  :payload payload-bytes
                                                  :rng (java.util.Random.)
                                                  :private-key (:private (:keys initiator))
                                                  :public-key (:public (:keys initiator))}))
            (async/<! (async/timeout (:broadcast-pause-ms cfg)))
            (recur (inc iteration)))))

      ;; Wait for completion
      (let [[_ port] (async/alts!! [done-ch (async/timeout (:completion-timeout-ms cfg))])]
        (when (not= port done-ch)
          (println "\n⚠️  Delivery status at timeout:")
          (doseq [bid (enumeration-seq (.keys delivery-chm))]
            (let [^java.util.Set s (.get delivery-chm bid)]
              (println (format "  Broadcast %s: %d/%d delivered" bid (.size s) honest-nodes))))

          ;; ─── Diagnostic state dump ───────────────────────────────────
          (println "\n🔍 Querying state of undelivered nodes...")
          (let [delivered-pubkeys (into #{}
                                       (mapcat (fn [bid]
                                                 (let [^java.util.Set s (.get delivery-chm bid)]
                                                   (iterator-seq (.iterator s))))
                                               (enumeration-seq (.keys delivery-chm))))
                undelivered-nodes (filterv #(not (contains? delivered-pubkeys (:pubkey-hex %)))
                                          (:h-nodes network))
                protocol-cfg (:protocol cfg)
                E-hat (:echo-threshold protocol-cfg)
                D-hat (:delivery-threshold protocol-cfg)
                ;; Query state for all undelivered nodes (with short timeout)
                node-states (doall
                              (keep (fn [n]
                                      (when-let [state (shell-core/query-node-state (:node n) :timeout-ms 2000)]
                                        {:pubkey (let [pk (:pubkey-hex n)] (subs pk (- (count pk) 8)))
                                         :state state}))
                                    undelivered-nodes))
                ;; Find the broadcast message-id(s)
                broadcast-ids (into #{} (enumeration-seq (.keys delivery-chm)))

                classify-node
                (fn [{:keys [pubkey state]}]
                  (let [known-ids (:contagion-known-ids state)
                        echo-sample (:global-echo-sample state)
                        ready-sample (:global-ready-sample state)
                        delivery-sample (:global-delivery-sample state)
                        echo-subs (:echo-subscribers state)
                        ready-subs (:ready-subscribers state)
                        delivery-subs (:delivery-subscribers state)
                        ;; Check per broadcast message
                        bid (first broadcast-ids)
                        has-message? (and bid (contains? known-ids bid))
                        echo-votes (get-in state [:echo-vote-counts bid] 0)
                        ready-votes (get-in state [:ready-vote-counts bid] 0)
                        delivery-votes (get-in state [:delivery-vote-counts bid] 0)
                        sieve-delivered? (and bid (contains? (:sieve-delivered-set state) bid))
                        local-ready? (and bid (contains? (:local-ready-set state) bid))]
                    {:pubkey pubkey
                     :group (cond
                              (empty? echo-sample)                           :no-echo-sample
                              (empty? echo-subs)                             :no-echo-subscribers
                              (empty? ready-subs)                            :no-ready-subscribers
                              (empty? delivery-subs)                         :no-delivery-subscribers
                              (not has-message?)                             :no-message
                              (and has-message? (not sieve-delivered?)
                                   (< echo-votes E-hat))                    :awaiting-sieve-echo
                              (and sieve-delivered? (not local-ready?))       :sieve-delivered-not-ready
                              (and local-ready?
                                   (< delivery-votes D-hat))                 :ready-awaiting-delivery
                              :else                                          :unknown)
                     :echo-sample-size (count echo-sample)
                     :ready-sample-size (count ready-sample)
                     :delivery-sample-size (count delivery-sample)
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

                classified (mapv classify-node node-states)
                groups (group-by :group classified)]

            (println (format "\n📊 Diagnostic Summary: %d undelivered nodes (queried %d, %d timed out)"
                            (count undelivered-nodes) (count node-states)
                            (- (count undelivered-nodes) (count node-states))))
            (println "════════════════════════════════════════════════════════════")
            (doseq [[group nodes] (sort-by (comp - count second) groups)]
              (let [sample (first nodes)]
                (println (format "\n  %-30s  %d nodes" (name group) (count nodes)))
                (println (format "    Sample node:  %s" (:pubkey sample)))
                (println (format "    Basalt view:  %d peers, epoch %d" (:basalt-view-size sample) (:epoch sample)))
                (println (format "    Samples:      E=%d  R=%d  D=%d" (:echo-sample-size sample) (:ready-sample-size sample) (:delivery-sample-size sample)))
                (println (format "    Subscribers:  echo=%d  ready=%d  delivery=%d" (:echo-sub-count sample) (:ready-sub-count sample) (:delivery-sub-count sample)))
                (println (format "    Has message:  %s  Sieve-delivered: %s  Ready: %s" (:has-message? sample) (:sieve-delivered? sample) (:local-ready? sample)))
                (println (format "    Votes:        echo=%d/%d  ready=%d  delivery=%d/%d"
                                (:echo-votes sample) E-hat
                                (:ready-votes sample)
                                (:delivery-votes sample) D-hat))))
            (println "\n════════════════════════════════════════════════════════════"))

          (throw (ex-info "Contagion broadcast failed to reach all honest nodes within timeout"
                          {:timeout-ms (:completion-timeout-ms cfg)}))))

      (let [wall-time (- (System/currentTimeMillis) start-wall-time)
            cmd-stats (into {} (map (fn [k] [(keyword k) (.get ^AtomicLong (.get cmd-counters k))])
                                    (enumeration-seq (.keys cmd-counters))))]
        (println "\n========================================")
        (println "SIMULATION COMPLETE")
        (println "========================================")
        (println "Network commands processed          " (->> cmd-stats (sort-by second) (reverse)))
        (println "Total messages routed:              " (.get total-routed))
        (println "Broadcasts Initiated:               " @broadcasts-initiated)
        (println "Broadcasts Delivered:               " (.get delivery-counter))
        (println "Wall-clock time:                    " wall-time "ms")
        (when (pos? (.get delivery-counter))
          (println "Time to Delivery:                 " (int (/ @total-consensus-time (.get delivery-counter))) "ms"))
        (println "========================================"))

      (stop-network network)
      (System/exit 0))))
