(ns bitecho.state-machine-fuzz-test
  "Generative state-machine fuzzer."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.state-machine :as sm]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def gen-cluster-size
  "Generates a small cluster size."
  (gen/choose 3 10))

(def gen-drop-rate
  "Generates a message drop rate between 0.0 and 0.3."
  (gen/double* {:min 0.0 :max 0.3 :NaN? false :infinite? false}))

(def gen-payload
  "Generates a random byte array payload."
  (gen/fmap byte-array (gen/vector (gen/choose 0 255) 1 64)))

(def gen-event
  "Generates a valid user-initiated cluster event."
  (gen/frequency
   [[5 (gen/return [:tick])]
    [1 (gen/fmap (fn [payload] [:broadcast payload]) gen-payload)]
    ;; Introduce minimal churn events for fuzzing coverage.
    ;; Since full TURN negotiation requires multi-step state transitions and signatures,
    ;; we simply inject random allocate requests to ensure the state machine doesn't crash.
    [1 (gen/return [:turn-allocate-request "client-pub-stub"])]]))

(def gen-events
  "Generates a sequence of cluster events to drive the simulation."
  (gen/vector gen-event 5 50))

(defn- init-cluster-state
  "Initializes a cluster of `n` nodes, establishing a fully connected initial topology."
  [n]
  (let [node-ids (range n)
        ;; Pre-generate pubkeys for the mock peers so they have stable identities
        node-keys (into {}
                        (for [i node-ids]
                          [i (bitecho.crypto/generate-keypair)]))
        node-info (into {}
                        (for [i node-ids]
                          [i {:ip (str "127.0.0." i)
                              :port (+ 8000 i)
                              :pubkey (:public (get node-keys i))
                              :age 0
                              :hash (str "hash-" i)}]))]
    (into {}
          (for [i node-ids]
            (let [initial-peers (map val (dissoc node-info i))
                  state (sm/init-state initial-peers (basalt/bytes->hex (:public (get node-keys i))))]
              [i (assoc state :keys (get node-keys i))])))))

(defn- extract-node-id
  "Helper to extract a node ID from a peer's hash."
  [peer]
  (if (map? peer)
    (if-let [match (re-find #"hash-(\d+)" (str (:hash peer)))]
      (Integer/parseInt (second match))
      -1)
    -1))

(defn- resolve-targets
  "Given commands that contain targets (as peers or a single target), map them to node IDs."
  [command]
  (cond
    (= :network-out (:type command)) [] ;; Ignore network-out for now since it's targeted externally (e.g. client pubkey string instead of peer map)
    (:targets command) (map extract-node-id (:targets command))
    (:target command) [(extract-node-id (:target command))]
    :else []))

(defn- dispatch-commands
  "Takes emitted commands from `sender-id`, maps them to network events,
   and randomly drops messages based on `drop-rate`."
  [sender-id commands drop-rate rng]
  (let [events (mapcat (fn [cmd]
                         (let [target-ids (resolve-targets cmd)]
                           (for [tid target-ids]
                             [tid cmd])))
                       commands)]
    (for [[target-id cmd] events
          :when (> (.nextDouble rng) drop-rate)]
      (case (:type cmd)
        :send-push-view
        [target-id {:type :receive-push-view :view (:view cmd)}]

        :send-summary
        [target-id {:type :receive-summary :sender {:hash (str "hash-" sender-id)} :summary (:summary cmd)}]

        :send-pull-request
        [target-id {:type :receive-pull-request
                    :sender {:hash (str "hash-" sender-id)}
                    :missing-ids (:missing-ids cmd)}]

        :send-gossip
        [target-id {:type :receive-gossip :message (:message cmd) :rng rng}]

        :app-event nil

        :turn-allocate-granted nil
        :relay-data nil

        nil))))

(defn- clean-dispatched
  "Removes nil results from dispatch"
  [dispatched]
  (filterv some? dispatched))

(defn- process-queue
  "Recursively processes a queue of `[target-id event]` pairs against the cluster state."
  [cluster-state queue drop-rate rng max-steps step]
  (if (or (empty? queue) (> step max-steps))
    cluster-state
    (let [[target-id event] (first queue)
          node-state (get cluster-state target-id)]
      (if (nil? node-state)
        ;; Node might not exist if extract-node-id failed, just skip
        (recur cluster-state (rest queue) drop-rate rng max-steps (inc step))
        (let [{:keys [state commands]} (sm/handle-event node-state event)
              new-cluster (assoc cluster-state target-id state)
              new-events (clean-dispatched (dispatch-commands target-id commands drop-rate rng))
              ;; Add newly generated network events to the back of the queue (BFS simulation)
              new-queue (into (vec (rest queue)) new-events)]
          ;; (println "Queue size:" (count new-queue) "Step:" step)
          (recur new-cluster new-queue drop-rate rng max-steps (inc step)))))))

(defn- simulate-network
  "Runs the simulation over a series of top-level user events."
  [n drop-rate events seed]
  (let [rng (java.util.Random. seed)
        initial-cluster (init-cluster-state n)
        ;; Add a stabilization phase: 100 extra ticks to allow gossip/anti-entropy to converge
        all-events (concat events (repeat 500 [:tick]))]
    (reduce (fn [cluster [event-type payload]]
              ;; Randomly select a node to initiate the event
              (let [target-id (.nextInt rng n)
                    event (case event-type
                            :tick {:type :tick :rng rng}
                            :broadcast {:type :contagion-broadcast
                                        :payload payload
                                        :private-key (:private (:keys (get cluster target-id)))
                                        :public-key (:public (:keys (get cluster target-id)))
                                        :rng rng}
                            :turn-allocate-request {:type :turn-allocate-request :client-pubkey payload}
                            {:type :tick :rng rng})]
                (process-queue cluster [[target-id event]] drop-rate rng 5000 0)))
            initial-cluster
            all-events)))

(defspec ^{:doc "Fuzzer property verifying network connectedness under varying drop rates."}
  fuzzer-property 100
  (prop/for-all [n gen-cluster-size
                 drop-rate gen-drop-rate
                 events gen-events
                 seed gen/large-integer]
                (with-redefs [sm/gossip-ttl-epochs 1000]
                  (let [final-cluster (simulate-network n drop-rate events seed)
            ;; Extract all the payloads that were broadcast during the simulation
                        broadcast-payloads (->> events
                                                (filter #(= :broadcast (first %)))
                                                (map second)
                                                set)]
                    (and (map? final-cluster)
                         (= n (count final-cluster))
             ;; Verify every node has a non-empty connected basalt view
                         (every? (comp seq :basalt-view val) final-cluster)
             ;; Verify every broadcast payload is in the murmur cache queue of every node
                         (every? (fn [node-state]
                                   (let [known-ids (:contagion-known-ids node-state)
                                         expected-ids (map (fn [p]
                                                             (basalt/bytes->hex (crypto/sha256 p)))
                                                           broadcast-payloads)]
                         ;; Every node should eventually know every broadcasted message ID
                                     (every? #(contains? known-ids %) expected-ids)))
                                 (vals final-cluster)))))))

;; --- Payment Channel Settlement Fuzzer ---

(def gen-channel-events
  "Generates a valid sequence of payment channel off-chain updates."
  (gen/vector (gen/tuple (gen/choose 1 10) (gen/choose 1 50)) 1 20))

(defn- apply-channel-updates
  "Applies a sequence of channel updates, maintaining valid mutual signatures."
  [initial-state updates priv-a priv-b]
  (reduce (fn [state [nonce-inc cost]]
            (let [chan (get-in state [:channels "chan-fuzz"])
                  new-nonce (+ (:nonce chan) nonce-inc)
                  ;; ensure we don't overspend to keep valid
                  actual-cost (min cost (:balance-a chan))
                  new-balance-a (- (:balance-a chan) actual-cost)
                  new-balance-b (+ (:balance-b chan) actual-cost)

                  update-map {:nonce new-nonce
                              :balance-a new-balance-a
                              :balance-b new-balance-b}
                  enriched-update-map (assoc update-map
                                             :channel-id "chan-fuzz"
                                             :pubkey-a (:pubkey-a chan)
                                             :pubkey-b (:pubkey-b chan))
                  canonical-map (into (sorted-map) enriched-update-map)
                  update-hash (crypto/sha256 (.getBytes (pr-str canonical-map) "UTF-8"))

                  sig-a (basalt/bytes->hex (crypto/sign priv-a update-hash))
                  sig-b (basalt/bytes->hex (crypto/sign priv-b update-hash))

                  evt {:type :update-channel
                       :channel-id "chan-fuzz"
                       :update update-map
                       :sig-a sig-a
                       :sig-b sig-b}]
              (:state (sm/handle-event state evt))))
          initial-state
          updates))

(defn- setup-and-settle-channel
  "Helper to set up ledger funds, construct settlement tx, and settle the channel."
  [state-after-updates final-chan pub-a init-amt-a]
  (let [puzzle-a (str "(= \"" pub-a "\" solution)")
        puzzle-a-hash (basalt/bytes->hex (crypto/sha256 (.getBytes puzzle-a "UTF-8")))

        mock-utxo {:amount init-amt-a :puzzle-hash puzzle-a-hash}
        ledger-with-funds (assoc-in (:ledger state-after-updates) [:utxos "utxo-1"] mock-utxo)
        state-with-funds (assoc state-after-updates :ledger ledger-with-funds)

        tx {:inputs ["utxo-1"]
            :outputs [{:amount (:balance-a final-chan)}
                      {:amount (:balance-b final-chan)}]
            :puzzles [puzzle-a]
            :solutions [pub-a]}

        settle-evt {:type :settle-channel
                    :channel-id "chan-fuzz"
                    :tx tx}]
    (:state (sm/handle-event state-with-funds settle-evt))))

(defspec ^{:doc "Fuzzer property verifying payment channel updates and final settlement."}
  channel-settlement-property 100
  (prop/for-all [updates gen-channel-events
                 seed gen/large-integer]
                (let [_rng (java.util.Random. seed)
          ;; Keys setup
                      client-keys (crypto/generate-keypair)
                      server-keys (crypto/generate-keypair)
                      pub-a (basalt/bytes->hex (:public client-keys))
                      pub-b (basalt/bytes->hex (:public server-keys))
                      priv-a (:private client-keys)
                      priv-b (:private server-keys)

          ;; Initial amounts
                      init-amt-a 1000
                      init-amt-b 0

          ;; Open Channel Event
                      open-evt {:type :open-channel
                                :channel-id "chan-fuzz"
                                :pubkey-a pub-a
                                :pubkey-b pub-b
                                :amount-a init-amt-a
                                :amount-b init-amt-b}

                      initial-node-state (sm/init-state [] (basalt/bytes->hex (:public server-keys)))

          ;; 1. Open
                      state-after-open (:state (sm/handle-event initial-node-state open-evt))

          ;; 2. Apply updates iteratively
                      state-after-updates (apply-channel-updates state-after-open updates priv-a priv-b)
                      final-chan (get-in state-after-updates [:channels "chan-fuzz"])

          ;; 3. Settle
                      state-after-settle (setup-and-settle-channel state-after-updates final-chan pub-a init-amt-a)]

                  (and
        ;; Invariants
                   (= (+ init-amt-a init-amt-b) (+ (:balance-a final-chan) (:balance-b final-chan)))
                   (>= (:nonce final-chan) (count updates))
        ;; Verify channel is closed after settlement
                   (nil? (get-in state-after-settle [:channels "chan-fuzz"]))
        ;; Verify the new UTXOs sum up to the original amount
                   (= (+ init-amt-a init-amt-b)
                      (reduce + (map :amount (vals (:utxos (:ledger state-after-settle))))))))))
