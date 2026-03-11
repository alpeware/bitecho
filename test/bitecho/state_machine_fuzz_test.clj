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
    [1 (gen/fmap (fn [payload] [:broadcast payload]) gen-payload)]]))

(def gen-events
  "Generates a sequence of cluster events to drive the simulation."
  (gen/vector gen-event 5 50))

(defn- init-cluster-state
  "Initializes a cluster of `n` nodes, establishing a fully connected initial topology."
  [n]
  (let [node-ids (range n)
        ;; Pre-generate pubkeys for the mock peers so they have stable identities
        node-info (into {}
                        (for [i node-ids]
                          [i {:ip (str "127.0.0." i)
                              :port (+ 8000 i)
                              :pubkey (byte-array 32)
                              :age 0
                              :hash (str "hash-" i)}]))]
    (into {}
          (for [i node-ids]
            (let [initial-peers (map val (dissoc node-info i))]
              [i (sm/init-state initial-peers)])))))

(defn- extract-node-id
  "Helper to extract a node ID from a peer's hash."
  [peer]
  (if-let [match (re-find #"hash-(\d+)" (:hash peer))]
    (Integer/parseInt (second match))
    -1))

(defn- resolve-targets
  "Given commands that contain targets (as peers or a single target), map them to node IDs."
  [command]
  (cond
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
        ;; Note: The true reliable broadcast uses Sieve (signed payloads) and Contagion.
        ;; Wait! Murmur initiates the broadcast but Sieve requires signatures.
        ;; Let's look at `state_machine.clj` `handle-broadcast`:
        ;; `(murmur/initiate-broadcast payload rng (:basalt-view state) murmur-k)`
        ;; Wait, the state machine itself bypasses Sieve for internally generated broadcasts?
        ;; Wait, `sieve.core` isn't used in `handle-event` inside `state_machine.clj`?!
        ;; Ah! Or maybe the Sieve wrap happens somewhere else?
        ;; Let's give it more ticks just to be sure. Also `max-steps` in process-queue is 500, which is enough.
        all-events (concat events (repeat 500 [:tick]))]
    (reduce (fn [cluster [event-type payload]]
              ;; Randomly select a node to initiate the event
              (let [target-id (.nextInt rng n)
                    event (if (= event-type :tick)
                            {:type :tick :rng rng}
                            {:type :broadcast :payload payload :rng rng})]
                (process-queue cluster [[target-id event]] drop-rate rng 5000 0)))
            initial-cluster
            all-events)))

(defspec ^{:doc "Fuzzer property verifying network connectedness under varying drop rates."}
  fuzzer-property 100
  (prop/for-all [n gen-cluster-size
                 drop-rate gen-drop-rate
                 events gen-events
                 seed gen/large-integer]
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
                           ;; Hash the payload exactly as initiate-broadcast does
                           ;; The crypto namespace should provide the sha256 bytes->hex logic.
                           ;; Wait, since we are fuzzer, we can just hash it.
                           ;; The payload is hashed by crypto/sha256 and converted to hex.
                                       expected-ids (map (fn [p]
                                                           (basalt/bytes->hex (crypto/sha256 p)))
                                                         broadcast-payloads)]
                       ;; Every node should eventually know every broadcasted message ID
                       ;; Note: Reliable broadcast requires time/ticks to disseminate.
                       ;; We might drop too many messages. Since we drop up to 0.5, it may not guarantee 100%
                       ;; delivery immediately if we don't have enough ticks.
                                   (every? #(contains? known-ids %) expected-ids)))
                               (vals final-cluster))))))
