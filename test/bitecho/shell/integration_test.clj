(ns bitecho.shell.integration-test
  "End-to-end integration test proving the concurrent shells can communicate
   via a mock network router."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.delegation :as delegation]
            [bitecho.economy.difficulty :as difficulty]
            [bitecho.economy.ledger :as ledger]
            [bitecho.lottery.core :as lottery]
            [bitecho.routing.ingress :as ingress]
            [bitecho.shell.agent :as agent-shell]
            [bitecho.shell.bootstrap :as boot-shell]
            [bitecho.shell.core :as shell-core]
            [clojure.core.async :as async]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]))

(defn start-mock-network
  "Takes a map of nodes (keyed by pubkey hex) and routes messages between them.
   Returns an atom that records all delivered messages."
  [nodes spy-ch]
  (let [delivered-messages (atom [])
        out-channels (mapv :net-out (vals nodes))
        stop-ch (async/chan)]
    (async/go-loop []
      (let [[val port] (async/alts! (conj out-channels stop-ch))]
        (if (= port stop-ch)
          nil ;; stop
          (do
            (when (map? val)
              (let [cmd val
                    targets (or (:targets cmd) (when (:target cmd) [(:target cmd)]))
                    sender-pubkey-hex (some (fn [[k v]] (when (= (:net-out v) port) k)) nodes)]
                (doseq [t targets]
                  (let [target-pubkey-hex (if (string? t) t (:pubkey t))]
                    (when-let [target-node (get nodes target-pubkey-hex)]
                      (swap! delivered-messages conj {:to target-pubkey-hex :cmd cmd})
                      (when spy-ch
                        (async/put! spy-ch {:to target-pubkey-hex :cmd cmd} (fn [_] nil)))
                      (case (:type cmd)
                        :send-push-view
                        (async/put! (:network-in target-node) {:type :receive-push-view :view (:view cmd)})
                        :send-summary
                        (async/put! (:network-in target-node) {:type :receive-summary
                                                               :sender sender-pubkey-hex
                                                               :summary (:summary cmd)})
                        :send-pull-request
                        (async/put! (:network-in target-node) {:type :receive-pull-request
                                                               :sender sender-pubkey-hex
                                                               :missing-ids (:missing-ids cmd)})
                        :send-gossip
                        (async/put! (:network-in target-node) {:type :receive-gossip
                                                               :message (:message cmd)
                                                               :rng (java.util.Random.)})
                        :send-directed-message
                        ;; IMPORTANT: the event type expected by handle-event is :route-directed-message
                        ;; We MUST inject it into :events-in because the mock router bypasses the network filter
                        ;; which drops route-directed-message!
                        (async/put! (:events-in target-node) {:type :route-directed-message
                                                              :envelope (:envelope cmd)
                                                              :payout-amount (:payout-amount cmd 100)
                                                              :network-size (:network-size cmd 10)
                                                              :rng (java.util.Random.)})
                        nil))))))
            (recur)))))
    {:stop-ch stop-ch :delivered-messages delivered-messages}))

(defn- create-node-channels
  [pubkey-hex node-type init-fn args]
  (let [node (apply init-fn args)]
    {:pubkey-hex pubkey-hex
     :type node-type
     :events-in (:events-in node)
     :network-in (:network-in node)
     :net-out (:net-out node)
     :node node}))

(deftest ^{:doc "Proves async shell nodes successfully route Sieve messages"}
  shell-integration-routing-test
  (testing "Gossip propagation across mock router"
    (let [;; 1. Generate keys
          boot-keys (crypto/generate-keypair)
          a1-keys (crypto/generate-keypair)
          a2-keys (crypto/generate-keypair)
          a3-keys (crypto/generate-keypair)

          ;; 2. Build Hex identities
          boot-pubkey-hex (basalt/bytes->hex (:public boot-keys))
          a1-pubkey-hex (basalt/bytes->hex (:public a1-keys))
          a2-pubkey-hex (basalt/bytes->hex (:public a2-keys))
          a3-pubkey-hex (basalt/bytes->hex (:public a3-keys))

          ;; 3. Generate DACs (for completeness of agent identity)
          _a1-dac (delegation/generate-dac boot-pubkey-hex (:private boot-keys) a1-pubkey-hex)
          _a2-dac (delegation/generate-dac boot-pubkey-hex (:private boot-keys) a2-pubkey-hex)
          _a3-dac (delegation/generate-dac boot-pubkey-hex (:private boot-keys) a3-pubkey-hex)

          ;; 4. Initialize nodes
          ;; Bootstrap peer record as seen by agents
          boot-peer {:ip "127.0.0.1" :port 8000 :pubkey boot-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public boot-keys)))}

          boot-chans (create-node-channels boot-pubkey-hex :bootstrap boot-shell/init-node [boot-pubkey-hex])
          a1-chans (create-node-channels a1-pubkey-hex :agent agent-shell/init-node [boot-peer a1-pubkey-hex])
          a2-chans (create-node-channels a2-pubkey-hex :agent agent-shell/init-node [boot-peer a2-pubkey-hex])
          a3-chans (create-node-channels a3-pubkey-hex :agent agent-shell/init-node [boot-peer a3-pubkey-hex])

          nodes {boot-pubkey-hex boot-chans
                 a1-pubkey-hex a1-chans
                 a2-pubkey-hex a2-chans
                 a3-pubkey-hex a3-chans}

          ticker-stop (async/chan)
          spy-ch (async/chan (async/sliding-buffer 1024))
          router (start-mock-network nodes spy-ch)
          stop-router (:stop-ch router)
          _delivered-messages (:delivered-messages router)]

      (try
        ;; 5. Background ticker for all nodes
        (async/go-loop []
          (let [[_ port] (async/alts! [(async/timeout 20) ticker-stop])]
            (when (not= port ticker-stop)
              (doseq [node (vals nodes)]
                (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)}))
              (recur))))

        ;; Wait for topology to form. Give it plenty of time and ticks to mix the peer views.
        (async/<!! (async/timeout 1000))

        ;; 6. The Action: Inject Broadcast to Agent 1
        ;; Manually connect the views to ensure they are fully populated before broadcast
        (let [boot-peer {:ip "127.0.0.1" :port 8000 :pubkey boot-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public boot-keys)))}
              a1-peer {:ip "127.0.0.1" :port 8001 :pubkey a1-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public a1-keys)))}
              a2-peer {:ip "127.0.0.1" :port 8002 :pubkey a2-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public a2-keys)))}
              a3-peer {:ip "127.0.0.1" :port 8003 :pubkey a3-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public a3-keys)))}]
          (async/put! (:network-in (:node a1-chans)) {:type :receive-push-view :view #{boot-peer a2-peer a3-peer}})
          (async/put! (:network-in (:node a2-chans)) {:type :receive-push-view :view #{boot-peer a1-peer a3-peer}})
          (async/put! (:network-in (:node a3-chans)) {:type :receive-push-view :view #{boot-peer a1-peer a2-peer}}))

        (async/<!! (async/timeout 50))

        (let [payload-str "Hello Mesh!"
              payload-bytes (.getBytes payload-str "UTF-8")]
          (async/put! (:events-in (get nodes a1-pubkey-hex))
                      {:type :broadcast
                       :payload payload-bytes
                       :private-key (:private a1-keys)
                       :public-key (:public a1-keys)
                       :rng (java.util.Random.)})
          (async/<!! (async/timeout 50))
          (doseq [_ (range 50)]
            (doseq [node (vals nodes)]
              (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)}))
            (async/<!! (async/timeout 20))))

        ;; Wait some time for the broadcast to propagate
        (async/<!! (async/timeout 500))
        (doseq [node (vals nodes)]
          (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)}))

        ;; 7. The Assertion: Synchronously block for Agent 2 and Agent 3 to receive the message
        (loop [a2-received false
               a3-received false
               attempts 0]
          (if (and a2-received a3-received)
            (is true "Both Agent 2 and Agent 3 received Hello Mesh!")
            (let [[msg port] (async/alts!! [spy-ch (async/timeout 50)])]
              (if (= port spy-ch)
                (let [target (:to msg)
                      cmd (:cmd msg)
                      is-gossip (= (:type cmd) :send-gossip)
                      has-payload (and is-gossip (contains? cmd :message) (= (String. ^bytes (:payload (:message cmd)) "UTF-8") "Hello Mesh!"))]
                  (recur (or a2-received (and has-payload (= target a2-pubkey-hex)))
                         (or a3-received (and has-payload (= target a3-pubkey-hex)))
                         attempts))
                (if (< attempts 10)
                  (do
                    (doseq [node (vals nodes)]
                      (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)}))
                    (recur a2-received a3-received (inc attempts)))
                  (is false "Timeout waiting for Hello Mesh! to propagate"))))))

        (finally
          (async/close! ticker-stop)
          (async/put! stop-router true)
          (async/close! stop-router)
          (shell-core/stop-node (:node boot-chans))
          (shell-core/stop-node (:node a1-chans))
          (shell-core/stop-node (:node a2-chans))
          (shell-core/stop-node (:node a3-chans))

          (try (io/delete-file (str "snapshot-" boot-pubkey-hex ".edn") true) (catch Exception _))
          (try (io/delete-file (str "snapshot-" a1-pubkey-hex ".edn") true) (catch Exception _))
          (try (io/delete-file (str "snapshot-" a2-pubkey-hex ".edn") true) (catch Exception _))
          (try (io/delete-file (str "snapshot-" a3-pubkey-hex ".edn") true) (catch Exception _)))))))

(deftest ^{:doc "Integration test across 3 nodes to ensure directed routing, lottery verification, and application events work."}
  shell-integration-economy-test
  (testing "Directed Message routing and Lottery payout across mock router"
    (let [;; 1. Generate keys
          boot-keys (crypto/generate-keypair)
          a1-keys (crypto/generate-keypair)
          a2-keys (crypto/generate-keypair)
          a3-keys (crypto/generate-keypair)

          ;; 2. Build Hex identities
          boot-pubkey-hex (basalt/bytes->hex (:public boot-keys))
          a1-pubkey-hex (basalt/bytes->hex (:public a1-keys))
          a2-pubkey-hex (basalt/bytes->hex (:public a2-keys))
          a3-pubkey-hex (basalt/bytes->hex (:public a3-keys))

          ;; 3. Generate DACs
          _a1-dac (delegation/generate-dac boot-pubkey-hex (:private boot-keys) a1-pubkey-hex)
          _a2-dac (delegation/generate-dac boot-pubkey-hex (:private boot-keys) a2-pubkey-hex)
          _a3-dac (delegation/generate-dac boot-pubkey-hex (:private boot-keys) a3-pubkey-hex)

          ;; 4. Initialize nodes with persistence files keyed by pubkey
          boot-peer {:ip "127.0.0.1" :port 8000 :pubkey boot-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public boot-keys)))}

          boot-chans (create-node-channels boot-pubkey-hex :bootstrap boot-shell/init-node [boot-pubkey-hex])
          a1-chans (create-node-channels a1-pubkey-hex :agent agent-shell/init-node [boot-peer a1-pubkey-hex])
          a2-chans (create-node-channels a2-pubkey-hex :agent agent-shell/init-node [boot-peer a2-pubkey-hex])
          a3-chans (create-node-channels a3-pubkey-hex :agent agent-shell/init-node [boot-peer a3-pubkey-hex])

          nodes {boot-pubkey-hex boot-chans
                 a1-pubkey-hex a1-chans
                 a2-pubkey-hex a2-chans
                 a3-pubkey-hex a3-chans}

          ticker-stop (async/chan)
          spy-ch (async/chan (async/sliding-buffer 1024))
          router (start-mock-network nodes spy-ch)
          stop-router (:stop-ch router)]

      (with-redefs [difficulty/calculate-difficulty (constantly (apply str (repeat 64 "f")))
                      ;; Bypass ingress for the test to ensure A1 can send to A2 without hitting the 5% trickle chance
                    ingress/admit-message? (constantly true)]
        (try
          ;; 5. Background ticker
          (async/go-loop []
            (let [[_ port] (async/alts! [(async/timeout 20) ticker-stop])]
              (when (not= port ticker-stop)
                (doseq [node (vals nodes)]
                  (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)}))
                (recur))))

          (async/<!! (async/timeout 1000))
          (async/put! ticker-stop true)
          (async/<!! (async/timeout 100))

          ;; 6. The Action: Inject Directed Message to Agent 1 targeted at Agent 3
          (let [a1-peer {:ip "127.0.0.1" :port 8001 :pubkey a1-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public a1-keys)))}
                a2-peer {:ip "127.0.0.1" :port 8002 :pubkey a2-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public a2-keys)))}
                a3-peer {:ip "127.0.0.1" :port 8003 :pubkey a3-pubkey-hex :age 0 :hash (basalt/bytes->hex (crypto/sha256 (:public a3-keys)))}]
            ;; Note: select-next-hop falls back to unweighted random if balances are missing/zero.
            ;; So A1 routes to A2. A2 routes to A3.
            (async/put! (:network-in (:node a1-chans)) {:type :receive-push-view :view #{a2-peer}})
            (async/put! (:network-in (:node a2-chans)) {:type :receive-push-view :view #{a3-peer}})
            (async/put! (:network-in (:node a3-chans)) {:type :receive-push-view :view #{a1-peer a2-peer}}))

          (async/<!! (async/timeout 50))

          (let [reply-ch (async/chan 1)
                _ (async/put! (:events-in (:node a1-chans)) {:type :query-state :reply-chan reply-ch})
                [a1-state _] (async/alts!! [reply-ch (async/timeout 1000)])
                current-epoch (or (:epoch a1-state) 0)
                payload-str "Secret message for C!"
                payload-bytes (.getBytes payload-str "UTF-8")
                ticket (lottery/generate-ticket payload-bytes 123 (:private a1-keys) (:public a1-keys) current-epoch)
                envelope {:destination a3-pubkey-hex
                          :encrypted-payload payload-bytes
                          :lottery-ticket ticket}]
            (async/put! (:events-in (get nodes a1-pubkey-hex))
                        {:type :route-directed-message
                         :envelope envelope
                         :payout-amount 100
                         :network-size 10
                         :rng (java.util.Random.)})
            (async/<!! (async/timeout 50)))

          (async/<!! (async/timeout 500))

          ;; 7. The Assertion: Synchronously block for Agent 3 to receive the direct message
          (loop [attempts 0]
            (let [[msg port] (async/alts!! [(:app-out (:node a3-chans)) (async/timeout 50)])]
              (if (= port (:app-out (:node a3-chans)))
                (do
                  (is (= :on-direct-message (:event-name msg)))
                  (is (= a3-pubkey-hex (:destination (:envelope msg))))
                  (is (= "Secret message for C!" (String. ^bytes (:encrypted-payload (:envelope msg)) "UTF-8")))
                  (is true "Agent 3 received directed message!"))
                (if (< attempts 20)
                  (do
                    (doseq [node (vals nodes)]
                      (async/put! (:events-in node) {:type :tick :rng (java.util.Random.)}))
                    (recur (inc attempts)))
                  (is false "Timeout waiting for directed message to reach Agent 3")))))

          ;; Wait a little to ensure persistence loop drained
          (async/<!! (async/timeout 500))

          ;; 8. Read the pure state of Node B (Agent 2) deterministically using the query-state RPC!
          (let [reply-ch (async/chan 1)
                _ (async/put! (:events-in (:node a2-chans)) {:type :query-state :reply-chan reply-ch})
                [a2-state _] (async/alts!! [reply-ch (async/timeout 1000)])]
            (is (map? a2-state) "Agent 2 state queried successfully")
            (when a2-state
              (let [a2-ledger (:ledger a2-state)
                    a2-puzzle-hash (ledger/standard-puzzle-hash a2-pubkey-hex)
                    a2-balance (->> (vals (:utxos a2-ledger))
                                    (filter #(= (:puzzle-hash %) a2-puzzle-hash))
                                    (map :amount)
                                    (reduce + 0))]
                (is (= 100 a2-balance) "Agent 2 successfully claimed the lottery ticket fee"))))

          (finally
            (try (async/close! ticker-stop) (catch Exception _))
            (async/put! stop-router true)
            (async/close! stop-router)
            (shell-core/stop-node (:node boot-chans))
            (shell-core/stop-node (:node a1-chans))
            (shell-core/stop-node (:node a2-chans))
            (shell-core/stop-node (:node a3-chans))
            (async/<!! (async/timeout 100))
            ;; Cleanup snapshot files
            (try (io/delete-file (str "snapshot-" boot-pubkey-hex ".edn") true) (catch Exception _))
            (try (io/delete-file (str "snapshot-" a1-pubkey-hex ".edn") true) (catch Exception _))
            (try (io/delete-file (str "snapshot-" a2-pubkey-hex ".edn") true) (catch Exception _))
            (try (io/delete-file (str "snapshot-" a3-pubkey-hex ".edn") true) (catch Exception _))))))))
