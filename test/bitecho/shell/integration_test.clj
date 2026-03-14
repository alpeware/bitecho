(ns bitecho.shell.integration-test
  "End-to-end integration test proving the concurrent shells can communicate
   via a mock network router."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.delegation :as delegation]
            [bitecho.shell.agent :as agent-shell]
            [bitecho.shell.bootstrap :as boot-shell]
            [bitecho.shell.core :as shell-core]
            [clojure.core.async :as async]
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
                      (when spy-ch (async/put! spy-ch {:to target-pubkey-hex :cmd cmd}))
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

          boot-chans (create-node-channels boot-pubkey-hex :bootstrap boot-shell/init-node [])
          a1-chans (create-node-channels a1-pubkey-hex :agent agent-shell/init-node [boot-peer])
          a2-chans (create-node-channels a2-pubkey-hex :agent agent-shell/init-node [boot-peer])
          a3-chans (create-node-channels a3-pubkey-hex :agent agent-shell/init-node [boot-peer])

          nodes {boot-pubkey-hex boot-chans
                 a1-pubkey-hex a1-chans
                 a2-pubkey-hex a2-chans
                 a3-pubkey-hex a3-chans}

          ticker-stop (async/chan)
          spy-ch (async/chan 1024)
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
          (shell-core/stop-node (:node a3-chans)))))))
