(ns bitecho.shell.agent-sim
  "Light Agent Swarm Simulator: pure envelope builders and WebRTC DataChannel swarm runner."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.mesh :as mesh]
            [bitecho.sieve.core :as sieve]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [datachannel.api :as api]
            [taoensso.nippy :as nippy])
  (:import [java.nio.charset StandardCharsets]
           [java.util UUID]))

;; ---------------------------------------------------------------------------
;; Pure Protocol-Event Builders & CLI Parser
;; ---------------------------------------------------------------------------

(defn build-gossip-envelope
  "Builds a signed Sieve gossip message with burn-amount and wraps it in an Ed25519 agent envelope."
  [sender-pub-hex sender-priv-bytes payload-bytes burn-amount]
  (let [sender-pub-bytes (if (bytes? sender-pub-hex)
                           sender-pub-hex
                           (basalt/hex->bytes sender-pub-hex))
        pub-hex (if (string? sender-pub-hex)
                  sender-pub-hex
                  (basalt/bytes->hex sender-pub-hex))
        sieve-msg (sieve/wrap-message payload-bytes sender-priv-bytes sender-pub-bytes burn-amount)
        message-id (basalt/bytes->hex (crypto/sha256 payload-bytes))
        agent-event {:type :receive-gossip :message (assoc sieve-msg :message-id message-id)}]
    (mesh/wrap-agent-event agent-event pub-hex sender-priv-bytes)))

(defn build-transfer-gossip-envelope
  "Creates a signed account Transfer, serializes it as an EDN payload, and wraps it in a gossip envelope.
   Returns {:envelope envelope :transfer signed-transfer :transfer-hash transfer-hash}."
  [sender-pub-hex sender-priv-bytes transfer-opts burn-amount]
  (let [unsigned (assoc transfer-opts :sender sender-pub-hex)
        signed-transfer (account/create-transfer sender-priv-bytes unsigned)
        transfer-map (into {} signed-transfer)
        payload-bytes (.getBytes ^String (pr-str {:transfer transfer-map}) StandardCharsets/UTF_8)
        envelope (build-gossip-envelope sender-pub-hex sender-priv-bytes payload-bytes burn-amount)
        thash (account/transfer-hash signed-transfer)]
    {:envelope envelope
     :transfer signed-transfer
     :transfer-hash thash}))

(defn build-home-set-envelope
  "Builds a signed agent envelope registering Rendezvous home-set candidates for callee."
  [agent-pub-hex agent-priv-bytes candidates price epoch]
  (let [event {:type :register-home-set
               :callee agent-pub-hex
               :candidates candidates
               :price price
               :price-max price
               :epoch epoch}]
    (mesh/wrap-agent-event event agent-pub-hex agent-priv-bytes)))

(defn parse-sim-args
  "Parses CLI arguments for simulate-agents:
   <bootstrap.edn> <keypair.edn> [--agents N] [--messages M] [--burn B].
   Defaults: :agents 10, :messages 30, :burn 500."
  [args]
  (let [[bootstrap-file keypair-file & flag-args] args]
    (when (or (nil? bootstrap-file) (nil? keypair-file)
              (str/starts-with? bootstrap-file "-")
              (str/starts-with? keypair-file "-"))
      (throw (ex-info "Usage: simulate-agents <bootstrap.edn> <keypair.edn> [--agents N] [--messages M] [--burn B]"
                      {:args args})))
    (loop [remaining flag-args
           opts {:agents 10 :messages 30 :burn 500}]
      (if (empty? remaining)
        {:bootstrap-file bootstrap-file
         :keypair-file keypair-file
         :opts opts}
        (let [flag (first remaining)
              val-str (second remaining)]
          (when (or (nil? val-str) (str/starts-with? val-str "--"))
            (throw (ex-info (str "Missing argument for flag " flag) {:flag flag :remaining remaining})))
          (let [v (try (Long/parseLong val-str)
                       (catch Exception _
                         (throw (ex-info (str "Invalid integer for flag " flag ": " val-str)
                                         {:flag flag :val val-str}))))]
            (case flag
              ("--agents" "-a")
              (recur (nnext remaining) (assoc opts :agents (int v)))

              ("--messages" "-m")
              (recur (nnext remaining) (assoc opts :messages (int v)))

              ("--burn" "-b")
              (recur (nnext remaining) (assoc opts :burn v))

              (throw (ex-info (str "Unknown flag: " flag) {:flag flag})))))))))

;; ---------------------------------------------------------------------------
;; Boundary Light Agent Swarm Runner
;; ---------------------------------------------------------------------------

(defn- connect-light-agent!
  "Connects a single client DataChannel node to a validator agent port.
   Returns a connection map with :agent-id, :node, :channel-id, :connected?."
  [agent-idx validator-cfg timeout-ms]
  (try
    (let [node (api/create-node {:port 0 :setup "active"})
          channel-id (atom nil)
          ready-prom (promise)
          remote-sdp {:ip (:ip validator-cfg)
                      :port (int (or (:agent-port validator-cfg) 5010))
                      :fingerprint (identity/normalize-fingerprint (:fingerprint validator-cfg))
                      :remote-ice-ufrag (:ice-ufrag validator-cfg)
                      :remote-ice-pwd (:ice-pwd validator-cfg)}
          callbacks {:on-open (fn [evt]
                                (let [cid (or (:channel-id evt)
                                              (api/create-data-channel! node "bitecho" {:ordered true}))]
                                  (reset! channel-id cid)
                                  (deliver ready-prom true)))
                     :on-close (fn [_]
                                 (reset! channel-id nil))
                     :on-message (fn [_] nil)}]
      (api/start! node remote-sdp callbacks)
      (let [connected? (deref ready-prom timeout-ms false)]
        {:agent-id agent-idx
         :node node
         :channel-id channel-id
         :connected? (boolean (and connected? (some? @channel-id)))}))
    (catch Exception e
      {:agent-id agent-idx
       :node nil
       :channel-id (atom nil)
       :connected? false
       :error (.getMessage e)})))

(defn- connect-swarm!
  "Spawns light agent connections in parallel, round-robin across validator nodes."
  [validator-nodes target-agents timeout-ms]
  (let [val-count (count validator-nodes)]
    (vec
     (pmap (fn [idx]
             (let [vcfg (nth validator-nodes (mod idx val-count))]
               (connect-light-agent! idx vcfg timeout-ms)))
           (range target-agents)))))

(defn- close-swarm!
  "Cleanly terminates all light agent DataChannel nodes."
  [connections]
  (doseq [conn connections
          :when (:node conn)]
    (try
      (api/close! (:node conn))
      (catch Exception _ nil))))

(defn- distribute-swarm-messages!
  "Distributes M unique signed gossip messages across the connected light agent channels."
  [connections sender-pub-hex sender-priv-bytes message-count burn-amount]
  (let [pacing-ms 20
        active-conns (filterv :connected? connections)
        active-count (count active-conns)]
    (if (zero? active-count)
      0
      (let [sent (atom 0)]
        (dotimes [i message-count]
          (let [conn (nth active-conns (mod i active-count))
                cid @(:channel-id conn)]
            (when (some? cid)
              (let [payload-str (format "bitecho-sim-msg-%d-%d-%s"
                                        i
                                        (System/currentTimeMillis)
                                        (UUID/randomUUID))
                    payload-bytes (.getBytes ^String payload-str StandardCharsets/UTF_8)
                    envelope (build-gossip-envelope sender-pub-hex sender-priv-bytes payload-bytes burn-amount)
                    frozen (nippy/freeze envelope)]
                (try
                  (api/send! (:node conn) frozen cid)
                  (swap! sent inc)
                  (catch Exception _ nil)))))
          (Thread/sleep (long pacing-ms)))
        @sent))))

(defn run-agent-simulation!
  "Boundary swarm runner: connects N light agents to Devnet validators and transmits M signed gossip frames."
  ([bootstrap-file keypair-file]
   (run-agent-simulation! bootstrap-file keypair-file {}))
  ([bootstrap-file keypair-file opts]
   (let [bootstrap-cfg (if (string? bootstrap-file)
                         (edn/read-string (slurp bootstrap-file))
                         bootstrap-file)
         keypair-map (if (string? keypair-file)
                       (edn/read-string (slurp keypair-file))
                       keypair-file)
         target-agents (int (or (:agents opts) 10))
         message-count (int (or (:messages opts) 30))
         burn-amount (or (:burn opts) 500)
         val-map (or (:nodes bootstrap-cfg) {})
         val-nodes (vec (sort-by :ip (vals val-map)))]
     (when (empty? val-nodes)
       (throw (ex-info "No validator nodes found in bootstrap config" {:bootstrap-cfg bootstrap-cfg})))
     (let [sender-pub-hex (or (:pubkey-hex keypair-map) (:pubkey keypair-map))
           sender-priv-hex (or (:privkey-hex keypair-map) (:privkey keypair-map))
           sender-priv-bytes (basalt/hex->bytes sender-priv-hex)
           _ (println (format "Connecting %d light agents across %d validators..." target-agents (count val-nodes)))
           connections (connect-swarm! val-nodes target-agents 10000)
           connected-count (count (filter :connected? connections))]
       (println (format "%d/%d light agents successfully connected via WebRTC DataChannel."
                        connected-count target-agents))
       (let [sent-count (if (pos? connected-count)
                          (do
                            (println (format "Transmitting %d signed gossip envelopes (burn=%d each)..."
                                             message-count burn-amount))
                            (distribute-swarm-messages! connections sender-pub-hex sender-priv-bytes message-count burn-amount))
                          0)]
         (Thread/sleep 1500)
         (close-swarm! connections)
         (let [summary {:connected-agents connected-count
                        :target-agents target-agents
                        :messages-sent sent-count
                        :total-burn-submitted (* sent-count burn-amount)}]
           (println (format "Simulation complete: %d/%d agents connected, %d messages sent, %d total burn."
                            (:connected-agents summary)
                            (:target-agents summary)
                            (:messages-sent summary)
                            (:total-burn-submitted summary)))
           summary))))))
