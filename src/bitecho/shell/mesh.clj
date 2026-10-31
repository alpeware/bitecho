(ns bitecho.shell.mesh
  "DataChannel mesh and boundary layer for Bitecho nodes.
   Provides WebRTC DataChannel full-mesh networking, mutual DTLS fingerprint
   authentication, transparent in-memory and datachannel transports,
   embedded HTTP /healthz & /statusz diagnostics, and node lifecycle management."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.shell.core :as core]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.persistence :as persistence]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datachannel.api :as api]
            [taoensso.nippy :as nippy])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.net InetSocketAddress]
           [java.nio.charset StandardCharsets]
           [java.util.concurrent Executors TimeUnit]))

(defn log-mesh-error
  "Logs an error message and exception with context for mesh operations."
  [context ^Throwable e]
  (binding [*out* *err*]
    (println (format "[mesh-error] %s: %s" context (or (when e (.getMessage e)) "unknown")))))

;; ---------------------------------------------------------------------------
;; Shared In-Memory Bus for Fast Test Transport
;; ---------------------------------------------------------------------------

(defonce ^:private in-memory-bus (atom {}))

;; ---------------------------------------------------------------------------
;; Pure Network Command & Event Translation
;; ---------------------------------------------------------------------------

(defn command->network-event
  "Translates an outgoing :net-out command to a peer's incoming network event."
  [cmd sender-pubkey-hex]
  (let [t (:type cmd)
        name-str (name t)
        receive-type (if (str/starts-with? name-str "send-")
                       (keyword (str "receive-" (subs name-str 5)))
                       t)]
    (-> cmd
        (assoc :type receive-type
               :sender sender-pubkey-hex)
        (dissoc :targets :target))))

(defn extract-command-target-hexes
  "Extracts a vector of distinct target peer pubkey hex strings from a network command."
  [cmd]
  (let [raw-targets (cond
                      (contains? cmd :targets) (:targets cmd)
                      (contains? cmd :target) [(:target cmd)]
                      :else [])
        resolve-hex (fn [t]
                      (cond
                        (string? t) t
                        (map? t) (let [pk (:pubkey t)]
                                   (cond
                                     (string? pk) pk
                                     (bytes? pk) (basalt/bytes->hex pk)
                                     :else nil))
                        :else nil))]
    (vec (distinct (keep resolve-hex raw-targets)))))

;; ---------------------------------------------------------------------------
;; Pure Agent Ingress Envelope & Authentication
;; ---------------------------------------------------------------------------

(def allowed-agent-events
  "Set of event types permitted from external agent connections on the agent ingress port."
  #{:receive-gossip
    :receive-summary
    :receive-pull-request
    :register-home-set
    :receive-offer-header})

(defn canonicalize-for-signing
  "Recursively converts a data structure into a content-deterministic
   canonical form for pr-str signing (converting byte arrays to [:bytes hex]
   and sorting maps and sets deterministically)."
  [x]
  (cond
    (bytes? x)
    [:bytes (basalt/bytes->hex x)]

    (map? x)
    (into (sorted-map-by (fn [a b] (compare (pr-str a) (pr-str b))))
          (map (fn [[k v]] [(canonicalize-for-signing k) (canonicalize-for-signing v)]) x))

    (set? x)
    (vec (sort-by pr-str (map canonicalize-for-signing x)))

    (sequential? x)
    (mapv canonicalize-for-signing x)

    :else x))

(defn agent-event-signing-bytes
  "Serializes agent public key and event map into deterministic byte array for Ed25519 signing."
  [agent-pubkey-hex event]
  (let [clean (dissoc event :sender :sender-pubkey-bytes :rng)]
    (.getBytes (pr-str [agent-pubkey-hex (canonicalize-for-signing clean)]) StandardCharsets/UTF_8)))

(defn wrap-agent-event
  "Wraps an agent event into an envelope signed with agent-privkey-bytes."
  [event agent-pubkey-hex ^bytes agent-privkey-bytes]
  (let [clean-event (dissoc event :sender :sender-pubkey-bytes :rng)
        sb (agent-event-signing-bytes agent-pubkey-hex clean-event)
        sig (crypto/sign agent-privkey-bytes sb)
        sig-hex (if (string? sig) sig (basalt/bytes->hex sig))]
    {:agent-pubkey agent-pubkey-hex
     :event clean-event
     :signature sig-hex}))

(defn unwrap-authenticated-agent-event
  "Unwraps and verifies an authenticated agent envelope.
   Returns sanitized event with bound :sender and :sender-pubkey-bytes if valid, or nil."
  [raw-msg]
  (try
    (let [msg (if (bytes? raw-msg)
                (try (nippy/thaw raw-msg) (catch Exception _ nil))
                raw-msg)]
      (when (and (map? msg)
                 (string? (:agent-pubkey msg))
                 (map? (:event msg))
                 (contains? allowed-agent-events (:type (:event msg)))
                 (or (string? (:signature msg)) (bytes? (:signature msg))))
        (let [agent-pub-hex (:agent-pubkey msg)
              agent-pub-bytes (basalt/hex->bytes agent-pub-hex)
              sig-bytes (if (bytes? (:signature msg))
                          (:signature msg)
                          (basalt/hex->bytes (:signature msg)))
              event (:event msg)
              sb (agent-event-signing-bytes agent-pub-hex event)]
          (when (and (some? agent-pub-bytes)
                     (some? sig-bytes)
                     (crypto/verify agent-pub-bytes sb sig-bytes))
            (-> event
                (dissoc :sender :sender-pubkey-bytes :rng)
                (assoc :sender agent-pub-hex
                       :sender-pubkey-bytes agent-pub-bytes
                       :rng (java.util.Random.)))))))
    (catch Exception _ nil)))

;; ---------------------------------------------------------------------------
;; Pure State Initialization & Status Rendering
;; ---------------------------------------------------------------------------

(defn- resolve-pubkey-bytes
  "Converts a hex string or byte array into a byte array."
  [pk]
  (cond
    (bytes? pk) pk
    (string? pk) (try (basalt/hex->bytes pk) (catch Exception _ nil))
    :else nil))

(defn- extract-top-level-overrides
  "Extracts and normalizes treasury, custody, and ledger overrides from config."
  [cfg cluster-cfg]
  (let [resolve-opt-bytes (fn [v] (when v (resolve-pubkey-bytes v)))
        tp-raw (or (:treasury-privkey cfg)
                   (get-in cfg [:protocol :treasury-privkey])
                   (get-in cluster-cfg [:treasury-privkey]))
        cp-raw (or (:custody-privkey cfg)
                   (get-in cfg [:protocol :custody-privkey])
                   (get-in cluster-cfg [:custody-privkey]))]
    (cond-> {}
      (or (:genesis-ledger cfg) (get-in cluster-cfg [:genesis-ledger]))
      (assoc :genesis-ledger (or (:genesis-ledger cfg) (get-in cluster-cfg [:genesis-ledger])))

      (or (:treasury-pubkey cfg) (get-in cluster-cfg [:treasury-pubkey]))
      (assoc :treasury-pubkey (or (:treasury-pubkey cfg) (get-in cluster-cfg [:treasury-pubkey])))

      tp-raw (assoc :treasury-privkey (resolve-opt-bytes tp-raw))

      (or (:custody-pubkey cfg) (get-in cluster-cfg [:custody-pubkey]))
      (assoc :custody-pubkey (or (:custody-pubkey cfg) (get-in cluster-cfg [:custody-pubkey])))

      cp-raw (assoc :custody-privkey (resolve-opt-bytes cp-raw))

      (or (:custody-allocations cfg) (get-in cluster-cfg [:custody-allocations]))
      (assoc :custody-allocations (or (:custody-allocations cfg) (get-in cluster-cfg [:custody-allocations])))

      (or (:bootstrap-sunset-epoch cfg) (get-in cluster-cfg [:bootstrap-sunset-epoch]))
      (assoc :bootstrap-sunset-epoch (or (:bootstrap-sunset-epoch cfg) (get-in cluster-cfg [:bootstrap-sunset-epoch]))))))

(defn build-initial-node-state
  "Constructs initial Bitecho state from cluster config and node identity."
  [cfg identity]
  (let [node-id (or (:node/id cfg) (:node-id cfg) (:node-id identity))
        pubkey-hex (:pubkey-hex identity)
        pubkey-bytes (resolve-pubkey-bytes (get-in identity [:keypair :public]))
        privkey-bytes (resolve-pubkey-bytes (get-in identity [:keypair :private]))
        cluster-cfg (get cfg :cluster {})
        nodes-cfg (get cluster-cfg :nodes {})
        raw-validators (or (:validators cluster-cfg) (keys nodes-cfg))
        validators (vec (sort (keep (fn [v] (if (keyword? v) (get-in nodes-cfg [v :pubkey]) v)) raw-validators)))
        mesh-nodes (or (:mesh-nodes cluster-cfg)
                       (into {} (map (fn [pk] [pk 1.0]) validators)))
        peer-entries (for [[_ ninfo] nodes-cfg
                           :let [pk (:pubkey ninfo)
                                 pk-bytes (resolve-pubkey-bytes pk)]
                           :when (some? pk-bytes)]
                       [(if (string? pk) pk (basalt/bytes->hex pk-bytes))
                        pk-bytes])
        peers-map (into {pubkey-hex pubkey-bytes} peer-entries)
        initial-peers (vec (for [[nid ninfo] nodes-cfg
                                 :when (not= nid node-id)
                                 :let [pk (:pubkey ninfo)
                                       pk-bytes (resolve-pubkey-bytes pk)]
                                 :when (some? pk-bytes)]
                             (basalt/make-peer (or (:ip ninfo) "127.0.0.1")
                                               (or (:port ninfo) 8000)
                                               pk-bytes)))
        overrides (extract-top-level-overrides cfg cluster-cfg)
        network (or (:network cfg) (get-in cfg [:cluster :network]) :mainnet)
        base-proto-cfg (if (= network :devnet)
                         config/devnet-config
                         config/default-config)
        proto-cfg (merge base-proto-cfg
                         (get cfg :protocol {})
                         (get cluster-cfg :protocol {})
                         overrides
                         {:validators validators
                          :mesh-nodes mesh-nodes})
        base-state (sm/init-state initial-peers pubkey-hex proto-cfg)]
    (merge base-state
           overrides
           {:node-id node-id
            :node-pubkey pubkey-hex
            :node-private-key privkey-bytes
            :keypair (:keypair identity)
            :validators validators
            :peers-map peers-map
            :mesh-nodes mesh-nodes})))

(defn rebind-restored-state
  "Rebinds node private keys, credentials, and configuration overrides to a deserialized snapshot state."
  [loaded-state config identity]
  (let [cluster-cfg (get config :cluster {})
        overrides (extract-top-level-overrides config cluster-cfg)
        privkey-bytes (resolve-pubkey-bytes (get-in identity [:keypair :private]))
        pubkey-hex (:pubkey-hex identity)]
    (merge loaded-state
           overrides
           {:node-pubkey pubkey-hex
            :node-private-key privkey-bytes
            :keypair (:keypair identity)})))

(defn- validate-peer-node-entry
  "Validates a single peer node entry in cluster config.
   Returns nil if valid, or an error string."
  [pid pcfg]
  (cond
    (not (map? pcfg))
    (format "Peer %s configuration must be a map" pid)

    (or (not (string? (:ip pcfg))) (str/blank? (:ip pcfg)))
    (format "Peer %s missing or invalid :ip" pid)

    (or (not (integer? (:port pcfg))) (not (pos? (:port pcfg))))
    (format "Peer %s missing or invalid :port" pid)

    (let [pk (:pubkey pcfg)]
      (not (and (string? pk) (= 88 (count pk)) (re-matches #"^[0-9a-fA-F]{88}$" pk))))
    (format "Peer %s has invalid :pubkey (must be 88-char hex)" pid)

    (not (identity/verify-peer-fingerprint? (:fingerprint pcfg) (:fingerprint pcfg)))
    (format "Peer %s has invalid DTLS :fingerprint" pid)

    (or (not (string? (:ice-ufrag pcfg))) (str/blank? (:ice-ufrag pcfg)))
    (format "Peer %s missing or invalid :ice-ufrag" pid)

    (or (not (string? (:ice-pwd pcfg))) (str/blank? (:ice-pwd pcfg)))
    (format "Peer %s missing or invalid :ice-pwd" pid)

    :else nil))

(defn validate-node-config
  "Validates a Bitecho node configuration map fail-closed:
   checks map structure, node-id keyword, non-blank state-dir, cluster peer fields,
   and verifies that initial node state construction succeeds.
   Returns {:valid? true} or {:valid? false :error <string>}."
  [cfg]
  (cond
    (not (map? cfg))
    {:valid? false :error "Config must be a map"}

    (not (keyword? (or (:node/id cfg) (:node-id cfg))))
    {:valid? false :error "Config missing valid :node/id or :node-id keyword"}

    (let [sd (:state-dir cfg)]
      (or (not (string? sd)) (str/blank? sd)))
    {:valid? false :error "Config missing or invalid :state-dir"}

    (and (contains? cfg :cluster) (not (map? (:cluster cfg))))
    {:valid? false :error "Cluster configuration must be a map"}

    (and (contains? cfg :cluster)
         (contains? (:cluster cfg) :nodes)
         (not (map? (get-in cfg [:cluster :nodes]))))
    {:valid? false :error "[:cluster :nodes] must be a map"}

    :else
    (let [node-id (or (:node/id cfg) (:node-id cfg))
          nodes (get-in cfg [:cluster :nodes])
          peer-errs (when (map? nodes)
                      (keep (fn [[pid pcfg]]
                              (when (not= pid node-id)
                                (validate-peer-node-entry pid pcfg)))
                            nodes))]
      (if (seq peer-errs)
        {:valid? false :error (first peer-errs)}
        (try
          (let [synth-id {:node-id node-id
                          :pubkey-hex (apply str (repeat 88 "a"))
                          :keypair (crypto/generate-keypair)}]
            (build-initial-node-state cfg synth-id)
            {:valid? true})
          (catch Exception e
            {:valid? false :error (str "State initialization failed: " (.getMessage e))}))))))

(defn render-statusz
  "Renders single-line diagnostic statusz string."
  [state connected-count total-peers]
  (let [vals-set (set (or (:validators state) (get-in state [:config :validators])))
        role (if (contains? vals-set (:node-pubkey state))
               "validator"
               "mesh")
        epoch (long (or (:epoch state) 0))
        head (str (or (:head-hash state) "genesis"))
        notarized (long (count (or (:notarized-blocks state) #{})))
        finalized (long (count (or (:finalized-blocks state) #{})))
        ledger (or (:ledger state) {})
        supply (long (reduce + 0 (map (fn [v] (if (map? v) (or (:balance v) 0) (or v 0))) (vals ledger))))
        minted (long (or (:total-minted state) 0))
        burns (long (reduce + 0 (vals (or (:epoch-burns state) {}))))]
    (format "role=%s epoch=%d head=%s notarized=%d finalized=%d peers=%d/%d supply=%d minted=%d burns=%d\n"
            role epoch head notarized finalized (long connected-count) (long total-peers) supply minted burns)))

;; ---------------------------------------------------------------------------
;; Embedded HTTP Server (/healthz & /statusz)
;; ---------------------------------------------------------------------------

(defn- query-node-state
  "Queries the active shell node for its current internal state with timeout."
  [shell-node timeout-ms]
  (let [reply-ch (async/promise-chan)]
    (async/put! (:events-in shell-node) {:type :query-state :reply-chan reply-ch})
    (let [[val _] (async/alts!! [reply-ch (async/timeout timeout-ms)])]
      val)))

(defn- make-http-handler
  "Creates an HttpHandler for healthz and statusz endpoints."
  [ctx total-peers fallback-state]
  (let [{:keys [shell-node peer-conns transport in-mem-bus]} ctx]
    (reify HttpHandler
      (handle [_ exchange]
        (let [path (.getPath (.getRequestURI ^HttpExchange exchange))
              [status body] (cond
                              (= path "/healthz")
                              [200 "ok\n"]

                              (= path "/statusz")
                              (let [st (or (query-node-state shell-node 500) fallback-state)
                                    connected (if (= transport :in-memory)
                                                (max 0 (dec (count @in-mem-bus)))
                                                (count (filter (fn [[_ c]] (some? @(:channel-id c))) @peer-conns)))]
                                [200 (render-statusz st connected total-peers)])

                              :else
                              [404 "not found\n"])
              resp-bytes (.getBytes ^String body StandardCharsets/UTF_8)]
          (.getResponseHeaders ^HttpExchange exchange)
          (.set (.getResponseHeaders ^HttpExchange exchange) "Content-Type" "text/plain; charset=utf-8")
          (.sendResponseHeaders ^HttpExchange exchange status (alength resp-bytes))
          (with-open [os (.getResponseBody ^HttpExchange exchange)]
            (.write os resp-bytes)))))))

(defn- start-http-server!
  "Starts embedded HTTP server if enabled."
  [http-cfg ctx total-peers fallback-state]
  (when (get http-cfg :enabled? true)
    (let [port (int (get http-cfg :port 8080))
          host (str (get http-cfg :host "127.0.0.1"))
          server (HttpServer/create (InetSocketAddress. ^String host port) 0)
          handler (make-http-handler ctx total-peers fallback-state)]
      (.createContext server "/healthz" handler)
      (.createContext server "/statusz" handler)
      (.setExecutor server (Executors/newVirtualThreadPerTaskExecutor))
      (.start server)
      server)))

;; ---------------------------------------------------------------------------
;; Mesh Transports & Lifecycle
;; ---------------------------------------------------------------------------

(declare init-datachannel-peer!)

(defn create-peer-datachannel-node
  "Constructs a DataChannel node map using persistent DTLS cert-data and deterministic ICE credentials,
   avoiding runtime throwaway certificate generation."
  [local-port setup cert-data local-ice local-fp]
  (let [opts {:port local-port :setup setup}
        local-sdp-params {:port local-port
                          :ice-ufrag (:ufrag local-ice)
                          :ice-pwd (:pwd local-ice)
                          :fingerprint local-fp
                          :setup setup}]
    {:opts opts
     :cert-data cert-data
     :ice-creds local-ice
     :local-sdp-params local-sdp-params
     :running (atom false)
     :state-atom (atom nil)
     :channel (atom nil)
     :selector (atom nil)
     :loop-future (atom nil)
     :remote-addr (atom nil)
     :shared-channel? false
     :callbacks (atom nil)}))

(defn send-peer-keepalives!
  "Sends a keepalive frame to each connected peer DataChannel."
  [peer-conns]
  (when peer-conns
    (let [keepalive-bytes (nippy/freeze {:type :keepalive})]
      (doseq [[_ conn] @peer-conns
              :when (some? @(:channel-id conn))]
        (try
          (api/send! (:node conn) keepalive-bytes @(:channel-id conn))
          (catch Exception e
            (log-mesh-error "Failed to send keepalive" e)))))))

(defn check-and-reconnect-peers!
  "Checks peer datachannel health and attempts reconnect if closed, stalled during handshake, or quiet past timeout-ms."
  ([ctx]
   (check-and-reconnect-peers! ctx 20000 (System/currentTimeMillis)))
  ([ctx timeout-ms]
   (check-and-reconnect-peers! ctx timeout-ms (System/currentTimeMillis)))
  ([ctx timeout-ms now-ms]
   (let [{:keys [nodes-cfg node-id peer-conns]} ctx]
     (doseq [[pid pcfg] nodes-cfg
             :when (not= pid node-id)
             :let [peer-hex (:pubkey pcfg)
                   conn (get @peer-conns peer-hex)
                   node (:node conn)
                   st (when node (try (api/get-state node) (catch Exception _ :closed)))
                   cid (when conn @(:channel-id conn))
                   created-at (get conn :created-at 0)
                   last-rx (when conn @(or (:last-rx-at conn) (atom now-ms)))
                   stalled-unconnected? (and (nil? cid) (> (- now-ms created-at) 12000))
                   timed-out-connected? (and (some? cid) (> (- now-ms (or last-rx now-ms)) (long timeout-ms)))]]
       (when (or (nil? conn)
                 (= st :closed)
                 stalled-unconnected?
                 timed-out-connected?)
         (try
           (init-datachannel-peer! ctx pid pcfg)
           (catch Exception e
             (log-mesh-error (str "Peer reconnect error for " pid) e))))))))

(defn- start-ticker!
  "Starts the periodic virtual-thread timer pushing :tick events, sending peer keepalives, and auto-reconnecting."
  [ctx tick-interval-ms]
  (let [{:keys [shell-node transport]} ctx
        timeout-ms (max 20000 (* 2 (long tick-interval-ms)))
        executor (Executors/newSingleThreadScheduledExecutor)
        initial-delay (let [t (long tick-interval-ms)
                            rem-ms (mod (System/currentTimeMillis) t)]
                        (if (zero? rem-ms) t (- t rem-ms)))]
    (.scheduleAtFixedRate executor
                          (fn []
                            (try
                              (async/put! (:events-in shell-node)
                                          {:type :tick :rng (java.util.Random.)})
                              (when (= transport :datachannel)
                                (send-peer-keepalives! (:peer-conns ctx))
                                (check-and-reconnect-peers! ctx timeout-ms))
                              (catch Exception e
                                (log-mesh-error "Ticker loop error" e))))
                          initial-delay
                          tick-interval-ms
                          TimeUnit/MILLISECONDS)
    executor))

(defn- start-net-out-loop!
  "Consumes net-out commands, transforms them to peer events, and delivers to targets."
  [ctx]
  (let [{:keys [shell-node identity transport peer-conns in-mem-bus]} ctx]
    (async/go-loop []
      (when-let [cmd (async/<! (:net-out shell-node))]
        (try
          (let [targets (extract-command-target-hexes cmd)
                sender-hex (:pubkey-hex identity)
                evt (command->network-event cmd sender-hex)
                frozen (nippy/freeze evt)]
            (doseq [target targets]
              (if (= transport :in-memory)
                (when-let [peer-entry (get @in-mem-bus target)]
                  (let [thawed (assoc (nippy/thaw frozen)
                                      :sender sender-hex
                                      :sender-pubkey-bytes (get-in identity [:keypair :public])
                                      :rng (java.util.Random.))]
                    (async/put! (:network-in peer-entry) thawed)))
                (when-let [conn (get @peer-conns target)]
                  (when-let [cid @(:channel-id conn)]
                    (api/send! (:node conn) frozen cid))))))
          (catch Exception e
            (log-mesh-error "Net-out loop error" e)))
        (recur)))))

(defn- init-datachannel-peer!
  "Establishes a single peer DataChannel connection."
  [ctx pid peer-cfg]
  (try
    (let [raw-fp (:fingerprint peer-cfg)
          peer-fp (when (identity/verify-peer-fingerprint? raw-fp raw-fp)
                    (identity/normalize-fingerprint raw-fp))]
      (if-not peer-fp
        (log-mesh-error (format "Invalid peer fingerprint for %s" pid)
                        (ex-info "Invalid peer fingerprint" {:peer pid :fingerprint raw-fp}))
        (let [{:keys [node-id identity node-idx nodes-cfg shell-node peer-conns]} ctx
              peer-hex (:pubkey peer-cfg)]
          (when-let [old-conn (get @peer-conns peer-hex)]
            (when-let [old-node (:node old-conn)]
              (try (api/close! old-node) (catch Exception _ nil))
              (Thread/sleep 50)))
          (let [peer-ip (or (:ip peer-cfg) "127.0.0.1")
                base-peer-port (int (or (:port peer-cfg) 5000))
                peer-port (+ base-peer-port (int (get node-idx node-id 0)))
                base-local-port (int (or (get-in nodes-cfg [node-id :port]) 5000))
                local-port (+ base-local-port (int (get node-idx pid 0)))
                setup (if (neg? (compare (name node-id) (name pid))) "active" "passive")
                local-fp (:fingerprint identity)
                local-ice (identity/deterministic-ice-creds node-id local-fp)
                node (create-peer-datachannel-node local-port setup (:cert-data identity) local-ice local-fp)
                channel-id (atom nil)
                last-rx-at (atom (System/currentTimeMillis))
                remote-ice (identity/deterministic-ice-creds pid peer-fp)
                remote-sdp {:ip peer-ip
                            :port peer-port
                            :fingerprint peer-fp
                            :remote-ice-ufrag (:ufrag remote-ice)
                            :remote-ice-pwd (:pwd remote-ice)}
                callbacks {:on-open (fn [evt]
                                      (reset! last-rx-at (System/currentTimeMillis))
                                      (if-let [cid (:channel-id evt)]
                                        (reset! channel-id cid)
                                        (reset! channel-id (api/create-data-channel! node "bitecho" {:ordered true}))))
                           :on-message (fn [evt]
                                         (reset! last-rx-at (System/currentTimeMillis))
                                         (when-let [msg (try (nippy/thaw (:payload evt)) (catch Exception _ nil))]
                                           (when-not (= :keepalive (:type msg))
                                             (let [event (assoc msg
                                                                :sender peer-hex
                                                                :sender-pubkey-bytes (basalt/hex->bytes peer-hex)
                                                                :rng (java.util.Random.))]
                                               (async/put! (:network-in shell-node) event)))))
                           :on-close (fn [_]
                                       (reset! channel-id nil))}]
            (api/start! node remote-sdp callbacks)
            (swap! peer-conns assoc peer-hex {:node node
                                              :channel-id channel-id
                                              :last-rx-at last-rx-at
                                              :created-at (System/currentTimeMillis)})))))
    (catch Exception e
      (log-mesh-error (format "Failed to connect to peer %s" pid) e)
      nil)))

(defn- init-agent-listener!
  "Starts agent ingress listener when enabled.
   Sanitizes incoming agent messages using unwrap-authenticated-agent-event."
  [config identity shell-node transport]
  (when (and (= transport :datachannel)
             (get-in config [:cluster :listen-agents?] false))
    (let [port (int (get-in config [:cluster :agent-port] 5010))
          listen-opts {:port port
                       :cert-data (:cert-data identity)
                       :ice-creds (:ice-creds identity)}]
      (api/listen! listen-opts
                   {:on-connection
                    (fn [agent-node]
                      (api/set-callbacks! agent-node
                                          {:on-message
                                           (fn [evt]
                                             (when-let [unwrapped (unwrap-authenticated-agent-event (:payload evt))]
                                               (async/put! (:network-in shell-node) unwrapped)))}))}))))

(defn stop-mesh-node!
  "Stops all running resources of a mesh node cleanly."
  [mesh-node]
  (when-let [srv (:http-server mesh-node)]
    (try (.stop ^HttpServer srv 0) (catch Exception _ nil)))
  (when-let [exec (:ticker-executor mesh-node)]
    (try (.shutdownNow ^java.util.concurrent.ExecutorService exec) (catch Exception _ nil)))
  (when-let [al (:agent-listener mesh-node)]
    (try (api/close! al) (catch Exception _ nil)))
  (doseq [[_ conn] @(:peer-conns mesh-node)]
    (when-let [n (:node conn)]
      (try (api/close! n) (catch Exception _ nil))))
  (when (= (:transport mesh-node) :in-memory)
    (swap! in-memory-bus dissoc (get-in mesh-node [:identity :pubkey-hex])))
  (when-let [sh (:shell-node mesh-node)]
    (try (async/put! (:stop-ch sh) :stop) (catch Exception _ nil)))
  true)

(defn start-mesh-node!
  "Starts a full Bitecho mesh node."
  ([config]
   (start-mesh-node! config {}))
  ([config opts]
   (let [node-id (or (:node/id config) (:node-id config) :node-1)
         state-dir (or (:state-dir config) "data")
         identity (or (:identity opts) (identity/load-or-create-node-identity! state-dir node-id))
         transport (or (:transport opts) (:transport config) :datachannel)
         snapshot-file (str (io/file state-dir "state" (str "snapshot-" (name node-id) ".edn")))
         loaded-state (or (when-let [f (:snapshot-file opts)] (persistence/load-state-from-disk f))
                          (when (.exists (io/file snapshot-file)) (persistence/load-state-from-disk snapshot-file)))
         initial-state (if loaded-state
                         (rebind-restored-state loaded-state config identity)
                         (build-initial-node-state config identity))
         shell-node (core/start-node initial-state snapshot-file {:persist? (get opts :persist? true)})
         peer-conns (atom {})
         cluster-cfg (get config :cluster {})
         nodes-cfg (get cluster-cfg :nodes {})
         sorted-ids (vec (sort-by name (keys nodes-cfg)))
         node-idx (into {} (map-indexed (fn [i k] [k i]) sorted-ids))
         ctx {:node-id node-id
              :identity identity
              :transport transport
              :shell-node shell-node
              :peer-conns peer-conns
              :in-mem-bus in-memory-bus
              :node-idx node-idx
              :nodes-cfg nodes-cfg}]
     (if (= transport :in-memory)
       (swap! in-memory-bus assoc (:pubkey-hex identity) {:node-id node-id :network-in (:network-in shell-node)})
       (doseq [[pid pcfg] nodes-cfg :when (not= pid node-id)]
         (try
           (init-datachannel-peer! ctx pid pcfg)
           (catch Exception e
             (log-mesh-error (str "Failed to initialize peer " pid) e)))))
     (start-net-out-loop! ctx)
     (let [tick-interval (or (get-in config [:protocol :tick-interval-ms])
                             (get-in initial-state [:config :tick-interval-ms])
                             (:tick-interval-ms config/devnet-config)
                             10000)
           ticker (start-ticker! ctx tick-interval)
           agent-listener (init-agent-listener! config identity shell-node transport)
           http-server (start-http-server! (get config :http {})
                                           ctx
                                           (count (disj (set (keys nodes-cfg)) node-id))
                                           initial-state)
           node-map {:node-id node-id
                     :identity identity
                     :transport transport
                     :shell-node shell-node
                     :peer-conns peer-conns
                     :http-server http-server
                     :ticker-executor ticker
                     :agent-listener agent-listener
                     :config config}]
       (assoc node-map :stop! #(stop-mesh-node! node-map))))))
