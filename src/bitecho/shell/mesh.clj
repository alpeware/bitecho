(ns bitecho.shell.mesh
  "DataChannel mesh and boundary layer for Bitecho nodes.
   Provides WebRTC DataChannel full-mesh networking, mutual DTLS fingerprint
   authentication, transparent in-memory and datachannel transports,
   embedded HTTP /healthz & /statusz diagnostics, and node lifecycle management."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
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
;; Pure State Initialization & Status Rendering
;; ---------------------------------------------------------------------------

(defn- resolve-pubkey-bytes
  "Converts a hex string or byte array into a byte array."
  [pk]
  (cond
    (bytes? pk) pk
    (string? pk) (basalt/hex->bytes pk)
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
                           :let [pk (:pubkey ninfo)]
                           :when (some? pk)]
                       [(if (string? pk) pk (basalt/bytes->hex pk))
                        (resolve-pubkey-bytes pk)])
        peers-map (into {pubkey-hex pubkey-bytes} peer-entries)
        initial-peers (vec (for [[nid ninfo] nodes-cfg
                                 :when (not= nid node-id)
                                 :let [pk (:pubkey ninfo)]
                                 :when (some? pk)]
                             (basalt/make-peer (or (:ip ninfo) "127.0.0.1")
                                               (or (:port ninfo) 8000)
                                               (resolve-pubkey-bytes pk))))
        overrides (extract-top-level-overrides cfg cluster-cfg)
        proto-cfg (merge config/devnet-config
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

(defn render-statusz
  "Renders single-line diagnostic statusz string."
  [state connected-count total-peers]
  (let [vals-set (set (or (:validators state) (get-in state [:config :validators])))
        role (if (contains? vals-set (:node-pubkey state))
               "validator"
               "mesh")
        epoch (long (or (:epoch state) 0))
        head (str (or (get-in state [:streamlet :head-hash]) (:head-hash state) "genesis"))
        notarized (long (or (get-in state [:streamlet :notarized-height])
                            (count (:notarized-blocks state))
                            0))
        finalized (long (or (get-in state [:streamlet :finalized-height])
                            (count (:finalized-blocks state))
                            0))
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
          server (HttpServer/create (InetSocketAddress. port) 0)
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

(defn- check-and-reconnect-peers!
  "Checks peer datachannel health and attempts reconnect if closed or stalled."
  [ctx]
  (let [{:keys [nodes-cfg node-id peer-conns]} ctx
        now-ms (System/currentTimeMillis)]
    (doseq [[pid pcfg] nodes-cfg
            :when (not= pid node-id)
            :let [peer-hex (:pubkey pcfg)
                  conn (get @peer-conns peer-hex)
                  node (:node conn)
                  st (when node (try (api/get-state node) (catch Exception _ :closed)))
                  stalled? (and (nil? @(:channel-id conn))
                                (> (- now-ms (:created-at conn 0)) 15000))]]
      (when (or (nil? conn) (= st :closed) stalled?)
        (try
          (init-datachannel-peer! ctx pid pcfg)
          (catch Exception _ nil))))))

(defn- start-ticker!
  "Starts the periodic virtual-thread timer pushing :tick events and auto-reconnecting."
  [ctx tick-interval-ms]
  (let [{:keys [shell-node transport]} ctx
        executor (Executors/newSingleThreadScheduledExecutor)]
    (.scheduleAtFixedRate executor
                          (fn []
                            (try
                              (async/put! (:events-in shell-node)
                                          {:type :tick :rng (java.util.Random.)})
                              (when (= transport :datachannel)
                                (check-and-reconnect-peers! ctx))
                              (catch Exception _ nil)))
                          tick-interval-ms
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
          (catch Exception _ nil))
        (recur)))))

(defn- init-datachannel-peer!
  "Establishes a single peer DataChannel connection."
  [ctx pid peer-cfg]
  (let [{:keys [node-id identity node-idx nodes-cfg shell-node peer-conns]} ctx
        peer-hex (:pubkey peer-cfg)]
    (when-let [old-conn (get @peer-conns peer-hex)]
      (when-let [old-node (:node old-conn)]
        (try (api/close! old-node) (catch Exception _ nil))))
    (let [peer-ip (or (:ip peer-cfg) "127.0.0.1")
          base-peer-port (int (or (:port peer-cfg) 5000))
          peer-port (+ base-peer-port (int (get node-idx node-id 0)))
          base-local-port (int (or (get-in nodes-cfg [node-id :port]) 5000))
          local-port (+ base-local-port (int (get node-idx pid 0)))
          setup (if (neg? (compare (name node-id) (name pid))) "active" "passive")
          raw-node (api/create-node {:port local-port :setup setup})
          local-fp (:fingerprint identity)
          local-ice (identity/deterministic-ice-creds node-id local-fp)
          node (assoc raw-node
                      :cert-data (:cert-data identity)
                      :ice-creds local-ice
                      :local-sdp-params (assoc (:local-sdp-params raw-node)
                                               :ice-ufrag (:ufrag local-ice)
                                               :ice-pwd (:pwd local-ice)
                                               :fingerprint local-fp
                                               :setup setup))
          channel-id (atom nil)
          peer-fp (identity/normalize-fingerprint (:fingerprint peer-cfg))
          remote-ice (identity/deterministic-ice-creds pid peer-fp)
          remote-sdp {:ip peer-ip
                      :port peer-port
                      :fingerprint peer-fp
                      :remote-ice-ufrag (:ufrag remote-ice)
                      :remote-ice-pwd (:pwd remote-ice)}
          callbacks {:on-open (fn [evt]
                                (when-not (:channel-id evt)
                                  (reset! channel-id (api/create-data-channel! node "bitecho" {:ordered true}))))
                     :on-message (fn [evt]
                                   (when-let [msg (try (nippy/thaw (:payload evt)) (catch Exception _ nil))]
                                     (let [event (assoc msg
                                                        :sender peer-hex
                                                        :sender-pubkey-bytes (basalt/hex->bytes peer-hex)
                                                        :rng (java.util.Random.))]
                                       (async/put! (:network-in shell-node) event))))
                     :on-close (fn [_] (reset! channel-id nil))}]
      (api/start! node remote-sdp callbacks)
      (swap! peer-conns assoc peer-hex {:node node
                                        :channel-id channel-id
                                        :created-at (System/currentTimeMillis)}))))

(defn- init-agent-listener!
  "Starts agent ingress listener when enabled.
   Sanitizes incoming agent messages: drops validator consensus events,
   strips unverified sender pubkey bytes, and attaches an rng instance."
  [config shell-node transport]
  (when (and (= transport :datachannel)
             (get-in config [:cluster :listen-agents?] false))
    (let [port (int (get-in config [:cluster :agent-port] 5010))]
      (api/listen! {:port port}
                   {:on-connection
                    (fn [agent-node]
                      (api/set-callbacks! agent-node
                                          {:on-message
                                           (fn [evt]
                                             (when-let [msg (try (nippy/thaw (:payload evt)) (catch Exception _ nil))]
                                               (when-not (#{:receive-propose :receive-vote} (:type msg))
                                                 (let [sanitized (-> msg
                                                                     (dissoc :sender-pubkey-bytes)
                                                                     (assoc :rng (java.util.Random.)))]
                                                   (async/put! (:network-in shell-node) sanitized)))))}))}))))

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
         initial-state (or (when-let [f (:snapshot-file opts)] (persistence/load-state-from-disk f))
                           (build-initial-node-state config identity))
         snapshot-file (str (io/file state-dir "state" (str "snapshot-" (name node-id) ".edn")))
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
         (init-datachannel-peer! ctx pid pcfg)))
     (start-net-out-loop! ctx)
     (let [tick-interval (or (get-in config [:protocol :tick-interval-ms])
                             (get-in initial-state [:config :tick-interval-ms])
                             (:tick-interval-ms config/devnet-config)
                             10000)
           ticker (start-ticker! ctx tick-interval)
           agent-listener (init-agent-listener! config shell-node transport)
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
