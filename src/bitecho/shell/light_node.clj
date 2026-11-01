(ns bitecho.shell.light-node
  "Light-node boundary shell for Bitecho.
   Handles CLI invocation, JSONL STDIN/STDOUT serve loop, state persistence
   with atomic rename (0600 permissions), and WebRTC DataChannel agent connections."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.discovery :as discovery]
            [bitecho.shell.identity :as identity]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datachannel.api :as api]
            [taoensso.nippy :as nippy])
  (:import [java.io BufferedReader InputStreamReader PrintWriter]
           [java.nio.file Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]))

;; -----------------------------------------------------------------------------
;; Pure State Sanitization & Argument Parsing
;; -----------------------------------------------------------------------------

(defn strip-sensitive-keys
  "Pure helper to remove ephemeral private keys from session state prior to persistence."
  [state]
  (let [clean-sessions (into {} (for [[sid s] (:sessions state)]
                                  [sid (dissoc s :ephemeral-priv)]))]
    (assoc state :sessions clean-sessions)))

(defn- extract-flag-value
  "Extracts the value following a flag from an argument vector."
  [args flag default-val]
  (let [idx (.indexOf ^java.util.List (vec args) flag)]
    (if (and (>= idx 0) (< (inc idx) (count args)))
      (nth args (inc idx))
      default-val)))

(defn- extract-long-flag
  "Extracts a numeric long value following a flag, or nil if missing."
  [args flag default-val]
  (if-let [v (extract-flag-value args flag nil)]
    (try (Long/parseLong (str v)) (catch Exception _ default-val))
    default-val))

(defn- build-one-shot-cmd-map
  "Constructs a JSON command map from parsed CLI arguments."
  [verb args]
  (let [first-arg (first args)
        json-args (when (and (string? first-arg) (str/starts-with? (str/trim first-arg) "{"))
                    (try (json/read-str first-arg) (catch Exception _ nil)))
        base-map (case verb
                   "identity" {"cmd" "identity"}
                   "status"   {"cmd" "status"}
                   "discover" {"cmd" "discover"}
                   "inbox"    {"cmd" "inbox"}
                   "offer"    (let [m {"cmd" "offer"
                                       "callee" (extract-flag-value args "--callee" nil)
                                       "price" (extract-long-flag args "--price" 10)
                                       "burn" (extract-long-flag args "--burn" 500)}
                                    hn (extract-flag-value args "--home-node" nil)]
                                (if hn (assoc m "home_node" hn) m))
                   "accept"   {"cmd" "accept"
                               "session_id" (or (extract-flag-value args "--session-id" nil)
                                                (extract-flag-value args "--session" nil))}
                   "send"     (let [m {"cmd" "send"
                                       "session_id" (or (extract-flag-value args "--session-id" nil)
                                                        (extract-flag-value args "--session" nil))
                                       "burn" (extract-long-flag args "--burn" 500)}
                                    t (extract-flag-value args "--text" nil)
                                    h (extract-flag-value args "--payload-hex" nil)]
                                (cond-> m
                                  t (assoc "text" t)
                                  h (assoc "payload_hex" h)))
                   "close"    {"cmd" "close"
                               "session_id" (or (extract-flag-value args "--session-id" nil)
                                                (extract-flag-value args "--session" nil))}
                   "transfer" {"cmd" "transfer"
                               "receiver" (or (extract-flag-value args "--receiver" nil)
                                              (extract-flag-value args "--recipient" nil))
                               "recipient" (or (extract-flag-value args "--receiver" nil)
                                               (extract-flag-value args "--recipient" nil))
                               "amount" (extract-long-flag args "--amount" 0)
                               "seq" (extract-long-flag args "--seq" nil)
                               "burn" (extract-long-flag args "--burn" 500)}
                   "register-home-set" {"cmd" "register-home-set"
                                        "home_nodes" (let [nodes (extract-flag-value args "--nodes" nil)]
                                                       (if nodes (str/split nodes #",") []))
                                        "burn" (extract-long-flag args "--burn" 500)}
                   {"cmd" verb})]
    (if (map? json-args)
      (merge base-map json-args {"cmd" verb})
      base-map)))

(defn resolve-proxy-url
  "Pure helper. Returns explicit proxy url, or resolves from environment variables
   in order: HTTPS_PROXY, https_proxy, HTTP_PROXY, http_proxy."
  ([explicit-proxy]
   (resolve-proxy-url explicit-proxy #(System/getenv %)))
  ([explicit-proxy getenv-fn]
   (or (when (and (string? explicit-proxy) (seq (str/trim explicit-proxy)))
         (str/trim explicit-proxy))
       (some (fn [env-var]
               (when-let [val (getenv-fn env-var)]
                 (when (seq (str/trim val))
                   (str/trim val))))
             ["HTTPS_PROXY" "https_proxy" "HTTP_PROXY" "http_proxy"]))))

(defn parse-light-node-args
  "Parses light-node command line arguments into an options map."
  [args]
  (let [clean-args (if (= (first args) "light-node") (vec (rest args)) (vec args))
        verb (first clean-args)
        serve? (= verb "serve")
        default-state-dir (str (System/getProperty "user.home") "/.bitecho/light-node")
        default-bootstrap "https://bitecho.org/devnet/bootstrap.txt"
        state-dir (or (extract-flag-value clean-args "--state-dir" nil) default-state-dir)
        bootstrap-path (or (extract-flag-value clean-args "--bootstrap" nil) default-bootstrap)
        autonomous? (some #{"--autonomous"} clean-args)
        transport-str (extract-flag-value clean-args "--transport" "udp")
        transport (case (str/lower-case transport-str)
                    "tcp" :tcp
                    "connect" :connect
                    :udp)
        timeout-ms (extract-long-flag clean-args "--timeout-ms" nil)
        proxy-cli (extract-flag-value clean-args "--proxy" nil)
        proxy-url (resolve-proxy-url proxy-cli)]
    (cond-> {:mode (if serve? :serve :one-shot)
             :verb verb
             :state-dir state-dir
             :bootstrap bootstrap-path
             :autonomous? (boolean autonomous?)
             :transport transport
             :cmd-map (when-not serve? (build-one-shot-cmd-map verb (rest clean-args)))}
      timeout-ms (assoc :timeout-ms timeout-ms)
      proxy-url (assoc :proxy proxy-url))))

;; -----------------------------------------------------------------------------
;; State Persistence & Identity Loading
;; -----------------------------------------------------------------------------

(defn save-light-state!
  "Persists sanitized light-node state via Nippy with atomic move and 0600 permissions."
  [state-file state]
  (let [f (io/file state-file)
        dir (.getParentFile f)
        _ (when dir (.mkdirs dir))
        tmp-file (io/file (str state-file ".tmp"))
        clean-state (strip-sensitive-keys state)
        frozen (nippy/freeze clean-state)]
    (Files/write (.toPath tmp-file) ^bytes frozen (into-array java.nio.file.OpenOption []))
    (try
      (Files/setPosixFilePermissions (.toPath tmp-file) (PosixFilePermissions/fromString "rw-------"))
      (catch UnsupportedOperationException _ nil))
    (try
      (Files/move (.toPath tmp-file) (.toPath f)
                  (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                        StandardCopyOption/REPLACE_EXISTING]))
      (catch Exception _
        (Files/move (.toPath tmp-file) (.toPath f)
                    (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
    true))

(defn load-light-state!
  "Loads persisted light-node state via Nippy, or nil if file does not exist."
  [state-file]
  (let [f (io/file state-file)]
    (when (.exists f)
      (let [b (Files/readAllBytes (.toPath f))]
        (nippy/thaw b)))))

(defn load-or-create-light-identity!
  "Loads or creates persistent light-node identity in state-dir.
   Throws descriptive exception on corrupt identity file."
  [state-dir]
  (let [node-id :light-node
        id-data (identity/load-or-create-node-identity! state-dir node-id)
        priv-bytes (if-let [kp (:keypair id-data)]
                     (:private kp)
                     (basalt/hex->bytes (:privkey-hex id-data)))]
    (assoc id-data :privkey-bytes priv-bytes)))

;; -----------------------------------------------------------------------------
;; Validator Connection Manager
;; -----------------------------------------------------------------------------

(defn- validate-node-fingerprints
  "Verifies DTLS fingerprints for all nodes in descriptor.
   Returns nil if valid, or {:ok? false :error \"bad-fingerprint\"} on mismatch."
  [descriptor]
  (let [nodes (vals (get descriptor :nodes {}))]
    (when (some (fn [node]
                  (let [raw-fp (:fingerprint node)]
                    (not (and (string? raw-fp)
                              (try (boolean (identity/normalize-fingerprint raw-fp))
                                   (catch Exception _ false))))))
                nodes)
      {:ok? false :error "bad-fingerprint"})))

(defn connection-live?
  "Checks if connection is marked ok and channel-id is present and state is connected."
  [conn state]
  (and (boolean (:ok? conn))
       (not (false? (:connected? state)))
       (if-let [cid-atom (:channel-id conn)]
         (some? @cid-atom)
         true)))

(defn send-all-envelopes!
  "Transmits all envelopes using send-fn and returns true only if all succeeded."
  [send-fn envelopes]
  (if (empty? envelopes)
    true
    (and (fn? send-fn)
         (every? true? (mapv #(boolean (send-fn %)) envelopes)))))

(defn- dispatch-auto-reply!
  "Sends auto-reply envelopes, attempting reconnect if connection is lost, or failing closed."
  [envelopes send-fn-atom state-atom event-out reconnect-fn]
  (let [live? (and @send-fn-atom (not (false? (:connected? @state-atom))))
        sent? (when live?
                (send-all-envelopes! @send-fn-atom envelopes))]
    (when-not sent?
      (if reconnect-fn
        (let [reconn (reconnect-fn)]
          (when-not (and (:ok? reconn)
                         (send-all-envelopes! (:send-fn reconn) envelopes))
            (let [err (or (:error reconn) "connection-closed")]
              (when state-atom
                (swap! state-atom assoc :connected? false :connection-error err))
              (when event-out
                (event-out {"event" "connection-failed" "connected" false "error" err})))))
        (let [err "connection-closed"]
          (when state-atom
            (swap! state-atom assoc :connected? false :connection-error err))
          (when event-out
            (event-out {"event" "connection-failed" "connected" false "error" err})))))))

(defn make-client-callbacks
  "Creates callback handlers for client DataChannel connection."
  [client-node channel-id connected? send-fn-atom ctx]
  (let [{:keys [identity state-atom conn-atom event-out reconnect-fn]} ctx]
    {:on-open (fn [evt]
                (if-let [cid (:channel-id evt)]
                  (reset! channel-id cid)
                  (reset! channel-id (api/create-data-channel! client-node "bitecho" {:ordered true})))
                (deliver connected? true))
     :on-message (fn [evt]
                   (when-let [cid (:channel-id evt)]
                     (reset! channel-id cid))
                   (when-let [payload (:payload evt)]
                     (when state-atom
                       (let [st @state-atom
                             res (light-core/handle-wire-payload st payload (:privkey-bytes identity))]
                         (reset! state-atom (:state res))
                         (when (and event-out (seq (:stdout-events res)))
                           (doseq [ev (:stdout-events res)]
                             (event-out ev)))
                         (when (seq (:net-envelopes res))
                           (dispatch-auto-reply! (:net-envelopes res) send-fn-atom state-atom event-out reconnect-fn))))))
     :on-error (fn [evt]
                 (when (str/includes? (str (:message evt)) "Fingerprint")
                   (deliver connected? :bad-fingerprint)))
     :on-close (fn [_]
                 (reset! channel-id nil)
                 (when conn-atom
                   (swap! conn-atom assoc :ok? false :error "connection-closed"))
                 (when state-atom
                   (swap! state-atom assoc :connected? false :connection-error "connection-closed")))}))

(defn- dial-single-node!
  "Dials a single validator node via WebRTC DataChannel (UDP, TCP, or HTTP CONNECT proxy)."
  [identity node opts]
  (let [client-node (api/create-node {:port 0
                                      :cert-data (:cert-data identity)
                                      :ice-creds (:ice-creds identity)
                                      :setup "active"})
        channel-id (atom nil)
        connected? (promise)
        send-fn-atom (atom nil)
        callbacks (make-client-callbacks client-node channel-id connected? send-fn-atom
                                         {:identity identity
                                          :state-atom (:state-atom opts)
                                          :conn-atom (:conn-atom opts)
                                          :event-out (:event-out opts)
                                          :reconnect-fn (:reconnect-fn opts)})
        transport (:transport opts)
        target-host (if (= transport :connect)
                      (or (:ingress-host node) (:ip node) "127.0.0.1")
                      (or (:ip node) "127.0.0.1"))
        target-port (case transport
                      :connect (int (or (:ingress-port node) (:agent-tcp-port node) (:agent-port node) 443))
                      :tcp (int (or (:agent-tcp-port node) (:agent-port node) (:port node) 5010))
                      (int (or (:agent-port node) (:port node) 5010)))
        remote-sdp (cond-> {:ip target-host
                            :port target-port
                            :fingerprint (identity/normalize-fingerprint (:fingerprint node))
                            :remote-ice-ufrag (or (:ice-ufrag node) "ufrag")
                            :remote-ice-pwd (or (:ice-pwd node) "pwd")}
                     (= transport :connect)
                     (assoc :proxy (or (:proxy opts) (resolve-proxy-url nil))))]
    (if (or (= transport :tcp) (= transport :connect))
      (try
        (api/start-tcp! client-node remote-sdp callbacks)
        (catch Exception _
          (deliver connected? :connect-failed)))
      (api/start! client-node remote-sdp callbacks))
    (let [timeout-ms (long (or (:timeout-ms opts) 8000))
          res (deref connected? timeout-ms :timeout)]
      (cond
        (= res :bad-fingerprint)
        (do (try (api/close! client-node) (catch Exception _ nil))
            {:ok? false :error "bad-fingerprint"})
        (or (= res :timeout) (= res :connect-failed))
        (do (try (api/close! client-node) (catch Exception _ nil))
            {:ok? false :error "listener-disabled"})
        :else
        (let [send-fn (fn [env]
                        (if-let [cid @channel-id]
                          (try
                            (let [payload (if (bytes? env) env (nippy/freeze env))]
                              (api/send! client-node payload cid)
                              true)
                            (catch Exception _
                              false))
                          false))]
          (reset! send-fn-atom send-fn)
          {:ok? true
           :node client-node
           :channel-id channel-id
           :send-fn send-fn})))))

(defn connect-validators!
  "Establishes WebRTC DataChannel connections to validators in bootstrap-descriptor.
   Returns connection result or error map (:bad-fingerprint or :listener-disabled)."
  [identity bootstrap-descriptor opts]
  (if-let [err (validate-node-fingerprints bootstrap-descriptor)]
    err
    (if-let [dialer (:dialer-fn opts)]
      (dialer identity bootstrap-descriptor opts)
      (let [nodes (vals (get bootstrap-descriptor :nodes {}))]
        (if (empty? nodes)
          {:ok? false :error "no-nodes-in-descriptor"}
          (loop [rem-nodes nodes]
            (if-let [node (first rem-nodes)]
              (let [res (dial-single-node! identity node opts)]
                (cond
                  (:ok? res) res
                  (= (:error res) "bad-fingerprint") res
                  :else (recur (rest rem-nodes))))
              {:ok? false :error "listener-disabled"})))))))

;; -----------------------------------------------------------------------------
;; CLI Runner (Serve & One-Shot Modes)
;; -----------------------------------------------------------------------------

(defn- emit-json-line!
  "Writes a data object as a JSON line to the dedicated print writer."
  [^PrintWriter writer data]
  (.println writer ^String (json/write-str data))
  (.flush writer))

(defn handle-serve-line!
  "Processes a single STDIN JSON line in serve mode, handling network retries if required."
  [line ctx]
  (let [{:keys [state-atom conn-atom out-writer state-file identity bootstrap conn-opts]} ctx
        res (light-core/process-jsonl-line @state-atom line (:privkey-bytes identity))
        needs-net? (seq (:net-envelopes res))]
    (if needs-net?
      (let [currently-live? (connection-live? @conn-atom @state-atom)
            sent? (when currently-live?
                    (send-all-envelopes! (:send-fn @conn-atom) (:net-envelopes res)))]
        (if sent?
          (do
            (reset! state-atom (assoc (:state res) :connected? true :connection-error nil))
            (save-light-state! state-file @state-atom)
            (when-let [resp (:response res)]
              (emit-json-line! out-writer resp)))
          (let [reconn (connect-validators! identity bootstrap conn-opts)]
            (reset! conn-atom reconn)
            (if (and (:ok? reconn)
                     (send-all-envelopes! (:send-fn reconn) (:net-envelopes res)))
              (do
                (reset! state-atom (assoc (:state res) :connected? true :connection-error nil))
                (save-light-state! state-file @state-atom)
                (when-let [resp (:response res)]
                  (emit-json-line! out-writer resp)))
              (let [err (or (:error @conn-atom) "listener-disabled")]
                (swap! state-atom assoc :connected? false :connection-error err)
                (emit-json-line! out-writer {"ok" false "error" err}))))))
      (do
        (reset! state-atom (:state res))
        (save-light-state! state-file @state-atom)
        (when-let [resp (:response res)]
          (emit-json-line! out-writer resp))))))

(defn run-serve!
  "Runs the light node in continuous JSONL serve mode reading STDIN and writing STDOUT."
  [opts]
  (let [state-dir (:state-dir opts)
        state-file (str (io/file state-dir "state.nippy"))
        identity (load-or-create-light-identity! state-dir)
        bootstrap (discovery/load-bootstrap-descriptor! (:bootstrap opts))
        loaded-state (load-light-state! state-file)
        initial-state (or (cond-> loaded-state
                            (:autonomous? opts) (assoc :autonomous? true))
                          (light-core/init-light-state identity {:bootstrap bootstrap
                                                                 :autonomous? (:autonomous? opts false)}))
        state-atom (atom initial-state)
        conn-atom (atom nil)
        out-writer (PrintWriter. System/out true)
        event-out (fn [ev] (emit-json-line! out-writer ev))
        conn-opts-atom (atom nil)
        reconnect-fn (fn []
                       (let [reconn (connect-validators! identity bootstrap @conn-opts-atom)]
                         (reset! conn-atom reconn)
                         (swap! state-atom assoc
                                :connected? (boolean (:ok? reconn))
                                :connection-error (:error reconn))
                         reconn))
        conn-opts (assoc opts
                         :state-atom state-atom
                         :conn-atom conn-atom
                         :event-out event-out
                         :reconnect-fn reconnect-fn)
        _ (reset! conn-opts-atom conn-opts)
        conn-res (reconnect-fn)
        ctx {:state-atom state-atom
             :conn-atom conn-atom
             :out-writer out-writer
             :state-file state-file
             :identity identity
             :bootstrap bootstrap
             :conn-opts conn-opts}]
    (if (:ok? conn-res)
      (emit-json-line! out-writer {"event" "ready"
                                   "connected" true
                                   "transport" (name (or (:transport opts) :udp))})
      (emit-json-line! out-writer {"event" "connection-failed"
                                   "connected" false
                                   "error" (:error conn-res)}))
    (binding [*out* *err*]
      (let [reader (BufferedReader. (InputStreamReader. System/in "UTF-8"))]
        (loop []
          (when-let [line (.readLine reader)]
            (when-not (str/blank? line)
              (handle-serve-line! line ctx))
            (recur)))))))

(defn run-one-shot!
  "Executes a single one-shot light-node command and outputs JSON response."
  [opts]
  (let [state-dir (:state-dir opts)
        state-file (str (io/file state-dir "state.nippy"))
        identity (load-or-create-light-identity! state-dir)
        bootstrap (discovery/load-bootstrap-descriptor! (:bootstrap opts))
        loaded-state (load-light-state! state-file)
        initial-state (or (cond-> loaded-state
                            (:autonomous? opts) (assoc :autonomous? true))
                          (light-core/init-light-state identity {:bootstrap bootstrap
                                                                 :autonomous? (:autonomous? opts false)}))
        cmd-map (:cmd-map opts)
        out-writer (PrintWriter. System/out true)]
    (binding [*out* *err*]
      (let [res (light-core/handle-command initial-state cmd-map (:privkey-bytes identity))
            new-state (:state res)
            needs-network? (and (seq (:net-envelopes res)) (:connect? opts true))]
        (if needs-network?
          (let [conn-res (connect-validators! identity bootstrap opts)]
            (if-not (:ok? conn-res)
              (let [err-resp {"ok" false "error" (or (:error conn-res) "listener-disabled")}]
                (emit-json-line! out-writer err-resp)
                err-resp)
              (let [sent? (send-all-envelopes! (:send-fn conn-res) (:net-envelopes res))]
                (when-let [n (:node conn-res)]
                  (try (api/close! n) (catch Exception _ nil)))
                (if sent?
                  (do
                    (save-light-state! state-file new-state)
                    (emit-json-line! out-writer (:response res))
                    (:response res))
                  (let [err-resp {"ok" false "error" "connection-closed"}]
                    (emit-json-line! out-writer err-resp)
                    err-resp)))))
          (do
            (save-light-state! state-file new-state)
            (emit-json-line! out-writer (:response res))
            (:response res)))))))

(defn run-light-node-cli!
  "Dispatches light-node CLI invocation based on parsed arguments."
  [args]
  (let [parsed (parse-light-node-args args)]
    (case (:mode parsed)
      :serve (run-serve! parsed)
      :one-shot (run-one-shot! parsed))))
