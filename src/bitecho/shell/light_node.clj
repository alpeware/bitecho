(ns bitecho.shell.light-node
  "Light-node boundary shell for Bitecho.
   Handles CLI invocation, JSONL STDIN/STDOUT serve loop, state persistence
   with atomic rename (0600 permissions), and WebRTC DataChannel agent connections."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.light-node.mcp :as mcp]
            [bitecho.shell.agent-sim :as agent-sim]
            [bitecho.shell.discovery :as discovery]
            [bitecho.shell.identity :as identity]
            [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datachannel.api :as api]
            [datachannel.mdns :as mdns])
  (:import [com.sun.net.httpserver HttpHandler HttpServer]
           [java.io BufferedReader InputStreamReader PrintWriter RandomAccessFile]
           [java.lang ProcessHandle ProcessBuilder ProcessBuilder$Redirect]
           [java.net InetSocketAddress StandardSocketOptions URI]
           [java.net.http HttpClient HttpClient$Redirect HttpClient$Version HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.channels DatagramChannel FileChannel]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files StandardCopyOption StandardOpenOption]
           [java.nio.file.attribute PosixFilePermissions]
           [java.time Duration]
           [java.util.concurrent Executors ThreadFactory]))

(declare dial-p2p-peer! send-routed-envelopes!)

;; -----------------------------------------------------------------------------
;; Shared Process-Wide HTTP Client & UDP Socket Buffer Helpers (P-SOAK-1, P-SOAK-4)
;; -----------------------------------------------------------------------------

(def ^:private shared-http-executor
  (delay
    (Executors/newCachedThreadPool
     (reify ThreadFactory
       (newThread [_ r]
         (doto (Thread. ^Runnable r)
           (.setName "bitecho-shared-http-client")
           (.setDaemon true)))))))

(def ^:private shared-http-client
  (delay
    (-> (HttpClient/newBuilder)
        (.connectTimeout (Duration/ofMillis 5000))
        (.followRedirects HttpClient$Redirect/NORMAL)
        (.executor @shared-http-executor)
        (.build))))

(def ^:private shared-http11-client
  (delay
    (-> (HttpClient/newBuilder)
        (.version HttpClient$Version/HTTP_1_1)
        (.connectTimeout (Duration/ofMillis 5000))
        (.followRedirects HttpClient$Redirect/NORMAL)
        (.executor @shared-http-executor)
        (.build))))

(defn default-http-client
  "Returns the process-wide shared `java.net.http.HttpClient` instance (`BUG-SOAK-01`)."
  ^HttpClient []
  @shared-http-client)

(defn default-http11-client
  "Returns the process-wide shared HTTP/1.1 `java.net.http.HttpClient` instance (`BUG-SOAK-01`)."
  ^HttpClient []
  @shared-http11-client)

(def default-udp-rcvbuf-bytes
  "Default 4 MB UDP socket receive buffer size (`DIAG-SOAK-03`)."
  4194304)

(defn configure-udp-receive-buffer!
  "Configures `SO_RCVBUF` on a `DatagramChannel`, `DatagramSocket`, or `clj-datachannel` node map
   to `buf-bytes` (default 4 MB / `4194304` bytes, `DIAG-SOAK-03`). Never throws."
  ([target]
   (configure-udp-receive-buffer! target default-udp-rcvbuf-bytes))
  ([target ^long buf-bytes]
   (let [sz (int (max 65536 buf-bytes))]
     (try
       (cond
         (instance? DatagramChannel target)
         (do (.setOption ^DatagramChannel target StandardSocketOptions/SO_RCVBUF (Integer/valueOf sz))
             true)

         (instance? java.net.DatagramSocket target)
         (do (.setReceiveBufferSize ^java.net.DatagramSocket target sz)
             true)

         (and (map? target) (instance? clojure.lang.IDeref (:channel target)) @(:channel target))
         (configure-udp-receive-buffer! @(:channel target) sz)

         (and (map? target) (:channel target))
         (configure-udp-receive-buffer! (:channel target) sz)

         :else false)
       (catch Throwable _ false)))))

;; -----------------------------------------------------------------------------
;; Pure State Sanitization & Argument Parsing
;; -----------------------------------------------------------------------------

(defn strip-sensitive-keys
  "Pure helper to remove single-use ECDH `:ephemeral-priv` keys from session state prior to persistence,
   and dissoc transient runtime connection liveness keys so `state.fressian` never persists them.
   Active session `:tx-key` and `:rx-key` are retained under the `0600` POSIX permission boundary of
   `state.fressian` (matching `identity/node-identity.edn`) to support one-shot CLI session resumption (`M2a-1`)."
  [state]
  (light-core/strip-sensitive-keys state))

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

(defn build-one-shot-cmd-map
  "Constructs a JSON command map from parsed CLI arguments by delegating to the
   shared pure `.cljc` parser `bitecho.light-node.cli/build-cmd-map` (`BIP-005` / `D31.3`),
   enriching platform file arguments (`--file`, `--spec-file`, `--claim-file`) on JVM."
  [verb args]
  (let [first-arg (first args)
        json-args (when (and (string? first-arg) (str/starts-with? (str/trim first-arg) "{"))
                    (try (json/read-str first-arg) (catch Exception _ nil)))
        raw-map (cli/build-cmd-map verb args)
        cmd (get raw-map "cmd")
        file-arg (extract-flag-value args "--file" nil)
        spec-file (extract-flag-value args "--spec-file" nil)
        claim-file (extract-flag-value args "--claim-file" nil)
        base-map
        (cond-> raw-map
          (and (= cmd "bip-submit") (nil? (get raw-map "spec_edn")) spec-file)
          (assoc "spec_edn" (try (slurp spec-file) (catch Exception _ nil)))

          (and (= cmd "bounty-settle") (nil? (get raw-map "claim_edn")) claim-file)
          (assoc "claim_edn" (try (slurp claim-file) (catch Exception _ nil)))

          (and (= cmd "artifact-put")
               (nil? (get raw-map "hex"))
               (nil? (get raw-map "text"))
               file-arg
               (.exists (io/file file-arg)))
          (into (let [h (try (basalt/bytes->hex (Files/readAllBytes (.toPath (io/file file-arg))))
                             (catch Exception _ nil))]
                  (if h {"hex" h "data_hex" h} {})))

          (and (= cmd "import-poll") file-arg)
          (assoc "file_content" (or (try (slurp file-arg) (catch Exception _ nil)) ""))

          (and (contains? #{"import" "import-envelope"} cmd)
               (nil? (extract-flag-value args "--hex" nil))
               file-arg)
          (assoc "hex" (or (try (slurp file-arg) (catch Exception _ nil)) "")))]
    (if (map? json-args)
      (merge base-map json-args {"cmd" (get base-map "cmd")})
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

(defn resolve-relay-url
  "Pure helper. Returns normalized explicit relay url, or resolves from environment variable
   BITECHO_RELAY_URL, normalized via relay/normalize-relay-base-url."
  ([explicit-relay]
   (resolve-relay-url explicit-relay #(System/getenv %)))
  ([explicit-relay getenv-fn]
   (let [candidate (or (when (and (string? explicit-relay) (seq (str/trim explicit-relay)))
                         (str/trim explicit-relay))
                       (when-let [val (getenv-fn "BITECHO_RELAY_URL")]
                         (when (seq (str/trim val))
                           (str/trim val))))]
     (when candidate
       (relay/normalize-relay-base-url candidate)))))

(defn extract-subverb-and-args
  "Extracts the subverb and remaining arguments, allowing global flags like
   --state-dir <path> or --control-port <port> to appear before or after the subverb."
  [tokens]
  (let [pre-verb-valued-flags #{"--state-dir" "--control-port" "--bootstrap" "--relay-url"
                                "--subnet-id" "--subnet" "--subscribe-subnets" "--subnets"
                                "--transport" "--proxy" "--timeout-ms" "--max-epoch-skew"
                                "--cmd-file" "--events-out" "--session-id" "--session"
                                "--min-seq" "--min-broadcast-seq" "--after-ts" "--min-balance"
                                "--ingress-tcp-port"
                                "--trusted-dac-anchors" "--turn-server" "--turn-username"
                                "--turn-password" "--turn-realm" "--sync-interval-ms"
                                "--price" "--price-max" "--burn" "--to" "--from"
                                "--callee" "--peer" "--receiver" "--recipient"
                                "--amount" "--text" "--message" "--payload-hex"
                                "--wait-open-ms" "--until-event"
                                "--path" "--cid" "--file" "--hex" "--seq" "--authority" "--prefix"}
        runner-valued-flags #{"--state-dir" "--control-port" "--bootstrap"}]
    (loop [rem (vec tokens)]
      (if (empty? rem)
        {:subverb nil :subargs []}
        (let [tok (first rem)]
          (if (contains? pre-verb-valued-flags tok)
            (recur (vec (drop 2 rem)))
            (if (str/starts-with? tok "--")
              (recur (vec (rest rem)))
              ;; Found the subverb
              (let [subverb tok
                    rest-tokens (vec (rest rem))
                    cleaned-subargs (loop [in rest-tokens
                                           out []]
                                      (if (empty? in)
                                        out
                                        (let [t (first in)]
                                          (if (contains? runner-valued-flags t)
                                            (recur (vec (drop 2 in)) out)
                                            (recur (vec (rest in)) (conj out t))))))]
                {:subverb subverb
                 :subargs cleaned-subargs}))))))))

(defn parse-light-node-args
  "Parses light-node command line arguments into an options map."
  ([args]
   (parse-light-node-args args #(System/getenv %)))
  ([args getenv-fn]
   (let [clean-args (if (= (first args) "light-node") (vec (rest args)) (vec args))
         first-tok (first clean-args)
         first-non-flag (if (and (string? first-tok) (str/starts-with? first-tok "--"))
                          (:subverb (extract-subverb-and-args clean-args))
                          first-tok)
         verb first-non-flag
         help? (boolean (or (some #{"--help" "-h"} clean-args) (= verb "help")))
         mcp? (boolean (or (some #{"--mcp"} clean-args) (= verb "mcp")))
         no-poll? (boolean (some #{"--no-poll"} clean-args))
         ctl? (= verb "ctl")
         serve? (= verb "serve")
         daemon? (= verb "daemon")
         wait-event? (= verb "wait-event")
         keep-alive-eof? (boolean (some #{"--keep-alive-eof"} clean-args))
         serve-daemon? (and serve? (boolean (some #{"--daemon"} clean-args)))
         ctl-sub (when ctl? (extract-subverb-and-args (rest clean-args)))
         daemon-sub (when daemon? (extract-subverb-and-args (rest clean-args)))
         ctl-ensure? (and ctl? (= (:subverb ctl-sub) "ensure"))
         default-state-dir (str (System/getProperty "user.home") "/.bitecho/light-node")
         default-bootstrap "https://bitecho.org/devnet/bootstrap.txt"
         state-dir (or (extract-flag-value clean-args "--state-dir" nil) default-state-dir)
         bootstrap-path (or (extract-flag-value clean-args "--bootstrap" nil) default-bootstrap)
         autonomous? (boolean (some #{"--autonomous"} clean-args))
         no-auto-sync? (boolean (some #{"--no-auto-sync"} clean-args))
         explicit-auto-sync? (boolean (some #{"--auto-sync"} clean-args))
         auto-sync? (and (not no-auto-sync?) (or explicit-auto-sync? serve?))
         sync? (boolean (some #{"--sync"} clean-args))
         connect? (cond
                    (some #{"--no-connect"} clean-args) false
                    (some #{"--connect"} clean-args) true
                    :else nil)
         sync-interval-ms (extract-long-flag clean-args "--sync-interval-ms" (when auto-sync? 15000))
         control-port (extract-long-flag clean-args "--control-port" (if serve? 5020 nil))
         raw-skew (extract-long-flag clean-args "--max-epoch-skew" nil)
         max-epoch-skew (when raw-skew (max 1 (long raw-skew)))
         no-auto-reg? (boolean (some #{"--no-auto-register-home-set"} clean-args))
         explicit-auto-reg? (boolean (some #{"--auto-register-home-set"} clean-args))
         auto-register-home-set? (and (not no-auto-reg?) (or explicit-auto-reg? (and serve? autonomous?)))
         home-set-price (extract-long-flag clean-args "--price" (when auto-register-home-set? 10))
         cmd-file (extract-flag-value clean-args "--cmd-file" nil)
         events-out (extract-flag-value clean-args "--events-out" nil)
         wait-session-id (or (extract-flag-value clean-args "--session-id" nil)
                             (extract-flag-value clean-args "--session" nil))
         min-seq (extract-long-flag clean-args "--min-seq" nil)
         min-broadcast-seq (extract-long-flag clean-args "--min-broadcast-seq" nil)
         min-balance (extract-long-flag clean-args "--min-balance" nil)
         after-ts (extract-long-flag clean-args "--after-ts" nil)
         transport-str (extract-flag-value clean-args "--transport" "udp")
         transport (case (str/lower-case transport-str)
                     "tcp" :tcp
                     "connect" :connect
                     :udp)
         timeout-ms (extract-long-flag clean-args "--timeout-ms" nil)
         ingress-tcp-port (extract-long-flag clean-args "--ingress-tcp-port" nil)
         proxy-cli (extract-flag-value clean-args "--proxy" nil)
         proxy-url (resolve-proxy-url proxy-cli getenv-fn)
         relay-cli (extract-flag-value clean-args "--relay-url" nil)
         relay-url (resolve-relay-url relay-cli getenv-fn)
         subnet-id (extract-flag-value clean-args "--subnet-id" nil)
         trusted-dac-anchors-raw (extract-flag-value clean-args "--trusted-dac-anchors" nil)
         trusted-dac-anchors (when (and (string? trusted-dac-anchors-raw) (not (str/blank? trusted-dac-anchors-raw)))
                               (let [raw-items (if (or (str/starts-with? (str/trim trusted-dac-anchors-raw) "[")
                                                       (str/starts-with? (str/trim trusted-dac-anchors-raw) "#{"))
                                                 (try (edn/read-string trusted-dac-anchors-raw)
                                                      (catch Exception _ (str/split trusted-dac-anchors-raw #",")))
                                                 (str/split trusted-dac-anchors-raw #","))]
                                 (set (map #(or (light-core/normalize-pubkey-hex %) (str/trim (str %))) (remove str/blank? (map str raw-items))))))
         turn-server (extract-flag-value clean-args "--turn-server" nil)
         turn-username (extract-flag-value clean-args "--turn-username" nil)
         turn-password (extract-flag-value clean-args "--turn-password" nil)
         turn-realm (extract-flag-value clean-args "--turn-realm" nil)
         turn-force-relay? (boolean (some #{"--turn-force-relay"} clean-args))
         turn-config (when (or turn-server turn-username turn-password turn-realm turn-force-relay?)
                       (let [[h p] (when turn-server (str/split turn-server #":" 2))]
                         {:server-host (or h "127.0.0.1")
                          :server-port (if (and p (seq p)) (try (Integer/parseInt p) (catch Exception _ 3478)) 3478)
                          :username turn-username
                          :password turn-password
                          :realm turn-realm
                          :force-relay? turn-force-relay?}))]
     (cond-> {:mode (cond
                      help? :help
                      mcp? :mcp
                      (or daemon? ctl-ensure? serve-daemon?) :daemon
                      ctl? :ctl
                      serve? :serve
                      wait-event? :wait-event
                      :else :one-shot)
              :verb verb
              :state-dir state-dir
              :bootstrap bootstrap-path
              :autonomous? autonomous?
              :auto-sync? (boolean auto-sync?)
              :auto-register-home-set? (boolean auto-register-home-set?)
              :keep-alive-eof? keep-alive-eof?
              :transport transport
              :cmd-map (let [m (when-not (or help? mcp? ctl? serve? wait-event? daemon? ctl-ensure? serve-daemon?)
                                 (build-one-shot-cmd-map verb (if (and (string? first-tok) (str/starts-with? first-tok "--"))
                                                                (:subargs (extract-subverb-and-args clean-args))
                                                                (rest clean-args))))]
                         (cond-> m
                           (and subnet-id (nil? (get m "subnet_id"))) (assoc "subnet_id" subnet-id)))}
       no-poll? (assoc :no-poll? true)
       control-port (assoc :control-port control-port)
       max-epoch-skew (assoc :max-epoch-skew max-epoch-skew)
       (or daemon? ctl-ensure? serve-daemon?)
       (assoc :daemon-action (cond
                               serve-daemon? "start"
                               ctl-ensure? "ensure"
                               daemon? (or (:subverb daemon-sub) "start")
                               :else "start")
              :daemon-args (cond
                             daemon? (or (:subargs daemon-sub) [])
                             ctl-ensure? (or (:subargs ctl-sub) [])
                             :else [])
              :raw-args clean-args)
       ctl? (assoc :ctl-subverb (:subverb ctl-sub)
                   :ctl-args (or (:subargs ctl-sub) []))
       sync-interval-ms (assoc :sync-interval-ms sync-interval-ms)
       home-set-price (assoc :home-set-price home-set-price)
       cmd-file (assoc :cmd-file cmd-file)
       events-out (assoc :events-out events-out)
       wait-session-id (assoc :session-id wait-session-id)
       min-seq (assoc :min-seq min-seq)
       min-broadcast-seq (assoc :min-broadcast-seq min-broadcast-seq)
       min-balance (assoc :min-balance min-balance)
       after-ts (assoc :after-ts after-ts)
       subnet-id (assoc :subnet-id subnet-id)
       timeout-ms (assoc :timeout-ms timeout-ms)
       ingress-tcp-port (assoc :ingress-tcp-port (int ingress-tcp-port))
       (seq trusted-dac-anchors) (assoc :trusted-dac-anchors trusted-dac-anchors)
       (some? sync?) (assoc :sync? sync?)
       (some? connect?) (assoc :connect? connect?)
       proxy-url (assoc :proxy proxy-url)
       relay-url (assoc :relay-url relay-url)
       turn-config (assoc :turn-config turn-config)))))

;; -----------------------------------------------------------------------------
;; State Persistence & Identity Loading
;; -----------------------------------------------------------------------------

(defonce ^:private light-state-save-lock (Object.))

(defn- write-state-bytes-atomic!
  [^java.io.File target-file ^bytes encoded-bytes]
  (let [dir (or (.getParentFile target-file) (io/file "."))
        _ (.mkdirs dir)
        tmp-file (java.io.File/createTempFile "light-state-" ".tmp" dir)]
    (try
      (Files/write (.toPath tmp-file) encoded-bytes (into-array java.nio.file.OpenOption []))
      (with-open [ch (FileChannel/open (.toPath tmp-file) (into-array java.nio.file.OpenOption [StandardOpenOption/WRITE]))]
        (.force ch true))
      (try
        (Files/setPosixFilePermissions (.toPath tmp-file) (PosixFilePermissions/fromString "rw-------"))
        (catch UnsupportedOperationException _ nil))
      (try
        (Files/move (.toPath tmp-file) (.toPath target-file)
                    (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                          StandardCopyOption/REPLACE_EXISTING]))
        (catch Exception _
          (Files/move (.toPath tmp-file) (.toPath target-file)
                      (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
      true
      (finally
        (when (.exists tmp-file)
          (try (.delete tmp-file) (catch Exception _ nil)))))))

(defn save-light-state!
  "Persists sanitized light-node state via cross-platform Fressian (`state.fressian`)
   with atomic move and 0600 permissions (`M2a-2`: writes strictly to `state-file` without
   dual-writing Fressian bytes into legacy `state.nippy`)."
  [state-file state]
  (when (and (some? state-file) (not (str/blank? (str state-file))))
    (locking light-state-save-lock
      (let [f (io/file state-file)
            encoded (light-core/encode-light-state state)]
        (write-state-bytes-atomic! f encoded)
        true))))

(declare execute-conn-effects! apply-conn-event!)

(defonce ^:private light-state-load-diagnostics-atom (atom {}))

(defn get-light-state-load-diagnostics
  "Returns counted diagnostic counters recorded during light-node state loading."
  []
  @light-state-load-diagnostics-atom)

(defn load-light-state!
  "Loads persisted light-node state strictly from `state.fressian`.
   Rejects legacy Nippy ('NPY') bytes fail-closed with a counted :diagnose
   :legacy-nippy-snapshot-rejected effect, returning nil."
  ([state-file]
   (load-light-state! state-file nil))
  ([state-file opts]
   (when (and (some? state-file) (not (str/blank? (str state-file))))
     (let [f (io/file state-file)]
       (when (.exists f)
         (let [b (Files/readAllBytes (.toPath f))]
           (when (pos? (alength b))
             (if (fressian/nippy-payload? b)
               (let [eff {:effect :diagnose
                          :reason :legacy-nippy-snapshot-rejected
                          :error "legacy-nippy-snapshot-rejected"
                          :state-file (str f)}]
                 (swap! light-state-load-diagnostics-atom update :legacy-nippy-snapshot-rejected (fnil inc 0))
                 (when-let [st-atom (:state-atom opts)]
                   (when (instance? clojure.lang.IAtom st-atom)
                     (swap! st-atom update-in [:diagnostics :legacy-nippy-snapshot-rejected] (fnil inc 0))))
                 (if-let [c-atom (:conn-atom opts)]
                   (apply-conn-event! c-atom {:type :legacy-nippy-snapshot-rejected
                                              :error "legacy-nippy-snapshot-rejected"}
                                      opts)
                   (execute-conn-effects! [eff] opts))
                 nil)
               (let [decoded (light-core/decode-light-state b)]
                 (when (light-core/legacy-v0238-state? decoded)
                   (let [bak-f (io/file (str (.getAbsolutePath f) ".v0238.bak"))]
                     (when-not (.exists bak-f)
                       (try (write-state-bytes-atomic! bak-f b) (catch Exception _ nil)))))
                 (light-core/migrate-light-state decoded))))))))))

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

(defn ordered-validator-candidates
  "Builds a deterministic, failover-prioritized list of validator candidate nodes.
   Prioritizes active home-set candidates, followed by the remaining bootstrap nodes
   sorted deterministically by name, and rotates the candidate list by validator-cursor."
  [bootstrap-descriptor home-set validator-cursor]
  (let [nodes-map (get bootstrap-descriptor :nodes {})
        norm-node-id (fn [item]
                       (cond
                         (keyword? item) item
                         (string? item) (keyword item)
                         (map? item) (recur (or (:node-id item) (:id item) (:node item)))
                         :else nil))
        normalized-home (vec (distinct (keep norm-node-id home-set)))
        all-node-keys (vec (sort-by name (keys nodes-map)))
        home-in-desc (filterv #(contains? nodes-map %) normalized-home)
        remainder-keys (remove (set home-in-desc) all-node-keys)
        ordered-keys (into (vec home-in-desc) remainder-keys)
        base-candidates (mapv (fn [k] (assoc (get nodes-map k) :node-id k)) ordered-keys)]
    (if (empty? base-candidates)
      []
      (let [n (count base-candidates)
            cursor (long (max 0 (or validator-cursor 0)))
            rot (mod cursor n)]
        (into (subvec base-candidates rot)
              (subvec base-candidates 0 rot))))))

(defn fetch-validator-accountz!
  "Fetches accountz info from a validator node via HTTP GET or :accountz-fetcher.
   Returns parsed EDN map or nil if unreachable."
  [bootstrap pubkey opts]
  (if-let [fetcher (:accountz-fetcher opts)]
    (fetcher pubkey)
    (let [candidates (ordered-validator-candidates bootstrap nil 0)
          client (or (:http-client opts) (default-http-client))]
      (some (fn [cand]
              (let [ip (:ip cand)
                    http-port (or (:http-port cand) (:http_port cand) 8080)
                    url-str (str "http://" ip ":" http-port "/accountz?pubkey=" pubkey)]
                (try
                  (let [req (-> (HttpRequest/newBuilder)
                                (.uri (URI/create url-str))
                                (.timeout (Duration/ofMillis 1500))
                                (.GET)
                                (.build))
                        resp (.send client req (HttpResponse$BodyHandlers/ofString))]
                    (when (= 200 (.statusCode resp))
                      (let [body (.body resp)]
                        (try
                          (edn/read-string body)
                          (catch Exception _ nil)))))
                  (catch Exception _ nil))))
            candidates))))

;; -----------------------------------------------------------------------------
;; HTTP Gateway Relay Client Helpers (/relay/v1/*)
;; -----------------------------------------------------------------------------

(defn submit-relay-envelope!
  "Submits an envelope (hex string, bytes, or map) to the HTTP relay at `relay-url`.
   Returns parsed response map or {:ok false :error ...}."
  ([relay-url envelope]
   (submit-relay-envelope! relay-url envelope nil))
  ([relay-url envelope opts]
   (let [client (or (:http-client opts) (default-http-client))
         url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/send")
         wire-hex (cond
                    (string? envelope) envelope
                    (bytes? envelope) (basalt/bytes->hex envelope)
                    (map? envelope) (try (basalt/bytes->hex (fressian/encode-canonical envelope))
                                         (catch Exception _ (basalt/bytes->hex (fressian/encode-wire envelope))))
                    :else (str envelope))
         payload (json/write-str {"envelope_hex" wire-hex})
         req (-> (HttpRequest/newBuilder)
                 (.uri (URI/create url))
                 (.header "Content-Type" "application/json")
                 (.timeout (Duration/ofMillis (long (or (:timeout-ms opts) 5000))))
                 (.POST (HttpRequest$BodyPublishers/ofString payload StandardCharsets/UTF_8))
                 (.build))]
     (try
       (let [resp (.send client req (HttpResponse$BodyHandlers/ofString))]
         (try
           (json/read-str (.body resp))
           (catch Exception _
             {"ok" false "error" "invalid-json-response" "status" (.statusCode resp)})))
       (catch Exception e
         {"ok" false "error" (.getMessage e)})))))

(defn poll-relay-envelopes!
  "Polls the HTTP relay for envelopes addressed to `pubkey` (or broadcast).
   Generates a proof-of-possession Ed25519 signature over pubkey + ts using `privkey`.
   `opts`: {:seq-gte :limit :timeout-ms :since-ms :http-client}
   Returns parsed response map or {:ok false :error ...}."
  ([relay-url pubkey privkey]
   (poll-relay-envelopes! relay-url pubkey privkey nil))
  ([relay-url pubkey privkey opts]
   (let [client (or (:http-client opts) (default-http-client))
         base-url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/poll")
         pk-hex (if (bytes? pubkey) (basalt/bytes->hex pubkey) (str pubkey))
         now-ms (System/currentTimeMillis)
         since-seq (long (or (:since-seq opts) (:seq-gte opts) 0))
         bseq (long (or (:since-broadcast-seq opts) 0))
         wait-ms (or (:timeout-ms opts) (:wait-ms opts))
         nonce (or (:nonce opts) (basalt/bytes->hex (crypto/random-bytes 16)))
         sig (relay/sign-poll-request privkey {:pubkey pk-hex
                                               :since-seq since-seq
                                               :timestamp-ms now-ms
                                               :nonce nonce})
         sub-param (when-let [s (:subnets opts)]
                     (if (coll? s) (str/join "," s) (str s)))
         params (cond-> {"pubkey" pk-hex
                         "since_seq" (str since-seq)}
                  (:since-broadcast-seq opts) (assoc "since_broadcast_seq" (str (:since-broadcast-seq opts)))
                  (:limit opts) (assoc "limit" (str (:limit opts)))
                  (:timeout-ms opts) (assoc "timeout_ms" (str (:timeout-ms opts)))
                  (:since-ms opts) (assoc "since_ms" (str (:since-ms opts)))
                  sub-param (assoc "subnets" sub-param))
         q-str (str/join "&" (map (fn [[k v]] (str (java.net.URLEncoder/encode (name k) StandardCharsets/UTF_8)
                                                   "="
                                                   (java.net.URLEncoder/encode (str v) StandardCharsets/UTF_8)))
                                  params))
         req (cond-> (HttpRequest/newBuilder)
               true (.uri (URI/create (str base-url "?" q-str)))
               true (.header "X-Bitecho-Pubkey" pk-hex)
               true (.header "X-Bitecho-Since-Seq" (str since-seq))
               true (.header "X-Bitecho-Since-Broadcast-Seq" (str bseq))
               true (.header "X-Bitecho-Timestamp-Ms" (str now-ms))
               true (.header "X-Bitecho-Nonce" nonce)
               true (.header "X-Bitecho-Signature" sig)
               (some? wait-ms) (.header "X-Bitecho-Wait-Ms" (str wait-ms))
               sub-param (.header "X-Bitecho-Subnets" sub-param)
               true (.timeout (Duration/ofMillis (long (+ (or (:timeout-ms opts) 0) 5000))))
               true (.GET)
               true (.build))]
     (try
       (let [resp (.send client req (HttpResponse$BodyHandlers/ofString))]
         (try
           (json/read-str (.body resp))
           (catch Exception _
             {"ok" false "error" "invalid-json-response" "status" (.statusCode resp)})))
       (catch Exception e
         {"ok" false "error" (.getMessage e)})))))

(defn ack-relay-envelopes!
  "Acknowledges envelopes processed up to `up-to-seq` at `relay-url`."
  ([relay-url pubkey privkey up-to-seq]
   (ack-relay-envelopes! relay-url pubkey privkey up-to-seq nil))
  ([relay-url pubkey privkey up-to-seq opts]
   (let [client (or (:http-client opts) (default-http-client))
         url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/ack")
         pk-hex (if (bytes? pubkey) (basalt/bytes->hex pubkey) (str pubkey))
         now-ms (System/currentTimeMillis)
         ack-seq (long (or up-to-seq 0))
         ack-bseq (or (:ack-broadcast-seq opts) (:ack_broadcast_seq opts))
         nonce (or (:nonce opts) (basalt/bytes->hex (crypto/random-bytes 16)))
         sig (relay/sign-poll-request privkey {:pubkey pk-hex
                                               :since-seq ack-seq
                                               :timestamp-ms now-ms
                                               :nonce nonce})
         payload-map (cond-> {"pubkey" pk-hex
                              "sig" sig
                              "signature" sig
                              "ts" now-ms
                              "timestamp_ms" now-ms
                              "nonce" nonce
                              "ack_seq" ack-seq
                              "up_to_seq" ack-seq}
                       ack-bseq (assoc "ack_broadcast_seq" (long ack-bseq)
                                       "ack-broadcast-seq" (long ack-bseq)))
         payload (json/write-str payload-map)
         req (cond-> (HttpRequest/newBuilder)
               true (.uri (URI/create url))
               true (.header "Content-Type" "application/json")
               true (.header "X-Bitecho-Pubkey" pk-hex)
               true (.header "X-Bitecho-Ack-Seq" (str ack-seq))
               true (.header "X-Bitecho-Timestamp-Ms" (str now-ms))
               true (.header "X-Bitecho-Nonce" nonce)
               true (.header "X-Bitecho-Signature" sig)
               ack-bseq (.header "X-Bitecho-Ack-Broadcast-Seq" (str ack-bseq))
               true (.timeout (Duration/ofMillis (long (or (:timeout-ms opts) 5000))))
               true (.POST (HttpRequest$BodyPublishers/ofString payload StandardCharsets/UTF_8))
               true (.build))]
     (try
       (let [resp (.send client req (HttpResponse$BodyHandlers/ofString))]
         (try
           (json/read-str (.body resp))
           (catch Exception _
             {"ok" false "error" "invalid-json-response" "status" (.statusCode resp)})))
       (catch Exception e
         {"ok" false "error" (.getMessage e)})))))

(defn fetch-relay-chain-state!
  "Fetches chain-state and bootstrap info from `relay-url`."
  ([relay-url]
   (fetch-relay-chain-state! relay-url nil))
  ([relay-url opts]
   (let [client (or (:http-client opts) (default-http-client))
         base-url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/chain-state")
         q-parts (cond-> []
                   (:pubkey opts) (conj (str "pubkey=" (java.net.URLEncoder/encode (str (:pubkey opts)) StandardCharsets/UTF_8)))
                   (:nonce opts) (conj (str "nonce=" (java.net.URLEncoder/encode (str (:nonce opts)) StandardCharsets/UTF_8))))
         url (if (seq q-parts)
               (str base-url "?" (str/join "&" q-parts))
               base-url)
         req (-> (HttpRequest/newBuilder)
                 (.uri (URI/create url))
                 (.timeout (Duration/ofMillis (long (or (:timeout-ms opts) 12000))))
                 (.GET)
                 (.build))]
     (try
       (let [resp (.send client req (HttpResponse$BodyHandlers/ofString))]
         (try
           (json/read-str (.body resp))
           (catch Exception _
             {"ok" false "error" "invalid-json-response" "status" (.statusCode resp)})))
       (catch Exception e
         {"ok" false "error" (.getMessage e)})))))

(defn query-validator-chain-state!
  "Dials a single validator node over Port 5010/DTLS, sends :query-chain-state,
   awaits and returns the signed :chain-state-snapshot map (or nil on timeout/error)."
  [identity node pubkey privkey-bytes opts]
  (let [query-ice-creds (identity/generate-random-ice-creds)
        turn-cfg (or (:turn-config opts) (:turn-config node))
        client-node (api/create-node (cond-> {:port 0
                                              :cert-data (:cert-data identity)
                                              :ice-creds query-ice-creds
                                              :setup "active"}
                                       turn-cfg (assoc :turn-config turn-cfg)
                                       (some? (:use-turn-relay? opts))
                                       (assoc :use-turn-relay? (boolean (:use-turn-relay? opts)))
                                       (and (nil? (:use-turn-relay? opts)) (some? (:use-turn-relay? turn-cfg)))
                                       (assoc :use-turn-relay? (boolean (:use-turn-relay? turn-cfg)))
                                       (and (nil? (:use-turn-relay? opts)) (nil? (:use-turn-relay? turn-cfg)) (true? (:force-relay? turn-cfg)))
                                       (assoc :use-turn-relay? true)))
        snapshot-promise (promise)
        nonce (or (:nonce opts) (str (System/currentTimeMillis) "-" (java.util.UUID/randomUUID)))
        transport (or (:transport opts) :datachannel)
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
                     (assoc :proxy (or (:proxy opts) (resolve-proxy-url nil))))
        callbacks {:on-open
                   (fn [evt]
                     (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)
                           signer-pk (or (:pubkey-hex identity) (:pubkey identity) pubkey)
                           query-env (light-core/build-chain-state-query-envelope signer-pk privkey-bytes {:nonce nonce :target-pubkey pubkey})
                           frozen (fressian/encode-wire query-env)]
                       (try
                         (api/send! client-node frozen cid)
                         (catch Exception _
                           (deliver snapshot-promise nil)))))
                   :on-message
                   (fn [evt]
                     (try
                       (let [payload (:payload evt)
                             msg (if (bytes? payload) (fressian/decode-wire payload) (fressian/strip-untrusted-crypto-tags payload))]
                         (when (and (map? msg) (= :chain-state-snapshot (or (:bitecho/type msg) (:type msg))))
                           (deliver snapshot-promise msg)))
                       (catch Exception _ nil)))
                   :on-error
                   (fn [_] (deliver snapshot-promise nil))
                   :on-close
                   (fn [_] (deliver snapshot-promise nil))}]
    (try
      (if (or (= transport :tcp) (= transport :connect))
        (api/start-tcp! client-node remote-sdp callbacks)
        (do
          (api/start! client-node remote-sdp callbacks)
          (configure-udp-receive-buffer! client-node)))
      (api/set-max-message-size! client-node)
      (let [timeout-ms (long (or (:timeout-ms opts) 4000))]
        (try
          (deref snapshot-promise timeout-ms nil)
          (catch InterruptedException _ nil)))
      (catch Exception _ nil)
      (finally
        (try (api/close! client-node) (catch Exception _ nil))))))

(defn fetch-directory-descriptor!
  "Fetches and parses a directory descriptor for nickname under domain.
   Supports qualified `<domain>/<nickname>` strings (`P-SOAK-2`).
   Supports injectable (:directory-fetcher opts) (fn [domain nickname] ...) for deterministic testing.
   Over HTTP/HTTPS, fetches https://<domain>/directory/<nickname>.json (falling back to https://<domain>/<nickname>),
   and parses via light-core/parse-directory-descriptor-text."
  ([domain nickname] (fetch-directory-descriptor! domain nickname nil))
  ([domain nickname opts]
   (let [raw-nick (str/trim (str (or nickname "")))
         slash-idx (.lastIndexOf raw-nick "/")
         [eff-domain eff-nick] (if (pos? slash-idx)
                                 [(subs raw-nick 0 slash-idx)
                                  (subs raw-nick (inc slash-idx))]
                                 [domain raw-nick])]
     (if-let [custom-fetcher (:directory-fetcher opts)]
       (try
         (let [res (or (custom-fetcher eff-domain eff-nick)
                       (when (not= raw-nick eff-nick)
                         (custom-fetcher domain raw-nick)))]
           (cond
             (map? res) res
             (string? res) (light-core/parse-directory-descriptor-text res)
             :else nil))
         (catch Exception _ nil))
       (let [dom (if (or (nil? eff-domain) (str/blank? eff-domain)) "bitecho.org" (str/trim eff-domain))
             net-uri (or (:network-uri opts) "bitecho.org")
             url-v1 (str "https://" dom "/directory/v1/" net-uri "/" eff-nick)
             url1 (str "https://" dom "/directory/" eff-nick ".json")
             url2 (str "https://" dom "/" eff-nick)
             local-f1 (io/file "devnet/directory" (str eff-nick ".json"))
             client (or (:http-client opts) (default-http-client))
             fetch-url (fn [^String u]
                         (try
                           (let [req (-> (HttpRequest/newBuilder)
                                         (.uri (URI/create u))
                                         (.timeout (Duration/ofMillis 4000))
                                         (.GET)
                                         (.build))
                                 resp (.send client req (HttpResponse$BodyHandlers/ofString))]
                             (when (= 200 (.statusCode resp))
                               (.body resp)))
                           (catch Exception _ nil)))]
         (or (if-let [body-v1 (fetch-url url-v1)]
               (light-core/parse-directory-descriptor-text body-v1)
               (if-let [body1 (fetch-url url1)]
                 (light-core/parse-directory-descriptor-text body1)
                 (when-let [body2 (fetch-url url2)]
                   (light-core/parse-directory-descriptor-text body2))))
             (when (.exists local-f1)
               (light-core/parse-directory-descriptor-text (slurp local-f1)))))))))

(defn fetch-inband-chain-state-quorum!
  "Fetches chain state snapshots from validators in parallel, cross-checking via verify-chain-state-quorum.
   Supports injectable (:inband-snapshot-fetcher opts) for deterministic testing.
   Returns {:ok? true :snapshot agreed-snap :quorum-count n :validators [...]} or {:ok? false :error <reason>}."
  [identity bootstrap pubkey privkey-bytes opts]
  (if-let [fetcher (:inband-snapshot-fetcher opts)]
    (let [res (fetcher pubkey)]
      (if (and (map? res) (contains? res :ok?) (false? (:ok? res)))
        res
        (let [snaps (if (map? res) (or (:snapshots res) [res]) res)
              trusted (set (keep :pubkey (vals (:nodes bootstrap))))
              q-opts (assoc opts
                            :expected-pubkey pubkey
                            :trusted-validators trusted
                            :min-finalized-epoch (long (or (:min-finalized-epoch opts) 0)))]
          (if (empty? snaps)
            {:ok? false :error "no-inband-snapshots-returned"}
            (light-core/verify-chain-state-quorum snaps q-opts)))))
    (let [nodes (vals (:nodes bootstrap))]
      (if (empty? nodes)
        {:ok? false :error "empty-bootstrap-nodes"}
        (let [timeout-ms (long (or (:timeout-ms opts) 2500))
              nonce (str (System/currentTimeMillis) "-" (java.util.UUID/randomUUID))
              q-opts (assoc opts :timeout-ms timeout-ms :nonce nonce)
              snaps (->> nodes
                         (pmap (fn [node]
                                 (try
                                   (query-validator-chain-state! identity node pubkey privkey-bytes q-opts)
                                   (catch Exception _ nil))))
                         (filterv some?))
              trusted (set (keep :pubkey nodes))
              verify-opts (assoc opts
                                 :expected-pubkey pubkey
                                 :expected-nonce nonce
                                 :trusted-validators trusted
                                 :min-finalized-epoch (long (or (:min-finalized-epoch opts) 0)))]
          (if (empty? snaps)
            {:ok? false :error "no-inband-snapshots-returned"}
            (light-core/verify-chain-state-quorum snaps verify-opts)))))))

(defn- infer-bootstrap-relay-url
  [bootstrap opts]
  (when (and (nil? (:inband-snapshot-fetcher opts))
             (nil? (:accountz-fetcher opts))
             (not (false? (:use-relay-fast-path? opts))))
    (let [u (or (:relay-url bootstrap)
                (get-in bootstrap [:relay :url])
                (first (:https-relay-urls bootstrap))
                (when (some #(contains? #{"35.212.172.159" "35.209.253.119" "35.211.30.106"} (:ip %))
                            (vals (:nodes bootstrap)))
                  "https://ns1.bitecho.org"))]
      (when (and (string? u) (not (str/blank? u)))
        u))))

(defn maybe-sync-account-state!
  "Attempts fast HTTPS `/relay/v1/chain-state` 2f+1 quorum verification first when a relay URL is configured
   or present on `bootstrap` (`P-NET-1`), falling back to in-band validator quorum sync over Port 5010/DTLS
   via `fetch-inband-chain-state-quorum!`.
   If quorum verification succeeds, updates state-atom and returns {:ok? true :state @state-atom :quorum-result q-res}."
  [state-atom bootstrap pubkey privkey-bytes opts]
  (if (and (string? (:relay-url opts)) (not (str/blank? (:relay-url opts))))
    (let [nonce (str (System/currentTimeMillis) "-" (java.util.UUID/randomUUID))
          relay-resp (fetch-relay-chain-state! (:relay-url opts) {:pubkey pubkey :nonce nonce :timeout-ms (:timeout-ms opts)})
          raw-snaps (or (get relay-resp "snapshots") (get relay-resp :snapshots) [])
          signed-snaps (filterv #(or (get % "signature") (get % :signature)) raw-snaps)]
      (if (seq signed-snaps)
        (let [trusted (set (keep :pubkey (vals (:nodes bootstrap))))
              verify-opts (assoc opts
                                 :expected-pubkey pubkey
                                 :expected-nonce nonce
                                 :trusted-validators trusted
                                 :min-finalized-epoch (long (or (:min-finalized-epoch opts) 0)))
              q-res (light-core/verify-chain-state-quorum signed-snaps verify-opts)]
          (if (:ok? q-res)
            (do
              (swap! state-atom (fn [st] (light-core/apply-verified-chain-state-snapshot st (:snapshot q-res))))
              {:ok? true :state @state-atom :quorum-result q-res})
            (do
              (swap! state-atom update-in [:diagnostics :chain-state-sync-failed] (fnil inc 0))
              {:ok? false :error (:error q-res)})))
        (do
          (swap! state-atom update-in [:diagnostics :chain-state-sync-failed] (fnil inc 0))
          {:ok? false :error (or (when-not (or (true? (get relay-resp "ok")) (true? (get relay-resp :ok)))
                                   (or (get relay-resp "error") (get relay-resp :error)))
                                 "no-verified-relay-snapshots")})))
    (let [fast-relay-url (infer-bootstrap-relay-url bootstrap opts)
          fast-res (when fast-relay-url
                     (try
                       (let [nonce (str (System/currentTimeMillis) "-" (java.util.UUID/randomUUID))
                             relay-resp (fetch-relay-chain-state! fast-relay-url {:pubkey pubkey :nonce nonce :timeout-ms (or (:timeout-ms opts) 3000)})
                             raw-snaps (or (get relay-resp "snapshots") (get relay-resp :snapshots) [])
                             signed-snaps (filterv #(or (get % "signature") (get % :signature)) raw-snaps)]
                         (when (seq signed-snaps)
                           (let [trusted (set (keep :pubkey (vals (:nodes bootstrap))))
                                 verify-opts (assoc opts
                                                    :expected-pubkey pubkey
                                                    :expected-nonce nonce
                                                    :trusted-validators trusted
                                                    :min-finalized-epoch (long (or (:min-finalized-epoch opts) 0)))
                                 q-res (light-core/verify-chain-state-quorum signed-snaps verify-opts)]
                             (when (:ok? q-res)
                               (swap! state-atom (fn [st] (light-core/apply-verified-chain-state-snapshot st (:snapshot q-res))))
                               {:ok? true :state @state-atom :quorum-result q-res}))))
                       (catch Exception _ nil)))]
      (if (:ok? fast-res)
        fast-res
        (let [id (or (:identity opts) {:pubkey-hex pubkey :privkey-bytes privkey-bytes})
              inband-res (fetch-inband-chain-state-quorum! id bootstrap pubkey privkey-bytes opts)]
          (cond
            (:ok? inband-res)
            (let [snap (:snapshot inband-res)]
              (swap! state-atom (fn [st] (light-core/apply-verified-chain-state-snapshot st snap)))
              {:ok? true :state @state-atom :quorum-result inband-res})

            (and (or (:auto-relay-fallback? opts)
                     (:relay-url bootstrap)
                     (get-in bootstrap [:relay :url]))
                 (not (:relay-url opts)))
            (let [fallback-url (or (:relay-url bootstrap)
                                   (get-in bootstrap [:relay :url])
                                   "https://bitecho.org/relay/v1")]
              (maybe-sync-account-state! state-atom bootstrap pubkey privkey-bytes (assoc opts :relay-url fallback-url)))

            (and (not= (:error inband-res) "no-inband-snapshots-returned")
                 (not= (:error inband-res) "empty-bootstrap-nodes"))
            {:ok? false :error (:error inband-res)}

            (:accountz-fetcher opts)
            (if-let [resp ((:accountz-fetcher opts) bootstrap pubkey opts)]
              (if (:account resp)
                (let [cmd {"cmd" "sync-account"
                           "balance" (get-in resp [:account :balance] 0)
                           "spendable" (:spendable resp)
                           "seq" (get-in resp [:account :seq] 0)
                           "deps" (vec (get-in resp [:account :deps] []))
                           "finalized_epoch" (:finalized-epoch resp 0)}
                      res (light-core/handle-command @state-atom cmd privkey-bytes)]
                  (reset! state-atom (:state res))
                  {:ok? true :state @state-atom :accountz resp})
                {:ok? false :error "no-account-in-accountz"})
              {:ok? false :error "accountz-fetcher-returned-nil"})

            :else
            (let [err (or (:error inband-res) "no-inband-snapshots-returned")]
              (swap! state-atom (fn [st]
                                  (-> st
                                      (update-in [:diagnostics :account-sync-inband-failed] (fnil inc 0))
                                      (update-in [:diagnostics :chain-state-sync-failed] (fnil inc 0)))))
              {:synced false :ok? false :reason err :error err})))))))

(defn init-conn-state
  "Initializes the pure single-authority connection lifecycle state map."
  []
  {:generation 0
   :phase :down
   :ok? false
   :channel-id nil
   :send-fn nil
   :node nil
   :error nil
   :last-error nil
   :dropped 0
   :ignored-stale 0
   :consecutive-send-failures 0
   :validator-id nil
   :validator-cursor 0
   :failover-count 0
   :diagnostics []})

(defn- push-diagnostic
  "Appends a diagnostic effect to conn's pure :diagnostics vector (capped at 64 entries)
   and sets :last-diagnostic."
  [conn eff]
  (-> conn
      (assoc :last-diagnostic eff)
      (update :diagnostics (fn [ds] (vec (take-last 64 (conj (vec ds) eff)))))))

(defn transition-conn
  "Pure reducer transitioning connection lifecycle state and returning [new-conn effects].
   Phases: :down, :dialing, :open, :closing, :failed.
   Ignores stale generation callbacks (< (:generation event) (:generation conn)) without mutating connection phase, liveness, or active resources, incrementing only :ignored-stale."
  [conn event]
  (let [conn (merge (init-conn-state) conn)]
    (if (and (contains? event :generation)
             (some? (:generation event))
             (< (:generation event) (:generation conn 0)))
      (let [eff {:effect :ignore-stale :generation (:generation event)}]
        [(-> conn
             (update :ignored-stale (fnil inc 0))
             (push-diagnostic eff))
         [eff]])
      (case (:type event)
        :dial-started
        (let [next-gen (long (or (:generation event) (inc (:generation conn 0))))
              node-to-close (:node conn)
              effects (if node-to-close
                        [{:effect :close-node :node node-to-close :generation (:generation conn 0)}]
                        [])
              new-conn (assoc conn
                              :generation next-gen
                              :phase :dialing
                              :ok? false
                              :channel-id nil
                              :send-fn nil
                              :node nil
                              :error nil)]
          [new-conn effects])

        :dial-ok
        (let [node-to-close (:node conn)
              target-gen (long (or (:generation event) (:generation conn 0)))
              failed-nodes (vec (or (:failed-nodes event) []))
              failover-attempts (long (or (:failover-attempts event) (count failed-nodes)))
              failed-drop-count (long (count failed-nodes))
              diag-effects (mapv (fn [fn-info]
                                   {:effect :diagnose
                                    :reason :dial-failover
                                    :validator-id (:validator-id fn-info)
                                    :error (or (:error fn-info) "listener-disabled")})
                                 failed-nodes)
              effects (cond-> (if (and node-to-close (not= node-to-close (:node event)))
                                [{:effect :close-node :node node-to-close :generation (:generation conn 0)}]
                                [])
                        (seq diag-effects) (into diag-effects))
              new-conn (-> (assoc conn
                                  :generation target-gen
                                  :phase :open
                                  :ok? true
                                  :channel-id (:channel-id event)
                                  :send-fn (:send-fn event)
                                  :node (:node event)
                                  :validator-id (:validator-id event)
                                  :failover-count (+ (long (:failover-count conn 0)) failover-attempts)
                                  :dropped (+ (long (:dropped conn 0)) failed-drop-count)
                                  :consecutive-send-failures 0
                                  :error nil)
                           (as-> c (reduce push-diagnostic c diag-effects)))]
          [new-conn effects])

        :dial-failed
        (let [err (or (:error event) "listener-disabled")
              node-to-close (or (:node event) (:node conn))
              diag-eff {:effect :diagnose :reason :dial-failed :error err}
              effects (cond-> []
                        node-to-close (conj {:effect :close-node :node node-to-close :generation (:generation conn 0)})
                        true (conj diag-eff))
              new-conn (-> conn
                           (assoc :phase :failed
                                  :ok? false
                                  :channel-id nil
                                  :send-fn nil
                                  :node nil
                                  :validator-id nil
                                  :validator-cursor (inc (long (:validator-cursor conn 0)))
                                  :error err
                                  :last-error err
                                  :dropped (inc (:dropped conn 0)))
                           (push-diagnostic diag-eff))]
          [new-conn effects])

        :on-close
        (let [err (or (:error event) "connection-closed")
              node-to-close (:node conn)
              diag-eff {:effect :diagnose :reason :on-close :error err}
              effects (cond-> []
                        node-to-close (conj {:effect :close-node :node node-to-close :generation (:generation conn 0)})
                        true (conj diag-eff))
              new-conn (-> conn
                           (assoc :phase :failed
                                  :ok? false
                                  :channel-id nil
                                  :send-fn nil
                                  :node nil
                                  :validator-id nil
                                  :validator-cursor (inc (long (:validator-cursor conn 0)))
                                  :error err
                                  :last-error err)
                           (push-diagnostic diag-eff))]
          [new-conn effects])

        :encode-failed
        (let [err (or (:error event) "encode-failed")
              diag-eff {:effect :diagnose :reason :encode-failed :error err}
              new-conn (-> conn
                           (assoc :last-error err
                                  :dropped (inc (long (:dropped conn 0)))
                                  :consecutive-send-failures (inc (long (:consecutive-send-failures conn 0))))
                           (push-diagnostic diag-eff))]
          [new-conn [diag-eff]])

        :send-failed
        (let [err (or (:error event) "send-failed")
              node-to-close (:node conn)
              diag-eff {:effect :diagnose :reason :send-failed :error err}
              effects (cond-> []
                        node-to-close (conj {:effect :close-node :node node-to-close :generation (:generation conn 0)})
                        true (conj diag-eff))
              new-conn (-> conn
                           (assoc :phase :failed
                                  :ok? false
                                  :channel-id nil
                                  :send-fn nil
                                  :node nil
                                  :validator-id nil
                                  :validator-cursor (inc (long (:validator-cursor conn 0)))
                                  :error err
                                  :last-error err
                                  :dropped (inc (:dropped conn 0))
                                  :consecutive-send-failures (inc (long (:consecutive-send-failures conn 0))))
                           (push-diagnostic diag-eff))]
          [new-conn effects])

        :persist-failed
        (let [err (or (:error event) "persist-failed")
              diag-eff {:effect :diagnose :reason :persist-failed :error err}
              new-conn (-> conn
                           (assoc :last-error err
                                  :dropped (inc (long (:dropped conn 0))))
                           (push-diagnostic diag-eff))]
          [new-conn [diag-eff]])

        :legacy-nippy-snapshot-rejected
        (let [err (or (:error event) "legacy-nippy-snapshot-rejected")
              diag-eff {:effect :diagnose :reason :legacy-nippy-snapshot-rejected :error err}
              new-conn (-> conn
                           (assoc :last-error err
                                  :dropped (inc (long (:dropped conn 0))))
                           (push-diagnostic diag-eff))]
          [new-conn [diag-eff]])

        :auto-sync-failed
        (let [err (or (:error event) "auto-sync-failed")
              diag-eff {:effect :diagnose :reason :auto-sync-failed :error err}
              new-conn (-> conn
                           (assoc :last-error err)
                           (push-diagnostic diag-eff))]
          [new-conn [diag-eff]])

        :shutdown
        (let [node-to-close (:node conn)
              effects (if node-to-close
                        [{:effect :close-node :node node-to-close :generation (:generation conn 0)}]
                        [])
              new-conn (assoc conn
                              :phase :down
                              :ok? false
                              :channel-id nil
                              :send-fn nil
                              :node nil
                              :error nil)]
          [new-conn effects])

        [conn []]))))

(defn execute-conn-effects!
  "Executes boundary side-effects resulting from connection state machine transitions.
   Handles :close-node, :diagnose, and :ignore-stale effects."
  ([effects]
   (execute-conn-effects! effects nil))
  ([effects opts]
   (doseq [eff effects]
     (case (:effect eff)
       :close-node
       (when-let [n (:node eff)]
         (try (api/close! n) (catch Exception _ nil)))

       (:diagnose :ignore-stale)
       (do
         (when-let [dfn (:diagnose-fn opts)]
           (when (fn? dfn)
             (try (dfn eff) (catch Exception _ nil))))
         (when-let [datom (:diagnostics-atom opts)]
           (when (instance? clojure.lang.IAtom datom)
             (swap! datom (fn [curr] (vec (take-last 64 (conj (vec curr) eff))))))))

       nil))))

(defn apply-conn-event!
  "Atomically transitions conn-atom via transition-conn, executes effects outside the swap, and returns @conn-atom."
  ([conn-atom event]
   (apply-conn-event! conn-atom event nil))
  ([conn-atom event opts]
   (let [effects-ref (atom [])]
     (swap! conn-atom (fn [conn]
                        (let [[new-conn effects] (transition-conn conn event)]
                          (reset! effects-ref effects)
                          new-conn)))
     (execute-conn-effects! @effects-ref opts)
     @conn-atom)))

(defn conn-diagnostics-summary
  "Constructs diagnostic summary map from a connection state map."
  [conn]
  (let [diag-count (count (or (:diagnostics conn) []))]
    (cond-> {:phase (name (or (:phase conn) :down))
             :generation (:generation conn 0)
             :last_error (:last-error conn)
             :dropped (:dropped conn 0)
             :ignored_stale (:ignored-stale conn 0)
             :consecutive_send_failures (:consecutive-send-failures conn 0)
             :validator_id (when-let [vid (:validator-id conn)] (name vid))
             :validator_cursor (:validator-cursor conn 0)
             :failover_count (:failover-count conn 0)
             :diagnostics_buffered (long diag-count)}
      (:last-diagnostic conn) (assoc :last_diagnostic (:last-diagnostic conn)))))

(defn- sync-conn-diagnostics!
  "Updates state-atom with connection liveness and conn-diagnostics summary."
  [state-atom conn-atom]
  (when (and state-atom conn-atom)
    (let [c @conn-atom
          diag (conn-diagnostics-summary c)]
      (swap! state-atom assoc
             :connected? (boolean (:ok? c))
             :connection-error (:error c)
             :conn-diagnostics diag))))

(defn- record-conn-diagnostic!
  "Records a connection-level diagnostic failure into state-atom under :diagnostics."
  [state-atom tag info]
  (when state-atom
    (swap! state-atom (fn [st]
                        (-> st
                            (update-in [:diagnostics tag] (fnil inc 0))
                            (assoc-in [:diagnostics :last-diagnostic] {:effect :diagnose :tag tag :info info}))))))

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
  "Checks if connection is marked ok and open, channel-id is present, and state is connected."
  [conn state]
  (and (boolean (:ok? conn))
       (or (nil? (:phase conn)) (= :open (:phase conn)))
       (not (false? (:connected? state)))
       (if-let [cid (:channel-id conn)]
         (if (instance? clojure.lang.IDeref cid)
           (some? @cid)
           (some? cid))
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
  [envelopes send-fn-atom state-atom conn-atom event-out reconnect-fn conn-opts]
  (let [live? (and @send-fn-atom (not (false? (:connected? @state-atom))))
        sent? (when live?
                (send-all-envelopes! @send-fn-atom envelopes))]
    (when-not sent?
      (if reconnect-fn
        (let [reconn (reconnect-fn)]
          (when-not (and (:ok? reconn)
                         (send-all-envelopes! (:send-fn reconn) envelopes))
            (let [err (or (:error reconn) "connection-closed")]
              (when conn-atom
                (apply-conn-event! conn-atom {:type :send-failed :error err} conn-opts))
              (when state-atom
                (swap! state-atom assoc :connected? false :connection-error err))
              (sync-conn-diagnostics! state-atom conn-atom)
              (when event-out
                (event-out {"event" "connection-failed" "connected" false "error" err})))))
        (let [err "connection-closed"]
          (when conn-atom
            (apply-conn-event! conn-atom {:type :send-failed :error err} conn-opts))
          (when state-atom
            (swap! state-atom assoc :connected? false :connection-error err))
          (sync-conn-diagnostics! state-atom conn-atom)
          (when event-out
            (event-out {"event" "connection-failed" "connected" false "error" err})))))))

(defn build-reconnect-recovery-envelopes
  "Pure helper to build recovery envelopes upon reconnection: re-registers home-set
   if present and replays unacknowledged session outbox gossip envelopes."
  [state privkey-bytes]
  (if-not privkey-bytes
    []
    (let [home-set (:home-set state)
          home-set-envs (if (seq home-set)
                          (let [price (long (or (get-in state [:rendezvous-policy :price]) 10))
                                pub (:pubkey state)
                                curr-epoch (:epoch state)
                                ice-ufrag (get-in state [:ice-creds :ufrag])
                                ice-pwd (get-in state [:ice-creds :pwd])
                                env-curr (agent-sim/build-home-set-envelope pub privkey-bytes home-set price curr-epoch ice-ufrag ice-pwd)
                                env-nil (agent-sim/build-home-set-envelope pub privkey-bytes home-set price nil ice-ufrag ice-pwd)]
                            [env-curr env-nil])
                          [])
          replay-envs (light-core/build-unacked-replay-envelopes state privkey-bytes)]
      (into (vec home-set-envs) replay-envs))))

(defn attempt-proactive-reconnect!
  "Attempts reconnect-fn up to max-attempts times with bounded exponential backoff until successful or exhausted."
  [reconnect-fn opts]
  (let [max-attempts (long (or (:reconnect-max-attempts opts) 3))
        backoff-ms (long (or (:reconnect-backoff-ms opts) 0))]
    (loop [attempt 0]
      (let [res (reconnect-fn)]
        (if (or (:ok? res) (>= (inc attempt) max-attempts))
          res
          (do
            (when (pos? backoff-ms)
              (let [sleep-ms (min (* backoff-ms (long (Math/pow 2 attempt))) 10000)]
                (try (Thread/sleep sleep-ms) (catch Exception _ nil))))
            (recur (inc attempt))))))))

(defn make-client-callbacks
  "Creates callback handlers for client DataChannel connection."
  [client-node channel-id connected? send-fn-atom ctx]
  (let [{:keys [identity state-atom conn-atom event-out reconnect-fn generation diagnostics-atom diagnose-fn state-file]} ctx
        cb-opts (cond-> {}
                  diagnostics-atom (assoc :diagnostics-atom diagnostics-atom)
                  diagnose-fn (assoc :diagnose-fn diagnose-fn))]
    {:on-open (fn [evt]
                (if (and conn-atom (some? generation) (< generation (:generation @conn-atom 0)))
                  (do
                    (apply-conn-event! conn-atom {:type :on-open :generation generation} cb-opts)
                    (sync-conn-diagnostics! state-atom conn-atom))
                  (do
                    (if-let [cid (:channel-id evt)]
                      (reset! channel-id cid)
                      (reset! channel-id (api/create-data-channel! client-node "bitecho" {:ordered true})))
                    (deliver connected? true))))
     :on-message (fn [evt]
                   (if (and conn-atom (some? generation) (< generation (:generation @conn-atom 0)))
                     (do
                       (apply-conn-event! conn-atom {:type :on-message :generation generation} cb-opts)
                       (sync-conn-diagnostics! state-atom conn-atom))
                     (do
                       (when-let [cid (:channel-id evt)]
                         (reset! channel-id cid))
                       (when-let [payload (:payload evt)]
                         (when-let [on-msg (:on-message ctx)]
                           (try (on-msg payload) (catch Exception _ nil)))
                         (when state-atom
                           (let [lock-obj (or (:cmd-lock ctx) state-atom)
                                 res (locking lock-obj
                                       (let [st @state-atom
                                             r (light-core/handle-wire-payload st payload (:privkey-bytes identity))]
                                         (reset! state-atom (:state r))
                                         (when (and state-file (not= st (:state r)))
                                           (try
                                             (save-light-state! state-file (:state r))
                                             (catch Exception e
                                               (when conn-atom
                                                 (apply-conn-event! conn-atom
                                                                    {:type :persist-failed
                                                                     :error (or (.getMessage e) "persist-failed")}
                                                                    cb-opts)
                                                 (sync-conn-diagnostics! state-atom conn-atom)))))
                                         r))]
                             (when (and event-out (seq (:stdout-events res)))
                               (doseq [ev (:stdout-events res)]
                                 (event-out ev)))
                             (when-let [dial-info (:p2p-dial res)]
                               (dial-p2p-peer! state-atom (:p2p-peers-atom ctx) (:ingress-peers-atom ctx) (:mdns-atom ctx) (:privkey-bytes identity) event-out dial-info))
                             (when (seq (:net-envelopes res))
                               (if (some #(or (:p2p-direct? %) (:p2p-broadcast? %)) (:net-envelopes res))
                                 (send-routed-envelopes! (:net-envelopes res) send-fn-atom (:p2p-peers-atom ctx) (:ingress-peers-atom ctx) state-atom (:privkey-bytes identity))
                                 (dispatch-auto-reply! (:net-envelopes res) send-fn-atom state-atom conn-atom event-out reconnect-fn cb-opts)))))))))
     :on-error (fn [evt]
                 (when (str/includes? (str (:message evt)) "Fingerprint")
                   (deliver connected? :bad-fingerprint)))
     :on-close (fn [_]
                 (if conn-atom
                   (if (and (some? generation)
                            (pos? (:generation @conn-atom 0))
                            (not= generation (:generation @conn-atom)))
                     (do
                       (apply-conn-event! conn-atom {:type :on-close :generation generation} cb-opts)
                       (sync-conn-diagnostics! state-atom conn-atom))
                     (let [curr-conn @conn-atom
                           already-closed-this-gen? (and (or (nil? generation)
                                                             (= (long generation) (long (:generation curr-conn 0))))
                                                         (contains? #{:failed :down} (:phase curr-conn)))]
                       (when (instance? clojure.lang.Atom channel-id)
                         (reset! channel-id nil))
                       (when-not already-closed-this-gen?
                         (apply-conn-event! conn-atom
                                            (cond-> {:type :on-close}
                                              (some? generation) (assoc :generation generation))
                                            cb-opts)
                         (when state-atom
                           (swap! state-atom assoc :connected? false :connection-error "connection-closed"))
                         (sync-conn-diagnostics! state-atom conn-atom)
                         (when (and reconnect-fn (not= :down (:phase @conn-atom)))
                           (if (:async-reconnect? ctx)
                             (future (attempt-proactive-reconnect! reconnect-fn ctx))
                             (attempt-proactive-reconnect! reconnect-fn ctx))))))
                   (do
                     (when (instance? clojure.lang.Atom channel-id)
                       (reset! channel-id nil))
                     (when state-atom
                       (swap! state-atom assoc :connected? false :connection-error "connection-closed")))))}))

(defn- dial-single-node!
  "Dials a single validator node via WebRTC DataChannel (UDP, TCP, or HTTP CONNECT proxy)."
  [identity node opts]
  (let [turn-cfg (or (:turn-config opts) (:turn-config node))
        client-node (api/create-node (cond-> {:port 0
                                              :cert-data (:cert-data identity)
                                              :ice-creds (:ice-creds identity)
                                              :setup "active"}
                                       turn-cfg (assoc :turn-config turn-cfg)
                                       (some? (:use-turn-relay? opts))
                                       (assoc :use-turn-relay? (boolean (:use-turn-relay? opts)))
                                       (and (nil? (:use-turn-relay? opts)) (some? (:use-turn-relay? turn-cfg)))
                                       (assoc :use-turn-relay? (boolean (:use-turn-relay? turn-cfg)))
                                       (and (nil? (:use-turn-relay? opts)) (nil? (:use-turn-relay? turn-cfg)) (true? (:force-relay? turn-cfg)))
                                       (assoc :use-turn-relay? true)))
        channel-id (atom nil)
        connected? (promise)
        send-fn-atom (atom nil)
        cb-opts (cond-> {}
                  (:diagnostics-atom opts) (assoc :diagnostics-atom (:diagnostics-atom opts))
                  (:diagnose-fn opts) (assoc :diagnose-fn (:diagnose-fn opts)))
        send-fn (fn [env]
                  (if-let [cid @channel-id]
                    (let [payload (try
                                    (if (bytes? env) env (fressian/encode-wire env))
                                    (catch Throwable t
                                      (let [err (str "encode-failed: " (or (.getMessage t) (.getSimpleName (class t))))]
                                        (when-let [ca (:conn-atom opts)]
                                          (apply-conn-event! ca {:type :encode-failed :error err} cb-opts)
                                          (sync-conn-diagnostics! (:state-atom opts) ca))
                                        nil)))]
                      (if (nil? payload)
                        false
                        (try
                          (api/send! client-node payload cid)
                          true
                          (catch Throwable t
                            (let [err (str "send-failed: " (or (.getMessage t) (.getSimpleName (class t))))]
                              (when-let [ca (:conn-atom opts)]
                                (apply-conn-event! ca {:type :send-failed :error err} cb-opts)
                                (sync-conn-diagnostics! (:state-atom opts) ca))
                              false)))))
                    false))
        _ (reset! send-fn-atom send-fn)
        callbacks (make-client-callbacks client-node channel-id connected? send-fn-atom
                                         {:identity identity
                                          :state-atom (:state-atom opts)
                                          :conn-atom (:conn-atom opts)
                                          :event-out (:event-out opts)
                                          :reconnect-fn (:reconnect-fn opts)
                                          :generation (:generation opts)
                                          :state-file (:state-file opts)
                                          :diagnostics-atom (:diagnostics-atom opts)
                                          :diagnose-fn (:diagnose-fn opts)
                                          :p2p-peers-atom (:p2p-peers-atom opts)
                                          :ingress-peers-atom (:ingress-peers-atom opts)
                                          :mdns-atom (:mdns-atom opts)
                                          :cmd-lock (:cmd-lock opts)
                                          :on-message (:on-message opts)})
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
        (api/set-max-message-size! client-node)
        (catch Exception _
          (deliver connected? :connect-failed)))
      (do
        (api/start! client-node remote-sdp callbacks)
        (configure-udp-receive-buffer! client-node)
        (api/set-max-message-size! client-node)))
    (Thread/interrupted)
    (let [timeout-ms (long (or (:timeout-ms opts) 8000))
          res (try
                (deref connected? timeout-ms :timeout)
                (catch InterruptedException _ :connect-failed))]
      (cond
        (= res :bad-fingerprint)
        (do (try (api/close! client-node) (catch Exception _ nil))
            {:ok? false :error "bad-fingerprint"})
        (or (= res :timeout) (= res :connect-failed))
        (do (try (api/close! client-node) (catch Exception _ nil))
            {:ok? false :error "listener-disabled"})
        :else
        {:ok? true
         :node client-node
         :channel-id channel-id
         :send-fn send-fn}))))

(defn connect-validators!
  "Establishes WebRTC DataChannel connections to validators in bootstrap-descriptor.
   Rotates through candidates using home-set priority and validator-cursor.
   Returns connection result or error map (:bad-fingerprint or :listener-disabled)."
  [identity bootstrap-descriptor opts]
  (if (and (string? (:relay-url opts)) (not (str/blank? (:relay-url opts))))
    {:ok? true
     :node nil
     :validator-id :http-relay
     :transport :http-relay
     :failover-attempts 0
     :failed-nodes []
     :send-fn (fn [env]
                (let [r (submit-relay-envelope! (:relay-url opts) env opts)]
                  (true? (get r "ok"))))}
    (if-let [err (validate-node-fingerprints bootstrap-descriptor)]
      err
      (if-let [dialer (:dialer-fn opts)]
        (dialer identity bootstrap-descriptor opts)
        (let [home-set (or (:home-set opts)
                           (when-let [sa (:state-atom opts)] (:home-set @sa)))
              cursor (or (:validator-cursor opts)
                         (when-let [ca (:conn-atom opts)] (:validator-cursor @ca 0))
                         0)
              candidates (ordered-validator-candidates bootstrap-descriptor home-set cursor)]
          (if (empty? candidates)
            {:ok? false :error "no-nodes-in-descriptor"}
            (loop [rem-candidates candidates
                   failed-nodes []]
              (if-let [node (first rem-candidates)]
                (let [res (dial-single-node! identity node opts)]
                  (cond
                    (:ok? res)
                    (assoc res
                           :validator-id (:node-id node)
                           :failover-attempts (count failed-nodes)
                           :failed-nodes failed-nodes)

                    :else
                    (recur (rest rem-candidates)
                           (conj failed-nodes {:validator-id (:node-id node)
                                               :error (or (:error res) "listener-disabled")}))))
                (let [fallback-url (when (or (:auto-relay-fallback? opts)
                                             (:relay-url bootstrap-descriptor)
                                             (get-in bootstrap-descriptor [:relay :url]))
                                     (or (:relay-url opts)
                                         (:relay-url bootstrap-descriptor)
                                         (get-in bootstrap-descriptor [:relay :url])
                                         "https://bitecho.org/relay/v1"))]
                  (if fallback-url
                    (connect-validators! identity bootstrap-descriptor (assoc opts :relay-url fallback-url))
                    {:ok? false
                     :error (if (some #(= (:error %) "bad-fingerprint") failed-nodes)
                              "bad-fingerprint"
                              "listener-disabled")
                     :failed-nodes failed-nodes}))))))))))

;; -----------------------------------------------------------------------------
;; CLI Runner (Serve, Wait-Event & One-Shot Modes)
;; -----------------------------------------------------------------------------

(defonce ^:private events-out-write-lock (Object.))

(def waitable-event-types
  "Set of incoming asynchronous event types eligible to wake `wait-event`."
  #{"message-received" "offer-received" "channel-opened" "session-established"
    "rendezvous-header-received" "rendezvous-reveal-received"
    "p2p-offer-received" "p2p-connected" "broadcast-received"})

(defn event-matches-wait-filter?
  "Pure predicate checking whether an emitted JSON event map satisfies a `wait-event` filter."
  [evt opts]
  (if-not (map? evt)
    false
    (let [ev-type (or (get evt "event") (some-> (:event evt) name))
          waitable? (contains? waitable-event-types ev-type)
          target-sid (:session-id opts)
          ev-sid (or (get evt "session_id") (get evt "session-id") (:session-id evt) (:session_id evt))
          target-subnet (or (:subnet-id opts) (:subnet opts))
          ev-subnet (or (get evt "subnet_id") (get evt "subnet-id") (:subnet-id evt) (:subnet_id evt))
          min-seq (:min-seq opts)
          raw-seq (or (get evt "seq") (:seq evt))
          ev-seq (when (some? raw-seq)
                   (try (Long/parseLong (str raw-seq)) (catch Exception _ nil)))
          min-bseq (:min-broadcast-seq opts)
          raw-bseq (or (get evt "broadcast_seq") (get evt "broadcast-seq") (:broadcast-seq evt) (:broadcast_seq evt))
          ev-bseq (when (some? raw-bseq)
                    (try (Long/parseLong (str raw-bseq)) (catch Exception _ nil)))
          after-ts (:after-ts opts)
          raw-ts (or (get evt "timestamp_ms") (:timestamp-ms evt) (:timestamp_ms evt))
          ev-ts (if (some? raw-ts)
                  (try (Long/parseLong (str raw-ts)) (catch Exception _ 0))
                  0)
          sid-ok? (or (nil? target-sid) (= (str ev-sid) (str target-sid)))
          subnet-ok? (or (nil? target-subnet) (= (str ev-subnet) (str target-subnet)))
          seq-ok? (or (nil? min-seq)
                      (and (some? ev-seq) (>= (long ev-seq) (long min-seq))))
          bseq-ok? (or (nil? min-bseq)
                       (and (some? ev-bseq) (>= (long ev-bseq) (long min-bseq))))
          ts-ok? (or (nil? after-ts) (> (long ev-ts) (long after-ts)))]
      (boolean (and waitable? sid-ok? subnet-ok? seq-ok? bseq-ok? ts-ok?)))))

(defn append-event-jsonl!
  "Appends a single JSON object line to events-out-path with a monotonic timestamp_ms field."
  [events-out-path data]
  (when (and (some? events-out-path) (not (str/blank? (str events-out-path))) (map? data))
    (locking events-out-write-lock
      (let [f (io/file events-out-path)
            parent (.getParentFile f)
            _ (when parent (.mkdirs parent))
            enriched (if (or (contains? data "timestamp_ms") (contains? data :timestamp-ms))
                       data
                       (assoc data "timestamp_ms" (System/currentTimeMillis)))]
        (spit f (str (json/write-str enriched) "\n") :append true)))))

(defn- emit-json-line!
  "Writes a data object as a JSON line to the dedicated print writer, and optionally mirrors to events-out-path."
  ([^PrintWriter writer data]
   (emit-json-line! writer data nil))
  ([^PrintWriter writer data events-out-path]
   (when writer
     (.println writer ^String (json/write-str data))
     (.flush writer))
   (when events-out-path
     (try (append-event-jsonl! events-out-path data) (catch Exception _ nil)))))

(defn read-new-cmd-file-lines!
  "Reads newly appended complete UTF-8 lines or balanced JSON objects from cmd-file-path
   starting at byte offset. Returns {:lines [...] :next-offset <long>}."
  [cmd-file-path ^long offset]
  (let [f (io/file cmd-file-path)]
    (if-not (.exists f)
      {:lines [] :next-offset offset}
      (let [len (.length f)
            safe-off (if (< len offset) 0 offset)]
        (if (<= len safe-off)
          {:lines [] :next-offset safe-off}
          (with-open [raf (RandomAccessFile. f "r")]
            (.seek raf safe-off)
            (let [rem (int (- len safe-off))
                  buf (byte-array rem)
                  read-n (.read raf buf 0 rem)]
              (if (<= read-n 0)
                {:lines [] :next-offset safe-off}
                (let [last-nl (loop [idx (dec read-n)]
                                (cond
                                  (neg? idx) -1
                                  (= (aget buf idx) (byte 10)) idx
                                  :else (recur (dec idx))))
                      nl-consumed (if (neg? last-nl) 0 (inc last-nl))
                      nl-text (when (pos? nl-consumed)
                                (String. buf 0 nl-consumed StandardCharsets/UTF_8))
                      nl-lines (if nl-text
                                 (mapcat cli/split-jsonl-commands (str/split-lines nl-text))
                                 [])
                      trailing-len (- read-n nl-consumed)
                      trailing-text (when (pos? trailing-len)
                                      (String. buf nl-consumed trailing-len StandardCharsets/UTF_8))
                      trailing-cmds (when (seq trailing-text)
                                      (cli/split-jsonl-commands trailing-text))
                      trailing-consumed (if (seq trailing-cmds)
                                          (let [last-cmd (last trailing-cmds)
                                                last-idx (.lastIndexOf ^String trailing-text ^String last-cmd)]
                                            (if (>= last-idx 0)
                                              (let [sub (subs trailing-text 0 (+ last-idx (count last-cmd)))]
                                                (alength (.getBytes sub StandardCharsets/UTF_8)))
                                              0))
                                          0)
                      total-consumed (+ nl-consumed trailing-consumed)
                      all-lines (vec (concat nl-lines (when (pos? trailing-consumed) trailing-cmds)))]
                  (if (zero? total-consumed)
                    {:lines [] :next-offset safe-off}
                    {:lines (->> all-lines (map str/trim) (remove str/blank?) vec)
                     :next-offset (+ safe-off total-consumed)}))))))))))

(defn run-wait-event!
  "Blocks until a matching incoming event appears in --events-out (or <state-dir>/events.jsonl),
   writes the matched event JSON line to STDOUT, and returns {:ok? true :event evt}.
   When --min-seq or --after-ts is specified, scans existing lines first so between-turn arrivals are never missed.
   Returns {:ok? false :error \"timeout\"} on timeout."
  [opts]
  (let [state-dir (or (:state-dir opts) (str (System/getProperty "user.home") "/.bitecho/light-node"))
        events-path (or (:events-out opts) (str (io/file state-dir "events.jsonl")))
        timeout-ms (long (or (:timeout-ms opts) 300000))
        poll-ms (long (or (:poll-ms opts) 50))
        out-writer (or (:out-writer opts) (PrintWriter. System/out true))
        scan-from-start? (or (some? (:min-seq opts)) (some? (:min-broadcast-seq opts)) (some? (:after-ts opts)))
        f (io/file events-path)
        initial-offset (if (and (not scan-from-start?) (.exists f))
                         (.length f)
                         0)
        deadline (+ (System/currentTimeMillis) (max 1 timeout-ms))]
    (loop [offset initial-offset]
      (let [{:keys [lines next-offset]} (read-new-cmd-file-lines! events-path offset)
            matched (some (fn [line]
                            (let [parsed (try (json/read-str line) (catch Exception _ nil))]
                              (when (event-matches-wait-filter? parsed opts)
                                parsed)))
                          lines)]
        (cond
          matched
          (do
            (emit-json-line! out-writer matched)
            {:ok? true :event matched})

          (>= (System/currentTimeMillis) deadline)
          (let [err-resp {"ok" false "error" "timeout"}]
            (emit-json-line! out-writer err-resp)
            {:ok? false :error "timeout"})

          :else
          (do
            (try (Thread/sleep (min poll-ms (max 1 (- deadline (System/currentTimeMillis)))))
                 (catch InterruptedException _ nil))
            (recur next-offset)))))))

;; -----------------------------------------------------------------------------
;; P2P Direct Signaling & Transport Binding
;; -----------------------------------------------------------------------------

(defn build-p2p-link-bind-envelope
  "Builds and signs a :p2p-link-bind envelope proving peer pubkey and session identity."
  [sender-pub sender-priv sid]
  (let [norm-sender (light-core/normalize-pubkey-hex sender-pub)
        sig-str (str "bitecho-p2p-link-bind-v1|" norm-sender "|" sid)
        sig-bytes (crypto/sign sender-priv (fressian/utf8->bytes sig-str))]
    {:bitecho/type :p2p-link-bind
     :type :p2p-link-bind
     :sender norm-sender
     :session-id sid
     :signature (fressian/bytes->hex sig-bytes)}))

(defn verify-p2p-link-bind
  "Verifies a :p2p-link-bind message signature."
  [msg]
  (when (and (map? msg) (= :p2p-link-bind (or (:type msg) (:bitecho/type msg))))
    (let [sender (light-core/normalize-pubkey-hex (:sender msg))
          sid (:session-id msg)
          sig-hex (:signature msg)]
      (when (and sender sid sig-hex)
        (let [pub-bytes (try (basalt/hex->bytes sender) (catch Exception _ nil))
              sig-bytes (try (basalt/hex->bytes sig-hex) (catch Exception _ nil))
              sig-str (str "bitecho-p2p-link-bind-v1|" sender "|" sid)]
          (boolean
           (and pub-bytes sig-bytes
                (crypto/verify pub-bytes (fressian/utf8->bytes sig-str) sig-bytes))))))))

(defn route-net-envelope!
  "Routes an outgoing network envelope directly to P2P peer(s) or falls back to validator gossip."
  [env send-fn-atom p2p-peers-atom ingress-peers-atom state-atom privkey-bytes]
  (let [send-default! (fn []
                        (when-let [sfn (cond
                                         (instance? clojure.lang.IAtom send-fn-atom) @send-fn-atom
                                         (fn? send-fn-atom) send-fn-atom
                                         :else nil)]
                          (sfn env)))]
    (cond
      (:p2p-broadcast? env)
      (let [p2p-sends (keep :send-fn (vals (or (when p2p-peers-atom @p2p-peers-atom) {})))
            ingress-sends (vals (or (when ingress-peers-atom @ingress-peers-atom) {}))
            all-sends (concat p2p-sends ingress-sends)]
        (doseq [sfn all-sends]
          (try (sfn env) (catch Throwable _ nil)))
        (send-default!))

      (:p2p-direct? env)
      (let [norm-target (light-core/normalize-pubkey-hex (:p2p-peer env))
            p2p-entry (when p2p-peers-atom (get @p2p-peers-atom norm-target))
            ingress-send (when ingress-peers-atom (get @ingress-peers-atom norm-target))
            direct-send (or (:send-fn p2p-entry) ingress-send)]
        (if direct-send
          (try
            (let [ok? (direct-send env)]
              (if (false? ok?)
                (throw (ex-info "p2p-direct-failed" {}))
                ok?))
            (catch Throwable _
              (when (and state-atom (:p2p-session-id env))
                (let [cmd-res (light-core/handle-command @state-atom
                                                         {"cmd" "p2p-channel-state"
                                                          "session_id" (:p2p-session-id env)
                                                          "connected" false
                                                          "error" "p2p-direct-failed"}
                                                         privkey-bytes)]
                  (reset! state-atom (:state cmd-res))))
              (send-default!)))
          (do
            (when (and state-atom (:p2p-session-id env))
              (let [cmd-res (light-core/handle-command @state-atom
                                                       {"cmd" "p2p-channel-state"
                                                        "session_id" (:p2p-session-id env)
                                                        "connected" false
                                                        "error" "no-direct-route"}
                                                       privkey-bytes)]
                (reset! state-atom (:state cmd-res))))
            (send-default!))))

      :else
      (send-default!))))

(defn send-routed-envelopes!
  "Routes a sequence of outgoing network envelopes via route-net-envelope!."
  [envs send-fn-atom p2p-peers-atom ingress-peers-atom state-atom privkey-bytes]
  (doseq [env envs]
    (route-net-envelope! env send-fn-atom p2p-peers-atom ingress-peers-atom state-atom privkey-bytes))
  true)

(defn dial-p2p-peer!
  "Dials a remote P2P candidate peer via WebRTC DataChannel (TCP/UDP/mDNS)."
  [state-atom p2p-peers-atom ingress-peers-atom mdns-atom privkey-bytes emit-event! dial-info]
  (let [peer-pk (light-core/normalize-pubkey-hex (:peer dial-info))
        sid (:session-id dial-info)
        force? (true? (:force-redial? dial-info))
        existing-p2p (when p2p-peers-atom (get @p2p-peers-atom peer-pk))]
    (when (and force? existing-p2p)
      (when-let [cf (:close-fn existing-p2p)]
        (try (cf) (catch Exception _ nil)))
      (when p2p-peers-atom (swap! p2p-peers-atom dissoc peer-pk)))
    (if (and (not force?) existing-p2p (:send-fn existing-p2p))
      (let [cmd-res (light-core/handle-command @state-atom
                                               {"cmd" "p2p-channel-state"
                                                "session_id" sid
                                                "connected" true}
                                               privkey-bytes)]
        (reset! state-atom (:state cmd-res))
        (when emit-event!
          (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))
      (let [candidates (or (:remote-candidates dial-info) [])
            mdns-svc (or (when (map? mdns-atom) mdns-atom)
                         (when (and mdns-atom (instance? clojure.lang.IMeta mdns-atom))
                           (:mdns-svc (meta mdns-atom))))
            mdns-table-atom (if (and (map? mdns-atom) (:table-atom mdns-atom))
                              (:table-atom mdns-atom)
                              mdns-atom)
            read-mdns-state (fn []
                              (when mdns-table-atom
                                (if (instance? clojure.lang.IDeref mdns-table-atom)
                                  @mdns-table-atom
                                  mdns-table-atom)))
            mdns-state (read-mdns-state)
            queried? (atom false)
            _ (doseq [cand candidates]
                (let [cand-map (if (map? cand) cand (light-core/parse-p2p-candidate cand nil))
                      raw-host (when (map? cand) (or (:host cand) (:ip cand)))
                      host (or raw-host (when (and cand-map (mdns/mdns-hostname? (:host cand-map))) (:host cand-map)))]
                  (when (and host (mdns/mdns-hostname? host))
                    (let [tab mdns-state]
                      (when-not (and tab (mdns/lookup-cached-ip tab host))
                        (when-let [sfn (:send-fn mdns-svc)]
                          (try
                            (sfn (mdns/encode-mdns-query host))
                            (reset! queried? true)
                            (catch Throwable _ nil))))))))
            _ (when @queried?
                (try (Thread/sleep 50) (catch Throwable _ nil)))
            mdns-state' (read-mdns-state)
            proxy-url (resolve-proxy-url nil)
            parsed-candidates (->> (keep #(light-core/parse-p2p-candidate % mdns-state') candidates)
                                   (remove (fn [c]
                                             (and (nil? proxy-url)
                                                  (or (= :connect (:transport c))
                                                      (:proxy-connect? c))))))
            success? (atom false)]
        (doseq [cand parsed-candidates
                :while (not @success?)]
          (let [host (:host cand)
                port (int (or (:port cand) 443))
                transport (or (:transport cand) :tcp)
                https-leg? (contains? #{:https :http "https" "http"} transport)]
            (if https-leg?
              (try
                (let [initial-relay-url (relay/normalize-relay-base-url
                                         (or (:url cand)
                                             (str (name transport) "://" host ":" port "/relay/v1")))
                      local-pub (or (:pubkey @state-atom) "")
                      probe-fn (fn [u]
                                 (let [r (try (poll-relay-envelopes! u local-pub privkey-bytes {:since-seq 0 :timeout-ms 0})
                                              (catch Throwable _ nil))]
                                   (and (map? r)
                                        (or (true? (get r "ok"))
                                            (true? (:ok r))
                                            (vector? (get r "messages"))
                                            (vector? (:messages r))))))
                      loopback-fallback-url (relay/normalize-relay-base-url "http://127.0.0.1:18080/relay/v1")
                      relay-base-url (cond
                                       (probe-fn initial-relay-url) initial-relay-url
                                       (and (not= initial-relay-url loopback-fallback-url)
                                            (not (contains? #{"127.0.0.1" "localhost" "::1"} (str/lower-case (str host))))
                                            (probe-fn loopback-fallback-url))
                                       loopback-fallback-url
                                       :else nil)
                      probe-ok? (some? relay-base-url)]
                  (when probe-ok?
                    (let [assigned-gen (atom nil)
                          on-close-fired? (atom false)
                          on-close-fn (fn [_]
                                        (when (compare-and-set! on-close-fired? false true)
                                          (let [my-gen @assigned-gen
                                                cur-gen (long (or (get-in @p2p-peers-atom [peer-pk :generation]) 0))]
                                            (if (and (pos? cur-gen) (or (nil? my-gen) (not (pos? (long my-gen))) (< (long my-gen) cur-gen)))
                                              (when state-atom
                                                (swap! state-atom update-in [:diagnostics :ignored-stale] (fnil inc 0)))
                                              (when (or (zero? cur-gen) (and my-gen (pos? (long my-gen)) (= (long my-gen) cur-gen)))
                                                (when p2p-peers-atom
                                                  (swap! p2p-peers-atom dissoc peer-pk))
                                                (when state-atom
                                                  (let [cmd-res (light-core/handle-command @state-atom
                                                                                           {"cmd" "p2p-channel-state"
                                                                                            "session_id" sid
                                                                                            "connected" false
                                                                                            "error" "channel-closed"}
                                                                                           privkey-bytes)]
                                                    (reset! state-atom (:state cmd-res))
                                                    (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))))))))
                          peer-send! (fn [env]
                                       (if @on-close-fired?
                                         false
                                         (try
                                           (let [r (submit-relay-envelope! relay-base-url env {:timeout-ms 5000})]
                                             (boolean (or (true? (get r "ok")) (true? (:ok r)))))
                                           (catch Throwable _ false))))
                          peer-close! (fn []
                                        (try
                                          (on-close-fn {:type :on-close})
                                          (catch Throwable _ nil)))
                          my-gen (inc (long (or (get-in @p2p-peers-atom [peer-pk :generation]) 0)))]
                      (reset! assigned-gen my-gen)
                      (reset! success? true)
                      (when p2p-peers-atom
                        (swap! p2p-peers-atom assoc peer-pk {:send-fn peer-send!
                                                             :close-fn peer-close!
                                                             :session-id sid
                                                             :transport "https"
                                                             :relay-url relay-base-url
                                                             :generation my-gen}))
                      (let [bind-env (build-p2p-link-bind-envelope local-pub privkey-bytes sid)]
                        (peer-send! bind-env))
                      (let [cmd-res (light-core/handle-command @state-atom
                                                               {"cmd" "p2p-channel-state"
                                                                "session_id" sid
                                                                "connected" true}
                                                               privkey-bytes)]
                        (reset! state-atom (:state cmd-res))
                        (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))
                      (doto (Thread.
                             ^Runnable
                             (fn []
                               (loop [since-mseq 0
                                      since-bseq 0]
                                 (when (and (not @on-close-fired?)
                                            p2p-peers-atom
                                            (= my-gen (get-in @p2p-peers-atom [peer-pk :generation])))
                                   (let [poll-res (try
                                                    (poll-relay-envelopes! relay-base-url local-pub privkey-bytes
                                                                           {:since-seq since-mseq
                                                                            :since-broadcast-seq since-bseq
                                                                            :wait-ms 2000})
                                                    (catch Throwable _ nil))
                                         msgs (or (get poll-res "messages") (get poll-res :messages) [])
                                         bcasts (or (get poll-res "broadcasts") (get poll-res :broadcasts) [])
                                         all-items (concat msgs bcasts)
                                         new-mseq (long (or (get (last msgs) "relay_seq") (get (last msgs) "relay-seq") since-mseq))
                                         new-bseq (long (or (get poll-res "last_broadcast_seq") (get poll-res :last_broadcast_seq) since-bseq))]
                                     (doseq [item all-items]
                                       (let [env-raw (or (get item "envelope_hex") (get item "envelope")
                                                         (get item :envelope_hex) (get item :envelope))
                                             wire-bytes (when env-raw (try (basalt/hex->bytes (str env-raw)) (catch Throwable _ nil)))]
                                         (when (and wire-bytes state-atom)
                                           (let [r (light-core/handle-wire-payload @state-atom wire-bytes privkey-bytes)]
                                             (reset! state-atom (:state r))
                                             (when emit-event! (doseq [ev (:stdout-events r)] (emit-event! ev)))
                                             (when (seq (:net-envelopes r))
                                               (send-routed-envelopes! (:net-envelopes r) nil p2p-peers-atom ingress-peers-atom state-atom privkey-bytes))))))
                                     (try (Thread/sleep 250) (catch InterruptedException _ (reset! on-close-fired? true)))
                                     (recur new-mseq new-bseq))))))
                        (.setDaemon true)
                        (.setName (str "bitecho-https-p2p-" (subs (str sid) 0 (min 8 (count (str sid))))))
                        (.start)))))
                (catch Throwable _ nil))
              (let [client-node (api/create-node {:port 0 :setup "active"})]
                (try
                  (let [connected-prom (promise)
                        channel-id (atom nil)
                        assigned-gen (atom nil)
                        on-close-fired? (atom false)
                        peer-send! (fn [env]
                                     (if-let [cid @channel-id]
                                       (let [payload (try (if (bytes? env) env (fressian/encode-wire env)) (catch Throwable _ nil))]
                                         (if payload
                                           (try (api/send! client-node payload cid) true (catch Throwable _ false))
                                           false))
                                       false))
                        on-close-fn (fn [_]
                                      (when (compare-and-set! on-close-fired? false true)
                                        (let [my-gen @assigned-gen
                                              cur-gen (long (or (get-in @p2p-peers-atom [peer-pk :generation]) 0))]
                                          (if (and (pos? cur-gen) (or (nil? my-gen) (not (pos? (long my-gen))) (< (long my-gen) cur-gen)))
                                            (when state-atom
                                              (swap! state-atom update-in [:diagnostics :ignored-stale] (fnil inc 0)))
                                            (when (or (zero? cur-gen) (and my-gen (pos? (long my-gen)) (= (long my-gen) cur-gen)))
                                              (when p2p-peers-atom
                                                (swap! p2p-peers-atom dissoc peer-pk))
                                              (when state-atom
                                                (let [cmd-res (light-core/handle-command @state-atom
                                                                                         {"cmd" "p2p-channel-state"
                                                                                          "session_id" sid
                                                                                          "connected" false
                                                                                          "error" "channel-closed"}
                                                                                         privkey-bytes)]
                                                  (reset! state-atom (:state cmd-res))
                                                  (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))))))))
                        peer-close! (fn []
                                      (try
                                        (api/close! client-node)
                                        (on-close-fn {:type :on-close})
                                        (catch Throwable _ nil)))
                        remote-sdp (cond-> {:ip host
                                            :port port
                                            :remote-ice-ufrag (or (:remote-ice-ufrag dial-info) "ufrag")
                                            :remote-ice-pwd (or (:remote-ice-pwd dial-info) "pwd")}
                                     (:remote-fingerprint dial-info)
                                     (assoc :fingerprint (identity/normalize-fingerprint (:remote-fingerprint dial-info)))
                                     (:proxy-connect? cand)
                                     (assoc :proxy (resolve-proxy-url nil)))
                        callbacks {:on-open (fn [evt]
                                              (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)]
                                                (reset! channel-id cid)
                                                (deliver connected-prom true)))
                                   :on-data-channel (fn [evt]
                                                      (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)]
                                                        (reset! channel-id cid)
                                                        (deliver connected-prom true)))
                                   :on-message (fn [evt]
                                                 (when-let [payload (:payload evt)]
                                                   (when state-atom
                                                     (let [st @state-atom
                                                           res (light-core/handle-wire-payload st payload privkey-bytes)]
                                                       (reset! state-atom (:state res))
                                                       (when (seq (:stdout-events res))
                                                         (when emit-event! (doseq [ev (:stdout-events res)] (emit-event! ev))))
                                                       (when (seq (:net-envelopes res))
                                                         (send-routed-envelopes! (:net-envelopes res) nil p2p-peers-atom ingress-peers-atom state-atom privkey-bytes))))))
                                   :on-close on-close-fn}]
                    (api/set-callbacks! client-node callbacks)
                    (if (or (= transport :tcp) (= transport :connect))
                      (api/start-tcp! client-node remote-sdp callbacks)
                      (do
                        (api/start! client-node remote-sdp callbacks)
                        (configure-udp-receive-buffer! client-node)))
                    (let [res (deref connected-prom 3000 :timeout)]
                      (if (= res true)
                        (let [my-gen (inc (long (or (get-in @p2p-peers-atom [peer-pk :generation]) 0)))]
                          (reset! assigned-gen my-gen)
                          (reset! success? true)
                          (when p2p-peers-atom
                            (swap! p2p-peers-atom assoc peer-pk {:send-fn peer-send!
                                                                 :close-fn peer-close!
                                                                 :session-id sid
                                                                 :generation my-gen}))
                          (let [local-pub (or (:pubkey @state-atom) "")
                                bind-env (build-p2p-link-bind-envelope local-pub privkey-bytes sid)]
                            (peer-send! bind-env))
                          (let [cmd-res (light-core/handle-command @state-atom
                                                                   {"cmd" "p2p-channel-state"
                                                                    "session_id" sid
                                                                    "connected" true}
                                                                   privkey-bytes)]
                            (reset! state-atom (:state cmd-res))
                            (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev)))))
                        (try (api/close! client-node) (catch Throwable _ nil)))))
                  (catch Throwable _
                    (try (api/close! client-node) (catch Throwable _ nil))))))))
        (when (and (not @success?) (not (get-in @state-atom [:sessions sid :p2p :connected?])))
          (let [cmd-res (light-core/handle-command @state-atom
                                                   {"cmd" "p2p-channel-state"
                                                    "session_id" sid
                                                    "connected" false
                                                    "error" "p2p-dial-failed"}
                                                   privkey-bytes)]
            (reset! state-atom (:state cmd-res))
            (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev)))))))))

(defn start-ingress-tcp-listener!
  "Starts a passive RFC 4571 DTLS-over-TCP DataChannel ingress listener on `:ingress-tcp-port`
   for direct `HTTP CONNECT` / TCP peer connections (Step 15C).
   Returns `{:listener listener :ingress-peers-atom ingress-peers-atom :stop! (fn [] ...)}` or nil."
  [identity opts]
  (let [port (int (or (:ingress-tcp-port opts) 0))]
    (when (pos? port)
      (let [{:keys [state-atom conn-atom event-out state-file p2p-peers-atom mdns-atom]} opts
            ingress-peers-atom (or (:ingress-peers-atom opts) (atom {}))
            peer-ice-pwds (atom {})
            on-conn-fn
            (fn [peer-node]
              (when (and (map? peer-node)
                         (instance? clojure.lang.IAtom (:loop-future peer-node))
                         (nil? @(:loop-future peer-node))
                         (instance? clojure.lang.IAtom (:selector peer-node)))
                (reset! (:selector peer-node) nil))
              (try (api/set-max-message-size! peer-node) (catch Exception _ nil))
              (let [peer-key (System/identityHashCode peer-node)
                    peer-cid (atom 0)
                    bound-sender (atom nil)
                    bound-gen (atom nil)
                    on-close-fired? (atom false)
                    peer-send! (fn [env]
                                 (let [payload (try
                                                 (if (bytes? env) env (fressian/encode-wire env))
                                                 (catch Throwable _ nil))]
                                   (if (nil? payload)
                                     false
                                     (try
                                       (api/send! peer-node payload (int (or @peer-cid 0)))
                                       true
                                       (catch Throwable _ false)))))
                    on-close-fn (fn [_]
                                  (when (compare-and-set! on-close-fired? false true)
                                    (swap! ingress-peers-atom dissoc peer-key)
                                    (when-let [peer @bound-sender]
                                      (let [my-gen @bound-gen
                                            cur-gen (long (or (get-in @p2p-peers-atom [peer :generation]) 0))]
                                        (if (and (pos? cur-gen) (or (nil? my-gen) (not (pos? (long my-gen))) (< (long my-gen) cur-gen)))
                                          (when state-atom
                                            (swap! state-atom update-in [:diagnostics :ignored-stale] (fnil inc 0)))
                                          (when (or (zero? cur-gen) (and my-gen (pos? (long my-gen)) (= (long my-gen) cur-gen)))
                                            (let [entry (when p2p-peers-atom (get @p2p-peers-atom peer))
                                                  sid (:session-id entry)]
                                              (when p2p-peers-atom (swap! p2p-peers-atom dissoc peer))
                                              (when (and state-atom sid (get-in @state-atom [:sessions sid]))
                                                (let [cmd-res (light-core/handle-command @state-atom
                                                                                         {"cmd" "p2p-channel-state"
                                                                                          "session_id" sid
                                                                                          "connected" false
                                                                                          "error" "channel-closed"}
                                                                                         (:privkey-bytes identity))]
                                                  (reset! state-atom (:state cmd-res))
                                                  (when (and event-out (seq (:stdout-events cmd-res)))
                                                    (doseq [ev (:stdout-events cmd-res)] (event-out ev))))))))))))
                    peer-close! (fn []
                                  (try
                                    (when-let [ch @(:channel peer-node)]
                                      (when (instance? java.io.Closeable ch)
                                        (.close ^java.io.Closeable ch)))
                                    (api/close! peer-node)
                                    (on-close-fn {:type :on-close})
                                    (catch Exception _ nil)))]
                (swap! ingress-peers-atom assoc peer-key peer-send!)
                (api/set-callbacks!
                 peer-node
                 {:on-open (fn [evt]
                             (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)]
                               (reset! peer-cid cid)))
                  :on-data-channel (fn [evt]
                                     (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)]
                                       (reset! peer-cid cid)))
                  :on-message
                  (fn [evt]
                    (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) @peer-cid 0)]
                      (reset! peer-cid cid)
                      (when-let [payload (:payload evt)]
                        (let [decoded (try (if (bytes? payload) (fressian/decode-wire payload) payload) (catch Exception _ nil))
                              inner-ev (if (and (map? decoded) (map? (:event decoded))) (:event decoded) decoded)]
                          (cond
                            (and (map? inner-ev) (= :p2p-link-bind (or (:type inner-ev) (:bitecho/type inner-ev))))
                            (let [norm-sender (light-core/normalize-pubkey-hex (:sender inner-ev))
                                  sid (:session-id inner-ev)
                                  sess (when (and state-atom sid) (get-in @state-atom [:sessions sid]))
                                  expected-peer (when sess (light-core/normalize-pubkey-hex (:peer sess)))
                                  p2p-phase (when sess (get-in sess [:p2p :phase]))
                                  valid? (and (verify-p2p-link-bind inner-ev)
                                              (some? sess)
                                              (= "open" (:state sess))
                                              (= norm-sender expected-peer)
                                              (contains? #{:offered :offer-received :connecting :open :closed nil} p2p-phase))]
                              (if valid?
                                (let [my-gen (inc (long (or (get-in @p2p-peers-atom [norm-sender :generation]) 0)))]
                                  (reset! bound-sender norm-sender)
                                  (reset! bound-gen my-gen)
                                  (when p2p-peers-atom
                                    (swap! p2p-peers-atom assoc norm-sender {:send-fn peer-send!
                                                                             :close-fn peer-close!
                                                                             :session-id sid
                                                                             :generation my-gen}))
                                  (when state-atom
                                    (let [cmd-res (light-core/handle-command @state-atom
                                                                             {"cmd" "p2p-channel-state"
                                                                              "session_id" sid
                                                                              "connected" true}
                                                                             (:privkey-bytes identity))]
                                      (reset! state-atom (:state cmd-res))
                                      (when (and event-out (seq (:stdout-events cmd-res)))
                                        (doseq [ev (:stdout-events cmd-res)] (event-out ev))))))
                                (when state-atom
                                  (swap! state-atom update-in [:diagnostics :p2p-signaling-rejected] (fnil inc 0)))))

                            (and (map? inner-ev) (= :query-chain-state (or (:type inner-ev) (:bitecho/type inner-ev))))
                            (let [st (if state-atom @state-atom {})
                                  target-pk (or (:pubkey inner-ev) (:agent-pubkey decoded) (:pubkey st) (:pubkey-hex identity))
                                  fin-ep (long (or (get-in st [:account :finalized-epoch]) (:epoch st) 0))
                                  bal (long (or (get-in st [:account :balance]) 0))
                                  spend (long (or (get-in st [:account :spendable]) bal 0))
                                  sq (long (or (get-in st [:account :seq]) 0))
                                  deps (vec (or (get-in st [:account :deps]) []))
                                  base-snap {:bitecho/type :chain-state-snapshot
                                             :type :chain-state-snapshot
                                             :validator-pubkey (or (:pubkey-hex identity) (:pubkey identity))
                                             :pubkey target-pk
                                             :finalized-epoch fin-ep
                                             :balance bal
                                             :spendable spend
                                             :seq sq
                                             :deps deps
                                             :escrows []
                                             :nonce (str (or (:nonce inner-ev) ""))}
                                  signed-snap (light-core/sign-chain-state-snapshot base-snap (:privkey-bytes identity))]
                              (peer-send! signed-snap))

                            :else
                            (when state-atom
                              (let [st @state-atom
                                    st-rej (+ (long (or (get-in st [:diagnostics :p2p-signaling-rejected]) 0))
                                              (long (or (get-in st [:diagnostics :broadcast-rejected]) 0)))
                                    res (light-core/handle-wire-payload st payload (:privkey-bytes identity))
                                    new-st (:state res)
                                    new-rej (+ (long (or (get-in new-st [:diagnostics :p2p-signaling-rejected]) 0))
                                               (long (or (get-in new-st [:diagnostics :broadcast-rejected]) 0)))]
                                (when (and (<= new-rej st-rej)
                                           (map? inner-ev)
                                           (contains? #{:p2p-offer :p2p-answer :p2p-broadcast :p2p-hub-relay :sealed-message :session-ack}
                                                      (or (:type inner-ev) (:bitecho/type inner-ev))))
                                  (when-let [norm-sender (light-core/normalize-pubkey-hex (:sender inner-ev))]
                                    (when (and p2p-peers-atom (get @p2p-peers-atom norm-sender))
                                      (reset! bound-sender norm-sender)
                                      (swap! p2p-peers-atom update norm-sender #(merge {:send-fn peer-send! :close-fn peer-close!} %)))))
                                (reset! state-atom new-st)
                                (when (and state-file (not= st new-st))
                                  (try (save-light-state! state-file new-st) (catch Exception _ nil)))
                                (when (and event-out (seq (:stdout-events res)))
                                  (doseq [ev (:stdout-events res)]
                                    (event-out ev)))
                                (when-let [dial-info (:p2p-dial res)]
                                  (dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom mdns-atom (:privkey-bytes identity) event-out dial-info))
                                (when (seq (:net-envelopes res))
                                  (send-routed-envelopes! (:net-envelopes res)
                                                          (when (and conn-atom (connection-live? @conn-atom @state-atom))
                                                            (:send-fn @conn-atom))
                                                          p2p-peers-atom
                                                          ingress-peers-atom
                                                          state-atom
                                                          (:privkey-bytes identity))))))))))
                  :on-close on-close-fn})))
            listen-opts {:port port
                         :cert-data (:cert-data identity)
                         :ice-creds (:ice-creds identity)
                         :peer-ice-pwds peer-ice-pwds}
            listener (api/listen-tcp! listen-opts {:on-connection on-conn-fn})
            udp-listener (try
                           (let [ul (api/listen! listen-opts {:on-connection on-conn-fn})]
                             (configure-udp-receive-buffer! ul)
                             ul)
                           (catch Exception e
                             (when state-atom
                               (record-conn-diagnostic! state-atom :udp-listen-failed {:port port :error (or (.getMessage e) (str e))}))
                             nil))]
        {:listener listener
         :udp-listener udp-listener
         :ingress-peers-atom ingress-peers-atom
         :p2p-peers-atom p2p-peers-atom
         :stop! (fn []
                  (try (api/close! listener) (catch Exception _ nil))
                  (when udp-listener (try (api/close! udp-listener) (catch Exception _ nil))))}))))

(defn- maybe-wait-open!
  [resp sid wait-ms state-atom conn-opts relay-url emit!]
  (if (and resp (true? (or (get resp "ok") (get resp :ok))) (string? sid) (pos? wait-ms))
    (let [deadline (+ (System/currentTimeMillis) wait-ms)]
      (loop []
        (let [st (get-in @state-atom [:sessions sid :state])]
          (cond
            (= st "open")
            (let [final-resp (assoc resp "state" "open")]
              (when emit! (emit! final-resp))
              final-resp)

            (>= (System/currentTimeMillis) deadline)
            (let [final-resp (assoc resp "state" (or st "offered") "wait_timed_out" true)]
              (when emit! (emit! final-resp))
              final-resp)

            :else
            (do
              (Thread/sleep 50)
              (when relay-url
                (try
                  (let [pk (or (:pubkey-hex (:identity conn-opts)) (:pubkey @state-atom))
                        sk (or (:privkey-bytes (:identity conn-opts)) (:privkey @state-atom))]
                    (when (and pk sk)
                      (poll-relay-envelopes! relay-url pk sk nil)))
                  (catch Exception _ nil)))
              (recur))))))
    (do
      (when (and resp emit!) (emit! resp))
      resp)))

(defn- artifact-endpoint-base-url
  [raw-url]
  (when (and (string? raw-url) (not (str/blank? raw-url)))
    (-> (str/trim raw-url)
        (str/replace #"/+$" "")
        (str/replace #"/relay/v1$" "")
        (str/replace #"/artifact/v1$" ""))))

(defn- effective-artifact-domain-verb
  [verb cmd-map]
  (let [v (str (or verb (get cmd-map "cmd") (:cmd cmd-map) ""))]
    (if (contains? #{"put" "get" "list" "lock" "spend" "connect" "wait-event"} v)
      (str (get (cli/desugar-cli-cmd-map (assoc (or cmd-map {}) "cmd" v)) "cmd" v))
      v)))

(defn- fetch-relay-pointer-seq
  [raw-relay-url raw-path]
  (when-let [base-url (artifact-endpoint-base-url raw-relay-url)]
    (when (and (string? raw-path) (not (str/blank? raw-path)))
      (let [clean-path (str/replace (str/trim raw-path) #"^/+" "")]
        (try
          (let [client (default-http-client)
                enc-prefix (java.net.URLEncoder/encode clean-path StandardCharsets/UTF_8)
                req (-> (HttpRequest/newBuilder)
                        (.uri (URI/create (str base-url "/artifact/v1/list?prefix=" enc-prefix)))
                        (.timeout (Duration/ofSeconds 5))
                        (.GET)
                        (.build))
                r (.send client req (HttpResponse$BodyHandlers/ofString StandardCharsets/UTF_8))
                body (when (= 200 (.statusCode r)) (json/read-str (.body r)))
                ptrs (when (map? body) (or (get body "pointers") (:pointers body)))
                matched (some (fn [p]
                                (when (= clean-path (or (get p "path") (:path p)))
                                  (or (get p "seq") (:seq p))))
                              ptrs)]
            (when (some? matched)
              (Long/parseLong (str matched))))
          (catch Exception _ nil))))))

(defn- enrich-artifact-cmd-map
  ([verb cmd-map]
   (enrich-artifact-cmd-map verb cmd-map nil))
  ([verb cmd-map default-relay-url]
   (let [eff-verb (effective-artifact-domain-verb verb cmd-map)
         m1 (if (and (= eff-verb "artifact-put")
                     (nil? (get cmd-map "hex"))
                     (nil? (get cmd-map "data_hex"))
                     (nil? (get cmd-map "text"))
                     (nil? (get cmd-map "data"))
                     (string? (get cmd-map "file"))
                     (not (str/blank? (get cmd-map "file"))))
              (let [f (io/file (get cmd-map "file"))]
                (if (.exists f)
                  (let [bs (Files/readAllBytes (.toPath f))
                        h (basalt/bytes->hex bs)]
                    (assoc cmd-map "hex" h "data_hex" h))
                  cmd-map))
              cmd-map)
         art-relay (or (get m1 "relay_url") (get m1 "relay-url") (:relay-url m1) default-relay-url)]
     (if (and (contains? #{"artifact-put" "artifact-revoke"} eff-verb)
              (nil? (get m1 "seq"))
              (nil? (:seq m1))
              (string? art-relay)
              (not (str/blank? art-relay)))
       (if-let [r-seq (fetch-relay-pointer-seq art-relay (or (get m1 "path") (:path m1)))]
         (assoc m1 "min_remote_seq" r-seq)
         m1)
       m1))))

(defn- post-artifact-to-relay!
  [raw-relay-url verb resp]
  (when-let [base-url (artifact-endpoint-base-url raw-relay-url)]
    (when (and (map? resp) (true? (or (get resp "ok") (:ok resp))))
      (try
        (let [client (default-http-client)
              post-json! (fn [subpath payload-str content-type timeout-ms]
                           (let [req (-> (HttpRequest/newBuilder)
                                         (.uri (URI/create (str base-url subpath)))
                                         (.timeout (Duration/ofMillis (long timeout-ms)))
                                         (.header "Content-Type" content-type)
                                         (.POST (HttpRequest$BodyPublishers/ofString payload-str StandardCharsets/UTF_8))
                                         (.build))
                                 r (.send client req (HttpResponse$BodyHandlers/ofString StandardCharsets/UTF_8))]
                             (try (json/read-str (.body r)) (catch Exception _ {"status" (.statusCode r)}))))]
          (when (contains? #{"artifact-put" "put"} (str verb))
            (when-let [blob (or (get resp "blob") (:blob resp))]
              (post-json! "/artifact/v1/blob"
                          (json/write-str {"bytes_hex" (basalt/bytes->hex (:blob/bytes blob))
                                           "cid" (:blob/cid blob)
                                           "media_type" (or (:blob/media-type blob) "application/octet-stream")})
                          "application/json"
                          30000)))
          (when-let [ptr (or (get resp "pointer") (:pointer resp))]
            (post-json! "/artifact/v1/pointer"
                        (pr-str ptr)
                        "application/edn"
                        15000)))
        (catch Exception _ nil)))))

(defn- maybe-write-artifact-out-file!
  [verb cmd-map resp]
  (let [eff-verb (effective-artifact-domain-verb verb cmd-map)]
    (when (and (= eff-verb "artifact-get")
               (map? resp)
               (true? (or (get resp "ok") (:ok resp)))
               (string? (get cmd-map "out_file"))
               (not (str/blank? (get cmd-map "out_file")))
               (string? (get resp "hex")))
      (try
        (let [f (io/file (get cmd-map "out_file"))]
          (when-let [p (.getParentFile f)] (.mkdirs p))
          (Files/write (.toPath f)
                       ^bytes (basalt/hex->bytes (get resp "hex"))
                       (into-array java.nio.file.OpenOption [])))
        (catch Exception _ nil)))))

(defn handle-serve-line!
  "Processes a single STDIN, --cmd-file JSON line, or control-socket command map in serve mode,
   handling network retries and returning response map."
  [cmd-or-line ctx]
  (let [{:keys [state-atom out-writer events-out state-file identity bootstrap conn-opts ingress-peers-atom p2p-peers-atom mdns-atom]} ctx
        conn-atom (or (:conn-atom ctx) (atom nil))
        emit! (fn [payload] (emit-json-line! out-writer payload events-out))
        cmd-map (cond
                  (map? cmd-or-line) cmd-or-line
                  (string? cmd-or-line) (try (json/read-str cmd-or-line) (catch Exception _ nil))
                  :else nil)
        wait-ms (long (or (get cmd-map "wait_open_ms") (get cmd-map "wait-open-ms") (get cmd-map :wait-open-ms) (get cmd-map :wait_open_ms) 0))
        relay-url (or (:relay-url conn-opts)
                      (get-in conn-opts [:relay :url])
                      (infer-bootstrap-relay-url bootstrap conn-opts)
                      (:relay-url bootstrap)
                      (get-in bootstrap [:relay :url])
                      (when (= "bitecho.org" (:domain bootstrap)) "https://ns1.bitecho.org"))]
    (if-not (and (map? cmd-map) (contains? cmd-map "cmd"))
      (let [err {"ok" false "error" (if (and (string? cmd-or-line) (str/blank? cmd-or-line)) "empty-line" "malformed-request")}]
        (emit! err)
        err)
      (let [verb (get cmd-map "cmd")
            sync-wanted? (or (and (= verb "sync-account") (nil? (get cmd-map "balance")) (nil? (get cmd-map "snapshots")) (nil? (get cmd-map "snapshot")))
                             (and (= verb "account") (or (get cmd-map "sync") (:sync? cmd-map)))
                             (and (= verb "escrows") (or (get cmd-map "sync") (:sync? cmd-map))))
            sync-opts (assoc (or conn-opts {}) :identity identity)
            sync-res (when sync-wanted?
                       (maybe-sync-account-state! state-atom bootstrap (or (:pubkey-hex identity) (:pubkey identity)) (:privkey-bytes identity) sync-opts))]
        (if (and sync-res (false? (:ok? sync-res)))
          (let [err-resp {"ok" false "error" (:error sync-res)}]
            (emit! err-resp)
            err-resp)
          (let [effective-map (-> (if (and (contains? #{"directory-lookup" "directory-verify"} verb)
                                           (not (contains? cmd-map "descriptor"))
                                           (not (contains? cmd-map :descriptor)))
                                    (let [nick (or (get cmd-map "nickname") (:nickname cmd-map)
                                                   (get cmd-map "name") (:name cmd-map))
                                          dom (or (get cmd-map "domain") (:domain cmd-map) "bitecho.org")
                                          desc (when (and (string? nick) (not (str/blank? nick)))
                                                 (fetch-directory-descriptor! dom nick conn-opts))]
                                      (cond-> cmd-map
                                        desc (assoc "descriptor" desc)))
                                    cmd-map)
                                  (as-> m (enrich-artifact-cmd-map verb m relay-url)))
                prev-state @state-atom
                eff-domain-verb (effective-artifact-domain-verb verb effective-map)
                res (light-core/handle-command @state-atom effective-map (:privkey-bytes identity))
                _ (maybe-write-artifact-out-file! eff-domain-verb effective-map (:response res))
                _ (when (contains? #{"artifact-put" "artifact-revoke"} eff-domain-verb)
                    (when-let [art-relay (or (get effective-map "relay_url")
                                             (get effective-map "relay-url")
                                             (:relay-url effective-map)
                                             relay-url)]
                      (post-artifact-to-relay! art-relay eff-domain-verb (:response res))))
                finish-resp! (fn [resp]
                               (if (and (contains? #{"offer" "rendezvous-offer"} verb) (pos? wait-ms))
                                 (let [sid (or (get resp "session_id") (get resp "session-id") (get resp :session-id) (get-in res [:response "session_id"]))]
                                   (maybe-wait-open! resp sid wait-ms state-atom conn-opts relay-url emit!))
                                 (do
                                   (when (and resp emit!) (emit! resp))
                                   resp)))
                _ (when (:state res)
                    (reset! state-atom (:state res)))
                _ (if (seq (:p2p-dials res))
                    (doseq [dial-info (:p2p-dials res)]
                      (dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom mdns-atom (:privkey-bytes identity) emit! dial-info))
                    (when-let [dial-info (:p2p-dial res)]
                      (dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom mdns-atom (:privkey-bytes identity) emit! dial-info)))
                shuttle-verb? (contains? #{"export-offer" "export-poll" "export-ack" "export-reveal" "export-p2p-offer" "export-p2p-answer" "export-send" "import-envelope" "import-poll" "import"} verb)
                import-shuttle-verb? (contains? #{"import-envelope" "import-poll" "import"} verb)
                connect-explicit? (true? (or (get cmd-map "connect") (:connect cmd-map)))
                currently-live? (connection-live? @conn-atom @state-atom)
                has-live-peers? (or (and p2p-peers-atom (seq @p2p-peers-atom))
                                    (and ingress-peers-atom (seq @ingress-peers-atom)))
                shuttle-can-forward? (and import-shuttle-verb?
                                          (or connect-explicit? currently-live? has-live-peers?))
                needs-net? (and (seq (:net-envelopes res))
                                (if shuttle-verb?
                                  (or connect-explicit? shuttle-can-forward?)
                                  true))]
            (if needs-net?
              (let [replay-envs (when (= verb "register-home-set")
                                  (light-core/build-unacked-replay-envelopes @state-atom (:privkey-bytes identity)))
                    live-envs (if (seq replay-envs)
                                (into (vec replay-envs) (:net-envelopes res))
                                (:net-envelopes res))
                    mirror-to-relay! (fn [envs]
                                       (if (and (string? relay-url)
                                                (not (str/blank? relay-url))
                                                (not= :http-relay (:transport @conn-atom)))
                                         (let [non-direct (remove :p2p-direct? envs)]
                                           (if (empty? non-direct)
                                             false
                                             (boolean
                                              (some (fn [env]
                                                      (try
                                                        (let [r (submit-relay-envelope! relay-url env {:timeout-ms 5000})]
                                                          (boolean (or (true? (get r "ok")) (true? (:ok r)))))
                                                        (catch Exception _ false)))
                                                    non-direct))))
                                         false))]
                (if (some #(or (:p2p-direct? %) (:p2p-broadcast? %)) live-envs)
                  (do
                    (when (and (not currently-live?)
                               (:reconnect-fn conn-opts)
                               (seq (:nodes bootstrap)))
                      (try ((:reconnect-fn conn-opts)) (catch Exception _ nil)))
                    (send-routed-envelopes! live-envs
                                            (when (connection-live? @conn-atom @state-atom) (:send-fn @conn-atom))
                                            p2p-peers-atom
                                            ingress-peers-atom
                                            state-atom
                                            (:privkey-bytes identity))
                    (mirror-to-relay! live-envs)
                    (sync-conn-diagnostics! state-atom conn-atom)
                    (when state-file (save-light-state! state-file @state-atom))
                    (finish-resp! (:response res)))
                  (let [sent-ingress? (boolean
                                       (when (and ingress-peers-atom (seq @ingress-peers-atom))
                                         (some true? (mapv #(send-all-envelopes! % live-envs) (vals @ingress-peers-atom)))))
                        sent-val? (when currently-live?
                                    (send-all-envelopes! (:send-fn @conn-atom) live-envs))
                        sent-relay? (mirror-to-relay! live-envs)
                        sent? (or sent-val? sent-ingress? sent-relay?)]
                    (if sent?
                      (do
                        (swap! state-atom assoc :connected? true :connection-error nil)
                        (sync-conn-diagnostics! state-atom conn-atom)
                        (when state-file (save-light-state! state-file @state-atom))
                        (finish-resp! (:response res)))
                      (do
                        (swap! state-atom assoc :connected? false :connection-error "send-failed")
                        (when conn-atom
                          (apply-conn-event! conn-atom {:type :dial-started} conn-opts))
                        (let [target-gen (if conn-atom (:generation @conn-atom 0) 1)
                              cursor (if conn-atom (:validator-cursor @conn-atom 0) 0)
                              home-set (if state-atom (:home-set @state-atom) [])
                              opts-with-gen (assoc (or conn-opts {})
                                                   :generation target-gen
                                                   :validator-cursor cursor
                                                   :home-set home-set)
                              reconn (connect-validators! identity bootstrap opts-with-gen)]
                          (if (:ok? reconn)
                            (do
                              (when conn-atom
                                (apply-conn-event! conn-atom (assoc reconn :type :dial-ok :generation target-gen) conn-opts))
                              (let [replay-envs (light-core/build-unacked-replay-envelopes @state-atom (:privkey-bytes identity))
                                    all-envs (into (vec replay-envs) (:net-envelopes res))]
                                (if (send-all-envelopes! (:send-fn reconn) all-envs)
                                  (do
                                    (swap! state-atom assoc :connected? true :connection-error nil)
                                    (sync-conn-diagnostics! state-atom conn-atom)
                                    (when state-file (save-light-state! state-file @state-atom))
                                    (finish-resp! (:response res)))
                                  (let [err "send-failed"]
                                    (swap! state-atom
                                           (fn [st]
                                             (:state (deploy/route-control-plane-envelope
                                                      (assoc st :connected? false :connection-error err)
                                                      (first all-envs)
                                                      (cond-> [{:id :validator-udp :available? true :send-ok? false}]
                                                        (and (string? relay-url) (not (str/blank? relay-url)))
                                                        (conj {:id :https-relay :available? true :send-ok? false}))))))
                                    (when conn-atom
                                      (apply-conn-event! conn-atom {:type :send-failed :error err :generation target-gen} conn-opts))
                                    (if (= verb "send")
                                      (do
                                        (sync-conn-diagnostics! state-atom conn-atom)
                                        (when state-file (save-light-state! state-file @state-atom))
                                        (let [err-map (assoc (or (:response res) {"ok" true}) "ok" true "queued" true "transport_error" err)]
                                          (emit! err-map)
                                          err-map))
                                      (do
                                        (when state-atom
                                          (swap! state-atom (fn [curr]
                                                              (assoc (merge prev-state (when-let [p2p-sess (into {} (keep (fn [[k s]] (when-let [p (:p2p s)] [k {:p2p p}]))) (:sessions curr))]
                                                                                         {:sessions (merge-with merge (:sessions prev-state) p2p-sess)}))
                                                                     :connected? false
                                                                     :connection-error err))))
                                        (sync-conn-diagnostics! state-atom conn-atom)
                                        (let [err-map {"ok" false "error" err}]
                                          (emit! err-map)
                                          err-map)))))))
                            (let [err (or (:error reconn) "listener-disabled")]
                              (when conn-atom
                                (apply-conn-event! conn-atom {:type :dial-failed :error err :node (:node reconn) :generation target-gen} conn-opts))
                              (swap! state-atom
                                     (fn [st]
                                       (:state (deploy/route-control-plane-envelope
                                                (assoc st :connected? false :connection-error err)
                                                (first live-envs)
                                                (cond-> [{:id :validator-udp :available? true :send-ok? false}]
                                                  (and (string? relay-url) (not (str/blank? relay-url)))
                                                  (conj {:id :https-relay :available? true :send-ok? false}))))))
                              (if (= verb "send")
                                (do
                                  (sync-conn-diagnostics! state-atom conn-atom)
                                  (when state-file (save-light-state! state-file @state-atom))
                                  (let [err-map (assoc (or (:response res) {"ok" true}) "ok" true "queued" true "transport_error" err)]
                                    (emit! err-map)
                                    err-map))
                                (do
                                  (when state-atom
                                    (swap! state-atom (fn [curr]
                                                        (assoc (merge prev-state (when-let [p2p-sess (into {} (keep (fn [[k s]] (when-let [p (:p2p s)] [k {:p2p p}]))) (:sessions curr))]
                                                                                   {:sessions (merge-with merge (:sessions prev-state) p2p-sess)}))
                                                               :connected? false
                                                               :connection-error err))))
                                  (sync-conn-diagnostics! state-atom conn-atom)
                                  (let [err-map {"ok" false "error" err}]
                                    (emit! err-map)
                                    err-map)))))))))))
              (let [deferred-forward? (and import-shuttle-verb? (seq (:net-envelopes res)))
                    final-resp (if deferred-forward?
                                 (do
                                   (swap! state-atom update-in [:diagnostics :shuttle-import-forward-deferred] (fnil inc 0))
                                   (assoc (:response res) "pending_forward_count" (count (:net-envelopes res))))
                                 (:response res))]
                (sync-conn-diagnostics! state-atom conn-atom)
                (when state-file (save-light-state! state-file @state-atom))
                (finish-resp! final-resp)))))))))

(defn- extract-pid []
  (try
    (let [ph-cls (Class/forName "java.lang.ProcessHandle")
          curr-m (.getMethod ph-cls "current" (into-array Class []))
          ph (.invoke curr-m nil (into-array Object []))
          pid-m (.getMethod ph-cls "pid" (into-array Class []))]
      (.invoke pid-m ph (into-array Object [])))
    (catch Exception _ 0)))

(defn- normalize-ctl-request-map
  "Normalizes a control server request map, translating {\"argv\": [...]} into a command map."
  [req-map]
  (if (and (map? req-map) (sequential? (or (get req-map "argv") (:argv req-map))))
    (let [raw-tokens (mapv str (or (get req-map "argv") (:argv req-map)))
          global-valued #{"--state-dir" "--bootstrap" "--port" "--control-port"
                          "--ice-ufrag" "--ice-pwd" "--events-out" "--cmd-file" "--transport"}
          global-bool #{"--auto-sync" "--no-auto-sync" "--autonomous"
                        "--auto-register-home-set" "--no-auto-register-home-set"}
          cleaned (loop [in (vec raw-tokens)
                         out []]
                    (if (empty? in)
                      out
                      (let [t (first in)]
                        (cond
                          (and (empty? out) (contains? #{"light-node" "ctl"} t))
                          (recur (vec (rest in)) out)

                          (contains? global-valued t)
                          (recur (vec (drop 2 in)) out)

                          (contains? global-bool t)
                          (recur (vec (rest in)) out)

                          :else
                          (recur (vec (rest in)) (conj out t))))))
          subverb (first cleaned)
          subargs (vec (rest cleaned))]
      (cond
        (or (nil? subverb) (str/blank? subverb))
        {"error" "missing-subverb"}

        (= subverb "wait-event")
        (build-one-shot-cmd-map "wait" subargs)

        :else
        (let [sync-flag? (some #{"--auto-sync" "--sync"} raw-tokens)
              m (build-one-shot-cmd-map subverb subargs)]
          (if (and sync-flag? (contains? #{"account" "escrows"} (get m "cmd")))
            (assoc m "sync" true)
            m))))
    req-map))

(defn post-control-request!
  "Sends a JSON command map or {\"argv\": [...]} payload to http://127.0.0.1:<port>/ctl."
  [port token payload-map timeout-ms]
  (let [body-json (json/write-str payload-map)
        client (default-http11-client)
        req (-> (HttpRequest/newBuilder)
                (.uri (URI/create (str "http://127.0.0.1:" port "/ctl")))
                (.timeout (Duration/ofMillis (max 1000 (long (or timeout-ms 10000)))))
                (.header "Authorization" (str "Bearer " token))
                (.header "Content-Type" "application/json")
                (.POST (HttpRequest$BodyPublishers/ofString body-json StandardCharsets/UTF_8))
                (.build))
        resp (.send client req (HttpResponse$BodyHandlers/ofString StandardCharsets/UTF_8))
        status-code (.statusCode resp)
        resp-body (.body resp)]
    (if (= status-code 200)
      (try (json/read-str resp-body) (catch Exception _ {"ok" false "error" "invalid-json" "raw" resp-body}))
      {"ok" false "status" status-code "error" resp-body})))

(defn start-control-server!
  "Starts loopback-only (127.0.0.1) control HTTP server on control-port (default 5020 or ephemeral).
   Writes <state-dir>/control.json with 0600 permissions."
  [state-dir ctx conn-opts]
  (let [req-port (int (or (:control-port conn-opts) 5020))
        server (try
                 (HttpServer/create (InetSocketAddress. "127.0.0.1" req-port) 0)
                 (catch Exception e
                   (binding [*out* *err*]
                     (println (str "WARN: Failed to bind control server to 127.0.0.1:" req-port " (" (.getMessage e) "). Falling back to ephemeral port.")))
                   (when-let [st (:state-atom ctx)]
                     (swap! st update-in [:diagnostics :control-port-bind-failed] (fnil inc 0)))
                   (try
                     (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
                     (catch Exception e2
                       (binding [*out* *err*]
                         (println (str "ERROR: Failed to bind control server to ephemeral port: " (.getMessage e2))))
                       (when-let [st (:state-atom ctx)]
                         (swap! st update-in [:diagnostics :control-server-bind-fatal] (fnil inc 0)))
                       (throw e2)))))
        actual-port (.getPort (.getAddress server))
        token (basalt/bytes->hex (crypto/random-bytes 32))
        pid (extract-pid)
        ctrl-file (io/file state-dir "control.json")
        ctrl-info {"port" actual-port
                   "token" token
                   "pid" (or pid 0)}
        state-atom (:state-atom ctx)
        executor (Executors/newCachedThreadPool
                  (reify ThreadFactory
                    (newThread [_ r]
                      (doto (Thread. ^Runnable r)
                        (.setName "bitecho-control-http")
                        (.setDaemon true)))))
        handler (reify HttpHandler
                  (handle [_ exchange]
                    (try
                      (let [path (.getPath (.getRequestURI exchange))
                            method (.getRequestMethod exchange)
                            auth-hdr (.getFirst (.getRequestHeaders exchange) "Authorization")
                            expected-auth (str "Bearer " token)]
                        (cond
                          (not= auth-hdr expected-auth)
                          (let [resp-bytes (.getBytes (json/write-str {"ok" false "error" "unauthorized"}) "UTF-8")]
                            (.sendResponseHeaders exchange 401 (alength resp-bytes))
                            (with-open [os (.getResponseBody exchange)]
                              (.write os resp-bytes)))

                          (and (= method "POST") (= path "/ctl"))
                          (let [body-str (with-open [is (.getRequestBody exchange)]
                                           (slurp is :encoding "UTF-8"))
                                raw-req (try (json/read-str body-str) (catch Exception _ nil))
                                cmd-map (normalize-ctl-request-map raw-req)]
                            (if-not (and (map? cmd-map) (contains? cmd-map "cmd"))
                              (let [resp-bytes (.getBytes (json/write-str {"ok" false "error" "malformed-command"}) "UTF-8")]
                                (.sendResponseHeaders exchange 400 (alength resp-bytes))
                                (with-open [os (.getResponseBody exchange)]
                                  (.write os resp-bytes)))
                              (let [cmd-lock (or (:cmd-lock ctx) (:serve-cmd-lock ctx) (Object.))
                                    res (if (= (get cmd-map "cmd") "wait")
                                          (let [peek? (or (true? (get cmd-map "peek"))
                                                          (true? (:peek cmd-map))
                                                          (= (get cmd-map "peek") "true"))]
                                            (if peek?
                                              (locking cmd-lock (handle-serve-line! cmd-map ctx))
                                              (let [_block? (boolean (or (get cmd-map "block") (get cmd-map :block) (get cmd-map "until_event") (get cmd-map "until-event")))
                                                    timeout-ms (long (or (get cmd-map "timeout_ms") (get cmd-map "timeout-ms") 30000))
                                                    min-seq (when-let [ms (or (get cmd-map "min_seq") (get cmd-map "min-seq") (:min-seq cmd-map))]
                                                              (long ms))
                                                    cursor (when-let [c (or (get cmd-map "cursor") (:cursor cmd-map))]
                                                             (long c))
                                                    deadline (+ (System/currentTimeMillis) timeout-ms)]
                                                (loop []
                                                  (let [popped (locking cmd-lock
                                                                 (let [q (:event-queue @state-atom)
                                                                       has-events? (if (or min-seq cursor)
                                                                                     (some (fn [ev]
                                                                                             (let [eid (long (or (get ev "event_id") (:event-id ev) (get ev "eid") (:eid ev) 0))
                                                                                                   s   (long (or (get ev "seq") (:seq ev) 0))]
                                                                                               (and (or (nil? min-seq) (>= eid min-seq) (>= s min-seq))
                                                                                                    (or (nil? cursor) (> eid cursor)))))
                                                                                           q)
                                                                                     (seq q))]
                                                                   (if has-events?
                                                                     (handle-serve-line! cmd-map ctx)
                                                                     nil)))]
                                                    (if popped
                                                      popped
                                                      (if (and (:daemon-running? ctx) (false? @(:daemon-running? ctx)))
                                                        {"ok" false "error" "daemon-shutting-down"}
                                                        (let [rem (- deadline (System/currentTimeMillis))]
                                                          (if (<= rem 0)
                                                            (locking cmd-lock (handle-serve-line! cmd-map ctx))
                                                            (do
                                                              (Thread/sleep (min 50 (max 10 rem)))
                                                              (recur)))))))))))
                                          (let [raw-res (locking cmd-lock
                                                          (handle-serve-line! cmd-map ctx))
                                                sid (when (map? raw-res) (or (get raw-res "session_id") (:session-id raw-res)))
                                                explicit-wait (or (get cmd-map "wait_open_ms")
                                                                  (get cmd-map "wait-open-ms")
                                                                  (:wait-open-ms cmd-map))
                                                live-net? (and (:conn-atom ctx)
                                                               (connection-live? @(:conn-atom ctx) @state-atom))
                                                wait-ms (long (or explicit-wait (if live-net? 3000 0)))]
                                            (if (and (= (get cmd-map "cmd") "offer")
                                                     (true? (get raw-res "ok"))
                                                     (string? sid))
                                              (do
                                                (when (and (pos? wait-ms) live-net?)
                                                  (let [deadline (+ (System/currentTimeMillis) wait-ms)]
                                                    (loop []
                                                      (let [st-phase (get-in @state-atom [:sessions sid :state])]
                                                        (when (and (not= st-phase "open")
                                                                   (< (System/currentTimeMillis) deadline))
                                                          (try (Thread/sleep 25) (catch InterruptedException _ nil))
                                                          (recur))))))
                                                (assoc raw-res
                                                       "session_phase"
                                                       (or (get-in @state-atom [:sessions sid :state]) "initiating")))
                                              raw-res)))
                                    resp-bytes (.getBytes (json/write-str res) "UTF-8")]
                                (.sendResponseHeaders exchange 200 (alength resp-bytes))
                                (with-open [os (.getResponseBody exchange)]
                                  (.write os resp-bytes)))))

                          :else
                          (let [resp-bytes (.getBytes (json/write-str {"ok" false "error" "not-found"}) "UTF-8")]
                            (.sendResponseHeaders exchange 404 (alength resp-bytes))
                            (with-open [os (.getResponseBody exchange)]
                              (.write os resp-bytes)))))
                      (catch Exception e
                        (when state-atom
                          (swap! state-atom update-in [:diagnostics :control-server-error] (fnil inc 0)))
                        (try
                          (let [err-map {"ok" false "error" "internal-server-error" "message" (or (.getMessage e) (str (class e)))}
                                err-bytes (.getBytes (json/write-str err-map) "UTF-8")]
                            (.sendResponseHeaders exchange 500 (alength err-bytes))
                            (with-open [os (.getResponseBody exchange)]
                              (.write os err-bytes)))
                          (catch Exception _ nil))))))]
    (.createContext server "/ctl" handler)
    (.setExecutor server executor)
    (.start server)
    (let [tmp-file (java.io.File/createTempFile "control-" ".tmp" (io/file state-dir))]
      (try
        (Files/write (.toPath tmp-file) (.getBytes (json/write-str ctrl-info) "UTF-8") (into-array java.nio.file.OpenOption []))
        (try (Files/setPosixFilePermissions (.toPath tmp-file) (PosixFilePermissions/fromString "rw-------")) (catch Exception _ nil))
        (Files/move (.toPath tmp-file) (.toPath ctrl-file) (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE StandardCopyOption/REPLACE_EXISTING]))
        (catch Exception _
          (Files/move (.toPath tmp-file) (.toPath ctrl-file) (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING])))))
    {:server server
     :port actual-port
     :token token
     :control-file ctrl-file
     :stop! (fn []
              (try (.stop server 0) (catch Exception _ nil))
              (try (.shutdownNow executor) (catch Exception _ nil))
              (when (.exists ctrl-file)
                (try (.delete ctrl-file) (catch Exception _ nil))))}))

(defn run-ctl!
  "Executes a CLI command against a running light-node daemon via loopback control socket."
  [opts]
  (let [state-dir (:state-dir opts)
        control-file (io/file state-dir "control.json")
        out-writer (PrintWriter. System/out true)]
    (if-not (.exists control-file)
      (let [err {"ok" false "error" "daemon-not-running" "hint" "start daemon with 'serve' first"}]
        (emit-json-line! out-writer err)
        err)
      (let [control-data (try
                           (json/read-str (slurp control-file))
                           (catch Exception e
                             {"error" (.getMessage e)}))
            port (or (:control-port opts) (get control-data "port") (get control-data :port))
            token (or (get control-data "token") (get control-data :token))
            subverb (:ctl-subverb opts)
            subargs (:ctl-args opts)]
        (if-not (and port token subverb)
          (let [err {"ok" false "error" "invalid-control-metadata-or-subverb"}]
            (emit-json-line! out-writer err)
            err)
          (let [cmd-map (build-one-shot-cmd-map subverb subargs)
                body-json (json/write-str cmd-map)
                block? (boolean (or (get cmd-map "block") (get cmd-map :block) (get cmd-map "until_event") (get cmd-map "until-event")))
                timeout (cond
                          (= subverb "wait")
                          (if block?
                            (Duration/ofDays 365)
                            (Duration/ofMillis (+ 5000 (long (or (get cmd-map "timeout_ms") (get cmd-map "timeout-ms") 30000)))))
                          (contains? #{"put" "artifact-put"} subverb)
                          (Duration/ofSeconds 60)
                          :else
                          (Duration/ofSeconds 10))
                client (default-http11-client)
                req (-> (HttpRequest/newBuilder)
                        (.uri (URI/create (str "http://127.0.0.1:" port "/ctl")))
                        (.timeout timeout)
                        (.header "Authorization" (str "Bearer " token))
                        (.header "Content-Type" "application/json")
                        (.POST (HttpRequest$BodyPublishers/ofString body-json StandardCharsets/UTF_8))
                        (.build))]
            (try
              (let [resp (.send client req (HttpResponse$BodyHandlers/ofString StandardCharsets/UTF_8))
                    status-code (.statusCode resp)
                    resp-body (.body resp)]
                (if (= status-code 200)
                  (let [parsed (try (json/read-str resp-body) (catch Exception _ resp-body))]
                    (if (map? parsed)
                      (emit-json-line! out-writer parsed)
                      (.println out-writer resp-body))
                    parsed)
                  (let [err {"ok" false "status" status-code "error" resp-body}]
                    (emit-json-line! out-writer err)
                    err)))
              (catch Exception e
                (let [err {"ok" false "error" "control-request-failed" "message" (.getMessage e)}]
                  (emit-json-line! out-writer err)
                  err)))))))))

(defn run-auto-sync-tick!
  "Executes a single non-blocking background chain-state quorum sync tick.
   Updates state-atom, persists to state-file when sync succeeds, emits a structured
   `auto-sync` JSONL event, diagnoses failures loudly (Rule 5), and optionally renews
   `register-home-set` when `:auto-register-home-set?` is enabled."
  [state-atom bootstrap identity state-file conn-opts]
  (let [pubkey (or (:pubkey-hex identity) (:pubkey identity))
        privkey (:privkey-bytes identity)
        conn-atom (:conn-atom conn-opts)
        event-out (:event-out conn-opts)
        sync-opts (assoc (or conn-opts {}) :identity identity)
        res (try
              (maybe-sync-account-state! state-atom bootstrap pubkey privkey sync-opts)
              (catch Exception e
                {:ok? false :error (or (.getMessage e) "auto-sync-tick-failed")}))]
    (if (:ok? res)
      (let [_ (when (:auto-register-home-set? conn-opts)
                (let [price (long (or (:home-set-price conn-opts) 10))
                      hs-res (light-core/handle-command @state-atom {"cmd" "register-home-set" "price" price} privkey)
                      replay-envs (light-core/build-unacked-replay-envelopes @state-atom privkey)
                      envs (into (vec replay-envs) (:net-envelopes hs-res))]
                  (when (seq envs)
                    (let [live? (and conn-atom (connection-live? @conn-atom @state-atom))
                          sent? (if live?
                                  (send-all-envelopes! (:send-fn @conn-atom) envs)
                                  (when-let [rfn (:reconnect-fn conn-opts)]
                                    (let [reconn (rfn)]
                                      (and (:ok? reconn)
                                           (send-all-envelopes! (:send-fn reconn) envs)))))]
                      (if sent?
                        (reset! state-atom (assoc (:state hs-res) :connected? true :connection-error nil))
                        (when conn-atom
                          (apply-conn-event! conn-atom {:type :send-failed :error "auto-register-home-set-send-failed"} conn-opts)
                          (sync-conn-diagnostics! state-atom conn-atom)))))))
            _ (when state-file
                (try (save-light-state! state-file @state-atom) (catch Exception _ nil)))
            st @state-atom
            fin-ep (long (or (get-in st [:account :finalized-epoch]) (:epoch st) 0))
            bal (long (or (get-in st [:account :balance]) 0))
            spend (long (or (get-in st [:account :spendable]) bal 0))]
        (when event-out
          (event-out {"event" "auto-sync"
                      "ok" true
                      "finalized_epoch" fin-ep
                      "balance" bal
                      "spendable" spend
                      "synced" true}))
        res)
      (let [err (str (or (:error res) "auto-sync-tick-failed"))]
        (when conn-atom
          (apply-conn-event! conn-atom {:type :auto-sync-failed :error err} conn-opts)
          (sync-conn-diagnostics! state-atom conn-atom))
        (when event-out
          (event-out {"event" "auto-sync"
                      "ok" false
                      "synced" false
                      "error" err}))
        res))))

(defn- detect-lan-ipv4
  "Finds the first up, non-loopback IPv4 host address, preferring site-local addresses,
   falling back to 127.0.0.1 on exception or if none found."
  []
  (try
    (let [ifaces (enumeration-seq (java.net.NetworkInterface/getNetworkInterfaces))
          valid-addrs (for [iface ifaces
                            :when (and (.isUp iface)
                                       (not (.isLoopback iface)))
                            addr (enumeration-seq (.getInetAddresses iface))
                            :when (and (instance? java.net.Inet4Address addr)
                                       (not (.isLoopbackAddress addr)))]
                        addr)
          site-local (first (filter #(.isSiteLocalAddress ^java.net.InetAddress %) valid-addrs))
          chosen (or site-local (first valid-addrs))]
      (if chosen
        (.getHostAddress ^java.net.InetAddress chosen)
        "127.0.0.1"))
    (catch Exception _
      "127.0.0.1")))

(defonce ^:private single-instance-lock-guard (Object.))

(defn- default-pid-alive?
  [pid]
  (try
    (when (and pid (pos? (long pid)))
      (let [ph (ProcessHandle/of (long pid))]
        (and (.isPresent ph) (.isAlive ^ProcessHandle (.get ph)))))
    (catch Exception _ false)))

(defn- current-jvm-pid
  ^long []
  (try
    (.pid (ProcessHandle/current))
    (catch Exception _ 1)))

(defn check-single-instance-lock
  "Atomic single-instance serve/driver guard (`BIP-010` / `P-OPS-3`, Rule 5):
   Probes `<state-dir>/serve.lock` and `<state-dir>/control.json` for an active PID.
   - If held by a live PID (`(pid-alive-fn locked-pid)` is true and `locked-pid != current-pid`),
     fails fast without overwriting `control.json`, returning a counted `:diagnose`
     (`:reason :duplicate-serve-instance-rejected`).
   - If the lock is from a dead PID, reclaims the stale lock, records `:reclaimed-stale-lock? true`,
     and writes `{:pid current-pid :timestamp-ms ...}` into `<state-dir>/serve.lock`."
  ([state-dir]
   (check-single-instance-lock state-dir nil))
  ([state-dir {:keys [current-pid pid-alive-fn timestamp-ms state]}]
   (locking single-instance-lock-guard
     (let [dir (io/file (or state-dir "."))
           _ (when-not (.exists dir) (.mkdirs dir))
           lock-file (io/file dir "serve.lock")
           ctrl-file (io/file dir "control.json")
           my-pid (long (or current-pid (current-jvm-pid)))
           alive-fn (or pid-alive-fn default-pid-alive?)
           now-ms (long (or timestamp-ms (System/currentTimeMillis)))
           lock-info (when (.exists lock-file)
                       (try (edn/read-string (slurp lock-file)) (catch Exception _ nil)))
           ctrl-info (when (.exists ctrl-file)
                       (try (json/read-str (slurp ctrl-file)) (catch Exception _ nil)))
           existing-pid (or (when (map? lock-info) (:pid lock-info))
                            (when (map? ctrl-info) (or (get ctrl-info "pid") (:pid ctrl-info))))
           existing-pid-long (when (some? existing-pid)
                               (try (Long/parseLong (str existing-pid)) (catch Exception _ nil)))
           live-holder? (boolean (and existing-pid-long
                                      (not= existing-pid-long my-pid)
                                      (alive-fn existing-pid-long)))]
       (if live-holder?
         (let [diag {:effect :diagnose
                     :type :diagnose
                     :reason :duplicate-serve-instance-rejected
                     :locked-pid existing-pid-long
                     :attempted-pid my-pid
                     :state-dir (.getAbsolutePath dir)}
               st' (update-in (or state {:diagnostics {}})
                              [:diagnostics :duplicate-serve-instance-rejected]
                              (fnil inc 0))]
           {:ok? false
            :error "already-running"
            :locked-pid existing-pid-long
            :attempted-pid my-pid
            :diagnose diag
            :diagnostics (:diagnostics st')
            :state st'
            :effects [diag]})
         (let [reclaimed? (boolean (and existing-pid-long (not= existing-pid-long my-pid)))
               new-lock {:pid my-pid
                         :timestamp-ms now-ms
                         :reclaimed-stale-pid (when reclaimed? existing-pid-long)}
               tmp-f (java.io.File/createTempFile "serve-lock-" ".tmp" dir)]
           (try
             (spit tmp-f (pr-str new-lock))
             (try
               (Files/move (.toPath tmp-f) (.toPath lock-file)
                           (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                                 StandardCopyOption/REPLACE_EXISTING]))
               (catch Exception _
                 (Files/move (.toPath tmp-f) (.toPath lock-file)
                             (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
             (finally
               (when (.exists tmp-f) (try (.delete tmp-f) (catch Exception _ nil)))))
           (cond-> {:ok? true
                    :locked-pid my-pid
                    :lock-file (.getAbsolutePath lock-file)
                    :reclaimed-stale-lock? reclaimed?
                    :effects (if reclaimed?
                               [{:effect :diagnose
                                 :type :diagnose
                                 :reason :stale-serve-lock-reclaimed
                                 :stale-pid existing-pid-long
                                 :new-pid my-pid}]
                               [])}
             reclaimed? (assoc :stale-pid existing-pid-long))))))))

(defn acquire-serve-lock!
  "Acquires the single-instance lock for `state-dir`."
  ([state-dir]
   (check-single-instance-lock state-dir nil))
  ([state-dir opts]
   (check-single-instance-lock state-dir opts)))

(defn release-serve-lock!
  "Releases `<state-dir>/serve.lock` if owned by `expected-pid` (or unconditionally when `expected-pid` is nil)."
  ([state-dir]
   (release-serve-lock! state-dir nil))
  ([state-dir expected-pid]
   (locking single-instance-lock-guard
     (when state-dir
       (let [lock-file (io/file state-dir "serve.lock")]
         (when (.exists lock-file)
           (let [info (try (edn/read-string (slurp lock-file)) (catch Exception _ nil))
                 owner-pid (when (map? info) (:pid info))]
             (when (or (nil? expected-pid)
                       (nil? owner-pid)
                       (= (long expected-pid) (long owner-pid)))
               (try (.delete lock-file) (catch Exception _ false))))))))))

(defn run-serve!
  "Runs the light node in continuous JSONL serve mode reading STDIN (and optional --cmd-file) and writing STDOUT (and optional --events-out).
   Enforces the atomic single-instance serve lock (`BIP-010` / `P-OPS-3`, Rule 5)."
  [opts]
  (let [state-dir (:state-dir opts)
        out-writer (or (:out-writer opts)
                       (if (:embedded? opts)
                         (PrintWriter. (java.io.StringWriter.) true)
                         (PrintWriter. System/out true)))
        events-out (:events-out opts)
        lock-res (if (:skip-single-instance-lock? opts)
                   {:ok? true :locked-pid (current-jvm-pid)}
                   (acquire-serve-lock! state-dir opts))]
    (if-not (:ok? lock-res)
      (let [err-ev {"event" "duplicate-serve-rejected"
                    "ok" false
                    "error" "already-running"
                    "locked_pid" (:locked-pid lock-res)
                    "diagnose" "duplicate-serve-instance-rejected"}]
        (emit-json-line! out-writer err-ev events-out)
        lock-res)
      (let [my-lock-pid (:locked-pid lock-res)
            _ (when (:reclaimed-stale-lock? lock-res)
                (emit-json-line! out-writer
                                 {"event" "stale-serve-lock-reclaimed"
                                  "stale_pid" (:stale-pid lock-res)
                                  "pid" my-lock-pid}
                                 events-out))
            state-file (str (io/file state-dir "state.fressian"))
            cmd-file (:cmd-file opts)
            identity (load-or-create-light-identity! state-dir)
            bootstrap (discovery/load-bootstrap-descriptor! (:bootstrap opts))
            loaded-state (load-light-state! state-file)
            base-state (or (when loaded-state
                             (cond-> loaded-state
                               (some? (:autonomous? opts)) (assoc :autonomous? (boolean (:autonomous? opts)))
                               (seq (:nodes bootstrap)) (assoc :bootstrap bootstrap)
                               (:directory-pubkey bootstrap) (assoc :trusted-directory-pubkey (:directory-pubkey bootstrap))
                               (:trusted-dac-anchors opts) (assoc :trusted-dac-anchors (:trusted-dac-anchors opts))
                               (:fingerprint identity) (assoc :fingerprint (:fingerprint identity))
                               (:ice-creds identity) (assoc :ice-creds (:ice-creds identity))
                               (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                               (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                               (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap)))))
                           (light-core/init-light-state identity (cond-> {:bootstrap bootstrap
                                                                          :autonomous? (boolean (:autonomous? opts false))}
                                                                   (:subnet-id opts) (assoc :subnet-id (:subnet-id opts))
                                                                   (:trusted-dac-anchors opts) (assoc :trusted-dac-anchors (:trusted-dac-anchors opts))
                                                                   (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                                                                   (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                                                                   (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap))))))
            initial-state (cond-> (assoc base-state :max-epoch-skew (long (or (:max-epoch-skew opts) (:max-epoch-skew base-state) 15)))
                            (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                            (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                            (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap))))
            state-atom (atom initial-state)
            conn-atom (atom (init-conn-state))
            event-out (fn [ev] (emit-json-line! out-writer ev events-out))
            serve-cmd-lock (Object.)
            conn-opts-atom (atom nil)
            reconnect-fn (fn []
                           (when conn-atom
                             (apply-conn-event! conn-atom {:type :dial-started} @conn-opts-atom))
                           (let [target-gen (if conn-atom (:generation @conn-atom 0) 1)
                                 cursor (if conn-atom (:validator-cursor @conn-atom 0) 0)
                                 home-set (if state-atom (:home-set @state-atom) [])
                                 opts-with-gen (assoc (or @conn-opts-atom {})
                                                      :generation target-gen
                                                      :validator-cursor cursor
                                                      :home-set home-set)
                                 reconn (connect-validators! identity bootstrap opts-with-gen)]
                             (if (:ok? reconn)
                               (do
                                 (when conn-atom
                                   (apply-conn-event! conn-atom (assoc reconn :type :dial-ok :generation target-gen) @conn-opts-atom))
                                 (swap! state-atom assoc
                                        :connected? true
                                        :connection-error nil)
                                 (sync-conn-diagnostics! state-atom conn-atom)
                                 (let [recovery-envs (build-reconnect-recovery-envelopes @state-atom (:privkey-bytes identity))]
                                   (when (seq recovery-envs)
                                     (send-all-envelopes! (:send-fn reconn) recovery-envs)))
                                 reconn)
                               (let [err (or (:error reconn) "listener-disabled")]
                                 (when conn-atom
                                   (apply-conn-event! conn-atom {:type :dial-failed :error err :node (:node reconn) :generation target-gen} @conn-opts-atom))
                                 (swap! state-atom assoc
                                        :connected? false
                                        :connection-error err)
                                 (sync-conn-diagnostics! state-atom conn-atom)
                                 reconn))))
            mdns-host (mdns/generate-mdns-hostname)
            lan-ip (detect-lan-ipv4)
            ingress-port (int (or (:ingress-tcp-port opts) 0))
            default-cands (if (pos? ingress-port)
                            [(str "udp://" mdns-host ":" ingress-port)
                             (str "udp://" lan-ip ":" ingress-port)
                             (str "tcp://" lan-ip ":" ingress-port)]
                            [])
            _ (swap! state-atom assoc
                     :mdns-hostname mdns-host
                     :lan-ip lan-ip
                     :default-p2p-candidates default-cands)
            mdns-svc (try (mdns/start-mdns-service! {:initial-hosts {mdns-host lan-ip}}) (catch Exception _ nil))
            mdns-atom (or mdns-svc (atom (mdns/init-mdns-table)))
            p2p-peers-atom (atom {})
            ingress-peers-atom (atom {})
            conn-opts (assoc opts
                             :state-atom state-atom
                             :conn-atom conn-atom
                             :event-out event-out
                             :reconnect-fn reconnect-fn
                             :state-file state-file
                             :ingress-peers-atom ingress-peers-atom
                             :p2p-peers-atom p2p-peers-atom
                             :mdns-atom mdns-atom
                             :mdns-svc mdns-svc
                             :cmd-lock serve-cmd-lock
                             :async-reconnect? true)
            _ (reset! conn-opts-atom conn-opts)
            ingress-listener (start-ingress-tcp-listener! identity conn-opts)
            conn-res (reconnect-fn)
            daemon-running? (atom true)
            auto-sync-enabled? (boolean (:auto-sync? opts true))
            sync-interval-ms (max 1000 (long (or (:sync-interval-ms opts) 15000)))
            ctx {:state-atom state-atom
                 :conn-atom conn-atom
                 :out-writer out-writer
                 :events-out events-out
                 :state-file state-file
                 :identity identity
                 :bootstrap bootstrap
                 :ingress-peers-atom ingress-peers-atom
                 :p2p-peers-atom p2p-peers-atom
                 :mdns-atom mdns-atom
                 :conn-opts conn-opts
                 :cmd-lock serve-cmd-lock
                 :serve-cmd-lock serve-cmd-lock
                 :daemon-running? daemon-running?}
            _ (when auto-sync-enabled?
                (doto (Thread.
                       ^Runnable
                       (fn []
                         (while @daemon-running?
                           (run-auto-sync-tick! state-atom bootstrap identity state-file conn-opts)
                           (try
                             (Thread/sleep sync-interval-ms)
                             (catch InterruptedException _
                               (reset! daemon-running? false))))))
                  (.setDaemon true)
                  (.setName "bitecho-light-node-auto-sync")
                  (.start)))
            _ (when (and cmd-file (not (str/blank? (str cmd-file))))
                (let [cf (io/file cmd-file)
                      _ (when-let [p (.getParentFile cf)] (.mkdirs p))
                      _ (when-not (.exists cf) (spit cf ""))
                      start-offset (.length cf)]
                  (doto (Thread.
                         ^Runnable
                         (fn []
                           (loop [offset start-offset]
                             (when @daemon-running?
                               (let [{:keys [lines next-offset]} (try
                                                                   (read-new-cmd-file-lines! cmd-file offset)
                                                                   (catch Exception _
                                                                     {:lines [] :next-offset offset}))]
                                 (doseq [line lines]
                                   (locking serve-cmd-lock
                                     (binding [*out* *err*]
                                       (handle-serve-line! line ctx))))
                                 (try
                                   (Thread/sleep 50)
                                   (catch InterruptedException _
                                     (reset! daemon-running? false)))
                                 (recur next-offset))))))
                    (.setDaemon true)
                    (.setName "bitecho-light-node-cmd-file")
                    (.start))))
            effective-relay-url (when-not (:no-poll? opts)
                                  (or (when (and (string? (:relay-url opts)) (not (str/blank? (:relay-url opts))))
                                        (:relay-url opts))
                                      (:relay-url bootstrap)
                                      (get-in bootstrap [:relay :url])
                                      (when (= (:domain bootstrap) "bitecho.org")
                                        "https://ns1.bitecho.org")))
            _ (when (and (string? effective-relay-url) (not (str/blank? effective-relay-url)))
                (doto (Thread.
                       ^Runnable
                       (fn []
                         (loop [since-mseq (long (or (:relay-since-seq @state-atom) 0))
                                since-bseq (long (or (:relay-since-broadcast-seq @state-atom) 0))]
                           (when @daemon-running?
                             (let [eff-subnets (vec (sort (light-core/effective-subscribed-subnets @state-atom)))
                                   subnets (or (:subnets opts) eff-subnets)
                                   poll-res (try
                                              (poll-relay-envelopes! effective-relay-url
                                                                     (:pubkey-hex identity)
                                                                     (:privkey-bytes identity)
                                                                     (cond-> {:since-seq since-mseq
                                                                              :since-broadcast-seq since-bseq
                                                                              :wait-ms 5000}
                                                                       subnets (assoc :subnets subnets)))
                                              (catch Exception _ nil))
                                   msgs (or (get poll-res "messages") (get poll-res :messages) [])
                                   bcasts (or (get poll-res "broadcasts") (get poll-res :broadcasts) [])
                                   last-bseq (or (get poll-res "last_broadcast_seq")
                                                 (get poll-res "last-broadcast-seq")
                                                 (get poll-res :last_broadcast_seq))
                                   all-items (concat msgs bcasts)
                                   new-mseq (long (or (get (last msgs) "relay_seq") (get (last msgs) "relay-seq") since-mseq))
                                   new-bseq (long (or last-bseq (get (last bcasts) "broadcast_seq") (get (last bcasts) "broadcast-seq") since-bseq))]
                               (when (or (not= new-mseq since-mseq) (not= new-bseq since-bseq))
                                 (swap! state-atom assoc :relay-since-seq new-mseq :relay-since-broadcast-seq new-bseq))
                               (doseq [item all-items]
                                 (let [env-raw (or (get item "envelope_hex") (get item "envelope")
                                                   (get item :envelope_hex) (get item :envelope))
                                       wire-bytes (when env-raw (try (basalt/hex->bytes (str env-raw)) (catch Exception _ nil)))]
                                   (when wire-bytes
                                     (let [r-box (atom nil)
                                           new-st (swap! state-atom
                                                         (fn [st]
                                                           (let [r (light-core/handle-wire-payload st wire-bytes (:privkey-bytes identity))]
                                                             (reset! r-box r)
                                                             (:state r))))
                                           r @r-box]
                                       (when state-file
                                         (try (save-light-state! state-file new-st) (catch Exception _ nil)))
                                       (when r
                                         (doseq [ev (:stdout-events r)]
                                           (event-out ev))
                                         (when-let [dial-info (:p2p-dial r)]
                                           (dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom mdns-atom (:privkey-bytes identity) event-out dial-info))
                                         (when (seq (:net-envelopes r))
                                           (send-routed-envelopes! (:net-envelopes r)
                                                                   (:send-fn conn-res)
                                                                   p2p-peers-atom
                                                                   ingress-peers-atom
                                                                   state-atom
                                                                   (:privkey-bytes identity))
                                           (when (not= :http-relay (:transport conn-res))
                                             (doseq [env (remove :p2p-direct? (:net-envelopes r))]
                                               (try
                                                 (submit-relay-envelope! effective-relay-url env {:timeout-ms 5000})
                                                 (catch Exception _ nil))))))))))
                               (when (or (seq msgs) (seq bcasts) (> new-bseq since-bseq))
                                 (try
                                   (ack-relay-envelopes! effective-relay-url
                                                         (:pubkey-hex identity)
                                                         (:privkey-bytes identity)
                                                         new-mseq
                                                         {:ack-broadcast-seq new-bseq})
                                   (catch Exception _ nil)))
                               (recur new-mseq new-bseq))))))
                  (.setDaemon true)
                  (.setName "bitecho-light-node-relay-poll")
                  (.start)))
            ctrl-svc (try
                       (start-control-server! state-dir ctx conn-opts)
                       (catch Exception e
                         (binding [*out* *err*]
                           (println (str "ERROR: Could not start control server: " (.getMessage e))))
                         (when-let [st (:state-atom ctx)]
                           (swap! st update-in [:diagnostics :control-server-fatal] (fnil inc 0)))
                         nil))
            shutdown-hook (Thread. ^Runnable (fn []
                                               (release-serve-lock! state-dir my-lock-pid)
                                               (when ctrl-svc
                                                 (try ((:stop! ctrl-svc)) (catch Exception _ nil)))))
            _ (.addShutdownHook (Runtime/getRuntime) shutdown-hook)
            _ (doto (Thread.
                     ^Runnable
                     (fn []
                       (while @daemon-running?
                         (try
                           (let [now-ms (System/currentTimeMillis)
                                 st @state-atom
                                 sessions (:sessions st)]
                         ;; F-5: 30s Outbox RTO Retransmit Loop across all open sessions
                             (doseq [[sid _] sessions]
                               (try
                                 (let [rx-res (light-core/retransmit-unacked-outbox @state-atom sid now-ms 30000)]
                                   (when (not= @state-atom (:state rx-res))
                                     (reset! state-atom (:state rx-res))
                                     (when (some? state-file)
                                       (save-light-state! state-file @state-atom))
                                     (when (seq (:net-envelopes rx-res))
                                       (send-routed-envelopes! (:net-envelopes rx-res)
                                                               (:send-fn @conn-atom)
                                                               p2p-peers-atom
                                                               ingress-peers-atom
                                                               state-atom
                                                               (:privkey-bytes identity)))
                                     (when (seq (:stdout-events rx-res))
                                       (doseq [evt (:stdout-events rx-res)]
                                         (emit-json-line! out-writer evt events-out)))))
                                 (catch Exception _ nil)))
                         ;; F-6: Gated Autonomous P2P Re-Offers with exponential backoff & tie-breaker protection
                             (let [reconn-sids (for [[sid _] (:sessions @state-atom)
                                                     :when (light-core/should-auto-reoffer? @state-atom sid now-ms (:autonomous? opts))]
                                                 sid)]
                               (doseq [sid reconn-sids]
                                 (let [sess (get-in @state-atom [:sessions sid])
                                       pref-cands (or (get-in sess [:p2p-meta :local-candidates])
                                                      (get-in sess [:p2p-meta :preferred-candidates])
                                                      (get-in sess [:p2p :local-candidates])
                                                      (:default-p2p-candidates @state-atom))
                                       pref-tr (or (get-in sess [:p2p-meta :preferred-transport]) "udp")
                                       cmd {"cmd" "p2p-offer" "session_id" sid "candidates" pref-cands "transport" pref-tr}]
                                   (swap! state-atom light-core/record-reoffer-attempt sid now-ms)
                                   (when (some? state-file)
                                     (save-light-state! state-file @state-atom))
                                   (locking serve-cmd-lock
                                     (handle-serve-line! cmd ctx))))))
                           (catch Exception _ nil))
                         (try (Thread/sleep 5000) (catch InterruptedException _ (reset! daemon-running? false))))))
                (.setDaemon true)
                (.setName "bitecho-light-node-maintenance")
                (.start))]
        (if (:ok? conn-res)
          (emit-json-line! out-writer {"event" "ready"
                                       "connected" true
                                       "transport" (if (and (string? (:relay-url opts)) (not (str/blank? (:relay-url opts))))
                                                     "http-relay"
                                                     (name (or (:transport opts) :udp)))}
                           events-out)
          (emit-json-line! out-writer {"event" "connection-failed"
                                       "connected" false
                                       "error" (:error conn-res)}
                           events-out))
        (if (:embedded? opts)
          {:state-atom state-atom
           :conn-atom conn-atom
           :control-server ctrl-svc
           :port (:port ctrl-svc)
           :token (:token ctrl-svc)
           :daemon-running? daemon-running?
           :stop! (fn []
                    (reset! daemon-running? false)
                    (release-serve-lock! state-dir my-lock-pid)
                    (when conn-atom
                      (apply-conn-event! conn-atom {:type :shutdown} conn-opts))
                    (when ctrl-svc
                      (try ((:stop! ctrl-svc)) (catch Exception _ nil)))
                    (when mdns-svc
                      (try (mdns/stop-mdns-service! mdns-svc) (catch Exception _ nil)))
                    (when-let [stop-fn (:stop! ingress-listener)]
                      (try (stop-fn) (catch Exception _ nil))))}
          (try
            (binding [*out* *err*]
              (let [reader (BufferedReader. (InputStreamReader. System/in "UTF-8"))]
                (loop []
                  (if-let [line (.readLine reader)]
                    (do
                      (when-not (str/blank? line)
                        (locking serve-cmd-lock
                          (handle-serve-line! line ctx)))
                      (recur))
                    (when (or (:keep-alive-eof? opts) (and cmd-file (not (str/blank? (str cmd-file)))))
                      (while @daemon-running?
                        (try (Thread/sleep 1000) (catch InterruptedException _ (reset! daemon-running? false)))))))))
            (finally
              (reset! daemon-running? false)
              (release-serve-lock! state-dir my-lock-pid)
              (when conn-atom
                (apply-conn-event! conn-atom {:type :shutdown} conn-opts))
              (when ctrl-svc
                (try ((:stop! ctrl-svc)) (catch Exception _ nil)))
              (when mdns-svc
                (try (mdns/stop-mdns-service! mdns-svc) (catch Exception _ nil)))
              (when-let [stop-fn (:stop! ingress-listener)]
                (try (stop-fn) (catch Exception _ nil))))))))))

(defn- pid-alive? [pid]
  (try
    (when-let [p (ProcessHandle/of (long pid))]
      (.isPresent p))
    (catch Exception _ false)))

(defn- try-delegate-one-shot-to-daemon!
  "If <state-dir>/control.json exists and the daemon's /ctl socket is reachable,
   delegates the one-shot command map to the running serve daemon (Rule 4).
   If unreachable and the daemon process is alive, fails closed with daemon-control-unreachable (F-D25-1)."
  [state-dir cmd-map opts]
  (let [ctrl-file (when state-dir (io/file state-dir "control.json"))]
    (when (and ctrl-file (.exists ctrl-file) (map? cmd-map) (contains? cmd-map "cmd"))
      (try
        (let [info (json/read-str (slurp ctrl-file))
              pid (or (get info "pid") (:pid info))
              port (or (:control-port opts) (get info "port") (:port info))
              token (or (get info "token") (:token info))
              eff-cmd (if (and (:auto-sync? opts) (contains? #{"account" "escrows"} (get cmd-map "cmd")))
                        (assoc cmd-map "sync" true)
                        cmd-map)
              timeout-ms (or (:timeout-ms opts)
                             (if (contains? #{"put" "artifact-put"} (get cmd-map "cmd")) 60000 15000))]
          (if (and port token)
            (let [res (try (post-control-request! port token eff-cmd timeout-ms) (catch Exception _ nil))]
              (cond
                res res
                (and pid (pid-alive? pid))
                {"ok" false
                 "error" "daemon-control-unreachable"
                 "pid" pid
                 "port" port
                 "status" "rejected"}
                :else nil))
            (when (and pid (pid-alive? pid))
              {"ok" false
               "error" "daemon-control-unreachable"
               "pid" pid
               "port" port
               "status" "rejected"})))
        (catch Exception _ nil)))))

(defn poll-and-ingest-relay-once!
  "Polls the relay once, ingests incoming messages/broadcasts, saves state to disk,
   and acks to the relay. Returns a vector of net-envelopes generated during ingestion."
  [relay-url identity state-atom state-file opts]
  (let [pk-hex (or (:pubkey-hex identity) (:pubkey identity))
        priv-bytes (:privkey-bytes identity)
        since-mseq (long (or (:relay-since-seq @state-atom) 0))
        since-bseq (long (or (:relay-since-broadcast-seq @state-atom) 0))
        eff-subnets (vec (sort (light-core/effective-subscribed-subnets @state-atom)))
        subnets (or (:subnets opts) eff-subnets)
        poll-res (try
                   (poll-relay-envelopes! relay-url
                                          pk-hex
                                          priv-bytes
                                          (cond-> {:since-seq since-mseq
                                                   :since-broadcast-seq since-bseq
                                                   :timeout-ms 0}
                                            subnets (assoc :subnets subnets)))
                   (catch Exception _ nil))
        msgs (or (get poll-res "messages") (get poll-res :messages) [])
        bcasts (or (get poll-res "broadcasts") (get poll-res :broadcasts) [])
        last-bseq (or (get poll-res "last_broadcast_seq")
                      (get poll-res "last-broadcast-seq")
                      (get poll-res :last_broadcast_seq))
        new-mseq (long (or (get (last msgs) "relay_seq") (get (last msgs) "relay-seq") since-mseq))
        new-bseq (long (or last-bseq (get (last bcasts) "broadcast_seq") (get (last bcasts) "broadcast-seq") since-bseq))
        all-items (concat msgs bcasts)
        auto-net-envs (atom [])]
    (when (and (not (:peek? opts))
               (or (not= new-mseq since-mseq) (not= new-bseq since-bseq)))
      (swap! state-atom assoc :relay-since-seq new-mseq :relay-since-broadcast-seq new-bseq))
    (doseq [item all-items]
      (let [env-raw (or (get item "envelope_hex") (get item "envelope")
                        (get item :envelope_hex) (get item :envelope))
            wire-bytes (when env-raw (try (basalt/hex->bytes (str env-raw)) (catch Exception _ nil)))]
        (when wire-bytes
          (let [r (light-core/handle-wire-payload @state-atom wire-bytes priv-bytes)]
            (reset! state-atom (:state r))
            (when (and (:p2p-dial r) (:p2p-peers-atom opts))
              (dial-p2p-peer! state-atom
                              (:p2p-peers-atom opts)
                              (:ingress-peers-atom opts)
                              (:mdns-atom opts)
                              priv-bytes
                              (:event-out opts)
                              (:p2p-dial r)))
            (when (seq (:net-envelopes r))
              (swap! auto-net-envs into (:net-envelopes r)))))))
    (when (and (not (:peek? opts))
               (or (not= new-mseq since-mseq) (not= new-bseq since-bseq) (seq all-items)))
      (when state-file
        (try (save-light-state! state-file @state-atom) (catch Exception _ nil))))
    (when (and (not (:peek? opts))
               (or (seq msgs) (seq bcasts) (> new-bseq since-bseq)))
      (try
        (ack-relay-envelopes! relay-url
                              pk-hex
                              priv-bytes
                              new-mseq
                              {:ack-broadcast-seq new-bseq})
        (catch Exception _ nil)))
    @auto-net-envs))

(defn run-one-shot!
  "Executes a single one-shot light-node command and outputs JSON response.
   When <state-dir>/control.json is present and reachable, automatically delegates
   to the running serve daemon over /ctl (Rule 4)."
  [opts]
  (let [state-dir (:state-dir opts)
        raw-cmd-map (:cmd-map opts)
        out-writer (PrintWriter. System/out true)]
    (if-let [delegated (try-delegate-one-shot-to-daemon! state-dir raw-cmd-map opts)]
      (do
        (emit-json-line! out-writer delegated)
        delegated)
      (let [state-file (str (io/file state-dir "state.fressian"))
            identity (load-or-create-light-identity! state-dir)
            bootstrap (discovery/load-bootstrap-descriptor! (:bootstrap opts))
            loaded-state (load-light-state! state-file)
            base-state (or (when loaded-state
                             (cond-> loaded-state
                               (some? (:autonomous? opts)) (assoc :autonomous? (boolean (:autonomous? opts)))
                               (seq (:nodes bootstrap)) (assoc :bootstrap bootstrap)
                               (:directory-pubkey bootstrap) (assoc :trusted-directory-pubkey (:directory-pubkey bootstrap))
                               (:trusted-dac-anchors opts) (assoc :trusted-dac-anchors (:trusted-dac-anchors opts))
                               (:fingerprint identity) (assoc :fingerprint (:fingerprint identity))
                               (:ice-creds identity) (assoc :ice-creds (:ice-creds identity))
                               (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                               (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                               (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap)))))
                           (light-core/init-light-state identity (cond-> {:bootstrap bootstrap
                                                                          :autonomous? (boolean (:autonomous? opts false))}
                                                                   (:subnet-id opts) (assoc :subnet-id (:subnet-id opts))
                                                                   (:trusted-dac-anchors opts) (assoc :trusted-dac-anchors (:trusted-dac-anchors opts))
                                                                   (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                                                                   (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                                                                   (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap))))))
            initial-state (cond-> (assoc base-state :max-epoch-skew (long (or (:max-epoch-skew opts) (:max-epoch-skew base-state) 15)))
                            (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                            (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                            (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap))))
            state-atom (atom initial-state)
            verb (when (map? raw-cmd-map) (get raw-cmd-map "cmd"))
            cmd-map (-> (if (and (contains? #{"directory-lookup" "directory-verify"} verb)
                                 (not (contains? raw-cmd-map "descriptor"))
                                 (not (contains? raw-cmd-map :descriptor)))
                          (let [nick (or (get raw-cmd-map "nickname") (:nickname raw-cmd-map)
                                         (get raw-cmd-map "name") (:name raw-cmd-map))
                                dom (or (get raw-cmd-map "domain") (:domain raw-cmd-map) "bitecho.org")
                                desc (when (and (string? nick) (not (str/blank? nick)))
                                       (fetch-directory-descriptor! dom nick opts))]
                            (cond-> raw-cmd-map
                              desc (assoc "descriptor" desc)))
                          raw-cmd-map)
                        (as-> m (enrich-artifact-cmd-map verb m (:relay-url opts))))
            shuttle-verb? (contains? #{"export-offer" "export-poll" "export-ack" "export-reveal"
                                       "export-p2p-offer" "export-p2p-answer" "export-send"
                                       "import-envelope" "import-poll" "import"}
                                     verb)
            sync-explicit? (boolean (or (:sync? opts) (get cmd-map "sync") (:sync? cmd-map)))
            sync-wanted? (if shuttle-verb?
                           sync-explicit?
                           (or (boolean (:auto-sync? opts))
                               (and (= verb "sync-account") (nil? (get cmd-map "balance")) (nil? (get cmd-map "snapshots")) (nil? (get cmd-map "snapshot")))
                               (and (= verb "account") sync-explicit?)
                               (and (= verb "escrows") sync-explicit?)))
            sync-opts (assoc opts :identity identity)
            sync-res (when sync-wanted?
                       (maybe-sync-account-state! state-atom bootstrap (or (:pubkey-hex identity) (:pubkey identity)) (:privkey-bytes identity) sync-opts))
            effective-relay-url (or (:relay-url opts)
                                    (:relay_url opts)
                                    (when-let [u (resolve-relay-url nil #(System/getenv %))] u)
                                    (when-let [u (:relay-url bootstrap)] (resolve-relay-url u #(System/getenv %)))
                                    (infer-bootstrap-relay-url bootstrap opts)
                                    (when (= "bitecho.org" (:domain bootstrap)) "https://ns1.bitecho.org"))
            poll-verb? (and (not (:no-poll? opts))
                            effective-relay-url
                            (not= (:connect? opts) false)
                            (or (contains? #{"inbox" "wait" "accept" "rendezvous-accept" "send"
                                             "p2p-offer" "p2p-answer" "close" "sync-account"
                                             "account" "escrows"} verb)
                                (and (= verb "status") (or (:sync? opts) (get cmd-map "sync") (:poll? opts) (get cmd-map "poll")))))
            poll-auto-envs (if poll-verb?
                             (poll-and-ingest-relay-once! effective-relay-url identity state-atom state-file opts)
                             [])]
        (if (and sync-res (false? (:ok? sync-res)))
          (let [err-resp {"ok" false "error" (:error sync-res)}]
            (emit-json-line! out-writer err-resp)
            err-resp)
          (binding [*out* *err*]
            (let [eff-domain-verb (effective-artifact-domain-verb verb cmd-map)
                  res (light-core/handle-command @state-atom cmd-map (:privkey-bytes identity))
                  _ (maybe-write-artifact-out-file! eff-domain-verb cmd-map (:response res))
                  _ (when (contains? #{"artifact-put" "artifact-revoke"} eff-domain-verb)
                      (when-let [art-relay (or (get cmd-map "relay_url")
                                               (get cmd-map "relay-url")
                                               (:relay-url cmd-map)
                                               effective-relay-url)]
                        (post-artifact-to-relay! art-relay eff-domain-verb (:response res))))
                  new-state (:state res)
                  all-net-envs (into (vec poll-auto-envs) (:net-envelopes res))
                  connect-explicit? (contains? opts :connect?)
                  connect-wanted? (if connect-explicit?
                                    (boolean (:connect? opts))
                                    (not shuttle-verb?))
                  needs-network? (and (seq all-net-envs) connect-wanted?)]
              (if needs-network?
                (let [conn-res (connect-validators! identity bootstrap opts)]
                  (if-not (:ok? conn-res)
                    (let [err-resp {"ok" false "error" (or (:error conn-res) "listener-disabled")}]
                      (emit-json-line! out-writer err-resp)
                      err-resp)
                    (let [sent? (send-all-envelopes! (:send-fn conn-res) all-net-envs)]
                      (when-let [n (:node conn-res)]
                        (try (api/close! n) (catch Exception _ nil)))
                      (if sent?
                        (do
                          (when-not (get cmd-map "peek")
                            (save-light-state! state-file new-state))
                          (emit-json-line! out-writer (:response res))
                          (:response res))
                        (let [err-resp {"ok" false "error" "connection-closed"}]
                          (emit-json-line! out-writer err-resp)
                          err-resp)))))
                (do
                  (when-not (get cmd-map "peek")
                    (save-light-state! state-file new-state))
                  (emit-json-line! out-writer (:response res))
                  (:response res))))))))))

(defn- check-daemon-status
  "Checks if a daemon is running and responsive via control.json. Returns parsed status map or nil."
  [state-dir]
  (let [ctrl-file (io/file state-dir "control.json")]
    (when (.exists ctrl-file)
      (try
        (let [info (json/read-str (slurp ctrl-file))
              port (get info "port")
              token (get info "token")
              pid (get info "pid")]
          (when (and port token)
            (let [client (default-http11-client)
                  req (-> (HttpRequest/newBuilder)
                          (.uri (URI/create (str "http://127.0.0.1:" port "/ctl")))
                          (.header "Authorization" (str "Bearer " token))
                          (.header "Content-Type" "application/json")
                          (.timeout (Duration/ofMillis 2000))
                          (.POST (HttpRequest$BodyPublishers/ofString (json/write-str {"cmd" "status"}) StandardCharsets/UTF_8))
                          (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString StandardCharsets/UTF_8))]
              (when (= 200 (.statusCode resp))
                (let [st (try (json/read-str (.body resp)) (catch Exception _ nil))]
                  (when (and (map? st) (get st "ok"))
                    (assoc st "running" true "pid" pid "control_port" port)))))))
        (catch Exception _ nil)))))

(defn run-daemon!
  "Zero-glue process supervisor managing the light-node serve daemon (start, stop, status, restart, ensure)."
  [opts]
  (let [state-dir (:state-dir opts)
        _ (when state-dir (let [d (io/file state-dir)] (when-not (.exists d) (.mkdirs d))))
        action (or (:daemon-action opts) "start")
        pid-file (io/file state-dir "daemon.pid")
        log-file (io/file state-dir "daemon.log")
        out-writer (PrintWriter. System/out true)]
    (case action
      "status"
      (if-let [st (check-daemon-status state-dir)]
        (do (emit-json-line! out-writer st) st)
        (let [res {"ok" false "running" false "error" "daemon-not-running"}]
          (emit-json-line! out-writer res)
          res))

      "stop"
      (let [ctrl-file (io/file state-dir "control.json")
            pid (or (when (.exists pid-file)
                      (try (Long/parseLong (str/trim (slurp pid-file))) (catch Exception _ nil)))
                    (when (.exists ctrl-file)
                      (try (get (json/read-str (slurp ctrl-file)) "pid") (catch Exception _ nil))))]
        (if (and pid (pos? (long pid)))
          (do
            (try
              (let [ph-opt (ProcessHandle/of (long pid))]
                (when (.isPresent ph-opt)
                  (let [ph (.get ph-opt)]
                    (.destroy ph)
                    (try (.get (.onExit ph) 3 java.util.concurrent.TimeUnit/SECONDS)
                         (catch Exception _ (.destroyForcibly ph))))))
              (catch Exception _ nil))
            (when (.exists pid-file) (try (.delete pid-file) (catch Exception _ nil)))
            (when (.exists ctrl-file) (try (.delete ctrl-file) (catch Exception _ nil)))
            (let [res {"ok" true "stopped" true "pid" pid}]
              (emit-json-line! out-writer res)
              res))
          (let [res {"ok" true "stopped" false "status" "not-running"}]
            (emit-json-line! out-writer res)
            res)))

      ("start" "ensure")
      (if-let [st (check-daemon-status state-dir)]
        ;; Idempotent: already running and healthy
        (let [res (assoc st "already_running" true)]
          (emit-json-line! out-writer res)
          res)
        ;; Not running: spawn background serve daemon
        (let [raw-args (or (:raw-args opts) [])
              filtered-args (vec (remove #(or (= % "--daemon")
                                              (= % "daemon")
                                              (= % "ensure")
                                              (= % "start")
                                              (= % "ctl"))
                                         raw-args))
              serve-args (into ["serve" "--keep-alive-eof"] (filter #(not= % "serve") filtered-args))
              serve-args (if (some #{"--state-dir"} serve-args)
                           serve-args
                           (into serve-args ["--state-dir" state-dir]))
              java-bin (str (System/getProperty "java.home") "/bin/java")
              cp (System/getProperty "java.class.path")
              jvm-flags ["--enable-native-access=ALL-UNNAMED"
                         "--add-exports=java.base/sun.security.tools.keytool=ALL-UNNAMED"
                         "--add-exports=java.base/sun.security.x509=ALL-UNNAMED"]
              cmd (into (into [java-bin] jvm-flags)
                        (into ["-cp" cp "clojure.main" "-m" "bitecho.main" "light-node"] serve-args))
              pb (doto (ProcessBuilder. (into-array String cmd))
                   (.redirectErrorStream true)
                   (.redirectOutput (ProcessBuilder$Redirect/appendTo log-file)))
              proc (.start pb)
              pid (.pid proc)]
          (spit pid-file (str pid "\n"))
          ;; Wait up to 30s for daemon to become ready
          (loop [attempts 0]
            (if-let [st (check-daemon-status state-dir)]
              (do
                (emit-json-line! out-writer st)
                st)
              (if (not (.isAlive proc))
                (let [exit-code (.exitValue proc)
                      log-tail (try (slurp log-file) (catch Exception _ ""))
                      err {"ok" false "error" "daemon-exited-early" "exit_code" exit-code "log" log-tail}]
                  (emit-json-line! out-writer err)
                  err)
                (if (>= attempts 60)
                  (let [err {"ok" false "error" "daemon-start-timeout" "pid" pid}]
                    (emit-json-line! out-writer err)
                    err)
                  (do
                    (Thread/sleep 500)
                    (recur (inc attempts)))))))))

      "restart"
      (do
        (run-daemon! (assoc opts :daemon-action "stop"))
        (Thread/sleep 500)
        (run-daemon! (assoc opts :daemon-action "start"))))))

(defn run-mcp!
  "Runs the Bitecho MCP JSON-RPC 2.0 server over stdio (`--mcp` / `mcp` mode, BIP-006 Part 1).
   All diagnostics/logging are bound to `*err*` so `stdout` carries strictly newline-delimited
   JSON-RPC 2.0 frames."
  [opts]
  (let [state-dir (:state-dir opts)
        state-file (str (io/file state-dir "state.fressian"))
        out-writer (or (:out-writer opts) (PrintWriter. System/out true))
        in-reader (or (:in-reader opts) (BufferedReader. (InputStreamReader. System/in StandardCharsets/UTF_8)))]
    (binding [*out* *err*]
      (let [identity (load-or-create-light-identity! state-dir)
            bootstrap (try (discovery/load-bootstrap-descriptor! (:bootstrap opts))
                           (catch Exception _ nil))
            loaded-state (load-light-state! state-file)
            base-state (or loaded-state
                           (light-core/init-light-state identity (cond-> {:bootstrap bootstrap}
                                                                   (:subnet-id opts) (assoc :subnet-id (:subnet-id opts)))))
            state-atom (atom base-state)
            effective-relay-url (or (:relay-url opts)
                                    (:relay-url bootstrap)
                                    (when (= (:domain bootstrap) "bitecho.org") "https://ns1.bitecho.org"))
            exec-cmd-fn (fn [cmd-map]
                          (if-let [delegated (try-delegate-one-shot-to-daemon! state-dir cmd-map opts)]
                            delegated
                            (let [verb (get cmd-map "cmd")
                                  enriched (enrich-artifact-cmd-map verb cmd-map)
                                  res (light-core/handle-command @state-atom enriched (:privkey-bytes identity))]
                              (reset! state-atom (:state res))
                              (when-not (get enriched "peek")
                                (try (save-light-state! state-file (:state res)) (catch Exception _ nil)))
                              (when (and effective-relay-url (seq (:net-envelopes res)))
                                (doseq [env (:net-envelopes res)]
                                  (try (submit-relay-envelope! effective-relay-url env {:timeout-ms 5000})
                                       (catch Exception _ nil))))
                              (:response res))))]
        (loop []
          (when-let [line (.readLine ^BufferedReader in-reader)]
            (let [trimmed (str/trim line)]
              (when-not (str/blank? trimmed)
                (let [req-map (try (json/read-str trimmed) (catch Exception _ nil))
                      rpc-resp (if (map? req-map)
                                 (mcp/handle-jsonrpc-request req-map exec-cmd-fn json/write-str)
                                 {"jsonrpc" "2.0"
                                  "id" nil
                                  "error" {"code" -32700 "message" "Parse error"}})]
                  (when rpc-resp
                    (.println ^PrintWriter out-writer (json/write-str rpc-resp))
                    (.flush ^PrintWriter out-writer)))))
            (recur)))))))

(defn run-light-node-cli!
  "Dispatches light-node CLI invocation based on parsed arguments."
  [args]
  (let [parsed (parse-light-node-args args)]
    (case (:mode parsed)
      :help
      (let [res {"ok" true
                 "help" true
                 "verbs" cli/supported-cli-verbs
                 "modes" ["one-shot" "serve" "ctl" "wait-event" "mcp"]
                 "flags" cli/known-command-flags}]
        (println (json/write-str res))
        res)
      :mcp (run-mcp! parsed)
      :daemon (run-daemon! parsed)
      :ctl (run-ctl! parsed)
      :serve (run-serve! parsed)
      :wait-event (run-wait-event! parsed)
      :one-shot (run-one-shot! parsed))))
