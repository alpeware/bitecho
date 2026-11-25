(ns bitecho.shell.light-node
  "Light-node boundary shell for Bitecho.
   Handles CLI invocation, JSONL STDIN/STDOUT serve loop, state persistence
   with atomic rename (0600 permissions), and WebRTC DataChannel agent connections."
  (:require [bitecho.backup.core :as backup]
            [bitecho.basalt.core :as basalt]
            [bitecho.cache.core :as cache]
            [bitecho.config.flags :as flags]
            [bitecho.core.data :as data]
            [bitecho.core.mesh :as core-mesh]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.key-provider :as kp]
            [bitecho.deploy.core :as deploy]
            [bitecho.errors.core :as errors]
            [bitecho.fressian :as fressian]
            [bitecho.lifecycle.lock-core :as lock-core]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.light-node.mcp :as mcp]
            [bitecho.shell.agent-sim :as agent-sim]
            [bitecho.shell.discovery :as discovery]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.updater :as updater]
            [bitecho.snapshot.core :as snap]
            [bitecho.status.core :as status-core]
            [bitecho.sync.core :as sync-core]
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
           [java.nio ByteBuffer]
           [java.nio.channels DatagramChannel FileChannel]
           [java.nio.charset StandardCharsets]
           [java.nio.file FileAlreadyExistsException Files StandardCopyOption StandardOpenOption]
           [java.nio.file.attribute PosixFilePermissions]
           [java.time Duration]
           [java.util.concurrent Executors LinkedBlockingQueue ThreadFactory TimeUnit]))

(declare dial-p2p-peer! send-routed-envelopes!)

(defonce ^:private jvm-mesh-chunk-handlers-atom (atom {}))

(defn- try-dispatch-jvm-mesh-chunk-res!
  "Intercepts inbound `:artifact-blob-chunk-res` frames strictly by `:req-id` (BIP-022 Stage D.1)."
  [payload]
  (when (seq @jvm-mesh-chunk-handlers-atom)
    (let [decoded (try (light-core/thaw-payload payload) (catch Exception _ nil))]
      (when (and (map? decoded) (= :artifact-blob-chunk-res (:type decoded)))
        (when-let [req-id (:req-id decoded)]
          (when-let [^LinkedBlockingQueue q (get @jvm-mesh-chunk-handlers-atom req-id)]
            (.offer q decoded)
            true))))))

(defn- fetch-mesh-chunks-jvm!
  "Executes the bounded synchronous BIP-017a mesh chunk pull over the active JVM DataChannel."
  [conn-atom identity cid eff]
  (let [send-fn (when conn-atom (:send-fn @conn-atom))]
    (if-not (fn? send-fn)
      {:ok? false :reason :mesh-disconnected}
      (let [gen (long (or (:generation eff) 1))
            chunk-bytes (long (or (:chunk-size-bytes eff) deploy/default-mesh-chunk-size-bytes))
            probe-ms (long (or (:probe-timeout-ms eff) deploy/default-mesh-probe-timeout-ms))
            chunk-ms (long (or (:chunk-timeout-ms eff) deploy/default-mesh-chunk-timeout-ms))
            total-ms (long (or (:total-timeout-ms eff) (deploy/compute-mesh-fetch-ceiling-ms 0)))
            req-id (str "jvm-mesh-upd-" gen "-" (subs (str cid) 0 (min 8 (count (str cid)))) "-" (System/currentTimeMillis))
            q (LinkedBlockingQueue.)
            deadline-ms (+ (System/currentTimeMillis) total-ms)
            pk-hex (or (:pubkey-hex identity) (:pubkey identity))
            priv-bs (:privkey-bytes identity)]
        (swap! jvm-mesh-chunk-handlers-atom assoc req-id q)
        (try
          (loop [asm (deploy/init-mesh-chunk-assembly cid chunk-bytes)
                 offset 0
                 length chunk-bytes
                 wait-ms probe-ms
                 retried? false]
            (let [remaining (- deadline-ms (System/currentTimeMillis))]
              (if (<= remaining 0)
                {:ok? false :reason :mesh-total-timeout}
                (let [req (deploy/build-mesh-chunk-request cid offset length req-id)
                      wire (core-mesh/wrap-agent-event req pk-hex priv-bs)
                      sent-ok? (try (send-fn wire) true (catch Exception _ false))]
                  (if-not sent-ok?
                    {:ok? false :reason :mesh-send-failed}
                    (let [resp (.poll q (min wait-ms remaining) TimeUnit/MILLISECONDS)]
                      (if (nil? resp)
                        (if-not retried?
                          (recur asm offset length chunk-ms true)
                          {:ok? false :reason :mesh-chunk-timeout})
                        (let [step (deploy/reduce-mesh-chunk-response asm resp)]
                          (cond
                            (not (:ok? step))
                            {:ok? false :reason (or (:error step) :mesh-chunk-error)}

                            (:done? step)
                            {:ok? true :bytes (:bytes step)}

                            :else
                            (recur (:state step)
                                   (long (get-in step [:next-req :offset]))
                                   (long (get-in step [:next-req :length]))
                                   chunk-ms
                                   false))))))))))
          (finally
            (swap! jvm-mesh-chunk-handlers-atom dissoc req-id)))))))

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
                                "--trusted-dac-anchors" "--trusted-deploy-authorities" "--turn-server" "--turn-username"
                                "--turn-password" "--turn-realm" "--sync-interval-ms"
                                "--price" "--price-max" "--burn" "--to" "--from"
                                "--callee" "--peer" "--receiver" "--recipient"
                                "--amount" "--text" "--message" "--payload-hex"
                                "--wait-open-ms" "--until-event"
                                "--path" "--cid" "--file" "--out" "--out-file" "--hex" "--seq" "--authority" "--prefix"
                                "--pin-version" "--auto-update-pointer" "--auto-update-interval-ms"
                                "--cold-root-recovery-cid"
                                "--max-cache-bytes" "--min-free-disk-bytes" "--min-free-disk-pct"
                                "--max-events-log-bytes" "--state-save-warn-ms" "--ctl-warn-ms"
                                "--event-loop-lag-warn-ms" "--snapshot-encode-warn-ms"}
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
         keystore-passphrase-file (extract-flag-value clean-args "--keystore-passphrase-file" nil)
         backup-slot (extract-flag-value clean-args "--slot" nil)
         reset-network-state? (boolean (some #(= % "--reset-network-state") clean-args))
         trusted-dac-anchors-spec (flags/parse-trusted-dac-anchors-arg clean-args)
         trusted-dac-anchors (when (= :set (:action trusted-dac-anchors-spec))
                               (set (map #(or (light-core/normalize-pubkey-hex %) %)
                                         (:anchors trusted-dac-anchors-spec))))
         turn-server (extract-flag-value clean-args "--turn-server" nil)
         pin-version (extract-flag-value clean-args "--pin-version" nil)
         auto-update-pointer (extract-flag-value clean-args "--auto-update-pointer" nil)
         auto-update-interval-ms (extract-long-flag clean-args "--auto-update-interval-ms" nil)
         auto-update-force-http? (boolean (some #{"--auto-update-force-http"} clean-args))
         cold-root-recovery-cid (extract-flag-value clean-args "--cold-root-recovery-cid" nil)
         max-cache-bytes (extract-long-flag clean-args "--max-cache-bytes" nil)
         min-free-disk-bytes (extract-long-flag clean-args "--min-free-disk-bytes" nil)
         min-free-disk-pct (extract-long-flag clean-args "--min-free-disk-pct" nil)
         max-events-log-bytes (extract-long-flag clean-args "--max-events-log-bytes" nil)
         state-save-warn-ms (extract-long-flag clean-args "--state-save-warn-ms" nil)
         ctl-warn-ms (extract-long-flag clean-args "--ctl-warn-ms" nil)
         event-loop-lag-warn-ms (extract-long-flag clean-args "--event-loop-lag-warn-ms" nil)
         snapshot-encode-warn-ms (extract-long-flag clean-args "--snapshot-encode-warn-ms" nil)
         trusted-deploy-auths-present? (boolean (some #(or (= % "--trusted-deploy-authorities")
                                                           (str/starts-with? (str %) "--trusted-deploy-authorities="))
                                                      clean-args))
         trusted-deploy-auths-raw (extract-flag-value clean-args "--trusted-deploy-authorities" nil)
         trusted-deploy-authorities (when trusted-deploy-auths-present?
                                      (let [trimmed (str/trim (str (or trusted-deploy-auths-raw "")))]
                                        (if (or (str/blank? trimmed) (= "none" (str/lower-case trimmed)))
                                          #{}
                                          (set (keep #(let [s (str/trim (str %))]
                                                        (when-not (str/blank? s)
                                                          (str/lower-case s)))
                                                     (str/split trimmed #","))))))
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
       max-cache-bytes (assoc :max-cache-bytes max-cache-bytes)
       min-free-disk-bytes (assoc :min-free-disk-bytes min-free-disk-bytes)
       min-free-disk-pct (assoc :min-free-disk-pct min-free-disk-pct)
       max-events-log-bytes (assoc :max-events-log-bytes max-events-log-bytes)
       state-save-warn-ms (assoc :state-save-warn-ms state-save-warn-ms)
       ctl-warn-ms (assoc :ctl-warn-ms ctl-warn-ms)
       event-loop-lag-warn-ms (assoc :event-loop-lag-warn-ms event-loop-lag-warn-ms)
       snapshot-encode-warn-ms (assoc :snapshot-encode-warn-ms snapshot-encode-warn-ms)
       cmd-file (assoc :cmd-file cmd-file)
       events-out (assoc :events-out events-out)
       wait-session-id (assoc :session-id wait-session-id)
       min-seq (assoc :min-seq min-seq)
       min-broadcast-seq (assoc :min-broadcast-seq min-broadcast-seq)
       min-balance (assoc :min-balance min-balance)
       after-ts (assoc :after-ts after-ts)
       cold-root-recovery-cid (assoc :cold-root-recovery-cid cold-root-recovery-cid)
       subnet-id (assoc :subnet-id subnet-id)
       keystore-passphrase-file (assoc :keystore-passphrase-file keystore-passphrase-file)
       backup-slot (assoc :slot backup-slot)
       reset-network-state? (assoc :reset-network-state? true)
       timeout-ms (assoc :timeout-ms timeout-ms)
       ingress-tcp-port (assoc :ingress-tcp-port (int ingress-tcp-port))
       (seq trusted-dac-anchors) (assoc :trusted-dac-anchors trusted-dac-anchors)
       trusted-dac-anchors-spec (assoc :trusted-dac-anchors-spec trusted-dac-anchors-spec)
       (seq trusted-deploy-authorities) (assoc :trusted-deploy-authorities trusted-deploy-authorities)
       (some? sync?) (assoc :sync? sync?)
       (some? connect?) (assoc :connect? connect?)
       proxy-url (assoc :proxy proxy-url)
       relay-url (assoc :relay-url relay-url)
       turn-config (assoc :turn-config turn-config)
       pin-version (assoc :pin-version pin-version)
       auto-update-pointer (assoc :auto-update-pointer auto-update-pointer)
       auto-update-interval-ms (assoc :auto-update-interval-ms auto-update-interval-ms)
       auto-update-force-http? (assoc :auto-update-force-http? true)
       trusted-deploy-auths-present? (assoc :trusted-deploy-authorities trusted-deploy-authorities)))))

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

(def ^:private light-state-async-executor
  (delay
    (Executors/newSingleThreadExecutor
     (reify ThreadFactory
       (newThread [_ r]
         (doto (Thread. ^Runnable r)
           (.setName "bitecho-light-state-async-io")
           (.setDaemon true)))))))

(defonce ^:private light-state-writers-atom (atom {}))

(defonce ^{:doc "BIP-025 F1 & F3: JVM light-node storage & latency telemetry state."}
  jvm-light-telemetry-atom
  (atom {:state-save-ms []
         :ctl-ms []
         :event-loop-lag-ms []
         :state-bytes 0
         :cache-index (cache/init-cache-index)
         :cache-budget-bytes cache/default-max-cache-bytes
         :events-log-bytes 0
         :events-log-max-bytes cli/default-max-events-log-bytes
         :warn-thresholds status-core/default-latency-thresholds
         :diagnostics {}}))

(defn record-state-save-latency!
  "BIP-025 §5.3 / F3: Records `save-ms` and `state-bytes` into `jvm-light-telemetry-atom`,
   emitting counted `:state-save-slow` diagnostic when exceeding threshold."
  ([save-ms state-bytes] (record-state-save-latency! save-ms state-bytes nil))
  ([save-ms state-bytes state-atom]
   (let [warn-ms (long (or (get-in @jvm-light-telemetry-atom [:warn-thresholds :state-save-ms])
                           (:state-save-ms status-core/default-latency-thresholds)))
         [next-ring effs] (status-core/record-latency-sample
                           (:state-save-ms @jvm-light-telemetry-atom)
                           save-ms
                           {:max-samples status-core/default-latency-ring-max
                            :warn-ms warn-ms
                            :diag-reason :state-save-slow})]
     (swap! jvm-light-telemetry-atom
            (fn [m]
              (cond-> (assoc m :state-save-ms next-ring :state-bytes (long (or state-bytes 0)))
                (seq effs) (update-in [:diagnostics :state-save-slow] (fnil inc 0)))))
     (when (and state-atom (seq effs))
       (swap! state-atom update-in [:diagnostics :state-save-slow] (fnil inc 0)))
     effs)))

(defn record-ctl-latency!
  "BIP-025 §5.3 / F3: Records `ctl-ms` into `jvm-light-telemetry-atom`, emitting counted
   `:ctl-latency-high` diagnostic when exceeding threshold."
  ([ctl-ms] (record-ctl-latency! ctl-ms nil nil))
  ([ctl-ms state-atom] (record-ctl-latency! ctl-ms state-atom nil))
  ([ctl-ms state-atom warn-ms-override]
   (let [warn-ms (long (or warn-ms-override
                           (get-in @jvm-light-telemetry-atom [:warn-thresholds :ctl-ms])
                           (:ctl-ms status-core/default-latency-thresholds)))
         [next-ring effs] (status-core/record-latency-sample
                           (:ctl-ms @jvm-light-telemetry-atom)
                           ctl-ms
                           {:max-samples status-core/default-latency-ring-max
                            :warn-ms warn-ms
                            :diag-reason :ctl-latency-high})]
     (swap! jvm-light-telemetry-atom
            (fn [m]
              (cond-> (assoc m :ctl-ms next-ring)
                (seq effs) (update-in [:diagnostics :ctl-latency-high] (fnil inc 0)))))
     (when (and state-atom (seq effs))
       (swap! state-atom update-in [:diagnostics :ctl-latency-high] (fnil inc 0)))
     effs)))

(defn build-light-runtime-ctx
  "BIP-025 F3: Projects live `jvm-light-telemetry-atom` storage and latency telemetry into
   `runtime-ctx` for `status-core/render-status` (`bitecho.status/v1`)."
  []
  (let [tm @jvm-light-telemetry-atom
        cs (cache/cache-storage-summary (:cache-index tm))]
    {:storage (merge cs
                     {:state-bytes (long (:state-bytes tm 0))
                      :cache-budget-bytes (long (:cache-budget-bytes tm cache/default-max-cache-bytes))
                      :events-log-bytes (long (:events-log-bytes tm 0))
                      :events-log-max-bytes (long (:events-log-max-bytes tm cli/default-max-events-log-bytes))})
     :latency {:state-save-ms (:state-save-ms tm)
               :ctl-ms (:ctl-ms tm)
               :event-loop-lag-ms (:event-loop-lag-ms tm)}}))

(defn save-light-state!
  "Persists sanitized light-node state via cross-platform Fressian (`state.fressian`)
   with atomic move and 0600 permissions (`M2a-2`: writes strictly to `state-file` without
   dual-writing Fressian bytes into legacy `state.nippy`).
   BIP-025 F2: Refuses to overwrite legacy `state.fressian` when `:migration-deferred?` is true,
   preserving unmigrated blobs and the restart retry path with zero silent data loss.
   Synchronous entry point reserved for one-shot CLI commands and graceful shutdown flushes."
  [state-file state]
  (when (and (some? state-file) (not (str/blank? (str state-file))))
    (if (true? (:migration-deferred? state))
      (do
        (swap! jvm-light-telemetry-atom update-in [:diagnostics :state-save-deferred-pending-migration] (fnil inc 0))
        false)
      (locking light-state-save-lock
        (let [t0 (System/currentTimeMillis)
              f (io/file state-file)
              encoded (light-core/encode-light-state state)]
          (write-state-bytes-atomic! f encoded)
          (record-state-save-latency! (max 0 (- (System/currentTimeMillis) t0)) (alength ^bytes encoded))
          true)))))

(defn- dispatch-light-writer-effects!
  [state-file writer-atom effects]
  (doseq [eff effects]
    (when (= :write-snapshot (:effect eff))
      (let [gen (:generation eff)
            ep (:epoch eff)
            st-to-save (:payload eff)]
        (.execute ^java.util.concurrent.ExecutorService @light-state-async-executor
                  ^Runnable (fn []
                              (let [ok? (try
                                          (save-light-state! state-file st-to-save)
                                          true
                                          (catch Exception _ false))
                                    next-effs (atom [])]
                                (swap! writer-atom
                                       (fn [wst]
                                         (let [[wst' effs] (snap/transition-writer
                                                            wst
                                                            (if ok?
                                                              {:type :write-succeeded :generation gen :epoch ep}
                                                              {:type :write-failed :generation gen :epoch ep :error :io-error}))]
                                           (reset! next-effs effs)
                                           wst')))
                                (dispatch-light-writer-effects! state-file writer-atom @next-effs))))))))

(defn save-light-state-async!
  "Coalesces and offloads runtime `state.fressian` writes onto a dedicated daemon I/O thread
   using `bitecho.snapshot.core/transition-writer` so Netty/WebRTC/relay threads never block on disk I/O
   (BIP-014 / P-ASYNC-3)."
  [state-file state]
  (when (and (some? state-file) (not (str/blank? (str state-file))))
    (let [path-key (str state-file)
          writer-atom (or (get @light-state-writers-atom path-key)
                          (let [a (atom (snap/init-writer-state {:node-id "light-node"}))]
                            (swap! light-state-writers-atom assoc path-key a)
                            (get @light-state-writers-atom path-key)))
          ep (long (or (:epoch state) 0))
          effs-box (atom [])]
      (swap! writer-atom
             (fn [wst]
               (let [[wst' effs] (snap/transition-writer wst {:type :request-write
                                                              :epoch ep
                                                              :payload state})]
                 (reset! effs-box effs)
                 wst')))
      (dispatch-light-writer-effects! path-key writer-atom @effs-box)
      true)))

(declare execute-conn-effects! apply-conn-event!)

(defonce ^:private light-state-load-diagnostics-atom (atom {}))

(defn get-light-state-load-diagnostics
  "Returns counted diagnostic counters recorded during light-node state loading."
  []
  @light-state-load-diagnostics-atom)

(defn- cache-blobs-root
  [state-dir]
  (io/file (str state-dir) "cache" "blobs"))

(defn- cache-index-file
  [state-dir]
  (io/file (str state-dir) "cache" "index.fressian"))

(defn write-cache-blob!
  "BIP-025 §2.1: Atomically writes raw blob bytes to `<state-dir>/cache/blobs/<2>/<cid>` (`0600`).
   Skips rewrite if an identical verified blob already exists on disk (crash-restart idempotency)."
  [state-dir cid ^bytes bs]
  (when-let [[shard norm-cid] (cache/cid-shard-relpath cid)]
    (let [dest (io/file (cache-blobs-root state-dir) shard norm-cid)]
      (if (and (.exists dest)
               (= (.length dest) (long (alength bs)))
               (try
                 (= norm-cid (data/compute-cid (Files/readAllBytes (.toPath dest))))
                 (catch Exception _ false)))
        {:ok? true :cid norm-cid :skipped? true :path (.getAbsolutePath dest)}
        (do
          (write-state-bytes-atomic! dest bs)
          {:ok? true :cid norm-cid :skipped? false :path (.getAbsolutePath dest)})))))

(defn save-cache-index!
  "BIP-025 §2.2 (Axiom A2): Atomically persists `<state-dir>/cache/index.fressian` (`0600`)."
  [state-dir cache-index]
  (let [idx-f (cache-index-file state-dir)
        encoded (fressian/encode-wire-uncompressed cache-index)]
    (write-state-bytes-atomic! idx-f encoded)
    {:ok? true :bytes (alength ^bytes encoded) :path (.getAbsolutePath idx-f)}))

(defn delete-cache-blob!
  "BIP-025 F1: Unlinks an evicted CID from `<state-dir>/cache/blobs/<2>/<cid>`."
  [state-dir cid]
  (when-let [[shard norm-cid] (cache/cid-shard-relpath cid)]
    (let [f (io/file (cache-blobs-root state-dir) shard norm-cid)]
      (when (.exists f)
        (io/delete-file f true))
      {:ok? true :cid norm-cid})))

(defn execute-cache-effects!
  "BIP-025 F1: Drains pure `:cache-effects` (`:cache-put`) emitted by `light_node/core` reducers:
   1. Writes each blob atomically to `<state-dir>/cache/blobs/<2>/<cid>` (`0600`).
   2. Records entry in `jvm-light-telemetry-atom` `:cache-index` via `cache/record-put`.
   3. Runs `cache/plan-evictions`, unlinks evicted files from disk, and emits counted `:diagnose` events.
   4. Persists `<state-dir>/cache/index.fressian`.
   5. Bounds/drops live `:blobs` in `state-atom` (`cache/prune-inline-hot-blobs`) so RSS stays flat."
  ([state-dir cache-effects state-atom]
   (execute-cache-effects! state-dir cache-effects state-atom nil))
  ([state-dir cache-effects state-atom opts]
   (when (and (some? state-dir) (seq cache-effects))
     (let [max-budget (long (or (:max-cache-bytes opts)
                                (:cache-budget-bytes @jvm-light-telemetry-atom)
                                cache/default-max-cache-bytes))
           max-hot (long (or (:max-hot-blobs opts) 0))
           st-snap (when state-atom @state-atom)
           pinned (set (or (:pinned-cids opts) (:pinned-cids st-snap) #{}))
           active (into #{} (keep :pointer/target) (vals (or (:pointers st-snap) {})))]
       (doseq [eff cache-effects]
         (when (= :cache-put (:effect eff))
           (let [cid (cache/normalize-cid (:cid eff))
                 blob (:blob eff)
                 bs (or (:blob/bytes blob) (:bytes eff))
                 sz (long (or (:size-bytes eff) (when bs (fressian/count-bytes bs)) 0))
                 mt (or (:media-type eff) (:blob/media-type blob) "application/octet-stream")
                 tier (or (:tier eff) (cache/classify-tier cid pinned active))]
             (when (and cid bs)
               (write-cache-blob! state-dir cid bs)
               (swap! jvm-light-telemetry-atom update :cache-index cache/record-put
                      {:cid cid :size-bytes sz :media-type mt :tier tier})))))
       (let [host-free (if (contains? opts :host-free-bytes)
                         (:host-free-bytes opts)
                         (try (.getUsableSpace (io/file state-dir)) (catch Exception _ nil)))
             ev-res (cache/plan-evictions (:cache-index @jvm-light-telemetry-atom)
                                          {:max-cache-bytes max-budget
                                           :host-free-bytes host-free
                                           :min-free-disk-bytes (or (:min-free-disk-bytes opts) 0)
                                           :pinned-cids pinned
                                           :active-pointer-cids active})]
         (swap! jvm-light-telemetry-atom assoc :cache-index (:cache-index ev-res))
         (doseq [eff (:effects ev-res)]
           (case (:effect eff)
             :cache-delete (delete-cache-blob! state-dir (:cid eff))
             :diagnose (let [r (:reason eff)]
                         (swap! jvm-light-telemetry-atom update-in [:diagnostics r] (fnil inc 0))
                         (when state-atom
                           (swap! state-atom update-in [:diagnostics r] (fnil inc 0))))
             nil))
         (try (save-cache-index! state-dir (:cache-index ev-res)) (catch Exception _ nil))
         (when state-atom
           (swap! state-atom cache/prune-inline-hot-blobs max-hot))
         {:ok? true
          :evicted (:evicted ev-res)
          :cache-index (:cache-index ev-res)
          :effects (:effects ev-res)})))))

(defn hydrate-cache-blob!
  "BIP-025 F1: Read-through hydration for JVM local blob cache.
   Checks hot `(:blobs @state-atom)` first; on miss, reads `<state-dir>/cache/blobs/<2>/<cid>`,
   verifies `sha256 == cid`, increments GDSF hit count (`cache/record-hit`) and persists index,
   or emits counted `:cache-miss` diagnostic on miss."
  [state-dir cid state-atom]
  (let [norm-cid (cache/normalize-cid cid)
        hot-blob (when (and norm-cid state-atom) (get-in @state-atom [:blobs norm-cid]))]
    (cond
      (nil? norm-cid)
      (do
        (swap! jvm-light-telemetry-atom update-in [:diagnostics :cache-miss] (fnil inc 0))
        (when state-atom (swap! state-atom update-in [:diagnostics :cache-miss] (fnil inc 0)))
        {:ok? false :error :cache-miss :cid cid})

      (some? hot-blob)
      (do
        (swap! jvm-light-telemetry-atom update :cache-index cache/record-hit norm-cid)
        {:ok? true :blob hot-blob :hydrated? false :cid norm-cid})

      :else
      (let [[shard _] (cache/cid-shard-relpath norm-cid)
            f (io/file (cache-blobs-root state-dir) shard norm-cid)]
        (if-let [bs (when (.exists f)
                      (try
                        (let [raw (Files/readAllBytes (.toPath f))]
                          (when (= norm-cid (data/compute-cid raw)) raw))
                        (catch Exception _ nil)))]
          (let [mt (or (get-in @jvm-light-telemetry-atom [:cache-index :entries norm-cid :media-type])
                       "application/octet-stream")
                blob {:blob/cid norm-cid :blob/bytes bs :blob/media-type mt}]
            (swap! jvm-light-telemetry-atom update :cache-index cache/record-hit norm-cid)
            (try (save-cache-index! state-dir (:cache-index @jvm-light-telemetry-atom)) (catch Exception _ nil))
            {:ok? true :blob blob :hydrated? true :cid norm-cid})
          (do
            (swap! jvm-light-telemetry-atom update-in [:diagnostics :cache-miss] (fnil inc 0))
            (when state-atom (swap! state-atom update-in [:diagnostics :cache-miss] (fnil inc 0)))
            {:ok? false :error :cache-miss :cid norm-cid}))))))

(defn maybe-hydrate-state-for-read!
  "BIP-025 F7: Production read-through hydration for JVM `storage-get` / `artifact-get`.
   If the target CID is absent from hot `:blobs`/`:storage-blobs`/`:artifact-blobs`, hydrates
   it from `<state-dir>/cache/blobs/<2>/<cid>`, updates GDSF hit count (`cache/record-hit`),
   and ephemerally injects it into the returned transient state map (leaving `state-atom` pruned)."
  [state-dir state-atom eff-verb cmd-map]
  (let [st @state-atom]
    (if-let [target-cid (and state-dir (cache/resolve-read-target-cid st eff-verb cmd-map))]
      (let [hyd (hydrate-cache-blob! state-dir target-cid state-atom)]
        (if (:ok? hyd)
          (cache/inject-hydrated-blob @state-atom target-cid (:blob hyd))
          @state-atom))
      st)))

(defn load-or-rebuild-cache-index!
  "BIP-025 §2.2 (Axiom A2): Loads `<state-dir>/cache/index.fressian` or, if missing/corrupt,
   scans `<state-dir>/cache/blobs/<2>/<cid>`, invokes pure `cache/rebuild-index-from-disk`,
   writes a fresh `cache/index.fressian`, and returns `{:cache-index idx :effects [...]}`."
  ([state-dir core-state] (load-or-rebuild-cache-index! state-dir core-state nil))
  ([state-dir core-state _opts]
   (let [idx-f (cache-index-file state-dir)
         pinned (set (or (:pinned-cids core-state) #{}))
         active (into #{} (keep :pointer/target) (vals (or (:pointers core-state) {})))
         loaded (when (.exists idx-f)
                  (try
                    (let [raw (Files/readAllBytes (.toPath idx-f))
                          dec-idx (when (pos? (alength raw)) (fressian/decode-wire raw))]
                      (when (and (map? dec-idx)
                                 (= cache/cache-index-schema-version (:schema dec-idx))
                                 (map? (:entries dec-idx)))
                        dec-idx))
                    (catch Exception _ nil)))]
     (if loaded
       {:cache-index (cache/reclassify-tiers loaded pinned active) :effects []}
       (let [root (cache-blobs-root state-dir)
             disk-entries (if (.exists root)
                            (for [^java.io.File f (file-seq root)
                                  :when (.isFile f)
                                  :when (not (str/ends-with? (.getName f) ".tmp"))]
                              {:cid (.getName f)
                               :size-bytes (.length f)
                               :mtime-ms (.lastModified f)})
                            [])
             rebuilt (cache/rebuild-index-from-disk (vec disk-entries)
                                                    {:pinned-cids pinned
                                                     :active-pointer-cids active})]
         (try (save-cache-index! state-dir (:cache-index rebuilt)) (catch Exception _ nil))
         rebuilt)))))

(defn migrate-legacy-state-file!
  "BIP-025 §2.4 (V2, A1, A2): Crash-safe, idempotent extract-before-compact migration of legacy
   bloated `state.fressian` into `<state-dir>/cache/blobs/<2>/<cid>` + `<state-dir>/cache/index.fressian`.
   Checks host free bytes before and during extraction; spills Tier 2 when tight; fails closed on
   ENOSPC / insufficient headroom leaving original `state.fressian` byte-for-byte intact."
  ([state-file decoded-state] (migrate-legacy-state-file! state-file decoded-state nil))
  ([state-file decoded-state opts]
   (let [ex (light-core/extract-legacy-inline-blobs decoded-state)]
     (if-not (:had-inline-blobs? ex)
       {:ok? true :migrated? false :state (:compacted-state ex) :effects []}
       (let [f (io/file state-file)
             state-dir (or (.getParent f) ".")
             compacted (:compacted-state ex)
             compacted-bytes (light-core/encode-light-state compacted)
             pinned (set (or (:pinned-cids compacted) #{}))
             active (into #{} (keep :pointer/target) (vals (or (:pointers compacted) {})))
             host-free (if (contains? opts :host-free-bytes)
                         (:host-free-bytes opts)
                         (try (.getUsableSpace (io/file state-dir)) (catch Exception _ nil)))
             min-free (if (contains? opts :min-free-disk-bytes)
                        (:min-free-disk-bytes opts)
                        cache/default-min-free-disk-bytes)
             plan (cache/plan-migration-spill (:unique-blobs ex)
                                              {:pinned-cids pinned
                                               :active-pointer-cids active
                                               :host-free-bytes host-free
                                               :compacted-core-bytes (alength ^bytes compacted-bytes)
                                               :min-free-disk-bytes min-free
                                               :legacy-state-bytes (if (.exists f) (.length f) 0)})]
         (if-not (:ok? plan)
           (do
             (swap! light-state-load-diagnostics-atom update :migration-insufficient-disk-space (fnil inc 0))
             {:ok? false
              :error :migration-insufficient-disk-space
              :state decoded-state
              :effects (:effects plan)})
           (try
             (let [retained-set (set (:retained-cids plan))
                   idx0 (reduce (fn [idx cid]
                                  (let [info (get (:unique-blobs ex) cid)
                                        _ (write-cache-blob! state-dir cid (:bytes info))
                                        tier (cache/classify-tier cid pinned active)]
                                    (cache/record-put idx {:cid cid
                                                           :size-bytes (:size-bytes info)
                                                           :media-type (:media-type info)
                                                           :tier tier})))
                                (cache/init-cache-index)
                                (sort retained-set))
                   _ (save-cache-index! state-dir idx0)
                   _ (write-state-bytes-atomic! f compacted-bytes)
                   mig-diag {:effect :diagnose
                             :reason :legacy-blobs-migrated-to-cache
                             :migrated-count (count retained-set)
                             :deduplicated-count (:deduplicated-count ex)
                             :spilled-tier2-count (count (:spilled-cids plan))
                             :corrupt-skipped-count (:corrupt-skipped-count ex)
                             :reclaimed-bytes (:reclaimed-bytes ex)}]
               (swap! light-state-load-diagnostics-atom update :legacy-blobs-migrated-to-cache (fnil inc 0))
               {:ok? true
                :migrated? true
                :state compacted
                :cache-index idx0
                :effects (conj (vec (:effects plan)) mig-diag)})
             (catch Exception e
               (swap! light-state-load-diagnostics-atom update :migration-insufficient-disk-space (fnil inc 0))
               {:ok? false
                :error :migration-insufficient-disk-space
                :detail (.getMessage e)
                :state decoded-state
                :effects [{:effect :diagnose
                           :reason :migration-insufficient-disk-space
                           :detail (.getMessage e)}]}))))))))

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
               (let [decoded (try
                               (light-core/decode-light-state b)
                               (catch Exception e
                                 {:__corrupt_error__ (.getMessage e)}))]
                 (if (or (not (map? decoded)) (contains? decoded :__corrupt_error__))
                   (let [eff {:effect :diagnose
                              :reason :local-state-corrupt-fallback
                              :error "local-state-corrupt-fallback"
                              :state-file (str f)
                              :detail (if (map? decoded) (:__corrupt_error__ decoded) "non-map-fressian-root")}]
                     (swap! light-state-load-diagnostics-atom update :local-state-corrupt-fallback (fnil inc 0))
                     (when-let [d-atom (:diagnostics-atom opts)]
                       (when (instance? clojure.lang.IAtom d-atom)
                         (swap! d-atom conj eff)))
                     (when-let [st-atom (:state-atom opts)]
                       (when (instance? clojure.lang.IAtom st-atom)
                         (swap! st-atom update-in [:diagnostics :local-state-corrupt-fallback] (fnil inc 0))))
                     (binding [*out* *err*]
                       (println (json/write-str {"event" "diagnose"
                                                 "reason" "local-state-corrupt-fallback"
                                                 "state_file" (str f)
                                                 "detail" (:detail eff)})))
                     nil)
                   (do
                     (when (light-core/legacy-v0238-state? decoded)
                       (let [bak-f (io/file (str (.getAbsolutePath f) ".v0238.bak"))]
                         (when-not (.exists bak-f)
                           (try (write-state-bytes-atomic! bak-f b) (catch Exception _ nil)))))
                     (let [migrated-v0238 (light-core/migrate-light-state decoded)
                           mig-res (migrate-legacy-state-file! (str f) migrated-v0238 opts)]
                       (if (:ok? mig-res)
                         (:state mig-res)
                         ;; BIP-025 F2 (A1): Preserve original unmigrated blobs & retry path; never strip/clobber on failure!
                         (-> (:state mig-res)
                             (assoc :migration-deferred? true)
                             (update-in [:diagnostics :migration-insufficient-disk-space] (fnil inc 0))))))))))))))))

(defn load-or-create-light-identity!
  "Loads or creates persistent light-node identity in state-dir (supporting Row 11 Phase 1
   encrypted `keystore.enc.edn` and seamless legacy `node-identity.edn` read-migration).
   Throws descriptive exception on corrupt identity file or fail-closed unlock error."
  ([state-dir]
   (load-or-create-light-identity! state-dir {}))
  ([state-dir opts]
   (let [node-id :light-node
         kp-opts (cond-> {}
                   (:passphrase opts) (assoc :passphrase (:passphrase opts))
                   (:keystore-passphrase-file opts) (assoc :passphrase-file (:keystore-passphrase-file opts))
                   (:passphrase-file opts) (assoc :passphrase-file (:passphrase-file opts))
                   (:kdf-iterations opts) (assoc :kdf-iterations (:kdf-iterations opts)))
         id-data (identity/load-key-provider-identity! state-dir node-id kp-opts)]
     (when (false? (:ok? id-data))
       (throw (ex-info (str "Keystore unlock failed: " (name (or (:error id-data) :keystore-unlock-failed)))
                       {:error (:error id-data)
                        :diagnostics (:diagnostics id-data)})))
     (let [priv-bytes (if-let [kp-m (:keypair id-data)]
                        (:private kp-m)
                        (basalt/hex->bytes (:privkey-hex id-data)))]
       (assoc id-data :privkey-bytes priv-bytes)))))

;; -----------------------------------------------------------------------------
;; Row 6: Fail-Closed Encrypted On-Network State Backup & Restore (`:bitecho.backup/v1`)
;; -----------------------------------------------------------------------------

(defn- jvm-artifact-base-url
  [relay-base-url]
  (-> (str (or relay-base-url "https://ns1.bitecho.org"))
      (str/replace #"/relay/v1/?$" "")
      (str/replace #"/+$" "")))

(defn- default-http-post-blob!
  [relay-base-url pubkey blob]
  (try
    (let [client (default-http-client)
          url (str (jvm-artifact-base-url relay-base-url) "/artifact/v1/blob")
          req (-> (HttpRequest/newBuilder (URI/create url))
                  (.timeout (Duration/ofSeconds 10))
                  (.header "Content-Type" (or (:blob/media-type blob) "application/x-bitecho-e2ee-fressian"))
                  (.header "X-Bitecho-Blob-Cid" (:blob/cid blob))
                  (.header "X-Bitecho-Pubkey" (str pubkey))
                  (.POST (HttpRequest$BodyPublishers/ofByteArray ^bytes (:blob/bytes blob)))
                  (.build))
          resp (.send client req (HttpResponse$BodyHandlers/ofString))
          code (.statusCode resp)]
      (if (<= 200 code 299)
        {:ok? true :status code :body (.body resp)}
        {:ok? false :status code :error (str "http-" code) :body (.body resp)}))
    (catch Exception e
      {:ok? false :status 0 :error (.getMessage e)})))

(defn- default-http-post-pointer!
  [relay-base-url pubkey pointer]
  (try
    (let [client (default-http-client)
          url (str (jvm-artifact-base-url relay-base-url) "/artifact/v1/pointer")
          body-json (json/write-str
                     {"subnet" (:pointer/subnet pointer)
                      "path" (:pointer/path pointer)
                      "authority" (:pointer/authority pointer)
                      "seq" (:pointer/seq pointer)
                      "leader_term" (:pointer/leader-term pointer)
                      "target" (:pointer/target pointer)
                      "proof" {"type" (name (or (get-in pointer [:pointer/proof :proof/type]) :self))}
                      "sig" (:pointer/sig pointer)})
          req (-> (HttpRequest/newBuilder (URI/create url))
                  (.timeout (Duration/ofSeconds 10))
                  (.header "Content-Type" "application/json; charset=utf-8")
                  (.header "X-Bitecho-Pubkey" (str pubkey))
                  (.POST (HttpRequest$BodyPublishers/ofString body-json StandardCharsets/UTF_8))
                  (.build))
          resp (.send client req (HttpResponse$BodyHandlers/ofString))
          code (.statusCode resp)]
      (if (<= 200 code 299)
        {:ok? true :status code :body (.body resp)}
        {:ok? false :status code :error (str "http-" code) :body (.body resp)}))
    (catch Exception e
      {:ok? false :status 0 :error (.getMessage e)})))

(defn publish-encrypted-backup!
  "Row 6 fail-closed 2-step encrypted state backup publisher:
   1. Packs encrypted `:bitecho.backup/v1` blob + signed monotonic pointer via `backup/pack-encrypted-backup`.
   2. Publishes `POST /artifact/v1/blob` FIRST.
   3. ONLY after verified HTTP 2xx blob ack publishes `POST /artifact/v1/pointer`.
   On ANY failure (e.g. HTTP 503), fails closed with canonical `:storage-publish-failed` + counted
   `:backup-publish-failed` `:diagnose`, ZERO partial pointer commit, and unchanged local `:backup-seq`."
  [{:keys [key-provider state subnet-id slot node-role now-ms relay-url
           http-post-blob-fn http-post-pointer-fn]}]
  (let [prev-seq (long (or (:backup-seq state) 0))
        next-seq (inc prev-seq)
        packed (backup/pack-encrypted-backup {:key-provider key-provider
                                              :state state
                                              :subnet-id (or subnet-id "bitecho.org/infra")
                                              :slot slot
                                              :seq next-seq
                                              :node-role (or node-role :jvm)
                                              :now-ms (or now-ms (System/currentTimeMillis))})]
    (if-not (:ok? packed)
      (let [err (errors/canonical-error (:error packed) {:stage "backup-pack"})
            st' (errors/record-error-diagnostic state err)]
        {:ok? false
         :error (:error err)
         :state st'
         :effects (vec (:effects packed))})
      (let [own-pk (kp/public-key key-provider)
            post-blob! (or http-post-blob-fn #(default-http-post-blob! relay-url own-pk %))
            post-ptr! (or http-post-pointer-fn #(default-http-post-pointer! relay-url own-pk %))
            blob-res (post-blob! (:blob packed))]
        (if-not (:ok? blob-res)
          (let [diag {:effect :diagnose
                      :reason :backup-publish-failed
                      :stage :blob
                      :status (or (:status blob-res) 0)
                      :error (:error blob-res)}
                err (errors/canonical-error :storage-publish-failed {:stage "blob" :status (:status blob-res)})
                st' (-> (errors/record-error-diagnostic state err)
                        (update-in [:diagnostics :backup-publish-failed] (fnil inc 0)))]
            {:ok? false
             :error :storage-publish-failed
             :stage :blob
             :status (:status blob-res)
             :state st'
             :effects [diag (errors/diagnose-effect err)]})
          (let [ptr-res (post-ptr! (:pointer packed))]
            (if-not (:ok? ptr-res)
              (let [diag {:effect :diagnose
                          :reason :backup-publish-failed
                          :stage :pointer
                          :status (or (:status ptr-res) 0)
                          :error (:error ptr-res)}
                    err (errors/canonical-error :storage-publish-failed {:stage "pointer" :status (:status ptr-res)})
                    st' (-> (errors/record-error-diagnostic state err)
                            (update-in [:diagnostics :backup-publish-failed] (fnil inc 0)))]
                {:ok? false
                 :error :storage-publish-failed
                 :stage :pointer
                 :status (:status ptr-res)
                 :state st'
                 :effects [diag (errors/diagnose-effect err)]})
              (let [st' (assoc state
                               :backup-seq next-seq
                               :backup-last-cid (:cid packed)
                               :backup-path (:path packed))]
                {:ok? true
                 :seq next-seq
                 :cid (:cid packed)
                 :path (:path packed)
                 :blob (:blob packed)
                 :pointer (:pointer packed)
                 :state st'
                 :effects []}))))))))

(defn restore-encrypted-backup!
  "Row 6 encrypted backup restore helper: verifies & decrypts backup via `backup/unpack-encrypted-backup`
   and merges into `local-state` via `backup/merge-restored-state` (honoring BIP-016 tombstones and
   Lumen `seq 7` per-session auto-quarantine)."
  [{:keys [key-provider local-state blob pointer slot min-expected-seq observed-hwm]}]
  (let [unpacked (backup/unpack-encrypted-backup {:key-provider key-provider
                                                  :blob blob
                                                  :pointer pointer
                                                  :slot slot
                                                  :min-expected-seq min-expected-seq})]
    (if-not (:ok? unpacked)
      {:ok? false
       :error (:error unpacked)
       :state local-state
       :effects (:effects unpacked)}
      (let [merged (backup/merge-restored-state local-state (:payload unpacked) observed-hwm)]
        {:ok? true
         :seq (:seq unpacked)
         :cid (:cid unpacked)
         :path (:path unpacked)
         :summary (:summary merged)
         :state (:state merged)
         :effects (:effects merged)}))))

(defn- default-http-fetch-backup-pointer-and-blob!
  [relay-base-url backup-path]
  (try
    (let [client (default-http-client)
          base (jvm-artifact-base-url relay-base-url)
          list-url (str base "/artifact/v1/list?prefix="
                        (java.net.URLEncoder/encode (str backup-path) "UTF-8"))
          list-req (-> (HttpRequest/newBuilder (URI/create list-url))
                       (.timeout (Duration/ofSeconds 10))
                       (.GET)
                       (.build))
          list-resp (.send client list-req (HttpResponse$BodyHandlers/ofString))
          list-code (.statusCode list-resp)]
      (if-not (<= 200 list-code 299)
        {:ok? false :error :backup-fetch-failed :stage :pointer :status list-code}
        (let [parsed (json/read-str (.body list-resp))
              items (or (get parsed "pointers") (get parsed "items") [])
              item (first (filter #(= backup-path (get % "path")) items))]
          (if-not (map? item)
            {:ok? false :error :backup-not-found :stage :pointer}
            (let [cid (or (get item "cid") (get item "target"))
                  blob-url (str base "/artifact/v1/blob/"
                                (java.net.URLEncoder/encode (str cid) "UTF-8"))
                  blob-req (-> (HttpRequest/newBuilder (URI/create blob-url))
                               (.timeout (Duration/ofSeconds 10))
                               (.GET)
                               (.build))
                  blob-resp (.send client blob-req (HttpResponse$BodyHandlers/ofByteArray))
                  blob-code (.statusCode blob-resp)]
              (if-not (<= 200 blob-code 299)
                {:ok? false :error :backup-fetch-failed :stage :blob :status blob-code}
                {:ok? true
                 :pointer {:pointer/subnet (or (get item "subnet") "bitecho.org/infra")
                           :pointer/path (get item "path")
                           :pointer/authority (get item "authority")
                           :pointer/seq (long (or (get item "seq") 0))
                           :pointer/leader-term (long (or (get item "leader_term") 0))
                           :pointer/target cid
                           :pointer/proof {:proof/type :self}
                           :pointer/sig (get item "sig")}
                 :blob {:blob/cid cid
                        :blob/bytes (.body blob-resp)
                        :blob/media-type "application/x-bitecho-e2ee-fressian"}}))))))
    (catch Exception e
      {:ok? false :error :backup-fetch-failed :detail (.getMessage e)})))

(defn- handle-jvm-stage-c-verb!
  "Handles Stage C verbs (`backup-put`, `backup-restore`, `identity-migrate`) on JVM."
  [verb cmd-map state-atom identity relay-url opts]
  (let [state @state-atom
        kp (or (:key-provider identity)
               (when (:privkey-bytes identity)
                 (kp/make-memory-key-provider
                  (:privkey-bytes identity)
                  (or (:keystore-security-tier identity) :legacy-file-0600))))
        art-relay (or (get cmd-map "relay_url")
                      (get cmd-map "relay-url")
                      (:relay-url cmd-map)
                      (:relay-url opts)
                      relay-url
                      "https://ns1.bitecho.org")
        sub-id (or (get cmd-map "subnet_id")
                   (get cmd-map "subnet-id")
                   (:subnet-id cmd-map)
                   (:subnet-id opts)
                   "bitecho.org/infra")
        slot (or (get cmd-map "slot") (:slot cmd-map) (:slot opts) "state-backup-v1")]
    (case verb
      "backup-put"
      (let [res (publish-encrypted-backup! {:key-provider kp
                                            :state state
                                            :subnet-id sub-id
                                            :slot slot
                                            :node-role :jvm
                                            :relay-url art-relay})]
        (if (:ok? res)
          {:state (:state res)
           :response {"ok" true
                      "cmd" "backup-put"
                      "seq" (:seq res)
                      "cid" (:cid res)
                      "path" (:path res)
                      "relay_url" art-relay}
           :effects (:effects res)}
          {:state (:state res)
           :response {"ok" false
                      "cmd" "backup-put"
                      "error" (name (or (:error res) :storage-publish-failed))
                      "stage" (when (:stage res) (name (:stage res)))
                      "status" (or (:status res) 0)}
           :effects (:effects res)}))

      "backup-restore"
      (let [own-pk (kp/public-key kp)
            backup-path (backup/backup-pointer-path own-pk slot)
            fetched (default-http-fetch-backup-pointer-and-blob! art-relay backup-path)]
        (if-not (:ok? fetched)
          {:state state
           :response {"ok" false
                      "cmd" "backup-restore"
                      "error" (name (or (:error fetched) :backup-fetch-failed))
                      "path" backup-path}}
          (let [res (restore-encrypted-backup! {:key-provider kp
                                                :local-state state
                                                :blob (:blob fetched)
                                                :pointer (:pointer fetched)
                                                :slot slot})]
            (if (:ok? res)
              {:state (:state res)
               :response {"ok" true
                          "cmd" "backup-restore"
                          "seq" (:seq res)
                          "cid" (:cid res)
                          "path" (:path res)
                          "summary" (:summary res)}
               :effects (:effects res)}
              {:state (:state res)
               :response {"ok" false
                          "cmd" "backup-restore"
                          "error" (name (or (:error res) :backup-restore-failed))}
               :effects (:effects res)}))))

      "identity-migrate"
      (let [state-dir (or (:state-dir opts) (str (io/file (System/getProperty "user.home") ".bitecho-light")))
            passphrase (or (get cmd-map "passphrase")
                           (:passphrase cmd-map)
                           (:passphrase opts))
            passphrase-file (or (get cmd-map "passphrase_file")
                                (get cmd-map "passphrase-file")
                                (get cmd-map "keystore_passphrase_file")
                                (get cmd-map "keystore-passphrase-file")
                                (:passphrase-file cmd-map)
                                (:keystore-passphrase-file cmd-map)
                                (:keystore-passphrase-file opts)
                                (:passphrase-file opts))
            mig (identity/load-key-provider-identity!
                 state-dir :light-node
                 (cond-> {}
                   passphrase (assoc :passphrase passphrase)
                   passphrase-file (assoc :passphrase-file passphrase-file)))
            migrated? (boolean (some #(= :keystore-migrated-to-encrypted (:reason %)) (:diagnostics mig)))]
        (if (and (not= false (:ok? mig))
                 (= :encrypted-keystore-0600 (:keystore-security-tier mig)))
          (let [st' (cond-> (assoc state :keystore-security-tier :encrypted-keystore-0600)
                      migrated? (update-in [:diagnostics :keystore-migrated-to-encrypted] (fnil inc 0)))]
            {:state st'
             :response {"ok" true
                        "cmd" "identity-migrate"
                        "migrated" migrated?
                        "pubkey" (or (:pubkey-hex mig) (kp/public-key (:key-provider mig)))
                        "keystore_path" (str (io/file state-dir "identity" "keystore.enc.edn"))
                        "keystore_security_tier" "encrypted-keystore-0600"}})
          {:state state
           :response {"ok" false
                      "cmd" "identity-migrate"
                      "error" (name (or (:error mig) :passphrase-required))}}))
      nil)))

(defn- apply-jvm-startup-diagnostics!
  [initial-state identity load-diags]
  (let [id-diags (vec (or (:diagnostics identity) []))
        all-diags (into id-diags (or load-diags []))
        corrupt-fallback? (boolean (some #(= :local-state-corrupt-fallback (:reason %)) load-diags))
        st-with-diags (reduce (fn [acc d]
                                (if-let [r (:reason d)]
                                  (update-in acc [:diagnostics r] (fnil inc 0))
                                  acc))
                              initial-state
                              all-diags)]
    (doseq [d all-diags]
      (binding [*out* *err*]
        (println (json/write-str {"event" "diagnostic"
                                  "reason" (name (or (:reason d) :unknown))
                                  "detail" (or (:detail d) (:path d) "")}))))
    (cond-> (assoc st-with-diags
                   :keystore-security-tier
                   (or (:keystore-security-tier identity)
                       (:keystore-security-tier st-with-diags)
                       :legacy-file-0600))
      corrupt-fallback? (assoc :pending-corrupt-auto-restore? true))))

(defn maybe-auto-restore-corrupt-state!
  "BIP-022 Stage C §3.2.2 (F3b): when `state-atom` has `:pending-corrupt-auto-restore? true`
   after a corrupt `state.fressian` fallback, automatically attempts on-network `backup-restore`
   for `storage/<64-hex-pubkey>/state-backup-v1`. Emits counted `:local-state-corrupt-auto-restored`,
   `:local-state-corrupt-no-backup`, or `:local-state-corrupt-auto-restore-failed` loudly (Rule 5)
   without ever crashing startup."
  [state-atom identity state-file relay-url opts]
  (when (:pending-corrupt-auto-restore? @state-atom)
    (let [state @state-atom
          kp (or (:key-provider identity)
                 (when (:privkey-bytes identity)
                   (kp/make-memory-key-provider
                    (:privkey-bytes identity)
                    (or (:keystore-security-tier identity) :legacy-file-0600))))
          slot (or (:slot opts) "state-backup-v1")
          fetch-fn (or (:fetch-backup-fn opts) default-http-fetch-backup-pointer-and-blob!)
          emit-diag! (fn [reason detail]
                       (binding [*out* *err*]
                         (println (json/write-str {"event" "diagnose"
                                                   "reason" (name reason)
                                                   "detail" (str (or detail ""))}))))]
      (if (or (nil? kp) (str/blank? (str relay-url)))
        (do
          (swap! state-atom #(-> (dissoc % :pending-corrupt-auto-restore?)
                                 (update-in [:diagnostics :local-state-corrupt-auto-restore-failed] (fnil inc 0))))
          (emit-diag! :local-state-corrupt-auto-restore-failed "missing-relay-or-key-provider")
          {:ok? false :reason :local-state-corrupt-auto-restore-failed})
        (let [own-pk (kp/public-key kp)
              backup-path (backup/backup-pointer-path own-pk slot)
              fetched (try (fetch-fn relay-url backup-path)
                           (catch Exception e
                             {:ok? false :error :backup-fetch-failed :detail (.getMessage e)}))]
          (if-not (:ok? fetched)
            (let [reason (if (= :backup-not-found (:error fetched))
                           :local-state-corrupt-no-backup
                           :local-state-corrupt-auto-restore-failed)]
              (swap! state-atom #(-> (dissoc % :pending-corrupt-auto-restore?)
                                     (update-in [:diagnostics reason] (fnil inc 0))))
              (emit-diag! reason (or (:detail fetched) (name (or (:error fetched) :backup-fetch-failed))))
              {:ok? false :reason reason})
            (let [res (restore-encrypted-backup! {:key-provider kp
                                                  :local-state (dissoc state :pending-corrupt-auto-restore?)
                                                  :blob (:blob fetched)
                                                  :pointer (:pointer fetched)
                                                  :slot slot})]
              (if (:ok? res)
                (let [st' (-> (:state res)
                              (dissoc :pending-corrupt-auto-restore?)
                              (update-in [:diagnostics :local-state-corrupt-auto-restored] (fnil inc 0)))]
                  (reset! state-atom st')
                  (when state-file
                    (try (save-light-state-async! state-file st') (catch Exception _ nil)))
                  (emit-diag! :local-state-corrupt-auto-restored (:cid res))
                  {:ok? true :reason :local-state-corrupt-auto-restored :seq (:seq res) :cid (:cid res) :summary (:summary res)})
                (do
                  (swap! state-atom #(-> (dissoc % :pending-corrupt-auto-restore?)
                                         (update-in [:diagnostics :local-state-corrupt-auto-restore-failed] (fnil inc 0))))
                  (emit-diag! :local-state-corrupt-auto-restore-failed (name (or (:error res) :backup-restore-failed)))
                  {:ok? false :reason :local-state-corrupt-auto-restore-failed :error (:error res)})))))))))

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
  "Updates state-atom with connection liveness, conn-diagnostics summary, and live :runtime-ctx."
  [state-atom conn-atom]
  (when (and state-atom conn-atom)
    (let [c @conn-atom
          diag (conn-diagnostics-summary c)]
      (swap! state-atom (fn [st]
                          (-> st
                              (assoc :connected? (boolean (:ok? c))
                                     :connection-error (:error c)
                                     :conn-diagnostics diag)
                              (update :runtime-ctx merge
                                      {:runtime :jvm
                                       :conn (assoc c :diagnostics diag)
                                       :connected? (boolean (:ok? c))})))))))

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
                         (when-not (try-dispatch-jvm-mesh-chunk-res! payload)
                           (when-let [on-msg (:on-message ctx)]
                             (try (on-msg payload) (catch Exception _ nil)))
                           (when state-atom
                             (let [lock-obj (or (:cmd-lock ctx) state-atom)
                                   res (locking lock-obj
                                         (let [st @state-atom
                                               r (light-core/handle-wire-payload st payload (:privkey-bytes identity))
                                               cache-effs (:cache-effects r)]
                                           (reset! state-atom (:state r))
                                           (when (and state-file (seq cache-effs))
                                             (execute-cache-effects! (.getParent (io/file state-file)) cache-effs state-atom))
                                           (let [next-st @state-atom]
                                             (when (and state-file (not= st next-st))
                                               (try
                                                 (save-light-state-async! state-file next-st)
                                                 (catch Exception e
                                                   (when conn-atom
                                                     (apply-conn-event! conn-atom
                                                                        {:type :persist-failed
                                                                         :error (or (.getMessage e) "persist-failed")}
                                                                        cb-opts)
                                                     (sync-conn-diagnostics! state-atom conn-atom)))))
                                             (assoc r :state next-st))))]
                               (when (and event-out (seq (:stdout-events res)))
                                 (doseq [ev (:stdout-events res)]
                                   (event-out ev)))
                               (when-let [dial-info (:p2p-dial res)]
                                 (dial-p2p-peer! state-atom (:p2p-peers-atom ctx) (:ingress-peers-atom ctx) (:mdns-atom ctx) (:privkey-bytes identity) event-out dial-info))
                               (when (seq (:net-envelopes res))
                                 (if (some #(or (:p2p-direct? %) (:p2p-broadcast? %)) (:net-envelopes res))
                                   (send-routed-envelopes! (:net-envelopes res) send-fn-atom (:p2p-peers-atom ctx) (:ingress-peers-atom ctx) state-atom (:privkey-bytes identity))
                                   (dispatch-auto-reply! (:net-envelopes res) send-fn-atom state-atom conn-atom event-out reconnect-fn cb-opts))))))))))
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
  light-core/waitable-event-types)

(defn event-matches-wait-filter?
  "Delegates to unified pure `.cljc` core `light-core/event-matches-wait-filter?`
   (supporting `broadcast_seq` and `config/equivalent-subnet-id?`)."
  [evt opts]
  (light-core/event-matches-wait-filter? evt opts))

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

(defonce ^:private events-out-error-count-atom (atom 0))

(defn- emit-json-line!
  "Writes a data object as a JSON line to the dedicated print writer, and optionally mirrors to events-out-path.
   Never swallows `append-event-jsonl!` I/O errors silently (Rule 5 / BIP-020 Catch 4)."
  ([^PrintWriter writer data]
   (emit-json-line! writer data nil nil))
  ([^PrintWriter writer data events-out-path]
   (emit-json-line! writer data events-out-path nil))
  ([^PrintWriter writer data events-out-path state-atom]
   (when writer
     (.println writer ^String (json/write-str data))
     (.flush writer))
   (when events-out-path
     (try
       (append-event-jsonl! events-out-path data)
       (catch Exception e
         (swap! events-out-error-count-atom inc)
         (when state-atom
           (swap! state-atom (fn [st]
                               (-> st
                                   (update-in [:diagnostics :events-out-write-failed] (fnil inc 0))
                                   (update-in [:diagnostics :dropped] (fnil inc 0))))))
         (binding [*out* *err*]
           (println (str "WARN: append-event-jsonl! failed for " events-out-path ": " (.getMessage e)))))))))

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
        ctrl-file (io/file state-dir "control.json")
        _ (when (.exists ctrl-file)
            (when-let [ctrl (try (json/read-str (slurp ctrl-file)) (catch Exception _ nil))]
              (when (contains? ctrl "events_out")
                (let [daemon-ev (get ctrl "events_out")
                      canon-target (.getCanonicalPath (io/file events-path))
                      canon-daemon (when (and (string? daemon-ev) (not (str/blank? daemon-ev)))
                                     (.getCanonicalPath (io/file daemon-ev)))]
                  (when (not= canon-target canon-daemon)
                    (binding [*out* *err*]
                      (println (str "WARN: events-out-mismatch: wait-event targeting " canon-target
                                    " but daemon control.json has events_out=" (pr-str canon-daemon)))))))))
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
  "Routes an outgoing network envelope directly to P2P peer(s) or falls back to validator/relay mesh.
   Returns `{:mesh-submitted? :p2p-direct? :mesh-peers-targeted :p2p-peers-targeted :error}` (BIP-020-STAGE4-F2)."
  [env send-fn-atom p2p-peers-atom ingress-peers-atom state-atom privkey-bytes]
  (let [send-default! (fn []
                        (if-let [sfn (cond
                                       (instance? clojure.lang.IAtom send-fn-atom) @send-fn-atom
                                       (fn? send-fn-atom) send-fn-atom
                                       :else nil)]
                          (try
                            (let [r (sfn env)]
                              (not (false? r)))
                            (catch Throwable _
                              false))
                          false))]
    (cond
      (:p2p-broadcast? env)
      (let [p2p-sends (keep :send-fn (vals (or (when p2p-peers-atom @p2p-peers-atom) {})))
            ingress-sends (vals (or (when ingress-peers-atom @ingress-peers-atom) {}))
            all-sends (concat p2p-sends ingress-sends)
            p2p-sent (reduce
                      (fn [acc sfn]
                        (try
                          (let [r (sfn env)]
                            (if (false? r) acc (inc acc)))
                          (catch Throwable _
                            (when state-atom
                              (swap! state-atom update-in [:diagnostics :p2p-send-failed] (fnil inc 0)))
                            acc)))
                      0
                      all-sends)
            mesh-ok? (boolean (send-default!))]
        {:mesh-submitted? mesh-ok?
         :p2p-direct? (pos? p2p-sent)
         :mesh-peers-targeted (if mesh-ok? 1 0)
         :p2p-peers-targeted p2p-sent
         :error (when-not (or mesh-ok? (pos? p2p-sent)) "broadcast-route-failed")})

      (:p2p-direct? env)
      (let [norm-target (light-core/normalize-pubkey-hex (:p2p-peer env))
            p2p-entry (when p2p-peers-atom (get @p2p-peers-atom norm-target))
            ingress-send (when ingress-peers-atom (get @ingress-peers-atom norm-target))
            direct-send (or (:send-fn p2p-entry) ingress-send)]
        (if direct-send
          (let [direct-ok? (try
                             (let [ok? (direct-send env)]
                               (if (false? ok?)
                                 (throw (ex-info "p2p-direct-failed" {}))
                                 true))
                             (catch Throwable _
                               (when (and state-atom (:p2p-session-id env))
                                 (let [cmd-res (light-core/handle-command @state-atom
                                                                          {"cmd" "p2p-channel-state"
                                                                           "session_id" (:p2p-session-id env)
                                                                           "connected" false
                                                                           "error" "p2p-direct-failed"}
                                                                          privkey-bytes)]
                                   (reset! state-atom (:state cmd-res))))
                               false))]
            (if direct-ok?
              {:mesh-submitted? false :p2p-direct? true :mesh-peers-targeted 0 :p2p-peers-targeted 1 :error nil}
              (let [mesh-ok? (boolean (send-default!))]
                {:mesh-submitted? mesh-ok?
                 :p2p-direct? false
                 :mesh-peers-targeted (if mesh-ok? 1 0)
                 :p2p-peers-targeted 0
                 :error (when-not mesh-ok? "direct-and-mesh-send-failed")})))
          (do
            (when (and state-atom (:p2p-session-id env))
              (let [cmd-res (light-core/handle-command @state-atom
                                                       {"cmd" "p2p-channel-state"
                                                        "session_id" (:p2p-session-id env)
                                                        "connected" false
                                                        "error" "no-direct-route"}
                                                       privkey-bytes)]
                (reset! state-atom (:state cmd-res))))
            (let [mesh-ok? (boolean (send-default!))]
              {:mesh-submitted? mesh-ok?
               :p2p-direct? false
               :mesh-peers-targeted (if mesh-ok? 1 0)
               :p2p-peers-targeted 0
               :error (when-not mesh-ok? "no-direct-or-mesh-route")}))))

      :else
      (let [mesh-ok? (boolean (send-default!))]
        {:mesh-submitted? mesh-ok?
         :p2p-direct? false
         :mesh-peers-targeted (if mesh-ok? 1 0)
         :p2p-peers-targeted 0
         :error (when-not mesh-ok? "mesh-send-failed")}))))

(defn send-routed-envelopes!
  "Routes a sequence of outgoing network envelopes via route-net-envelope! and returns
   an aggregated delivery outcome map `{:ok? :mesh-submitted? :p2p-direct? :mesh-peers-targeted :p2p-peers-targeted :error}`."
  [envs send-fn-atom p2p-peers-atom ingress-peers-atom state-atom privkey-bytes]
  (let [outcomes (mapv #(route-net-envelope! % send-fn-atom p2p-peers-atom ingress-peers-atom state-atom privkey-bytes)
                       envs)
        mesh-ok? (boolean (some :mesh-submitted? outcomes))
        p2p-ok? (boolean (some :p2p-direct? outcomes))
        mesh-peers (reduce + 0 (map #(long (or (:mesh-peers-targeted %) 0)) outcomes))
        p2p-peers (reduce + 0 (map #(long (or (:p2p-peers-targeted %) 0)) outcomes))]
    {:ok? (or mesh-ok? p2p-ok? (empty? envs))
     :mesh-submitted? mesh-ok?
     :p2p-direct? p2p-ok?
     :mesh-peers-targeted mesh-peers
     :p2p-peers-targeted p2p-peers
     :error (when-not (or mesh-ok? p2p-ok? (empty? envs))
              (or (some :error outcomes) "send-routed-failed"))}))

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
                                    cache-effs (:cache-effects res)
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
                                (when (and state-file (seq cache-effs))
                                  (execute-cache-effects! (.getParent (io/file state-file)) cache-effs state-atom))
                                (when (and state-file (not= st @state-atom))
                                  (try (save-light-state-async! state-file @state-atom) (catch Exception _ nil)))
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
  "Uploads blob + pointer to `raw-relay-url` and returns a structured receipt
   `{:ok? true :endpoints [base-url]}` on HTTP 2xx or `{:ok? false :status ... :error ...}`
   on failure (fail-closed, Rule 5)."
  [raw-relay-url verb resp]
  (let [base-url (artifact-endpoint-base-url raw-relay-url)]
    (cond
      (nil? base-url)
      {:ok? false :error "missing-relay-url" :detail {:relay-url raw-relay-url}}

      (not (map? resp))
      {:ok? false :error "invalid-artifact-payload"}

      :else
      (try
        (let [client (default-http-client)
              post-req! (fn [subpath payload-str content-type timeout-ms]
                          (let [req (-> (HttpRequest/newBuilder)
                                        (.uri (URI/create (str base-url subpath)))
                                        (.timeout (Duration/ofMillis (long timeout-ms)))
                                        (.header "Content-Type" content-type)
                                        (.POST (HttpRequest$BodyPublishers/ofString payload-str StandardCharsets/UTF_8))
                                        (.build))
                                r (.send client req (HttpResponse$BodyHandlers/ofString StandardCharsets/UTF_8))
                                st (.statusCode r)]
                            {:ok? (<= 200 st 299)
                             :status st
                             :body (.body r)}))
              needs-blob? (contains? #{"artifact-put" "put" "storage-put"} (str verb))
              blob (or (get resp "blob") (:blob resp))
              ptr (or (get resp "pointer") (:pointer resp))
              blob-res (if (and needs-blob? blob)
                         (post-req! "/artifact/v1/blob"
                                    (json/write-str {"bytes_hex" (basalt/bytes->hex (:blob/bytes blob))
                                                     "cid" (:blob/cid blob)
                                                     "media_type" (or (:blob/media-type blob) "application/octet-stream")})
                                    "application/json"
                                    30000)
                         {:ok? true :status 200})]
          (if-not (:ok? blob-res)
            {:ok? false
             :status (:status blob-res)
             :error "artifact-blob-upload-failed"
             :detail {:endpoint base-url :status (:status blob-res)}}
            (let [ptr-res (if ptr
                            (post-req! "/artifact/v1/pointer"
                                       (pr-str ptr)
                                       "application/edn"
                                       15000)
                            {:ok? true :status 200})]
              (if (:ok? ptr-res)
                {:ok? true :endpoints [base-url]}
                {:ok? false
                 :status (:status ptr-res)
                 :error "artifact-pointer-upload-failed"
                 :detail {:endpoint base-url :status (:status ptr-res)}}))))
        (catch Exception e
          {:ok? false
           :error "relay-upload-exception"
           :detail {:endpoint base-url :message (.getMessage e)}})))))

(defn- maybe-write-artifact-out-file!
  "When `artifact-get` has `out_file` (`--out <file>`), writes verified raw bytes atomically
   (`.tmp` + rename) and returns `{:applied? true :ok? true :response <compact-receipt>}`.
   On any write or verification error, fails closed with canonical `:artifact-out-write-failed`
   and counted Rule 5 `:diagnose` (zero silent catch)."
  [verb cmd-map resp state-atom]
  (let [eff-verb (effective-artifact-domain-verb verb cmd-map)
        out-file (or (get cmd-map "out_file") (get cmd-map "out"))]
    (if (and (= eff-verb "artifact-get")
             (map? resp)
             (true? (or (get resp "ok") (:ok resp)))
             (string? out-file)
             (not (str/blank? out-file))
             (string? (get resp "hex")))
      (try
        (let [raw-bytes ^bytes (basalt/hex->bytes (get resp "hex"))
              expected-cid (or (get resp "cid") (:cid resp))
              actual-cid (when (and (string? expected-cid) (not (str/blank? expected-cid)))
                           (str/lower-case (basalt/bytes->hex (crypto/sha256 raw-bytes))))]
          (if (and actual-cid (not= (str/lower-case expected-cid) actual-cid))
            (let [err (errors/canonical-error :artifact-out-write-failed
                                              {:out-file out-file :reason "cid-mismatch"})]
              (when state-atom (swap! state-atom errors/record-error-diagnostic err))
              {:applied? true :ok? false :response (errors/canonical-error->wire err)})
            (let [f (io/file out-file)
                  _ (when (.isDirectory f)
                      (throw (ex-info "Target --out path is a directory" {:out-file out-file})))
                  parent (.getParentFile f)
                  _ (when parent (.mkdirs parent))
                  tmp-f (io/file (or parent (io/file "."))
                                 (str ".bitecho-art-" (System/nanoTime) ".tmp"))]
              (Files/write (.toPath tmp-f)
                           raw-bytes
                           (into-array java.nio.file.OpenOption [StandardOpenOption/CREATE
                                                                 StandardOpenOption/TRUNCATE_EXISTING
                                                                 StandardOpenOption/WRITE]))
              (try
                (Files/move (.toPath tmp-f)
                            (.toPath f)
                            (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE
                                                                  StandardCopyOption/REPLACE_EXISTING]))
                (catch Exception _
                  (Files/move (.toPath tmp-f)
                              (.toPath f)
                              (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))))
              {:applied? true
               :ok? true
               :response (flags/format-artifact-get-out-receipt resp out-file (alength raw-bytes))})))
        (catch Exception e
          (let [err (errors/canonical-error :artifact-out-write-failed
                                            {:out-file out-file :message (.getMessage e)})]
            (when state-atom (swap! state-atom errors/record-error-diagnostic err))
            {:applied? true :ok? false :response (errors/canonical-error->wire err)})))
      {:applied? false :ok? true :response resp})))

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
                effective-map-with-now (if (and (contains? #{"send" "broadcast"} verb)
                                                (not (contains? effective-map "now_ms")))
                                         (assoc effective-map "now_ms" (System/currentTimeMillis))
                                         effective-map)
                res (cond
                      (contains? #{"backup-put" "backup-restore" "identity-migrate"} verb)
                      (handle-jvm-stage-c-verb! verb effective-map-with-now state-atom identity relay-url conn-opts)

                      (and (= eff-domain-verb "storage-put")
                           (not (boolean (or (get effective-map-with-now "local_only")
                                             (get effective-map-with-now "local-only")
                                             (:local-only effective-map-with-now)))))
                      (let [sub-str (str (or (get effective-map-with-now "subnet_id") (:subnet-id @state-atom) "global"))
                            prep (light-core/prepare-storage-put @state-atom effective-map-with-now (:privkey-bytes identity) sub-str)]
                        (if-not (:ok? prep)
                          (dissoc prep :ok?)
                          (let [art-relay (or (get effective-map-with-now "relay_url")
                                              (get effective-map-with-now "relay-url")
                                              (:relay-url effective-map-with-now)
                                              relay-url)
                                net-receipt (post-artifact-to-relay! art-relay "storage-put" (:publish-intent prep))
                                committed (light-core/commit-storage-put-outcome @state-atom (:publish-intent prep) net-receipt)]
                            (assoc (dissoc committed :ok?)
                                   :net-envelopes (if (:ok? committed) (:net-envelopes prep) [])))))

                      :else
                      (let [read-blob-cmd? (contains? #{"storage-get" "artifact-get"} eff-domain-verb)
                            hydrated-from-cache? (and read-blob-cmd?
                                                      state-file
                                                      (some? (cache/resolve-read-target-cid @state-atom eff-domain-verb effective-map-with-now)))
                            st-for-cmd (cond
                                         (= eff-domain-verb "status")
                                         (assoc @state-atom :runtime-ctx (merge (:runtime-ctx @state-atom) (build-light-runtime-ctx)))

                                         hydrated-from-cache?
                                         (maybe-hydrate-state-for-read! (or (.getParent (io/file state-file)) ".") state-atom eff-domain-verb effective-map-with-now)

                                         :else
                                         @state-atom)
                            cmd-res (light-core/handle-command st-for-cmd effective-map-with-now (:privkey-bytes identity))]
                        (if hydrated-from-cache?
                          (assoc cmd-res :state (cache/prune-inline-hot-blobs (:state cmd-res) 0))
                          cmd-res)))
                _ (when (:state res)
                    (reset! state-atom (:state res)))
                _ (when (and state-file (seq (:cache-effects res)))
                    (let [sd (or (.getParent (io/file state-file)) ".")]
                      (execute-cache-effects! sd (:cache-effects res) state-atom)))
                out-write-res (maybe-write-artifact-out-file! eff-domain-verb effective-map (:response res) state-atom)
                res (if (:applied? out-write-res)
                      (assoc res :response (:response out-write-res) :state @state-atom)
                      res)
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
                                                        (let [r (submit-relay-envelope! relay-url env {:timeout-ms 5000})
                                                              ok? (boolean (or (true? (get r "ok")) (true? (:ok r))))]
                                                          (when-not ok?
                                                            (swap! state-atom update-in [:diagnostics :relay-mirror-failed] (fnil inc 0)))
                                                          ok?)
                                                        (catch Exception _
                                                          (swap! state-atom update-in [:diagnostics :relay-mirror-failed] (fnil inc 0))
                                                          false)))
                                                    non-direct))))
                                         false))
                    commit-intent! (fn [res-map outcome]
                                     (if-let [intent (:fanout-intent res-map)]
                                       (let [committed (light-core/commit-delivery-outcome
                                                        @state-atom
                                                        intent
                                                        (assoc outcome :now-ms (System/currentTimeMillis)))]
                                         (reset! state-atom (:state committed))
                                         (:response committed))
                                       (:response res-map)))]
                (if (some #(or (:p2p-direct? %) (:p2p-broadcast? %)) live-envs)
                  (let [_ (when (and (not currently-live?)
                                     (:reconnect-fn conn-opts)
                                     (seq (:nodes bootstrap)))
                            (try ((:reconnect-fn conn-opts)) (catch Exception _ nil)))
                        route-res (send-routed-envelopes! live-envs
                                                          (when (connection-live? @conn-atom @state-atom) (:send-fn @conn-atom))
                                                          p2p-peers-atom
                                                          ingress-peers-atom
                                                          state-atom
                                                          (:privkey-bytes identity))
                        mirror-ok? (mirror-to-relay! live-envs)
                        mesh-ok? (boolean (or (:mesh-submitted? route-res) mirror-ok?))
                        committed-resp (commit-intent!
                                        res
                                        (assoc route-res
                                               :mesh-submitted? mesh-ok?
                                               :mesh-peers-targeted (max (long (or (:mesh-peers-targeted route-res) 0))
                                                                         (if mirror-ok? 1 0))))]
                    (sync-conn-diagnostics! state-atom conn-atom)
                    (when state-file (save-light-state-async! state-file @state-atom))
                    (finish-resp! committed-resp))
                  (let [sent-ingress? (boolean
                                       (when (and ingress-peers-atom (seq @ingress-peers-atom))
                                         (some true? (mapv #(send-all-envelopes! % live-envs) (vals @ingress-peers-atom)))))
                        sent-val? (when currently-live?
                                    (send-all-envelopes! (:send-fn @conn-atom) live-envs))
                        sent-relay? (mirror-to-relay! live-envs)
                        sent? (or sent-val? sent-ingress? sent-relay?)]
                    (if sent?
                      (let [mesh-ok? (boolean (or sent-val? sent-relay?))
                            committed-resp (commit-intent!
                                            res
                                            {:mesh-submitted? mesh-ok?
                                             :p2p-direct? sent-ingress?
                                             :mesh-peers-targeted (if mesh-ok? 1 0)
                                             :p2p-peers-targeted (if sent-ingress? 1 0)})]
                        (swap! state-atom assoc :connected? true :connection-error nil)
                        (sync-conn-diagnostics! state-atom conn-atom)
                        (when state-file (save-light-state-async! state-file @state-atom))
                        (finish-resp! committed-resp))
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
                                  (let [committed-resp (commit-intent!
                                                        res
                                                        {:mesh-submitted? true
                                                         :p2p-direct? false
                                                         :mesh-peers-targeted 1
                                                         :p2p-peers-targeted 0})]
                                    (swap! state-atom assoc :connected? true :connection-error nil)
                                    (sync-conn-diagnostics! state-atom conn-atom)
                                    (when state-file (save-light-state-async! state-file @state-atom))
                                    (finish-resp! committed-resp))
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
                                        (when-let [intent (:fanout-intent res)]
                                          (swap! state-atom #(:state (light-core/commit-delivery-outcome % intent {:mesh-submitted? false :p2p-direct? false :error err :now-ms (System/currentTimeMillis)}))))
                                        (sync-conn-diagnostics! state-atom conn-atom)
                                        (when state-file (save-light-state-async! state-file @state-atom))
                                        (let [err-map (assoc (or (:response res) {"ok" false}) "ok" false "queued" true "mesh_submitted" false "transport_error" err "error" err)]
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
                                  (when state-file (save-light-state-async! state-file @state-atom))
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
                (when state-file (save-light-state-async! state-file @state-atom))
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
        raw-events-out (or (:events-out conn-opts) (:events-out ctx))
        canon-events-out (when (and (string? raw-events-out) (not (str/blank? raw-events-out)))
                           (.getCanonicalPath (io/file raw-events-out)))
        state-atom (:state-atom ctx)
        _ (when state-atom
            (swap! state-atom assoc :events-out canon-events-out))
        ctrl-info {"port" actual-port
                   "token" token
                   "pid" (or pid 0)
                   "events_out" canon-events-out}
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
                              (let [ctl-t0 (System/currentTimeMillis)
                                    cmd-lock (or (:cmd-lock ctx) (:serve-cmd-lock ctx) (Object.))
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
                                                    sub-filter (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) (:subnet cmd-map))
                                                    sid-filter (or (get cmd-map "session_id") (get cmd-map "session-id") (:session-id cmd-map))
                                                    min-bseq (when-let [mb (or (get cmd-map "min_broadcast_seq") (get cmd-map "min-broadcast-seq") (:min-broadcast-seq cmd-map))]
                                                               (long mb))
                                                    after-ts (when-let [at (or (get cmd-map "after_ts") (get cmd-map "after-ts") (:after-ts cmd-map))]
                                                               (long at))
                                                    has-filter? (or min-seq cursor sub-filter sid-filter min-bseq after-ts)
                                                    filter-opts {:enforce-waitable-type? false
                                                                 :cursor cursor
                                                                 :session-id sid-filter
                                                                 :subnet-id sub-filter
                                                                 :min-seq min-seq
                                                                 :min-broadcast-seq min-bseq
                                                                 :after-ts after-ts
                                                                 :allow-eid-fallback-for-min-seq? (nil? cursor)}
                                                    deadline (+ (System/currentTimeMillis) timeout-ms)]
                                                (loop []
                                                  (let [popped (locking cmd-lock
                                                                 (let [st @state-atom
                                                                       q (if (some? cursor)
                                                                           (let [h (:event-history st)] (if (seq h) h (:event-queue st)))
                                                                           (:event-queue st))
                                                                       has-events? (if has-filter?
                                                                                     (some #(light-core/event-matches-wait-filter? % filter-opts) q)
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
                                    _ (record-ctl-latency! (max 0 (- (System/currentTimeMillis) ctl-t0))
                                                           state-atom
                                                           (:ctl-warn-ms conn-opts))
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
  "Executes a single non-blocking background chain-state quorum sync tick driven by
   `bitecho.sync.core/step-auto-sync` (BIP-022 Stage B, Row 5; Rules 2, 4, 5).
   Updates state-atom, persists to state-file when sync succeeds, detects F-EPOCH-1
   stalls loudly, emits structured `auto-sync` JSONL events, diagnoses failures loudly,
   and optionally renews `register-home-set` when `:auto-register-home-set?` is enabled."
  [state-atom bootstrap identity state-file conn-opts]
  (let [pubkey (or (:pubkey-hex identity) (:pubkey identity))
        privkey (:privkey-bytes identity)
        conn-atom (:conn-atom conn-opts)
        event-out (:event-out conn-opts)
        now-fn (or (:now-ms-fn conn-opts) #(System/currentTimeMillis))
        sync-atom (or (:sync-atom conn-opts)
                      (atom (sync-core/init-sync-state
                             {:interval-ms (or (:sync-interval-ms conn-opts) sync-core/default-sync-interval-ms)
                              :stall-threshold-ms (or (:stall-threshold-ms conn-opts) sync-core/default-stall-threshold-ms)})))
        cur-gen (:generation @sync-atom 1)
        [tick-st tick-effs] (sync-core/step-auto-sync @sync-atom
                                                      {:type :tick
                                                       :generation cur-gen
                                                       :now-ms (now-fn)
                                                       :active? true})
        _ (reset! sync-atom tick-st)
        _ (swap! state-atom assoc-in [:runtime-ctx :sync-state] tick-st)
        should-fetch? (boolean (some #(= :fetch-quorum-sync (:effect %)) tick-effs))]
    (if-not should-fetch?
      {:ok? true :skipped? true}
      (let [sync-opts (assoc (or conn-opts {}) :identity identity)
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
                st0 @state-atom
                fin-ep (long (or (get-in st0 [:account :finalized-epoch]) (:epoch st0) 0))
                bal (long (or (get-in st0 [:account :balance]) 0))
                spend (long (or (get-in st0 [:account :spendable]) bal 0))
                [sync-st' effs] (sync-core/step-auto-sync @sync-atom
                                                          {:type :fetch-ok
                                                           :generation cur-gen
                                                           :now-ms (now-fn)
                                                           :finalized-epoch fin-ep
                                                           :head-epoch (:head-epoch res)
                                                           :balance bal
                                                           :spendable spend})
                _ (reset! sync-atom sync-st')
                _ (swap! state-atom
                         (fn [s]
                           (let [tracker {:last-finalized-epoch (:last-finalized-epoch sync-st')
                                          :last-advanced-ms (:last-advanced-ms sync-st')
                                          :stalled? (:stalled? sync-st')
                                          :stall-started-ms (:stall-started-ms sync-st')
                                          :stall-duration-ms (:stall-duration-ms sync-st')}]
                             (cond-> (-> s
                                         (assoc :auto-sync-stall-tracker tracker
                                                :auto-sync-last-error (:last-error sync-st'))
                                         (assoc-in [:runtime-ctx :sync-state] sync-st'))
                               (:stalled? sync-st')
                               (-> (update-in [:diagnostics :auto-sync-stalled] (fnil inc 0))
                                   (update-in [:diagnostics :finalized-epoch-stalled] (fnil inc 0)))))))
                _ (when state-file
                    (try (save-light-state-async! state-file @state-atom) (catch Exception _ nil)))]
            (doseq [eff effs]
              (case (:effect eff)
                :diagnose
                (when (= :auto-sync-stalled (:reason eff))
                  (when conn-atom
                    (apply-conn-event! conn-atom
                                       {:type :finalized-epoch-stalled
                                        :finalized-epoch fin-ep
                                        :stall-duration-ms (:stall-duration-ms eff)
                                        :diagnose eff}
                                       conn-opts)
                    (sync-conn-diagnostics! state-atom conn-atom)))

                :emit-event
                (when event-out
                  (event-out (:event eff)))

                nil))
            (assoc res
                   :stalled? (:stalled? sync-st')
                   :stall-duration-ms (:stall-duration-ms sync-st')))
          (let [err (str (or (:error res) "auto-sync-tick-failed"))
                [sync-st' effs] (sync-core/step-auto-sync @sync-atom
                                                          {:type :fetch-error
                                                           :generation cur-gen
                                                           :now-ms (now-fn)
                                                           :error err})]
            (reset! sync-atom sync-st')
            (swap! state-atom (fn [s]
                                (-> s
                                    (assoc :auto-sync-last-error err)
                                    (assoc-in [:runtime-ctx :sync-state] sync-st'))))
            (when conn-atom
              (apply-conn-event! conn-atom {:type :auto-sync-failed :error err} conn-opts)
              (sync-conn-diagnostics! state-atom conn-atom))
            (doseq [eff effs]
              (when (and (= :emit-event (:effect eff)) event-out)
                (event-out (:event eff))))
            res))))))

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

(defn- generate-lock-token
  []
  (let [bytes (byte-array 8)]
    (.nextBytes (java.security.SecureRandom.) bytes)
    (apply str (map #(format "%02x" (bit-and % 0xff)) bytes))))

(defn- write-lock-exclusive!
  "OS-atomic CREATE_NEW write with POSIX 0600 permissions and fsync (`force(true)`).
   Returns `:created` or `:exists`."
  [^java.io.File lock-file payload-map]
  (let [path (.toPath lock-file)
        bytes (.getBytes (pr-str payload-map) StandardCharsets/UTF_8)]
    (try
      (with-open [ch (FileChannel/open path
                                       (into-array java.nio.file.OpenOption
                                                   [StandardOpenOption/CREATE_NEW
                                                    StandardOpenOption/WRITE]))]
        (try
          (Files/setPosixFilePermissions path (PosixFilePermissions/fromString "rw-------"))
          (catch UnsupportedOperationException _ nil))
        (let [buf (ByteBuffer/wrap bytes)]
          (while (.hasRemaining buf)
            (.write ch buf)))
        (.force ch true))
      :created
      (catch FileAlreadyExistsException _
        :exists))))

(defn- read-existing-lock-holder
  [^java.io.File lock-file ^java.io.File ctrl-file]
  (let [lock-info (when (.exists lock-file)
                    (try (edn/read-string (slurp lock-file)) (catch Exception _ nil)))
        ctrl-info (when (.exists ctrl-file)
                    (try (json/read-str (slurp ctrl-file)) (catch Exception _ nil)))
        raw-pid (or (when (map? lock-info) (:pid lock-info))
                    (when (map? ctrl-info) (or (get ctrl-info "pid") (:pid ctrl-info))))
        pid-long (when (some? raw-pid)
                   (try (Long/parseLong (str raw-pid)) (catch Exception _ nil)))]
    (when (or (map? lock-info) (some? pid-long))
      {:pid pid-long
       :token (when (map? lock-info) (:token lock-info))
       :timestamp-ms (when (map? lock-info) (:timestamp-ms lock-info))})))

(defn check-single-instance-lock
  "OS-atomic single-instance serve/driver guard (`BIP-022` Row 10 / `BIP-010` / `P-OPS-3`, Rules 4 & 5):
   Uses `FileChannel.open(CREATE_NEW, WRITE)` with POSIX `0600` + `force(true)` driven by
   `bitecho.lifecycle.lock-core/transition-lock`.
   - If `serve.lock` (or `control.json`) is held by a live PID (`!= current-pid`), fails fast
     without touching `control.json`, returning canonical `:duplicate-instance` error + counted
     `:diagnose {:reason :duplicate-serve-instance-rejected}`.
   - If held by a dead PID (or corrupt lock), unlinks and retries atomic `CREATE_NEW` (bounded
     by `lock-core/default-max-reclaim-retries`), emitting counted `:stale-serve-lock-reclaimed`."
  ([state-dir]
   (check-single-instance-lock state-dir nil))
  ([state-dir {:keys [current-pid pid-alive-fn timestamp-ms state token]}]
   (locking single-instance-lock-guard
     (let [dir (io/file (or state-dir "."))
           _ (when-not (.exists dir) (.mkdirs dir))
           lock-file (io/file dir "serve.lock")
           ctrl-file (io/file dir "control.json")
           my-pid (long (or current-pid (current-jvm-pid)))
           my-tok (or token (generate-lock-token))
           alive-fn (or pid-alive-fn default-pid-alive?)
           now-ms (long (or timestamp-ms (System/currentTimeMillis)))
           ;; Upgrade compatibility: if serve.lock does not exist yet, check live control.json PID
           ctrl-holder (when (and (not (.exists lock-file)) (.exists ctrl-file))
                         (read-existing-lock-holder lock-file ctrl-file))
           init-st (lock-core/init-lock-state {:mode :pid-file
                                               :lock-id (.getAbsolutePath lock-file)
                                               :self-id my-pid
                                               :token my-tok
                                               :runtime "jvm"
                                               :generation 1})
           [st0 effs0] (lock-core/transition-lock init-st {:type :acquire-requested :now-ms now-ms})]
       (loop [cur-st st0
              effs effs0
              all-diags []]
         (let [diag-effs (filterv #(= :diagnose (:effect %)) effs)
               next-diags (into all-diags diag-effs)
               action-eff (first (remove #(= :diagnose (:effect %)) effs))]
           (case (:effect action-eff)
             :fs-create-exclusive
             (let [live-ctrl? (boolean (and ctrl-holder
                                            (some? (:pid ctrl-holder))
                                            (not= (:pid ctrl-holder) my-pid)
                                            (alive-fn (:pid ctrl-holder))))
                   create-res (if live-ctrl?
                                :exists
                                (write-lock-exclusive! lock-file (:payload action-eff)))]
               (if (= :created create-res)
                 (let [[st' effs'] (lock-core/transition-lock cur-st {:type :create-exclusive-ok
                                                                      :generation (:generation action-eff)
                                                                      :now-ms now-ms})]
                   (recur st' effs' next-diags))
                 (let [holder (or (read-existing-lock-holder lock-file ctrl-file) ctrl-holder)
                       h-pid (:pid holder)
                       alive? (boolean (and h-pid (not= h-pid my-pid) (alive-fn h-pid)))
                       [st' effs'] (lock-core/transition-lock cur-st {:type :create-exclusive-exists
                                                                      :generation (:generation action-eff)
                                                                      :existing-holder holder
                                                                      :holder-alive? alive?
                                                                      :now-ms now-ms})]
                   (recur st' effs' next-diags))))

             :fs-reclaim-stale
             (do
               (when (.exists lock-file)
                 (try (.delete lock-file) (catch Exception _ nil)))
               (let [recreate-res (write-lock-exclusive! lock-file (:payload action-eff))]
                 (if (= :created recreate-res)
                   (let [[st' effs'] (lock-core/transition-lock cur-st {:type :stale-reclaim-ok
                                                                        :generation (:generation action-eff)
                                                                        :stale-pid (:expected-stale-pid action-eff)
                                                                        :now-ms now-ms})]
                     (recur st' effs' next-diags))
                   (let [[st' effs'] (lock-core/transition-lock cur-st {:type :stale-reclaim-race
                                                                        :generation (:generation action-eff)
                                                                        :now-ms now-ms})]
                     (recur st' effs' next-diags)))))

             :activate-leader
             (let [reclaimed? (boolean (:reclaimed-stale-lock? cur-st))
                   stale-pid (:stale-pid cur-st)]
               (cond-> {:ok? true
                        :locked-pid my-pid
                        :token my-tok
                        :lock-file (.getAbsolutePath lock-file)
                        :reclaimed-stale-lock? reclaimed?
                        :lock-state cur-st
                        :effects next-diags}
                 reclaimed? (assoc :stale-pid stale-pid)))

             :reject-duplicate
             (let [canon-err (:error action-eff)
                   locked-pid (:holder-pid cur-st)
                   diag (or (first (filter #(= :duplicate-serve-instance-rejected (:reason %)) next-diags))
                            {:effect :diagnose
                             :type :diagnose
                             :reason :duplicate-serve-instance-rejected
                             :locked-pid locked-pid
                             :attempted-pid my-pid
                             :state-dir (.getAbsolutePath dir)})
                   st' (update-in (or state {:diagnostics {}})
                                  [:diagnostics :duplicate-serve-instance-rejected]
                                  (fnil inc 0))]
               {:ok? false
                :error "already-running"
                :canonical-error canon-err
                :locked-pid locked-pid
                :attempted-pid my-pid
                :lock-state cur-st
                :diagnose diag
                :diagnostics (:diagnostics st')
                :state st'
                :effects next-diags})

             {:ok? false
              :error "lock-acquisition-failed"
              :lock-state cur-st
              :effects next-diags})))))))

(defn acquire-serve-lock!
  "Acquires the OS-atomic single-instance lock for `state-dir`."
  ([state-dir]
   (check-single-instance-lock state-dir nil))
  ([state-dir opts]
   (check-single-instance-lock state-dir opts)))

(defn release-serve-lock!
  "Releases `<state-dir>/serve.lock` only if owned by `expected-pid` (and `expected-token` when provided)."
  ([state-dir]
   (release-serve-lock! state-dir nil nil))
  ([state-dir expected-pid]
   (release-serve-lock! state-dir expected-pid nil))
  ([state-dir expected-pid expected-token]
   (locking single-instance-lock-guard
     (when state-dir
       (let [lock-file (io/file state-dir "serve.lock")]
         (when (.exists lock-file)
           (let [info (try (edn/read-string (slurp lock-file)) (catch Exception _ nil))
                 owner-pid (when (map? info) (:pid info))
                 owner-tok (when (map? info) (:token info))
                 pid-ok? (or (nil? expected-pid)
                             (nil? owner-pid)
                             (= (long expected-pid) (long owner-pid)))
                 tok-ok? (or (nil? expected-token)
                             (nil? owner-tok)
                             (= (str expected-token) (str owner-tok)))]
             (when (and pid-ok? tok-ok?)
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
      (let [canon-wire (errors/canonical-error->wire
                        (or (:canonical-error lock-res)
                            (errors/canonical-error :duplicate-instance
                                                    {:locked-pid (:locked-pid lock-res)
                                                     :attempted-pid (:attempted-pid lock-res)
                                                     :lock-file (str (io/file state-dir "serve.lock"))})))
            err-ev (merge canon-wire
                          {"event" "duplicate-serve-rejected"
                           "ok" false
                           "error" "duplicate-instance"
                           "legacy_error" "already-running"
                           "locked_pid" (:locked-pid lock-res)
                           "diagnose" "duplicate-serve-instance-rejected"})]
        (emit-json-line! out-writer err-ev events-out)
        lock-res)
      (let [my-lock-pid (:locked-pid lock-res)
            my-lock-token (:token lock-res)
            lock-state (:lock-state lock-res)
            _ (when (:reclaimed-stale-lock? lock-res)
                (emit-json-line! out-writer
                                 {"event" "stale-serve-lock-reclaimed"
                                  "stale_pid" (:stale-pid lock-res)
                                  "pid" my-lock-pid}
                                 events-out))
            state-file (str (io/file state-dir "state.fressian"))
            cmd-file (:cmd-file opts)
            identity (load-or-create-light-identity! state-dir opts)
            bootstrap (discovery/load-bootstrap-descriptor! (:bootstrap opts))
            load-diags-atom (atom [])
            loaded-state (load-light-state! state-file
                                            (cond-> {:diagnostics-atom load-diags-atom}
                                              (some? (:min-free-disk-bytes opts)) (assoc :min-free-disk-bytes (:min-free-disk-bytes opts))))
            reconciled-res (when loaded-state
                             (light-core/reconcile-startup-subnet-id
                              loaded-state
                              (:subnet-id opts)
                              (:subscribe-subnets opts)
                              {:reset-network-state? (boolean (:reset-network-state? opts))}))
            _ (when (and reconciled-res (false? (:ok? reconciled-res)))
                (emit-json-line! out-writer
                                 {"event" "cross-network-subnet-switch-blocked"
                                  "ok" false
                                  "error" "cross-network-subnet-switch-blocked"
                                  "from" (:subnet-id loaded-state)
                                  "to" (:subnet-id opts)}
                                 (:events-out opts))
                (throw (ex-info "Cross-network subnet switch blocked (pass --reset-network-state to override)"
                                {:error :cross-network-subnet-switch-blocked})))
            _ (when (and reconciled-res (:reconciled? reconciled-res))
                (doseq [ev (:stdout-events reconciled-res)]
                  (emit-json-line! out-writer ev (:events-out opts))))
            loaded-reconciled (if reconciled-res (:state reconciled-res) loaded-state)
            base-state (or (when loaded-reconciled
                             (cond-> loaded-reconciled
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
            initial-state-raw (cond-> (assoc base-state :max-epoch-skew (long (or (:max-epoch-skew opts) (:max-epoch-skew base-state) 15)))
                                (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                                (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                                (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap)))
                                (:pin-version opts) (assoc :pin-version (:pin-version opts))
                                (:auto-update-pointer opts) (assoc :auto-update-pointer (:auto-update-pointer opts))
                                (seq (:trusted-deploy-authorities opts)) (assoc :trusted-deploy-authorities (:trusted-deploy-authorities opts)))
            dac-rec (flags/reconcile-trusted-dac-anchors initial-state-raw
                                                         (:trusted-dac-anchors-spec opts)
                                                         (:trusted-dac-anchors bootstrap))
            initial-state (apply-jvm-startup-diagnostics! (:state dac-rec) identity @load-diags-atom)
            _ (doseq [ev (:stdout-events dac-rec)]
                (emit-json-line! out-writer ev (:events-out opts)))
            _ (let [sec-echo (flags/security-flags->wire
                              (flags/build-security-flags-echo
                               {:subnet-id (:subnet-id initial-state)
                                :subnet-id-overridden? (boolean (:subnet-id-overridden? initial-state false))
                                :trusted-dac-anchors (:trusted-dac-anchors initial-state)
                                :trusted-dac-anchors-provenance (:trusted-dac-anchors-provenance initial-state)
                                :trusted-deploy-authorities (:trusted-deploy-authorities initial-state)
                                :pin-version (:pin-version initial-state)
                                :auto-update-pointer (:auto-update-pointer initial-state)
                                :keystore-security-tier (:keystore-security-tier initial-state)}))]
                (binding [*out* *err*]
                  (println (json/write-str {"event" "startup-security-flags" "security_flags" sec-echo}))))
            _ (when (or (and reconciled-res (:reconciled? reconciled-res))
                        (seq (:effects dac-rec)))
                (try (save-light-state! state-file initial-state) (catch Exception _ nil)))
            state-atom (atom initial-state)
            _ (when (and (:pending-corrupt-auto-restore? @state-atom)
                         (not= (:connect? opts) false))
                (let [auto-relay (or (:relay-url opts)
                                     (:relay_url opts)
                                     (infer-bootstrap-relay-url bootstrap opts)
                                     (when (= "bitecho.org" (:domain bootstrap)) "https://ns1.bitecho.org"))]
                  (maybe-auto-restore-corrupt-state! state-atom identity state-file auto-relay opts)))
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
            sync-interval-ms (max 1000 (long (or (:sync-interval-ms opts) sync-core/default-sync-interval-ms)))
            sync-atom (atom (sync-core/init-sync-state {:interval-ms sync-interval-ms
                                                        :stall-threshold-ms (or (:stall-threshold-ms opts)
                                                                                sync-core/default-stall-threshold-ms)
                                                        :enabled? (boolean (:auto-sync? opts true))}))
            _ (swap! state-atom assoc
                     :mdns-hostname mdns-host
                     :lan-ip lan-ip
                     :default-p2p-candidates default-cands
                     :runtime-ctx {:runtime :jvm
                                   :lock-state lock-state
                                   :sync-state @sync-atom})
            mdns-svc (try (mdns/start-mdns-service! {:initial-hosts {mdns-host lan-ip}}) (catch Exception _ nil))
            stop-updater! (when (:auto-update-pointer opts)
                            (updater/start-jvm-auto-updater!
                             (cond-> {:node-id (or (:peer-id identity) "jvm-light-node")
                                      :pointer-url (:auto-update-pointer opts)
                                      :poll-interval-ms (:auto-update-interval-ms opts)
                                      :pinned-version (:pin-version opts)
                                      :force-http? (boolean (:auto-update-force-http? opts))
                                      :mesh-connected-fn (fn [] (fn? (:send-fn @conn-atom)))
                                      :mesh-chunk-fetch-fn (fn [cid eff] (fetch-mesh-chunks-jvm! conn-atom identity cid eff))
                                      :on-event (fn [ev] (event-out ev))
                                      :stop-node-fn! (fn [] (try (save-light-state! state-file @state-atom) (catch Exception _ nil)))}
                               (contains? opts :trusted-deploy-authorities)
                               (assoc :trusted-deploy-authorities (:trusted-deploy-authorities opts)))))
            _ (when stop-updater!
                (.addShutdownHook (Runtime/getRuntime) (Thread. ^Runnable stop-updater!)))
            mdns-atom (or mdns-svc (atom (mdns/init-mdns-table)))
            p2p-peers-atom (atom {})
            ingress-peers-atom (atom {})
            conn-opts (assoc opts
                             :state-atom state-atom
                             :conn-atom conn-atom
                             :sync-atom sync-atom
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
                                           _ (swap! state-atom
                                                    (fn [st]
                                                      (let [r (light-core/handle-wire-payload st wire-bytes (:privkey-bytes identity))]
                                                        (reset! r-box r)
                                                        (:state r))))
                                           r @r-box
                                           _ (when (and state-file (seq (:cache-effects r)))
                                               (execute-cache-effects! (.getParent (io/file state-file)) (:cache-effects r) state-atom))
                                           new-st @state-atom]
                                       (when state-file
                                         (try (save-light-state-async! state-file new-st) (catch Exception _ nil)))
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
                                               (release-serve-lock! state-dir my-lock-pid my-lock-token)
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
                                       (save-light-state-async! state-file @state-atom))
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
                                     (save-light-state-async! state-file @state-atom))
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
                    (release-serve-lock! state-dir my-lock-pid my-lock-token)
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
              (release-serve-lock! state-dir my-lock-pid my-lock-token)
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
          (let [r (light-core/handle-wire-payload @state-atom wire-bytes priv-bytes)
                cache-effs (:cache-effects r)]
            (reset! state-atom (:state r))
            (when (and state-file (seq cache-effs))
              (execute-cache-effects! (.getParent (io/file state-file)) cache-effs state-atom))
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
        (try (save-light-state-async! state-file @state-atom) (catch Exception _ nil))))
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
            identity (load-or-create-light-identity! state-dir opts)
            bootstrap (discovery/load-bootstrap-descriptor! (:bootstrap opts))
            load-diags-atom (atom [])
            loaded-state (load-light-state! state-file
                                            (cond-> {:diagnostics-atom load-diags-atom}
                                              (some? (:min-free-disk-bytes opts)) (assoc :min-free-disk-bytes (:min-free-disk-bytes opts))))
            reconciled-res (when loaded-state
                             (light-core/reconcile-startup-subnet-id
                              loaded-state
                              (:subnet-id opts)
                              (:subscribe-subnets opts)
                              {:reset-network-state? (boolean (:reset-network-state? opts))}))
            _ (when (and reconciled-res (false? (:ok? reconciled-res)))
                (emit-json-line! out-writer
                                 {"event" "cross-network-subnet-switch-blocked"
                                  "ok" false
                                  "error" "cross-network-subnet-switch-blocked"
                                  "from" (:subnet-id loaded-state)
                                  "to" (:subnet-id opts)}
                                 (:events-out opts))
                (throw (ex-info "Cross-network subnet switch blocked (pass --reset-network-state to override)"
                                {:error :cross-network-subnet-switch-blocked})))
            _ (when (and reconciled-res (:reconciled? reconciled-res))
                (doseq [ev (:stdout-events reconciled-res)]
                  (emit-json-line! out-writer ev (:events-out opts))))
            loaded-reconciled (if reconciled-res (:state reconciled-res) loaded-state)
            base-state (or (when loaded-reconciled
                             (cond-> loaded-reconciled
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
            initial-state-raw (cond-> (assoc base-state :max-epoch-skew (long (or (:max-epoch-skew opts) (:max-epoch-skew base-state) 15)))
                                (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                                (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                                (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap)))
                                (:pin-version opts) (assoc :pin-version (:pin-version opts))
                                (:auto-update-pointer opts) (assoc :auto-update-pointer (:auto-update-pointer opts))
                                (seq (:trusted-deploy-authorities opts)) (assoc :trusted-deploy-authorities (:trusted-deploy-authorities opts)))
            dac-rec (flags/reconcile-trusted-dac-anchors initial-state-raw
                                                         (:trusted-dac-anchors-spec opts)
                                                         (:trusted-dac-anchors bootstrap))
            initial-state (apply-jvm-startup-diagnostics! (:state dac-rec) identity @load-diags-atom)
            _ (doseq [ev (:stdout-events dac-rec)]
                (emit-json-line! out-writer ev (:events-out opts)))
            _ (let [sec-echo (flags/security-flags->wire
                              (flags/build-security-flags-echo
                               {:subnet-id (:subnet-id initial-state)
                                :subnet-id-overridden? (boolean (:subnet-id-overridden? initial-state false))
                                :trusted-dac-anchors (:trusted-dac-anchors initial-state)
                                :trusted-dac-anchors-provenance (:trusted-dac-anchors-provenance initial-state)
                                :trusted-deploy-authorities (:trusted-deploy-authorities initial-state)
                                :pin-version (:pin-version initial-state)
                                :auto-update-pointer (:auto-update-pointer initial-state)
                                :keystore-security-tier (:keystore-security-tier initial-state)}))]
                (binding [*out* *err*]
                  (println (json/write-str {"event" "startup-security-flags" "security_flags" sec-echo}))))
            _ (when (or (and reconciled-res (:reconciled? reconciled-res))
                        (seq (:effects dac-rec)))
                (try (save-light-state! state-file initial-state) (catch Exception _ nil)))
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
                  res (cond
                        (contains? #{"backup-put" "backup-restore" "identity-migrate"} verb)
                        (handle-jvm-stage-c-verb! verb cmd-map state-atom identity effective-relay-url opts)

                        (and (= eff-domain-verb "storage-put")
                             (not (boolean (or (get cmd-map "local_only")
                                               (get cmd-map "local-only")
                                               (:local-only cmd-map)))))
                        (let [sub-str (str (or (get cmd-map "subnet_id") (:subnet-id @state-atom) "global"))
                              prep (light-core/prepare-storage-put @state-atom cmd-map (:privkey-bytes identity) sub-str)]
                          (if-not (:ok? prep)
                            (dissoc prep :ok?)
                            (let [art-relay (or (get cmd-map "relay_url")
                                                (get cmd-map "relay-url")
                                                (:relay-url cmd-map)
                                                effective-relay-url)
                                  net-receipt (post-artifact-to-relay! art-relay "storage-put" (:publish-intent prep))
                                  committed (light-core/commit-storage-put-outcome @state-atom (:publish-intent prep) net-receipt)]
                              (assoc (dissoc committed :ok?)
                                     :net-envelopes (if (:ok? committed) (:net-envelopes prep) [])))))

                        :else
                        (let [read-blob-cmd? (contains? #{"storage-get" "artifact-get"} eff-domain-verb)
                              hydrated-from-cache? (and read-blob-cmd?
                                                        state-file
                                                        (some? (cache/resolve-read-target-cid @state-atom eff-domain-verb cmd-map)))
                              st-for-cmd (if hydrated-from-cache?
                                           (maybe-hydrate-state-for-read! (or (.getParent (io/file state-file)) ".") state-atom eff-domain-verb cmd-map)
                                           @state-atom)
                              cmd-res (light-core/handle-command st-for-cmd cmd-map (:privkey-bytes identity))]
                          (if hydrated-from-cache?
                            (assoc cmd-res :state (cache/prune-inline-hot-blobs (:state cmd-res) 0))
                            cmd-res)))
                  _ (when (:state res) (reset! state-atom (:state res)))
                  _ (when (and state-file (seq (:cache-effects res)))
                      (let [sd (or (.getParent (io/file state-file)) ".")]
                        (execute-cache-effects! sd (:cache-effects res) state-atom)))
                  out-write-res (maybe-write-artifact-out-file! eff-domain-verb cmd-map (:response res) state-atom)
                  res (if (:applied? out-write-res)
                        (assoc res :response (:response out-write-res) :state @state-atom)
                        res)
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
            loaded-state (load-light-state! state-file
                                            (cond-> {}
                                              (some? (:min-free-disk-bytes opts)) (assoc :min-free-disk-bytes (:min-free-disk-bytes opts))))
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
                                (try (save-light-state-async! state-file (:state res)) (catch Exception _ nil)))
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
