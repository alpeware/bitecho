(ns bitecho.shell.smtp
  "Inbound Virtual-Thread TCP `:25` + `STARTTLS` SMTP boundary shell:
   - Single-authority generation-tagged lifecycle state via `bitecho.shell.infra/transition-shell` (Rule 4).
   - Executes pure RFC 5321 protocol state transitions via `bitecho.core.protocol.smtp`.
   - On `:deliver-mail`, prepends RFC 5321 `Received:` trace header, hashes the `.eml` into a
     `\"message/rfc822\"` `Blob` in `bitecho.shell.blob-fs`, and publishes/replicates a signed
     `\"mail/<rcpt>/<ts>-<cid8>\"` `Pointer` into the unified Subnet runtime (`\"bitecho.org/infra\"`).
   - Records every relay denial, oversize rejection, rate-limit drop, or socket error in counted
     shell diagnostics (Rule 5)."
  (:require [bitecho.core.data :as data]
            [bitecho.core.protocol.dns :as dns-proto]
            [bitecho.core.protocol.smtp :as smtp-proto]
            [bitecho.fressian :as fressian]
            [bitecho.shell.infra :as infra]
            [clojure.string :as str])
  (:import [java.io BufferedReader BufferedWriter InputStreamReader OutputStreamWriter]
           [java.net InetSocketAddress ServerSocket Socket SocketException SocketTimeoutException]
           [java.nio.charset StandardCharsets]
           [java.text SimpleDateFormat]
           [java.util Date Locale UUID]
           [java.util.concurrent Executors ExecutorService Semaphore]
           [java.util.concurrent.atomic AtomicBoolean AtomicLong]
           [javax.net.ssl SSLContext SSLSocket]))

(defn read-bounded-line
  "Reads a single line up to `max-line-chars` (default `4096`), stripping `\r\n`."
  ([^BufferedReader reader]
   (read-bounded-line reader 4096))
  ([^BufferedReader reader ^long max-line-chars]
   (let [sb (StringBuilder.)]
     (loop []
       (let [ch (.read reader)]
         (cond
           (= ch -1)
           (if (pos? (.length sb)) (.toString sb) nil)

           (= ch (int \newline))
           (let [s (.toString sb)]
             (if (str/ends-with? s "\r")
               (subs s 0 (dec (count s)))
               s))

           (>= (.length sb) max-line-chars)
           (throw (ex-info "SMTP line length limit exceeded" {:type :smtp/line-too-long :limit max-line-chars}))

           :else
           (do (.append sb (char ch))
               (recur))))))))

(defn- build-received-eml
  [{:keys [id domain remote-ip helo received-at raw-eml]}]
  (let [sdf (SimpleDateFormat. "EEE, d MMM yyyy HH:mm:ss Z" Locale/US)
        date-str (.format sdf (Date. (long received-at)))
        hdr (str "Received: from " (or helo "unknown") " ([" (or remote-ip "127.0.0.1") "])\r\n"
                 "        by " (or domain "localhost") " with ESMTP\r\n"
                 "        id " id "; " date-str "\r\n")]
    (if (str/starts-with? (str/trim (or raw-eml "")) "Received:")
      raw-eml
      (str hdr raw-eml))))

(defn- deliver-mail-to-subnet!
  [subnet-runtime domain remote-ip deliver-eff ^AtomicLong seq-counter]
  (let [received-at (System/currentTimeMillis)
        msg-id (str (UUID/randomUUID))
        full-eml (build-received-eml {:id msg-id
                                      :domain domain
                                      :remote-ip remote-ip
                                      :helo (:helo deliver-eff)
                                      :received-at received-at
                                      :raw-eml (:data-str deliver-eff)})
        blob (data/make-blob (fressian/utf8->bytes full-eml) "message/rfc822")
        cid8 (subs (:blob/cid blob) 0 8)
        auth-pub (:default-sender subnet-runtime)
        auth-priv (:node-privkey subnet-runtime)]
    (when (and subnet-runtime auth-pub auth-priv)
      (doseq [rcpt (:to deliver-eff)]
        (let [path (str "mail/" rcpt "/" received-at "-" cid8)
              s (.incrementAndGet seq-counter)]
          (infra/publish-blob-and-pointer! subnet-runtime
                                           {:blob blob
                                            :path path
                                            :seq s
                                            :authority-pubkey auth-pub
                                            :authority-privkey auth-priv
                                            :now-ms received-at}))))
    {:id msg-id :cid (:blob/cid blob) :received-at received-at}))

(defn- run-session-loop!
  [^Socket initial-socket config tls-manager subnet-runtime shell-atom ^AtomicLong seq-counter sock-timeout]
  (let [domain (get config :domain "localhost")
        smtp-cfg (get config :smtp {})
        max-bytes (long (get smtp-cfg :max-message-bytes 131072))
        allowed (get smtp-cfg :allowed-recipients #{})
        remote-ip (or (some-> (.getInetAddress initial-socket) (.getHostAddress)) "127.0.0.1")
        init-in (BufferedReader. (InputStreamReader. (.getInputStream initial-socket) StandardCharsets/UTF_8))
        init-out (BufferedWriter. (OutputStreamWriter. (.getOutputStream initial-socket) StandardCharsets/UTF_8))
        greet (smtp-proto/greeting (smtp-proto/init-session {:domain domain
                                                             :max-message-bytes max-bytes
                                                             :allowed-recipients allowed
                                                             :tls-active? (instance? SSLSocket initial-socket)}))]
    (doseq [resp (:responses greet)]
      (.write init-out (str resp "\r\n")))
    (.flush init-out)
    (loop [cur-sock initial-socket
           in init-in
           out init-out
           st (:state greet)]
      (let [line (try
                   (read-bounded-line in 4096)
                   (catch SocketTimeoutException _
                     (infra/apply-shell-event! shell-atom {:type :drop :reason :smtp-read-timeout})
                     nil)
                   (catch Exception e
                     (infra/apply-shell-event! shell-atom {:type :drop :reason :smtp-read-error :detail (.getMessage e)})
                     nil))]
        (when line
          (let [res (smtp-proto/handle-smtp-line st line)
                new-st (:state res)
                effects (:effects res)]
            (doseq [eff effects]
              (when (= :diagnose (:effect eff))
                (infra/apply-shell-event! shell-atom {:type :drop :reason (:reason eff)})))
            (doseq [resp (:responses res)]
              (.write out (str resp "\r\n")))
            (.flush out)
            (when-let [deliv (first (filter #(= :deliver-mail (:type %)) effects))]
              (deliver-mail-to-subnet! subnet-runtime domain remote-ip deliv seq-counter))
            (cond
              (some #(= :close (:type %)) effects)
              nil

              (some #(= :starttls (:type %)) effects)
              (let [^SSLContext ssl-ctx @(:ssl-context-atom tls-manager)
                    ssl-sock ^SSLSocket (.createSocket (.getSocketFactory ssl-ctx)
                                                       cur-sock remote-ip (.getPort cur-sock) true)]
                (.setUseClientMode ssl-sock false)
                (.setEnabledProtocols ssl-sock (into-array String ["TLSv1.3" "TLSv1.2"]))
                (.setSoTimeout ssl-sock (int sock-timeout))
                (.startHandshake ssl-sock)
                (recur ssl-sock
                       (BufferedReader. (InputStreamReader. (.getInputStream ssl-sock) StandardCharsets/UTF_8))
                       (BufferedWriter. (OutputStreamWriter. (.getOutputStream ssl-sock) StandardCharsets/UTF_8))
                       new-st))

              :else
              (recur cur-sock in out new-st))))))))

(defn start-smtp-server!
  "Starts Virtual-Thread TCP SMTP server (`:25` or ephemeral `0`) backed by `subnet-runtime`."
  [config tls-manager subnet-runtime]
  (let [shell-atom (atom (infra/init-shell-state :smtp-shell))
        _ (infra/apply-shell-event! shell-atom {:type :start})
        gen (:generation @shell-atom)
        smtp-cfg (get config :smtp {})
        bind-ip (get smtp-cfg :bind-ip "0.0.0.0")
        port (int (get smtp-cfg :port 25))
        sock-timeout (int (get smtp-cfg :socket-timeout-ms 30000))
        running? (AtomicBoolean. true)
        seq-counter (AtomicLong. 0)
        semaphore (Semaphore. 10)
        limiter-atom (atom (dns-proto/init-limiter {:capacity 20.0 :refill-per-sec 5.0}))
        vthread-executor (Executors/newVirtualThreadPerTaskExecutor)]
    (try
      (let [server-socket (doto (ServerSocket.)
                            (.setReuseAddress true)
                            (.bind (InetSocketAddress. ^String bind-ip port)))
            bound-port (.getLocalPort server-socket)
            close-resources! (fn [{:keys [sock exec]}]
                               (.set running? false)
                               (when sock (try (.close ^ServerSocket sock) (catch Exception _ nil)))
                               (when exec (try (.shutdownNow ^ExecutorService exec) (catch Exception _ nil))))]
        (.submit vthread-executor
                 ^Runnable
                 (fn []
                   (while (.get running?)
                     (try
                       (let [client (.accept server-socket)]
                         (.submit vthread-executor
                                  ^Runnable
                                  (fn []
                                    (try
                                      (.setSoTimeout client sock-timeout)
                                      (if-not (.tryAcquire semaphore)
                                        (do
                                          (infra/apply-shell-event! shell-atom {:type :drop :reason :smtp-max-sessions-busy})
                                          (with-open [w (BufferedWriter. (OutputStreamWriter. (.getOutputStream client) StandardCharsets/UTF_8))]
                                            (.write w "421 4.3.2 Server too busy\r\n")
                                            (.flush w)))
                                        (try
                                          (let [rip (or (some-> (.getInetAddress client) (.getHostAddress)) "127.0.0.1")
                                                skey (dns-proto/ip->subnet-key rip)
                                                now-ms (System/currentTimeMillis)
                                                ok-box (atom false)
                                                _ (swap! limiter-atom
                                                         (fn [st]
                                                           (let [r (dns-proto/check-and-consume st skey 1.0 now-ms)]
                                                             (reset! ok-box (:allowed? r))
                                                             (:state r))))]
                                            (if-not @ok-box
                                              (do
                                                (infra/apply-shell-event! shell-atom {:type :drop :reason :smtp-rate-limited :detail skey})
                                                (with-open [w (BufferedWriter. (OutputStreamWriter. (.getOutputStream client) StandardCharsets/UTF_8))]
                                                  (.write w "421 4.7.0 Too many connections\r\n")
                                                  (.flush w)))
                                              (run-session-loop! client config tls-manager subnet-runtime shell-atom seq-counter sock-timeout)))
                                          (finally
                                            (.release semaphore))))
                                      (catch Exception e
                                        (when (.get running?)
                                          (infra/apply-shell-event! shell-atom {:type :drop :reason :smtp-session-error :detail (.getMessage e)})))
                                      (finally
                                        (try (.close client) (catch Exception _ nil)))))))
                       (catch SocketException _ (.set running? false))
                       (catch Exception e
                         (when (.get running?)
                           (infra/apply-shell-event! shell-atom {:type :diagnose :reason :smtp-accept-error :detail (.getMessage e)})))))))
        (infra/apply-shell-event! shell-atom {:type :started :generation gen :resources {:sock server-socket :exec vthread-executor}})
        {:shell-atom shell-atom
         :server-socket server-socket
         :port bound-port
         :running? running?
         :stop-fn (fn []
                    (infra/apply-shell-event! shell-atom {:type :stop} close-resources!))})
      (catch Exception e
        (infra/apply-shell-event! shell-atom {:type :failed :generation gen :error :smtp-bind-failed :detail (.getMessage e)})
        (throw e)))))

(defn stop-smtp-server!
  "Stops the SMTP server and transitions lifecycle state to `:stopped`."
  [server]
  (when-let [stop-fn (:stop-fn server)]
    (stop-fn))
  server)

(defn smtp-status
  "Returns generation-tagged SMTP shell lifecycle & diagnostic counters."
  [server]
  (infra/shell-status-summary @(:shell-atom server)))
