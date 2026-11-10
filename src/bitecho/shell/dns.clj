(ns bitecho.shell.dns
  "Authoritative UDP + Virtual-Thread TCP DNS boundary shell (`:53` or ephemeral `0`)
   backed by a unified Subnet runtime (`\"bitecho.org/infra\"`):
   - Single-authority generation-tagged lifecycle state via `bitecho.shell.infra/transition-shell` (Rule 4).
   - Evaluates queries purely via `bitecho.core.protocol.dns/resolve-query` (Gap G8 `2s`/`6s` liveness + fallback).
   - Hydrates any cold-evicted `dns/*` or `acme/challenge/*` Blobs from `bitecho.shell.blob-fs` prior to resolution.
   - Emits counted `:drop` / `:diagnose` events on every RRL rate-limit drop, `FORMERR` malformed packet,
     or socket failure (Rule 5)."
  (:require [bitecho.core.protocol.dns :as dns-proto]
            [bitecho.shell.infra :as infra]
            [clojure.string :as str])
  (:import [java.io BufferedInputStream BufferedOutputStream DataInputStream DataOutputStream]
           [java.net InetSocketAddress ServerSocket SocketException StandardSocketOptions]
           [java.nio ByteBuffer]
           [java.nio.channels AsynchronousCloseException ClosedByInterruptException ClosedChannelException DatagramChannel]
           [java.util.concurrent Executors ExecutorService]
           [java.util.concurrent.atomic AtomicBoolean]))

(defn- hydrate-cold-dns-blobs!
  "Ensures any pinned `dns/*` or `acme/challenge/*` Blobs in `subnet-runtime` are warm in RAM before pure resolution."
  [subnet-runtime now-ms]
  (when (and (map? subnet-runtime) (:subnet-atom subnet-runtime))
    (let [inst @(:subnet-atom subnet-runtime)
          sid (:subnet-id inst)
          ptrs (get-in inst [:data :pointers] {})
          blobs (get-in inst [:data :blobs :entries] {})]
      (doseq [[[psub ppath] ptr] ptrs
              :let [cid (:pointer/target ptr)]
              :when (and (= psub sid)
                         cid
                         (or (str/starts-with? ppath "dns/")
                             (str/starts-with? ppath "acme/challenge/"))
                         (nil? (get-in blobs [cid :bytes])))]
        (infra/resolve-path-blob! subnet-runtime ppath now-ms)))))

(defn- current-zone-state
  [subnet-runtime now-ms]
  (cond
    (and (map? subnet-runtime) (:subnet-atom subnet-runtime))
    (do
      (hydrate-cold-dns-blobs! subnet-runtime now-ms)
      @(:subnet-atom subnet-runtime))

    (instance? clojure.lang.IDeref subnet-runtime)
    @subnet-runtime

    :else
    subnet-runtime))

(defn start-dns-server!
  "Starts authoritative UDP and TCP DNS listeners backed by `subnet-runtime`.
   Returns server handle map with `:shell-atom`, `:udp-port`, `:tcp-port`, and `:stop-fn`."
  ([config subnet-runtime]
   (start-dns-server! config subnet-runtime {}))
  ([config subnet-runtime opts]
   (let [shell-atom (atom (infra/init-shell-state :dns-shell))
         _ (infra/apply-shell-event! shell-atom {:type :start})
         gen (:generation @shell-atom)
         bind-host (get-in config [:dns :bind-ip] "0.0.0.0")
         bind-port (int (get-in config [:dns :port] 53))
         running? (AtomicBoolean. true)
         limiter-atom (atom (dns-proto/init-limiter
                             {:capacity (double (or (:rrl-capacity opts) 40.0))
                              :refill-per-sec (double (or (:rrl-refill-per-sec opts) 20.0))}))]
     (try
       (let [udp-channel (DatagramChannel/open)
             _ (.setOption udp-channel StandardSocketOptions/SO_REUSEADDR true)
             _ (.bind udp-channel (InetSocketAddress. ^String bind-host bind-port))
             bound-udp-port (.getPort ^InetSocketAddress (.getLocalAddress udp-channel))
             tcp-socket (ServerSocket.)
             _ (.setReuseAddress tcp-socket true)
             _ (if (zero? bind-port)
                 (try
                   (.bind tcp-socket (InetSocketAddress. ^String bind-host bound-udp-port))
                   (catch Exception _
                     (.bind tcp-socket (InetSocketAddress. ^String bind-host 0))))
                 (.bind tcp-socket (InetSocketAddress. ^String bind-host bind-port)))
             bound-tcp-port (.getLocalPort tcp-socket)
             tcp-executor (Executors/newVirtualThreadPerTaskExecutor)
             close-resources! (fn [{:keys [udp tcp exec]}]
                                (.set running? false)
                                (when udp (try (.close ^DatagramChannel udp) (catch Exception _ nil)))
                                (when tcp (try (.close ^ServerSocket tcp) (catch Exception _ nil)))
                                (when exec (try (.shutdownNow ^ExecutorService exec) (catch Exception _ nil))))]

         ;; UDP worker loop on virtual thread
         (-> (Thread/ofVirtual)
             (.name "bitecho-dns-udp")
             (.start
              (fn []
                (let [buf (ByteBuffer/allocate 4096)]
                  (while (.get running?)
                    (try
                      (.clear buf)
                      (when-let [client-addr (.receive udp-channel buf)]
                        (let [len (.position buf)]
                          (.flip buf)
                          (let [req-bytes (byte-array len)
                                _ (.get buf req-bytes)
                                client-ip (if (instance? InetSocketAddress client-addr)
                                            (.getHostAddress (.getAddress ^InetSocketAddress client-addr))
                                            (str client-addr))
                                subnet-key (dns-proto/ip->subnet-key client-ip)
                                now-ms (System/currentTimeMillis)
                                allowed-box (atom false)
                                _ (swap! limiter-atom
                                         (fn [st]
                                           (let [r (dns-proto/check-and-consume st subnet-key 1.0 now-ms)]
                                             (reset! allowed-box (:allowed? r))
                                             (:state r))))]
                            (if-not @allowed-box
                              (infra/apply-shell-event! shell-atom {:type :drop :reason :dns-rrl-rate-limited :detail subnet-key})
                              (try
                                (let [query-pkt (dns-proto/decode-packet req-bytes)
                                      st (current-zone-state subnet-runtime now-ms)
                                      resp-pkt (dns-proto/resolve-query config st query-pkt now-ms)
                                      resp-bytes (dns-proto/encode-packet resp-pkt {:max-bytes 512})]
                                  (.send udp-channel (ByteBuffer/wrap resp-bytes) client-addr))
                                (catch Exception e
                                  (infra/apply-shell-event! shell-atom {:type :drop :reason :dns-udp-formerr :detail (.getMessage e)})
                                  (when-let [id (:id (ex-data e))]
                                    (try
                                      (let [err-resp (dns-proto/encode-packet {:id id
                                                                               :qr? true
                                                                               :opcode 0
                                                                               :aa? false
                                                                               :tc? false
                                                                               :rd? false
                                                                               :ra? false
                                                                               :rcode :formerr
                                                                               :questions []})]
                                        (.send udp-channel (ByteBuffer/wrap err-resp) client-addr))
                                      (catch Exception _ nil)))))))))
                      (catch ClosedChannelException _ (.set running? false))
                      (catch ClosedByInterruptException _ (.set running? false))
                      (catch AsynchronousCloseException _ (.set running? false))
                      (catch SocketException _ (.set running? false))
                      (catch Exception e
                        (when (.get running?)
                          (infra/apply-shell-event! shell-atom {:type :diagnose :reason :dns-udp-loop-error :detail (.getMessage e)})))))))))

         ;; TCP accept loop on virtual thread
         (-> (Thread/ofVirtual)
             (.name "bitecho-dns-tcp-accept")
             (.start
              (fn []
                (while (.get running?)
                  (try
                    (let [client (.accept tcp-socket)]
                      (.submit tcp-executor
                               ^Runnable
                               (fn []
                                 (try
                                   (.setSoTimeout client 5000)
                                   (with-open [in (DataInputStream. (BufferedInputStream. (.getInputStream client)))
                                               out (DataOutputStream. (BufferedOutputStream. (.getOutputStream client)))]
                                     (let [len (.readUnsignedShort in)
                                           buf (byte-array len)
                                           _ (.readFully in buf)
                                           now-ms (System/currentTimeMillis)
                                           query-pkt (dns-proto/decode-packet buf)
                                           st (current-zone-state subnet-runtime now-ms)
                                           resp-pkt (dns-proto/resolve-query config st query-pkt now-ms)
                                           resp-bytes (dns-proto/encode-packet resp-pkt {:max-bytes 65535})]
                                       (.writeShort out (alength resp-bytes))
                                       (.write out resp-bytes 0 (alength resp-bytes))
                                       (.flush out)))
                                   (catch Exception e
                                     (when (.get running?)
                                       (infra/apply-shell-event! shell-atom {:type :drop :reason :dns-tcp-conn-error :detail (.getMessage e)})))
                                   (finally
                                     (try (.close client) (catch Exception _ nil)))))))
                    (catch SocketException _ (.set running? false))
                    (catch Exception e
                      (when (.get running?)
                        (infra/apply-shell-event! shell-atom {:type :diagnose :reason :dns-tcp-accept-error :detail (.getMessage e)}))))))))

         (let [resources {:udp udp-channel :tcp tcp-socket :exec tcp-executor}]
           (infra/apply-shell-event! shell-atom {:type :started :generation gen :resources resources})
           {:shell-atom shell-atom
            :udp-channel udp-channel
            :udp-port bound-udp-port
            :tcp-socket tcp-socket
            :tcp-port bound-tcp-port
            :limiter-atom limiter-atom
            :running? running?
            :stop-fn (fn []
                       (infra/apply-shell-event! shell-atom {:type :stop} close-resources!))}))
       (catch Exception e
         (infra/apply-shell-event! shell-atom {:type :failed :generation gen :error :dns-bind-failed :detail (.getMessage e)})
         (throw e))))))

(defn stop-dns-server!
  "Stops the DNS server and transitions its lifecycle state to `:stopped`."
  [server]
  (when-let [stop-fn (:stop-fn server)]
    (stop-fn))
  server)

(defn dns-status
  "Returns generation-tagged DNS shell lifecycle & diagnostic counters."
  [server]
  (infra/shell-status-summary @(:shell-atom server)))
