(ns bitecho.shell.upnp
  "UPnP Internet Gateway Device (`IGD` `WANIPConnection` / `WANPPPConnection`) port-mapping shell:
   - Pure Sans-IO SSDP `M-SEARCH` request/response & UPnP IGD XML/SOAP builders and parsers
     (ported cleanly from `jaq.http.xrf.upnp`).
   - Thin bounded-timeout UDP (`239.255.255.250:1900` default) & HTTP SOAP boundary shell
     (`discover-gateway!`, `get-external-ip!`, `add-port-mapping!`, `delete-port-mapping!`)
     emitting counted `:diagnose` effects on timeout, CGNAT, or SOAP faults (Rule 5)."
  (:require [bitecho.core.protocol.dns :as dns-proto]
            [clojure.string :as str]
            [clojure.xml :as xml])
  (:import [java.io ByteArrayInputStream]
           [java.net DatagramPacket DatagramSocket InetSocketAddress Socket SocketTimeoutException URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.time Duration]))

(def ^{:doc "Standard UPnP SSDP IPv4 multicast address."} default-ssdp-host "239.255.255.250")
(def ^{:doc "Standard UPnP SSDP UDP port."} default-ssdp-port 1900)

;; =============================================================================
;; 1. Pure Sans-IO SSDP & UPnP SOAP XML Builders / Parsers
;; =============================================================================

(defn build-msearch-request
  "Builds an RFC-compliant UPnP SSDP `M-SEARCH` datagram string."
  ([search-target]
   (build-msearch-request default-ssdp-host default-ssdp-port search-target))
  ([host port search-target]
   (str "M-SEARCH * HTTP/1.1\r\n"
        "HOST: " host ":" port "\r\n"
        "ST: " (or search-target "urn:schemas-upnp-org:service:WANIPConnection:1") "\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "USER-AGENT: bitecho/1.0\r\n"
        "MX: 2\r\n\r\n")))

(defn parse-ssdp-response
  "Purely parses an HTTP-over-UDP SSDP `200 OK` datagram into lowercase headers + `:location`, `:st`, `:usn`."
  [raw-text]
  (when (and (string? raw-text) (not (str/blank? raw-text)))
    (let [lines (str/split raw-text #"\r?\n")
          status-line (first lines)]
      (when (and status-line (re-find #"(?i)^HTTP/1\.[01]\s+200\b" (str/trim status-line)))
        (let [hdrs (reduce (fn [acc line]
                             (if-let [idx (str/index-of line ":")]
                               (let [k (str/lower-case (str/trim (subs line 0 idx)))
                                     v (str/trim (subs line (inc idx)))]
                                 (assoc acc k v))
                               acc))
                           {}
                           (rest lines))]
          (when-let [loc (get hdrs "location")]
            {:headers hdrs
             :location loc
             :st (get hdrs "st")
             :usn (get hdrs "usn")}))))))

(defn- base-origin
  [^String location-url]
  (let [u (URI/create location-url)
        port (.getPort u)]
    (str (.getScheme u) "://" (.getHost u) (when (pos? port) (str ":" port)))))

(defn- resolve-control-url
  [^String base ^String control-url]
  (cond
    (or (str/starts-with? control-url "http://")
        (str/starts-with? control-url "https://"))
    control-url

    (str/starts-with? control-url "/")
    (str (str/replace base #"/$" "") control-url)

    :else
    (str (str/replace base #"/$" "") "/" control-url)))

(defn- local-tag-name
  [tag]
  (let [s (if (keyword? tag) (name tag) (str tag))]
    (last (str/split s #":"))))

(defn parse-igd-services-xml
  "Purely parses a UPnP root device XML description and extracts the first `WANIPConnection`
   or `WANPPPConnection` service `{:service-type ... :control-url ...}`."
  [location-url xml-str]
  (try
    (let [doc (xml/parse (ByteArrayInputStream. (.getBytes ^String xml-str StandardCharsets/UTF_8)))
          url-base (or (->> (xml-seq doc)
                            (filter #(= "URLBase" (local-tag-name (:tag %))))
                            (keep #(first (:content %)))
                            first)
                       (base-origin location-url))
          services (->> (xml-seq doc)
                        (filter #(= "service" (local-tag-name (:tag %))))
                        (map (fn [svc]
                               (into {}
                                     (keep (fn [child]
                                             (when (map? child)
                                               [(keyword (local-tag-name (:tag child)))
                                                (str/trim (str (first (:content child))))])))
                                     (:content svc)))))
          wan-svc (first (filter (fn [{:keys [serviceType]}]
                                   (and serviceType
                                        (re-matches #"(?i).*:(wanipconnection|wanpppconnection):.*" serviceType)))
                                 services))]
      (when (and wan-svc (:controlURL wan-svc))
        {:location location-url
         :service-type (:serviceType wan-svc)
         :control-url (resolve-control-url url-base (:controlURL wan-svc))}))
    (catch Exception _ nil)))

(defn- escape-xml
  [s]
  (-> (str (or s ""))
      (str/replace "&" "&amp;")
      (str/replace "<" "&lt;")
      (str/replace ">" "&gt;")
      (str/replace "\"" "&quot;")))

(defn build-soap-envelope
  "Builds a UPnP SOAP 1.1 XML envelope for `service-type`, `action`, and ordered `[arg-name arg-val]` pairs."
  [service-type action arg-pairs]
  (let [args-xml (apply str
                        (map (fn [[k v]]
                               (let [kn (if (keyword? k) (name k) (str k))]
                                 (str "<" kn ">" (escape-xml v) "</" kn ">")))
                             arg-pairs))]
    (str "<?xml version=\"1.0\"?>"
         "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
         "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
         "<s:Body>"
         "<u:" action " xmlns:u=\"" service-type "\">"
         args-xml
         "</u:" action ">"
         "</s:Body>"
         "</s:Envelope>")))

(defn parse-xml-tag-text
  "Purely extracts the trimmed text of the first XML element matching `local-name`."
  [xml-str local-name]
  (try
    (let [doc (xml/parse (ByteArrayInputStream. (.getBytes ^String xml-str StandardCharsets/UTF_8)))]
      (->> (xml-seq doc)
           (filter #(and (map? %) (= local-name (local-tag-name (:tag %)))))
           (keep #(some-> (:content %) first str str/trim))
           (remove str/blank?)
           first))
    (catch Exception _ nil)))

(defn classify-external-ip
  "Purely classifies an IPv4 string returned by UPnP `GetExternalIPAddress`:
   `:public`, `:private` (RFC 1918), `:cgnat` (RFC 6598 `100.64.0.0/10`), `:loopback`, `:link-local`, or `:invalid`."
  [ip-str]
  (if-let [octets (dns-proto/parse-ipv4 ip-str)]
    (let [[a b _c _d] octets]
      (cond
        (or (zero? a) (>= a 224)) :invalid
        (= a 127) :loopback
        (= a 10) :private
        (and (= a 172) (<= 16 b 31)) :private
        (and (= a 192) (= b 168)) :private
        (and (= a 169) (= b 254)) :link-local
        (and (= a 100) (<= 64 b 127)) :cgnat
        :else :public))
    :invalid))

(defn public-ipv4?
  "Returns true iff `ip-str` is a routable public IPv4 address."
  [ip-str]
  (= :public (classify-external-ip ip-str)))

(defn build-ingress-port-mappings
  "Purely constructs the canonical ingress port-mapping plan (`UDP 53`, `TCP 53`, `TCP 80`, `TCP 443`)
   for a local 1-node `bitecho infra-node` instance."
  [{:keys [internal-client dns-udp-port dns-tcp-port http-port https-port lease-seconds description-prefix]}]
  (let [client (or internal-client "127.0.0.1")
        lease (int (or lease-seconds 0))
        prefix (or description-prefix "bitecho-ingress")
        u53 (int (or dns-udp-port 53))
        t53 (int (or dns-tcp-port dns-udp-port 53))
        h80 (int (or http-port 80))
        h443 (int (or https-port 443))]
    [{:protocol "UDP"
      :external-port 53
      :internal-port u53
      :internal-client client
      :lease-seconds lease
      :description (str prefix "-dns-udp")}
     {:protocol "TCP"
      :external-port 53
      :internal-port t53
      :internal-client client
      :lease-seconds lease
      :description (str prefix "-dns-tcp")}
     {:protocol "TCP"
      :external-port 80
      :internal-port h80
      :internal-client client
      :lease-seconds lease
      :description (str prefix "-http")}
     {:protocol "TCP"
      :external-port 443
      :internal-port h443
      :internal-client client
      :lease-seconds lease
      :description (str prefix "-https")}]))

;; =============================================================================
;; 2. Bounded-Timeout UDP SSDP & HTTP SOAP Boundary Shell
;; =============================================================================

(defn- execute-soap-action!
  [gateway action arg-pairs opts]
  (let [timeout-ms (long (or (:timeout-ms opts) 3000))
        service-type (:service-type gateway)
        control-url (:control-url gateway)]
    (if-not (and service-type control-url)
      {:ok? false
       :error :invalid-gateway
       :effects [{:effect :diagnose :reason :upnp-invalid-gateway :action action}]}
      (try
        (let [body (build-soap-envelope service-type action arg-pairs)
              client (-> (HttpClient/newBuilder)
                         (.connectTimeout (Duration/ofMillis timeout-ms))
                         (.build))
              req (-> (HttpRequest/newBuilder (URI/create control-url))
                      (.timeout (Duration/ofMillis timeout-ms))
                      (.header "Content-Type" "text/xml; charset=\"utf-8\"")
                      (.header "SOAPAction" (str "\"" service-type "#" action "\""))
                      (.POST (HttpRequest$BodyPublishers/ofString body StandardCharsets/UTF_8))
                      (.build))
              resp (.send client req (HttpResponse$BodyHandlers/ofString StandardCharsets/UTF_8))
              status (.statusCode resp)
              resp-body (.body resp)]
          (if (<= 200 status 299)
            {:ok? true :status status :body resp-body :effects []}
            (let [fault-code (parse-xml-tag-text resp-body "errorCode")
                  fault (or (parse-xml-tag-text resp-body "errorDescription")
                            (parse-xml-tag-text resp-body "faultstring")
                            (str "HTTP " status))]
              {:ok? false
               :error :upnp-soap-fault
               :status status
               :fault-code fault-code
               :fault fault
               :body resp-body
               :effects [{:effect :diagnose
                          :reason :upnp-soap-fault
                          :action action
                          :fault-code fault-code
                          :fault fault}]})))
        (catch Exception e
          {:ok? false
           :error :upnp-io-error
           :effects [{:effect :diagnose :reason :upnp-soap-io-error :action action :message (.getMessage e)}]})))))

(defn discover-gateway!
  "Discovers a UPnP `WANIPConnection` / `WANPPPConnection` gateway on the LAN via SSDP `M-SEARCH`
   and fetches its XML service description. Never throws; emits counted `:diagnose` on timeout/failure."
  ([] (discover-gateway! {}))
  ([opts]
   (let [ssdp-host (or (:ssdp-host opts) default-ssdp-host)
         ssdp-port (int (or (:ssdp-port opts) default-ssdp-port))
         timeout-ms (int (or (:timeout-ms opts) 2000))
         targets (or (:search-targets opts)
                     ["urn:schemas-upnp-org:service:WANIPConnection:1"
                      "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
                      "ssdp:all"])]
     (try
       (with-open [sock (DatagramSocket.)]
         (.setSoTimeout sock timeout-ms)
         (doseq [st targets]
           (let [bs (.getBytes ^String (build-msearch-request ssdp-host ssdp-port st) StandardCharsets/UTF_8)
                 pkt (DatagramPacket. bs (alength bs) (InetSocketAddress. ^String ssdp-host ssdp-port))]
             (.send sock pkt)))
         (let [deadline (+ (System/currentTimeMillis) timeout-ms)
               buf (byte-array 4096)
               http-client (-> (HttpClient/newBuilder)
                               (.connectTimeout (Duration/ofMillis timeout-ms))
                               (.build))]
           (loop [seen-locs #{}]
             (let [rem (- deadline (System/currentTimeMillis))]
               (if (<= rem 0)
                 {:ok? false
                  :error :upnp-discovery-timeout
                  :effects [{:effect :diagnose :reason :upnp-discovery-timeout}]}
                 (do
                   (.setSoTimeout sock (int (max 25 rem)))
                   (let [rpkt (DatagramPacket. buf (alength buf))
                         got? (try (.receive sock rpkt) true
                                   (catch SocketTimeoutException _ false))]
                     (if-not got?
                       {:ok? false
                        :error :upnp-discovery-timeout
                        :effects [{:effect :diagnose :reason :upnp-discovery-timeout}]}
                       (let [raw (String. buf 0 (.getLength rpkt) StandardCharsets/UTF_8)
                             parsed (parse-ssdp-response raw)
                             loc (:location parsed)]
                         (if (and loc (not (contains? seen-locs loc)))
                           (let [gw (try
                                      (let [req (-> (HttpRequest/newBuilder (URI/create loc))
                                                    (.timeout (Duration/ofMillis timeout-ms))
                                                    (.GET)
                                                    (.build))
                                            resp (.send http-client req (HttpResponse$BodyHandlers/ofString StandardCharsets/UTF_8))]
                                        (when (<= 200 (.statusCode resp) 299)
                                          (parse-igd-services-xml loc (.body resp))))
                                      (catch Exception _ nil))]
                             (if gw
                               {:ok? true :gateway gw :effects []}
                               (recur (conj seen-locs loc))))
                           (recur seen-locs)))))))))))
       (catch Exception e
         {:ok? false
          :error :upnp-discovery-failed
          :effects [{:effect :diagnose :reason :upnp-discovery-failed :message (.getMessage e)}]})))))

(defn get-external-ip!
  "Queries `GetExternalIPAddress` on `gateway`."
  ([gateway] (get-external-ip! gateway {}))
  ([gateway opts]
   (let [res (execute-soap-action! gateway "GetExternalIPAddress" [] opts)]
     (if-not (:ok? res)
       res
       (if-let [ip (parse-xml-tag-text (:body res) "NewExternalIPAddress")]
         {:ok? true :external-ip ip :effects []}
         {:ok? false
          :error :missing-external-ip
          :effects [{:effect :diagnose :reason :upnp-missing-external-ip}]})))))

(defn- only-permanent-leases-fault?
  "Returns true iff a failed `AddPortMapping` response indicates UPnP fault `725` (`OnlyPermanentLeasesSupported`)."
  [{:keys [error fault-code fault body]}]
  (and (= :upnp-soap-fault error)
       (or (= "725" (some-> fault-code str str/trim))
           (some-> fault str str/lower-case (str/includes? "725"))
           (some-> fault str str/lower-case (str/includes? "onlypermanentleasessupported"))
           (some-> body str str/lower-case (str/includes? "onlypermanentleasessupported")))))

(defn add-port-mapping!
  "Executes `AddPortMapping` on `gateway`. Automatically retries once with `NewLeaseDuration=0`
   (permanent lease) iff the router rejects a non-zero lease duration with UPnP fault `725`
   (`OnlyPermanentLeasesSupported`)."
  [gateway {:keys [remote-host external-port protocol internal-port internal-client description lease-seconds] :as opts}]
  (let [lease (int (if (some? lease-seconds) lease-seconds 3600))
        attempt! (fn [dur]
                   (execute-soap-action!
                    gateway
                    "AddPortMapping"
                    [["NewRemoteHost" (or remote-host "")]
                     ["NewExternalPort" (int external-port)]
                     ["NewProtocol" (str/upper-case (or protocol "TCP"))]
                     ["NewInternalPort" (int (or internal-port external-port))]
                     ["NewInternalClient" (str internal-client)]
                     ["NewEnabled" "1"]
                     ["NewPortMappingDescription" (or description "bitecho")]
                     ["NewLeaseDuration" (int dur)]]
                    opts))
        res (attempt! lease)]
    (if (or (:ok? res) (zero? lease) (not (only-permanent-leases-fault? res)))
      res
      (let [retry-res (attempt! 0)]
        (if (:ok? retry-res)
          (assoc retry-res :retried-permanent-lease? true)
          res)))))

(defn delete-port-mapping!
  "Executes `DeletePortMapping` on `gateway`."
  [gateway {:keys [remote-host external-port protocol] :as opts}]
  (execute-soap-action!
   gateway
   "DeletePortMapping"
   [["NewRemoteHost" (or remote-host "")]
    ["NewExternalPort" (int external-port)]
    ["NewProtocol" (str/upper-case (or protocol "TCP"))]]
   opts))

(defn ensure-ingress-port-mappings!
  "Discovers a UPnP gateway, queries the external IP, and maps all configured ingress ports
   (`UDP 53`, `TCP 53`, `TCP 80`, `TCP 443`).
   Supports best-effort UPnP with explicit `:manual-port-forward? true` + `:manual-external-ip`
   fallback when the router lacks UPnP (emitting a counted `:diagnose` effect per Rule 5)."
  [opts]
  (let [mappings (or (:mappings opts) (build-ingress-port-mappings opts))
        disc (discover-gateway! opts)]
    (if (:ok? disc)
      (let [gw (:gateway disc)
            ext-res (get-external-ip! gw opts)
            ext-ip (or (:external-ip ext-res) (:manual-external-ip opts))
            ip-class (classify-external-ip ext-ip)
            map-results (mapv #(assoc (add-port-mapping! gw (merge opts %))
                                      :mapping %)
                              mappings)
            failed (filterv #(not (:ok? %)) map-results)]
        (if (and (empty? failed) (string? ext-ip) (not (str/blank? ext-ip)))
          {:ok? true
           :mode :upnp
           :gateway gw
           :external-ip ext-ip
           :ip-classification ip-class
           :mappings mappings
           :effects (if (= :cgnat ip-class)
                      [{:effect :diagnose :reason :upnp-cgnat-detected :external-ip ext-ip}]
                      [])}
          (if (and (:manual-port-forward? opts) (string? (:manual-external-ip opts)))
            {:ok? true
             :mode :manual-fallback
             :external-ip (:manual-external-ip opts)
             :mappings mappings
             :effects [{:effect :diagnose
                        :reason :upnp-manual-fallback
                        :external-ip (:manual-external-ip opts)}]}
            {:ok? false
             :error :upnp-port-mapping-failed
             :failed-mappings failed
             :effects (into (vec (:effects ext-res))
                            (mapcat :effects failed))})))
      (if (and (:manual-port-forward? opts) (string? (:manual-external-ip opts)))
        {:ok? true
         :mode :manual-fallback
         :external-ip (:manual-external-ip opts)
         :mappings mappings
         :effects (conj (vec (:effects disc))
                        {:effect :diagnose
                         :reason :upnp-manual-fallback
                         :external-ip (:manual-external-ip opts)})}
        disc))))

(defn teardown-ingress-port-mappings!
  "Deletes previously registered UPnP port mappings on `gateway`."
  [gateway mappings opts]
  (when gateway
    (mapv #(delete-port-mapping! gateway (merge opts %)) mappings)))

(defn default-reachability-probe!
  "Probes external reachability of `ip:port` over `protocol` (`\"TCP\"` socket connect or
   `\"UDP\"` RFC 1035 DNS query/response)."
  [ip protocol port {:keys [timeout-ms domain]}]
  (let [t-ms (int (or timeout-ms 2500))
        proto (str/upper-case (or protocol "TCP"))]
    (try
      (if (= proto "UDP")
        (with-open [sock (DatagramSocket.)]
          (.setSoTimeout sock t-ms)
          (let [qname (or domain "bitecho.org")
                q-bytes (dns-proto/encode-packet {:id 0x4242 :rd? false :questions [{:qname qname :qtype :SOA :qclass :IN}]})
                pkt (DatagramPacket. q-bytes (alength q-bytes) (InetSocketAddress. ^String ip (int port)))
                _ (.send sock pkt)
                rbuf (byte-array 512)
                rpkt (DatagramPacket. rbuf (alength rbuf))
                _ (.receive sock rpkt)
                resp (dns-proto/decode-packet (java.util.Arrays/copyOf rbuf (.getLength rpkt)))]
            (if (= 0x4242 (:id resp))
              {:ok? true}
              {:ok? false :error :invalid-dns-response})))
        (with-open [sock (Socket.)]
          (.connect sock (InetSocketAddress. ^String ip (int port)) t-ms)
          {:ok? true}))
      (catch Exception e
        {:ok? false :error (or (.getMessage e) "unreachable")}))))

(defn verify-external-reachability!
  "Pre-flight external reachability gate (M3 Step 15A): verifies that mapped external ports
   (`UDP 53`, `TCP 53`, `TCP 80`, `TCP 443`) are reachable on `:external-ip` before attempting ACME
   challenge validation. Emits a counted `:diagnose` effect when any port fails."
  [{:keys [external-ip ports probe-fn timeout-ms domain]}]
  (let [probe (or probe-fn default-reachability-probe!)
        req-ports (or ports
                      [{:protocol "UDP" :port 53}
                       {:protocol "TCP" :port 53}
                       {:protocol "TCP" :port 80}
                       {:protocol "TCP" :port 443}])
        results (mapv (fn [{:keys [protocol port] :as p}]
                        (let [r (probe external-ip protocol port {:timeout-ms timeout-ms :domain domain})]
                          (assoc p :ok? (boolean (:ok? r)) :error (:error r))))
                      req-ports)
        dns-udp-ok? (boolean (:ok? (first (filter #(and (= "UDP" (str/upper-case (str (:protocol %))))
                                                        (= 53 (int (:port %))))
                                                  results))))
        dns-tcp-ok? (boolean (:ok? (first (filter #(and (= "TCP" (str/upper-case (str (:protocol %))))
                                                        (= 53 (int (:port %))))
                                                  results))))
        failed (filterv #(not (:ok? %)) results)]
    (if (empty? failed)
      {:ok? true
       :external-ip external-ip
       :dns-udp-ok? dns-udp-ok?
       :dns-tcp-ok? dns-tcp-ok?
       :results results
       :effects []}
      {:ok? false
       :error :external-reachability-gate-failed
       :external-ip external-ip
       :dns-udp-ok? dns-udp-ok?
       :dns-tcp-ok? dns-tcp-ok?
       :failed-ports failed
       :results results
       :effects [{:effect :diagnose
                  :reason :external-reachability-gate-failed
                  :external-ip external-ip
                  :failed-ports (mapv #(select-keys % [:protocol :port :error]) failed)}]})))
