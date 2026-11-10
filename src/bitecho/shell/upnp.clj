(ns bitecho.shell.upnp
  "UPnP Internet Gateway Device (`IGD` `WANIPConnection` / `WANPPPConnection`) port-mapping shell:
   - Pure Sans-IO SSDP `M-SEARCH` request/response & UPnP IGD XML/SOAP builders and parsers
     (ported cleanly from `jaq.http.xrf.upnp`).
   - Thin bounded-timeout UDP (`239.255.255.250:1900` default) & HTTP SOAP boundary shell
     (`discover-gateway!`, `get-external-ip!`, `add-port-mapping!`, `delete-port-mapping!`)
     emitting counted `:diagnose` effects on timeout, CGNAT, or SOAP faults (Rule 5)."
  (:require [clojure.string :as str]
            [clojure.xml :as xml])
  (:import [java.io ByteArrayInputStream]
           [java.net DatagramPacket DatagramSocket InetSocketAddress SocketTimeoutException URI]
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
            (let [fault (or (parse-xml-tag-text resp-body "errorDescription")
                            (parse-xml-tag-text resp-body "faultstring")
                            (str "HTTP " status))]
              {:ok? false
               :error :upnp-soap-fault
               :status status
               :fault fault
               :effects [{:effect :diagnose :reason :upnp-soap-fault :action action :fault fault}]})))
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

(defn add-port-mapping!
  "Executes `AddPortMapping` on `gateway`."
  [gateway {:keys [remote-host external-port protocol internal-port internal-client description lease-seconds] :as opts}]
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
    ["NewLeaseDuration" (int (or lease-seconds 3600))]]
   opts))

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
