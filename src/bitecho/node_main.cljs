(ns bitecho.node-main
  "Standalone Node.js Light-Node CLI & Daemon Boundary Shell (Phase 4 Milestone 14 Step 14B / M2b).
   Provides 100% CLI flag, JSONL wire, `state.fressian` persistence, `node-identity.edn` identity,
   and transport (`UDP` via `node:dgram` + RFC 4571 `TCP` / `HTTP CONNECT` via `node:net`) parity
   with the JVM `bitecho.shell.light-node` shell, backed by `bitecho.light-node.core`,
   `bitecho.fressian`, and `datachannel.api`."
  (:require [bitecho.backup.core :as backup]
            [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.config.flags :as flags]
            [bitecho.core.infra :as core-infra]
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
            [bitecho.snapshot.core :as snap]
            [bitecho.sync.core :as sync-core]
            [cljs.reader :as edn]
            [clojure.string :as str]
            [datachannel.api :as api]
            [datachannel.dtls :as dtls]
            [datachannel.mdns :as mdns]
            [goog.object :as gobj]))

(def ^:private node-fs (js/require "node:fs"))
(def ^:private node-fsp (.-promises node-fs))
(def ^:private node-path (js/require "node:path"))
(def ^:private node-os (js/require "node:os"))
(def ^:private node-http (js/require "node:http"))
(def ^:private node-https (js/require "node:https"))
(def ^:private node-tls (js/require "node:tls"))
(def ^:private node-readline (js/require "node:readline"))
(def ^:private node-crypto (js/require "node:crypto"))
(def ^:private node-child-process (js/require "node:child_process"))

(def ^:private bytes? fressian/bytes?)

;; =============================================================================
;; 1. Fingerprints, ICE Credentials, & Bootstrap Descriptor Parsing
;; =============================================================================

(def ^:private fingerprint-pattern
  #"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")

(def ^:private valid-pubkey-regex
  #"^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{88}$")

(def default-devnet-authority-pubkey
  "Pinned Directory Authority public key for bitecho.org devnet."
  "302a300506032b657003210056b505baa32c3b99663d163d6ee00b5018a26e182405f5ec4d5062f12f633ce9")

(declare dial-p2p-peer! send-routed-envelopes! resolve-proxy-url)

(defn normalize-fingerprint
  "Normalizes a SHA-256 DTLS fingerprint string to 32 uppercase colon-separated hex pairs."
  [fp]
  (when (or (nil? fp) (str/blank? (str fp)))
    (throw (ex-info "Invalid fingerprint: cannot be nil or blank" {:fingerprint fp})))
  (let [trimmed (str/trim (str fp))
        stripped (if (str/starts-with? (str/lower-case trimmed) "sha-256:")
                   (str/trim (subs trimmed 8))
                   trimmed)
        upper (str/upper-case stripped)]
    (if (re-matches fingerprint-pattern upper)
      upper
      (throw (ex-info "Invalid fingerprint format" {:fingerprint fp :normalized upper})))))

(defn generate-random-ice-creds
  "Generates cryptographically random ICE credentials via `node:crypto`."
  ([] (generate-random-ice-creds nil nil))
  ([_node-id] (generate-random-ice-creds nil nil))
  ([_node-id _fingerprint]
   (let [ufrag-buf (.randomBytes node-crypto 4)
         pwd-buf (.randomBytes node-crypto 12)]
     {:ufrag (.toString ufrag-buf "hex")
      :pwd (.toString pwd-buf "hex")})))

(defn- validate-pubkey!
  [pubkey-str context-label]
  (let [cleaned (when (string? pubkey-str) (str/trim pubkey-str))]
    (when-not (and cleaned (re-matches valid-pubkey-regex cleaned))
      (throw (ex-info (str "Invalid descriptor: " context-label " public key hex string is invalid")
                      {:error :invalid-descriptor
                       :field context-label
                       :pubkey pubkey-str})))
    (str/lower-case cleaned)))

(defn- parse-long-safe
  [v default-val]
  (if (nil? v)
    default-val
    (let [n (js/parseInt (str v) 10)]
      (if (js/isNaN n) default-val n))))

(defn- normalize-node-entry
  [node-id-key node-map]
  (let [node-id (keyword node-id-key)
        ip (when-let [ip-raw (:ip node-map)] (str/trim (str ip-raw)))
        port (when-let [p (:port node-map)] (parse-long-safe p nil))
        agent-port (when-let [ap (:agent-port node-map)] (parse-long-safe ap nil))
        agent-tcp-port (when-let [atp (:agent-tcp-port node-map)] (parse-long-safe atp nil))
        ingress-host (when-let [ih (:ingress-host node-map)] (str/trim (str ih)))
        ingress-port (when-let [ip-p (:ingress-port node-map)] (parse-long-safe ip-p nil))
        pubkey (validate-pubkey! (:pubkey node-map) (str "node " node-id))
        raw-fp (:fingerprint node-map)
        fp (normalize-fingerprint raw-fp)
        ufrag (when-let [u (:ice-ufrag node-map)] (str/trim (str u)))
        pwd (when-let [p (:ice-pwd node-map)] (str/trim (str p)))]
    (when (or (str/blank? ip) (nil? port) (nil? agent-port) (str/blank? ufrag) (str/blank? pwd))
      (throw (ex-info (str "Invalid descriptor: incomplete node entry for " node-id)
                      {:error :invalid-descriptor :node-id node-id :node node-map})))
    (cond-> {:node-id node-id
             :ip ip
             :port port
             :agent-port agent-port
             :pubkey pubkey
             :fingerprint fp
             :ice-ufrag ufrag
             :ice-pwd pwd}
      agent-tcp-port (assoc :agent-tcp-port agent-tcp-port)
      (seq ingress-host) (assoc :ingress-host ingress-host)
      ingress-port (assoc :ingress-port ingress-port))))

(defn parse-bootstrap-edn
  "Parses a `bootstrap.edn` string or map into a validated descriptor map."
  [edn-or-map]
  (let [data (if (map? edn-or-map)
               edn-or-map
               (edn/read-string edn-or-map))
        network (keyword (:network data :devnet))
        treasury-pk (validate-pubkey! (:treasury-pubkey data) "treasury")
        custody-pk (validate-pubkey! (:custody-pubkey data) "custody")
        dir-pk (when-let [dp (:directory-pubkey data)] (validate-pubkey! dp "directory"))
        dom (when-let [d (:domain data)] (str/trim (str d)))
        auth-pk (when-let [ap (:authority-pubkey data)] (validate-pubkey! ap "authority"))
        issued-ep (when-let [ie (:issued-epoch data)] (parse-long-safe ie nil))
        expires-ep (when-let [ee (:expires-epoch data)] (parse-long-safe ee nil))
        sig (when-let [s (:signature data)] (str/trim (str s)))
        relay-url (or (when-let [ru (:relay-url data)] (relay/normalize-relay-base-url ru))
                      (when (= dom "bitecho.org") "https://ns1.bitecho.org"))
        nodes-map (or (:nodes data) {})
        _ (when (empty? nodes-map)
            (throw (ex-info "Bootstrap descriptor contains no validator nodes"
                            {:error :invalid-descriptor :data data})))
        normalized-nodes (into {} (for [[k v] nodes-map]
                                    [(keyword k)
                                     (try
                                       (normalize-node-entry k v)
                                       (catch :default e
                                         (throw (ex-info "Invalid validator entry in bootstrap descriptor"
                                                         {:line (str k " " v)
                                                          :entry k
                                                          :node v
                                                          :error :invalid-validator-entry}
                                                         e))))]))]
    (cond-> {:network network
             :treasury-pubkey treasury-pk
             :custody-pubkey custody-pk
             :nodes normalized-nodes}
      dir-pk (assoc :directory-pubkey dir-pk)
      dom (assoc :domain dom)
      auth-pk (assoc :authority-pubkey auth-pk)
      issued-ep (assoc :issued-epoch issued-ep)
      expires-ep (assoc :expires-epoch expires-ep)
      sig (assoc :signature sig)
      (seq relay-url) (assoc :relay-url relay-url)
      (contains? data :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? data)))
      (some? (:burn-floor data)) (assoc :burn-floor (long (:burn-floor data)))
      (some? (:min-signaling-burn data)) (assoc :min-signaling-burn (long (:min-signaling-burn data))))))

(defn- parse-single-node-txt-block
  [block-str]
  (let [id-match (re-find #"(?i)Node:\s*([a-zA-Z0-9_\-]+)" block-str)
        node-id (when id-match (keyword (second id-match)))
        cluster-match (re-find #"(?i)Cluster Address:\s*([^\s:]+):([0-9]+)" block-str)
        agent-match (re-find #"(?i)Agent Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        agent-tcp-match (re-find #"(?i)Agent TCP Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        agent-proxy-match (re-find #"(?i)Agent HTTPS/Proxy Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        pubkey-match (re-find #"(?i)Ed25519 Pubkey:\s*([0-9a-fA-F]+)" block-str)
        fp-match (re-find #"(?i)DTLS Fingerprint:\s*([0-9a-fA-F:]+)" block-str)
        ice-match (re-find #"(?i)ICE Credentials:\s*ufrag=([^\s]+)\s+pwd=([^\s]+)" block-str)]
    (when node-id
      [node-id
       (normalize-node-entry
        node-id
        (cond-> {:ip (when cluster-match (nth cluster-match 1))
                 :port (when cluster-match (parse-long-safe (nth cluster-match 2) nil))
                 :agent-port (when agent-match (parse-long-safe (nth agent-match 2) nil))
                 :pubkey (when pubkey-match (second pubkey-match))
                 :fingerprint (when fp-match (second fp-match))
                 :ice-ufrag (when ice-match (nth ice-match 1))
                 :ice-pwd (when ice-match (nth ice-match 2))}
          agent-tcp-match (assoc :agent-tcp-port (parse-long-safe (nth agent-tcp-match 2) nil))
          agent-proxy-match (assoc :ingress-host (nth agent-proxy-match 1)
                                   :ingress-port (parse-long-safe (nth agent-proxy-match 2) nil))))])))

(defn parse-bootstrap-txt
  "Parses a `bootstrap.txt` descriptor string into a validated descriptor map."
  [txt-str]
  (when (or (nil? txt-str) (str/blank? txt-str))
    (throw (ex-info "Empty bootstrap.txt descriptor" {:error :invalid-descriptor})))
  (let [lines (str/split-lines txt-str)
        _ (doseq [line lines]
            (let [trimmed (str/trim line)]
              (when (re-find #"(?i)^validator[=:]" trimmed)
                (let [parts (str/split trimmed #"[=:\s]+")]
                  (when (< (count parts) 2)
                    (throw (ex-info "Invalid validator entry in bootstrap.txt"
                                    {:line trimmed :error :invalid-validator-entry})))
                  (let [cand-pk (last parts)]
                    (when-not (re-matches valid-pubkey-regex cand-pk)
                      (throw (ex-info "Invalid validator entry in bootstrap.txt"
                                      {:line trimmed :error :invalid-validator-entry}))))))))
        find-header (fn [prefix-re]
                      (some (fn [line]
                              (when-let [m (re-find prefix-re line)]
                                (second m)))
                            lines))
        net-str (find-header #"(?i)^Network:\s*([a-zA-Z0-9_\-]+)")
        dom (find-header #"(?i)^Domain:\s*([^\s]+)")
        auth-raw (find-header #"(?i)^Authority Pubkey:\s*([0-9a-fA-F]+)")
        issued-raw (find-header #"(?i)^Issued Epoch:\s*([0-9]+)")
        expires-raw (find-header #"(?i)^Expires Epoch:\s*([0-9]+)")
        sig (find-header #"(?i)^Authority Signature:\s*([0-9a-fA-F]+)")
        treasury-raw (find-header #"(?i)^Treasury Public Key:\s*([0-9a-fA-F]+)")
        custody-raw (find-header #"(?i)^Custody Public Key:\s*([0-9a-fA-F]+)")
        dir-raw (find-header #"(?i)^Directory Authority Public Key:\s*([0-9a-fA-F]+)")
        econ-raw (find-header #"(?i)^Economy Enabled:\s*([^\s]+)")
        burn-floor-raw (find-header #"(?i)^Burn Floor:\s*([0-9]+)")
        min-burn-raw (find-header #"(?i)^Min Signaling Burn:\s*([0-9]+)")
        relay-match (or (find-header #"(?i)^Relay URL:\s*([^\s]+)")
                        (find-header #"(?i)^relay[=:]\s*([^\s]+)"))
        relay-url (or (when relay-match (relay/normalize-relay-base-url relay-match))
                      (when (= dom "bitecho.org") "https://ns1.bitecho.org"))
        network (keyword (str/lower-case (or net-str "devnet")))
        auth-pk (when auth-raw (validate-pubkey! auth-raw "authority"))
        issued-ep (when issued-raw (parse-long-safe issued-raw nil))
        expires-ep (when expires-raw (parse-long-safe expires-raw nil))
        treasury-pk (validate-pubkey! treasury-raw "treasury")
        custody-pk (validate-pubkey! custody-raw "custody")
        dir-pk (when dir-raw (validate-pubkey! dir-raw "directory"))
        econ-enabled (when econ-raw (= "true" (str/lower-case (str/trim econ-raw))))
        burn-floor (when burn-floor-raw (parse-long-safe burn-floor-raw nil))
        min-burn (when min-burn-raw (parse-long-safe min-burn-raw nil))
        blocks (loop [rem-lines lines
                      curr nil
                      acc []]
                 (if (empty? rem-lines)
                   (if curr (conj acc (str/join "\n" curr)) acc)
                   (let [ln (first rem-lines)]
                     (if (re-find #"(?i)^Node:\s*" ln)
                       (recur (rest rem-lines) [ln] (if curr (conj acc (str/join "\n" curr)) acc))
                       (recur (rest rem-lines) (when curr (conj curr ln)) acc)))))
        nodes-entries (mapv (fn [b]
                              (let [trimmed (str/trim b)
                                    entry (try
                                            (parse-single-node-txt-block b)
                                            (catch :default e
                                              (throw (ex-info "Invalid validator entry in bootstrap.txt"
                                                              {:line trimmed :error :invalid-validator-entry}
                                                              e))))]
                                (when-not entry
                                  (throw (ex-info "Invalid validator entry in bootstrap.txt"
                                                  {:line trimmed :error :invalid-validator-entry})))
                                entry))
                            blocks)
        nodes-map (into {} nodes-entries)]
    (when (empty? nodes-map)
      (throw (ex-info "No validator node blocks found in bootstrap.txt"
                      {:error :invalid-descriptor :raw-text txt-str})))
    (cond-> {:network network
             :treasury-pubkey treasury-pk
             :custody-pubkey custody-pk
             :nodes nodes-map}
      dir-pk (assoc :directory-pubkey dir-pk)
      dom (assoc :domain dom)
      auth-pk (assoc :authority-pubkey auth-pk)
      issued-ep (assoc :issued-epoch issued-ep)
      expires-ep (assoc :expires-epoch expires-ep)
      sig (assoc :signature sig)
      (seq relay-url) (assoc :relay-url relay-url)
      (some? econ-enabled) (assoc :economy-enabled? econ-enabled)
      burn-floor (assoc :burn-floor burn-floor)
      min-burn (assoc :min-signaling-burn min-burn))))

(defn parse-bootstrap-descriptor
  "Auto-detects EDN or text format and parses into a validated descriptor map."
  [str-or-map]
  (cond
    (map? str-or-map)
    (parse-bootstrap-edn str-or-map)

    (string? str-or-map)
    (let [trimmed (str/trim str-or-map)]
      (cond
        (str/starts-with? trimmed "{")
        (parse-bootstrap-edn trimmed)

        (str/starts-with? trimmed ";;")
        (try
          (parse-bootstrap-edn trimmed)
          (catch :default _
            (parse-bootstrap-txt trimmed)))

        :else
        (parse-bootstrap-txt trimmed)))

    :else
    (throw (ex-info "Unsupported descriptor format" {:error :invalid-descriptor :input str-or-map}))))

(def ^:private recognized-header-prefixes
  [#"(?i)^Network:"
   #"(?i)^Domain:"
   #"(?i)^Authority Pubkey:"
   #"(?i)^Issued Epoch:"
   #"(?i)^Expires Epoch:"
   #"(?i)^Authority Signature:"
   #"(?i)^Treasury Public Key:"
   #"(?i)^Custody Public Key:"
   #"(?i)^Directory Authority Public Key:"
   #"(?i)^Economy Enabled:"
   #"(?i)^Burn Floor:"
   #"(?i)^Min Signaling Burn:"
   #"(?i)^Relay URL:"
   #"(?i)^relay[=:]"
   #"(?i)^Bootstrap Validators:"
   #"(?i)^Connection Instructions"
   #"(?i)^Node:"
   #"(?i)^Cluster Address:"
   #"(?i)^Agent Ingress:"
   #"(?i)^Agent TCP Ingress:"
   #"(?i)^Agent HTTPS/Proxy Ingress:"
   #"(?i)^HTTP Diagnostics:"
   #"(?i)^Ed25519 Pubkey:"
   #"(?i)^DTLS Fingerprint:"
   #"(?i)^ICE Credentials:"
   #"(?i)^Generated:"
   #"(?i)^Agents connect"
   #"(?i)^\"bitecho\""
   #"(?i)^All inbound"
   #"(?i)^Ed25519-signed"])

(defn parse-bootstrap-descriptor-with-diagnostics
  "Parses a bootstrap descriptor (EDN or text) with strict validation, returning the
   descriptor map augmented with :diagnostics (vector of dropped/unrecognized lines/elements)
   and :dropped count. Fails closed throwing on invalid validator entries."
  [str-or-map]
  (let [desc (parse-bootstrap-descriptor str-or-map)
        diags (if (string? str-or-map)
                (let [trimmed-input (str/trim str-or-map)]
                  (if (or (str/starts-with? trimmed-input "{")
                          (str/starts-with? trimmed-input ";;"))
                    ;; EDN string diagnostics
                    (let [data (try (edn/read-string trimmed-input) (catch :default _ {}))
                          known-keys #{:network :domain :authority-pubkey :issued-epoch :expires-epoch
                                       :signature :treasury-pubkey :custody-pubkey :directory-pubkey
                                       :economy-enabled? :burn-floor :min-signaling-burn :relay-url
                                       :nodes :dropped-entries :diagnostics :dropped}
                          extra (remove known-keys (keys data))]
                      (mapv (fn [k] {:reason :unrecognized-key :key k :value (get data k)}) extra))
                    ;; Text descriptor line diagnostics
                    (let [lines (str/split-lines str-or-map)]
                      (loop [rem-lines lines
                             acc []]
                        (if (empty? rem-lines)
                          acc
                          (let [line (first rem-lines)
                                tr (str/trim line)]
                            (cond
                              (str/blank? tr)
                              (recur (rest rem-lines) acc)

                              (or (str/starts-with? tr "#")
                                  (str/starts-with? tr ";")
                                  (str/starts-with? tr "=")
                                  (str/starts-with? tr "-"))
                              (recur (rest rem-lines) acc)

                              ;; Optional keys with format checks
                              (re-find #"(?i)^turn[=:]" tr)
                              (let [val (str/trim (subs tr (if (str/includes? tr "=") (inc (str/index-of tr "=")) (inc (str/index-of tr ":")))))]
                                (if (re-matches #"^turn:[^\s]+:[0-9]+" val)
                                  (recur (rest rem-lines) acc)
                                  (recur (rest rem-lines) (conj acc {:reason :malformed-optional :line tr :element :turn}))))

                              (re-find #"(?i)^signal[=:]" tr)
                              (let [val (str/trim (subs tr (if (str/includes? tr "=") (inc (str/index-of tr "=")) (inc (str/index-of tr ":")))))]
                                (if (re-matches #"^https?://[^\s]+" val)
                                  (recur (rest rem-lines) acc)
                                  (recur (rest rem-lines) (conj acc {:reason :malformed-optional :line tr :element :signal}))))

                              (some #(re-find % tr) recognized-header-prefixes)
                              (recur (rest rem-lines) acc)

                              :else
                              (recur (rest rem-lines) (conj acc {:reason :unrecognized-line :line tr})))))))))
                [])]
    (assoc desc
           :diagnostics diags
           :dropped (count diags)
           :descriptor desc)))

(defn- http-get-string!
  "Fetches `url-str` over HTTP/HTTPS with a timeout, invoking `(cb body-or-nil)`."
  [url-str timeout-ms cb]
  (let [settled? (atom false)
        done! (fn [res]
                (when (compare-and-set! settled? false true)
                  (cb res)))]
    (try
      (let [client (if (str/starts-with? (str/lower-case url-str) "https://")
                     node-https
                     node-http)
            req (.get client url-str #js {:timeout (or timeout-ms 4000)}
                      (fn [res]
                        (if (not= 200 (.-statusCode res))
                          (do (.resume res) (done! nil))
                          (let [chunks #js []]
                            (.on res "data" (fn [c] (.push chunks c)))
                            (.on res "end" (fn []
                                             (let [buf (js/Buffer.concat chunks)]
                                               (done! (.toString buf "utf8")))))
                            (.on res "error" (fn [_] (done! nil)))))))]
        (.on req "timeout" (fn [] (.destroy req) (done! nil)))
        (.on req "error" (fn [_] (done! nil))))
      (catch :default _
        (done! nil)))))

(defn- open-https-proxy-tls-socket!
  "Opens an HTTP CONNECT tunnel through `proxy-url-str` to `target-host`:`target-port`
   and upgrades the socket via `node:tls`, invoking `(cb tls-socket-or-nil err-or-nil)`."
  [proxy-url-str target-host target-port timeout-ms cb]
  (try
    (let [proxy-u (js/URL. (if (re-find #"^https?://" proxy-url-str)
                             proxy-url-str
                             (str "http://" proxy-url-str)))
          p-host (.-hostname proxy-u)
          p-port (int (or (not-empty (str (.-port proxy-u))) 3128))
          p-user (not-empty (str (.-username proxy-u)))
          p-pass (not-empty (str (.-password proxy-u)))
          auth-hdr (when (or p-user p-pass)
                     (let [u (js/decodeURIComponent (or p-user ""))
                           p (js/decodeURIComponent (or p-pass ""))
                           b64 (.toString (.from (.-Buffer js/globalThis) (str u ":" p) "utf8") "base64")]
                       (str "Basic " b64)))
          req-headers (if auth-hdr
                        #js {"Host" (str target-host ":" target-port)
                             "Proxy-Authorization" auth-hdr}
                        #js {"Host" (str target-host ":" target-port)})
          settled? (atom false)
          done! (fn [sock err]
                  (when (compare-and-set! settled? false true)
                    (cb sock err)))
          connect-req (.request node-http
                                #js {:hostname p-host
                                     :port p-port
                                     :method "CONNECT"
                                     :path (str target-host ":" target-port)
                                     :headers req-headers
                                     :timeout (or timeout-ms 5000)})]
      (.on connect-req "connect"
           (fn [res sock _head]
             (if (not= 200 (.-statusCode res))
               (do (try (.destroy sock) (catch :default _ nil))
                   (done! nil (str "proxy-connect-status-" (.-statusCode res))))
               (try
                 (let [tls-sock (.connect node-tls #js {:socket sock :servername target-host})]
                   (.on tls-sock "error"
                        (fn [e]
                          (try (.destroy sock) (catch :default _ nil))
                          (done! nil (str e))))
                   (.once tls-sock "secureConnect"
                          (fn []
                            (done! tls-sock nil))))
                 (catch :default e
                   (try (.destroy sock) (catch :default _ nil))
                   (done! nil (str e)))))))
      (.on connect-req "timeout" (fn [] (try (.destroy connect-req) (catch :default _ nil)) (done! nil "proxy-connect-timeout")))
      (.on connect-req "error" (fn [e] (done! nil (str e))))
      (.end connect-req))
    (catch :default e
      (cb nil (str e)))))

(defn- http-get-json!
  "Fetches `url-str` over HTTP/HTTPS with a timeout (tunneling via HTTPS_PROXY when present),
   reading body on any status code, parsing JSON, attaching `:status (.-statusCode res)`,
   and invoking `(cb parsed-map)`."
  ([url-str timeout-ms cb]
   (http-get-json! url-str nil timeout-ms cb))
  ([url-str headers timeout-ms cb]
   (let [settled? (atom false)
         done! (fn [res]
                 (when (compare-and-set! settled? false true)
                   (cb res)))]
     (try
       (let [https? (str/starts-with? (str/lower-case url-str) "https://")
             url-obj (js/URL. url-str)
             target-host (.-hostname url-obj)
             target-port (int (or (not-empty (str (.-port url-obj))) (if https? 443 80)))
             proxy-str (when (and https?
                                  (not= target-host "127.0.0.1")
                                  (not= target-host "localhost"))
                         (resolve-proxy-url nil))
             run-get! (fn [tls-sock]
                        (try
                          (let [client (if https? node-https node-http)
                                opts-obj #js {:protocol (.-protocol url-obj)
                                              :hostname target-host
                                              :port target-port
                                              :path (str (.-pathname url-obj) (.-search url-obj))
                                              :method "GET"
                                              :timeout (or timeout-ms 4000)}
                                _ (when (map? headers)
                                    (set! (.-headers opts-obj) (clj->js headers)))
                                _ (when tls-sock
                                    (set! (.-agent opts-obj) false)
                                    (let [h (or (.-headers opts-obj) #js {})]
                                      (aset h "Connection" "close")
                                      (set! (.-headers opts-obj) h))
                                    (set! (.-createConnection opts-obj) (fn [_ _] tls-sock)))
                                req (.request client opts-obj
                                              (fn [res]
                                                (let [status-code (.-statusCode res)
                                                      chunks #js []]
                                                  (.on res "data" (fn [c] (.push chunks c)))
                                                  (.on res "end" (fn []
                                                                   (try
                                                                     (let [buf (js/Buffer.concat chunks)
                                                                           txt (.toString buf "utf8")
                                                                           parsed (try (js->clj (js/JSON.parse txt)) (catch :default _ nil))]
                                                                       (done! (if (map? parsed)
                                                                                (assoc parsed :status status-code)
                                                                                {:status status-code :raw-body txt})))
                                                                     (catch :default _
                                                                       (done! {:status status-code :error "json-parse-failed"})))))
                                                  (.on res "error" (fn [err] (done! {:error (str err) :status status-code}))))))]
                            (.on req "timeout" (fn [] (.destroy req) (done! {:error "timeout" :status 408})))
                            (.on req "error" (fn [err] (done! {:error (str err) :status 500})))
                            (.end req))
                          (catch :default e
                            (done! {:error (str e) :status 500}))))]
         (if proxy-str
           (open-https-proxy-tls-socket!
            proxy-str target-host target-port (or timeout-ms 4000)
            (fn [tls-sock err]
              (if tls-sock
                (run-get! tls-sock)
                (done! {:error (or err "proxy-connect-failed") :status 502}))))
           (run-get! nil)))
       (catch :default e
         (done! {:error (str e) :status 500}))))))

(defn- http-get-bytes!
  "Fetches raw bytes from `url-str` over HTTP/HTTPS (honoring `proxy-url` / `HTTPS_PROXY`),
   using a dedicated non-pooled connection (`agent: false`, `Connection: close`,
   `Accept-Encoding: identity`), explicit `aborted`/`close`/truncation detection, optional
   HTTP `Range: bytes=S-E`, and a hard total transfer deadline (BIP-022 Stage D.1)."
  ([url-str proxy-url timeout-ms cb]
   (http-get-bytes! url-str proxy-url timeout-ms nil cb))
  ([url-str proxy-url timeout-ms extra-opts cb]
   (let [settled? (atom false)
         total-timer (atom nil)
         active-req (atom nil)
         done! (fn [res]
                 (when (compare-and-set! settled? false true)
                   (when-let [t @total-timer]
                     (js/clearTimeout t)
                     (reset! total-timer nil))
                   (cb res)))
         total-deadline-ms (long (or (:total-timeout-ms extra-opts) timeout-ms 30000))
         inactivity-ms (long (min 15000 (or timeout-ms 15000)))
         range-vec (:range extra-opts)]
     (try
       (let [https? (str/starts-with? (str/lower-case (str url-str)) "https://")
             ^js url-obj (js/URL. url-str)
             target-host (.-hostname url-obj)
             target-port (int (or (not-empty (str (.-port url-obj))) (if https? 443 80)))
             eff-proxy (when (and https?
                                  (not= target-host "127.0.0.1")
                                  (not= target-host "localhost"))
                         (or proxy-url (resolve-proxy-url nil)))
             run-get! (fn [tls-sock]
                        (try
                          (let [^js client (if https? node-https node-http)
                                hdrs #js {"Connection" "close"
                                          "Accept-Encoding" "identity"}
                                _ (when (and (vector? range-vec) (= 2 (count range-vec)))
                                    (gobj/set hdrs "Range" (str "bytes=" (first range-vec) "-" (second range-vec))))
                                opts-obj #js {:protocol (.-protocol url-obj)
                                              :hostname target-host
                                              :port target-port
                                              :path (str (.-pathname url-obj) (.-search url-obj))
                                              :method "GET"
                                              :agent false
                                              :headers hdrs
                                              :timeout inactivity-ms}
                                _ (when tls-sock
                                    (gobj/set opts-obj "createConnection" (fn [_ _] tls-sock)))
                                ^js req (.request
                                         client opts-obj
                                         (fn [^js res]
                                           (let [status-code (.-statusCode res)
                                                 res-hdrs (.-headers res)
                                                 cl-raw (gobj/get res-hdrs "content-length")
                                                 expected-len (when (and cl-raw (not (str/blank? (str cl-raw))))
                                                                (let [n (js/parseInt (str cl-raw) 10)]
                                                                  (when (and (not (js/isNaN n)) (>= n 0)) n)))
                                                 etag (gobj/get res-hdrs "etag")
                                                 content-range (gobj/get res-hdrs "content-range")
                                                 chunks #js []
                                                 received-len (atom 0)
                                                 partial-u8 (fn []
                                                              (when (pos? @received-len)
                                                                (crypto/compact-u8 (js/Buffer.concat chunks))))]
                                             (.on res "data" (fn [^js c]
                                                               (.push chunks c)
                                                               (swap! received-len + (.-length c))))
                                             (.on res "aborted"
                                                  (fn []
                                                    (let [n @received-len]
                                                      (done! {:ok? false
                                                              :status status-code
                                                              :aborted-mid-body? (pos? n)
                                                              :received-bytes n
                                                              :total-bytes expected-len
                                                              :partial-bytes (partial-u8)
                                                              :etag etag
                                                              :error "aborted"}))))
                                             (.on res "close"
                                                  (fn []
                                                    (when (and (not @settled?)
                                                               (not (boolean (gobj/get res "complete"))))
                                                      (let [n @received-len]
                                                        (done! {:ok? false
                                                                :status status-code
                                                                :aborted-mid-body? (pos? n)
                                                                :received-bytes n
                                                                :total-bytes expected-len
                                                                :partial-bytes (partial-u8)
                                                                :etag etag
                                                                :error "premature-close"})))))
                                             (.on res "end"
                                                  (fn []
                                                    (let [n @received-len]
                                                      (if (and (>= status-code 200) (< status-code 300)
                                                               (number? expected-len)
                                                               (< (long n) (long expected-len)))
                                                        (done! {:ok? false
                                                                :status status-code
                                                                :aborted-mid-body? true
                                                                :received-bytes n
                                                                :total-bytes expected-len
                                                                :partial-bytes (partial-u8)
                                                                :etag etag
                                                                :error "truncated-body"})
                                                        (let [buf (js/Buffer.concat chunks)
                                                              u8 (crypto/compact-u8 buf)]
                                                          (done! {:ok? (and (>= status-code 200) (< status-code 300))
                                                                  :status status-code
                                                                  :bytes u8
                                                                  :content-range content-range
                                                                  :etag etag
                                                                  :total-bytes expected-len
                                                                  :headers (js->clj res-hdrs)}))))))
                                             (.on res "error"
                                                  (fn [err]
                                                    (let [n @received-len]
                                                      (done! {:ok? false
                                                              :status status-code
                                                              :aborted-mid-body? (pos? n)
                                                              :received-bytes n
                                                              :total-bytes expected-len
                                                              :partial-bytes (partial-u8)
                                                              :etag etag
                                                              :error (str err)})))))))]
                            (reset! active-req req)
                            (.on req "timeout" (fn [] (.destroy req) (done! {:ok? false :status 408 :error "timeout"})))
                            (.on req "error" (fn [err] (done! {:ok? false :status 500 :error (str err)})))
                            (.end req))
                          (catch :default e
                            (done! {:ok? false :status 500 :error (str e)}))))]
         (reset! total-timer
                 (js/setTimeout (fn []
                                  (when-let [^js r @active-req]
                                    (try (.destroy r) (catch :default _ nil)))
                                  (done! {:ok? false :status 408 :error "total-transfer-timeout"}))
                                total-deadline-ms))
         (if eff-proxy
           (open-https-proxy-tls-socket!
            eff-proxy target-host target-port inactivity-ms
            (fn [tls-sock err]
              (if tls-sock
                (run-get! tls-sock)
                (done! {:ok? false :status 502 :error (or err "proxy-connect-failed")}))))
           (run-get! nil)))
       (catch :default e
         (done! {:ok? false :status 500 :error (str e)}))))))

(defn- http-post-json!
  "Posts `json-body-str` to `url-str` over HTTP/HTTPS with a timeout (tunneling via HTTPS_PROXY when present),
   invoking `(cb body-or-nil)`."
  ([url-str json-body-str timeout-ms cb]
   (http-post-json! url-str json-body-str nil timeout-ms cb))
  ([url-str json-body-str headers timeout-ms cb]
   (let [settled? (atom false)
         done! (fn [res]
                 (when (compare-and-set! settled? false true)
                   (cb res)))]
     (try
       (let [https? (str/starts-with? (str/lower-case url-str) "https://")
             body-buf (.from (.-Buffer js/globalThis) (str json-body-str) "utf8")
             url-obj (js/URL. url-str)
             target-host (.-hostname url-obj)
             target-port (int (or (not-empty (str (.-port url-obj))) (if https? 443 80)))
             proxy-str (when (and https?
                                  (not= target-host "127.0.0.1")
                                  (not= target-host "localhost"))
                         (resolve-proxy-url nil))
             hdrs (cond-> {"Content-Type" "application/json"
                           "Content-Length" (.-length body-buf)}
                    (map? headers) (merge headers))
             run-post! (fn [tls-sock]
                         (try
                           (let [client (if https? node-https node-http)
                                 options #js {:protocol (.-protocol url-obj)
                                              :hostname target-host
                                              :port target-port
                                              :path (str (.-pathname url-obj) (.-search url-obj))
                                              :method "POST"
                                              :timeout (or timeout-ms 5000)
                                              :headers (clj->js hdrs)}
                                 _ (when tls-sock
                                     (set! (.-agent options) false)
                                     (let [h (or (.-headers options) #js {})]
                                       (aset h "Connection" "close")
                                       (set! (.-headers options) h))
                                     (set! (.-createConnection options) (fn [_ _] tls-sock)))
                                 req (.request client options
                                               (fn [res]
                                                 (let [chunks #js []]
                                                   (.on res "data" (fn [c] (.push chunks c)))
                                                   (.on res "end" (fn []
                                                                    (let [buf (.concat (.-Buffer js/globalThis) chunks)]
                                                                      (done! (.toString buf "utf8")))))
                                                   (.on res "error" (fn [_] (done! nil))))))]
                             (.on req "timeout" (fn [] (.destroy req) (done! nil)))
                             (.on req "error" (fn [_] (done! nil)))
                             (.write req body-buf)
                             (.end req))
                           (catch :default _
                             (done! nil))))]
         (if proxy-str
           (open-https-proxy-tls-socket!
            proxy-str target-host target-port (or timeout-ms 5000)
            (fn [tls-sock _err]
              (if tls-sock
                (run-post! tls-sock)
                (done! nil))))
           (run-post! nil)))
       (catch :default _
         (done! nil))))))

(defn- http-post-bytes-detailed!
  "Posts raw `Buffer`/`Uint8Array` or UTF-8 string `body` to `url-str` over HTTP/HTTPS,
   invoking `(cb {:status int-or-nil :body str-or-nil :error str-or-nil})`."
  [url-str body headers timeout-ms cb]
  (let [settled? (atom false)
        done! (fn [res]
                (when (compare-and-set! settled? false true)
                  (cb res)))]
    (try
      (let [https? (str/starts-with? (str/lower-case url-str) "https://")
            Buf (.-Buffer js/globalThis)
            body-buf (cond
                       (.isBuffer Buf body) body
                       (instance? js/Uint8Array body) (.from Buf (.-buffer body) (.-byteOffset body) (.-byteLength body))
                       :else (.from Buf (str body) "utf8"))
            url-obj (js/URL. url-str)
            target-host (.-hostname url-obj)
            target-port (int (or (not-empty (str (.-port url-obj))) (if https? 443 80)))
            proxy-str (when (and https?
                                 (not= target-host "127.0.0.1")
                                 (not= target-host "localhost"))
                        (resolve-proxy-url nil))
            hdrs (cond-> {"Content-Type" "application/octet-stream"
                          "Content-Length" (.-length body-buf)}
                   (map? headers) (merge headers))
            run-post! (fn [tls-sock]
                        (try
                          (let [client (if https? node-https node-http)
                                options #js {:protocol (.-protocol url-obj)
                                             :hostname target-host
                                             :port target-port
                                             :path (str (.-pathname url-obj) (.-search url-obj))
                                             :method "POST"
                                             :timeout (or timeout-ms 30000)
                                             :headers (clj->js hdrs)}
                                _ (when tls-sock
                                    (set! (.-agent options) false)
                                    (let [h (or (.-headers options) #js {})]
                                      (aset h "Connection" "close")
                                      (set! (.-headers options) h))
                                    (set! (.-createConnection options) (fn [_ _] tls-sock)))
                                req (.request client options
                                              (fn [res]
                                                (let [status (.-statusCode res)
                                                      chunks #js []
                                                      ended? (atom false)]
                                                  (.on res "data" (fn [c] (.push chunks c)))
                                                  (.on res "end" (fn []
                                                                   (reset! ended? true)
                                                                   (let [buf (.concat Buf chunks)]
                                                                     (done! {:status status
                                                                             :body (.toString buf "utf8")
                                                                             :error nil}))))
                                                  (.on res "aborted" (fn []
                                                                       (when-not @ended?
                                                                         (done! {:status status
                                                                                 :body nil
                                                                                 :error "response-aborted"}))))
                                                  (.on res "close" (fn []
                                                                     (when-not @ended?
                                                                       (done! {:status status
                                                                               :body nil
                                                                               :error "response-closed-early"}))))
                                                  (.on res "error" (fn [e]
                                                                     (done! {:status status
                                                                             :body nil
                                                                             :error (or (.-message e) (str e))}))))))]
                            (.on req "timeout" (fn []
                                                 (.destroy req)
                                                 (done! {:status nil :body nil :error "timeout"})))
                            (.on req "error" (fn [e]
                                               (done! {:status nil :body nil :error (or (.-message e) (str e))})))
                            (.write req body-buf)
                            (.end req))
                          (catch :default e
                            (done! {:status nil :body nil :error (or (.-message e) (str e))}))))]
        (if proxy-str
          (open-https-proxy-tls-socket!
           proxy-str target-host target-port (or timeout-ms 30000)
           (fn [tls-sock err]
             (if tls-sock
               (run-post! tls-sock)
               (done! {:status nil :body nil :error (or err "proxy-connect-failed")}))))
          (run-post! nil)))
      (catch :default e
        (done! {:status nil :body nil :error (or (.-message e) (str e))})))))

(defn- read-json-str
  [s]
  (try
    (js->clj (js/JSON.parse s) :keywordize-keys true)
    (catch :default _ nil)))

;; -----------------------------------------------------------------------------
;; HTTP Gateway Relay Client Helpers (/relay/v1/*)
;; -----------------------------------------------------------------------------

(defn submit-relay-envelope!
  "Submits an envelope (hex string, bytes, or map) to HTTP relay at `relay-url`."
  ([relay-url envelope] (submit-relay-envelope! relay-url envelope nil nil))
  ([relay-url envelope arg]
   (if (fn? arg)
     (submit-relay-envelope! relay-url envelope nil arg)
     (submit-relay-envelope! relay-url envelope arg nil)))
  ([relay-url envelope opts cb]
   (let [promise-fn
         (fn [resolve _]
           (let [url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/send")
                 env-hex (cond
                           (fressian/bytes? envelope) (fressian/bytes->hex envelope)
                           (string? envelope) envelope
                           (map? envelope) (try (fressian/bytes->hex (fressian/encode-canonical envelope)) (catch :default _ nil))
                           :else (str envelope))
                 body-str (js/JSON.stringify #js {:envelope_hex env-hex})
                 done (fn [res-str]
                        (let [parsed (when res-str (read-json-str res-str))
                              res (or parsed {:ok false :error "network-or-timeout"})]
                          (if cb (cb res) (resolve res))))]
             (http-post-json! url body-str (or (:timeout-ms opts) 5000) done)))]
     (if (fn? cb)
       (do (promise-fn nil nil) nil)
       (js/Promise. promise-fn)))))

(defn poll-relay-envelopes!
  "Polls HTTP relay at `relay-url` for envelopes addressed to `pubkey`."
  ([relay-url pubkey privkey] (poll-relay-envelopes! relay-url pubkey privkey nil nil))
  ([relay-url pubkey privkey arg]
   (if (fn? arg)
     (poll-relay-envelopes! relay-url pubkey privkey nil arg)
     (poll-relay-envelopes! relay-url pubkey privkey arg nil)))
  ([relay-url pubkey privkey opts cb]
   (let [promise-fn
         (fn [resolve _]
           (let [now-ms (.now js/Date)
                 pk-hex (if (fressian/bytes? pubkey) (fressian/bytes->hex pubkey) (str pubkey))
                 since-seq (long (or (:since-seq opts) (:seq-gte opts) 0))
                 bseq (long (or (:since-broadcast-seq opts) 0))
                 nonce (or (:nonce opts) (fressian/bytes->hex (crypto/random-bytes 16)))
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
                          sub-param (assoc "subnets" sub-param))
                 q-str (str/join "&" (map (fn [[k v]] (str (js/encodeURIComponent (name k)) "=" (js/encodeURIComponent (str v)))) params))
                 base-url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/poll")
                 url (str base-url "?" q-str)
                 headers (cond-> {"X-Bitecho-Pubkey" pk-hex
                                  "X-Bitecho-Since-Seq" (str since-seq)
                                  "X-Bitecho-Since-Broadcast-Seq" (str bseq)
                                  "X-Bitecho-Timestamp-Ms" (str now-ms)
                                  "X-Bitecho-Nonce" nonce
                                  "X-Bitecho-Signature" sig}
                           (:timeout-ms opts) (assoc "X-Bitecho-Wait-Ms" (str (:timeout-ms opts)))
                           sub-param (assoc "X-Bitecho-Subnets" sub-param))
                 done (fn [res]
                        (if cb (cb res) (resolve res)))]
             (http-get-json! url headers (+ (or (:timeout-ms opts) 0) 5000) done)))]
     (if (fn? cb)
       (do (promise-fn nil nil) nil)
       (js/Promise. promise-fn)))))

(defn ack-relay-envelopes!
  "Acknowledges envelopes processed up to `up-to-seq` at `relay-url`."
  ([relay-url pubkey privkey up-to-seq] (ack-relay-envelopes! relay-url pubkey privkey up-to-seq nil nil))
  ([relay-url pubkey privkey up-to-seq arg]
   (if (fn? arg)
     (ack-relay-envelopes! relay-url pubkey privkey up-to-seq nil arg)
     (ack-relay-envelopes! relay-url pubkey privkey up-to-seq arg nil)))
  ([relay-url pubkey privkey up-to-seq opts cb]
   (let [promise-fn
         (fn [resolve _]
           (let [now-ms (.now js/Date)
                 pk-hex (if (fressian/bytes? pubkey) (fressian/bytes->hex pubkey) (str pubkey))
                 ack-seq (long (or up-to-seq 0))
                 ack-bseq (or (:ack-broadcast-seq opts) (:ack_broadcast_seq opts))
                 nonce (or (:nonce opts) (fressian/bytes->hex (crypto/random-bytes 16)))
                 sig (relay/sign-poll-request privkey {:pubkey pk-hex
                                                       :since-seq ack-seq
                                                       :timestamp-ms now-ms
                                                       :nonce nonce})
                 url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/ack")
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
                 payload (js/JSON.stringify (clj->js payload-map))
                 headers (cond-> {"X-Bitecho-Pubkey" pk-hex
                                  "X-Bitecho-Ack-Seq" (str ack-seq)
                                  "X-Bitecho-Timestamp-Ms" (str now-ms)
                                  "X-Bitecho-Nonce" nonce
                                  "X-Bitecho-Signature" sig}
                           ack-bseq (assoc "X-Bitecho-Ack-Broadcast-Seq" (str ack-bseq)))
                 done (fn [res-str]
                        (let [parsed (when res-str (read-json-str res-str))
                              res (or parsed {:ok false :error "network-or-timeout"})]
                          (if cb (cb res) (resolve res))))]
             (http-post-json! url payload headers (or (:timeout-ms opts) 5000) done)))]
     (if (fn? cb)
       (do (promise-fn nil nil) nil)
       (js/Promise. promise-fn)))))

(defn fetch-relay-chain-state!
  "Fetches chain-state and bootstrap info from `relay-url`."
  ([relay-url] (fetch-relay-chain-state! relay-url nil nil))
  ([relay-url arg]
   (if (fn? arg)
     (fetch-relay-chain-state! relay-url nil arg)
     (fetch-relay-chain-state! relay-url arg nil)))
  ([relay-url opts cb]
   (let [promise-fn
         (fn [resolve _]
           (let [base-url (str (relay/normalize-relay-base-url relay-url) "/relay/v1/chain-state")
                 q-parts (cond-> []
                           (:pubkey opts) (conj (str "pubkey=" (js/encodeURIComponent (str (:pubkey opts)))))
                           (:nonce opts) (conj (str "nonce=" (js/encodeURIComponent (str (:nonce opts))))))
                 url (if (seq q-parts) (str base-url "?" (str/join "&" q-parts)) base-url)
                 done (fn [res]
                        (if cb (cb res) (resolve res)))]
             (http-get-json! url (or (:timeout-ms opts) 12000) done)))]
     (if (fn? cb)
       (do (promise-fn nil nil) nil)
       (js/Promise. promise-fn)))))

(defn load-bootstrap-descriptor!
  "Loads and verifies a bootstrap descriptor from a local file or HTTP/HTTPS URL,
   invoking `(cb {:ok? true :descriptor desc})` or `(cb {:ok? false :error ...})`."
  [source-or-url opts cb]
  (let [finish-parse (fn [content remote-url?]
                       (try
                         (let [desc (parse-bootstrap-descriptor content)
                               expected-pk (:expected-authority-pubkey opts)
                               verify-sig? (:verify-signature? opts)
                               current-epoch (:current-epoch opts)
                               must-verify? (or (true? verify-sig?)
                                                (some? expected-pk)
                                                (and (not (false? verify-sig?))
                                                     (or remote-url? (some? (:signature desc)))))]
                           (when must-verify?
                             (let [auth-pk (or expected-pk default-devnet-authority-pubkey)
                                   v-res (light-core/verify-bootstrap-descriptor auth-pk desc current-epoch)]
                               (when-not (:ok? v-res)
                                 (throw (ex-info (str "Bootstrap descriptor verification failed: " (:error v-res))
                                                 {:type :UntrustedBootstrapDescriptor :error (:error v-res)})))))
                           (cb {:ok? true :descriptor desc}))
                         (catch :default e
                           (cb {:ok? false :error (or (ex-message e) "invalid-bootstrap-descriptor")}))))]
    (cond
      (map? source-or-url)
      (finish-parse source-or-url false)

      (and (string? source-or-url) (re-matches #"^https?://.*" source-or-url))
      (http-get-string! source-or-url 4000
                        (fn [body]
                          (if (and body (not (str/blank? body)))
                            (finish-parse body true)
                            (if (.existsSync node-fs "devnet/bootstrap.txt")
                              (finish-parse (.readFileSync node-fs "devnet/bootstrap.txt" "utf8") true)
                              (cb {:ok? false :error "descriptor-load-failed"})))))

      :else
      (if (.existsSync node-fs (str source-or-url))
        (finish-parse (.readFileSync node-fs (str source-or-url) "utf8") false)
        (cb {:ok? false :error "descriptor-file-not-found"})))))

;; =============================================================================
;; 2. Argument Parsing (`parse-light-node-args` & `build-one-shot-cmd-map`)
;; =============================================================================

(defn strip-sensitive-keys
  "Pure helper delegating to `bitecho.light-node.core/strip-sensitive-keys` (`M2a-1`)."
  [state]
  (light-core/strip-sensitive-keys state))

(defn- extract-flag-value
  [args flag default-val]
  (let [v (vec args)
        idx (.indexOf (to-array v) flag)]
    (if (and (>= idx 0) (< (inc idx) (count v)))
      (nth v (inc idx))
      default-val)))

(defn- extract-long-flag
  [args flag default-val]
  (if-let [v (extract-flag-value args flag nil)]
    (parse-long-safe v default-val)
    default-val))

(defn- parse-json-safe
  [s]
  (cond
    (map? s) s
    (nil? s) nil
    :else
    (try
      (js->clj (js/JSON.parse s))
      (catch :default _ nil))))

(defn build-one-shot-cmd-map
  "Constructs a JSON command map from parsed CLI arguments by delegating to the
   shared pure `.cljc` parser `bitecho.light-node.cli/build-cmd-map` (`BIP-005` / `D31.3`),
   enriching platform file arguments (`--file`, `--spec-file`, `--claim-file`) on Node.js."
  [verb args]
  (let [first-arg (first args)
        json-args (when (and (string? first-arg) (str/starts-with? (str/trim first-arg) "{"))
                    (parse-json-safe first-arg))
        raw-map (cli/build-cmd-map verb args)
        cmd (get raw-map "cmd")
        file-arg (extract-flag-value args "--file" nil)
        spec-file (extract-flag-value args "--spec-file" nil)
        claim-file (extract-flag-value args "--claim-file" nil)
        base-map
        (cond-> raw-map
          (and (= cmd "bip-submit") (nil? (get raw-map "spec_edn")) spec-file)
          (assoc "spec_edn" (try (.readFileSync node-fs spec-file "utf8") (catch :default _ nil)))

          (and (= cmd "bounty-settle") (nil? (get raw-map "claim_edn")) claim-file)
          (assoc "claim_edn" (try (.readFileSync node-fs claim-file "utf8") (catch :default _ nil)))

          (and (= cmd "artifact-put")
               (nil? (get raw-map "hex"))
               (nil? (get raw-map "text"))
               file-arg
               (.existsSync node-fs file-arg))
          (into (let [h (try (.toString (.readFileSync node-fs file-arg) "hex")
                             (catch :default _ nil))]
                  (if h {"hex" h "data_hex" h} {})))

          (and (= cmd "artifact-manifest-verify")
               file-arg
               (.existsSync node-fs file-arg))
          (assoc "manifest_json" (try (.readFileSync node-fs file-arg "utf8") (catch :default _ nil)))

          (and (contains? #{"web-release-publish" "web-release-rollback" "web-release-verify"} cmd)
               file-arg
               (.existsSync node-fs file-arg))
          (assoc "release_json" (try (.readFileSync node-fs file-arg "utf8") (catch :default _ nil)))

          (and (= cmd "import-poll") file-arg)
          (assoc "file_content" (or (try (.readFileSync node-fs file-arg "utf8") (catch :default _ nil)) ""))

          (and (contains? #{"import" "import-envelope"} cmd)
               (nil? (extract-flag-value args "--hex" nil))
               file-arg)
          (assoc "hex" (or (try (.readFileSync node-fs file-arg "utf8") (catch :default _ nil)) "")))]
    (if (map? json-args)
      (merge base-map json-args {"cmd" (get base-map "cmd")})
      base-map)))

(defn resolve-proxy-url
  "Pure helper resolving proxy URL from explicit flag or environment variables."
  ([explicit-proxy]
   (resolve-proxy-url explicit-proxy #(aget (.-env js/process) %)))
  ([explicit-proxy getenv-fn]
   (or (when (and (string? explicit-proxy) (seq (str/trim explicit-proxy)))
         (str/trim explicit-proxy))
       (some (fn [env-var]
               (when-let [val (getenv-fn env-var)]
                 (when (seq (str/trim (str val)))
                   (str/trim (str val)))))
             ["HTTPS_PROXY" "https_proxy" "HTTP_PROXY" "http_proxy"]))))

(defn resolve-relay-url
  "Pure helper resolving relay URL from explicit flag or BITECHO_RELAY_URL environment variable,
   normalized via `relay/normalize-relay-base-url`."
  ([explicit-relay]
   (resolve-relay-url explicit-relay #(aget (.-env js/process) %)))
  ([explicit-relay getenv-fn]
   (let [candidate (or (when (and (string? explicit-relay) (seq (str/trim explicit-relay)))
                         (str/trim explicit-relay))
                       (when-let [val (getenv-fn "BITECHO_RELAY_URL")]
                         (when (seq (str/trim (str val)))
                           (str/trim (str val)))))]
     (when candidate
       (relay/normalize-relay-base-url candidate)))))

(defn- extract-subverb-and-args
  "Extracts the subverb and remaining arguments, allowing global flags like
   --state-dir <path> or --control-port <port> to appear before or after the subverb."
  [tokens]
  (let [pre-verb-valued-flags #{"--state-dir" "--control-port" "--bootstrap" "--relay-url"
                                "--subnet-id" "--subnet" "--subscribe-subnets" "--subnets"
                                "--transport" "--proxy" "--timeout-ms" "--max-epoch-skew"
                                "--cmd-file" "--events-out" "--session-id" "--session"
                                "--min-seq" "--min-broadcast-seq" "--min-balance"
                                "--after-ts" "--ingress-tcp-port"
                                "--trusted-dac-anchors" "--trusted-deploy-authorities" "--turn-server" "--turn-username"
                                "--turn-password" "--turn-realm" "--sync-interval-ms"
                                "--price" "--price-max" "--burn" "--to" "--from"
                                "--callee" "--peer" "--receiver" "--recipient"
                                "--amount" "--text" "--message" "--payload-hex"
                                "--wait-open-ms" "--until-event"
                                "--path" "--cid" "--file" "--out" "--out-file" "--hex" "--seq" "--authority" "--prefix"
                                "--pin-version" "--auto-update-pointer" "--auto-update-interval-ms"}
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
   (parse-light-node-args args #(aget (.-env js/process) %)))
  ([args getenv-fn]
   (let [clean-args (if (= (first args) "light-node") (vec (rest args)) (vec args))
         first-tok (first clean-args)
         first-non-flag (if (and (string? first-tok) (str/starts-with? first-tok "--"))
                          (:subverb (extract-subverb-and-args clean-args))
                          first-tok)
         help? (boolean (or (some #{"--help" "-h"} clean-args) (= first-non-flag "help")))
         mcp? (boolean (or (some #{"--mcp"} clean-args) (= first-non-flag "mcp")))
         verb (cond help? "help" mcp? "mcp" :else (or first-non-flag "status"))
         no-poll? (boolean (some #{"--no-poll"} clean-args))
         ctl? (= verb "ctl")
         serve? (= verb "serve")
         daemon? (= verb "daemon")
         wait-event? (= verb "wait-event")
         serve-daemon? (and serve? (boolean (some #{"--daemon"} clean-args)))
         ctl-sub (when ctl? (extract-subverb-and-args (rest clean-args)))
         daemon-sub (when daemon? (extract-subverb-and-args (rest clean-args)))
         ctl-ensure? (and ctl? (= (:subverb ctl-sub) "ensure"))
         default-state-dir (.join node-path (.homedir node-os) ".bitecho" "light-node")
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
         no-auto-reg? (boolean (some #{"--no-auto-register-home-set"} clean-args))
         explicit-auto-reg? (boolean (some #{"--auto-register-home-set"} clean-args))
         auto-register-home-set? (and (not no-auto-reg?) (or explicit-auto-reg? (and serve? autonomous?)))
         home-set-price (extract-long-flag clean-args "--price" (when auto-register-home-set? 10))
         control-port (extract-long-flag clean-args "--control-port" (if serve? 5020 nil))
         raw-skew (extract-long-flag clean-args "--max-epoch-skew" nil)
         max-epoch-skew (when raw-skew (max 1 (long raw-skew)))
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
         pin-version (extract-flag-value clean-args "--pin-version" nil)
         auto-update-pointer (extract-flag-value clean-args "--auto-update-pointer" nil)
         auto-update-interval-ms (extract-long-flag clean-args "--auto-update-interval-ms" nil)
         auto-update-force-http? (boolean (some #{"--auto-update-force-http"} clean-args))
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
         relay-cli (extract-flag-value clean-args "--relay-url" nil)
         relay-url (resolve-relay-url relay-cli getenv-fn)
         subnet-id (extract-flag-value clean-args "--subnet-id" nil)
         keystore-passphrase-file (or (extract-flag-value clean-args "--keystore-passphrase-file" nil)
                                      (extract-flag-value clean-args "--passphrase-file" nil))
         backup-slot (extract-flag-value clean-args "--slot" nil)
         reset-network-state? (boolean (some #(= % "--reset-network-state") clean-args))
         trusted-dac-anchors-spec (flags/parse-trusted-dac-anchors-arg clean-args)
         trusted-dac-anchors (when (= :set (:action trusted-dac-anchors-spec))
                               (set (map #(or (light-core/normalize-pubkey-hex %) %)
                                         (:anchors trusted-dac-anchors-spec))))
         turn-server (extract-flag-value clean-args "--turn-server" nil)
         turn-username (extract-flag-value clean-args "--turn-username" nil)
         turn-password (extract-flag-value clean-args "--turn-password" nil)
         turn-realm (extract-flag-value clean-args "--turn-realm" nil)
         turn-force-relay? (boolean (some #{"--turn-force-relay"} clean-args))
         turn-config (when (or turn-server turn-username turn-password turn-realm turn-force-relay?)
                       (let [[h p] (when turn-server (str/split turn-server #":" 2))]
                         {:server-host (or h "127.0.0.1")
                          :server-port (if (and p (seq p)) (parse-long-safe p 3478) 3478)
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
       keystore-passphrase-file (assoc :keystore-passphrase-file keystore-passphrase-file)
       backup-slot (assoc :slot backup-slot)
       reset-network-state? (assoc :reset-network-state? true)
       timeout-ms (assoc :timeout-ms timeout-ms)
       ingress-tcp-port (assoc :ingress-tcp-port ingress-tcp-port)
       (seq trusted-dac-anchors) (assoc :trusted-dac-anchors trusted-dac-anchors)
       trusted-dac-anchors-spec (assoc :trusted-dac-anchors-spec trusted-dac-anchors-spec)
       (seq trusted-deploy-authorities) (assoc :trusted-deploy-authorities trusted-deploy-authorities)
       (some? sync?) (assoc :sync? sync?)
       (some? connect?) (assoc :connect? connect?)
       proxy-url (assoc :proxy proxy-url)
       pin-version (assoc :pin-version pin-version)
       auto-update-pointer (assoc :auto-update-pointer auto-update-pointer)
       auto-update-interval-ms (assoc :auto-update-interval-ms auto-update-interval-ms)
       auto-update-force-http? (assoc :auto-update-force-http? true)
       trusted-deploy-auths-present? (assoc :trusted-deploy-authorities trusted-deploy-authorities)
       relay-url (assoc :relay-url relay-url)
       turn-config (assoc :turn-config turn-config)))))

;; =============================================================================
;; 3. Atomic `state.fressian` & `node-identity.edn` Persistence (`0600`)
;; =============================================================================

(defn- write-bytes-atomic!
  [target-file u8-or-buf]
  (let [dir (.dirname node-path (str target-file))
        _ (.mkdirSync node-fs dir #js {:recursive true})
        tmp-file (.join node-path dir (str ".tmp-" (.-pid js/process) "-" (js/Date.now) "-" (rand-int 1000000)))
        buf (if (js/Buffer.isBuffer u8-or-buf)
              u8-or-buf
              (js/Buffer.from u8-or-buf))]
    (try
      (let [fd (.openSync node-fs tmp-file "w" 8r600)]
        (try
          (.writeSync node-fs fd buf 0 (.-length buf))
          (.fsyncSync node-fs fd)
          (finally
            (.closeSync node-fs fd))))
      (try (.chmodSync node-fs tmp-file 8r600) (catch :default _ nil))
      (.renameSync node-fs tmp-file (str target-file))
      true
      (finally
        (when (.existsSync node-fs tmp-file)
          (try (.unlinkSync node-fs tmp-file) (catch :default _ nil)))))))

(defonce ^:private light-state-writers-atom (atom {}))

(defn- write-bytes-atomic-async!
  "Zero-Sync-IO async atomic write via `fs.promises` with `0600` permissions (BIP-014 / P-ASYNC-2)."
  [target-file u8-or-buf]
  (let [target-str (str target-file)
        dir (.dirname node-path target-str)
        tmp-file (.join node-path dir (str ".tmp-" (.-pid js/process) "-" (js/Date.now) "-" (rand-int 1000000)))
        buf (if (js/Buffer.isBuffer u8-or-buf)
              u8-or-buf
              (js/Buffer.from u8-or-buf))]
    (-> (.mkdir node-fsp dir #js {:recursive true})
        (.then (fn [_] (.writeFile node-fsp tmp-file buf #js {:mode 8r600})))
        (.then (fn [_]
                 (-> (.chmod node-fsp tmp-file 8r600)
                     (.catch (fn [_] nil)))))
        (.then (fn [_] (.rename node-fsp tmp-file target-str)))
        (.then (fn [_] true))
        (.catch (fn [e]
                  (-> (.unlink node-fsp tmp-file)
                      (.catch (fn [_] nil))
                      (.then (fn [_] (js/Promise.reject e)))))))))

(declare dispatch-light-writer-effects!)

(defn- dispatch-light-writer-effects!
  [path-key writer-atom effects]
  (doseq [eff effects]
    (when (= :write-snapshot (:effect eff))
      (let [gen (:generation eff)
            ep (:epoch eff)
            st-to-save (:payload eff)]
        (js/setImmediate
         (fn []
           (try
             (let [encoded (light-core/encode-light-state st-to-save)]
               (-> (write-bytes-atomic-async! path-key encoded)
                   (.then (fn [_]
                            (let [next-effs (atom [])]
                              (swap! writer-atom
                                     (fn [wst]
                                       (let [[wst' effs] (snap/transition-writer
                                                          wst
                                                          {:type :write-succeeded :generation gen :epoch ep})]
                                         (reset! next-effs effs)
                                         wst')))
                              (dispatch-light-writer-effects! path-key writer-atom @next-effs))))
                   (.catch (fn [e]
                             (let [next-effs (atom [])]
                               (swap! writer-atom
                                      (fn [wst]
                                        (let [[wst' effs] (snap/transition-writer
                                                           wst
                                                           {:type :write-failed
                                                            :generation gen
                                                            :epoch ep
                                                            :error (or (.-message e) (str e))})]
                                          (reset! next-effs effs)
                                          wst')))
                               (dispatch-light-writer-effects! path-key writer-atom @next-effs))))))
             (catch :default e
               (let [next-effs (atom [])]
                 (swap! writer-atom
                        (fn [wst]
                          (let [[wst' effs] (snap/transition-writer
                                             wst
                                             {:type :write-failed
                                              :generation gen
                                              :epoch ep
                                              :error (or (.-message e) (str e))})]
                            (reset! next-effs effs)
                            wst')))
                 (dispatch-light-writer-effects! path-key writer-atom @next-effs))))))))))

(defn save-light-state-async!
  "Coalesces and offloads runtime `state.fressian` persistence via `bitecho.snapshot.core/transition-writer`
   and `fs.promises` so the Node.js event loop never blocks on disk I/O (BIP-014 / P-ASYNC-2)."
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

(defn save-light-state!
  "Persists sanitized light-node state via cross-platform Fressian (`state.fressian`)
   with atomic rename and `0600` permissions (`M2a-2`).
   Synchronous entry point reserved for one-shot CLI commands and graceful SIGTERM flush."
  [state-file state]
  (when (and (some? state-file) (not (str/blank? (str state-file))))
    (let [encoded (light-core/encode-light-state state)]
      (write-bytes-atomic! (str state-file) encoded)
      true)))

(defonce ^:private light-state-barrier-chains-atom (atom {}))

(defn save-light-state-barrier!
  "BIP-021 §2.4: Non-blocking generation-ordered async write-barrier (`write-temp` + async `fh.sync()` + `rename`)
   serialized per `state-file` via `fs.promises` (NEVER blocking `.fsyncSync` on Node.js's event loop).
   Returns a Promise that resolves once state is durably flushed."
  [state-file state]
  (if-not (and (some? state-file) (not (str/blank? (str state-file))))
    (js/Promise.resolve false)
    (let [path-key (str state-file)
          encoded (light-core/encode-light-state state)
          buf (if (.isBuffer js/Buffer encoded)
                encoded
                (.from js/Buffer (.-buffer encoded) (.-byteOffset encoded) (.-byteLength encoded)))
          tmp-path (str path-key ".barrier." (.now js/Date) ".tmp")
          prev-p (or (get @light-state-barrier-chains-atom path-key) (js/Promise.resolve true))
          next-p (-> prev-p
                     (.catch (fn [_] nil))
                     (.then (fn [_]
                              (-> (.open node-fsp tmp-path "w" 0600)
                                  (.then (fn [fh]
                                           (-> (.writeFile fh buf)
                                               (.then (fn [_] (.sync fh)))
                                               (.then (fn [_] (.close fh))
                                                      (fn [err]
                                                        (-> (.close fh)
                                                            (.catch (fn [_] nil))
                                                            (.then (fn [_] (throw err)))))))))
                                  (.then (fn [_] (.rename node-fsp tmp-path path-key)))
                                  (.then (fn [_] true))
                                  (.catch (fn [err]
                                            (try (.unlink node-fsp tmp-path) (catch :default _ nil))
                                            (throw err)))))))]
      (swap! light-state-barrier-chains-atom assoc path-key next-p)
      next-p)))

(def ^:private last-load-diagnostics-atom (atom []))

(defn- emit-stderr-diagnose!
  [d]
  (let [reason-str (if (keyword? (:reason d)) (name (:reason d)) (str (or (:reason d) "unknown")))
        payload (merge {"event" "diagnose" "reason" reason-str}
                       (when (:path d) {"path" (str (:path d))})
                       (when (:state-file d) {"state_file" (str (:state-file d))})
                       (when (:detail d) {"detail" (if (keyword? (:detail d)) (name (:detail d)) (str (:detail d)))})
                       (when (:hint d) {"hint" (str (:hint d))}))]
    (.write (.-stderr js/process) (str (.stringify js/JSON (clj->js payload)) "\n"))))

(defn- apply-startup-identity-and-load-diagnostics!
  "Propagates live identity `:keystore-security-tier`, merges identity + corrupt-state-load
   diagnostics into `[:diagnostics]`, marks `:pending-corrupt-auto-restore? true` on corrupt
   `state.fressian` fallback (F3b), and emits structured JSON `:diagnose` lines on stderr."
  [state identity]
  (let [load-diags @last-load-diagnostics-atom
        _ (reset! last-load-diagnostics-atom [])
        corrupt-fallback? (boolean (some #(= :local-state-corrupt-fallback (:reason %)) load-diags))
        all-diags (into (vec (or (:diagnostics identity) [])) load-diags)
        tier (or (:keystore-security-tier identity) (:keystore-security-tier state) :legacy-file-0600)
        st-with-diags (reduce (fn [st d]
                                (if-let [r (:reason d)]
                                  (update-in st [:diagnostics r] (fnil inc 0))
                                  st))
                              (assoc state :keystore-security-tier tier)
                              all-diags)]
    (doseq [d all-diags]
      (emit-stderr-diagnose! d))
    (cond-> st-with-diags
      corrupt-fallback? (assoc :pending-corrupt-auto-restore? true))))

(defn load-light-state!
  "Loads persisted light-node state from `state.fressian`, returning nil if absent or corrupt.
   Guards `(map? decoded)` so corrupt bytes never crash downstream state reducers, emitting
   a counted `:local-state-corrupt-fallback` diagnostic."
  [state-file]
  (when (and (some? state-file)
             (not (str/blank? (str state-file)))
             (.existsSync node-fs (str state-file)))
    (let [buf (.readFileSync node-fs (str state-file))
          u8 (crypto/compact-u8 buf)]
      (when (pos? (.-byteLength u8))
        (let [decoded (try
                        (light-core/decode-light-state u8)
                        (catch :default e
                          {:__corrupt_error__ (or (.-message e) (str e))}))]
          (if (or (not (map? decoded)) (contains? decoded :__corrupt_error__))
            (let [diag {:effect :diagnose
                        :reason :local-state-corrupt-fallback
                        :state-file (str state-file)
                        :detail (if (map? decoded) (:__corrupt_error__ decoded) "non-map-fressian-root")}]
              (swap! last-load-diagnostics-atom conj diag)
              nil)
            (do
              (when (light-core/legacy-v0238-state? decoded)
                (let [bak-path (str state-file ".v0238.bak")]
                  (when-not (.existsSync node-fs bak-path)
                    (try (write-bytes-atomic! bak-path buf) (catch :default _ nil)))))
              (light-core/migrate-light-state decoded))))))))

(defn- resolve-node-keystore-passphrase!
  [{:keys [passphrase passphrase-file keystore-passphrase-file]}]
  (let [pw-file (or passphrase-file keystore-passphrase-file)]
    (cond
      (and (string? passphrase) (not (str/blank? passphrase)))
      {:passphrase passphrase :diagnostics []}

      (and (string? pw-file) (not (str/blank? pw-file)))
      (if-not (.existsSync node-fs pw-file)
        {:passphrase nil
         :diagnostics [{:effect :diagnose
                        :reason :keystore-passphrase-file-not-found
                        :path pw-file}]}
        (let [st (.statSync node-fs pw-file)
              mode (bit-and (.-mode st) 0777)
              insecure? (pos? (bit-and mode 0077))
              pw (str/trim (.readFileSync node-fs pw-file "utf8"))]
          {:passphrase (when-not (str/blank? pw) pw)
           :diagnostics (if insecure?
                          [{:effect :diagnose
                            :reason :keystore-passphrase-file-insecure-perms
                            :path pw-file}]
                          [])}))

      :else
      (let [env-pw (aget (.-env js/process) "BITECHO_KEYSTORE_PASSPHRASE")]
        {:passphrase (when (and (string? env-pw) (not (str/blank? env-pw))) env-pw)
         :diagnostics []}))))

(defn load-or-create-light-identity!
  "Loads or creates persistent light-node identity in `<state-dir>/identity/` with `0600` permissions,
   supporting Row 11 Phase 1 encrypted `keystore.enc.edn` and seamless read-migration from legacy
   `node-identity.edn`, fully interchangeable with JVM `bitecho.shell.identity`."
  ([state-dir]
   (load-or-create-light-identity! state-dir {}))
  ([state-dir opts]
   (let [identity-dir (.join node-path (str state-dir) "identity")
         _ (.mkdirSync node-fs identity-dir #js {:recursive true})
         enc-file (.join node-path identity-dir "keystore.enc.edn")
         identity-file (.join node-path identity-dir "node-identity.edn")
         {:keys [passphrase diagnostics]} (resolve-node-keystore-passphrase! opts)
         kdf-iters (long (or (:kdf-iterations opts) kp/min-kdf-iterations))]
     (cond
       ;; Case 1: Encrypted keystore exists -> fail-closed unlock
       (.existsSync node-fs enc-file)
       (if (str/blank? (str passphrase))
         (throw (ex-info "Keystore unlock failed: missing passphrase"
                         {:error :keystore-unlock-failed
                          :diagnostics (conj (vec diagnostics)
                                             {:effect :diagnose :reason :keystore-unlock-failed :detail :missing-passphrase})}))
         (let [ks-map (try (edn/read-string (.readFileSync node-fs enc-file "utf8")) (catch :default _ nil))
               opened (kp/open-keystore-edn ks-map passphrase)]
           (when-not (:ok? opened)
             (throw (ex-info (str "Keystore unlock failed: " (name (or (:error opened) :invalid-passphrase-or-corrupt)))
                             {:error :keystore-unlock-failed
                              :diagnostics (conj (vec diagnostics)
                                                 {:effect :diagnose :reason :keystore-unlock-failed :detail (:error opened)})})))
           (let [seed (:seed-bytes opened)
                 provider (kp/make-memory-key-provider seed :encrypted-keystore-0600)
                 kp-map (crypto/pure-ed25519-keypair seed)
                 pub-hex (basalt/bytes->hex (:public kp-map))
                 priv-hex (basalt/bytes->hex (:private kp-map))
                 meta-m (:metadata opened)
                 gen-cert (when-not (and (string? (:cert-pem meta-m)) (string? (:key-pem meta-m)))
                            (dtls/generate-cert))
                 cert-pem (or (:cert-pem meta-m) (:cert-pem gen-cert))
                 key-pem (or (:key-pem meta-m) (:key-pem gen-cert))
                 fp (normalize-fingerprint (or (:fingerprint meta-m) (:fingerprint gen-cert)))
                 ice-creds (or (:ice-creds meta-m) (generate-random-ice-creds :light-node fp))]
             {:node-id :light-node
              :key-provider provider
              :keystore-security-tier :encrypted-keystore-0600
              :raw-pubkey-hex (kp/public-key provider)
              :pubkey-hex pub-hex
              :privkey-hex priv-hex
              :privkey-bytes (:private kp-map)
              :keypair kp-map
              :fingerprint fp
              :ice-creds ice-creds
              :cert-data {:cert cert-pem
                          :key key-pem
                          :fingerprint fp}
              :diagnostics (vec diagnostics)})))

       ;; Case 2: Legacy node-identity.edn exists -> migrate if passphrase supplied, else loud advisory
       (.existsSync node-fs identity-file)
       (let [edn-data (edn/read-string (.readFileSync node-fs identity-file "utf8"))]
         (when-not (and (map? edn-data)
                        (:pubkey-hex edn-data)
                        (:privkey-hex edn-data)
                        (:cert-pem edn-data)
                        (:key-pem edn-data)
                        (:fingerprint edn-data)
                        (:ice-creds edn-data))
           (throw (ex-info "Corrupt node-identity.edn file: missing required fields"
                           {:file identity-file})))
         (let [pub-bytes (basalt/hex->bytes (:pubkey-hex edn-data))
               priv-bytes (basalt/hex->bytes (:privkey-hex edn-data))
               seed (kp/extract-ed25519-seed priv-bytes)
               fp (normalize-fingerprint (:fingerprint edn-data))
               base {:node-id :light-node
                     :pubkey-hex (:pubkey-hex edn-data)
                     :privkey-hex (:privkey-hex edn-data)
                     :privkey-bytes priv-bytes
                     :keypair {:public pub-bytes :private priv-bytes}
                     :fingerprint fp
                     :ice-creds (:ice-creds edn-data)
                     :cert-data {:cert (:cert-pem edn-data)
                                 :key (:key-pem edn-data)
                                 :fingerprint fp}}]
           (if-not (str/blank? (str passphrase))
             (let [sealed-ks (kp/seal-keystore-edn {:pubkey (:pubkey-hex edn-data)
                                                    :seed-bytes seed
                                                    :passphrase passphrase
                                                    :iterations kdf-iters
                                                    :created-ms (.now js/Date)
                                                    :metadata {:cert-pem (:cert-pem edn-data)
                                                               :key-pem (:key-pem edn-data)
                                                               :fingerprint fp
                                                               :ice-creds (:ice-creds edn-data)}})
                   _ (write-bytes-atomic! enc-file (js/Buffer.from (pr-str sealed-ks) "utf8"))
                   verify-open (kp/open-keystore-edn (edn/read-string (.readFileSync node-fs enc-file "utf8")) passphrase)]
               (when-not (:ok? verify-open)
                 (throw (ex-info "Keystore migration verification failed"
                                 {:error :keystore-unlock-failed})))
               (let [provider (kp/make-memory-key-provider seed :encrypted-keystore-0600)]
                 (assoc base
                        :key-provider provider
                        :keystore-security-tier :encrypted-keystore-0600
                        :raw-pubkey-hex (kp/public-key provider)
                        :diagnostics (conj (vec diagnostics)
                                           {:effect :diagnose :reason :keystore-migrated-to-encrypted :path enc-file}))))
             (let [provider (kp/make-memory-key-provider seed :legacy-file-0600)]
               (assoc base
                      :key-provider provider
                      :keystore-security-tier :legacy-file-0600
                      :raw-pubkey-hex (kp/public-key provider)
                      :diagnostics (conj (vec diagnostics)
                                         {:effect :diagnose
                                          :reason :legacy-plaintext-keystore-in-use
                                          :hint "Provide --keystore-passphrase-file or BITECHO_KEYSTORE_PASSPHRASE to migrate to keystore.enc.edn (0600)."}))))))

       ;; Case 3: Fresh state-dir
       :else
       (let [cert-data (dtls/generate-cert)
             fp (normalize-fingerprint (:fingerprint cert-data))
             cert-pem (:cert-pem cert-data)
             key-pem (:key-pem cert-data)
             ice-creds (generate-random-ice-creds :light-node fp)
             kp-map (crypto/generate-keypair)
             seed (kp/extract-ed25519-seed (:private kp-map))
             pub-hex (basalt/bytes->hex (:public kp-map))
             priv-hex (basalt/bytes->hex (:private kp-map))]
         (if-not (str/blank? (str passphrase))
           (let [sealed-ks (kp/seal-keystore-edn {:pubkey pub-hex
                                                  :seed-bytes seed
                                                  :passphrase passphrase
                                                  :iterations kdf-iters
                                                  :created-ms (.now js/Date)
                                                  :metadata {:cert-pem cert-pem
                                                             :key-pem key-pem
                                                             :fingerprint fp
                                                             :ice-creds ice-creds}})
                 _ (write-bytes-atomic! enc-file (js/Buffer.from (pr-str sealed-ks) "utf8"))
                 provider (kp/make-memory-key-provider seed :encrypted-keystore-0600)]
             {:node-id :light-node
              :key-provider provider
              :keystore-security-tier :encrypted-keystore-0600
              :raw-pubkey-hex (kp/public-key provider)
              :pubkey-hex pub-hex
              :privkey-hex priv-hex
              :privkey-bytes (:private kp-map)
              :keypair kp-map
              :fingerprint fp
              :ice-creds ice-creds
              :cert-data {:cert cert-pem :key key-pem :fingerprint fp}
              :diagnostics (vec diagnostics)})
           (let [data-to-save {:pubkey-hex pub-hex
                               :privkey-hex priv-hex
                               :cert-pem cert-pem
                               :key-pem key-pem
                               :fingerprint fp
                               :ice-creds ice-creds}
                 _ (write-bytes-atomic! identity-file (js/Buffer.from (pr-str data-to-save) "utf8"))
                 provider (kp/make-memory-key-provider seed :legacy-file-0600)]
             {:node-id :light-node
              :key-provider provider
              :keystore-security-tier :legacy-file-0600
              :raw-pubkey-hex (kp/public-key provider)
              :pubkey-hex pub-hex
              :privkey-hex priv-hex
              :privkey-bytes (:private kp-map)
              :keypair kp-map
              :fingerprint fp
              :ice-creds ice-creds
              :cert-data {:cert cert-pem :key key-pem :fingerprint fp}
              :diagnostics (conj (vec diagnostics)
                                 {:effect :diagnose
                                  :reason :legacy-plaintext-keystore-in-use
                                  :hint "Provide --keystore-passphrase-file or BITECHO_KEYSTORE_PASSPHRASE to use encrypted keystore.enc.edn (0600)."})})))))))

(declare pack-node-encrypted-backup restore-node-encrypted-backup)

(defn- node-artifact-base-url
  [relay-url]
  (-> (str (or relay-url "https://ns1.bitecho.org"))
      (str/replace #"/relay/v1/?$" "")
      (str/replace #"/+$" "")))

(defn- node-http-request!
  "Low-level Node.js HTTP/HTTPS request helper returning `{:ok? :status :body-buf :error}` via `cb`."
  [url-str method headers body-buf timeout-ms cb]
  (try
    (let [u (js/URL. url-str)
          is-https? (= (.-protocol u) "https:")
          mod (if is-https? node-https node-http)
          done (atom false)
          finish! (fn [res]
                    (when (compare-and-set! done false true)
                      (cb res)))
          req-opts #js {:hostname (.-hostname u)
                        :port (when (not (str/blank? (.-port u))) (js/parseInt (.-port u) 10))
                        :path (str (.-pathname u) (.-search u))
                        :method method
                        :headers (clj->js headers)
                        :timeout (or timeout-ms 10000)}
          req (.request mod req-opts
                        (fn [res]
                          (let [chunks #js []
                                code (.-statusCode res)]
                            (.on res "data" (fn [c] (.push chunks c)))
                            (.on res "end" (fn []
                                             (let [buf (.concat js/Buffer chunks)]
                                               (finish! {:ok? (and (>= code 200) (<= code 299))
                                                         :status code
                                                         :body-buf buf}))))
                            (.on res "error" (fn [e]
                                               (finish! {:ok? false :status 0 :error (or (.-message e) (str e))}))))))]
      (.on req "timeout" (fn []
                           (.destroy req)
                           (finish! {:ok? false :status 0 :error "timeout"})))
      (.on req "error" (fn [e]
                         (finish! {:ok? false :status 0 :error (or (.-message e) (str e))})))
      (when body-buf
        (.write req body-buf))
      (.end req))
    (catch :default e
      (cb {:ok? false :status 0 :error (or (.-message e) (str e))}))))

(defn- handle-node-stage-c-verb!
  "Handles Row 6 & Row 11 Phase 1 shell verbs (`backup-put`, `backup-restore`, `identity-migrate`)
   uniformly across Node.js Light one-shot CLI and `ctl` daemon control server."
  [verb cmd-map state-atom identity state-dir state-file relay-url opts cb]
  (case verb
    "backup-put"
    (let [st @state-atom
          provider (:key-provider identity)
          sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) "bitecho.org/infra"))
          slot (or (get cmd-map "slot") (:slot cmd-map) (:slot opts) backup/default-backup-slot)
          next-seq (inc (long (or (:backup-seq st) 0)))
          packed (pack-node-encrypted-backup {:key-provider provider
                                              :state st
                                              :subnet-id sub-id
                                              :slot slot
                                              :seq next-seq
                                              :now-ms (.now js/Date)})]
      (if-not (:ok? packed)
        (let [err (errors/canonical-error (:error packed) {:stage "backup-pack"})
              st' (errors/record-error-diagnostic st err)]
          (reset! state-atom st')
          (cb {:ok? false :state st' :response (errors/canonical-error->wire err)}))
        (let [base-url (node-artifact-base-url (or (get cmd-map "relay_url") (get cmd-map "relay-url")
                                                   (:relay-url cmd-map) relay-url (:relay-url opts)))
              own-pk (kp/public-key provider)
              blob (:blob packed)
              ptr (:pointer packed)
              blob-buf (.from js/Buffer (:blob/bytes blob))]
          (node-http-request!
           (str base-url "/artifact/v1/blob")
           "POST"
           {"Content-Type" (or (:blob/media-type blob) "application/x-bitecho-e2ee-fressian")
            "X-Bitecho-Blob-Cid" (:blob/cid blob)
            "X-Bitecho-Pubkey" own-pk
            "Content-Length" (.-length blob-buf)}
           blob-buf
           10000
           (fn [b-res]
             (if-not (:ok? b-res)
               (let [err (errors/canonical-error :storage-publish-failed {:stage "blob" :status (:status b-res)})
                     st' (-> (errors/record-error-diagnostic @state-atom err)
                             (update-in [:diagnostics :backup-publish-failed] (fnil inc 0)))]
                 (emit-stderr-diagnose! {:reason :backup-publish-failed :detail (str "blob-http-" (:status b-res))})
                 (reset! state-atom st')
                 (when state-file (try (save-light-state! state-file st') (catch :default _ nil)))
                 (cb {:ok? false :state st' :response (errors/canonical-error->wire err)}))
               (let [ptr-json (.stringify js/JSON
                                          (clj->js {"subnet" (:pointer/subnet ptr)
                                                    "path" (:pointer/path ptr)
                                                    "authority" (:pointer/authority ptr)
                                                    "seq" (:pointer/seq ptr)
                                                    "leader_term" (:pointer/leader-term ptr)
                                                    "target" (:pointer/target ptr)
                                                    "proof" {"type" "self"}
                                                    "sig" (:pointer/sig ptr)}))
                     ptr-buf (.from js/Buffer ptr-json "utf8")]
                 (node-http-request!
                  (str base-url "/artifact/v1/pointer")
                  "POST"
                  {"Content-Type" "application/json; charset=utf-8"
                   "X-Bitecho-Pubkey" own-pk
                   "Content-Length" (.-length ptr-buf)}
                  ptr-buf
                  10000
                  (fn [p-res]
                    (if-not (:ok? p-res)
                      (let [err (errors/canonical-error :storage-publish-failed {:stage "pointer" :status (:status p-res)})
                            st' (-> (errors/record-error-diagnostic @state-atom err)
                                    (update-in [:diagnostics :backup-publish-failed] (fnil inc 0)))]
                        (emit-stderr-diagnose! {:reason :backup-publish-failed :detail (str "pointer-http-" (:status p-res))})
                        (reset! state-atom st')
                        (when state-file (try (save-light-state! state-file st') (catch :default _ nil)))
                        (cb {:ok? false :state st' :response (errors/canonical-error->wire err)}))
                      (let [st' (assoc @state-atom
                                       :backup-seq next-seq
                                       :backup-last-cid (:cid packed)
                                       :backup-path (:path packed))]
                        (reset! state-atom st')
                        (when state-file (try (save-light-state! state-file st') (catch :default _ nil)))
                        (cb {:ok? true
                             :state st'
                             :response {"ok" true
                                        "seq" next-seq
                                        "cid" (:cid packed)
                                        "path" (:path packed)
                                        "subnet_id" sub-id}}))))))))))))

    "backup-restore"
    (let [st @state-atom
          provider (:key-provider identity)
          own-pk (kp/public-key provider)
          slot (or (get cmd-map "slot") (:slot cmd-map) (:slot opts) backup/default-backup-slot)
          sub-id (str (or (get cmd-map "subnet_id") (get cmd-map "subnet-id") (:subnet-id cmd-map) "bitecho.org/infra"))
          path (backup/backup-pointer-path own-pk slot)
          base-url (node-artifact-base-url (or (get cmd-map "relay_url") (get cmd-map "relay-url")
                                               (:relay-url cmd-map) relay-url (:relay-url opts)))
          list-url (str base-url "/artifact/v1/list?prefix=" (js/encodeURIComponent path))]
      (node-http-request!
       list-url "GET" {} nil 10000
       (fn [l-res]
         (if-not (:ok? l-res)
           (cb {:ok? false :state st :response {"ok" false "error" "backup-pointer-fetch-failed" "status" (:status l-res)}})
           (let [parsed (try (parse-json-safe (.toString (:body-buf l-res) "utf8")) (catch :default _ nil))
                 ptrs (or (get parsed "pointers") [])
                 matched (first (filter #(= (get % "path") path) ptrs))]
             (if-not matched
               (cb {:ok? false :state st :response {"ok" false "error" "backup-not-found" "path" path}})
               (let [cid (get matched "cid")
                     ptr-map {:pointer/subnet (or (get matched "subnet") sub-id)
                              :pointer/path (get matched "path")
                              :pointer/authority (get matched "authority")
                              :pointer/seq (long (or (get matched "seq") 1))
                              :pointer/leader-term (long (or (get matched "leader_term") 1))
                              :pointer/target cid
                              :pointer/proof {:proof/type :self}
                              :pointer/sig (get matched "sig")}]
                 (node-http-request!
                  (str base-url "/artifact/v1/blob/" cid) "GET" {} nil 10000
                  (fn [b-res]
                    (if-not (:ok? b-res)
                      (cb {:ok? false :state st :response {"ok" false "error" "backup-blob-fetch-failed" "status" (:status b-res)}})
                      (let [blob-map {:blob/cid cid
                                      :blob/media-type "application/x-bitecho-e2ee-fressian"
                                      :blob/bytes (crypto/compact-u8 (:body-buf b-res))}
                            res (restore-node-encrypted-backup {:key-provider provider
                                                                :local-state @state-atom
                                                                :blob blob-map
                                                                :pointer ptr-map
                                                                :slot slot
                                                                :min-expected-seq (or (get cmd-map "min_expected_seq") (:min-expected-seq cmd-map))
                                                                :observed-hwm (or (get cmd-map "observed_hwm") (:observed-hwm cmd-map))})]
                        (if-not (:ok? res)
                          (cb {:ok? false :state @state-atom :response {"ok" false "error" (name (or (:error res) :backup-restore-failed))}})
                          (let [st' (assoc (:state res) :keystore-security-tier (:keystore-security-tier identity))]
                            (doseq [e (:effects res)]
                              (when (= :diagnose (:effect e))
                                (emit-stderr-diagnose! e)))
                            (reset! state-atom st')
                            (when state-file (try (save-light-state! state-file st') (catch :default _ nil)))
                            (cb {:ok? true
                                 :state st'
                                 :response {"ok" true
                                            "restored" true
                                            "seq" (:seq res)
                                            "cid" (:cid res)
                                            "path" (:path res)
                                            "summary" (:summary res)}}))))))))))))))

    "identity-migrate"
    (let [pw-file (or (get cmd-map "keystore_passphrase_file")
                      (get cmd-map "keystore-passphrase-file")
                      (get cmd-map "passphrase_file")
                      (get cmd-map "passphrase-file")
                      (:keystore-passphrase-file opts))
          {:keys [passphrase diagnostics]} (resolve-node-keystore-passphrase!
                                            {:passphrase (or (get cmd-map "passphrase") (:passphrase cmd-map))
                                             :passphrase-file pw-file})]
      (doseq [d diagnostics] (emit-stderr-diagnose! d))
      (if (str/blank? (str passphrase))
        (cb {:ok? false
             :state @state-atom
             :response (errors/canonical-error->wire (errors/canonical-error :keystore-unlock-failed {:detail "missing-passphrase"}))})
        (let [identity-dir (.join node-path (str state-dir) "identity")
              _ (.mkdirSync node-fs identity-dir #js {:recursive true})
              enc-file (.join node-path identity-dir "keystore.enc.edn")
              seed (kp/extract-ed25519-seed (:privkey-bytes identity))
              sealed-ks (kp/seal-keystore-edn {:pubkey (:pubkey-hex identity)
                                               :seed-bytes seed
                                               :passphrase passphrase
                                               :created-ms (.now js/Date)
                                               :metadata {:cert-pem (get-in identity [:cert-data :cert])
                                                          :key-pem (get-in identity [:cert-data :key])
                                                          :fingerprint (:fingerprint identity)
                                                          :ice-creds (:ice-creds identity)}})
              _ (write-bytes-atomic! enc-file (js/Buffer.from (pr-str sealed-ks) "utf8"))
              verify-open (kp/open-keystore-edn (edn/read-string (.readFileSync node-fs enc-file "utf8")) passphrase)]
          (if-not (:ok? verify-open)
            (cb {:ok? false
                 :state @state-atom
                 :response (errors/canonical-error->wire (errors/canonical-error :keystore-unlock-failed {:detail "migration-verify-failed"}))})
            (let [st' (-> @state-atom
                          (assoc :keystore-security-tier :encrypted-keystore-0600)
                          (update-in [:diagnostics :keystore-migrated-to-encrypted] (fnil inc 0)))]
              (emit-stderr-diagnose! {:reason :keystore-migrated-to-encrypted :path enc-file})
              (reset! state-atom st')
              (when state-file (try (save-light-state! state-file st') (catch :default _ nil)))
              (cb {:ok? true
                   :state st'
                   :response {"ok" true
                              "migrated" true
                              "keystore_security_tier" "encrypted-keystore-0600"
                              "path" enc-file}}))))))))

(defn pack-node-encrypted-backup
  "Node.js Light encrypted backup packer backed by `bitecho.backup.core` (Row 6)."
  [{:keys [key-provider state subnet-id slot seq now-ms]}]
  (backup/pack-encrypted-backup {:key-provider key-provider
                                 :state state
                                 :subnet-id (or subnet-id "bitecho.org/infra")
                                 :slot slot
                                 :seq (or seq (inc (long (or (:backup-seq state) 0))))
                                 :node-role :nodejs
                                 :now-ms (or now-ms (.now js/Date))}))

(defn restore-node-encrypted-backup
  "Node.js Light encrypted backup restore backed by `bitecho.backup.core` (Row 6)."
  [{:keys [key-provider local-state blob pointer slot min-expected-seq observed-hwm]}]
  (let [unpacked (backup/unpack-encrypted-backup {:key-provider key-provider
                                                  :blob blob
                                                  :pointer pointer
                                                  :slot slot
                                                  :min-expected-seq min-expected-seq})]
    (if-not (:ok? unpacked)
      {:ok? false :error (:error unpacked) :state local-state :effects (:effects unpacked)}
      (let [merged (backup/merge-restored-state local-state (:payload unpacked) observed-hwm)]
        {:ok? true
         :seq (:seq unpacked)
         :cid (:cid unpacked)
         :path (:path unpacked)
         :summary (:summary merged)
         :state (:state merged)
         :effects (:effects merged)}))))

;; =============================================================================
;; 4. Single-Authority Shell Lifecycle State Machine (Rules 4 & 5)
;; =============================================================================

(defn ordered-validator-candidates
  "Builds a deterministic, failover-prioritized list of validator candidate nodes."
  [bootstrap-descriptor home-set validator-cursor]
  (let [nodes-map (get bootstrap-descriptor :nodes {})
        norm-node-id (fn norm-id [item]
                       (cond
                         (keyword? item) item
                         (string? item) (keyword item)
                         (map? item) (norm-id (or (:node-id item) (:id item) (:node item)))
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
            cursor (max 0 (or validator-cursor 0))
            rot (mod cursor n)]
        (into (subvec base-candidates rot)
              (subvec base-candidates 0 rot))))))

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
  [conn eff]
  (-> conn
      (assoc :last-diagnostic eff)
      (update :diagnostics (fn [ds] (vec (take-last 64 (conj (vec ds) eff)))))))

(defn transition-conn
  "Pure reducer transitioning connection lifecycle state and returning `[new-conn effects]`."
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
        (let [next-gen (or (:generation event) (inc (:generation conn 0)))
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
              target-gen (or (:generation event) (:generation conn 0))
              failed-nodes (vec (or (:failed-nodes event) []))
              failover-attempts (or (:failover-attempts event) (count failed-nodes))
              failed-drop-count (count failed-nodes)
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
                                  :failover-count (+ (:failover-count conn 0) failover-attempts)
                                  :dropped (+ (:dropped conn 0) failed-drop-count)
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
                                  :validator-cursor (inc (:validator-cursor conn 0))
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
                                  :validator-cursor (inc (:validator-cursor conn 0))
                                  :error err
                                  :last-error err)
                           (push-diagnostic diag-eff))]
          [new-conn effects])

        :encode-failed
        (let [err (or (:error event) "encode-failed")
              diag-eff {:effect :diagnose :reason :encode-failed :error err}
              new-conn (-> conn
                           (assoc :last-error err
                                  :dropped (inc (:dropped conn 0))
                                  :consecutive-send-failures (inc (:consecutive-send-failures conn 0)))
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
                                  :validator-cursor (inc (:validator-cursor conn 0))
                                  :error err
                                  :last-error err
                                  :dropped (inc (:dropped conn 0))
                                  :consecutive-send-failures (inc (:consecutive-send-failures conn 0)))
                           (push-diagnostic diag-eff))]
          [new-conn effects])

        :persist-failed
        (let [err (or (:error event) "persist-failed")
              diag-eff {:effect :diagnose :reason :persist-failed :error err}
              new-conn (-> conn
                           (assoc :last-error err
                                  :dropped (inc (:dropped conn 0)))
                           (push-diagnostic diag-eff))]
          [new-conn [diag-eff]])

        :auto-sync-failed
        (let [err (or (:error event) "auto-sync-failed")
              diag-eff {:effect :diagnose :reason :auto-sync-failed :error err}
              new-conn (-> conn
                           (assoc :last-error err)
                           (push-diagnostic diag-eff))]
          [new-conn [diag-eff]])

        :finalized-epoch-stalled
        (let [diag-eff (or (:diagnose event)
                           {:effect :diagnose
                            :type :diagnose
                            :reason :finalized-epoch-stalled
                            :finalized-epoch (:finalized-epoch event)
                            :stall-duration-ms (:stall-duration-ms event)})
              new-conn (-> conn
                           (assoc :last-error "finalized-epoch-stalled")
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
  "Executes boundary side-effects resulting from connection state machine transitions."
  ([effects] (execute-conn-effects! effects nil))
  ([effects opts]
   (doseq [eff effects]
     (case (:effect eff)
       :close-node
       (when-let [n (:node eff)]
         (try (api/close! n) (catch :default _ nil)))

       (:diagnose :ignore-stale)
       (do
         (when-let [dfn (:diagnose-fn opts)]
           (when (fn? dfn)
             (try (dfn eff) (catch :default _ nil))))
         (when-let [datom (:diagnostics-atom opts)]
           (when (satisfies? IAtom datom)
             (swap! datom (fn [curr] (vec (take-last 64 (conj (vec curr) eff))))))))

       nil))))

(defn apply-conn-event!
  "Atomically transitions `conn-atom` via `transition-conn` and executes effects outside the swap."
  ([conn-atom event] (apply-conn-event! conn-atom event nil))
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
             :diagnostics_buffered diag-count}
      (:last-diagnostic conn) (assoc :last_diagnostic (:last-diagnostic conn)))))

(defonce ^:private mesh-chunk-handlers-atom (atom {}))

(defn- try-dispatch-mesh-chunk-res!
  "Intercepts inbound `:artifact-blob-chunk-res` frames strictly by `:req-id` (BIP-022 Stage D.1).
   Returns true if handled, false otherwise. Emits counted Rule 5 `:mesh-chunk-dispatch-error`
   diagnostic if a chunk handler throws (zero silent catches)."
  ([payload]
   (try-dispatch-mesh-chunk-res! payload nil nil))
  ([payload state-atom event-out]
   (when (seq @mesh-chunk-handlers-atom)
     (let [decoded (try (light-core/thaw-payload payload) (catch :default _ nil))]
       (when (and (map? decoded) (= :artifact-blob-chunk-res (:type decoded)))
         (let [req-id (:req-id decoded)
               cid (str (:cid decoded))
               handler (when req-id (get @mesh-chunk-handlers-atom req-id))]
           (when (fn? handler)
             (try
               (handler decoded)
               (catch :default e
                 (let [msg (or (ex-message e) (str e))]
                   (when state-atom
                     (swap! state-atom update-in [:diagnostics :mesh-chunk-dispatch-error] (fnil inc 0)))
                   (when event-out
                     (event-out {"event" "auto-update-diagnose"
                                 "reason" "mesh-chunk-dispatch-error"
                                 "cid" cid
                                 "detail" msg})))))
             true)))))))

(defn- sync-conn-diagnostics!
  "Synchronizes derived runtime liveness, conn-diagnostics, and live :runtime-ctx into `state-atom`."
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
                                      {:runtime :nodejs
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

(defn connection-live?
  "Checks if connection is marked ok and open, channel-id is present, and state is connected."
  [conn state]
  (and (boolean (:ok? conn))
       (or (nil? (:phase conn)) (= :open (:phase conn)))
       (not (false? (:connected? state)))
       (if-let [cid (:channel-id conn)]
         (if (satisfies? IDeref cid)
           (some? @cid)
           (some? cid))
         true)))

(defn send-all-envelopes!
  "Transmits all envelopes using `send-fn` and returns true only if all succeeded.
   Supports optional callback `(send-all-envelopes! send-fn envelopes cb)` chaining
   sequential delivery over async transports (such as HTTP gateway relay)."
  ([send-fn envelopes]
   (if (empty? envelopes)
     true
     (and (fn? send-fn)
          (every? true? (mapv #(boolean (send-fn %)) envelopes)))))
  ([send-fn envelopes cb]
   (if (empty? envelopes)
     (when (fn? cb) (cb true))
     (letfn [(step [rem]
               (if-let [env (first rem)]
                 (if (fn? send-fn)
                   (send-fn env (fn [ok?]
                                  (if ok?
                                    (step (rest rem))
                                    (when (fn? cb) (cb false)))))
                   (when (fn? cb) (cb false)))
                 (when (fn? cb) (cb true))))]
       (step (vec envelopes))))))

(defn build-reconnect-recovery-envelopes
  "Pure helper to build recovery envelopes upon reconnection."
  [state privkey-bytes]
  (if-not privkey-bytes
    []
    (let [home-set (:home-set state)
          home-set-envs (if (seq home-set)
                          (let [price (or (get-in state [:rendezvous-policy :price]) 10)
                                pub (:pubkey state)
                                curr-epoch (:epoch state)
                                ice-ufrag (get-in state [:ice-creds :ufrag])
                                ice-pwd (get-in state [:ice-creds :pwd])
                                env-curr (light-core/build-home-set-envelope pub privkey-bytes home-set price curr-epoch ice-ufrag ice-pwd)
                                env-nil (light-core/build-home-set-envelope pub privkey-bytes home-set price nil ice-ufrag ice-pwd)]
                            [env-curr env-nil])
                          [])
          replay-envs (light-core/build-unacked-replay-envelopes state privkey-bytes)]
      (into (vec home-set-envs) replay-envs))))

;; =============================================================================
;; 5. Async DataChannel Dialing, Validator Quorum Sync, & Directory Fetching
;; =============================================================================

(defn- validate-node-fingerprints
  [descriptor]
  (let [nodes (vals (get descriptor :nodes {}))]
    (when (some (fn [node]
                  (let [raw-fp (:fingerprint node)]
                    (not (and (string? raw-fp)
                              (try (boolean (normalize-fingerprint raw-fp))
                                   (catch :default _ false))))))
                nodes)
      {:ok? false :error "bad-fingerprint"})))

(defn- dispatch-auto-reply!
  [envelopes send-fn-atom state-atom conn-atom event-out reconnect-fn conn-opts]
  (let [live? (and @send-fn-atom (not (false? (:connected? @state-atom))))
        sent? (when live?
                (send-all-envelopes! @send-fn-atom envelopes))]
    (when-not sent?
      (if reconnect-fn
        (reconnect-fn
         (fn [reconn]
           (when-not (and (:ok? reconn)
                          (send-all-envelopes! (:send-fn reconn) envelopes))
             (let [err (or (:error reconn) "connection-closed")]
               (when conn-atom
                 (apply-conn-event! conn-atom {:type :send-failed :error err} conn-opts))
               (when state-atom
                 (swap! state-atom assoc :connected? false :connection-error err))
               (sync-conn-diagnostics! state-atom conn-atom)
               (when event-out
                 (event-out {"event" "connection-failed" "connected" false "error" err}))))))
        (let [err "connection-closed"]
          (when conn-atom
            (apply-conn-event! conn-atom {:type :send-failed :error err} conn-opts))
          (when state-atom
            (swap! state-atom assoc :connected? false :connection-error err))
          (sync-conn-diagnostics! state-atom conn-atom)
          (when event-out
            (event-out {"event" "connection-failed" "connected" false "error" err})))))))

(defn make-client-callbacks
  "Creates callback handlers for Node.js DataChannel connection."
  [client-node channel-id settle-fn! send-fn-atom ctx]
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
                    (settle-fn! :open))))
     :on-message (fn [evt]
                   (if (and conn-atom (some? generation) (< generation (:generation @conn-atom 0)))
                     (do
                       (apply-conn-event! conn-atom {:type :on-message :generation generation} cb-opts)
                       (sync-conn-diagnostics! state-atom conn-atom))
                     (do
                       (when-let [cid (:channel-id evt)]
                         (reset! channel-id cid))
                       (when-let [payload (:payload evt)]
                         (when-not (try-dispatch-mesh-chunk-res! payload state-atom event-out)
                           (when state-atom
                             (let [st @state-atom
                                   res (light-core/handle-wire-payload st payload (:privkey-bytes identity))]
                               (reset! state-atom (:state res))
                               (when (and state-file (not= st (:state res)))
                                 (try
                                   (save-light-state-async! state-file (:state res))
                                   (catch :default e
                                     (when conn-atom
                                       (apply-conn-event! conn-atom
                                                          {:type :persist-failed
                                                           :error (or (ex-message e) "persist-failed")}
                                                          cb-opts)
                                       (sync-conn-diagnostics! state-atom conn-atom)))))
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
                   (settle-fn! :bad-fingerprint)))
     :on-close (fn [_]
                 (settle-fn! :connect-failed)
                 (if conn-atom
                   (if (and (some? generation)
                            (pos? (:generation @conn-atom 0))
                            (not= generation (:generation @conn-atom)))
                     (do
                       (apply-conn-event! conn-atom {:type :on-close :generation generation} cb-opts)
                       (sync-conn-diagnostics! state-atom conn-atom))
                     (let [curr-conn @conn-atom
                           already-closed-this-gen? (and (or (nil? generation)
                                                             (= generation (:generation curr-conn 0)))
                                                         (contains? #{:failed :down} (:phase curr-conn)))]
                       (when (satisfies? IAtom channel-id)
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
                           (reconnect-fn (fn [_] nil))))))
                   (do
                     (when (satisfies? IAtom channel-id)
                       (reset! channel-id nil))
                     (when state-atom
                       (swap! state-atom assoc :connected? false :connection-error "connection-closed")))))}))

(defn dial-single-node!
  "Dials a single validator node via `datachannel.api` (UDP, TCP, or HTTP CONNECT proxy)
   and invokes `(cb {:ok? true ...})` or `(cb {:ok? false :error ...})`."
  [identity node opts cb]
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
        settled? (atom false)
        timer-atom (atom nil)
        send-fn-atom (atom nil)
        cb-opts (cond-> {}
                  (:diagnostics-atom opts) (assoc :diagnostics-atom (:diagnostics-atom opts))
                  (:diagnose-fn opts) (assoc :diagnose-fn (:diagnose-fn opts)))
        send-fn (fn [env]
                  (if-let [cid @channel-id]
                    (let [payload (try
                                    (if (bytes? env) env (fressian/encode-wire env))
                                    (catch :default t
                                      (let [err (str "encode-failed: " (or (ex-message t) "error"))]
                                        (when-let [ca (:conn-atom opts)]
                                          (apply-conn-event! ca {:type :encode-failed :error err} cb-opts)
                                          (sync-conn-diagnostics! (:state-atom opts) ca))
                                        nil)))]
                      (if (nil? payload)
                        false
                        (try
                          (api/send! client-node payload cid)
                          true
                          (catch :default t
                            (let [err (str "send-failed: " (or (ex-message t) "error"))]
                              (when-let [ca (:conn-atom opts)]
                                (apply-conn-event! ca {:type :send-failed :error err} cb-opts)
                                (sync-conn-diagnostics! (:state-atom opts) ca))
                              false)))))
                    false))
        _ (reset! send-fn-atom send-fn)
        settle! (fn [status]
                  (when (compare-and-set! settled? false true)
                    (when-let [tm @timer-atom]
                      (js/clearTimeout tm))
                    (cond
                      (= status :bad-fingerprint)
                      (do (try (api/close! client-node) (catch :default _ nil))
                          (cb {:ok? false :error "bad-fingerprint"}))

                      (or (= status :timeout) (= status :connect-failed))
                      (do (try (api/close! client-node) (catch :default _ nil))
                          (cb {:ok? false :error "listener-disabled"}))

                      :else
                      (cb {:ok? true
                           :node client-node
                           :channel-id channel-id
                           :send-fn send-fn}))))
        callbacks (make-client-callbacks client-node channel-id settle! send-fn-atom
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
                                          :mdns-atom (:mdns-atom opts)})
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
                            :fingerprint (normalize-fingerprint (:fingerprint node))
                            :remote-ice-ufrag (or (:ice-ufrag node) "ufrag")
                            :remote-ice-pwd (or (:ice-pwd node) "pwd")}
                     (= transport :connect)
                     (assoc :proxy (or (:proxy opts) (resolve-proxy-url nil))))
        timeout-ms (or (:timeout-ms opts) 8000)]
    (reset! timer-atom (js/setTimeout #(settle! :timeout) timeout-ms))
    (try
      (if (or (= transport :tcp) (= transport :connect))
        (api/start-tcp! client-node remote-sdp callbacks)
        (api/start! client-node remote-sdp callbacks))
      (api/set-max-message-size! client-node)
      (catch :default _
        (settle! :connect-failed)))))

(defn connect-validators!
  "Establishes WebRTC DataChannel connection to validators in `bootstrap-descriptor`,
   rotating through candidates and invoking `(cb res)`."
  [identity bootstrap-descriptor opts cb]
  (if (and (string? (:relay-url opts)) (not (str/blank? (:relay-url opts))))
    (let [queue-atom (atom #queue [])
          in-flight? (atom false)
          state-atom (:state-atom opts)
          relay-url (:relay-url opts)
          drain! (fn drain! []
                   (if (empty? @queue-atom)
                     (reset! in-flight? false)
                     (let [[env send-cb] (peek @queue-atom)]
                       (submit-relay-envelope!
                        relay-url env opts
                        (fn [r]
                          (let [ok? (true? (or (get r "ok") (:ok r)))]
                            (when-not ok?
                              (record-conn-diagnostic! state-atom :validator-relay-send-failed {:error (or (get r "error") (:error r) "relay-send-failed")}))
                            (when (fn? send-cb)
                              (try (send-cb ok?) (catch :default _ nil)))
                            (swap! queue-atom pop)
                            (drain!)))))))
          send-fn (fn send-fn
                    ([env]
                     (send-fn env nil))
                    ([env send-cb]
                     (if (>= (count @queue-atom) 256)
                       (do
                         (record-conn-diagnostic! state-atom :validator-relay-queue-overflow {:max 256})
                         (when (fn? send-cb) (send-cb false))
                         false)
                       (do
                         (swap! queue-atom conj [env send-cb])
                         (when (compare-and-set! in-flight? false true)
                           (drain!))
                         true))))]
      (cb {:ok? true
           :node nil
           :validator-id :http-relay
           :transport :http-relay
           :failover-attempts 0
           :failed-nodes []
           :send-fn send-fn}))
    (if-let [err (validate-node-fingerprints bootstrap-descriptor)]
      (cb err)
      (if-let [dialer (:dialer-fn opts)]
        (cb (dialer identity bootstrap-descriptor opts))
        (let [home-set (or (:home-set opts)
                           (when-let [sa (:state-atom opts)] (:home-set @sa)))
              cursor (or (:validator-cursor opts)
                         (when-let [ca (:conn-atom opts)] (:validator-cursor @ca 0))
                         0)
              candidates (ordered-validator-candidates bootstrap-descriptor home-set cursor)]
          (if (empty? candidates)
            (cb {:ok? false :error "no-nodes-in-descriptor"})
            (letfn [(step [rem-candidates failed-nodes]
                      (if-let [node (first rem-candidates)]
                        (dial-single-node!
                         identity node opts
                         (fn [res]
                           (if (:ok? res)
                             (cb (assoc res
                                        :validator-id (:node-id node)
                                        :failover-attempts (count failed-nodes)
                                        :failed-nodes failed-nodes))
                             (step (rest rem-candidates)
                                   (conj failed-nodes {:validator-id (:node-id node)
                                                       :error (or (:error res) "listener-disabled")})))))
                        (let [fallback-url (when (or (:auto-relay-fallback? opts)
                                                     (:relay-url bootstrap-descriptor)
                                                     (get-in bootstrap-descriptor [:relay :url]))
                                             (or (:relay-url opts)
                                                 (:relay-url bootstrap-descriptor)
                                                 (get-in bootstrap-descriptor [:relay :url])
                                                 "https://bitecho.org/relay/v1"))]
                          (if fallback-url
                            (connect-validators! identity bootstrap-descriptor (assoc opts :relay-url fallback-url) cb)
                            (cb {:ok? false
                                 :error (if (some #(= (:error %) "bad-fingerprint") failed-nodes)
                                          "bad-fingerprint"
                                          "listener-disabled")
                                 :failed-nodes failed-nodes})))))]
              (step candidates []))))))))

(defn query-validator-chain-state!
  "Dials a single validator node over Port 5010/DTLS, sends `:query-chain-state`,
   and invokes `(cb snapshot-or-nil)`."
  [identity node pubkey privkey-bytes opts cb]
  (let [query-ice-creds (generate-random-ice-creds)
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
        settled? (atom false)
        timer-atom (atom nil)
        nonce (or (:nonce opts) (str (js/Date.now) "-" (.toString (.randomBytes node-crypto 8) "hex")))
        transport (or (:transport opts) :udp)
        target-host (if (= transport :connect)
                      (or (:ingress-host node) (:ip node) "127.0.0.1")
                      (or (:ip node) "127.0.0.1"))
        target-port (case transport
                      :connect (int (or (:ingress-port node) (:agent-tcp-port node) (:agent-port node) 443))
                      :tcp (int (or (:agent-tcp-port node) (:agent-port node) (:port node) 5010))
                      (int (or (:agent-port node) (:port node) 5010)))
        remote-sdp (cond-> {:ip target-host
                            :port target-port
                            :fingerprint (normalize-fingerprint (:fingerprint node))
                            :remote-ice-ufrag (or (:ice-ufrag node) "ufrag")
                            :remote-ice-pwd (or (:ice-pwd node) "pwd")}
                     (= transport :connect)
                     (assoc :proxy (or (:proxy opts) (resolve-proxy-url nil))))
        done! (fn [res]
                (when (compare-and-set! settled? false true)
                  (when-let [tm @timer-atom]
                    (js/clearTimeout tm))
                  (try (api/close! client-node) (catch :default _ nil))
                  (cb res)))
        callbacks {:on-open
                   (fn [evt]
                     (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)
                           signer-pk (or (:pubkey-hex identity) (:pubkey identity) pubkey)
                           query-env (light-core/build-chain-state-query-envelope signer-pk privkey-bytes {:nonce nonce :target-pubkey pubkey})
                           frozen (fressian/encode-wire query-env)]
                       (try
                         (api/send! client-node frozen cid)
                         (catch :default _
                           (done! nil)))))
                   :on-message
                   (fn [evt]
                     (try
                       (let [payload (:payload evt)
                             msg (if (bytes? payload)
                                   (fressian/decode-wire payload)
                                   (fressian/strip-untrusted-crypto-tags payload))]
                         (when (and (map? msg) (= :chain-state-snapshot (or (:bitecho/type msg) (:type msg))))
                           (done! msg)))
                       (catch :default _ nil)))
                   :on-error (fn [_] (done! nil))
                   :on-close (fn [_] (js/setTimeout #(done! nil) 50))}
        timeout-ms (or (:timeout-ms opts) 4000)]
    (reset! timer-atom (js/setTimeout #(done! nil) timeout-ms))
    (try
      (if (or (= transport :tcp) (= transport :connect))
        (api/start-tcp! client-node remote-sdp callbacks)
        (api/start! client-node remote-sdp callbacks))
      (api/set-max-message-size! client-node)
      (catch :default _
        (done! nil)))))

(defn fetch-inband-chain-state-quorum!
  "Queries all validator nodes in `bootstrap` in parallel and verifies quorum via `light-core/verify-chain-state-quorum`."
  [identity bootstrap pubkey privkey-bytes opts cb]
  (if-let [fetcher (:inband-snapshot-fetcher opts)]
    (let [res (fetcher pubkey)]
      (if (and (map? res) (contains? res :ok?) (false? (:ok? res)))
        (cb res)
        (let [snaps (if (map? res) (or (:snapshots res) [res]) res)
              trusted (set (keep :pubkey (vals (:nodes bootstrap))))
              q-opts (assoc opts
                            :expected-pubkey pubkey
                            :trusted-validators trusted
                            :min-finalized-epoch (or (:min-finalized-epoch opts) 0))]
          (cb (if (empty? snaps)
                {:ok? false :error "no-inband-snapshots-returned"}
                (light-core/verify-chain-state-quorum snaps q-opts))))))
    (let [nodes (vec (vals (:nodes bootstrap)))]
      (if (empty? nodes)
        (cb {:ok? false :error "empty-bootstrap-nodes"})
        (let [timeout-ms (or (:timeout-ms opts) 4000)
              nonce (str (js/Date.now) "-" (.toString (.randomBytes node-crypto 8) "hex"))
              q-opts (assoc opts :timeout-ms timeout-ms :nonce nonce)
              remaining (atom (count nodes))
              results (atom [])
              trusted (set (keep :pubkey nodes))
              verify-opts (assoc opts
                                 :expected-pubkey pubkey
                                 :expected-nonce nonce
                                 :trusted-validators trusted
                                 :min-finalized-epoch (or (:min-finalized-epoch opts) 0))]
          (doseq [node nodes]
            (query-validator-chain-state!
             identity node pubkey privkey-bytes q-opts
             (fn [snap]
               (when snap
                 (swap! results conj snap))
               (when (zero? (swap! remaining dec))
                 (let [snaps @results]
                   (if (empty? snaps)
                     (cb {:ok? false :error "no-inband-snapshots-returned"})
                     (cb (light-core/verify-chain-state-quorum snaps verify-opts)))))))))))))

(defn fetch-validator-accountz!
  "Fallback HTTP `/accountz` fetcher across validator candidates."
  [bootstrap pubkey opts cb]
  (if-let [fetcher (:accountz-fetcher opts)]
    (cb (fetcher pubkey))
    (let [candidates (ordered-validator-candidates bootstrap nil 0)]
      (letfn [(step [rem-cands]
                (if-let [cand (first rem-cands)]
                  (let [ip (:ip cand)
                        http-port (or (:http-port cand) (:http_port cand) 8080)
                        url-str (str "http://" ip ":" http-port "/accountz?pubkey=" pubkey)]
                    (http-get-string!
                     url-str 1500
                     (fn [body]
                       (let [parsed (when body (try (edn/read-string body) (catch :default _ nil)))]
                         (if (map? parsed)
                           (cb parsed)
                           (step (rest rem-cands)))))))
                  (cb nil)))]
        (step candidates)))))

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
   and HTTP `/accountz` if unreachable."
  [state-atom bootstrap pubkey privkey-bytes opts cb]
  (if-let [relay-url (let [u (or (:relay-url opts) (:relay_url opts))]
                       (when (and (string? u) (not (str/blank? u))) u))]
    (let [nonce (str (js/Date.now) "-" (.toString (.randomBytes node-crypto 8) "hex"))
          opts' (assoc opts :pubkey pubkey :nonce nonce)]
      (fetch-relay-chain-state!
       relay-url opts'
       (fn [relay-resp]
         (let [raw-snaps (vec (or (get relay-resp "snapshots") (get relay-resp :snapshots)))
               signed-snaps (filterv (fn [s] (or (get s "signature") (get s :signature)))
                                     (mapv (fn [s]
                                             (if (string? s)
                                               (try (edn/read-string s) (catch :default _ s))
                                               s))
                                           raw-snaps))]
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
                   (cb {:ok? true :state @state-atom :quorum-result q-res}))
                 (do
                   (swap! state-atom update-in [:diagnostics :chain-state-sync-failed] (fnil inc 0))
                   (cb {:ok? false :error (:error q-res)}))))
             (do
               (swap! state-atom update-in [:diagnostics :chain-state-sync-failed] (fnil inc 0))
               (cb {:ok? false :error (or (when-not (or (true? (get relay-resp "ok")) (true? (get relay-resp :ok)))
                                            (or (get relay-resp "error") (get relay-resp :error)))
                                          "no-verified-relay-snapshots")})))))))
    (let [run-inband!
          (fn []
            (let [id (or (:identity opts) {:pubkey-hex pubkey :privkey-bytes privkey-bytes})]
              (fetch-inband-chain-state-quorum!
               id bootstrap pubkey privkey-bytes opts
               (fn [inband-res]
                 (cond
                   (:ok? inband-res)
                   (let [snap (:snapshot inband-res)]
                     (swap! state-atom (fn [st] (light-core/apply-verified-chain-state-snapshot st snap)))
                     (cb {:ok? true :state @state-atom :quorum-result inband-res}))

                   (and (or (:auto-relay-fallback? opts)
                            (:relay-url bootstrap)
                            (get-in bootstrap [:relay :url]))
                        (not (:relay-url opts)))
                   (let [fallback-url (or (:relay-url bootstrap)
                                          (get-in bootstrap [:relay :url])
                                          "https://bitecho.org/relay/v1")]
                     (maybe-sync-account-state! state-atom bootstrap pubkey privkey-bytes (assoc opts :relay-url fallback-url) cb))

                   (and (not= (:error inband-res) "no-inband-snapshots-returned")
                        (not= (:error inband-res) "empty-bootstrap-nodes"))
                   (cb {:ok? false :error (:error inband-res)})

                   (:accountz-fetcher opts)
                   (fetch-validator-accountz!
                    bootstrap pubkey opts
                    (fn [resp]
                      (if resp
                        (if (:account resp)
                          (let [cmd {"cmd" "sync-account"
                                     "balance" (get-in resp [:account :balance] 0)
                                     "spendable" (:spendable resp)
                                     "seq" (get-in resp [:account :seq] 0)
                                     "deps" (vec (get-in resp [:account :deps] []))
                                     "finalized_epoch" (:finalized-epoch resp 0)}
                                res (light-core/handle-command @state-atom cmd privkey-bytes)]
                            (reset! state-atom (:state res))
                            (cb {:ok? true :state @state-atom :accountz resp}))
                          (cb {:ok? false :error "no-account-in-accountz"}))
                        (cb {:ok? false :error "accountz-fetcher-returned-nil"}))))

                   :else
                   (let [err (or (:error inband-res) "no-inband-snapshots-returned")]
                     (swap! state-atom (fn [st]
                                         (-> st
                                             (update-in [:diagnostics :account-sync-inband-failed] (fnil inc 0))
                                             (update-in [:diagnostics :chain-state-sync-failed] (fnil inc 0)))))
                     (cb {:synced false :ok? false :reason err :error err})))))))]
      (if-let [fast-relay-url (infer-bootstrap-relay-url bootstrap opts)]
        (let [nonce (str (js/Date.now) "-" (.toString (.randomBytes node-crypto 8) "hex"))
              opts' (assoc opts :pubkey pubkey :nonce nonce :timeout-ms (or (:timeout-ms opts) 3000))]
          (fetch-relay-chain-state!
           fast-relay-url opts'
           (fn [relay-resp]
             (let [raw-snaps (vec (or (get relay-resp "snapshots") (get relay-resp :snapshots)))
                   signed-snaps (filterv (fn [s] (or (get s "signature") (get s :signature)))
                                         (mapv (fn [s]
                                                 (if (string? s)
                                                   (try (edn/read-string s) (catch :default _ s))
                                                   s))
                                               raw-snaps))]
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
                       (cb {:ok? true :state @state-atom :quorum-result q-res}))
                     (run-inband!)))
                 (run-inband!))))))
        (run-inband!)))))

(defn fetch-directory-descriptor!
  "Fetches and parses a directory descriptor for `nickname` under `domain`."
  [domain nickname opts cb]
  (if-let [custom-fetcher (:directory-fetcher opts)]
    (try
      (let [res (custom-fetcher domain nickname)]
        (cb (cond
              (map? res) res
              (string? res) (light-core/parse-directory-descriptor-text res)
              :else nil)))
      (catch :default _ (cb nil)))
    (let [dom (if (or (nil? domain) (str/blank? domain)) "bitecho.org" (str/trim domain))
          net-uri (or (:network-uri opts) "bitecho.org")
          url-v1 (str "https://" dom "/directory/v1/" net-uri "/" nickname)
          url1 (str "https://" dom "/directory/" nickname ".json")
          url2 (str "https://" dom "/" nickname)
          local-path (.join node-path "devnet" "directory" (str nickname ".json"))]
      (http-get-string!
       url-v1 4000
       (fn [body-v1]
         (if-let [dv1 (when body-v1 (light-core/parse-directory-descriptor-text body-v1))]
           (cb dv1)
           (http-get-string!
            url1 4000
            (fn [body1]
              (if-let [d1 (when body1 (light-core/parse-directory-descriptor-text body1))]
                (cb d1)
                (http-get-string!
                 url2 4000
                 (fn [body2]
                   (if-let [d2 (when body2 (light-core/parse-directory-descriptor-text body2))]
                     (cb d2)
                     (if (.existsSync node-fs local-path)
                       (cb (light-core/parse-directory-descriptor-text (.readFileSync node-fs local-path "utf8")))
                       (cb nil))))))))))))))

;; =============================================================================
;; 6. JSONL Output, `wait-event`, `serve`, & `one-shot` Execution Modes
;; =============================================================================

(def waitable-event-types
  "Set of incoming asynchronous event types eligible to wake `wait-event`."
  light-core/waitable-event-types)

(defn event-matches-wait-filter?
  "Delegates to unified pure `.cljc` core `light-core/event-matches-wait-filter?`
   (supporting `broadcast_seq` and `config/equivalent-subnet-id?`)."
  [evt opts]
  (light-core/event-matches-wait-filter? evt opts))

(defn- raw-byte-array?
  [v]
  (or (instance? js/Uint8Array v)
      (.isBuffer js/Buffer v)))

(defn- safe-map-get
  "Safe lookup that never throws CompareError when probing keyword keys on string-keyed sorted-maps."
  [m k]
  (try (get m k) (catch :default _ nil)))

(defn- sanitize-stdout-log-data
  "Strips raw byte arrays (`:bytes`, `:blob/bytes`, `Uint8Array`, `Buffer`) from stdout/events JSONL logs,
   preserving only `{:cid :size_bytes :media_type}` metadata (BIP-018 Track 2 / Twin Edge Case #1)."
  [v]
  (cond
    (raw-byte-array? v)
    {"size_bytes" (.-length v)}

    (map? v)
    (let [raw-bs (or (safe-map-get v :blob/bytes)
                     (safe-map-get v :bytes)
                     (safe-map-get v "blob/bytes")
                     (safe-map-get v "bytes"))]
      (if (and (some? raw-bs) (raw-byte-array? raw-bs))
        (let [cid-val (or (safe-map-get v :blob/cid) (safe-map-get v :cid) (safe-map-get v "cid"))
              mt-val (or (safe-map-get v :blob/media-type) (safe-map-get v :media-type) (safe-map-get v :media_type) (safe-map-get v "media_type"))]
          (cond-> {"size_bytes" (.-length raw-bs)}
            cid-val (assoc "cid" cid-val)
            mt-val (assoc "media_type" mt-val)))
        (reduce-kv (fn [acc k val]
                     (if (contains? #{:bytes :blob/bytes "bytes" "blob/bytes"} k)
                       (if (raw-byte-array? val)
                         (assoc acc "size_bytes" (.-length val))
                         acc)
                       (assoc acc k (sanitize-stdout-log-data val))))
                   {}
                   v)))

    (vector? v)
    (mapv sanitize-stdout-log-data v)

    (sequential? v)
    (mapv sanitize-stdout-log-data v)

    :else v))

(defn- write-json-str
  [data]
  (js/JSON.stringify (clj->js data)))

(defn append-event-jsonl!
  "Appends a single JSON object line to `events-out-path` with a `timestamp_ms` field."
  [events-out-path data]
  (when (and (some? events-out-path) (not (str/blank? (str events-out-path))) (map? data))
    (let [p (str events-out-path)
          parent (.dirname node-path p)
          _ (when parent (.mkdirSync node-fs parent #js {:recursive true}))
          safe-data (sanitize-stdout-log-data data)
          enriched (if (or (contains? safe-data "timestamp_ms") (contains? safe-data :timestamp-ms))
                     safe-data
                     (assoc safe-data "timestamp_ms" (js/Date.now)))]
      (.appendFileSync node-fs p (str (write-json-str enriched) "\n") "utf8"))))

(defonce ^:private events-out-error-count-atom (atom 0))

(defn emit-json-line!
  "Writes `data` as a JSON line to `process.stdout` and optionally mirrors to `events-out-path`.
   Sanitizes raw byte arrays so `artifact-replicated` / `put` logs never dump raw Uint8Arrays.
   Never swallows `append-event-jsonl!` I/O errors silently (Rule 5 / BIP-020 Catch 4)."
  ([data] (emit-json-line! data nil nil))
  ([data events-out-path] (emit-json-line! data events-out-path nil))
  ([data events-out-path state-atom]
   (let [safe-data (sanitize-stdout-log-data data)]
     (.write (.-stdout js/process) (str (write-json-str safe-data) "\n"))
     (when events-out-path
       (try
         (append-event-jsonl! events-out-path safe-data)
         (catch :default err
           (swap! events-out-error-count-atom inc)
           (when state-atom
             (swap! state-atom (fn [st]
                                 (-> st
                                     (update-in [:diagnostics :events-out-write-failed] (fnil inc 0))
                                     (update-in [:diagnostics :dropped] (fnil inc 0))))))
           (try
             (.write (.-stderr js/process)
                     (str "WARN: append-event-jsonl! failed for " events-out-path ": " err "\n"))
             (catch :default _ nil))))))))

(defn read-new-cmd-file-lines!
  "Reads newly appended complete UTF-8 lines or balanced JSON objects from `cmd-file-path` starting at byte `offset`."
  [cmd-file-path offset]
  (let [p (str cmd-file-path)]
    (if-not (.existsSync node-fs p)
      {:lines [] :next-offset offset}
      (let [stat (.statSync node-fs p)
            len (.-size stat)
            safe-off (if (< len offset) 0 offset)]
        (if (<= len safe-off)
          {:lines [] :next-offset safe-off}
          (let [rem (- len safe-off)
                buf (js/Buffer.alloc rem)
                fd (.openSync node-fs p "r")]
            (try
              (let [read-n (.readSync node-fs fd buf 0 rem safe-off)]
                (if (<= read-n 0)
                  {:lines [] :next-offset safe-off}
                  (let [last-nl (loop [idx (dec read-n)]
                                  (cond
                                    (neg? idx) -1
                                    (= (.readUInt8 buf idx) 10) idx
                                    :else (recur (dec idx))))
                        nl-consumed (if (neg? last-nl) 0 (inc last-nl))
                        nl-text (when (pos? nl-consumed)
                                  (.toString buf "utf8" 0 nl-consumed))
                        nl-lines (if nl-text
                                   (mapcat cli/split-jsonl-commands (str/split-lines nl-text))
                                   [])
                        trailing-len (- read-n nl-consumed)
                        trailing-text (when (pos? trailing-len)
                                        (.toString buf "utf8" nl-consumed read-n))
                        trailing-cmds (when (seq trailing-text)
                                        (cli/split-jsonl-commands trailing-text))
                        trailing-consumed (if (seq trailing-cmds)
                                            (let [last-cmd (last trailing-cmds)
                                                  last-idx (.lastIndexOf trailing-text last-cmd)]
                                              (if (>= last-idx 0)
                                                (let [sub (.substring trailing-text 0 (+ last-idx (count last-cmd)))]
                                                  (.-length (js/Buffer.from sub "utf8")))
                                                0))
                                            0)
                        total-consumed (+ nl-consumed trailing-consumed)
                        all-lines (vec (concat nl-lines (when (pos? trailing-consumed) trailing-cmds)))]
                    (if (zero? total-consumed)
                      {:lines [] :next-offset safe-off}
                      {:lines (->> all-lines (map str/trim) (remove str/blank?) vec)
                       :next-offset (+ safe-off total-consumed)}))))
              (finally
                (try (.closeSync node-fs fd) (catch :default _ nil))))))))))

(defn run-wait-event!
  "Polls `--events-out` (or `<state-dir>/events.jsonl`) until a matching incoming event arrives.
   Checks `<state-dir>/control.json` for `events_out` mismatch and emits a loud warning + diagnostic (BIP-020 Catch 4)."
  [opts]
  (let [state-dir (or (:state-dir opts) (.join node-path (.homedir node-os) ".bitecho" "light-node"))
        events-path (or (:events-out opts) (.join node-path state-dir "events.jsonl"))
        ctrl-file (.join node-path state-dir "control.json")
        _ (when (.existsSync node-fs ctrl-file)
            (when-let [ctrl (try (parse-json-safe (.readFileSync node-fs ctrl-file "utf8")) (catch :default _ nil))]
              (when (contains? ctrl "events_out")
                (let [daemon-ev (get ctrl "events_out")
                      canon-target (.resolve node-path (str events-path))
                      canon-daemon (when (and (string? daemon-ev) (not (str/blank? daemon-ev)))
                                     (.resolve node-path daemon-ev))]
                  (when (not= canon-target canon-daemon)
                    (try
                      (.write (.-stderr js/process)
                              (str "WARN: events-out-mismatch: wait-event targeting " canon-target
                                   " but daemon control.json has events_out=" (pr-str canon-daemon) "\n"))
                      (catch :default _ nil)))))))
        timeout-ms (max 1 (or (:timeout-ms opts) 300000))
        poll-ms (or (:poll-ms opts) 50)
        scan-from-start? (or (some? (:min-seq opts)) (some? (:min-broadcast-seq opts)) (some? (:after-ts opts)))
        initial-offset (if (and (not scan-from-start?) (.existsSync node-fs events-path))
                         (.-size (.statSync node-fs events-path))
                         0)
        deadline (+ (js/Date.now) timeout-ms)]
    (letfn [(poll-step [offset]
              (let [{:keys [lines next-offset]} (read-new-cmd-file-lines! events-path offset)
                    matched (some (fn [line]
                                    (let [parsed (parse-json-safe line)]
                                      (when (event-matches-wait-filter? parsed opts)
                                        parsed)))
                                  lines)]
                (cond
                  matched
                  (do
                    (emit-json-line! matched)
                    (.exit js/process 0))

                  (>= (js/Date.now) deadline)
                  (do
                    (emit-json-line! {"ok" false "error" "timeout"})
                    (.exit js/process 1))

                  :else
                  (js/setTimeout #(poll-step next-offset)
                                 (min poll-ms (max 1 (- deadline (js/Date.now))))))))]
      (poll-step initial-offset))))

;; =============================================================================
;; P2P Direct Signaling & Transport Binding
;; =============================================================================

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
        (let [pub-bytes (try (basalt/hex->bytes sender) (catch :default _ nil))
              sig-bytes (try (basalt/hex->bytes sig-hex) (catch :default _ nil))
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
                                       (instance? cljs.core/Atom send-fn-atom) @send-fn-atom
                                       (fn? send-fn-atom) send-fn-atom
                                       :else nil)]
                          (try
                            (let [r (sfn env)]
                              (not (false? r)))
                            (catch :default _
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
                          (catch :default _
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
                             (let [r (direct-send env)]
                               (not (false? r)))
                             (catch :default ex
                               (when (and state-atom (:p2p-session-id env))
                                 (let [cmd-res (light-core/handle-command @state-atom
                                                                          {"cmd" "p2p-channel-state"
                                                                           "session_id" (:p2p-session-id env)
                                                                           "connected" false
                                                                           "error" (str "direct-send-failed: " (or (ex-message ex) (str ex)))}
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
  [state-atom p2p-peers-atom ingress-peers-atom mdns-atom privkey-bytes emit-event! dial-info & [state-file]]
  (let [peer-pk (light-core/normalize-pubkey-hex (:peer dial-info))
        sid (:session-id dial-info)
        force? (true? (:force-redial? dial-info))
        existing-p2p (when p2p-peers-atom (get @p2p-peers-atom peer-pk))]
    (when (and force? existing-p2p)
      (when-let [cf (:close-fn existing-p2p)]
        (try (cf) (catch :default _ nil)))
      (when p2p-peers-atom (swap! p2p-peers-atom dissoc peer-pk)))
    (if (and (not force?) existing-p2p (:send-fn existing-p2p))
      (let [cmd-res (light-core/handle-command @state-atom
                                               {"cmd" "p2p-channel-state"
                                                "session_id" sid
                                                "connected" true}
                                               privkey-bytes)]
        (reset! state-atom (:state cmd-res))
        (when state-file (try (save-light-state! state-file (:state cmd-res)) (catch :default _ nil)))
        (when emit-event!
          (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))
      (let [candidates (or (:remote-candidates dial-info) [])
            mdns-svc (or (when (map? mdns-atom) mdns-atom)
                         (when (and mdns-atom (satisfies? IMeta mdns-atom))
                           (:mdns-svc (meta mdns-atom))))
            mdns-table-atom (if (and (map? mdns-atom) (:table-atom mdns-atom))
                              (:table-atom mdns-atom)
                              mdns-atom)
            read-mdns-state (fn []
                              (when mdns-table-atom
                                (if (satisfies? IDeref mdns-table-atom)
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
                            (catch :default _ nil))))))))
            attempt-dial!
            (fn []
              (let [mdns-state' (read-mdns-state)
                    proxy-url (resolve-proxy-url nil)
                    parsed-candidates (->> (keep #(light-core/parse-p2p-candidate % mdns-state') candidates)
                                           (remove (fn [c]
                                                     (and (nil? proxy-url)
                                                          (or (= :connect (:transport c))
                                                              (:proxy-connect? c)))))
                                           vec)
                    success? (atom false)
                    dial-step!
                    (fn dial-step! [idx]
                      (if (or @success? (get-in @state-atom [:sessions sid :p2p :connected?]))
                        nil
                        (if (>= idx (count parsed-candidates))
                          (let [cmd-res (light-core/handle-command @state-atom
                                                                   {"cmd" "p2p-channel-state"
                                                                    "session_id" sid
                                                                    "connected" false
                                                                    "error" "p2p-dial-failed"}
                                                                   privkey-bytes)]
                            (reset! state-atom (:state cmd-res))
                            (when state-file (try (save-light-state! state-file (:state cmd-res)) (catch :default _ nil)))
                            (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))
                          (let [cand (nth parsed-candidates idx)
                                host (:host cand)
                                port (int (or (:port cand) 443))
                                transport (or (:transport cand) :tcp)
                                https-leg? (contains? #{:https :http "https" "http"} transport)
                                channel-id (atom nil)
                                assigned-gen (atom nil)
                                on-close-fired? (atom false)
                                timeout-id (atom nil)
                                poll-timer (atom nil)
                                client-node (when-not https-leg?
                                              (api/create-node {:port 0 :setup "active"}))
                                advance! (fn []
                                           (when-let [tid @timeout-id]
                                             (js/clearTimeout tid)
                                             (reset! timeout-id nil))
                                           (when-let [pt @poll-timer]
                                             (js/clearTimeout pt)
                                             (reset! poll-timer nil))
                                           (when client-node
                                             (try (api/close! client-node) (catch :default _ nil)))
                                           (dial-step! (inc idx)))
                                relay-base-url-atom (atom (when https-leg?
                                                            (relay/normalize-relay-base-url
                                                             (or (:url cand)
                                                                 (str (name transport) "://" host ":" port "/relay/v1")))))
                                peer-send! (if https-leg?
                                             (fn [env]
                                               (if @on-close-fired?
                                                 false
                                                 (do
                                                   (submit-relay-envelope! @relay-base-url-atom env {:timeout-ms 5000} (fn [_] nil))
                                                   true)))
                                             (fn [env]
                                               (if-let [cid @channel-id]
                                                 (let [payload (try (if (bytes? env) env (fressian/encode-wire env)) (catch :default _ nil))]
                                                   (if payload
                                                     (try (api/send! client-node payload cid) true (catch :default _ false))
                                                     false))
                                                 false)))
                                on-close-fn (fn [_]
                                              (when (compare-and-set! on-close-fired? false true)
                                                (when-let [pt @poll-timer]
                                                  (js/clearTimeout pt)
                                                  (reset! poll-timer nil))
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
                                                          (when state-file (try (save-light-state! state-file (:state cmd-res)) (catch :default _ nil)))
                                                          (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))))))))
                                peer-close! (fn []
                                              (try
                                                (when-let [pt @poll-timer]
                                                  (js/clearTimeout pt)
                                                  (reset! poll-timer nil))
                                                (when client-node
                                                  (api/close! client-node))
                                                (on-close-fn {:type :on-close})
                                                (catch :default _ nil)))
                                remote-sdp (when-not https-leg?
                                             (cond-> {:ip host
                                                      :port port
                                                      :remote-ice-ufrag (or (:remote-ice-ufrag dial-info) "ufrag")
                                                      :remote-ice-pwd (or (:remote-ice-pwd dial-info) "pwd")}
                                               (:remote-fingerprint dial-info)
                                               (assoc :fingerprint (normalize-fingerprint (:remote-fingerprint dial-info)))
                                               (:proxy-connect? cand)
                                               (assoc :proxy (resolve-proxy-url nil))))
                                on-opened! (fn [cid]
                                             (when-let [tid @timeout-id]
                                               (js/clearTimeout tid)
                                               (reset! timeout-id nil))
                                             (reset! channel-id cid)
                                             (when (compare-and-set! success? false true)
                                               (let [my-gen (inc (long (or (get-in @p2p-peers-atom [peer-pk :generation]) 0)))]
                                                 (reset! assigned-gen my-gen)
                                                 (when p2p-peers-atom
                                                   (swap! p2p-peers-atom assoc peer-pk (cond-> {:send-fn peer-send!
                                                                                                :close-fn peer-close!
                                                                                                :session-id sid
                                                                                                :generation my-gen}
                                                                                         https-leg? (assoc :transport "https" :relay-url @relay-base-url-atom))))
                                                 (let [local-pub (or (:pubkey @state-atom) "")
                                                       bind-env (build-p2p-link-bind-envelope local-pub privkey-bytes sid)]
                                                   (peer-send! bind-env))
                                                 (let [cmd-res (light-core/handle-command @state-atom
                                                                                          {"cmd" "p2p-channel-state"
                                                                                           "session_id" sid
                                                                                           "connected" true}
                                                                                          privkey-bytes)]
                                                   (reset! state-atom (:state cmd-res))
                                                   (when state-file (try (save-light-state! state-file (:state cmd-res)) (catch :default _ nil)))
                                                   (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev)))))))
                                callbacks (when-not https-leg?
                                            {:on-open (fn [evt]
                                                        (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)]
                                                          (on-opened! cid)))
                                             :on-data-channel (fn [evt]
                                                                (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)]
                                                                  (on-opened! cid)))
                                             :on-message (fn [evt]
                                                           (when-let [payload (:payload evt)]
                                                             (when state-atom
                                                               (let [st @state-atom
                                                                     res (light-core/handle-wire-payload st payload privkey-bytes)]
                                                                 (reset! state-atom (:state res))
                                                                 (when state-file (try (save-light-state! state-file (:state res)) (catch :default _ nil)))
                                                                 (when (seq (:stdout-events res))
                                                                   (when emit-event! (doseq [ev (:stdout-events res)] (emit-event! ev))))
                                                                 (when (seq (:net-envelopes res))
                                                                   (send-routed-envelopes! (:net-envelopes res) nil p2p-peers-atom ingress-peers-atom state-atom privkey-bytes))))))
                                             :on-close (fn [evt]
                                                         (if-not @success?
                                                           (advance!)
                                                           (on-close-fn evt)))})]
                            (try
                              (reset! timeout-id (js/setTimeout advance! (if https-leg? 5000 3000)))
                              (if https-leg?
                                (let [local-pub (or (:pubkey @state-atom) "")
                                      probe-ok? (fn [probe-res]
                                                  (and (map? probe-res)
                                                       (or (true? (get probe-res "ok"))
                                                           (true? (:ok probe-res))
                                                           (vector? (get probe-res "messages"))
                                                           (vector? (:messages probe-res)))))
                                      start-https-leg!
                                      (fn [active-relay-url]
                                        (reset! relay-base-url-atom active-relay-url)
                                        (let [my-gen-fn (fn [] @assigned-gen)
                                              since-mseq-atom (atom 0)
                                              since-bseq-atom (atom 0)
                                              poll-https-leg!
                                              (fn poll-https-leg! []
                                                (when (and (not @on-close-fired?)
                                                           p2p-peers-atom
                                                           (some? (my-gen-fn))
                                                           (= (my-gen-fn) (get-in @p2p-peers-atom [peer-pk :generation])))
                                                  (poll-relay-envelopes!
                                                   @relay-base-url-atom local-pub privkey-bytes
                                                   {:since-seq @since-mseq-atom
                                                    :since-broadcast-seq @since-bseq-atom
                                                    :timeout-ms 1500}
                                                   (fn [poll-res]
                                                     (when (and (not @on-close-fired?)
                                                                p2p-peers-atom
                                                                (= (my-gen-fn) (get-in @p2p-peers-atom [peer-pk :generation])))
                                                       (let [msgs (or (get poll-res "messages") (get poll-res :messages) [])
                                                             bcasts (or (get poll-res "broadcasts") (get poll-res :broadcasts) [])
                                                             all-items (concat msgs bcasts)
                                                             new-mseq (long (or (get (last msgs) "relay_seq") (get (last msgs) "relay-seq") @since-mseq-atom))
                                                             new-bseq (long (or (get poll-res "last_broadcast_seq") (get poll-res :last_broadcast_seq) @since-bseq-atom))]
                                                         (reset! since-mseq-atom new-mseq)
                                                         (reset! since-bseq-atom new-bseq)
                                                         (doseq [item all-items]
                                                           (let [env-raw (or (get item "envelope_hex") (get item "envelope")
                                                                             (get item :envelope_hex) (get item :envelope))
                                                                 wire-bytes (when env-raw (try (fressian/hex->bytes (str env-raw)) (catch :default _ nil)))]
                                                             (when (and wire-bytes state-atom)
                                                               (let [r (light-core/handle-wire-payload @state-atom wire-bytes privkey-bytes)]
                                                                 (reset! state-atom (:state r))
                                                                 (when state-file (try (save-light-state! state-file (:state r)) (catch :default _ nil)))
                                                                 (when emit-event! (doseq [ev (:stdout-events r)] (emit-event! ev)))
                                                                 (when (seq (:net-envelopes r))
                                                                   (send-routed-envelopes! (:net-envelopes r) nil p2p-peers-atom ingress-peers-atom state-atom privkey-bytes)))))))
                                                       (reset! poll-timer (js/setTimeout poll-https-leg! 250)))))))]
                                          (on-opened! 0)
                                          (reset! poll-timer (js/setTimeout poll-https-leg! 100))))]
                                  (poll-relay-envelopes!
                                   @relay-base-url-atom local-pub privkey-bytes
                                   {:since-seq 0 :timeout-ms 0}
                                   (fn [probe-res]
                                     (if (probe-ok? probe-res)
                                       (start-https-leg! @relay-base-url-atom)
                                       (let [loopback-fallback (relay/normalize-relay-base-url "http://127.0.0.1:18080/relay/v1")]
                                         (if (and (not= @relay-base-url-atom loopback-fallback)
                                                  (not (contains? #{"127.0.0.1" "localhost" "::1"} (str/lower-case (str host)))))
                                           (poll-relay-envelopes!
                                            loopback-fallback local-pub privkey-bytes
                                            {:since-seq 0 :timeout-ms 0}
                                            (fn [fb-res]
                                              (if (probe-ok? fb-res)
                                                (start-https-leg! loopback-fallback)
                                                (advance!))))
                                           (advance!)))))))
                                (if (or (= transport :tcp) (= transport :connect))
                                  (api/start-tcp! client-node remote-sdp callbacks)
                                  (api/start! client-node remote-sdp callbacks)))
                              (catch :default _
                                (advance!)))))))]
                (dial-step! 0)))]
        (if (and @queried? (identical? mdns-state (read-mdns-state)))
          (js/setTimeout attempt-dial! 50)
          (attempt-dial!))))))

(defn start-ingress-tcp-listener!
  "Starts a passive RFC 4571 DTLS-over-TCP DataChannel ingress listener on `:ingress-tcp-port`
   for direct `HTTP CONNECT` / TCP peer connections (Step 15C).
   Returns `{:listener listener :ingress-peers-atom ingress-peers-atom :stop! (fn [] ...)}` or nil."
  [identity opts]
  (let [port (int (or (:ingress-tcp-port opts) 0))]
    (when (pos? port)
      (let [{:keys [state-atom conn-atom event-out state-file p2p-peers-atom mdns-atom]} opts
            ingress-peers-atom (or (:ingress-peers-atom opts) (atom {}))
            peer-seq (atom 0)
            peer-ice-pwds (atom {})
            on-conn-fn
            (fn [peer-node]
              (try (api/set-max-message-size! peer-node) (catch :default _ nil))
              (let [peer-key (swap! peer-seq inc)
                    peer-cid (atom 0)
                    bound-sender (atom nil)
                    bound-gen (atom nil)
                    on-close-fired? (atom false)
                    peer-send! (fn [env]
                                 (let [payload (try
                                                 (if (bytes? env) env (fressian/encode-wire env))
                                                 (catch :default _ nil))]
                                   (if (nil? payload)
                                     false
                                     (try
                                       (api/send! peer-node payload (int (or @peer-cid 0)))
                                       true
                                       (catch :default _ false)))))
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
                                                  (when state-file (try (save-light-state! state-file (:state cmd-res)) (catch :default _ nil)))
                                                  (when (and event-out (seq (:stdout-events cmd-res)))
                                                    (doseq [ev (:stdout-events cmd-res)] (event-out ev))))))))))))
                    peer-close! (fn []
                                  (try
                                    (when-let [ch @(:channel peer-node)]
                                      (cond
                                        (fn? (.-destroy ch)) (.destroy ch)
                                        (fn? (.-close ch)) (.close ch)))
                                    (api/close! peer-node)
                                    (on-close-fn {:type :on-close})
                                    (catch :default _ nil)))]
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
                        (let [decoded (try (if (bytes? payload) (fressian/decode-wire payload) payload) (catch :default _ nil))
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
                                      (when state-file (try (save-light-state! state-file (:state cmd-res)) (catch :default _ nil)))
                                      (when (and event-out (seq (:stdout-events cmd-res)))
                                        (doseq [ev (:stdout-events cmd-res)] (event-out ev))))))
                                (when state-atom
                                  (swap! state-atom update-in [:diagnostics :p2p-signaling-rejected] (fnil inc 0)))))

                            (and (map? inner-ev) (= :query-chain-state (or (:type inner-ev) (:bitecho/type inner-ev))))
                            (let [st (if state-atom @state-atom {})
                                  target-pk (or (:pubkey inner-ev) (:agent-pubkey decoded) (:pubkey st) (:pubkey-hex identity))
                                  fin-ep (or (get-in st [:account :finalized-epoch]) (:epoch st) 0)
                                  bal (or (get-in st [:account :balance]) 0)
                                  spend (or (get-in st [:account :spendable]) bal 0)
                                  sq (or (get-in st [:account :seq]) 0)
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
                                  (try (save-light-state! state-file new-st) (catch :default _ nil)))
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
                           (api/listen! listen-opts {:on-connection on-conn-fn})
                           (catch :default e
                             (when state-atom
                               (record-conn-diagnostic! state-atom :udp-listen-failed {:port port :error (or (ex-message e) (str e))}))
                             nil))]
        {:listener listener
         :udp-listener udp-listener
         :ingress-peers-atom ingress-peers-atom
         :p2p-peers-atom p2p-peers-atom
         :stop! (fn []
                  (try (api/close! listener) (catch :default _ nil))
                  (when udp-listener (try (api/close! udp-listener) (catch :default _ nil))))}))))

(defn- maybe-wait-open!
  [resp sid wait-ms state-atom conn-opts relay-url emit! done-cb]
  (if (and resp (true? (or (get resp "ok") (get resp :ok))) (string? sid) (pos? wait-ms))
    (let [deadline (+ (.now js/Date) wait-ms)
          poll-step!
          (fn poll-step! []
            (let [st (get-in @state-atom [:sessions sid :state])]
              (cond
                (= st "open")
                (let [final-resp (assoc resp "state" "open")]
                  (when emit! (emit! final-resp))
                  (done-cb final-resp))

                (>= (.now js/Date) deadline)
                (let [final-resp (assoc resp "state" (or st "offered") "wait_timed_out" true)]
                  (when emit! (emit! final-resp))
                  (done-cb final-resp))

                :else
                (do
                  (when relay-url
                    (try
                      (let [pk (or (:pubkey-hex (:identity conn-opts)) (:pubkey @state-atom))
                            sk (or (:privkey-bytes (:identity conn-opts)) (:privkey @state-atom))]
                        (when (and pk sk)
                          (poll-relay-envelopes! relay-url pk sk nil nil)))
                      (catch :default _ nil)))
                  (js/setTimeout poll-step! 50)))))]
      (poll-step!))
    (do
      (when (and resp emit!) (emit! resp))
      (done-cb resp))))

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

(defn- enrich-artifact-cmd-map
  [verb cmd-map]
  (let [eff-verb (effective-artifact-domain-verb verb cmd-map)]
    (if (and (= eff-verb "artifact-put")
             (nil? (get cmd-map "hex"))
             (nil? (get cmd-map "data_hex"))
             (nil? (get cmd-map "text"))
             (nil? (get cmd-map "data"))
             (string? (get cmd-map "file"))
             (not (str/blank? (get cmd-map "file"))))
      (let [f (get cmd-map "file")]
        (if (.existsSync node-fs f)
          (let [h (.toString (.readFileSync node-fs f) "hex")]
            (assoc cmd-map "hex" h "data_hex" h))
          cmd-map))
      cmd-map)))

(defn- maybe-write-artifact-out-file!
  "When `artifact-get` has `out_file` (`--out <file>`), writes verified raw bytes atomically
   (`write-bytes-atomic!`) and returns `{:applied? true :ok? true :response <compact-receipt>}`.
   On error, fails closed with canonical `:artifact-out-write-failed` + counted Rule 5 `:diagnose`."
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
        (let [buf (.from (.-Buffer js/globalThis) (get resp "hex") "hex")
              expected-cid (or (get resp "cid") (:cid resp))
              actual-cid (when (and (string? expected-cid) (not (str/blank? expected-cid)))
                           (-> (.createHash node-crypto "sha256")
                               (.update buf)
                               (.digest "hex")
                               str/lower-case))]
          (if (and actual-cid (not= (str/lower-case expected-cid) actual-cid))
            (let [err (errors/canonical-error :artifact-out-write-failed
                                              {:out-file out-file :reason "cid-mismatch"})]
              (when state-atom (swap! state-atom errors/record-error-diagnostic err))
              {:applied? true :ok? false :response (errors/canonical-error->wire err)})
            (do
              (write-bytes-atomic! out-file buf)
              {:applied? true
               :ok? true
               :response (flags/format-artifact-get-out-receipt resp out-file (.-length buf))})))
        (catch :default e
          (let [err (errors/canonical-error :artifact-out-write-failed
                                            {:out-file out-file :message (or (.-message e) (str e))})]
            (when state-atom (swap! state-atom errors/record-error-diagnostic err))
            {:applied? true :ok? false :response (errors/canonical-error->wire err)})))
      {:applied? false :ok? true :response resp})))

(defn- post-artifact-to-relay!
  "Uploads raw binary blob bytes (`X-Bitecho-Blob-Cid`) and pointer to `raw-relay-url`.
   Validates both blob and pointer uploads via `core-infra/evaluate-artifact-blob-upload-response`
   and `core-infra/evaluate-artifact-pointer-upload-response` with up to 2 retries on retryable
   transport/5xx errors, failing closed (`{:ok? false ...}`) if either upload fails so callers
   never report `ok=true` after a failed upload (Rule 5, SOAK-F3/F4)."
  [raw-relay-url verb resp cb]
  (let [base-url (artifact-endpoint-base-url raw-relay-url)
        resp-ok? (and (map? resp) (true? (or (get resp "ok") (:ok resp))))
        is-storage-put? (= (str verb) "storage-put")
        is-put? (contains? #{"artifact-put" "put" "storage-put"} (str verb))]
    (cond
      (not resp-ok?)
      (when cb (cb {:ok? true}))

      (nil? base-url)
      (when cb
        (cb {:ok? false
             :error "artifact-blob-upload-failed"
             :status nil
             :detail "missing-relay-url"
             :relay-url raw-relay-url
             :cid (or (get resp "cid") (:cid resp))}))

      :else
      (let [post-ptr!
            (fn []
              (if-let [ptr (or (get resp "pointer") (:pointer resp))]
                (let [ptr-body (pr-str ptr)
                      ptr-attempt!
                      (fn ptr-attempt! [attempt]
                        (http-post-bytes-detailed!
                         (str base-url "/artifact/v1/pointer")
                         ptr-body
                         {"Content-Type" "application/edn"}
                         15000
                         (fn [{:keys [status body error]}]
                           (let [parsed (when (and (string? body) (not (str/blank? body)))
                                          (try (js->clj (js/JSON.parse body)) (catch :default _ nil)))
                                 eval-res (core-infra/evaluate-artifact-pointer-upload-response
                                           {:status status
                                            :parsed-body parsed
                                            :transport-error error})]
                             (cond
                               (:ok? eval-res)
                               (when cb (cb {:ok? true :endpoints [base-url]}))

                               (and (:retryable? eval-res) (< attempt 2))
                               (js/setTimeout #(ptr-attempt! (inc attempt)) (* 250 (inc attempt)))

                               (and is-put? (not is-storage-put?) (integer? (:status eval-res)) (<= 400 (:status eval-res) 499))
                               ;; Blob was already durably stored; cross-subnet relays may return 400/403 on pointer index
                               (when cb (cb {:ok? true :endpoints [base-url] :pointer-status (:status eval-res)}))

                               :else
                               (when cb
                                 (cb {:ok? false
                                      :error "artifact-pointer-upload-failed"
                                      :status (:status eval-res)
                                      :detail (or (:detail eval-res) (name (or (:error eval-res) :pointer-upload-failed)))
                                      :relay-url base-url
                                      :cid (or (get resp "cid") (:cid resp))})))))))]
                  (ptr-attempt! 0))
                (when cb (cb {:ok? true}))))]
        (if is-put?
          (let [blob (or (get resp "blob") (:blob resp))
                cid (:blob/cid blob)
                media-type (or (:blob/media-type blob) "application/octet-stream")
                raw-bytes (:blob/bytes blob)]
            (if-not (and (map? blob) (string? cid) (not (str/blank? cid)) (some? raw-bytes))
              (when cb
                (cb {:ok? false
                     :error "artifact-blob-upload-failed"
                     :status nil
                     :detail "missing-blob-payload"
                     :relay-url base-url
                     :cid (or cid (get resp "cid") (:cid resp))}))
              (let [upload-attempt!
                    (fn upload-attempt! [attempt]
                      (http-post-bytes-detailed!
                       (str base-url "/artifact/v1/blob")
                       raw-bytes
                       {"Content-Type" media-type
                        "X-Bitecho-Blob-Cid" cid}
                       30000
                       (fn [{:keys [status body error]}]
                         (let [parsed (when (and (string? body) (not (str/blank? body)))
                                        (try (js->clj (js/JSON.parse body)) (catch :default _ nil)))
                               eval-res (core-infra/evaluate-artifact-blob-upload-response
                                         {:status status
                                          :parsed-body parsed
                                          :transport-error error
                                          :expected-cid cid})]
                           (cond
                             (:ok? eval-res)
                             (post-ptr!)

                             (and (:retryable? eval-res) (< attempt 2))
                             (js/setTimeout #(upload-attempt! (inc attempt)) (* 250 (inc attempt)))

                             :else
                             (when cb
                               (cb {:ok? false
                                    :error "artifact-blob-upload-failed"
                                    :status (:status eval-res)
                                    :detail (or (:detail eval-res) (name (or (:error eval-res) :upload-failed)))
                                    :relay-url base-url
                                    :cid cid})))))))]
                (upload-attempt! 0))))
          (post-ptr!))))))

(defn handle-serve-line!
  "Processes a single STDIN or `--cmd-file` JSON line in `serve` mode, invoking `(done-cb resp)` when complete."
  [line ctx done-cb]
  (let [{:keys [state-atom conn-atom events-out state-file identity bootstrap conn-opts ingress-peers-atom p2p-peers-atom mdns-atom]} ctx
        emit! (fn [payload] (emit-json-line! payload events-out))
        raw-cmd-map (parse-json-safe line)
        verb (when (map? raw-cmd-map) (get raw-cmd-map "cmd"))
        cmd-map (if (map? raw-cmd-map) (enrich-artifact-cmd-map verb raw-cmd-map) raw-cmd-map)
        line-str (if (map? cmd-map) (write-json-str cmd-map) (if (string? line) line (write-json-str line)))
        wait-ms (long (or (get cmd-map "wait_open_ms") (get cmd-map "wait-open-ms") (get cmd-map :wait-open-ms) (get cmd-map :wait_open_ms) 0))
        relay-url (or (:relay-url conn-opts)
                      (get-in conn-opts [:relay :url])
                      (:relay-url bootstrap)
                      (get-in bootstrap [:relay :url])
                      (when (= "bitecho.org" (:domain bootstrap)) "https://ns1.bitecho.org"))
        sync-wanted? (or (and (= verb "sync-account")
                              (nil? (get cmd-map "balance"))
                              (nil? (get cmd-map "snapshots"))
                              (nil? (get cmd-map "snapshot")))
                         (and (= verb "account") (or (get cmd-map "sync") (:sync? cmd-map)))
                         (and (= verb "escrows") (or (get cmd-map "sync") (:sync? cmd-map))))
        sync-opts (assoc (or conn-opts {}) :identity identity)
        finish-resp!
        (fn [res-map]
          (let [resp (:response res-map)]
            (if (and (contains? #{"offer" "rendezvous-offer"} verb) (pos? wait-ms))
              (let [sid (or (get resp "session_id") (get resp "session-id") (get resp :session-id))]
                (maybe-wait-open! resp sid wait-ms state-atom conn-opts relay-url emit! done-cb))
              (do
                (when (and resp emit!) (emit! resp))
                (done-cb resp)))))
        execute-cmd!
        (fn [effective-line]
          (let [eff-domain-verb (effective-artifact-domain-verb verb cmd-map)
                stage-c-verb? (contains? #{"backup-put" "backup-restore" "identity-migrate"} (str verb))
                storage-put-net? (and (= eff-domain-verb "storage-put")
                                      (not (boolean (or (get cmd-map "local_only")
                                                        (get cmd-map "local-only")
                                                        (:local-only cmd-map)))))]
            (cond
              stage-c-verb?
              (handle-node-stage-c-verb!
               (str verb) cmd-map state-atom identity
               (when state-file (.dirname node-path (str state-file)))
               state-file relay-url conn-opts
               (fn [res]
                 (finish-resp! (dissoc res :ok?))))

              storage-put-net?
              (let [sub-str (str (or (get cmd-map "subnet_id") (:subnet-id @state-atom) "global"))
                    prep (light-core/prepare-storage-put @state-atom cmd-map (:privkey-bytes identity) sub-str)]
                (if-not (:ok? prep)
                  (do
                    (when (:state prep)
                      (reset! state-atom (:state prep))
                      (when state-file (try (save-light-state! state-file @state-atom) (catch :default _ nil))))
                    (finish-resp! (dissoc prep :ok?)))
                  (let [art-relay (or (get cmd-map "relay_url")
                                      (get cmd-map "relay-url")
                                      (:relay-url cmd-map)
                                      relay-url)]
                    (post-artifact-to-relay!
                     art-relay "storage-put" (assoc (:publish-intent prep) "ok" true)
                     (fn [net-receipt]
                       (let [committed (light-core/commit-storage-put-outcome @state-atom (:publish-intent prep) net-receipt)]
                         (reset! state-atom (:state committed))
                         (when state-file (try (save-light-state! state-file @state-atom) (catch :default _ nil)))
                         (finish-resp! (dissoc committed :ok?))))))))

              :else
              (let [line-with-now (if (contains? #{"send" "broadcast"} verb)
                                    (let [m (parse-json-safe effective-line)]
                                      (if (and (map? m) (not (contains? m "now_ms")))
                                        (write-json-str (assoc m "now_ms" (.now js/Date)))
                                        effective-line))
                                    effective-line)
                    raw-res (light-core/process-jsonl-line @state-atom line-with-now (:privkey-bytes identity))
                    out-write-res (maybe-write-artifact-out-file! eff-domain-verb cmd-map (:response raw-res) state-atom)
                    res (if (:applied? out-write-res)
                          (assoc raw-res :response (:response out-write-res) :state @state-atom)
                          raw-res)
                    art-relay (when (contains? #{"artifact-put" "artifact-revoke"} eff-domain-verb)
                                (or (get cmd-map "relay_url")
                                    (get cmd-map "relay-url")
                                    (:relay-url cmd-map)
                                    relay-url))
                    proceed-after-artifact!
                    (fn []
                      (when (:state res)
                        (reset! state-atom (:state res))
                        (when state-file
                          (try (save-light-state! state-file @state-atom) (catch :default _ nil))))
                      (if (seq (:p2p-dials res))
                        (doseq [dial-info (:p2p-dials res)]
                          (dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom mdns-atom (:privkey-bytes identity) emit! dial-info state-file))
                        (when-let [dial-info (:p2p-dial res)]
                          (dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom mdns-atom (:privkey-bytes identity) emit! dial-info state-file)))
                      (let [shuttle-verb? (contains? #{"export-offer" "export-poll" "export-ack" "export-reveal" "export-p2p-offer" "export-p2p-answer" "export-send" "import-envelope" "import-poll" "import"} verb)
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
                                                   (when (and (string? relay-url)
                                                              (not (str/blank? relay-url))
                                                              (not= :http-relay (:transport @conn-atom)))
                                                     (doseq [env (remove :p2p-direct? envs)]
                                                       (try
                                                         (submit-relay-envelope!
                                                          relay-url env
                                                          (fn [r]
                                                            (when-not (and (map? r) (or (true? (get r "ok")) (true? (:ok r))))
                                                              (swap! state-atom update-in [:diagnostics :relay-mirror-failed] (fnil inc 0))))
                                                          {:timeout-ms 5000})
                                                         (catch :default _
                                                           (swap! state-atom update-in [:diagnostics :relay-mirror-failed] (fnil inc 0)))))))
                                commit-intent! (fn [res-map outcome]
                                                 (if-let [intent (:fanout-intent res-map)]
                                                   (let [committed (light-core/commit-delivery-outcome
                                                                    @state-atom
                                                                    intent
                                                                    (assoc outcome :now-ms (.now js/Date)))]
                                                     (reset! state-atom (:state committed))
                                                     (assoc res-map
                                                            :state (:state committed)
                                                            :response (:response committed)))
                                                   res-map))]
                            (if (some #(or (:p2p-direct? %) (:p2p-broadcast? %)) live-envs)
                              (let [route-res (send-routed-envelopes! live-envs
                                                                      (when currently-live? (:send-fn @conn-atom))
                                                                      p2p-peers-atom
                                                                      ingress-peers-atom
                                                                      state-atom
                                                                      (:privkey-bytes identity))
                                    _ (mirror-to-relay! live-envs)
                                    committed-res (commit-intent! res route-res)]
                                (sync-conn-diagnostics! state-atom conn-atom)
                                (save-light-state! state-file @state-atom)
                                (finish-resp! committed-res))
                              (let [sent-ingress? (boolean
                                                   (when (and ingress-peers-atom (seq @ingress-peers-atom))
                                                     (some true? (mapv #(send-all-envelopes! % live-envs) (vals @ingress-peers-atom)))))
                                    sent-val? (when currently-live?
                                                (send-all-envelopes! (:send-fn @conn-atom) live-envs))
                                    _ (mirror-to-relay! live-envs)
                                    sent? (or sent-val? sent-ingress?)]
                                (if sent?
                                  (let [committed-res (commit-intent!
                                                       res
                                                       {:mesh-submitted? (boolean sent-val?)
                                                        :p2p-direct? sent-ingress?
                                                        :mesh-peers-targeted (if sent-val? 1 0)
                                                        :p2p-peers-targeted (if sent-ingress? 1 0)})]
                                    (swap! state-atom assoc :connected? true :connection-error nil)
                                    (sync-conn-diagnostics! state-atom conn-atom)
                                    (save-light-state! state-file @state-atom)
                                    (finish-resp! committed-res))
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
                                                               :home-set home-set)]
                                      (connect-validators!
                                       identity bootstrap opts-with-gen
                                       (fn [reconn]
                                         (if (:ok? reconn)
                                           (do
                                             (when conn-atom
                                               (apply-conn-event! conn-atom (assoc reconn :type :dial-ok :generation target-gen) conn-opts))
                                             (let [r-envs (light-core/build-unacked-replay-envelopes @state-atom (:privkey-bytes identity))
                                                   all-envs (into (vec r-envs) (:net-envelopes res))]
                                               (if (send-all-envelopes! (:send-fn reconn) all-envs)
                                                 (let [committed-res (commit-intent!
                                                                      res
                                                                      {:mesh-submitted? true
                                                                       :p2p-direct? false
                                                                       :mesh-peers-targeted 1
                                                                       :p2p-peers-targeted 0})]
                                                   (swap! state-atom assoc :connected? true :connection-error nil)
                                                   (sync-conn-diagnostics! state-atom conn-atom)
                                                   (save-light-state! state-file @state-atom)
                                                   (finish-resp! committed-res))
                                                 (let [err "send-failed"]
                                                   (when conn-atom
                                                     (apply-conn-event! conn-atom {:type :send-failed :error err :generation target-gen} conn-opts))
                                                   (swap! state-atom assoc :connected? false :connection-error err)
                                                   (if (= verb "send")
                                                     (do
                                                       (when-let [intent (:fanout-intent res)]
                                                         (swap! state-atom #(:state (light-core/commit-delivery-outcome % intent {:mesh-submitted? false :p2p-direct? false :error err :now-ms (.now js/Date)}))))
                                                       (sync-conn-diagnostics! state-atom conn-atom)
                                                       (save-light-state! state-file @state-atom)
                                                       (let [err-map (assoc (or (:response res) {"ok" false}) "ok" false "queued" true "mesh_submitted" false "transport_error" err "error" err)]
                                                         (emit! err-map)
                                                         (done-cb err-map)))
                                                     (do
                                                       (sync-conn-diagnostics! state-atom conn-atom)
                                                       (let [resp {"ok" false "mesh_submitted" false "error" err}]
                                                         (emit! resp)
                                                         (done-cb resp))))))))
                                           (let [err (or (:error reconn) "listener-disabled")]
                                             (when conn-atom
                                               (apply-conn-event! conn-atom {:type :dial-failed :error err :node (:node reconn) :generation target-gen} conn-opts))
                                             (swap! state-atom assoc :connected? false :connection-error err)
                                             (if (= verb "send")
                                               (do
                                                 (when-let [intent (:fanout-intent res)]
                                                   (swap! state-atom #(:state (light-core/commit-delivery-outcome % intent {:mesh-submitted? false :p2p-direct? false :error err :now-ms (.now js/Date)}))))
                                                 (sync-conn-diagnostics! state-atom conn-atom)
                                                 (save-light-state! state-file @state-atom)
                                                 (let [err-map (assoc (or (:response res) {"ok" false}) "ok" false "queued" true "mesh_submitted" false "transport_error" err "error" err)]
                                                   (emit! err-map)
                                                   (done-cb err-map)))
                                               (do
                                                 (sync-conn-diagnostics! state-atom conn-atom)
                                                 (let [resp {"ok" false "mesh_submitted" false "error" err}]
                                                   (emit! resp)
                                                   (done-cb resp))))))))))))))
                          (let [deferred-forward? (and import-shuttle-verb? (seq (:net-envelopes res)))
                                final-res (if deferred-forward?
                                            (do
                                              (swap! state-atom update-in [:diagnostics :shuttle-import-forward-deferred] (fnil inc 0))
                                              (update res :response assoc "pending_forward_count" (count (:net-envelopes res))))
                                            res)]
                            (sync-conn-diagnostics! state-atom conn-atom)
                            (save-light-state! state-file @state-atom)
                            (finish-resp! final-res)))))]
                (if (and art-relay
                         (true? (or (get (:response res) "ok") (:ok (:response res)))))
                  (post-artifact-to-relay!
                   art-relay eff-domain-verb (:response res)
                   (fn [art-res]
                     (if (false? (:ok? art-res))
                       (finish-resp!
                        {:response {"ok" false
                                    "error" (or (:error art-res) "artifact-blob-upload-failed")
                                    "status" (:status art-res)
                                    "detail" (:detail art-res)
                                    "relay_url" (:relay-url art-res)
                                    "cid" (:cid art-res)}})
                       (proceed-after-artifact!))))
                  (proceed-after-artifact!))))))
        after-sync!
        (fn []
          (if (and (contains? #{"directory-lookup" "directory-verify"} verb)
                   (not (contains? cmd-map "descriptor"))
                   (not (contains? cmd-map :descriptor)))
            (let [nick (or (get cmd-map "nickname") (:nickname cmd-map))
                  dom (or (get cmd-map "domain") (:domain cmd-map) "bitecho.org")]
              (if (and (string? nick) (not (str/blank? nick)))
                (fetch-directory-descriptor!
                 dom nick conn-opts
                 (fn [desc]
                   (execute-cmd! (if desc (write-json-str (assoc cmd-map "descriptor" desc)) line-str))))
                (execute-cmd! line-str)))
            (execute-cmd! line-str)))]
    (if sync-wanted?
      (maybe-sync-account-state!
       state-atom bootstrap (or (:pubkey-hex identity) (:pubkey identity)) (:privkey-bytes identity) sync-opts
       (fn [sync-res]
         (if (false? (:ok? sync-res))
           (let [resp {"ok" false "error" (:error sync-res)}]
             (emit! resp)
             (done-cb resp))
           (after-sync!))))
      (after-sync!))))

(defn- handle-ctl-wait!
  "Non-blocking wait handler for control server /ctl endpoint."
  [cmd-map ctx cb]
  (let [peek? (or (true? (get cmd-map "peek"))
                  (true? (:peek cmd-map))
                  (= (get cmd-map "peek") "true"))]
    (if peek?
      (handle-serve-line! cmd-map ctx cb)
      (let [state-atom (:state-atom ctx)
            _block? (boolean (or (get cmd-map "block") (get cmd-map :block) (get cmd-map "until_event") (get cmd-map "until-event")))
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
            deadline (+ (.now js/Date) timeout-ms)
            check! (fn check! []
                     (let [st @state-atom
                           q (if (some? cursor)
                               (let [h (:event-history st)] (if (seq h) h (:event-queue st)))
                               (:event-queue st))
                           has-filter? (or min-seq cursor sub-filter sid-filter min-bseq after-ts)
                           filter-opts {:enforce-waitable-type? false
                                        :cursor cursor
                                        :session-id sid-filter
                                        :subnet-id sub-filter
                                        :min-seq min-seq
                                        :min-broadcast-seq min-bseq
                                        :after-ts after-ts
                                        :allow-eid-fallback-for-min-seq? (nil? cursor)}
                           has-event? (if has-filter?
                                        (boolean (some #(light-core/event-matches-wait-filter? % filter-opts) q))
                                        (boolean (seq q)))]
                       (if (or has-event?
                               (>= (.now js/Date) deadline))
                         (handle-serve-line! cmd-map ctx cb)
                         (js/setTimeout check! 50))))]
        (check!)))))

(defn start-control-server!
  "Starts loopback-only (127.0.0.1) control HTTP server on control-port (default 5020 or ephemeral).
   Writes <state-dir>/control.json with 0600 permissions including canonical `events_out` (BIP-020 Catch 4)."
  [state-dir ctx conn-opts]
  (let [req-port (int (or (:control-port conn-opts) 5020))
        raw-events-out (or (:events-out conn-opts) (:events-out ctx))
        canon-events-out (when (and (string? raw-events-out) (not (str/blank? raw-events-out)))
                           (.resolve node-path raw-events-out))
        _ (when-let [st-atom (:state-atom ctx)]
            (swap! st-atom assoc :events-out canon-events-out))
        token (.toString (.randomBytes node-crypto 32) "hex")
        pid (.-pid js/process)
        ctrl-file (.join node-path state-dir "control.json")
        record-ctl-sock-err! (fn [err]
                               (when-let [st-atom (:state-atom ctx)]
                                 (swap! st-atom update-in [:diagnostics :ctl-socket-error] (fnil inc 0)))
                               (emit-json-line! {"event" "diagnostic"
                                                 "reason" "ctl-socket-error"
                                                 "code" (or (when err (.-code err)) "unknown")
                                                 "detail" (or (when err (.-message err)) (str err))}
                                                (:events-out ctx)))
        safe-send-json! (fn [res status-code payload-map]
                          (when (and res (not (.-writableEnded res)) (not (.-destroyed res)))
                            (try
                              (.writeHead res status-code #js {"Content-Type" "application/json"})
                              (.end res (write-json-str payload-map))
                              (catch :default e
                                (record-ctl-sock-err! e)))))
        server (.createServer
                node-http
                (fn [req res]
                  (.on req "error" record-ctl-sock-err!)
                  (.on res "error" record-ctl-sock-err!)
                  (try
                    (let [url-str (str "http://127.0.0.1" (.-url req))
                          url-obj (js/URL. url-str)
                          path (.-pathname url-obj)
                          method (.-method req)
                          auth-hdr (aget (.-headers req) "authorization")
                          expected-auth (str "Bearer " token)]
                      (cond
                        (not= auth-hdr expected-auth)
                        (safe-send-json! res 401 {"ok" false "error" "unauthorized"})

                        (and (= method "POST") (= path "/ctl"))
                        (let [body-chunks #js []]
                          (.on req "data" (fn [chunk] (.push body-chunks chunk)))
                          (.on req "end"
                               (fn []
                                 (let [body-str (.toString (.concat (.-Buffer js/globalThis) body-chunks) "utf8")
                                       cmd-map (parse-json-safe body-str)]
                                   (if-not (and (map? cmd-map) (contains? cmd-map "cmd"))
                                     (safe-send-json! res 400 {"ok" false "error" "malformed-command"})
                                     (let [done-fn (fn [result]
                                                     (safe-send-json! res 200 (or result {"ok" true})))]
                                       (if (= (get cmd-map "cmd") "wait")
                                         (handle-ctl-wait! cmd-map ctx done-fn)
                                         (handle-serve-line! cmd-map ctx done-fn))))))))

                        :else
                        (safe-send-json! res 404 {"ok" false "error" "not-found"})))
                    (catch :default _
                      (safe-send-json! res 500 {"ok" false "error" "internal-server-error"})))))]
    (.on server "connection"
         (fn [sock]
           (when sock
             (.on sock "error" record-ctl-sock-err!))))
    (let [write-ctrl-file!
          (fn []
            (let [actual-port (.-port (.address server))
                  ctrl-info {"port" actual-port
                             "token" token
                             "pid" (or pid 0)
                             "events_out" canon-events-out}
                  json-str (write-json-str ctrl-info)]
              (try
                (write-bytes-atomic! ctrl-file (js/Buffer.from json-str "utf8"))
                (catch :default _ nil))))]
      (.once server "error"
             (fn [err]
               (let [code (.-code err)
                     st-atom (:state-atom ctx)]
                 (when (and st-atom (= code "EADDRINUSE"))
                   (swap! st-atom update-in [:diagnostics :control-port-bind-failed] (fnil inc 0)))
                 (try
                   (binding [*print-fn* *print-err-fn*]
                     (println (str "WARN: Control port " req-port " unavailable (" code "), falling back to ephemeral port")))
                   (catch :default _ nil))
                 (when (= code "EADDRINUSE")
                   (.listen server 0 "127.0.0.1" write-ctrl-file!)))))
      (.listen server req-port "127.0.0.1" write-ctrl-file!))
    {:server server
     :control-file ctrl-file
     :stop! (fn []
              (try (.close server) (catch :default _ nil))
              (try
                (when (.existsSync node-fs ctrl-file)
                  (.unlinkSync node-fs ctrl-file))
                (catch :default _ nil)))}))

(defn run-ctl!
  "Executes a CLI command against a running light-node daemon via loopback control socket."
  [opts]
  (let [state-dir (:state-dir opts)
        control-file (.join node-path state-dir "control.json")]
    (if-not (.existsSync node-fs control-file)
      (let [err {"ok" false "error" "daemon-not-running" "hint" "start daemon with 'serve' first"}]
        (emit-json-line! err)
        (.exit js/process 1))
      (let [control-data (try
                           (parse-json-safe (.readFileSync node-fs control-file "utf8"))
                           (catch :default e
                             {"error" (str e)}))
            port (or (:control-port opts) (get control-data "port") (get control-data :port))
            token (or (get control-data "token") (get control-data :token))
            subverb (:ctl-subverb opts)
            subargs (:ctl-args opts)]
        (if-not (and port token subverb)
          (let [err {"ok" false "error" "invalid-control-metadata-or-subverb"}]
            (emit-json-line! err)
            (.exit js/process 1))
          (let [cmd-map (build-one-shot-cmd-map subverb subargs)
                body-json (write-json-str cmd-map)
                body-buf (.from (.-Buffer js/globalThis) body-json "utf8")
                block? (boolean (or (get cmd-map "block") (get cmd-map :block) (get cmd-map "until_event") (get cmd-map "until-event")))
                timeout-ms (cond
                             (= subverb "wait")
                             (if block?
                               0
                               (+ 5000 (long (or (get cmd-map "timeout_ms") (get cmd-map "timeout-ms") 30000))))
                             (contains? #{"put" "artifact-put"} subverb)
                             60000
                             :else
                             10000)
                req-opts (cond-> #js {:hostname "127.0.0.1"
                                      :port (int port)
                                      :path "/ctl"
                                      :method "POST"
                                      :headers #js {"Authorization" (str "Bearer " token)
                                                    "Content-Type" "application/json"
                                                    "Content-Length" (.-length body-buf)}}
                           (pos? timeout-ms) (doto (unchecked-set "timeout" timeout-ms)))
                req (.request node-http req-opts
                              (fn [res]
                                (let [chunks #js []]
                                  (.on res "data" (fn [c] (.push chunks c)))
                                  (.on res "end"
                                       (fn []
                                         (let [resp-str (.toString (.concat (.-Buffer js/globalThis) chunks) "utf8")
                                               parsed (try (parse-json-safe resp-str) (catch :default _ resp-str))]
                                           (if (map? parsed)
                                             (emit-json-line! parsed)
                                             (.write (.-stdout js/process) (str resp-str "\n")))
                                           (.exit js/process (if (and (map? parsed) (false? (get parsed "ok"))) 1 0))))))))]
            (.on req "error"
                 (fn [err]
                   (emit-json-line! {"ok" false "error" "control-request-failed" "message" (.-message err)})
                   (.exit js/process 1)))
            (when (pos? timeout-ms)
              (.on req "timeout"
                   (fn []
                     (.destroy req)
                     (emit-json-line! {"ok" false "error" "control-request-timeout"})
                     (.exit js/process 1))))
            (.write req body-buf)
            (.end req)))))))

(defn run-auto-sync-tick!
  "Executes a single non-blocking background chain-state quorum sync tick on Node.js
   driven by `bitecho.sync.core/step-auto-sync` (BIP-022 Stage B, Row 5; Rules 2, 4, 5)."
  [state-atom bootstrap identity state-file conn-opts]
  (let [pubkey (or (:pubkey-hex identity) (:pubkey identity))
        privkey (:privkey-bytes identity)
        conn-atom (:conn-atom conn-opts)
        event-out (:event-out conn-opts)
        now-fn (or (:now-ms-fn conn-opts) #(.now js/Date))
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
        should-fetch? (boolean (some #(= :fetch-quorum-sync (:effect %)) tick-effs))
        sync-opts (assoc (or conn-opts {}) :identity identity)]
    (when should-fetch?
      (maybe-sync-account-state!
       state-atom bootstrap pubkey privkey sync-opts
       (fn [res]
         (if (:ok? res)
           (let [finish! (fn []
                           (let [st0 @state-atom
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
                                 st @state-atom]
                             (when state-file
                               (try (save-light-state! state-file st) (catch :default _ nil)))
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

                                 nil))))]
             (if (:auto-register-home-set? conn-opts)
               (let [price (or (:home-set-price conn-opts) 10)
                     hs-res (light-core/handle-command @state-atom {"cmd" "register-home-set" "price" price} privkey)
                     replay-envs (light-core/build-unacked-replay-envelopes @state-atom privkey)
                     envs (into (vec replay-envs) (:net-envelopes hs-res))]
                 (if (seq envs)
                   (if (and conn-atom (connection-live? @conn-atom @state-atom)
                            (send-all-envelopes! (:send-fn @conn-atom) envs))
                     (do
                       (reset! state-atom (assoc (:state hs-res) :connected? true :connection-error nil))
                       (finish!))
                     (if-let [rfn (:reconnect-fn conn-opts)]
                       (rfn (fn [reconn]
                              (if (and (:ok? reconn)
                                       (send-all-envelopes! (:send-fn reconn) envs))
                                (reset! state-atom (assoc (:state hs-res) :connected? true :connection-error nil))
                                (when conn-atom
                                  (apply-conn-event! conn-atom {:type :send-failed :error "auto-register-home-set-send-failed"} conn-opts)
                                  (sync-conn-diagnostics! state-atom conn-atom)))
                              (finish!)))
                       (do
                         (when conn-atom
                           (apply-conn-event! conn-atom {:type :send-failed :error "auto-register-home-set-send-failed"} conn-opts)
                           (sync-conn-diagnostics! state-atom conn-atom))
                         (finish!))))
                   (finish!)))
               (finish!)))
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
                 (event-out (:event eff)))))))))))

(defn- detect-lan-ipv4
  "Finds the first non-internal IPv4 address using node:os networkInterfaces,
   falling back to 127.0.0.1 on exception or if none found."
  []
  (try
    (let [ifaces (.networkInterfaces node-os)
          addrs (for [k (js/Object.keys ifaces)
                      entry (aget ifaces k)
                      :when (and (not (.-internal entry))
                                 (= (.-family entry) "IPv4"))]
                  (.-address entry))]
      (or (first addrs) "127.0.0.1"))
    (catch :default _
      "127.0.0.1")))

(defn- start-light-node-auto-updater!
  "P-UPD-1 / D40.1: Runs the generation-tagged `deploy/reduce-light-update-tick` polling loop
   for Node.js light nodes (`serve` mode). Verifies pointer signature + monotonic version +
   SHA-256 == CID, runs async pre-swap `--version` health check, atomically swaps bundle (with
   `.lkg` rollback backup), emits structured JSONL events, and exits cleanly (`0`) for
   supervisor/driver respawn."
  ([opts identity events-out stop-all! save-state-fn!]
   (start-light-node-auto-updater! opts identity events-out stop-all! save-state-fn! nil))
  ([opts identity events-out stop-all! save-state-fn! conn-atom]
   (when-let [pointer-url (:auto-update-pointer opts)]
     (let [bundle-path (when (exists? js/__filename) js/__filename)
           current-cid (try
                         (when (and bundle-path (.existsSync node-fs bundle-path))
                           (let [h (.createHash node-crypto "sha256")]
                             (.update h (.readFileSync node-fs bundle-path))
                             (.digest h "hex")))
                         (catch :default _ nil))
           proxy-url (resolve-proxy-url (:proxy opts))
           poll-ms (max 5000 (long (or (:auto-update-interval-ms opts) 60000)))
           trusted-auths (if (contains? opts :trusted-deploy-authorities)
                           (:trusted-deploy-authorities opts)
                           config/default-trusted-deploy-authorities)
           updater-atom (atom (deploy/init-light-updater-state
                               (cond-> {:node-id (or (:peer-id identity) "light-node")
                                        :artifact-role :light-node
                                        :current-version "0.23.22"
                                        :current-cid current-cid
                                        :pointer-url pointer-url
                                        :force-http? (boolean (:auto-update-force-http? opts))
                                        :trusted-deploy-authorities trusted-auths
                                        :pinned-version (:pin-version opts)
                                        :proxy-url proxy-url
                                        :poll-interval-ms poll-ms}
                                 (some? (:last-applied-seq opts)) (assoc :last-applied-seq (long (:last-applied-seq opts))))))
           staged-bytes-atom (atom nil)
           staged-path-atom (atom nil)
           stage-write-promise-atom (atom nil)
           retry-timer-atom (atom nil)
           dispatch! (fn dispatch! [ev]
                       (let [effs-box (atom [])]
                         (swap! updater-atom
                                (fn [st]
                                  (let [[st' effs] (deploy/reduce-light-update-tick st ev)]
                                    (reset! effs-box effs)
                                    st')))
                         (doseq [eff @effs-box]
                           (case (:effect eff)
                             :fetch-pointer
                             (let [gen (:generation eff)]
                               (http-get-bytes!
                                pointer-url (:proxy-url eff) 15000
                                (fn [res]
                                  (if (:ok? res)
                                    (let [txt (fressian/bytes->utf8 (:bytes res))
                                          ptr (try (edn/read-string txt) (catch :default _ nil))]
                                      (if (map? ptr)
                                        (let [mesh-ok? (boolean (and conn-atom (fn? (:send-fn @conn-atom))))]
                                          (dispatch! {:type :pointer-seen
                                                      :pointer ptr
                                                      :pointer-url pointer-url
                                                      :mesh-connected? mesh-ok?
                                                      :generation gen}))
                                        (emit-json-line! {"event" "auto-update-diagnose"
                                                          "reason" "malformed-pointer-edn"
                                                          "url" pointer-url}
                                                         events-out)))
                                    (emit-json-line! {"event" "auto-update-diagnose"
                                                      "reason" "fetch-pointer-failed"
                                                      "status" (:status res)
                                                      "error" (:error res)}
                                                     events-out)))))

                             :fetch-bundle-mesh-chunks
                             (let [gen (:generation eff)
                                   cid (:cid eff)
                                   chunk-bytes (or (:chunk-size-bytes eff) deploy/default-mesh-chunk-size-bytes)
                                   probe-ms (or (:probe-timeout-ms eff) 3000)
                                   chunk-ms (or (:chunk-timeout-ms eff) 5000)
                                   total-ms (or (:total-timeout-ms eff) 15000)
                                   send-fn (when conn-atom (:send-fn @conn-atom))]
                               (if-not (fn? send-fn)
                                 (dispatch! {:type :mesh-fetch-failed
                                             :cid cid
                                             :reason :mesh-disconnected
                                             :generation gen})
                                 (let [req-id (str "mesh-upd-" gen "-" (subs (str cid) 0 (min 8 (count (str cid)))) "-" (.now js/Date))
                                       asm-atom (atom (deploy/init-mesh-chunk-assembly cid chunk-bytes))
                                       settled? (atom false)
                                       chunk-timer (atom nil)
                                       total-timer (atom nil)
                                       cleanup! (fn []
                                                  (swap! mesh-chunk-handlers-atom dissoc req-id)
                                                  (when-let [t @chunk-timer]
                                                    (js/clearTimeout t)
                                                    (reset! chunk-timer nil))
                                                  (when-let [t @total-timer]
                                                    (js/clearTimeout t)
                                                    (reset! total-timer nil)))
                                       fail! (fn [reason]
                                               (when (compare-and-set! settled? false true)
                                                 (cleanup!)
                                                 (dispatch! {:type :mesh-fetch-failed
                                                             :cid cid
                                                             :reason reason
                                                             :generation gen})))
                                       send-chunk! (fn send-chunk! [offset length timeout-ms retried?]
                                                     (when-let [t @chunk-timer]
                                                       (js/clearTimeout t))
                                                     (reset! chunk-timer
                                                             (js/setTimeout
                                                              (fn []
                                                                (if (and (not @settled?) (not retried?))
                                                                  (send-chunk! offset length chunk-ms true)
                                                                  (fail! :mesh-chunk-timeout)))
                                                              timeout-ms))
                                                     (try
                                                       (let [req (deploy/build-mesh-chunk-request cid offset length req-id)
                                                             pk-hex (or (:pubkey-hex identity) (:pubkey identity))
                                                             wire (core-mesh/wrap-agent-event req pk-hex (:privkey-bytes identity))]
                                                         (send-fn wire))
                                                       (catch :default _
                                                         (fail! :mesh-send-failed))))
                                       on-chunk-res (fn [res]
                                                      (when (and (not @settled?)
                                                                 (= req-id (:req-id res)))
                                                        (let [step (deploy/reduce-mesh-chunk-response @asm-atom res)]
                                                          (cond
                                                            (not (:ok? step))
                                                            (fail! (or (:error step) :mesh-chunk-error))

                                                            (:done? step)
                                                            (when (compare-and-set! settled? false true)
                                                              (cleanup!)
                                                              (reset! staged-bytes-atom (:bytes step))
                                                              (dispatch! {:type :blob-fetched
                                                                          :cid cid
                                                                          :bytes (:bytes step)
                                                                          :source :mesh
                                                                          :generation gen}))

                                                            :else
                                                            (do
                                                              (reset! asm-atom (:state step))
                                                              (send-chunk! (get-in step [:next-req :offset])
                                                                           (get-in step [:next-req :length])
                                                                           chunk-ms
                                                                           false))))))]
                                   (swap! mesh-chunk-handlers-atom assoc req-id on-chunk-res)
                                   (reset! total-timer (js/setTimeout #(fail! :mesh-total-timeout) total-ms))
                                   (send-chunk! 0 chunk-bytes probe-ms false))))

                             :schedule-http-retry
                             (let [gen (:generation eff)
                                   delay-ms (max 100 (long (or (:delay-ms eff) 1000)))]
                               (when-let [prev @retry-timer-atom]
                                 (js/clearTimeout prev))
                               (reset! retry-timer-atom
                                       (js/setTimeout #(dispatch! {:type :http-retry-timer-fired :generation gen})
                                                      delay-ms)))

                             :fetch-bundle-blob
                             (let [gen (:generation eff)
                                   cid (:cid eff)
                                   range-vec (:range eff)
                                   blob-url (or (:url eff) (deploy/build-blob-fetch-url pointer-url cid))
                                   timeout-ms (if range-vec 15000 30000)]
                               (http-get-bytes!
                                blob-url (:proxy-url eff) timeout-ms
                                {:range range-vec :total-timeout-ms timeout-ms}
                                (fn [res]
                                  (cond
                                    (and range-vec (:ok? res) (= 206 (:status res)))
                                    (if-let [cr (deploy/parse-content-range (:content-range res))]
                                      (dispatch! {:type :http-range-chunk-fetched
                                                  :status 206
                                                  :start (:start cr)
                                                  :end (:end cr)
                                                  :total-bytes (:total-bytes cr)
                                                  :bytes (:bytes res)
                                                  :etag (:etag res)
                                                  :generation gen})
                                      (dispatch! {:type :blob-fetch-failed
                                                  :cid cid
                                                  :status 206
                                                  :reason :malformed-content-range
                                                  :generation gen}))

                                    (and range-vec (:ok? res) (= 200 (:status res)))
                                    (do
                                      (reset! staged-bytes-atom (:bytes res))
                                      (dispatch! {:type :http-range-chunk-fetched
                                                  :status 200
                                                  :bytes (:bytes res)
                                                  :generation gen}))

                                    (:ok? res)
                                    (do
                                      (reset! staged-bytes-atom (:bytes res))
                                      (dispatch! {:type :blob-fetched :cid cid :bytes (:bytes res) :generation gen}))

                                    :else
                                    (do
                                      (emit-json-line! {"event" "auto-update-diagnose"
                                                        "reason" "fetch-bundle-blob-failed"
                                                        "cid" cid
                                                        "url" blob-url
                                                        "status" (:status res)
                                                        "error" (:error res)}
                                                       events-out)
                                      (dispatch! (cond-> {:type :blob-fetch-failed
                                                          :cid cid
                                                          :status (:status res)
                                                          :reason (or (:error res) :http-fetch-failed)
                                                          :aborted-mid-body? (true? (:aborted-mid-body? res))
                                                          :received-bytes (long (or (:received-bytes res) 0))
                                                          :generation gen}
                                                   (:total-bytes res) (assoc :total-bytes (:total-bytes res))
                                                   (:partial-bytes res) (assoc :partial-bytes (:partial-bytes res))
                                                   (:etag res) (assoc :etag (:etag res)))))))))

                             :stage-light-bundle
                             (let [bs (or (:bytes eff) @staged-bytes-atom)]
                               (when (and bundle-path bs)
                                 (reset! staged-bytes-atom bs)
                                 (let [dir (.dirname node-path bundle-path)
                                       cid8 (subs (str (:cid eff)) 0 (min 8 (count (str (:cid eff)))))
                                       tmp-p (.join node-path dir (str ".bitecho-update-" cid8 ".cjs.tmp"))
                                       buf (.from js/Buffer (.-buffer bs)
                                                  (.-byteOffset bs)
                                                  (.-byteLength bs))]
                                   (reset! staged-path-atom tmp-p)
                                   (reset! stage-write-promise-atom
                                           (-> (.writeFile node-fsp tmp-p buf #js {:mode 0755})
                                               (.catch (fn [e]
                                                         (emit-json-line! {"event" "auto-update-diagnose"
                                                                           "reason" "stage-write-failed"
                                                                           "detail" (.-message e)}
                                                                          events-out)
                                                         (throw e))))))))

                             :atomic-swap-and-restart-light-node
                             (let [gen (:generation eff)
                                   cid (:cid eff)
                                   tmp-p @staged-path-atom
                                   write-p (or @stage-write-promise-atom (js/Promise.resolve nil))]
                               (when (and bundle-path tmp-p)
                                 (-> write-p
                                     (.then (fn [_]
                                              (.execFile node-child-process
                                                         (.-execPath js/process)
                                                         #js [tmp-p "--help"]
                                                         #js {:timeout 10000}
                                                         (fn [err _stdout _stderr]
                                                           (if err
                                                             (dispatch! {:type :health-check-result :healthy? false :generation gen})
                                                             (let [lkg-p (str bundle-path ".lkg")]
                                                               (-> (.copyFile node-fsp bundle-path lkg-p)
                                                                   (.catch (fn [_] nil))
                                                                   (.then (fn [_] (.rename node-fsp tmp-p bundle-path)))
                                                                   (.then (fn [_]
                                                                            (emit-json-line! {"event" "auto-update-applied"
                                                                                              "cid" cid
                                                                                              "restarting" true}
                                                                                             events-out)
                                                                            (when save-state-fn! (save-state-fn!))
                                                                            (when stop-all! (stop-all!))
                                                                            (.exit js/process 0)))
                                                                   (.catch (fn [e]
                                                                             (emit-json-line! {"event" "auto-update-diagnose"
                                                                                               "reason" "atomic-swap-failed"
                                                                                               "detail" (.-message e)}
                                                                                              events-out)
                                                                             (dispatch! {:type :health-check-result :healthy? false :generation gen}))))))))))
                                     (.catch (fn [_]
                                               (dispatch! {:type :health-check-result :healthy? false :generation gen}))))))

                             :restore-lkg-light-bundle
                             (do
                               (when-let [tmp-p @staged-path-atom]
                                 (-> (.unlink node-fsp tmp-p) (.catch (fn [_] nil))))
                               (emit-json-line! {"event" "auto-update-rolled-back"
                                                 "lkg_version" (:lkg-version eff)
                                                 "lkg_cid" (:lkg-cid eff)}
                                                events-out))

                             :diagnose
                             (emit-json-line! {"event" "auto-update-diagnose"
                                               "reason" (name (or (:reason eff) :unknown))
                                               "cause" (when (:cause eff) (name (:cause eff)))}
                                              events-out)

                             :obs-record
                             (emit-json-line! {"event" "auto-update-obs"
                                               "transition" (name (or (get-in eff [:record :data :transition]) :unknown))}
                                              events-out)

                             nil))))
           t0 (js/setTimeout #(dispatch! {:type :poll-tick}) 15000)
           iv (js/setInterval #(dispatch! {:type :poll-tick}) poll-ms)]
       (fn []
         (js/clearTimeout t0)
         (js/clearInterval iv)
         (when-let [rt @retry-timer-atom]
           (js/clearTimeout rt)
           (reset! retry-timer-atom nil)))))))

(defn- node-pid-alive?
  [pid]
  (if (and (number? pid) (pos? pid))
    (try
      (.kill js/process (int pid) 0)
      true
      (catch :default e
        (= "EPERM" (.-code e))))
    false))

(defn- generate-node-lock-token
  []
  (try
    (.toString (.randomBytes ^js node-crypto 8) "hex")
    (catch :default _
      (str (.now js/Date) "-" (.-pid js/process)))))

(defn- node-write-lock-exclusive!
  "OS-atomic O_CREAT|O_EXCL|O_WRONLY (mode 0600) write + fsyncSync + closeSync.
   Returns `:created` or `:exists`."
  [lock-path payload-map]
  (let [consts (.-constants ^js node-fs)
        flags (bit-or (.-O_CREAT ^js consts)
                      (.-O_EXCL ^js consts)
                      (.-O_WRONLY ^js consts))
        data (pr-str payload-map)]
    (try
      (let [fd (.openSync ^js node-fs lock-path flags 0600)]
        (try
          (.writeSync ^js node-fs fd data nil "utf8")
          (.fsyncSync ^js node-fs fd)
          (finally
            (.closeSync ^js node-fs fd))))
      :created
      (catch :default e
        (if (= "EEXIST" (.-code e))
          :exists
          (throw e))))))

(defn- node-read-existing-lock-holder
  [lock-path ctrl-path]
  (let [lock-info (when (.existsSync ^js node-fs lock-path)
                    (try (edn/read-string (.readFileSync ^js node-fs lock-path "utf8"))
                         (catch :default _ nil)))
        ctrl-info (when (.existsSync ^js node-fs ctrl-path)
                    (try (js->clj (.parse js/JSON (.readFileSync ^js node-fs ctrl-path "utf8")))
                         (catch :default _ nil)))
        raw-pid (or (when (map? lock-info) (:pid lock-info))
                    (when (map? ctrl-info) (or (get ctrl-info "pid") (:pid ctrl-info))))
        pid-num (when (some? raw-pid)
                  (let [n (js/Number raw-pid)]
                    (when (and (js/Number.isFinite n) (pos? n)) (long n))))]
    (when (or (map? lock-info) (some? pid-num))
      {:pid pid-num
       :token (when (map? lock-info) (:token lock-info))
       :timestamp-ms (when (map? lock-info) (:timestamp-ms lock-info))})))

(defn acquire-serve-lock!
  "OS-atomic single-instance `serve.lock` guard for Node.js (`BIP-022` Stage B Row 10; Rules 4 & 5).
   Driven by `bitecho.lifecycle.lock-core/transition-lock` using `O_CREAT|O_EXCL|O_WRONLY` (`0600`)."
  ([state-dir] (acquire-serve-lock! state-dir nil))
  ([state-dir {:keys [current-pid pid-alive-fn timestamp-ms token]}]
   (let [dir (or state-dir ".")
         _ (when-not (.existsSync ^js node-fs dir)
             (.mkdirSync ^js node-fs dir #js {:recursive true :mode 0700}))
         lock-path (.join ^js node-path dir "serve.lock")
         ctrl-path (.join ^js node-path dir "control.json")
         my-pid (long (or current-pid (.-pid js/process)))
         my-tok (or token (generate-node-lock-token))
         alive-fn (or pid-alive-fn node-pid-alive?)
         now-ms (long (or timestamp-ms (.now js/Date)))
         ctrl-holder (when (and (not (.existsSync ^js node-fs lock-path))
                                (.existsSync ^js node-fs ctrl-path))
                       (node-read-existing-lock-holder lock-path ctrl-path))
         init-st (lock-core/init-lock-state {:mode :pid-file
                                             :lock-id lock-path
                                             :self-id my-pid
                                             :token my-tok
                                             :runtime "nodejs"
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
                              (node-write-lock-exclusive! lock-path (:payload action-eff)))]
             (if (= :created create-res)
               (let [[st' effs'] (lock-core/transition-lock cur-st {:type :create-exclusive-ok
                                                                    :generation (:generation action-eff)
                                                                    :now-ms now-ms})]
                 (recur st' effs' next-diags))
               (let [holder (or (node-read-existing-lock-holder lock-path ctrl-path) ctrl-holder)
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
             (when (.existsSync ^js node-fs lock-path)
               (try (.unlinkSync ^js node-fs lock-path) (catch :default _ nil)))
             (let [recreate-res (node-write-lock-exclusive! lock-path (:payload action-eff))]
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
                      :lock-file lock-path
                      :reclaimed-stale-lock? reclaimed?
                      :lock-state cur-st
                      :effects next-diags}
               reclaimed? (assoc :stale-pid stale-pid)))

           :reject-duplicate
           (let [canon-err (:error action-eff)
                 locked-pid (:holder-pid cur-st)
                 diag (first (filter #(= :duplicate-serve-instance-rejected (:reason %)) next-diags))]
             {:ok? false
              :error "duplicate-instance"
              :canonical-error canon-err
              :locked-pid locked-pid
              :attempted-pid my-pid
              :lock-state cur-st
              :diagnose diag
              :effects next-diags})

           {:ok? false
            :error "lock-acquisition-failed"
            :lock-state cur-st
            :effects next-diags}))))))

(defn release-serve-lock!
  "Releases `<state-dir>/serve.lock` only if on-disk `:pid` and `:token` match self."
  ([state-dir] (release-serve-lock! state-dir nil nil))
  ([state-dir expected-pid] (release-serve-lock! state-dir expected-pid nil))
  ([state-dir expected-pid expected-token]
   (when state-dir
     (let [lock-path (.join ^js node-path state-dir "serve.lock")]
       (when (.existsSync ^js node-fs lock-path)
         (let [info (try (edn/read-string (.readFileSync ^js node-fs lock-path "utf8"))
                         (catch :default _ nil))
               owner-pid (when (map? info) (:pid info))
               owner-tok (when (map? info) (:token info))
               pid-ok? (or (nil? expected-pid)
                           (nil? owner-pid)
                           (= (long expected-pid) (long owner-pid)))
               tok-ok? (or (nil? expected-token)
                           (nil? owner-tok)
                           (= (str expected-token) (str owner-tok)))]
           (when (and pid-ok? tok-ok?)
             (try (.unlinkSync ^js node-fs lock-path) (catch :default _ false)))))))))

(defn run-serve!
  "Runs the Node.js light node in continuous JSONL `serve` mode reading STDIN (and optional `--cmd-file`)
   and writing STDOUT (and optional `--events-out`). Enforces OS-atomic `serve.lock` (Row 10)."
  [opts]
  (let [state-dir (:state-dir opts)
        events-out (:events-out opts)
        lock-res (if (:skip-single-instance-lock? opts)
                   {:ok? true
                    :locked-pid (.-pid js/process)
                    :lock-state (assoc (lock-core/init-lock-state {:mode :pid-file
                                                                   :lock-id (.join ^js node-path state-dir "serve.lock")
                                                                   :self-id (.-pid js/process)
                                                                   :runtime "nodejs"})
                                       :role :single
                                       :holder-pid (.-pid js/process))}
                   (acquire-serve-lock! state-dir opts))]
    (if-not (:ok? lock-res)
      (let [canon-wire (errors/canonical-error->wire
                        (or (:canonical-error lock-res)
                            (errors/canonical-error :duplicate-instance
                                                    {:locked-pid (:locked-pid lock-res)
                                                     :attempted-pid (:attempted-pid lock-res)
                                                     :lock-file (.join ^js node-path state-dir "serve.lock")})))]
        (emit-json-line! (merge canon-wire
                                {"event" "duplicate-serve-rejected"
                                 "locked_pid" (:locked-pid lock-res)
                                 "diagnose" "duplicate-serve-instance-rejected"})
                         events-out)
        (.exit js/process 1))
      (let [my-lock-pid (:locked-pid lock-res)
            my-lock-token (:token lock-res)
            lock-state (:lock-state lock-res)
            _ (when (:reclaimed-stale-lock? lock-res)
                (emit-json-line! {"event" "stale-serve-lock-reclaimed"
                                  "stale_pid" (:stale-pid lock-res)
                                  "pid" my-lock-pid}
                                 events-out))
            state-file (.join node-path state-dir "state.fressian")
            cmd-file (:cmd-file opts)
            identity (load-or-create-light-identity! state-dir opts)]
        (load-bootstrap-descriptor!
         (:bootstrap opts) nil
         (fn [b-res]
           (if-not (:ok? b-res)
             (do
               (release-serve-lock! state-dir my-lock-pid my-lock-token)
               (emit-json-line! {"event" "connection-failed" "connected" false "error" (:error b-res)} events-out)
               (.exit js/process 1))
             (let [bootstrap (:descriptor b-res)
                   loaded-state (load-light-state! state-file)
                   reconciled-res (when loaded-state
                                    (light-core/reconcile-startup-subnet-id
                                     loaded-state
                                     (:subnet-id opts)
                                     (:subscribe-subnets opts)
                                     {:reset-network-state? (boolean (:reset-network-state? opts))}))
                   _ (when (and reconciled-res (false? (:ok? reconciled-res)))
                       (emit-json-line! {"event" "cross-network-subnet-switch-blocked"
                                         "ok" false
                                         "error" "cross-network-subnet-switch-blocked"
                                         "from" (:subnet-id loaded-state)
                                         "to" (:subnet-id opts)}
                                        events-out)
                       (.exit js/process 1))
                   _ (when (and reconciled-res (:reconciled? reconciled-res))
                       (doseq [ev (:stdout-events reconciled-res)]
                         (emit-json-line! ev events-out)))
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
                   initial-state-raw (cond-> (assoc base-state :max-epoch-skew (or (:max-epoch-skew opts) (:max-epoch-skew base-state) 15))
                                       (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                                       (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                                       (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap)))
                                       (:pin-version opts) (assoc :pin-version (:pin-version opts))
                                       (:auto-update-pointer opts) (assoc :auto-update-pointer (:auto-update-pointer opts))
                                       (seq (:trusted-deploy-authorities opts)) (assoc :trusted-deploy-authorities (:trusted-deploy-authorities opts)))
                   dac-rec (flags/reconcile-trusted-dac-anchors initial-state-raw
                                                                (:trusted-dac-anchors-spec opts)
                                                                (:trusted-dac-anchors bootstrap))
                   initial-state (apply-startup-identity-and-load-diagnostics! (:state dac-rec) identity)
                   _ (doseq [ev (:stdout-events dac-rec)]
                       (emit-json-line! ev events-out))
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
                       (.write (.-stderr js/process)
                               (str (write-json-str {"event" "startup-security-flags" "security_flags" sec-echo}) "\n")))
                   _ (when (or (and reconciled-res (:reconciled? reconciled-res))
                               (seq (:effects dac-rec)))
                       (try (save-light-state! state-file initial-state) (catch :default _ nil)))
                   state-atom (atom initial-state)
                   _ (when (and (:pending-corrupt-auto-restore? @state-atom)
                                (not= (:connect? opts) false))
                       (let [auto-relay (or (:relay-url opts)
                                            (:relay_url opts)
                                            (:relay-url bootstrap)
                                            (when (= "bitecho.org" (:domain bootstrap)) "https://ns1.bitecho.org"))]
                         (if (str/blank? (str auto-relay))
                           (do
                             (swap! state-atom #(-> (dissoc % :pending-corrupt-auto-restore?)
                                                    (update-in [:diagnostics :local-state-corrupt-auto-restore-failed] (fnil inc 0))))
                             (emit-stderr-diagnose! {:reason :local-state-corrupt-auto-restore-failed :detail "no-relay-url"}))
                           (handle-node-stage-c-verb!
                            "backup-restore"
                            {"cmd" "backup-restore" "relay_url" auto-relay}
                            state-atom identity state-dir state-file auto-relay opts
                            (fn [res]
                              (if (:ok? res)
                                (do
                                  (swap! state-atom #(-> (dissoc % :pending-corrupt-auto-restore?)
                                                         (update-in [:diagnostics :local-state-corrupt-auto-restored] (fnil inc 0))))
                                  (try (save-light-state! state-file @state-atom) (catch :default _ nil))
                                  (emit-stderr-diagnose! {:reason :local-state-corrupt-auto-restored
                                                          :detail (get-in res [:response "cid"] "restored")}))
                                (let [err-str (get-in res [:response "error"] "backup-restore-failed")
                                      reason (if (= "backup-not-found" err-str)
                                               :local-state-corrupt-no-backup
                                               :local-state-corrupt-auto-restore-failed)]
                                  (swap! state-atom #(-> (dissoc % :pending-corrupt-auto-restore?)
                                                         (update-in [:diagnostics reason] (fnil inc 0))))
                                  (emit-stderr-diagnose! {:reason reason :detail err-str}))))))))
                   conn-atom (atom (init-conn-state))
                   event-out (fn [ev] (emit-json-line! ev events-out))
                   conn-opts-atom (atom nil)
                   reconnect-fn
                   (fn [cb]
                     (when conn-atom
                       (apply-conn-event! conn-atom {:type :dial-started} @conn-opts-atom))
                     (let [target-gen (if conn-atom (:generation @conn-atom 0) 1)
                           cursor (if conn-atom (:validator-cursor @conn-atom 0) 0)
                           home-set (if state-atom (:home-set @state-atom) [])
                           opts-with-gen (assoc (or @conn-opts-atom {})
                                                :generation target-gen
                                                :validator-cursor cursor
                                                :home-set home-set)]
                       (connect-validators!
                        identity bootstrap opts-with-gen
                        (fn [reconn]
                          (if (:ok? reconn)
                            (do
                              (when conn-atom
                                (apply-conn-event! conn-atom (assoc reconn :type :dial-ok :generation target-gen) @conn-opts-atom))
                              (swap! state-atom assoc :connected? true :connection-error nil)
                              (sync-conn-diagnostics! state-atom conn-atom)
                              (let [recovery-envs (build-reconnect-recovery-envelopes @state-atom (:privkey-bytes identity))]
                                (when (seq recovery-envs)
                                  (send-all-envelopes! (:send-fn reconn) recovery-envs)))
                              (when cb (cb reconn)))
                            (let [err (or (:error reconn) "listener-disabled")]
                              (when conn-atom
                                (apply-conn-event! conn-atom {:type :dial-failed :error err :node (:node reconn) :generation target-gen} @conn-opts-atom))
                              (swap! state-atom assoc :connected? false :connection-error err)
                              (sync-conn-diagnostics! state-atom conn-atom)
                              (when cb (cb reconn))))))))
                   mdns-host (mdns/generate-mdns-hostname)
                   lan-ip (detect-lan-ipv4)
                   ingress-port (int (or (:ingress-tcp-port opts) 0))
                   default-cands (if (pos? ingress-port)
                                   [(str "tcp://" mdns-host ":" ingress-port)
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
                            :runtime-ctx {:runtime :nodejs
                                          :lock-state lock-state
                                          :sync-state @sync-atom})
                   mdns-svc (try (mdns/start-mdns-service! {:initial-hosts {mdns-host lan-ip}}) (catch :default _ nil))
                   mdns-atom (or mdns-svc (atom (mdns/init-mdns-table)))
                   p2p-peers-atom (atom {})
                   ingress-peers-atom (atom {})
                   conn-opts (assoc opts
                                    :state-atom state-atom
                                    :conn-atom conn-atom
                                    :sync-atom sync-atom
                                    :event-out event-out
                                    :reconnect-fn reconnect-fn
                                    :ingress-peers-atom ingress-peers-atom
                                    :p2p-peers-atom p2p-peers-atom
                                    :mdns-atom mdns-atom
                                    :mdns-svc mdns-svc
                                    :state-file state-file)
                   _ (reset! conn-opts-atom conn-opts)
                   ingress-listener (start-ingress-tcp-listener! identity conn-opts)
                   ctx {:state-atom state-atom
                        :conn-atom conn-atom
                        :events-out events-out
                        :state-file state-file
                        :identity identity
                        :bootstrap bootstrap
                        :ingress-peers-atom ingress-peers-atom
                        :p2p-peers-atom p2p-peers-atom
                        :mdns-atom mdns-atom
                        :conn-opts conn-opts}
                   ctrl-svc (try (start-control-server! state-dir ctx opts) (catch :default _ nil))
                   maint-timer (atom nil)
                   stop-updater-atom (atom nil)
                   stop-all! (fn []
                               (when-let [su @stop-updater-atom] (try (su) (catch :default _ nil)))
                               (when @maint-timer (try (js/clearInterval @maint-timer) (catch :default _ nil)))
                               (when mdns-svc (try (mdns/stop-mdns-service! mdns-svc) (catch :default _ nil)))
                               (when-let [stop-fn (:stop! ingress-listener)]
                                 (try (stop-fn) (catch :default _ nil)))
                               (when-let [stop-ctrl (:stop! ctrl-svc)]
                                 (try (stop-ctrl) (catch :default _ nil)))
                               (release-serve-lock! state-dir my-lock-pid my-lock-token))
                   _ (when-let [su (start-light-node-auto-updater!
                                    opts identity events-out stop-all!
                                    #(save-light-state! state-file @state-atom)
                                    conn-atom)]
                       (reset! stop-updater-atom su))
                   _ (.on js/process "exit" (fn [_] (stop-all!)))
                   _ (.on js/process "beforeExit" (fn [_] (stop-all!)))
                   _ (.on js/process "SIGINT" (fn [] (stop-all!) (.exit js/process 0)))
                   _ (.on js/process "SIGTERM" (fn [] (stop-all!) (.exit js/process 0)))
                   line-queue (atom [])
                   processing? (atom false)
                   drain-queue!
                   (fn drain! []
                     (when (compare-and-set! processing? false true)
                       (if-let [next-line (first @line-queue)]
                         (do
                           (swap! line-queue #(vec (rest %)))
                           (handle-serve-line!
                            next-line ctx
                            (fn [_]
                              (reset! processing? false)
                              (drain!))))
                         (reset! processing? false))))
                   enqueue-line!
                   (fn [line]
                     (when-not (str/blank? line)
                       (swap! line-queue conj line)
                       (drain-queue!)))
                   _ (let [maint-tick!
                           (fn []
                             (try
                               (let [now-ms (.now js/Date)
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
                                             (emit-json-line! evt events-out)))))
                                     (catch :default _ nil)))
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
                                       (enqueue-line! (write-json-str cmd))))))
                               (catch :default _ nil)))]
                       (reset! maint-timer (js/setInterval maint-tick! 5000)))]
               (reconnect-fn
                (fn [conn-res]
                  (if (:ok? conn-res)
                    (emit-json-line! {"event" "ready"
                                      "connected" true
                                      "transport" (if (and (string? (:relay-url opts)) (not (str/blank? (:relay-url opts))))
                                                    "http-relay"
                                                    (name (or (:transport opts) :udp)))}
                                     events-out)
                    (emit-json-line! {"event" "connection-failed"
                                      "connected" false
                                      "error" (:error conn-res)}
                                     events-out))
                  (let [effective-relay-url (when-not (:no-poll? opts)
                                              (or (when (and (string? (:relay-url opts)) (not (str/blank? (:relay-url opts))))
                                                    (:relay-url opts))
                                                  (:relay-url bootstrap)
                                                  (get-in bootstrap [:relay :url])
                                                  (when (= (:domain bootstrap) "bitecho.org")
                                                    "https://ns1.bitecho.org")))]
                    (when (and (string? effective-relay-url) (not (str/blank? effective-relay-url)))
                      (let [since-mseq (atom (long (or (:relay-since-seq @state-atom) 0)))
                            since-bseq (atom (long (or (:relay-since-broadcast-seq @state-atom) 0)))
                            polling? (atom false)
                            poll-tick!
                            (fn poll-tick! []
                              (when (compare-and-set! polling? false true)
                                (let [eff-subnets (vec (sort (light-core/effective-subscribed-subnets @state-atom)))
                                      subnets (or (:subnets opts) eff-subnets)]
                                  (poll-relay-envelopes!
                                   effective-relay-url
                                   (or (:pubkey-hex identity) (:pubkey identity))
                                   (:privkey-bytes identity)
                                   (cond-> {:since-seq @since-mseq
                                            :since-broadcast-seq @since-bseq
                                            :timeout-ms 2000}
                                     subnets (assoc :subnets subnets))
                                   (fn [poll-res]
                                     (try
                                       (let [msgs (or (get poll-res "messages") (get poll-res :messages) [])
                                             bcasts (or (get poll-res "broadcasts") (get poll-res :broadcasts) [])
                                             last-bseq (or (get poll-res "last_broadcast_seq")
                                                           (get poll-res "last-broadcast-seq")
                                                           (get poll-res :last_broadcast_seq))
                                             all-items (concat msgs bcasts)
                                             old-bseq @since-bseq]
                                         (when (seq msgs)
                                           (let [last-m (last msgs)
                                                 mseq (or (get last-m "relay_seq") (get last-m "relay-seq")
                                                          (get last-m :relay_seq) (get last-m :relay-seq))]
                                             (when mseq (reset! since-mseq (long mseq)))))
                                         (let [bseq (or last-bseq
                                                        (when (seq bcasts)
                                                          (let [last-b (last bcasts)]
                                                            (or (get last-b "broadcast_seq") (get last-b "broadcast-seq")
                                                                (get last-b :broadcast_seq) (get last-b :broadcast-seq)))))]
                                           (when bseq (reset! since-bseq (long bseq))))
                                         (swap! state-atom assoc :relay-since-seq @since-mseq :relay-since-broadcast-seq @since-bseq)
                                         (doseq [item all-items]
                                           (let [env-raw (or (get item "envelope_hex") (get item "envelope")
                                                             (get item :envelope_hex) (get item :envelope))
                                                 wire-bytes (when env-raw
                                                              (try (basalt/hex->bytes (str env-raw)) (catch :default _ nil)))]
                                             (when wire-bytes
                                               (let [st @state-atom
                                                     r (light-core/handle-wire-payload st wire-bytes (:privkey-bytes identity))]
                                                 (reset! state-atom (:state r))
                                                 (when state-file
                                                   (try (save-light-state! state-file (:state r)) (catch :default _ nil)))
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
                                                         (submit-relay-envelope! effective-relay-url env (fn [_] nil) {:timeout-ms 5000})
                                                         (catch :default _ nil)))))))))
                                         (when (or (seq msgs) (seq bcasts) (> @since-bseq old-bseq))
                                           (ack-relay-envelopes!
                                            effective-relay-url
                                            (or (:pubkey-hex identity) (:pubkey identity))
                                            (:privkey-bytes identity)
                                            @since-mseq
                                            {:ack-broadcast-seq @since-bseq})))
                                       (finally
                                         (reset! polling? false))))))))]
                        (poll-tick!)
                        (js/setInterval poll-tick! 1000))))
                  (when (boolean (:auto-sync? opts true))
                    (let [sync-interval-ms (max 1000 (or (:sync-interval-ms opts) 15000))]
                      (run-auto-sync-tick! state-atom bootstrap identity state-file conn-opts)
                      (js/setInterval
                       #(run-auto-sync-tick! state-atom bootstrap identity state-file conn-opts)
                       sync-interval-ms)))
                  (when (and cmd-file (not (str/blank? (str cmd-file))))
                    (let [cf (str cmd-file)
                          parent (.dirname node-path cf)
                          _ (when parent (.mkdirSync node-fs parent #js {:recursive true}))
                          _ (when-not (.existsSync node-fs cf) (.writeFileSync node-fs cf "" "utf8"))
                          offset-atom (atom (.-size (.statSync node-fs cf)))]
                      (js/setInterval
                       (fn []
                         (let [{:keys [lines next-offset]} (try
                                                             (read-new-cmd-file-lines! cf @offset-atom)
                                                             (catch :default _
                                                               {:lines [] :next-offset @offset-atom}))]
                           (reset! offset-atom next-offset)
                           (doseq [ln lines]
                             (enqueue-line! ln))))
                       50)))
                  (let [rl (.createInterface node-readline #js {:input (.-stdin js/process)
                                                                :terminal false})]
                    (.on rl "line" (fn [line] (enqueue-line! line)))
                    (.on rl "close" (fn []
                                      (when-not (and cmd-file (not (str/blank? (str cmd-file))))
                                        (js/setTimeout #(.exit js/process 0) 100)))))))))))))))

(defn- pid-alive? [pid]
  (try
    (boolean (.kill js/process (long pid) 0))
    (catch :default e
      (= (.-code e) "EPERM"))))

(defn- try-delegate-one-shot-to-daemon!
  "If <state-dir>/control.json exists and the daemon's /ctl socket is reachable,
   delegates the one-shot command map to the running serve daemon (Rule 4).
   If unreachable and the daemon process is alive, fails closed with daemon-control-unreachable (F-D25-1).
   Invokes (cb result) if handled/rejected, or (cb nil) to proceed with one-shot."
  [state-dir cmd-map opts cb]
  (let [ctrl-file (when state-dir (.join node-path state-dir "control.json"))]
    (if-not (and ctrl-file (.existsSync node-fs ctrl-file) (map? cmd-map) (contains? cmd-map "cmd"))
      (cb nil)
      (let [control-data (try
                           (parse-json-safe (.readFileSync node-fs ctrl-file "utf8"))
                           (catch :default _ nil))
            pid (or (get control-data "pid") (get control-data :pid))
            port (or (:control-port opts) (get control-data "port") (get control-data :port))
            token (or (get control-data "token") (get control-data :token))
            eff-cmd (if (and (:auto-sync? opts) (contains? #{"account" "escrows"} (get cmd-map "cmd")))
                      (assoc cmd-map "sync" true)
                      cmd-map)
            timeout-ms (or (:timeout-ms opts)
                           (if (contains? #{"put" "artifact-put"} (get cmd-map "cmd")) 60000 15000))]
        (if-not (and port token)
          (if (and pid (pid-alive? pid))
            (cb {"ok" false
                 "error" "daemon-control-unreachable"
                 "pid" pid
                 "port" port
                 "status" "rejected"})
            (cb nil))
          (let [body-json (write-json-str eff-cmd)
                body-buf (.from (.-Buffer js/globalThis) body-json "utf8")
                called? (atom false)
                finish! (fn [val]
                          (when (compare-and-set! called? false true)
                            (cb val)))
                req-opts #js {:hostname "127.0.0.1"
                              :port (int port)
                              :path "/ctl"
                              :method "POST"
                              :headers #js {"Authorization" (str "Bearer " token)
                                            "Content-Type" "application/json"
                                            "Content-Length" (.-length body-buf)}
                              :timeout timeout-ms}
                req (.request node-http req-opts
                              (fn [res]
                                (let [chunks #js []]
                                  (.on res "data" (fn [c] (.push chunks c)))
                                  (.on res "end"
                                       (fn []
                                         (let [resp-str (.toString (.concat (.-Buffer js/globalThis) chunks) "utf8")
                                               parsed (try (parse-json-safe resp-str) (catch :default _ nil))]
                                           (if (map? parsed)
                                             (finish! parsed)
                                             (if (and pid (pid-alive? pid))
                                               (finish! {"ok" false
                                                         "error" "daemon-control-unreachable"
                                                         "pid" pid
                                                         "port" port
                                                         "status" "rejected"})
                                               (finish! nil)))))))))]
            (.on req "error"
                 (fn [_]
                   (if (and pid (pid-alive? pid))
                     (finish! {"ok" false
                               "error" "daemon-control-unreachable"
                               "pid" pid
                               "port" port
                               "status" "rejected"})
                     (finish! nil))))
            (.on req "timeout"
                 (fn []
                   (.destroy req)
                   (if (and pid (pid-alive? pid))
                     (finish! {"ok" false
                               "error" "daemon-control-unreachable"
                               "pid" pid
                               "port" port
                               "status" "rejected"})
                     (finish! nil))))
            (.write req body-buf)
            (.end req)))))))

(defn poll-and-ingest-relay-once!
  "Polls the relay once on Node.js, ingests incoming messages/broadcasts, saves state to disk,
   and acks to the relay. Calls (cb auto-net-envelopes) upon completion."
  [relay-url identity state-atom state-file opts cb]
  (let [pk-hex (or (:pubkey-hex identity) (:pubkey identity))
        priv-bytes (:privkey-bytes identity)
        since-mseq (long (or (:relay-since-seq @state-atom) 0))
        since-bseq (long (or (:relay-since-broadcast-seq @state-atom) 0))
        eff-subnets (vec (sort (light-core/effective-subscribed-subnets @state-atom)))
        subnets (or (:subnets opts) eff-subnets)]
    (poll-relay-envelopes!
     relay-url pk-hex priv-bytes
     (cond-> {:since-seq since-mseq
              :since-broadcast-seq since-bseq
              :timeout-ms 0}
       subnets (assoc :subnets subnets))
     (fn [poll-res]
       (let [msgs (or (get poll-res "messages") (get poll-res :messages) [])
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
                 wire-bytes (when env-raw (try (basalt/hex->bytes (str env-raw)) (catch :default _ nil)))]
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
                                   (:p2p-dial r)
                                   state-file))
                 (when (seq (:net-envelopes r))
                   (swap! auto-net-envs into (:net-envelopes r)))))))
         (when (and (not (:peek? opts))
                    (or (not= new-mseq since-mseq) (not= new-bseq since-bseq) (seq all-items)))
           (when state-file
             (try (save-light-state! state-file @state-atom) (catch :default _ nil))))
         (if (and (not (:peek? opts))
                  (or (seq msgs) (seq bcasts) (> new-bseq since-bseq)))
           (ack-relay-envelopes!
            relay-url pk-hex priv-bytes new-mseq
            {:ack-broadcast-seq new-bseq}
            (fn [_] (cb @auto-net-envs)))
           (cb @auto-net-envs)))))))

(defn run-one-shot!
  "Executes a single one-shot light-node command on Node.js and outputs JSON response."
  [opts]
  (let [state-dir (:state-dir opts)
        raw-cmd-map (:cmd-map opts)]
    (try-delegate-one-shot-to-daemon!
     state-dir raw-cmd-map opts
     (fn [delegated]
       (if delegated
         (do
           (emit-json-line! delegated)
           (.exit js/process (if (and (map? delegated) (false? (get delegated "ok"))) 1 0)))
         (let [state-file (.join node-path state-dir "state.fressian")
               identity (load-or-create-light-identity! state-dir opts)]
           (load-bootstrap-descriptor!
            (:bootstrap opts) nil
            (fn [b-res]
              (if-not (:ok? b-res)
                (do
                  (emit-json-line! {"ok" false "error" (:error b-res)})
                  (.exit js/process 0))
                (let [bootstrap (:descriptor b-res)
                      loaded-state (load-light-state! state-file)
                      reconciled-res (when loaded-state
                                       (light-core/reconcile-startup-subnet-id
                                        loaded-state
                                        (:subnet-id opts)
                                        (:subscribe-subnets opts)))
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
                      initial-state-raw (cond-> (assoc base-state :max-epoch-skew (or (:max-epoch-skew opts) (:max-epoch-skew base-state) 15))
                                          (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                                          (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                                          (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap)))
                                          (:pin-version opts) (assoc :pin-version (:pin-version opts))
                                          (:auto-update-pointer opts) (assoc :auto-update-pointer (:auto-update-pointer opts))
                                          (seq (:trusted-deploy-authorities opts)) (assoc :trusted-deploy-authorities (:trusted-deploy-authorities opts)))
                      dac-rec (flags/reconcile-trusted-dac-anchors initial-state-raw
                                                                   (:trusted-dac-anchors-spec opts)
                                                                   (:trusted-dac-anchors bootstrap))
                      initial-state (apply-startup-identity-and-load-diagnostics! (:state dac-rec) identity)
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
                          (.write (.-stderr js/process)
                                  (str (write-json-str {"event" "startup-security-flags" "security_flags" sec-echo}) "\n")))
                      _ (when (or (and reconciled-res (:reconciled? reconciled-res))
                                  (seq (:effects dac-rec)))
                          (try (save-light-state! state-file initial-state) (catch :default _ nil)))
                      state-atom (atom initial-state)
                      verb (when (map? raw-cmd-map) (get raw-cmd-map "cmd"))
                      run-cmd-with-map!
                      (fn [raw-map]
                        (let [cmd-map (enrich-artifact-cmd-map verb raw-map)
                              shuttle-verb? (contains? #{"export-offer" "export-poll" "export-ack" "export-reveal"
                                                         "export-p2p-offer" "export-p2p-answer" "export-send"
                                                         "import-envelope" "import-poll" "import"}
                                                       verb)
                              sync-explicit? (boolean (or (:sync? opts) (get cmd-map "sync") (:sync? cmd-map)))
                              sync-wanted? (if shuttle-verb?
                                             sync-explicit?
                                             (or (boolean (:auto-sync? opts))
                                                 (and (= verb "sync-account")
                                                      (nil? (get cmd-map "balance"))
                                                      (nil? (get cmd-map "snapshots"))
                                                      (nil? (get cmd-map "snapshot")))
                                                 (and (= verb "account") sync-explicit?)
                                                 (and (= verb "escrows") sync-explicit?)))
                              sync-opts (assoc opts :identity identity)
                              after-sync!
                              (fn []
                                (let [effective-relay-url (or (:relay-url opts)
                                                              (:relay_url opts)
                                                              (when-let [u (resolve-relay-url nil #(aget (.-env js/process) %))] u)
                                                              (when-let [u (:relay-url bootstrap)] (resolve-relay-url u #(aget (.-env js/process) %)))
                                                              (when (= "bitecho.org" (:domain bootstrap)) "https://ns1.bitecho.org"))
                                      poll-verb? (and (not (:no-poll? opts))
                                                      effective-relay-url
                                                      (not= (:connect? opts) false)
                                                      (or (contains? #{"inbox" "wait" "accept" "rendezvous-accept" "send"
                                                                       "p2p-offer" "p2p-answer" "close" "sync-account"
                                                                       "account" "escrows"} verb)
                                                          (and (= verb "status") (or (:sync? opts) (get cmd-map "sync") (:poll? opts) (get cmd-map "poll")))))
                                      after-poll!
                                      (fn [poll-auto-envs]
                                        (let [eff-domain-verb (effective-artifact-domain-verb verb cmd-map)
                                              stage-c-verb? (contains? #{"backup-put" "backup-restore" "identity-migrate"} (str verb))
                                              storage-put-net? (and (= eff-domain-verb "storage-put")
                                                                    (not (boolean (or (get cmd-map "local_only")
                                                                                      (get cmd-map "local-only")
                                                                                      (:local-only cmd-map)))))]
                                          (cond
                                            stage-c-verb?
                                            (handle-node-stage-c-verb!
                                             (str verb) cmd-map state-atom identity state-dir state-file effective-relay-url opts
                                             (fn [res]
                                               (emit-json-line! (:response res))
                                               (.exit js/process (if (:ok? res) 0 1))))

                                            storage-put-net?
                                            (let [sub-str (str (or (get cmd-map "subnet_id") (:subnet-id @state-atom) "global"))
                                                  prep (light-core/prepare-storage-put @state-atom cmd-map (:privkey-bytes identity) sub-str)]
                                              (if-not (:ok? prep)
                                                (do
                                                  (when (:state prep) (save-light-state! state-file (:state prep)))
                                                  (emit-json-line! (:response prep))
                                                  (.exit js/process 1))
                                                (let [art-relay (or (get cmd-map "relay_url")
                                                                    (get cmd-map "relay-url")
                                                                    (:relay-url cmd-map)
                                                                    effective-relay-url)]
                                                  (post-artifact-to-relay!
                                                   art-relay "storage-put" (assoc (:publish-intent prep) "ok" true)
                                                   (fn [net-receipt]
                                                     (let [committed (light-core/commit-storage-put-outcome @state-atom (:publish-intent prep) net-receipt)]
                                                       (reset! state-atom (:state committed))
                                                       (save-light-state! state-file @state-atom)
                                                       (emit-json-line! (:response committed))
                                                       (.exit js/process (if (:ok? committed) 0 1))))))))

                                            :else
                                            (let [raw-res (light-core/handle-command @state-atom cmd-map (:privkey-bytes identity))
                                                  out-write-res (maybe-write-artifact-out-file! eff-domain-verb cmd-map (:response raw-res) state-atom)
                                                  res (if (:applied? out-write-res)
                                                        (assoc raw-res :response (:response out-write-res) :state @state-atom)
                                                        raw-res)
                                                  art-relay (when (contains? #{"artifact-put" "artifact-revoke"} eff-domain-verb)
                                                              (or (get cmd-map "relay_url")
                                                                  (get cmd-map "relay-url")
                                                                  (:relay-url cmd-map)
                                                                  effective-relay-url))
                                                  new-state (:state res)
                                                  connect-explicit? (contains? opts :connect?)
                                                  connect-wanted? (if connect-explicit?
                                                                    (boolean (:connect? opts))
                                                                    (not shuttle-verb?))
                                                  all-envs (into (vec poll-auto-envs) (:net-envelopes res))
                                                  needs-network? (and (seq all-envs) connect-wanted?)
                                                  proceed-after-artifact!
                                                  (fn []
                                                    (if needs-network?
                                                      (if-let [relay-url (let [u (or (:relay-url opts) (:relay_url opts))]
                                                                           (when (and (string? u) (not (str/blank? u))) u))]
                                                        (let [relay-opts (assoc opts :timeout-ms (or (:timeout-ms opts) 5000))
                                                              envs (vec all-envs)
                                                              step (fn step [idx]
                                                                     (if (>= idx (count envs))
                                                                       (do
                                                                         (when-not (get cmd-map "peek")
                                                                           (save-light-state! state-file new-state))
                                                                         (emit-json-line! (:response res))
                                                                         (.exit js/process 0))
                                                                       (-> (submit-relay-envelope! relay-url (nth envs idx) relay-opts)
                                                                           (.then (fn [item-res]
                                                                                    (let [res-map (if (map? item-res) item-res (js->clj item-res :keywordize-keys true))]
                                                                                      (if (false? (or (:ok res-map) (get res-map "ok")))
                                                                                        (do
                                                                                          (emit-json-line! {"ok" false "error" (or (:error res-map) "relay-submit-failed")})
                                                                                          (.exit js/process 0))
                                                                                        (step (inc idx))))))
                                                                           (.catch (fn [err]
                                                                                     (emit-json-line! {"ok" false "error" (str err)})
                                                                                     (.exit js/process 0))))))]
                                                          (step 0))
                                                        (connect-validators!
                                                         identity bootstrap opts
                                                         (fn [conn-res]
                                                           (if-not (:ok? conn-res)
                                                             (do
                                                               (emit-json-line! {"ok" false "error" (or (:error conn-res) "listener-disabled")})
                                                               (.exit js/process 0))
                                                             (let [send-fn (:send-fn conn-res)
                                                                   finish! (fn [sent?]
                                                                             (when-let [n (:node conn-res)]
                                                                               (try (api/close! n) (catch :default _ nil)))
                                                                             (if sent?
                                                                               (do
                                                                                 (when-not (get cmd-map "peek")
                                                                                   (save-light-state! state-file new-state))
                                                                                 (emit-json-line! (:response res))
                                                                                 (.exit js/process 0))
                                                                               (do
                                                                                 (emit-json-line! {"ok" false "error" "connection-closed"})
                                                                                 (.exit js/process 0))))]
                                                               (if (= :http-relay (:transport conn-res))
                                                                 (send-all-envelopes! send-fn all-envs (fn [sent?] (finish! sent?)))
                                                                 (let [sent? (send-all-envelopes! send-fn all-envs)]
                                                                   (js/setTimeout
                                                                    (fn []
                                                                      (finish! sent?))
                                                                    50))))))))
                                                      (do
                                                        (when-not (get cmd-map "peek")
                                                          (save-light-state! state-file new-state))
                                                        (emit-json-line! (:response res))
                                                        (.exit js/process 0))))]
                                              (if art-relay
                                                (post-artifact-to-relay!
                                                 art-relay eff-domain-verb (:response res)
                                                 (fn [art-res]
                                                   (if (false? (:ok? art-res))
                                                     (do
                                                       (emit-json-line! {"ok" false
                                                                         "error" (or (:error art-res) "artifact-blob-upload-failed")
                                                                         "status" (:status art-res)
                                                                         "detail" (:detail art-res)
                                                                         "relay_url" (:relay-url art-res)
                                                                         "cid" (:cid art-res)})
                                                       (.exit js/process 1))
                                                     (proceed-after-artifact!))))
                                                (proceed-after-artifact!))))))]
                                  (if poll-verb?
                                    (poll-and-ingest-relay-once! effective-relay-url identity state-atom state-file opts after-poll!)
                                    (after-poll! []))))]
                          (if sync-wanted?
                            (maybe-sync-account-state!
                             state-atom bootstrap (or (:pubkey-hex identity) (:pubkey identity)) (:privkey-bytes identity) sync-opts
                             (fn [sync-res]
                               (if (false? (:ok? sync-res))
                                 (do
                                   (emit-json-line! {"ok" false "error" (:error sync-res)})
                                   (.exit js/process 0))
                                 (after-sync!))))
                            (after-sync!))))]
                  (if (and (contains? #{"directory-lookup" "directory-verify"} verb)
                           (not (contains? raw-cmd-map "descriptor"))
                           (not (contains? raw-cmd-map :descriptor)))
                    (let [nick (or (get raw-cmd-map "nickname") (:nickname raw-cmd-map))
                          dom (or (get raw-cmd-map "domain") (:domain raw-cmd-map) "bitecho.org")]
                      (if (and (string? nick) (not (str/blank? nick)))
                        (fetch-directory-descriptor!
                         dom nick opts
                         (fn [desc]
                           (run-cmd-with-map! (cond-> raw-cmd-map desc (assoc "descriptor" desc)))))
                        (run-cmd-with-map! raw-cmd-map)))
                    (run-cmd-with-map! raw-cmd-map))))))))))))

(defn- check-daemon-status
  "Checks if a daemon is running and responsive via control.json. Calls cb with status map or nil."
  [state-dir cb]
  (let [ctrl-file (.join node-path state-dir "control.json")]
    (if-not (.existsSync node-fs ctrl-file)
      (cb nil)
      (let [control-data (try
                           (parse-json-safe (.readFileSync node-fs ctrl-file "utf8"))
                           (catch :default _ nil))
            port (or (get control-data "port") (get control-data :port))
            token (or (get control-data "token") (get control-data :token))
            pid (or (get control-data "pid") (get control-data :pid))]
        (if-not (and port token)
          (cb nil)
          (let [body-json (write-json-str {"cmd" "status"})
                body-buf (.from (.-Buffer js/globalThis) body-json "utf8")
                called? (atom false)
                finish! (fn [val]
                          (when (compare-and-set! called? false true)
                            (cb val)))
                req-opts #js {:hostname "127.0.0.1"
                              :port (int port)
                              :path "/ctl"
                              :method "POST"
                              :headers #js {"Authorization" (str "Bearer " token)
                                            "Content-Type" "application/json"
                                            "Content-Length" (.-length body-buf)}
                              :timeout 2000}
                req (.request node-http req-opts
                              (fn [res]
                                (if (not= 200 (.-statusCode res))
                                  (finish! nil)
                                  (let [chunks #js []]
                                    (.on res "data" (fn [c] (.push chunks c)))
                                    (.on res "end"
                                         (fn []
                                           (let [resp-str (.toString (.concat (.-Buffer js/globalThis) chunks) "utf8")
                                                 st (try (parse-json-safe resp-str) (catch :default _ nil))]
                                             (if (and (map? st) (get st "ok"))
                                               (finish! (assoc st "running" true "pid" pid "control_port" port))
                                               (finish! nil)))))))))]
            (.on req "error" (fn [_] (finish! nil)))
            (.on req "timeout" (fn [] (.destroy req) (finish! nil)))
            (.write req body-buf)
            (.end req)))))))

(defn run-daemon!
  "Zero-glue process supervisor managing the light-node serve daemon (start, stop, status, restart, ensure)."
  [opts]
  (let [state-dir (:state-dir opts)
        _ (when state-dir
            (try (.mkdirSync node-fs state-dir #js {:recursive true}) (catch :default _ nil)))
        action (or (:daemon-action opts) "start")
        pid-file (.join node-path state-dir "daemon.pid")
        log-file (.join node-path state-dir "daemon.log")]
    (case action
      "status"
      (check-daemon-status
       state-dir
       (fn [st]
         (if st
           (do (emit-json-line! st) (.exit js/process 0))
           (let [res {"ok" false "running" false "error" "daemon-not-running"}]
             (emit-json-line! res)
             (.exit js/process 1)))))

      "stop"
      (let [ctrl-file (.join node-path state-dir "control.json")
            pid (or (when (.existsSync node-fs pid-file)
                      (try (parse-long-safe (str/trim (.readFileSync node-fs pid-file "utf8")) nil)
                           (catch :default _ nil)))
                    (when (.existsSync node-fs ctrl-file)
                      (try (get (parse-json-safe (.readFileSync node-fs ctrl-file "utf8")) "pid")
                           (catch :default _ nil))))]
        (if (and pid (pos? (long pid)))
          (do
            (try (.kill js/process (long pid) "SIGTERM") (catch :default _ nil))
            (js/setTimeout
             (fn []
               (when (pid-alive? pid)
                 (try (.kill js/process (long pid) "SIGKILL") (catch :default _ nil)))
               (try (when (.existsSync node-fs pid-file) (.unlinkSync node-fs pid-file)) (catch :default _ nil))
               (try (when (.existsSync node-fs ctrl-file) (.unlinkSync node-fs ctrl-file)) (catch :default _ nil))
               (let [res {"ok" true "stopped" true "pid" pid}]
                 (emit-json-line! res)
                 (.exit js/process 0)))
             500))
          (let [res {"ok" true "stopped" false "status" "not-running"}]
            (emit-json-line! res)
            (.exit js/process 0))))

      ("start" "ensure")
      (check-daemon-status
       state-dir
       (fn [st]
         (if st
           ;; Idempotent: already running and healthy
           (let [res (assoc st "already_running" true)]
             (emit-json-line! res)
             (.exit js/process 0))
           ;; Not running: spawn background serve daemon
           (let [raw-args (or (:raw-args opts) [])
                 filtered-args (vec (remove #(or (= % "--daemon")
                                                 (= % "daemon")
                                                 (= % "ensure")
                                                 (= % "start")
                                                 (= % "ctl"))
                                            raw-args))
                 serve-args (into ["serve"] (filter #(not= % "serve") filtered-args))
                 serve-args (if (some #{"--state-dir"} serve-args)
                              serve-args
                              (into serve-args ["--state-dir" state-dir]))
                 script-path (aget (.-argv js/process) 1)
                 out-fd (.openSync node-fs log-file "a")
                 spawn-args (into [script-path] serve-args)
                 child (.spawn node-child-process (.-execPath js/process) (to-array spawn-args)
                               #js {:detached true
                                    :stdio #js ["ignore" out-fd out-fd]})
                 pid (.-pid child)]
             (.unref child)
             (try
               (.writeFileSync node-fs pid-file (str pid "\n") "utf8")
               (catch :default _ nil))
             ;; Wait up to 30s for daemon to become ready
             (let [attempts (atom 0)
                   poll! (fn poll! []
                           (check-daemon-status
                            state-dir
                            (fn [ready-st]
                              (if ready-st
                                (do
                                  (emit-json-line! ready-st)
                                  (.exit js/process 0))
                                (if (not (pid-alive? pid))
                                  (let [log-tail (try (.readFileSync node-fs log-file "utf8") (catch :default _ ""))
                                        err {"ok" false "error" "daemon-exited-early" "log" log-tail}]
                                    (emit-json-line! err)
                                    (.exit js/process 1))
                                  (if (>= @attempts 60)
                                    (let [err {"ok" false "error" "daemon-start-timeout" "pid" pid}]
                                      (emit-json-line! err)
                                      (.exit js/process 1))
                                    (do
                                      (swap! attempts inc)
                                      (js/setTimeout poll! 500))))))))]
               (js/setTimeout poll! 300))))))

      "restart"
      (let [ctrl-file (.join node-path state-dir "control.json")
            pid (or (when (.existsSync node-fs pid-file)
                      (try (parse-long-safe (str/trim (.readFileSync node-fs pid-file "utf8")) nil)
                           (catch :default _ nil)))
                    (when (.existsSync node-fs ctrl-file)
                      (try (get (parse-json-safe (.readFileSync node-fs ctrl-file "utf8")) "pid")
                           (catch :default _ nil))))]
        (if (and pid (pos? (long pid)))
          (do
            (try (.kill js/process (long pid) "SIGTERM") (catch :default _ nil))
            (js/setTimeout
             (fn []
               (when (pid-alive? pid)
                 (try (.kill js/process (long pid) "SIGKILL") (catch :default _ nil)))
               (try (when (.existsSync node-fs pid-file) (.unlinkSync node-fs pid-file)) (catch :default _ nil))
               (try (when (.existsSync node-fs ctrl-file) (.unlinkSync node-fs ctrl-file)) (catch :default _ nil))
               (run-daemon! (assoc opts :daemon-action "start")))
             500))
          (run-daemon! (assoc opts :daemon-action "start")))))))

(defn run-mcp!
  "Runs the Node.js Bitecho MCP JSON-RPC 2.0 server over stdio (`--mcp` / `mcp` mode, BIP-006 Part 1).
   All diagnostics/logging go to stderr so stdout carries strictly newline-delimited JSON-RPC 2.0 frames."
  [opts]
  (let [state-dir (:state-dir opts)
        state-file (.join node-path state-dir "state.fressian")
        identity (load-or-create-light-identity! state-dir opts)
        loaded-state (load-light-state! state-file)
        base-state (apply-startup-identity-and-load-diagnostics!
                    (or loaded-state
                        (light-core/init-light-state identity (cond-> {}
                                                                (:subnet-id opts) (assoc :subnet-id (:subnet-id opts)))))
                    identity)
        state-atom (atom base-state)
        effective-relay-url (or (:relay-url opts) "https://ns1.bitecho.org")
        exec-local! (fn [cmd-map]
                      (let [verb (get cmd-map "cmd")
                            enriched (enrich-artifact-cmd-map verb cmd-map)
                            res (light-core/handle-command @state-atom enriched (:privkey-bytes identity))]
                        (reset! state-atom (:state res))
                        (when-not (get enriched "peek")
                          (try (save-light-state! state-file (:state res)) (catch :default _ nil)))
                        (when (and effective-relay-url (seq (:net-envelopes res)))
                          (doseq [env (:net-envelopes res)]
                            (submit-relay-envelope! effective-relay-url env {:timeout-ms 5000} (fn [_] nil))))
                        (:response res)))
        rl (.createInterface node-readline #js {:input (.-stdin js/process)
                                                :terminal false})]
    (.on rl "line"
         (fn [line]
           (let [trimmed (str/trim (str line))]
             (when-not (str/blank? trimmed)
               (let [req-map (parse-json-safe trimmed)]
                 (if-not (map? req-map)
                   (emit-json-line! {"jsonrpc" "2.0"
                                     "id" nil
                                     "error" {"code" -32700 "message" "Parse error"}})
                   (let [method (str (or (get req-map "method") (:method req-map) ""))]
                     (if (= method "tools/call")
                       (let [id (or (get req-map "id") (:id req-map))
                             params (or (get req-map "params") (:params req-map) {})
                             tname (or (get params "name") (:name params))
                             targs (or (get params "arguments") (:arguments params) {})
                             trans (mcp/tool-call->cmd-map tname targs)]
                         (if-not (:ok? trans)
                           (emit-json-line! {"jsonrpc" "2.0"
                                             "id" id
                                             "error" {"code" -32602 "message" (:error trans)}})
                           (try-delegate-one-shot-to-daemon!
                            state-dir (:cmd-map trans) opts
                            (fn [delegated]
                              (let [cmd-resp (or delegated (exec-local! (:cmd-map trans)))]
                                (emit-json-line! {"jsonrpc" "2.0"
                                                  "id" id
                                                  "result" (mcp/format-mcp-tool-result cmd-resp write-json-str)}))))))
                       (when-let [rpc-resp (mcp/handle-jsonrpc-request req-map exec-local! write-json-str)]
                         (emit-json-line! rpc-resp))))))))))
    (.on rl "close"
         (fn []
           (js/setTimeout #(.exit js/process 0) 50)))))

(defn run-light-node-cli!
  "Dispatches Node.js light-node CLI invocation based on parsed arguments."
  [args]
  (let [parsed (parse-light-node-args args)]
    (case (:mode parsed)
      :help
      (let [res {"ok" true
                 "help" true
                 "verbs" cli/supported-cli-verbs
                 "modes" ["one-shot" "serve" "ctl" "wait-event" "mcp"]
                 "flags" cli/known-command-flags}]
        (emit-json-line! res)
        (.exit js/process 0))
      :mcp (run-mcp! parsed)
      :daemon (run-daemon! parsed)
      :ctl (run-ctl! parsed)
      :serve (run-serve! parsed)
      :wait-event (run-wait-event! parsed)
      :one-shot (run-one-shot! parsed))))

(defn -main
  "Entrypoint for `node dist/bitecho-light-node.cjs`."
  [& args]
  (run-light-node-cli! (vec args)))

(set! *main-cli-fn* -main)
