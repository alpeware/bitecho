(ns bitecho.node-main
  "Standalone Node.js Light-Node CLI & Daemon Boundary Shell (Phase 4 Milestone 14 Step 14B / M2b).
   Provides 100% CLI flag, JSONL wire, `state.fressian` persistence, `node-identity.edn` identity,
   and transport (`UDP` via `node:dgram` + RFC 4571 `TCP` / `HTTP CONNECT` via `node:net`) parity
   with the JVM `bitecho.shell.light-node` shell, backed by `bitecho.light-node.core`,
   `bitecho.fressian`, and `datachannel.api`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [cljs.reader :as edn]
            [clojure.string :as str]
            [datachannel.api :as api]
            [datachannel.dtls :as dtls]
            [datachannel.mdns :as mdns]))

(def ^:private node-fs (js/require "node:fs"))
(def ^:private node-path (js/require "node:path"))
(def ^:private node-os (js/require "node:os"))
(def ^:private node-http (js/require "node:http"))
(def ^:private node-https (js/require "node:https"))
(def ^:private node-readline (js/require "node:readline"))
(def ^:private node-crypto (js/require "node:crypto"))

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

(declare dial-p2p-peer! send-routed-envelopes!)

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
        nodes-map (or (:nodes data) {})
        _ (when (empty? nodes-map)
            (throw (ex-info "Bootstrap descriptor contains no validator nodes"
                            {:error :invalid-descriptor :data data})))
        normalized-nodes (into {} (for [[k v] nodes-map]
                                    [(keyword k) (normalize-node-entry k v)]))]
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
        nodes-map (into {} (keep parse-single-node-txt-block blocks))]
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
      (if (or (str/starts-with? trimmed "{")
              (str/starts-with? trimmed ";;"))
        (try
          (parse-bootstrap-edn trimmed)
          (catch :default _
            (parse-bootstrap-txt trimmed)))
        (parse-bootstrap-txt trimmed)))

    :else
    (throw (ex-info "Unsupported descriptor format" {:error :invalid-descriptor :input str-or-map}))))

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
  (try
    (js->clj (js/JSON.parse s))
    (catch :default _ nil)))

(defn build-one-shot-cmd-map
  "Constructs a JSON command map from parsed CLI arguments."
  [verb args]
  (let [first-arg (first args)
        json-args (when (and (string? first-arg) (str/starts-with? (str/trim first-arg) "{"))
                    (parse-json-safe first-arg))
        base-map (case verb
                   "identity" {"cmd" "identity"}
                   "status"   {"cmd" "status"}
                   "discover" {"cmd" "discover"}
                   "inbox"    {"cmd" "inbox"}
                   "offer"    (let [m {"cmd" "offer"
                                       "callee" (extract-flag-value args "--callee" nil)
                                       "price" (extract-long-flag args "--price" 0)
                                       "burn" (extract-long-flag args "--burn" 500)}
                                    hn (extract-flag-value args "--home-node" nil)]
                                (if hn (assoc m "home_node" hn) m))
                   "accept"   {"cmd" "accept"
                               "session_id" (or (extract-flag-value args "--session-id" nil)
                                                (extract-flag-value args "--session" nil))}
                   "rendezvous-policy" (let [min-burn (extract-long-flag args "--min-burn" nil)
                                             price (extract-long-flag args "--price" nil)
                                             allowlist (extract-flag-value args "--allowlist" nil)
                                             hn (extract-flag-value args "--home-node" nil)
                                             auto-acc (extract-flag-value args "--auto-accept" nil)
                                             auto-acc-bool (if (some #{"--auto-accept"} args)
                                                             (if (and auto-acc (re-matches #"(?i)false" auto-acc))
                                                               false
                                                               true)
                                                             nil)
                                             m {"cmd" "rendezvous-policy"}]
                                         (cond-> m
                                           min-burn (assoc "min_burn" min-burn)
                                           price (assoc "price" price)
                                           allowlist (assoc "allowlist" (if (str/includes? allowlist ",")
                                                                          (mapv str/trim (str/split allowlist #","))
                                                                          [(str/trim allowlist)]))
                                           hn (assoc "home_node" hn)
                                           (some? auto-acc-bool) (assoc "auto_accept" auto-acc-bool)))
                   "rendezvous-offer" (let [callee (or (extract-flag-value args "--callee" nil)
                                                       (extract-flag-value args "--to" nil))
                                            burn (extract-long-flag args "--burn" nil)
                                            topic (extract-flag-value args "--topic" nil)
                                            hn (extract-flag-value args "--home-node" nil)
                                            text (extract-flag-value args "--text" nil)
                                            m {"cmd" "rendezvous-offer"
                                               "callee" callee}]
                                        (cond-> m
                                          burn (assoc "burn" burn)
                                          topic (assoc "topic" topic)
                                          hn (assoc "home_node" hn)
                                          text (assoc "text" text)))
                   "rendezvous-accept" (let [oh (extract-flag-value args "--offer-hash" nil)
                                             from (extract-flag-value args "--from" nil)
                                             m {"cmd" "rendezvous-accept"}]
                                         (cond-> m
                                           oh (assoc "offer_hash" oh)
                                           from (assoc "from" from)))
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
                   "register-home-set" (let [nodes (extract-flag-value args "--nodes" nil)
                                             p (extract-long-flag args "--price" 0)
                                             p-max (extract-long-flag args "--price-max" nil)
                                             m {"cmd" "register-home-set"
                                                "price" p
                                                "home_nodes" (if nodes (str/split nodes #",") [])
                                                "burn" (extract-long-flag args "--burn" 500)}]
                                         (cond-> m
                                           p-max (assoc "price_max" p-max)))
                   "account"   (let [sync? (boolean (some #{"--sync"} args))
                                     b (extract-long-flag args "--balance" nil)
                                     s (extract-long-flag args "--seq" nil)
                                     m {"cmd" "account"}]
                                 (cond-> m
                                   sync? (assoc "sync" true)
                                   b (assoc "balance" b)
                                   s (assoc "seq" s)))
                   "sync-account" (let [b (extract-long-flag args "--balance" nil)
                                        s (extract-long-flag args "--seq" nil)
                                        m {"cmd" "sync-account"}]
                                    (cond-> m
                                      b (assoc "balance" b)
                                      s (assoc "seq" s)))
                   "settle-intent" {"cmd" "settle-intent"
                                    "receiver" (or (extract-flag-value args "--receiver" nil)
                                                   (extract-flag-value args "--recipient" nil))
                                    "recipient" (or (extract-flag-value args "--receiver" nil)
                                                    (extract-flag-value args "--recipient" nil))
                                    "amount" (extract-long-flag args "--amount" 0)}
                   "lock-intent" (let [recv (or (extract-flag-value args "--receiver" nil)
                                                (extract-flag-value args "--recipient" nil)
                                                (extract-flag-value args "--to" nil))
                                       amt (extract-long-flag args "--amount" nil)
                                       dh (extract-flag-value args "--deliverable-hash" nil)
                                       ep (extract-long-flag args "--expires-epoch" nil)
                                       eid (extract-flag-value args "--escrow-id" nil)
                                       m {"cmd" "lock-intent"}]
                                   (cond-> m
                                     recv (assoc "receiver" recv "recipient" recv)
                                     amt (assoc "amount" amt)
                                     dh (assoc "deliverable_hash" dh)
                                     ep (assoc "expires_epoch" ep)
                                     eid (assoc "escrow_id" eid)))
                   "release-intent" (let [eid (extract-flag-value args "--escrow-id" nil)
                                          pre (extract-flag-value args "--preimage" nil)
                                          m {"cmd" "release-intent"}]
                                      (cond-> m
                                        eid (assoc "escrow_id" eid)
                                        pre (assoc "preimage" pre)))
                   "refund-intent" (let [eid (extract-flag-value args "--escrow-id" nil)
                                         m {"cmd" "refund-intent"}]
                                     (cond-> m
                                       eid (assoc "escrow_id" eid)))
                   "escrows" (let [sync? (boolean (some #{"--sync"} args))]
                               (cond-> {"cmd" "escrows"}
                                 sync? (assoc "sync" true)))
                   "submit-vouchers" {"cmd" "submit-vouchers"}
                   "petname-set" {"cmd" "petname-set"
                                  "petname" (extract-flag-value args "--petname" nil)
                                  "pubkey" (extract-flag-value args "--pubkey" nil)
                                  "overwrite" (boolean (some #{"--overwrite"} args))}
                   "petname-list" {"cmd" "petname-list"}
                   "petname-remove" {"cmd" "petname-remove"
                                     "petname" (extract-flag-value args "--petname" nil)
                                     "pubkey" (extract-flag-value args "--pubkey" nil)}
                   "petname-resolve" {"cmd" "petname-resolve"
                                      "petname" (extract-flag-value args "--petname" nil)
                                      "pubkey" (extract-flag-value args "--pubkey" nil)}
                   "dac-attach" {"cmd" "dac-attach"}
                   "dac-revoke" {"cmd" "dac-revoke"}
                   "directory-verify" (let [nick (extract-flag-value args "--nickname" nil)
                                            dom (extract-flag-value args "--domain" nil)
                                            pk (extract-flag-value args "--directory-pubkey" nil)]
                                        (cond-> {"cmd" "directory-verify"}
                                          nick (assoc "nickname" nick)
                                          dom (assoc "domain" dom)
                                          pk (assoc "directory_pubkey" pk)))
                   "directory-register" (let [nick (extract-flag-value args "--nickname" nil)
                                              dom (extract-flag-value args "--domain" nil)
                                              mb (extract-flag-value args "--mailbox" nil)
                                              prev-pk (extract-flag-value args "--prev-pubkey" nil)
                                              prev-sk (extract-flag-value args "--prev-privkey" nil)
                                              m {"cmd" "directory-register"}]
                                          (cond-> m
                                            nick (assoc "nickname" nick)
                                            dom (assoc "domain" dom)
                                            mb (assoc "mailbox" mb)
                                            prev-pk (assoc "prev_pubkey" prev-pk)
                                            prev-sk (assoc "prev_privkey" prev-sk)))
                   "directory-lookup" (let [nick (extract-flag-value args "--nickname" nil)
                                            dom (extract-flag-value args "--domain" nil)
                                            dir-pk (extract-flag-value args "--directory-pubkey" nil)
                                            m {"cmd" "directory-lookup"}]
                                        (cond-> m
                                          nick (assoc "nickname" nick)
                                          dom (assoc "domain" dom)
                                          dir-pk (assoc "directory_pubkey" dir-pk)))
                   "p2p-offer" (let [sid (or (extract-flag-value args "--session-id" nil)
                                             (extract-flag-value args "--session" nil))
                                     cands (extract-flag-value args "--candidates" nil)
                                     tr (extract-flag-value args "--transport" nil)
                                     m {"cmd" "p2p-offer"}]
                                 (cond-> m
                                   sid (assoc "session_id" sid)
                                   cands (assoc "candidates" (vec (remove str/blank? (map str/trim (str/split cands #",")))))
                                   tr (assoc "transport" tr)))
                   "p2p-answer" (let [sid (or (extract-flag-value args "--session-id" nil)
                                              (extract-flag-value args "--session" nil))
                                      cands (extract-flag-value args "--candidates" nil)
                                      tr (extract-flag-value args "--transport" nil)
                                      m {"cmd" "p2p-answer"}]
                                  (cond-> m
                                    sid (assoc "session_id" sid)
                                    cands (assoc "candidates" (vec (remove str/blank? (map str/trim (str/split cands #",")))))
                                    tr (assoc "transport" tr)))
                   "p2p-channel-state" (let [sid (or (extract-flag-value args "--session-id" nil)
                                                     (extract-flag-value args "--session" nil))
                                             conn-raw (extract-flag-value args "--connected" nil)
                                             conn? (if (some? conn-raw)
                                                     (not= (str/lower-case (str/trim (str conn-raw))) "false")
                                                     (boolean (some #{"--connected"} args)))
                                             tr (extract-flag-value args "--transport" nil)
                                             err (extract-flag-value args "--error" nil)
                                             m {"cmd" "p2p-channel-state"
                                                "session_id" sid
                                                "connected" conn?}]
                                         (cond-> m
                                           tr (assoc "transport" tr)
                                           err (assoc "error" err)))
                   "broadcast" (let [t (extract-flag-value args "--text" nil)
                                     sub (extract-flag-value args "--subnet-id" nil)
                                     m {"cmd" "broadcast"}]
                                 (cond-> m
                                   t (assoc "text" t)
                                   sub (assoc "subnet_id" sub)))
                   {"cmd" verb})]
    (if (map? json-args)
      (merge base-map json-args {"cmd" verb})
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

(defn parse-light-node-args
  "Parses light-node command line arguments into an options map."
  [args]
  (let [clean-args (if (= (first args) "light-node") (vec (rest args)) (vec args))
        verb (or (first clean-args) "status")
        serve? (= verb "serve")
        wait-event? (= verb "wait-event")
        default-state-dir (.join node-path (.homedir node-os) ".bitecho" "light-node")
        default-bootstrap "https://bitecho.org/devnet/bootstrap.txt"
        state-dir (or (extract-flag-value clean-args "--state-dir" nil) default-state-dir)
        bootstrap-path (or (extract-flag-value clean-args "--bootstrap" nil) default-bootstrap)
        autonomous? (boolean (some #{"--autonomous"} clean-args))
        no-auto-sync? (boolean (some #{"--no-auto-sync"} clean-args))
        explicit-auto-sync? (boolean (some #{"--auto-sync"} clean-args))
        auto-sync? (and (not no-auto-sync?) (or explicit-auto-sync? serve?))
        sync-interval-ms (extract-long-flag clean-args "--sync-interval-ms" (when auto-sync? 15000))
        no-auto-reg? (boolean (some #{"--no-auto-register-home-set"} clean-args))
        explicit-auto-reg? (boolean (some #{"--auto-register-home-set"} clean-args))
        auto-register-home-set? (and (not no-auto-reg?) (or explicit-auto-reg? (and serve? autonomous?)))
        home-set-price (extract-long-flag clean-args "--price" (when auto-register-home-set? 10))
        cmd-file (extract-flag-value clean-args "--cmd-file" nil)
        events-out (extract-flag-value clean-args "--events-out" nil)
        wait-session-id (or (extract-flag-value clean-args "--session-id" nil)
                            (extract-flag-value clean-args "--session" nil))
        min-seq (extract-long-flag clean-args "--min-seq" nil)
        after-ts (extract-long-flag clean-args "--after-ts" nil)
        transport-str (extract-flag-value clean-args "--transport" "udp")
        transport (case (str/lower-case transport-str)
                    "tcp" :tcp
                    "connect" :connect
                    :udp)
        timeout-ms (extract-long-flag clean-args "--timeout-ms" nil)
        ingress-tcp-port (extract-long-flag clean-args "--ingress-tcp-port" nil)
        proxy-cli (extract-flag-value clean-args "--proxy" nil)
        proxy-url (resolve-proxy-url proxy-cli)
        subnet-id (extract-flag-value clean-args "--subnet-id" nil)
        trusted-dac-anchors-raw (extract-flag-value clean-args "--trusted-dac-anchors" nil)
        trusted-dac-anchors (when (and (string? trusted-dac-anchors-raw) (not (str/blank? trusted-dac-anchors-raw)))
                              (let [raw-items (if (or (str/starts-with? (str/trim trusted-dac-anchors-raw) "[")
                                                      (str/starts-with? (str/trim trusted-dac-anchors-raw) "#{"))
                                                (try (edn/read-string trusted-dac-anchors-raw)
                                                     (catch :default _ (str/split trusted-dac-anchors-raw #",")))
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
                         :server-port (if (and p (seq p)) (parse-long-safe p 3478) 3478)
                         :username turn-username
                         :password turn-password
                         :realm turn-realm
                         :force-relay? turn-force-relay?}))]
    (cond-> {:mode (cond
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
             :cmd-map (let [m (when-not (or serve? wait-event?) (build-one-shot-cmd-map verb (rest clean-args)))]
                        (cond-> m
                          subnet-id (assoc "subnet_id" subnet-id)))}
      sync-interval-ms (assoc :sync-interval-ms sync-interval-ms)
      home-set-price (assoc :home-set-price home-set-price)
      cmd-file (assoc :cmd-file cmd-file)
      events-out (assoc :events-out events-out)
      wait-session-id (assoc :session-id wait-session-id)
      min-seq (assoc :min-seq min-seq)
      after-ts (assoc :after-ts after-ts)
      subnet-id (assoc :subnet-id subnet-id)
      timeout-ms (assoc :timeout-ms timeout-ms)
      ingress-tcp-port (assoc :ingress-tcp-port ingress-tcp-port)
      (seq trusted-dac-anchors) (assoc :trusted-dac-anchors trusted-dac-anchors)
      proxy-url (assoc :proxy proxy-url)
      turn-config (assoc :turn-config turn-config))))

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
      (.writeFileSync node-fs tmp-file buf #js {:mode 0600})
      (try (.chmodSync node-fs tmp-file 0600) (catch :default _ nil))
      (.renameSync node-fs tmp-file (str target-file))
      true
      (finally
        (when (.existsSync node-fs tmp-file)
          (try (.unlinkSync node-fs tmp-file) (catch :default _ nil)))))))

(defn save-light-state!
  "Persists sanitized light-node state via cross-platform Fressian (`state.fressian`)
   with atomic rename and `0600` permissions (`M2a-2`)."
  [state-file state]
  (when (and (some? state-file) (not (str/blank? (str state-file))))
    (let [encoded (light-core/encode-light-state state)]
      (write-bytes-atomic! (str state-file) encoded)
      true)))

(defn load-light-state!
  "Loads persisted light-node state from `state.fressian`, returning nil if absent."
  [state-file]
  (when (and (some? state-file)
             (not (str/blank? (str state-file)))
             (.existsSync node-fs (str state-file)))
    (let [buf (.readFileSync node-fs (str state-file))
          u8 (js/Uint8Array. (.-buffer buf) (.-byteOffset buf) (.-byteLength buf))]
      (when (pos? (.-byteLength u8))
        (light-core/decode-light-state u8)))))

(defn load-or-create-light-identity!
  "Loads or creates persistent light-node identity in `<state-dir>/identity/node-identity.edn`
   with `0600` permissions, fully interchangeable with JVM `bitecho.shell.identity`."
  [state-dir]
  (let [identity-dir (.join node-path (str state-dir) "identity")
        _ (.mkdirSync node-fs identity-dir #js {:recursive true})
        identity-file (.join node-path identity-dir "node-identity.edn")]
    (if (.existsSync node-fs identity-file)
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
              fp (normalize-fingerprint (:fingerprint edn-data))]
          {:node-id :light-node
           :pubkey-hex (:pubkey-hex edn-data)
           :privkey-hex (:privkey-hex edn-data)
           :privkey-bytes priv-bytes
           :keypair {:public pub-bytes :private priv-bytes}
           :fingerprint fp
           :ice-creds (:ice-creds edn-data)
           :cert-data {:cert (:cert-pem edn-data)
                       :key (:key-pem edn-data)
                       :fingerprint fp}}))
      (let [cert-data (dtls/generate-cert)
            fp (normalize-fingerprint (:fingerprint cert-data))
            cert-pem (:cert-pem cert-data)
            key-pem (:key-pem cert-data)
            ice-creds (generate-random-ice-creds :light-node fp)
            kp (crypto/generate-keypair)
            pub-hex (basalt/bytes->hex (:public kp))
            priv-hex (basalt/bytes->hex (:private kp))
            data-to-save {:pubkey-hex pub-hex
                          :privkey-hex priv-hex
                          :cert-pem cert-pem
                          :key-pem key-pem
                          :fingerprint fp
                          :ice-creds ice-creds}]
        (write-bytes-atomic! identity-file (js/Buffer.from (pr-str data-to-save) "utf8"))
        {:node-id :light-node
         :pubkey-hex pub-hex
         :privkey-hex priv-hex
         :privkey-bytes (:private kp)
         :keypair kp
         :fingerprint fp
         :ice-creds ice-creds
         :cert-data {:cert cert-pem
                     :key key-pem
                     :fingerprint fp}}))))

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

(defn- sync-conn-diagnostics!
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
  "Transmits all envelopes using `send-fn` and returns true only if all succeeded."
  [send-fn envelopes]
  (if (empty? envelopes)
    true
    (and (fn? send-fn)
         (every? true? (mapv #(boolean (send-fn %)) envelopes)))))

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
                         (when state-atom
                           (let [st @state-atom
                                 res (light-core/handle-wire-payload st payload (:privkey-bytes identity))]
                             (reset! state-atom (:state res))
                             (when (and state-file (not= st (:state res)))
                               (try
                                 (save-light-state! state-file (:state res))
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
                                 (dispatch-auto-reply! (:net-envelopes res) send-fn-atom state-atom conn-atom event-out reconnect-fn cb-opts)))))))))
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
                                          :diagnose-fn (:diagnose-fn opts)})
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
                         (cond
                           (:ok? res)
                           (cb (assoc res
                                      :validator-id (:node-id node)
                                      :failover-attempts (count failed-nodes)
                                      :failed-nodes failed-nodes))

                           (= (:error res) "bad-fingerprint")
                           (cb res)

                           :else
                           (step (rest rem-candidates)
                                 (conj failed-nodes {:validator-id (:node-id node)
                                                     :error (or (:error res) "listener-disabled")})))))
                      (cb {:ok? false
                           :error "listener-disabled"
                           :failed-nodes failed-nodes})))]
            (step candidates [])))))))

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
                           query-env (light-core/build-chain-state-query-envelope pubkey privkey-bytes {:nonce nonce})
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
                   :on-close (fn [_] (done! nil))}
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
    (let [snaps (fetcher pubkey)
          trusted (set (keep :pubkey (vals (:nodes bootstrap))))
          q-opts (assoc opts
                        :expected-pubkey pubkey
                        :trusted-validators trusted
                        :min-finalized-epoch (or (:min-finalized-epoch opts) 0))]
      (cb (light-core/verify-chain-state-quorum snaps q-opts)))
    (let [nodes (vec (vals (:nodes bootstrap)))]
      (if (empty? nodes)
        (cb {:ok? false :error "empty-bootstrap-nodes"})
        (let [timeout-ms (or (:timeout-ms opts) 2500)
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

(defn maybe-sync-account-state!
  "Attempts in-band validator quorum sync over Port 5010/DTLS and falls back to HTTP `/accountz` if unreachable."
  [state-atom bootstrap pubkey privkey-bytes opts cb]
  (let [id (or (:identity opts) {:pubkey-hex pubkey :privkey-bytes privkey-bytes})]
    (fetch-inband-chain-state-quorum!
     id bootstrap pubkey privkey-bytes opts
     (fn [inband-res]
       (cond
         (:ok? inband-res)
         (let [snap (:snapshot inband-res)]
           (swap! state-atom (fn [st] (light-core/apply-verified-chain-state-snapshot st snap)))
           (cb {:ok? true :state @state-atom :quorum-result inband-res}))

         (or (:inband-snapshot-fetcher opts)
             (and (not= (:error inband-res) "no-inband-snapshots-returned")
                  (not= (:error inband-res) "empty-bootstrap-nodes")))
         (cb {:ok? false :error (:error inband-res)})

         :else
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
              (cb {:ok? false :error (or (:error inband-res) "all-sync-methods-failed")})))))))))

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
          url1 (str "https://" dom "/directory/" nickname ".json")
          url2 (str "https://" dom "/" nickname)
          local-path (.join node-path "devnet" "directory" (str nickname ".json"))]
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
                  (cb nil)))))))))))

;; =============================================================================
;; 6. JSONL Output, `wait-event`, `serve`, & `one-shot` Execution Modes
;; =============================================================================

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
          min-seq (:min-seq opts)
          raw-seq (or (get evt "seq") (:seq evt))
          ev-seq (when (some? raw-seq) (parse-long-safe raw-seq nil))
          after-ts (:after-ts opts)
          raw-ts (or (get evt "timestamp_ms") (:timestamp-ms evt) (:timestamp_ms evt))
          ev-ts (if (some? raw-ts) (parse-long-safe raw-ts 0) 0)
          sid-ok? (or (nil? target-sid) (= (str ev-sid) (str target-sid)))
          seq-ok? (or (nil? min-seq) (and (some? ev-seq) (>= (or ev-seq 0) (or min-seq 0))))
          ts-ok? (or (nil? after-ts) (> (or ev-ts 0) (or after-ts 0)))]
      (boolean (and waitable? sid-ok? seq-ok? ts-ok?)))))

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
          enriched (if (or (contains? data "timestamp_ms") (contains? data :timestamp-ms))
                     data
                     (assoc data "timestamp_ms" (js/Date.now)))]
      (.appendFileSync node-fs p (str (write-json-str enriched) "\n") "utf8"))))

(defn emit-json-line!
  "Writes `data` as a JSON line to `process.stdout` and optionally mirrors to `events-out-path`."
  ([data] (emit-json-line! data nil))
  ([data events-out-path]
   (.write (.-stdout js/process) (str (write-json-str data) "\n"))
   (when events-out-path
     (try (append-event-jsonl! events-out-path data) (catch :default _ nil)))))

(defn read-new-cmd-file-lines!
  "Reads newly appended complete UTF-8 lines from `cmd-file-path` starting at byte `offset`."
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
                                    :else (recur (dec idx))))]
                    (if (neg? last-nl)
                      {:lines [] :next-offset safe-off}
                      (let [consumed (inc last-nl)
                            text (.toString buf "utf8" 0 consumed)
                            lines (->> (str/split-lines text)
                                       (map str/trim)
                                       (remove str/blank?)
                                       vec)]
                        {:lines lines
                         :next-offset (+ safe-off consumed)})))))
              (finally
                (try (.closeSync node-fs fd) (catch :default _ nil))))))))))

(defn run-wait-event!
  "Polls `--events-out` (or `<state-dir>/events.jsonl`) until a matching incoming event arrives."
  [opts]
  (let [state-dir (or (:state-dir opts) (.join node-path (.homedir node-os) ".bitecho" "light-node"))
        events-path (or (:events-out opts) (.join node-path state-dir "events.jsonl"))
        timeout-ms (max 1 (or (:timeout-ms opts) 300000))
        poll-ms (or (:poll-ms opts) 50)
        scan-from-start? (or (some? (:min-seq opts)) (some? (:after-ts opts)))
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
  "Routes an outgoing network envelope directly to P2P peer(s) or falls back to validator gossip."
  [env send-fn-atom p2p-peers-atom ingress-peers-atom state-atom privkey-bytes]
  (let [send-default! (fn []
                        (when-let [sfn (cond
                                         (instance? cljs.core/Atom send-fn-atom) @send-fn-atom
                                         (fn? send-fn-atom) send-fn-atom
                                         :else nil)]
                          (sfn env)))]
    (cond
      (:p2p-broadcast? env)
      (let [p2p-sends (keep :send-fn (vals (or (when p2p-peers-atom @p2p-peers-atom) {})))
            ingress-sends (vals (or (when ingress-peers-atom @ingress-peers-atom) {}))
            all-sends (concat p2p-sends ingress-sends)]
        (if (seq all-sends)
          (doseq [sfn all-sends]
            (try (sfn env) (catch :default _ nil)))
          (send-default!)))

      (:p2p-direct? env)
      (let [norm-target (light-core/normalize-pubkey-hex (:p2p-peer env))
            p2p-entry (when p2p-peers-atom (get @p2p-peers-atom norm-target))
            ingress-send (when ingress-peers-atom (get @ingress-peers-atom norm-target))
            direct-send (or (:send-fn p2p-entry) ingress-send)]
        (if direct-send
          (try (direct-send env) (catch :default _ (send-default!)))
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
        existing-p2p (when p2p-peers-atom (get @p2p-peers-atom peer-pk))]
    (if (and existing-p2p (:send-fn existing-p2p))
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
                    parsed-candidates (keep #(light-core/parse-p2p-candidate % mdns-state') candidates)
                    success? (atom false)]
                (if (empty? parsed-candidates)
                  (let [cmd-res (light-core/handle-command @state-atom
                                                           {"cmd" "p2p-channel-state"
                                                            "session_id" sid
                                                            "connected" false
                                                            "error" "p2p-dial-failed"}
                                                           privkey-bytes)]
                    (reset! state-atom (:state cmd-res))
                    (when state-atom
                      (swap! state-atom update-in [:diagnostics :p2p-dial-failed] (fnil inc 0)))
                    (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))
                  (doseq [cand parsed-candidates
                          :while (not @success?)]
                    (try
                      (let [host (:host cand)
                            port (int (:port cand))
                            transport (or (:transport cand) :tcp)
                            channel-id (atom nil)
                            assigned-gen (atom nil)
                            on-close-fired? (atom false)
                            client-node (api/create-node {:port 0 :setup "active"})
                            peer-send! (fn [env]
                                         (if-let [cid @channel-id]
                                           (let [payload (try (if (bytes? env) env (fressian/encode-wire env)) (catch :default _ nil))]
                                             (if payload
                                               (try (api/send! client-node payload cid) true (catch :default _ false))
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
                                            (catch :default _ nil)))
                            remote-sdp (cond-> {:ip host
                                                :port port
                                                :remote-ice-ufrag (or (:remote-ice-ufrag dial-info) "ufrag")
                                                :remote-ice-pwd (or (:remote-ice-pwd dial-info) "pwd")}
                                         (:remote-fingerprint dial-info)
                                         (assoc :fingerprint (normalize-fingerprint (:remote-fingerprint dial-info)))
                                         (:proxy-connect? cand)
                                         (assoc :proxy (resolve-proxy-url nil)))
                            callbacks {:on-open (fn [evt]
                                                  (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)]
                                                    (reset! channel-id cid)
                                                    (when (compare-and-set! success? false true)
                                                      (let [my-gen (inc (long (or (get-in @p2p-peers-atom [peer-pk :generation]) 0)))]
                                                        (reset! assigned-gen my-gen)
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
                                                          (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))))))
                                       :on-data-channel (fn [evt]
                                                          (let [cid (or (:channel-id evt) (:stream-id evt) (get-in evt [:channel :id]) 0)]
                                                            (reset! channel-id cid)
                                                            (when (compare-and-set! success? false true)
                                                              (let [my-gen (inc (long (or (get-in @p2p-peers-atom [peer-pk :generation]) 0)))]
                                                                (reset! assigned-gen my-gen)
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
                                                                  (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))))))
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
                        (if (or (= transport :tcp) (= transport :connect))
                          (api/start-tcp! client-node remote-sdp callbacks)
                          (api/start! client-node remote-sdp callbacks))
                        (js/setTimeout
                         (fn []
                           (when-not @success?
                             (let [cmd-res (light-core/handle-command @state-atom
                                                                      {"cmd" "p2p-channel-state"
                                                                       "session_id" sid
                                                                       "connected" false
                                                                       "error" "p2p-dial-failed"}
                                                                      privkey-bytes)]
                               (reset! state-atom (:state cmd-res))
                               (when state-atom
                                 (swap! state-atom update-in [:diagnostics :p2p-dial-failed] (fnil inc 0)))
                               (when emit-event! (doseq [ev (:stdout-events cmd-res)] (emit-event! ev))))))
                         3000))
                      (catch :default _ nil))))))]
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
                                              (contains? #{:offered :offer-received :connecting :open nil} p2p-phase))]
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

(defn handle-serve-line!
  "Processes a single STDIN or `--cmd-file` JSON line in `serve` mode, invoking `(done-cb)` when complete."
  [line ctx done-cb]
  (let [{:keys [state-atom conn-atom events-out state-file identity bootstrap conn-opts ingress-peers-atom p2p-peers-atom mdns-atom]} ctx
        emit! (fn [payload] (emit-json-line! payload events-out))
        cmd-map (parse-json-safe line)
        verb (when (map? cmd-map) (get cmd-map "cmd"))
        sync-wanted? (or (and (= verb "sync-account")
                              (nil? (get cmd-map "balance"))
                              (nil? (get cmd-map "snapshots"))
                              (nil? (get cmd-map "snapshot")))
                         (and (= verb "account") (or (get cmd-map "sync") (:sync? cmd-map)))
                         (and (= verb "escrows") (or (get cmd-map "sync") (:sync? cmd-map))))
        sync-opts (assoc (or conn-opts {}) :identity identity)
        execute-cmd!
        (fn [effective-line]
          (let [res (light-core/process-jsonl-line @state-atom effective-line (:privkey-bytes identity))
                _ (when-let [dial-info (:p2p-dial res)]
                    (dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom mdns-atom (:privkey-bytes identity) emit! dial-info))
                needs-net? (seq (:net-envelopes res))]
            (if needs-net?
              (let [currently-live? (connection-live? @conn-atom @state-atom)
                    replay-envs (when (= verb "register-home-set")
                                  (light-core/build-unacked-replay-envelopes @state-atom (:privkey-bytes identity)))
                    live-envs (if (seq replay-envs)
                                (into (vec replay-envs) (:net-envelopes res))
                                (:net-envelopes res))]
                (if (some #(or (:p2p-direct? %) (:p2p-broadcast? %)) live-envs)
                  (do
                    (send-routed-envelopes! live-envs
                                            (when currently-live? (:send-fn @conn-atom))
                                            p2p-peers-atom
                                            ingress-peers-atom
                                            state-atom
                                            (:privkey-bytes identity))
                    (reset! state-atom (:state res))
                    (sync-conn-diagnostics! state-atom conn-atom)
                    (save-light-state! state-file @state-atom)
                    (when-let [resp (:response res)]
                      (emit! resp))
                    (done-cb))
                  (let [sent-ingress? (boolean
                                       (when (and ingress-peers-atom (seq @ingress-peers-atom))
                                         (some true? (mapv #(send-all-envelopes! % live-envs) (vals @ingress-peers-atom)))))
                        sent-val? (when currently-live?
                                    (send-all-envelopes! (:send-fn @conn-atom) live-envs))
                        sent? (or sent-val? sent-ingress?)]
                    (if sent?
                      (do
                        (reset! state-atom (assoc (:state res) :connected? true :connection-error nil))
                        (sync-conn-diagnostics! state-atom conn-atom)
                        (save-light-state! state-file @state-atom)
                        (when-let [resp (:response res)]
                          (emit! resp))
                        (done-cb))
                      (do
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
                                     (do
                                       (reset! state-atom (assoc (:state res) :connected? true :connection-error nil))
                                       (sync-conn-diagnostics! state-atom conn-atom)
                                       (save-light-state! state-file @state-atom)
                                       (when-let [resp (:response res)]
                                         (emit! resp)))
                                     (let [err "send-failed"]
                                       (when conn-atom
                                         (apply-conn-event! conn-atom {:type :send-failed :error err :generation target-gen} conn-opts))
                                       (when state-atom
                                         (swap! state-atom assoc :connected? false :connection-error err))
                                       (sync-conn-diagnostics! state-atom conn-atom)
                                       (emit! {"ok" false "error" err})))))
                               (let [err (or (:error reconn) "listener-disabled")]
                                 (when conn-atom
                                   (apply-conn-event! conn-atom {:type :dial-failed :error err :node (:node reconn) :generation target-gen} conn-opts))
                                 (when state-atom
                                   (swap! state-atom assoc :connected? false :connection-error err))
                                 (sync-conn-diagnostics! state-atom conn-atom)
                                 (emit! {"ok" false "error" err})))
                             (done-cb)))))))))
              (do
                (reset! state-atom (:state res))
                (sync-conn-diagnostics! state-atom conn-atom)
                (save-light-state! state-file @state-atom)
                (when-let [resp (:response res)]
                  (emit! resp))
                (done-cb)))))
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
                   (execute-cmd! (if desc (write-json-str (assoc cmd-map "descriptor" desc)) line))))
                (execute-cmd! line)))
            (execute-cmd! line)))]
    (if sync-wanted?
      (maybe-sync-account-state!
       state-atom bootstrap (or (:pubkey-hex identity) (:pubkey identity)) (:privkey-bytes identity) sync-opts
       (fn [sync-res]
         (if (false? (:ok? sync-res))
           (do
             (emit! {"ok" false "error" (:error sync-res)})
             (done-cb))
           (after-sync!))))
      (after-sync!))))

(defn run-auto-sync-tick!
  "Executes a single non-blocking background chain-state quorum sync tick on Node.js."
  [state-atom bootstrap identity state-file conn-opts]
  (let [pubkey (or (:pubkey-hex identity) (:pubkey identity))
        privkey (:privkey-bytes identity)
        conn-atom (:conn-atom conn-opts)
        event-out (:event-out conn-opts)
        sync-opts (assoc (or conn-opts {}) :identity identity)]
    (maybe-sync-account-state!
     state-atom bootstrap pubkey privkey sync-opts
     (fn [res]
       (if (:ok? res)
         (let [finish! (fn []
                         (when state-file
                           (try (save-light-state! state-file @state-atom) (catch :default _ nil)))
                         (let [st @state-atom
                               fin-ep (or (get-in st [:account :finalized-epoch]) (:epoch st) 0)
                               bal (or (get-in st [:account :balance]) 0)
                               spend (or (get-in st [:account :spendable]) bal 0)]
                           (when event-out
                             (event-out {"event" "auto-sync"
                                         "ok" true
                                         "finalized_epoch" fin-ep
                                         "balance" bal
                                         "spendable" spend
                                         "synced" true}))))]
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
         (let [err (str (or (:error res) "auto-sync-tick-failed"))]
           (when conn-atom
             (apply-conn-event! conn-atom {:type :auto-sync-failed :error err} conn-opts)
             (sync-conn-diagnostics! state-atom conn-atom))
           (when event-out
             (event-out {"event" "auto-sync"
                         "ok" false
                         "synced" false
                         "error" err}))))))))

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

(defn run-serve!
  "Runs the Node.js light node in continuous JSONL `serve` mode reading STDIN (and optional `--cmd-file`)
   and writing STDOUT (and optional `--events-out`)."
  [opts]
  (let [state-dir (:state-dir opts)
        state-file (.join node-path state-dir "state.fressian")
        events-out (:events-out opts)
        cmd-file (:cmd-file opts)
        identity (load-or-create-light-identity! state-dir)]
    (load-bootstrap-descriptor!
     (:bootstrap opts) nil
     (fn [b-res]
       (if-not (:ok? b-res)
         (do
           (emit-json-line! {"event" "connection-failed" "connected" false "error" (:error b-res)} events-out)
           (.exit js/process 1))
         (let [bootstrap (:descriptor b-res)
               loaded-state (load-light-state! state-file)
               base-state (or (when loaded-state
                                (cond-> loaded-state
                                  (some? (:autonomous? opts)) (assoc :autonomous? (boolean (:autonomous? opts)))
                                  (seq (:nodes bootstrap)) (assoc :bootstrap bootstrap)
                                  (:directory-pubkey bootstrap) (assoc :trusted-directory-pubkey (:directory-pubkey bootstrap))
                                  (:trusted-dac-anchors opts) (assoc :trusted-dac-anchors (:trusted-dac-anchors opts))
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
               initial-state (cond-> (assoc base-state :max-epoch-skew (or (:max-epoch-skew base-state) 15))
                               (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                               (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                               (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap))))
               state-atom (atom initial-state)
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
               _ (swap! state-atom assoc
                        :mdns-hostname mdns-host
                        :lan-ip lan-ip
                        :default-p2p-candidates default-cands)
               mdns-svc (try (mdns/start-mdns-service! {:initial-hosts {mdns-host lan-ip}}) (catch :default _ nil))
               mdns-atom (or mdns-svc (atom (mdns/init-mdns-table)))
               p2p-peers-atom (atom {})
               ingress-peers-atom (atom {})
               conn-opts (assoc opts
                                :state-atom state-atom
                                :conn-atom conn-atom
                                :event-out event-out
                                :reconnect-fn reconnect-fn
                                :ingress-peers-atom ingress-peers-atom
                                :p2p-peers-atom p2p-peers-atom
                                :mdns-atom mdns-atom
                                :mdns-svc mdns-svc
                                :state-file state-file)
               _ (reset! conn-opts-atom conn-opts)
               ingress-listener (start-ingress-tcp-listener! identity conn-opts)
               stop-ingress! (fn []
                               (when mdns-svc (try (mdns/stop-mdns-service! mdns-svc) (catch :default _ nil)))
                               (when-let [stop-fn (:stop! ingress-listener)]
                                 (try (stop-fn) (catch :default _ nil))))
               _ (.on js/process "exit" (fn [_] (stop-ingress!)))
               _ (.on js/process "SIGINT" (fn [] (stop-ingress!) (.exit js/process 0)))
               _ (.on js/process "SIGTERM" (fn [] (stop-ingress!) (.exit js/process 0)))
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
                        (fn []
                          (reset! processing? false)
                          (drain!))))
                     (reset! processing? false))))
               enqueue-line!
               (fn [line]
                 (when-not (str/blank? line)
                   (swap! line-queue conj line)
                   (drain-queue!)))]
           (reconnect-fn
            (fn [conn-res]
              (if (:ok? conn-res)
                (emit-json-line! {"event" "ready"
                                  "connected" true
                                  "transport" (name (or (:transport opts) :udp))}
                                 events-out)
                (emit-json-line! {"event" "connection-failed"
                                  "connected" false
                                  "error" (:error conn-res)}
                                 events-out))
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
                                    (js/setTimeout #(.exit js/process 0) 100)))))))))))))

(defn run-one-shot!
  "Executes a single one-shot light-node command on Node.js and outputs JSON response."
  [opts]
  (let [state-dir (:state-dir opts)
        state-file (.join node-path state-dir "state.fressian")
        identity (load-or-create-light-identity! state-dir)]
    (load-bootstrap-descriptor!
     (:bootstrap opts) nil
     (fn [b-res]
       (if-not (:ok? b-res)
         (do
           (emit-json-line! {"ok" false "error" (:error b-res)})
           (.exit js/process 0))
         (let [bootstrap (:descriptor b-res)
               loaded-state (load-light-state! state-file)
               base-state (or (when loaded-state
                                (cond-> loaded-state
                                  (some? (:autonomous? opts)) (assoc :autonomous? (boolean (:autonomous? opts)))
                                  (seq (:nodes bootstrap)) (assoc :bootstrap bootstrap)
                                  (:directory-pubkey bootstrap) (assoc :trusted-directory-pubkey (:directory-pubkey bootstrap))
                                  (:trusted-dac-anchors opts) (assoc :trusted-dac-anchors (:trusted-dac-anchors opts))
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
               initial-state (cond-> (assoc base-state :max-epoch-skew (or (:max-epoch-skew base-state) 15))
                               (contains? bootstrap :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? bootstrap)))
                               (:burn-floor bootstrap) (assoc :burn-floor (long (:burn-floor bootstrap)))
                               (:min-signaling-burn bootstrap) (assoc :min-signaling-burn (long (:min-signaling-burn bootstrap))))
               state-atom (atom initial-state)
               raw-cmd-map (:cmd-map opts)
               verb (when (map? raw-cmd-map) (get raw-cmd-map "cmd"))
               run-cmd-with-map!
               (fn [cmd-map]
                 (let [sync-wanted? (or (boolean (:auto-sync? opts))
                                        (and (= verb "sync-account")
                                             (nil? (get cmd-map "balance"))
                                             (nil? (get cmd-map "snapshots"))
                                             (nil? (get cmd-map "snapshot")))
                                        (and (= verb "account") (or (:sync? opts) (get cmd-map "sync") (:sync? cmd-map)))
                                        (and (= verb "escrows") (or (:sync? opts) (get cmd-map "sync") (:sync? cmd-map))))
                       sync-opts (assoc opts :identity identity)
                       after-sync!
                       (fn []
                         (let [res (light-core/handle-command @state-atom cmd-map (:privkey-bytes identity))
                               new-state (:state res)
                               needs-network? (and (seq (:net-envelopes res)) (:connect? opts true))]
                           (if needs-network?
                             (connect-validators!
                              identity bootstrap opts
                              (fn [conn-res]
                                (if-not (:ok? conn-res)
                                  (do
                                    (emit-json-line! {"ok" false "error" (or (:error conn-res) "listener-disabled")})
                                    (.exit js/process 0))
                                  (let [sent? (send-all-envelopes! (:send-fn conn-res) (:net-envelopes res))]
                                    (js/setTimeout
                                     (fn []
                                       (when-let [n (:node conn-res)]
                                         (try (api/close! n) (catch :default _ nil)))
                                       (if sent?
                                         (do
                                           (save-light-state! state-file new-state)
                                           (emit-json-line! (:response res))
                                           (.exit js/process 0))
                                         (do
                                           (emit-json-line! {"ok" false "error" "connection-closed"})
                                           (.exit js/process 0))))
                                     50)))))
                             (do
                               (save-light-state! state-file new-state)
                               (emit-json-line! (:response res))
                               (.exit js/process 0)))))]
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
             (run-cmd-with-map! raw-cmd-map))))))))

(defn run-light-node-cli!
  "Dispatches Node.js light-node CLI invocation based on parsed arguments."
  [args]
  (let [parsed (parse-light-node-args args)]
    (case (:mode parsed)
      :serve (run-serve! parsed)
      :wait-event (run-wait-event! parsed)
      :one-shot (run-one-shot! parsed))))

(defn -main
  "Entrypoint for `node dist/bitecho-light-node.cjs`."
  [& args]
  (run-light-node-cli! (vec args)))

(set! *main-cli-fn* -main)
