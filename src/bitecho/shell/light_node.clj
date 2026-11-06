(ns bitecho.shell.light-node
  "Light-node boundary shell for Bitecho.
   Handles CLI invocation, JSONL STDIN/STDOUT serve loop, state persistence
   with atomic rename (0600 permissions), and WebRTC DataChannel agent connections."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.agent-sim :as agent-sim]
            [bitecho.shell.discovery :as discovery]
            [bitecho.shell.identity :as identity]
            [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [datachannel.api :as api]
            [taoensso.nippy :as nippy])
  (:import [java.io BufferedReader InputStreamReader PrintWriter]
           [java.net URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.nio.file Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]
           [java.time Duration]))

;; -----------------------------------------------------------------------------
;; Pure State Sanitization & Argument Parsing
;; -----------------------------------------------------------------------------

(defn strip-sensitive-keys
  "Pure helper to remove ephemeral private keys from session state prior to persistence,
   and dissoc transient runtime connection liveness keys so state.nippy never persists them."
  [state]
  (let [clean-sessions (into {} (for [[sid s] (:sessions state)]
                                  [sid (dissoc s :ephemeral-priv)]))]
    (-> state
        (assoc :sessions clean-sessions)
        (dissoc :connected? :connection-error :conn-diagnostics))))

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
        no-auto-sync? (boolean (some #{"--no-auto-sync"} clean-args))
        explicit-auto-sync? (boolean (some #{"--auto-sync"} clean-args))
        auto-sync? (and (not no-auto-sync?) (or explicit-auto-sync? serve?))
        sync-interval-ms (extract-long-flag clean-args "--sync-interval-ms" (when auto-sync? 15000))
        transport-str (extract-flag-value clean-args "--transport" "udp")
        transport (case (str/lower-case transport-str)
                    "tcp" :tcp
                    "connect" :connect
                    :udp)
        timeout-ms (extract-long-flag clean-args "--timeout-ms" nil)
        proxy-cli (extract-flag-value clean-args "--proxy" nil)
        proxy-url (resolve-proxy-url proxy-cli)
        subnet-id (extract-flag-value clean-args "--subnet-id" nil)
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
    (cond-> {:mode (if serve? :serve :one-shot)
             :verb verb
             :state-dir state-dir
             :bootstrap bootstrap-path
             :autonomous? (boolean autonomous?)
             :auto-sync? (boolean auto-sync?)
             :transport transport
             :cmd-map (let [m (when-not serve? (build-one-shot-cmd-map verb (rest clean-args)))]
                        (cond-> m
                          subnet-id (assoc "subnet_id" subnet-id)))}
      sync-interval-ms (assoc :sync-interval-ms sync-interval-ms)
      subnet-id (assoc :subnet-id subnet-id)
      timeout-ms (assoc :timeout-ms timeout-ms)
      proxy-url (assoc :proxy proxy-url)
      turn-config (assoc :turn-config turn-config))))

;; -----------------------------------------------------------------------------
;; State Persistence & Identity Loading
;; -----------------------------------------------------------------------------

(defonce ^:private light-state-save-lock (Object.))

(defn save-light-state!
  "Persists sanitized light-node state via Nippy with atomic move and 0600 permissions."
  [state-file state]
  (when (and (some? state-file) (not (str/blank? (str state-file))))
    (locking light-state-save-lock
      (let [f (io/file state-file)
            dir (or (.getParentFile f) (io/file "."))
            _ (.mkdirs dir)
            tmp-file (java.io.File/createTempFile "light-state-" ".tmp" dir)]
        (try
          (let [clean-state (strip-sensitive-keys state)
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
            true)
          (finally
            (when (.exists tmp-file)
              (try (.delete tmp-file) (catch Exception _ nil)))))))))

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
          client (-> (HttpClient/newBuilder)
                     (.connectTimeout (Duration/ofMillis 1500))
                     (.build))]
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
                           query-env (light-core/build-chain-state-query-envelope pubkey privkey-bytes {:nonce nonce})
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
        (api/start! client-node remote-sdp callbacks))
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
   Supports injectable (:directory-fetcher opts) (fn [domain nickname] ...) for deterministic testing.
   Over HTTP/HTTPS, fetches https://<domain>/directory/<nickname>.json (falling back to https://<domain>/<nickname>),
   and parses via light-core/parse-directory-descriptor-text."
  ([domain nickname] (fetch-directory-descriptor! domain nickname nil))
  ([domain nickname opts]
   (if-let [custom-fetcher (:directory-fetcher opts)]
     (try
       (let [res (custom-fetcher domain nickname)]
         (cond
           (map? res) res
           (string? res) (light-core/parse-directory-descriptor-text res)
           :else nil))
       (catch Exception _ nil))
     (let [dom (if (or (nil? domain) (str/blank? domain)) "bitecho.org" (str/trim domain))
           url1 (str "https://" dom "/directory/" nickname ".json")
           url2 (str "https://" dom "/" nickname)
           local-f1 (io/file "devnet/directory" (str nickname ".json"))
           client (HttpClient/newHttpClient)
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
       (or (if-let [body1 (fetch-url url1)]
             (light-core/parse-directory-descriptor-text body1)
             (when-let [body2 (fetch-url url2)]
               (light-core/parse-directory-descriptor-text body2)))
           (when (.exists local-f1)
             (light-core/parse-directory-descriptor-text (slurp local-f1))))))))

(defn fetch-inband-chain-state-quorum!
  "Fetches chain state snapshots from validators in parallel, cross-checking via verify-chain-state-quorum.
   Supports injectable (:inband-snapshot-fetcher opts) for deterministic testing.
   Returns {:ok? true :snapshot agreed-snap :quorum-count n :validators [...]} or {:ok? false :error <reason>}."
  [identity bootstrap pubkey privkey-bytes opts]
  (if-let [fetcher (:inband-snapshot-fetcher opts)]
    (let [snaps (fetcher pubkey)
          trusted (set (keep :pubkey (vals (:nodes bootstrap))))
          q-opts (assoc opts
                        :expected-pubkey pubkey
                        :trusted-validators trusted
                        :min-finalized-epoch (long (or (:min-finalized-epoch opts) 0)))]
      (light-core/verify-chain-state-quorum snaps q-opts))
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

(defn maybe-sync-account-state!
  "Attempts in-band validator quorum sync over Port 5010/DTLS via fetch-inband-chain-state-quorum!.
   If in-band returns snapshots and verifies quorum, updates state-atom and returns {:ok? true :state @state-atom :quorum-result q-res}.
   If in-band quorum verification fails, fails closed immediately and returns {:ok? false :error (:error inband-res)}.
   If zero in-band snapshots were reachable (and no inband fetcher provided), falls back to legacy HTTP fetch-validator-accountz!."
  [state-atom bootstrap pubkey privkey-bytes opts]
  (let [id (or (:identity opts) {:pubkey-hex pubkey :privkey-bytes privkey-bytes})
        inband-res (fetch-inband-chain-state-quorum! id bootstrap pubkey privkey-bytes opts)]
    (cond
      (:ok? inband-res)
      (let [snap (:snapshot inband-res)]
        (swap! state-atom (fn [st] (light-core/apply-verified-chain-state-snapshot st snap)))
        {:ok? true :state @state-atom :quorum-result inband-res})

      (or (:inband-snapshot-fetcher opts)
          (and (not= (:error inband-res) "no-inband-snapshots-returned")
               (not= (:error inband-res) "empty-bootstrap-nodes")))
      {:ok? false :error (:error inband-res)}

      :else
      (if-let [resp (fetch-validator-accountz! bootstrap pubkey opts)]
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
        {:ok? false :error (or (:error inband-res) "all-sync-methods-failed")}))))

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
                         (when state-atom
                           (let [st @state-atom
                                 res (light-core/handle-wire-payload st payload (:privkey-bytes identity))]
                             (reset! state-atom (:state res))
                             (when (and state-file (not= st (:state res)))
                               (try
                                 (save-light-state! state-file (:state res))
                                 (catch Exception e
                                   (when conn-atom
                                     (apply-conn-event! conn-atom
                                                        {:type :persist-failed
                                                         :error (or (.getMessage e) "persist-failed")}
                                                        cb-opts)
                                     (sync-conn-diagnostics! state-atom conn-atom)))))
                             (when (and event-out (seq (:stdout-events res)))
                               (doseq [ev (:stdout-events res)]
                                 (event-out ev)))
                             (when (seq (:net-envelopes res))
                               (dispatch-auto-reply! (:net-envelopes res) send-fn-atom state-atom conn-atom event-out reconnect-fn cb-opts))))))))
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

                  (= (:error res) "bad-fingerprint")
                  res

                  :else
                  (recur (rest rem-candidates)
                         (conj failed-nodes {:validator-id (:node-id node)
                                             :error (or (:error res) "listener-disabled")}))))
              {:ok? false
               :error "listener-disabled"
               :failed-nodes failed-nodes})))))))

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
        cmd-map (try (json/read-str line) (catch Exception _ nil))
        verb (when (map? cmd-map) (get cmd-map "cmd"))
        sync-wanted? (or (and (= verb "sync-account") (nil? (get cmd-map "balance")) (nil? (get cmd-map "snapshots")) (nil? (get cmd-map "snapshot")))
                         (and (= verb "account") (or (get cmd-map "sync") (:sync? cmd-map)))
                         (and (= verb "escrows") (or (get cmd-map "sync") (:sync? cmd-map))))
        sync-opts (assoc (or conn-opts {}) :identity identity)
        sync-res (when sync-wanted?
                   (maybe-sync-account-state! state-atom bootstrap (or (:pubkey-hex identity) (:pubkey identity)) (:privkey-bytes identity) sync-opts))]
    (if (and sync-res (false? (:ok? sync-res)))
      (let [err-resp {"ok" false "error" (:error sync-res)}]
        (emit-json-line! out-writer err-resp)
        err-resp)
      (let [effective-line (if (and (contains? #{"directory-lookup" "directory-verify"} verb)
                                    (not (contains? cmd-map "descriptor"))
                                    (not (contains? cmd-map :descriptor)))
                             (let [nick (or (get cmd-map "nickname") (:nickname cmd-map))
                                   dom (or (get cmd-map "domain") (:domain cmd-map) "bitecho.org")
                                   desc (when (and (string? nick) (not (str/blank? nick)))
                                          (fetch-directory-descriptor! dom nick conn-opts))]
                               (if desc
                                 (json/write-str (assoc cmd-map "descriptor" desc))
                                 line))
                             line)
            res (light-core/process-jsonl-line @state-atom effective-line (:privkey-bytes identity))
            needs-net? (seq (:net-envelopes res))]
        (if needs-net?
          (let [currently-live? (connection-live? @conn-atom @state-atom)
                replay-envs (when (= verb "register-home-set")
                              (light-core/build-unacked-replay-envelopes @state-atom (:privkey-bytes identity)))
                live-envs (if (seq replay-envs)
                            (into (vec replay-envs) (:net-envelopes res))
                            (:net-envelopes res))
                sent? (when currently-live?
                        (send-all-envelopes! (:send-fn @conn-atom) live-envs))]
            (if sent?
              (do
                (reset! state-atom (assoc (:state res) :connected? true :connection-error nil))
                (sync-conn-diagnostics! state-atom conn-atom)
                (save-light-state! state-file @state-atom)
                (when-let [resp (:response res)]
                  (emit-json-line! out-writer resp)))
              (do
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
                            (reset! state-atom (assoc (:state res) :connected? true :connection-error nil))
                            (sync-conn-diagnostics! state-atom conn-atom)
                            (save-light-state! state-file @state-atom)
                            (when-let [resp (:response res)]
                              (emit-json-line! out-writer resp)))
                          (let [err "send-failed"]
                            (when conn-atom
                              (apply-conn-event! conn-atom {:type :send-failed :error err :generation target-gen} conn-opts))
                            (when state-atom
                              (swap! state-atom assoc :connected? false :connection-error err))
                            (sync-conn-diagnostics! state-atom conn-atom)
                            (emit-json-line! out-writer {"ok" false "error" err})))))
                    (let [err (or (:error reconn) "listener-disabled")]
                      (when conn-atom
                        (apply-conn-event! conn-atom {:type :dial-failed :error err :node (:node reconn) :generation target-gen} conn-opts))
                      (when state-atom
                        (swap! state-atom assoc :connected? false :connection-error err))
                      (sync-conn-diagnostics! state-atom conn-atom)
                      (emit-json-line! out-writer {"ok" false "error" err})))))))
          (do
            (reset! state-atom (:state res))
            (sync-conn-diagnostics! state-atom conn-atom)
            (save-light-state! state-file @state-atom)
            (when-let [resp (:response res)]
              (emit-json-line! out-writer resp))))))))

(defn run-auto-sync-tick!
  "Executes a single non-blocking background chain-state quorum sync tick.
   Updates state-atom and persists to state-file when sync succeeds."
  [state-atom bootstrap identity state-file conn-opts]
  (try
    (let [pubkey (or (:pubkey-hex identity) (:pubkey identity))
          privkey (:privkey-bytes identity)
          sync-opts (assoc (or conn-opts {}) :identity identity)
          res (maybe-sync-account-state! state-atom bootstrap pubkey privkey sync-opts)]
      (when (and (:ok? res) state-file)
        (try (save-light-state! state-file @state-atom) (catch Exception _ nil)))
      res)
    (catch Exception e
      {:ok? false :error (or (.getMessage e) "auto-sync-tick-failed")})))

(defn run-serve!
  "Runs the light node in continuous JSONL serve mode reading STDIN and writing STDOUT."
  [opts]
  (let [state-dir (:state-dir opts)
        state-file (str (io/file state-dir "state.nippy"))
        identity (load-or-create-light-identity! state-dir)
        bootstrap (discovery/load-bootstrap-descriptor! (:bootstrap opts))
        loaded-state (load-light-state! state-file)
        base-state (or (when loaded-state
                         (cond-> loaded-state
                           (some? (:autonomous? opts)) (assoc :autonomous? (boolean (:autonomous? opts)))
                           (seq (:nodes bootstrap)) (assoc :bootstrap bootstrap)
                           (:directory-pubkey bootstrap) (assoc :trusted-directory-pubkey (:directory-pubkey bootstrap))))
                       (light-core/init-light-state identity (cond-> {:bootstrap bootstrap
                                                                      :autonomous? (boolean (:autonomous? opts false))}
                                                               (:subnet-id opts) (assoc :subnet-id (:subnet-id opts)))))
        initial-state (assoc base-state :max-epoch-skew (long (or (:max-epoch-skew base-state) 15)))
        state-atom (atom initial-state)
        conn-atom (atom (init-conn-state))
        out-writer (PrintWriter. System/out true)
        event-out (fn [ev] (emit-json-line! out-writer ev))
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
        conn-opts (assoc opts
                         :state-atom state-atom
                         :conn-atom conn-atom
                         :event-out event-out
                         :reconnect-fn reconnect-fn
                         :state-file state-file
                         :async-reconnect? true)
        _ (reset! conn-opts-atom conn-opts)
        conn-res (reconnect-fn)
        auto-sync-running? (atom (boolean (:auto-sync? opts true)))
        sync-interval-ms (max 1000 (long (or (:sync-interval-ms opts) 15000)))
        _ (when @auto-sync-running?
            (doto (Thread.
                   ^Runnable
                   (fn []
                     (while @auto-sync-running?
                       (run-auto-sync-tick! state-atom bootstrap identity state-file conn-opts)
                       (try
                         (Thread/sleep sync-interval-ms)
                         (catch InterruptedException _
                           (reset! auto-sync-running? false))))))
              (.setDaemon true)
              (.setName "bitecho-light-node-auto-sync")
              (.start)))
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
    (try
      (binding [*out* *err*]
        (let [reader (BufferedReader. (InputStreamReader. System/in "UTF-8"))]
          (loop []
            (when-let [line (.readLine reader)]
              (when-not (str/blank? line)
                (handle-serve-line! line ctx))
              (recur)))))
      (finally
        (reset! auto-sync-running? false)))))

(defn run-one-shot!
  "Executes a single one-shot light-node command and outputs JSON response."
  [opts]
  (let [state-dir (:state-dir opts)
        state-file (str (io/file state-dir "state.nippy"))
        identity (load-or-create-light-identity! state-dir)
        bootstrap (discovery/load-bootstrap-descriptor! (:bootstrap opts))
        loaded-state (load-light-state! state-file)
        base-state (or (when loaded-state
                         (cond-> loaded-state
                           (some? (:autonomous? opts)) (assoc :autonomous? (boolean (:autonomous? opts)))
                           (seq (:nodes bootstrap)) (assoc :bootstrap bootstrap)
                           (:directory-pubkey bootstrap) (assoc :trusted-directory-pubkey (:directory-pubkey bootstrap))))
                       (light-core/init-light-state identity (cond-> {:bootstrap bootstrap
                                                                      :autonomous? (boolean (:autonomous? opts false))}
                                                               (:subnet-id opts) (assoc :subnet-id (:subnet-id opts)))))
        initial-state (assoc base-state :max-epoch-skew (long (or (:max-epoch-skew base-state) 15)))
        state-atom (atom initial-state)
        raw-cmd-map (:cmd-map opts)
        verb (when (map? raw-cmd-map) (get raw-cmd-map "cmd"))
        cmd-map (if (and (contains? #{"directory-lookup" "directory-verify"} verb)
                         (not (contains? raw-cmd-map "descriptor"))
                         (not (contains? raw-cmd-map :descriptor)))
                  (let [nick (or (get raw-cmd-map "nickname") (:nickname raw-cmd-map))
                        dom (or (get raw-cmd-map "domain") (:domain raw-cmd-map) "bitecho.org")
                        desc (when (and (string? nick) (not (str/blank? nick)))
                               (fetch-directory-descriptor! dom nick opts))]
                    (cond-> raw-cmd-map
                      desc (assoc "descriptor" desc)))
                  raw-cmd-map)
        sync-wanted? (or (boolean (:auto-sync? opts))
                         (and (= verb "sync-account") (nil? (get cmd-map "balance")) (nil? (get cmd-map "snapshots")) (nil? (get cmd-map "snapshot")))
                         (and (= verb "account") (or (:sync? opts) (get cmd-map "sync") (:sync? cmd-map)))
                         (and (= verb "escrows") (or (:sync? opts) (get cmd-map "sync") (:sync? cmd-map))))
        sync-opts (assoc opts :identity identity)
        sync-res (when sync-wanted?
                   (maybe-sync-account-state! state-atom bootstrap (or (:pubkey-hex identity) (:pubkey identity)) (:privkey-bytes identity) sync-opts))
        out-writer (PrintWriter. System/out true)]
    (if (and sync-res (false? (:ok? sync-res)))
      (let [err-resp {"ok" false "error" (:error sync-res)}]
        (emit-json-line! out-writer err-resp)
        err-resp)
      (binding [*out* *err*]
        (let [res (light-core/handle-command @state-atom cmd-map (:privkey-bytes identity))
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
              (:response res))))))))

(defn run-light-node-cli!
  "Dispatches light-node CLI invocation based on parsed arguments."
  [args]
  (let [parsed (parse-light-node-args args)]
    (case (:mode parsed)
      :serve (run-serve! parsed)
      :one-shot (run-one-shot! parsed))))
