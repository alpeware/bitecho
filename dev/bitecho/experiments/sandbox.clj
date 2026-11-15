(ns bitecho.experiments.sandbox
  "Bubblewrap (`bwrap`) filesystem/namespace sandbox builder, EDN experiment schema
   validator, and per-node local UDP DNS allowlist proxy (`INV-D16-1`..`INV-D16-3`)."
  (:require [bitecho.core.protocol.dns :as dns]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.net DatagramPacket DatagramSocket InetAddress SocketException]
           [java.util Arrays]
           [java.util.concurrent TimeUnit]))

;; =============================================================================
;; 1. Supported Models & Experiment Schema Validation (`INV-D16-1`)
;; =============================================================================

(def supported-agy-models
  "Set of valid model identifiers supported by `agy --mode headless -m <model>`."
  #{"gemini-4-carbon-medium"
    "gemini-4-carbon-high"
    "gemini-4-carbon-low"
    "gemini-4-argon-medium"
    "gemini-4-argon-high"
    "gemini-4-argon-low"
    "gemini-4-hydrogen-high"
    "gemini-4-hydrogen-xhigh"
    "gemini-4-hydrogen-medium"
    "gemini-4-hydrogen-low"
    "gemini-pro-orchestrator"
    "gemini-pro-orchestrator-argon"
    "gemini-3.8-flash-high"
    "gemini-3.8-flash-medium"
    "gemini-3.8-flash-low"
    "claude-opus-5-5-low"
    "claude-opus-5-5-medium"
    "claude-opus-5-5-high"
    "claude-sonnet-5-5-low"
    "claude-sonnet-5-5-medium"
    "claude-sonnet-5-5-high"
    "gpt-oss-120b-medium"})

(def root-funding-sources
  "Valid root funding parent identifiers that mint initial experiment supply."
  #{:genesis-custody :treasury})

(defn validate-node-config
  "Validates a single node configuration map per `INV-D16-1`.
   Returns `{:ok? boolean :error keyword-or-nil :node-id ...}`."
  [node-cfg]
  (let [{:keys [node-id parent-id start-balance model-type initial-prompt dns-allow-list]} node-cfg]
    (cond
      (not (keyword? node-id))
      {:ok? false :error :invalid-node-id :node-id node-id}

      (not (keyword? parent-id))
      {:ok? false :error :invalid-parent-id :node-id node-id}

      (or (not (integer? start-balance)) (neg? start-balance))
      {:ok? false :error :invalid-start-balance :node-id node-id}

      (not (contains? supported-agy-models model-type))
      {:ok? false :error :unsupported-model-type :node-id node-id :model-type model-type}

      (or (not (string? initial-prompt)) (str/blank? initial-prompt))
      {:ok? false :error :blank-initial-prompt :node-id node-id}

      (or (not (sequential? dns-allow-list))
          (empty? dns-allow-list)
          (not (every? #(and (string? %) (not (str/blank? %))) dns-allow-list)))
      {:ok? false :error :invalid-dns-allow-list :node-id node-id}

      :else
      {:ok? true :node-id node-id})))

(defn validate-experiment-config
  "Validates a full multi-node experiment configuration map and resolves hierarchical
   parent-child funding (`INV-D16-1`).
   When a node's `:parent-id` is another sibling node in `:nodes`, the child's `:start-balance`
   is deducted from the parent node's `:start-balance` so total experiment supply is conserved.
   Fails closed if any parent's balance would become negative or if an unknown `:parent-id`
   is referenced."
  [exp-cfg]
  (let [nodes (:nodes exp-cfg)]
    (cond
      (or (not (map? exp-cfg))
          (str/blank? (str (:experiment-id exp-cfg))))
      {:ok? false :error :missing-experiment-id}

      (or (not (sequential? nodes)) (empty? nodes))
      {:ok? false :error :empty-nodes}

      :else
      (let [node-validations (mapv validate-node-config nodes)
            first-err (first (remove :ok? node-validations))
            node-ids (mapv :node-id nodes)
            node-id-set (set node-ids)]
        (cond
          first-err
          first-err

          (not= (count node-ids) (count node-id-set))
          {:ok? false :error :duplicate-node-ids}

          :else
          (let [unknown-parent (first (filter (fn [{:keys [parent-id node-id]}]
                                                (or (= parent-id node-id)
                                                    (and (not (contains? root-funding-sources parent-id))
                                                         (not (contains? node-id-set parent-id)))))
                                              nodes))]
            (if unknown-parent
              {:ok? false
               :error :invalid-parent-reference
               :node-id (:node-id unknown-parent)
               :parent-id (:parent-id unknown-parent)}
              (let [initial-map (into {} (map (juxt :node-id :start-balance) nodes))
                    effective-map (reduce
                                   (fn [acc {:keys [parent-id start-balance]}]
                                     (if (contains? node-id-set parent-id)
                                       (update acc parent-id - start-balance)
                                       acc))
                                   initial-map
                                   nodes)
                    over-allocated (first (filter (fn [[_ bal]] (neg? bal)) effective-map))]
                (if over-allocated
                  {:ok? false
                   :error :insufficient-parent-balance
                   :parent-id (first over-allocated)
                   :remaining-balance (second over-allocated)}
                  {:ok? true
                   :effective-balances effective-map
                   :initial-supply (reduce + 0 (vals effective-map))})))))))))

;; =============================================================================
;; 2. Per-Node UDP DNS Allowlist Packet Filter & Server (`INV-D16-3`, `A-CARB-D16-2`)
;; =============================================================================

(defn normalize-domain
  "Normalizes a DNS domain name by lower-casing and stripping any trailing dot."
  [s]
  (let [trimmed (str/lower-case (str/trim (str s)))]
    (if (str/ends-with? trimmed ".")
      (subs trimmed 0 (dec (count trimmed)))
      trimmed)))

(defn domain-allowed?
  "Returns true if `qname` matches an entry in `allow-list` (supporting exact match
   or `*.suffix` wildcard match)."
  [qname allow-list]
  (let [norm (normalize-domain qname)]
    (boolean
     (some (fn [pattern]
             (let [p (normalize-domain pattern)]
               (cond
                 (= p "*") true
                 (str/starts-with? p "*.")
                 (let [suffix (subs p 1)] ; e.g. ".bitecho.org"
                   (and (str/ends-with? norm suffix)
                        (> (count norm) (count suffix))))
                 :else
                 (= norm p))))
           allow-list))))

(defn resolve-domain-ip
  "Resolves an allowed domain name to an IPv4 string using `dns-records` first,
   falling back to `InetAddress/getByName` or `127.0.0.1`."
  [qname dns-records]
  (let [norm (normalize-domain qname)
        norm-records (into {} (map (fn [[k v]] [(normalize-domain k) v]) dns-records))]
    (or (get norm-records norm)
        (some (fn [[k v]]
                (when (and (str/starts-with? k "*.")
                           (str/ends-with? norm (subs k 1)))
                  v))
              norm-records)
        (try
          (.getHostAddress (InetAddress/getByName norm))
          (catch Exception _
            "127.0.0.1")))))

(defn handle-dns-query-bytes
  "Pure DNS allowlist packet handler (`INV-D16-3`).
   Decodes `query-bytes` via `bitecho.core.protocol.dns/decode-packet`, checks the
   queried domain against `allow-list`, and returns:
   `{:allowed? boolean :qname str :rcode :noerror|:refused :response-bytes byte-array}`."
  [^bytes query-bytes allow-list dns-records]
  (let [decoded (dns/decode-packet query-bytes)
        question (first (:questions decoded))
        qname (or (:qname question) "")
        allowed? (and (some? question) (domain-allowed? qname allow-list))]
    (if allowed?
      (let [ip-str (resolve-domain-ip qname dns-records)
            resp-bytes (dns/encode-packet
                        {:id (or (:id decoded) 0)
                         :qr? true
                         :opcode (or (:opcode decoded) 0)
                         :aa? true
                         :rd? (boolean (:rd? decoded))
                         :ra? true
                         :rcode :noerror
                         :questions (vec (:questions decoded))
                         :answers [{:name qname
                                    :type :A
                                    :class :IN
                                    :ttl 60
                                    :rdata ip-str}]})]
        {:allowed? true
         :qname (normalize-domain qname)
         :rcode :noerror
         :ip ip-str
         :response-bytes resp-bytes})
      (let [resp-bytes (dns/encode-packet
                        {:id (or (:id decoded) 0)
                         :qr? true
                         :opcode (or (:opcode decoded) 0)
                         :aa? true
                         :rd? (boolean (:rd? decoded))
                         :ra? true
                         :rcode :refused
                         :questions (vec (:questions decoded))
                         :answers []})]
        {:allowed? false
         :qname (normalize-domain qname)
         :rcode :refused
         :response-bytes resp-bytes}))))

(defn start-dns-allowlist-server!
  "Starts a local UDP DNS allowlist server bound to `127.0.0.1` on an ephemeral port.
   Returns `{:socket DatagramSocket :port int :running? atom :stats-atom atom :thread Thread}`."
  [allow-list dns-records]
  (let [sock (DatagramSocket. 0 (InetAddress/getByName "127.0.0.1"))
        port (.getLocalPort sock)
        running? (atom true)
        stats-atom (atom {:allowed-count 0 :refused-count 0 :queries []})
        worker (Thread.
                (fn []
                  (let [buf (byte-array 512)]
                    (while @running?
                      (try
                        (let [pkt (DatagramPacket. buf (alength buf))]
                          (.receive sock pkt)
                          (let [q-bytes (Arrays/copyOf (.getData pkt) (.getLength pkt))
                                res (handle-dns-query-bytes q-bytes allow-list dns-records)
                                ^bytes resp-bytes (:response-bytes res)
                                resp-pkt (DatagramPacket.
                                          resp-bytes
                                          (alength resp-bytes)
                                          (.getAddress pkt)
                                          (.getPort pkt))]
                            (swap! stats-atom
                                   (fn [st]
                                     (-> st
                                         (update (if (:allowed? res) :allowed-count :refused-count) inc)
                                         (update :queries conj {:qname (:qname res)
                                                                :allowed? (:allowed? res)
                                                                :rcode (:rcode res)}))))
                            (.send sock resp-pkt)))
                        (catch SocketException _
                          (reset! running? false))
                        (catch Throwable _
                          nil)))))
                (str "bitecho-dns-allowlist-" port))]
    (.setDaemon worker true)
    (.start worker)
    {:socket sock
     :port port
     :allow-list (vec allow-list)
     :dns-records (or dns-records {})
     :running? running?
     :stats-atom stats-atom
     :thread worker}))

(defn stop-dns-allowlist-server!
  "Stops a running local UDP DNS allowlist server."
  [srv]
  (when srv
    (when-let [r (:running? srv)]
      (reset! r false))
    (when-let [^DatagramSocket sock (:socket srv)]
      (try
        (.close sock)
        (catch Exception _ nil)))))

;; =============================================================================
;; 3. Bubblewrap (`bwrap`) Command Builder & Preflight Verifier (`INV-D16-2`)
;; =============================================================================

(defn build-bwrap-command
  "Constructs the exact `bwrap` command-line vector isolating a node (`INV-D16-2`, `A-CARB-D16-1`):
   - Mounts host `/` read-only (`--ro-bind / /`)
   - Unshares PID, IPC, and UTS namespaces and binds `--die-with-parent`
   - Masks `/tmp`, `/run/systemd/resolve`, `~/.cache`, `~/.ssh`, and repo `.ssh` with fresh `--tmpfs`
   - Masks `<nodes-root-dir>` with `--tmpfs` and binds only this node's directory
   - Binds per-node `.gemini/antigravity-cli` state directory while read-only binding host OAuth token
   - Read-only binds per-node `/etc/resolv.conf`, `/etc/nsswitch.conf`, and `/etc/hosts`"
  [exp-ctx node-ctx inner-cmd-vec]
  (let [user-home (System/getProperty "user.home" "/home/simonpure")
        repo-ssh "/home/simonpure/src/alpeware/bitecho/.ssh"
        host-oauth (io/file user-home ".gemini/antigravity-cli/antigravity-oauth-token")
        nodes-root (:nodes-root-dir exp-ctx)
        node-dir (:node-dir node-ctx)
        workspace-dir (:workspace-dir node-ctx)
        state-dir (or (:state-dir node-ctx) (str workspace-dir "/data"))
        bootstrap (or (:bootstrap exp-ctx) "https://bitecho.org/devnet/bootstrap.txt")
        gemini-dir (:gemini-dir node-ctx)
        resolv-conf (:resolv-conf-path node-ctx)
        nsswitch-conf (:nsswitch-conf-path node-ctx)
        hosts-path (:hosts-path node-ctx)
        base-args ["bwrap"
                   "--ro-bind" "/" "/"
                   "--dev" "/dev"
                   "--proc" "/proc"
                   "--unshare-pid"
                   "--unshare-ipc"
                   "--unshare-uts"
                   "--die-with-parent"
                   "--tmpfs" "/tmp"
                   "--tmpfs" "/run"
                   "--dir" "/run/systemd/resolve"
                   "--tmpfs" (str user-home "/.cache")
                   "--tmpfs" (str user-home "/.ssh")
                   "--tmpfs" repo-ssh
                   "--tmpfs" nodes-root
                   "--bind" node-dir node-dir
                   "--bind" gemini-dir (str user-home "/.gemini/antigravity-cli")]
        oauth-args (if (.exists host-oauth)
                     ["--ro-bind" (.getAbsolutePath host-oauth) (.getAbsolutePath host-oauth)]
                     [])
        etc-args ["--ro-bind" resolv-conf "/etc/resolv.conf"
                  "--ro-bind" nsswitch-conf "/etc/nsswitch.conf"
                  "--ro-bind" hosts-path "/etc/hosts"
                  "--setenv" "PATH" (str workspace-dir "/bin:" user-home "/.local/bin:/usr/local/bin:/usr/bin:/bin")
                  "--setenv" "BITECHO_NODE_ID" (name (:node-id node-ctx))
                  "--setenv" "BITECHO_NODE_WORKSPACE" workspace-dir
                  "--setenv" "BITECHO_STATE_DIR" state-dir
                  "--setenv" "BITECHO_BOOTSTRAP" (str bootstrap)
                  "--setenv" "BITECHO_DNS_PORT" (str (get-in node-ctx [:dns-server :port] 0))
                  "--chdir" workspace-dir
                  "--"]]
    (vec (concat base-args oauth-args etc-args inner-cmd-vec))))

(defn run-command-vec!
  "Executes `cmd-vec` via `ProcessBuilder` with `:timeout-ms` (default 15000ms).
   Returns `{:exit int :out str :err str :timed-out? boolean}`."
  ([cmd-vec]
   (run-command-vec! cmd-vec {}))
  ([cmd-vec {:keys [timeout-ms dir] :or {timeout-ms 15000}}]
   (let [pb (ProcessBuilder. ^java.util.List (mapv str cmd-vec))]
     (when dir
       (.directory pb (io/file dir)))
     (let [proc (.start pb)
           out-fut (future (slurp (.getInputStream proc)))
           err-fut (future (slurp (.getErrorStream proc)))
           finished? (.waitFor proc (long timeout-ms) TimeUnit/MILLISECONDS)]
       (if finished?
         {:exit (.exitValue proc)
          :out @out-fut
          :err @err-fut
          :timed-out? false}
         (do
           (.destroyForcibly proc)
           {:exit -1
            :out (deref out-fut 200 "")
            :err (deref err-fut 200 "Process timed out")
            :timed-out? true}))))))

(defn- sample-allowed-domain
  [allow-list]
  (let [first-pat (or (first allow-list) "bitecho.org")
        norm (normalize-domain first-pat)]
    (if (str/starts-with? norm "*.")
      (str "probe" (subs norm 1))
      norm)))

(defn verify-sandbox-isolation!
  "Runs preflight isolation checks inside `bwrap` and against the per-node DNS allowlist
   proxy (`INV-D16-2`, `INV-D16-3`).
   Verifies:
   1. Read-only root filesystem (`touch /usr/d16_ro_probe` fails).
   2. Secret directories (`~/.ssh` and repo `.ssh`) are empty inside `bwrap`.
   3. Sibling directories under `<nodes-root-dir>` are invisible inside `bwrap`.
   4. Node workspace is writable (`touch <workspace>/.d16_rw_probe` succeeds).
   5. OS-level `getent hosts` inside `bwrap` resolves allowed domains and blocks non-allowlisted domains.
   6. Allowed domain resolves with `:noerror` and non-allowlisted domain returns `:refused` (`RCODE=5`) via the node's UDP DNS allowlist server."
  [exp-ctx node-ctx]
  (let [nodes-root (:nodes-root-dir exp-ctx)
        workspace-dir (:workspace-dir node-ctx)
        allowed-qname (sample-allowed-domain (:dns-allow-list node-ctx))
        blocked-qname "unauthorized-probe.forbidden.invalid"
        probe-script (str
                      "set -u\n"
                      "RO_OK=0\n"
                      "if ! touch /usr/d16_ro_probe 2>/dev/null; then RO_OK=1; fi\n"
                      "SSH_COUNT=$(( $(ls -A /home/simonpure/src/alpeware/bitecho/.ssh 2>/dev/null | wc -l) + $(ls -A /home/simonpure/.ssh 2>/dev/null | wc -l) ))\n"
                      "SIB_COUNT=$(ls -1 " nodes-root " 2>/dev/null | wc -l)\n"
                      "RW_OK=0\n"
                      "if touch " workspace-dir "/.d16_rw_probe 2>/dev/null; then rm -f " workspace-dir "/.d16_rw_probe; RW_OK=1; fi\n"
                      "GETENT_ALLOW=0\n"
                      "if getent hosts " allowed-qname " >/dev/null 2>&1; then GETENT_ALLOW=1; fi\n"
                      "GETENT_BLOCK=0\n"
                      "if ! getent hosts " blocked-qname " >/dev/null 2>&1; then GETENT_BLOCK=1; fi\n"
                      "echo \"RO_OK=$RO_OK SSH_COUNT=$SSH_COUNT SIB_COUNT=$SIB_COUNT RW_OK=$RW_OK GETENT_ALLOW=$GETENT_ALLOW GETENT_BLOCK=$GETENT_BLOCK\"\n")
        cmd (build-bwrap-command exp-ctx node-ctx ["bash" "-c" probe-script])
        res (run-command-vec! cmd {:timeout-ms 10000})
        out (str (:out res))
        ro-root-enforced? (str/includes? out "RO_OK=1")
        ssh-masked? (str/includes? out "SSH_COUNT=0")
        sibling-masked? (str/includes? out "SIB_COUNT=1")
        workspace-writable? (str/includes? out "RW_OK=1")
        getent-allow? (str/includes? out "GETENT_ALLOW=1")
        getent-block? (str/includes? out "GETENT_BLOCK=1")
        dns-srv (:dns-server node-ctx)
        [udp-allowed-resolved? udp-blocked-refused?]
        (if (and dns-srv (pos? (int (:port dns-srv))))
          (with-open [sock (DatagramSocket.)]
            (.setSoTimeout sock 2000)
            (let [port (int (:port dns-srv))
                  loopback (InetAddress/getByName "127.0.0.1")
                  q1 (dns/encode-packet
                      {:id 501 :qr? false :rd? true
                       :questions [{:qname allowed-qname :qtype :A :qclass :IN}]})
                  _ (.send sock (DatagramPacket. q1 (alength q1) loopback port))
                  rx1 (DatagramPacket. (byte-array 512) 512)
                  _ (.receive sock rx1)
                  d1 (dns/decode-packet (Arrays/copyOf (.getData rx1) (.getLength rx1)))
                  q2 (dns/encode-packet
                      {:id 502 :qr? false :rd? true
                       :questions [{:qname blocked-qname :qtype :A :qclass :IN}]})
                  _ (.send sock (DatagramPacket. q2 (alength q2) loopback port))
                  rx2 (DatagramPacket. (byte-array 512) 512)
                  _ (.receive sock rx2)
                  d2 (dns/decode-packet (Arrays/copyOf (.getData rx2) (.getLength rx2)))]
              [(= :noerror (:rcode d1))
               (= :refused (:rcode d2))]))
          [false false])
        allowed-dns-resolved? (and getent-allow? udp-allowed-resolved?)
        blocked-dns-refused? (and getent-block? udp-blocked-refused?)
        ok? (and (zero? (:exit res))
                 ro-root-enforced?
                 ssh-masked?
                 sibling-masked?
                 workspace-writable?
                 allowed-dns-resolved?
                 blocked-dns-refused?)]
    {:ok? ok?
     :ro-root-enforced? ro-root-enforced?
     :ssh-masked? ssh-masked?
     :sibling-masked? sibling-masked?
     :workspace-writable? workspace-writable?
     :allowed-dns-resolved? allowed-dns-resolved?
     :blocked-dns-refused? blocked-dns-refused?
     :raw-output (str/trim out)
     :exit (:exit res)
     :err (:err res)}))
