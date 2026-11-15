(ns bitecho.experiments.runner
  "Multi-agent headless `agy` experiment provisioner, long-lived `stream-json`
   session manager, turn scheduler, ledger/halt reconciler, and Markdown/EDN
   report generator (`INV-D16-1`..`INV-D16-5`, `INV-D17-1`..`INV-D17-3`)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.experiments.node-tool :as node-tool]
            [bitecho.experiments.sandbox :as sandbox]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint]
            [clojure.string :as str])
  (:import [java.io BufferedReader BufferedWriter InputStreamReader OutputStreamWriter]
           [java.nio.charset StandardCharsets]
           [java.util.concurrent LinkedBlockingQueue TimeUnit]))

;; =============================================================================
;; 1. Experiment Directory & Per-Node Sandbox Provisioning
;; =============================================================================

(defn- write-json-map!
  [file-path m]
  (let [entries (map (fn [[k v]]
                       (let [k-str (if (keyword? k) (name k) (str k))
                             v-str (cond
                                     (nil? v) "null"
                                     (boolean? v) (if v "true" "false")
                                     (number? v) (str v)
                                     (keyword? v) (str "\"" (name v) "\"")
                                     (sequential? v) (str "["
                                                          (str/join ", "
                                                                    (map #(str "\"" % "\"") v))
                                                          "]")
                                     :else (pr-str (str v)))]
                         (str "  \"" k-str "\": " v-str)))
                     m)]
    (spit file-path (str "{\n" (str/join ",\n" entries) "\n}\n"))))

(defn- write-node-initial-state!
  [workspace-dir node-id-kw address balance min-echo-balance]
  (let [nid-str (name node-id-kw)
        halted? (< (long balance) (long min-echo-balance))
        halt-reason (when halted? "out-of-echos")
        state-json-file (io/file workspace-dir "node-state.json")
        state-edn-file (io/file workspace-dir "node-state.edn")]
    (write-json-map!
     state-json-file
     {"node_id" nid-str
      "address" address
      "balance" (long balance)
      "min_echo_balance" (long min-echo-balance)
      "seq" 0
      "halted" halted?
      "halt_reason" halt-reason
      "subnets" []
      "credited_tx_ids" []
      "summary" ""})
    (spit state-edn-file
          (pr-str {:node-id node-id-kw
                   :address address
                   :balance (long balance)
                   :min-echo-balance (long min-echo-balance)
                   :seq 0
                   :halted? halted?
                   :halt-reason (when halted? :out-of-echos)
                   :subnets #{}
                   :summary ""}))))

(defn- expand-allowlist-hosts
  "Expands `allow-list` into concrete hostnames for `/etc/hosts` inside `bwrap`
   so glibc (`hosts: files`) resolves only allowlisted domains (`A-D17-3`, `A-CARB-D17-1`)."
  [allow-list]
  (let [base (mapcat (fn [pat]
                       (let [norm (sandbox/normalize-domain pat)]
                         (cond
                           (= norm "*.googleapis.com")
                           ["daily-cloudcode-pa.googleapis.com"
                            "oauth2.googleapis.com"
                            "www.googleapis.com"
                            "probe.googleapis.com"]

                           (= norm "*.bitecho.org")
                           ["ns1.bitecho.org"
                            "ns2.bitecho.org"
                            "ns3.bitecho.org"
                            "node1.bitecho.org"
                            "node2.bitecho.org"
                            "node3.bitecho.org"
                            "probe.bitecho.org"]

                           (= norm "*.wikipedia.org")
                           ["en.wikipedia.org"
                            "www.wikipedia.org"
                            "wikipedia.org"
                            "upload.wikimedia.org"
                            "probe.wikipedia.org"]

                           (str/starts-with? norm "*.")
                           [(str "probe" (subs norm 1))]

                           :else
                           [norm])))
                     allow-list)]
    (distinct base)))

(defn provision-experiment!
  "Validates `exp-cfg`, provisions isolated node directories, starts per-node
   local UDP DNS allowlist servers, writes per-node `/etc/{resolv.conf,nsswitch.conf,hosts}`,
   and installs `bin/bitecho-node`, `AGENTS.md`, `SCENARIO.md`, and `SKILL.md`."
  [exp-cfg]
  (let [validation (sandbox/validate-experiment-config exp-cfg)]
    (when-not (:ok? validation)
      (throw (ex-info "Invalid experiment configuration" validation)))
    (let [exp-id (str (:experiment-id exp-cfg))
          base-dir (or (:base-dir exp-cfg) "/var/tmp/bitecho-experiments")
          exp-dir (.getAbsolutePath (io/file base-dir exp-id))
          nodes-root (.getAbsolutePath (io/file exp-dir "nodes"))
          shared-bus (.getAbsolutePath (io/file exp-dir "shared-bus"))
          min-echo-balance (long (or (:min-echo-balance exp-cfg) 100))
          max-turns (long (or (:max-turns exp-cfg) 6))
          effective-balances (:effective-balances validation)
          node-order (mapv :node-id (:nodes exp-cfg))
          default-dns-records (merge {"bitecho.org" "35.212.172.159"
                                      "*.bitecho.org" "35.209.253.119"}
                                     (:dns-records exp-cfg))]
      (.mkdirs (io/file nodes-root))
      (.mkdirs (io/file shared-bus "inboxes"))
      (.mkdirs (io/file shared-bus "subnets"))
      ;; Reset shared-bus and telemetry files on fresh provision so re-runs are clean
      (doseq [^java.io.File f (concat (file-seq (io/file shared-bus "inboxes"))
                                      (file-seq (io/file shared-bus "subnets"))
                                      [(io/file shared-bus "events.jsonl")
                                       (io/file shared-bus "capabilities.jsonl")
                                       (io/file exp-dir "agy-events.jsonl")])]
        (when (and (.exists f) (.isFile f))
          (.delete f)))
      (let [raw-nodes
            (mapv (fn [ncfg]
                    (let [nid (:node-id ncfg)
                          nid-str (name nid)
                          kp (crypto/generate-keypair (str exp-id "-" nid-str))
                          pub-hex (basalt/bytes->hex (:public kp))
                          address (str "ech1" (subs pub-hex (max 0 (- (count pub-hex) 32))))
                          node-dir (.getAbsolutePath (io/file nodes-root nid-str))
                          workspace-dir (.getAbsolutePath (io/file node-dir "workspace"))
                          gemini-dir (.getAbsolutePath (io/file node-dir "gemini"))
                          etc-dir (.getAbsolutePath (io/file node-dir "etc"))
                          resolv-conf (.getAbsolutePath (io/file etc-dir "resolv.conf"))
                          nsswitch-conf (.getAbsolutePath (io/file etc-dir "nsswitch.conf"))
                          hosts-path (.getAbsolutePath (io/file etc-dir "hosts"))
                          dns-srv (sandbox/start-dns-allowlist-server!
                                   (:dns-allow-list ncfg)
                                   default-dns-records)
                          eff-bal (long (get effective-balances nid 0))
                          expanded-hosts (expand-allowlist-hosts (:dns-allow-list ncfg))
                          host-lines (map (fn [h]
                                            (str (sandbox/resolve-domain-ip h default-dns-records)
                                                 " " h))
                                          expanded-hosts)]
                      (.mkdirs (io/file workspace-dir "bin"))
                      (.mkdirs (io/file gemini-dir))
                      (.mkdirs (io/file etc-dir))
                      (doseq [^java.io.File lf [(io/file node-dir "agy-stream.jsonl")
                                                (io/file node-dir "agy-stderr.log")]]
                        (when (.exists lf) (.delete lf)))
                      (spit resolv-conf
                            (str "# Generated by Bitecho D16/D17 Sandbox for :" nid-str "\n"
                                 "nameserver 0.0.0.0\n"
                                 "options ndots:1 timeout:1 attempts:1\n"))
                      (spit nsswitch-conf
                            "hosts: files\nnetworks: files\n")
                      (spit hosts-path
                            (str "127.0.0.1 localhost\n"
                                 "::1 localhost\n"
                                 (str/join "\n" host-lines)
                                 "\n"))
                      (write-node-initial-state! workspace-dir nid address eff-bal min-echo-balance)
                      (assoc ncfg
                             :address address
                             :pubkey-hex pub-hex
                             :effective-balance eff-bal
                             :node-dir node-dir
                             :workspace-dir workspace-dir
                             :gemini-dir gemini-dir
                             :etc-dir etc-dir
                             :resolv-conf-path resolv-conf
                             :nsswitch-conf-path nsswitch-conf
                             :hosts-path hosts-path
                             :dns-server dns-srv
                             :agy-session-atom (atom nil))))
                  (:nodes exp-cfg))
            siblings-map (into {}
                               (map (fn [n]
                                      [(:node-id n)
                                       {:node-id (:node-id n)
                                        :address (:address n)
                                        :parent-id (:parent-id n)}])
                                    raw-nodes))]
        (doseq [n raw-nodes]
          (spit (io/file (:workspace-dir n) "siblings.edn") (pr-str siblings-map))
          (write-json-map!
           (io/file (:workspace-dir n) "siblings.json")
           (into {} (map (fn [[k v]] [(name k) (:address v)]) siblings-map)))
          (node-tool/write-node-cli-and-skill-files! n siblings-map min-echo-balance))
        {:experiment-id exp-id
         :experiment-dir exp-dir
         :nodes-root-dir nodes-root
         :shared-bus-dir shared-bus
         :min-echo-balance min-echo-balance
         :max-turns max-turns
         :initial-supply (:initial-supply validation)
         :effective-balances effective-balances
         :node-order node-order
         :nodes (into {} (map (juxt :node-id identity) raw-nodes))}))))

(defn exec-in-node-sandbox!
  "Executes `inner-cmd-vec` inside the node's `bwrap` sandbox and returns
   `{:exit int :out str :err str :timed-out? boolean}`."
  ([exp-ctx node-ctx inner-cmd-vec]
   (exec-in-node-sandbox! exp-ctx node-ctx inner-cmd-vec {:timeout-ms 15000}))
  ([exp-ctx node-ctx inner-cmd-vec opts]
   (let [bwrap-cmd (sandbox/build-bwrap-command exp-ctx node-ctx inner-cmd-vec)]
     (sandbox/run-command-vec! bwrap-cmd opts))))

(defn read-node-local-state
  "Reads `<node-workspace>/node-state.edn` and returns the parsed Clojure map."
  [node-ctx]
  (let [f (io/file (:workspace-dir node-ctx) "node-state.edn")]
    (when (.exists f)
      (edn/read-string (slurp f)))))

;; =============================================================================
;; 2. Long-Lived `stream-json` `agy` Session Lifecycle (`INV-D17-2`, `INV-D17-3`)
;; =============================================================================

(def ^:private agy-log-lock (Object.))

(defn- append-line-safe!
  [^java.io.File f ^String line]
  (locking agy-log-lock
    (spit f (str line "\n") :append true)))

(defn stop-node-agy-session!
  "Cleanly closes stdin and terminates a node's long-lived `agy` process (`INV-D17-2`)."
  [node-ctx]
  (when-let [sess-atom (:agy-session-atom node-ctx)]
    (when-let [sess @sess-atom]
      (reset! sess-atom nil)
      (try
        (when-let [^BufferedWriter w (:stdin-writer sess)]
          (.close w))
        (catch Exception _ nil))
      (try
        (when-let [^Process p (:process sess)]
          (when (.isAlive p)
            (.destroy p)
            (when-not (.waitFor p 1500 TimeUnit/MILLISECONDS)
              (.destroyForcibly p))))
        (catch Exception _ nil)))))

(defn shutdown-experiment!
  "Stops all per-node long-lived `agy` sessions and UDP DNS allowlist servers in `exp-ctx`."
  [exp-ctx]
  (doseq [[_ node-ctx] (:nodes exp-ctx)]
    (stop-node-agy-session! node-ctx)
    (when-let [srv (:dns-server node-ctx)]
      (sandbox/stop-dns-allowlist-server! srv))))

(defn start-node-agy-session!
  "Starts (or returns the already-alive) long-lived `agy --input-format stream-json
   --output-format stream-json` process inside the node's `bwrap` sandbox (`INV-D17-2`,
   `A-D17-1`, `A-CARB-D17-2`, `A-CARB-D17-5`)."
  [exp-ctx node-ctx]
  (let [sess-atom (:agy-session-atom node-ctx)
        existing @sess-atom]
    (if (and existing (.isAlive ^Process (:process existing)))
      existing
      (let [nid-str (name (:node-id node-ctx))
            inner-cmd ["agy"
                       "--input-format" "stream-json"
                       "--output-format" "stream-json"
                       "--model" (:model-type node-ctx)
                       "--dangerously-skip-permissions"]
            bwrap-cmd (sandbox/build-bwrap-command exp-ctx node-ctx inner-cmd)
            pb (ProcessBuilder. ^java.util.List (mapv str bwrap-cmd))
            stderr-file (io/file (:node-dir node-ctx) "agy-stderr.log")
            node-stream-file (io/file (:node-dir node-ctx) "agy-stream.jsonl")
            exp-stream-file (io/file (:experiment-dir exp-ctx) "agy-events.jsonl")
            _ (.directory pb (io/file (:workspace-dir node-ctx)))
            _ (.redirectError pb (java.lang.ProcessBuilder$Redirect/appendTo stderr-file))
            proc (.start pb)
            stdin-writer (BufferedWriter.
                          (OutputStreamWriter. (.getOutputStream proc) StandardCharsets/UTF_8))
            stdout-reader (BufferedReader.
                           (InputStreamReader. (.getInputStream proc) StandardCharsets/UTF_8))
            queue (LinkedBlockingQueue.)
            reader-thread (Thread.
                           (fn []
                             (try
                               (loop []
                                 (when-let [line (.readLine stdout-reader)]
                                   (let [trimmed (str/trim line)]
                                     (when-not (str/blank? trimmed)
                                       (append-line-safe! node-stream-file trimmed)
                                       (append-line-safe!
                                        exp-stream-file
                                        (str "{\"node_id\":\"" nid-str "\",\"event\":" trimmed "}"))
                                       (.put queue {:type :line :line trimmed})))
                                   (recur)))
                               (catch Exception _ nil)
                               (finally
                                 (.put queue {:type :eof}))))
                           (str "bitecho-agy-stream-" nid-str))]
        (.setDaemon reader-thread true)
        (.start reader-thread)
        (let [sess {:process proc
                    :stdin-writer stdin-writer
                    :stdout-reader stdout-reader
                    :queue queue
                    :reader-thread reader-thread}]
          (reset! sess-atom sess)
          sess)))))

(defn- build-turn-prompt
  [exp-ctx node-ctx turn-idx st-before]
  (if (zero? (long turn-idx))
    (:initial-prompt node-ctx)
    (let [nid-str (name (:node-id node-ctx))
          inbox-file (io/file (:shared-bus-dir exp-ctx) "inboxes" (str nid-str ".jsonl"))
          caps-file (io/file (:shared-bus-dir exp-ctx) "capabilities.jsonl")
          inbox-str (if (.exists inbox-file) (str/trim (slurp inbox-file)) "none")
          caps-str (if (.exists caps-file) (str/trim (slurp caps-file)) "none")
          followup (or (:followup-prompt node-ctx)
                       "Complete any remaining orders/deliveries or run `bitecho-node halt accomplished-goal \"...\"` if finished.")]
      (str "Turn " (inc turn-idx) " Situational Update for :" nid-str "\n"
           "- Current Node State: " (pr-str st-before) "\n"
           "- Recent Inbox Messages (`p2p-inbox`): " (if (str/blank? inbox-str) "none" inbox-str) "\n"
           "- Advertised Marketplace Capabilities (`capability-list`): " (if (str/blank? caps-str) "none" caps-str) "\n\n"
           "Instructions for this turn:\n"
           followup))))

(defn run-node-agy-turn!
  "Sends one NDJSON user turn to the node's long-lived `stream-json` `agy` process
   and waits until its `{\"event\":\"result\",...}` frame is emitted (`INV-D17-2`, `INV-D17-3`)."
  [exp-ctx node-ctx turn-idx]
  ;; Sync incoming transfers or capability-order payments before reading state (`A-D17-2`)
  (exec-in-node-sandbox! exp-ctx node-ctx ["bitecho-node" "status"] {:timeout-ms 5000})
  (let [st-before (read-node-local-state node-ctx)]
    (if (:halted? st-before)
      (do
        (stop-node-agy-session! node-ctx)
        {:node-id (:node-id node-ctx)
         :turn turn-idx
         :skipped? true
         :halt-reason (:halt-reason st-before)})
      (let [prompt (build-turn-prompt exp-ctx node-ctx turn-idx st-before)
            sess (start-node-agy-session! exp-ctx node-ctx)
            ^BufferedWriter writer (:stdin-writer sess)
            ^LinkedBlockingQueue queue (:queue sess)
            ndjson-msg (str "{\"event\":\"user\",\"message\":{\"content\":" (pr-str prompt) "}}\n")
            deadline (+ (System/currentTimeMillis) 120000)]
        (.write writer ndjson-msg)
        (.flush writer)
        (let [turn-res
              (loop [tool-calls 0
                     subagents 0
                     last-result nil]
                (let [remaining (- deadline (System/currentTimeMillis))]
                  (if (<= remaining 0)
                    {:timed-out? true
                     :tool-calls tool-calls
                     :subagents subagents
                     :result-line last-result}
                    (let [item (.poll queue remaining TimeUnit/MILLISECONDS)]
                      (cond
                        (nil? item)
                        {:timed-out? true
                         :tool-calls tool-calls
                         :subagents subagents
                         :result-line last-result}

                        (= :eof (:type item))
                        {:timed-out? false
                         :eof? true
                         :tool-calls tool-calls
                         :subagents subagents
                         :result-line last-result}

                        :else
                        (let [line (str (:line item))
                              is-tool? (str/includes? line "\"step_type\":\"tool\"")
                              is-subagent? (str/includes? line "\"subagent_info\"")
                              is-result? (str/includes? line "\"event\":\"result\"")
                              next-tools (if is-tool? (inc tool-calls) tool-calls)
                              next-subs (if is-subagent? (inc subagents) subagents)]
                          (if is-result?
                            {:timed-out? false
                             :eof? false
                             :tool-calls next-tools
                             :subagents next-subs
                             :result-line line}
                            (recur next-tools next-subs line))))))))
              ;; Sync state after turn completes
              _ (exec-in-node-sandbox! exp-ctx node-ctx ["bitecho-node" "status"] {:timeout-ms 5000})
              st-after (read-node-local-state node-ctx)]
          (when (or (:halted? st-after) (:timed-out? turn-res) (:eof? turn-res))
            (stop-node-agy-session! node-ctx))
          {:node-id (:node-id node-ctx)
           :turn turn-idx
           :timed-out? (:timed-out? turn-res)
           :tool-calls (:tool-calls turn-res)
           :subagents (:subagents turn-res)
           :state-after st-after
           :out-snippet (let [s (str (:result-line turn-res ""))]
                          (subs s 0 (min 500 (count s))))})))))

(defn render-experiment-report-md
  "Renders a human-readable Markdown summary report (`report.md`) for an experiment."
  [exp-ctx final-states turn-history]
  (let [order (or (seq (:node-order exp-ctx)) (sort (keys (:nodes exp-ctx))))
        rows (map (fn [nid]
                    (let [nctx (get-in exp-ctx [:nodes nid])
                          st (get final-states nid)]
                      (str "| `:" (name nid) "` | `" (:model-type nctx) "` | `"
                           (:parent-id nctx) "` | `" (:effective-balance nctx) "` | `"
                           (:balance st) "` | `" (boolean (:halted? st)) "` | `"
                           (or (:halt-reason st) ":active") "` | "
                           (or (:summary st) "") " |")))
                  order)]
    (str
     "# Bitecho Multi-Agent Sandbox Experiment Report: `" (:experiment-id exp-ctx) "`\n\n"
     "- **Initial Supply:** `" (:initial-supply exp-ctx) " ECH`\n"
     "- **Minimum Operating Balance:** `" (:min-echo-balance exp-ctx) " ECH`\n"
     "- **Max Turns:** `" (:max-turns exp-ctx) "`\n"
     "- **Total Turns Executed:** `" (count turn-history) "`\n\n"
     "## Node Outcomes\n\n"
     "| Node | Model | Parent | Initial ECH | Final ECH | Halted? | Halt Reason | Summary |\n"
     "|---|---|---|---|---|---|---|---|\n"
     (str/join "\n" rows)
     "\n")))

(defn run-experiment!
  "Provisions and executes a full multi-agent sandbox experiment (either in `:dry-run?`
   preflight mode or live long-lived `stream-json` `agy` mode), writing `experiment.jsonl`,
   `agy-events.jsonl`, `summary.edn`, and `report.md`."
  [config-or-path & [{:keys [dry-run?] :or {dry-run? false}}]]
  (let [exp-cfg (if (string? config-or-path)
                  (edn/read-string (slurp config-or-path))
                  config-or-path)
        exp-ctx (provision-experiment! exp-cfg)]
    (try
      ;; 1. Verify sandbox & DNS isolation preflight for every node (`INV-D16-2`, `INV-D16-3`)
      (doseq [nid (:node-order exp-ctx)]
        (let [nctx (get-in exp-ctx [:nodes nid])
              iso (sandbox/verify-sandbox-isolation! exp-ctx nctx)]
          (when-not (:ok? iso)
            (throw (ex-info (str "Sandbox isolation preflight failed for " nid) iso)))))
      ;; 2. Run multi-turn loop in deterministic `:node-order` unless dry-run? (`A-D17-4`)
      (let [max-turns (:max-turns exp-ctx)
            turn-history (atom [])]
        (when-not dry-run?
          (loop [turn 0]
            (let [states (into {}
                               (map (fn [nid]
                                      (let [nctx (get-in exp-ctx [:nodes nid])]
                                        [nid (read-node-local-state nctx)]))
                                    (:node-order exp-ctx)))
                  all-halted? (every? :halted? (vals states))]
              (when (and (< turn max-turns) (not all-halted?))
                (doseq [nid (:node-order exp-ctx)]
                  (let [nctx (get-in exp-ctx [:nodes nid])
                        tr (run-node-agy-turn! exp-ctx nctx turn)]
                    (swap! turn-history conj tr)))
                (recur (inc turn))))))
        ;; 3. Mark any still-running node at max-turns with :max-turns-exceeded if not dry-run?
        (when-not dry-run?
          (doseq [nid (:node-order exp-ctx)]
            (let [nctx (get-in exp-ctx [:nodes nid])
                  st (read-node-local-state nctx)]
              (when-not (:halted? st)
                (exec-in-node-sandbox!
                 exp-ctx nctx
                 ["bitecho-node" "halt" "max-turns-exceeded" "Reached max-turns limit"])))))
        (let [final-states (into {}
                                 (map (fn [nid]
                                        (let [nctx (get-in exp-ctx [:nodes nid])]
                                          (exec-in-node-sandbox! exp-ctx nctx ["bitecho-node" "status"])
                                          [nid (read-node-local-state nctx)]))
                                      (:node-order exp-ctx)))
              bus-events-file (io/file (:shared-bus-dir exp-ctx) "events.jsonl")
              exp-jsonl-file (io/file (:experiment-dir exp-ctx) "experiment.jsonl")
              events-content (if (.exists bus-events-file)
                               (slurp bus-events-file)
                               "")
              summary {:experiment-id (:experiment-id exp-ctx)
                       :experiment-dir (:experiment-dir exp-ctx)
                       :initial-supply (:initial-supply exp-ctx)
                       :final-states final-states
                       :turns @turn-history}
              report-md (render-experiment-report-md exp-ctx final-states @turn-history)]
          (spit exp-jsonl-file events-content)
          (spit (io/file (:experiment-dir exp-ctx) "summary.edn")
                (with-out-str (pprint/pprint summary)))
          (spit (io/file (:experiment-dir exp-ctx) "report.md") report-md)
          summary))
      (finally
        (shutdown-experiment! exp-ctx)))))

(defn -main
  "CLI entrypoint:
   `clojure -M:simulate -m bitecho.experiments.runner dev/experiments/homebrew_cafe_civilization.edn [--dry-run]`"
  [& args]
  (let [cfg-path (or (first args) "dev/experiments/homebrew_cafe_civilization.edn")
        dry-run? (boolean (some #{"--dry-run"} args))
        res (run-experiment! cfg-path {:dry-run? dry-run?})]
    (println (str "Experiment completed: " (:experiment-id res)
                  " -> " (:experiment-dir res) "/report.md"))
    (flush)
    (shutdown-agents)))
