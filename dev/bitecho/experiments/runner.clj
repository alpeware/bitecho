(ns bitecho.experiments.runner
  "Multi-agent headless `agy` experiment provisioner, turn scheduler, ledger/halt
   reconciler, and Markdown/EDN report generator (`INV-D16-1`..`INV-D16-5`)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.experiments.node-tool :as node-tool]
            [bitecho.experiments.sandbox :as sandbox]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint]
            [clojure.string :as str]))

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
   so glibc (`hosts: files`) resolves only allowlisted domains."
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

                           (str/starts-with? norm "*.")
                           [(str "probe" (subs norm 1))]

                           :else
                           [norm])))
                     allow-list)]
    (distinct base)))

(defn provision-experiment!
  "Validates `exp-cfg`, provisions isolated node directories, starts per-node
   local UDP DNS allowlist servers, writes per-node `/etc/{resolv.conf,nsswitch.conf,hosts}`,
   and installs `bin/bitecho-node`, `AGENTS.md`, and `SKILL.md`."
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
          default-dns-records (merge {"bitecho.org" "35.212.172.159"
                                      "*.bitecho.org" "35.209.253.119"}
                                     (:dns-records exp-cfg))]
      (.mkdirs (io/file nodes-root))
      (.mkdirs (io/file shared-bus "inboxes"))
      (.mkdirs (io/file shared-bus "subnets"))
      ;; Reset shared-bus files on fresh provision so re-runs are clean
      (doseq [^java.io.File f (concat (file-seq (io/file shared-bus "inboxes"))
                                      (file-seq (io/file shared-bus "subnets"))
                                      [(io/file shared-bus "events.jsonl")])]
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
                      (spit resolv-conf
                            (str "# Generated by Bitecho D16 Sandbox for :" nid-str "\n"
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
                             :dns-server dns-srv)))
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
         :nodes (into {} (map (juxt :node-id identity) raw-nodes))}))))

(defn shutdown-experiment!
  "Stops all per-node UDP DNS allowlist servers in `exp-ctx`."
  [exp-ctx]
  (doseq [[_ node-ctx] (:nodes exp-ctx)]
    (when-let [srv (:dns-server node-ctx)]
      (sandbox/stop-dns-allowlist-server! srv))))

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
;; 2. Headless `agy` Turn Scheduler & Markdown Report Generator
;; =============================================================================

(defn run-node-agy-turn!
  "Invokes one turn of `agy -p <prompt> --model <model-type> --dangerously-skip-permissions`
   inside the node's `bwrap` sandbox."
  [exp-ctx node-ctx turn-idx]
  (let [st-before (read-node-local-state node-ctx)]
    (if (:halted? st-before)
      {:node-id (:node-id node-ctx)
       :turn turn-idx
       :skipped? true
       :halt-reason (:halt-reason st-before)}
      (let [prompt (if (zero? (long turn-idx))
                     (:initial-prompt node-ctx)
                     (str "Turn " (inc turn-idx) ": Check `bitecho-node status` and `bitecho-node p2p-inbox`. "
                          "Complete any remaining subnet/P2P/transfer actions, or run `bitecho-node halt accomplished-goal \"...\"` if finished."))
            cmd ["agy"
                 "-p" prompt
                 "--model" (:model-type node-ctx)
                 "--dangerously-skip-permissions"]
            res (exec-in-node-sandbox! exp-ctx node-ctx cmd {:timeout-ms 90000})
            ;; Sync inbox transfers via status
            _ (exec-in-node-sandbox! exp-ctx node-ctx ["bitecho-node" "status"] {:timeout-ms 5000})
            st-after (read-node-local-state node-ctx)]
        {:node-id (:node-id node-ctx)
         :turn turn-idx
         :exit (:exit res)
         :timed-out? (:timed-out? res)
         :state-after st-after
         :out-snippet (subs (str (:out res)) 0 (min 400 (count (str (:out res)))))}))))

(defn render-experiment-report-md
  "Renders a human-readable Markdown summary report (`report.md`) for an experiment."
  [exp-ctx final-states turn-history]
  (let [rows (map (fn [[nid nctx]]
                    (let [st (get final-states nid)]
                      (str "| `:" (name nid) "` | `" (:model-type nctx) "` | `"
                           (:parent-id nctx) "` | `" (:effective-balance nctx) "` | `"
                           (:balance st) "` | `" (boolean (:halted? st)) "` | `"
                           (or (:halt-reason st) ":active") "` | "
                           (or (:summary st) "") " |")))
                  (sort-by first (:nodes exp-ctx)))]
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
   preflight mode or live headless `agy` mode), writing `experiment.jsonl`, `summary.edn`,
   and `report.md`."
  [config-or-path & [{:keys [dry-run?] :or {dry-run? false}}]]
  (let [exp-cfg (if (string? config-or-path)
                  (edn/read-string (slurp config-or-path))
                  config-or-path)
        exp-ctx (provision-experiment! exp-cfg)]
    (try
      ;; 1. Verify sandbox & DNS isolation preflight for every node (`INV-D16-2`, `INV-D16-3`)
      (doseq [[nid nctx] (:nodes exp-ctx)]
        (let [iso (sandbox/verify-sandbox-isolation! exp-ctx nctx)]
          (when-not (:ok? iso)
            (throw (ex-info (str "Sandbox isolation preflight failed for " nid) iso)))))
      ;; 2. Run multi-turn loop unless dry-run?
      (let [max-turns (:max-turns exp-ctx)
            turn-history (atom [])]
        (when-not dry-run?
          (loop [turn 0]
            (let [states (into {}
                               (map (fn [[nid nctx]]
                                      [nid (read-node-local-state nctx)])
                                    (:nodes exp-ctx)))
                  all-halted? (every? :halted? (vals states))]
              (when (and (< turn max-turns) (not all-halted?))
                (doseq [[_ nctx] (sort-by first (:nodes exp-ctx))]
                  (let [tr (run-node-agy-turn! exp-ctx nctx turn)]
                    (swap! turn-history conj tr)))
                (recur (inc turn))))))
        ;; 3. Mark any still-running node at max-turns with :max-turns-exceeded if not dry-run?
        (when-not dry-run?
          (doseq [[_ nctx] (:nodes exp-ctx)]
            (let [st (read-node-local-state nctx)]
              (when-not (:halted? st)
                (exec-in-node-sandbox!
                 exp-ctx nctx
                 ["bitecho-node" "halt" "max-turns-exceeded" "Reached max-turns limit"])))))
        (let [final-states (into {}
                                 (map (fn [[nid nctx]]
                                        (exec-in-node-sandbox! exp-ctx nctx ["bitecho-node" "status"])
                                        [nid (read-node-local-state nctx)])
                                      (:nodes exp-ctx)))
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
   `clojure -M:simulate -m bitecho.experiments.runner dev/experiments/sociocratic_subnet_demo.edn [--dry-run]`"
  [& args]
  (let [cfg-path (or (first args) "dev/experiments/sociocratic_subnet_demo.edn")
        dry-run? (boolean (some #{"--dry-run"} args))
        res (run-experiment! cfg-path {:dry-run? dry-run?})]
    (println (str "Experiment completed: " (:experiment-id res)
                  " -> " (:experiment-dir res) "/report.md"))
    (flush)
    (shutdown-agents)))
