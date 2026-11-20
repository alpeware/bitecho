(ns bitecho.browser-cli
  "Pure Sans-IO Browser Light Node Console CLI dispatch, verb parity inventory,
   and parameter normalization core (Rules 1, 2, 5, 6).
   Derives its verb inventory directly from `bitecho.light-node.cli/all-recognized-cli-verbs-set`
   so every Node/JVM light-node CLI verb is available on `window.BitechoLightNode` by construction."
  (:require [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.browser :as browser]
            [clojure.string :as str]))

;; =============================================================================
;; 1. Browser Verb Parity Inventory (Rule 6)
;; =============================================================================

(def browser-unsupported-verb-reasons
  "Explicit map of CLI verbs that are genuinely OS-impossible inside a browser tab
   (local TCP daemon socket, OS process/PID management, stdio pipe JSON-RPC).
   Every other verb in `cli/all-recognized-cli-verbs-set` is supported in-browser."
  {"serve"  "OS daemon mode (local TCP control socket & filesystem --state-dir) is not available in a browser tab; the browser light node runs live in-page."
   "daemon" "OS background process management (PID files / start / stop / restart) is not available in a browser tab."
   "mcp"    "MCP stdio JSON-RPC server requires OS stdin/stdout pipes unavailable in a browser tab."})

(def browser-unsupported-verbs
  "Set of CLI verbs explicitly unsupported in the browser runtime."
  (set (keys browser-unsupported-verb-reasons)))

(defn verb->js-method-name
  "Converts a kebab-case CLI verb (e.g. \"p2p-channel-state\") to its canonical
   camelCase JS method name (e.g. \"p2pChannelState\")."
  [verb]
  (let [s (str/lower-case (str/trim (if (keyword? verb) (name verb) (str verb))))
        parts (str/split s #"-")]
    (if (<= (count parts) 1)
      s
      (apply str
             (first parts)
             (map (fn [p]
                    (if (str/blank? p)
                      ""
                      (str (str/upper-case (subs p 0 1)) (subs p 1))))
                  (rest parts))))))

(defn js-method-name->verb
  "Converts a camelCase JS method name or kebab-case string (e.g. \"p2pChannelState\"
   or \"p2p-channel-state\") back to canonical lowercase kebab-case CLI verb."
  [s]
  (let [raw (str/trim (if (keyword? s) (name s) (str s)))]
    (-> raw
        (str/replace #"([a-z0-9])([A-Z])" "$1-$2")
        (str/replace #"([A-Z]+)([A-Z][a-z])" "$1-$2")
        (str/replace #"_" "-")
        str/lower-case)))

(def browser-cli-verb-inventory
  "Complete deterministic inventory of every recognized Node/JVM CLI verb mapped to its
   browser console JS method name, canonical verb, and browser support status (Rule 6)."
  (into (sorted-map)
        (map (fn [verb]
               (let [unsupported? (contains? browser-unsupported-verbs verb)
                     canonical (or (get-in cli/legacy-verb-desugar-table [verb :canonical])
                                   (get-in cli/runner-alias-desugar-table [verb :canonical])
                                   (when (contains? cli/canonical-cli-verbs-set verb) verb)
                                   verb)]
                 [verb (cond-> {:verb verb
                                :js-method (verb->js-method-name verb)
                                :canonical canonical
                                :support (if unsupported? :unsupported-in-browser :supported)}
                         unsupported?
                         (assoc :reason (get browser-unsupported-verb-reasons verb)))])))
        (sort cli/all-recognized-cli-verbs-set)))

;; =============================================================================
;; 2. Parameter & Invocation Normalization (Rule 2)
;; =============================================================================

(defn normalize-param-key
  "Normalizes camelCase, kebab-case, or snake_case keyword/string parameter keys
   into canonical lowercase snake_case string keys expected by `light-core/handle-command`."
  [k]
  (let [raw (if (keyword? k) (name k) (str k))
        stripped (if (str/starts-with? raw "--") (subs raw 2) raw)]
    (-> stripped
        (str/replace #"([a-z0-9])([A-Z])" "$1_$2")
        (str/replace #"([A-Z]+)([A-Z][a-z])" "$1_$2")
        (str/replace #"-" "_")
        str/lower-case)))

(defn normalize-params-map
  "Normalizes a flat parameter map so all keys are canonical snake_case strings."
  [params]
  (if (map? params)
    (reduce-kv (fn [acc k v]
                 (if (some? v)
                   (assoc acc (normalize-param-key k) v)
                   acc))
               {}
               params)
    {}))

(defn normalize-cli-invocation
  "Normalizes a browser console invocation `(verb-or-cmd params)` into a validated
   command descriptor.
   - Accepts kebab-case or camelCase verb names (e.g. \"p2p-channel-state\" or \"p2pChannelState\").
   - Rejects browser-unsupported OS daemon verbs with explicit `:unsupported-in-browser` + `:diagnose`.
   - Rejects unknown verbs fail-closed with `:invalid-verb` + `:diagnose`.
   - Desugars canonical verbs via `cli/desugar-cli-cmd-map` so all 12 canonical + 68 legacy + aliases work."
  [verb-or-cmd params]
  (let [raw-verb (cond
                   (keyword? verb-or-cmd) (name verb-or-cmd)
                   (string? verb-or-cmd) verb-or-cmd
                   :else "")
        norm-verb (js-method-name->verb raw-verb)]
    (cond
      (str/blank? norm-verb)
      {:ok? false
       :error :invalid-verb
       :verb norm-verb
       :response {"ok" false
                  "error" "invalid-verb"
                  "verb" norm-verb
                  "supported_verbs" cli/supported-cli-verbs}
       :diagnose {:type :diagnose
                  :kind :invalid-verb
                  :verb norm-verb
                  :reason "empty-verb"}}

      (contains? browser-unsupported-verbs norm-verb)
      (let [reason (get browser-unsupported-verb-reasons norm-verb)]
        {:ok? false
         :unsupported? true
         :error :unsupported-in-browser
         :verb norm-verb
         :response {"ok" false
                    "error" "unsupported-in-browser"
                    "verb" norm-verb
                    "reason" reason}
         :diagnose {:type :diagnose
                    :kind :unsupported-in-browser
                    :verb norm-verb
                    :reason reason}})

      (not (contains? cli/all-recognized-cli-verbs-set norm-verb))
      {:ok? false
       :error :invalid-verb
       :verb norm-verb
       :response {"ok" false
                  "error" "invalid-verb"
                  "verb" norm-verb
                  "supported_verbs" cli/supported-cli-verbs}
       :diagnose {:type :diagnose
                  :kind :invalid-verb
                  :verb norm-verb
                  :reason (str "unknown-verb:" norm-verb)}}

      :else
      (let [norm-params (normalize-params-map params)
            base-cmd (assoc norm-params "cmd" norm-verb)
            desugared (cli/desugar-cli-cmd-map base-cmd)]
        {:ok? true
         :verb norm-verb
         :js-method (verb->js-method-name norm-verb)
         :cmd-map desugared}))))

;; =============================================================================
;; 3. Pure Help & Verb Dispatch (Rule 2 & Rule 5)
;; =============================================================================

(defn build-browser-help
  "Builds structured help output for `BitechoLightNode.help([verb])`."
  ([] (build-browser-help nil))
  ([verb]
   (if (and (some? verb) (not (str/blank? (str verb))))
     (let [norm-verb (js-method-name->verb (str verb))
           entry (get browser-cli-verb-inventory norm-verb)]
       (if entry
         {"ok" true
          "help" true
          "verb" (:verb entry)
          "js_method" (:js-method entry)
          "canonical" (:canonical entry)
          "support" (name (:support entry))
          "reason" (:reason entry)
          "example" (str "await BitechoLightNode." (:js-method entry) "({})")}
         {"ok" false
          "error" "invalid-verb"
          "verb" norm-verb
          "supported_verbs" cli/supported-cli-verbs}))
     (let [supported (vec (sort (keep (fn [[v e]] (when (= :supported (:support e)) v))
                                      browser-cli-verb-inventory)))
           unsupported (into {} (map (fn [[v e]] [v (:reason e)])
                                     (filter (fn [[_ e]] (= :unsupported-in-browser (:support e)))
                                             browser-cli-verb-inventory)))
           methods (into {} (map (fn [[v e]] [v (:js-method e)]) browser-cli-verb-inventory))]
       {"ok" true
        "help" true
        "runtime" "browser"
        "usage" ["await BitechoLightNode.status()"
                 "await BitechoLightNode.p2pChannelState({sessionId, connected})"
                 "await BitechoLightNode.exec(\"petname-list\", {})"
                 "await BitechoLightNode.cli(\"inbox --peek\")"
                 "await BitechoLightNode.peers()"
                 "await BitechoLightNode.verbs()"]
        "verbs" cli/supported-cli-verbs
        "canonical_verbs" cli/canonical-cli-verbs
        "browser_supported_verbs" supported
        "browser_unsupported_verbs" unsupported
        "js_methods" methods
        "flags" cli/known-command-flags}))))

(defn dispatch-browser-cli
  "Pure Sans-IO dispatcher for browser light-node CLI invocations.
   Accepts:
   - `state`: browser node state map (containing `:light-state` and optional `:mesh-conns`)
   - `verb-or-cmd`: CLI verb string/keyword (kebab-case or camelCase)
   - `params`: optional map of parameters (camelCase, kebab-case, or snake_case)
   - `privkey-bytes`: signing private key bytes (or nil if hardware-locked)
   Returns `{:ok? bool :verb str :response map :state updated-state :net-envelopes vec :p2p-dial map-or-nil :effects vec}`."
  [state verb-or-cmd params privkey-bytes]
  (let [norm (normalize-cli-invocation verb-or-cmd params)]
    (if-not (:ok? norm)
      {:ok? false
       :error (:error norm)
       :verb (:verb norm)
       :state state
       :response (:response norm)
       :net-envelopes []
       :stdout-events []
       :effects (if (:diagnose norm) [(:diagnose norm)] [])}
      (let [verb (:verb norm)
            cmd-map (:cmd-map norm)]
        (cond
          (= verb "help")
          (let [target-verb (or (get cmd-map "verb") (get cmd-map "topic"))]
            {:ok? true
             :verb "help"
             :state state
             :response (build-browser-help target-verb)
             :net-envelopes []
             :stdout-events []
             :effects []})

          :else
          (let [target-state (if (map? (:light-state state)) (:light-state state) state)
                res (light-core/handle-command target-state cmd-map privkey-bytes)
                raw-resp (:response res)
                mesh-diag (when (map? (:mesh-conns state))
                            (browser/summarize-mesh-diagnostics (:mesh-conns state)))
                enriched-resp (if (and (= (get cmd-map "cmd") "status") mesh-diag)
                                (assoc raw-resp
                                       "mesh_diagnostics" mesh-diag
                                       "connected_nodes" (:open-peers mesh-diag)
                                       "closed_nodes" (:closed-peers mesh-diag)
                                       "degraded" (:degraded? mesh-diag))
                                raw-resp)
                updated-state (if (map? (:light-state state))
                                (-> state
                                    (assoc :light-state (:state res))
                                    (assoc :sessions (:sessions (:state res))))
                                (:state res))]
            {:ok? (boolean (get enriched-resp "ok" true))
             :verb verb
             :state updated-state
             :response enriched-resp
             :net-envelopes (vec (or (:net-envelopes res) []))
             :p2p-dial (:p2p-dial res)
             :stdout-events (vec (or (:stdout-events res) []))
             :effects []}))))))
