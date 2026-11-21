(ns bitecho.browser-cli
  "Pure Sans-IO Browser Light Node Console CLI dispatch, verb parity inventory,
   and parameter normalization core (Rules 1, 2, 5, 6).
   Derives its verb inventory directly from `bitecho.light-node.cli/all-recognized-cli-verbs-set`
   so every Node/JVM light-node CLI verb is available on `window.BitechoLightNode` by construction."
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.browser :as browser]
            [clojure.string :as str]))

(def api-version
  "Headless Browser Light Node API contract version (D40.4)."
  "1.0.0")

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
                                   (get-in cli/memento-verb-desugar-table [verb :canonical])
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
        "api_version" api-version
        "usage" ["await BitechoLightNode.getStatus()"
                 "BitechoLightNode.onEvent(fn)"
                 "await BitechoLightNode.listPetnames()"
                 "await BitechoLightNode.setPetname(pubkey, {petname, voiceId, color})"
                 "await BitechoLightNode.listSessions()"
                 "await BitechoLightNode.listSubnets()"
                 "await BitechoLightNode.sendMessage(sessionId, text)"
                 "await BitechoLightNode.sendBroadcast(subnetId, text)"
                 "await BitechoLightNode.getArtifact({cid})"
                 "await BitechoLightNode.status()"
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

;; =============================================================================
;; 4. Petname / Rolodex Metadata (D40.4, BIP-016 Aligned, Pure Sans-IO)
;; =============================================================================

(defn- merged-petname-meta-map
  [state]
  (let [base (or (get-in state [:light-state :petname-meta]) {})
        top (or (:petname-meta state) {})]
    (reduce-kv (fn [acc k v]
                 (let [k-str (if (keyword? k) (name k) (str k))
                       norm-k (or (light-core/normalize-pubkey-hex k-str) k-str)]
                   (if (and (string? norm-k) (map? v))
                     (assoc acc norm-k
                            {:petname (or (:petname v) (get v "petname"))
                             :voice-id (or (:voice-id v) (:voiceId v) (get v "voice-id") (get v "voiceId"))
                             :color (or (:color v) (get v "color"))})
                     acc)))
               {}
               (merge base top))))

(defn- merged-petnames-map
  [state]
  (let [base (or (get-in state [:light-state :petnames]) {})
        top (or (:petnames state) {})
        from-meta (reduce-kv (fn [acc pk m]
                               (if-let [pn (:petname m)]
                                 (assoc acc pn pk)
                                 acc))
                             {}
                             (merged-petname-meta-map state))]
    (reduce-kv (fn [acc k v]
                 (let [k-str (if (keyword? k) (name k) (str k))
                       norm-v (or (light-core/normalize-pubkey-hex v) v)]
                   (if (and (string? k-str) (not (str/blank? k-str)) (string? norm-v))
                     (assoc acc k-str norm-v)
                     acc)))
               {}
               (merge from-meta base top))))

(defn- normalize-optional-str
  [v]
  (when (and (string? v) (not (str/blank? v)))
    (str/trim v)))

(defn resolve-petname-entry
  "Resolves a peer pubkey against local `:petnames` and `:petname-meta` (Rolodex) state.
   Returns `{:pubkey norm-pub :petname str-or-nil :voice-id str-or-nil :color str-or-nil}`."
  [state pubkey]
  (let [raw-str (when (some? pubkey) (str/trim (str pubkey)))
        norm-pub (when (and raw-str (not (str/blank? raw-str)))
                   (or (light-core/normalize-pubkey-hex raw-str) raw-str))
        pnames (merged-petnames-map state)
        pmeta (merged-petname-meta-map state)
        pname (when norm-pub
                (some (fn [[k v]]
                        (when (= v norm-pub) k))
                      pnames))
        meta-entry (when norm-pub (get pmeta norm-pub))]
    {:pubkey norm-pub
     :petname pname
     :voice-id (normalize-optional-str (:voice-id meta-entry))
     :color (normalize-optional-str (:color meta-entry))}))

(defn- opt-present?
  [m ks]
  (boolean (some #(contains? m %) ks)))

(defn- opt-first-val
  [m ks]
  (some (fn [k] (when (contains? m k) (get m k))) ks))

(defn merge-petname-entry
  "Purely updates a peer's Rolodex entry (`petname`, `voiceId`, `color`) in browser node state,
   preserving 100% compatibility with existing `:petnames` (`petname -> pubkey`) maps."
  [state pubkey opts]
  (let [raw-pub (when (some? pubkey) (str/trim (str pubkey)))
        norm-pub (when (and raw-pub (not (str/blank? raw-pub)))
                   (light-core/normalize-pubkey-hex raw-pub))]
    (if-not norm-pub
      {:ok? false
       :error :invalid-pubkey
       :state state
       :diagnose {:type :diagnose
                  :kind :invalid-pubkey
                  :reason "invalid-or-empty-pubkey"}}
      (let [opts-map (cond
                       (map? opts) opts
                       (string? opts) {:petname opts}
                       :else {})
            has-pname? (opt-present? opts-map [:petname "petname" :name "name"])
            raw-pname (when has-pname? (opt-first-val opts-map [:petname "petname" :name "name"]))
            norm-pname (when (and (string? raw-pname) (not (str/blank? raw-pname)))
                         (light-core/normalize-petname raw-pname))
            invalid-pname? (and has-pname?
                                (some? raw-pname)
                                (not (str/blank? (str raw-pname)))
                                (nil? norm-pname))]
        (if invalid-pname?
          {:ok? false
           :error :invalid-petname
           :state state
           :diagnose {:type :diagnose
                      :kind :invalid-petname
                      :reason (str "invalid-petname:" raw-pname)}}
          (let [existing-pnames (merged-petnames-map state)
                existing-meta (merged-petname-meta-map state)
                prev-meta (get existing-meta norm-pub {})
                has-voice? (opt-present? opts-map [:voice-id :voiceId "voice-id" "voiceId" "voice_id"])
                has-color? (opt-present? opts-map [:color "color"])
                eff-voice (if has-voice?
                            (normalize-optional-str (opt-first-val opts-map [:voice-id :voiceId "voice-id" "voiceId" "voice_id"]))
                            (normalize-optional-str (:voice-id prev-meta)))
                eff-color (if has-color?
                            (normalize-optional-str (opt-first-val opts-map [:color "color"]))
                            (normalize-optional-str (:color prev-meta)))
                updated-pnames (if has-pname?
                                 (let [cleaned (into {}
                                                     (remove (fn [[_k v]] (= v norm-pub)))
                                                     existing-pnames)]
                                   (if norm-pname
                                     (assoc cleaned norm-pname norm-pub)
                                     cleaned))
                                 existing-pnames)
                eff-pname (if has-pname?
                            norm-pname
                            (or (some (fn [[k v]] (when (= v norm-pub) k)) existing-pnames)
                                (:petname prev-meta)))
                cleaned-meta (if (and has-pname? norm-pname)
                               (reduce-kv (fn [acc k m]
                                            (if (and (not= k norm-pub) (= (:petname m) norm-pname))
                                              (assoc acc k (assoc m :petname nil))
                                              (assoc acc k m)))
                                          {}
                                          existing-meta)
                               existing-meta)
                updated-meta (assoc cleaned-meta norm-pub {:petname eff-pname
                                                           :voice-id eff-voice
                                                           :color eff-color})
                updated-state (cond-> (-> state
                                          (assoc :petnames updated-pnames)
                                          (assoc :petname-meta updated-meta))
                                (map? (:light-state state))
                                (-> (assoc-in [:light-state :petnames] updated-pnames)
                                    (assoc-in [:light-state :petname-meta] updated-meta)))
                entry (resolve-petname-entry updated-state norm-pub)]
            {:ok? true
             :state updated-state
             :entry entry}))))))

(defn list-petname-entries
  "Returns a sorted vector of Rolodex entries `[{:pubkey :petname :voice-id :color}]`
   covering all pubkeys present in `:petnames` and/or `:petname-meta`."
  [state]
  (let [pnames (merged-petnames-map state)
        pmeta (merged-petname-meta-map state)
        all-pks (into (set (vals pnames)) (keys pmeta))]
    (->> all-pks
         (map #(resolve-petname-entry state %))
         (sort-by (fn [e] [(or (:petname e) "") (or (:pubkey e) "")]))
         vec)))

;; =============================================================================
;; 5. Normalized Event Formatting (D40.4, Pure Sans-IO)
;; =============================================================================

(def valid-browser-event-types
  "Canonical set of `BitechoLightNode.onEvent` event type strings."
  #{"message-received" "broadcast-received" "status" "diagnose"})

(defn normalize-browser-event
  "Pure Sans-IO event normalizer for `BitechoLightNode.onEvent`.
   Resolves `fromPetname`, `voiceId`, and `color` from local petname/Rolodex state if set,
   otherwise `nil` so callers (e.g. Hive UI) can apply deterministic fallbacks."
  [state raw-event]
  (let [ev (if (map? raw-event) raw-event {})
        raw-type (or (:type ev) (get ev "type") "status")
        type-str (let [s (if (keyword? raw-type) (name raw-type) (str raw-type))]
                   (if (contains? valid-browser-event-types s) s "diagnose"))
        session-id (or (:session-id ev) (:session_id ev) (:sessionId ev)
                       (get ev "sessionId") (get ev "session_id"))
        subnet-id (or (:subnet-id ev) (:subnet_id ev) (:subnetId ev)
                      (get ev "subnetId") (get ev "subnet_id"))
        raw-from (or (:from ev) (:sender ev) (:peer-id ev) (:peer ev)
                     (get ev "from") (get ev "sender"))
        norm-from (when (and (some? raw-from) (not (str/blank? (str raw-from))))
                    (or (light-core/normalize-pubkey-hex (str raw-from))
                        (str/trim (str raw-from))))
        rolodex (when norm-from (resolve-petname-entry state norm-from))
        from-petname (or (:petname rolodex)
                         (normalize-optional-str (or (:from-petname ev) (:from_petname ev)
                                                     (:fromPetname ev) (get ev "fromPetname"))))
        voice-id (:voice-id rolodex)
        color (:color rolodex)
        raw-seq (or (:seq ev) (get ev "seq"))
        seq-num (when (some? raw-seq) (long raw-seq))
        raw-text (cond
                   (contains? ev :text) (:text ev)
                   (contains? ev "text") (get ev "text")
                   (contains? ev :message) (:message ev)
                   (contains? ev "message") (get ev "message")
                   :else nil)
        text-str (when (some? raw-text) (str raw-text))
        ts-ms (long (or (:timestamp-ms ev) (:timestampMs ev) (get ev "timestampMs") 0))
        event-id (or (normalize-optional-str (or (:event-id ev) (:eventId ev) (get ev "eventId") (:msg-id ev)))
                     (str type-str ":" (or session-id subnet-id "node") ":" (or seq-num 0) ":" ts-ms))
        kind-val (or (:kind ev) (get ev "kind"))
        reason-val (or (:reason ev) (get ev "reason"))
        phase-val (or (:phase ev) (get ev "phase"))
        gen-val (or (:generation ev) (get ev "generation"))]
    (cond-> {:event-id event-id
             :type type-str
             :session-id (when (some? session-id) (str session-id))
             :subnet-id (when (some? subnet-id) (str subnet-id))
             :from norm-from
             :from-petname from-petname
             :voice-id voice-id
             :color color
             :seq seq-num
             :text text-str
             :timestamp-ms ts-ms}
      (some? kind-val) (assoc :kind (if (keyword? kind-val) (name kind-val) (str kind-val)))
      (some? reason-val) (assoc :reason (str reason-val))
      (some? phase-val) (assoc :phase (if (keyword? phase-val) (name phase-val) (str phase-val)))
      (some? gen-val) (assoc :generation (long gen-val)))))

(defn event->js-map
  "Converts a normalized browser event map into a Closure `:advanced`-safe string-keyed
   camelCase map for JS subscribers."
  [ev]
  (cond-> {"eventId" (:event-id ev)
           "type" (:type ev)
           "sessionId" (:session-id ev)
           "subnetId" (:subnet-id ev)
           "from" (:from ev)
           "fromPetname" (:from-petname ev)
           "voiceId" (:voice-id ev)
           "color" (:color ev)
           "seq" (:seq ev)
           "text" (:text ev)
           "timestampMs" (:timestamp-ms ev)}
    (some? (:kind ev)) (assoc "kind" (:kind ev))
    (some? (:reason ev)) (assoc "reason" (:reason ev))
    (some? (:phase ev)) (assoc "phase" (:phase ev))
    (some? (:generation ev)) (assoc "generation" (:generation ev))))

;; =============================================================================
;; 6. Multi-Line UTF-8 Safe Messaging & Broadcast Arg Normalization (D40.4)
;; =============================================================================

(defn normalize-send-message-args
  "Normalizes `BitechoLightNode.sendMessage(sessionId, text)` or `sendMessage({sessionId, text})`.
   Preserves multi-line UTF-8 `text` verbatim without shell tokenization or trimming."
  [arg1 arg2]
  (let [obj? (map? arg1)
        raw-sid (if obj?
                  (or (:sessionId arg1) (:session-id arg1) (:session_id arg1)
                      (get arg1 "sessionId") (get arg1 "session_id") (get arg1 "session-id")
                      (:peer arg1) (get arg1 "peer"))
                  arg1)
        raw-text (if obj?
                   (cond
                     (contains? arg1 :text) (:text arg1)
                     (contains? arg1 "text") (get arg1 "text")
                     (contains? arg1 :message) (:message arg1)
                     (contains? arg1 "message") (get arg1 "message")
                     :else nil)
                   arg2)
        sid (when (and (string? raw-sid) (not (str/blank? raw-sid)))
              (str/trim raw-sid))]
    (cond
      (nil? sid)
      {:ok? false :error :invalid-session-id :reason "missing-or-blank-session-id"}

      (not (string? raw-text))
      {:ok? false :error :invalid-text :reason "message-text-must-be-string"}

      :else
      {:ok? true :session-id sid :text raw-text})))

(defn normalize-send-broadcast-args
  "Normalizes `BitechoLightNode.sendBroadcast(subnetId, text)` or `sendBroadcast({subnetId, text})`.
   Preserves multi-line UTF-8 `text` verbatim without shell tokenization or trimming."
  [arg1 arg2]
  (let [obj? (map? arg1)
        raw-sub (if obj?
                  (or (:subnetId arg1) (:subnet-id arg1) (:subnet_id arg1)
                      (get arg1 "subnetId") (get arg1 "subnet_id") (get arg1 "subnet-id")
                      (:subnet arg1) (get arg1 "subnet"))
                  arg1)
        raw-text (if obj?
                   (cond
                     (contains? arg1 :text) (:text arg1)
                     (contains? arg1 "text") (get arg1 "text")
                     (contains? arg1 :message) (:message arg1)
                     (contains? arg1 "message") (get arg1 "message")
                     :else nil)
                   arg2)
        sub (when (and (string? raw-sub) (not (str/blank? raw-sub)))
              (str/trim raw-sub))]
    (cond
      (nil? sub)
      {:ok? false :error :invalid-subnet-id :reason "missing-or-blank-subnet-id"}

      (not (string? raw-text))
      {:ok? false :error :invalid-text :reason "broadcast-text-must-be-string"}

      :else
      {:ok? true :subnet-id sub :text raw-text})))

;; =============================================================================
;; 7. Artifact Fetch Plan & SHA-256 CID Verification (D40.4, Rule 5)
;; =============================================================================

(def default-artifact-base-urls
  "Default HTTPS artifact gateway origins for `BitechoLightNode.getArtifact`."
  ["https://bitecho.org" "https://ns1.bitecho.org"])

(defn- normalize-base-url
  [u]
  (when (and (string? u) (not (str/blank? u)))
    (str/replace (str/trim u) #"/+$" "")))

(defn build-artifact-fetch-plan
  "Purely builds a validated HTTPS artifact fetch plan from `{cid}` or `{subnet, path}`
   plus optional `{baseUrl}`. Rejects invalid CIDs and path traversal (`..`) fail-closed."
  [opts]
  (let [m (if (map? opts) opts {})
        raw-base (or (:base-url m) (:baseUrl m) (get m "baseUrl") (get m "base_url"))
        norm-base (normalize-base-url raw-base)
        base-urls (if norm-base [norm-base] default-artifact-base-urls)
        raw-cid (or (:cid m) (get m "cid"))
        raw-subnet (or (:subnet m) (:subnet-id m) (:subnetId m) (get m "subnet") (get m "subnetId"))
        raw-path (or (:path m) (get m "path"))]
    (cond
      (some? raw-cid)
      (let [cid-str (str/lower-case (str/trim (str raw-cid)))]
        (if (re-matches #"^[0-9a-f]{64}$" cid-str)
          {:ok? true
           :mode :cid
           :cid cid-str
           :urls (mapv #(str % "/artifact/v1/blob/" cid-str) base-urls)}
          {:ok? false
           :error :invalid-cid
           :reason (str "invalid-cid:" cid-str)
           :diagnose {:type :diagnose
                      :kind :invalid-cid
                      :reason (str "invalid-cid:" cid-str)}}))

      (and (string? raw-path) (not (str/blank? raw-path)))
      (let [clean-path (str/replace (str/trim raw-path) #"^/+" "")
            clean-sub (when (and (string? raw-subnet) (not (str/blank? raw-subnet)))
                        (str/replace (str/trim raw-subnet) #"^/+|/+$" ""))]
        (if (or (str/blank? clean-path)
                (str/includes? clean-path "..")
                (and clean-sub (str/includes? clean-sub "..")))
          {:ok? false
           :error :invalid-artifact-path
           :reason "path-traversal-rejected"
           :diagnose {:type :diagnose
                      :kind :invalid-artifact-path
                      :reason "path-traversal-rejected"}}
          (let [rel-path (if (and clean-sub
                                  (not (contains? #{"bitecho.org" "ns1.bitecho.org" "global"} clean-sub))
                                  (not (str/starts-with? clean-path (str clean-sub "/"))))
                           (str clean-sub "/" clean-path)
                           clean-path)]
            {:ok? true
             :mode :path
             :subnet clean-sub
             :path clean-path
             :urls (mapv #(str % "/" rel-path) base-urls)})))

      :else
      {:ok? false
       :error :invalid-artifact-request
       :reason "missing-cid-or-path"
       :diagnose {:type :diagnose
                  :kind :invalid-artifact-request
                  :reason "missing-cid-or-path"}})))

(defn verify-artifact-bytes
  "Purely verifies SHA-256 of fetched artifact bytes against `expected-cid` (when provided).
   Fails closed with `{:ok? false :error \"cid-mismatch\" :diagnose ...}` on mismatch (Rule 5)."
  [expected-cid data-bytes]
  (if (nil? data-bytes)
    {:ok? false
     :error "empty-artifact-bytes"
     :diagnose {:type :diagnose
                :kind :empty-artifact-bytes
                :reason "empty-artifact-bytes"}}
    (let [actual-cid (str/lower-case (fressian/bytes->hex (crypto/sha256 data-bytes)))
          norm-expected (when (and (some? expected-cid) (not (str/blank? (str expected-cid))))
                          (str/lower-case (str/trim (str expected-cid))))]
      (if (and norm-expected (not= actual-cid norm-expected))
        {:ok? false
         :error "cid-mismatch"
         :expected-cid norm-expected
         :actual-cid actual-cid
         :diagnose {:type :diagnose
                    :kind :cid-mismatch
                    :expected-cid norm-expected
                    :actual-cid actual-cid
                    :reason (str "cid-mismatch:expected=" norm-expected ",actual=" actual-cid)}}
        {:ok? true
         :cid actual-cid
         :bytes data-bytes}))))
