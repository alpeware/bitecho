(ns bitecho.core.infra
  "Pure Sans-IO `.cljc` Infrastructure Node helpers shared across JVM and Node.js runtimes (Rules 2, 4, 5):
   - Single-authority generation-tagged shell lifecycle reducer (`transition-shell`)
   - Canonical `bitecho.org/infra` policy builder & upgrade merger (`default-infra-policy`, `merge-upgraded-policy`)
   - Fail-closed HTTP path sanitization, MIME type resolution, byte-range & query parsing
   - Allowlisted `HTTP CONNECT` backend resolver (`resolve-connect-backend`)
   - Artifact pointer/blob normalization (`normalize-artifact-pointer`, `normalize-artifact-blob`)
   - RFC 5321 `Received:` header builder for SMTP mail delivery."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.subnet :as subnet]
            [bitecho.fressian :as fressian]
            [clojure.string :as str])
  #?(:clj (:import [java.net URLDecoder]
                   [java.nio.charset StandardCharsets])))

;; =============================================================================
;; 1. Single-Authority Generation-Tagged Shell Lifecycle Reducer (Rules 4 & 5)
;; =============================================================================

(defn init-shell-state
  "Initializes a generation-tagged single-authority shell lifecycle state map."
  ([] (init-shell-state :shell))
  ([shell-id]
   {:shell-id shell-id
    :phase :stopped
    :generation 0
    :resources nil
    :last-error nil
    :dropped 0
    :ignored-stale 0
    :diagnostics-counts {}
    :diagnostics []}))

(defn record-shell-diagnostic
  "Records a `:diagnose` map into `:diagnostics-counts` and bounded 64-entry `:diagnostics` ring."
  [state diag]
  (let [reason (or (:reason diag) (:error diag) :unknown)]
    (-> state
        (update-in [:diagnostics-counts reason] (fnil inc 0))
        (update :diagnostics (fn [ds]
                               (if (map? ds)
                                 (update-in ds [reason :count] (fnil inc 0))
                                 (vec (take-last 64 (conj (vec ds) diag)))))))))

(defn transition-shell
  "Pure reducer `(transition-shell state event) -> [new-state effects]`.
   Phases: `:stopped`, `:starting`, `:running`, `:stopping`, `:failed`."
  [state event]
  (let [st (merge (init-shell-state) state)
        cur-gen (long (:generation st 0))
        ev-gen (:generation event)
        etype (:type event)]
    (cond
      (and (some? ev-gen) (< (long ev-gen) cur-gen))
      (let [diag {:effect :diagnose
                  :shell (:shell-id st)
                  :reason :stale-generation-callback
                  :event-type etype
                  :event-generation (long ev-gen)
                  :current-generation cur-gen}
            st' (-> st
                    (update :ignored-stale (fnil inc 0))
                    (record-shell-diagnostic diag))]
        [st' [diag]])

      (= etype :start)
      (let [next-gen (inc cur-gen)
            close-effs (if (:resources st)
                         [{:effect :close-resources :resources (:resources st) :generation cur-gen}]
                         [])]
        [(assoc st
                :phase :starting
                :generation next-gen
                :resources nil
                :last-error nil)
         close-effs])

      (= etype :started)
      [(assoc st
              :phase :running
              :resources (:resources event)
              :last-error nil)
       []]

      (= etype :failed)
      (let [err (or (:error event) :shell-failed)
            diag {:effect :diagnose
                  :shell (:shell-id st)
                  :reason err
                  :generation cur-gen
                  :detail (:detail event)}
            close-effs (if (:resources st)
                         [{:effect :close-resources :resources (:resources st) :generation cur-gen}]
                         [])
            st' (-> st
                    (assoc :phase :failed
                           :resources nil
                           :last-error err)
                    (record-shell-diagnostic diag))]
        [st' (conj close-effs diag)])

      (= etype :stop)
      (let [close-effs (if (:resources st)
                         [{:effect :close-resources :resources (:resources st) :generation cur-gen}]
                         [])]
        [(assoc st
                :phase :stopped
                :resources nil)
         close-effs])

      (= etype :drop)
      (let [reason (or (:reason event) :packet-dropped)
            diag (cond-> {:effect :diagnose
                          :shell (:shell-id st)
                          :reason reason
                          :generation cur-gen}
                   (:detail event) (assoc :detail (:detail event)))
            st' (-> st
                    (update :dropped (fnil inc 0))
                    (record-shell-diagnostic diag))]
        [st' [diag]])

      (= etype :diagnose)
      (let [reason (or (:reason event) :diagnostic)
            diag (assoc event :effect :diagnose :shell (:shell-id st) :reason reason)
            st' (record-shell-diagnostic st diag)]
        [st' [diag]])

      :else
      (let [diag {:effect :diagnose :shell (:shell-id st) :reason :unknown-shell-event :event-type etype}
            st' (record-shell-diagnostic st diag)]
        [st' [diag]]))))

(defn shell-status-summary
  "Extracts clean status diagnostics (`:phase`, `:generation`, `:last-error`, `:dropped`, `:ignored-stale`, `:diagnostics-counts`)."
  [shell-state]
  (select-keys shell-state [:shell-id :phase :generation :last-error :dropped :ignored-stale :diagnostics-counts :diagnostics]))

;; =============================================================================
;; 2. Canonical `bitecho.org/infra` Policy & Upgrade Merge
;; =============================================================================

(def k-cold-root-pubkey
  "Tier-0 Cold Root Key (K_cold) for bitecho.org/infra governance and artifact streams (BIP-004 §B.2)."
  "302a300506032b6570032100d88b92f094f65be1d32c8c1fb6c85f7913458a99ebdc142009ab2f18fd1bf641")

(def k-nexus-builder-pubkey
  "Tier-1 Nexus Builder Key (K_nexus) for dist/*, releases/*, pkg/*, and docs/blog streams (BIP-004 §B.2)."
  "302a300506032b65700321009b33a9ebd1866d6db419edabe2de9ee74c884dc86b4214f60e3a26f04cbd9cfc")

(def k-axiom-steward-pubkey
  "Tier-1 Axiom Steward Key (K_axiom) for pkg/* and docs/blog streams (BIP-004 §B.2)."
  "302a300506032b6570032100b53afd55492fe17fca9d0ef0e07b367bf8333490e43b4ecd3610c12c8e6a79f8")

(def k-lumen-researcher-pubkey
  "Tier-1 Lumen Researcher Key (K_lumen) for web/SKILL.md, docs, and blog/* streams (BIP-004 §B.2)."
  "302a300506032b6570032100ccc35a321c00d0f05a056228a5d0682038235aea817a4a0bd4d6c681f5c970de")

(def k-vector-agent-pubkey
  "Tier-1 Vector Agent Key (K_vector) for web/*, blog/*, bip/*, and bitecho.org/dev governance streams."
  "302a300506032b6570032100365bd3dc35b4f609d6ac147c129c5b791798765b181d53341e58d6fcf1c6cd62")

(def k-node1-validator-pubkey
  "Devnet validator node1 Ed25519 pubkey authorized for telemetry/node1/* observability digests."
  "302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086")

(def k-node2-validator-pubkey
  "Devnet validator node2 Ed25519 pubkey authorized for telemetry/node2/* observability digests."
  "302a300506032b6570032100592ab794dea07da278ef3853e8cc2d2f6ac5e3417eac80d93ab01e1fc61653ba")

(def k-node3-validator-pubkey
  "Devnet validator node3 Ed25519 pubkey authorized for telemetry/node3/* observability digests."
  "302a300506032b65700321007b7f58652a2c26b4180aeee45ff12f927a45d92e00fc3462c5d854f6203351f1")

(defn default-infra-policy
  "Constructs the canonical `\"bitecho.org/infra\"` Subnet policy map."
  [{:keys [subnet-id trust-anchors cold-pubkey domain-pubkey threshold acme-thumbprint denied-cids]}]
  (let [sid (or subnet-id "bitecho.org/infra")
        anchors (set (map #(str/lower-case (str/trim (str %))) trust-anchors))
        cold-pk (when (and (string? cold-pubkey) (not (str/blank? cold-pubkey)))
                  (str/lower-case (str/trim cold-pubkey)))
        dom-pk (when (and (string? domain-pubkey) (not (str/blank? domain-pubkey)))
                 (str/lower-case (str/trim domain-pubkey)))
        k-cold (str/lower-case (str/trim k-cold-root-pubkey))
        k-nexus (str/lower-case (str/trim k-nexus-builder-pubkey))
        k-axiom (str/lower-case (str/trim k-axiom-steward-pubkey))
        k-lumen (str/lower-case (str/trim k-lumen-researcher-pubkey))
        k-vector (str/lower-case (str/trim k-vector-agent-pubkey))
        cold-set (cond-> #{k-cold} cold-pk (conj cold-pk))
        dist-signers (into cold-set [k-nexus])
        releases-signers (into anchors dist-signers)
        pkg-signers (into dist-signers [k-axiom])
        doc-blog-signers (into anchors (into pkg-signers [k-lumen k-vector]))
        telemetry-signers (into doc-blog-signers
                                [(str/lower-case (str/trim k-node1-validator-pubkey))
                                 (str/lower-case (str/trim k-node2-validator-pubkey))
                                 (str/lower-case (str/trim k-node3-validator-pubkey))])
        thresh (long (or threshold (max 1 (min 2 (count anchors)))))
        gov (cond-> {:governance/type (if cold-pk :cold-key-or-quorum :quorum)
                     :threshold thresh}
              cold-pk (assoc :cold-pubkey cold-pk))
        gate (cond-> {:gate/mode :permissioned
                      :gate/admission :allowlist
                      :gate/trust-anchors anchors
                      :gate/governance gov}
               (and (string? acme-thumbprint) (not (str/blank? acme-thumbprint)))
               (assoc :gate/acme-thumbprint (str/trim acme-thumbprint)))
        dns-rule (if dom-pk
                   {:pattern "dns/*" :principal {:type :pubkey :pubkey dom-pk}}
                   {:pattern "dns/*" :principal {:type :allowlist}})
        base (cond-> {:subnet/id sid
                      :subnet/parent-id "global"
                      :subnet/gate gate
                      :subnet/path-acl [{:pattern "subnet/policy"    :principal {:type :governance}}
                                        {:pattern "dist/*"           :principal {:type :allowlist :signers dist-signers}}
                                        {:pattern "releases/*"       :principal {:type :allowlist :signers releases-signers}}
                                        {:pattern "pkg/*"            :principal {:type :allowlist :signers pkg-signers}}
                                        {:pattern "web/SKILL.md"     :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "web/ONBOARDING.md" :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "web/llms.txt"     :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "llms.txt"         :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "web/references/*" :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "web/agents/*"     :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "web/blog/*"       :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "blog/*"           :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "web/bip/*"        :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "bip/*"            :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "config/*"         :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "sla/*"            :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "incidents/*"      :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "deploy/*"         :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "research/*"       :principal {:type :allowlist :signers doc-blog-signers}}
                                        {:pattern "telemetry/*"      :principal {:type :allowlist :signers telemetry-signers}}
                                        {:pattern "web/app/*"        :principal {:type :allowlist :signers releases-signers}}
                                        {:pattern "web/*"            :principal {:type :allowlist}}
                                        {:pattern "bootstrap"        :principal {:type :allowlist}}
                                        {:pattern "dir/*"            :principal {:type :allowlist}}
                                        {:pattern "acme/challenge/*" :principal {:type :leader}}
                                        {:pattern "tls/*"            :principal {:type :leader}}
                                        {:pattern "bounty/*"         :principal {:type :allowlist}}
                                        {:pattern "head/*"           :principal {:type :allowlist}}
                                        {:pattern "mail/*"           :principal {:type :allowlist}}
                                        dns-rule]
                      :subnet/economy {:economy/mode :none
                                       :economy/burn-floor 0
                                       :economy/settlement-take-bps 0}
                      :subnet/replication {:replication/pointers :leader-election
                                           :replication/blobs :eager-push}}
               (seq denied-cids)
               (assoc :subnet/denied-cids (set (map #(str/lower-case (str/trim (str %))) denied-cids))))]
    (assoc base :subnet/genesis-policy-cid (subnet/policy-cid base))))

(defn merge-upgraded-policy
  "Pure helper: merges newly added `:subnet/path-acl` patterns and upgraded
   `:signers` sets from `default-pol` into a persisted `snap-pol` loaded from `subnet-pointers.fressian`."
  [default-pol snap-pol]
  (cond
    (nil? snap-pol) default-pol
    (nil? default-pol) snap-pol
    :else
    (let [def-acl (vec (or (:subnet/path-acl default-pol) []))
          snap-acl (vec (or (:subnet/path-acl snap-pol) []))
          snap-by-pat (into {} (map (fn [r] [(:pattern r) r]) snap-acl))
          def-pats (set (map :pattern def-acl))
          merge-rule (fn [def-rule snap-rule]
                       (if (nil? snap-rule)
                         def-rule
                         (let [def-p (:principal def-rule)
                               snap-p (:principal snap-rule)
                               def-signers (:signers def-p)
                               snap-signers (:signers snap-p)
                               merged-p (cond-> (merge def-p snap-p)
                                          (or (seq def-signers) (seq snap-signers))
                                          (assoc :signers (into (set (or snap-signers #{}))
                                                                (or def-signers #{}))))]
                           (assoc snap-rule :principal merged-p))))
          merged-def (mapv (fn [def-r]
                             (merge-rule def-r (get snap-by-pat (:pattern def-r))))
                           def-acl)
          extra-snap (filterv #(not (contains? def-pats (:pattern %))) snap-acl)
          final-acl (into merged-def extra-snap)
          merged-denied (into (set (or (:subnet/denied-cids default-pol) #{}))
                              (or (:subnet/denied-cids snap-pol) #{}))
          merged-base (cond-> (assoc snap-pol :subnet/path-acl final-acl)
                        (seq merged-denied) (assoc :subnet/denied-cids merged-denied))]
      (assoc merged-base :subnet/genesis-policy-cid (subnet/policy-cid merged-base)))))

;; =============================================================================
;; 3. CID Validation, MIME Types, Path Sanitization, Byte Range, Query Params
;; =============================================================================

(defn normalize-cid
  "Normalizes a 64-char hex CID string to lowercase trimmed."
  [cid]
  (when cid
    (str/lower-case (str/trim (str cid)))))

(defn valid-cid?
  "Returns true if `cid` is a valid 64-char lowercase hex SHA-256 CID."
  [cid]
  (and (string? cid)
       (boolean (re-matches #"[0-9a-f]{64}" (str/lower-case (str/trim cid))))))

(defn- url-decode-safe
  [s]
  (try
    #?(:clj (URLDecoder/decode (str s) StandardCharsets/UTF_8)
       :cljs (js/decodeURIComponent (str/replace (str s) #"\+" " ")))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(defn- parse-long-safe
  [s default-val]
  (let [trimmed (str/trim (str (or s "")))
        d (long default-val)]
    (if (re-matches #"-?\d+" trimmed)
      #?(:clj (try (Long/parseLong trimmed) (catch Exception _ d))
         :cljs (let [n (js/parseInt trimmed 10)] (if (js/isNaN n) d (long n))))
      d)))

(def extension->media-type
  "Canonical ordered extension-to-MIME-type table."
  [[".tar.gz" "application/gzip"]
   [".tgz" "application/gzip"]
   [".md" "text/markdown; charset=utf-8"]
   [".js" "application/javascript; charset=utf-8"]
   [".mjs" "application/javascript; charset=utf-8"]
   [".cjs" "application/javascript; charset=utf-8"]
   [".html" "text/html; charset=utf-8"]
   [".htm" "text/html; charset=utf-8"]
   [".css" "text/css; charset=utf-8"]
   [".json" "application/json; charset=utf-8"]
   [".xml" "application/xml; charset=utf-8"]
   [".pom" "application/xml; charset=utf-8"]
   [".clj" "text/plain; charset=utf-8"]
   [".cljc" "text/plain; charset=utf-8"]
   [".cljs" "text/plain; charset=utf-8"]
   [".edn" "text/plain; charset=utf-8"]
   [".txt" "text/plain; charset=utf-8"]
   [".sha1" "text/plain; charset=utf-8"]
   [".sha256" "text/plain; charset=utf-8"]
   [".sri" "text/plain; charset=utf-8"]
   [".sh" "text/x-shellscript; charset=utf-8"]
   [".jar" "application/java-archive"]])

(def default-extension-media-types
  "Complete set of default extension-derived MIME types."
  (conj (set (map second extension->media-type))
        "application/octet-stream"))

(defn content-type-for-file
  "Resolves the default extension-based MIME type for `name-str`."
  [name-str]
  (let [l (str/lower-case (or name-str ""))]
    (if (= l "head")
      "text/plain; charset=utf-8"
      (or (some (fn [[ext mt]]
                  (when (str/ends-with? l ext) mt))
                extension->media-type)
          "application/octet-stream"))))

(defn compressible-content-type?
  "Returns true if `ct` is a compressible text/script/json/xml MIME type."
  [ct]
  (let [l (str/lower-case (or ct ""))]
    (or (str/starts-with? l "text/")
        (str/includes? l "json")
        (str/includes? l "xml")
        (str/includes? l "markdown")
        (str/includes? l "javascript"))))

(defn sanitize-web-subpath
  "Fail-closed URL path sanitizer: rejects NUL bytes, invalid percent-encoding, `..`, and dotfiles.
   Returns normalized slash-joined relative subpath (empty string for `/`), or `nil` if forbidden."
  [raw-path]
  (when-not (str/includes? (or raw-path "") "\u0000")
    (let [path-only (first (str/split (or raw-path "/") #"\?" 2))
          decoded (url-decode-safe path-only)]
      (when (and decoded (not (str/includes? decoded "\u0000")))
        (let [segs (remove str/blank? (str/split decoded #"[/\\]"))]
          (when-not (some #(or (= % "..") (and (str/starts-with? % ".") (not= % "."))) segs)
            (str/join "/" segs)))))))

(defn parse-query-params
  "Parses URL query string into lowercase key -> decoded value map."
  [raw-query]
  (if (str/blank? raw-query)
    {}
    (into {}
          (keep (fn [pair]
                  (let [[k v] (str/split pair #"=" 2)
                        dk (when (and k (seq k)) (url-decode-safe k))]
                    (when (and dk (seq dk))
                      [(str/lower-case dk)
                       (if v (or (url-decode-safe v) "") "")]))))
          (str/split raw-query #"&"))))

(defn parse-byte-range
  "Parses an HTTP `Range: bytes=...` header against `total-size`, returning `[start end]` or `nil`."
  [range-header total-size]
  (let [total (long total-size)]
    (when (and (string? range-header) (str/starts-with? range-header "bytes=") (pos? total))
      (let [spec (subs range-header 6)]
        (cond
          (re-matches #"^(\d+)-(\d+)$" spec)
          (let [[_ s e] (re-matches #"^(\d+)-(\d+)$" spec)
                start (parse-long-safe s -1)
                end (parse-long-safe e -1)]
            (when (and (>= start 0) (<= start end) (< start total))
              [start (min end (dec total))]))

          (re-matches #"^(\d+)-$" spec)
          (let [[_ s] (re-matches #"^(\d+)-$" spec)
                start (parse-long-safe s -1)]
            (when (and (>= start 0) (< start total))
              [start (dec total)]))

          (re-matches #"^-(\d+)$" spec)
          (let [[_ suf] (re-matches #"^-(\d+)$" spec)
                slen (parse-long-safe suf 0)]
            (when (pos? slen)
              [(max 0 (- total slen)) (dec total)])))))))

;; =============================================================================
;; 4. HTTP CONNECT Allowlist Resolver
;; =============================================================================

(defn resolve-connect-backend
  "Purely resolves an `HTTP CONNECT` request (`{:host <host> :port <int>}`) against
   allowlisted `connect-targets`, `connect-routes`, and `ingress-target`.
   Returns `{:host ... :port ...}` if allowed, or `nil` (fail-closed) if denied."
  [conn-req connect-targets connect-routes ingress-target]
  (let [h (str/lower-case (str (:host conn-req)))
        p (int (:port conn-req))
        target-key (str h ":" p)
        routes-map (into {}
                         (concat
                          (when (map? connect-targets)
                            (for [[k v] connect-targets]
                              [(str/lower-case (str k)) v]))
                          (when (map? connect-routes)
                            (for [[k v] connect-routes]
                              [(str/lower-case (str k)) v]))))
        allowed-keys (if (map? connect-targets)
                       (set (keys routes-map))
                       (into (set (keys routes-map))
                             (map #(str/lower-case (str %)) (or connect-targets #{}))))
        wildcard-ingress? (some #(and (str/starts-with? % "*.")
                                      (str/ends-with? target-key (subs % 1)))
                                allowed-keys)
        allowed? (or (contains? allowed-keys target-key)
                     (boolean wildcard-ingress?))]
    (when allowed?
      (or (get routes-map target-key)
          (if (and (map? ingress-target)
                   (or (not (contains? #{"127.0.0.1" "localhost" "::1"} h))
                       (= p 443)))
            ingress-target
            {:host h :port p})))))

;; =============================================================================
;; 5. Artifact Pointer & Blob Normalization
;; =============================================================================

(defn normalize-artifact-proof
  "Normalizes an artifact pointer proof map (EDN or JSON keys)."
  [proof]
  (if (map? proof)
    (let [raw-type (or (:proof/type proof) (get proof "proof/type") (:type proof) (get proof "type") :self)
          ptype (if (keyword? raw-type)
                  raw-type
                  (keyword (str/replace (str/trim (str raw-type)) #"^:+" "")))]
      (cond-> {:proof/type ptype}
        (or (:signatures proof) (get proof "signatures"))
        (assoc :signatures (into {}
                                 (map (fn [[k v]]
                                        [(str/lower-case (str/trim (if (keyword? k) (name k) (str k))))
                                         (str/lower-case (str/trim (str v)))]))
                                 (or (:signatures proof) (get proof "signatures"))))
        (or (:agent-pubkey proof) (get proof "agent_pubkey") (get proof "agent-pubkey"))
        (assoc :agent-pubkey (str/lower-case (str/trim (str (or (:agent-pubkey proof) (get proof "agent_pubkey") (get proof "agent-pubkey"))))))
        (or (:pop-sig proof) (get proof "pop_sig") (get proof "pop-sig"))
        (assoc :pop-sig (str/lower-case (str/trim (str (or (:pop-sig proof) (get proof "pop_sig") (get proof "pop-sig"))))))))
    {:proof/type :self}))

(defn normalize-artifact-pointer
  "Normalizes an EDN or JSON artifact pointer map into canonical `:pointer/*` keys."
  [raw-p]
  (let [p (if (and (map? raw-p) (or (map? (:pointer raw-p)) (map? (get raw-p "pointer"))))
            (or (:pointer raw-p) (get raw-p "pointer"))
            raw-p)]
    (when (map? p)
      (let [auth (or (:pointer/authority p) (get p "pointer/authority") (:authority p) (get p "authority")
                     (:pointer/authority-pubkey p) (get p "authority_pubkey"))
            sub (or (:pointer/subnet p) (get p "pointer/subnet") (:subnet p) (get p "subnet")
                    (:subnet-id p) (get p "subnet_id") "bitecho.org/infra")
            path (or (:pointer/path p) (get p "pointer/path") (:path p) (get p "path"))
            seq-raw (or (:pointer/seq p) (get p "pointer/seq") (:seq p) (get p "seq") 1)
            seq-num (parse-long-safe seq-raw 1)
            has-term? (or (contains? p :pointer/leader-term)
                          (contains? p "pointer/leader-term")
                          (contains? p :leader-term)
                          (contains? p "leader_term")
                          (contains? p "leader-term"))
            term-raw (or (:pointer/leader-term p) (get p "pointer/leader-term")
                         (:leader-term p) (get p "leader_term") (get p "leader-term"))
            has-exp? (or (contains? p :pointer/expires)
                         (contains? p "pointer/expires")
                         (contains? p :expires)
                         (contains? p "expires"))
            exp-raw (or (:pointer/expires p) (get p "pointer/expires") (:expires p) (get p "expires"))
            has-ts? (or (contains? p :pointer/timestamp)
                        (contains? p "pointer/timestamp")
                        (contains? p :timestamp)
                        (contains? p "timestamp"))
            ts-raw (or (:pointer/timestamp p) (get p "pointer/timestamp") (:timestamp p) (get p "timestamp"))
            raw-target (if (or (contains? p :pointer/target) (contains? p "pointer/target")
                               (contains? p :target) (contains? p "target")
                               (contains? p :cid) (contains? p "cid"))
                         (or (:pointer/target p) (get p "pointer/target")
                             (:target p) (get p "target")
                             (:cid p) (get p "cid"))
                         nil)
            target (when (and (some? raw-target) (not (str/blank? (str raw-target))))
                     (str/lower-case (str/trim (str raw-target))))
            sig (or (:pointer/sig p) (get p "pointer/sig") (:sig p) (get p "sig")
                    (:pointer/signature p) (get p "signature"))
            proof (normalize-artifact-proof
                   (or (:pointer/proof p) (get p "pointer/proof") (:proof p) (get p "proof")))]
        (cond-> {:pointer/authority (when auth (str/lower-case (str/trim (str auth))))
                 :pointer/subnet (str sub)
                 :pointer/path (when path (str/replace (str/trim (str path)) #"^/+" ""))
                 :pointer/seq (long seq-num)
                 :pointer/target target
                 :pointer/proof proof
                 :pointer/sig (when sig (str/lower-case (str/trim (str sig))))}
          (and has-term? (some? term-raw))
          (assoc :pointer/leader-term (long (parse-long-safe term-raw 1)))
          (and has-exp? (some? exp-raw))
          (assoc :pointer/expires (long (parse-long-safe exp-raw 0)))
          (and has-ts? (some? ts-raw))
          (assoc :pointer/timestamp (long (parse-long-safe ts-raw 0))))))))

(defn normalize-artifact-blob
  "Normalizes an EDN/JSON/raw artifact blob map and verifies optional declared CID."
  [raw-b]
  (let [b (if (and (map? raw-b) (or (map? (:blob raw-b)) (map? (get raw-b "blob"))))
            (or (:blob raw-b) (get raw-b "blob"))
            raw-b)]
    (when (map? b)
      (let [media (str (or (:blob/media-type b) (get b "blob/media-type")
                           (:media-type b) (get b "media_type") (get b "media-type")
                           "application/octet-stream"))
            raw-bytes (or (:blob/bytes b) (get b "blob/bytes")
                          (:bytes b) (get b "bytes")
                          (:bytes-hex b) (get b "bytes_hex") (get b "bytes-hex")
                          (:data b) (get b "data"))
            bs (cond
                 (fressian/bytes? raw-bytes) raw-bytes
                 (and (string? raw-bytes)
                      (or (contains? b :bytes-hex) (contains? b "bytes_hex") (contains? b "bytes-hex")
                          (and (even? (count (str/trim raw-bytes)))
                               (re-matches #"[0-9a-fA-F]+" (str/trim raw-bytes)))))
                 (try (basalt/hex->bytes (str/trim raw-bytes))
                      (catch #?(:clj Exception :cljs :default) _ (fressian/utf8->bytes raw-bytes)))
                 (string? raw-bytes)
                 (fressian/utf8->bytes raw-bytes)
                 :else nil)
            blob (when (fressian/bytes? bs) (data/make-blob bs media))
            declared-cid (or (:blob/cid b) (get b "blob/cid") (:cid b) (get b "cid"))]
        (when blob
          (if (and (string? declared-cid) (not (str/blank? declared-cid))
                   (not= (str/lower-case (str/trim declared-cid)) (:blob/cid blob)))
            {:ok? false :error :blob-cid-mismatch :expected (str/lower-case (str/trim declared-cid)) :actual (:blob/cid blob)}
            {:ok? true :blob blob}))))))

;; =============================================================================
;; 6. SMTP Received Header Builder
;; =============================================================================

(defn build-received-eml
  "Prepends an RFC 5321 `Received:` trace header to `raw-eml` if not already present."
  [{:keys [id domain remote-ip helo date-str raw-eml]}]
  (let [hdr (str "Received: from " (or helo "unknown") " ([" (or remote-ip "127.0.0.1") "])\r\n"
                 "        by " (or domain "localhost") " with ESMTP\r\n"
                 "        id " (or id "msg") "; " (or date-str "Thu, 1 Jan 1970 00:00:00 +0000") "\r\n")]
    (if (str/starts-with? (str/trim (or raw-eml "")) "Received:")
      raw-eml
      (str hdr raw-eml))))

;; =============================================================================
;; 7. Artifact Blob Upload & Peer Replication Classification (BIP-018-SOAK-F3)
;; =============================================================================

(defn evaluate-artifact-blob-upload-response
  "Purely evaluates an HTTP `POST /artifact/v1/blob` result (Rule 2, Rule 5).
   Fails closed on any transport error, non-2xx HTTP status, missing/false `ok`,
   or CID mismatch so callers never report `ok=true` after a failed upload."
  [{:keys [status parsed-body transport-error expected-cid]}]
  (let [norm-expected (when (string? expected-cid) (normalize-cid expected-cid))
        body-ok? (when (map? parsed-body)
                   (or (true? (:ok parsed-body))
                       (true? (get parsed-body "ok"))))
        raw-cid (when (map? parsed-body)
                  (or (:cid parsed-body) (get parsed-body "cid")))
        norm-returned (when (string? raw-cid) (normalize-cid raw-cid))]
    (cond
      (some? transport-error)
      {:ok? false
       :error :transport-error
       :retryable? true
       :detail (str transport-error)}

      (not (and (integer? status) (<= 200 status 299)))
      {:ok? false
       :error (if (integer? status) :http-error :missing-status)
       :status status
       :retryable? (boolean (or (nil? status)
                                (= status 408)
                                (= status 429)
                                (and (integer? status) (>= status 500))))
       :detail (or (when (map? parsed-body) (or (:error parsed-body) (get parsed-body "error")))
                   (when (integer? status) (str "http-" status))
                   "missing-http-status")}

      (not (true? body-ok?))
      {:ok? false
       :error :invalid-response-body
       :status status
       :retryable? false
       :detail (or (when (map? parsed-body) (or (:error parsed-body) (get parsed-body "error")))
                   "missing-ok-true")}

      (and norm-expected (not= norm-expected norm-returned))
      {:ok? false
       :error :cid-mismatch
       :status status
       :retryable? false
       :expected norm-expected
       :actual norm-returned}

      :else
      {:ok? true
       :status status
       :cid (or norm-returned norm-expected)})))

(defn classify-peer-replication-response
  "Purely classifies an inter-node peer replication HTTP outcome (Rule 2, Rule 5).
   Every non-2xx status or transport error produces a counted `:diagnose` event."
  [{:keys [status error peer reason]}]
  (let [diag-reason (or reason :peer-artifact-replicate-failed)]
    (cond
      (some? error)
      {:ok? false
       :diagnose {:type :diagnose
                  :reason diag-reason
                  :peer peer
                  :detail (str error)}}

      (not (and (integer? status) (<= 200 status 299)))
      {:ok? false
       :diagnose {:type :diagnose
                  :reason diag-reason
                  :peer peer
                  :status status
                  :detail (if (integer? status) (str "http-" status) "missing-status")}}

      :else
      {:ok? true :status status})))

(defn evaluate-artifact-pointer-upload-response
  "Purely evaluates an HTTP `POST /artifact/v1/pointer` result (Rule 2, Rule 5, SOAK-F4).
   Fails closed on any transport error, non-2xx HTTP status, or missing/false `ok`."
  [{:keys [status parsed-body transport-error]}]
  (let [body-ok? (when (map? parsed-body)
                   (or (true? (:ok parsed-body))
                       (true? (get parsed-body "ok"))))]
    (cond
      (some? transport-error)
      {:ok? false
       :error :transport-error
       :retryable? true
       :detail (str transport-error)}

      (not (and (integer? status) (<= 200 status 299)))
      {:ok? false
       :error (if (integer? status) :http-error :missing-status)
       :status status
       :retryable? (boolean (or (nil? status)
                                (= status 408)
                                (= status 429)
                                (and (integer? status) (>= status 500))))
       :detail (or (when (map? parsed-body) (or (:error parsed-body) (get parsed-body "error")))
                   (when (integer? status) (str "http-" status))
                   "missing-http-status")}

      (not (true? body-ok?))
      {:ok? false
       :error :invalid-response-body
       :status status
       :retryable? false
       :detail (or (when (map? parsed-body) (or (:error parsed-body) (get parsed-body "error")))
                   "missing-ok-true")}

      :else
      {:ok? true :status status})))

(defn normalize-memory-telemetry
  "Purely normalizes Node.js `process.memoryUsage()` counters into the structured
   `/statusz` `:memory` map (`:rss-bytes`, `:heap-used-bytes`, `:heap-total-bytes`,
   `:external-bytes`, `:array-buffers-bytes`, plus derived `:off-heap-bytes`).
   Coerces missing/negative values safely to `0` (BIP-018-SOAK-F1)."
  [raw]
  (let [clamp-nonneg (fn [v] (if (number? v) (max 0 (long v)) 0))
        rss (clamp-nonneg (or (:rss-bytes raw) (:rss raw) (get raw "rss")))
        heap-used (clamp-nonneg (or (:heap-used-bytes raw) (:heapUsed raw) (get raw "heapUsed")))
        heap-total (clamp-nonneg (or (:heap-total-bytes raw) (:heapTotal raw) (get raw "heapTotal")))
        external (clamp-nonneg (or (:external-bytes raw) (:external raw) (get raw "external")))
        array-buffers (clamp-nonneg (or (:array-buffers-bytes raw) (:arrayBuffers raw) (get raw "arrayBuffers")))
        off-heap (max 0 (- rss heap-total))]
    {:rss-bytes rss
     :heap-used-bytes heap-used
     :heap-total-bytes heap-total
     :external-bytes external
     :array-buffers-bytes array-buffers
     :off-heap-bytes off-heap}))

(defn should-trigger-offheap-gc?
  "Purely decides whether a throttled V8 major GC should be triggered to reclaim
   uncounted off-heap `ArrayBuffer`/`Buffer` backing stores in Node.js v26 / V8 14.6
   (BIP-018-SOAK-F1). Returns `true` only when `gc-available?` is true, at least
   `cooldown-ms` (default 30s) has elapsed since `last-gc-ms`, and either
   `array-buffers-bytes >= max-array-buffers-bytes` (default 8 MiB) or
   `external-bytes >= max-external-bytes` (default 16 MiB)."
  [{:keys [memory last-gc-ms now-ms gc-available? cooldown-ms max-array-buffers-bytes max-external-bytes]}]
  (let [m (normalize-memory-telemetry memory)
        cd (long (or cooldown-ms 30000))
        ab-cap (long (or max-array-buffers-bytes (* 8 1024 1024)))
        ext-cap (long (or max-external-bytes (* 16 1024 1024)))
        last-t (long (or last-gc-ms 0))
        now-t (long (or now-ms 0))]
    (boolean
     (and (true? gc-available?)
          (>= (- now-t last-t) cd)
          (or (>= (:array-buffers-bytes m) ab-cap)
              (>= (:external-bytes m) ext-cap))))))
