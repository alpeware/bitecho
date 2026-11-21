(ns bitecho.governance.integrity
  "Pure Sans-IO governance receipt integrity, CLI/SKILL.md inventory parity,
   documentation link/staleness linting, canonical channel migration readiness,
   and dist/* pointer-bump release-gate validators (BIP-015 / Milestone D41).
   Conforms to AGENTS.md Rules 1, 2, 5, and 6."
  (:require [bitecho.browser-cli :as browser-cli]
            [bitecho.light-node.cli :as cli]
            [clojure.string :as str]))

;; =============================================================================
;; 1. Canonical Constants & CID Helpers (P-GOV-1 / P-CHAN-1)
;; =============================================================================

(def ^:private sha256-hex-pattern
  #"^[0-9a-f]{64}$")

(def canonical-primary-circle-channel
  "Single primary circle coordination & consent channel settled in BIP-015 Stage 1."
  "bitecho.org/team")

(def canonical-required-channels
  "Core canonical channels required for agent/browser/watcher migration readiness."
  #{"bitecho.org/team" "bitecho.org/dev" "bitecho.org/ops"})

(def canonical-all-channels
  "Full taxonomy of canonical Bitecho channels."
  ["bitecho.org/team"
   "bitecho.org/dev"
   "bitecho.org/ops"
   "bitecho.org/observability"
   "bitecho.org/infra"])

(def legacy-deprecated-channel
  "Legacy coordination channel scheduled for deprecation after dual-post soak."
  "chat/simon-nexus-axiom")

(def required-migration-participants
  "All 4 circle agents + Simon's browser node + watcher/bridge required before deprecating legacy channel."
  #{"axiom" "nexus" "vector" "lumen" "simon" "watcher"})

(defn valid-sha256-cid?
  "Returns true iff `s` is an exact 64-character lowercase hexadecimal SHA-256 CID."
  [s]
  (boolean (and (string? s) (re-matches sha256-hex-pattern s))))

(defn- diag
  [kind detail]
  {:effect :diagnose
   :type :diagnose
   :kind kind
   :detail detail})

;; =============================================================================
;; 2. S-D41-1: BIP Receipt & CID Integrity Validator
;; =============================================================================

(defn- collect-cid-fields
  "Extracts [path-key value] pairs for all SHA-256 CID fields present in a BIP EDN map."
  [bip]
  (let [top-keys [:bip/parent-bip-cid :parent-bip-cid]
        parent-docs (when (map? (:parent-documents bip))
                      (map (fn [[k v]] [(keyword "parent-documents" (name k)) v])
                           (:parent-documents bip)))
        oracle (:oracle-receipts bip)
        oracle-cids (when (map? oracle)
                      (keep (fn [[k v]]
                              (when (and (string? v)
                                         (or (str/includes? (name k) "sha256")
                                             (str/includes? (name k) "cid")))
                                [(keyword "oracle-receipts" (name k)) v]))
                            oracle))
        bip-oracle (:bip/oracle-receipts bip)
        bip-oracle-cids (when (map? bip-oracle)
                          (keep (fn [[k v]]
                                  (when (and (string? v)
                                             (or (str/includes? (name k) "sha256")
                                                 (str/includes? (name k) "cid")))
                                    [(keyword "bip-oracle-receipts" (name k)) v]))
                                bip-oracle))
        code-art (:code-artifact bip)
        patch-cid (when (and (map? code-art) (contains? code-art :patch-cid))
                    [[:code-artifact/patch-cid (:patch-cid code-art)]])]
    (vec (concat (keep (fn [k]
                         (when (contains? bip k)
                           [k (get bip k)]))
                       top-keys)
                 parent-docs
                 oracle-cids
                 bip-oracle-cids
                 patch-cid))))

(defn- has-valid-open-findings?
  [open-findings]
  (and (sequential? open-findings)
       (seq open-findings)
       (every? (fn [f]
                 (and (map? f)
                      (some? (:owner f))
                      (some? (:target-milestone f))))
               open-findings)))

(defn validate-bip-receipt
  "Pure validator for committed BIP receipts (S-D41-1 / P-GOV-1).
   Options:
   - `:require-patch?` (default false): assert non-nil 64-char `:code-artifact/:patch-cid` and positive `:patch-size-bytes`.
   - `:require-5-consents?` (default false): assert >= 5 populated consent records.
   Always enforces:
   1. All present CID/SHA-256 fields are exact 64-char lowercase hex (no 8-char prefixes).
   2. Zero `:pending` consent records.
   3. Any `:consented-with-flags` or `:consented-with-addendum` verdict has explicit `:flag-resolutions` or owned `:open-findings`.
   Returns `{:ok? bool :errors [...] :diagnostics [...]}`."
  ([bip] (validate-bip-receipt bip {}))
  ([bip {:keys [require-patch? require-5-consents?]}]
   (if-not (map? bip)
     {:ok? false
      :errors ["BIP receipt must be a map"]
      :diagnostics [(diag :invalid-bip-receipt "BIP receipt must be a map")]}
     (let [cid-issues (for [[k v] (collect-cid-fields bip)
                            :when (not (valid-sha256-cid? v))]
                        [:invalid-cid (str "CID field " k " is not a full 64-char lowercase SHA-256 hex string: " (pr-str v))])
           consents (:consent-records bip)
           count-issues (when (and require-5-consents? (< (count consents) 5))
                          [[:incomplete-consents (str "Expected at least 5 consent records, found " (count consents))]])
           pending-issues (for [c consents
                                :when (or (= :pending (:verdict c))
                                          (= :pending (:status c))
                                          (= "pending" (:verdict c)))]
                            [:pending-consent (str "Committed BIP contains :pending consent for agent " (pr-str (:agent c)))])
           flagged? (some #(contains? #{:consented-with-flags :consented-with-addendum} (:verdict %))
                          consents)
           resolutions (:flag-resolutions bip)
           open-findings (:open-findings bip)
           flag-issues (when (and flagged?
                                  (not (and (map? resolutions) (seq resolutions)))
                                  (not (has-valid-open-findings? open-findings)))
                         [[:unresolved-consent-flags
                           "CONSENT-WITH-FLAGS / CONSENT-WITH-ADDENDUM verdict requires non-empty :flag-resolutions or owned :open-findings"]])
           code-art (:code-artifact bip)
           patch-issues (when require-patch?
                          (cond-> []
                            (not (valid-sha256-cid? (:patch-cid code-art)))
                            (conj [:missing-patch-cid "Stage 2 receipt requires a valid 64-char :code-artifact/:patch-cid"])
                            (not (and (integer? (:patch-size-bytes code-art))
                                      (pos? (:patch-size-bytes code-art))))
                            (conj [:invalid-patch-size "Stage 2 receipt requires positive integer :code-artifact/:patch-size-bytes"])))
           all-issues (vec (concat cid-issues count-issues pending-issues flag-issues patch-issues))]
       {:ok? (empty? all-issues)
        :errors (mapv second all-issues)
        :diagnostics (mapv (fn [[k msg]] (diag k msg)) all-issues)}))))

;; =============================================================================
;; 3. S-D41-2: Live CLI / Browser-CLI vs. SKILL.md Inventory Parity
;; =============================================================================

(defn extract-markdown-flags
  "Extracts the set of all `--flag-name` CLI flags referenced in `markdown-text`."
  [markdown-text]
  (if (string? markdown-text)
    (set (re-seq #"--[a-z][a-z0-9-]*" markdown-text))
    #{}))

(defn check-skill-inventory-parity
  "Compares live `bitecho.light-node.cli` and `bitecho.browser-cli` inventories against
   `skill-md` content with zero drift (S-D41-2 / P-DOCS-2 / Rule 6).
   Returns `{:ok? bool :missing-canonical-verbs [...] :missing-flags [...] :missing-browser-unsupported [...] :errors [...] :diagnostics [...]}`."
  [skill-md]
  (let [text (or skill-md "")
        found-flags (extract-markdown-flags text)
        missing-flags (->> cli/known-command-flags
                           (remove #(contains? found-flags %))
                           vec)
        missing-canonical (->> cli/canonical-cli-verbs
                               (remove #(or (str/includes? text (str "`" % "`"))
                                            (re-find (re-pattern (str "\\b" % "\\b")) text)))
                               vec)
        missing-browser-unsup (->> (sort browser-cli/browser-unsupported-verbs)
                                   (remove #(str/includes? text %))
                                   vec)
        has-browser-global? (str/includes? text "BitechoLightNode")
        stale-count? (boolean (re-find #"(?i)\b19\s+verbs\b|\b25\s+flags\b" text))
        errors (cond-> []
                 (seq missing-canonical)
                 (conj (str "Missing canonical CLI verbs in SKILL.md: " (pr-str missing-canonical)))
                 (seq missing-flags)
                 (conj (str "Missing live CLI flags in SKILL.md: " (pr-str missing-flags)))
                 (not has-browser-global?)
                 (conj "SKILL.md missing BitechoLightNode browser console CLI reference")
                 (seq missing-browser-unsup)
                 (conj (str "SKILL.md missing browser-unsupported verb listing: " (pr-str missing-browser-unsup)))
                 stale-count?
                 (conj "SKILL.md contains stale hardcoded 19-verb / 25-flag count"))
        diags (mapv #(diag :skill-inventory-drift %) errors)]
    {:ok? (empty? errors)
     :live-canonical-verb-count (count cli/canonical-cli-verbs)
     :live-legacy-verb-count (count cli/supported-cli-verbs)
     :live-flag-count (count cli/known-command-flags)
     :missing-canonical-verbs missing-canonical
     :missing-flags missing-flags
     :missing-browser-unsupported missing-browser-unsup
     :errors errors
     :diagnostics diags}))

;; =============================================================================
;; 4. S-D41-3: Docs Link & Staleness Linter + BIP Index Coverage
;; =============================================================================

(def ^:private local-file-url-pattern
  #"file:///(?:home|Users|tmp|root|var)/[^\s\)\"'>]+")

(def ^:private default-stale-patterns
  [{:id :state-nippy :regex #"state\.nippy" :message "Stale state.nippy reference (replaced by state.fressian)"}
   {:id :build-sea :regex #"build-sea\.sh" :message "Stale build-sea.sh SEA binary reference (replaced by Node.js .cjs bundles)"}])

(defn lint-doc-links
  "Pure linter over `{doc-path markdown-text}` map (S-D41-3 / P-DOCS-3).
   Options:
   - `:forbid-stale-in`: set of doc paths where stale patterns (`state.nippy`, `build-sea.sh`) are rejected.
   Returns `{:ok? bool :hardcoded-local-links [...] :stale-references [...] :diagnostics [...]}`."
  ([docs-map] (lint-doc-links docs-map {}))
  ([docs-map {:keys [forbid-stale-in]}]
   (let [forbid-set (set (or forbid-stale-in #{}))
         sorted-docs (sort-by key docs-map)
         local-hits (vec (for [[path content] sorted-docs
                               m (re-seq local-file-url-pattern (or content ""))]
                           {:path path :url m}))
         stale-hits (vec (for [[path content] sorted-docs
                               :when (contains? forbid-set path)
                               {:keys [id regex message]} default-stale-patterns
                               :when (re-find regex (or content ""))]
                           {:path path :pattern id :message message}))
         diags (vec (concat (map #(diag :hardcoded-local-file-link (str (:path %) ": " (:url %))) local-hits)
                            (map #(diag :stale-doc-reference (str (:path %) ": " (:message %))) stale-hits)))]
     {:ok? (and (empty? local-hits) (empty? stale-hits))
      :hardcoded-local-links local-hits
      :stale-references stale-hits
      :diagnostics diags})))

(defn check-bip-index-coverage
  "Verifies that `index-md` (`docs/bips/INDEX.md`) references every committed BIP filename
   and its exact 64-char SHA-256 CID (S-D41-3 / P-DOCS-3)."
  [index-md bip-entries]
  (let [text (or index-md "")
        missing-files (->> bip-entries
                           (remove #(str/includes? text (:filename %)))
                           (mapv :filename))
        missing-cids (->> bip-entries
                          (remove #(and (valid-sha256-cid? (:cid %))
                                        (str/includes? text (:cid %))))
                          (mapv #(select-keys % [:filename :cid])))
        errors (cond-> []
                 (seq missing-files) (conj (str "Missing BIP filenames in docs/bips/INDEX.md: " (pr-str missing-files)))
                 (seq missing-cids) (conj (str "Missing or mismatched 64-char CIDs in docs/bips/INDEX.md: " (pr-str missing-cids))))
        diags (mapv #(diag :bip-index-gap %) errors)]
    {:ok? (empty? errors)
     :missing-files missing-files
     :missing-cids missing-cids
     :errors errors
     :diagnostics diags}))

;; =============================================================================
;; 5. S-D41-4: Canonical Channel Migration Readiness Evaluator
;; =============================================================================

(defn evaluate-channel-migration-readiness
  "Pure evaluator for legacy channel (`chat/simon-nexus-axiom`) deprecation readiness (S-D41-4 / P-CHAN-1).
   Input:
   {:participants [{:id \"axiom\" :role :agent :subscribed-subnets #{\"bitecho.org/team\" ...}}]
    :dual-post-soak {:verified-deliveries N :missed-deliveries M :window-hours H}
    :closing-pin-posted? bool}
   Returns `{:ok? bool :ready-to-deprecate? bool :missing-subscriptions [...] :errors [...] :diagnostics [...]}`."
  [{:keys [participants dual-post-soak closing-pin-posted?]}]
  (let [by-id (into {} (map (fn [p] [(:id p) p]) participants))
        missing-participants (->> (sort required-migration-participants)
                                  (remove #(contains? by-id %))
                                  vec)
        missing-subs (vec
                      (for [pid (sort required-migration-participants)
                            :let [p (get by-id pid)
                                  subs (set (:subscribed-subnets p))]
                            :when p
                            ch (sort canonical-required-channels)
                            :when (not (contains? subs ch))]
                        {:participant pid :missing-channel ch}))
        verified (or (:verified-deliveries dual-post-soak) 0)
        missed (or (:missed-deliveries dual-post-soak) 0)
        errors (cond-> []
                 (seq missing-participants)
                 (conj (str "Missing required migration participants: " (pr-str missing-participants)))
                 (seq missing-subs)
                 (conj (str "Participants missing required canonical channel subscriptions: " (pr-str missing-subs)))
                 (<= verified 0)
                 (conj "Dual-post soak window has zero verified deliveries")
                 (pos? missed)
                 (conj (str "Dual-post soak window recorded " missed " missed deliveries"))
                 (not closing-pin-posted?)
                 (conj (str "Final closing pin not yet posted on " legacy-deprecated-channel)))
        diags (mapv #(diag :channel-migration-blocked %) errors)]
    {:ok? (empty? errors)
     :ready-to-deprecate? (empty? errors)
     :missing-participants missing-participants
     :missing-subscriptions missing-subs
     :errors errors
     :diagnostics diags}))

;; =============================================================================
;; 6. S-D41-5: Automated dist/* & web/app/* Pointer-Bump Release Gate
;; =============================================================================

(def required-release-pointers
  "Canonical on-network pointers that override local disk and MUST be bumped on release."
  ["dist/bitecho-light-node.cjs"
   "dist/bitecho-browser.js"
   "dist/bitecho-full-node.cjs"
   "web/app/bitecho-browser.js"
   "web/app/index.html"])

(defn evaluate-pointer-bump-gate
  "Pure release-gate evaluator for automated signed `dist/*` and `web/app/*` pointer bumps (S-D41-5 / P-DOCS-1).
   Verifies:
   1. `landing-version` == `cluster-version` (non-blank).
   2. Every required pointer has strictly increasing `:seq` (> prior `:seq`).
   3. Every required pointer `:target-cid` is a valid 64-char SHA-256 matching `built-artifacts`.
   Returns `{:ok? bool :errors [...] :diagnostics [...]}`."
  [{:keys [cluster-version landing-version built-artifacts prior-pointers bumped-pointers]}]
  (let [ver-issues (when (or (str/blank? (str cluster-version))
                             (str/blank? (str landing-version))
                             (not= (str/trim (str cluster-version))
                                   (str/trim (str landing-version))))
                     [[:version-mismatch
                       (str "Landing version (" (pr-str landing-version)
                            ") does not match cluster version (" (pr-str cluster-version) ")")]])
        ptr-issues (mapcat
                    (fn [p]
                      (let [expected-cid (get built-artifacts p)
                            prior-seq (or (get-in prior-pointers [p :seq]) 0)
                            bumped (get bumped-pointers p)
                            new-seq (:seq bumped)
                            new-cid (:target-cid bumped)]
                        (cond-> []
                          (not (valid-sha256-cid? expected-cid))
                          (conj [:missing-built-artifact (str "Built artifact SHA-256 missing or invalid for " p)])
                          (not (and (integer? new-seq) (> new-seq prior-seq)))
                          (conj [:stale-pointer-seq (str "Pointer " p " seq (" (pr-str new-seq) ") must be > prior seq (" prior-seq ")")])
                          (not (and (valid-sha256-cid? new-cid) (= new-cid expected-cid)))
                          (conj [:pointer-cid-mismatch (str "Pointer " p " target-cid (" (pr-str new-cid) ") != built SHA-256 (" (pr-str expected-cid) ")")]))))
                    required-release-pointers)
        all-issues (vec (concat ver-issues ptr-issues))]
    {:ok? (empty? all-issues)
     :errors (mapv second all-issues)
     :diagnostics (mapv (fn [[k msg]] (diag k msg)) all-issues)}))
