(ns bitecho.d41-bip015-governance-and-docs-test
  "Milestone D41 (BIP-015): Sociocratic Governance Formalization, Canonical Broadcast Channels,
   and Repository Documentation Cleanup.
   Covers S-D41-1 through S-D41-5 with Rule 1 generative test.check properties and live repo checks."
  (:require [bitecho.browser-cli :as browser-cli]
            [bitecho.governance.integrity :as integrity]
            [bitecho.light-node.cli :as cli]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.nio.file Files]
           [java.security MessageDigest]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- sha256-file-hex
  [^File f]
  (let [md (MessageDigest/getInstance "SHA-256")
        bs (Files/readAllBytes (.toPath f))
        digest (.digest md bs)]
    (apply str (map #(format "%02x" (bit-and % 0xff)) digest))))

(def ^:private gen-hex-char
  (gen/elements (vec "0123456789abcdef")))

(def ^:private gen-cid64
  (gen/fmap #(apply str %) (gen/vector gen-hex-char 64)))

(def ^:private gen-short-cid
  (gen/fmap #(apply str %) (gen/vector gen-hex-char 8 32)))

(defn- valid-sample-stage2-receipt
  [parent-cid patch-cid bundle-cid]
  {:bip-id "BIP-099"
   :version "v0.23.99"
   :milestone "D99"
   :bip/status :consented
   :bip/parent-bip-cid parent-cid
   :consent-records [{:agent "simon" :role :human-anchor :verdict :consented}
                     {:agent "axiom" :role :architect :verdict :consented-with-flags}
                     {:agent "nexus" :role :builder-lead :verdict :consented}
                     {:agent "vector" :role :soak-tester :verdict :consented}
                     {:agent "lumen" :role :research-lead :verdict :consented}]
   :flag-resolutions {:F-1 "Resolved pre-commit in final EDN"}
   :oracle-receipts {:deterministic-bundle-sha256 bundle-cid}
   :code-artifact {:patch-path "dist/bips/bip-099-v02399.patch"
                   :patch-cid patch-cid
                   :patch-size-bytes 4096}})

;; =============================================================================
;; Generative Properties (Rule 1 Strict TDD)
;; =============================================================================

(defspec ^{:doc "S-D41-1 Property: Valid 64-char CIDs & complete consents pass; short CIDs, :pending, nil patch, or unresolved flags fail loudly with :diagnose."}
  prop-bip-receipt-cid-and-consent-integrity 50
  (prop/for-all [parent-cid gen-cid64
                 patch-cid gen-cid64
                 bundle-cid gen-cid64
                 short-cid gen-short-cid]
                (let [good (valid-sample-stage2-receipt parent-cid patch-cid bundle-cid)
                      res-good (integrity/validate-bip-receipt good {:require-patch? true
                                                                     :require-5-consents? true})
                      bad-short (assoc good :bip/parent-bip-cid short-cid)
                      res-short (integrity/validate-bip-receipt bad-short {:require-patch? true})
                      bad-pending (assoc-in good [:consent-records 0 :verdict] :pending)
                      res-pending (integrity/validate-bip-receipt bad-pending {:require-patch? true})
                      bad-patch (assoc-in good [:code-artifact :patch-cid] nil)
                      res-patch (integrity/validate-bip-receipt bad-patch {:require-patch? true})
                      bad-unresolved (dissoc good :flag-resolutions)
                      res-unresolved (integrity/validate-bip-receipt bad-unresolved {:require-patch? true})]
                  (and (true? (:ok? res-good))
                       (empty? (:errors res-good))
                       (false? (:ok? res-short))
                       (pos? (count (:diagnostics res-short)))
                       (false? (:ok? res-pending))
                       (pos? (count (:diagnostics res-pending)))
                       (false? (:ok? res-patch))
                       (pos? (count (:diagnostics res-patch)))
                       (false? (:ok? res-unresolved))
                       (pos? (count (:diagnostics res-unresolved)))))))

(defspec ^{:doc "S-D41-3 Property: Doc link linter always catches hardcoded file:///home/ or file:///Users/ links and emits counted :diagnose."}
  prop-doc-link-lint-rejects-local-file-urls 50
  (prop/for-all [user (gen/not-empty gen/string-alphanumeric)
                 fname (gen/not-empty gen/string-alphanumeric)]
                (let [bad-md (str "See [Spec](file:///home/" user "/repo/" fname ".md) for details.")
                      good-md (str "See [Spec](docs/" fname ".md) for details.")
                      res-bad (integrity/lint-doc-links {"docs/README.md" bad-md} {})
                      res-good (integrity/lint-doc-links {"docs/README.md" good-md} {})]
                  (and (false? (:ok? res-bad))
                       (= 1 (count (:hardcoded-local-links res-bad)))
                       (pos? (count (:diagnostics res-bad)))
                       (true? (:ok? res-good))
                       (empty? (:hardcoded-local-links res-good))))))

(defspec ^{:doc "S-D41-2 Property: Dropping any live CLI flag from SKILL.md is always detected as drift."}
  prop-skill-flag-inventory-drift-detection 30
  (prop/for-all [idx (gen/choose 0 (dec (count cli/known-command-flags)))]
                (let [omitted-flag (nth cli/known-command-flags idx)
                      kept-flags (remove #(= % omitted-flag) cli/known-command-flags)
                      synthetic-md (str "# SKILL\n"
                                        (str/join " " (map #(str "`" % "`") cli/canonical-cli-verbs)) "\n"
                                        (str/join " " kept-flags) "\n"
                                        "BitechoLightNode unsupported: serve daemon mcp\n")
                      res (integrity/check-skill-inventory-parity synthetic-md)]
                  (and (false? (:ok? res))
                       (contains? (set (:missing-flags res)) omitted-flag)
                       (pos? (count (:diagnostics res)))))))

(defspec ^{:doc "S-D41-4 Property: Channel migration readiness requires all participants subscribed, zero missed soak deliveries, and closing pin."}
  prop-channel-migration-readiness-invariants 40
  (prop/for-all [verified (gen/choose 1 50)
                 missed (gen/choose 1 10)]
                (let [all-subs #{"bitecho.org/team" "bitecho.org/dev" "bitecho.org/ops"}
                      participants [{:id "axiom" :role :agent :subscribed-subnets all-subs}
                                    {:id "nexus" :role :agent :subscribed-subnets all-subs}
                                    {:id "vector" :role :agent :subscribed-subnets all-subs}
                                    {:id "lumen" :role :agent :subscribed-subnets all-subs}
                                    {:id "simon" :role :browser-node :subscribed-subnets all-subs}
                                    {:id "watcher" :role :bridge :subscribed-subnets all-subs}]
                      ready-res (integrity/evaluate-channel-migration-readiness
                                 {:participants participants
                                  :dual-post-soak {:verified-deliveries verified
                                                   :missed-deliveries 0
                                                   :window-hours 24}
                                  :closing-pin-posted? true})
                      missed-res (integrity/evaluate-channel-migration-readiness
                                  {:participants participants
                                   :dual-post-soak {:verified-deliveries verified
                                                    :missed-deliveries missed
                                                    :window-hours 24}
                                   :closing-pin-posted? true})
                      unsub-res (integrity/evaluate-channel-migration-readiness
                                 {:participants (assoc-in participants [0 :subscribed-subnets] #{"bitecho.org/dev"})
                                  :dual-post-soak {:verified-deliveries verified
                                                   :missed-deliveries 0
                                                   :window-hours 24}
                                  :closing-pin-posted? true})]
                  (and (true? (:ready-to-deprecate? ready-res))
                       (false? (:ready-to-deprecate? missed-res))
                       (pos? (count (:diagnostics missed-res)))
                       (false? (:ready-to-deprecate? unsub-res))
                       (pos? (count (:diagnostics unsub-res)))))))

(defspec ^{:doc "S-D41-5 Property: Pointer-bump gate requires strictly increasing seq and exact 64-char SHA match with landing version."}
  prop-pointer-bump-gate-monotonic-seq-and-sha-match 40
  (prop/for-all [prior-seq (gen/choose 1 1000)
                 cid-light gen-cid64
                 cid-browser gen-cid64
                 cid-full gen-cid64
                 cid-index gen-cid64
                 wrong-cid gen-cid64]
                (let [built {"dist/bitecho-light-node.cjs" cid-light
                             "dist/bitecho-browser.js" cid-browser
                             "dist/bitecho-full-node.cjs" cid-full
                             "web/app/bitecho-browser.js" cid-browser
                             "web/app/index.html" cid-index}
                      prior (into {} (map (fn [[k _]] [k {:seq prior-seq}]) built))
                      bumped (into {} (map (fn [[k cid]] [k {:seq (inc prior-seq) :target-cid cid}]) built))
                      ok-res (integrity/evaluate-pointer-bump-gate
                              {:cluster-version "v0.23.18"
                               :landing-version "v0.23.18"
                               :built-artifacts built
                               :prior-pointers prior
                               :bumped-pointers bumped})
                      stale-seq-res (integrity/evaluate-pointer-bump-gate
                                     {:cluster-version "v0.23.18"
                                      :landing-version "v0.23.18"
                                      :built-artifacts built
                                      :prior-pointers prior
                                      :bumped-pointers (assoc-in bumped ["dist/bitecho-light-node.cjs" :seq] prior-seq)})
                      mismatch-ver-res (integrity/evaluate-pointer-bump-gate
                                        {:cluster-version "v0.23.18"
                                         :landing-version "v0.23.17"
                                         :built-artifacts built
                                         :prior-pointers prior
                                         :bumped-pointers bumped})
                      mismatch-cid-res (when (not= cid-light wrong-cid)
                                         (integrity/evaluate-pointer-bump-gate
                                          {:cluster-version "v0.23.18"
                                           :landing-version "v0.23.18"
                                           :built-artifacts built
                                           :prior-pointers prior
                                           :bumped-pointers (assoc-in bumped ["dist/bitecho-light-node.cjs" :target-cid] wrong-cid)}))]
                  (and (true? (:ok? ok-res))
                       (false? (:ok? stale-seq-res))
                       (false? (:ok? mismatch-ver-res))
                       (or (= cid-light wrong-cid)
                           (false? (:ok? mismatch-cid-res)))))))

;; =============================================================================
;; Concrete Repository Gate Tests (S-D41-1 .. S-D41-5)
;; =============================================================================

(deftest test-s-d41-1-committed-bip-receipt-and-cid-integrity
  (testing "BIP-015 Stage-1 EDN is committed with exact canonical CID and zero :pending consent records"
    (let [f (io/file "docs/bips/bip-015-D41.edn")]
      (is (.exists f) "docs/bips/bip-015-D41.edn must exist")
      (is (= "bb2747ade85584de02e9d596b013ded0ffe5f58abe81e9e35987a5c762cc8fce"
             (sha256-file-hex f))
          "Committed bip-015-D41.edn must preserve exact Stage-1 unanimously consented CID")
      (let [doc (edn/read-string (slurp f))
            res (integrity/validate-bip-receipt doc {:require-patch? false
                                                     :require-5-consents? true})]
        (is (true? (:ok? res)) (str "BIP-015 validation errors: " (:errors res)))
        (is (= "D41" (:milestone doc))))))

  (testing "BIP-013 & BIP-014 committed receipts pass CID and zero-:pending checks"
    (doseq [path ["docs/bips/bip-013-v02316.edn" "docs/bips/bip-014-v02317.edn"]]
      (let [doc (edn/read-string (slurp path))
            require-patch? (some? (:code-artifact doc))
            res (integrity/validate-bip-receipt doc {:require-patch? require-patch?
                                                     :require-5-consents? true})]
        (is (true? (:ok? res)) (str path " validation errors: " (:errors res))))))

  (testing "docs/GOVERNANCE.md codifies two-gate consent, verdicts, 64-char CIDs, and rollback-first SOP"
    (let [gov (slurp "docs/GOVERNANCE.md")]
      (is (str/includes? gov "CONSENT-WITH-ADDENDUM"))
      (is (str/includes? gov "PARAMOUNT-OBJECTION"))
      (is (str/includes? gov "Stage 1"))
      (is (str/includes? gov "Stage 2"))
      (is (str/includes? gov "64-char"))
      (is (str/includes? gov ":pending"))
      (is (str/includes? gov "unknown-bip"))
      (is (str/includes? gov "F-EPOCH-1")))))

(deftest test-s-d41-2-skill-md-live-cli-and-browser-inventory-parity
  (testing "skill/SKILL.md matches live bitecho.light-node.cli and bitecho.browser-cli with zero drift"
    (let [skill-md (slurp "skill/SKILL.md")
          res (integrity/check-skill-inventory-parity skill-md)]
      (is (true? (:ok? res))
          (str "SKILL.md inventory drift detected: " (pr-str res)))
      (is (empty? (:missing-canonical-verbs res)))
      (is (empty? (:missing-flags res)))
      (is (empty? (:missing-browser-unsupported res)))
      (is (str/includes? skill-md "BitechoLightNode"))
      (is (str/includes? skill-md "--auto-update-pointer"))
      (is (str/includes? skill-md "--auto-update-interval-ms"))
      (is (str/includes? skill-md "--pin-version"))
      (is (= (count cli/canonical-cli-verbs) 12))
      (is (= (count browser-cli/browser-unsupported-verbs) 3)))))

(deftest test-s-d41-3-docs-links-staleness-and-bip-index
  (testing "Repository documentation has zero hardcoded file:///home/... links and zero stale state.nippy / build-sea.sh instructions"
    (let [doc-paths ["README.md"
                     "RELEASE.md"
                     "ONBOARDING.md"
                     "docs/README.md"
                     "docs/GOVERNANCE.md"
                     "docs/CHANNELS.md"
                     "docs/SPEC.md"
                     "docs/bips/INDEX.md"
                     "skill/SKILL.md"]
          docs-map (into {} (map (fn [p] [p (slurp p)]) doc-paths))
          res (integrity/lint-doc-links docs-map {:forbid-stale-in #{"README.md" "RELEASE.md" "ONBOARDING.md" "skill/SKILL.md"}})]
      (is (true? (:ok? res))
          (str "Doc lint failures: " (pr-str res)))))

  (testing "docs/bips/INDEX.md covers every committed docs/bips/*.edn file and its exact 64-char SHA-256 CID"
    (let [index-md (slurp "docs/bips/INDEX.md")
          bip-files (->> (.listFiles (io/file "docs/bips"))
                         (filter #(str/ends-with? (.getName ^File %) ".edn"))
                         (sort-by #(.getName ^File %)))
          bip-entries (mapv (fn [^File f]
                              {:filename (.getName f)
                               :cid (sha256-file-hex f)})
                            bip-files)
          res (integrity/check-bip-index-coverage index-md bip-entries)]
      (is (true? (:ok? res))
          (str "BIP index coverage gaps: " (pr-str res)))
      (is (>= (count bip-entries) 12)))))

(deftest test-s-d41-4-canonical-channels-and-migration-docs
  (testing "docs/CHANNELS.md and ONBOARDING.md establish bitecho.org/team as primary circle channel and document legacy deprecation"
    (let [channels-md (slurp "docs/CHANNELS.md")
          onboarding-md (slurp "ONBOARDING.md")]
      (doseq [ch ["bitecho.org/team" "bitecho.org/dev" "bitecho.org/ops"
                  "bitecho.org/observability" "bitecho.org/infra" "lab-01"
                  "chat/simon-nexus-axiom"]]
        (is (str/includes? channels-md ch) (str "docs/CHANNELS.md missing " ch)))
      (is (str/includes? onboarding-md "bitecho.org/team"))
      (is (str/includes? onboarding-md "state.fressian"))
      (is (str/includes? onboarding-md "6-node")))))

(deftest test-s-d41-5-release-pointer-bump-gate-and-docs
  (testing "RELEASE.md documents Hardened Gentoo, OpenRC, Node.js bundles, P-UPD-1 shipped in D40, and pointer-bump gate"
    (let [release-md (slurp "RELEASE.md")
          cluster-sh (slurp "scripts/cluster.sh")]
      (is (str/includes? release-md "Hardened Gentoo"))
      (is (str/includes? release-md "OpenRC"))
      (is (str/includes? release-md "bitecho-full-node.cjs"))
      (is (str/includes? release-md "P-UPD-1"))
      (is (str/includes? release-md "D40.2.1"))
      (is (str/includes? release-md "bump-pointers"))
      (is (str/includes? release-md "sla/latest.edn"))
      (is (str/includes? cluster-sh "cmd_bump_pointers"))
      (is (str/includes? cluster-sh "bump-pointers")))))

(deftest values-v01-cid-drift-guard-test
  (testing "Ratified Shared Values v0.1 (5/5 consent) matches canonical CID 2b6d6a6a... bit-exact"
    (let [f (java.io.File. "docs/VALUES.md")
          expected-cid "2b6d6a6a794ef168a00184faf35d3b77efb083c24671e3ff1092a432405f9448"]
      (is (.exists f) "docs/VALUES.md must exist in repository")
      (let [bs (java.nio.file.Files/readAllBytes (.toPath f))
            md (java.security.MessageDigest/getInstance "SHA-256")
            got-cid (.formatHex (java.util.HexFormat/of) (.digest md bs))]
        (is (= 3899 (alength bs)))
        (is (= expected-cid got-cid))))))
