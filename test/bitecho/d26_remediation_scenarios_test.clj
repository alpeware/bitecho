(ns bitecho.d26-remediation-scenarios-test
  "Milestone D26 (v0.23.4) Remediation & Scenario Verification Suite (S16-S24)
   incorporating Circle and Axiom Amendments A-D26-1..5, A-CARB-D26-1..6, F-D26-1..13
   under strict TDD (Rules 1-6)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.protocol.faucet :as faucet]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.light-node :as shell]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- make-tmp-dir! ^File []
  (let [p (Files/createTempDirectory "bitecho-d26-test-" (into-array FileAttribute []))]
    (.toFile p)))

;; =============================================================================
;; Scenario S16: Accountz Fallback Removal & Fail-Closed Diagnostics
;; (F-D26-1 / F-D26-5 / A-CARB-D26-1)
;; =============================================================================

(deftest test-scenario-s16-accountz-fallback-removal-and-fail-closed
  (testing "maybe-sync-account-state! fails closed without calling :8080 when (:accountz-fetcher opts) is nil"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          pubkey (or (:pubkey-hex id) (:pubkey id))
          privkey-bytes (:privkey-bytes id)
          state-atom (atom (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"}))
          bootstrap {:nodes {:node1 {:pubkey "302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111"
                                     :ip "127.0.0.1" :port 5010}}}
          ;; opts without :accountz-fetcher, and with inband returning empty snapshots
          opts {:inband-snapshot-fetcher (fn [& _] {:ok? false :error "no-inband-snapshots-returned"})}
          res (shell/maybe-sync-account-state! state-atom bootstrap pubkey privkey-bytes opts)]
      (is (false? (:ok? res)))
      (is (= "no-inband-snapshots-returned" (or (:error res) (:reason res))))
      (is (pos? (long (get-in @state-atom [:diagnostics :account-sync-inband-failed] 0)))
          ":account-sync-inband-failed diagnostic must be incremented")
      (is (pos? (long (get-in @state-atom [:diagnostics :chain-state-sync-failed] 0)))
          ":chain-state-sync-failed diagnostic must be incremented")))

  (testing "maybe-sync-account-state! invokes (:accountz-fetcher opts) when explicitly provided"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          pubkey (or (:pubkey-hex id) (:pubkey id))
          privkey-bytes (:privkey-bytes id)
          state-atom (atom (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"}))
          bootstrap {:nodes {:node1 {:pubkey "302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111"
                                     :ip "127.0.0.1" :port 5010}}}
          fetcher-called (atom false)
          mock-fetcher (fn [_boot _pk _opts]
                         (reset! fetcher-called true)
                         {:account {:balance 5000 :seq 1 :deps []}
                          :spendable 5000
                          :finalized-epoch 1})
          opts {:accountz-fetcher mock-fetcher
                :inband-snapshot-fetcher (fn [& _] {:ok? false :error "no-inband-snapshots-returned"})}
          res (shell/maybe-sync-account-state! state-atom bootstrap pubkey privkey-bytes opts)]
      (is (true? @fetcher-called) "Explicit :accountz-fetcher mock must be invoked")
      (is (true? (:ok? res)))
      (is (= 5000 (get-in @state-atom [:account :balance]))))))

;; =============================================================================
;; Scenario S17: Second p2p-answer State & Response Preservation
;; (F-D26-2 / F-D26-4 / F-D26-9 / A-D26-2 / A-CARB-D26-2)
;; =============================================================================

(deftest test-scenario-s17-second-p2p-answer-preserves-open-state
  (testing "exec-p2p-answer preserves phase :open and connected? true when channel is already open"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          peer-kp (crypto/generate-keypair)
          peer-pub (basalt/bytes->hex (:public peer-kp))
          sid "test-open-session-sid-001"
          initial-st (-> (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
                         (assoc-in [:sessions sid]
                                   {:session-id sid
                                    :state "open"
                                    :peer peer-pub
                                    :p2p {:phase :open
                                          :connected? true
                                          :zero-burn? true
                                          :remote-candidates ["127.0.0.1:9001"]}
                                    :p2p-meta {:remote-candidates ["127.0.0.1:9001"]}}))
          answer-cmd {"cmd" "p2p-answer"
                      "session_id" sid
                      "transport" "udp"
                      "candidates" ["127.0.0.1:9002"]}
          res (light-core/handle-command initial-st answer-cmd (:privkey-bytes id))]
      ;; Response assertions
      (is (true? (get-in res [:response "ok"])))
      (is (= "open" (get-in res [:response "phase"])) "Response phase must remain 'open'")
      (is (true? (get-in res [:response "connected"])) "Response connected must remain true")
      ;; State assertions
      (let [st' (:state res)
            sess' (get-in st' [:sessions sid])]
        (is (= :open (get-in sess' [:p2p :phase])) "State phase must remain :open")
        (is (true? (get-in sess' [:p2p :connected?])) "State connected? must remain true")
        (is (true? (get-in sess' [:p2p :zero-burn?])) "State zero-burn? must remain true")
        (is (nil? (:p2p-dial res)) ":p2p-dial must be nil when already open without force_dial")
        (is (pos? (long (get-in st' [:diagnostics :duplicate-p2p-answer-ignored] 0)))
            ":duplicate-p2p-answer-ignored diagnostic must be incremented"))))

  (testing "exec-p2p-answer allows force_dial true to re-dial even if already open"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          peer-kp (crypto/generate-keypair)
          peer-pub (basalt/bytes->hex (:public peer-kp))
          sid "test-open-session-sid-002"
          initial-st (-> (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
                         (assoc-in [:sessions sid]
                                   {:session-id sid
                                    :state "open"
                                    :peer peer-pub
                                    :p2p {:phase :open
                                          :connected? true
                                          :zero-burn? true
                                          :remote-candidates ["127.0.0.1:9001"]}
                                    :p2p-meta {:remote-candidates ["127.0.0.1:9001"]}}))
          answer-cmd {"cmd" "p2p-answer"
                      "session_id" sid
                      "transport" "udp"
                      "candidates" ["127.0.0.1:9002"]
                      "force_dial" true}
          res (light-core/handle-command initial-st answer-cmd (:privkey-bytes id))]
      (is (some? (:p2p-dial res)) ":p2p-dial must be present when force_dial true is passed"))))

;; =============================================================================
;; Scenario S18: Offer-Hash :network-uri Binding & Rolling Upgrade Tolerance
;; (F-D26-2 / F-D26-3 / A-D26-1 / A-CARB-D26-4)
;; =============================================================================

(deftest test-scenario-s18-offer-hash-network-binding-and-rolling-upgrade
  (testing "compute-offer-hash and sealed/offer-hash bind :network-uri into hash preimage"
    (let [base-offer {:session-id "sid-net-binding-test"
                      :caller "caller-pubkey-hex"
                      :callee "callee-pubkey-hex"
                      :caller-ephemeral-pub "eph-pubkey-hex"
                      :epoch 10
                      :price 0
                      :home-node "node1"}
          dev-offer (assoc base-offer :network-uri "devnet.bitecho.org")
          test-offer (assoc base-offer :network-uri "testnet.bitecho.org")
          main-offer (assoc base-offer :network-uri "mainnet.bitecho.org")
          unbound-offer base-offer

          h-dev (light-core/compute-offer-hash dev-offer)
          h-test (light-core/compute-offer-hash test-offer)
          h-main (light-core/compute-offer-hash main-offer)
          h-unbound (light-core/compute-offer-hash unbound-offer)]
      ;; All 3 network hashes must be distinct from each other and from unbound
      (is (not= h-dev h-test))
      (is (not= h-dev h-main))
      (is (not= h-test h-main))
      (is (not= h-dev h-unbound))

      ;; sealed/offer-hash parity
      (is (not= (sealed/offer-hash dev-offer) (sealed/offer-hash test-offer)))
      (is (not= (sealed/offer-hash dev-offer) (sealed/offer-hash unbound-offer)))

      ;; 5-field variant parity (caller-callee-eph-epoch-burn[|dac][|net:<uri>])
      (let [h5-dev (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "caller-pubkey-hex-callee-pubkey-hex-eph-pubkey-hex-10-0|net:devnet.bitecho.org")))
            h5-test (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "caller-pubkey-hex-callee-pubkey-hex-eph-pubkey-hex-10-0|net:testnet.bitecho.org")))
            h5-unbound (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "caller-pubkey-hex-callee-pubkey-hex-eph-pubkey-hex-10-0")))]
        (is (not= h5-dev h5-test))
        (is (not= h5-dev h5-unbound)))))

  (testing "matching-offer-hash? accepts both network-bound and legacy unbound during rolling upgrade across compute-offer-hash and sealed/offer-hash"
    (let [st {:network-uri "devnet.bitecho.org" :subnet-id "devnet.bitecho.org"}
          base-offer {:session-id "sid-rolling-upgrade-test"
                      :caller "caller-pubkey-hex"
                      :callee "callee-pubkey-hex"
                      :caller-ephemeral-pub "eph-pubkey-hex"
                      :epoch 10
                      :price 0
                      :home-node "node1"}
          bound-offer (assoc base-offer :network-uri "devnet.bitecho.org")
          h-bound (light-core/compute-offer-hash bound-offer)
          h-unbound (light-core/compute-offer-hash base-offer)
          h-sealed-bound (sealed/offer-hash bound-offer)
          h-sealed-unbound (sealed/offer-hash base-offer)]
      (is (true? (light-core/matching-offer-hash? bound-offer st h-bound))
          "Must match bound compute-offer-hash")
      (is (true? (light-core/matching-offer-hash? bound-offer st h-unbound))
          "Must match legacy unbound compute-offer-hash during rolling upgrade")
      (is (true? (light-core/matching-offer-hash? bound-offer st h-sealed-bound))
          "Must match bound sealed/offer-hash")
      (is (true? (light-core/matching-offer-hash? bound-offer st h-sealed-unbound))
          "Must match legacy unbound sealed/offer-hash during rolling upgrade")))

  (testing "handle-wire-offer rejects foreign :network-uri fail-closed"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          st (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
          caller-kp (crypto/generate-keypair)
          caller-pub (basalt/bytes->hex (:public caller-kp))
          callee-pub (or (:pubkey-hex id) (:pubkey id))
          eph-pub "302a300506032b656e0321000102030405060708091011121314151617181920212223242526272829303132"
          sid (light-core/compute-session-id caller-pub callee-pub eph-pub)
          foreign-offer {:session-id sid
                         :caller caller-pub
                         :callee callee-pub
                         :caller-ephemeral-pub eph-pub
                         :epoch 0
                         :price 0
                         :burn 0
                         :home-node "node1"
                         :network-uri "mainnet.bitecho.org"} ;; Mismatched network-uri!
          off-hash (light-core/compute-offer-hash foreign-offer)
          sig (basalt/bytes->hex (crypto/sign (:private caller-kp) (fressian/utf8->bytes off-hash)))
          wire-msg (assoc foreign-offer
                          :offer-hash off-hash
                          :signature sig
                          :bitecho/type :channel-offer)
          wire-env {:bitecho/type :channel-offer
                    :event wire-msg}
          res (light-core/handle-wire-payload st (fressian/encode-wire wire-env) (:privkey-bytes id))]
      (is (empty? (get-in res [:state :pending-offers]))
          "Foreign network-uri offer MUST be rejected fail-closed")
      (is (pos? (long (get-in res [:state :diagnostics :network-replay-rejected] 0)))
          ":network-replay-rejected diagnostic must be incremented"))))

;; =============================================================================
;; Scenario S19: BIP-000 Charter & Strict Admission Validation
;; (F-D26-1)
;; =============================================================================

(deftest test-scenario-s19-bip-000-charter-and-strict-admission
  (testing "BIP-000 charter EDN specification loads and passes validation"
    (let [charter-file (io/file "docs/bips/bip-000-charter.edn")]
      (is (.exists charter-file) "docs/bips/bip-000-charter.edn must exist")
      (let [bip (edn/read-string (slurp charter-file))]
        (is (= "BIP-000" (:bip-id bip)))
        (is (map? (:jurisdiction-map bip)))
        (is (= "2027-06-30" (:human-anchor-sunset bip)))
        (is (map? (:invariant-diff bip)))
        (is (seq (:defspec-vars (:invariant-diff bip))))
        (is (true? (:sans-io-pure? (:invariant-diff bip))))
        (is (true? (:diagnose-coverage? (:invariant-diff bip))))
        (is (true? (:co-committed-spec-and-flags? (:invariant-diff bip))))
        (is (map? (:oracle-receipts bip)))
        (is (true? (get-in bip [:oracle-receipts :four-way-golden-oracle :passed?])))
        (is (true? (get-in bip [:oracle-receipts :vopr-jepsen-non-vacuity :passed?])))
        (is (string? (get-in bip [:oracle-receipts :deterministic-bundle-sha256])))
        (is (not= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                  (get-in bip [:oracle-receipts :deterministic-bundle-sha256]))
            "BIP-000 bundle SHA-256 must be a real bundle hash, never the empty-input hash")
        (is (true? (get-in bip [:oracle-receipts :bwrap-civilization-regression :passed?])))
        (let [gate-res (gov/verify-bip-admission-gates bip)]
          (is (true? (:ok? gate-res)) (str "BIP-000 admission gates must pass: " (:missing-gates gate-res)))))))

  (testing "exec-bip-submit has zero fabricated passing defaults and admits BIP-000 with explicit spec"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          st (-> (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
                 (assoc-in [:account :balance] 10000)
                 (assoc-in [:account :spendable] 10000))
          ;; 1. Submitting without spec_edn fails closed unconditionally (no fabricated defaults)
          cmd-empty {"cmd" "bip-submit"
                     "bip_id" "BIP-999"
                     "title" "Unadmitted BIP Without Spec"
                     "burn" 100}
          res-empty (light-core/handle-command st cmd-empty (:privkey-bytes id))
          ;; 2. Submitting BIP-000 with explicit charter spec succeeds
          charter-edn-str (slurp "docs/bips/bip-000-charter.edn")
          cmd-charter {"cmd" "bip-submit"
                       "bip_id" "BIP-000"
                       "subnet_id" "devnet.bitecho.org"
                       "spec_edn" charter-edn-str
                       "burn" 100}
          res-charter (light-core/handle-command st cmd-charter (:privkey-bytes id))]
      (is (false? (get-in res-empty [:response "ok"])))
      (is (= "bip-admission-rejected" (get-in res-empty [:response "error"])))
      (is (seq (get-in res-empty [:response "missing_gates"])))
      (is (pos? (long (get-in res-empty [:state :diagnostics :bip-admission-rejected] 0))))
      (is (true? (get-in res-charter [:response "ok"])))
      (is (= "BIP-000" (get-in res-charter [:response "bip_id"])))
      (is (= "under-review" (get-in res-charter [:response "status"])))
      ;; 3. Verify bip-consent emits integer (long) :weight in :bip-response and replicates cleanly across Fressian roundtrip
      (let [st-after-sub (:state res-charter)
            consent-res (light-core/handle-command
                         st-after-sub
                         {"cmd" "bip-consent"
                          "bip_id" "BIP-000"
                          "subnet_id" "devnet.bitecho.org"
                          "circle" "builders-stewards"
                          "weight" 12
                          "burn" 100}
                         (:privkey-bytes id))
            rep-env (first (:net-envelopes consent-res))
            peer-dir (make-tmp-dir!)
            peer-id (shell/load-or-create-light-identity! (str peer-dir))
            peer-st0 (-> (light-core/init-light-state peer-id {:subnet-id "devnet.bitecho.org"})
                         (light-core/handle-wire-payload (fressian/encode-wire (first (:net-envelopes res-charter))) (:privkey-bytes peer-id))
                         :state)
            ;; Simulate JS/Node.js Fressian roundtrip where :weight is integer long 12
            wire-bytes (fressian/encode-wire rep-env)
            peer-res (light-core/handle-wire-payload peer-st0 wire-bytes (:privkey-bytes peer-id))]
        (is (integer? (get-in rep-env [:body :weight]))
            ":weight in :bip-response body must be a long integer for JVM/Node.js Fressian parity")
        (is (= 12 (get-in rep-env [:body :weight])))
        (is (zero? (long (get-in peer-res [:state :diagnostics :governance-replication-rejected] 0)))
            "Peer must verify :bip-response signature without governance-replication-rejected")))))

;; =============================================================================
;; Scenario S20: Release Proof Generator & Deploy Gate R7
;; (F-D26-3 / F-D26-6 / A-CARB-D26-3)
;; =============================================================================

(deftest test-scenario-s20-release-proof-generator-and-deploy-gate
  (testing "config/version is 0.23.4..0.23.9 and config/legacy-unbound-offer-hash-sunset is defined"
    (is (contains? #{"0.23.4" "0.23.5" "0.23.6" "0.23.7" "0.23.8" "0.23.9"} config/version))
    (is (= "2026-12-31" config/legacy-unbound-offer-hash-sunset)))

  (testing "scripts/cluster.sh and scripts/infra_cluster.sh contain verify_release_proof_gate"
    (let [c-sh (slurp "scripts/cluster.sh")
          ic-sh (slurp "scripts/infra_cluster.sh")]
      (is (str/includes? c-sh "verify_release_proof_gate"))
      (is (str/includes? c-sh "RELEASE_PROOF"))
      (is (str/includes? ic-sh "verify_release_proof_gate"))
      (is (str/includes? ic-sh "RELEASE_PROOF")))))

;; =============================================================================
;; Scenario S21: Multi-Cluster Network Profiles & Parameterization
;; (F-D26-7)
;; =============================================================================

(deftest test-scenario-s21-multi-cluster-network-profiles
  (testing "ops/networks profile files exist for devnet, testnet, and mainnet"
    (doseq [net ["devnet" "testnet" "mainnet"]]
      (let [f (io/file (str "ops/networks/" net ".env"))]
        (is (.exists f) (str f " must exist"))
        (let [content (slurp f)]
          (is (str/includes? content "NETWORK_URI="))
          (is (str/includes? content "GCP_PROJECT="))
          (is (str/includes? content "BOOTSTRAP_FILE="))
          (is (str/includes? content "TREASURY_PUBKEY="))))))

  (testing "scripts/cluster.sh and scripts/infra_cluster.sh parse --network and --project"
    (let [c-sh (slurp "scripts/cluster.sh")
          ic-sh (slurp "scripts/infra_cluster.sh")]
      (is (str/includes? c-sh "--network"))
      (is (str/includes? c-sh "--project"))
      (is (str/includes? ic-sh "--network"))
      (is (str/includes? ic-sh "--project")))))

;; =============================================================================
;; Scenario S22: Daemon Bridge Additions: wait-event & --min-balance Guard
;; (F-D26-8 / A-D26-4)
;; =============================================================================

(deftest test-scenario-s22-wait-event-broadcast-and-min-balance-guard
  (testing "cli/known-command-flags includes --min-broadcast-seq and --min-balance"
    (is (contains? (set cli/known-command-flags) "--min-broadcast-seq"))
    (is (contains? (set cli/known-command-flags) "--min-balance")))

  (testing "handle-command enforces --min-balance pre-transition guard on burn commands"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          st (-> (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
                 (assoc-in [:account :balance] 150)
                 (assoc-in [:account :spendable] 150))
          ;; Attempt broadcast burning 100 with min-balance 100: (150 - 100) = 50 < 100 -> REJECT!
          cmd {"cmd" "broadcast"
               "text" "test min balance guard"
               "burn" 100
               "min_balance" 100}
          res (light-core/handle-command st cmd (:privkey-bytes id))]
      (is (false? (get-in res [:response "ok"])))
      (is (= "below-min-balance" (get-in res [:response "error"])))
      (is (= 150 (get-in res [:response "spendable"])))
      (is (= 100 (get-in res [:response "required_burn"])))
      (is (= 100 (get-in res [:response "min_balance"])))
      ;; Balance must not be deducted
      (is (= 150 (get-in res [:state :account :spendable])))
      ;; Diagnostics and stdout events
      (is (pos? (long (get-in res [:state :diagnostics :below-min-balance-rejected] 0))))
      (let [events (:stdout-events res)]
        (is (some #(= "budget-floor-reached" (get % "event")) events)))))

  (testing "handle-command allows burn command when spendable minus burn >= min-balance"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          st (-> (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
                 (assoc-in [:account :balance] 250)
                 (assoc-in [:account :spendable] 250))
          ;; Attempt broadcast burning 100 with min-balance 100: (250 - 100) = 150 >= 100 -> ACCEPT!
          cmd {"cmd" "broadcast"
               "text" "test min balance allowed"
               "burn" 100
               "min_balance" 100}
          res (light-core/handle-command st cmd (:privkey-bytes id))]
      (is (true? (get-in res [:response "ok"])))
      (is (= 150 (get-in res [:state :account :spendable]))))))

;; =============================================================================
;; Scenario S23: Treasury-Managed Hardware-Key Faucet, Directory & Blog
;; (F-D26-11 / F-D26-12 / A-D26-3 / A-CARB-D26-5)
;; =============================================================================

(deftest test-scenario-s23-treasury-faucet-directory-and-blog
  (testing "faucet/issue-faucet-challenge generates 60s challenge bound to network-uri"
    (let [st (faucet/init-faucet-state {:network-uri "devnet.bitecho.org"})
          c-res (faucet/issue-faucet-challenge st {:network-uri "devnet.bitecho.org"} 1000000)
          challenge (:challenge c-res)]
      (is (string? (:nonce challenge)))
      (is (= "devnet.bitecho.org" (:network-uri challenge)))
      (is (= 1060000 (:expires-at challenge)) "60 second TTL")))

  (testing "faucet/reduce-faucet-claim rejects expired challenges"
    (let [st (faucet/init-faucet-state {:network-uri "devnet.bitecho.org"})
          c-res (faucet/issue-faucet-challenge st {:network-uri "devnet.bitecho.org"} 1000000)
          st' (:state c-res)
          nonce (get-in c-res [:challenge :nonce])
          claim-req {:nonce nonce
                     :network-uri "devnet.bitecho.org"
                     :claimant-pubkey "302a300506032b6570032100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                     :credential-id-hash "cred-hash-001"}
          res (faucet/reduce-faucet-claim st' claim-req 1060001)] ;; 1ms after expiry!
      (is (false? (:ok? res)))
      (is (= :faucet-challenge-expired (:error res)))
      (is (pos? (long (get-in res [:state :diagnostics :faucet-challenge-expired] 0))))))

  (testing "faucet/reduce-faucet-claim rejects duplicate claims for same credential id"
    (let [treasury-kp (crypto/generate-keypair)
          st (faucet/init-faucet-state {:network-uri "devnet.bitecho.org"
                                        :treasury-privkey (:private treasury-kp)
                                        :treasury-pubkey (basalt/bytes->hex (:public treasury-kp))
                                        :drip-amount-ech 1000000})
          ;; Claim 1
          c-res1 (faucet/issue-faucet-challenge st {:network-uri "devnet.bitecho.org"} 1000000)
          claim-req1 {:nonce (get-in c-res1 [:challenge :nonce])
                      :network-uri "devnet.bitecho.org"
                      :claimant-pubkey "302a300506032b6570032100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                      :credential-id-hash "cred-hash-unique-001"
                      :authenticator-verified? true}
          res1 (faucet/reduce-faucet-claim (:state c-res1) claim-req1 1010000)]
      (is (true? (:ok? res1)))
      (is (= 1000000 (get-in res1 [:transfer-intent :amount])))
      (is (= "faucet/devnet.bitecho.org/claims/cred-hash-unique-001" (:receipt-path res1)))

      ;; Claim 2 with same credential ID must be rejected
      (let [c-res2 (faucet/issue-faucet-challenge (:state res1) {:network-uri "devnet.bitecho.org"} 1020000)
            claim-req2 {:nonce (get-in c-res2 [:challenge :nonce])
                        :network-uri "devnet.bitecho.org"
                        :claimant-pubkey "302a300506032b6570032100cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        :credential-id-hash "cred-hash-unique-001" ;; Duplicate!
                        :authenticator-verified? true}
            res2 (faucet/reduce-faucet-claim (:state c-res2) claim-req2 1025000)]
        (is (false? (:ok? res2)))
        (is (= :faucet-credential-already-claimed (:error res2)))
        (is (pos? (long (get-in res2 [:state :diagnostics :faucet-credential-already-claimed] 0))))))))

;; =============================================================================
;; Scenario S24: SEA Build Script & SKILL.md Re-Grounding
;; (Direction 3)
;; =============================================================================

(deftest test-scenario-s24-sea-build-script-and-skill-regrounding
  (testing "scripts/build-sea.sh exists, is executable, and contains SEA configurations"
    (let [sea-sh (io/file "scripts/build-sea.sh")]
      (is (.exists sea-sh) "scripts/build-sea.sh must exist")
      (is (.canExecute sea-sh) "scripts/build-sea.sh must be executable (chmod +x)")
      (let [content (slurp sea-sh)]
        (is (str/includes? content "sea-config.json"))
        (is (str/includes? content "disableExperimentalSEAWarning"))
        (is (str/includes? content "useCodeCache")))))

  (testing "skill/SKILL.md documents v0.23.4 additions"
    (let [skill-md (slurp "skill/SKILL.md")]
      (is (str/includes? skill-md "--min-broadcast-seq"))
      (is (str/includes? skill-md "--min-balance"))
      (is (str/includes? skill-md "bip-submit"))
      (is (str/includes? skill-md "bip-consent"))
      (is (str/includes? skill-md "bip-status")))))

;; =============================================================================
;; Generative Invariant Properties (Rules 1 & 2)
;; =============================================================================

(defspec ^{:doc "Property: 5-field offer hash strictly binds network-uri while matching-offer-hash? supports rolling upgrade interop with legacy unbound hashes until sunset date."}
  prop-offer-hash-network-binding-and-rolling-upgrade 50
  (prop/for-all [sid gen/string-alphanumeric
                 caller gen/string-alphanumeric
                 callee gen/string-alphanumeric
                 eph gen/string-alphanumeric
                 epoch gen/nat
                 net-a (gen/elements ["devnet.bitecho.org" "testnet.bitecho.org" "mainnet.bitecho.org"])
                 net-b (gen/elements ["devnet.bitecho.org" "testnet.bitecho.org" "mainnet.bitecho.org"])]
                (let [base {:session-id sid :caller caller :callee callee :caller-ephemeral-pub eph :epoch epoch :price 0}
                      ha (light-core/compute-offer-hash (assoc base :network-uri net-a))
                      hb (light-core/compute-offer-hash (assoc base :network-uri net-b))
                      hunbound (light-core/compute-offer-hash base)
                      st {:network-uri net-a :subnet-id net-a}]
                  (and (if (= net-a net-b)
                         (= ha hb)
                         (not= ha hb))
                       (not= ha hunbound)
                       (light-core/matching-offer-hash? (assoc base :network-uri net-a) st ha)
                       (light-core/matching-offer-hash? (assoc base :network-uri net-a) st hunbound)))))

(defonce ^:private prop-test-kp (crypto/generate-keypair "d26-prop-min-balance"))

(defspec ^{:doc "Property: Min-balance budget floor guard halts burn-bearing commands pre-transition without mutating account balance."}
  prop-min-balance-budget-floor-invariant 50
  (prop/for-all [initial-bal (gen/choose 100 10000)
                 required-burn (gen/choose 10 200)
                 min-bal (gen/choose 50 5000)]
                (let [id {:pubkey (basalt/bytes->hex (:public prop-test-kp))
                          :privkey-bytes (:private prop-test-kp)}
                      st (-> (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
                             (assoc-in [:account :balance] initial-bal)
                             (assoc-in [:account :spendable] initial-bal))
                      cmd {"cmd" "broadcast"
                           "text" "prop test"
                           "burn" required-burn
                           "min_balance" min-bal}
                      res (light-core/handle-command st cmd (:privkey-bytes id))
                      expected-reject? (< (- initial-bal required-burn) min-bal)]
                  (if expected-reject?
                    (and (false? (get-in res [:response "ok"]))
                         (= "below-min-balance" (get-in res [:response "error"]))
                         (= initial-bal (get-in res [:state :account :spendable])))
                    (and (true? (get-in res [:response "ok"]))
                         (= (- initial-bal required-burn) (get-in res [:state :account :spendable])))))))
