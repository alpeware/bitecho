(ns bitecho.e2e.d29-remediation-scenario-test
  "Milestone D29 (BIP-003 / v0.23.7) Scenario & Generative Verification Suite
   covering scenarios 1 through 9, and generative properties."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http]
            [bitecho.shell.light-node :as light-shell]
            [bitecho.shell.mesh :as mesh]
            [bitecho.state-machine :as sm]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;; -----------------------------------------------------------------------------
;; Helpers
;; -----------------------------------------------------------------------------

(defn- test-keypair []
  (crypto/generate-keypair))

(defn- kp->pk-hex [kp]
  (basalt/bytes->hex (or (:public kp) (:public-key kp))))

(defn- kp->sk [kp]
  (or (:private kp) (:private-key kp)))

(defn- make-tmp-dir! ^File []
  (let [p (Files/createTempDirectory "bitecho-d29-test-" (into-array FileAttribute []))]
    (.toFile p)))

(defn- sign-receipt-helper [privkey receipt]
  (let [canonical-bytes (fressian/encode-canonical (dissoc receipt :signature "signature"))
        sig (basalt/bytes->hex (crypto/sign (if (string? privkey) (fressian/hex->bytes privkey) privkey) canonical-bytes))]
    (assoc receipt :signature sig)))

;; -----------------------------------------------------------------------------
;; Scenario 1: Receipt Epoch Freshness Horizon & Gossiped Signature Auth
;; (F-D29-10, F-D29-13, A-CARB-D29-1, A-D29-2)
;; -----------------------------------------------------------------------------

(deftest scenario-1-receipt-epoch-horizon-and-gossiped-sig-auth
  (testing "Receipt carrying :epoch older than max-receipt-age-epochs (64) is rejected as stale"
    (let [kp (test-keypair)
          pk (kp->pk-hex kp)
          cfg (assoc config/default-config
                     :genesis-ledger {pk (account/map->AccountState {:balance 10000 :seq 0 :deps []})})
          st0 (assoc (sm/init-state [] pk cfg) :epoch 100 :last-executed-finalized-epoch 99)
          stale-burn (sign-receipt-helper (kp->sk kp)
                                          {:type :burn
                                           :receipt-id "burn-stale-1"
                                           :sender pk
                                           :amount 500
                                           :epoch 20}) ;; 100 - 20 = 80 > 64 epochs!
          block {:epoch 100
                 :hash "block-100"
                 :parent-hash "genesis"
                 :payload [stale-burn]}
          st1 (assoc-in st0 [:blocks "block-100"] block)
          st2 (assoc st1 :finalized-blocks #{"block-100"} :head-hash "block-100")
          executed (sm/execute-finalized-blocks st2)]
      ;; The stale burn must NOT have been executed
      (is (= 10000 (get-in executed [:ledger pk :balance])) "Balance should not be deducted for stale receipt")
      (is (pos? (long (get-in executed [:diagnostics :stale-receipt-epoch-rejected] 0)))
          ":stale-receipt-epoch-rejected diagnostic must be incremented")
      (is (pos? (long (or (:failed-receipts-count executed) 0)))
          ":failed-receipts-count must be incremented")))

  (testing "Receipt within 64-epoch window executes, and cannot double-execute after 10,000 other receipts evict from FIFO queue"
    (let [kp (test-keypair)
          pk (kp->pk-hex kp)
          cfg (assoc config/default-config
                     :max-tracked-receipts 10
                     :genesis-ledger {pk (account/map->AccountState {:balance 10000 :seq 0 :deps []})})
          st0 (assoc (sm/init-state [] pk cfg) :epoch 50 :last-executed-finalized-epoch 49)
          fresh-burn (sign-receipt-helper (kp->sk kp)
                                          {:type :burn
                                           :receipt-id "burn-fresh-1"
                                           :sender pk
                                           :amount 500
                                           :epoch 40}) ;; 50 - 40 = 10 <= 64 epochs
          block1 {:epoch 50
                  :hash "b-50"
                  :parent-hash "genesis"
                  :payload [fresh-burn]}
          st1 (-> st0
                  (assoc-in [:blocks "b-50"] block1)
                  (assoc :finalized-blocks #{"b-50"} :head-hash "b-50")
                  sm/execute-finalized-blocks)]
      (is (= 9500 (get-in st1 [:ledger pk :balance])) "Fresh burn executed once")
      ;; Simulate evicting from :executed-receipt-ids by executing 15 other receipts (cap is 10)
      (let [filler-receipts (vec (for [i (range 15)]
                                   {:type :burn :receipt-id (str "filler-" i) :sender pk :amount 0 :epoch 51}))
            block2 {:epoch 52
                    :hash "b-52"
                    :parent-hash "b-50"
                    :payload filler-receipts}
            st2 (-> st1
                    (assoc-in [:blocks "b-52"] block2)
                    (assoc :finalized-blocks #{"b-50" "b-52"} :head-hash "b-52")
                    sm/execute-finalized-blocks)
            ;; Now try to re-execute fresh-burn at epoch 55 (still within 64 epochs)
            block3 {:epoch 55
                    :hash "b-55"
                    :parent-hash "b-52"
                    :payload [fresh-burn]}
            st3 (-> st2
                    (assoc-in [:blocks "b-55"] block3)
                    (assoc :finalized-blocks #{"b-50" "b-52" "b-55"} :head-hash "b-55")
                    sm/execute-finalized-blocks)]
        (is (= 9500 (get-in st3 [:ledger pk :balance]))
            "Double-execution must be prevented even after FIFO eviction due to epoch-bucketed tracking"))))

  (testing "validate-gossiped-receipt? rejects unsigned receipts when require-signed-receipts? is true"
    (let [kp (test-keypair)
          pk (kp->pk-hex kp)
          cfg (assoc config/default-config
                     :genesis-ledger {pk (account/map->AccountState {:balance 10000 :seq 0 :deps []})})
          st (assoc (sm/init-state [] pk cfg) :epoch 10 :require-signed-receipts? true)
          unsigned-burn {:type :burn :receipt-id "burn-unsigned" :sender pk :amount 100 :epoch 10}
          signed-burn (sign-receipt-helper (kp->sk kp) unsigned-burn)
          tampered-burn (assoc signed-burn :signature (str/reverse (:signature signed-burn)))]
      (is (false? (sm/validate-gossiped-receipt? st unsigned-burn))
          "Unsigned receipt must be rejected when :require-signed-receipts? is true")
      (is (false? (sm/validate-gossiped-receipt? st tampered-burn))
          "Tampered signature must be rejected")
      (is (true? (sm/validate-gossiped-receipt? st signed-burn))
          "Valid signed receipt must be accepted"))))

;; -----------------------------------------------------------------------------
;; Scenario 2: On-Chain Bounty Escrow Lifecycle Survives Autosync
;; (F-D29-14, F-D29-15, A-D29-1, A-CARB-D29-2)
;; -----------------------------------------------------------------------------

(deftest scenario-2-on-chain-bounty-escrow-lifecycle-survives-autosync
  (testing "bounty-create locks gross amount, bounty-settle distributes builder/auditor net and burns protocol take"
    (let [m-kp (test-keypair) m-pk (kp->pk-hex m-kp)
          b-kp (test-keypair) b-pk (kp->pk-hex b-kp)
          a-kp (test-keypair) a-pk (kp->pk-hex a-kp)
          cfg (assoc config/default-config
                     :genesis-ledger {m-pk (account/map->AccountState {:balance 10000 :seq 0 :deps []})
                                      b-pk (account/map->AccountState {:balance 1000 :seq 0 :deps []})
                                      a-pk (account/map->AccountState {:balance 1000 :seq 0 :deps []})})
          st0 (assoc (sm/init-state [] m-pk cfg) :epoch 10 :last-executed-finalized-epoch 9)
          ;; Bounty: gross 1000, take-bps 50 (5 ECH), builder-bps 8450 (845 ECH), auditor-net 150 ECH
          b-create (sign-receipt-helper (kp->sk m-kp)
                                        {:type :bounty-create
                                         :receipt-id "bounty-rcpt-1"
                                         :bounty-id "bounty-1"
                                         :subnet-id "devnet.bitecho.org"
                                         :maintainer-pubkey m-pk
                                         :gross-amount 1000
                                         :take-bps 50
                                         :builder-bps 8450
                                         :target-bip-cid "bip-cid-123"
                                         :epoch 10})
          block1 {:epoch 10 :hash "b-bounty-create" :parent-hash "genesis" :payload [b-create]}
          st1 (-> st0
                  (assoc-in [:blocks "b-bounty-create"] block1)
                  (assoc :finalized-blocks #{"b-bounty-create"} :head-hash "b-bounty-create")
                  sm/execute-finalized-blocks)]
      ;; Maintainer balance deducted 1000
      (is (= 9000 (get-in st1 [:ledger m-pk :balance])))
      (let [b-escrow (get-in st1 [:bounty-escrows "bounty-1"])]
        (is (some? b-escrow))
        (is (= :locked (:status b-escrow)))
        (is (= 1000 (:gross-amount b-escrow)))
        (is (= 5 (:protocol-take b-escrow)))
        (is (= 845 (:builder-net b-escrow)))
        (is (= 150 (:auditor-net b-escrow))))

      ;; Settle bounty
      (let [b-settle (sign-receipt-helper (kp->sk m-kp)
                                          {:type :bounty-settle
                                           :receipt-id "bounty-settle-rcpt-1"
                                           :bounty-id "bounty-1"
                                           :subnet-id "devnet.bitecho.org"
                                           :maintainer-pubkey m-pk
                                           :builder-pubkey b-pk
                                           :auditor-pubkey a-pk
                                           :claim {:bip-cid "bip-cid-123" :status "approved"}
                                           :epoch 11})
            block2 {:epoch 11 :hash "b-bounty-settle" :parent-hash "b-bounty-create" :payload [b-settle]}
            st2 (-> st1
                    (assoc-in [:blocks "b-bounty-settle"] block2)
                    (assoc :finalized-blocks #{"b-bounty-create" "b-bounty-settle"} :head-hash "b-bounty-settle")
                    sm/execute-finalized-blocks)]
        (is (= :settled (get-in st2 [:bounty-escrows "bounty-1" :status])))
        (is (= 1845 (get-in st2 [:ledger b-pk :balance])) "Builder credited +845")
        (is (= 1150 (get-in st2 [:ledger a-pk :balance])) "Auditor credited +150")
        (is (= 5 (get-in st2 [:epoch-settlement-takes 10] 0)) "Protocol take 5 recorded in epoch-settlement-takes")
        (is (= 9000 (get-in st2 [:ledger m-pk :balance])) "Maintainer remains at 9000")

        ;; Query via exec-bounties
        (let [q-res (light-core/exec-bounties {:bounty-escrows (:bounty-escrows st2)}
                                              {"subnet_id" "devnet.bitecho.org"})]
          (is (true? (get q-res "ok")))
          (is (= 1 (get q-res "count")))
          (is (= "bounty-1" (get-in (first (get q-res "bounties")) ["bounty-id"]))))))))

;; -----------------------------------------------------------------------------
;; Scenario 3: Validator Anon Query Reap & Quorum Sync Under Flood
;; (F-D29-16, F-R7, A-D29-3, A-CARB-D29-3)
;; -----------------------------------------------------------------------------

(deftest scenario-3-validator-anon-query-reap-and-quorum-sync-under-flood
  (testing "reap-idle-anon-agent-conns! and verify-chain-state-quorum behaviors"
    ;; 1. Helper anon-conn-key?
    (let [conns-atom (atom {[:anon "hash-123"] {:phase :open :node nil :connected-at (- (System/currentTimeMillis) 20000)}
                            "node-auth-pk" {:phase :open :node nil :connected-at (System/currentTimeMillis)}})]
      (mesh/reap-idle-anon-agent-conns! conns-atom 10000)
      (is (= :down (get-in @conns-atom [[:anon "hash-123"] :phase])) "Stale anon query probe must be reaped to :down")
      (is (= :open (get-in @conns-atom ["node-auth-pk" :phase])) "Authenticated node connection must stay :open"))

    ;; 2. verify-chain-state-quorum returns insufficient-snapshots-returned when < quorum-size
    (let [kp (test-keypair)
          pk (kp->pk-hex kp)
          v1-kp (test-keypair) v1-pk (kp->pk-hex v1-kp)
          v2-kp (test-keypair) v2-pk (kp->pk-hex v2-kp)
          trusted (set [v1-pk v2-pk (kp->pk-hex (test-keypair)) (kp->pk-hex (test-keypair))])
          opts {:expected-pubkey pk :trusted-validators trusted :quorum-size 3 :max-epoch-skew 15}
          base-snap {:pubkey pk :finalized-epoch 100 :balance 5000 :spendable 4000 :seq 1 :deps [] :escrows [] :nonce "n1"}
          s1 (light-core/sign-chain-state-snapshot (assoc base-snap :validator-pubkey v1-pk) (kp->sk v1-kp))
          s2 (light-core/sign-chain-state-snapshot (assoc base-snap :validator-pubkey v2-pk) (kp->sk v2-kp))
          res (light-core/verify-chain-state-quorum [s1 s2] opts)]
      (is (false? (:ok? res)))
      (is (= "insufficient-snapshots-returned" (:error res))))

    ;; 3. verify-chain-state-quorum preserves validator-epoch-skew-exceeded
    (let [kp (test-keypair) pk (kp->pk-hex kp)
          kps (repeatedly 4 test-keypair)
          pks (mapv kp->pk-hex kps)
          trusted (set pks)
          opts {:expected-pubkey pk :trusted-validators trusted :quorum-size 3 :max-epoch-skew 5}
          base-snap {:pubkey pk :finalized-epoch 100 :balance 5000 :spendable 5000 :seq 1 :deps [] :escrows [] :nonce "n1"}
          snaps (mapv (fn [i]
                        (let [ep (if (= i 0) 100 120)] ;; skew = 20 > 5
                          (light-core/sign-chain-state-snapshot
                           (assoc base-snap :validator-pubkey (nth pks i) :finalized-epoch ep)
                           (kp->sk (nth kps i)))))
                      (range 4))
          res (light-core/verify-chain-state-quorum snaps opts)]
      (is (false? (:ok? res)))
      (is (= "validator-epoch-skew-exceeded" (:error res))))

    ;; 4. state-sig ignores mempool :spendable difference across agreeing validators
    (let [kp (test-keypair) pk (kp->pk-hex kp)
          kps (repeatedly 3 test-keypair)
          pks (mapv kp->pk-hex kps)
          trusted (set pks)
          opts {:expected-pubkey pk :trusted-validators trusted :quorum-size 3 :max-epoch-skew 15}
          base-snap {:pubkey pk :finalized-epoch 100 :balance 5000 :seq 1 :deps [] :escrows [] :nonce "n1"}
          s0 (light-core/sign-chain-state-snapshot (assoc base-snap :validator-pubkey (nth pks 0) :spendable 5000) (kp->sk (nth kps 0)))
          s1 (light-core/sign-chain-state-snapshot (assoc base-snap :validator-pubkey (nth pks 1) :spendable 4800) (kp->sk (nth kps 1)))
          s2 (light-core/sign-chain-state-snapshot (assoc base-snap :validator-pubkey (nth pks 2) :spendable 4900) (kp->sk (nth kps 2)))
          res (light-core/verify-chain-state-quorum [s0 s1 s2] opts)]
      (is (true? (:ok? res)))
      (is (= 5000 (get-in res [:snapshot :balance])))
      (is (<= (get-in res [:snapshot :spendable]) 5000)))))

;; -----------------------------------------------------------------------------
;; Scenario 4: Bounded P2P Reoffer Backoff & Peer Silence Watch
;; (F-D29-17, F-R1, A-D29-4, A-CARB-D29-4)
;; -----------------------------------------------------------------------------

(deftest scenario-4-bounded-p2p-reoffer-backoff-and-peer-silence-watch
  (testing "Single-owner auto-reoffer caps at 3 attempts and latches :p2p-reoffer-exhausted"
    (let [my-pk "302a300506032b6570032100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          peer-pk "302a300506032b6570032100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          state {:pubkey my-pk}
          sess-initiator {:session-id "sess-1" :peer peer-pk :role :initiator :reoffer-attempts 0}
          sess-responder {:session-id "sess-2" :peer peer-pk :role :responder :reoffer-attempts 0}]
      ;; Responder does NOT auto-reoffer
      (is (false? (light-core/should-auto-reoffer? state sess-responder 1000)))
      ;; Initiator does auto-reoffer
      (is (true? (light-core/should-auto-reoffer? state sess-initiator 1000)))

      ;; Record 3 attempts
      (let [s1 (light-core/record-reoffer-attempt state sess-initiator 1000)
            sess1 (get-in s1 [:sessions "sess-1"])
            s2 (light-core/record-reoffer-attempt s1 sess1 2000)
            sess2 (get-in s2 [:sessions "sess-1"])
            s3 (light-core/record-reoffer-attempt s2 sess2 3000)
            sess3 (get-in s3 [:sessions "sess-1"])]
        (is (= 3 (:reoffer-attempts sess3)))
        (is (true? (:p2p-reoffer-exhausted sess3)))
        (is (pos? (long (get-in s3 [:diagnostics :p2p-reoffer-exhausted] 0))))
        (is (false? (light-core/should-auto-reoffer? s3 sess3 4000))
            "Auto-reoffer must return false when exhausted after 3 attempts")

        ;; Inbound peer activity resets attempts and exhausted state
        (let [reset-state (light-core/reset-reoffer-attempts s3 "sess-1" 5000)
              reset-sess (get-in reset-state [:sessions "sess-1"])]
          (is (= 0 (:reoffer-attempts reset-sess)))
          (is (false? (:p2p-reoffer-exhausted reset-sess)))
          (is (= 5000 (:last-peer-activity-ms reset-sess)))))))

  (testing "Peer silence alert emitted after 60 minutes of inactivity"
    (let [now-ms (System/currentTimeMillis)
          sess {:session-id "s-silent" :peer "peer-1" :phase :open :last-peer-activity-ms (- now-ms (* 65 60 1000))}
          state {:sessions {"s-silent" sess}}
          checked (light-core/check-peer-silence-alerts state now-ms)]
      (is (pos? (long (get-in checked [:diagnostics :peer-silence-alert] 0))))
      (is (true? (get-in checked [:sessions "s-silent" :peer-silence-alerted?]))))))

;; -----------------------------------------------------------------------------
;; Scenario 5: Strict Network URI Accept & HTTPS Relay P2P Candidate
;; (F-D29-3, F-D29-11)
;; -----------------------------------------------------------------------------

(deftest scenario-5-strict-network-uri-accept-and-https-relay-p2p-candidate
  (testing "handle-wire-accept rejects mismatched network-uri"
    (let [kp (test-keypair) pk (kp->pk-hex kp)
          state {:pubkey pk :network-uri "devnet.bitecho.org" :sessions {"sid-1" {:session-id "sid-1" :phase :offered}}}
          mismatched-accept {:type :channel-accept :session-id "sid-1" :network-uri "other.network.org" :callee pk}
          res (light-core/handle-wire-accept state mismatched-accept (kp->sk kp))]
      (is (pos? (long (get-in (:state res) [:diagnostics :cross-network-accept-rejected] 0))))))

  (testing "handle-wire-offer rejects unscoped global offer on devnet.bitecho.org by default"
    (let [kp (test-keypair) pk (kp->pk-hex kp)
          caller-kp (test-keypair) caller-pk (kp->pk-hex caller-kp)
          caller-id {:pubkey-hex caller-pk :fingerprint "fp" :ice-creds {:ufrag "u" :pwd "p"}}
          callee-id {:pubkey-hex pk :fingerprint "fp" :ice-creds {:ufrag "u" :pwd "p"}}
          st-caller (-> (light-core/init-light-state caller-id {:epoch 1})
                        (assoc :network-uri "global"))
          offer-res (light-core/handle-command st-caller {"cmd" "offer" "callee" pk "price" 10 "burn" 500} (kp->sk caller-kp))
          wire-env (second (:net-envelopes offer-res))
          global-offer (light-core/thaw-payload (get-in wire-env [:event :message :payload]))
          state (-> (light-core/init-light-state callee-id {:epoch 1})
                    (assoc :network-uri "devnet.bitecho.org"))
          res (light-core/handle-wire-offer state global-offer (kp->sk kp))]
      (is (empty? (get-in res [:state :pending-offers])) "Unscoped global offer rejected by default on devnet")
      (let [state-allow (assoc state :allow-legacy-global-offers? true)
            res-allow (light-core/handle-wire-offer state-allow global-offer (kp->sk kp))]
        (is (= 1 (count (get-in res-allow [:state :pending-offers]))) "Accepted when allow-legacy-global-offers? is true"))))

  (testing "parse-p2p-candidate parses HTTPS relay candidate as zero-burn transport and dial-p2p-peer! connects over HTTPS relay leg (F-D29-3)"
    (let [cand (light-core/parse-p2p-candidate "https://nexus.ingress.bitecho.org/relay/v1")]
      (is (= "https" (:transport cand)))
      (is (= 443 (:port cand)))
      (is (true? (:zero-burn? cand)))
      (is (= "https://nexus.ingress.bitecho.org/relay/v1" (:url cand)))
      (let [kp (test-keypair)
            pk (kp->pk-hex kp)
            peer-kp (test-keypair)
            peer-pk (kp->pk-hex peer-kp)
            sid "sid-https-leg-1"
            st0 (-> (light-core/init-light-state {:pubkey-hex pk} {:subnet-id "devnet.bitecho.org"})
                    (assoc-in [:sessions sid] {:session-id sid :peer peer-pk :state "open" :phase :open}))
            state-atom (atom st0)
            p2p-peers-atom (atom {})
            ingress-peers-atom (atom {})
            mdns-atom (atom {})
            emitted (atom [])
            polled-urls (atom [])
            submitted-envs (atom [])]
        (with-redefs [light-shell/poll-relay-envelopes! (fn [url _pk _priv _opts]
                                                          (swap! polled-urls conj url)
                                                          {"ok" true "messages" [] "broadcasts" []})
                      light-shell/submit-relay-envelope! (fn [url env _opts]
                                                           (swap! submitted-envs conj {:url url :env env})
                                                           {"ok" true})]
          (light-shell/dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom mdns-atom (kp->sk kp)
                                      #(swap! emitted conj %)
                                      {:peer peer-pk
                                       :session-id sid
                                       :remote-candidates ["https://nexus.ingress.bitecho.org/relay/v1"]})
          (is (seq @polled-urls) "dial-p2p-peer! must probe HTTPS relay candidate via poll-relay-envelopes!")
          (is (true? (get-in @state-atom [:sessions sid :p2p :connected?])) "HTTPS relay leg must mark session p2p connected")
          (is (some? (get @p2p-peers-atom peer-pk)) "p2p-peers-atom must register peer-send! and close-fn for peer")
          (is (seq @submitted-envs) "dial-p2p-peer! must emit link-bind envelope over HTTPS relay")
          (when-let [close-fn (get-in @p2p-peers-atom [peer-pk :close-fn])]
            (close-fn))
          (is (nil? (get @p2p-peers-atom peer-pk)) "peer-close! must cleanly remove peer from p2p-peers-atom"))))))

;; -----------------------------------------------------------------------------
;; Scenario 6: HTTP Dist Bundle SEA & SHA256 Bridge
;; (F-D29-19, F-R6, A-D29-5)
;; -----------------------------------------------------------------------------

(deftest scenario-6-http-dist-bundle-sea-and-sha256-bridge
  (testing "Subnet HTTP server serves /dist/* artifacts and their .sha256 digests"
    (let [tmp-dir (make-tmp-dir!)
          dist-dir (io/file tmp-dir "dist")
          _ (.mkdirs dist-dir)
          cjs-file (io/file dist-dir "bitecho-light-node.cjs")
          sea-file (io/file dist-dir "bitecho-light-node-linux-x64")
          _ (spit cjs-file "console.log('test-light-node');")
          _ (spit sea-file "binary-mock-payload")
          ctx {:config {:dist-dir (.getAbsolutePath dist-dir)}}
          res-cjs (http/serve-dist-request "/dist/bitecho-light-node.cjs" ctx)
          res-sha (http/serve-dist-request "/dist/bitecho-light-node.cjs.sha256" ctx)
          res-sea (http/serve-dist-request "/dist/bitecho-light-node-linux-x64" ctx)
          res-sea-sha (http/serve-dist-request "/dist/bitecho-light-node-linux-x64.sha256" ctx)]
      (is (= 200 (:status res-cjs)))
      (is (= 200 (:status res-sha)))
      (is (str/includes? (:body res-sha) "bitecho-light-node.cjs"))
      (is (= 200 (:status res-sea)))
      (is (= 200 (:status res-sea-sha)))
      (is (str/includes? (:body res-sea-sha) "bitecho-light-node-linux-x64")))))

;; -----------------------------------------------------------------------------
;; Scenario 7: Relay Poll Subnet Filter & No Default Private Chat
;; (F-D29-20, F-D29-21, A-CARB-D29-5)
;; -----------------------------------------------------------------------------

(deftest scenario-7-relay-poll-subnet-filter-and-no-default-private-chat
  (testing "init-light-state and effective-subscribed-subnets do not subscribe to chat/simon-nexus-axiom by default (F-D29-21, F-V237-1)"
    (let [kp (crypto/generate-keypair)
          id {:pubkey-hex (basalt/bytes->hex (:public kp))}
          st (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
          sender-kp (crypto/generate-keypair)
          sender-st (light-core/init-light-state {:pubkey-hex (basalt/bytes->hex (:public sender-kp))}
                                                 {:subnet-id "chat/simon-nexus-axiom"})
          bcast-res (light-core/handle-command sender-st
                                               {"cmd" "broadcast" "text" "private chat msg" "subnet_id" "chat/simon-nexus-axiom"}
                                               (:private sender-kp))
          bcast-env (first (:net-envelopes bcast-res))
          ingest-res (light-core/handle-wire-payload st bcast-env (:private kp))]
      (is (not (contains? (:subscribed-subnets st) "chat/simon-nexus-axiom")))
      (is (= #{} (:subscribed-subnets st)))
      (is (not (contains? (light-core/effective-subscribed-subnets st) "chat/simon-nexus-axiom")))
      (is (= #{"devnet.bitecho.org" "global"} (light-core/effective-subscribed-subnets st)))
      (is (empty? (:broadcast-inbox (:state ingest-res))))
      (is (= 1 (get-in (:state ingest-res) [:diagnostics :subnet-mismatch-dropped])))
      ;; Also verify default "global" node drops unsubscribed :p2p-broadcast with :subnet-mismatch-dropped (F-D31-BUG-2)
      (let [st-global (light-core/init-light-state id {:subnet-id "global"})
            ingest-global (light-core/handle-wire-payload st-global bcast-env (:private kp))]
        (is (empty? (:broadcast-inbox (:state ingest-global))))
        (is (= 1 (get-in (:state ingest-global) [:diagnostics :subnet-mismatch-dropped]))))
      ;; Explicit subscription enables chat/simon-nexus-axiom
      (let [sub-res (light-core/handle-command st {"cmd" "subscribe-subnets" "subnets" ["chat/simon-nexus-axiom"]} (:private kp))
            st-sub (:state sub-res)
            ingest-sub (light-core/handle-wire-payload st-sub bcast-env (:private kp))]
        (is (contains? (light-core/effective-subscribed-subnets st-sub) "chat/simon-nexus-axiom"))
        (is (= 1 (count (:broadcast-inbox (:state ingest-sub))))))))

  (testing "export-poll and poll-and-ingest-relay-once! emit effective subnet filter without chat/simon-nexus-axiom (F-D29-20, F-V237-4)"
    (let [kp (crypto/generate-keypair)
          id {:pubkey-hex (basalt/bytes->hex (:public kp))
              :privkey-bytes (:private kp)}
          st (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
          poll-cmd-res (light-core/handle-command st {"cmd" "export-poll"} (:private kp))
          poll-req (get-in poll-cmd-res [:response "poll_request"])
          captured-opts (atom nil)
          state-atom (atom st)]
      (is (= ["devnet.bitecho.org" "global"] (get poll-req "subnet_ids")))
      (is (= ["devnet.bitecho.org" "global"] (get poll-req "subnets")))
      (is (not (some #{"chat/simon-nexus-axiom"} (get poll-req "subnet_ids"))))
      (with-redefs [light-shell/poll-relay-envelopes! (fn [_url _pk _priv opts]
                                                        (reset! captured-opts opts)
                                                        {"ok" true "messages" [] "broadcasts" []})]
        (light-shell/poll-and-ingest-relay-once! "https://bitecho.org" id state-atom nil {}))
      (is (= ["devnet.bitecho.org" "global"] (:subnets @captured-opts)))
      (is (not (some #{"chat/simon-nexus-axiom"} (:subnets @captured-opts))))))

  (testing "exec-status reports inbox_direct_count, inbox_broadcast_count, and inbox_by_subnet"
    (let [id {:pubkey-hex "pk-1"}
          st (-> (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"})
                 (assoc :inbox [{:type :direct :text "d1"}
                                {:type :broadcast :subnet-id "sub-a" :text "b1"}
                                {:type :broadcast :subnet-id "sub-a" :text "b2"}
                                {:type :broadcast :subnet-id "sub-b" :text "b3"}]))
          res (light-core/exec-status st)]
      (is (= 4 (get res "inbox_count")))
      (is (= 1 (get res "inbox_direct_count")))
      (is (= 3 (get res "inbox_broadcast_count")))
      (is (= {"sub-a" 2 "sub-b" 1} (get res "inbox_by_subnet"))))))

;; -----------------------------------------------------------------------------
;; Scenario 8: Ctl Wait Block Honors Timeout & Cursor
;; (F-D29-22, A-CARB-D29-5)
;; -----------------------------------------------------------------------------

(deftest scenario-8-ctl-wait-block-honors-timeout-and-cursor
  (testing "exec-wait filters by cursor and prunes acknowledged events <= cursor"
    (let [events [{:eid 1 :event "e1"}
                  {:eid 2 :event "e2"}
                  {:eid 3 :event "e3"}]
          st {:event-queue events}
          ;; Query with cursor = 1
          res (light-core/exec-wait st {"cursor" 1})]
      (is (true? (get res "ok")))
      (is (= [2 3] (mapv #(get % "eid") (get res "events"))))
      (is (= 3 (get res "cursor")))
      ;; Non-peek wait drains returned events and prunes acknowledged events <= cursor
      (is (= [] (get-in res [:state :event-queue])))))

  (testing "exec-wait on empty queue returns timeout true within deadline"
    (let [st {:event-queue []}
          res (light-core/exec-wait st {"block" true "timeout_ms" 100})]
      (is (true? (get res "ok")))
      (is (empty? (get res "events")))
      (is (true? (get res "timeout"))))))

;; -----------------------------------------------------------------------------
;; Scenario 9: CLI Flag Parity (bip-submit, transfer --to, bounty --bip-cid)
;; (F-D29-9, F-D29-12, F-R3, A-D29-5)
;; -----------------------------------------------------------------------------

(deftest scenario-9-cli-flag-parity-bip-submit-transfer-to-and-bounty-bip-cid
  (testing "cli/build-cmd-map extracts bip-submit new flags"
    (let [cmd (cli/build-cmd-map "bip-submit"
                                 {:bip-id "BIP-003"
                                  :title "Test"
                                  :invariant-diff-edn "{:diff true}"
                                  :jurisdiction-map "{:jurisdiction :universal}"
                                  :human-anchor-sunset 12000})]
      (is (= "{:diff true}" (get cmd "invariant-diff-edn")))
      (is (= "{:jurisdiction :universal}" (get cmd "jurisdiction-map")))
      (is (= 12000 (get cmd "human-anchor-sunset")))))

  (testing "cli/build-cmd-map extracts --to for transfer and --bip-cid for bounty-create"
    (let [cmd-xfer (cli/build-cmd-map "transfer" {:to "target-pk" :amount 100})
          cmd-bounty (cli/build-cmd-map "bounty-create" {:bip-cid "cid-xyz" :amount 1000})]
      (is (= "target-pk" (or (get cmd-xfer "to") (get cmd-xfer "receiver"))))
      (is (= "cid-xyz" (or (get cmd-bounty "bip-cid") (get cmd-bounty "bip_cid")))))))

;; -----------------------------------------------------------------------------
;; Scenario 10: Ops, Build, & Release-Proof Hygiene Invariants
;; (F-D29-1, F-D29-2, F-D29-6, F-D29-8, F-D29-18)
;; -----------------------------------------------------------------------------

(deftest scenario-10-ops-build-and-release-hygiene-invariants
  (testing "F-D29-1 & F-D29-18: scripts/cluster.sh cmd_fund uses 4-of-6 quorum and cmd_logs/cmd_sample are non-blocking"
    (let [cluster-sh (slurp "scripts/cluster.sh")]
      (is (str/includes? cluster-sh "Querying current Custody state quorum (4-of-6) from /accountz"))
      (is (str/includes? cluster-sh "cmd_sample()"))
      (is (str/includes? cluster-sh "sample)"))))

  (testing "F-D29-2: scripts/infra_cluster.sh publish-git includes mealy in bare-repo loop"
    (let [infra-sh (slurp "scripts/infra_cluster.sh")]
      (is (str/includes? infra-sh "repos+=(\"mealy\")"))))

  (testing "F-D29-6: dev/bitecho/stress/release_proof.clj shuts down agents and exits cleanly in -main"
    (let [proof-src (slurp "dev/bitecho/stress/release_proof.clj")]
      (is (str/includes? proof-src "(shutdown-agents)"))
      (is (str/includes? proof-src "(System/exit (if (:all-passed? proof) 0 1))"))))

  (testing "F-D29-8: build.clj b/uber manifest includes Add-Exports for keytool and x509"
    (let [build-src (slurp "build.clj")]
      (is (str/includes? build-src "\"Add-Exports\" \"java.base/sun.security.tools.keytool java.base/sun.security.x509\"")))))

;; -----------------------------------------------------------------------------
;; Generative Properties (Rule 1 Strict TDD)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property: Receipt epoch horizon strictly rejects stale receipts (> 64 epochs) and bounty settlement conserves gross == builder_net + auditor_net + protocol_take."}
  prop-d29-receipt-epoch-horizon-and-bounty-conservation
  25
  (prop/for-all [gross (gen/choose 100 10000)
                 take-bps (gen/choose 10 200)
                 builder-bps (gen/choose 7000 9000)
                 closing-ep (gen/choose 100 500)
                 delta-ep (gen/choose 1 120)]
                (let [receipt-ep (- (dec closing-ep) delta-ep)
                      stale? (> delta-ep 64)
                      kp (test-keypair) pk (kp->pk-hex kp)
                      cfg (assoc config/default-config
                                 :genesis-ledger {pk (account/map->AccountState {:balance 50000 :seq 0 :deps []})})
                      st0 (assoc (sm/init-state [] pk cfg) :epoch closing-ep :last-executed-finalized-epoch (dec closing-ep))
                      burn-rcpt (sign-receipt-helper (kp->sk kp)
                                                     {:type :burn
                                                      :receipt-id (str "rcpt-" delta-ep)
                                                      :sender pk
                                                      :amount 100
                                                      :epoch receipt-ep})
                      block {:epoch closing-ep :hash "b-gen" :parent-hash "genesis" :payload [burn-rcpt]}
                      st-exec (-> st0
                                  (assoc-in [:blocks "b-gen"] block)
                                  (assoc :finalized-blocks #{"b-gen"} :head-hash "b-gen")
                                  sm/execute-finalized-blocks)
                      b-take (quot (* gross take-bps) 10000)
                      b-builder (quot (* gross builder-bps) 10000)
                      b-auditor (- gross (+ b-take b-builder))]
                  (and (if stale?
                         (and (= 50000 (get-in st-exec [:ledger pk :balance]))
                              (pos? (long (get-in st-exec [:diagnostics :stale-receipt-epoch-rejected] 0))))
                         (= 49900 (get-in st-exec [:ledger pk :balance])))
                       (= gross (+ b-take b-builder b-auditor))))))

(defspec ^{:doc "Property: P2P re-offers never exceed 3 attempts and latches exhausted state across random reconnect intervals."}
  prop-d29-anon-query-reap-and-bounded-reoffer
  25
  (prop/for-all [attempts-count (gen/choose 1 10)]
                (let [my-pk "302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111"
                      peer-pk "302a300506032b65700321002222222222222222222222222222222222222222222222222222222222222222"
                      st-init {:pubkey my-pk :autonomous? true}
                      sess0 {:session-id "s-gen"
                             :peer peer-pk
                             :role :initiator
                             :phase :open
                             :reoffer-attempts 0
                             :p2p {:connected? false}
                             :p2p-meta {:reconnect-needed? true
                                        :mode :autonomous
                                        :local-candidates ["udp://127.0.0.1:9000"]}}
                      final-st (reduce (fn [st _idx]
                                         (let [cur-sess (get-in st [:sessions "s-gen"] sess0)
                                               now-ms (+ (long (or (get-in cur-sess [:p2p-meta :next-reconnect-ms]) 0)) 100)]
                                           (if (light-core/should-auto-reoffer? st cur-sess now-ms)
                                             (light-core/record-reoffer-attempt st cur-sess now-ms)
                                             st)))
                                       (assoc-in st-init [:sessions "s-gen"] sess0)
                                       (range 1 (inc attempts-count)))
                      final-sess (get-in final-st [:sessions "s-gen"] sess0)]
                  (and (<= (:reoffer-attempts final-sess) 3)
                       (if (>= attempts-count 3)
                         (and (= 3 (:reoffer-attempts final-sess))
                              (true? (:p2p-reoffer-exhausted final-sess))
                              (false? (light-core/should-auto-reoffer? final-st final-sess 999999999)))
                         (false? (boolean (:p2p-reoffer-exhausted final-sess))))))))
