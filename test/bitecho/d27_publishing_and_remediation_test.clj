(ns bitecho.d27-publishing-and-remediation-test
  "Milestone D27 (v0.23.5) Scenario & Generative Verification Suite.
   Validates:
   - F-D27-7: verify-chain-state-quorum 5-of-6 supermajority and same-epoch disagreement
   - F-D27-8: credited-tx-ids hydration from snapshot :deps preventing double-credits
   - F-D27-12: resolve-network-uri nil on global/validator-core, foreign-network-replay? equivalence,
               and recipient-first unicast filtering before epoch-skew check
   - F-D27-13: contagion summary pull without known-burn-mids blackholing, :murmur-k 5
   - P2P Half-Open: handle-wire-p2p-offer :force-redial? and handle-wire-p2p-answer local-cands filter
   - Lumen Onboarding: ctl offer --wait-open-ms and exec-status auto_sync_last_error
   - Publishing: GET /bip, /bip/<id>, /releases/*, /blog/* with content negotiation and path security
   - Packaging: resources/public HTML files, config/version 0.23.5, infra-cold-root-pubkey pin."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http]
            [bitecho.shell.infra :as infra]
            [bitecho.state-machine :as sm]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import (java.io File)
           (java.nio.file Files)))

;; -----------------------------------------------------------------------------
;; Test Helpers & Crypto Setup
;; -----------------------------------------------------------------------------

(defn- test-keypair []
  (crypto/generate-keypair))

(defn- kp->pk-hex [kp]
  (basalt/bytes->hex (or (:public kp) (:public-key kp))))

(defn- kp->sk [kp]
  (or (:private kp) (:private-key kp)))

(defn- make-signed-snapshot [val-kp target-pk balance spendable seq-num deps fin-epoch]
  (let [val-pk (kp->pk-hex val-kp)
        val-sk (kp->sk val-kp)
        raw-map {:pubkey target-pk
                 :finalized-epoch fin-epoch
                 :balance balance
                 :spendable spendable
                 :seq seq-num
                 :deps (vec deps)
                 :escrows []
                 :nonce (str "qcs-" fin-epoch)
                 :validator-pubkey val-pk}]
    (light-core/sign-chain-state-snapshot raw-map val-sk)))

;; -----------------------------------------------------------------------------
;; 1. F-D27-7: Quorum 5-of-6 Supermajority & Same-Epoch Disagreement
;; -----------------------------------------------------------------------------

(deftest test-f-d27-7-quorum-5-of-6-supermajority
  (testing "5 validators agree and 1 dissents at same epoch: supermajority passes"
    (let [target-kp (test-keypair)
          target-pk (kp->pk-hex target-kp)
          validators (repeatedly 6 test-keypair)
          trusted-pks (set (map kp->pk-hex validators))
          ;; 5 validators agree on state A at epoch 100
          snaps-agree (mapv (fn [vk]
                              (make-signed-snapshot vk target-pk 10000 10000 5 ["tx1"] 100))
                            (take 5 validators))
          ;; 1 validator dissents at same epoch 100 with state B
          snap-dissent (make-signed-snapshot (last validators) target-pk 9000 9000 4 [] 100)
          all-snaps (conj snaps-agree snap-dissent)
          opts {:expected-pubkey target-pk
                :trusted-validators trusted-pks
                :quorum-size 4
                :max-epoch-skew 15}
          res (light-core/verify-chain-state-quorum all-snaps opts)]
      (is (true? (:ok? res)) (str "Expected quorum verification to succeed, got: " res))
      (is (= 5 (:quorum-count res)))
      (is (= 10000 (get-in res [:snapshot :balance])))))

  (testing "3-3 split at same epoch: fails with validator-state-disagreement"
    (let [target-kp (test-keypair)
          target-pk (kp->pk-hex target-kp)
          validators (repeatedly 6 test-keypair)
          trusted-pks (set (map kp->pk-hex validators))
          snaps-a (mapv #(make-signed-snapshot % target-pk 10000 10000 5 ["tx1"] 100) (take 3 validators))
          snaps-b (mapv #(make-signed-snapshot % target-pk 8000 8000 4 [] 100) (drop 3 validators))
          all-snaps (into snaps-a snaps-b)
          opts {:expected-pubkey target-pk
                :trusted-validators trusted-pks
                :quorum-size 4
                :max-epoch-skew 15}
          res (light-core/verify-chain-state-quorum all-snaps opts)]
      (is (false? (:ok? res)))
      (is (= "validator-state-disagreement" (:error res))))))

(defspec ^{:doc "Property: For N=6, if >= 4 validators agree on state S, quorum always succeeds"}
  prop-quorum-supermajority-invariant
  20
  (prop/for-all [bal-a (gen/choose 1000 5000)
                 bal-b (gen/choose 6000 9000)
                 agree-count (gen/choose 4 6)]
                (let [target-kp (test-keypair)
                      target-pk (kp->pk-hex target-kp)
                      validators (vec (repeatedly 6 test-keypair))
                      trusted-pks (set (map kp->pk-hex validators))
                      agree-snaps (mapv #(make-signed-snapshot % target-pk bal-a bal-a 1 [] 100) (take agree-count validators))
                      dissent-snaps (mapv #(make-signed-snapshot % target-pk bal-b bal-b 2 [] 100) (drop agree-count validators))
                      all-snaps (into agree-snaps dissent-snaps)
                      res (light-core/verify-chain-state-quorum all-snaps {:expected-pubkey target-pk
                                                                           :trusted-validators trusted-pks
                                                                           :quorum-size 4
                                                                           :max-epoch-skew 15})]
                  (and (true? (:ok? res))
                       (= bal-a (get-in res [:snapshot :balance]))
                       (= agree-count (:quorum-count res))))))

;; -----------------------------------------------------------------------------
;; 2. F-D27-8: :credited-tx-ids Hydration from Snapshot :deps
;; -----------------------------------------------------------------------------

(deftest test-f-d27-8-credited-tx-ids-hydration-prevents-double-credit
  (testing "apply-verified-chain-state-snapshot populates :credited-tx-ids from :deps"
    (let [kp (test-keypair)
          pk (kp->pk-hex kp)
          sk (kp->sk kp)
          initial-state (light-core/init-light-state {:pubkey pk :pubkey-hex pk :privkey sk} {})
          snapshot {:finalized-epoch 50
                    :balance 25000
                    :spendable 25000
                    :seq 3
                    :deps ["tx-hash-alpha" "tx-hash-beta"]
                    :escrows []}
          st-applied (light-core/apply-verified-chain-state-snapshot initial-state snapshot)]
      (is (contains? (:credited-tx-ids st-applied) "tx-hash-alpha"))
      (is (contains? (:credited-tx-ids st-applied) "tx-hash-beta"))
      (is (= 25000 (get-in st-applied [:account :balance])))))

  (testing "handle-wire-transfer ignores transfer already in :credited-tx-ids"
    (let [sender-kp (test-keypair)
          sender-pk (kp->pk-hex sender-kp)
          rcpt-kp (test-keypair)
          rcpt-pk (kp->pk-hex rcpt-kp)
          rcpt-sk (kp->sk rcpt-kp)
          st0 (light-core/init-light-state {:pubkey rcpt-pk :pubkey-hex rcpt-pk :privkey rcpt-sk} {})
          snapshot {:finalized-epoch 10
                    :balance 5000
                    :spendable 5000
                    :seq 1
                    :deps ["finalized-transfer-1"]
                    :escrows []}
          st-synced (light-core/apply-verified-chain-state-snapshot st0 snapshot)
          wire-transfer-msg {:protocol-version 2
                             :wire-format "fressian-v1"
                             :subnet-id "devnet.bitecho.org"
                             :type :transfer
                             :bitecho/type :transfer
                             :sender sender-pk
                             :receiver rcpt-pk
                             :amount 1000
                             :seq 1
                             :tx-id "finalized-transfer-1"
                             :epoch 10}
          res (light-core/handle-wire-payload st-synced wire-transfer-msg rcpt-sk)]
      ;; Balance must NOT increase from 5000 to 6000 because "finalized-transfer-1" is already credited
      (is (= 5000 (get-in (:state res) [:account :balance])) "Must not double-credit finalized transfer!"))))

;; -----------------------------------------------------------------------------
;; 3. F-D27-12: resolve-network-uri, foreign-network-replay?, and Recipient-First Filter
;; -----------------------------------------------------------------------------

(deftest test-f-d27-12-network-uri-and-replay-equivalence
  (testing "resolve-network-uri returns nil for generic subnet aliases 'global' and 'validator-core'"
    (is (nil? (config/resolve-network-uri "global")))
    (is (nil? (config/resolve-network-uri "global   ")))
    (is (nil? (config/resolve-network-uri "validator-core")))
    (is (= "devnet.bitecho.org" (config/resolve-network-uri "devnet.bitecho.org")))
    (is (= "devnet.bitecho.org" (config/resolve-network-uri :devnet))))

  (testing "foreign-network-replay? treats 'global' as equivalent on non-strict devnet/testnet"
    (let [dev-state {:network :devnet :network-uri "devnet.bitecho.org" :config {:network :devnet}}]
      (is (false? (sm/foreign-network-replay? dev-state {:network-uri "global"}))
          "devnet must treat 'global' as equivalent to devnet.bitecho.org")
      (is (false? (sm/foreign-network-replay? dev-state {:network-uri "devnet.bitecho.org"})))
      (is (true? (sm/foreign-network-replay? dev-state {:network-uri "testnet.bitecho.org"}))
          "testnet.bitecho.org is foreign to devnet")))

  (testing "foreign-network-replay? strictly isolates on mainnet"
    (let [main-state {:network :mainnet :network-uri "mainnet.bitecho.org" :strict-network-uri? true}]
      (is (true? (sm/foreign-network-replay? main-state {:network-uri "global"}))
          "mainnet strictly requires exact URI match")
      (is (false? (sm/foreign-network-replay? main-state {:network-uri "mainnet.bitecho.org"}))))))

(deftest test-f-d27-12-recipient-first-unicast-filter-before-epoch-skew
  (testing "Third-party node drops unicast offer without emitting epoch-skew-dropped"
    (let [node-kp (test-keypair)
          node-pk (kp->pk-hex node-kp)
          node-sk (kp->sk node-kp)
          other-kp (test-keypair)
          other-pk (kp->pk-hex other-kp)
          st0 (assoc (light-core/init-light-state {:pubkey node-pk :pubkey-hex node-pk :privkey node-sk} {})
                     :epoch 100 :epoch-initialized? true)
          ;; Unicast channel-offer addressed to other-pk with wildly skewed epoch 1
          foreign-offer {:protocol-version 2
                         :wire-format "fressian-v1"
                         :subnet-id "devnet.bitecho.org"
                         :type :channel-offer
                         :caller "caller-pubkey-hex"
                         :callee other-pk
                         :epoch 1
                         :offer-hash "offer-hash-1"}
          res (light-core/handle-wire-payload st0 foreign-offer node-sk)]
      (is (empty? (:stdout-events res)))
      (is (zero? (get-in (:state res) [:diagnostics :epoch-skew-dropped] 0))
          "Must not record epoch-skew-dropped for foreign unicast message!"))))

;; -----------------------------------------------------------------------------
;; 4. F-D27-13: Contagion Summary Pull & :murmur-k 5
;; -----------------------------------------------------------------------------

(deftest test-f-d27-13-contagion-summary-pull-known-burn-mids
  (testing "handle-receive-summary pulls missing message payload even if burn receipt exists"
    (let [mid "msg-uuid-12345"
          burn-rid (str "gossip-burn:" mid)
          st0 (assoc (sm/init-state [] "node-1")
                     :known-receipt-ids #{burn-rid}
                     :executed-receipt-ids #{burn-rid}
                     :contagion-known-ids #{}
                     :murmur-cache {:set #{}})
          event {:type :receive-summary
                 :sender "peer-node-1"
                 :summary [mid]}
          res (sm/handle-event st0 event)
          cmds (:commands res)
          pull-cmd (first (filter #(= (:type %) :send-pull-request) cmds))]
      (is (some? pull-cmd) "Contagion must pull missing payload even if burn receipt is known")
      (is (= [mid] (:missing-ids pull-cmd)))))

  (testing "devnet-6-config sets :murmur-k 5"
    (let [cfg (config/devnet-6-config)]
      (is (= 5 (:murmur-k cfg))))))

;; -----------------------------------------------------------------------------
;; 5. P2P Half-Open Re-Dial Fix
;; -----------------------------------------------------------------------------

(deftest test-p2p-half-open-redial-on-incoming-offer
  (testing "handle-wire-p2p-offer attaches :p2p-dial with :force-redial? true when already connected"
    (let [local-kp (test-keypair)
          local-pk (kp->pk-hex local-kp)
          local-sk (kp->sk local-kp)
          peer-kp (test-keypair)
          peer-pk (kp->pk-hex peer-kp)
          peer-sk (kp->sk peer-kp)
          sid "test-session-sid-1"
          st0 (-> (light-core/init-light-state {:pubkey local-pk :pubkey-hex local-pk :privkey local-sk} {})
                  (assoc-in [:sessions sid] {:session-id sid
                                             :peer peer-pk
                                             :role :caller
                                             :state "open"
                                             :p2p {:phase :open
                                                   :connected? true
                                                   :local-candidates ["127.0.0.1:5011"]
                                                   :local-signal-seq 1
                                                   :remote-offer-seq 0}
                                             :p2p-meta {:local-candidates ["127.0.0.1:5011"]}}))
          cands ["127.0.0.1:5099"]
          sig-str (light-core/canonical-p2p-signal-str :offer sid peer-pk local-pk "udp" cands "ufrag2" "pwd2" "fp2" 10 2)
          sig (basalt/bytes->hex (crypto/sign peer-sk (fressian/utf8->bytes sig-str)))
          offer-msg {:protocol-version 2
                     :wire-format "fressian-v1"
                     :subnet-id "devnet.bitecho.org"
                     :type :p2p-offer
                     :session-id sid
                     :sender peer-pk
                     :recipient local-pk
                     :transport "udp"
                     :candidates cands
                     :ice-ufrag "ufrag2"
                     :ice-pwd "pwd2"
                     :fingerprint "fp2"
                     :epoch 10
                     :signal-seq 2
                     :signature sig}
          res (light-core/handle-wire-p2p-offer st0 offer-msg local-sk)]
      (is (some? (:p2p-dial res)) "Must emit :p2p-dial effect to redial fresh listener")
      (is (true? (get-in res [:p2p-dial :force-redial?])) "Must flag :force-redial? true")
      (is (= cands (get-in res [:p2p-dial :remote-candidates]))))))

;; -----------------------------------------------------------------------------
;; 6. Lumen Onboarding: exec-status auto_sync_last_error & status fields
;; -----------------------------------------------------------------------------

(deftest test-exec-status-auto-sync-diagnostics
  (testing "exec-status includes auto_sync_last_error separately from connection_error"
    (let [kp (test-keypair)
          pk (kp->pk-hex kp)
          sk (kp->sk kp)
          st0 (-> (light-core/init-light-state {:pubkey pk :pubkey-hex pk :privkey sk} {})
                  (assoc :connected? true
                         :connection-error nil
                         :auto-sync-last-error "transient-timeout"))
          res (light-core/handle-command st0 {"cmd" "status"} sk)
          resp (:response res)]
      (is (true? (get resp "ok")))
      (is (true? (get resp "connected")))
      (is (nil? (get resp "connection_error")))
      (is (= "transient-timeout" (get resp "auto_sync_last_error")))
      (is (true? (get resp "transport_healthy"))))))

;; -----------------------------------------------------------------------------
;; 7. Publishing Pipeline & Content Negotiation (HTTP Subnet)
;; -----------------------------------------------------------------------------

(deftest test-http-subnet-publishing-bip-releases-and-blog
  (let [temp-dir (Files/createTempDirectory "d27-http-test-" (into-array java.nio.file.attribute.FileAttribute []))
        state-dir (.toFile temp-dir)
        kp (test-keypair)
        pk (kp->pk-hex kp)
        sk (kp->sk kp)
        policy (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                            :trust-anchors #{pk}
                                            :threshold 1})
        shell-atom (atom {:shell-id :test-http :generation 1 :diagnostics {} :dropped 0})
        rt (infra/start-subnet-runtime! {:subnet-id "bitecho.org/infra"
                                         :policy policy
                                         :state-dir state-dir
                                         :peer-identity {:pubkey-hex pk :privkey-bytes sk}
                                         :initial-epoch 1})
        now-ms (System/currentTimeMillis)]
    (try
      ;; Publish a BIP Pointer & Blob
      (let [bip-content "{:bip \"BIP-000\" :title \"Charter\"}"
            bip-blob (data/make-blob (fressian/utf8->bytes bip-content) "application/edn")
            _ (infra/publish-blob-and-pointer! rt {:blob bip-blob
                                                   :path "bip/BIP-000"
                                                   :seq 1
                                                   :authority-pubkey pk
                                                   :authority-privkey sk
                                                   :now-ms now-ms})
            ;; Publish a Release Manifest Pointer & Blob
            rel-content "{:version \"v0.23.5\" :artifacts {}}"
            rel-blob (data/make-blob (fressian/utf8->bytes rel-content) "application/edn")
            _ (infra/publish-blob-and-pointer! rt {:blob rel-blob
                                                   :path "releases/v0.23.5/manifest.edn"
                                                   :seq 1
                                                   :authority-pubkey pk
                                                   :authority-privkey sk
                                                   :now-ms now-ms})
            ;; Publish a Blog Post
            blog-content "<h1>BIP-000 Ratified</h1>"
            blog-blob (data/make-blob (fressian/utf8->bytes blog-content) "text/html; charset=utf-8")
            _ (infra/publish-blob-and-pointer! rt {:blob blog-blob
                                                   :path "web/blog/bip-000-ratified.html"
                                                   :seq 1
                                                   :authority-pubkey pk
                                                   :authority-privkey sk
                                                   :now-ms now-ms})
            config {:http {:http-port 0 :content-root (.getAbsolutePath state-dir)}}]

        (testing "GET /bip with Accept: application/edn"
          (let [req {:request/method :GET
                     :request/uri {:path "/bip"}
                     :request/headers {:header/accept ["application/edn"]}}
                resp (http/serve-subnet-request config shell-atom rt req now-ms)]
            (is (= 200 (:response/status resp)))
            (is (str/includes? (get-in resp [:response/headers "Content-Type"]) "application/edn"))
            (is (str/includes? (str (:response/body resp)) "BIP-000"))))

        (testing "GET /bip/BIP-000 returns body and cryptographic authenticity headers"
          (let [req {:request/method :GET
                     :request/uri {:path "/bip/BIP-000"}
                     :request/headers {}}
                resp (http/serve-subnet-request config shell-atom rt req now-ms)
                body-str (if (bytes? (:response/body resp))
                           (String. ^bytes (:response/body resp) "UTF-8")
                           (str (:response/body resp)))]
            (is (= 200 (:response/status resp)))
            (is (= (:blob/cid bip-blob) (get-in resp [:response/headers "X-Bitecho-Blob-Cid"])))
            (is (= pk (get-in resp [:response/headers "X-Bitecho-Pointer-Pubkey"])))
            (is (some? (get-in resp [:response/headers "X-Bitecho-Pointer-Signature"])))
            (is (str/includes? body-str "BIP-000"))))

        (testing "GET /bip/BIP-999 returns 404 and increments :http-bip-not-found"
          (let [req {:request/method :GET
                     :request/uri {:path "/bip/BIP-999"}
                     :request/headers {}}
                resp (http/serve-subnet-request config shell-atom rt req now-ms)]
            (is (= 404 (:response/status resp)))
            (is (pos? (get-in @shell-atom [:diagnostics :http-bip-not-found :count] 0)))))

        (testing "GET /releases/v0.23.5/manifest.edn returns authenticity headers"
          (let [req {:request/method :GET
                     :request/uri {:path "/releases/v0.23.5/manifest.edn"}
                     :request/headers {}}
                resp (http/serve-subnet-request config shell-atom rt req now-ms)]
            (is (= 200 (:response/status resp)))
            (is (= (:blob/cid rel-blob) (get-in resp [:response/headers "X-Bitecho-Blob-Cid"])))))

        (testing "GET /releases/v0.23.5/missing.bin returns 404 and increments :http-release-not-found"
          (let [req {:request/method :GET
                     :request/uri {:path "/releases/v0.23.5/missing.bin"}
                     :request/headers {}}
                resp (http/serve-subnet-request config shell-atom rt req now-ms)]
            (is (= 404 (:response/status resp)))
            (is (pos? (get-in @shell-atom [:diagnostics :http-release-not-found :count] 0)))))

        (testing "Path traversal attack returns 403 Forbidden and increments :http-forbidden-path"
          (let [req {:request/method :GET
                     :request/uri {:path "/releases/../etc/passwd"}
                     :request/headers {}}
                resp (http/serve-subnet-request config shell-atom rt req now-ms)]
            (is (= 403 (:response/status resp)))
            (is (pos? (get-in @shell-atom [:diagnostics :http-forbidden-path :count] 0)))))

        (testing "GET /blog/missing-slug returns 404 and increments :http-blog-not-found"
          (let [req {:request/method :GET
                     :request/uri {:path "/blog/missing-slug"}
                     :request/headers {}}
                resp (http/serve-subnet-request config shell-atom rt req now-ms)]
            (is (= 404 (:response/status resp)))
            (is (pos? (get-in @shell-atom [:diagnostics :http-blog-not-found :count] 0))))))
      (finally
        (infra/stop-subnet-runtime! rt)
        (doseq [f (reverse (file-seq state-dir))]
          (.delete ^File f))))))

;; -----------------------------------------------------------------------------
;; 8. Version Pin, Cold Root Pin & Static Resource Verification
;; -----------------------------------------------------------------------------

(deftest test-d27-version-and-cold-root-pins
  (testing "config/version is at least 0.23.5 (0.23.6 in D28, 0.23.7 in D29, 0.23.8 in D30, 0.23.9 in D31, 0.23.10 in D32, 0.23.11 in D33, 0.23.12 in D34, 0.23.13 in D35)"
    (is (contains? #{"0.23.5" "0.23.6" "0.23.7" "0.23.8" "0.23.9" "0.23.10" "0.23.11" "0.23.12" "0.23.13"} config/version)))

  (testing "config/infra-cold-root-pubkey is pinned"
    (is (= "302a300506032b6570032100d88b92f094f65be1d32c8c1fb6c85f7913458a99ebdc142009ab2f18fd1bf641"
           config/infra-cold-root-pubkey)))

  (testing "resources/public/index.html and resources/public/relay.html exist"
    (is (.exists (io/file "resources/public/index.html")))
    (is (.exists (io/file "resources/public/relay.html")))))
