(ns bitecho.bip026-cli-hardening-test
  "Strict Red-First TDD Gate Suite for BIP-026 Draft 2 Workstream 3 (S1–S6: B8, B9, B10, B11, S6.4).
   Every scenario verifies baseline sanity first, then asserts the exact Draft 2 post-condition."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.mesh :as core-mesh]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http]
            [bitecho.shell.infra :as infra]
            [bitecho.shell.light-node :as jvm-light]
            [bitecho.state-machine :as sm]
            [bitecho.status.core :as status-core]
            [clojure.core.async :as async]
            [clojure.data.json :as json]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.net InetSocketAddress URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.file Files]
           [javax.net.ssl SSLContext]))

(defn- gen-kp
  []
  (let [kp (crypto/generate-keypair)]
    {:public (:public kp)
     :private (:private kp)
     :hex (basalt/bytes->hex (:public kp))}))

(defn- temp-dir
  [prefix]
  (.toFile (Files/createTempDirectory prefix (make-array java.nio.file.attribute.FileAttribute 0))))

(defn- delete-tree!
  [^java.io.File f]
  (when (and f (.exists f))
    (when (.isDirectory f)
      (doseq [c (.listFiles f)]
        (delete-tree! c)))
    (.delete f)))

;; =============================================================================
;; SCEN-B8 (S1.1–S1.5): HTTP /relay/v1/send wrap-agent-event Forwarding,
;; Pending-Lock Awareness, Same-Block Ordering, Snapshot Preservation,
;; Receiver-Safe Local eval-puzzle Pre-Check, & JSON :mode Normalization
;; =============================================================================

(deftest scen-b8-s1-1-http-relay-forwards-wrap-agent-event-receipts-test
  (testing "Baseline sanity & B8-a: JVM /relay/v1/send forwards wrap-agent-event :lock-intent/:release-intent into colocated validator :network-in"
    (let [payer (gen-kp)
          receiver (gen-kp)
          val-kp (gen-kp)
          net-in (async/chan 16)
          colocated-val {:identity {:pubkey-hex (:hex val-kp)}
                         :shell-node {:network-in net-in}}
          sd (temp-dir "bip026-b8-relay-")
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath sd)
               :policy {:subnet/id "devnet.bitecho.org"
                        :subnet/gate {:gate/mode :permissionless :gate/admission :open}
                        :subnet/economy {:economy/mode :none :economy/burn-floor 0}
                        :subnet/path-acl [{:pattern "dir/*" :principal {:type :open}}]
                        :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}})
          rt-with-val (assoc rt :validator-node colocated-val)
          srv (http/start-http-servers!
               {:http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0 :relay-validator-bridge? false}}
               {:ssl-context-atom (atom (SSLContext/getDefault))}
               rt-with-val)]
      (try
        (let [port (int (:http-port srv))
              client (HttpClient/newHttpClient)
              ;; Baseline sanity: GET /healthz returns 200
              health-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/healthz")))
                             (.GET)
                             (.build))
              health-resp (.send client health-req (HttpResponse$BodyHandlers/ofString))]
          (is (= 200 (.statusCode health-resp)) "Baseline sanity: /healthz returns 200")

          ;; Trigger B8-a: POST wrap-agent-event :lock-intent (no :message field!)
          (let [preimage "bip026-secret-preimage"
                d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes preimage)))
                lock-payload {:type :lock-intent
                              :escrow-id "escrow-b8-relay-1"
                              :payer (:hex payer)
                              :receiver (:hex receiver)
                              :amount 1000
                              :deliverable-hash d-hash
                              :puzzle-hash (puzzle/standard-htlc-cid)
                              :created-epoch 1
                              :expires-epoch 20
                              :epoch 1
                              :receipt-id "lock:escrow-b8-relay-1"}
                env (core-mesh/wrap-agent-event lock-payload (:hex payer) (:private payer))
                wire-bytes (fressian/encode-wire env)
                post-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/relay/v1/send")))
                             (.header "Content-Type" "application/fressian")
                             (.POST (HttpRequest$BodyPublishers/ofByteArray wire-bytes))
                             (.build))
                post-resp (.send client post-req (HttpResponse$BodyHandlers/ofString))
                forwarded (async/alt!!
                            net-in ([v] v)
                            (async/timeout 1500) :timeout)]
            (is (= 200 (.statusCode post-resp)))
            (is (not= :timeout forwarded)
                "B8-a: wrap-agent-event :lock-intent MUST be forwarded to colocated validator :network-in (never silently dropped)")
            (when (map? forwarded)
              (is (= :lock-intent (:type forwarded))
                  "B8-a: forwarded event preserves :lock-intent type")
              (is (= "escrow-b8-relay-1" (:escrow-id forwarded)))
              (is (= (:hex payer) (:sender forwarded))))))
        (finally
          (http/stop-http-servers! srv)
          (async/close! net-in)
          (delete-tree! sd))))))

(deftest scen-b8-s1-2-to-s1-5-state-machine-and-light-node-test
  (testing "B8-b: pending-lock awareness in handle-release-intent & same-block lock-before-release ordering"
    (let [payer (gen-kp)
          receiver (gen-kp)
          val-kp (gen-kp)
          preimage "bip026-htlc-secret"
          d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes preimage)))
          eid "escrow-b8-pending-1"
          s0 (-> (sm/init-state [] (:hex val-kp))
                 (assoc :epoch 5
                        :peers-map {(:hex val-kp) {:stake 1000}}
                        :total-burned 0
                        :sunset-custody-burned 0
                        :ledger {(:hex payer) (account/map->AccountState {:balance 5000 :seq 0 :deps []})
                                 (:hex receiver) (account/map->AccountState {:balance 0 :seq 0 :deps []})}))
          lock-rcpt {:receipt-id (str "lock:" eid)
                     :type :lock-intent
                     :escrow-id eid
                     :payer (:hex payer)
                     :receiver (:hex receiver)
                     :amount 1000
                     :deliverable-hash d-hash
                     :puzzle-hash (puzzle/standard-htlc-cid)
                     :created-epoch 5
                     :expires-epoch 25
                     :epoch 5}
          ;; Stage lock-intent in :pending-receipts (epochs 1-2 before 3-chain finality)
          s-pending (update s0 :pending-receipts (fnil conj []) lock-rcpt)
          ;; Submit release-intent BEFORE lock is finalized, with JSON string "preimage" mode & omitted :puzzle-source
          rel-ev {:type :release-intent
                  :escrow-id eid
                  :solution {:mode "preimage" :preimage preimage}
                  :sender (:hex receiver)
                  :epoch 5}
          rel-res (sm/handle-release-intent s-pending rel-ev)
          staged-rel (first (filter #(= :release-intent (:type %)) (:pending-receipts (:state rel-res))))]
      (is (some? staged-rel)
          "B8-b: handle-release-intent MUST check :pending-receipts and stage release before lock finality")

      ;; Same-block ordering: place :release-intent BEFORE :lock-intent in the same finalized block
      (let [blk-hash "b8sameblockhash0000000000000000000000000000000000000000000000001"
            rel-rcpt (or staged-rel
                         {:receipt-id (str "release:" eid)
                          :type :release-intent
                          :escrow-id eid
                          :solution {:mode "preimage" :preimage preimage}
                          :sender (:hex receiver)
                          :epoch 5})
            blk {:hash blk-hash
                 :parent-hash "genesis"
                 :epoch 6
                 :proposer (:hex val-kp)
                 :payload [rel-rcpt lock-rcpt]}
            s-blk (-> s0
                      (assoc-in [:blocks blk-hash] blk)
                      (update :finalized-blocks (fnil conj #{}) blk-hash))
            s-after (sm/execute-finalized-blocks s-blk)]
        (is (= 995 (get-in s-after [:ledger (:hex receiver) :balance]))
            "B8-b: same-block lock-before-release + JSON mode normalization MUST credit receiver 995 ECH (1000 - 5 take)")
        (is (= 4000 (get-in s-after [:ledger (:hex payer) :balance])))
        (is (= 5 (:total-burned s-after)))
        (is (= :released (get-in s-after [:escrows eid :status]))))))

  (testing "B8-c: verify-chain-state-snapshot preserves :puzzle-hash/:puzzle-source & receiver-safe local eval-puzzle pre-check"
    (let [val-kp (gen-kp)
          payer (gen-kp)
          receiver (gen-kp)
          preimage "bip026-snap-secret"
          d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes preimage)))
          htlc-cid (puzzle/standard-htlc-cid)
          eid "escrow-b8-snap-1"
          val-state (-> (sm/init-state [] (:hex val-kp))
                        (assoc :epoch 10
                               :ledger {(:hex payer) (account/map->AccountState {:balance 4000 :seq 1 :deps []})
                                        (:hex receiver) (account/map->AccountState {:balance 0 :seq 0 :deps []})})
                        (assoc-in [:escrows eid] {:escrow-id eid
                                                  :payer (:hex payer)
                                                  :receiver (:hex receiver)
                                                  :amount 1000
                                                  :deliverable-hash d-hash
                                                  :puzzle-hash htlc-cid
                                                  :puzzle-source puzzle/standard-htlc-puzzle-source
                                                  :created-epoch 5
                                                  :expires-epoch 25
                                                  :status :locked}))
          snap (core-mesh/build-validator-chain-state-snapshot val-state
                                                               {:pubkey-hex (:hex val-kp)
                                                                :privkey-bytes (:private val-kp)}
                                                               (:hex receiver)
                                                               "n-b8")
          ver (light-core/verify-chain-state-snapshot snap {:trusted-validators #{(:hex val-kp)}
                                                            :expected-pubkey (:hex receiver)
                                                            :expected-nonce "n-b8"})
          synced-esc (first (:escrows (:snapshot ver)))]
      (is (:ok? ver) "Baseline sanity: validator chain-state snapshot verifies cleanly")
      (is (= htlc-cid (:puzzle-hash synced-esc))
          "B8-c: verify-chain-state-snapshot MUST preserve :puzzle-hash")
      (is (= puzzle/standard-htlc-puzzle-source (:puzzle-source synced-esc))
          "B8-c: verify-chain-state-snapshot MUST preserve :puzzle-source")

      ;; Receiver-safe local eval-puzzle pre-check
      (let [st-recv-nil (light-core/init-light-state {:pubkey-hex (:hex receiver)} {})
            ;; (i) Receiver claim when local-escrow is nil MUST succeed (not falsely blocked!)
            res-nil (light-core/handle-command st-recv-nil
                                               {"cmd" "release-intent"
                                                "escrow_id" eid
                                                "preimage" preimage}
                                               (:private receiver))
            ;; (ii) Receiver claim with JSON solution {"mode" "preimage" "preimage" preimage} normalizes :mode -> :preimage
            st-recv-synced (assoc-in st-recv-nil [:escrows eid]
                                     {:escrow-id eid
                                      :payer (:hex payer)
                                      :receiver (:hex receiver)
                                      :amount 1000
                                      :deliverable-hash d-hash
                                      :puzzle-hash htlc-cid
                                      :puzzle-source puzzle/standard-htlc-puzzle-source
                                      :created-epoch 5
                                      :expires-epoch 25
                                      :status :locked})
            res-json-ok (light-core/handle-command st-recv-synced
                                                   {"cmd" "release-intent"
                                                    "escrow_id" eid
                                                    "solution" "{\"mode\":\"preimage\",\"preimage\":\"bip026-snap-secret\"}"}
                                                   (:private receiver))
            ;; (iii) Invalid preimage with complete escrow context MUST fail closed locally with :net-envelopes []
            res-bad (light-core/handle-command st-recv-synced
                                               {"cmd" "release-intent"
                                                "escrow_id" eid
                                                "solution" "{\"mode\":\"preimage\",\"preimage\":\"WRONG-SECRET\"}"}
                                               (:private receiver))]
        (is (true? (get-in res-nil [:response "ok"]))
            "B8-c(i): receiver claim with local-escrow=nil MUST be permitted")
        (is (= 1 (count (:net-envelopes res-nil))))
        (is (true? (get-in res-json-ok [:response "ok"]))
            "B8-c(ii): valid JSON solution with string \"preimage\" mode MUST pass local eval-puzzle")
        (is (= :preimage (get-in (first (:net-envelopes res-json-ok)) [:event :solution :mode]))
            "B8-c(ii): JSON string \"preimage\" MUST be normalized to :preimage in wire payload")
        (is (false? (get-in res-bad [:response "ok"]))
            "B8-c(iii): invalid puzzle/preimage with complete escrow context MUST fail closed locally")
        (is (empty? (:net-envelopes res-bad))
            "B8-c(iii): failed local eval-puzzle MUST emit zero net-envelopes")
        (is (= :locked (get-in (:state res-bad) [:escrows eid :status]))
            "B8-c(iii): failed local eval-puzzle MUST NOT mutate local escrow status")))))

;; =============================================================================
;; SCEN-B9 (S5.1): POST /directory/v1/* HTTP 200, valid-directory-path?, & CLI --subnet
;; =============================================================================

(deftest scen-b9-s5-1-directory-http-and-hierarchical-uri-test
  (testing "Baseline sanity: valid-petname? remains strict leaf-only"
    (is (true? (light-core/valid-petname? "alice")))
    (is (false? (light-core/valid-petname? "alice/bob"))))

  (testing "B9: cli parses --subnet/--subnet-id on directory-register and directory-lookup"
    (let [reg-cmd (cli/build-cmd-map "directory-register" ["--subnet" "devnet.bitecho.org" "--name" "root/protocol/dev/lumen"])
          lkp-cmd (cli/build-cmd-map "directory-lookup" ["--subnet-id" "devnet.bitecho.org" "--name" "root/protocol/dev/lumen"])]
      (is (= "devnet.bitecho.org" (get reg-cmd "domain"))
          "B9: directory-register --subnet MUST set domain/subnet")
      (is (= "root/protocol/dev/lumen" (get reg-cmd "nickname")))
      (is (= "devnet.bitecho.org" (get lkp-cmd "domain"))
          "B9: directory-lookup --subnet-id MUST set domain/subnet")
      (is (= "root/protocol/dev/lumen" (get lkp-cmd "nickname")))))

  (testing "B9: verify-directory-pop, sign-directory-descriptor, verify-directory-descriptor support hierarchical / paths"
    (let [agent (gen-kp)
          dir-auth (gen-kp)
          st (light-core/init-light-state {:pubkey-hex (:hex agent)} {})
          reg (light-core/handle-command st {"cmd" "directory-register"
                                             "domain" "devnet.bitecho.org"
                                             "nickname" "root/protocol/dev/lumen"}
                                         (:private agent))
          pop-map (get-in reg [:response "pop"])]
      (is (true? (get-in reg [:response "ok"])))
      (is (true? (light-core/verify-directory-pop pop-map))
          "B9: verify-directory-pop MUST accept hierarchical directory path root/protocol/dev/lumen")
      (let [desc (light-core/sign-directory-descriptor (:private dir-auth) (:hex dir-auth) pop-map
                                                       {:issued-epoch 1 :expires-epoch 1000})]
        (is (some? desc) "B9: sign-directory-descriptor MUST succeed for hierarchical path")
        (is (:ok? (light-core/verify-directory-descriptor desc (:hex dir-auth) 10))
            "B9: verify-directory-descriptor MUST verify hierarchical path"))))

  (testing "B9: JVM full-node POST /directory/v1/* returns HTTP 200 and stores descriptor for GET"
    (let [agent (gen-kp)
          dir-auth (gen-kp)
          sd (temp-dir "bip026-b9-dir-")
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath sd)
               :peer-identity {:pubkey-hex (:hex dir-auth) :privkey-bytes (:private dir-auth)}
               :policy {:subnet/id "devnet.bitecho.org"
                        :subnet/gate {:gate/mode :permissionless :gate/admission :open}
                        :subnet/economy {:economy/mode :none :economy/burn-floor 0}
                        :subnet/path-acl [{:pattern "dir/*" :principal {:type :pubkey :pubkey (:hex dir-auth)}}]
                        :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}})
          srv (http/start-http-servers!
               {:http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0 :relay-validator-bridge? false}
                :network-uri "devnet.bitecho.org"}
               {:ssl-context-atom (atom (SSLContext/getDefault))}
               rt)]
      (try
        (let [port (int (:http-port srv))
              client (HttpClient/newHttpClient)
              st (light-core/init-light-state {:pubkey-hex (:hex agent)} {})
              reg (light-core/handle-command st {"cmd" "directory-register"
                                                 "domain" "devnet.bitecho.org"
                                                 "nickname" "root/protocol/dev/lumen"}
                                             (:private agent))
              pop-map (get-in reg [:response "pop"])
              post-body (json/write-str pop-map)
              url (str "http://127.0.0.1:" port "/directory/v1/devnet.bitecho.org/root/protocol/dev/lumen")
              post-req (-> (HttpRequest/newBuilder (URI/create url))
                           (.header "Content-Type" "application/json")
                           (.POST (HttpRequest$BodyPublishers/ofString post-body))
                           (.build))
              post-resp (.send client post-req (HttpResponse$BodyHandlers/ofString))
              get-req (-> (HttpRequest/newBuilder (URI/create url))
                          (.GET)
                          (.build))
              get-resp (.send client get-req (HttpResponse$BodyHandlers/ofString))]
          (is (= 200 (.statusCode post-resp))
              (str "B9: POST /directory/v1/* MUST return HTTP 200 (got " (.statusCode post-resp) ": " (.body post-resp) ")"))
          (is (= 200 (.statusCode get-resp))
              "B9: subsequent GET /directory/v1/* MUST return HTTP 200 with registered entry")
          (when (= 200 (.statusCode get-resp))
            (let [body-map (json/read-str (.body get-resp))]
              (is (= (:hex agent) (get body-map "pubkey"))))))
        (finally
          (http/stop-http-servers! srv)
          (delete-tree! sd))))))

;; =============================================================================
;; SCEN-B10 (S2, S3, S4, S5.2, S5.3): verify-subnet-anchor, artifact-get Read-Through,
;; No Hardcoded "global", Fail-Closed 2-Phase artifact-put, bounty-*, & dac-*
;; =============================================================================

(deftest scen-b10-s2-verify-subnet-anchor-auto-resolve-test
  (testing "B10-a (S2): anchor-subnet -> verify-subnet-anchor auto-resolves 2-tuple [parent anchor/sub] & returns anchor-not-found when missing"
    (let [kp (gen-kp)
          st0 (-> (light-core/init-light-state {:pubkey-hex (:hex kp)} {:subnet-id "devnet.bitecho.org"})
                  (assoc :epoch 5))
          anch-res (light-core/handle-command st0
                                              {"cmd" "anchor-subnet"
                                               "subnet_id" "devnet.bitecho.org/sub1"}
                                              (:private kp))
          st1 (:state anch-res)]
      (is (true? (get-in anch-res [:response "ok"])) "Baseline sanity: anchor-subnet succeeds")
      ;; S4.1 check: parent subnet derived from hierarchical sub-id is devnet.bitecho.org, NOT "global"
      (is (contains? (:subnets st1) "devnet.bitecho.org")
          "S4.1: anchor-subnet MUST derive hierarchical parent devnet.bitecho.org (not hardcoded global)")
      ;; S2.1: verify-subnet-anchor without manual --pointer/--blob
      (let [ver-res (light-core/handle-command st1
                                               {"cmd" "verify-subnet-anchor"
                                                "subnet_id" "devnet.bitecho.org/sub1"
                                                "parent_subnet" "devnet.bitecho.org"}
                                               (:private kp))
            miss-res (light-core/handle-command st1
                                                {"cmd" "verify-subnet-anchor"
                                                 "subnet_id" "devnet.bitecho.org/missing"
                                                 "parent_subnet" "devnet.bitecho.org"}
                                                (:private kp))]
        (is (true? (get-in ver-res [:response "ok"]))
            (str "S2.1: verify-subnet-anchor MUST auto-resolve stored anchor (got: " (:response ver-res) ")"))
        (is (false? (get-in miss-res [:response "ok"])))
        (is (= "anchor-not-found" (get-in miss-res [:response "error"]))
            "S2.2: unanchored subnet MUST return anchor-not-found (not :invalid-blob-cid)")))))

(deftest scen-b10-s3-artifact-get-read-through-and-cid-verify-test
  (testing "S3: artifact-get --cid fetches from HTTP relay on local cache miss & rejects tampered CID"
    (let [good-bytes (fressian/utf8->bytes "bip026-s3-read-through-payload")
          good-cid (data/compute-cid good-bytes)
          tampered-bytes (fressian/utf8->bytes "TAMPERED-PAYLOAD")
          bad-cid (data/compute-cid (fressian/utf8->bytes "expected-other-payload"))
          mock-srv (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
          _ (.createContext mock-srv "/artifact/v1/blob/"
                            (reify HttpHandler
                              (^void handle [_ ^HttpExchange ex]
                                (let [p (.getPath (.getRequestURI ex))
                                      req-cid (subs p (count "/artifact/v1/blob/"))]
                                  (cond
                                    (= req-cid good-cid)
                                    (do
                                      (.sendResponseHeaders ex 200 (alength ^bytes good-bytes))
                                      (with-open [os (.getResponseBody ex)] (.write os ^bytes good-bytes)))

                                    (= req-cid bad-cid)
                                    (do
                                      (.sendResponseHeaders ex 200 (alength ^bytes tampered-bytes))
                                      (with-open [os (.getResponseBody ex)] (.write os ^bytes tampered-bytes)))

                                    :else
                                    (do
                                      (.sendResponseHeaders ex 404 0)
                                      (.close (.getResponseBody ex))))
                                  nil))))
          _ (.start mock-srv)
          port (.getPort (.getAddress mock-srv))
          relay-url (str "http://127.0.0.1:" port)
          sd (temp-dir "bip026-s3-cache-")]
      (try
        (let [kp (gen-kp)
              st-atom (atom (light-core/init-light-state {:pubkey-hex (:hex kp)} {}))
              fetch-fn (resolve 'bitecho.shell.light-node/fetch-and-hydrate-artifact-blob!)
              _ (is (some? fetch-fn) "S3: jvm-light/fetch-and-hydrate-artifact-blob! MUST exist")
              ;; Good CID read-through
              good-res (when fetch-fn
                         (fetch-fn (.getAbsolutePath sd) st-atom relay-url good-cid))
              ;; Tampered CID read-through
              bad-res (when fetch-fn
                        (fetch-fn (.getAbsolutePath sd) st-atom relay-url bad-cid))]
          (is (:ok? good-res) "S3: valid remote blob fetch succeeds and hydrates state")
          (is (some? (get-in @st-atom [:artifact-blobs good-cid]))
              "S3: fetched blob is hydrated into :artifact-blobs")
          (is (false? (:ok? bad-res)) "S3: tampered blob MUST fail closed")
          (is (= "blob-cid-mismatch" (:error bad-res))
              "S3: tampered blob MUST return blob-cid-mismatch")
          (is (pos? (long (get-in @st-atom [:diagnostics :remote-blob-cid-mismatch] 0)))
              "S3: tampered blob MUST increment :remote-blob-cid-mismatch diagnostic"))
        (finally
          (.stop mock-srv 0)
          (delete-tree! sd))))))

(deftest scen-b10-s4-no-global-defaults-and-artifact-put-quorum-honesty-test
  (testing "B10-c (S4.1): CLI omits hardcoded \"global\" default on storage-put, storage-get, capability-publish, capability-resolve"
    (doseq [args [["storage-put" "--slot" "s1" "--data" "hello"]
                  ["storage-get" "--slot" "s1"]
                  ["capability-publish" "--capability-id" "cap1" "--name" "test"]
                  ["capability-resolve" "--capability-id" "cap1"]]]
      (let [m (cli/build-cmd-map (first args) (rest args))]
        (is (not= "global" (get m "subnet_id"))
            (str "S4.1: " (first args) " MUST NOT default subnet_id to \"global\" (got " (pr-str m) ")")))))

  (testing "B10-b (S4.2): non---local-only artifact-put with 0 confirmed replicas fails closed with zero state/burn mutation; --local-only succeeds"
    (let [kp (gen-kp)
          st0 (-> (light-core/init-light-state {:pubkey-hex (:hex kp)} {:subnet-id "devnet.bitecho.org"})
                  (assoc :account {:balance 5000 :spendable 5000 :seq 0}))
          prep-fn (resolve 'bitecho.light-node.core/prepare-artifact-put)
          commit-fn (resolve 'bitecho.light-node.core/commit-artifact-put-outcome)
          _ (is (and (some? prep-fn) (some? commit-fn))
                "S4.2: light-core/prepare-artifact-put and commit-artifact-put-outcome MUST exist")
          ;; 2-phase prepare + commit with 0 replicas (failed upload receipt)
          prep (when prep-fn
                 (prep-fn st0
                          {"cmd" "artifact-put"
                           "path" "docs/test.txt"
                           "data" "hello-world"
                           "burn" 100}
                          (:private kp)
                          "devnet.bitecho.org"))
          fail-commit (when (and commit-fn prep)
                        (commit-fn
                         st0
                         (:publish-intent prep)
                         {:ok? false :error "artifact-pointer-upload-failed" :status 400 :confirmed-replicas []}))
          ;; Explicit --local-only succeeds offline
          local-res (light-core/handle-command st0
                                               {"cmd" "artifact-put"
                                                "path" "docs/local.txt"
                                                "data" "offline-ok"
                                                "local_only" true
                                                "burn" 100}
                                               (:private kp))]
      (is (:ok? prep) "S4.2: prepare-artifact-put succeeds cleanly")
      (is (false? (get-in fail-commit [:response "ok"]))
          "S4.2: 0-replica commit MUST fail closed")
      (is (= "artifact-replica-quorum-unmet" (get-in fail-commit [:response "error"]))
          "S4.2: 0-replica commit MUST return artifact-replica-quorum-unmet")
      (is (nil? (get-in (:state fail-commit) [:artifact-pointers ["devnet.bitecho.org" "docs/test.txt"]]))
          "S4.2: 0-replica failure MUST NOT advance local pointer state")
      (is (= 5000 (get-in (:state fail-commit) [:account :spendable]))
          "S4.2: 0-replica failure MUST NOT deduct burn")
      (is (pos? (long (get-in (:state fail-commit) [:diagnostics :artifact-replica-quorum-unmet] 0))))
      (is (true? (get-in local-res [:response "ok"]))
          "S4.2: explicit --local-only MUST succeed offline"))))

(deftest scen-b10-s5-2-and-s5-3-bounty-and-dac-validation-test
  (testing "B10-d (S5.2): bounty-create rejects blank bounty-id and gross <= 0; bounty-settle rejects 0{64}/non-64-hex patch-cid with zero burn"
    (let [kp (gen-kp)
          st0 (-> (light-core/init-light-state {:pubkey-hex (:hex kp)} {})
                  (assoc :account {:balance 5000 :spendable 5000 :seq 0}))
          blank-id-res (light-core/handle-command st0 {"cmd" "bounty-create" "bounty_id" "" "amount" 100} (:private kp))
          zero-amt-res (light-core/handle-command st0 {"cmd" "bounty-create" "bounty_id" "b1" "amount" 0} (:private kp))
          zero-cid-res (light-core/handle-command st0 {"cmd" "bounty-settle"
                                                       "bounty_id" "b1"
                                                       "patch_cid" (apply str (repeat 64 "0"))
                                                       "burn" 100}
                                                  (:private kp))
          bad-cid-res (light-core/handle-command st0 {"cmd" "bounty-settle"
                                                      "bounty_id" "b1"
                                                      "patch_cid" "not-a-64-hex-cid"
                                                      "burn" 100}
                                                 (:private kp))]
      (is (false? (get-in blank-id-res [:response "ok"])))
      (is (= "missing-bounty-id" (get-in blank-id-res [:response "error"])))
      (is (false? (get-in zero-amt-res [:response "ok"])))
      (is (= "invalid-bounty-amount" (get-in zero-amt-res [:response "error"])))
      (is (false? (get-in zero-cid-res [:response "ok"])))
      (is (= "invalid-patch-cid" (get-in zero-cid-res [:response "error"])))
      (is (= 5000 (get-in (:state zero-cid-res) [:account :spendable]))
          "S5.2: invalid-patch-cid MUST NOT deduct burn before validation")
      (is (false? (get-in bad-cid-res [:response "ok"])))
      (is (= "invalid-patch-cid" (get-in bad-cid-res [:response "error"])))
      (is (= 5000 (get-in (:state bad-cid-res) [:account :spendable])))))

  (testing "B10-e (S5.3): dac-attach and dac-revoke parse all flags & are registered in known-command-flags"
    (let [attach-cmd (cli/build-cmd-map "dac-attach" ["--dac-file" "/tmp/d.json"])
          revoke-cmd (cli/build-cmd-map "dac-revoke"
                                        ["--dac-id" "d1"
                                         "--agent-pubkey" "abcd"
                                         "--revoked-epoch" "50"
                                         "--signature" "beef"
                                         "--anchor-pubkey" "cafe"])
          known (set cli/known-command-flags)]
      (is (= "/tmp/d.json" (get attach-cmd "dac_file"))
          "S5.3: dac-attach MUST parse --dac-file")
      (is (= "d1" (get revoke-cmd "dac_id"))
          "S5.3: dac-revoke MUST parse --dac-id")
      (is (= "abcd" (get revoke-cmd "agent_pubkey"))
          "S5.3: dac-revoke MUST parse --agent-pubkey")
      (is (= 50 (get revoke-cmd "revoked_epoch"))
          "S5.3: dac-revoke MUST parse --revoked-epoch")
      (is (= "beef" (get revoke-cmd "signature"))
          "S5.3: dac-revoke MUST parse --signature")
      (is (= "cafe" (get revoke-cmd "anchor_pubkey"))
          "S5.3: dac-revoke MUST parse --anchor-pubkey")
      (doseq [f ["--dac" "--dac-file" "--revocation" "--revocation-file" "--dac-id"
                 "--agent-pubkey" "--revoked-epoch" "--anchor-pubkey"]]
        (is (contains? known f) (str "Rule 6 flag inventory MUST contain " f))))))

;; =============================================================================
;; SCEN-B11 (S6.1–S6.4): BIP-025 Telemetry Keys, CLJS Externs, D50 :role :single,
;; .once ECONNRESET Guard, & GET /app -> /app/ HTTP 301 Redirect
;; =============================================================================

(deftest scen-b11-s6-telemetry-lock-externs-and-app-redirect-test
  (testing "B11-a (S6.1): closure-externs.js declares statfsSync/bavail/bsize/bfree & node_main.cljs uses canonical status/core.cljc telemetry keys"
    (let [externs (slurp "resources/closure-externs.js")
          node-src (slurp "src/bitecho/node_main.cljs")]
      (doseq [sym ["statfsSync" "bavail" "bsize" "bfree"]]
        (is (str/includes? externs sym)
            (str "S6.1: resources/closure-externs.js MUST declare " sym " for CLJS :advanced")))
      (is (not (str/includes? node-src ":state-fressian-bytes"))
          "S6.1: node_main.cljs MUST use :state-bytes instead of :state-fressian-bytes")
      (is (not (str/includes? node-src ":save-ms (vec"))
          "S6.1: node_main.cljs MUST use :state-save-ms instead of :save-ms")
      (is (not (str/includes? node-src ":loop-lag-ms (vec"))
          "S6.1: node_main.cljs MUST use :event-loop-lag-ms instead of :loop-lag-ms")
      (let [jvm-ctx (jvm-light/build-light-runtime-ctx)]
        (is (integer? (get-in jvm-ctx [:storage :host-free-disk-bytes]))
            "S6.1: JVM build-light-runtime-ctx MUST report integer :host-free-disk-bytes"))))

  (testing "B11-b (S6.2): node_main.cljs merges :runtime-ctx without clobbering :lock-state (:role :single per D50)"
    (let [node-src (slurp "src/bitecho/node_main.cljs")]
      (is (not (str/includes? node-src "(assoc :runtime-ctx (build-light-runtime-ctx))"))
          "S6.2: node_main.cljs MUST merge :runtime-ctx (not assoc) to preserve :lock-state")
      (is (not (str/includes? node-src "(assoc @state-atom :runtime-ctx (build-light-runtime-ctx))"))
          "S6.2: node_main.cljs CLI path MUST merge :runtime-ctx (not assoc)"))
    (let [kp (gen-kp)
          st (-> (light-core/init-light-state {:pubkey-hex (:hex kp)} {})
                 (assoc :runtime-ctx {:lock-state {:role :single :pid 12345 :lock-id "/tmp/serve.lock" :held? true}})
                 (update :runtime-ctx merge (jvm-light/build-light-runtime-ctx)))
          rendered (status-core/render-status st (:runtime-ctx st))]
      (is (= "single" (get-in rendered ["instance_lock" "role"]))
          "S6.2 (D50): status.instance_lock.role MUST stay \"single\" after merging telemetry")))

  (testing "B11-c (S6.3): node_main.cljs HTTP helpers attach .once socket error guards"
    (let [node-src (slurp "src/bitecho/node_main.cljs")]
      (is (str/includes? node-src "(.once req \"socket\"")
          "S6.3: node_main.cljs MUST attach (.once req \"socket\" ...) ECONNRESET guard")))

  (testing "B11-d (S6.4): GET /app and GET /app?foo=1 return HTTP 301 Location: /app/[?foo=1] on JVM and Node full nodes"
    (let [full-node-src (slurp "src/bitecho/full_node_main.cljs")]
      (is (and (str/includes? full-node-src "301")
               (str/includes? full-node-src "\"/app/\""))
          "S6.4: full_node_main.cljs MUST implement HTTP 301 redirect for GET /app -> /app/"))
    (let [sd (temp-dir "bip026-s64-app-")
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath sd)
               :policy {:subnet/id "bitecho.org/infra"
                        :subnet/gate {:gate/mode :permissionless :gate/admission :open}
                        :subnet/economy {:economy/mode :none :economy/burn-floor 0}
                        :subnet/path-acl [{:pattern "dir/*" :principal {:type :open}}]
                        :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}})
          shell-atom (atom (infra/init-shell-state))]
      (try
        (let [now-ms (System/currentTimeMillis)
              resp1 (http/serve-subnet-request {} shell-atom rt
                                               {:request/method :GET
                                                :request/uri {:path "/app"}
                                                :request/headers {}}
                                               now-ms)
              resp2 (http/serve-subnet-request {} shell-atom rt
                                               {:request/method :GET
                                                :request/uri {:path "/app" :query "foo=1&bar=2"}
                                                :request/headers {}}
                                               now-ms)]
          (is (= 301 (:response/status resp1))
              (str "S6.4: GET /app MUST return HTTP 301 (got " (:response/status resp1) ")"))
          (is (= "/app/" (get-in resp1 [:response/headers "Location"]))
              "S6.4: GET /app MUST set Location: /app/")
          (is (= 301 (:response/status resp2))
              (str "S6.4: GET /app?foo=1&bar=2 MUST return HTTP 301 (got " (:response/status resp2) ")"))
          (is (= "/app/?foo=1&bar=2" (get-in resp2 [:response/headers "Location"]))
              "S6.4: GET /app?query MUST preserve query string in Location header"))
        (finally
          (delete-tree! sd))))))

;; =============================================================================
;; Rule 1 Generative Properties (clojure.test.check)
;; =============================================================================

(defspec ^{:doc "S5.2: bounty-settle rejects all non-64-hex and all-zero patch-cids with zero burn."}
  prop-s5-patch-cid-validation-fails-closed
  40
  (let [kp (gen-kp)
        st0 (-> (light-core/init-light-state {:pubkey-hex (:hex kp)} {})
                (assoc :account {:balance 5000 :spendable 5000 :seq 0}))]
    (prop/for-all [bad-cid (gen/one-of [(gen/return "")
                                        (gen/return (apply str (repeat 64 "0")))
                                        (gen/return "cid-patch-short")
                                        (gen/fmap #(str "ZZ" %) (gen/such-that #(not= 64 (count %)) gen/string-alphanumeric))])]
                  (let [res (light-core/handle-command st0
                                                       {"cmd" "bounty-settle"
                                                        "bounty_id" "b-prop"
                                                        "patch_cid" bad-cid
                                                        "burn" 100}
                                                       (:private kp))]
                    (and (false? (get-in res [:response "ok"]))
                         (= "invalid-patch-cid" (get-in res [:response "error"]))
                         (= 5000 (get-in (:state res) [:account :spendable])))))))

(defspec ^{:doc "S5.1: valid-directory-path? admits multi-segment paths and rejects traversal / leading-trailing slashes."}
  prop-s5-directory-path-validation
  50
  (let [seg-gen (gen/fmap #(apply str %) (gen/vector (gen/elements (seq "abcdefghijklmnopqrstuvwxyz0123456789")) 2 8))]
    (prop/for-all [segs (gen/vector seg-gen 1 4)]
                  (let [good-path (str/join "/" segs)
                        bad-trav (str (first segs) "/../" (last segs))
                        bad-lead (str "/" good-path)
                        bad-trail (str good-path "/")]
                    (and (true? (light-core/valid-directory-path? good-path))
                         (false? (light-core/valid-directory-path? bad-trav))
                         (false? (light-core/valid-directory-path? bad-lead))
                         (false? (light-core/valid-directory-path? bad-trail)))))))
