(ns bitecho.experiments-test
  "Unit, integration, and clojure.test.check generative property tests for Milestone D16:
   Bubblewrap-sandboxed headless `agy` multi-agent experiments (`INV-D16-1` .. `INV-D16-5`)."
  (:require [bitecho.core.protocol.dns :as dns]
            [bitecho.experiments.runner :as runner]
            [bitecho.experiments.sandbox :as sandbox]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.net DatagramPacket DatagramSocket InetAddress]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(defn- delete-recursively!
  [^File f]
  (when (and f (.exists f))
    (doseq [c (reverse (file-seq f))]
      (.delete ^File c))))

;; =============================================================================
;; 1. INV-D16-1: Strict EDN Config Validation & Hierarchical Funding Lineage
;; =============================================================================

(deftest inv-d16-1-config-validation-and-funding-lineage-test
  (testing "Valid multi-node experiment config with hierarchical parent-child funding passes"
    (let [cfg {:experiment-id "test-valid-exp"
               :max-turns 4
               :min-echo-balance 100
               :nodes [{:node-id :alpha
                        :parent-id :genesis-custody
                        :start-balance 5000
                        :model-type "gemini-4-hydrogen-low"
                        :initial-prompt "Coordinate subnet sociocratic-lab."
                        :dns-allow-list ["bitecho.org" "*.bitecho.org"]}
                       {:node-id :beta
                        :parent-id :alpha
                        :start-balance 1500
                        :model-type "gemini-3.8-flash-low"
                        :initial-prompt "Join subnet and respond to alpha."
                        :dns-allow-list ["bitecho.org"]}
                       {:node-id :gamma
                        :parent-id :alpha
                        :start-balance 1000
                        :model-type "gemini-4-carbon-low"
                        :initial-prompt "Audit subnet transcript."
                        :dns-allow-list ["bitecho.org"]}]}
          res (sandbox/validate-experiment-config cfg)]
      (is (:ok? res))
      (is (= {:alpha 2500 :beta 1500 :gamma 1000}
             (:effective-balances res)))
      (is (= 5000 (reduce + (vals (:effective-balances res)))))))

  (testing "Rejects invalid model-type, negative start-balance, empty dns-allow-list, unknown parent, and over-allocated parent balance"
    (is (not (:ok? (sandbox/validate-node-config
                    {:node-id :n1
                     :parent-id :genesis-custody
                     :start-balance 1000
                     :model-type "non-existent-model-xyz"
                     :initial-prompt "Hello"
                     :dns-allow-list ["bitecho.org"]}))))
    (is (not (:ok? (sandbox/validate-node-config
                    {:node-id :n1
                     :parent-id :genesis-custody
                     :start-balance -50
                     :model-type "gemini-4-hydrogen-low"
                     :initial-prompt "Hello"
                     :dns-allow-list ["bitecho.org"]}))))
    (is (not (:ok? (sandbox/validate-node-config
                    {:node-id :n1
                     :parent-id :genesis-custody
                     :start-balance 1000
                     :model-type "gemini-4-hydrogen-low"
                     :initial-prompt "   "
                     :dns-allow-list ["bitecho.org"]}))))
    (is (not (:ok? (sandbox/validate-node-config
                    {:node-id :n1
                     :parent-id :genesis-custody
                     :start-balance 1000
                     :model-type "gemini-4-hydrogen-low"
                     :initial-prompt "Hello"
                     :dns-allow-list []}))))
    ;; Over-allocating parent balance fails closed
    (let [over-cfg {:experiment-id "over-alloc"
                    :nodes [{:node-id :alpha
                             :parent-id :genesis-custody
                             :start-balance 1000
                             :model-type "gemini-4-hydrogen-low"
                             :initial-prompt "Coord"
                             :dns-allow-list ["bitecho.org"]}
                            {:node-id :beta
                             :parent-id :alpha
                             :start-balance 1200
                             :model-type "gemini-3.8-flash-low"
                             :initial-prompt "Worker"
                             :dns-allow-list ["bitecho.org"]}]}
          res (sandbox/validate-experiment-config over-cfg)]
      (is (not (:ok? res)))
      (is (= :insufficient-parent-balance (:error res))))))

;; =============================================================================
;; 2. INV-D16-3 & A-D16-5: Generative DNS Allowlist Packet Filter Property
;; =============================================================================

(def gen-subdomain-label
  "Generator for lowercase alphanumeric DNS subdomain labels."
  (gen/fmap #(apply str %)
            (gen/vector (gen/elements (vec "abcdefghijklmnopqrstuvwxyz0123456789")) 2 10)))

(defspec ^{:doc "Property: DNS allowlist proxy resolves allowed domains and returns RCODE=5 (:refused) for non-allowlisted domains (INV-D16-3)."}
  dns-allowlist-packet-filter-prop 40
  (prop/for-all [tx-id (gen/choose 1 65534)
                 sub-lbl gen-subdomain-label
                 blocked-lbl gen-subdomain-label
                 upper? gen/boolean]
                (let [allow-list ["bitecho.org" "*.bitecho.org"]
                      dns-records {"bitecho.org" "35.212.172.159"
                                   (str sub-lbl ".bitecho.org") "35.209.253.119"}
                      allowed-qname (let [s (str sub-lbl ".bitecho.org")]
                                      (if upper? (str/upper-case s) s))
                      blocked-qname (str blocked-lbl ".unauthorized-domain.invalid")
                      allowed-query (dns/encode-packet
                                     {:id tx-id
                                      :qr? false
                                      :opcode 0
                                      :rd? true
                                      :questions [{:qname allowed-qname :qtype :A :qclass :IN}]})
                      blocked-query (dns/encode-packet
                                     {:id (inc (mod tx-id 65000))
                                      :qr? false
                                      :opcode 0
                                      :rd? true
                                      :questions [{:qname blocked-qname :qtype :A :qclass :IN}]})
                      allowed-res (sandbox/handle-dns-query-bytes allowed-query allow-list dns-records)
                      blocked-res (sandbox/handle-dns-query-bytes blocked-query allow-list dns-records)
                      decoded-allowed (dns/decode-packet (:response-bytes allowed-res))
                      decoded-blocked (dns/decode-packet (:response-bytes blocked-res))]
                  (and (:allowed? allowed-res)
                       (= :noerror (:rcode decoded-allowed))
                       (= 1 (count (:answers decoded-allowed)))
                       (= "35.209.253.119" (:rdata (first (:answers decoded-allowed))))
                       (not (:allowed? blocked-res))
                       (= :refused (:rcode decoded-blocked))
                       (empty? (:answers decoded-blocked))))))

(deftest inv-d16-3-udp-dns-allowlist-server-lifecycle-test
  (let [srv (sandbox/start-dns-allowlist-server!
             ["bitecho.org" "*.bitecho.org"]
             {"bitecho.org" "35.212.172.159"})]
    (try
      (is (pos? (:port srv)))
      (with-open [sock (DatagramSocket.)]
        (.setSoTimeout sock 3000)
        (let [q-ok (dns/encode-packet
                    {:id 101 :qr? false :rd? true
                     :questions [{:qname "bitecho.org" :qtype :A :qclass :IN}]})
              pkt-ok (DatagramPacket. q-ok (alength q-ok) (InetAddress/getByName "127.0.0.1") (int (:port srv)))
              _ (.send sock pkt-ok)
              rx-buf (byte-array 512)
              rx-pkt (DatagramPacket. rx-buf (alength rx-buf))
              _ (.receive sock rx-pkt)
              resp-ok (dns/decode-packet (java.util.Arrays/copyOf rx-buf (.getLength rx-pkt)))

              q-bad (dns/encode-packet
                     {:id 102 :qr? false :rd? true
                      :questions [{:qname "forbidden.example.com" :qtype :A :qclass :IN}]})
              pkt-bad (DatagramPacket. q-bad (alength q-bad) (InetAddress/getByName "127.0.0.1") (int (:port srv)))
              _ (.send sock pkt-bad)
              rx-buf2 (byte-array 512)
              rx-pkt2 (DatagramPacket. rx-buf2 (alength rx-buf2))
              _ (.receive sock rx-pkt2)
              resp-bad (dns/decode-packet (java.util.Arrays/copyOf rx-buf2 (.getLength rx-pkt2)))
              stats @(:stats-atom srv)]
          (is (= :noerror (:rcode resp-ok)))
          (is (= "35.212.172.159" (:rdata (first (:answers resp-ok)))))
          (is (= :refused (:rcode resp-bad)))
          (is (= 1 (:allowed-count stats)))
          (is (= 1 (:refused-count stats)))))
      (finally
        (sandbox/stop-dns-allowlist-server! srv)))))

;; =============================================================================
;; 3. INV-D16-2, INV-D16-3, & INV-D16-4: Live Bubblewrap Isolation & CLI Test
;; =============================================================================

(deftest ^:integration inv-d16-2-and-4-live-bwrap-sandbox-preflight-and-node-cli-test
  (let [tmp-root (.toFile (Files/createTempDirectory
                           (.toPath (io/file "/var/tmp"))
                           "bitecho-d16-test-"
                           (into-array FileAttribute [])))
        exp-cfg {:experiment-id "d16-bwrap-test"
                 :base-dir (.getAbsolutePath tmp-root)
                 :max-turns 3
                 :min-echo-balance 100
                 :nodes [{:node-id :alpha
                          :parent-id :genesis-custody
                          :start-balance 2000
                          :model-type "gemini-4-hydrogen-low"
                          :initial-prompt "Test alpha"
                          :dns-allow-list ["bitecho.org" "*.bitecho.org"]}
                         {:node-id :beta
                          :parent-id :alpha
                          :start-balance 650
                          :model-type "gemini-3.8-flash-low"
                          :initial-prompt "Test beta"
                          :dns-allow-list ["bitecho.org"]}]}]
    (try
      (let [provisioned (runner/provision-experiment! exp-cfg)]
        (try
          (let [alpha-ctx (get-in provisioned [:nodes :alpha])
                beta-ctx (get-in provisioned [:nodes :beta])
                bwrap-cmd (sandbox/build-bwrap-command provisioned alpha-ctx ["true"])
                iso-alpha (sandbox/verify-sandbox-isolation! provisioned alpha-ctx)
                iso-beta (sandbox/verify-sandbox-isolation! provisioned beta-ctx)]
            (testing "sociocratic_subnet_demo.edn and homebrew_cafe_civilization.edn validate cleanly with conserved 5000 ECH supply"
              (let [demo-cfg (edn/read-string (slurp "dev/experiments/sociocratic_subnet_demo.edn"))
                    demo-res (sandbox/validate-experiment-config demo-cfg)
                    cafe-cfg (edn/read-string (slurp "dev/experiments/homebrew_cafe_civilization.edn"))
                    cafe-res (sandbox/validate-experiment-config cafe-cfg)]
                (is (:ok? demo-res))
                (is (= 5000 (:initial-supply demo-res)))
                (is (= {:alpha-coordinator 2300
                        :beta-worker 1250
                        :gamma-auditor 1200
                        :delta-constrained 250}
                       (:effective-balances demo-res)))
                (is (:ok? cafe-res))
                (is (= 5000 (:initial-supply cafe-res)))
                (is (= {:archivist-hypatia 700
                        :alchemist-tesla 1400
                        :patron-medici 2650
                        :nomad-diogenes 250}
                       (:effective-balances cafe-res)))
                (is (.exists (io/file (:workspace-dir alpha-ctx) "SCENARIO.md")))))

            (testing "bwrap command contains mandatory read-only root, secret/sibling masks, and zero shared-bus"
              (is (some #{"--ro-bind"} bwrap-cmd))
              (is (some #{"--unshare-pid"} bwrap-cmd))
              (is (some #{"--die-with-parent"} bwrap-cmd))
              (is (some #{"/home/simonpure/src/alpeware/bitecho/.ssh"} bwrap-cmd))
              (is (not (.exists (io/file (:experiment-dir provisioned) "shared-bus"))))
              (is (.exists (io/file (:data-dir alpha-ctx) "control.json")))
              (is (.exists (io/file (:data-dir alpha-ctx) "state.fressian")))
              (let [skill-md (slurp (io/file (:workspace-dir alpha-ctx) ".agents" "skills" "bitecho-light-node" "SKILL.md"))]
                (is (str/includes? skill-md "capability-publish"))
                (is (str/includes? skill-md "storage-put"))))

            (testing "live bwrap preflight enforces read-only root, secret masking, sibling masking, and DNS allowlist"
              (is (:ok? iso-alpha) (pr-str iso-alpha))
              (is (:ro-root-enforced? iso-alpha))
              (is (:ssh-masked? iso-alpha))
              (is (:sibling-masked? iso-alpha))
              (is (:workspace-writable? iso-alpha))
              (is (:allowed-dns-resolved? iso-alpha))
              (is (:blocked-dns-refused? iso-alpha))
              (is (:ok? iso-beta) (pr-str iso-beta)))

            (testing "real light-node CLI (clojure -M:light-node / bitecho-light-node) executes inside bwrap over /ctl and live validator WebRTC DataChannel for broadcast, storage, capability, session, transfer, out-of-echos, and SUMMARY.md accomplished-goal"
              (let [;; 1. Verify status and petname-list via clojure -M:light-node and bitecho-light-node
                    r1 (runner/exec-in-node-sandbox! provisioned alpha-ctx ["clojure" "-M:light-node" "status"])
                    _ (is (zero? (:exit r1)) (pr-str r1))
                    r-pets (runner/exec-in-node-sandbox! provisioned alpha-ctx ["clojure" "-M:light-node" "petname-list"])
                    _ (is (zero? (:exit r-pets)) (pr-str r-pets))
                    _ (is (str/includes? (:out r-pets) "beta"))
                    ;; 2. Alpha (starts with 1350 ECH): broadcast (1250), storage-put (1150), storage-get, capability-publish (1050)
                    bcast-res (runner/exec-in-node-sandbox!
                               provisioned alpha-ctx
                               ["clojure" "-M:light-node" "broadcast" "--subnet-id" "sociocratic-lab" "--text" "hello-circle" "--burn" "100"])
                    _ (is (zero? (:exit bcast-res)) (pr-str bcast-res))
                    put-res (runner/exec-in-node-sandbox!
                             provisioned alpha-ctx
                             ["clojure" "-M:light-node" "storage-put" "--slot-id" "wiki-cache" "--subnet-id" "sociocratic-lab" "--data" "Byzantine summary" "--burn" "100"])
                    _ (is (zero? (:exit put-res)) (pr-str put-res))
                    get-res (runner/exec-in-node-sandbox!
                             provisioned alpha-ctx
                             ["clojure" "-M:light-node" "storage-get" "--slot-id" "wiki-cache" "--subnet-id" "sociocratic-lab"])
                    _ (is (zero? (:exit get-res)) (pr-str get-res))
                    _ (is (str/includes? (:out get-res) "Byzantine summary"))
                    cap-pub (runner/exec-in-node-sandbox!
                             provisioned alpha-ctx
                             ["clojure" "-M:light-node" "capability-publish"
                              "--capability-id" "wikipedia-oracle"
                              "--capability-type" "compute/uop-kernel"
                              "--subnet-id" "sociocratic-lab"
                              "--price" "100"
                              "--burn" "100"])
                    _ (is (zero? (:exit cap-pub)) (pr-str cap-pub))
                    ;; 3. Alpha opens sealed session to beta (950), waits for live validator round-trip auto-accept, and sends direct ping (850)
                    offer-res (runner/exec-in-node-sandbox!
                               provisioned alpha-ctx
                               ["clojure" "-M:light-node" "offer" "--callee" "beta" "--price" "0" "--burn" "100"])
                    _ (is (zero? (:exit offer-res)) (pr-str offer-res))
                    _ (Thread/sleep 400)
                    send-res (runner/exec-in-node-sandbox!
                              provisioned alpha-ctx
                              ["clojure" "-M:light-node" "send" "--to" "beta" "--text" "direct-ping-from-alpha" "--burn" "100"])
                    _ (is (zero? (:exit send-res)) (pr-str send-res))
                    _ (Thread/sleep 300)
                    ;; 4. Beta (starts with 650 ECH): lists replicated capabilities, broadcasts on subnet (550), pays alpha 100 ECH for wikipedia-oracle (100+100 -> 350 left; alpha +100 -> 950)
                    cap-list (runner/exec-in-node-sandbox! provisioned beta-ctx ["clojure" "-M:light-node" "capability-list"])
                    _ (is (zero? (:exit cap-list)) (pr-str cap-list))
                    _ (is (str/includes? (:out cap-list) "wikipedia-oracle"))
                    b-bcast (runner/exec-in-node-sandbox!
                             provisioned beta-ctx
                             ["clojure" "-M:light-node" "broadcast" "--subnet-id" "sociocratic-lab" "--text" "beta-joined" "--burn" "100"])
                    _ (is (zero? (:exit b-bcast)) (pr-str b-bcast))
                    buy-tf (runner/exec-in-node-sandbox!
                            provisioned beta-ctx
                            ["clojure" "-M:light-node" "transfer" "--receiver" "alpha" "--amount" "100" "--burn" "100"])
                    _ (is (zero? (:exit buy-tf)) (pr-str buy-tf))
                    ;; 5. Alpha delivers capability result over sealed session to beta (950 - 100 -> 850)
                    deliv-res (runner/exec-in-node-sandbox!
                               provisioned alpha-ctx
                               ["clojure" "-M:light-node" "send" "--to" "beta" "--text" "Byzantine summary" "--burn" "100"])
                    _ (is (zero? (:exit deliv-res)) (pr-str deliv-res))
                    _ (Thread/sleep 800)
                    ;; 6. Beta drains inbox and verifies both sealed messages and subnet broadcast
                    inbox-beta (runner/exec-in-node-sandbox! provisioned beta-ctx ["clojure" "-M:light-node" "inbox"])
                    _ (is (zero? (:exit inbox-beta)) (pr-str inbox-beta))
                    _ (is (str/includes? (:out inbox-beta) "hello-circle"))
                    _ (is (str/includes? (:out inbox-beta) "direct-ping-from-alpha"))
                    _ (is (str/includes? (:out inbox-beta) "Byzantine summary"))
                    ;; 7. Beta has 350 ECH left. Transferring 200 ECH to alpha + 100 burn leaves 50 ECH (< 100 min-echo-balance) -> out-of-echos!
                    ;; Alpha receives +200 ECH over live validator gossip -> 1050 ECH.
                    _ (runner/exec-in-node-sandbox!
                       provisioned beta-ctx
                       ["clojure" "-M:light-node" "transfer" "--receiver" "alpha" "--amount" "200" "--burn" "100"])
                    _ (Thread/sleep 800)
                    st-beta (runner/read-node-local-state beta-ctx)
                    _ (spit (io/file (:workspace-dir alpha-ctx) "SUMMARY.md")
                            "Subnet, P2P, & Capability verified over live validator\n")
                    st-alpha (runner/read-node-local-state alpha-ctx)]
                (is (:halted? st-beta))
                (is (= :out-of-echos (:halt-reason st-beta)))
                (is (= 50 (:balance st-beta)))
                (is (:halted? st-alpha))
                (is (= :accomplished-goal (:halt-reason st-alpha)))
                (is (= 1050 (:balance st-alpha))))))
          (finally
            (runner/shutdown-experiment! provisioned))))
      (finally
        (delete-recursively! tmp-root)))))
