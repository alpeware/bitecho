(ns bitecho.experiments-test
  "Unit, integration, and clojure.test.check generative property tests for Milestone D16:
   Bubblewrap-sandboxed headless `agy` multi-agent experiments (`INV-D16-1` .. `INV-D16-5`)."
  (:require [bitecho.core.protocol.dns :as dns]
            [bitecho.experiments.node-tool :as node-tool]
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
;; 3. INV-D16-4 & INV-D16-5 & A-D16-5: Generative Supply Conservation & Halts
;; =============================================================================

(def gen-node-action
  "Generator for random light-node actions (:transfer, :subnet-join, :subnet-broadcast, :p2p-send, :halt)."
  (gen/one-of
   [(gen/fmap (fn [[from to amt]]
                {:type :transfer :node-id from :target to :amount amt})
              (gen/tuple (gen/elements [:alpha :beta :gamma])
                         (gen/elements [:alpha :beta :gamma])
                         (gen/choose 10 300)))
    (gen/fmap (fn [[nid sub]]
                {:type :subnet-join :node-id nid :subnet-id sub})
              (gen/tuple (gen/elements [:alpha :beta :gamma])
                         (gen/elements ["sociocratic-lab" "kernel-ring"])))
    (gen/fmap (fn [[nid sub msg]]
                {:type :subnet-broadcast :node-id nid :subnet-id sub :message msg})
              (gen/tuple (gen/elements [:alpha :beta :gamma])
                         (gen/elements ["sociocratic-lab" "kernel-ring"])
                         (gen/elements ["proposal-1" "consent-vote-ok"])))
    (gen/fmap (fn [[from to msg]]
                {:type :p2p-send :node-id from :target to :message msg})
              (gen/tuple (gen/elements [:alpha :beta :gamma])
                         (gen/elements [:alpha :beta :gamma])
                         (gen/elements ["hello-sibling" "ack-digest"])))
    (gen/fmap (fn [[nid mode]]
                {:type :halt :node-id nid :halt-reason mode :summary "done"})
              (gen/tuple (gen/elements [:alpha :beta :gamma])
                         (gen/elements [:accomplished-goal :gave-up])))]))

(defspec ^{:doc "Property: Arbitrary sequences of light-node actions strictly conserve total ECH supply and deterministically halt nodes below min-echo-balance (INV-D16-4, INV-D16-5)."}
  node-tool-supply-conservation-and-halt-prop 40
  (prop/for-all [actions (gen/vector gen-node-action 1 25)]
                (let [init-world (node-tool/init-world-state
                                  {:min-echo-balance 100
                                   :max-turns 8
                                   :balances {:alpha 600 :beta 350 :gamma 250}})
                      final-world (reduce
                                   (fn [w act]
                                     (:world (node-tool/apply-node-action w act)))
                                   init-world
                                   actions)]
                  (and (node-tool/conserve-supply? final-world)
                       (every? (fn [[_ nd]]
                                 (if (< (:balance nd) 100)
                                   (and (:halted? nd)
                                        (contains? #{:out-of-echos :accomplished-goal :gave-up :max-turns-exceeded}
                                                   (:halt-reason nd)))
                                   true))
                               (:nodes final-world))))))

;; =============================================================================
;; 4. INV-D16-2, INV-D16-3, & INV-D16-4: Live Bubblewrap Isolation & CLI Test
;; =============================================================================

(deftest inv-d16-2-and-4-live-bwrap-sandbox-preflight-and-node-cli-test
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
                          :start-balance 450
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
            (testing "sociocratic_subnet_demo.edn validates cleanly with conserved 5000 ECH supply"
              (let [demo-cfg (edn/read-string (slurp "dev/experiments/sociocratic_subnet_demo.edn"))
                    demo-res (sandbox/validate-experiment-config demo-cfg)]
                (is (:ok? demo-res))
                (is (= 5000 (:initial-supply demo-res)))
                (is (= {:alpha-coordinator 2300
                        :beta-worker 1250
                        :gamma-auditor 1200
                        :delta-constrained 250}
                       (:effective-balances demo-res)))))

            (testing "bwrap command contains mandatory read-only root and secret/sibling masks"
              (is (some #{"--ro-bind"} bwrap-cmd))
              (is (some #{"--unshare-pid"} bwrap-cmd))
              (is (some #{"--die-with-parent"} bwrap-cmd))
              (is (some #{"/home/simonpure/src/alpeware/bitecho/.ssh"} bwrap-cmd)))

            (testing "live bwrap preflight enforces read-only root, secret masking, sibling masking, and DNS allowlist"
              (is (:ok? iso-alpha) (pr-str iso-alpha))
              (is (:ro-root-enforced? iso-alpha))
              (is (:ssh-masked? iso-alpha))
              (is (:sibling-masked? iso-alpha))
              (is (:workspace-writable? iso-alpha))
              (is (:allowed-dns-resolved? iso-alpha))
              (is (:blocked-dns-refused? iso-alpha))
              (is (:ok? iso-beta) (pr-str iso-beta)))

            (testing "bin/bitecho-node executes inside bwrap for subnet, P2P, transfer, out-of-echos, and accomplished-goal"
              (let [r1 (runner/exec-in-node-sandbox! provisioned alpha-ctx ["bitecho-node" "status"])
                    _ (is (zero? (:exit r1)) (pr-str r1))
                    _ (runner/exec-in-node-sandbox! provisioned alpha-ctx ["bitecho-node" "subnet-join" "sociocratic-lab"])
                    _ (runner/exec-in-node-sandbox! provisioned beta-ctx ["bitecho-node" "subnet-join" "sociocratic-lab"])
                    _ (runner/exec-in-node-sandbox! provisioned alpha-ctx ["bitecho-node" "subnet-broadcast" "sociocratic-lab" "hello-circle"])
                    _ (runner/exec-in-node-sandbox! provisioned alpha-ctx ["bitecho-node" "p2p-send" "beta" "direct-ping-from-alpha"])
                    inbox-beta (runner/exec-in-node-sandbox! provisioned beta-ctx ["bitecho-node" "p2p-inbox"])
                    _ (is (zero? (:exit inbox-beta)))
                    _ (is (str/includes? (:out inbox-beta) "direct-ping-from-alpha"))
                    ;; Beta starts with 450 ECH; subnet-join burned 100 (350 left).
                    ;; Transferring 200 ECH to alpha + 100 burn leaves 50 ECH (< 100 min-echo-balance) -> out-of-echos!
                    _ (runner/exec-in-node-sandbox! provisioned beta-ctx ["bitecho-node" "transfer" "alpha" "200"])
                    st-beta (runner/read-node-local-state beta-ctx)
                    _ (runner/exec-in-node-sandbox! provisioned alpha-ctx ["bitecho-node" "halt" "accomplished-goal" "Subnet & P2P verified"])
                    st-alpha (runner/read-node-local-state alpha-ctx)]
                (is (:halted? st-beta))
                (is (= :out-of-echos (:halt-reason st-beta)))
                (is (= 50 (:balance st-beta)))
                (is (:halted? st-alpha))
                (is (= :accomplished-goal (:halt-reason st-alpha))))))
          (finally
            (runner/shutdown-experiment! provisioned))))
      (finally
        (delete-recursively! tmp-root)))))
