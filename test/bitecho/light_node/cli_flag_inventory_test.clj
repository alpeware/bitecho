(ns bitecho.light-node.cli-flag-inventory-test
  "Automated CLI flag inventory and options parser tests (Rule 6 & Rule 1).
   Verifies CLI and daemon protocol verbs: `ctl`, `export-poll`, `import-poll`, `import`,
   `export-offer`, `export-send`, `export-ack`, `wait`, `retransmit-outbox`, and flags:
   `--since-seq`, `--since-broadcast-seq`, `--control-port`, `--max-epoch-skew`, etc."
  (:require [bitecho.shell.light-node :as shell]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; 1. Daemon Control Verb (`ctl`) & Subverb Dispatch
;; =============================================================================

(deftest test-ctl-verb-dispatch
  (testing "ctl status"
    (let [parsed (shell/parse-light-node-args ["ctl" "status"])]
      (is (= :ctl (:mode parsed)))
      (is (= "status" (:ctl-subverb parsed)))
      (is (= [] (:ctl-args parsed)))))

  (testing "ctl send with subargs"
    (let [parsed (shell/parse-light-node-args ["ctl" "send" "--to" "alice" "--text" "hello daemon"])]
      (is (= :ctl (:mode parsed)))
      (is (= "send" (:ctl-subverb parsed)))
      (is (= ["--to" "alice" "--text" "hello daemon"] (:ctl-args parsed)))))

  (testing "ctl wait with timeout"
    (let [parsed (shell/parse-light-node-args ["ctl" "wait" "--timeout-ms" "3000"])]
      (is (= :ctl (:mode parsed)))
      (is (= "wait" (:ctl-subverb parsed)))
      (is (= ["--timeout-ms" "3000"] (:ctl-args parsed))))))

;; =============================================================================
;; 2. Shuttle Air-Gap Verbs & Flag Inventory
;; =============================================================================

(deftest test-shuttle-verbs-inventory
  (testing "export-poll flags"
    (let [parsed (shell/parse-light-node-args ["export-poll" "--since-seq" "42" "--since-broadcast-seq" "17"])
          cmd (:cmd-map parsed)]
      (is (= "export-poll" (get cmd "cmd")))
      (is (= 42 (get cmd "since_seq")))
      (is (= 17 (get cmd "since_broadcast_seq")))))

  (testing "import-poll payload and file args"
    (let [parsed (shell/parse-light-node-args ["import-poll" "--payload" "{\"messages\":[]}"])
          cmd (:cmd-map parsed)]
      (is (= "import-poll" (get cmd "cmd")))
      (is (= "{\"messages\":[]}" (get cmd "file_content")))))

  (testing "import raw hex"
    (let [parsed (shell/parse-light-node-args ["import" "--hex" "deadbeef01020304"])
          cmd (:cmd-map parsed)]
      (is (= "import" (get cmd "cmd")))
      (is (= "deadbeef01020304" (get cmd "hex")))))

  (testing "export-offer flags"
    (let [parsed (shell/parse-light-node-args ["export-offer" "--to" "bob-pubkey" "--price" "25" "--burn" "500" "--epoch" "100"])
          cmd (:cmd-map parsed)]
      (is (= "export-offer" (get cmd "cmd")))
      (is (= "bob-pubkey" (get cmd "callee")))
      (is (= "bob-pubkey" (get cmd "to")))
      (is (= 25 (get cmd "price")))
      (is (= 500 (get cmd "burn")))
      (is (= 100 (get cmd "epoch")))))

  (testing "export-send flags"
    (let [parsed (shell/parse-light-node-args ["export-send" "--to" "carol-pubkey" "--message" "offline hello" "--burn" "500"])
          cmd (:cmd-map parsed)]
      (is (= "export-send" (get cmd "cmd")))
      (is (= "carol-pubkey" (get cmd "to")))
      (is (= "carol-pubkey" (get cmd "session_id")))
      (is (= "offline hello" (get cmd "message")))
      (is (= 500 (get cmd "burn")))))

  (testing "export-ack flags"
    (let [parsed (shell/parse-light-node-args ["export-ack" "--up-to-seq" "99" "--up-to-broadcast-seq" "33"])
          cmd (:cmd-map parsed)]
      (is (= "export-ack" (get cmd "cmd")))
      (is (= 99 (get cmd "up_to_seq")))
      (is (= 33 (get cmd "up_to_broadcast_seq")))))

  (testing "wait flag"
    (let [parsed (shell/parse-light-node-args ["wait" "--timeout-ms" "4500"])
          cmd (:cmd-map parsed)]
      (is (= "wait" (get cmd "cmd")))
      (is (= 4500 (get cmd "timeout_ms")))))

  (testing "retransmit-outbox flag"
    (let [parsed (shell/parse-light-node-args ["retransmit-outbox" "--session-id" "sess-xyz"])
          cmd (:cmd-map parsed)]
      (is (= "retransmit-outbox" (get cmd "cmd")))
      (is (= "sess-xyz" (get cmd "session_id"))))))

;; =============================================================================
;; 3. Send Verb Target & Message Synonyms
;; =============================================================================

(deftest test-send-flag-synonyms
  (testing "--to and --message"
    (let [cmd (shell/build-one-shot-cmd-map "send" ["--to" "alice" "--message" "msg-text"])]
      (is (= "send" (get cmd "cmd")))
      (is (= "alice" (get cmd "to")))
      (is (= "alice" (get cmd "session_id")))
      (is (= "msg-text" (get cmd "message")))
      (is (= "msg-text" (get cmd "text")))))

  (testing "--peer and --text"
    (let [cmd (shell/build-one-shot-cmd-map "send" ["--peer" "bob" "--text" "text-body"])]
      (is (= "send" (get cmd "cmd")))
      (is (= "bob" (get cmd "to")))
      (is (= "bob" (get cmd "session_id")))
      (is (= "text-body" (get cmd "text"))))))

;; =============================================================================
;; 4. Daemon Flags: --control-port and --max-epoch-skew
;; =============================================================================

(deftest test-daemon-flags
  (testing "serve with explicit control port and max epoch skew"
    (let [parsed (shell/parse-light-node-args ["serve" "--control-port" "5055" "--max-epoch-skew" "25"])]
      (is (= :serve (:mode parsed)))
      (is (= 5055 (:control-port parsed)))
      (is (= 25 (:max-epoch-skew parsed)))))

  (testing "serve with default control port when omitted"
    (let [parsed (shell/parse-light-node-args ["serve"])]
      (is (= :serve (:mode parsed)))
      (is (= 5020 (:control-port parsed)))
      (is (nil? (:max-epoch-skew parsed))))))

;; =============================================================================
;; 5. Generative Property Checks (Rule 1 Strict TDD)
;; =============================================================================

(defspec ^{:doc "Property: Arbitrary sequence numbers parse strictly in export-poll"}
  prop-export-poll-flag-parsing 50
  (prop/for-all [sseq gen/nat
                 bseq gen/nat]
                (let [parsed (shell/parse-light-node-args ["export-poll"
                                                           "--since-seq" (str sseq)
                                                           "--since-broadcast-seq" (str bseq)])
                      cmd (:cmd-map parsed)]
                  (and (= "export-poll" (get cmd "cmd"))
                       (= (long sseq) (get cmd "since_seq"))
                       (= (long bseq) (get cmd "since_broadcast_seq"))))))

(defspec ^{:doc "Property: Arbitrary control ports and epoch skews parse strictly in serve mode"}
  prop-control-port-and-epoch-skew 50
  (prop/for-all [port (gen/choose 1024 65535)
                 skew (gen/choose 1 100)]
                (let [parsed (shell/parse-light-node-args ["serve"
                                                           "--control-port" (str port)
                                                           "--max-epoch-skew" (str skew)])]
                  (and (= :serve (:mode parsed))
                       (= (long port) (:control-port parsed))
                       (= (long skew) (:max-epoch-skew parsed))))))
