(ns bitecho.light-node.cli-flag-inventory-test
  "Automated CLI flag inventory and options parser tests (Rule 6 & Rule 1).
   Verifies CLI and daemon protocol verbs: `ctl`, `export-poll`, `import-poll`, `import`,
   `export-offer`, `export-send`, `export-ack`, `wait`, `retransmit-outbox`, and flags:
   `--since-seq`, `--since-broadcast-seq`, `--control-port`, `--max-epoch-skew`, etc."
  (:require [bitecho.light-node.core :as light-core]
            [bitecho.shell.light-node :as shell]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

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
      (is (= ["--timeout-ms" "3000"] (:ctl-args parsed)))))

  (testing "ctl flag ordering flexibility: --state-dir and --control-port before or after subverb"
    (let [p1 (shell/parse-light-node-args ["ctl" "--state-dir" "/tmp/st1" "status"])]
      (is (= :ctl (:mode p1)))
      (is (= "status" (:ctl-subverb p1)))
      (is (= "/tmp/st1" (:state-dir p1)))
      (is (= [] (:ctl-args p1))))
    (let [p2 (shell/parse-light-node-args ["ctl" "status" "--state-dir" "/tmp/st2"])]
      (is (= :ctl (:mode p2)))
      (is (= "status" (:ctl-subverb p2)))
      (is (= "/tmp/st2" (:state-dir p2)))
      (is (= [] (:ctl-args p2))))
    (let [p3 (shell/parse-light-node-args ["ctl" "--state-dir" "/tmp/st3" "ensure"])]
      (is (= :daemon (:mode p3)))
      (is (= "ensure" (:daemon-action p3)))
      (is (= "/tmp/st3" (:state-dir p3))))
    (let [p4 (shell/parse-light-node-args ["daemon" "--state-dir" "/tmp/st4" "status"])]
      (is (= :daemon (:mode p4)))
      (is (= "status" (:daemon-action p4)))
      (is (= "/tmp/st4" (:state-dir p4))))
    (let [p5 (shell/parse-light-node-args ["ctl" "--state-dir" "/tmp/st5" "send" "--to" "alice" "--text" "hi"])]
      (is (= :ctl (:mode p5)))
      (is (= "send" (:ctl-subverb p5)))
      (is (= ["--to" "alice" "--text" "hi"] (:ctl-args p5)))))

  (testing "ctl wait --block and --until-event flags"
    (let [cmd1 (shell/build-one-shot-cmd-map "wait" ["--block"])]
      (is (= "wait" (get cmd1 "cmd")))
      (is (true? (get cmd1 "block"))))
    (let [cmd2 (shell/build-one-shot-cmd-map "wait" ["--until-event"])]
      (is (= "wait" (get cmd2 "cmd")))
      (is (true? (get cmd2 "block"))))
    (let [cmd3 (shell/build-one-shot-cmd-map "wait" ["--min-seq" "100" "--block"])]
      (is (= 100 (get cmd3 "min_seq")))
      (is (true? (get cmd3 "block"))))))

(deftest test-jvm-control-server-e2e
  (testing "JVM start-control-server! handles real HTTP requests without hanging or slurp errors"
    (let [temp-path (Files/createTempDirectory "bitecho-ctl-test-" (into-array FileAttribute []))
          state-dir (.toFile temp-path)
          state-file (str (io/file state-dir "state.fressian"))
          identity (shell/load-or-create-light-identity! (str state-dir))
          state-atom (atom (light-core/init-light-state identity {}))
          conn-atom (atom {:phase :disconnected})
          cmd-lock (Object.)
          ctx {:state-atom state-atom
               :conn-atom conn-atom
               :identity identity
               :state-file state-file
               :cmd-lock cmd-lock
               :serve-cmd-lock cmd-lock}
          ctrl-svc (shell/start-control-server! (str state-dir) ctx {:control-port 0})]
      (try
        ;; 1. ctl status with --state-dir before status
        (let [status-res1 (shell/run-light-node-cli! ["ctl" "--state-dir" (str state-dir) "status"])]
          (is (map? status-res1))
          (is (true? (or (get status-res1 "ok") (:ok status-res1))))
          (is (contains? (or status-res1 {}) "pubkey")))

        ;; 2. ctl status with --state-dir after status
        (let [status-res2 (shell/run-light-node-cli! ["ctl" "status" "--state-dir" (str state-dir)])]
          (is (map? status-res2))
          (is (true? (or (get status-res2 "ok") (:ok status-res2)))))

        ;; 3. ctl send via control server (transport fails since disconnected -> returns ok: true, queued: true)
        (swap! state-atom assoc-in [:sessions "sess-1"] {:state "open"
                                                         :peer "02112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
                                                         :tx-key (byte-array 32)
                                                         :rx-key (byte-array 32)
                                                         :outbox {}})
        (let [send-res (shell/run-light-node-cli! ["ctl" "--state-dir" (str state-dir)
                                                   "send" "--session-id" "sess-1"
                                                   "--text" "hello control socket"])]
          (is (map? send-res))
          (is (true? (or (get send-res "ok") (:ok send-res))))
          (is (true? (or (get send-res "queued") (:queued send-res)))))

        ;; 4. ctl wait with short timeout on empty queue -> returns ok: true, events: []
        (let [wait-res (shell/run-light-node-cli! ["ctl" "--state-dir" (str state-dir) "wait" "--timeout-ms" "150"])]
          (is (map? wait-res))
          (is (true? (or (get wait-res "ok") (:ok wait-res))))
          (is (empty? (or (get wait-res "events") (:events wait-res)))))

        ;; 5. Concurrent ctl wait callers popping distinct events
        (let [waiter1 (future (shell/run-light-node-cli! ["ctl" "--state-dir" (str state-dir) "wait" "--timeout-ms" "3000"]))
              waiter2 (future (shell/run-light-node-cli! ["ctl" "--state-dir" (str state-dir) "wait" "--timeout-ms" "3000"]))]
          (Thread/sleep 100)
          (locking cmd-lock
            (swap! state-atom light-core/enqueue-actionable-events [{"event" "message-received" "text" "ev1"}
                                                                    {"event" "message-received" "text" "ev2"}]))
          (let [res1 (deref waiter1 5000 {:error "timeout1"})
                res2 (deref waiter2 5000 {:error "timeout2"})
                evs1 (vec (or (get res1 "events") (:events res1) []))
                evs2 (vec (or (get res2 "events") (:events res2) []))
                all-evs (into evs1 evs2)]
            (is (true? (or (get res1 "ok") (:ok res1))))
            (is (true? (or (get res2 "ok") (:ok res2))))
            (is (= 2 (count all-evs)))
            (is (= 2 (count (distinct all-evs))))))
        (finally
          (when ctrl-svc
            (try ((:stop! ctrl-svc)) (catch Exception _ nil)))
          (try (run! io/delete-file (reverse (file-seq state-dir))) (catch Exception _ nil)))))))

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
      (is (nil? (:max-epoch-skew parsed)))))

  (testing "serve with non-positive max-epoch-skew clamps to 1"
    (let [p0 (shell/parse-light-node-args ["serve" "--max-epoch-skew" "0"])
          p-neg (shell/parse-light-node-args ["serve" "--max-epoch-skew" "-5"])]
      (is (= 1 (:max-epoch-skew p0)))
      (is (= 1 (:max-epoch-skew p-neg)))))

  (testing "serve --daemon mode dispatch"
    (let [parsed (shell/parse-light-node-args ["serve" "--daemon" "--control-port" "5020"])]
      (is (= :daemon (:mode parsed)))
      (is (= "start" (:daemon-action parsed)))))

  (testing "ctl ensure mode dispatch"
    (let [parsed (shell/parse-light-node-args ["ctl" "ensure"])]
      (is (= :daemon (:mode parsed)))
      (is (= "ensure" (:daemon-action parsed)))))

  (testing "daemon subverbs (start, stop, status, restart)"
    (doseq [action ["start" "stop" "status" "restart"]]
      (let [parsed (shell/parse-light-node-args ["daemon" action])]
        (is (= :daemon (:mode parsed)))
        (is (= action (:daemon-action parsed))))))

  (testing "ctl wait flags --timeout-ms and --min-seq"
    (let [cmd (shell/build-one-shot-cmd-map "wait" ["--timeout-ms" "45000" "--min-seq" "10"])]
      (is (= "wait" (get cmd "cmd")))
      (is (= 45000 (get cmd "timeout_ms")))
      (is (= 10 (get cmd "min_seq"))))
    (let [cmd-def (shell/build-one-shot-cmd-map "wait" [])]
      (is (= 30000 (get cmd-def "timeout_ms"))))))

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
