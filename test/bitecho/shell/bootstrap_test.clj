(ns bitecho.shell.bootstrap-test
  "Tests for the bootstrap node entry point."
  (:require [bitecho.shell.bootstrap :as bootstrap]
            [clojure.test :refer [deftest is testing]]))

(deftest ^{:doc "Tests that the bootstrap node can initialize its flow without throwing exceptions."}
  test-bootstrap-init
  ;; Since -main is designed for an actual executable, we might test a core init function.
  ;; For now, we'll verify it returns a topology or starts without error given stubbed args.
  ;; We will call a helper `init-node` rather than `-main` directly to avoid System/exit or blocking.
  (let [node (bootstrap/init-node "node-pubkey-stub")]
    (is (map? node))
    (is (contains? node :events-in))
    (is (contains? node :net-out))
    (is (contains? node :stop-ch))))

(deftest test-cluster-ops-subcommand-inventory
  (testing "scripts/cluster.sh declares audit subcommand in usage and dispatcher"
    (let [script (slurp "scripts/cluster.sh")]
      (is (re-find #"audit\s+Audit /statusz" script))
      (is (re-find #"cmd_audit\(\)" script))
      (is (re-find #"audit\)\s+cmd_audit" script)))))
