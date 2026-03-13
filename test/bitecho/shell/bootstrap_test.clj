(ns bitecho.shell.bootstrap-test
  "Tests for the bootstrap node entry point."
  (:require [bitecho.shell.bootstrap :as bootstrap]
            [clojure.test :refer [deftest is]]))

(deftest ^{:doc "Tests that the bootstrap node can initialize its flow without throwing exceptions."}
  test-bootstrap-init
  ;; Since -main is designed for an actual executable, we might test a core init function.
  ;; For now, we'll verify it returns a topology or starts without error given stubbed args.
  ;; We will call a helper `init-node` rather than `-main` directly to avoid System/exit or blocking.
  (let [topology (bootstrap/init-node)]
    (is (map? topology))
    (is (contains? topology :procs))
    (is (contains? topology :conns))))
