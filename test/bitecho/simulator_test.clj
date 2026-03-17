(ns bitecho.simulator-test
  (:require [bitecho.simulator.core :as sim]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]))

(deftest ^:integration orchestrator-start-test
  (testing "start-network boots the specified number of bootstrap and agent nodes"
    (let [config {:bootstraps 2 :agents 3 :spammers 0}
          network (sim/start-network config)]

      ;; Verify network map structure
      (is (contains? network :nodes))
      (is (contains? network :stop-ch))

      ;; Verify counts
      (let [nodes (:nodes network)
            bootstraps (filter #(= :bootstrap (:type %)) (vals nodes))
            agents (filter #(= :agent (:type %)) (vals nodes))]
        (is (= 2 (count bootstraps)))
        (is (= 3 (count agents))))

      ;; Stop network to clean up
      (sim/stop-network network)

      ;; Clean up snapshot files
      (doseq [pubkey (keys (:nodes network))]
        (try (io/delete-file (str "snapshot-" pubkey ".edn") true) (catch Exception _))))))
