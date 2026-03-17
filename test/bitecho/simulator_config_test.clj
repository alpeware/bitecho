(ns bitecho.simulator-config-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]))

(deftest ^:integration simulator-scaffolding-test
  (testing "deps.edn contains :simulate alias with dev path"
    (let [deps (-> "deps.edn" io/file slurp edn/read-string)]
      (is (contains? (:aliases deps) :simulate) "deps.edn must have a :simulate alias")
      (let [simulate-alias (get-in deps [:aliases :simulate])]
        (is (= ["dev"] (:extra-paths simulate-alias)) ":simulate alias must have :extra-paths [\"dev\"]"))))

  (testing "Simulator core namespace file exists"
    (let [f (io/file "dev/bitecho/simulator/core.clj")]
      (is (.exists f) "dev/bitecho/simulator/core.clj must exist"))))
