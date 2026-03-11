(ns bitecho.basalt.core-test
  "Tests for Basalt peer sampling core logic."
  (:require [bitecho.basalt.core :as basalt]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest ^{:doc "Tests creation of peer records."} peer-creation-test
  (testing "creates a peer with proper hashed id"
    (let [peer (basalt/make-peer "127.0.0.1" 8080 (byte-array 32))]
      (is (= "127.0.0.1" (:ip peer)))
      (is (= 8080 (:port peer)))
      (is (= 0 (:age peer)))
      (is (some? (:pubkey peer)))
      (is (= 64 (count (:hash peer)))))))

(defspec ^{:doc "Tests view initialization spec."} view-initialization-spec 100
  (prop/for-all [peers (gen/list (gen/tuple
                                  (gen/return "127.0.0.1")
                                  gen/nat
                                  (gen/return (byte-array 32))))]
                (let [peer-records (map (fn [[ip port pubkey]]
                                          (basalt/make-peer ip port pubkey))
                                        peers)
                      view (basalt/init-view peer-records)]
                  (and (set? view)
                       (every? #(instance? bitecho.basalt.core.Peer %) view)))))
