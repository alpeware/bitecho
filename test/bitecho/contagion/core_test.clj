(ns bitecho.contagion.core-test
  "Tests for Contagion reliable broadcast protocol."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.contagion.core :as contagion]
            [bitecho.crypto :as crypto]
            [clojure.set :as set]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def ^{:doc "Generator for Ed25519 public keys"} gen-pubkey
  (gen/fmap (fn [_] (:public (crypto/generate-keypair)))
            (gen/return nil)))

(def ^{:doc "Generator for Basalt peers"} gen-peer
  (gen/let [ip gen/string-alphanumeric
            port gen/nat
            pubkey gen-pubkey]
    (basalt/make-peer ip port pubkey)))

(def ^{:doc "Generator for Basalt views"} gen-view
  (gen/fmap (fn [peers] (basalt/init-view peers 10 (java.util.Random. 42)))
            (gen/vector gen-peer 0 10)))

(def ^{:doc "Generator for byte array payloads"} gen-payload
  (gen/fmap byte-array (gen/vector gen/byte)))

(def ^{:doc "Generator for message ids"} gen-message-id
  (gen/fmap basalt/bytes->hex (gen/fmap crypto/sha256 gen-payload)))

(def ^{:doc "Generator for known message id sets"} gen-known-ids
  (gen/fmap set (gen/vector gen-message-id 0 20)))

(defspec ^{:doc "generate-summary selects 1 target from view and includes all known ids"}
  generate-summary-invariants
  100
  (prop/for-all [view gen-view
                 known-ids gen-known-ids
                 seed gen/nat]
                (let [rng (java.util.Random. seed)
                      result (contagion/generate-summary rng view known-ids)
                      extracted (basalt/extract-peers view)]
                  (if (empty? extracted)
                    (nil? result)
                    (and
                     (= known-ids (:summary result))
                     (some #(= % (:target result)) extracted))))))

(deftest ^{:doc "Test edge cases for generate summary"} test-generate-summary
  (testing "empty view returns nil"
    (let [rng (java.util.Random. 42)
          known-ids #{"id1" "id2"}
          result (contagion/generate-summary rng #{} known-ids)]
      (is (nil? result)))))

(defspec ^{:doc "lazy-pull only requests missing ids"}
  lazy-pull-requests-missing-only
  100
  (prop/for-all [local-known-ids gen-known-ids
                 remote-summary gen-known-ids]
                (let [missing (contagion/lazy-pull local-known-ids remote-summary)]
                  (and
                   (every? #(contains? remote-summary %) missing)
                   (every? #(not (contains? local-known-ids %)) missing)
                   (= missing (set/difference remote-summary local-known-ids))))))

(deftest ^{:doc "Test explicit cases for lazy pull"} test-lazy-pull
  (testing "returns missing ids"
    (let [local-known #{"a" "b"}
          remote-summary #{"b" "c" "d"}
          missing (contagion/lazy-pull local-known remote-summary)]
      (is (= #{"c" "d"} missing))))

  (testing "returns empty set when no missing ids"
    (let [local-known #{"a" "b" "c"}
          remote-summary #{"b" "c"}
          missing (contagion/lazy-pull local-known remote-summary)]
      (is (= #{} missing)))))
