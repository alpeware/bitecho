(ns bitecho.murmur.core-test
  "Tests for Murmur probabilistic broadcast protocol."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.murmur.core :as murmur]
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
  (gen/fmap basalt/init-view (gen/vector gen-peer 0 10)))

(def ^{:doc "Generator for byte array payloads"} gen-payload
  (gen/fmap byte-array (gen/vector gen/byte)))

(defspec ^{:doc "Initiate broadcast targets k random peers and deterministic ID"}
  initiate-broadcast-invariants
  100
  (prop/for-all [view gen-view
                 k gen/nat
                 payload gen-payload
                 seed gen/nat]
                (let [rng (java.util.Random. seed)
                      result (murmur/initiate-broadcast payload rng view k)
                      expected-id (basalt/bytes->hex (crypto/sha256 payload))
                      expected-target-count (min k (count view))]
                  (and
                   (= expected-id (:message-id result))
                   (= (seq payload) (seq (:payload result)))
                   (= expected-target-count (count (:targets result)))
       ;; verify targets is a subset of view
                   (set/subset? (set (:targets result)) (set view))))))

(deftest ^{:doc "Test edge cases for initiate broadcast"} test-initiate-broadcast
  (testing "empty view returns no targets"
    (let [rng (java.util.Random. 42)
          payload (.getBytes "hello")
          result (murmur/initiate-broadcast payload rng #{} 3)]
      (is (= 0 (count (:targets result))))
      (is (= (basalt/bytes->hex (crypto/sha256 payload)) (:message-id result)))))

  (testing "k greater than view size returns all view elements"
    (let [rng (java.util.Random. 42)
          view (basalt/init-view [(basalt/make-peer "127.0.0.1" 8080 (:public (crypto/generate-keypair)))
                                  (basalt/make-peer "127.0.0.1" 8081 (:public (crypto/generate-keypair)))])
          payload (.getBytes "hello")
          result (murmur/initiate-broadcast payload rng view 5)]
      (is (= 2 (count (:targets result))))
      (is (= view (set (:targets result)))))))
