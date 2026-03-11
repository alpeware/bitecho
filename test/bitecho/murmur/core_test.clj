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

(def ^{:doc "Generator for message ids"} gen-message-id
  (gen/fmap basalt/bytes->hex (gen/fmap crypto/sha256 gen-payload)))

(def ^{:doc "Generator for Murmur messages"} gen-message
  (gen/let [msg-id gen-message-id
            payload gen-payload]
    {:message-id msg-id
     :payload payload}))

(defspec ^{:doc "receive-gossip forwards unseen messages and updates cache"}
  receive-gossip-unseen-invariants
  100
  (prop/for-all [view gen-view
                 k gen/nat
                 msg gen-message
                 seed gen/nat
                 max-cache-size (gen/choose 1 100)]
                (let [rng (java.util.Random. seed)
                      empty-cache {:set #{} :queue clojure.lang.PersistentQueue/EMPTY}
                      result (murmur/receive-gossip empty-cache msg rng view k max-cache-size)
                      expected-target-count (min k (count view))]
                  (and
                   (contains? (-> result :cache :set) (:message-id msg))
                   (= msg (:message result))
                   (= expected-target-count (count (:forward-targets result)))
                   (set/subset? (set (:forward-targets result)) (set view))))))

(defspec ^{:doc "receive-gossip drops seen messages"}
  receive-gossip-seen-invariants
  100
  (prop/for-all [view gen-view
                 k gen/nat
                 msg gen-message
                 seed gen/nat
                 max-cache-size (gen/choose 1 100)]
                (let [rng (java.util.Random. seed)
                      cache {:set #{(:message-id msg)} :queue (conj clojure.lang.PersistentQueue/EMPTY (:message-id msg))}
                      result (murmur/receive-gossip cache msg rng view k max-cache-size)]
                  (and
                   (= cache (:cache result))
                   (nil? (:message result))
                   (empty? (:forward-targets result))))))

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

(deftest ^{:doc "Test cache eviction in receive-gossip"} test-receive-gossip-cache
  (testing "cache evicts oldest element when max-cache-size is exceeded"
    (let [rng (java.util.Random. 42)
          view #{}
          k 3
          max-size 2
          msg1 {:message-id "id1" :payload (.getBytes "p1")}
          msg2 {:message-id "id2" :payload (.getBytes "p2")}
          msg3 {:message-id "id3" :payload (.getBytes "p3")}
          empty-cache {:set #{} :queue clojure.lang.PersistentQueue/EMPTY}

          res1 (murmur/receive-gossip empty-cache msg1 rng view k max-size)
          cache1 (:cache res1)

          res2 (murmur/receive-gossip cache1 msg2 rng view k max-size)
          cache2 (:cache res2)

          res3 (murmur/receive-gossip cache2 msg3 rng view k max-size)
          cache3 (:cache res3)]

      (is (= #{"id1"} (:set cache1)))
      (is (= #{"id1" "id2"} (:set cache2)))
      (is (= #{"id2" "id3"} (:set cache3)))
      (is (= ["id2" "id3"] (vec (:queue cache3)))))))
