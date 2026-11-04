(ns bitecho.murmur.core-test
  "Tests for Murmur probabilistic broadcast protocol.
   Portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.murmur.core :as murmur]
            [clojure.set :as set]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def ^:private empty-queue
  #?(:clj clojure.lang.PersistentQueue/EMPTY
     :cljs (.-EMPTY cljs.core/PersistentQueue)))

(def ^{:doc "Generator for Ed25519 public keys"} gen-pubkey
  (gen/fmap (fn [_] (:public (crypto/generate-keypair)))
            (gen/return nil)))

(def ^{:doc "Generator for Basalt peers"} gen-peer
  (gen/let [ip gen/string-alphanumeric
            port gen/nat
            pubkey gen-pubkey]
    (basalt/make-peer ip port pubkey)))

(def ^{:doc "Generator for Basalt views"} gen-view
  (gen/vector gen-peer 0 10))

(def ^{:doc "Generator for byte array payloads"} gen-payload
  (gen/fmap (fn [v] #?(:clj (byte-array (map byte v))
                       :cljs (js/Uint8Array. (clj->js v))))
            (gen/vector #?(:clj gen/byte :cljs (gen/choose -128 127)))))

(defspec ^{:doc "Initiate broadcast targets k random peers and deterministic ID"}
  initiate-broadcast-invariants
  50
  (prop/for-all [view gen-view
                 k gen/nat
                 payload gen-payload
                 seed gen/nat]
                (let [rng (crypto/make-random seed)
                      result (murmur/initiate-broadcast payload rng view k)
                      expected-id (basalt/bytes->hex (crypto/sha256 payload))
                      expected-target-count (min k (count (set view)))]
                  (and
                   (= expected-id (:message-id result))
                   (fressian/byte-array-equals? payload (:payload result))
                   (= expected-target-count (count (:targets result)))
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
  50
  (prop/for-all [view gen-view
                 k gen/nat
                 msg gen-message
                 seed gen/nat
                 max-cache-size (gen/choose 1 100)]
                (let [rng (crypto/make-random seed)
                      empty-cache {:set #{} :queue empty-queue}
                      result (murmur/receive-gossip empty-cache msg rng view k max-cache-size)
                      expected-target-count (min k (count (set view)))]
                  (and
                   (contains? (-> result :cache :set) (:message-id msg))
                   (= msg (:message result))
                   (= expected-target-count (count (:forward-targets result)))
                   (= (set (:forward-targets result)) (set (take expected-target-count (:forward-targets result))))
                   (set/subset? (set (:forward-targets result)) (set view))))))

(defspec ^{:doc "receive-gossip drops seen messages"}
  receive-gossip-seen-invariants
  50
  (prop/for-all [view gen-view
                 k gen/nat
                 msg gen-message
                 seed gen/nat
                 max-cache-size (gen/choose 1 100)]
                (let [rng (crypto/make-random seed)
                      cache {:set #{(:message-id msg)} :queue (conj empty-queue (:message-id msg))}
                      result (murmur/receive-gossip cache msg rng view k max-cache-size)]
                  (and
                   (= cache (:cache result))
                   (nil? (:message result))
                   (empty? (:forward-targets result))))))

(deftest ^{:doc "Test edge cases for initiate broadcast"} test-initiate-broadcast
  (testing "empty view returns no targets"
    (let [rng (crypto/make-random 42)
          payload (fressian/utf8->bytes "hello")
          result (murmur/initiate-broadcast payload rng #{} 3)]
      (is (= 0 (count (:targets result))))
      (is (= (basalt/bytes->hex (crypto/sha256 payload)) (:message-id result)))))

  (testing "k greater than view size returns all view elements"
    (let [rng (crypto/make-random 42)
          peers [(basalt/make-peer "127.0.0.1" 8080 (:public (crypto/generate-keypair)))
                 (basalt/make-peer "127.0.0.1" 8081 (:public (crypto/generate-keypair)))]
          view peers
          payload (fressian/utf8->bytes "hello")
          result (murmur/initiate-broadcast payload rng view 5)]
      (is (= 2 (count (:targets result))))
      (is (= (set view) (set (:targets result)))))))

(deftest ^{:doc "Test cache eviction in receive-gossip"} test-receive-gossip-cache
  (testing "cache evicts oldest element when max-cache-size is exceeded"
    (let [rng (crypto/make-random 42)
          view #{}
          k 3
          max-size 2
          msg1 {:message-id "id1" :payload (fressian/utf8->bytes "p1")}
          msg2 {:message-id "id2" :payload (fressian/utf8->bytes "p2")}
          msg3 {:message-id "id3" :payload (fressian/utf8->bytes "p3")}
          empty-cache {:set #{} :queue empty-queue}

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
