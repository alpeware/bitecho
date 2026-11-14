(ns bitecho.shell.persistence-test
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.light-node :as light-node]
            [bitecho.shell.persistence :as persistence]
            [bitecho.streamlet.core :as streamlet]
            [clojure.core.async :as async]
            [clojure.test :refer [deftest is testing]])
  (:import [java.nio.file Files]))

(deftest ^{:doc "Tests that strip-unserializable-state converts PersistentQueue to vector"}
  strip-unserializable-state-test
  (testing "strip-unserializable-state converts PersistentQueue to vector"
    (let [queue (into clojure.lang.PersistentQueue/EMPTY [1 2 3])
          state {:murmur-cache {:queue queue :set #{1 2 3}} :other "data"}
          stripped (persistence/strip-unserializable-state state)]
      (is (vector? (get-in stripped [:murmur-cache :queue])))
      (is (= [1 2 3] (get-in stripped [:murmur-cache :queue])))
      (is (= #{1 2 3} (get-in stripped [:murmur-cache :set])))
      (is (= "data" (:other stripped))))))

(deftest ^{:doc "Tests that restore-unserializable-state converts vector back to PersistentQueue"}
  restore-unserializable-state-test
  (testing "restore-unserializable-state converts vector back to PersistentQueue"
    (let [state {:murmur-cache {:queue [1 2 3] :set #{1 2 3}} :other "data"}
          restored (persistence/restore-unserializable-state state)
          queue (get-in restored [:murmur-cache :queue])]
      (is (instance? clojure.lang.PersistentQueue queue))
      (is (= '(1 2 3) (seq queue)))
      (is (= #{1 2 3} (get-in restored [:murmur-cache :set])))
      (is (= "data" (:other restored))))))

(deftest ^{:doc "Tests that round-trip save and load to disk preserves state"}
  save-and-load-test
  (testing "save-and-load-test to a temporary file"
    (let [temp-file (java.io.File/createTempFile "bitecho-test" ".bin")
          filepath (.getAbsolutePath temp-file)
          queue (into clojure.lang.PersistentQueue/EMPTY [1 2 3])
          state {:murmur-cache {:queue queue :set #{1 2 3}}
                 :basalt-view #{{:pubkey "abc"}}
                 :contagion-known-ids #{"a" "b"}
                 :channels {"chan1" {:pubkey-a "a" :balance-a 100}}}
          _ (persistence/save-state-to-disk filepath state)
          loaded (persistence/load-state-from-disk filepath)]
      (is (instance? clojure.lang.PersistentQueue (get-in loaded [:murmur-cache :queue])))
      (is (= '(1 2 3) (seq (get-in loaded [:murmur-cache :queue]))))
      (is (= #{1 2 3} (get-in loaded [:murmur-cache :set])))
      (is (= #{{:pubkey "abc"}} (:basalt-view loaded)))
      (is (= #{"a" "b"} (:contagion-known-ids loaded)))
      (is (= 100 (get-in loaded [:channels "chan1" :balance-a])))
      (.delete temp-file))))

(deftest ^{:doc "Tests that strip-unserializable-state removes Random and channels"}
  strip-unserializable-state-walk-test
  (testing "strip-unserializable-state removes Random and core.async channels"
    (let [queue (into clojure.lang.PersistentQueue/EMPTY [1 2 3])
          chan (async/chan)
          rand (java.util.Random.)
          state {:murmur-cache {:queue queue :set #{1 2 3}}
                 :events-in chan
                 :rng rand
                 :nested {:more-rand rand :data "data"}}
          stripped (persistence/strip-unserializable-state state)]
      (is (vector? (get-in stripped [:murmur-cache :queue])))
      (is (= [1 2 3] (get-in stripped [:murmur-cache :queue])))
      (is (= #{1 2 3} (get-in stripped [:murmur-cache :set])))
      (is (nil? (:events-in stripped)))
      (is (nil? (:rng stripped)))
      (is (nil? (:more-rand (:nested stripped))))
      (is (= "data" (:data (:nested stripped)))))))

(deftest ^{:doc "Tests 16 concurrent threads saving state simultaneously without NoSuchFileException"}
  concurrent-save-race-resilience-test
  (testing "16 concurrent threads saving snapshot-save-to-disk and save-light-state! without race conditions"
    (let [temp-snap (java.io.File/createTempFile "snap-race" ".bin")
          snap-path (.getAbsolutePath temp-snap)
          temp-light (java.io.File/createTempFile "light-race" ".bin")
          light-path (.getAbsolutePath temp-light)
          n-threads 16
          pool (java.util.concurrent.Executors/newFixedThreadPool n-threads)]
      (try
        ;; Test persistence/save-state-to-disk
        (let [tasks (mapv (fn [i]
                            (fn []
                              (persistence/save-state-to-disk snap-path {:index i :payload (str "data-" i)})))
                          (range n-threads))
              futures (.invokeAll pool tasks)
              results (mapv (fn [^java.util.concurrent.Future f] (.get f)) futures)]
          (is (every? true? results))
          (is (some? (persistence/load-state-from-disk snap-path))))

        ;; Test light-node/save-light-state!
        (let [tasks (mapv (fn [i]
                            (fn []
                              (light-node/save-light-state! light-path {:index i :identity {:pubkey (str "pk-" i)}})))
                          (range n-threads))
              futures (.invokeAll pool tasks)
              results (mapv (fn [^java.util.concurrent.Future f] (.get f)) futures)]
          (is (every? true? results))
          (is (some? (light-node/load-light-state! light-path))))
        (finally
          (.shutdown pool)
          (try (.delete temp-snap) (catch Exception _ nil))
          (try (.delete temp-light) (catch Exception _ nil)))))))

(deftest fressian-record-reconstitution-and-nippy-rejection-test
  (testing "persistence/save-state-to-disk and load-state-from-disk reconstitute records and sets and reject NPY magic bytes fail-closed"
    (let [temp-file (java.io.File/createTempFile "bitecho-fressian-snap" ".bin")
          filepath (.getAbsolutePath temp-file)
          acct (account/map->AccountState {:balance 5000 :seq 2 :deps ["d1"]})
          blk (streamlet/map->Block {:epoch 1 :parent-hash "genesis" :txs ["tx1"] :proposer "p1" :signature "sig1"})
          vote (streamlet/map->Vote {:epoch 1 :block-hash "bh1" :voter "v1" :signature "vsig1"})
          ack (rendezvous/map->DeliveryAck {:offer-hash "oh1" :seq 1 :callee "c1" :home-node :node1 :epoch 1 :debit 10 :signature "asig1"})
          peer (basalt/make-peer "127.0.0.1" 5000 (byte-array 32 (byte 7)))
          state {:ledger {"alice" acct}
                 :blocks {"bh1" blk}
                 :block-votes {"bh1" #{"v1"}}
                 :block-vote-proofs {"bh1" {"v1" vote}}
                 :pending-vouchers [ack]
                 :basalt-view [{:hash (byte-array 32) :peer peer}]
                 :notarized-blocks #{"bh1"}
                 :finalized-blocks #{"genesis"}
                 :executed-finalized-blocks #{"genesis"}
                 :minted-epochs #{1}
                 :contagion-known-ids #{"m1"}
                 :known-receipt-ids #{"r1"}
                 :executed-receipt-ids #{"r0"}
                 :settled-escrow-ids #{"e1"}
                 :voted-epochs #{1}
                 :equivocated-voters #{"bad1"}
                 :murmur-cache {:queue (into clojure.lang.PersistentQueue/EMPTY ["m1"])
                                :seen #{"m1"}}}]
      (try
        (persistence/save-state-to-disk filepath state)
        (let [raw-bytes (Files/readAllBytes (.toPath temp-file))
              loaded (persistence/load-state-from-disk filepath)]
          (is (not (fressian/nippy-payload? raw-bytes)))
          (is (instance? bitecho.economy.account.AccountState (get-in loaded [:ledger "alice"])))
          (is (instance? bitecho.streamlet.core.Block (get-in loaded [:blocks "bh1"])))
          (is (instance? bitecho.streamlet.core.Vote (get-in loaded [:block-vote-proofs "bh1" "v1"])))
          (is (instance? bitecho.rendezvous.core.DeliveryAck (first (:pending-vouchers loaded))))
          (is (instance? bitecho.basalt.core.Peer (get-in loaded [:basalt-view 0 :peer])))
          (is (set? (get-in loaded [:block-votes "bh1"])))
          (is (set? (:notarized-blocks loaded)))
          (is (set? (:finalized-blocks loaded)))
          (is (set? (:executed-finalized-blocks loaded)))
          (is (set? (:minted-epochs loaded)))
          (is (instance? clojure.lang.PersistentQueue (get-in loaded [:murmur-cache :queue]))))
        ;; Write legacy NPY magic header bytes and verify fail-closed rejection
        (Files/write (.toPath temp-file)
                     (byte-array [78 80 89 0 1 2 3 4])
                     (into-array java.nio.file.OpenOption []))
        (is (nil? (persistence/load-state-from-disk filepath)))
        (finally
          (.delete temp-file))))))
