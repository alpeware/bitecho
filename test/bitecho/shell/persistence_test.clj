(ns bitecho.shell.persistence-test
  (:require [bitecho.shell.persistence :as persistence]
            [clojure.core.async :as async]
            [clojure.test :refer [deftest is testing]]))

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
                 :basalt-view #{{:pubkey "abc" :age 1}}
                 :contagion-known-ids #{"a" "b"}
                 :channels {"chan1" {:pubkey-a "a" :balance-a 100}}}
          _ (persistence/save-state-to-disk filepath state)
          loaded (persistence/load-state-from-disk filepath)]
      (is (instance? clojure.lang.PersistentQueue (get-in loaded [:murmur-cache :queue])))
      (is (= '(1 2 3) (seq (get-in loaded [:murmur-cache :queue]))))
      (is (= #{1 2 3} (get-in loaded [:murmur-cache :set])))
      (is (= #{{:pubkey "abc" :age 1}} (:basalt-view loaded)))
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
