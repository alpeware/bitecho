(ns bitecho.economy.difficulty-test
  "Tests for dynamic lottery difficulty calculation."
  (:require [bitecho.economy.difficulty :as difficulty]
            [clojure.test :refer [deftest is]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.math BigInteger]))

(def gen-k
  "Generator for k (fanout), typically a small positive integer."
  (gen/choose 1 100))

(def gen-network-scale
  "Generator for network size estimates."
  (gen/choose 1 1000000))

(defn- hex->bigint
  "Converts a hex string to a BigInteger."
  [^String hex-str]
  (BigInteger. hex-str 16))

(defspec ^{:doc "Difficulty should scale inversely with network size for a fixed k."}
  difficulty-scales-inversely-with-network-scale
  100
  (prop/for-all [k gen-k
                 n1 gen-network-scale
                 n2 gen-network-scale]
                (if (< n1 n2)
                  (let [diff1 (difficulty/calculate-difficulty k n1)
                        diff2 (difficulty/calculate-difficulty k n2)
                        val1 (hex->bigint diff1)
                        val2 (hex->bigint diff2)]
                    (>= (.compareTo val1 val2) 0)) ;; diff1 (smaller net) >= diff2 (larger net)
                  true)))

(defspec ^{:doc "Difficulty should scale proportionally with k for a fixed network size."}
  difficulty-scales-proportionally-with-k
  100
  (prop/for-all [k1 gen-k
                 k2 gen-k
                 n gen-network-scale]
                (if (< k1 k2)
                  (let [diff1 (difficulty/calculate-difficulty k1 n)
                        diff2 (difficulty/calculate-difficulty k2 n)
                        val1 (hex->bigint diff1)
                        val2 (hex->bigint diff2)]
                    (<= (.compareTo val1 val2) 0)) ;; diff1 (smaller k) <= diff2 (larger k)
                  true)))

(deftest ^{:doc "Difficulty should be bounded by max-target (all FFs)."}
  difficulty-is-bounded-by-max-target
  (let [diff (difficulty/calculate-difficulty 100 1) ;; k > n to test upper bound clamping
        max-target (apply str (repeat 64 "f"))]
    (is (= diff max-target))))

(deftest ^{:doc "Difficulty is exactly a 64 character hex string."}
  difficulty-is-padded-to-64-chars
  (let [diff (difficulty/calculate-difficulty 1 1000000)]
    (is (= 64 (count diff)))
    (is (re-matches #"^[0-9a-f]{64}$" diff))))
