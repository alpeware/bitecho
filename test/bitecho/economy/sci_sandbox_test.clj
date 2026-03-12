(ns bitecho.economy.sci-sandbox-test
  "Tests for the pure-functional sci sandbox"
  (:require [bitecho.economy.sci-sandbox :as sci-sandbox]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]))

(deftest ^{:doc "Test basic evaluations inside the sandbox"}
  eval-string-basic-test
  (testing "Basic arithmetic works"
    (is (= 6 (sci-sandbox/eval-string "(+ 1 2 3)")))
    (is (= 120 (sci-sandbox/eval-string "(* 1 2 3 4 5)"))))
  (testing "Basic pure core functions work"
    (is (= [2 3 4] (sci-sandbox/eval-string "(map inc [1 2 3])")))))

(deftest ^{:doc "Test that side-effecting functions are unavailable or fail"}
  eval-string-isolation-test
  (testing "slurp is disabled"
    (is (thrown? Exception (sci-sandbox/eval-string "(slurp \"deps.edn\")"))))
  (testing "spit is disabled"
    (is (thrown? Exception (sci-sandbox/eval-string "(spit \"test.txt\" \"hello\")"))))
  (testing "println does not leak outside (or is disabled)"
    (is (thrown? Exception (sci-sandbox/eval-string "(println \"hello\")"))))
  (testing "Future/threads are disabled"
    (is (thrown? Exception (sci-sandbox/eval-string "(future 1)"))))
  (testing "Atom mutations are disabled"
    (is (thrown? Exception (sci-sandbox/eval-string "(reset! (atom 1) 2)")))))

(deftest ^{:doc "Test that infinite loops are blocked by the AST pre-validator"}
  eval-string-turing-incomplete-test
  (testing "loop is blocked"
    (is (thrown-with-msg? Exception #"Script contains forbidden recursive/looping constructs"
                          (sci-sandbox/eval-string "(loop [] (recur))"))))
  (testing "recur is blocked"
    (is (thrown-with-msg? Exception #"Script contains forbidden recursive/looping constructs"
                          (sci-sandbox/eval-string "(recur)"))))
  (testing "fn is blocked"
    (is (thrown-with-msg? Exception #"Script contains forbidden recursive/looping constructs"
                          (sci-sandbox/eval-string "(fn [] 1)"))))
  (testing "defn is blocked"
    (is (thrown-with-msg? Exception #"Script contains forbidden recursive/looping constructs"
                          (sci-sandbox/eval-string "(defn a [] 1)"))))
  (testing "while is blocked"
    (is (thrown-with-msg? Exception #"Script contains forbidden recursive/looping constructs"
                          (sci-sandbox/eval-string "(while true 1)"))))
  (testing "for is blocked"
    (is (thrown-with-msg? Exception #"Script contains forbidden recursive/looping constructs"
                          (sci-sandbox/eval-string "(for [x [1]] x)")))))

(deftest ^{:doc "Test that scripts have bounded execution limits"}
  eval-string-size-limit-test
  (testing "Script exceeding 4096 bytes is rejected"
    (let [large-script (str "(+ 1 " (str/join " " (repeat 4000 "1")) ")")]
      (is (thrown-with-msg? Exception #"Script exceeds maximum allowed size"
                            (sci-sandbox/eval-string large-script))))))

(deftest ^{:doc "Test infinite sequence prevention"}
  eval-string-no-infinite-seqs-test
  (testing "range is disabled"
    (is (thrown? Exception (sci-sandbox/eval-string "(range 10)"))))
  (testing "repeat is disabled"
    (is (thrown? Exception (sci-sandbox/eval-string "(repeat 1)"))))
  (testing "iterate is disabled"
    (is (thrown? Exception (sci-sandbox/eval-string "(iterate inc 1)")))))
