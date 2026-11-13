(ns bitecho.light-node.cli-test
  "Automated flag inventory, tokenizer, and command parser tests for bitecho.light-node.cli (Rules 1 & 6)."
  (:require [bitecho.light-node.cli :as cli]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; 1. Verb Inventory Verification (Rule 6)
;; =============================================================================

(deftest test-supported-verbs-inventory
  (testing "Exact 51 canonical verbs in supported-cli-verbs"
    (is (= 51 (count cli/supported-cli-verbs)))
    (is (= (count (distinct cli/supported-cli-verbs)) (count cli/supported-cli-verbs)))
    (is (= cli/supported-cli-verbs (vec (sort cli/supported-cli-verbs))))
    (is (every? #(re-matches #"^[a-z0-9]+(-[a-z0-9]+)*$" %) cli/supported-cli-verbs))
    (is (= (set cli/supported-cli-verbs) cli/supported-cli-verbs-set)))

  (testing "Presence of Milestone 2, 3, 4 verbs"
    (is (contains? cli/supported-cli-verbs-set "storage-put"))
    (is (contains? cli/supported-cli-verbs-set "storage-get"))
    (is (contains? cli/supported-cli-verbs-set "capability-publish"))
    (is (contains? cli/supported-cli-verbs-set "capability-resolve"))
    (is (contains? cli/supported-cli-verbs-set "lock-intent"))
    (is (contains? cli/supported-cli-verbs-set "release-intent"))
    (is (contains? cli/supported-cli-verbs-set "status"))
    (is (contains? cli/supported-cli-verbs-set "identity"))
    (is (contains? cli/supported-cli-verbs-set "wait"))))

;; =============================================================================
;; 2. CLI String Tokenizer
;; =============================================================================

(deftest test-tokenize-cli-string
  (testing "Basic whitespace tokenization"
    (is (= ["transfer" "--to" "alice" "--amount" "100"]
           (cli/tokenize-cli-string "transfer --to alice --amount 100"))))

  (testing "Double quoted strings with internal whitespace"
    (is (= ["send" "--to" "bob" "--message" "hello world from bitecho"]
           (cli/tokenize-cli-string "send --to bob --message \"hello world from bitecho\""))))

  (testing "Single quoted strings"
    (is (= ["send" "--to" "bob" "--text" "simple text"]
           (cli/tokenize-cli-string "send --to bob --text 'simple text'"))))

  (testing "Escaped quotes inside strings"
    (is (= ["send" "--message" "quote \"here\" works"]
           (cli/tokenize-cli-string "send --message \"quote \\\"here\\\" works\""))))

  (testing "Empty or blank strings"
    (is (= [] (cli/tokenize-cli-string "")))
    (is (= [] (cli/tokenize-cli-string "   \t\n  "))))

  (testing "Multiple spaces between tokens"
    (is (= ["status" "--verbose"]
           (cli/tokenize-cli-string "   status    --verbose   ")))))

;; =============================================================================
;; 3. Parse CLI Command
;; =============================================================================

(deftest test-parse-cli-command-verbs-and-flags
  (testing "transfer command parsing"
    (let [res (cli/parse-cli-command "transfer --to 302a... --amount 500 --seq 42")]
      (is (true? (:ok? res)))
      (is (= "transfer" (:verb res)))
      (is (= "302a..." (get-in res [:cmd-map "receiver"])))
      (is (= 500 (get-in res [:cmd-map "amount"])))
      (is (= 42 (get-in res [:cmd-map "seq"])))))

  (testing "storage-put command parsing"
    (let [res (cli/parse-cli-command "storage-put --subnet nexus --slot profile --data '{\"name\":\"alice\"}' --seq 3")]
      (is (true? (:ok? res)))
      (is (= "storage-put" (:verb res)))
      (is (= "nexus" (get-in res [:cmd-map "subnet_id"])))
      (is (= "profile" (get-in res [:cmd-map "slot"])))
      (is (= "{\"name\":\"alice\"}" (get-in res [:cmd-map "data"])))
      (is (= 3 (get-in res [:cmd-map "seq"])))))

  (testing "storage-get command parsing"
    (let [res (cli/parse-cli-command "storage-get --subnet nexus --slot profile --min-seq 2")]
      (is (true? (:ok? res)))
      (is (= "storage-get" (:verb res)))
      (is (= "nexus" (get-in res [:cmd-map "subnet_id"])))
      (is (= "profile" (get-in res [:cmd-map "slot"])))
      (is (= 2 (get-in res [:cmd-map "min_seq"])))))

  (testing "capability-publish command parsing"
    (let [res (cli/parse-cli-command "capability-publish --subnet nexus --capability-id uop-relu --capability-type compute/uop-kernel --price-echo 250")]
      (is (true? (:ok? res)))
      (is (= "capability-publish" (:verb res)))
      (is (= "nexus" (get-in res [:cmd-map "subnet_id"])))
      (is (= "uop-relu" (get-in res [:cmd-map "capability_id"])))
      (is (= "compute/uop-kernel" (get-in res [:cmd-map "capability_type"])))
      (is (= 250 (get-in res [:cmd-map "price_echo"])))))

  (testing "capability-resolve command parsing"
    (let [res (cli/parse-cli-command "capability-resolve --subnet nexus --capability-id uop-relu --authority 302a...")]
      (is (true? (:ok? res)))
      (is (= "capability-resolve" (:verb res)))
      (is (= "nexus" (get-in res [:cmd-map "subnet_id"])))
      (is (= "uop-relu" (get-in res [:cmd-map "capability_id"])))
      (is (= "302a..." (get-in res [:cmd-map "authority"])))))

  (testing "lock-intent with --puzzle-hash"
    (let [res (cli/parse-cli-command "lock-intent --to bob --amount 1000 --deliverable-hash dhash123 --puzzle-hash phash456 --expires-epoch 10")]
      (is (true? (:ok? res)))
      (is (= "lock-intent" (:verb res)))
      (is (= "phash456" (get-in res [:cmd-map "puzzle_hash"])))
      (is (= "dhash123" (get-in res [:cmd-map "deliverable_hash"])))
      (is (= 1000 (get-in res [:cmd-map "amount"])))
      (is (= 10 (get-in res [:cmd-map "expires_epoch"])))))

  (testing "release-intent with --puzzle-source and --solution"
    (let [res (cli/parse-cli-command "release-intent --escrow-id eid-1 --puzzle-source '(and true true)' --solution '{\"x\":1}'")]
      (is (true? (:ok? res)))
      (is (= "release-intent" (:verb res)))
      (is (= "eid-1" (get-in res [:cmd-map "escrow_id"])))
      (is (= "(and true true)" (get-in res [:cmd-map "puzzle_source"])))
      (is (= "{\"x\":1}" (get-in res [:cmd-map "solution"])))))

  (testing "Map input parsing"
    (let [res (cli/parse-cli-command {"cmd" "status"})]
      (is (true? (:ok? res)))
      (is (= "status" (:verb res)))
      (is (= {"cmd" "status"} (:cmd-map res))))
    (let [res2 (cli/parse-cli-command {:verb "transfer" :to "alice" :amount 100})]
      (is (true? (:ok? res2)))
      (is (= "transfer" (:verb res2)))
      (is (= "alice" (get-in res2 [:cmd-map "to"])))))

  (testing "Unknown verb rejected with structured error (Rule 5)"
    (let [res (cli/parse-cli-command "unknown-hack --flag 1")]
      (is (false? (:ok? res)))
      (is (= :invalid-verb (:error res)))
      (is (= "unknown-hack" (:verb res)))
      (is (vector? (:supported-verbs res))))))

;; =============================================================================
;; 4. Generative Invariant Property Checks (Rule 1)
;; =============================================================================

(defspec ^{:doc "Property: All supported verbs parse cleanly from vector and string format"}
  prop-all-supported-verbs-parse 51
  (prop/for-all [idx (gen/choose 0 (dec (count cli/supported-cli-verbs)))]
                (let [verb (nth cli/supported-cli-verbs idx)
                      res-vec (cli/parse-cli-command [verb])
                      res-str (cli/parse-cli-command verb)]
                  (and (true? (:ok? res-vec))
                       (true? (:ok? res-str))
                       (= verb (:verb res-vec))
                       (= verb (:verb res-str))
                       (= verb (get-in res-vec [:cmd-map "cmd"]))
                       (= verb (get-in res-str [:cmd-map "cmd"]))))))

(defspec ^{:doc "Property: Arbitrary unrecognized strings fail closed with :invalid-verb"}
  prop-unrecognized-verbs-fail-closed 30
  (prop/for-all [rnd-name (gen/fmap #(str "x-" %) (gen/not-empty gen/string-alphanumeric))]
                (if (cli/supported-cli-verbs-set (str/lower-case rnd-name))
                  true
                  (let [res (cli/parse-cli-command rnd-name)]
                    (and (false? (:ok? res))
                         (= :invalid-verb (:error res))
                         (= (str/lower-case rnd-name) (:verb res)))))))
