(ns bitecho.economy.puzzle-test
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [bitecho.state-machine :as sm]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest test-puzzle-cid-content-addressing
  (testing "puzzle-cid computes canonical SHA-256 matching canonical AST Blob CID"
    (let [src "(and (= (get solution :x) 42) true)"
          cid (puzzle/puzzle-cid src)
          ast (puzzle/canonicalize-puzzle-ast src)
          blob (data/make-blob (fressian/encode-canonical ast) "application/x-bitecho-sci-puzzle")]
      (is (= 64 (count cid)))
      (is (= cid (:blob/cid blob)))
      (is (re-matches #"[0-9a-f]{64}" cid)))))

(deftest test-puzzle-ast-canonicalization-invariants
  (testing "Comments, extra whitespace, newlines, and map key reordering produce exact same puzzle-cid"
    (let [src1 "(fn [env solution]\n  ;; author comment\n  {:b 2 :a 1})"
          src2 "   (fn [env solution] {:a 1 :b 2}   )\n\n"
          src3 "(fn [env solution] {:b 2 :a 1})"
          cid1 (puzzle/puzzle-cid src1)
          cid2 (puzzle/puzzle-cid src2)
          cid3 (puzzle/puzzle-cid src3)]
      (is (= cid1 cid2))
      (is (= cid1 cid3))))

  (testing "Disjoint tagged collections: list (+ 1 2) vs vector [+ 1 2] produce different puzzle-cid"
    (let [cid-list (puzzle/puzzle-cid "(+ 1 2)")
          cid-vec (puzzle/puzzle-cid "[+ 1 2]")]
      (is (not= cid-list cid-vec))))

  (testing "Symbol, keyword, and literal changes produce different puzzle-cid"
    (let [c1 (puzzle/puzzle-cid "(fn [env sol] 42)")
          c2 (puzzle/puzzle-cid "(fn [env sol] 43)")
          c3 (puzzle/puzzle-cid "(fn [env sol] :foo)")
          c4 (puzzle/puzzle-cid "(fn [env sol] :bar)")]
      (is (not= c1 c2))
      (is (not= c3 c4))
      (is (not= c1 c3)))))

(deftest test-standard-htlc-puzzle-evaluation
  (testing "standard-htlc-cid is deterministic and 64 hex characters"
    (let [cid (puzzle/standard-htlc-cid)]
      (is (string? cid))
      (is (= 64 (count cid)))
      (is (= cid (puzzle/puzzle-cid puzzle/standard-htlc-puzzle-source)))))

  (testing "standard-htlc-puzzle-source evaluates payer-authorized release"
    (let [env {:amount 1000 :receiver "alice" :payer "bob"}
          sol {:mode :payer-authorized}
          res (puzzle/eval-puzzle puzzle/standard-htlc-puzzle-source sol env)]
      (is (true? (:valid? res)))
      (is (= [{:type :release :amount 1000 :receiver "alice"}] (:conditions res)))))

  (testing "standard-htlc-puzzle-source evaluates deliverable preimage release"
    (let [secret "bitecho-secret-deliverable-data"
          d-hash (str/lower-case (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes secret))))
          env {:amount 1000 :receiver "alice" :payer "bob" :deliverable-hash d-hash}
          sol {:mode :preimage :preimage secret}
          res (puzzle/eval-puzzle puzzle/standard-htlc-puzzle-source sol env)]
      (is (true? (:valid? res)))
      (is (= [{:type :release :amount 1000 :receiver "alice"}] (:conditions res))))

    (let [env {:amount 1000 :receiver "alice" :payer "bob" :deliverable-hash "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa"}
          sol {:mode :preimage :preimage "wrong-preimage"}
          res (puzzle/eval-puzzle puzzle/standard-htlc-puzzle-source sol env)]
      (is (false? (:valid? res)))
      (is (= :invalid-puzzle-conditions (:error res))))))

(deftest test-eval-puzzle-boolean-return
  (testing "Boolean true returns default release condition"
    (let [src "(= (get solution :secret) \"open-sesame\")"
          sol {:secret "open-sesame"}
          env {:amount 500 :receiver "alice" :payer "bob"}
          res (puzzle/eval-puzzle src sol env)]
      (is (true? (:valid? res)))
      (is (= [{:type :release :receiver "alice" :amount 500}] (:conditions res)))))

  (testing "Boolean false or nil returns false error"
    (let [src "(= (get solution :secret) \"open-sesame\")"
          sol {:secret "wrong-pass"}
          env {:amount 500 :receiver "alice" :payer "bob"}
          res (puzzle/eval-puzzle src sol env)]
      (is (false? (:valid? res)))
      (is (= :puzzle-returned-false (:error res))))))

(deftest test-eval-puzzle-content-address-mismatch
  (testing "Mismatch against (:puzzle-hash env-ctx) fails before execution"
    (let [src "(+ 1 2)"
          bogus-cid "0000000000000000000000000000000000000000000000000000000000000000"
          env {:amount 100 :receiver "alice" :payer "bob" :puzzle-hash bogus-cid}
          res (puzzle/eval-puzzle src {} env)]
      (is (false? (:valid? res)))
      (is (= :puzzle-hash-mismatch (:error res))))))

(deftest test-eval-puzzle-step-budget-exceeded
  (testing "Infinite or expensive iteration halts with puzzle-budget-exceeded"
    (let [src "(reduce + 0 (range 1000))"
          env {:amount 100 :receiver "alice" :payer "bob"}
          res (puzzle/eval-puzzle src {} env {:max-steps 100})]
      (is (false? (:valid? res)))
      (is (= :puzzle-budget-exceeded (:error res))))))

(deftest test-eval-puzzle-size-bounds
  (testing "Source exceeding max-bytes rejected"
    (let [src (str/join "" (repeat 20000 " "))
          env {:amount 100 :receiver "alice" :payer "bob"}
          res (puzzle/eval-puzzle src {} env {:max-bytes 1000})]
      (is (false? (:valid? res)))
      (is (= :puzzle-size-exceeded (:error res))))))

(deftest test-eval-puzzle-sandbox-security
  (testing "Denied operations (host classes, loop, def) fail in sandbox"
    (let [env {:amount 100 :receiver "alice" :payer "bob"}]
      (is (= :puzzle-eval-error (:error (puzzle/eval-puzzle "(System/exit 0)" {} env))))
      (is (= :puzzle-eval-error (:error (puzzle/eval-puzzle "(loop [x 0] (recur (inc x)))" {} env))))
      (is (= :puzzle-eval-error (:error (puzzle/eval-puzzle "(def x 10)" {} env))))
      (is (= :puzzle-eval-error (:error (puzzle/eval-puzzle "(slurp \"/etc/passwd\")" {} env)))))))

(deftest test-eval-puzzle-uop-kernel-oracle-scenario
  (testing "Scenario 1: UOp kernel + Oracle attestation split"
    (let [oracle-kp (crypto/generate-keypair)
          oracle-pub (basalt/bytes->hex (:public oracle-kp))
          kernel-src "float sigmoid(float x) { return 1.0f / (1.0f + expf(-x)); }"
          kernel-hash (str/lower-case (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes kernel-src))))
          oracle-sig (basalt/bytes->hex (crypto/sign (:private oracle-kp) (fressian/utf8->bytes kernel-src)))
          puzzle-code (str "(and (= (sha256 (get solution :uop-kernel-source)) (get env :deliverable-hash))\n"
                           "     (verify-signature \"" oracle-pub "\" (get solution :uop-kernel-source) (get solution :oracle-sig))\n"
                           "     [ {:type :release :receiver (:receiver env) :amount 900}\n"
                           "       {:type :release :receiver \"" oracle-pub "\" :amount 100} ])")
          p-cid (puzzle/puzzle-cid puzzle-code)
          env {:amount 1000 :receiver "alice" :payer "bob" :deliverable-hash kernel-hash :puzzle-hash p-cid}
          sol {:uop-kernel-source kernel-src :oracle-sig oracle-sig}
          res (puzzle/eval-puzzle puzzle-code sol env)]
      (is (true? (:valid? res)))
      (is (= [{:type :release :receiver "alice" :amount 900}
              {:type :release :receiver oracle-pub :amount 100}]
             (:conditions res)))

      (testing "Adversarial invalid signature fails"
        (let [bad-sol {:uop-kernel-source kernel-src :oracle-sig (basalt/bytes->hex (byte-array 64))}
              bad-res (puzzle/eval-puzzle puzzle-code bad-sol env)]
          (is (false? (:valid? bad-res)))
          (is (= :puzzle-returned-false (:error bad-res))))))))

(deftest test-eval-puzzle-recursion-budget-exceeded
  (testing "Uncharged recursion attack ((fn [x] (x x)) (fn [x] (x x))) is halted with puzzle-budget-exceeded"
    (let [src "((fn [x] (x x)) (fn [x] (x x)))"
          env {:amount 100 :receiver "alice" :payer "bob"}
          res (puzzle/eval-puzzle src {} env {:max-steps 100})]
      (is (false? (:valid? res)))
      (is (= :puzzle-budget-exceeded (:error res))))))

(deftest test-eval-puzzle-allocation-budget-exceeded
  (testing "Excessive allocation is halted with puzzle-budget-exceeded"
    (let [src "(vec (range 200))"
          env {:amount 100 :receiver "alice" :payer "bob"}
          res (puzzle/eval-puzzle src {} env {:max-bytes 50})]
      (is (false? (:valid? res)))
      (is (= :puzzle-budget-exceeded (:error res))))))

(deftest test-puzzle-locked-escrow-preimage-bypass-rejected
  (testing "B-P23-1: Submitting deliverable preimage on a puzzle-locked escrow without puzzle-source is rejected"
    (let [client-pub "302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111"
          author-pub "302a300506032b65700321002222222222222222222222222222222222222222222222222222222222222222"
          init-st (-> (sm/init-state [] "val-1" (assoc config/default-config :settlement-take-bps 50))
                      (assoc-in [:ledger client-pub]
                                (account/map->AccountState {:balance 2000 :seq 0 :deps []})))
          kernel-src "float relu(float x) { return x > 0.0f ? x : 0.0f; }"
          kernel-hash (str/lower-case (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes kernel-src))))
          puzzle-code "(= (get solution :secret) 42)"
          puzzle-hash (puzzle/puzzle-cid puzzle-code)
          escrow-id (escrow/compute-escrow-id client-pub author-pub 1000 kernel-hash 1 100 "test-bypass-escrow")
          lock-evt {:type :lock-intent
                    :escrow-id escrow-id
                    :payer client-pub
                    :receiver author-pub
                    :amount 1000
                    :deliverable-hash kernel-hash
                    :puzzle-hash puzzle-hash
                    :created-epoch 1
                    :expires-epoch 100
                    :epoch 1
                    :sender client-pub}
          st-locked (:state (sm/handle-event init-st lock-evt))
          _ (is (= :locked (get-in st-locked [:escrows escrow-id :status])))
          bypass-res (sm/handle-event st-locked
                                      {:type :release-intent
                                       :escrow-id escrow-id
                                       :preimage kernel-src
                                       :sender author-pub
                                       :epoch 2})]
      (is (= :locked (get-in (:state bypass-res) [:escrows escrow-id :status]))))))

(deftest test-eval-puzzle-overspend-and-auto-refund
  (testing "Conditions exceeding env amount trigger overspend violation"
    (let [src "[{:type :release :receiver \"alice\" :amount 800}\n {:type :release :receiver \"charlie\" :amount 300}]"
          env {:amount 1000 :receiver "alice" :payer "bob"}
          res (puzzle/eval-puzzle src {} env)]
      (is (false? (:valid? res)))
      (is (= :puzzle-overspend-violation (:error res)))))

  (testing "Conditions less than env amount auto-refund remainder to payer"
    (let [src "[{:type :release :receiver \"alice\" :amount 700}]"
          env {:amount 1000 :receiver "alice" :payer "bob"}
          res (puzzle/eval-puzzle src {} env)]
      (is (true? (:valid? res)))
      (is (= [{:type :release :receiver "alice" :amount 700}
              {:type :refund-remainder :receiver "bob" :amount 300}]
             (:conditions res))))))

;; =============================================================================
;; Generative Invariant Properties (Rule 1)
;; =============================================================================

(defspec ^{:doc "Invariantly preserves token conservation: conditions release + refund equals original amount."}
  prop-puzzle-tokenomic-conservation 30
  (prop/for-all [total-amount (gen/choose 100 10000)
                 pct1 (gen/choose 10 50)
                 pct2 (gen/choose 10 40)]
                (let [amt1 (quot (* total-amount pct1) 100)
                      amt2 (quot (* total-amount pct2) 100)
                      src (str "[{:type :release :receiver \"recipient-1\" :amount " amt1 "}\n"
                               " {:type :release :receiver \"recipient-2\" :amount " amt2 "}]")
                      env {:amount total-amount :receiver "recipient-1" :payer "payer-1"}
                      res (puzzle/eval-puzzle src {} env)]
                  (and (true? (:valid? res))
                       (let [conds (:conditions res)
                             total-cond-sum (reduce + 0 (map :amount conds))]
                         (= total-amount total-cond-sum))))))

(defspec ^{:doc "Invariantly preserves canonical puzzle-cid under arbitrary comments and whitespace additions."}
  prop-puzzle-comments-and-whitespace-invariance 30
  (prop/for-all [comment-text (gen/fmap (partial apply str) (gen/vector gen/char-alphanumeric 0 32))
                 whitespace (gen/elements [" " "   " "\n  \t\n" "\n\n   "])]
                (let [base-src "(fn [env solution] [[:release (:amount env) (:receiver env)]])"
                      decorated-src (str whitespace base-src " ;; " comment-text "\n" whitespace)
                      base-cid (puzzle/puzzle-cid base-src)
                      dec-cid (puzzle/puzzle-cid decorated-src)]
                  (= base-cid dec-cid))))

(defspec ^{:doc "Invariantly detects and rejects any tampering with puzzle source AST forms."}
  prop-puzzle-content-address-tamper-resistance 30
  (prop/for-all [val (gen/choose 1 1000)]
                (let [base-src "(and true true)"
                      tampered-src (str "(and true " val ")")
                      canonical-cid (puzzle/puzzle-cid base-src)
                      env {:amount 100 :receiver "alice" :payer "bob" :puzzle-hash canonical-cid}
                      res (puzzle/eval-puzzle tampered-src {} env)]
                  (and (false? (:valid? res))
                       (= :puzzle-hash-mismatch (:error res))))))
