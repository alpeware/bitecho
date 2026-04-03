(ns bitecho.economy.account-test
  (:require [bitecho.economy.account :as account]
            [clojure.test :refer [deftest is testing]]))

(deftest account-records-test
  (testing "AccountState record creation"
    (let [state (account/map->AccountState {:balance 100
                                            :seq 5
                                            :deps ["hash1" "hash2"]})]
      (is (= 100 (:balance state)))
      (is (= 5 (:seq state)))
      (is (= ["hash1" "hash2"] (:deps state)))))

  (testing "Transfer record creation"
    (let [transfer (account/map->Transfer {:sender "pubkey1"
                                           :receiver "pubkey2"
                                           :amount 50
                                           :seq 6
                                           :deps ["hash3"]
                                           :signature "sig123"})]
      (is (= "pubkey1" (:sender transfer)))
      (is (= "pubkey2" (:receiver transfer)))
      (is (= 50 (:amount transfer)))
      (is (= 6 (:seq transfer)))
      (is (= ["hash3"] (:deps transfer)))
      (is (= "sig123" (:signature transfer))))))
