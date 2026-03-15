(ns bitecho.lottery.core-ttl-test
  (:require [bitecho.crypto :as crypto]
            [bitecho.lottery.core :as lottery]
            [clojure.test :refer [deftest is]]))

(deftest ^{:doc "Tests that old lottery tickets fail validation"} ticket-expiration-test
  (let [payload (.getBytes "hello")
        nonce 123
        keypair (crypto/generate-keypair)
        max-difficulty (apply str (repeat 64 "f"))
        ;; Ticket generated now (epoch 0)
        ticket (lottery/generate-ticket payload nonce (:private keypair) (:public keypair) 0)
        ;; Ticket is valid right now (epoch 0)
        valid-now (lottery/winning-ticket? ticket max-difficulty 0)
        ;; Ticket is invalid after expiration (say, epoch 10 if ttl is 10)
        valid-later (lottery/winning-ticket? ticket max-difficulty 11)]
    (is valid-now)
    (is (not valid-later))))
