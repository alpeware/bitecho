(ns bitecho.channels.core-test
  "Tests for the pure data structures and functions of a 2-of-2 multisig Payment Channel state."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.channels.core :as channels]
            [bitecho.crypto :as crypto]
            [bitecho.economy.sci-sandbox :as sci-sandbox]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def gen-amount "Generator for positive amounts" gen/pos-int)

(deftest ^{:doc "Creating an initial channel state should establish correct keys and balances"}
  create-initial-state-test
  (testing "Initial state contains pubkeys and 0 nonce"
    (let [kp-a (crypto/generate-keypair)
          kp-b (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          pub-b (basalt/bytes->hex (:public kp-b))
          amount-a 100
          amount-b 50
          state (channels/create-initial-state pub-a pub-b amount-a amount-b)]
      (is (= pub-a (:pubkey-a state)))
      (is (= pub-b (:pubkey-b state)))
      (is (= amount-a (:balance-a state)))
      (is (= amount-b (:balance-b state)))
      (is (= 0 (:nonce state))))))

(defspec ^{:doc "Generated multisig puzzle evaluates to true only with correct cryptographic solutions"}
  generate-multisig-puzzle-spec
  100
  (prop/for-all [_amount-a gen-amount]
                (let [kp-a (crypto/generate-keypair)
                      kp-b (crypto/generate-keypair)
                      pub-a (basalt/bytes->hex (:public kp-a))
                      pub-b (basalt/bytes->hex (:public kp-b))
                      puzzle (channels/generate-multisig-puzzle pub-a pub-b)
                      tx-hash-str "dummy-tx-hash-for-testing"
                      tx-hash-bytes (crypto/sha256 (.getBytes tx-hash-str "UTF-8"))
                      tx-hash-hex (basalt/bytes->hex tx-hash-bytes)

                      sig-a-hex (basalt/bytes->hex (crypto/sign (:private kp-a) tx-hash-bytes))
                      sig-b-hex (basalt/bytes->hex (crypto/sign (:private kp-b) tx-hash-bytes))

                      kp-c (crypto/generate-keypair)
                      bad-sig-hex (basalt/bytes->hex (crypto/sign (:private kp-c) tx-hash-bytes))]

                  (and
                   ;; Valid solution
                   (true? (sci-sandbox/eval-string
                           (str "(let [solution {:sig-a \"" sig-a-hex "\" :sig-b \"" sig-b-hex "\" :tx-hash \"" tx-hash-hex "\"}] " puzzle ")")))
                   ;; Invalid sig A
                   (false? (sci-sandbox/eval-string
                            (str "(let [solution {:sig-a \"" bad-sig-hex "\" :sig-b \"" sig-b-hex "\" :tx-hash \"" tx-hash-hex "\"}] " puzzle ")")))
                   ;; Invalid sig B
                   (false? (sci-sandbox/eval-string
                            (str "(let [solution {:sig-a \"" sig-a-hex "\" :sig-b \"" bad-sig-hex "\" :tx-hash \"" tx-hash-hex "\"}] " puzzle ")")))))))

(defspec ^{:doc "Mutually signing an update properly verifies signatures against canonical hash and requires nonce increment"}
  mutually-sign-update-spec
  100
  (prop/for-all [amount-a gen-amount
                 amount-b gen-amount
                 new-amount-a gen-amount
                 new-amount-b gen-amount]
                (let [kp-a (crypto/generate-keypair)
                      kp-b (crypto/generate-keypair)
                      pub-a (basalt/bytes->hex (:public kp-a))
                      pub-b (basalt/bytes->hex (:public kp-b))
                      initial-state (channels/create-initial-state pub-a pub-b amount-a amount-b)

                      ;; Prepare update data
                      update-map {:balance-a new-amount-a
                                  :balance-b new-amount-b
                                  :nonce (inc (:nonce initial-state))}
                      canonical-map (into (sorted-map) update-map)
                      update-hash (crypto/sha256 (.getBytes (pr-str canonical-map) "UTF-8"))

                      ;; Signatures
                      sig-a (basalt/bytes->hex (crypto/sign (:private kp-a) update-hash))
                      sig-b (basalt/bytes->hex (crypto/sign (:private kp-b) update-hash))

                      ;; Bad signatures
                      kp-c (crypto/generate-keypair)
                      bad-sig (basalt/bytes->hex (crypto/sign (:private kp-c) update-hash))

                      ;; Apply update
                      valid-update (channels/mutually-sign-update initial-state update-map sig-a sig-b)
                      invalid-update-a (channels/mutually-sign-update initial-state update-map bad-sig sig-b)
                      invalid-update-b (channels/mutually-sign-update initial-state update-map sig-a bad-sig)

                      ;; Replay attack (same nonce)
                      replay-update-map (assoc update-map :nonce (:nonce initial-state))
                      replay-canonical-map (into (sorted-map) replay-update-map)
                      replay-hash (crypto/sha256 (.getBytes (pr-str replay-canonical-map) "UTF-8"))
                      replay-sig-a (basalt/bytes->hex (crypto/sign (:private kp-a) replay-hash))
                      replay-sig-b (basalt/bytes->hex (crypto/sign (:private kp-b) replay-hash))
                      replay-update (channels/mutually-sign-update initial-state replay-update-map replay-sig-a replay-sig-b)]
                  (and
                   ;; Valid update returns new state
                   (= valid-update (assoc update-map :pubkey-a pub-a :pubkey-b pub-b))
                   ;; Invalid updates return unchanged initial state
                   (= invalid-update-a initial-state)
                   (= invalid-update-b initial-state)
                   ;; Replay updates return unchanged initial state
                   (= replay-update initial-state)))))
