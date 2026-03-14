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

(deftest ^{:doc "Creating an initial channel state should establish correct keys, balances, and channel-id"}
  create-initial-state-test
  (testing "Initial state contains pubkeys, channel-id, and 0 nonce"
    (let [channel-id "chan-1"
          kp-a (crypto/generate-keypair)
          kp-b (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          pub-b (basalt/bytes->hex (:public kp-b))
          amount-a 100
          amount-b 50
          state (channels/create-initial-state channel-id pub-a pub-b amount-a amount-b)]
      (is (= channel-id (:channel-id state)))
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
                           (str "(let [solution {:sig-a \"" sig-a-hex "\" :sig-b \"" sig-b-hex "\"}] " puzzle ")")
                           {'tx-hash tx-hash-hex}))
                   ;; Invalid sig A
                   (false? (sci-sandbox/eval-string
                            (str "(let [solution {:sig-a \"" bad-sig-hex "\" :sig-b \"" sig-b-hex "\"}] " puzzle ")")
                            {'tx-hash tx-hash-hex}))
                   ;; Invalid sig B
                   (false? (sci-sandbox/eval-string
                            (str "(let [solution {:sig-a \"" sig-a-hex "\" :sig-b \"" bad-sig-hex "\"}] " puzzle ")")
                            {'tx-hash tx-hash-hex}))))))

(defspec ^{:doc "Mutually signing an update properly verifies signatures against canonical hash and requires nonce increment"}
  mutually-sign-update-spec
  100
  (prop/for-all [amount-a gen-amount
                 amount-b gen-amount
                 gen-new-amount-a gen-amount]
                (let [kp-a (crypto/generate-keypair)
                      kp-b (crypto/generate-keypair)
                      pub-a (basalt/bytes->hex (:public kp-a))
                      pub-b (basalt/bytes->hex (:public kp-b))
                      channel-id "chan-1"
                      initial-state (channels/create-initial-state channel-id pub-a pub-b amount-a amount-b)

                      ;; Ensure balance is conserved
                      total (+ amount-a amount-b)
                      new-amount-a (min gen-new-amount-a total)
                      new-amount-b (- total new-amount-a)

                      ;; Prepare update data
                      update-map {:balance-a new-amount-a
                                  :balance-b new-amount-b
                                  :nonce (inc (:nonce initial-state))}
                      enriched-update-map (assoc update-map :channel-id channel-id :pubkey-a pub-a :pubkey-b pub-b)
                      canonical-map (into (sorted-map) enriched-update-map)
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
                      replay-enriched-map (assoc replay-update-map :channel-id channel-id :pubkey-a pub-a :pubkey-b pub-b)
                      replay-canonical-map (into (sorted-map) replay-enriched-map)
                      replay-hash (crypto/sha256 (.getBytes (pr-str replay-canonical-map) "UTF-8"))
                      replay-sig-a (basalt/bytes->hex (crypto/sign (:private kp-a) replay-hash))
                      replay-sig-b (basalt/bytes->hex (crypto/sign (:private kp-b) replay-hash))
                      replay-update (channels/mutually-sign-update initial-state replay-update-map replay-sig-a replay-sig-b)

                      ;; Cross-channel replay attack
                      other-channel-id "chan-2"
                      other-initial-state (channels/create-initial-state other-channel-id pub-a pub-b amount-a amount-b)
                      cross-channel-update (channels/mutually-sign-update other-initial-state update-map sig-a sig-b)]
                  (and
                   ;; Valid update returns new state
                   (= valid-update (assoc update-map :channel-id channel-id :pubkey-a pub-a :pubkey-b pub-b))
                   ;; Invalid updates return unchanged initial state
                   (= invalid-update-a initial-state)
                   (= invalid-update-b initial-state)
                   ;; Replay updates return unchanged initial state
                   (= replay-update initial-state)
                   ;; Cross-channel replay returns unchanged initial state
                   (= cross-channel-update other-initial-state)))))

(deftest ^{:doc "Mutually signing an update must conserve balance"}
  mutually-sign-update-balance-conservation-test
  (testing "Update is rejected if balance-a + balance-b changes"
    (let [channel-id "chan-1"
          kp-a (crypto/generate-keypair)
          kp-b (crypto/generate-keypair)
          pub-a (basalt/bytes->hex (:public kp-a))
          pub-b (basalt/bytes->hex (:public kp-b))
          amount-a 100
          amount-b 50
          state (channels/create-initial-state channel-id pub-a pub-b amount-a amount-b)

          ;; invalid update map (total is 160 instead of 150)
          update-map {:balance-a 100 :balance-b 60 :nonce 1}
          enriched-update-map (assoc update-map
                                     :channel-id (:channel-id state)
                                     :pubkey-a (:pubkey-a state)
                                     :pubkey-b (:pubkey-b state))
          canonical-map (into (sorted-map) enriched-update-map)
          update-hash (crypto/sha256 (.getBytes (pr-str canonical-map) "UTF-8"))
          sig-a (basalt/bytes->hex (crypto/sign (:private kp-a) update-hash))
          sig-b (basalt/bytes->hex (crypto/sign (:private kp-b) update-hash))]
      (is (= state (channels/mutually-sign-update state update-map sig-a sig-b))))))
