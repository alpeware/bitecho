(ns bitecho.crypto.delegation-test
  "Tests for bitecho.crypto.delegation Delegated Agent Certificates (DACs)"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.delegation :as delegation]
            [clojure.test :refer [deftest is testing]]))

(deftest ^{:doc "Tests generation and verification of valid DACs"} valid-dac-lifecycle-test
  (testing "Generates a DAC and verifies it successfully"
    (let [parent-keys (crypto/generate-keypair)
          node-keys (crypto/generate-keypair)
          parent-pubkey (basalt/bytes->hex (:public parent-keys))
          parent-privkey (:private parent-keys)
          node-pubkey (basalt/bytes->hex (:public node-keys))
          dac (delegation/generate-dac parent-pubkey parent-privkey node-pubkey)]
      (is (= parent-pubkey (:parent-pubkey dac)))
      (is (= node-pubkey (:node-pubkey dac)))
      (is (string? (:signature dac)))
      (is (true? (delegation/verify-dac dac))))))

(deftest ^{:doc "Tests DAC verification fails when forged"} forged-dac-test
  (testing "Fails verification if the parent pubkey is altered"
    (let [parent-keys (crypto/generate-keypair)
          fake-parent-keys (crypto/generate-keypair)
          node-keys (crypto/generate-keypair)
          parent-pubkey (basalt/bytes->hex (:public parent-keys))
          parent-privkey (:private parent-keys)
          node-pubkey (basalt/bytes->hex (:public node-keys))
          dac (delegation/generate-dac parent-pubkey parent-privkey node-pubkey)
          forged-dac (assoc dac :parent-pubkey (basalt/bytes->hex (:public fake-parent-keys)))]
      (is (false? (delegation/verify-dac forged-dac)))))

  (testing "Fails verification if the node pubkey is altered"
    (let [parent-keys (crypto/generate-keypair)
          node-keys (crypto/generate-keypair)
          fake-node-keys (crypto/generate-keypair)
          parent-pubkey (basalt/bytes->hex (:public parent-keys))
          parent-privkey (:private parent-keys)
          node-pubkey (basalt/bytes->hex (:public node-keys))
          dac (delegation/generate-dac parent-pubkey parent-privkey node-pubkey)
          forged-dac (assoc dac :node-pubkey (basalt/bytes->hex (:public fake-node-keys)))]
      (is (false? (delegation/verify-dac forged-dac)))))

  (testing "Fails verification if the signature is altered"
    (let [parent-keys (crypto/generate-keypair)
          node-keys (crypto/generate-keypair)
          parent-pubkey (basalt/bytes->hex (:public parent-keys))
          parent-privkey (:private parent-keys)
          node-pubkey (basalt/bytes->hex (:public node-keys))
          dac (delegation/generate-dac parent-pubkey parent-privkey node-pubkey)
          forged-dac (assoc dac :signature (basalt/bytes->hex (crypto/sha256 (.getBytes "fake" "UTF-8"))))]
      (is (false? (delegation/verify-dac forged-dac))))))
