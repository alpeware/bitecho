(ns bitecho.peer-review.core-test
  "Tests for Peer Review Protocol."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.peer-review.core :as peer-review]
            [bitecho.sieve.core :as sieve]
            [clojure.test :as t]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defn- generate-valid-chain
  "Generates a valid chain of receipts for a given message and a list of keypairs."
  [initial-message keypairs]
  (let [initial-sig (:signature initial-message)]
    (loop [kps keypairs
           prev-sig initial-sig
           chain []]
      (if (empty? kps)
        chain
        (let [kp (first kps)
              node-pubkey (basalt/bytes->hex (:public kp))
              sig-payload prev-sig
              node-sig (crypto/sign (:private kp) sig-payload)
              receipt {:node node-pubkey :signature node-sig}]
          (recur (rest kps) node-sig (conj chain receipt)))))))

(def gen-keypairs
  "Generator for a list of Ed25519 keypairs."
  (gen/fmap (fn [count]
              (vec (repeatedly count crypto/generate-keypair)))
            (gen/choose 1 5)))

(def gen-payload
  "Generator for a random payload byte array."
  (gen/fmap byte-array (gen/vector gen/byte 10 100)))

(defspec ^{:doc "Generative test verifying that a properly constructed chain of receipts is always valid."}
  valid-chain-is-accepted
  100
  (prop/for-all [payload gen-payload
                 keypairs gen-keypairs]
                (let [sender-kp (crypto/generate-keypair)
                      message (sieve/wrap-message payload (:private sender-kp) (:public sender-kp))
                      chain (generate-valid-chain message keypairs)]
                  (peer-review/validate-proof-of-relay message chain))))

(defspec ^{:doc "Generative test verifying that tampering with any receipt signature invalidates the chain."}
  tampered-chain-is-rejected
  100
  (prop/for-all [payload gen-payload
                 keypairs gen-keypairs
                 tamper-index (gen/choose 0 10)] ; will wrap around with mod
                (let [sender-kp (crypto/generate-keypair)
                      message (sieve/wrap-message payload (:private sender-kp) (:public sender-kp))
                      chain (generate-valid-chain message keypairs)
                      idx (mod tamper-index (count chain))
                      tampered-sig (crypto/sha256 (:signature (nth chain idx))) ; fake signature
                      tampered-chain (assoc-in chain [idx :signature] tampered-sig)]
                  (not (peer-review/validate-proof-of-relay message tampered-chain)))))

(t/deftest ^{:doc "Validates empty proof is valid (no relays yet)."}
  test-empty-proof
  (t/is (= true (peer-review/validate-proof-of-relay {:payload (.getBytes "test") :signature (.getBytes "sig") :sender "sender"} []))))
