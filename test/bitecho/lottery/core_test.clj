(ns bitecho.lottery.core-test
  "Generative tests for cryptographic lottery tickets."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.lottery.core :as lottery]
            [clojure.test :refer [deftest is]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def gen-payload
  "Generator for arbitrary byte arrays (payloads)."
  gen/bytes)

(def gen-nonce
  "Generator for 64-bit nonces."
  gen/large-integer)

(deftest ^{:doc "Validates that a generated ticket has the correct structure."}
  generate-ticket-structure
  (let [payload (byte-array [1 2 3 4])
        nonce 42
        keypair (crypto/generate-keypair)
        ticket (lottery/generate-ticket payload nonce (:private keypair) (:public keypair))]
    (is (map? ticket))
    (is (= (basalt/bytes->hex (crypto/sha256 payload)) (:payload-hash ticket)))
    (is (= nonce (:nonce ticket)))
    (is (string? (:signature ticket)))
    (is (string? (:public-key ticket)))))

(defspec ^{:doc "A valid generated ticket must pass winning-ticket? if the difficulty is maximum."}
  generated-ticket-always-wins-max-difficulty
  100
  (prop/for-all [payload gen-payload
                 nonce gen-nonce]
                (let [keypair (crypto/generate-keypair)
                      ticket (lottery/generate-ticket payload nonce (:private keypair) (:public keypair))
          ;; Maximum difficulty: all FF bytes, so any hash will be less than this
                      max-difficulty (apply str (repeat 64 "f"))]
                  (lottery/winning-ticket? ticket max-difficulty))))

(defspec ^{:doc "A ticket should fail validation if its signature is corrupted."}
  ticket-fails-corrupt-signature
  100
  (prop/for-all [payload gen-payload
                 nonce gen-nonce]
                (let [keypair (crypto/generate-keypair)
                      ticket (lottery/generate-ticket payload nonce (:private keypair) (:public keypair))
          ;; Invalidate signature by appending/prepending or changing chars
                      corrupt-sig (apply str (reverse (:signature ticket)))
                      bad-ticket (assoc ticket :signature corrupt-sig)
                      max-difficulty (apply str (repeat 64 "f"))]
                  (not (lottery/winning-ticket? bad-ticket max-difficulty)))))

(defspec ^{:doc "A ticket should fail validation if its difficulty is minimum (impossible to beat)."}
  ticket-fails-min-difficulty
  100
  (prop/for-all [payload gen-payload
                 nonce gen-nonce]
                (let [keypair (crypto/generate-keypair)
                      ticket (lottery/generate-ticket payload nonce (:private keypair) (:public keypair))
          ;; Minimum difficulty: all 00 bytes, so no hash can be less than this
                      min-difficulty (apply str (repeat 64 "0"))]
                  (not (lottery/winning-ticket? ticket min-difficulty)))))
