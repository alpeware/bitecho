(ns bitecho.message.envelope-test
  "Tests for directed message envelope specification."
  (:require [bitecho.message.envelope :as envelope]
            [clojure.spec.alpha :as s]
            [clojure.test :refer [deftest is]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def gen-hex-string
  "Generator for valid hex strings."
  (gen/fmap (fn [bytes-val]
              (apply str (map #(format "%02x" %) bytes-val)))
            (gen/vector (gen/choose 0 255) 32)))

(def gen-payload
  "Generator for byte arrays."
  gen/bytes)

(def gen-ticket
  "Generator for dummy lottery tickets."
  (gen/hash-map :payload-hash gen-hex-string
                :nonce gen/large-integer
                :public-key gen-hex-string
                :signature gen-hex-string))

(deftest ^{:doc "Validates that a constructed envelope contains the correct fields."}
  wrap-envelope-structure
  (let [destination "a1b2c3d4e5f6"
        payload (byte-array [10 20 30])
        ticket {:payload-hash "hash" :nonce 123 :public-key "pub" :signature "sig"}
        env (envelope/wrap-envelope destination payload ticket)]
    (is (map? env))
    (is (= destination (:destination env)))
    (is (= payload (:encrypted-payload env)))
    (is (= ticket (:lottery-ticket env)))))

(defspec ^{:doc "A wrapped envelope should always maintain the provided destination, payload and ticket."}
  wrap-envelope-preserves-data
  100
  (prop/for-all [destination gen-hex-string
                 payload gen-payload
                 ticket gen-ticket]
                (let [env (envelope/wrap-envelope destination payload ticket)]
                  (and (= destination (:destination env))
                       (= payload (:encrypted-payload env))
                       (= ticket (:lottery-ticket env))))))

(defspec ^{:doc "A wrapped envelope must conform to the spec."}
  wrap-envelope-conforms-to-spec
  100
  (prop/for-all [destination gen-hex-string
                 payload gen-payload
                 ticket gen-ticket]
                (let [env (envelope/wrap-envelope destination payload ticket)]
                  (s/valid? ::envelope/envelope env))))
