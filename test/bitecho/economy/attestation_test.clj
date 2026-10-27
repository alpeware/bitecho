(ns bitecho.economy.attestation-test
  "Tests for bilateral epoch transcript attestations and node weight calculation."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.economy.attestation :as attestation]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(deftest compute-exchange-digest-test
  (let [kp-a (crypto/generate-keypair)
        kp-b (crypto/generate-keypair)
        pub-a (basalt/bytes->hex (:public kp-a))
        pub-b (basalt/bytes->hex (:public kp-b))
        roles [{:message-id "msg-1" :role :echo}
               {:message-id "msg-2" :role :ready}]
        digest-1 (attestation/compute-exchange-digest 1 pub-a pub-b roles)
        digest-2 (attestation/compute-exchange-digest 1 pub-b pub-a (reverse roles))]
    (testing "Produces a 64-character SHA-256 hex string"
      (is (string? digest-1))
      (is (= 64 (count digest-1)))
      (is (re-matches #"^[0-9a-fA-F]{64}$" digest-1)))

    (testing "Digest is bilaterally symmetric and invariant to peer order and role list order"
      (is (= digest-1 digest-2)))

    (testing "Digest is sensitive to input changes"
      (is (not= digest-1 (attestation/compute-exchange-digest 2 pub-a pub-b roles)))
      (is (not= digest-1 (attestation/compute-exchange-digest 1 pub-a pub-b [{:message-id "msg-1" :role :echo}]))))))

(deftest mutually-signed-transcript-test
  (let [kp-a (crypto/generate-keypair)
        kp-b (crypto/generate-keypair)
        pub-a (basalt/bytes->hex (:public kp-a))
        pub-b (basalt/bytes->hex (:public kp-b))
        roles [{:message-id "msg-10" :role :delivery}]
        transcript (attestation/create-transcript 1 pub-a pub-b roles [(:private kp-a) (:private kp-b)])]
    (testing "Creates a valid mutually signed transcript"
      (is (some? (:sig-a transcript)))
      (is (some? (:sig-b transcript)))
      (is (true? (attestation/verify-transcript transcript)))
      (is (true? (attestation/mutually-signed? transcript)))
      (is (false? (attestation/half-signed? transcript))))

    (testing "Fails verification when digest is tampered"
      (let [tampered (assoc transcript :digest "0000000000000000000000000000000000000000000000000000000000000000")]
        (is (false? (attestation/verify-transcript tampered)))))

    (testing "Fails verification when sig-a or sig-b is corrupted"
      (let [corrupted-a (update transcript :sig-a #(assoc (vec %) 0 (byte (inc (first %)))))]
        (is (false? (attestation/verify-transcript corrupted-a))))
      (let [corrupted-b (update transcript :sig-b #(assoc (vec %) 0 (byte (inc (first %)))))]
        (is (false? (attestation/verify-transcript corrupted-b)))))))

(deftest half-signed-fallback-transcript-test
  (let [kp-a (crypto/generate-keypair)
        kp-b (crypto/generate-keypair)
        pub-a (basalt/bytes->hex (:public kp-a))
        pub-b (basalt/bytes->hex (:public kp-b))
        roles [{:message-id "msg-20" :role :ready}]
        half-transcript (attestation/create-transcript 1 pub-a pub-b roles (:private kp-a))]
    (testing "Creates a valid half-signed fallback transcript"
      (is (some? (:sig-a half-transcript)))
      (is (nil? (:sig-b half-transcript)))
      (is (true? (attestation/verify-transcript half-transcript)))
      (is (true? (attestation/half-signed? half-transcript)))
      (is (false? (attestation/mutually-signed? half-transcript))))

    (testing "Co-signing a half-signed transcript makes it mutually signed"
      (let [cosigned (attestation/cosign-transcript half-transcript (:private kp-b))]
        (is (some? (:sig-b cosigned)))
        (is (true? (attestation/verify-transcript cosigned)))
        (is (true? (attestation/mutually-signed? cosigned)))
        (is (false? (attestation/half-signed? cosigned)))))))

(deftest calculate-node-weight-test
  (testing "Calculates node weight using w_i = participation_i * min(4.0, stake_i / S_min)"
    (is (= 50.0 (attestation/calculate-node-weight 100 500 1000)))
    (is (= 100.0 (attestation/calculate-node-weight 100 1000 1000)))
    (is (= 200.0 (attestation/calculate-node-weight 100 2000 1000)))
    (is (= 400.0 (attestation/calculate-node-weight 100 4000 1000)))
    (is (= 400.0 (attestation/calculate-node-weight 100 8000 1000))
        "Caps stake multiplier at 4.0"))

  (testing "Zero and boundary inputs return 0.0 without division by zero errors"
    (is (= 0.0 (attestation/calculate-node-weight 0 5000 1000)))
    (is (= 0.0 (attestation/calculate-node-weight 100 0 1000)))
    (is (= 0.0 (attestation/calculate-node-weight 100 5000 0)))
    (is (= 0.0 (attestation/calculate-node-weight 100 5000 -100)))
    (is (= 0.0 (attestation/calculate-node-weight -10 5000 1000)))))

(defspec ^{:doc "Property: compute-exchange-digest is deterministic and bilaterally symmetric"}
  prop-exchange-digest-deterministic-and-symmetric 50
  (prop/for-all [epoch (gen/choose 1 1000)
                 msg-count (gen/choose 0 5)]
                (let [kp-a (crypto/generate-keypair)
                      kp-b (crypto/generate-keypair)
                      pub-a (basalt/bytes->hex (:public kp-a))
                      pub-b (basalt/bytes->hex (:public kp-b))
                      roles (mapv (fn [i] {:message-id (str "msg-" i) :role :echo}) (range msg-count))
                      digest-ab (attestation/compute-exchange-digest epoch pub-a pub-b roles)
                      digest-ba (attestation/compute-exchange-digest epoch pub-b pub-a (vec (reverse roles)))]
                  (and (string? digest-ab)
                       (= 64 (count digest-ab))
                       (= digest-ab digest-ba)))))

(defspec ^{:doc "Property: Transcript verification is sound for mutually-signed and half-signed transcripts"}
  prop-transcript-verification-soundness 50
  (prop/for-all [epoch (gen/choose 1 500)
                 mutual? gen/boolean]
                (let [kp-a (crypto/generate-keypair)
                      kp-b (crypto/generate-keypair)
                      pub-a (basalt/bytes->hex (:public kp-a))
                      pub-b (basalt/bytes->hex (:public kp-b))
                      roles [{:message-id "prop-msg" :role :echo}]
                      transcript (if mutual?
                                   (attestation/create-transcript epoch pub-a pub-b roles [(:private kp-a) (:private kp-b)])
                                   (attestation/create-transcript epoch pub-a pub-b roles (:private kp-a)))]
                  (and (attestation/verify-transcript transcript)
                       (if mutual?
                         (attestation/mutually-signed? transcript)
                         (attestation/half-signed? transcript))))))

(defspec ^{:doc "Property: Node weight calculation satisfies bounds [0, 4.0 * participation]"}
  prop-calculate-node-weight-bounds 50
  (prop/for-all [participation (gen/choose 0 10000)
                 stake (gen/choose 0 1000000)
                 s-min (gen/choose 1 50000)]
                (let [weight (attestation/calculate-node-weight participation stake s-min)
                      max-allowed (* 4.0 (double participation))]
                  (and (number? weight)
                       (>= weight 0.0)
                       (<= weight (+ max-allowed 1e-9))
                       (if (>= stake (* 4 s-min))
                         (<= (Math/abs (- weight max-allowed)) 1e-9)
                         true)))))
