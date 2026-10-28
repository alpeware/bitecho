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
  (testing "Calculates node weight using w_i = participation_i * min(4.0, stake_i / S_min) with continuous linear scaling"
    (is (= 50.0 (attestation/calculate-node-weight 100 500 1000))
        "Continuous linear scaling: stake = 500, S_min = 1000, ratio = 0.5")
    (is (= 100.0 (attestation/calculate-node-weight 100 1000 1000)))
    (is (= 200.0 (attestation/calculate-node-weight 100 2000 1000)))
    (is (= 400.0 (attestation/calculate-node-weight 100 4000 1000)))
    (is (= 400.0 (attestation/calculate-node-weight 100 8000 1000))
        "Caps stake multiplier at 4.0"))

  (testing "Ratified default S_min is 250,000 with continuous linear scaling"
    (is (= 250000 attestation/default-min-stake))
    (is (= 0.5 (attestation/calculate-node-weight 1.0 125000))
        "Continuous linear: stake = 125000 with default S_min = 250000 and participation = 1.0 returns 0.5")
    (is (= 99.9996 (attestation/calculate-node-weight 100 249999))
        "Below default S_min scales continuously without cliff")
    (is (= 100.0 (attestation/calculate-node-weight 100 250000))
        "At default S_min multiplier is 1.0")
    (is (= 400.0 (attestation/calculate-node-weight 100 1000000))
        "At 4x default S_min multiplier is 4.0"))

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

(defspec ^{:doc "Property: Node weight calculation satisfies bounds [0, 4.0 * participation] with continuous linear scaling"}
  prop-calculate-node-weight-bounds 50
  (prop/for-all [participation (gen/choose 1 10000)
                 stake (gen/choose 0 1000000)
                 s-min (gen/choose 1 50000)]
                (let [weight (attestation/calculate-node-weight participation stake s-min)
                      max-allowed (* 4.0 (double participation))
                      expected (if (or (<= participation 0) (<= stake 0) (<= s-min 0))
                                 0.0
                                 (* (double participation) (min 4.0 (/ (double stake) (double s-min)))))]
                  (and (number? weight)
                       (>= weight 0.0)
                       (<= weight (+ max-allowed 1e-9))
                       (<= (Math/abs (- weight expected)) 1e-9)))))

(deftest canonical-exchange-digest-byte-concatenation-test
  (let [epoch 1
        peer-a "0101010101010101010101010101010101010101010101010101010101010101"
        peer-b "0202020202020202020202020202020202020202020202020202020202020202"
        roles [["msg-1" :echo] ["msg-2" :ready]]
        expected-roles-vec [["msg-1" :echo] ["msg-2" :ready]]
        baos (java.io.ByteArrayOutputStream.)
        _ (do
            (.write baos (.getBytes (str (int epoch)) "UTF-8"))
            (.write baos (.getBytes peer-a "UTF-8"))
            (.write baos (.getBytes peer-b "UTF-8"))
            (.write baos (.getBytes (pr-str expected-roles-vec) "UTF-8")))
        expected-digest (basalt/bytes->hex (crypto/sha256 (.toByteArray baos)))
        actual-digest (attestation/compute-exchange-digest epoch peer-a peer-b roles)]
    (testing "Exchange digest matches raw UTF-8 byte concatenation of epoch || peer_a || peer_b || pr-str(sorted_vec)"
      (is (= expected-digest actual-digest)))
    (testing "Bilateral symmetry: swapping peers and reversing roles preserves exact byte-concatenated digest"
      (is (= expected-digest (attestation/compute-exchange-digest epoch peer-b peer-a (reverse roles)))))))

(deftest reconcile-message-roles-test
  (testing "reconcile-message-roles keeps only message IDs present in both frozen sets"
    (let [frozen-a #{"m1" "m2" "m3"}
          frozen-b #{"m2" "m3" "m4"}
          roles [["m1" :echo] ["m2" :ready] ["m3" :seen] ["m4" :delivery] ["m5" :seen]]
          reconciled (attestation/reconcile-message-roles frozen-a frozen-b roles)]
      (is (= [["m2" :ready] ["m3" :seen]] reconciled)))))

(deftest verify-transcript-against-log-test
  (let [kp-a (crypto/generate-keypair)
        kp-b (crypto/generate-keypair)
        pub-a (basalt/bytes->hex (:public kp-a))
        pub-b (basalt/bytes->hex (:public kp-b))
        honest-roles [["m1" :echo] ["m2" :ready]]
        transcript (attestation/create-transcript 1 pub-a pub-b honest-roles [(:private kp-a) (:private kp-b)])
        fabricated-roles [["fake-m99" :delivery]]
        fabricated-tx (attestation/create-transcript 1 pub-a pub-b fabricated-roles [(:private kp-a) (:private kp-b)])]
    (testing "Verifies successfully when transcript digest matches frozen log roles"
      (is (true? (attestation/verify-transcript-against-log transcript honest-roles))))

    (testing "Rejects fabricated self-consistent transcript with valid signatures but invented roles"
      (is (true? (attestation/verify-transcript fabricated-tx)) "Self-consistent signatures are valid")
      (is (false? (attestation/verify-transcript-against-log fabricated-tx honest-roles))
          "Must fail against real frozen log!"))))

(deftest evaluate-transcript-dispute-test
  (let [kp-a (crypto/generate-keypair)
        kp-b (crypto/generate-keypair)
        pub-a (basalt/bytes->hex (:public kp-a))
        pub-b (basalt/bytes->hex (:public kp-b))
        frozen-roles [["m1" :echo] ["m2" :ready]]
        valid-mutual (attestation/create-transcript 1 pub-a pub-b frozen-roles [(:private kp-a) (:private kp-b)])
        valid-half (attestation/create-transcript 1 pub-a pub-b frozen-roles (:private kp-a))
        fabricated-half (attestation/create-transcript 1 pub-a pub-b [["invented" :echo]] (:private kp-a))]
    (testing "Mutually signed transcript matching frozen log settles with credit to both and no strikes"
      (let [res (attestation/evaluate-transcript-dispute valid-mutual frozen-roles)]
        (is (= :settled (:status res)))
        (is (= #{pub-a pub-b} (:credit res)))
        (is (nil? (:strike res)))))

    (testing "Log-verified half-signed transcript credits reporting peer A and strikes non-signing peer B"
      (let [res (attestation/evaluate-transcript-dispute valid-half frozen-roles)]
        (is (= :half-signed-fault (:status res)))
        (is (= #{pub-a} (:credit res)))
        (is (= pub-b (:strike res)))))

    (testing "Fabricated unilateral report earns no credit and NEVER strikes the honest counterparty"
      (let [res (attestation/evaluate-transcript-dispute fabricated-half frozen-roles)]
        (is (= :rejected (:status res)))
        (is (= #{} (:credit res)))
        (is (nil? (:strike res)) "Honest peer B is protected from false strike!")))))

(defspec ^{:doc "Property: Fabricated transcripts never strike counterparty and only log-verified digests can credit/strike"}
  prop-transcript-dispute-safety 50
  (prop/for-all [epoch (gen/choose 1 500)
                 fabricated? gen/boolean
                 mutual? gen/boolean]
                (let [kp-a (crypto/generate-keypair)
                      kp-b (crypto/generate-keypair)
                      pub-a (basalt/bytes->hex (:public kp-a))
                      pub-b (basalt/bytes->hex (:public kp-b))
                      frozen-roles [["log-msg-1" :echo] ["log-msg-2" :ready]]
                      tx-roles (if fabricated?
                                 [["invented-msg-x" :echo]]
                                 frozen-roles)
                      tx (if mutual?
                           (attestation/create-transcript epoch pub-a pub-b tx-roles [(:private kp-a) (:private kp-b)])
                           (attestation/create-transcript epoch pub-a pub-b tx-roles (:private kp-a)))
                      res (attestation/evaluate-transcript-dispute tx frozen-roles)]
                  (if fabricated?
                    (and (= :rejected (:status res))
                         (= #{} (:credit res))
                         (nil? (:strike res)))
                    (if mutual?
                      (and (= :settled (:status res))
                           (= #{pub-a pub-b} (:credit res))
                           (nil? (:strike res)))
                      (and (= :half-signed-fault (:status res))
                           (= #{pub-a} (:credit res))
                           (= pub-b (:strike res))))))))

(deftest signed-frozen-log-test
  (let [kp (crypto/generate-keypair)
        pub-hex (basalt/bytes->hex (:public kp))
        priv (:private kp)
        epoch 5
        frozen-ids ["msg-b" "msg-a" "msg-c"]
        signed-log (attestation/sign-frozen-log epoch pub-hex frozen-ids priv)]
    (testing "Produces a map with normalized peer, sorted frozen-ids, and hex signature"
      (is (= epoch (:epoch signed-log)))
      (is (= pub-hex (:peer signed-log)))
      (is (= ["msg-a" "msg-b" "msg-c"] (:frozen-ids signed-log)))
      (is (string? (:signature signed-log)))
      (is (re-matches #"^[0-9a-fA-F]+$" (:signature signed-log))))

    (testing "Valid signed frozen log passes verify-frozen-log"
      (is (true? (attestation/verify-frozen-log signed-log))))

    (testing "Rejects tampered epoch"
      (is (false? (attestation/verify-frozen-log (assoc signed-log :epoch 6)))))

    (testing "Rejects tampered peer"
      (let [other-kp (crypto/generate-keypair)
            other-pub (basalt/bytes->hex (:public other-kp))]
        (is (false? (attestation/verify-frozen-log (assoc signed-log :peer other-pub))))))

    (testing "Rejects tampered or modified frozen-ids"
      (is (false? (attestation/verify-frozen-log (assoc signed-log :frozen-ids ["msg-a" "msg-b"]))))
      (is (false? (attestation/verify-frozen-log (assoc signed-log :frozen-ids ["msg-a" "msg-b" "msg-c" "msg-d"]))))
      (is (false? (attestation/verify-frozen-log (assoc signed-log :frozen-ids ["msg-a" "msg-b" "msg-tampered"])))))

    (testing "Rejects corrupted signature"
      (let [sig (:signature signed-log)
            corrupted-sig (str (if (= \0 (first sig)) "f" "0") (subs sig 1))]
        (is (false? (attestation/verify-frozen-log (assoc signed-log :signature corrupted-sig))))))

    (testing "Rejects malformed inputs gracefully"
      (is (false? (attestation/verify-frozen-log nil)))
      (is (false? (attestation/verify-frozen-log {})))
      (is (false? (attestation/verify-frozen-log (dissoc signed-log :signature))))
      (is (false? (attestation/verify-frozen-log (assoc signed-log :epoch "not-an-int")))))))

(defspec ^{:doc "Property: Cryptographic frozen log signatures strictly verify and fail on any tampering"}
  prop-frozen-log-signature-integrity 50
  (prop/for-all [epoch (gen/choose 0 1000)
                 ids (gen/vector gen/string-alphanumeric 0 10)
                 tamper-choice (gen/choose 0 3)]
                (let [kp (crypto/generate-keypair)
                      pub-hex (basalt/bytes->hex (:public kp))
                      priv (:private kp)
                      signed (attestation/sign-frozen-log epoch pub-hex ids priv)]
                  (case tamper-choice
                    0 (true? (attestation/verify-frozen-log signed))
                    1 (false? (attestation/verify-frozen-log (assoc signed :epoch (inc epoch))))
                    2 (false? (attestation/verify-frozen-log (assoc signed :frozen-ids (conj ids "tampered-mid"))))
                    3 (let [sig (:signature signed)] (false? (attestation/verify-frozen-log (assoc signed :signature (str (if (= "0" (subs sig 0 1)) "f" "0") (subs sig 1))))))))))

