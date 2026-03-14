(ns bitecho.services.turn-test
  "Tests for the pure TURN negotiation protocol."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.services.turn :as turn]
            [clojure.test :refer [deftest is]]))

(deftest ^{:doc "Tests creating and handling a TURN allocation request."} test-allocation-request
  (let [client-pubkey "client-pubkey-hex"
        server-pubkey "server-pubkey-hex"
        price 10
        req (turn/create-allocation-request client-pubkey)
        res (turn/handle-allocation-request req server-pubkey price)]
    (is (= :turn-allocate-request (:type req)))
    (is (= client-pubkey (:client-pubkey req)))
    (is (= :turn-allocate-granted (:type res)))
    (is (= server-pubkey (:server-pubkey res)))
    (is (= price (:price-per-byte res)))))

(deftest ^{:doc "Tests verifying an open payment channel."} test-verify-channel-open
  (let [state {:pubkey-a "client-hex"
               :pubkey-b "server-hex"
               :balance-a 1000
               :balance-b 0
               :nonce 0}]
    (is (true? (turn/verify-channel-open state "client-hex" "server-hex" 500)))
    (is (false? (turn/verify-channel-open state "wrong-client" "server-hex" 500)))
    (is (false? (turn/verify-channel-open state "client-hex" "wrong-server" 500)))
    (is (false? (turn/verify-channel-open state "client-hex" "server-hex" 2000)))))

(deftest ^{:doc "Tests creating and handling a TURN relay request."} test-relay-request
  (let [client-keys (crypto/generate-keypair)
        server-keys (crypto/generate-keypair)
        client-pub (basalt/bytes->hex (:public client-keys))
        server-pub (basalt/bytes->hex (:public server-keys))
        client-priv (:private client-keys)
        server-priv (:private server-keys)
        initial-state {:pubkey-a client-pub
                       :pubkey-b server-pub
                       :balance-a 1000
                       :balance-b 0
                       :nonce 0}
        data (.getBytes "hello TURN")
        data-len (count data)
        price 10
        req (turn/create-relay-request initial-state data price client-priv)
        res (turn/handle-relay-request req initial-state price server-priv)]
    (is (= :turn-relay-request (:type req)))
    (is (= data (:data req)))
    (is (= 1 (:nonce (:update req))))
    (is (= (- 1000 (* data-len price)) (:balance-a (:update req))))
    (is (= (* data-len price) (:balance-b (:update req))))

    (is (:valid? res))
    (is (= :relay-data (:type (:command res))))
    (is (= data (:data (:command res))))
    (let [new-state (:new-state res)]
      (is (= 1 (:nonce new-state)))
      (is (= (- 1000 (* data-len price)) (:balance-a new-state)))
      (is (= (* data-len price) (:balance-b new-state))))))

(deftest ^{:doc "Tests handle-relay-request rejects invalid updates."} test-invalid-relay-request
  (let [client-keys (crypto/generate-keypair)
        server-keys (crypto/generate-keypair)
        client-pub (basalt/bytes->hex (:public client-keys))
        server-pub (basalt/bytes->hex (:public server-keys))
        client-priv (:private client-keys)
        server-priv (:private server-keys)
        initial-state {:pubkey-a client-pub
                       :pubkey-b server-pub
                       :balance-a 1000
                       :balance-b 0
                       :nonce 0}
        data (.getBytes "hello TURN")
        price 10]

    ;; Test bad nonce
    (let [req (turn/create-relay-request initial-state data price client-priv)
          bad-req (assoc-in req [:update :nonce] 0)
          res (turn/handle-relay-request bad-req initial-state price server-priv)]
      (is (false? (:valid? res))))

    ;; Test insufficient payment / bad balance math
    (let [req (turn/create-relay-request initial-state data price client-priv)
          bad-req (assoc-in req [:update :balance-b] 0)
          ;; the signature will be wrong for the modified update, but let's test logic
          ;; actually, handle-relay-request will fail on signature or math.
          res (turn/handle-relay-request bad-req initial-state price server-priv)]
      (is (false? (:valid? res))))))

(deftest ^{:doc "Tests handle-relay-request accepts valid skipped nonces (HIGH-06)."} test-skipped-nonce-relay-request
  (let [client-keys (crypto/generate-keypair)
        server-keys (crypto/generate-keypair)
        client-pub (basalt/bytes->hex (:public client-keys))
        server-pub (basalt/bytes->hex (:public server-keys))
        client-priv (:private client-keys)
        server-priv (:private server-keys)
        initial-state {:channel-id "test-channel"
                       :pubkey-a client-pub
                       :pubkey-b server-pub
                       :balance-a 1000
                       :balance-b 0
                       :nonce 0}
        data (.getBytes "hello TURN")
        data-len (count data)
        price 10
        cost (* data-len price)

        ;; A valid update that skips nonces (e.g. cumulative payment for 5 requests)
        skipped-update {:nonce 5
                        :balance-a (- 1000 (* 5 cost))
                        :balance-b (* 5 cost)}

        ;; Helper to compute the hash as handle-relay-request does
        update-hash (let [enriched (assoc skipped-update
                                          :channel-id (:channel-id initial-state)
                                          :pubkey-a (:pubkey-a initial-state)
                                          :pubkey-b (:pubkey-b initial-state))
                          canonical (into (sorted-map) enriched)]
                      (crypto/sha256 (.getBytes (pr-str canonical) "UTF-8")))
        sig-a (basalt/bytes->hex (crypto/sign client-priv update-hash))
        req {:type :turn-relay-request
             :data data
             :update skipped-update
             :sig-a sig-a}

        res (turn/handle-relay-request req initial-state price server-priv)]
    (is (:valid? res))
    (let [new-state (:new-state res)]
      (is (= 5 (:nonce new-state)))
      (is (= (- 1000 (* 5 cost)) (:balance-a new-state)))
      (is (= (* 5 cost) (:balance-b new-state))))))

(deftest ^{:doc "Tests handle-relay-request rejects non-monotonic nonces."} test-replay-relay-request
  (let [client-keys (crypto/generate-keypair)
        server-keys (crypto/generate-keypair)
        client-pub (basalt/bytes->hex (:public client-keys))
        server-pub (basalt/bytes->hex (:public server-keys))
        client-priv (:private client-keys)
        server-priv (:private server-keys)
        initial-state {:channel-id "test-channel"
                       :pubkey-a client-pub
                       :pubkey-b server-pub
                       :balance-a 500
                       :balance-b 500
                       :nonce 5}
        data (.getBytes "hello TURN")
        data-len (count data)
        price 10
        cost (* data-len price)

        ;; An invalid update that replays an old nonce
        replayed-update {:nonce 5
                         :balance-a (- 500 cost)
                         :balance-b (+ 500 cost)}

        update-hash (let [enriched (assoc replayed-update
                                          :channel-id (:channel-id initial-state)
                                          :pubkey-a (:pubkey-a initial-state)
                                          :pubkey-b (:pubkey-b initial-state))
                          canonical (into (sorted-map) enriched)]
                      (crypto/sha256 (.getBytes (pr-str canonical) "UTF-8")))
        sig-a (basalt/bytes->hex (crypto/sign client-priv update-hash))
        req {:type :turn-relay-request
             :data data
             :update replayed-update
             :sig-a sig-a}

        res (turn/handle-relay-request req initial-state price server-priv)]
    (is (false? (:valid? res)))))
