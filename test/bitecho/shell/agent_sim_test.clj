(ns bitecho.shell.agent-sim-test
  "Tests for the Light Agent Swarm Simulator pure builders and CLI parsers."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.shell.agent-sim :as sim]
            [bitecho.shell.mesh :as mesh]
            [bitecho.state-machine :as sm]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [taoensso.nippy :as nippy]))

(defn- setup-test-state
  "Constructs a clean state-machine test state with funded sender."
  [node-hex sender-hex initial-balance]
  (let [view (basalt/init-view [] 10 (java.util.Random. 42))
        cfg config/devnet-config]
    {:epoch 1
     :config cfg
     :node-pubkey node-hex
     :basalt-view view
     :ledger {sender-hex (account/map->AccountState {:balance initial-balance :seq 0 :deps []})}
     :epoch-burns {}
     :messages {}
     :message-epochs {}
     :epoch-to-messages {}
     :epoch-to-message-roles {}
     :contagion-known-ids #{}
     :delivered-set #{}
     :local-ready-set #{}
     :sieve-delivered-set #{}
     :received-echoes {}
     :received-readies {}
     :echo-vote-counts {}
     :ready-vote-counts {}
     :delivery-vote-counts {}
     :murmur-cache {:set #{} :queue clojure.lang.PersistentQueue/EMPTY}}))

(defspec ^{:doc "Property: build-gossip-envelope produces valid signed agent envelopes that survive serialization and deduct signaling burn from funded sender."}
  test-prop-gossip-envelope-roundtrip 50
  (prop/for-all [burn (gen/choose 100 2000)
                 payload-str (gen/not-empty gen/string-alphanumeric)]
                (let [sender-kp (crypto/generate-keypair)
                      sender-pub-hex (basalt/bytes->hex (:public sender-kp))
                      sender-priv-bytes (:private sender-kp)
                      node-kp (crypto/generate-keypair)
                      node-pub-hex (basalt/bytes->hex (:public node-kp))
                      payload-bytes (.getBytes ^String payload-str "UTF-8")
                      initial-bal 50000

                      envelope (sim/build-gossip-envelope sender-pub-hex sender-priv-bytes payload-bytes burn)
                      frozen (nippy/freeze envelope)
                      thawed (nippy/thaw frozen)
                      unwrapped (mesh/unwrap-authenticated-agent-event thawed)

                      state (setup-test-state node-pub-hex sender-pub-hex initial-bal)
                      res (sm/handle-event state unwrapped)
                      st' (:state res)]
                  (and (some? unwrapped)
                       (= :receive-gossip (:type unwrapped))
                       (= (get-in st' [:epoch-burns 1]) burn)
                       (= (get-in st' [:ledger sender-pub-hex :balance]) (- initial-bal burn))
                       (contains? (:contagion-known-ids st') (get-in unwrapped [:message :message-id]))))))

(deftest test-transfer-gossip-envelope-e2e
  (testing "build-transfer-gossip-envelope produces valid transfer delivered via on-deliver"
    (let [sender-kp (crypto/generate-keypair)
          sender-pub-hex (basalt/bytes->hex (:public sender-kp))
          sender-priv-bytes (:private sender-kp)
          receiver-kp (crypto/generate-keypair)
          receiver-pub-hex (basalt/bytes->hex (:public receiver-kp))
          node-kp (crypto/generate-keypair)
          node-pub-hex (basalt/bytes->hex (:public node-kp))
          burn-amt 500
          transfer-amt 1000
          initial-bal 20000

          transfer-opts {:receiver receiver-pub-hex
                         :amount transfer-amt
                         :seq 1
                         :deps []}
          transfer-pack (sim/build-transfer-gossip-envelope sender-pub-hex sender-priv-bytes transfer-opts burn-amt)
          envelope (:envelope transfer-pack)
          signed-transfer (:transfer transfer-pack)
          thash (:transfer-hash transfer-pack)]

      (is (map? envelope))
      (is (= thash (account/transfer-hash signed-transfer)))

      ;; 1. Unpack envelope via mesh
      (let [unwrapped (mesh/unwrap-authenticated-agent-event (nippy/freeze envelope))]
        (is (some? unwrapped))
        (is (= :receive-gossip (:type unwrapped)))

        ;; 2. Ingest gossip into state-machine (burn deducted)
        (let [st0 (setup-test-state node-pub-hex sender-pub-hex initial-bal)
              res1 (sm/handle-event st0 unwrapped)
              st1 (:state res1)
              msg-id (get-in unwrapped [:message :message-id])]
          (is (= (get-in st1 [:ledger sender-pub-hex :balance]) (- initial-bal burn-amt)))
          (is (= (get-in st1 [:epoch-burns 1]) burn-amt))

          ;; 3. Contagion delivery applies transfer to ledger
          (let [res2 (sm/handle-event st1 {:type :on-deliver
                                           :payload (get-in unwrapped [:message :payload])
                                           :message-id msg-id})
                st2 (:state res2)]
            (is (= (get-in st2 [:ledger receiver-pub-hex :balance]) transfer-amt))
            (is (= (get-in st2 [:ledger sender-pub-hex :balance]) (- initial-bal burn-amt transfer-amt)))
            (is (= (get-in st2 [:ledger sender-pub-hex :seq]) 1))
            (is (= (get-in st2 [:ledger sender-pub-hex :deps]) [thash]))))))))

(deftest test-home-set-envelope-roundtrip
  (testing "build-home-set-envelope produces valid signed agent registration"
    (let [agent-kp (crypto/generate-keypair)
          agent-pub-hex (basalt/bytes->hex (:public agent-kp))
          agent-priv-bytes (:private agent-kp)
          node-kp (crypto/generate-keypair)
          node-pub-hex (basalt/bytes->hex (:public node-kp))
          candidates [{:node-id "node-cand-1" :price 200}
                      {:node-id "node-cand-2" :price 200}
                      {:node-id "node-cand-3" :price 250}]
          price 250
          epoch 5
          envelope (sim/build-home-set-envelope agent-pub-hex agent-priv-bytes candidates price epoch)
          unwrapped (mesh/unwrap-authenticated-agent-event (nippy/freeze envelope))
          st0 (setup-test-state node-pub-hex agent-pub-hex 10000)
          res (sm/handle-event st0 unwrapped)
          st1 (:state res)]
      (is (some? unwrapped))
      (is (= :register-home-set (:type unwrapped)))
      (is (= agent-pub-hex (:callee unwrapped)))
      (is (= candidates (:candidates unwrapped)))
      (is (= price (:price unwrapped)))
      (is (contains? (:home-sets st1) [agent-pub-hex epoch])))))

(deftest test-parse-sim-args
  (testing "parse-sim-args applies defaults when flags omitted"
    (let [args ["devnet/bootstrap.edn" ".ssh/keypair.edn"]
          parsed (sim/parse-sim-args args)]
      (is (= "devnet/bootstrap.edn" (:bootstrap-file parsed)))
      (is (= ".ssh/keypair.edn" (:keypair-file parsed)))
      (is (= 10 (get-in parsed [:opts :agents])))
      (is (= 30 (get-in parsed [:opts :messages])))
      (is (= 500 (get-in parsed [:opts :burn])))))

  (testing "parse-sim-args parses explicit flags"
    (let [args ["bootstrap.edn" "keypair.edn" "--agents" "5" "--messages" "50" "--burn" "750"]
          parsed (sim/parse-sim-args args)]
      (is (= "bootstrap.edn" (:bootstrap-file parsed)))
      (is (= "keypair.edn" (:keypair-file parsed)))
      (is (= 5 (get-in parsed [:opts :agents])))
      (is (= 50 (get-in parsed [:opts :messages])))
      (is (= 750 (get-in parsed [:opts :burn])))))

  (testing "parse-sim-args throws ex-info on missing positional arguments"
    (is (thrown? Exception (sim/parse-sim-args [])))
    (is (thrown? Exception (sim/parse-sim-args ["only-one.edn"])))))
