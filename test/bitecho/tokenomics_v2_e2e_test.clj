(ns bitecho.tokenomics-v2-e2e-test
  "End-to-end multi-node, multi-epoch scenario verifying the full Tokenomics v2 system
   reconciles with real Ed25519 cryptography throughout (zero dummy-verify or with-redefs)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.attestation :as attestation]
            [bitecho.economy.treasury :as treasury]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defn- make-actor
  "Generates an actor with a real Ed25519 keypair and public key representations."
  [name-str]
  (let [kp (crypto/generate-keypair)]
    {:name name-str
     :keypair kp
     :privkey (:private kp)
     :pubkey-bytes (:public kp)
     :pubkey-hex (basalt/bytes->hex (:public kp))}))

(defn- make-scenario-actors
  "Generates all scenario actors with authentic cryptographic keypairs."
  []
  {:bootstrap (make-actor "bootstrap-custody")
   :team (make-actor "team-custody")
   :partners (make-actor "partners-custody")
   :ecosystem (make-actor "ecosystem-custody")
   :treasury (make-actor "treasury-mint-authority")
   :caller (make-actor "node-a-caller")
   :callee (make-actor "node-b-callee")
   :home (make-actor "node-h-home")
   :validator (make-actor "node-v-validator")
   :unseeded (make-actor "node-u-unseeded")})

(defn- compute-total-ledger-balance
  "Sums the balances of all account states present in the ledger."
  [ledger]
  (reduce + 0 (map #(or (:balance %) 0) (vals ledger))))

(defn- compute-total-burned
  "Sums all burned tokens recorded across all epochs in state."
  [state]
  (reduce + 0 (vals (or (:epoch-burns state) {}))))

(defn- assert-epoch-conservation
  "Asserts exact Tokenomics v2 conservation invariants at an epoch boundary."
  [state initial-supply initial-custody-bal]
  (let [ledger (or (:ledger state) {})
        total-ledger (compute-total-ledger-balance ledger)
        total-minted (or (:total-minted state) 0)
        total-burned (compute-total-burned state)
        expected-total (- (+ initial-supply total-minted) total-burned)
        custody-pub (get-in state [:config :custody-pubkey])
        remaining-custody (or (:balance (get ledger custody-pub)) 0)]
    (is (= expected-total total-ledger)
        "Total ledger balance must strictly equal initial-supply + total-minted - total-burned")
    (is (<= remaining-custody initial-custody-bal)
        "Remaining custody balance must never exceed initial custody allocation")
    (is (<= total-minted treasury/max-conditional-mint-supply)
        "Total minted must never exceed max-conditional-mint-supply (23.1B)")
    (is (<= (+ treasury/genesis-custody-supply total-minted) treasury/hard-cap)
        "Cumulative supply must never exceed the 42B hard cap")))

(defn- build-scenario-state
  "Initializes the pure root state machine with default Genesis custody and initial balances."
  [actors caller-bal callee-bal custody-release-amt]
  (let [custody-pks {:bootstrap (:pubkey-bytes (:bootstrap actors))
                     :team (:pubkey-bytes (:team actors))
                     :partners (:pubkey-bytes (:partners actors))
                     :ecosystem (:pubkey-bytes (:ecosystem actors))}
        genesis-custody (treasury/default-genesis-ledger custody-pks)
        caller-hex (:pubkey-hex (:caller actors))
        callee-hex (:pubkey-hex (:callee actors))
        genesis-ledger (assoc genesis-custody
                              caller-hex (account/map->AccountState {:balance caller-bal :seq 0 :deps []})
                              callee-hex (account/map->AccountState {:balance callee-bal :seq 0 :deps []}))
        home-peer (basalt/make-peer "127.0.0.1" 8000 (:pubkey-bytes (:home actors)))
        cfg (assoc config/default-config
                   :genesis-ledger genesis-ledger
                   :custody-pubkey (:pubkey-hex (:bootstrap actors))
                   :custody-privkey (:privkey (:bootstrap actors))
                   :custody-allocations [{:receiver caller-hex :amount custody-release-amt}]
                   :treasury-pubkey (:pubkey-hex (:treasury actors))
                   :treasury-privkey (:privkey (:treasury actors))
                   :treasury-trailing-epochs 1
                   :validators [(:pubkey-hex (:validator actors))]
                   :mesh-nodes {caller-hex 1.0})]
    (sm/init-state [home-peer] (:pubkey-hex (:home actors)) cfg)))

(defn- execute-epoch-0-actions
  "Executes Phase 5 burns, control frames, and rendezvous vouchers in Epoch 0."
  [state actors]
  (let [caller-hex (:pubkey-hex (:caller actors))
        callee-hex (:pubkey-hex (:callee actors))
        home-hex (:pubkey-hex (:home actors))
        ;; 1. Burn fee
        burn-res (sm/handle-event state {:type :signaling-burn :sender caller-hex :burn 200})
        s-burn (:state burn-res)
        ;; 2. Signed control frame (sieve echo)
        sieve-echo (sieve/sign-control-frame :sieve-echo "msg-e2e-1"
                                             (:privkey (:caller actors))
                                             (:pubkey-bytes (:caller actors)))
        s-echo-sample (assoc s-burn :global-echo-sample #{caller-hex})
        echo-event (assoc sieve-echo :type :receive-sieve-echo)
        s-echo (:state (sm/handle-event s-echo-sample echo-event))
        ;; 3. Register home set
        reg-event {:type :register-home-set
                   :callee callee-hex
                   :epoch 0
                   :candidates [{:node-id home-hex :price 15}
                                {:node-id "cand-extra-1" :price 15}
                                {:node-id "cand-extra-2" :price 15}]
                   :price 15
                   :price-max 15}
        s-reg (:state (sm/handle-event s-echo reg-event))
        ;; 4. DeliveryAck vouchers (seq 1 & seq 2)
        ev-1 {:type :receive-offer-header
              :caller caller-hex
              :callee callee-hex
              :callee-privkey (:privkey (:callee actors))
              :home-node home-hex
              :offer-hash "hash-offer-1"
              :seq 1}
        ev-2 {:type :receive-offer-header
              :caller caller-hex
              :callee callee-hex
              :callee-privkey (:privkey (:callee actors))
              :home-node home-hex
              :offer-hash "hash-offer-2"
              :seq 2}
        s-ack1 (:state (sm/handle-event s-reg ev-1))
        s-ack2 (:state (sm/handle-event s-ack1 ev-2))]
    s-ack2))

(defn- execute-epoch-tick
  "Advances an epoch boundary via :tick with a deterministic Streamlet block."
  [state proposer-actor new-epoch]
  (let [block (streamlet/->Block new-epoch "genesis" [] (:pubkey-hex proposer-actor))
        event {:type :tick
               :latest-finalized-block block
               :rng (java.util.Random. 42)}]
    (:state (sm/handle-event state event))))

(defn- verify-attestation-disputes
  "Evaluates mutually-signed, log-verified half-signed, and fabricated transcripts."
  [state actors]
  (let [pub-a (:pubkey-hex (:caller actors))
        pub-b (:pubkey-hex (:callee actors))
        frozen-msgs (get-in state [:frozen-epoch-messages 0] #{})
        m-id (or (first frozen-msgs) "msg-attest-1")
        honest-roles [[m-id :echo]]
        valid-half (attestation/create-transcript 0 pub-a pub-b honest-roles (:privkey (:caller actors)))
        fabricated-half (attestation/create-transcript 0 pub-a pub-b [["invented-fake-id" :seen]] (:privkey (:caller actors)))
        state-with-frozen (update-in state [:frozen-epoch-messages 0] (fnil conj #{}) m-id)
        ;; Fabricated transcript is rejected
        res-fab (sm/handle-event state-with-frozen {:type :submit-transcript :transcript fabricated-half})
        ;; Log-verified half-signed transcript strikes withholding peer B
        res-valid (sm/handle-event state-with-frozen {:type :submit-transcript
                                                      :transcript valid-half
                                                      :frozen-log-roles honest-roles})]
    (is (= {} (:fault-strikes (:state res-fab))) "Fabricated transcript must never strike honest peer B")
    (is (= 1 (get-in (:state res-valid) [:fault-strikes pub-b])) "Peer B struck for withholding signature")))

(deftest tokenomics-v2-end-to-end-scenario-test
  (testing "Tokenomics v2 multi-epoch integration with real Ed25519 cryptography throughout"
    (let [actors (make-scenario-actors)
          initial-caller 5000000
          initial-callee 1000000
          custody-release 50000
          initial-custody 4200000000
          initial-supply (+ treasury/genesis-custody-supply initial-caller initial-callee)
          init-state (build-scenario-state actors initial-caller initial-callee custody-release)
          unseeded-hex (:pubkey-hex (:unseeded actors))
          caller-hex (:pubkey-hex (:caller actors))
          callee-hex (:pubkey-hex (:callee actors))
          home-hex (:pubkey-hex (:home actors))
          validator-hex (:pubkey-hex (:validator actors))]

      ;; Phase 1: Genesis balances & unseeded verification (5.1)
      (testing "Genesis custody and unseeded node initialization"
        (is (= 0 (or (:balance (get-in init-state [:ledger unseeded-hex])) 0))
            "Unseeded node starts with zero balance")
        (is (= initial-caller (:balance (get-in init-state [:ledger caller-hex]))))
        (is (= initial-callee (:balance (get-in init-state [:ledger callee-hex]))))
        (is (= initial-custody (:balance (get-in init-state [:ledger (:pubkey-hex (:bootstrap actors))]))))
        (assert-epoch-conservation init-state initial-supply initial-custody))

      ;; Phase 2: Epoch 0 Burns, Signed Frames, Rendezvous Vouchers (5.6, 5.7a, 5.7b)
      (let [s-ep0 (execute-epoch-0-actions init-state actors)]
        (testing "Epoch 0 signaling burn deducted and vouchers accumulated"
          (is (= (- initial-caller 200) (:balance (get-in s-ep0 [:ledger caller-hex]))))
          (is (= 200 (get-in s-ep0 [:epoch-burns 0])))
          (is (= 1 (get-in s-ep0 [:echo-vote-counts "msg-e2e-1"])))
          (is (= 2 (count (:pending-vouchers s-ep0))))
          (assert-epoch-conservation s-ep0 initial-supply initial-custody))

        ;; Phase 3: Epoch 1 Boundary (:tick), Settlement, Mint, Custody (5.3, 5.4, 5.5, 5.6, 5.9)
        (let [s-ep1 (execute-epoch-tick s-ep0 (:validator actors) 1)]
          (testing "Epoch 1 tick compacts vouchers, applies demand-gated mint, and draws custody"
            ;; Vouchers settled: Callee B paid 30 to Home Node H
            (is (= (- initial-callee 30) (:balance (get-in s-ep1 [:ledger callee-hex]))))
            (is (= 30 (:balance (get-in s-ep1 [:ledger home-hex]))))
            (is (empty? (:pending-vouchers s-ep1)))
            (is (contains? (:settled-voucher-tuples s-ep1) [callee-hex home-hex 0]))
            ;; Treasury: Demand mint M_t calculated from trailing burn 200 (50% k-bps -> 100)
            ;; Split 20/80: validator gets 20, mesh node gets 80
            (is (= 100 (:total-minted s-ep1)))
            (is (= 20 (:balance (get-in s-ep1 [:ledger validator-hex]))))
            ;; Custody: Bootstrap drawn down by 50,000 to caller without inflating total-minted
            (is (= (- initial-custody custody-release)
                   (:balance (get-in s-ep1 [:ledger (:pubkey-hex (:bootstrap actors))]))))
            (is (= (+ (- initial-caller 200) 80 custody-release)
                   (:balance (get-in s-ep1 [:ledger caller-hex]))))
            ;; Conservation invariant strictly holds
            (assert-epoch-conservation s-ep1 initial-supply initial-custody))

          ;; Phase 4: Dispute resolution against frozen epoch messages (5.5)
          (testing "Transcript verification and dispute safety against frozen epoch messages"
            (verify-attestation-disputes s-ep1 actors)))))))

(defspec ^{:doc "Property: Exact Tokenomics v2 ledger conservation invariant holds across randomized multi-epoch schedules"}
  prop-tokenomics-v2-multi-epoch-supply-conservation 30
  (prop/for-all [burn-amount (gen/choose 100 1000)
                 voucher-count (gen/choose 1 5)
                 custody-amt (gen/choose 1000 50000)]
                (let [actors (make-scenario-actors)
                      initial-caller 50000000
                      initial-callee 10000000
                      initial-supply (+ treasury/genesis-custody-supply initial-caller initial-callee)
                      init-state (build-scenario-state actors initial-caller initial-callee custody-amt)
                      caller-hex (:pubkey-hex (:caller actors))
                      callee-hex (:pubkey-hex (:callee actors))
                      home-hex (:pubkey-hex (:home actors))
                      ;; 1. Burn
                      s-burn (:state (sm/handle-event init-state {:type :signaling-burn :sender caller-hex :burn burn-amount}))
                      ;; 2. Vouchers
                      s-reg (:state (sm/handle-event s-burn {:type :register-home-set
                                                             :callee callee-hex
                                                             :epoch 0
                                                             :candidates [{:node-id home-hex :price 10}
                                                                          {:node-id "extra-h2" :price 10}
                                                                          {:node-id "extra-h3" :price 10}]
                                                             :price 10
                                                             :price-max 10}))
                      s-vouchers (reduce (fn [st seq-n]
                                           (:state (sm/handle-event st {:type :receive-offer-header
                                                                        :caller caller-hex
                                                                        :callee callee-hex
                                                                        :callee-privkey (:privkey (:callee actors))
                                                                        :home-node home-hex
                                                                        :offer-hash (str "hash-" seq-n)
                                                                        :seq seq-n})))
                                         s-reg
                                         (range 1 (inc voucher-count)))
                      ;; 3. Epoch Tick
                      block (streamlet/->Block 1 "genesis" [] (:pubkey-hex (:validator actors)))
                      s-tick (:state (sm/handle-event s-vouchers {:type :tick :latest-finalized-block block :rng (java.util.Random. 99)}))
                      ledger (:ledger s-tick)
                      total-ledger (compute-total-ledger-balance ledger)
                      total-minted (or (:total-minted s-tick) 0)
                      total-burned (compute-total-burned s-tick)
                      expected-total (- (+ initial-supply total-minted) total-burned)]
                  (and (= expected-total total-ledger)
                       (<= total-minted treasury/max-conditional-mint-supply)
                       (<= (+ treasury/genesis-custody-supply total-minted) treasury/hard-cap)))))
