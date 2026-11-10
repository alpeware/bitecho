(ns bitecho.state-machine-portability-test
  "Cross-runtime portability tests verifying that Bitecho's pure state machine
   initializes, transitions, and preserves invariants identically on both JVM and Node/CLJS."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.attestation :as attestation]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.treasury :as treasury]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.rendezvous.core :as rdv]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.buffer :as dc-buf]
            [datachannel.core :as dc-core]
            [datachannel.dcep :as dc-dcep]
            [datachannel.dtls :as dc-dtls]
            [datachannel.sctp :as dc-sctp]
            [datachannel.sdp :as dc-sdp]
            [datachannel.stun :as dc-stun]
            [datachannel.tcp :as dc-tcp]
            [datachannel.turn :as dc-turn]))

(defn- make-peer [i]
  (let [kp (crypto/generate-keypair)
        pub-hex (basalt/bytes->hex (:public kp))]
    {:ip (str "127.0.0." i)
     :port (+ 8000 i)
     :pubkey (:public kp)
     :hash (str "hash-" i)
     :node-id pub-hex}))

(deftest state-machine-init-portability-test
  (testing "State machine initializes identically across runtimes"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          peers [(make-peer 1) (make-peer 2) (make-peer 3)]
          cfg (assoc config/default-config
                     :genesis-ledger {pub-hex {:balance 1000 :seq 0 :deps []}}
                     :epoch-entropy "genesis-entropy-test")
          state (sm/init-state peers pub-hex cfg)]
      (is (some? state))
      (is (= pub-hex (:node-pubkey state)))
      (is (= 0 (:epoch state)))
      (is (= "genesis-entropy-test" (:epoch-entropy state)))
      (is (= 1000 (:balance (get-in state [:ledger pub-hex]))))
      (is (record? (get-in state [:ledger pub-hex])))
      (is (vector? (:basalt-view state)))
      (is (map? (:murmur-cache state)))
      (is (set? (:contagion-known-ids state))))))

(deftest state-machine-tick-portability-test
  (testing "handle-tick executes deterministic transitions and command generation"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          state (sm/init-state [] pub-hex config/default-config)
          res (sm/handle-event state {:type :tick})]
      (is (map? res))
      (is (contains? res :state))
      (is (contains? res :commands))
      (is (vector? (:commands res)))
      (is (= 1 (:epoch (:state res)))))))

(deftest state-machine-transfer-event-portability-test
  (testing "Pure state machine validates and applies canonical transfers"
    (let [alice-kp (crypto/generate-keypair)
          bob-kp (crypto/generate-keypair)
          alice-pub (basalt/bytes->hex (:public alice-kp))
          bob-pub (basalt/bytes->hex (:public bob-kp))
          alice-priv (:private alice-kp)
          cfg (assoc config/default-config
                     :genesis-ledger {alice-pub {:balance 500 :seq 0 :deps []}
                                      bob-pub   {:balance 100 :seq 0 :deps []}})
          state (sm/init-state [] alice-pub cfg)
          unsigned-tx {:sender alice-pub
                       :receiver bob-pub
                       :amount 150
                       :seq 1
                       :deps []}
          tx (account/create-transfer alice-priv unsigned-tx)
          expected-hash (account/transfer-hash tx)
          transfer-event {:type :on-deliver
                          :sender alice-pub
                          :payload (fressian/encode-canonical {:transfer (into {} tx)})}
          res (sm/handle-event state transfer-event)
          new-state (:state res)]
      (is (some? new-state))
      (is (= 350 (:balance (get-in new-state [:ledger alice-pub]))))
      (is (= 250 (:balance (get-in new-state [:ledger bob-pub]))))
      (is (= 1 (:seq (get-in new-state [:ledger alice-pub]))))
      (is (= [expected-hash] (:deps (get-in new-state [:ledger alice-pub])))))))

(defspec ^{:doc "Property: State machine balance conservation under arbitrary sequence of valid transfers"}
  prop-state-machine-transfer-balance-conservation 50
  (prop/for-all [amount-1 (gen/choose 1 100)
                 amount-2 (gen/choose 1 100)]
                (let [alice-kp (crypto/generate-keypair)
                      bob-kp (crypto/generate-keypair)
                      alice-pub (basalt/bytes->hex (:public alice-kp))
                      bob-pub (basalt/bytes->hex (:public bob-kp))
                      alice-priv (:private alice-kp)
                      initial-alice 500
                      initial-bob 200
                      total-initial (+ initial-alice initial-bob)
                      cfg (assoc config/default-config
                                 :genesis-ledger {alice-pub {:balance initial-alice :seq 0 :deps []}
                                                  bob-pub   {:balance initial-bob :seq 0 :deps []}})
                      state0 (sm/init-state [] alice-pub cfg)
                      ;; Transfer 1: Alice -> Bob
                      tx1 (account/create-transfer alice-priv {:sender alice-pub :receiver bob-pub :amount amount-1 :seq 1 :deps []})
                      p1 (fressian/encode-canonical {:transfer (into {} tx1)})
                      res1 (sm/handle-event state0 {:type :on-deliver :sender alice-pub :payload p1})
                      state1 (:state res1)
                      ;; Transfer 2: Alice -> Bob
                      tx2 (account/create-transfer alice-priv {:sender alice-pub :receiver bob-pub :amount amount-2 :seq 2 :deps [(account/transfer-hash tx1)]})
                      p2 (fressian/encode-canonical {:transfer (into {} tx2)})
                      res2 (sm/handle-event state1 {:type :on-deliver :sender alice-pub :payload p2})
                      state2 (:state res2)
                      final-alice (:balance (get-in state2 [:ledger alice-pub]))
                      final-bob   (:balance (get-in state2 [:ledger bob-pub]))]
                  (and (= total-initial (+ final-alice final-bob))
                       (= (- initial-alice amount-1 amount-2) final-alice)
                       (= (+ initial-bob amount-1 amount-2) final-bob)
                       (= 2 (:seq (get-in state2 [:ledger alice-pub])))
                       (= 0 (:seq (get-in state2 [:ledger bob-pub])))))))

(deftest shell-boundary-crypto-portability-test
  (testing "Decision A(i): shell-boundary pre-verify-envelope, sign-and-emit, and seal-and-emit work across JVM and CLJS"
    (let [boundary (crypto/make-crypto-boundary)
          kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          priv (:private kp)
          ;; 1. Deferred signing from light-node.core (no private key inside reducer)
          deferred-env (light-core/build-chain-state-query-envelope pub-hex :defer-crypto {:epoch 7 :nonce "n-7"})
          _ (is (= :sign-and-emit (get-in deferred-env [:crypto-effect :effect])))
          _ (is (nil? (:signature deferred-env)))
          ;; Fulfill :sign-and-emit at the shell boundary
          signed-env (crypto/sign-and-emit boundary (assoc deferred-env :private-key priv))
          _ (is (string? (:signature signed-env)))
          _ (is (nil? (:crypto-effect signed-env)))
          ;; 2. Pre-verify at the shell boundary before passing to pure reducer
          verified-env (crypto/pre-verify-envelope boundary signed-env)
          _ (is (true? (:crypto/verified? verified-env)))
          ;; 3. Sieve message pre-verification + validation
          sieve-msg (sieve/wrap-message (fressian/utf8->bytes "hello-boundary") priv (:public kp) 100)
          pre-verified-sieve (crypto/pre-verify-envelope boundary sieve-msg)
          _ (is (true? (:crypto/verified? pre-verified-sieve)))
          _ (is (some? (sieve/validate-message pre-verified-sieve)))
          ;; 4. seal-and-emit boundary effect
          sealed-atom (atom nil)
          sealed-out (crypto/seal-and-emit boundary {:plaintext "secret-data"
                                                     :seal-fn #(str "sealed:" %)
                                                     :on-sealed #(reset! sealed-atom %)})]
      (is (= "sealed:secret-data" sealed-out))
      (is (= "sealed:secret-data" @sealed-atom)))))

(deftest light-node-core-signing-paths-portability-test
  (testing "light-node.core signing, attestation, DAC, and command paths run identically on JVM and CLJS without .getBytes errors"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          priv (:private kp)
          dir-kp (crypto/generate-keypair)
          dir-pub-hex (basalt/bytes->hex (:public dir-kp))
          dir-priv (:private dir-kp)
          anc-kp (crypto/generate-keypair)
          anc-pub-hex (basalt/bytes->hex (:public anc-kp))
          anc-priv (:private anc-kp)
          peer-kp (crypto/generate-keypair)
          peer-pub-hex (basalt/bytes->hex (:public peer-kp))

          ;; 1. Directory PoP
          pop-map (light-core/create-directory-pop priv {:domain "bitecho.org"
                                                         :nickname "alice"
                                                         :pubkey pub-hex
                                                         :epoch 10})
          _ (is (some? pop-map))
          _ (is (true? (light-core/verify-directory-pop pop-map)))

          ;; 2. Directory Attestation Descriptor
          desc (light-core/sign-directory-descriptor dir-priv dir-pub-hex pop-map
                                                     {:issued-epoch 10
                                                      :expires-epoch 25
                                                      :mailbox "mb-alice"})
          _ (is (some? desc))
          desc-res (light-core/verify-directory-descriptor desc dir-pub-hex 15)
          _ (is (true? (:ok? desc-res)))
          _ (is (true? (:valid? desc-res)))

          ;; 3. DAC creation and verification
          dac (light-core/create-dac anc-priv {:anchor-pubkey anc-pub-hex
                                               :agent-pubkey pub-hex
                                               :issued-epoch 10
                                               :expires-epoch 30
                                               :max-spend-per-epoch 1000
                                               :scopes ["transfer" "lock-intent" "offer"]})
          _ (is (some? dac))
          dac-res (light-core/verify-dac dac {:expected-agent-pubkey pub-hex
                                              :current-epoch 15
                                              :required-scope "transfer"})
          _ (is (true? (:ok? dac-res)))
          _ (is (true? (:valid? dac-res)))

          ;; 4. light-core/handle-command execution
          st0 (-> (light-core/init-light-state {:pubkey-hex pub-hex
                                                :fingerprint "fp-alice"
                                                :ice-creds {:u "u" :p "p"}}
                                               {:epoch 10})
                  (assoc :account {:balance 5000 :spendable 5000 :seq 0}))

          ;; 4a. directory-register
          reg-res (light-core/handle-command st0 {"cmd" "directory-register"
                                                  "nickname" "alice"
                                                  "domain" "bitecho.org"} priv)
          _ (is (= true (get-in reg-res [:response "ok"])))
          _ (is (= "alice" (get-in reg-res [:response "nickname"])))

          ;; 4b. transfer
          tf-res (light-core/handle-command st0 {"cmd" "transfer"
                                                 "receiver" peer-pub-hex
                                                 "amount" 250} priv)
          _ (is (= true (get-in tf-res [:response "ok"])))
          _ (is (pos? (count (:net-envelopes tf-res))))

          ;; 4c. lock-intent
          d-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "secret-deliverable")))
          lock-res (light-core/handle-command st0 {"cmd" "lock-intent"
                                                   "receiver" peer-pub-hex
                                                   "amount" 300
                                                   "deliverable_hash" d-hash
                                                   "expires_epoch" 25} priv)
          _ (is (= true (get-in lock-res [:response "ok"])))
          eid (get-in lock-res [:response "escrow_id"])
          _ (is (string? eid))
          st-locked (:state lock-res)

          ;; 4d. release-intent
          rel-res (light-core/handle-command st-locked {"cmd" "release-intent"
                                                        "escrow_id" eid} priv)
          _ (is (= true (get-in rel-res [:response "ok"])))
          _ (is (= "release-submitted" (get-in rel-res [:response "status"])))

          ;; 4e. refund-intent
          ref-res (light-core/handle-command st-locked {"cmd" "refund-intent"
                                                        "escrow_id" eid} priv)
          _ (is (= true (get-in ref-res [:response "ok"])))
          _ (is (= "refund-submitted" (get-in ref-res [:response "status"])))

          ;; 4f. rendezvous-offer
          rdv-res (light-core/handle-command st0 {"cmd" "rendezvous-offer"
                                                  "callee" peer-pub-hex
                                                  "burn" 25
                                                  "topic" "chat"} priv)
          _ (is (= true (get-in rdv-res [:response "ok"])))
          _ (is (= 1 (count (:net-envelopes rdv-res))))

          ;; 5. verify-chain-state-quorum
          val-kps [(crypto/generate-keypair) (crypto/generate-keypair) (crypto/generate-keypair)]
          val-pubs (mapv #(basalt/bytes->hex (:public %)) val-kps)
          base-snap {:pubkey pub-hex
                     :balance 2000
                     :spendable 2000
                     :finalized-epoch 10
                     :seq 1
                     :deps []
                     :escrows {}
                     :nonce "quorum-nonce-1"}
          signed-snaps (mapv (fn [i]
                               (light-core/sign-chain-state-snapshot
                                (assoc base-snap :validator-pubkey (nth val-pubs i))
                                (:private (nth val-kps i))))
                             (range 3))
          q-res (light-core/verify-chain-state-quorum signed-snaps
                                                      {:expected-pubkey pub-hex
                                                       :trusted-validators (set val-pubs)
                                                       :min-finalized-epoch 5})]
      (is (true? (:ok? q-res)))
      (is (= 3 (:quorum-count q-res))))))

(deftest test-crypto-verified-bypass-rejected-across-all-validators
  (testing "Forged incoming envelopes/messages carrying :crypto/verified? true and garbage signatures are rejected across all core validators"
    (let [kp (crypto/generate-keypair)
          pub-hex (basalt/bytes->hex (:public kp))
          other-kp (crypto/generate-keypair)
          other-pub-hex (basalt/bytes->hex (:public other-kp))
          garbage-sig "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

          ;; 1. sieve/validate-message
          bad-sieve-msg {:payload (fressian/utf8->bytes "tampered-gossip")
                         :sender pub-hex
                         :signature garbage-sig
                         :crypto/verified? true
                         :crypto/verified-a? true}
          _ (is (nil? (sieve/validate-message bad-sieve-msg)))

          ;; 2. sieve/validate-control-frame
          bad-control-frame {:sender pub-hex
                             :message-id "mid-bad"
                             :signature garbage-sig
                             :crypto/verified? true
                             :crypto/verified-a? true}
          _ (is (false? (sieve/validate-control-frame bad-control-frame :subscribe)))

          ;; 3. streamlet/verify-block-signature
          bad-block {:epoch 1
                     :parent-hash "genesis"
                     :payload []
                     :proposer pub-hex
                     :signature garbage-sig
                     :crypto/verified? true
                     :crypto/verified-a? true}
          _ (is (false? (streamlet/verify-block-signature bad-block (:public kp))))

          ;; 4. streamlet/verify-vote-signature
          bad-vote {:epoch 1
                    :block-hash "blk-1"
                    :voter pub-hex
                    :voter-signature garbage-sig
                    :crypto/verified? true
                    :crypto/verified-a? true}
          _ (is (false? (streamlet/verify-vote-signature bad-vote (:public kp))))

          ;; 5. account/validate-transfer
          account-st {:balance 1000 :seq 0 :deps []}
          bad-transfer {:sender pub-hex
                        :receiver other-pub-hex
                        :amount 100
                        :seq 1
                        :deps []
                        :signature garbage-sig
                        :crypto/verified? true
                        :crypto/verified-a? true}
          _ (is (false? (account/validate-transfer account-st bad-transfer)))

          ;; 6. treasury/apply-epoch-mint
          treasury-st {:treasury-pubkey pub-hex
                       :total-minted 0
                       :minted-epochs #{}
                       :ledger {}}
          bad-mint {:epoch 1
                    :allocations {other-pub-hex 500}
                    :treasury-pubkey pub-hex
                    :signature garbage-sig
                    :crypto/verified? true
                    :crypto/verified-a? true}
          minted-st (treasury/apply-epoch-mint treasury-st bad-mint)
          _ (is (= treasury-st minted-st))

          ;; 7. attestation/verify-transcript
          transcript-digest (attestation/compute-exchange-digest 1 pub-hex other-pub-hex [{:role :alice :message-id "m-1"}])
          bad-transcript {:epoch 1
                          :peer-a pub-hex
                          :peer-b other-pub-hex
                          :digest transcript-digest
                          :message-roles [{:role :alice :message-id "m-1"}]
                          :sig-a garbage-sig
                          :crypto/verified? true
                          :crypto/verified-a? true}
          _ (is (false? (attestation/verify-transcript bad-transcript)))

          ;; 8. attestation/verify-frozen-log
          bad-frozen-log {:epoch 1
                          :peer pub-hex
                          :frozen-ids ["m-1"]
                          :signature garbage-sig
                          :crypto/verified? true
                          :crypto/verified-a? true}
          _ (is (false? (attestation/verify-frozen-log bad-frozen-log)))

          ;; 9. rendezvous/verify-delivery-ack
          bad-ack {:epoch 1
                   :caller pub-hex
                   :callee other-pub-hex
                   :offer-hash "oh-1"
                   :home-node "node1"
                   :signature garbage-sig
                   :crypto/verified? true
                   :crypto/verified-a? true}
          _ (is (false? (rdv/verify-delivery-ack bad-ack)))

          ;; 10. crypto/pre-verify-envelope
          bad-envelope {:bitecho/type :light-node-query
                        :sender pub-hex
                        :signature garbage-sig
                        :crypto/verified? true
                        :crypto/verified-a? true}
          pre-res (crypto/pre-verify-envelope (crypto/make-crypto-boundary) bad-envelope)
          _ (is (false? (:crypto/verified? pre-res)))
          _ (is (= :failed (:crypto/verification-status pre-res)))
          _ (is (= :pre-verify-failed (get-in pre-res [:diagnose :reason])))

          ;; 11. state-machine/handle-event rejects forged gossip
          sm-st (sm/init-state [] pub-hex config/default-config)
          gossip-event {:type :receive-gossip
                        :message {:payload (fressian/utf8->bytes "forged-gossip")
                                  :sender pub-hex
                                  :burn-amount burn/min-signaling-burn
                                  :signature garbage-sig
                                  :crypto/verified? true
                                  :crypto/verified-a? true}}
          sm-res (sm/handle-event sm-st gossip-event)]
      (is (empty? (:commands sm-res))))))

(deftest shell-boundary-crypto-fail-closed-test
  (testing "Shell boundary crypto primitives fail closed with :diagnose effect on invalid inputs"
    (let [boundary (crypto/make-crypto-boundary)]
      ;; 1. sign-and-emit missing private key
      (let [res (crypto/sign-and-emit boundary {:payload {:data 123}})]
        (is (false? (:ok? res)))
        (is (= :missing-private-key-or-payload (:error res)))
        (is (= :sign-and-emit-invalid-input (get-in res [:diagnose :reason]))))

      ;; 2. seal-and-emit missing seal-fn
      (let [res (crypto/seal-and-emit boundary {:plaintext "secret"})]
        (is (false? (:ok? res)))
        (is (= :missing-seal-fn (:error res)))
        (is (= :seal-and-emit-missing-seal-fn (get-in res [:diagnose :reason]))))

      ;; 3. seal-and-emit missing plaintext/data
      (let [res (crypto/seal-and-emit boundary {:seal-fn #(str "sealed:" %)})]
        (is (false? (:ok? res)))
        (is (= :missing-seal-fn (:error res)))
        (is (= :seal-and-emit-missing-seal-fn (get-in res [:diagnose :reason])))))))

(defspec ^{:doc "Property: M2a state.fressian encode-light-state / decode-light-state round-trips cleanly across JVM and CLJS while stripping sensitive/transient keys."}
  prop-light-state-fressian-persistence-roundtrip 30
  (prop/for-all [epoch (gen/choose 1 10000)
                 bal (gen/choose 0 1000000)
                 burned (gen/choose 0 50000)
                 autonomous? gen/boolean
                 session-id (gen/fmap #(str "sess-" %) (gen/choose 1 9999))]
                (let [kp (crypto/generate-keypair)
                      pub-hex (basalt/bytes->hex (:public kp))
                      base-st (-> (light-core/init-light-state {:pubkey-hex pub-hex
                                                                :fingerprint "AA:BB:CC"}
                                                               {:epoch epoch
                                                                :autonomous? autonomous?})
                                  (assoc :account {:balance bal :spendable bal :seq 3 :finalized-epoch epoch})
                                  (assoc-in [:local-accounting :burned-ech] burned)
                                  (assoc-in [:sessions session-id] {:session-id session-id
                                                                    :peer pub-hex
                                                                    :state :established
                                                                    :ephemeral-priv (:private kp)})
                                  (assoc :connected? true
                                         :connection-error "transient-err"
                                         :conn-diagnostics {:phase :live :generation 4}))
                      encoded (light-core/encode-light-state base-st)
                      decoded (light-core/decode-light-state encoded)]
                  (and (= pub-hex (:pubkey decoded))
                       (= epoch (:epoch decoded))
                       (= autonomous? (:autonomous? decoded))
                       (= bal (get-in decoded [:account :balance]))
                       (= burned (get-in decoded [:local-accounting :burned-ech]))
                       (= :established (get-in decoded [:sessions session-id :state]))
                       (nil? (get-in decoded [:sessions session-id :ephemeral-priv]))
                       (not (contains? decoded :connected?))
                       (not (contains? decoded :connection-error))
                       (not (contains? decoded :conn-diagnostics))))))

(deftest m2a-datachannel-cljc-portability-test
  (testing "M2a: clj-datachannel .cljc Sans-IO core and IDtlsEngine run identically on JVM and Node.js inside Bitecho"
    (let [fp-b "FF:EE:DD:CC:BB:AA:00:99:88:77:66:55:44:33:22:11:FF:EE:DD:CC:BB:AA:00:99:88:77:66:55:44:33:22:11"
          mock-engine (reify dc-dtls/IDtlsEngine
                        (begin-handshake! [_] nil)
                        (handshake-finished? [_] true)
                        (handshake-step [_ _] {:status :finished :finished? true :packets [] :app-data dc-buf/empty-bytes})
                        (wrap-app-data [_ plain] {:status :ok :bytes (dc-buf/to-bytes plain)})
                        (unwrap-packet [_ net] {:status :ok :bytes (dc-buf/to-bytes net)})
                        (peer-fingerprint [_] fp-b))
          conn (dc-core/create-connection {:ice-ufrag "u1"
                                           :ice-pwd "p1234567890123456789012"
                                           :remote-fingerprint fp-b
                                           :dtls/engine mock-engine}
                                          true)
          cand (dc-sdp/format-candidate {:foundation "1" :component 1 :transport "UDP" :ip "127.0.0.1" :port 5010 :type "host"})
          parsed-cand (dc-sdp/parse-candidate cand)
          dcep-bytes (dc-dcep/encode-message {:type :open :label "bitecho" :protocol "fressian-v1" :ordered true})
          dcep-msg (dc-dcep/decode-message dcep-bytes)
          sctp-buf (dc-buf/allocate-buffer 256)
          _ (dc-sctp/encode-packet {:src-port 5000 :dst-port 5000 :verification-tag 42
                                    :chunks [{:type :cookie-ack}]}
                                   sctp-buf {:zero-checksum? false})
          _ (dc-buf/buf-flip! sctp-buf)
          decoded-sctp (dc-sctp/decode-packet sctp-buf)
          stun-req (dc-stun/make-binding-request "u1" "u2" "secretPassword1234567890")
          turn-tc (dc-turn/init-turn-client {:username "u" :password "p"})
          framed (dc-tcp/encode-rfc4571-frame (dc-buf/utf8->bytes "hello-rfc4571"))
          deframed (dc-tcp/decode-rfc4571-stream dc-buf/empty-bytes framed)]
      (is (true? (dc-dtls/verify-peer-fingerprint mock-engine fp-b)))
      (is (= "u1" (:ice-ufrag conn)))
      (is (= 5010 (:port parsed-cand)))
      (is (= "bitecho" (:label dcep-msg)))
      (is (= 42 (:verification-tag decoded-sctp)))
      (is (pos? (dc-buf/buf-remaining stun-req)))
      (is (= :idle (:state turn-tc)))
      (is (= "hello-rfc4571" (dc-buf/bytes->utf8 (first (:frames deframed))))))))
