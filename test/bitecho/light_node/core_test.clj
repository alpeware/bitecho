(ns bitecho.light-node.core-test
  "Tests and generative invariants for the pure light-node protocol state machine."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.economy.account :as account]
            [bitecho.economy.burn :as burn]
            [bitecho.light-node.core :as light-core]
            [bitecho.rendezvous.core :as rdv]
            [bitecho.shell.mesh :as mesh]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.data.json :as json]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [taoensso.nippy :as nippy]))

(defn- sample-pubkey-hex
  "Returns an 88-character SubjectPublicKeyInfo hex string for testing."
  []
  (basalt/bytes->hex (:public (crypto/generate-keypair))))

(defn- test-identity
  "Creates a test identity map with keypair."
  []
  (let [kp (crypto/generate-keypair)
        pub-hex (basalt/bytes->hex (:public kp))]
    {:identity {:pubkey-hex pub-hex
                :fingerprint "95:09:40:3B:04:A0:B3:F5:88:26:51:CE:C9:A9:8E:0C:A1:15:92:8F:D5:7D:4A:11:A2:6C:3C:B0:0B:AB:0C:3B"
                :ice-creds {:ufrag "ufrag123" :pwd "pwd123456789012345678901"}}
     :keypair kp
     :pubkey-hex pub-hex
     :privkey-bytes (:private kp)}))

(def gen-text-message
  "Generator for non-blank ascii test strings."
  (gen/such-that #(not (str/blank? %))
                 (gen/fmap (partial apply str) (gen/vector gen/char-ascii 1 128))))

(defn- gossip-env?
  "Predicate to detect gossip network envelopes."
  [env]
  (or (= :receive-gossip (:type env))
      (= :receive-gossip (get-in env [:event :type]))))

(defspec ^{:doc "Property: Two-party light-node rendezvous and sealed-channel bidirectional messaging conversation"}
  prop-two-party-sealed-conversation 20
  (prop/for-all [msg1-text gen-text-message
                 msg2-text gen-text-message
                 autonomous? gen/boolean]
                (let [alice (test-identity)
                      bob (test-identity)
                      descriptor {:network :devnet
                                  :treasury-pubkey (sample-pubkey-hex)
                                  :custody-pubkey (sample-pubkey-hex)
                                  :nodes {:node1 {:node-id :node1 :ip "127.0.0.1" :port 5000 :agent-port 5010
                                                  :pubkey (:pubkey-hex alice)
                                                  :fingerprint "95:09:40:3B:04:A0:B3:F5:88:26:51:CE:C9:A9:8E:0C:A1:15:92:8F:D5:7D:4A:11:A2:6C:3C:B0:0B:AB:0C:3B"
                                                  :ice-ufrag "ufrag123" :ice-pwd "pwd123456789012345678901"}}}
                      ;; Init states
                      st-alice0 (light-core/init-light-state (:identity alice) {:bootstrap descriptor :epoch 1})
                      st-bob0 (light-core/init-light-state (:identity bob) {:bootstrap descriptor :epoch 1 :autonomous? autonomous?})
                      ;; 1. Alice creates channel offer
                      offer-cmd {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 10 "burn" 500}
                      res-offer (light-core/handle-command st-alice0 offer-cmd (:privkey-bytes alice))
                      st-alice1 (:state res-offer)
                      offer-resp (:response res-offer)
                      session-id (get offer-resp "session_id")
                      offer-envelopes (:net-envelopes res-offer)
                      offer-env (first (filter gossip-env? offer-envelopes))
                      ;; 2. Bob receives offer
                      res-bob-offer (light-core/handle-wire-payload st-bob0 offer-env (:privkey-bytes bob))
                      st-bob1 (:state res-bob-offer)
                      ;; If not autonomous, Bob accepts manually
                      bob-acc-res (when-not autonomous?
                                    (light-core/handle-command st-bob1 {"cmd" "accept" "session_id" session-id} (:privkey-bytes bob)))
                      st-bob2 (if autonomous? st-bob1 (:state bob-acc-res))
                      accept-env (first (filter gossip-env? (if autonomous?
                                                              (:net-envelopes res-bob-offer)
                                                              (:net-envelopes bob-acc-res))))
                      ;; 3. Alice receives accept
                      res-alice-accept (light-core/handle-wire-payload st-alice1 accept-env (:privkey-bytes alice))
                      st-alice2 (:state res-alice-accept)
                      ;; Both sessions should now be open
                      alice-sess (get-in st-alice2 [:sessions session-id])
                      bob-sess (get-in st-bob2 [:sessions session-id])
                      open-ok? (and (= "open" (:state alice-sess))
                                    (= "open" (:state bob-sess)))
                      ;; 4. Alice sends message to Bob
                      send-cmd1 {"cmd" "send" "session_id" session-id "text" msg1-text "burn" 500}
                      res-send1 (light-core/handle-command st-alice2 send-cmd1 (:privkey-bytes alice))
                      st-alice3 (:state res-send1)
                      msg1-env (first (filter gossip-env? (:net-envelopes res-send1)))
                      ;; Bob receives message 1
                      res-bob-rx1 (light-core/handle-wire-payload st-bob2 msg1-env (:privkey-bytes bob))
                      st-bob3 (:state res-bob-rx1)
                      inbox-res1 (light-core/handle-command st-bob3 {"cmd" "inbox"} (:privkey-bytes bob))
                      st-bob4 (:state inbox-res1)
                      bob-inbox (get-in inbox-res1 [:response "messages"])
                      msg1-delivered? (= msg1-text (get (first bob-inbox) :text))
                      ;; 5. Bob sends reply to Alice
                      send-cmd2 {"cmd" "send" "session_id" session-id "text" msg2-text "burn" 500}
                      res-send2 (light-core/handle-command st-bob4 send-cmd2 (:privkey-bytes bob))
                      _st-bob5 (:state res-send2)
                      msg2-env (first (filter gossip-env? (:net-envelopes res-send2)))
                      ;; Alice receives message 2
                      res-alice-rx2 (light-core/handle-wire-payload st-alice3 msg2-env (:privkey-bytes alice))
                      st-alice4 (:state res-alice-rx2)
                      inbox-res2 (light-core/handle-command st-alice4 {"cmd" "inbox"} (:privkey-bytes alice))
                      alice-inbox (get-in inbox-res2 [:response "messages"])
                      msg2-delivered? (= msg2-text (get (first alice-inbox) :text))]
                  (and open-ok?
                       msg1-delivered?
                       msg2-delivered?))))

(defspec ^{:doc "Property: 2-epoch skew tolerance and replay-protection enforcement in wire payload processing"}
  prop-epoch-skew-and-replay-protection 25
  (prop/for-all [skew (gen/choose -5 5)
                 duplicate? gen/boolean]
                (let [alice (test-identity)
                      bob (test-identity)
                      session-id "sess-skew-test"
                      shared-secret (byte-array 32)
                      alice-keys (sealed/derive-channel-keys shared-secret session-id :initiator)
                      bob-keys (sealed/derive-channel-keys shared-secret session-id :responder)
                      state-bob {:pubkey (:pubkey-hex bob)
                                 :epoch 10
                                 :sessions {session-id {:session-id session-id
                                                        :peer (:pubkey-hex alice)
                                                        :role :responder
                                                        :state "open"
                                                        :rx-key (:rx-key bob-keys)
                                                        :tx-key (:tx-key bob-keys)
                                                        :replay-window (sealed/init-replay-window 64)}}
                                 :inbox []}
                      msg-epoch (+ 10 skew)
                      plain-bytes (.getBytes "skew-test-payload" "UTF-8")
                      sealed (sealed/seal-message (:tx-key alice-keys) 1 plain-bytes (.getBytes session-id "UTF-8"))
                      wire-msg {:bitecho/type :sealed-message
                                :session-id session-id
                                :sender (:pubkey-hex alice)
                                :recipient (:pubkey-hex bob)
                                :epoch msg-epoch
                                :seq 1
                                :nonce (basalt/bytes->hex (:nonce sealed))
                                :ciphertext (basalt/bytes->hex (:ciphertext sealed))}
                      res1 (light-core/handle-wire-payload state-bob wire-msg (:privkey-bytes bob))
                      within-tolerance? (<= (Math/abs skew) 2)]
                  (if within-tolerance?
                    (let [accepted? (= 1 (count (:inbox (:state res1))))
                          ;; Test replay
                          res-replay (light-core/handle-wire-payload (:state res1) wire-msg (:privkey-bytes bob))
                          replay-dropped? (= 1 (count (:inbox (:state res-replay))))]
                      (and accepted? (if duplicate? replay-dropped? true)))
                    ;; Out of tolerance: must be dropped cleanly
                    (and (empty? (:inbox (:state res1)))
                         (empty? (:stdout-events res1)))))))

(defspec ^{:doc "Property: JSONL processor handles arbitrary strings without crashing and never leaks private keys"}
  prop-jsonl-robustness-and-no-key-leaks 50
  (prop/for-all [input-str (gen/one-of [(gen/fmap (partial apply str) (gen/vector gen/char-ascii 0 64))
                                        (gen/fmap (partial apply str) (gen/vector gen/char-alphanumeric 0 64))
                                        (gen/elements ["{}" "{\"cmd\":\"unknown\"}" "{\"cmd\":\"identity\"}" "not-json" "{\"cmd\":123}"])])
                 cmd (gen/elements ["identity" "status" "inbox" "discover" "malformed"])]
                (let [alice (test-identity)
                      state (light-core/init-light-state (:identity alice) {})
                      priv-hex (basalt/bytes->hex (:privkey-bytes alice))
                      line (if (= cmd "malformed") input-str (str "{\"cmd\":\"" cmd "\"}"))
                      res (light-core/process-jsonl-line state line (:privkey-bytes alice))
                      json-resp-str (json/write-str (:response res))
                      events-str (json/write-str (:stdout-events res))]
                  (and (map? (:state res))
                       (map? (:response res))
                       (vector? (:stdout-events res))
                       (vector? (:net-envelopes res))
                       ;; Key leak invariant: private key hex must NEVER appear in output
                       (not (str/includes? json-resp-str priv-hex))
                       (not (str/includes? events-str priv-hex))))))

(deftest test-handle-command-nested-and-flat-args
  (testing "handle-command produces identical results for flat maps and {\"cmd\": ..., \"args\": {...}}"
    (let [id (test-identity)
          state (light-core/init-light-state (:identity id) {})
          cmd-flat {"cmd" "offer" "callee" (sample-pubkey-hex) "price" 15 "burn" 600}
          cmd-nested {"cmd" "offer" "args" {"callee" (get cmd-flat "callee") "price" 15 "burn" 600}}
          res-flat (light-core/handle-command state cmd-flat (:privkey-bytes id))
          res-nested (light-core/handle-command state cmd-nested (:privkey-bytes id))]
      (is (= (dissoc (:response res-flat) "session_id")
             (dissoc (:response res-nested) "session_id")))
      (is (= 15 (get-in res-flat [:response "price"])))
      (is (= 15 (get-in res-nested [:response "price"]))))))

(defspec ^{:doc "Property: Tampered offers (price, epoch, session-id, offer-hash) are rejected, untampered accepted"}
  prop-offer-integrity-and-tamper-rejection 25
  (prop/for-all [price (gen/choose 1 1000)
                 epoch (gen/choose 1 100)
                 tamper-field (gen/elements [:price :epoch :session-id :offer-hash :none])]
                (let [alice (test-identity)
                      bob (test-identity)
                      callee (:pubkey-hex bob)
                      cmd {"cmd" "offer" "callee" callee "price" price "burn" 500}
                      st-alice (light-core/init-light-state (:identity alice) {:epoch epoch})
                      res-offer (light-core/handle-command st-alice cmd (:privkey-bytes alice))
                      offer-env (first (filter gossip-env? (:net-envelopes res-offer)))
                      raw-msg (try (nippy/thaw (get-in offer-env [:event :message :payload])) (catch Exception _ nil))
                      tampered-msg (case tamper-field
                                     :price (assoc raw-msg :price (inc price))
                                     :epoch (assoc raw-msg :epoch (+ epoch 5))
                                     :session-id (assoc raw-msg :session-id "sess-forged")
                                     :offer-hash (assoc raw-msg :offer-hash "hash-forged")
                                     :none raw-msg)
                      st-bob (light-core/init-light-state (:identity bob) {:epoch epoch})
                      res-bob (light-core/handle-wire-payload st-bob tampered-msg (:privkey-bytes bob))]
                  (if (= tamper-field :none)
                    (and (= 1 (count (:pending-offers (:state res-bob))))
                         (= 1 (count (:stdout-events res-bob))))
                    (and (empty? (:pending-offers (:state res-bob)))
                         (empty? (:stdout-events res-bob)))))))

(defspec ^{:doc "Property: Consecutive transfers auto-increment seq and chain causal deps"}
  prop-transfer-auto-sequence-and-deps 20
  (prop/for-all [n (gen/choose 2 5)]
                (let [alice (test-identity)
                      recipient (sample-pubkey-hex)
                      st0 (light-core/init-light-state (:identity alice) {})
                      steps (reduce (fn [{:keys [state txs]} _]
                                      (let [cmd {"cmd" "transfer" "recipient" recipient "amount" 100}
                                            res (light-core/handle-command state cmd (:privkey-bytes alice))
                                            resp (:response res)]
                                        {:state (:state res)
                                         :txs (conj txs resp)}))
                                    {:state st0 :txs []}
                                    (range n))
                      txs (:txs steps)]
                  (and (= n (count txs))
                       (= (range 1 (inc n)) (map #(get % "seq") txs))
                       (every? #(and (get % "ok")
                                     (= (get % "transfer_hash") (get % "tx_id"))
                                     (= recipient (get % "receiver"))
                                     (= recipient (get % "recipient")))
                               txs)
                       (= (get-in steps [:state :transfer-seq]) n)
                       (= (get-in steps [:state :last-transfer-hash]) (get (last txs) "transfer_hash"))))))

(deftest test-non-vacuous-epoch-skew-and-adoption
  (testing "Light node adopts first epoch when uninitialized and rejects skew > 2 even from epoch 0"
    (let [alice (test-identity)
          bob (test-identity)
          session-id "sess-adopt-epoch"
          sec (byte-array 32)
          alice-keys (sealed/derive-channel-keys sec session-id :initiator)
          bob-keys (sealed/derive-channel-keys sec session-id :responder)
          plain (.getBytes "test" "UTF-8")
          sealed-fn (fn [seq-n] (sealed/seal-message (:tx-key alice-keys) seq-n plain (.getBytes session-id "UTF-8")))
          make-msg (fn [ep seq-n]
                     (let [s (sealed-fn seq-n)]
                       {:bitecho/type :sealed-message
                        :session-id session-id
                        :sender (:pubkey-hex alice)
                        :recipient (:pubkey-hex bob)
                        :epoch ep
                        :seq seq-n
                        :nonce (basalt/bytes->hex (:nonce s))
                        :ciphertext (basalt/bytes->hex (:ciphertext s))}))
          st0 (light-core/init-light-state (:identity bob) {})
          st-sess (assoc-in st0 [:sessions session-id]
                            {:session-id session-id :peer (:pubkey-hex alice) :role :responder :state "open"
                             :rx-key (:rx-key bob-keys) :tx-key (:tx-key bob-keys)
                             :replay-window (sealed/init-replay-window 64)})
          ;; 1. First message arrives with epoch 0 -> node adopts epoch 0
          res1 (light-core/handle-wire-payload st-sess (make-msg 0 1) (:privkey-bytes bob))
          st1 (:state res1)
          ;; 2. Message arrives with epoch 3 (> 2 skew from 0) -> dropped!
          res2 (light-core/handle-wire-payload st1 (make-msg 3 2) (:privkey-bytes bob))
          ;; 3. Message arrives with epoch 2 (<= 2 skew from 0) -> accepted!
          res3 (light-core/handle-wire-payload st1 (make-msg 2 3) (:privkey-bytes bob))]
      (is (false? (:epoch-initialized? st0)))
      (is (= 0 (:epoch st1)))
      (is (true? (:epoch-initialized? st1)))
      (is (= 1 (count (:inbox st1))))
      (is (= 1 (count (:inbox (:state res2)))))
      (is (= 2 (count (:inbox (:state res3))))))))

(deftest test-discover-status-inbox-keys
  (testing "exec-discover, exec-status, and exec-inbox output required keys"
    (let [alice (test-identity)
          desc {:network :devnet
                :treasury-pubkey (sample-pubkey-hex)
                :custody-pubkey (sample-pubkey-hex)
                :nodes {:node1 {:node-id :node1 :ip "127.0.0.1" :port 5000 :agent-port 5010
                                :pubkey (sample-pubkey-hex)
                                :ingress-host "ingress.bitecho.org"
                                :ingress-port 443
                                :fingerprint "95:09:40:3B..."}}}
          st (light-core/init-light-state (:identity alice) {:bootstrap desc})
          disc-res (light-core/handle-command st {"cmd" "discover"} (:privkey-bytes alice))
          val1 (first (get-in disc-res [:response "validators"]))
          status-res (light-core/handle-command st {"cmd" "status"} (:privkey-bytes alice))
          st-with-inbox (assoc st :inbox [{:session-id "s1" :session_id "s1"
                                           :from "peer1" :seq 1 :text "hi"
                                           :payload-hex "aabb" :payload_hex "aabb"}])
          inbox-res (light-core/handle-command st-with-inbox {"cmd" "inbox"} (:privkey-bytes alice))
          first-msg (first (get-in inbox-res [:response "messages"]))]
      ;; discover keys
      (is (= "ingress.bitecho.org" (get val1 "ingress_host")))
      (is (= 443 (get val1 "ingress_port")))
      (is (some? (get val1 "pubkey")))
      ;; status keys
      (is (contains? (:response status-res) "connected"))
      (is (contains? (:response status-res) "connection_error"))
      ;; inbox keys
      (is (= "s1" (or (get first-msg "session_id") (get first-msg :session_id))))
      (is (= "aabb" (or (get first-msg "payload_hex") (get first-msg :payload_hex)))))))

(defspec ^{:doc "Property: Outbox buffering, unacked replay across failover, idempotent deduplication, and signed session-ack reconciliation"}
  prop-idempotent-session-replay-and-ack-reconciliation 25
  (prop/for-all [msg-texts (gen/vector gen-text-message 1 5)
                 epoch-advance (gen/choose 0 3)]
                (let [alice (test-identity)
                      bob (test-identity)
                      descriptor {:network :devnet
                                  :nodes {:node1 {:node-id :node1 :ip "127.0.0.1" :agent-port 5010
                                                  :fingerprint (:fingerprint (:identity alice))
                                                  :ice-ufrag "u1" :ice-pwd "p1"}}}
                      st-alice0 (light-core/init-light-state (:identity alice) {:bootstrap descriptor :epoch 1})
                      st-bob0 (light-core/init-light-state (:identity bob) {:bootstrap descriptor :epoch 1 :autonomous? true})
          ;; Alice creates offer
                      offer-res (light-core/handle-command st-alice0 {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 10} (:privkey-bytes alice))
                      session-id (get-in offer-res [:response "session_id"])
                      offer-env (first (filter gossip-env? (:net-envelopes offer-res)))
          ;; Bob accepts (autonomous)
                      bob-accept-res (light-core/handle-wire-payload st-bob0 offer-env (:privkey-bytes bob))
                      accept-env (first (filter gossip-env? (:net-envelopes bob-accept-res)))
          ;; Alice opens session
                      alice-accept-res (light-core/handle-wire-payload (:state offer-res) accept-env (:privkey-bytes alice))
                      st-a1 (:state alice-accept-res)
                      st-b1 (:state bob-accept-res)
                      a-sess0 (get-in st-a1 [:sessions session-id])
                      b-sess0 (get-in st-b1 [:sessions session-id])]
                  (and (= "open" (:state a-sess0))
                       (= "open" (:state b-sess0))
                       (= 0 (:acked-seq a-sess0))
                       (= 0 (:rx-high-seq b-sess0))
                       (= 0 (:replays-deduped b-sess0))
                       (map? (:outbox a-sess0))
                       (vector? (:outbox-order a-sess0))
             ;; Now Alice sends each message
                       (let [send-res (reduce (fn [{:keys [state a-envelopes]} txt]
                                                (let [res (light-core/handle-command state {"cmd" "send" "session_id" session-id "text" txt} (:privkey-bytes alice))
                                                      env (first (filter gossip-env? (:net-envelopes res)))]
                                                  {:state (:state res)
                                                   :a-envelopes (conj a-envelopes env)}))
                                              {:state st-a1 :a-envelopes []}
                                              msg-texts)
                             st-a2 (:state send-res)
                             envs (:a-envelopes send-res)
                             n (count msg-texts)
                             a-sess2 (get-in st-a2 [:sessions session-id])]
               ;; All N messages must be buffered in Alice's outbox before acks
                         (and (= n (count (:outbox a-sess2)))
                              (= (vec (range 1 (inc n))) (:outbox-order a-sess2))
                    ;; First delivery: deliver the envelopes to Bob
                              (let [rx1-res (reduce (fn [{:keys [state acks events]} env]
                                                      (let [res (light-core/handle-wire-payload state env (:privkey-bytes bob))]
                                                        {:state (:state res)
                                                         :acks (into acks (filter gossip-env? (:net-envelopes res)))
                                                         :events (into events (:stdout-events res))}))
                                                    {:state st-b1 :acks [] :events []}
                                                    envs)
                                    st-b2 (:state rx1-res)
                                    b-inbox1 (:inbox st-b2)
                                    b-sess2 (get-in st-b2 [:sessions session-id])]
                      ;; Bob inbox has exactly N messages, rx-high-seq = N, 0 replays deduped, N ack envelopes produced
                                (and (= n (count b-inbox1))
                                     (= n (count (:events rx1-res)))
                                     (= n (:rx-high-seq b-sess2))
                                     (= 0 (:replays-deduped b-sess2))
                                     (= n (count (:acks rx1-res)))
                           ;; Advance epoch across network (simulating epoch progression during failover)
                                     (let [st-a-advanced (update st-a2 :epoch + epoch-advance)
                                           st-b-advanced (update st-b2 :epoch + epoch-advance)
                                           replay-envs (light-core/build-unacked-replay-envelopes st-a-advanced (:privkey-bytes alice))]
                             ;; build-unacked-replay-envelopes returns N replay envelopes
                                       (and (= n (count replay-envs))
                                  ;; Second delivery (Replay/Duplicate after failover):
                                  ;; Deliver replay-envs to Bob again!
                                            (let [rx2-res (reduce (fn [{:keys [state acks events]} env]
                                                                    (let [res (light-core/handle-wire-payload state env (:privkey-bytes bob))]
                                                                      {:state (:state res)
                                                                       :acks (into acks (filter gossip-env? (:net-envelopes res)))
                                                                       :events (into events (:stdout-events res))}))
                                                                  {:state st-b-advanced :acks [] :events []}
                                                                  replay-envs)
                                                  st-b3 (:state rx2-res)
                                                  b-sess3 (get-in st-b3 [:sessions session-id])]
                                    ;; Strict Idempotency:
                                    ;; 1. Bob's inbox STILL has exactly N messages (no duplicates)
                                    ;; 2. No duplicate message-received stdout events emitted
                                    ;; 3. replays-deduped incremented by N
                                    ;; 4. Duplicate acks are still emitted so sender can clear outbox
                                              (and (= n (count (:inbox st-b3)))
                                                   (= 0 (count (:events rx2-res)))
                                                   (= n (:replays-deduped b-sess3))
                                                   (= n (count (:acks rx2-res)))
                                         ;; Now Alice receives Bob's acks (delivering all emitted acks to Alice)
                                                   (let [ack-envs (into (:acks rx1-res) (:acks rx2-res))
                                                         ack-res (reduce (fn [st a-env]
                                                                           (:state (light-core/handle-wire-payload st a-env (:privkey-bytes alice))))
                                                                         st-a-advanced
                                                                         ack-envs)
                                                         a-sess-final (get-in ack-res [:sessions session-id])
                                                         empty-replays (light-core/build-unacked-replay-envelopes ack-res (:privkey-bytes alice))]
                                           ;; Alice's outbox is completely drained!
                                                     (and (= 0 (count (:outbox a-sess-final)))
                                                          (= 0 (count (:outbox-order a-sess-final)))
                                                          (= n (:acked-seq a-sess-final))
                                                          (= 0 (count empty-replays))))))))))))))))

(deftest test-out-of-order-sack-and-contiguous-reconciliation
  (testing "Out-of-order delivery SACK purges only received sequence, preserves unreceived sequences in outbox, and contiguous ack reconciles all"
    (let [alice (test-identity)
          bob (test-identity)
          descriptor {:network :devnet
                      :nodes {:node1 {:node-id :node1 :ip "127.0.0.1" :agent-port 5010
                                      :fingerprint (:fingerprint (:identity alice))
                                      :ice-ufrag "u1" :ice-pwd "p1"}}}
          st-alice0 (light-core/init-light-state (:identity alice) {:bootstrap descriptor :epoch 1})
          st-bob0 (light-core/init-light-state (:identity bob) {:bootstrap descriptor :epoch 1 :autonomous? true})
          offer-res (light-core/handle-command st-alice0 {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 10} (:privkey-bytes alice))
          session-id (get-in offer-res [:response "session_id"])
          offer-env (first (filter gossip-env? (:net-envelopes offer-res)))
          bob-accept-res (light-core/handle-wire-payload st-bob0 offer-env (:privkey-bytes bob))
          accept-env (first (filter gossip-env? (:net-envelopes bob-accept-res)))
          alice-accept-res (light-core/handle-wire-payload (:state offer-res) accept-env (:privkey-bytes alice))
          st-a0 (:state alice-accept-res)
          st-b0 (:state bob-accept-res)]
      (is (= "open" (get-in st-a0 [:sessions session-id :state])))
      (is (= "open" (get-in st-b0 [:sessions session-id :state])))

      ;; Alice sends seq 1, seq 2, seq 3
      (let [res1 (light-core/handle-command st-a0 {"cmd" "send" "session_id" session-id "text" "msg1"} (:privkey-bytes alice))
            env1 (first (filter gossip-env? (:net-envelopes res1)))
            res2 (light-core/handle-command (:state res1) {"cmd" "send" "session_id" session-id "text" "msg2"} (:privkey-bytes alice))
            env2 (first (filter gossip-env? (:net-envelopes res2)))
            res3 (light-core/handle-command (:state res2) {"cmd" "send" "session_id" session-id "text" "msg3"} (:privkey-bytes alice))
            env3 (first (filter gossip-env? (:net-envelopes res3)))
            st-a-sent (:state res3)
            a-sess-sent (get-in st-a-sent [:sessions session-id])]
        (is (= [1 2 3] (:outbox-order a-sess-sent)))
        (is (= #{1 2 3} (set (keys (:outbox a-sess-sent)))))

        ;; Simulate packet loss: env1 and env2 are lost, only env3 reaches Bob!
        (let [rx-res3 (light-core/handle-wire-payload st-b0 env3 (:privkey-bytes bob))
              st-b-after-3 (:state rx-res3)
              b-sess-after-3 (get-in st-b-after-3 [:sessions session-id])
              ack-env3 (first (filter gossip-env? (:net-envelopes rx-res3)))]
          ;; Bob received seq 3 out-of-order:
          ;; rx-high-seq is 3, but contiguous-rx-seq is still 0!
          (is (= 3 (:rx-high-seq b-sess-after-3)))
          (is (= 0 (:contiguous-rx-seq b-sess-after-3)))
          (is (some? ack-env3))

          ;; Alice receives Bob's SACK for seq 3
          (let [ack-res3 (light-core/handle-wire-payload st-a-sent ack-env3 (:privkey-bytes alice))
                st-a-after-sack (:state ack-res3)
                a-sess-after-sack (get-in st-a-after-sack [:sessions session-id])]
            ;; SACK purges ONLY seq 3 from Alice's outbox!
            ;; seq 1 and seq 2 MUST remain in outbox!
            (is (= #{1 2} (set (keys (:outbox a-sess-after-sack)))))
            (is (= [1 2] (:outbox-order a-sess-after-sack)))
            (is (= 0 (:acked-seq a-sess-after-sack)))

            ;; Replaying unacked envelopes returns exactly seq 1 and seq 2 (NOT seq 3)!
            (let [replays (light-core/build-unacked-replay-envelopes st-a-after-sack (:privkey-bytes alice))]
              (is (= 2 (count replays)))

              ;; Now deliver seq 1 to Bob
              (let [rx-res1 (light-core/handle-wire-payload st-b-after-3 env1 (:privkey-bytes bob))
                    st-b-after-1 (:state rx-res1)
                    b-sess-after-1 (get-in st-b-after-1 [:sessions session-id])
                    ack-env1 (first (filter gossip-env? (:net-envelopes rx-res1)))]
                ;; Now seq 1 received: contiguous-rx-seq is 1
                (is (= 1 (:contiguous-rx-seq b-sess-after-1)))

                ;; Alice processes ack for seq 1
                (let [ack-res1 (light-core/handle-wire-payload st-a-after-sack ack-env1 (:privkey-bytes alice))
                      st-a-after-ack1 (:state ack-res1)
                      a-sess-after-ack1 (get-in st-a-after-ack1 [:sessions session-id])]
                  (is (= #{2} (set (keys (:outbox a-sess-after-ack1)))))
                  (is (= [2] (:outbox-order a-sess-after-ack1)))
                  (is (= 1 (:acked-seq a-sess-after-ack1)))

                  ;; Finally deliver seq 2 to Bob
                  (let [rx-res2 (light-core/handle-wire-payload st-b-after-1 env2 (:privkey-bytes bob))
                        st-b-after-2 (:state rx-res2)
                        b-sess-after-2 (get-in st-b-after-2 [:sessions session-id])
                        ack-env2 (first (filter gossip-env? (:net-envelopes rx-res2)))]
                    ;; Now that seq 2 arrived, contiguous-rx-seq jumps from 1 straight to 3!
                    (is (= 3 (:contiguous-rx-seq b-sess-after-2)))

                    ;; Alice processes ack for seq 2: outbox is completely drained, acked-seq is 3!
                    (let [ack-res2 (light-core/handle-wire-payload st-a-after-ack1 ack-env2 (:privkey-bytes alice))
                          st-a-final (:state ack-res2)
                          a-sess-final (get-in st-a-final [:sessions session-id])]
                      (is (= 0 (count (:outbox a-sess-final))))
                      (is (= [] (:outbox-order a-sess-final)))
                      (is (= 3 (:acked-seq a-sess-final)))
                      (is (empty? (light-core/build-unacked-replay-envelopes st-a-final (:privkey-bytes alice)))))))))))))))

(deftest test-duplicate-offer-does-not-reset-open-session-or-rekey
  (testing "Duplicate offer arrives at autonomous responder with open session: no rekeying, outbox preserved, no envelopes, replays-deduped incremented"
    (let [alice (test-identity)
          bob (test-identity)
          descriptor {:network :devnet
                      :nodes {:node1 {:node-id :node1 :ip "127.0.0.1" :agent-port 5010
                                      :fingerprint (:fingerprint (:identity alice))
                                      :ice-ufrag "u1" :ice-pwd "p1"}}}
          st-alice0 (light-core/init-light-state (:identity alice) {:bootstrap descriptor :epoch 1})
          st-bob0 (light-core/init-light-state (:identity bob) {:bootstrap descriptor :epoch 1 :autonomous? true})
          offer-res (light-core/handle-command st-alice0 {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 10} (:privkey-bytes alice))
          session-id (get-in offer-res [:response "session_id"])
          offer-env (first (filter gossip-env? (:net-envelopes offer-res)))
          bob-accept-res (light-core/handle-wire-payload st-bob0 offer-env (:privkey-bytes bob))
          accept-env (first (filter gossip-env? (:net-envelopes bob-accept-res)))
          alice-accept-res (light-core/handle-wire-payload (:state offer-res) accept-env (:privkey-bytes alice))
          st-a0 (:state alice-accept-res)
          st-b0 (:state bob-accept-res)]
      (is (= "open" (get-in st-a0 [:sessions session-id :state])))
      (is (= "open" (get-in st-b0 [:sessions session-id :state])))

      ;; Bob sends a message to Alice so Bob's session has tx-seq > 0 and non-empty outbox
      (let [send-res (light-core/handle-command st-b0 {"cmd" "send" "session_id" session-id "text" "bob-msg1"} (:privkey-bytes bob))
            st-b-open (:state send-res)
            b-sess-before (get-in st-b-open [:sessions session-id])]
        (is (= 1 (:tx-seq b-sess-before)))
        (is (= 1 (count (:outbox b-sess-before))))
        (is (some? (:tx-key b-sess-before)))
        (is (some? (:rx-key b-sess-before)))
        (is (= 0 (:replays-deduped b-sess-before)))

        ;; Now deliver the SAME offer-env again to Bob (simulating gossip replay / duplicate offer)
        (let [dup-res (light-core/handle-wire-payload st-b-open offer-env (:privkey-bytes bob))
              st-b-after (:state dup-res)
              b-sess-after (get-in st-b-after [:sessions session-id])]
          ;; Invariants:
          ;; 1. No new envelopes emitted (do NOT emit duplicate channel-accept!)
          (is (empty? (:net-envelopes dup-res)))
          ;; 2. No stdout events emitted
          (is (empty? (:stdout-events dup-res)))
          ;; 3. Session state is still "open"
          (is (= "open" (:state b-sess-after)))
          ;; 4. Keys and seqs NOT reset: tx-seq is still 1, outbox is still intact
          (is (= 1 (:tx-seq b-sess-after)))
          (is (= (:tx-key b-sess-before) (:tx-key b-sess-after)))
          (is (= (:rx-key b-sess-before) (:rx-key b-sess-after)))
          (is (= (:outbox b-sess-before) (:outbox b-sess-after)))
          ;; 5. replays-deduped incremented to 1
          (is (= 1 (:replays-deduped b-sess-after)))

          ;; Also test manual exec-accept on existing session
          (let [manual-accept-res (light-core/handle-command st-b-after {"cmd" "accept" "session_id" session-id} (:privkey-bytes bob))]
            (is (= false (get-in manual-accept-res [:response "ok"])))
            (is (= "session-already-exists" (get-in manual-accept-res [:response "error"])))
            (is (empty? (:net-envelopes manual-accept-res)))))))))

(deftest test-outbox-eviction-counter-and-status
  (testing "Outbox eviction counter increments when outbox exceeds max-outbox-size and surfaces in exec-status"
    (let [alice (test-identity)
          bob (test-identity)
          descriptor {:network :devnet
                      :nodes {:node1 {:node-id :node1 :ip "127.0.0.1" :agent-port 5010
                                      :fingerprint (:fingerprint (:identity alice))
                                      :ice-ufrag "u1" :ice-pwd "p1"}}}
          st-alice0 (assoc (light-core/init-light-state (:identity alice) {:bootstrap descriptor :epoch 1})
                           :max-outbox-size 2)
          st-bob0 (light-core/init-light-state (:identity bob) {:bootstrap descriptor :epoch 1 :autonomous? true})
          offer-res (light-core/handle-command st-alice0 {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 10} (:privkey-bytes alice))
          session-id (get-in offer-res [:response "session_id"])
          offer-env (first (filter gossip-env? (:net-envelopes offer-res)))
          bob-accept-res (light-core/handle-wire-payload st-bob0 offer-env (:privkey-bytes bob))
          accept-env (first (filter gossip-env? (:net-envelopes bob-accept-res)))
          alice-accept-res (light-core/handle-wire-payload (:state offer-res) accept-env (:privkey-bytes alice))
          st-a0 (:state alice-accept-res)]
      (is (= 0 (get-in st-a0 [:sessions session-id :outbox-evicted])))

      ;; Send 4 messages with max-outbox-size = 2 without acks:
      (let [st1 (:state (light-core/handle-command st-a0 {"cmd" "send" "session_id" session-id "text" "m1"} (:privkey-bytes alice)))
            st2 (:state (light-core/handle-command st1 {"cmd" "send" "session_id" session-id "text" "m2"} (:privkey-bytes alice)))
            st3 (:state (light-core/handle-command st2 {"cmd" "send" "session_id" session-id "text" "m3"} (:privkey-bytes alice)))
            st4 (:state (light-core/handle-command st3 {"cmd" "send" "session_id" session-id "text" "m4"} (:privkey-bytes alice)))
            sess4 (get-in st4 [:sessions session-id])
            status-res (light-core/handle-command st4 {"cmd" "status"} (:privkey-bytes alice))
            sess-summary (first (filter #(= session-id (:session-id %)) (get-in status-res [:response "sessions"])))]
        (is (= 4 (:tx-seq sess4)))
        (is (= [3 4] (:outbox-order sess4)))
        (is (= #{3 4} (set (keys (:outbox sess4)))))
        (is (= 2 (:outbox-evicted sess4)))
        (is (= 2 (:outbox-evicted sess-summary)))
        (is (= 2 (:unacked-count sess-summary)))))))

(defspec ^{:doc "Property: End-to-end light-node economic lifecycle across sync-account, transfer, settle-intent, and submit-vouchers with consensus finalization"}
  prop-light-node-economic-envelopes-e2e 25
  (prop/for-all [transfer-amt (gen/choose 10 500)
                 burn-amt (gen/elements [500 1000])
                 intent-amt (gen/choose 100 2000)
                 voucher-seq (gen/choose 1 10)
                 voucher-price (gen/elements [5 10])]
                (let [voucher-debit (* voucher-seq voucher-price)
                      init-balance (+ transfer-amt burn-amt intent-amt voucher-debit 10000)
                      alice (test-identity)
                      alice-pub (:pubkey-hex alice)
                      alice-priv (:privkey-bytes alice)
                      bob (test-identity)
                      bob-pub (:pubkey-hex bob)
                      validator (test-identity)
                      val-pub (:pubkey-hex validator)

                      ;; Consensus-mode validator setup
                      cfg (config/make-config
                           {:mode :consensus
                            :genesis-ledger {alice-pub (account/map->AccountState {:balance init-balance :seq 0 :deps []})
                                             bob-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})
                                             val-pub (account/map->AccountState {:balance 0 :seq 0 :deps []})}
                            :peers-map {val-pub (:public (:keypair validator))}})
                      val-st0 (sm/init-state [] val-pub (assoc cfg :keypair (:keypair validator)))
                      val-st1 (assoc-in val-st0 [:home-sets [alice-pub 1]]
                                        {:status :active
                                         :callee alice-pub
                                         :epoch 1
                                         :nodes [:node1 :node2 :node3]
                                         :price voucher-price})

                      ;; Light node: 1. sync-account
                      st-a0 (light-core/init-light-state (:identity alice) {:epoch 1})
                      sync-res (light-core/handle-command st-a0 {"cmd" "sync-account" "balance" init-balance "spendable" init-balance "seq" 0 "deps" [] "finalized_epoch" 1} alice-priv)
                      st-a1 (:state sync-res)

                      ;; 2. transfer
                      tf-res (light-core/handle-command st-a1 {"cmd" "transfer" "receiver" bob-pub "amount" transfer-amt "burn" burn-amt} alice-priv)
                      st-a2 (:state tf-res)
                      deliver-env (second (:net-envelopes tf-res))
                      deliver-ev (mesh/unwrap-authenticated-agent-event deliver-env)
                      val-st2 (:state (sm/handle-event val-st1 deliver-ev))

                      ;; 3. settle-intent
                      intent-res (light-core/handle-command st-a2 {"cmd" "settle-intent" "receiver" bob-pub "amount" intent-amt} alice-priv)
                      st-a3 (:state intent-res)
                      intent-env (first (:net-envelopes intent-res))
                      intent-ev (mesh/unwrap-authenticated-agent-event intent-env)
                      val-st3 (:state (sm/handle-event val-st2 intent-ev))

                      ;; 4. submit-vouchers
                      ack (rdv/create-delivery-ack alice-priv alice-pub :node1 1 "offer-hash" voucher-seq voucher-debit)
                      vouchers-res (light-core/handle-command st-a3 {"cmd" "submit-vouchers" "vouchers" [ack]} alice-priv)
                      voucher-env (first (:net-envelopes vouchers-res))
                      voucher-ev (mesh/unwrap-authenticated-agent-event voucher-env)
                      val-st4 (:state (sm/handle-event val-st3 voucher-ev))

                      ;; 5. Finalize consensus blocks: b1 executes transfers/intents, b2 settles epoch 1 vouchers
                      b1 {:epoch 1
                          :parent-hash "genesis"
                          :payload (:pending-receipts val-st4)}
                      b1-hash (streamlet/hash-block b1)
                      b2 {:epoch 2
                          :parent-hash b1-hash
                          :payload []}
                      b2-hash (streamlet/hash-block b2)
                      val-final (-> val-st4
                                    (assoc-in [:blocks b1-hash] b1)
                                    (assoc-in [:blocks b2-hash] b2)
                                    (assoc :latest-finalized-block-hash b2-hash
                                           :finalized-blocks #{b1-hash b2-hash})
                                    sm/execute-finalized-blocks)

                      ;; Calculated economic expectations
                      take-amt (burn/calculate-settlement-take intent-amt burn/default-settlement-take-bps)
                      net-intent (- intent-amt take-amt)
                      expected-alice-bal (- init-balance transfer-amt intent-amt voucher-debit)
                      expected-bob-bal (+ transfer-amt net-intent)
                      burn-win (:window (sm/extract-burn-window val-final))
                      win-entry-0 (first (filter #(= 0 (first %)) burn-win))]
                  (and (= 3 (count (:pending-receipts val-st4)))
                       (empty? (:pending-receipts val-final))
                       ;; Causal sequence advances
                       (= 1 (:seq (get-in val-final [:ledger alice-pub])))
                       (= [(get-in tf-res [:response "transfer_hash"])] (:deps (get-in val-final [:ledger alice-pub])))
                       ;; Sender balance debited by transfer + intent + voucher
                       (= expected-alice-bal (:balance (get-in val-final [:ledger alice-pub])))
                       ;; Receiver credited by transfer + net-intent
                       (= expected-bob-bal (:balance (get-in val-final [:ledger bob-pub])))
                       ;; Home node credited by voucher-debit
                       (= voucher-debit (or (get-in val-final [:ledger :node1 :balance])
                                            (get-in val-final [:ledger "node1" :balance])
                                            0))
                       ;; Protocol settlement take recorded
                       (= take-amt (get-in val-final [:epoch-settlement-takes 0] 0))
                       ;; Total burn window includes take-amt
                       (= take-amt (nth win-entry-0 2))))))

;; -----------------------------------------------------------------------------
;; 13. Local Petnames, 1:1 Bijection, and Bidirectional Resolution (Step 2A)
;; -----------------------------------------------------------------------------

(deftest test-petname-pure-validation-and-resolution-helpers
  (let [alice-id (test-identity)
        bob-id (test-identity)
        pub-alice (:pubkey-hex alice-id)
        pub-bob (:pubkey-hex bob-id)
        st0 (light-core/init-light-state (:identity alice-id) {})]
    (testing "valid-pubkey-hex? and normalize-pubkey-hex"
      (is (true? (light-core/valid-pubkey-hex? pub-alice)))
      (is (true? (light-core/valid-pubkey-hex? (str/upper-case pub-alice))))
      (is (true? (light-core/valid-pubkey-hex? (str "  " pub-alice "  "))))
      (is (false? (light-core/valid-pubkey-hex? (apply str (repeat 88 "a")))) "88-char hex without Ed25519 SPKI prefix must be rejected")
      (is (false? (light-core/valid-pubkey-hex? (apply str (repeat 88 "0")))))
      (is (false? (light-core/valid-pubkey-hex? "")))
      (is (false? (light-core/valid-pubkey-hex? nil)))
      (is (false? (light-core/valid-pubkey-hex? "not-a-hex")))
      (is (false? (light-core/valid-pubkey-hex? (subs pub-alice 0 87))))
      (is (= (str/lower-case pub-alice) (light-core/normalize-pubkey-hex pub-alice)))
      (is (= (str/lower-case pub-alice) (light-core/normalize-pubkey-hex (str "  " (str/upper-case pub-alice) "  ")))))

    (testing "valid-petname? and normalize-petname"
      (is (true? (light-core/valid-petname? "alice")))
      (is (true? (light-core/valid-petname? "@alice")))
      (is (true? (light-core/valid-petname? "bob-node.1_2")))
      (is (false? (light-core/valid-petname? "")))
      (is (false? (light-core/valid-petname? "@")))
      (is (false? (light-core/valid-petname? nil)))
      (is (false? (light-core/valid-petname? "has spaces")))
      (is (false? (light-core/valid-petname? pub-alice)) "Raw pubkey hex must NOT be a valid petname")
      (is (= "alice" (light-core/normalize-petname "alice")))
      (is (= "alice" (light-core/normalize-petname "@Alice")))
      (is (= "alice" (light-core/normalize-petname "  @ALICE  "))))

    (testing "pubkey->petname and petname->pubkey lookups"
      (let [st (assoc st0 :petnames {"bob" pub-bob})]
        (is (= pub-bob (light-core/petname->pubkey st "bob")))
        (is (= pub-bob (light-core/petname->pubkey st "@Bob")))
        (is (nil? (light-core/petname->pubkey st "charlie")))
        (is (= "bob" (light-core/pubkey->petname st pub-bob)))
        (is (= "bob" (light-core/pubkey->petname st (str/upper-case pub-bob))))
        (is (nil? (light-core/pubkey->petname st pub-alice)))))

    (testing "resolve-counterparty"
      (let [st (assoc st0 :petnames {"bob" pub-bob})]
        (is (= {:ok? false :error "missing-counterparty"} (light-core/resolve-counterparty st "")))
        (is (= {:ok? false :error "missing-counterparty"} (light-core/resolve-counterparty st nil)))
        (is (= {:ok? true :pubkey pub-bob :petname "bob"} (light-core/resolve-counterparty st "bob")))
        (is (= {:ok? true :pubkey pub-bob :petname "bob"} (light-core/resolve-counterparty st "@BOB")))
        (is (= {:ok? true :pubkey pub-bob :petname "bob"} (light-core/resolve-counterparty st pub-bob)))
        (is (= {:ok? true :pubkey pub-alice :petname nil} (light-core/resolve-counterparty st pub-alice)))
        (is (= {:ok? false :error "unknown-petname"} (light-core/resolve-counterparty st "unknown-agent")))))))

(deftest test-petname-commands-and-bijection
  (let [alice-id (test-identity)
        bob-id (test-identity)
        charlie-id (test-identity)
        pub-bob (:pubkey-hex bob-id)
        pub-charlie (:pubkey-hex charlie-id)
        priv-alice (:privkey-bytes alice-id)
        st0 (light-core/init-light-state (:identity alice-id) {})]

    (testing "petname-set, petname-list, petname-resolve, and petname-remove"
      ;; 1. Initial list empty
      (let [res (light-core/handle-command st0 {"cmd" "petname-list"} priv-alice)]
        (is (= true (get-in res [:response "ok"])))
        (is (= 0 (get-in res [:response "count"])))
        (is (= {} (get-in res [:response "petnames"]))))

      ;; 2. Invalid petname or pubkey
      (let [r1 (light-core/handle-command st0 {"cmd" "petname-set" "petname" "" "pubkey" pub-bob} priv-alice)
            r2 (light-core/handle-command st0 {"cmd" "petname-set" "petname" "bob" "pubkey" "bad-key"} priv-alice)]
        (is (= false (get-in r1 [:response "ok"])))
        (is (= "invalid-petname" (get-in r1 [:response "error"])))
        (is (= false (get-in r2 [:response "ok"])))
        (is (= "invalid-pubkey" (get-in r2 [:response "error"]))))

      ;; 3. Valid set
      (let [res1 (light-core/handle-command st0 {"cmd" "petname-set" "petname" "@Bob" "pubkey" pub-bob} priv-alice)
            st1 (:state res1)]
        (is (= true (get-in res1 [:response "ok"])))
        (is (= "bob" (get-in res1 [:response "petname"])))
        (is (= pub-bob (get-in res1 [:response "pubkey"])))
        (is (= {"bob" pub-bob} (:petnames st1)))

        ;; 4. Idempotent set of identical binding
        (let [res-idemp (light-core/handle-command st1 {"cmd" "petname-set" "petname" "bob" "pubkey" pub-bob} priv-alice)]
          (is (= true (get-in res-idemp [:response "ok"])))
          (is (= (:petnames st1) (:petnames (:state res-idemp)))))

        ;; 5. Conflict: same petname to different pubkey without overwrite fails
        (let [res-conf1 (light-core/handle-command st1 {"cmd" "petname-set" "petname" "bob" "pubkey" pub-charlie} priv-alice)]
          (is (= false (get-in res-conf1 [:response "ok"])))
          (is (= "petname-conflict" (get-in res-conf1 [:response "error"])))
          (is (= pub-bob (get-in res-conf1 [:response "existing_pubkey"])))
          (is (= (:petnames st1) (:petnames (:state res-conf1)))))

        ;; 6. Conflict: different petname to same pubkey without overwrite fails
        (let [res-conf2 (light-core/handle-command st1 {"cmd" "petname-set" "petname" "robert" "pubkey" pub-bob} priv-alice)]
          (is (= false (get-in res-conf2 [:response "ok"])))
          (is (= "petname-conflict" (get-in res-conf2 [:response "error"])))
          (is (= "bob" (get-in res-conf2 [:response "existing_petname"])))
          (is (= (:petnames st1) (:petnames (:state res-conf2)))))

        ;; 6b. Explicit overwrite false or "false" also rejects conflict
        (let [r-false-bool (light-core/handle-command st1 {"cmd" "petname-set" "petname" "bob" "pubkey" pub-charlie "overwrite" false} priv-alice)
              r-false-str (light-core/handle-command st1 {"cmd" "petname-set" "petname" "bob" "pubkey" pub-charlie "overwrite" "false"} priv-alice)]
          (is (= false (get-in r-false-bool [:response "ok"])))
          (is (= "petname-conflict" (get-in r-false-bool [:response "error"])))
          (is (= false (get-in r-false-str [:response "ok"])))
          (is (= "petname-conflict" (get-in r-false-str [:response "error"]))))

        ;; 7. Overwrite allows re-keying and preserves 1:1 bijection (tested with true and "true")
        (let [res-over (light-core/handle-command st1 {"cmd" "petname-set" "petname" "robert" "pubkey" pub-bob "overwrite" true} priv-alice)
              st-over (:state res-over)]
          (is (= true (get-in res-over [:response "ok"])))
          (is (= {"robert" pub-bob} (:petnames st-over))))

        ;; 8. petname-resolve forward and reverse
        (let [r-pname (light-core/handle-command st1 {"cmd" "petname-resolve" "petname" "bob"} priv-alice)
              r-pub (light-core/handle-command st1 {"cmd" "petname-resolve" "pubkey" pub-bob} priv-alice)
              r-tgt (light-core/handle-command st1 {"cmd" "petname-resolve" "target" "@bob"} priv-alice)
              r-miss (light-core/handle-command st1 {"cmd" "petname-resolve" "petname" "ghost"} priv-alice)]
          (is (= true (get-in r-pname [:response "ok"])))
          (is (= pub-bob (get-in r-pname [:response "pubkey"])))
          (is (= true (get-in r-pub [:response "ok"])))
          (is (= "bob" (get-in r-pub [:response "petname"])))
          (is (= true (get-in r-tgt [:response "ok"])))
          (is (= false (get-in r-miss [:response "ok"])))
          (is (= "petname-not-found" (get-in r-miss [:response "error"]))))

        ;; 9. petname-remove by petname and by pubkey
        (let [r-rm (light-core/handle-command st1 {"cmd" "petname-remove" "petname" "bob"} priv-alice)
              st-empty (:state r-rm)]
          (is (= true (get-in r-rm [:response "ok"])))
          (is (= true (get-in r-rm [:response "removed"])))
          (is (= {} (:petnames st-empty))))

        (let [st2 (assoc st0 :petnames {"charlie" pub-charlie})
              r-rm2 (light-core/handle-command st2 {"cmd" "petname-remove" "pubkey" pub-charlie} priv-alice)]
          (is (= true (get-in r-rm2 [:response "ok"])))
          (is (= {} (:petnames (:state r-rm2)))))))))

(deftest test-petname-bidirectional-counterparty-resolution-and-events
  (let [alice-id (test-identity)
        bob-id (test-identity)
        pub-alice (:pubkey-hex alice-id)
        pub-bob (:pubkey-hex bob-id)
        priv-alice (:privkey-bytes alice-id)
        priv-bob (:privkey-bytes bob-id)
        st-a0 (assoc (light-core/init-light-state (:identity alice-id) {:epoch 1})
                     :petnames {"bob" pub-bob})
        st-b0 (assoc (light-core/init-light-state (:identity bob-id) {:epoch 1})
                     :petnames {"alice" pub-alice})]

    (testing "1. offer addressed by petname @bob"
      (let [res-offer (light-core/handle-command st-a0 {"cmd" "offer" "callee" "@bob" "price" 10} priv-alice)
            st-a1 (:state res-offer)
            sid (get-in res-offer [:response "session_id"])]
        (is (= true (get-in res-offer [:response "ok"])))
        (is (= pub-bob (get-in res-offer [:response "callee"])))
        (is (= "bob" (get-in res-offer [:response "callee_petname"])))
        (is (= "bob" (get-in res-offer [:response "peer_petname"])))

        ;; Inbound wire offer at Bob: event enriched with caller_petname "alice", wire petname ignored
        (let [gossip-offer (second (:net-envelopes res-offer))
              wire-payload (assoc (nippy/thaw (get-in gossip-offer [:event :message :payload]))
                                  :petname "spoofed-attacker-name"
                                  :nickname "spoofed-nick")
              res-b-wire (light-core/handle-wire-payload st-b0 wire-payload priv-bob)
              st-b1 (:state res-b-wire)
              ev (first (:stdout-events res-b-wire))]
          (is (= "offer-received" (get ev "event")))
          (is (= "alice" (get ev "caller_petname")))
          (is (= {"alice" pub-alice} (:petnames st-b1)) "Wire-claimed petname was NEVER imported")
          (is (nil? (get-in st-b1 [:pending-offers sid :petname])) "Wire offer in pending-offers must NOT store :petname")
          (is (nil? (get-in st-b1 [:pending-offers sid :nickname])) "Wire offer in pending-offers must NOT store :nickname")

          ;; Dedicated check: When caller has NO local petname, wire offer must NOT surface spoofed petname/nickname in inbox pending_offers
          (let [res-wire-anon (light-core/handle-wire-payload (assoc st-b0 :petnames {}) wire-payload priv-bob)
                st-anon (:state res-wire-anon)
                inbox-anon (light-core/handle-command st-anon {"cmd" "inbox"} priv-bob)
                anon-offers (get-in inbox-anon [:response "pending_offers"])]
            (is (= 1 (count anon-offers)))
            (is (nil? (:petname (first anon-offers))))
            (is (nil? (:nickname (first anon-offers))))
            (is (nil? (get (first anon-offers) "petname")))
            (is (nil? (get (first anon-offers) "nickname")))
            (is (nil? (:caller_petname (first anon-offers))))
            (is (nil? (get (first anon-offers) "caller_petname"))))

          ;; 2. Bob accepts offer
          (let [res-accept (light-core/handle-command st-b1 {"cmd" "accept" "session_id" sid} priv-bob)
                st-b2 (:state res-accept)
                accept-ev (first (:stdout-events res-accept))]
            (is (= true (get-in res-accept [:response "ok"])))
            (is (= "alice" (get-in res-accept [:response "peer_petname"])))
            (is (= "alice" (get accept-ev "peer_petname")))

            ;; Inbound wire accept at Alice: event enriched with peer_petname "bob"
            (let [accept-gossip (first (:net-envelopes res-accept))
                  accept-wire (assoc (nippy/thaw (get-in accept-gossip [:event :message :payload])) :nickname "fake-bob")
                  res-a-wire (light-core/handle-wire-payload st-a1 accept-wire priv-alice)
                  st-a2 (:state res-a-wire)
                  a-ev (first (:stdout-events res-a-wire))]
              (is (= "channel-opened" (get a-ev "event")))
              (is (= "bob" (get a-ev "peer_petname")))
              (is (= {"bob" pub-bob} (:petnames st-a2)) "Wire-claimed nickname was NEVER imported")

              ;; 3. Alice sends message addressing session by petname "bob"
              (let [res-send (light-core/handle-command st-a2 {"cmd" "send" "peer" "@bob" "text" "hello bob"} priv-alice)
                    st-a3 (:state res-send)]
                (is (= true (get-in res-send [:response "ok"])))
                (is (= sid (get-in res-send [:response "session_id"])))
                (is (= "bob" (get-in res-send [:response "peer_petname"])))

                ;; Inbound sealed message at Bob: enriched with from_petname "alice"
                (let [msg-gossip (first (:net-envelopes res-send))
                      res-b-msg (light-core/handle-wire-payload st-b2 msg-gossip priv-bob)
                      st-b3 (:state res-b-msg)
                      b-msg-ev (first (:stdout-events res-b-msg))]
                  (is (= "message-received" (get b-msg-ev "event")))
                  (is (= "alice" (get b-msg-ev "from_petname")))
                  (is (nil? (:from_petname (first (:inbox st-b3)))) "Stored inbox item must not permanently store :from_petname")

                  ;; Note 1: If petname is removed before inbox is read, inbox does NOT show stale :from_petname
                  (let [st-b3-unnamed (update st-b3 :petnames dissoc "alice")
                        res-inbox-unnamed (light-core/handle-command st-b3-unnamed {"cmd" "inbox"} priv-bob)
                        msgs-unnamed (get-in res-inbox-unnamed [:response "messages"])]
                    (is (= 1 (count msgs-unnamed)))
                    (is (nil? (:from_petname (first msgs-unnamed))))
                    (is (nil? (get (first msgs-unnamed) "from_petname"))))

                  ;; When petname is present, Bob's inbox is dynamically enriched with from_petname
                  (let [res-inbox (light-core/handle-command st-b3 {"cmd" "inbox"} priv-bob)
                        inbox-msgs (get-in res-inbox [:response "messages"])]
                    (is (= 1 (count inbox-msgs)))
                    (is (= "alice" (:from_petname (first inbox-msgs)))))

                  ;; 4. Bob closes session addressing by petname "alice"
                  (let [res-close (light-core/handle-command st-b3 {"cmd" "close" "peer" "alice"} priv-bob)
                        _st-b4 (:state res-close)]
                    (is (= true (get-in res-close [:response "ok"])))
                    (is (= "alice" (get-in res-close [:response "peer_petname"])))

                    ;; Alice handles wire close
                    (let [close-gossip (first (:net-envelopes res-close))
                          res-a-close (light-core/handle-wire-payload st-a3 close-gossip priv-alice)
                          close-ev (first (:stdout-events res-a-close))]
                      (is (= "channel-closed" (get close-ev "event")))
                      (is (= "bob" (get close-ev "peer_petname"))))))))))))

    (testing "2. transfer and settle-intent addressed by petname"
      (let [st-funded (assoc st-a0 :account {:balance 50000 :spendable 50000 :seq 0 :deps []})
            res-tf (light-core/handle-command st-funded {"cmd" "transfer" "receiver" "@bob" "amount" 1000} priv-alice)
            res-si (light-core/handle-command st-funded {"cmd" "settle-intent" "receiver" "bob" "amount" 500} priv-alice)
            res-tf-unknown (light-core/handle-command st-funded {"cmd" "transfer" "receiver" "nobody" "amount" 100} priv-alice)]
        (is (= true (get-in res-tf [:response "ok"])))
        (is (= pub-bob (get-in res-tf [:response "receiver"])))
        (is (= "bob" (get-in res-tf [:response "receiver_petname"])))
        (is (= true (get-in res-si [:response "ok"])))
        (is (= pub-bob (get-in res-si [:response "receiver"])))
        (is (= "bob" (get-in res-si [:response "receiver_petname"])))
        (is (= false (get-in res-tf-unknown [:response "ok"])))
        (is (= "unknown-petname" (get-in res-tf-unknown [:response "error"])))))

    (testing "3. status command surfaces petnames and enriches sessions"
      (let [dummy-sess {:session-id "s1" :peer pub-bob :role :initiator :state "open" :tx-seq 1 :epoch 1 :outbox {}}
            st (assoc st-a0 :sessions {"s1" dummy-sess})
            res-status (light-core/handle-command st {"cmd" "status"} priv-alice)
            sess-summary (first (get-in res-status [:response "sessions"]))]
        (is (= {"bob" pub-bob} (get-in res-status [:response "petnames"])))
        (is (= 1 (get-in res-status [:response "petnames_count"])))
        (is (= "bob" (:peer_petname sess-summary)))))

    (testing "4. resolve-session-id fails closed on ambiguous multiple active sessions"
      (let [tx-k (byte-array 32)
            st-multi (-> st-a0
                         (assoc-in [:sessions "sess-1"] {:session-id "sess-1" :peer pub-bob :state "open" :tx-key tx-k :replay-window (sealed/init-replay-window)})
                         (assoc-in [:sessions "sess-2"] {:session-id "sess-2" :peer pub-bob :state "open" :tx-key tx-k :replay-window (sealed/init-replay-window)}))]
        ;; Ambiguous: 2 open sessions to bob -> send by petname fails closed
        (let [res-ambig (light-core/handle-command st-multi {"cmd" "send" "peer" "@bob" "text" "hi"} priv-alice)]
          (is (= false (get-in res-ambig [:response "ok"])))
          (is (= "session-not-open" (get-in res-ambig [:response "error"]))))

        ;; Ambiguous: 2 active sessions to bob -> close by petname fails closed
        (let [res-ambig-close (light-core/handle-command st-multi {"cmd" "close" "peer" "bob"} priv-alice)]
          (is (= false (get-in res-ambig-close [:response "ok"])))
          (is (= "session-not-found" (get-in res-ambig-close [:response "error"]))))

        ;; Explicit session ID succeeds
        (let [res-exp (light-core/handle-command st-multi {"cmd" "close" "session_id" "sess-2"} priv-alice)
              st-after-close (:state res-exp)]
          (is (= true (get-in res-exp [:response "ok"])))
          (is (= "sess-2" (get-in res-exp [:response "session_id"])))

          ;; Now only 1 open session (sess-1) remains -> send by petname @bob resolves cleanly to sess-1
          (let [res-one-open (light-core/handle-command st-after-close {"cmd" "send" "peer" "@bob" "text" "hi"} priv-alice)]
            (is (= true (get-in res-one-open [:response "ok"])))
            (is (= "sess-1" (get-in res-one-open [:response "session_id"])))))))))

(defspec ^{:doc "Property: Strict 1:1 petname bijection, conflict isolation without overwrite, and bidirectional resolution across arbitrary command sequences"}
  prop-petname-bijection-and-bidirectional-resolution 50
  (prop/for-all [actions (gen/vector (gen/tuple (gen/elements [:set :remove :resolve :transfer])
                                                (gen/elements ["alice" "bob" "charlie" "dave" "eve"])
                                                (gen/choose 0 3)
                                                gen/boolean)
                                     5 25)]
                (let [alice-id (test-identity)
                      priv-alice (:privkey-bytes alice-id)
                      kps (vec (repeatedly 4 test-identity))
                      pubs (mapv :pubkey-hex kps)
                      init-st (assoc (light-core/init-light-state (:identity alice-id) {:epoch 1})
                                     :account {:balance 1000000 :spendable 1000000 :seq 0 :deps []})
                      final-st (reduce (fn [curr-st [action petname pub-idx overwrite?]]
                                         (let [pub (nth pubs pub-idx)]
                                           (case action
                                             :set
                                             (:state (light-core/handle-command curr-st
                                                                                {"cmd" "petname-set"
                                                                                 "petname" petname
                                                                                 "pubkey" pub
                                                                                 "overwrite" overwrite?}
                                                                                priv-alice))

                                             :remove
                                             (:state (light-core/handle-command curr-st
                                                                                {"cmd" "petname-remove"
                                                                                 "petname" petname}
                                                                                priv-alice))

                                             :resolve
                                             (let [res (light-core/handle-command curr-st
                                                                                  {"cmd" "petname-resolve"
                                                                                   "petname" petname}
                                                                                  priv-alice)]
                                               ;; resolve must be side-effect free
                                               (:state res))

                                             :transfer
                                             (let [res (light-core/handle-command curr-st
                                                                                  {"cmd" "transfer"
                                                                                   "receiver" petname
                                                                                   "amount" 10}
                                                                                  priv-alice)]
                                               (:state res)))))
                                       init-st
                                       actions)
                      pnames (:petnames final-st)]
                  ;; 1. Strict 1:1 bijection invariant holds at all times
                  (and (= (count pnames) (count (distinct (vals pnames))))
                       (every? (fn [[pn pk]]
                                 (and (light-core/valid-petname? pn)
                                      (light-core/valid-pubkey-hex? pk)
                                      (= pn (light-core/pubkey->petname final-st pk))
                                      (= pk (light-core/petname->pubkey final-st pn))))
                               pnames)))))

;; -----------------------------------------------------------------------------
;; Directory-Signed Attestation & DAC Delegation Tests (Milestone 2 - Step 2B)
;; -----------------------------------------------------------------------------

(deftest test-directory-signed-attestation-and-pop
  (let [agent-id (test-identity)
        agent-pub (:pubkey-hex agent-id)
        agent-priv (:privkey-bytes agent-id)
        dir-id (test-identity)
        dir-pub (:pubkey-hex dir-id)
        dir-priv (:privkey-bytes dir-id)
        prev-id (test-identity)
        prev-pub (:pubkey-hex prev-id)
        prev-priv (:privkey-bytes prev-id)]

    (testing "1. Proof-of-Possession creation and verification"
      (let [pop-data {:domain "bitecho.org"
                      :nickname "agent-smith"
                      :pubkey agent-pub
                      :home-set ["node1" "node2"]
                      :epoch 5}
            pop (light-core/create-directory-pop agent-priv pop-data)]
        (is (= true (light-core/verify-directory-pop pop)))
        (is (= "agent-smith" (:nickname pop)))
        (is (= agent-pub (:pubkey pop)))
        (is (= ["node1" "node2"] (:home-set pop)))
        (is (= 5 (:epoch pop)))
        (is (string? (:pop-signature pop)))

        ;; Tampered signature fails
        (let [tampered (assoc pop :pop-signature (apply str (repeat 128 "0")))]
          (is (= false (light-core/verify-directory-pop tampered))))

        ;; Tampered pubkey fails
        (let [tampered (assoc pop :pubkey prev-pub)]
          (is (= false (light-core/verify-directory-pop tampered))))

        ;; Invalid nickname fails
        (let [tampered (assoc pop :nickname "invalid name with spaces")]
          (is (= false (light-core/verify-directory-pop tampered))))))

    (testing "2. Proof-of-Possession with key rotation continuity"
      (let [pop-rot-data {:domain "bitecho.org"
                          :nickname "agent-smith"
                          :pubkey agent-pub
                          :home-set ["node1"]
                          :epoch 10
                          :prev-pubkey prev-pub
                          :prev-privkey-bytes prev-priv}
            pop-rot (light-core/create-directory-pop agent-priv pop-rot-data)]
        (is (= true (light-core/verify-directory-pop pop-rot)))
        (is (= prev-pub (:prev-pubkey pop-rot)))
        (is (string? (:rotation-signature pop-rot)))

        ;; Corrupted rotation signature fails
        (let [tampered (assoc pop-rot :rotation-signature (apply str (repeat 128 "1")))]
          (is (= false (light-core/verify-directory-pop tampered))))

        ;; Missing rotation signature when prev-pubkey is set fails
        (let [tampered (dissoc pop-rot :rotation-signature)]
          (is (= false (light-core/verify-directory-pop tampered))))

        ;; Rotation to identical pubkey is rejected
        (is (nil? (light-core/create-directory-pop agent-priv (assoc pop-rot-data :prev-pubkey agent-pub))))))

    (testing "3. Directory descriptor signing and verification"
      (let [pop (light-core/create-directory-pop agent-priv {:domain "bitecho.org"
                                                             :nickname "agent-smith"
                                                             :pubkey agent-pub
                                                             :home-set ["node1" "node2"]
                                                             :epoch 5})
            desc (light-core/sign-directory-descriptor dir-priv dir-pub pop {:mailbox "agent-smith@bitecho.org"
                                                                             :issued-epoch 5
                                                                             :expires-epoch 15})]
        (is (some? desc))
        (is (= :directory-descriptor (:bitecho/type desc)))
        (is (= "bitecho.org/agent-smith" (:uri desc)))
        (is (= dir-pub (:directory-pubkey desc)))

        ;; Successful verification
        (let [res (light-core/verify-directory-descriptor desc dir-pub 10)]
          (is (= true (:ok? res)))
          (is (= desc (:descriptor res))))

        ;; Agent self-signed descriptor (without directory authority signature) is strictly rejected
        (let [self-signed (light-core/sign-directory-descriptor agent-priv agent-pub pop {:issued-epoch 5 :expires-epoch 15})
              res-self (light-core/verify-directory-descriptor self-signed dir-pub 10)]
          (is (= false (:ok? res-self)))
          (is (= "untrusted-directory-authority" (:error res-self))))

        ;; Forged directory signature rejected
        (let [tampered (assoc desc :directory-signature (apply str (repeat 128 "a")))
              res-tamp (light-core/verify-directory-descriptor tampered dir-pub 10)]
          (is (= false (:ok? res-tamp)))
          (is (= "invalid-directory-signature" (:error res-tamp))))

        ;; Forged PoP signature rejected
        (let [tampered (assoc desc :pop-signature (apply str (repeat 128 "b")))
              res-pop (light-core/verify-directory-descriptor tampered dir-pub 10)]
          (is (= false (:ok? res-pop)))
          (is (= "invalid-pop-signature" (:error res-pop))))

        ;; Expired descriptor rejected
        (let [res-exp (light-core/verify-directory-descriptor desc dir-pub 20)]
          (is (= false (:ok? res-exp)))
          (is (= "descriptor-expired" (:error res-exp))))

        ;; Future issued epoch (> current + 2) rejected
        (let [res-fut (light-core/verify-directory-descriptor desc dir-pub 2)]
          (is (= false (:ok? res-fut)))
          (is (= "descriptor-future-epoch" (:error res-fut))))))))

(deftest test-dac-creation-revocation-and-commands
  (let [anchor-id (test-identity)
        anchor-pub (:pubkey-hex anchor-id)
        anchor-priv (:privkey-bytes anchor-id)
        agent-id (test-identity)
        agent-pub (:pubkey-hex agent-id)
        agent-priv (:privkey-bytes agent-id)
        callee-id (test-identity)
        callee-pub (:pubkey-hex callee-id)
        callee-priv (:privkey-bytes callee-id)
        dir-id (test-identity)
        dir-pub (:pubkey-hex dir-id)
        dir-priv (:privkey-bytes dir-id)
        init-st (light-core/init-light-state (:identity agent-id) {:epoch 10 :bootstrap {:custody-pubkey dir-pub}})]

    (testing "1. DAC creation, verification, and revocation"
      (let [dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                    :agent-pubkey agent-pub
                                                    :issued-epoch 10
                                                    :expires-epoch 20
                                                    :max-spend-per-epoch 100000
                                                    :scopes ["gossip" "offer" "settle-intent" "transfer"]})]
        (is (= :dac (:bitecho/type dac)))
        (is (string? (:dac-id dac)))
        (is (= anchor-pub (:anchor-pubkey dac)))
        (is (= agent-pub (:agent-pubkey dac)))

        ;; Valid DAC
        (let [v (light-core/verify-dac dac {:expected-agent-pubkey agent-pub
                                            :current-epoch 15})]
          (is (= true (:ok? v)))
          (is (= (:dac-id dac) (:dac-id v)))
          (is (= anchor-pub (:anchor-pubkey v))))

        ;; Agent mismatch
        (let [v (light-core/verify-dac dac {:expected-agent-pubkey callee-pub
                                            :current-epoch 15})]
          (is (= false (:ok? v)))
          (is (= "dac-agent-mismatch" (:error v))))

        ;; Scope enforcement
        (let [v-ok (light-core/verify-dac dac {:required-scope "offer" :current-epoch 15})
              v-no (light-core/verify-dac dac {:required-scope "admin" :current-epoch 15})]
          (is (= true (:ok? v-ok)))
          (is (= false (:ok? v-no)))
          (is (= "dac-scope-not-permitted" (:error v-no))))

        ;; Expiry enforcement
        (let [v-exp (light-core/verify-dac dac {:current-epoch 25})]
          (is (= false (:ok? v-exp)))
          (is (= "dac-expired" (:error v-exp))))

        ;; Future epoch enforcement
        (let [v-fut (light-core/verify-dac dac {:current-epoch 5})]
          (is (= false (:ok? v-fut)))
          (is (= "dac-future-epoch" (:error v-fut))))

        ;; Signature tampering
        (let [tampered (assoc dac :signature (apply str (repeat 128 "0")))
              v (light-core/verify-dac tampered {:current-epoch 15})]
          (is (= false (:ok? v)))
          (is (= "invalid-dac-signature" (:error v))))

        ;; Revocation
        (let [rev (light-core/create-dac-revocation anchor-priv {:anchor-pubkey anchor-pub
                                                                 :agent-pubkey agent-pub
                                                                 :dac-id (:dac-id dac)
                                                                 :revoked-epoch 12})]
          (is (= true (light-core/verify-dac-revocation rev)))
          (let [tampered-rev (assoc rev :signature (apply str (repeat 128 "0")))]
            (is (= false (light-core/verify-dac-revocation tampered-rev))))
          (let [v-rev (light-core/verify-dac dac {:revoked-dac-ids #{(:dac-id dac)} :current-epoch 15})]
            (is (= false (:ok? v-rev)))
            (is (= "dac-revoked" (:error v-rev)))))))

    (testing "2. Light-node commands: dac-attach, dac-revoke, directory-verify"
      (let [dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                    :agent-pubkey agent-pub
                                                    :issued-epoch 10
                                                    :expires-epoch 30
                                                    :max-spend-per-epoch 50000})
            ;; dac-attach
            attach-res (light-core/handle-command init-st {"cmd" "dac-attach" "dac" dac} agent-priv)
            st-attached (:state attach-res)]
        (is (= true (get-in attach-res [:response "ok"])))
        (is (= (:dac-id dac) (get-in attach-res [:response "dac_id"])))
        (is (= anchor-pub (get-in attach-res [:response "anchor_pubkey"])))

        ;; status shows attached DAC
        (let [stat-res (light-core/handle-command st-attached {"cmd" "status"} agent-priv)
              resp (:response stat-res)]
          (is (= (:dac-id dac) (get-in resp ["dac" "dac_id"])))
          (is (= anchor-pub (get-in resp ["dac" "anchor_pubkey"])))
          (is (= 0 (get resp "revoked_dacs_count"))))

        ;; identity shows attached DAC
        (let [id-res (light-core/handle-command st-attached {"cmd" "identity"} agent-priv)
              resp (:response id-res)]
          (is (= (:dac-id dac) (get-in resp ["dac" "dac_id"])))
          (is (= anchor-pub (get-in resp ["dac" "anchor_pubkey"]))))

        ;; dac-revoke
        (let [rev (light-core/create-dac-revocation anchor-priv {:anchor-pubkey anchor-pub
                                                                 :agent-pubkey agent-pub
                                                                 :dac-id (:dac-id dac)
                                                                 :revoked-epoch 11})
              rev-res (light-core/handle-command st-attached {"cmd" "dac-revoke" "revocation" rev} agent-priv)
              st-revoked (:state rev-res)]
          (is (= true (get-in rev-res [:response "ok"])))
          (is (= true (get-in rev-res [:response "revoked"])))
          (is (nil? (:dac st-revoked)))
          (is (= 1 (count (:revoked-dacs st-revoked))))

          ;; Attaching a revoked DAC fails closed
          (let [re-attach (light-core/handle-command st-revoked {"cmd" "dac-attach" "dac" dac} agent-priv)]
            (is (= false (get-in re-attach [:response "ok"])))
            (is (= "dac-revoked" (get-in re-attach [:response "error"])))))))

    (testing "3. directory-verify command and key continuity"
      (let [pop1 (light-core/create-directory-pop agent-priv {:domain "bitecho.org"
                                                              :nickname "smith"
                                                              :pubkey agent-pub
                                                              :home-set ["node1"]
                                                              :epoch 10})
            desc1 (light-core/sign-directory-descriptor dir-priv dir-pub pop1 {:issued-epoch 10 :expires-epoch 30})
            ver-res (light-core/handle-command init-st {"cmd" "directory-verify"
                                                        "descriptor" desc1
                                                        "directory_pubkey" dir-pub}
                                               agent-priv)
            st-dir (:state ver-res)]
        (is (= true (get-in ver-res [:response "ok"])))
        (is (= "smith" (get-in ver-res [:response "nickname"])))
        (is (= agent-pub (get-in ver-res [:response "pubkey"])))
        (is (= 1 (count (:directory-cache st-dir))))
        (is (empty? (:petnames st-dir)) "directory-verify must NEVER mutate :petnames")

        ;; Key rotation continuity:
        (let [new-agent (test-identity)
              new-pub (:pubkey-hex new-agent)
              new-priv (:privkey-bytes new-agent)
              ;; 3a. Valid rotation with prev-pubkey
              pop-rot (light-core/create-directory-pop new-priv {:domain "bitecho.org"
                                                                 :nickname "smith"
                                                                 :pubkey new-pub
                                                                 :home-set ["node1"]
                                                                 :epoch 11
                                                                 :prev-pubkey agent-pub
                                                                 :prev-privkey-bytes agent-priv})
              desc-rot (light-core/sign-directory-descriptor dir-priv dir-pub pop-rot {:issued-epoch 11 :expires-epoch 40})
              res-rot (light-core/handle-command st-dir {"cmd" "directory-verify"
                                                         "descriptor" desc-rot
                                                         "directory_pubkey" dir-pub}
                                                 agent-priv)]
          (is (= true (get-in res-rot [:response "ok"])))
          (is (= new-pub (get-in res-rot [:response "pubkey"])))

          ;; 3b. Broken key continuity: attempted takeover without matching prev-pubkey fails closed
          (let [third-agent (test-identity)
                third-pub (:pubkey-hex third-agent)
                third-priv (:privkey-bytes third-agent)
                pop-hijack (light-core/create-directory-pop third-priv {:domain "bitecho.org"
                                                                        :nickname "smith"
                                                                        :pubkey third-pub
                                                                        :home-set ["node1"]
                                                                        :epoch 11
                                                                        :prev-pubkey callee-pub
                                                                        :prev-privkey-bytes callee-priv})
                desc-hijack (light-core/sign-directory-descriptor dir-priv dir-pub pop-hijack {:issued-epoch 11 :expires-epoch 40})
                res-hijack (light-core/handle-command st-dir {"cmd" "directory-verify"
                                                              "descriptor" desc-hijack
                                                              "directory_pubkey" dir-pub}
                                                      agent-priv)]
            (is (= false (get-in res-hijack [:response "ok"])))
            (is (= "broken-key-continuity" (get-in res-hijack [:response "error"])))))))

    (testing "4. Wire Offer & Mesh Envelope DAC Attachment and Verification"
      (let [dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                    :agent-pubkey agent-pub
                                                    :issued-epoch 10
                                                    :expires-epoch 30
                                                    :max-spend-per-epoch 50000})
            st-with-dac (assoc init-st :dac dac)
            ;; Caller sends offer
            offer-res (light-core/handle-command st-with-dac {"cmd" "offer" "callee" callee-pub "price" 10 "burn" 500} agent-priv)
            gossip-env (second (:net-envelopes offer-res))
            wire-payload (nippy/thaw (get-in gossip-env [:event :message :payload]))]
        (is (= :channel-offer (:bitecho/type wire-payload)))
        (is (some? (:dac wire-payload)) "Offer must attach active DAC")
        (is (= (:dac-id dac) (:dac-id (:dac wire-payload))))

        ;; Callee receives valid wire offer
        (let [callee-st (light-core/init-light-state (:identity callee-id) {:epoch 10})
              recv-res (light-core/handle-wire-payload callee-st wire-payload callee-priv)
              ev (first (:stdout-events recv-res))]
          (is (= "offer-received" (get ev "event")))
          (is (= anchor-pub (get ev "anchor_pubkey")))
          (is (= (:dac-id dac) (get ev "dac_id")))
          (is (some? (:dac (get-in recv-res [:state :pending-offers (:session-id wire-payload)])))))

        ;; Callee drops wire offer if DAC is forged or revoked
        (let [tampered-payload (assoc-in wire-payload [:dac :signature] (apply str (repeat 128 "0")))
              callee-st (light-core/init-light-state (:identity callee-id) {:epoch 10})
              recv-bad (light-core/handle-wire-payload callee-st tampered-payload callee-priv)]
          (is (empty? (:stdout-events recv-bad)))
          (is (empty? (get-in recv-bad [:state :pending-offers]))))

        ;; Mesh agent event envelope with DAC
        (let [event {:type :settle-intent :payer agent-pub :receiver callee-pub :amount 100 :epoch 10}
              wrapped (mesh/wrap-agent-event event agent-pub agent-priv dac)
              unwrapped (mesh/unwrap-authenticated-agent-event wrapped)]
          (is (some? unwrapped))
          (is (= agent-pub (:sender unwrapped)))
          (is (= (:dac-id dac) (get-in unwrapped [:dac :dac-id]))))

        ;; Mesh drops envelope if DAC is expired or invalid
        (let [bad-event {:type :settle-intent :payer agent-pub :receiver callee-pub :amount 100 :epoch 10}
              bad-wrapped (assoc (mesh/wrap-agent-event bad-event agent-pub agent-priv dac)
                                 :dac (assoc dac :signature (apply str (repeat 128 "0"))))
              unwrapped-bad (mesh/unwrap-authenticated-agent-event bad-wrapped)]
          (is (nil? unwrapped-bad)))))))

(defspec ^{:doc "Property: Directory attestation PoP & authority security, key rotation continuity, and DAC delegation invariants"}
  prop-directory-attestation-and-dac-security-invariants 50
  (prop/for-all [nick-suffix (gen/elements ["alpha" "bravo" "charlie" "delta" "echo" "foxtrot"])
                 epoch (gen/choose 1 100)
                 validity-span (gen/choose 5 50)
                 max-spend (gen/choose 100 100000)]
                (let [agent-id (test-identity)
                      agent-pub (:pubkey-hex agent-id)
                      agent-priv (:privkey-bytes agent-id)
                      dir-id (test-identity)
                      dir-pub (:pubkey-hex dir-id)
                      dir-priv (:privkey-bytes dir-id)
                      anchor-id (test-identity)
                      anchor-pub (:pubkey-hex anchor-id)
                      anchor-priv (:privkey-bytes anchor-id)
                      prev-id (test-identity)
                      prev-pub (:pubkey-hex prev-id)
                      prev-priv (:privkey-bytes prev-id)
                      nick (str "agent-" nick-suffix)
                      issued-ep (long epoch)
                      expires-ep (+ issued-ep (long validity-span))
                      pop (light-core/create-directory-pop agent-priv {:domain "bitecho.org"
                                                                       :nickname nick
                                                                       :pubkey agent-pub
                                                                       :home-set ["node1"]
                                                                       :epoch issued-ep})
                      desc (light-core/sign-directory-descriptor dir-priv dir-pub pop {:issued-epoch issued-ep
                                                                                       :expires-epoch expires-ep})
                      dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                              :agent-pubkey agent-pub
                                                              :issued-epoch issued-ep
                                                              :expires-epoch expires-ep
                                                              :max-spend-per-epoch max-spend
                                                              :scopes ["gossip" "offer" "settle-intent" "transfer"]})]
                  (and
        ;; Invariant 1: Valid directory descriptor verifies cleanly under trusted authority
                   (= true (:ok? (light-core/verify-directory-descriptor desc dir-pub issued-ep)))

        ;; Invariant 2: Self-signed descriptor without directory authority signature fails closed
                   (let [self-desc (light-core/sign-directory-descriptor agent-priv agent-pub pop {:issued-epoch issued-ep :expires-epoch expires-ep})
                         v (light-core/verify-directory-descriptor self-desc dir-pub issued-ep)]
                     (and (= false (:ok? v))
                          (or (= "untrusted-directory-authority" (:error v))
                              (= "invalid-directory-signature" (:error v)))))

        ;; Invariant 3: Descriptor with tampered PoP fails closed
                   (let [bad-pop-desc (assoc desc :pop-signature (apply str (repeat 128 "0")))
                         v (light-core/verify-directory-descriptor bad-pop-desc dir-pub issued-ep)]
                     (and (= false (:ok? v))
                          (= "invalid-pop-signature" (:error v))))

        ;; Invariant 4: Key rotation continuity
                   (let [rot-pop (light-core/create-directory-pop agent-priv {:domain "bitecho.org"
                                                                              :nickname nick
                                                                              :pubkey agent-pub
                                                                              :home-set ["node1"]
                                                                              :epoch issued-ep
                                                                              :prev-pubkey prev-pub
                                                                              :prev-privkey-bytes prev-priv})
                         rot-desc (light-core/sign-directory-descriptor dir-priv dir-pub rot-pop {:issued-epoch issued-ep :expires-epoch expires-ep})
                         v-rot (light-core/verify-directory-descriptor rot-desc dir-pub issued-ep)]
                     (and (= true (:ok? v-rot))
                          (let [tampered-rot (assoc rot-desc :rotation-signature (apply str (repeat 128 "0")))
                                v-bad-rot (light-core/verify-directory-descriptor tampered-rot dir-pub issued-ep)]
                            (and (= false (:ok? v-bad-rot))
                                 (= "invalid-pop-signature" (:error v-bad-rot))))))

        ;; Invariant 5: DAC validity, expiry, and revocation
                   (= true (:ok? (light-core/verify-dac dac {:expected-agent-pubkey agent-pub :current-epoch issued-ep})))
                   (= false (:ok? (light-core/verify-dac dac {:current-epoch (+ expires-ep 1)})))
                   (= "dac-expired" (:error (light-core/verify-dac dac {:current-epoch (+ expires-ep 1)})))
                   (= false (:ok? (light-core/verify-dac dac {:revoked-dac-ids #{(:dac-id dac)} :current-epoch issued-ep})))
                   (= "dac-revoked" (:error (light-core/verify-dac dac {:revoked-dac-ids #{(:dac-id dac)} :current-epoch issued-ep})))))))

;; -----------------------------------------------------------------------------
;; Axiom Step 2B Hardening: String-Keyed Continuity, Mistyped Fields, Spend Limits, Offer Binding
;; -----------------------------------------------------------------------------

(deftest test-directory-verify-string-keys-continuity
  (testing "FLAG 1: directory-verify key continuity and caching with string-keyed JSONL descriptors"
    (let [agent-id (test-identity)
          agent-pub (:pubkey-hex agent-id)
          agent-priv (:privkey-bytes agent-id)
          dir-id (test-identity)
          dir-pub (:pubkey-hex dir-id)
          dir-priv (:privkey-bytes dir-id)
          init-st (light-core/init-light-state (:identity agent-id) {:epoch 10 :bootstrap {:custody-pubkey dir-pub}})
          nick "alice"
          pop1 (light-core/create-directory-pop agent-priv {:domain "bitecho.org"
                                                            :nickname nick
                                                            :pubkey agent-pub
                                                            :home-set ["node1"]
                                                            :epoch 10})
          desc1 (light-core/sign-directory-descriptor dir-priv dir-pub pop1 {:issued-epoch 10
                                                                             :expires-epoch 20})
          str-desc1 (json/read-str (json/write-str desc1))
          res1 (light-core/handle-command init-st {"cmd" "directory-verify"
                                                   "descriptor" str-desc1
                                                   "directory_pubkey" dir-pub}
                                          agent-priv)
          st1 (:state res1)
          cached1 (get-in st1 [:directory-cache nick])]

      ;; 1. First directory-verify with string-keyed descriptor succeeds and caches normalized keyword map
      (is (= true (get-in res1 [:response "ok"])))
      (is (= nick (get-in res1 [:response "nickname"])))
      (is (= agent-pub (get-in res1 [:response "pubkey"])))
      (is (map? cached1))
      (is (= agent-pub (:pubkey cached1)))
      (is (= :directory-descriptor (:bitecho/type cached1)))

      ;; 2. Re-verifying the EXACT same string-keyed descriptor a second time succeeds (idempotent re-verification)
      (let [res2 (light-core/handle-command st1 {"cmd" "directory-verify"
                                                 "descriptor" str-desc1
                                                 "directory_pubkey" dir-pub}
                                            agent-priv)]
        (is (= true (get-in res2 [:response "ok"])))
        (is (= agent-pub (get-in res2 [:response "pubkey"])))
        (is (= agent-pub (get-in res2 [:state :directory-cache nick :pubkey]))))

        ;; 3. Verifying a rotated string-keyed descriptor succeeds and updates :directory-cache
      (let [agent-id2 (test-identity)
            agent-pub2 (:pubkey-hex agent-id2)
            agent-priv2 (:privkey-bytes agent-id2)
            rot-pop (light-core/create-directory-pop agent-priv2 {:domain "bitecho.org"
                                                                  :nickname nick
                                                                  :pubkey agent-pub2
                                                                  :home-set ["node1" "node2"]
                                                                  :epoch 11
                                                                  :prev-pubkey agent-pub
                                                                  :prev-privkey-bytes agent-priv})
            rot-desc (light-core/sign-directory-descriptor dir-priv dir-pub rot-pop {:issued-epoch 11
                                                                                     :expires-epoch 25})
            str-rot-desc (json/read-str (json/write-str rot-desc))
            res3 (light-core/handle-command st1 {"cmd" "directory-verify"
                                                 "descriptor" str-rot-desc
                                                 "directory_pubkey" dir-pub}
                                            agent-priv2)
            st3 (:state res3)
            cached3 (get-in st3 [:directory-cache nick])]
        (is (= true (get-in res3 [:response "ok"])))
        (is (= agent-pub2 (get-in res3 [:response "pubkey"])))
        (is (= agent-pub2 (:pubkey cached3)))
        (is (= agent-pub (:prev-pubkey cached3)))

          ;; 4. Verifying a string-keyed descriptor with a different pubkey and no valid rotation link fails closed
        (let [agent-id3 (test-identity)
              agent-pub3 (:pubkey-hex agent-id3)
              agent-priv3 (:privkey-bytes agent-id3)
              unlinked-pop (light-core/create-directory-pop agent-priv3 {:domain "bitecho.org"
                                                                         :nickname nick
                                                                         :pubkey agent-pub3
                                                                         :home-set ["node1"]
                                                                         :epoch 11})
              unlinked-desc (light-core/sign-directory-descriptor dir-priv dir-pub unlinked-pop {:issued-epoch 11
                                                                                                 :expires-epoch 25})
              str-unlinked (json/read-str (json/write-str unlinked-desc))
              res4 (light-core/handle-command st3 {"cmd" "directory-verify"
                                                   "descriptor" str-unlinked
                                                   "directory_pubkey" dir-pub}
                                              agent-priv3)]
          (is (= false (get-in res4 [:response "ok"])))
          (is (= "broken-key-continuity" (get-in res4 [:response "error"])))
            ;; Cache retains the legitimately rotated pubkey2
          (is (= agent-pub2 (get-in res4 [:state :directory-cache nick :pubkey]))))))))

(defspec ^{:doc "Property: directory-verify with string-keyed JSON roundtrip preserves continuity and rejects unauthorized replacement"}
  prop-directory-verify-string-keys-continuity 25
  (prop/for-all [nick-suffix (gen/choose 1000 9999)
                 epoch (gen/choose 1 50)
                 validity (gen/choose 5 30)]
                (let [agent-id1 (test-identity)
                      agent-pub1 (:pubkey-hex agent-id1)
                      agent-priv1 (:privkey-bytes agent-id1)
                      agent-id2 (test-identity)
                      agent-pub2 (:pubkey-hex agent-id2)
                      agent-priv2 (:privkey-bytes agent-id2)
                      agent-id3 (test-identity)
                      agent-pub3 (:pubkey-hex agent-id3)
                      agent-priv3 (:privkey-bytes agent-id3)
                      dir-id (test-identity)
                      dir-pub (:pubkey-hex dir-id)
                      dir-priv (:privkey-bytes dir-id)
                      nick (str "spec-agent-" nick-suffix)
                      init-st (light-core/init-light-state (:identity agent-id1) {:epoch epoch :bootstrap {:custody-pubkey dir-pub}})
                      pop1 (light-core/create-directory-pop agent-priv1 {:domain "bitecho.org"
                                                                         :nickname nick
                                                                         :pubkey agent-pub1
                                                                         :home-set ["node1"]
                                                                         :epoch epoch})
                      desc1 (light-core/sign-directory-descriptor dir-priv dir-pub pop1 {:issued-epoch epoch
                                                                                         :expires-epoch (+ epoch validity)})
                      str-desc1 (json/read-str (json/write-str desc1))
                      res1 (light-core/handle-command init-st {"cmd" "directory-verify" "descriptor" str-desc1 "directory-pubkey" dir-pub} agent-priv1)
                      st1 (:state res1)
                      res-idem (light-core/handle-command st1 {"cmd" "directory-verify" "descriptor" str-desc1 "directory-pubkey" dir-pub} agent-priv1)
                      rot-pop (light-core/create-directory-pop agent-priv2 {:domain "bitecho.org"
                                                                            :nickname nick
                                                                            :pubkey agent-pub2
                                                                            :home-set ["node1"]
                                                                            :epoch (inc epoch)
                                                                            :prev-pubkey agent-pub1
                                                                            :prev-privkey-bytes agent-priv1})
                      rot-desc (light-core/sign-directory-descriptor dir-priv dir-pub rot-pop {:issued-epoch (inc epoch)
                                                                                               :expires-epoch (+ epoch validity 5)})
                      str-rot (json/read-str (json/write-str rot-desc))
                      res-rot (light-core/handle-command st1 {"cmd" "directory-verify" "descriptor" str-rot "directory-pubkey" dir-pub} agent-priv2)
                      st-rot (:state res-rot)
                      hijack-pop (light-core/create-directory-pop agent-priv3 {:domain "bitecho.org"
                                                                               :nickname nick
                                                                               :pubkey agent-pub3
                                                                               :home-set ["node1"]
                                                                               :epoch (inc epoch)})
                      hijack-desc (light-core/sign-directory-descriptor dir-priv dir-pub hijack-pop {:issued-epoch (inc epoch)
                                                                                                     :expires-epoch (+ epoch validity 5)})
                      str-hijack (json/read-str (json/write-str hijack-desc))
                      res-hijack (light-core/handle-command st-rot {"cmd" "directory-verify" "descriptor" str-hijack "directory-pubkey" dir-pub} agent-priv3)]
                  (and (= true (get-in res1 [:response "ok"]))
                       (= true (get-in res-idem [:response "ok"]))
                       (= true (get-in res-rot [:response "ok"]))
                       (= false (get-in res-hijack [:response "ok"]))
                       (= "broken-key-continuity" (get-in res-hijack [:response "error"]))))))

(deftest test-verifiers-fail-closed-on-mistyped-wire-fields
  (testing "FLAG 2: Pure verifiers fail closed with zero exceptions on mistyped wire fields"
    (let [agent-id (test-identity)
          agent-pub (:pubkey-hex agent-id)
          agent-priv (:privkey-bytes agent-id)
          anchor-id (test-identity)
          anchor-pub (:pubkey-hex anchor-id)
          anchor-priv (:privkey-bytes anchor-id)
          dir-id (test-identity)
          dir-pub (:pubkey-hex dir-id)
          dir-priv (:privkey-bytes dir-id)
          valid-pop (light-core/create-directory-pop agent-priv {:domain "bitecho.org"
                                                                 :nickname "tester"
                                                                 :pubkey agent-pub
                                                                 :home-set ["node1"]
                                                                 :epoch 10})
          valid-desc (light-core/sign-directory-descriptor dir-priv dir-pub valid-pop {:issued-epoch 10
                                                                                       :expires-epoch 20})
          valid-dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                        :agent-pubkey agent-pub
                                                        :issued-epoch 10
                                                        :expires-epoch 20
                                                        :max-spend-per-epoch 50000
                                                        :scopes ["gossip" "offer" "transfer"]})
          valid-rev (light-core/create-dac-revocation anchor-priv {:anchor-pubkey anchor-pub
                                                                   :agent-pubkey agent-pub
                                                                   :dac-id (:dac-id valid-dac)
                                                                   :revoked-epoch 10})]

      ;; 1. verify-directory-pop with mistyped fields
      (is (= false (light-core/verify-directory-pop nil)))
      (is (= false (light-core/verify-directory-pop "not-a-map")))
      (is (= false (light-core/verify-directory-pop 12345)))
      (is (= false (light-core/verify-directory-pop [])))
      (is (= false (light-core/verify-directory-pop (assoc valid-pop :epoch "10"))))
      (is (= false (light-core/verify-directory-pop (assoc valid-pop :pubkey 12345))))
      (is (= false (light-core/verify-directory-pop (assoc valid-pop :domain 42))))
      (is (= false (light-core/verify-directory-pop (assoc valid-pop :home-set 123))))
      (is (= false (light-core/verify-directory-pop (assoc valid-pop :home-set ["node1" 123]))))
      (is (= false (light-core/verify-directory-pop (assoc valid-pop :pop-signature 999))))
      (is (= false (light-core/verify-directory-pop (assoc valid-pop :prev-pubkey 123))))
      (is (= false (light-core/verify-directory-pop (assoc valid-pop :rotation-signature 123))))

      ;; 2. verify-directory-descriptor with mistyped fields
      (is (= false (:ok? (light-core/verify-directory-descriptor nil dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor "string" dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor 123 dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :issued-epoch "10") dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :expires-epoch "20") dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :epoch "10") dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor valid-desc dir-pub "not-integer-epoch"))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :home-set "not-a-coll") dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :home-set [123 {}]) dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :domain 123) dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :nickname 456) dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :pubkey 789) dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor (assoc valid-desc :directory-pubkey 111) dir-pub 10))))
      (is (= false (:ok? (light-core/verify-directory-descriptor valid-desc 99999 10))))

      ;; 3. verify-dac-revocation with mistyped fields
      (is (= false (light-core/verify-dac-revocation nil)))
      (is (= false (light-core/verify-dac-revocation "str")))
      (is (= false (light-core/verify-dac-revocation 123)))
      (is (= false (light-core/verify-dac-revocation (assoc valid-rev :revoked-epoch "10"))))
      (is (= false (light-core/verify-dac-revocation (assoc valid-rev :anchor-pubkey 123))))
      (is (= false (light-core/verify-dac-revocation (assoc valid-rev :agent-pubkey 456))))
      (is (= false (light-core/verify-dac-revocation (assoc valid-rev :dac-id 789))))
      (is (= false (light-core/verify-dac-revocation (assoc valid-rev :signature 999))))

      ;; 4. verify-dac with mistyped fields
      (is (= false (:ok? (light-core/verify-dac nil {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac "str" {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac 123 {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :issued-epoch "10") {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :expires-epoch "20") {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :max-spend-per-epoch "50000") {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :max-spend-per-epoch -10) {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac valid-dac {:current-epoch "bad-epoch"}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :scopes "not-coll") {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :scopes [123 {}]) {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :scopes []) {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :anchor-pubkey 123) {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :agent-pubkey 456) {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :dac-id 789) {:current-epoch 10}))))
      (is (= false (:ok? (light-core/verify-dac (assoc valid-dac :signature 999) {:current-epoch 10}))))

      ;; 5. Inbound wire offer with malformed :dac drops cleanly with zero exceptions
      (let [init-st (light-core/init-light-state (:identity agent-id) {:epoch 10})
            wire-offer {:bitecho/type :channel-offer
                        :session-id "sess-1"
                        :caller anchor-pub
                        :callee agent-pub
                        :caller-ephemeral-pub (basalt/bytes->hex (:public (sealed/generate-x25519-keypair)))
                        :epoch 10
                        :price 0
                        :home-node "node1"
                        :offer-hash "hash"
                        :burn 500
                        :signature (apply str (repeat 128 "0"))
                        :dac "not-a-map"}
            res (light-core/handle-wire-payload init-st wire-offer agent-priv)]
        (is (= init-st (:state res)))
        (is (empty? (:net-envelopes res))))

      ;; 6. LOW Flag (seq 61/62): sealed/offer-hash and handle-wire-payload on mistyped epoch/price
      ;; 6a. sealed/offer-hash with string and boolean epoch/price never throws ClassCastException
      (is (string? (sealed/offer-hash {:epoch "1" :price "10" :caller agent-pub :callee anchor-pub})))
      (is (string? (sealed/offer-hash {:epoch true :burn false :caller agent-pub :callee anchor-pub})))
      (is (string? (light-core/compute-offer-hash {:epoch "1" :price "10" :caller agent-pub :callee anchor-pub})))
      (is (string? (light-core/compute-offer-hash {:epoch true :burn false :caller agent-pub :callee anchor-pub})))

      ;; 6b. create-directory-pop with mistyped epoch returns nil cleanly without throwing
      (is (nil? (light-core/create-directory-pop agent-priv {:domain "bitecho.org" :nickname "tester" :pubkey agent-pub :epoch "10"})))
      (is (nil? (light-core/create-directory-pop agent-priv {:domain "bitecho.org" :nickname "tester" :pubkey agent-pub :epoch true})))

      ;; 6c. handle-wire-payload with mistyped epoch and burn in :channel-offer drops cleanly with zero exceptions
      (let [init-st (light-core/init-light-state (:identity agent-id) {:epoch 10})
            offer-str-ep {:bitecho/type :channel-offer
                          :session-id "sess-1"
                          :caller anchor-pub
                          :callee agent-pub
                          :caller-ephemeral-pub "eph-pub"
                          :epoch "1"
                          :burn "10"
                          :offer-hash "oh"
                          :signature "sig"}
            offer-bool-ep {:bitecho/type :channel-offer
                           :session-id "sess-1"
                           :caller anchor-pub
                           :callee agent-pub
                           :caller-ephemeral-pub "eph-pub"
                           :epoch true
                           :burn false
                           :offer-hash "oh"
                           :signature "sig"}
            res-str (light-core/handle-wire-payload init-st offer-str-ep agent-priv)
            res-bool (light-core/handle-wire-payload init-st offer-bool-ep agent-priv)]
        (is (= 0 (count (:pending-offers (:state res-str)))))
        (is (= 0 (count (:pending-offers (:state res-bool)))))))))

(deftest test-note-2-dac-max-spend-per-epoch-enforcement
  (testing "Note 2: DAC max-spend-per-epoch enforcement, epoch rollover, expiry, and scope denial in transfer and settle-intent"
    (let [agent-id (test-identity)
          agent-pub (:pubkey-hex agent-id)
          agent-priv (:privkey-bytes agent-id)
          anchor-id (test-identity)
          anchor-pub (:pubkey-hex anchor-id)
          anchor-priv (:privkey-bytes anchor-id)
          recipient-id (test-identity)
          recipient-pub (:pubkey-hex recipient-id)
          dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                  :agent-pubkey agent-pub
                                                  :issued-epoch 10
                                                  :expires-epoch 20
                                                  :max-spend-per-epoch 50000
                                                  :scopes ["transfer" "settle-intent"]})
          init-st (-> (light-core/init-light-state (:identity agent-id) {:epoch 10})
                      (assoc :dac dac
                             :account {:balance 200000 :spendable 200000 :seq 0 :deps []}))
          res1 (light-core/handle-command init-st {"cmd" "transfer"
                                                   "recipient" recipient-pub
                                                   "amount" "30000"
                                                   "burn" "500"}
                                          agent-priv)
          st1 (:state res1)]

      ;; 1. Transfer 30,000 within budget (30,000 <= 50,000) -> succeeds
      (is (= true (get-in res1 [:response "ok"])))
      (is (= {:epoch 10 :spent 30000} (get-in st1 [:dac-spend (:dac-id dac)])))

      ;; 2. Second transfer 25,000 exceeds epoch budget (30,000 + 25,000 = 55,000 > 50,000) -> fails closed
      (let [res2 (light-core/handle-command st1 {"cmd" "transfer"
                                                 "recipient" recipient-pub
                                                 "amount" "25000"}
                                            agent-priv)]
        (is (= false (get-in res2 [:response "ok"])))
        (is (= "dac-max-spend-exceeded" (get-in res2 [:response "error"])))
        (is (= {:epoch 10 :spent 30000} (get-in (:state res2) [:dac-spend (:dac-id dac)])))

          ;; 3. Transfer remaining 20,000 in same epoch (30,000 + 20,000 = 50,000 <= 50,000) -> succeeds
        (let [res3 (light-core/handle-command st1 {"cmd" "transfer"
                                                   "recipient" recipient-pub
                                                   "amount" "20000"
                                                   "burn" "500"}
                                              agent-priv)
              st3 (:state res3)]
          (is (= true (get-in res3 [:response "ok"])))
          (is (= {:epoch 10 :spent 50000} (get-in st3 [:dac-spend (:dac-id dac)])))

            ;; 4. Any further spend in epoch 10 fails closed
          (let [res-over (light-core/handle-command st3 {"cmd" "transfer"
                                                         "recipient" recipient-pub
                                                         "amount" "1"}
                                                    agent-priv)]
            (is (= false (get-in res-over [:response "ok"])))
            (is (= "dac-max-spend-exceeded" (get-in res-over [:response "error"]))))

            ;; 5. Advance epoch: rollover resets spend counter for new epoch
          (let [st-ep11 (assoc st3 :epoch 11)
                res-ep11 (light-core/handle-command st-ep11 {"cmd" "transfer"
                                                             "recipient" recipient-pub
                                                             "amount" "35000"
                                                             "burn" "500"}
                                                    agent-priv)
                st-after-ep11 (:state res-ep11)]
            (is (= true (get-in res-ep11 [:response "ok"])))
            (is (= {:epoch 11 :spent 35000} (get-in st-after-ep11 [:dac-spend (:dac-id dac)])))

              ;; 6. settle-intent in epoch 11: 20,000 exceeds (35,000 + 20,000 = 55,000 > 50,000) -> fails closed
            (let [res-settle-fail (light-core/handle-command st-after-ep11 {"cmd" "settle-intent"
                                                                            "receiver" recipient-pub
                                                                            "amount" "20000"}
                                                             agent-priv)]
              (is (= false (get-in res-settle-fail [:response "ok"])))
              (is (= "dac-max-spend-exceeded" (get-in res-settle-fail [:response "error"]))))

              ;; 7. settle-intent 15,000 (35,000 + 15,000 = 50,000 <= 50,000) -> succeeds
            (let [res-settle-ok (light-core/handle-command st-after-ep11 {"cmd" "settle-intent"
                                                                          "receiver" recipient-pub
                                                                          "amount" "15000"}
                                                           agent-priv)]
              (is (= true (get-in res-settle-ok [:response "ok"])))
              (is (= {:epoch 11 :spent 50000} (get-in (:state res-settle-ok) [:dac-spend (:dac-id dac)])))))))

        ;; 8. DAC expired at epoch 25 -> fails closed with dac-expired
      (let [st-exp (assoc st1 :epoch 25)
            res-exp (light-core/handle-command st-exp {"cmd" "transfer"
                                                       "recipient" recipient-pub
                                                       "amount" "1000"}
                                               agent-priv)]
        (is (= false (get-in res-exp [:response "ok"])))
        (is (= "dac-expired" (get-in res-exp [:response "error"]))))

        ;; 9. Scope denial: DAC with only "gossip" scope cannot transfer or settle
      (let [dac-gossip-only (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                                :agent-pubkey agent-pub
                                                                :issued-epoch 10
                                                                :expires-epoch 20
                                                                :max-spend-per-epoch 50000
                                                                :scopes ["gossip" "offer"]})
            st-gossip (assoc init-st :dac dac-gossip-only)
            res-tx (light-core/handle-command st-gossip {"cmd" "transfer"
                                                         "recipient" recipient-pub
                                                         "amount" "1000"}
                                              agent-priv)
            res-settle (light-core/handle-command st-gossip {"cmd" "settle-intent"
                                                             "receiver" recipient-pub
                                                             "amount" "1000"}
                                                  agent-priv)]
        (is (= false (get-in res-tx [:response "ok"])))
        (is (= "dac-scope-denied" (get-in res-tx [:response "error"])))
        (is (= false (get-in res-settle [:response "ok"])))
        (is (= "dac-scope-denied" (get-in res-settle [:response "error"])))))))

(deftest test-note-3-offer-hash-dac-binding
  (testing "Note 3: offer-hash cryptographically binds :dac when present and rejects stripping/tampering"
    (let [caller-id (test-identity)
          caller-pub (:pubkey-hex caller-id)
          callee-id (test-identity)
          callee-pub (:pubkey-hex callee-id)
          anchor-id (test-identity)
          anchor-pub (:pubkey-hex anchor-id)
          anchor-priv (:privkey-bytes anchor-id)
          dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                  :agent-pubkey caller-pub
                                                  :issued-epoch 10
                                                  :expires-epoch 20
                                                  :max-spend-per-epoch 50000
                                                  :scopes ["offer"]})
          kp-eph (sealed/generate-x25519-keypair)
          eph-pub (basalt/bytes->hex (:public kp-eph))
          session-id (light-core/compute-session-id caller-pub callee-pub eph-pub)
          base-offer {:session-id session-id
                      :caller caller-pub
                      :callee callee-pub
                      :caller-ephemeral-pub eph-pub
                      :epoch 10
                      :price 100
                      :home-node "node1"}
          hash-without-dac (sealed/offer-hash base-offer)
          hash-with-dac (sealed/offer-hash (assoc base-offer :dac dac))]

      ;; Invariant 1: Hash without DAC matches canonical format
      (is (string? hash-without-dac))
      ;; Invariant 2: Hash with DAC appends |<dac-id> and differs from hash without DAC
      (is (string? hash-with-dac))
      (is (not= hash-without-dac hash-with-dac))

      ;; Invariant 3: Stripping DAC invalidates signature on wire offer
      (let [callee-st (light-core/init-light-state (:identity callee-id) {:epoch 10})
            sig-with-dac (basalt/bytes->hex (crypto/sign (:privkey-bytes caller-id) (.getBytes hash-with-dac "UTF-8")))
            wire-offer {:bitecho/type :channel-offer
                        :session-id session-id
                        :caller caller-pub
                        :callee callee-pub
                        :caller-ephemeral-pub eph-pub
                        :epoch 10
                        :price 100
                        :home-node "node1"
                        :offer-hash hash-with-dac
                        :burn 500
                        :signature sig-with-dac
                        :dac dac}
            ;; Valid offer with DAC arrives and is accepted
            res-ok (light-core/handle-wire-payload callee-st wire-offer (:privkey-bytes callee-id))]
        (is (= 1 (count (:pending-offers (:state res-ok)))))

        ;; Adversary strips :dac from the wire offer
        (let [stripped-offer (dissoc wire-offer :dac)
              res-stripped (light-core/handle-wire-payload callee-st stripped-offer (:privkey-bytes callee-id))]
          ;; compute-offer-hash without DAC produces hash-without-dac != hash-with-dac -> dropped!
          (is (= 0 (count (:pending-offers (:state res-stripped)))))
          (is (empty? (:net-envelopes res-stripped))))))))

(deftest test-note-1-unwrap-authenticated-agent-event-opts-and-dac-epoch
  (testing "Note 1: unwrap-authenticated-agent-event accepts 2-arity opts and fails closed when DAC is present without valid epoch"
    (let [agent-id (test-identity)
          agent-pub (:pubkey-hex agent-id)
          agent-priv (:privkey-bytes agent-id)
          anchor-id (test-identity)
          anchor-pub (:pubkey-hex anchor-id)
          anchor-priv (:privkey-bytes anchor-id)
          dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                  :agent-pubkey agent-pub
                                                  :issued-epoch 10
                                                  :expires-epoch 20
                                                  :max-spend-per-epoch 50000
                                                  :scopes ["settle-intent" "gossip"]})
          raw-event {:type :settle-intent
                     :payer agent-pub
                     :receiver "302a000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                     :amount 1000
                     :epoch 15
                     :receipt-id "rec-1"}
          env-no-dac (mesh/wrap-agent-event raw-event agent-pub agent-priv)
          env-with-dac (mesh/wrap-agent-event (assoc raw-event :dac dac) agent-pub agent-priv)]

      ;; 1. Event without DAC unwraps in 1-arity cleanly
      (let [unwrapped (mesh/unwrap-authenticated-agent-event env-no-dac)]
        (is (some? unwrapped))
        (is (= agent-pub (:sender unwrapped))))

      ;; 2. Event with DAC and valid epoch unwraps in 1-arity cleanly
      (let [unwrapped (mesh/unwrap-authenticated-agent-event env-with-dac)]
        (is (some? unwrapped))
        (is (= agent-pub (:sender unwrapped))))

      ;; 3. Event with DAC and MISSING epoch in 1-arity fails closed (returns nil)
      (let [event-no-ep {:type :settle-intent
                         :payer agent-pub
                         :receiver "302a000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                         :amount 1000
                         :receipt-id "rec-2"
                         :dac dac}
            env-no-ep (mesh/wrap-agent-event event-no-ep agent-pub agent-priv)]
        (is (nil? (mesh/unwrap-authenticated-agent-event env-no-ep)))

        ;; But succeeds in 2-arity when opts supplies :current-epoch 15
        (let [unwrapped (mesh/unwrap-authenticated-agent-event env-no-ep {:current-epoch 15
                                                                          :required-scope "settle-intent"})]
          (is (some? unwrapped))
          (is (= agent-pub (:sender unwrapped))))

        ;; And fails closed in 2-arity when required-scope is not permitted by DAC
        (let [unwrapped-denied (mesh/unwrap-authenticated-agent-event env-no-ep {:current-epoch 15
                                                                                 :required-scope "admin"})]
          (is (nil? unwrapped-denied)))

        ;; And fails closed in 2-arity when DAC is revoked
        (let [unwrapped-revoked (mesh/unwrap-authenticated-agent-event env-no-ep {:current-epoch 15
                                                                                  :revoked-dacs #{(:dac-id dac)}})]
          (is (nil? unwrapped-revoked)))))))

;; -----------------------------------------------------------------------------
;; Step 2C: Two-Phase Callee-Pays Rendezvous -> Sealed-Channel Key-Exchange Handoff
;; -----------------------------------------------------------------------------

(deftest test-rendezvous-policy-command-and-enforcement
  (testing "Callee rendezvous-policy command, query, and wire header enforcement (min-burn & allowlist)"
    (let [callee-id (test-identity)
          callee-pub (:pubkey-hex callee-id)
          callee-priv (:privkey-bytes callee-id)
          caller-allowed-id (test-identity)
          caller-allowed-pub (:pubkey-hex caller-allowed-id)
          caller-denied-id (test-identity)
          caller-denied-pub (:pubkey-hex caller-denied-id)
          caller-denied-priv (:privkey-bytes caller-denied-id)
          init-st (light-core/init-light-state (:identity callee-id) {:epoch 10})

          ;; 1. Configure policy
          pol-cmd {"cmd" "rendezvous-policy"
                   "min-burn" 250
                   "price" 15
                   "allowlist" [caller-allowed-pub]
                   "auto-accept" false
                   "home-node" "node1"}
          pol-res (light-core/handle-command init-st pol-cmd callee-priv)
          pol-st (:state pol-res)
          st-resp (light-core/handle-command pol-st {"cmd" "status"} callee-priv)]

      (is (= true (get-in pol-res [:response "ok"])))
      (is (= 250 (get-in pol-res [:response "rendezvous_policy" "min_burn"])))
      (is (= 15 (get-in pol-res [:response "rendezvous_policy" "price"])))
      (is (= [caller-allowed-pub] (get-in pol-res [:response "rendezvous_policy" "allowlist"])))
      (is (= "node1" (get-in pol-res [:response "rendezvous_policy" "home_node"])))
      (is (= false (get-in pol-res [:response "rendezvous_policy" "auto_accept"])))
      ;; status reflects rendezvous_policy
      (is (= 250 (:min-burn (get-in st-resp [:response "rendezvous_policy"]))))

      ;; 2. Wire offer header from denied caller rejected fail-closed by allowlist
      (let [kp-eph (sealed/generate-x25519-keypair)
            eph-pub (basalt/bytes->hex (:public kp-eph))
            sid (light-core/compute-session-id caller-denied-pub callee-pub eph-pub)
            oh (light-core/compute-offer-hash {:session-id sid :caller caller-denied-pub :callee callee-pub
                                               :caller-ephemeral-pub eph-pub :epoch 10 :price 300 :burn 300})
            hdr-str (light-core/canonical-rendezvous-header-str caller-denied-pub callee-pub oh 10 300 "" "node1" nil)
            sig (basalt/bytes->hex (crypto/sign caller-denied-priv (.getBytes hdr-str "UTF-8")))
            denied-hdr {:bitecho/type :rendezvous-offer-header
                        :caller caller-denied-pub
                        :callee callee-pub
                        :offer-hash oh
                        :epoch 10
                        :burn 300
                        :topic ""
                        :home-node "node1"
                        :signature sig}
            recv-denied (light-core/handle-wire-payload pol-st denied-hdr callee-priv)]
        (is (empty? (:stdout-events recv-denied)))
        (is (empty? (:pending-rendezvous (:state recv-denied)))))

      ;; 3. Wire offer header with burn < min-burn rejected fail-closed
      (let [kp-eph (sealed/generate-x25519-keypair)
            eph-pub (basalt/bytes->hex (:public kp-eph))
            sid (light-core/compute-session-id caller-allowed-pub callee-pub eph-pub)
            oh (light-core/compute-offer-hash {:session-id sid :caller caller-allowed-pub :callee callee-pub
                                               :caller-ephemeral-pub eph-pub :epoch 10 :price 100 :burn 100})
            hdr-str (light-core/canonical-rendezvous-header-str caller-allowed-pub callee-pub oh 10 100 "" "node1" nil)
            sig (basalt/bytes->hex (crypto/sign (:privkey-bytes caller-allowed-id) (.getBytes hdr-str "UTF-8")))
            low-burn-hdr {:bitecho/type :rendezvous-offer-header
                          :caller caller-allowed-pub
                          :callee callee-pub
                          :offer-hash oh
                          :epoch 10
                          :burn 100
                          :topic ""
                          :home-node "node1"
                          :signature sig}
            recv-low (light-core/handle-wire-payload pol-st low-burn-hdr callee-priv)]
        (is (empty? (:stdout-events recv-low)))
        (is (empty? (:pending-rendezvous (:state recv-low)))))

      ;; 4. Valid wire offer header meeting policy accepted and buffered in :pending-rendezvous
      (let [kp-eph (sealed/generate-x25519-keypair)
            eph-pub (basalt/bytes->hex (:public kp-eph))
            sid (light-core/compute-session-id caller-allowed-pub callee-pub eph-pub)
            oh (light-core/compute-offer-hash {:session-id sid :caller caller-allowed-pub :callee callee-pub
                                               :caller-ephemeral-pub eph-pub :epoch 10 :price 300 :burn 300})
            hdr-str (light-core/canonical-rendezvous-header-str caller-allowed-pub callee-pub oh 10 300 "chat" "node1" nil)
            sig (basalt/bytes->hex (crypto/sign (:privkey-bytes caller-allowed-id) (.getBytes hdr-str "UTF-8")))
            valid-hdr {:bitecho/type :rendezvous-offer-header
                       :caller caller-allowed-pub
                       :callee callee-pub
                       :offer-hash oh
                       :epoch 10
                       :burn 300
                       :topic "chat"
                       :home-node "node1"
                       :signature sig}
            recv-valid (light-core/handle-wire-payload pol-st valid-hdr callee-priv)]
        (is (= 1 (count (:pending-rendezvous (:state recv-valid)))))
        (is (some? (get-in recv-valid [:state :pending-rendezvous oh])))))))

(deftest test-two-phase-rendezvous-handshake-end-to-end
  (testing "Two-Phase Callee-Pays Rendezvous -> Sealed-Channel Key-Exchange Handoff with initial message"
    (let [caller-id (test-identity)
          _caller-pub (:pubkey-hex caller-id)
          caller-priv (:privkey-bytes caller-id)
          callee-id (test-identity)
          callee-pub (:pubkey-hex callee-id)
          callee-priv (:privkey-bytes callee-id)
          init-caller (light-core/init-light-state (:identity caller-id) {:epoch 10})
          init-callee (light-core/init-light-state (:identity callee-id) {:epoch 10})

          ;; 1. Caller initiates Phase 1 rendezvous-offer with initial text
          offer-res (light-core/handle-command init-caller
                                               {"cmd" "rendezvous-offer"
                                                "callee" callee-pub
                                                "burn" 500
                                                "topic" "secret-chat"
                                                "text" "Hello Callee via sealed rendezvous!"}
                                               caller-priv)
          st-caller-1 (:state offer-res)
          offer-hash (get-in offer-res [:response "offer_hash"])
          sid (get-in offer-res [:response "session_id"])
          hdr-gossip-env (first (:net-envelopes offer-res))
          hdr-payload (nippy/thaw (get-in hdr-gossip-env [:event :message :payload]))]

      (is (= true (get-in offer-res [:response "ok"])))
      (is (string? offer-hash))
      (is (string? sid))
      (is (= 1 (count (:outbound-rendezvous st-caller-1))))
      (is (= :rendezvous-offer-header (:bitecho/type hdr-payload)))
      ;; Ephemeral key withheld in Phase 1!
      (is (nil? (:caller-x25519 hdr-payload)))
      (is (nil? (:caller-ephemeral-pub hdr-payload)))

      ;; 2. Callee receives Phase 1 offer header
      (let [callee-recv-hdr (light-core/handle-wire-payload init-callee hdr-payload callee-priv)
            st-callee-1 (:state callee-recv-hdr)
            inbox-res1 (light-core/handle-command st-callee-1 {"cmd" "inbox"} callee-priv)]
        (is (= 1 (count (:pending-rendezvous st-callee-1))))
        (is (= 1 (count (get-in inbox-res1 [:response "pending_rendezvous"]))))

        ;; 3. Callee accepts offer via rendezvous-accept
        (let [accept-res (light-core/handle-command st-callee-1
                                                    {"cmd" "rendezvous-accept"
                                                     "offer_hash" offer-hash}
                                                    callee-priv)
              st-callee-2 (:state accept-res)
              ack-gossip-env (first (:net-envelopes accept-res))
              ack-payload (nippy/thaw (get-in ack-gossip-env [:event :message :payload]))]
          (is (= true (get-in accept-res [:response "ok"])))
          (is (= 1 (count (:pending-rendezvous-accepts st-callee-2))))
          (is (= 0 (count (:pending-rendezvous st-callee-2))))
          (is (= :rendezvous-ack-voucher (:bitecho/type ack-payload)))
          (is (some? (:delivery-ack ack-payload)))
          (is (string? (:callee-x25519 ack-payload)))

          ;; 4. Caller receives Phase 1b :rendezvous-ack-voucher
          (let [caller-recv-ack (light-core/handle-wire-payload st-caller-1 ack-payload caller-priv)
                st-caller-2 (:state caller-recv-ack)
                reveal-env (first (:net-envelopes caller-recv-ack))
                msg-env (second (:net-envelopes caller-recv-ack))
                reveal-payload (nippy/thaw (get-in reveal-env [:event :message :payload]))
                sealed-payload (nippy/thaw (get-in msg-env [:event :message :payload]))]
            (is (= 0 (count (:outbound-rendezvous st-caller-2))))
            (is (= 1 (count (:vouchers st-caller-2))))
            (is (= "open" (get-in st-caller-2 [:sessions sid :state])))
            (is (= :rendezvous-reveal (:bitecho/type reveal-payload)))
            (is (string? (:caller-x25519 reveal-payload)))
            (is (= :sealed-message (:bitecho/type sealed-payload)))

            ;; 5. Callee receives Phase 2 :rendezvous-reveal
            (let [callee-recv-reveal (light-core/handle-wire-payload st-callee-2 reveal-payload callee-priv)
                  st-callee-3 (:state callee-recv-reveal)]
              (is (= 0 (count (:pending-rendezvous-accepts st-callee-3))))
              (is (= "open" (get-in st-callee-3 [:sessions sid :state])))

              ;; 6. Callee receives initial :sealed-message
              (let [callee-recv-msg (light-core/handle-wire-payload st-callee-3 sealed-payload callee-priv)
                    st-callee-4 (:state callee-recv-msg)
                    inbox-res2 (light-core/handle-command st-callee-4 {"cmd" "inbox"} callee-priv)]
                (is (= 1 (count (get-in inbox-res2 [:response "messages"]))))
                (is (= "Hello Callee via sealed rendezvous!" (:text (first (get-in inbox-res2 [:response "messages"])))))

                ;; 7. Bidirectional encrypted conversation: Callee replies to Caller
                (let [reply-res (light-core/handle-command st-callee-4
                                                           {"cmd" "send"
                                                            "session_id" sid
                                                            "text" "Welcome to the encrypted channel!"}
                                                           callee-priv)
                      _st-callee-5 (:state reply-res)
                      reply-env (first (:net-envelopes reply-res))
                      reply-payload (nippy/thaw (get-in reply-env [:event :message :payload]))
                      caller-recv-reply (light-core/handle-wire-payload st-caller-2 reply-payload caller-priv)
                      st-caller-3 (:state caller-recv-reply)
                      caller-inbox (light-core/handle-command st-caller-3 {"cmd" "inbox"} caller-priv)]
                  (is (= true (get-in reply-res [:response "ok"])))
                  (is (= 1 (count (get-in caller-inbox [:response "messages"]))))
                  (is (= "Welcome to the encrypted channel!" (:text (first (get-in caller-inbox [:response "messages"]))))))))))))))

(deftest test-rendezvous-tamper-resistance-and-fail-closed
  (testing "Phase 2 commitment binding tamper resistance, signature verification, and fail-closed behavior"
    (let [caller-id (test-identity)
          _caller-pub (:pubkey-hex caller-id)
          caller-priv (:privkey-bytes caller-id)
          callee-id (test-identity)
          callee-pub (:pubkey-hex callee-id)
          callee-priv (:privkey-bytes callee-id)
          init-caller (light-core/init-light-state (:identity caller-id) {:epoch 10})
          init-callee (light-core/init-light-state (:identity callee-id) {:epoch 10})

          offer-res (light-core/handle-command init-caller
                                               {"cmd" "rendezvous-offer"
                                                "callee" callee-pub
                                                "burn" 500}
                                               caller-priv)
          st-caller (:state offer-res)
          offer-hash (get-in offer-res [:response "offer_hash"])
          _sid (get-in offer-res [:response "session_id"])
          hdr-payload (nippy/thaw (get-in (first (:net-envelopes offer-res)) [:event :message :payload]))
          st-callee-1 (:state (light-core/handle-wire-payload init-callee hdr-payload callee-priv))
          accept-res (light-core/handle-command st-callee-1 {"cmd" "rendezvous-accept" "offer_hash" offer-hash} callee-priv)
          st-callee-2 (:state accept-res)
          ack-payload (nippy/thaw (get-in (first (:net-envelopes accept-res)) [:event :message :payload]))
          caller-res (light-core/handle-wire-payload st-caller ack-payload caller-priv)
          reveal-payload (nippy/thaw (get-in (first (:net-envelopes caller-res)) [:event :message :payload]))]

      ;; 1. Reveal with swapped :caller-x25519 fails offer-hash commitment verification -> drops cleanly
      (let [swapped-eph (basalt/bytes->hex (:public (sealed/generate-x25519-keypair)))
            tampered-reveal (assoc reveal-payload :caller-x25519 swapped-eph)
            res (light-core/handle-wire-payload st-callee-2 tampered-reveal callee-priv)]
        (is (= 0 (count (:sessions (:state res)))))
        (is (empty? (:stdout-events res))))

      ;; 2. Reveal with forged signature -> drops cleanly
      (let [forged-sig (apply str (repeat 128 "0"))
            tampered-reveal (assoc reveal-payload :signature forged-sig)
            res (light-core/handle-wire-payload st-callee-2 tampered-reveal callee-priv)]
        (is (= 0 (count (:sessions (:state res)))))
        (is (empty? (:stdout-events res))))

      ;; 3. Ack voucher with forged DeliveryAck -> caller drops cleanly
      (let [tampered-ack (assoc-in ack-payload [:delivery-ack :signature] (apply str (repeat 128 "0")))
            res (light-core/handle-wire-payload st-caller tampered-ack caller-priv)]
        (is (= 0 (count (:vouchers (:state res)))))
        (is (= 0 (count (:sessions (:state res))))))

      ;; 4. Phase 1 header with forged caller signature -> callee drops cleanly
      (let [tampered-hdr (assoc hdr-payload :signature (apply str (repeat 128 "0")))
            res (light-core/handle-wire-payload init-callee tampered-hdr callee-priv)]
        (is (= 0 (count (:pending-rendezvous (:state res))))))

      ;; 5. Mistyped wire fields fail closed with zero exceptions
      (let [mistyped-hdr (assoc hdr-payload :epoch "10" :burn true)
            mistyped-ack (assoc ack-payload :epoch true)
            mistyped-rev (assoc reveal-payload :epoch "bad-epoch")
            res-h (light-core/handle-wire-payload init-callee mistyped-hdr callee-priv)
            res-a (light-core/handle-wire-payload st-caller mistyped-ack caller-priv)
            res-r (light-core/handle-wire-payload st-callee-2 mistyped-rev callee-priv)]
        (is (= init-callee (:state res-h)))
        (is (= st-caller (:state res-a)))
        (is (= st-callee-2 (:state res-r)))))))

(defspec ^{:doc "Property: Two-phase callee-pays rendezvous -> sealed-channel key-exchange handoff"}
  prop-two-phase-rendezvous-to-sealed-handoff 50
  (prop/for-all [epoch (gen/choose 1 50)
                 burn (gen/choose 200 800)
                 topic (gen/elements ["greeting" "file-transfer" "query" "attest"])
                 text (gen/not-empty gen/string-ascii)]
                (let [caller-id (test-identity)
                      _caller-pub (:pubkey-hex caller-id)
                      caller-priv (:privkey-bytes caller-id)
                      callee-id (test-identity)
                      callee-pub (:pubkey-hex callee-id)
                      callee-priv (:privkey-bytes callee-id)
                      init-caller (light-core/init-light-state (:identity caller-id) {:epoch epoch})
                      init-callee (light-core/init-light-state (:identity callee-id) {:epoch epoch})

          ;; 1. Caller creates offer
                      offer-res (light-core/handle-command init-caller
                                                           {"cmd" "rendezvous-offer"
                                                            "callee" callee-pub
                                                            "burn" burn
                                                            "topic" topic
                                                            "text" text}
                                                           caller-priv)
                      st-caller-1 (:state offer-res)
                      offer-hash (get-in offer-res [:response "offer_hash"])
                      sid (get-in offer-res [:response "session_id"])
                      hdr-payload (nippy/thaw (get-in (first (:net-envelopes offer-res)) [:event :message :payload]))

          ;; 2. Callee receives header
                      callee-recv-hdr (light-core/handle-wire-payload init-callee hdr-payload callee-priv)
                      st-callee-1 (:state callee-recv-hdr)

          ;; 3. Callee accepts
                      accept-res (light-core/handle-command st-callee-1 {"cmd" "rendezvous-accept" "offer_hash" offer-hash} callee-priv)
                      st-callee-2 (:state accept-res)
                      ack-payload (nippy/thaw (get-in (first (:net-envelopes accept-res)) [:event :message :payload]))

          ;; 4. Caller receives ack
                      caller-recv-ack (light-core/handle-wire-payload st-caller-1 ack-payload caller-priv)
                      st-caller-2 (:state caller-recv-ack)
                      reveal-payload (nippy/thaw (get-in (first (:net-envelopes caller-recv-ack)) [:event :message :payload]))
                      msg-payload (nippy/thaw (get-in (second (:net-envelopes caller-recv-ack)) [:event :message :payload]))

          ;; 5. Callee receives reveal
                      callee-recv-reveal (light-core/handle-wire-payload st-callee-2 reveal-payload callee-priv)
                      st-callee-3 (:state callee-recv-reveal)

          ;; 6. Callee receives sealed message
                      callee-recv-msg (light-core/handle-wire-payload st-callee-3 msg-payload callee-priv)
                      st-callee-4 (:state callee-recv-msg)

                      caller-sess (get-in st-caller-2 [:sessions sid])
                      callee-sess (get-in st-callee-4 [:sessions sid])
                      inbox (get-in st-callee-4 [:inbox])]

                  (and (= "open" (:state caller-sess))
                       (= "open" (:state callee-sess))
                       (= 1 (count (:vouchers st-caller-2)))
           ;; Key symmetry: caller TX == callee RX, caller RX == callee TX
                       (java.util.Arrays/equals ^bytes (:tx-key caller-sess) ^bytes (:rx-key callee-sess))
                       (java.util.Arrays/equals ^bytes (:rx-key caller-sess) ^bytes (:tx-key callee-sess))
           ;; Message delivery: initial text successfully decrypted in Callee's inbox
                       (= 1 (count inbox))
                       (= text (:text (first inbox)))))))


