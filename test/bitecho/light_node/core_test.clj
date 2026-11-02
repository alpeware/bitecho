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

