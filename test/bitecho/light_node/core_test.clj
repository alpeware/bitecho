(ns bitecho.light-node.core-test
  "Tests and generative invariants for the pure light-node protocol state machine."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.economy.account :as account]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.escrow :as escrow]
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
            [clojure.test.check.properties :as prop]))

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

(defspec ^{:doc "Property: 2-epoch skew tolerance and replay-protection enforcement in wire payload processing for non-open sessions"}
  prop-epoch-skew-and-replay-protection 25
  (prop/for-all [skew (gen/choose -5 5)
                 duplicate? gen/boolean]
                (let [alice (test-identity)
                      bob (test-identity)
                      callee (:pubkey-hex bob)
                      cmd {"cmd" "offer" "callee" callee "price" 10 "burn" 500}
                      msg-epoch (+ 10 skew)
                      st-alice (light-core/init-light-state (:identity alice) {:epoch msg-epoch})
                      res-offer (light-core/handle-command st-alice cmd (:privkey-bytes alice))
                      offer-env (first (filter gossip-env? (:net-envelopes res-offer)))
                      st-bob (light-core/init-light-state (:identity bob) {:epoch 10})
                      res-bob (light-core/handle-wire-payload st-bob offer-env (:privkey-bytes bob))
                      within-tolerance? (<= (Math/abs skew) 2)]
                  (if within-tolerance?
                    (let [accepted? (= 1 (count (:pending-offers (:state res-bob))))
                          res-replay (light-core/handle-wire-payload (:state res-bob) offer-env (:privkey-bytes bob))
                          replay-dropped? (= 1 (count (:pending-offers (:state res-replay))))]
                      (and accepted? (if duplicate? replay-dropped? true)))
                    (and (empty? (:pending-offers (:state res-bob)))
                         (pos? (get-in (:state res-bob) [:diagnostics :epoch-skew-dropped] 0)))))))

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
                      raw-msg (try (light-core/thaw-payload (get-in offer-env [:event :message :payload])) (catch Exception _ nil))
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
                         (if (= tamper-field :epoch)
                           (= 1 (count (:stdout-events res-bob)))
                           (empty? (:stdout-events res-bob))))))))

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
  (testing "Light node adopts first epoch when uninitialized and rejects skew > 2 on non-open session even from epoch 0"
    (let [alice (test-identity)
          bob (test-identity)
          callee (:pubkey-hex bob)
          make-offer (fn [ep]
                       (let [st-alice (light-core/init-light-state (:identity alice) {:epoch ep})
                             res (light-core/handle-command st-alice {"cmd" "offer" "callee" callee "price" 10 "burn" 500} (:privkey-bytes alice))]
                         (first (filter gossip-env? (:net-envelopes res)))))
          st0 (light-core/init-light-state (:identity bob) {})
          ;; 1. First offer arrives with epoch 0 -> node adopts epoch 0
          res1 (light-core/handle-wire-payload st0 (make-offer 0) (:privkey-bytes bob))
          st1 (:state res1)
          ;; 2. Offer arrives with epoch 3 (> 2 skew from 0) -> dropped!
          res2 (light-core/handle-wire-payload st1 (make-offer 3) (:privkey-bytes bob))
          ;; 3. Offer arrives with epoch 2 (<= 2 skew from 0) -> accepted!
          res3 (light-core/handle-wire-payload st1 (make-offer 2) (:privkey-bytes bob))]
      (is (false? (:epoch-initialized? st0)))
      (is (= 0 (:epoch st1)))
      (is (true? (:epoch-initialized? st1)))
      (is (= 1 (count (:pending-offers st1))))
      (is (= 1 (count (:pending-offers (:state res2)))))
      (is (= 2 (count (:pending-offers (:state res3))))))))

(deftest test-open-session-epoch-skew-immunity
  (testing "Open session established at epoch 100 continues to accept sealed-message, session-ack, p2p-offer, and p2p-answer at epoch 5000"
    (let [alice (test-identity)
          bob (test-identity)
          session-id "sess-long-lived"
          sec (byte-array 32)
          alice-keys (sealed/derive-channel-keys sec session-id :initiator)
          bob-keys (sealed/derive-channel-keys sec session-id :responder)
          plain (.getBytes "hello long-lived session" "UTF-8")
          make-sealed-msg (fn [ep seq-n]
                            (let [s (sealed/seal-message (:tx-key alice-keys) seq-n plain (.getBytes session-id "UTF-8"))]
                              {:bitecho/type :sealed-message
                               :session-id session-id
                               :sender (:pubkey-hex alice)
                               :recipient (:pubkey-hex bob)
                               :epoch ep
                               :seq seq-n
                               :nonce (basalt/bytes->hex (:nonce s))
                               :ciphertext (basalt/bytes->hex (:ciphertext s))}))
          st-bob (-> (light-core/init-light-state (:identity bob) {:epoch 5000})
                     (assoc-in [:sessions session-id]
                               {:session-id session-id
                                :peer (:pubkey-hex alice)
                                :role :responder
                                :state "open"
                                :epoch 100
                                :rx-key (:rx-key bob-keys)
                                :tx-key (:tx-key bob-keys)
                                :replay-window (sealed/init-replay-window 64)
                                :p2p {:phase :connecting
                                      :signal-seq 1}}))
          ;; 1. Sealed message with peer epoch 100 arriving at Bob (epoch 5000) -> ACCEPTED!
          res1 (light-core/handle-wire-payload st-bob (make-sealed-msg 100 1) (:privkey-bytes bob))]
      (is (= 1 (count (:inbox (:state res1)))))
      (is (= 5000 (get-in (:state res1) [:sessions session-id :epoch])))

      ;; 2. Replay of seq 1 on the open session is REJECTED by replay window
      (let [res-replay (light-core/handle-wire-payload (:state res1) (make-sealed-msg 100 1) (:privkey-bytes bob))]
        (is (= 1 (count (:inbox (:state res-replay))))))

      ;; 3. Sealed message with peer epoch 0 arriving at Bob (epoch 5000) -> ACCEPTED!
      (let [res2 (light-core/handle-wire-payload (:state res1) (make-sealed-msg 0 2) (:privkey-bytes bob))]
        (is (= 2 (count (:inbox (:state res2)))))
        (is (= 5000 (get-in (:state res2) [:sessions session-id :epoch]))))

      ;; 4. Session ACK with epoch 100 -> ACCEPTED!
      (let [ack-msg {:bitecho/type :session-ack
                     :session-id session-id
                     :sender (:pubkey-hex alice)
                     :recipient (:pubkey-hex bob)
                     :epoch 100
                     :acked-seq 1
                     :ack-seq 1}
            res-ack (light-core/handle-wire-payload (:state res1) ack-msg (:privkey-bytes bob))]
        (is (some? (get-in (:state res-ack) [:sessions session-id]))))

      ;; 5. P2P-offer on open session with epoch 100 and signal-seq 2 -> ACCEPTED!
      (let [st-alice (-> (light-core/init-light-state (:identity alice) {:epoch 100})
                         (assoc-in [:sessions session-id]
                                   {:session-id session-id
                                    :peer (:pubkey-hex bob)
                                    :role :initiator
                                    :state "open"
                                    :epoch 100
                                    :p2p {:local-signal-seq 1}}))
            res-alice (light-core/handle-command st-alice
                                                 {"cmd" "p2p-offer"
                                                  "session_id" session-id
                                                  "candidates" ["udp://198.51.100.1:5010"]}
                                                 (:privkey-bytes alice))
            offer-env (first (:net-envelopes res-alice))
            res-p2p (light-core/handle-wire-payload (:state res1) offer-env (:privkey-bytes bob))
            ;; 6. Stale P2P-offer with signal-seq 1 (<= current 2) -> REJECTED
            st-alice-stale (-> (light-core/init-light-state (:identity alice) {:epoch 5000})
                               (assoc-in [:sessions session-id]
                                         {:session-id session-id
                                          :peer (:pubkey-hex bob)
                                          :role :initiator
                                          :state "open"
                                          :epoch 5000
                                          :p2p {:local-signal-seq 0}}))
            res-alice-stale (light-core/handle-command st-alice-stale
                                                       {"cmd" "p2p-offer"
                                                        "session_id" session-id
                                                        "candidates" ["udp://198.51.100.1:5010"]}
                                                       (:privkey-bytes alice))
            stale-env (first (:net-envelopes res-alice-stale))
            res-stale (light-core/handle-wire-payload (:state res-p2p) stale-env (:privkey-bytes bob))]
        (is (= :offer-received (get-in (:state res-p2p) [:sessions session-id :p2p :phase])))
        (is (pos? (get-in (:state res-stale) [:diagnostics :p2p-signal-deduped] 0)))
        (is (empty? (:stdout-events res-stale))))

      ;; 7. Non-open session still enforces 2-epoch skew check!
      (let [closed-sid "sess-closed"
            st-closed (assoc-in (:state res1) [:sessions closed-sid]
                                {:session-id closed-sid
                                 :peer (:pubkey-hex alice)
                                 :role :responder
                                 :state "closed"
                                 :epoch 100})
            closed-msg (assoc (make-sealed-msg 100 1) :session-id closed-sid)
            res-closed (light-core/handle-wire-payload st-closed closed-msg (:privkey-bytes bob))]
        (is (pos? (get-in (:state res-closed) [:diagnostics :epoch-skew-dropped] 0)))))))

(deftest test-p2p-connection-failure-auto-relay-fallback
  (testing "handle-p2p-connection-failure defaults auto-relay-fallback? to true unless explicitly false"
    (let [alice (test-identity)
          sid "sess-p2p-fail"
          st (-> (light-core/init-light-state (:identity alice) {})
                 (assoc-in [:sessions sid] {:session-id sid
                                            :peer (sample-pubkey-hex)
                                            :state "open"
                                            :p2p {:phase :connecting}}))
          st-failed (light-core/handle-p2p-connection-failure st sid "dial-timeout")]
      (is (= :closed (get-in st-failed [:sessions sid :p2p :phase])))
      (is (= true (get-in st-failed [:sessions sid :relay-fallback?])))
      (is (= true (get-in st-failed [:sessions sid :p2p :relay-fallback?]))))

    (testing "explicit :auto-relay-fallback? false suppresses relay-fallback?"
      (let [alice (test-identity)
            sid "sess-p2p-fail"
            st (-> (light-core/init-light-state (:identity alice) {:auto-relay-fallback? false})
                   (assoc-in [:sessions sid] {:session-id sid
                                              :peer (sample-pubkey-hex)
                                              :state "open"
                                              :p2p {:phase :connecting}}))
            st-failed (light-core/handle-p2p-connection-failure st sid "dial-timeout")]
        (is (= :closed (get-in st-failed [:sessions sid :p2p :phase])))
        (is (nil? (get-in st-failed [:sessions sid :relay-fallback?])))
        (is (nil? (get-in st-failed [:sessions sid :p2p :relay-fallback?])))))))

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
              wire-payload (assoc (light-core/thaw-payload (get-in gossip-offer [:event :message :payload]))
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
                  accept-wire (assoc (light-core/thaw-payload (get-in accept-gossip [:event :message :payload])) :nickname "fake-bob")
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

    (testing "4. resolve-session-id resolves most active session on multiple open sessions"
      (let [tx-k (byte-array 32)
            st-multi (-> st-a0
                         (assoc-in [:sessions "sess-1"] {:session-id "sess-1" :peer pub-bob :state "open" :tx-key tx-k :replay-window (sealed/init-replay-window)})
                         (assoc-in [:sessions "sess-2"] {:session-id "sess-2" :peer pub-bob :state "open" :tx-key tx-k :replay-window (sealed/init-replay-window)}))]
        ;; Multiple open sessions to bob -> send by petname resolves to most active (tie-break sess-2)
        (let [res-ambig (light-core/handle-command st-multi {"cmd" "send" "peer" "@bob" "text" "hi"} priv-alice)]
          (is (= true (get-in res-ambig [:response "ok"])))
          (is (= "sess-2" (get-in res-ambig [:response "session_id"]))))

        ;; Ambiguous: 2 active sessions to bob -> close by petname still fails closed
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
            wire-payload (light-core/thaw-payload (get-in gossip-env [:event :message :payload]))]
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
          hdr-payload (light-core/thaw-payload (get-in hdr-gossip-env [:event :message :payload]))]

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
              ack-payload (light-core/thaw-payload (get-in ack-gossip-env [:event :message :payload]))]
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
                reveal-payload (light-core/thaw-payload (get-in reveal-env [:event :message :payload]))
                sealed-payload (light-core/thaw-payload (get-in msg-env [:event :message :payload]))]
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
                      reply-payload (light-core/thaw-payload (get-in reply-env [:event :message :payload]))
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
          hdr-payload (light-core/thaw-payload (get-in (first (:net-envelopes offer-res)) [:event :message :payload]))
          st-callee-1 (:state (light-core/handle-wire-payload init-callee hdr-payload callee-priv))
          accept-res (light-core/handle-command st-callee-1 {"cmd" "rendezvous-accept" "offer_hash" offer-hash} callee-priv)
          st-callee-2 (:state accept-res)
          ack-payload (light-core/thaw-payload (get-in (first (:net-envelopes accept-res)) [:event :message :payload]))
          caller-res (light-core/handle-wire-payload st-caller ack-payload caller-priv)
          reveal-payload (light-core/thaw-payload (get-in (first (:net-envelopes caller-res)) [:event :message :payload]))]

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
                 text gen-text-message]
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
                      hdr-payload (light-core/thaw-payload (get-in (first (:net-envelopes offer-res)) [:event :message :payload]))

          ;; 2. Callee receives header
                      callee-recv-hdr (light-core/handle-wire-payload init-callee hdr-payload callee-priv)
                      st-callee-1 (:state callee-recv-hdr)

          ;; 3. Callee accepts
                      accept-res (light-core/handle-command st-callee-1 {"cmd" "rendezvous-accept" "offer_hash" offer-hash} callee-priv)
                      st-callee-2 (:state accept-res)
                      ack-payload (light-core/thaw-payload (get-in (first (:net-envelopes accept-res)) [:event :message :payload]))

          ;; 4. Caller receives ack
                      caller-recv-ack (light-core/handle-wire-payload st-caller-1 ack-payload caller-priv)
                      st-caller-2 (:state caller-recv-ack)
                      reveal-payload (light-core/thaw-payload (get-in (first (:net-envelopes caller-recv-ack)) [:event :message :payload]))
                      msg-payload (light-core/thaw-payload (get-in (second (:net-envelopes caller-recv-ack)) [:event :message :payload]))

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

(deftest test-flag-c-compute-offer-hash-exact-format
  (testing "Flag C: compute-offer-hash reproduces exact 2d21308 base format (session-id-caller-callee-eph-epoch-price-homenode) with optional |<dac-id>"
    (let [no-dac {:session-id "s1"
                  :caller "c1"
                  :callee "c2"
                  :caller-ephemeral-pub "eph1"
                  :epoch 5
                  :price 10
                  :home-node "node1"}
          with-dac (assoc no-dac :dac {:dac-id "d1"})
          expected-no-dac (basalt/bytes->hex (crypto/sha256 (.getBytes "s1-c1-c2-eph1-5-10-node1" "UTF-8")))
          expected-with-dac (basalt/bytes->hex (crypto/sha256 (.getBytes "s1-c1-c2-eph1-5-10-node1|d1" "UTF-8")))]
      (is (= expected-no-dac (light-core/compute-offer-hash no-dac)))
      (is (= expected-with-dac (light-core/compute-offer-hash with-dac))))))

(deftest test-flag-d-string-typed-numerics-and-rejection
  (testing "Flag D: string-typed numbers succeed, and unparseable/negative strings fail closed without ClassCastException"
    (let [agent-id (test-identity)
          _agent-pub (:pubkey-hex agent-id)
          agent-priv (:privkey-bytes agent-id)
          peer-id (test-identity)
          peer-pub (:pubkey-hex peer-id)
          st (light-core/init-light-state (:identity agent-id) {:epoch 10})]

      ;; 1. rendezvous-policy with string integers succeeds
      (let [res (light-core/handle-command st {"cmd" "rendezvous-policy"
                                               "min_burn" "100"
                                               "price" "20"}
                                           agent-priv)]
        (is (= true (get-in res [:response "ok"])))
        (is (= 100 (get-in res [:response "rendezvous_policy" "min_burn"])))
        (is (= 20 (get-in res [:response "rendezvous_policy" "price"]))))

      ;; 2. rendezvous-policy with invalid non-numeric strings returns error cleanly
      (let [res-bad-burn (light-core/handle-command st {"cmd" "rendezvous-policy" "min_burn" "not-a-number"} agent-priv)
            res-bad-price (light-core/handle-command st {"cmd" "rendezvous-policy" "price" "invalid"} agent-priv)
            res-neg-burn (light-core/handle-command st {"cmd" "rendezvous-policy" "min_burn" -5} agent-priv)]
        (is (= false (get-in res-bad-burn [:response "ok"])))
        (is (= "invalid-policy-numeric" (get-in res-bad-burn [:response "error"])))
        (is (= false (get-in res-bad-price [:response "ok"])))
        (is (= "invalid-policy-numeric" (get-in res-bad-price [:response "error"])))
        (is (= false (get-in res-neg-burn [:response "ok"])))
        (is (= "invalid-policy-numeric" (get-in res-neg-burn [:response "error"]))))

      ;; 3. rendezvous-offer with string burn succeeds
      (let [res-ok (light-core/handle-command st {"cmd" "rendezvous-offer"
                                                  "callee" peer-pub
                                                  "burn" "500"}
                                              agent-priv)]
        (is (= true (get-in res-ok [:response "ok"])))
        (is (= 500 (get-in res-ok [:response "burn"]))))

      ;; 4. rendezvous-offer with invalid non-numeric burn returns error cleanly
      (let [res-bad (light-core/handle-command st {"cmd" "rendezvous-offer"
                                                   "callee" peer-pub
                                                   "burn" "bad-burn"}
                                               agent-priv)
            res-neg (light-core/handle-command st {"cmd" "rendezvous-offer"
                                                   "callee" peer-pub
                                                   "burn" -10}
                                               agent-priv)]
        (is (= false (get-in res-bad [:response "ok"])))
        (is (= "invalid-burn" (get-in res-bad [:response "error"])))
        (is (= false (get-in res-neg [:response "ok"])))
        (is (= "invalid-burn" (get-in res-neg [:response "error"]))))

      ;; 5. offer with string price and burn succeeds
      (let [res-offer-ok (light-core/handle-command st {"cmd" "offer"
                                                        "callee" peer-pub
                                                        "price" "10"
                                                        "burn" "500"}
                                                    agent-priv)]
        (is (= true (get-in res-offer-ok [:response "ok"])))
        (is (= 10 (get-in res-offer-ok [:response "price"])))
        (is (= 500 (get-in res-offer-ok [:response "burn"]))))

      ;; 6. offer with invalid non-numeric price or burn returns error cleanly
      (let [res-offer-bad (light-core/handle-command st {"cmd" "offer"
                                                         "callee" peer-pub
                                                         "price" "bad-price"}
                                                     agent-priv)
            res-offer-neg (light-core/handle-command st {"cmd" "offer"
                                                         "callee" peer-pub
                                                         "price" -50}
                                                     agent-priv)]
        (is (= false (get-in res-offer-bad [:response "ok"])))
        (is (= "invalid-numeric-parameter" (get-in res-offer-bad [:response "error"])))
        (is (= false (get-in res-offer-neg [:response "ok"])))
        (is (= "invalid-numeric-parameter" (get-in res-offer-neg [:response "error"])))))))

(deftest test-light-node-escrow-commands-and-dac-enforcement
  (testing "Light-node escrow commands: lock-intent, release-intent, refund-intent, escrows, and DAC enforcement"
    (let [agent-id (test-identity)
          agent-pub (:pubkey-hex agent-id)
          agent-priv (:privkey-bytes agent-id)
          peer-id (test-identity)
          peer-pub (:pubkey-hex peer-id)
          d-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          s0 (-> (light-core/init-light-state (:identity agent-id) {:epoch 10})
                 (assoc :petnames {"bob" peer-pub})
                 (assoc :account {:balance 5000 :spendable 5000 :seq 0}))]

      ;; 1. lock-intent by petname succeeds and creates local escrow
      (let [res1 (light-core/handle-command s0 {"cmd" "lock-intent"
                                                "receiver" "bob"
                                                "amount" "1000"
                                                "deliverable_hash" d-hash
                                                "expires_epoch" "20"}
                                            agent-priv)
            eid (get-in res1 [:response "escrow_id"])
            s1 (:state res1)]
        (is (= true (get-in res1 [:response "ok"])))
        (is (string? eid))
        (is (= "locked" (get-in res1 [:response "status"])))
        (is (= "bob" (get-in res1 [:response "receiver_petname"])))
        (is (= 4000 (get-in s1 [:account :spendable])))
        (is (= 1 (count (:net-envelopes res1))))
        (let [unwrapped (mesh/unwrap-authenticated-agent-event (first (:net-envelopes res1)))]
          (is (= :lock-intent (:type unwrapped)))
          (is (= agent-pub (:payer unwrapped)))
          (is (= peer-pub (:receiver unwrapped))))

        ;; 2. escrows lists the active escrow enriched with petname
        (let [res-list (light-core/handle-command s1 {"cmd" "escrows"} agent-priv)
              escrow-list (get-in res-list [:response "escrows"])]
          (is (= true (get-in res-list [:response "ok"])))
          (is (= 1 (count escrow-list)))
          (is (= "bob" (:receiver_petname (first escrow-list)))))

        ;; 3. release-intent auto-signs when local node is payer
        (let [res-rel (light-core/handle-command s1 {"cmd" "release-intent" "escrow_id" eid} agent-priv)]
          (is (= true (get-in res-rel [:response "ok"])))
          (is (= "release-submitted" (get-in res-rel [:response "status"])))
          (let [unwrapped (mesh/unwrap-authenticated-agent-event (first (:net-envelopes res-rel)))]
            (is (= :release-intent (:type unwrapped)))
            (is (string? (:payer-signature unwrapped)))
            (is (escrow/verify-escrow-release-sig agent-pub eid d-hash (:payer-signature unwrapped)))))

        ;; 4. release-intent with preimage
        (let [secret "my-deliverable-secret"
              secret-hash (basalt/bytes->hex (crypto/sha256 (.getBytes secret "UTF-8")))
              res-pre-lock (light-core/handle-command s0 {"cmd" "lock-intent"
                                                          "receiver" peer-pub
                                                          "amount" 500
                                                          "deliverable_hash" secret-hash
                                                          "expires_epoch" 25}
                                                      agent-priv)
              eid-pre (get-in res-pre-lock [:response "escrow_id"])
              res-pre-rel (light-core/handle-command (:state res-pre-lock)
                                                     {"cmd" "release-intent"
                                                      "escrow_id" eid-pre
                                                      "preimage" secret}
                                                     agent-priv)]
          (is (= true (get-in res-pre-rel [:response "ok"])))
          (let [unwrapped (mesh/unwrap-authenticated-agent-event (first (:net-envelopes res-pre-rel)))]
            (is (= secret (:preimage unwrapped)))))

        ;; 5. refund-intent emits refund envelope
        (let [res-ref (light-core/handle-command s1 {"cmd" "refund-intent" "escrow_id" eid} agent-priv)]
          (is (= true (get-in res-ref [:response "ok"])))
          (is (= "refund-submitted" (get-in res-ref [:response "status"])))
          (let [unwrapped (mesh/unwrap-authenticated-agent-event (first (:net-envelopes res-ref)))]
            (is (= :refund-intent (:type unwrapped)))
            (is (= eid (:escrow-id unwrapped))))))

      ;; 6. DAC spend authorization enforcement on lock-intent
      (let [anchor-id (test-identity)
            anchor-pub (:pubkey-hex anchor-id)
            anchor-priv (:privkey-bytes anchor-id)
            dac (light-core/create-dac anchor-priv {:anchor-pubkey anchor-pub
                                                    :agent-pubkey agent-pub
                                                    :issued-epoch 5
                                                    :expires-epoch 50
                                                    :max-spend-per-epoch 500
                                                    :scopes ["lock-intent"]})
            s-dac (assoc s0 :dac dac)
            ;; First lock with amount 400 succeeds (spent = 400 <= 500)
            res-dac-ok (light-core/handle-command s-dac {"cmd" "lock-intent"
                                                         "receiver" peer-pub
                                                         "amount" "400"
                                                         "deliverable_hash" d-hash
                                                         "expires_epoch" "20"}
                                                  agent-priv)
            ;; Second lock with amount 200 exceeds max-spend (400 + 200 = 600 > 500)
            res-dac-exceeded (light-core/handle-command (:state res-dac-ok)
                                                        {"cmd" "lock-intent"
                                                         "receiver" peer-pub
                                                         "amount" "200"
                                                         "deliverable_hash" d-hash
                                                         "expires_epoch" "20"}
                                                        agent-priv)]
        (is (= true (get-in res-dac-ok [:response "ok"])))
        (is (= false (get-in res-dac-exceeded [:response "ok"])))
        (is (= "dac-max-spend-exceeded" (get-in res-dac-exceeded [:response "error"]))))

      ;; 7. Validation: invalid amount, expires-epoch <= current-epoch, invalid deliverable-hash fail closed
      (let [res-bad-amt (light-core/handle-command s0 {"cmd" "lock-intent" "receiver" peer-pub "amount" "not-a-number" "deliverable_hash" d-hash "expires_epoch" 20} agent-priv)
            res-neg-amt (light-core/handle-command s0 {"cmd" "lock-intent" "receiver" peer-pub "amount" -10 "deliverable_hash" d-hash "expires_epoch" 20} agent-priv)
            res-bad-ep (light-core/handle-command s0 {"cmd" "lock-intent" "receiver" peer-pub "amount" 100 "deliverable_hash" d-hash "expires_epoch" 5} agent-priv)
            res-bad-dh (light-core/handle-command s0 {"cmd" "lock-intent" "receiver" peer-pub "amount" 100 "deliverable_hash" "bad-hash" "expires_epoch" 20} agent-priv)]
        (is (= "invalid-amount" (get-in res-bad-amt [:response "error"])))
        (is (= "invalid-amount" (get-in res-neg-amt [:response "error"])))
        (is (= "invalid-expires-epoch" (get-in res-bad-ep [:response "error"])))
        (is (= "invalid-deliverable-hash" (get-in res-bad-dh [:response "error"])))))))

(defspec ^{:doc "Property: sync-account updates on-chain finalized_epoch for economic/escrow commands without breaking peer-to-peer wire epoch skew tolerance"}
  prop-sync-account-preserves-wire-epoch-and-session-delivery 25
  (prop/for-all [fin-epoch (gen/choose 10 500)
                 msg-a->b (gen/not-empty gen/string-alphanumeric)
                 msg-b->a (gen/not-empty gen/string-alphanumeric)]
                (let [alice (test-identity)
                      bob (test-identity)
                      priv-a (:privkey-bytes alice)
                      pub-b (:pubkey-hex bob)
                      priv-b (:privkey-bytes bob)
                      d-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                      ;; Both Alice and Bob initialize at wire epoch 0 and open a sealed session
                      st-a0 (light-core/init-light-state (:identity alice) {})
                      st-b0 (light-core/init-light-state (:identity bob) {:autonomous? true})
                      offer-res (light-core/handle-command st-a0 {"cmd" "offer" "callee" pub-b "price" 10 "burn" 500} priv-a)
                      sid (get-in offer-res [:response "session_id"])
                      offer-env (first (filter gossip-env? (:net-envelopes offer-res)))
                      b-after-offer (light-core/handle-wire-payload st-b0 offer-env priv-b)
                      accept-env (first (filter gossip-env? (:net-envelopes b-after-offer)))
                      a-after-accept (light-core/handle-wire-payload (:state offer-res) accept-env priv-a)
                      ;; Now Alice runs sync-account with on-chain finalized_epoch = fin-epoch (>= 10), while Bob stays unsynced at epoch 0
                      sync-res (light-core/handle-command (:state a-after-accept)
                                                          {"cmd" "sync-account"
                                                           "balance" 100000
                                                           "spendable" 100000
                                                           "seq" 0
                                                           "deps" []
                                                           "finalized_epoch" fin-epoch}
                                                          priv-a)
                      st-a-synced (:state sync-res)
                      ;; 1. Alice sends a sealed message to Bob; Bob (still at wire epoch 0) must accept it
                      send-ab (light-core/handle-command st-a-synced {"cmd" "send" "session_id" sid "text" msg-a->b} priv-a)
                      ab-env (first (:net-envelopes send-ab))
                      b-after-rx (light-core/handle-wire-payload (:state b-after-offer) ab-env priv-b)
                      ack-env (first (:net-envelopes b-after-rx))
                      ;; 2. Alice must accept Bob's session-ack and purge her outbox
                      a-after-ack (light-core/handle-wire-payload (:state send-ab) ack-env priv-a)
                      ;; 3. Bob (at wire epoch 0) sends a sealed message to Alice; Alice must accept it
                      send-ba (light-core/handle-command (:state b-after-rx) {"cmd" "send" "session_id" sid "text" msg-b->a} priv-b)
                      ba-env (first (:net-envelopes send-ba))
                      a-after-rx (light-core/handle-wire-payload (:state a-after-ack) ba-env priv-a)
                      ;; 4. Alice's lock-intent must enforce expires_epoch > fin-epoch using synced finalized_epoch
                      bad-lock (light-core/handle-command (:state a-after-rx)
                                                          {"cmd" "lock-intent"
                                                           "receiver" pub-b
                                                           "amount" 1000
                                                           "deliverable_hash" d-hash
                                                           "expires_epoch" (dec fin-epoch)}
                                                          priv-a)
                      good-lock (light-core/handle-command (:state a-after-rx)
                                                           {"cmd" "lock-intent"
                                                            "receiver" pub-b
                                                            "amount" 1000
                                                            "deliverable_hash" d-hash
                                                            "expires_epoch" (+ fin-epoch 20)}
                                                           priv-a)]
                  (and (= 1 (count (:inbox (:state b-after-rx))))
                       (= msg-a->b (:text (first (:inbox (:state b-after-rx)))))
                       (empty? (get-in (:state a-after-ack) [:sessions sid :outbox]))
                       (= 1 (count (:inbox (:state a-after-rx))))
                       (= msg-b->a (:text (first (:inbox (:state a-after-rx)))))
                       (false? (get-in bad-lock [:response "ok"]))
                       (= "invalid-expires-epoch" (get-in bad-lock [:response "error"]))
                       (true? (get-in good-lock [:response "ok"]))))))

(deftest test-unacked-replay-envelope-reuse-and-session-epoch-authority
  (testing "build-unacked-replay-envelopes reuses original gossip envelope preserving message-id and delivers across epoch skew"
    (let [alice (test-identity)
          bob (test-identity)
          priv-a (:privkey-bytes alice)
          pub-b (:pubkey-hex bob)
          priv-b (:privkey-bytes bob)
          ;; Alice and Bob open a session at wire epoch 0
          st-a0 (light-core/init-light-state (:identity alice) {})
          st-b0 (light-core/init-light-state (:identity bob) {:autonomous? true})
          offer-res (light-core/handle-command st-a0 {"cmd" "offer" "callee" pub-b "price" 10 "burn" 500} priv-a)
          sid (get-in offer-res [:response "session_id"])
          offer-env (first (filter gossip-env? (:net-envelopes offer-res)))
          b-after-offer (light-core/handle-wire-payload st-b0 offer-env priv-b)
          accept-env (first (filter gossip-env? (:net-envelopes b-after-offer)))
          a-after-accept (light-core/handle-wire-payload (:state offer-res) accept-env priv-a)
          st-a-open (:state a-after-accept)
          st-b-open (:state b-after-offer)
          ;; Alice sends a message at epoch 0
          send-res (light-core/handle-command st-a-open {"cmd" "send" "session_id" sid "text" "hello from epoch 0"} priv-a)
          orig-env (first (:net-envelopes send-res))
          orig-msg-id (get-in orig-env [:event :message :message-id])
          orig-payload (get-in orig-env [:event :message :payload])
          st-a-sent (:state send-res)
          ;; Now Alice's local state epoch advances to 971 (e.g. from validator sync or time)
          st-a-advanced (assoc st-a-sent :epoch 971)
          replayed-envs (light-core/build-unacked-replay-envelopes st-a-advanced priv-a)
          replayed-env (first replayed-envs)]
      ;; (a) Exact message-id and payload bytes preserved (no epoch bump, no new message-id)
      (is (some? orig-msg-id))
      (is (= 1 (count replayed-envs)))
      (is (= orig-msg-id (get-in replayed-env [:event :message :message-id])))
      (is (= (seq orig-payload) (seq (get-in replayed-env [:event :message :payload]))))
      (is (= orig-env replayed-env))

      ;; (b) Bob is at local epoch 0 with session opened at epoch 0.
      ;; When Alice replays the unacked message from epoch 971 state, Bob must accept it!
      (let [b-rx-replayed (light-core/handle-wire-payload st-b-open replayed-env priv-b)]
        (is (= 1 (count (:inbox (:state b-rx-replayed)))))
        (is (= "hello from epoch 0" (:text (first (:inbox (:state b-rx-replayed)))))))

      ;; Also when Alice (now at epoch 971) sends a brand-new message on the epoch-0 session:
      (let [send-new (light-core/handle-command st-a-advanced {"cmd" "send" "session_id" sid "text" "message while alice is at 971"} priv-a)
            new-env (first (:net-envelopes send-new))
            ;; Bob at epoch 0 accepts it because session-epoch is authoritative (epoch 0)
            b-rx-new (light-core/handle-wire-payload st-b-open new-env priv-b)]
        (is (= 1 (count (:inbox (:state b-rx-new)))))
        (is (= "message while alice is at 971" (:text (first (:inbox (:state b-rx-new))))))))))

;; -----------------------------------------------------------------------------
;; Milestone 5 (Pillar B): Generative Quorum & Wire Skew Bypass Tests
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property: inband chain-state snapshot quorum, wire bypass, and fail-closed invariants across validator state disagreement, untrusted nodes, and tampered signatures"}
  prop-inband-chain-state-snapshot-quorum-and-fail-closed 50
  (prop/for-all [bal (gen/choose 1000 50000)
                 spd-offset (gen/choose 0 500)
                 seq-num (gen/choose 1 100)
                 fin-ep (gen/choose 10 500)
                 num-escrows (gen/choose 0 3)]
                (let [user-kp (crypto/generate-keypair)
                      user-pub (basalt/bytes->hex (:public user-kp))
                      user-priv (:private user-kp)
                      spd (max 0 (- bal spd-offset))
                      val-kps [(crypto/generate-keypair) (crypto/generate-keypair) (crypto/generate-keypair)]
                      val-pubs (mapv #(basalt/bytes->hex (:public %)) val-kps)
                      trusted (set val-pubs)
                      bootstrap {:nodes {"v1" {:pubkey (nth val-pubs 0) :ip "127.0.0.1" :port 5001 :fingerprint "FP1"}
                                         "v2" {:pubkey (nth val-pubs 1) :ip "127.0.0.1" :port 5002 :fingerprint "FP2"}
                                         "v3" {:pubkey (nth val-pubs 2) :ip "127.0.0.1" :port 5003 :fingerprint "FP3"}}}
                      init-st (assoc (light-core/init-light-state {:identity {:pubkey-hex user-pub}} {:bootstrap bootstrap})
                                     :epoch 1)
                      statuses [:locked :released :refunded]
                      escrows (vec (for [i (range num-escrows)]
                                     (let [st-val (nth statuses (mod i 3))]
                                       (cond-> {:escrow-id (str "esc-" i)
                                                :payer user-pub
                                                :receiver (sample-pubkey-hex)
                                                :amount (+ 100 (* i 50))
                                                :deliverable-hash (basalt/bytes->hex (crypto/sha256 (.getBytes (str "deliv-" i) "UTF-8")))
                                                :created-epoch (max 0 (- fin-ep 5))
                                                :expires-epoch (+ fin-ep 10)
                                                :status st-val}
                                         (= st-val :released) (assoc :settled-epoch fin-ep :net-amount (+ 95 (* i 50)))
                                         (= st-val :refunded) (assoc :settled-epoch fin-ep :refund-reason "timeout")))))
                      deps [(str "dep-" seq-num)]
                      base-snap {:pubkey user-pub
                                 :finalized-epoch fin-ep
                                 :balance bal
                                 :spendable spd
                                 :seq seq-num
                                 :deps deps
                                 :escrows escrows
                                 :nonce "test-nonce"}
                      signed-snaps (mapv (fn [i]
                                           (light-core/sign-chain-state-snapshot
                                            (assoc base-snap :validator-pubkey (nth val-pubs i))
                                            (:private (nth val-kps i))))
                                         (range 3))
                      opts {:expected-pubkey user-pub
                            :trusted-validators trusted
                            :min-finalized-epoch 5}
          ;; 1. Valid 3/3 quorum succeeds and updates state correctly
                      q-res (light-core/verify-chain-state-quorum signed-snaps opts)
                      applied (when (:ok? q-res) (light-core/apply-verified-chain-state-snapshot init-st (:snapshot q-res)))]
                  (and (:ok? q-res)
                       (= 3 (:quorum-count q-res))
                       (= bal (get-in applied [:account :balance]))
                       (= spd (get-in applied [:account :spendable]))
                       (= seq-num (get-in applied [:account :seq]))
                       (= (max 1 fin-ep) (:epoch applied))
                       (= (count escrows) (count (:escrows applied)))

           ;; 2. Valid 2/3 agreement succeeds
                       (let [q2-res (light-core/verify-chain-state-quorum [(nth signed-snaps 0) (nth signed-snaps 1)] opts)]
                         (and (:ok? q2-res) (= 2 (:quorum-count q2-res))))

             ;; 3. Tampered balance or signature fails closed ("invalid-snapshot-signature")
                       (let [tampered (assoc (nth signed-snaps 0) :balance (inc bal))
                             t-res (light-core/verify-chain-state-quorum [tampered (nth signed-snaps 1) (nth signed-snaps 2)] opts)]
                         (and (false? (:ok? t-res))
                              (= "invalid-snapshot-signature" (:error t-res))))

             ;; 4. Untrusted validator fails closed ("untrusted-validator")
                       (let [rogue-kp (crypto/generate-keypair)
                             rogue-pub (basalt/bytes->hex (:public rogue-kp))
                             rogue-snap (light-core/sign-chain-state-snapshot
                                         (assoc base-snap :validator-pubkey rogue-pub)
                                         (:private rogue-kp))
                             u-res (light-core/verify-chain-state-quorum [rogue-snap (nth signed-snaps 1) (nth signed-snaps 2)] opts)]
                         (and (false? (:ok? u-res))
                              (= "untrusted-validator" (:error u-res))))

             ;; 5. Stale finalized epoch fails closed ("stale-finalized-epoch")
                       (let [stale-opts (assoc opts :min-finalized-epoch (+ fin-ep 100))
                             stale-res (light-core/verify-chain-state-quorum signed-snaps stale-opts)]
                         (and (false? (:ok? stale-res))
                              (= "stale-finalized-epoch" (:error stale-res))))

             ;; 6. Disagreement among validators (different balances at same epoch) fails closed ("validator-state-disagreement")
                       (let [disagree-snap (light-core/sign-chain-state-snapshot
                                            (assoc base-snap :validator-pubkey (nth val-pubs 2) :balance (+ bal 1000))
                                            (:private (nth val-kps 2)))
                             d-res (light-core/verify-chain-state-quorum [(nth signed-snaps 0) (nth signed-snaps 1) disagree-snap] opts)]
                         (and (false? (:ok? d-res))
                              (= "validator-state-disagreement" (:error d-res))))

             ;; 7. Excessive epoch skew (> 2) fails closed ("validator-epoch-skew-exceeded")
                       (let [skewed-snap (light-core/sign-chain-state-snapshot
                                          (assoc base-snap :validator-pubkey (nth val-pubs 2) :finalized-epoch (+ fin-ep 5))
                                          (:private (nth val-kps 2)))
                             sk-res (light-core/verify-chain-state-quorum [(nth signed-snaps 0) (nth signed-snaps 1) skewed-snap] opts)]
                         (and (false? (:ok? sk-res))
                              (= "validator-epoch-skew-exceeded" (:error sk-res))))

             ;; 8. Inbound :chain-state-snapshot via handle-wire-payload buffers and applies on 2/3 BFT quorum
                       (let [advance-snap-0 (light-core/sign-chain-state-snapshot
                                             (assoc base-snap :validator-pubkey (nth val-pubs 0) :finalized-epoch 6600)
                                             (:private (nth val-kps 0)))
                             advance-snap-1 (light-core/sign-chain-state-snapshot
                                             (assoc base-snap :validator-pubkey (nth val-pubs 1) :finalized-epoch 6600)
                                             (:private (nth val-kps 1)))
                             wire-res1 (light-core/handle-wire-payload init-st advance-snap-0 user-priv)
                             st1 (:state wire-res1)
                             wire-res2 (light-core/handle-wire-payload st1 advance-snap-1 user-priv)
                             st2 (:state wire-res2)
                             stdout (first (:stdout-events wire-res2))]
                         (and (= 1 (count (:chain-state-snapshots st1)))
                              (= 1 (:epoch st1))
                              (nil? (get-in st1 [:account :finalized-epoch]))
                              (empty? (:stdout-events wire-res1))
                              (= 6600 (get-in st2 [:account :finalized-epoch]))
                              (= 6600 (:epoch st2))
                              (some? stdout)
                              (= "chain-state-synced" (get stdout "event"))
                              (= 6600 (get stdout "finalized_epoch"))))))))

(deftest test-chain-state-snapshot-wire-bft-quorum-and-invariants
  (let [user-kp (crypto/generate-keypair)
        user-pub (basalt/bytes->hex (:public user-kp))
        user-priv (:private user-kp)
        val-kps [(crypto/generate-keypair) (crypto/generate-keypair) (crypto/generate-keypair)]
        val-pubs (mapv #(basalt/bytes->hex (:public %)) val-kps)
        bootstrap {:nodes {"v1" {:pubkey (nth val-pubs 0) :ip "127.0.0.1" :port 5001}
                           "v2" {:pubkey (nth val-pubs 1) :ip "127.0.0.1" :port 5002}
                           "v3" {:pubkey (nth val-pubs 2) :ip "127.0.0.1" :port 5003}}}
        init-st (assoc (light-core/init-light-state {:identity {:pubkey-hex user-pub}} {:bootstrap bootstrap})
                       :epoch 1)
        base-snap {:pubkey user-pub
                   :finalized-epoch 100
                   :balance 50000
                   :spendable 45000
                   :seq 42
                   :deps []
                   :escrows [{:escrow-id "esc-1"
                              :payer user-pub
                              :receiver (nth val-pubs 0)
                              :amount 5000
                              :deliverable-hash "abc123"
                              :created-epoch 90
                              :expires-epoch 110
                              :status :locked}]
                   :nonce "test-nonce"}]

    ;; MEDIUM 1: verify-chain-state-snapshot fails closed when trusted-validators is nil or empty
    (let [signed-snap (light-core/sign-chain-state-snapshot
                       (assoc base-snap :validator-pubkey (nth val-pubs 0))
                       (:private (nth val-kps 0)))
          opts-nil {:expected-pubkey user-pub :trusted-validators nil :min-finalized-epoch 0}
          opts-empty {:expected-pubkey user-pub :trusted-validators #{} :min-finalized-epoch 0}]
      (is (= {:ok? false :error "untrusted-validator"} (light-core/verify-chain-state-snapshot signed-snap opts-nil)))
      (is (= {:ok? false :error "untrusted-validator"} (light-core/verify-chain-state-snapshot signed-snap opts-empty))))

    ;; HIGH 1: handle-wire-payload buffers snapshot until 2/3 BFT quorum reached
    (let [snap-0 (light-core/sign-chain-state-snapshot
                  (assoc base-snap :validator-pubkey (nth val-pubs 0))
                  (:private (nth val-kps 0)))
          snap-1 (light-core/sign-chain-state-snapshot
                  (assoc base-snap :validator-pubkey (nth val-pubs 1))
                  (:private (nth val-kps 1)))
          res-1 (light-core/handle-wire-payload init-st snap-0 user-priv)
          st-1 (:state res-1)]
      ;; First snapshot buffered, no state mutation
      (is (= 1 (count (:chain-state-snapshots st-1))))
      (is (= 1 (:epoch st-1)))
      (is (nil? (get-in st-1 [:account :finalized-epoch])))
      (is (empty? (:stdout-events res-1)))

      ;; Second matching snapshot from different validator completes 2/3 quorum
      (let [res-2 (light-core/handle-wire-payload st-1 snap-1 user-priv)
            st-2 (:state res-2)
            sync-event (first (:stdout-events res-2))]
        (is (= 100 (get-in st-2 [:account :finalized-epoch])))
        (is (= 100 (:epoch st-2)))
        (is (= 50000 (get-in st-2 [:account :balance])))
        (is (= 45000 (get-in st-2 [:account :spendable])))
        (is (= 42 (get-in st-2 [:account :seq])))
        (is (= "chain-state-synced" (get sync-event "event")))
        (is (= 100 (get sync-event "finalized_epoch")))
        (is (= 2 (get sync-event "quorum_count")))))

    ;; LOW 1: Monotonicity guard in apply-verified-chain-state-snapshot
    (let [current-st (assoc-in init-st [:account :finalized-epoch] 200)
          stale-snap {:pubkey user-pub :finalized-epoch 150 :balance 99999}
          applied (light-core/apply-verified-chain-state-snapshot current-st stale-snap)]
      (is (= current-st applied) "Must return unchanged state when incoming finalized-epoch < current finalized-epoch"))

    ;; LOW 2: Stale status-dependent fields cleared when merging escrows
    (let [existing-escrow {:escrow-id "esc-1"
                           :payer user-pub
                           :receiver (nth val-pubs 0)
                           :amount 5000
                           :deliverable-hash "abc123"
                           :created-epoch 90
                           :expires-epoch 110
                           :status :released
                           :settled-epoch 95
                           :net-amount 4975
                           :take-burned 25}
          state-with-escrow (-> init-st
                                (assoc-in [:account :finalized-epoch] 95)
                                (assoc :escrows {"esc-1" existing-escrow}))
          ;; Incoming snapshot updates escrow back to locked or to refunded
          locked-snap {:pubkey user-pub
                       :finalized-epoch 100
                       :balance 50000
                       :spendable 45000
                       :seq 42
                       :escrows [{:escrow-id "esc-1"
                                  :payer user-pub
                                  :receiver (nth val-pubs 0)
                                  :amount 5000
                                  :deliverable-hash "abc123"
                                  :created-epoch 90
                                  :expires-epoch 110
                                  :status :locked}]}
          applied-locked (light-core/apply-verified-chain-state-snapshot state-with-escrow locked-snap)
          merged-locked (get-in applied-locked [:escrows "esc-1"])]
      (is (= :locked (:status merged-locked)))
      (is (nil? (:settled-epoch merged-locked)))
      (is (nil? (:net-amount merged-locked)))
      (is (nil? (:take-burned merged-locked)))
      (is (nil? (:refund-reason merged-locked)))

      ;; Now verify refunded escrow clears net-amount and take-burned
      (let [refunded-snap (assoc locked-snap :escrows [{:escrow-id "esc-1"
                                                        :payer user-pub
                                                        :receiver (nth val-pubs 0)
                                                        :amount 5000
                                                        :deliverable-hash "abc123"
                                                        :created-epoch 90
                                                        :expires-epoch 110
                                                        :status :refunded
                                                        :settled-epoch 100
                                                        :refund-reason "timeout"}])
            applied-refunded (light-core/apply-verified-chain-state-snapshot state-with-escrow refunded-snap)
            merged-refunded (get-in applied-refunded [:escrows "esc-1"])]
        (is (= :refunded (:status merged-refunded)))
        (is (= 100 (:settled-epoch merged-refunded)))
        (is (= "timeout" (:refund-reason merged-refunded)))
        (is (nil? (:net-amount merged-refunded)))
        (is (nil? (:take-burned merged-refunded)))))

    ;; Axiom seq: 112: Pruning of expired non-terminal escrows absent from snapshot with escrows
    (let [esc-old-locked {:escrow-id "esc-old"
                          :status :locked
                          :created-epoch 80}
          esc-recent-locked {:escrow-id "esc-recent"
                             :status :locked
                             :created-epoch 96}
          esc-old-released {:escrow-id "esc-released"
                            :status :released
                            :created-epoch 80}
          st-with-escrows (-> init-st
                              (assoc-in [:account :finalized-epoch] 90)
                              (assoc :escrows {"esc-old" esc-old-locked
                                               "esc-recent" esc-recent-locked
                                               "esc-released" esc-old-released}))
          snap-at-100 {:pubkey user-pub
                       :finalized-epoch 100
                       :balance 50000
                       :spendable 45000
                       :seq 42
                       :escrows [{:escrow-id "esc-new"
                                  :status :locked
                                  :created-epoch 98}]}
          applied (light-core/apply-verified-chain-state-snapshot st-with-escrows snap-at-100)]
      ;; "esc-old" is (< 80 (- 100 5)), non-terminal, and absent -> pruned!
      (is (nil? (get-in applied [:escrows "esc-old"])))
      ;; "esc-recent" is (>= 96 (- 100 5)) -> preserved!
      (is (some? (get-in applied [:escrows "esc-recent"])))
      ;; "esc-released" is terminal -> preserved!
      (is (some? (get-in applied [:escrows "esc-released"])))
      ;; "esc-new" from snapshot -> added!
      (is (some? (get-in applied [:escrows "esc-new"]))))))

(deftest test-fresh-node-raw-epoch-side-channel-guard
  (testing "Axiom seq: 102 LOW 1: forged or pre-quorum :chain-state-snapshot never pins epoch on a fresh node"
    (let [user-kp (crypto/generate-keypair)
          user-pub (basalt/bytes->hex (:public user-kp))
          user-priv (:private user-kp)
          val-kps [(crypto/generate-keypair) (crypto/generate-keypair) (crypto/generate-keypair)]
          val-pubs (mapv #(basalt/bytes->hex (:public %)) val-kps)
          bootstrap {:nodes {"v1" {:pubkey (nth val-pubs 0) :ip "127.0.0.1" :port 5001}
                             "v2" {:pubkey (nth val-pubs 1) :ip "127.0.0.1" :port 5002}
                             "v3" {:pubkey (nth val-pubs 2) :ip "127.0.0.1" :port 5003}}}
          fresh-st (light-core/init-light-state {:identity {:pubkey-hex user-pub}} {:bootstrap bootstrap})
          base-snap {:pubkey user-pub
                     :finalized-epoch 6600
                     :balance 50000
                     :spendable 45000
                     :seq 42
                     :deps []
                     :escrows []
                     :nonce "test-nonce"}]
      ;; Fresh node starts uninitialized
      (is (= 0 (:epoch fresh-st)))
      (is (false? (:epoch-initialized? fresh-st)))

      ;; 1. Forged snapshot with epoch 99999
      (let [forged-snap (assoc base-snap
                               :type :chain-state-snapshot
                               :validator-pubkey (nth val-pubs 0)
                               :epoch 99999
                               :finalized-epoch 99999
                               :signature "deadbeef")
            res-forged (light-core/handle-wire-payload fresh-st forged-snap user-priv)
            st-forged (:state res-forged)]
        (is (= 0 (:epoch st-forged)))
        (is (false? (:epoch-initialized? st-forged))))

      ;; 2. Single 1-of-3 pre-quorum signed snapshot with epoch 6600
      (let [snap-0 (light-core/sign-chain-state-snapshot
                    (assoc base-snap :validator-pubkey (nth val-pubs 0))
                    (:private (nth val-kps 0)))
            res-1 (light-core/handle-wire-payload fresh-st snap-0 user-priv)
            st-1 (:state res-1)]
        (is (= 0 (:epoch st-1)))
        (is (false? (:epoch-initialized? st-1)))
        (is (= 1 (count (:chain-state-snapshots st-1))))

        ;; 3. Second matching snapshot reaches 2/3 BFT quorum -> now epoch advances
        (let [snap-1 (light-core/sign-chain-state-snapshot
                      (assoc base-snap :validator-pubkey (nth val-pubs 1))
                      (:private (nth val-kps 1)))
              res-2 (light-core/handle-wire-payload st-1 snap-1 user-priv)
              st-2 (:state res-2)]
          (is (= 6600 (:epoch st-2)))
          (is (true? (:epoch-initialized? st-2)))
          (is (= 6600 (get-in st-2 [:account :finalized-epoch]))))))))

;; -----------------------------------------------------------------------------
;; 27. Wire Protocol Versioning & Rolling-Upgrade Compatibility (Milestone 7 / FLAG B)
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property: Rolling-upgrade wire protocol compatibility across N-1 (unversioned), N (v1), and N+1 (v2) payloads with fail-closed rejection and counted diagnostics for unsupported versions"}
  prop-wire-version-rolling-upgrade-compatibility 50
  (prop/for-all [v-unsupported (gen/elements [-5 0 3 4 99 999])
                 supported-v (gen/elements [nil 1 2])
                 use-string-key? gen/boolean]
                (let [id (test-identity)
                      user-pub (:pubkey-hex id)
                      user-priv (:privkey-bytes id)
                      bootstrap {:network :devnet :nodes {}}
                      base-st (light-core/init-light-state id {:bootstrap bootstrap})
          ;; 1. Check check-wire-version-compatibility helper
                      unsupported-msg (if use-string-key?
                                        {"cmd" "offer" "protocol_version" v-unsupported}
                                        {:bitecho/type :channel-offer :protocol-version v-unsupported})
                      unsupported-chk (light-core/check-wire-version-compatibility unsupported-msg)
                      supported-msg (cond
                                      (nil? supported-v) {:bitecho/type :channel-offer}
                                      use-string-key? {"protocol_version" supported-v}
                                      :else {:protocol-version supported-v})
                      supported-chk (light-core/check-wire-version-compatibility supported-msg)

          ;; 2. handle-wire-payload fail-closed on unsupported version
                      bogus-wire (if use-string-key?
                                   {"protocol_version" v-unsupported "type" "channel-offer"}
                                   {:protocol-version v-unsupported :bitecho/type :channel-offer})
                      rej-res (light-core/handle-wire-payload base-st bogus-wire user-priv)
                      st-rej (:state rej-res)

          ;; 3. mesh envelope helpers
                      valid-env? (mesh/valid-agent-envelope-version? supported-msg)
                      invalid-env? (mesh/valid-agent-envelope-version? unsupported-msg)
                      sample-event {:type :refund-intent :escrow-id "escrow-1" :epoch 1 :seq 1}
                      wrapped (mesh/wrap-agent-event sample-event user-pub user-priv)
                      unwrapped (mesh/unwrap-authenticated-agent-event wrapped)]
                  (and
       ;; Helper invariants
                   (false? (:ok? unsupported-chk))
                   (= "unsupported-wire-version" (:error unsupported-chk))
                   (= v-unsupported (:version unsupported-chk))
                   (true? (:ok? supported-chk))
                   (if (nil? supported-v)
                     (true? (:legacy-unversioned? supported-chk))
                     (false? (:legacy-unversioned? supported-chk)))

       ;; handle-wire-payload invariants (Rule 5: Zero Silent Failures, counted diagnostics)
                   (= false (get-in rej-res [:response "ok"]))
                   (= "unsupported-wire-version" (get-in rej-res [:response "error"]))
                   (= 1 (get-in st-rej [:wire-version-diagnostics :unsupported-dropped]))
                   (= v-unsupported (get-in st-rej [:wire-version-diagnostics :last-unsupported-version]))
                   (= "unsupported-wire-version" (get-in st-rej [:wire-version-diagnostics :last-error]))
                   (= 1 (count (:stdout-events rej-res)))
                   (= "wire-version-rejected" (get (first (:stdout-events rej-res)) "event"))

       ;; mesh envelope invariants
                   (true? valid-env?)
                   (false? invalid-env?)
                   (= 1 (:protocol-version wrapped))
                   (some? unwrapped)
                   (= 1 (:protocol-version unwrapped))))))

(deftest test-sync-account-updates-top-level-epoch
  (testing "sync-account with finalized_epoch updates top-level :epoch and :epoch-initialized?"
    (let [node (test-identity)
          st0 (light-core/init-light-state (:identity node) {})
          res (light-core/handle-command st0
                                         {"cmd" "sync-account"
                                          "balance" 95000
                                          "spendable" 95000
                                          "seq" 1
                                          "deps" []
                                          "finalized_epoch" 1850}
                                         (:privkey-bytes node))
          st1 (:state res)]
      (is (true? (get-in res [:response "ok"])))
      (is (= 1850 (get-in st1 [:account :finalized-epoch])))
      (is (= 1850 (:epoch st1)))
      (is (true? (:epoch-initialized? st1))))))

(deftest test-epoch-skew-diagnostic-event-f-bb-8
  (testing "Incoming offer with epoch skew > 15 emits diagnostic event and counts in diagnostics"
    (let [alice (test-identity)
          bob (test-identity)
          st-bob (light-core/init-light-state (:identity bob) {:epoch 100})
          ;; Alice creates offer at epoch 50 (|50 - 100| = 50 > 15)
          offer-res (light-core/handle-command (light-core/init-light-state (:identity alice) {:epoch 50})
                                               {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 10 "burn" 500}
                                               (:privkey-bytes alice))
          offer-env (first (:net-envelopes offer-res))
          bob-recv (light-core/handle-wire-payload st-bob offer-env (:privkey-bytes bob))]
      (is (= 1 (get-in (:state bob-recv) [:diagnostics :epoch-skew-dropped])))
      (let [diag (first (filter #(= "diagnostic" (get % "event")) (:stdout-events bob-recv)))]
        (is (some? diag))
        (is (= "epoch-skew-dropped" (get diag "reason")))
        (is (= 50 (get diag "offer_epoch")))
        (is (= 100 (get diag "local_epoch")))
        (is (= (:pubkey-hex alice) (get diag "from")))))))

(deftest test-multi-session-resolution-and-export-send
  (testing "Multi-session resolution picks most recently active open session"
    (let [alice (test-identity)
          bob (test-identity)
          st-alice (light-core/init-light-state (:identity alice) {:epoch 10})
          st-bob (light-core/init-light-state (:identity bob) {:epoch 10})

          ;; Create first session sid-1
          off-1 (light-core/handle-command st-alice {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 0 "burn" 500} (:privkey-bytes alice))
          env-1 (first (filter gossip-env? (:net-envelopes off-1)))
          sid-1 (get-in off-1 [:response "session_id"])
          bob-1 (light-core/handle-wire-payload st-bob env-1 (:privkey-bytes bob))
          acc-1 (light-core/handle-command (:state bob-1) {"cmd" "accept" "session_id" sid-1} (:privkey-bytes bob))
          env-acc-1 (first (filter gossip-env? (:net-envelopes acc-1)))
          alice-open-1 (light-core/handle-wire-payload (:state off-1) env-acc-1 (:privkey-bytes alice))

          ;; Create second session sid-2
          st-alice-2 (assoc-in (:state alice-open-1) [:sessions sid-1 :created-epoch] 10)
          off-2 (light-core/handle-command st-alice-2 {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 0 "burn" 500} (:privkey-bytes alice))
          env-2 (first (filter gossip-env? (:net-envelopes off-2)))
          sid-2 (get-in off-2 [:response "session_id"])
          bob-2 (light-core/handle-wire-payload (:state acc-1) env-2 (:privkey-bytes bob))
          acc-2 (light-core/handle-command (:state bob-2) {"cmd" "accept" "session_id" sid-2} (:privkey-bytes bob))
          env-acc-2 (first (filter gossip-env? (:net-envelopes acc-2)))
          alice-open-2 (light-core/handle-wire-payload (:state off-2) env-acc-2 (:privkey-bytes alice))
          st-both (-> (:state alice-open-2)
                      (assoc-in [:sessions sid-1 :created-epoch] 10)
                      (assoc-in [:sessions sid-1 :last-active-epoch] 10)
                      (assoc-in [:sessions sid-2 :created-epoch] 20)
                      (assoc-in [:sessions sid-2 :last-active-epoch] 20))]

      (is (not= sid-1 sid-2))
      (is (= "open" (get-in st-both [:sessions sid-1 :state])))
      (is (= "open" (get-in st-both [:sessions sid-2 :state])))

      ;; Send targeting bob's pubkey without session-id picks sid-2 (more recent epoch)
      (let [send-res (light-core/handle-command st-both
                                                {"cmd" "send" "to" (:pubkey-hex bob) "message" "hello sid-2"}
                                                (:privkey-bytes alice))]
        (is (true? (get-in send-res [:response "ok"])))
        (is (= sid-2 (get-in send-res [:response "session_id"]))))

      ;; Send targeting sid-1 directly picks sid-1
      (let [send-res (light-core/handle-command st-both
                                                {"cmd" "send" "session_id" sid-1 "message" "hello sid-1"}
                                                (:privkey-bytes alice))]
        (is (true? (get-in send-res [:response "ok"])))
        (is (= sid-1 (get-in send-res [:response "session_id"])))))))

(deftest test-actionable-event-queue-and-wait
  (testing "Actionable events are enqueued with monotonic :event-id and popped via cmd: wait"
    (let [alice (test-identity)
          bob (test-identity)
          st-bob (light-core/init-light-state (:identity bob) {:epoch 10})
          off-res (light-core/handle-command (light-core/init-light-state (:identity alice) {:epoch 10})
                                             {"cmd" "offer" "callee" (:pubkey-hex bob) "price" 0 "burn" 500}
                                             (:privkey-bytes alice))
          bob-recv (light-core/handle-wire-payload st-bob (first (filter gossip-env? (:net-envelopes off-res))) (:privkey-bytes bob))
          st1 (:state bob-recv)]
      ;; "offer-received" is actionable -> should be in :event-queue
      (is (pos? (count (:event-queue st1))))
      (let [ev (first (:event-queue st1))]
        (is (= "offer-received" (get ev "event")))
        (is (= 1 (or (get ev "event_id") (:event-id ev)))))

      ;; cmd: status surfaces unread_events
      (let [stat-res (light-core/handle-command st1 {"cmd" "status"} (:privkey-bytes bob))]
        (is (= (count (:event-queue st1)) (get-in stat-res [:response "unread_events"]))))

      ;; cmd: wait pops all queued events
      (let [wait-res (light-core/handle-command st1 {"cmd" "wait"} (:privkey-bytes bob))]
        (is (true? (get-in wait-res [:response "ok"])))
        (is (= 1 (count (get-in wait-res [:response "events"]))))
        (is (empty? (:event-queue (:state wait-res))))
        ;; Second wait on empty queue returns park: true
        (let [wait-empty (light-core/handle-command (:state wait-res) {"cmd" "wait"} (:privkey-bytes bob))]
          (is (true? (get-in wait-empty [:response "ok"])))
          (is (true? (get-in wait-empty [:response "park"])))
          (is (empty? (get-in wait-empty [:response "events"]))))))))

(deftest test-p2p-signal-deduplication-and-preservation
  (testing "Duplicate p2p-offer is deduplicated without dropping connected state"
    (let [alice (test-identity)
          bob (test-identity)
          sid "test-p2p-sess-42"
          init-sess {:session-id sid
                     :state "open"
                     :peer (:pubkey-hex bob)
                     :p2p {:phase :open
                           :connected? true
                           :remote-offer-seq 5
                           :transport "udp"}
                     :p2p-meta {:local-signal-seq 2
                                :remote-offer-seq 5
                                :preferred-transport "udp"}}
          st-alice (-> (light-core/init-light-state (:identity alice) {:epoch 10})
                       (assoc-in [:sessions sid] init-sess))
          canonical-str (light-core/canonical-p2p-signal-str :offer sid (:pubkey-hex bob) (:pubkey-hex alice) "udp" ["c1"] "u" "p" "fp" 10 5)
          sig (basalt/bytes->hex (crypto/sign (:privkey-bytes bob) (.getBytes canonical-str "UTF-8")))
          dup-msg {:bitecho/type :p2p-offer
                   :session-id sid
                   :sender (:pubkey-hex bob)
                   :recipient (:pubkey-hex alice)
                   :transport "udp"
                   :candidates ["c1"]
                   :ice-ufrag "u"
                   :ice-pwd "p"
                   :fingerprint "fp"
                   :epoch 10
                   :signal-seq 5
                   :signature sig}
          res (light-core/handle-wire-payload st-alice dup-msg (:privkey-bytes alice))]
      (is (= 1 (get-in (:state res) [:diagnostics :p2p-signal-deduped])))
      (is (true? (get-in (:state res) [:sessions sid :p2p :connected?])) "Leg remains connected!")
      (is (empty? (:stdout-events res)) "No error event emitted on duplicate signal"))))

(deftest test-f2-session-prefix-and-raw-pubkey-resolution
  (testing "F-2: Unique session prefix matches open session"
    (let [alice (test-identity)
          bob (test-identity)
          sid1 "1234567890abcdef1234567890abcdef"
          sid2 "abcdef1234567890abcdef1234567890"
          sess1 {:session-id sid1 :state "open" :peer (:pubkey-hex bob) :contiguous-rx-seq 0 :outbound-seq 0}
          sess2 {:session-id sid2 :state "open" :peer (:pubkey-hex bob) :contiguous-rx-seq 0 :outbound-seq 0}
          st (-> (light-core/init-light-state (:identity alice) {:epoch 1})
                 (assoc-in [:sessions sid1] sess1)
                 (assoc-in [:sessions sid2] sess2))]
      (is (= sid1 (light-core/resolve-session-id st {"session_id" "123456"} :open)))
      (is (= sid2 (light-core/resolve-session-id st {"session_id" "abcdef"} :open)))))

  (testing "F-2: Ambiguous session prefix fails closed across all commands"
    (let [alice (test-identity)
          bob (test-identity)
          sid1 "deadbeef111111111111111111111111"
          sid2 "deadbeef222222222222222222222222"
          sess1 {:session-id sid1 :state "open" :peer (:pubkey-hex bob) :contiguous-rx-seq 0 :outbound-seq 0
                 :tx-key (byte-array 32) :rx-key (byte-array 32) :suite sealed/suite-v1-chacha20poly1305}
          sess2 {:session-id sid2 :state "open" :peer (:pubkey-hex bob) :contiguous-rx-seq 0 :outbound-seq 0
                 :tx-key (byte-array 32) :rx-key (byte-array 32) :suite sealed/suite-v1-chacha20poly1305}
          st (-> (light-core/init-light-state (:identity alice) {:epoch 1})
                 (assoc-in [:sessions sid1] sess1)
                 (assoc-in [:sessions sid2] sess2))
          prefix "deadbeef"
          cmds [{"cmd" "send" "to" prefix "text" "hello"}
                {"cmd" "ack" "session_id" prefix}
                {"cmd" "p2p-offer" "session_id" prefix}
                {"cmd" "export-send" "to" prefix "text" "hello"}
                {"cmd" "export-ack" "to" prefix}
                {"cmd" "export-offer" "to" prefix}]]
      ;; Direct resolve-session-id
      (let [res (light-core/resolve-session-id st {"session_id" prefix} :open)]
        (is (map? res))
        (is (false? (:ok? res)))
        (is (= "ambiguous-session-prefix" (:error res)))
        (is (= [sid1 sid2] (sort (:matches res)))))
      ;; Across all 6 commands
      (doseq [cmd-map cmds]
        (let [res (light-core/handle-command st cmd-map (:privkey-bytes alice))]
          (is (false? (get-in res [:response "ok"])) (str "Command failed closed: " (get cmd-map "cmd")))
          (is (= "ambiguous-session-prefix" (get-in res [:response "error"])) (str "Error matches for " (get cmd-map "cmd")))
          (is (= [sid1 sid2] (sort (get-in res [:response "matches"]))) (str "Matches surfaced for " (get cmd-map "cmd")))))))

  (testing "F-2: 64-hex raw pubkey resolution across commands"
    (let [alice (test-identity)
          bob (test-identity)
          bob-spki (:pubkey-hex bob)
          bob-raw (subs bob-spki 24)
          sid "cafe0102030405060708090a0b0c0d0e"
          sess {:session-id sid :state "open" :peer bob-spki :contiguous-rx-seq 0 :outbound-seq 0
                :tx-key (byte-array 32) :rx-key (byte-array 32) :suite sealed/suite-v1-chacha20poly1305}
          st (-> (light-core/init-light-state (:identity alice) {:epoch 1})
                 (assoc-in [:sessions sid] sess))]
      ;; Send via 64-hex raw pubkey
      (let [res (light-core/handle-command st {"cmd" "send" "to" bob-raw "text" "hi"} (:privkey-bytes alice))]
        (is (true? (get-in res [:response "ok"])))
        (is (= sid (get-in res [:response "session_id"]))))
      ;; Ack via 64-hex raw pubkey
      (let [res (light-core/handle-command st {"cmd" "ack" "to" bob-raw} (:privkey-bytes alice))]
        (is (true? (get-in res [:response "ok"])))
        (is (= sid (get-in res [:response "session_id"]))))
      ;; Export-send via 64-hex raw pubkey
      (let [res (light-core/handle-command st {"cmd" "export-send" "to" bob-raw "text" "hi"} (:privkey-bytes alice))]
        (is (true? (get-in res [:response "ok"])))
        (is (string? (get-in res [:response "envelope_hex"]))))
      ;; Export-ack via 64-hex raw pubkey
      (let [res (light-core/handle-command st {"cmd" "export-ack" "to" bob-raw} (:privkey-bytes alice))]
        (is (true? (get-in res [:response "ok"])))
        (is (string? (get-in res [:response "envelope_hex"]))))
      ;; P2P-offer via 64-hex raw pubkey
      (let [res (light-core/handle-command st {"cmd" "p2p-offer" "to" bob-raw "candidates" ["c1"]} (:privkey-bytes alice))]
        (is (true? (get-in res [:response "ok"])))
        (is (= sid (get-in res [:response "session_id"]))))
      ;; Export-offer via 64-hex raw pubkey
      (let [res (light-core/handle-command st {"cmd" "export-offer" "to" bob-raw} (:privkey-bytes alice))]
        (is (true? (get-in res [:response "ok"])))
        (is (string? (get-in res [:response "envelope_hex"])))))))

(defspec ^{:doc "Property: Generative test for unique session ID prefix resolution"}
  test-generative-session-prefix-invariants
  50
  (prop/for-all [hex-tail (gen/fmap (partial apply str) (gen/vector (gen/elements [\0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \a \b \c \d \e \f]) 26 26))
                 hex-head (gen/fmap (partial apply str) (gen/vector (gen/elements [\0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \a \b \c \d \e \f]) 6 6))]
                (let [sid (str hex-head hex-tail)
                      sess {:session-id sid :state "open" :peer (sample-pubkey-hex)}
                      alice (test-identity)
                      st (-> (light-core/init-light-state (:identity alice) {:epoch 1})
                             (assoc-in [:sessions sid] sess))]
                  (= sid (light-core/resolve-session-id st {"session_id" hex-head} :open)))))

(deftest test-f3-handle-wire-p2p-offer-answers-while-open
  (testing "F-3: handle-wire-p2p-offer preserves connected? true and emits p2p-answer when already open"
    (let [alice (test-identity)
          bob (test-identity)
          sid "f3-session-001"
          init-sess {:session-id sid
                     :state "open"
                     :peer (:pubkey-hex bob)
                     :p2p {:phase :open
                           :connected? true
                           :remote-offer-seq 5
                           :transport "udp"
                           :local-transport "udp"
                           :local-candidates ["a-cand-1"]}
                     :p2p-meta {:local-signal-seq 2
                                :remote-offer-seq 5
                                :preferred-transport "udp"
                                :preferred-candidates ["a-cand-1"]}}
          st-alice (-> (light-core/init-light-state (:identity alice) {:epoch 10})
                       (assoc-in [:sessions sid] init-sess))
          canonical-str (light-core/canonical-p2p-signal-str :offer sid (:pubkey-hex bob) (:pubkey-hex alice) "udp" ["b-cand-1"] "u" "p" "fp" 10 9)
          sig (basalt/bytes->hex (crypto/sign (:privkey-bytes bob) (.getBytes canonical-str "UTF-8")))
          offer-msg {:bitecho/type :p2p-offer
                     :session-id sid
                     :sender (:pubkey-hex bob)
                     :recipient (:pubkey-hex alice)
                     :transport "udp"
                     :candidates ["b-cand-1"]
                     :ice-ufrag "u"
                     :ice-pwd "p"
                     :fingerprint "fp"
                     :epoch 10
                     :signal-seq 9
                     :signature sig}
          res (light-core/handle-wire-p2p-offer st-alice offer-msg (:privkey-bytes alice))]
      ;; Connected state preserved
      (is (= :open (get-in (:state res) [:sessions sid :p2p :phase])))
      (is (true? (get-in (:state res) [:sessions sid :p2p :connected?])))
      (is (= 9 (get-in (:state res) [:sessions sid :p2p :remote-offer-seq])))
      ;; Answer envelope emitted with :p2p-broadcast? true
      (is (= 1 (count (:net-envelopes res))))
      (let [ans-env (first (:net-envelopes res))]
        (is (true? (:p2p-broadcast? ans-env)))
        (is (= sid (:p2p-session-id ans-env)))
        (is (= (:pubkey-hex bob) (:p2p-peer ans-env))))
      ;; Actionable event emitted
      (is (= 1 (count (:stdout-events res))))
      (let [evt (first (:stdout-events res))]
        (is (= "p2p-offer-answered-while-open" (or (get evt "event") (get evt :event))))
        (is (= sid (or (get evt "session_id") (get evt :session_id)))))
      ;; Diagnostics incremented
      (is (= 1 (get-in (:state res) [:diagnostics :p2p-offer-answered-while-open]))))))

(deftest test-f4-chunk-checksum-verification
  (testing "F-4: verify-and-strip-chunk-prefixes validates correct checksums"
    (let [payload "0123456789abcdef"
          sha (subs (basalt/bytes->hex (crypto/sha256 (.getBytes payload "UTF-8"))) 0 8)
          chunk-line (str "L01 [16c sha=" sha "]: " payload)
          res (light-core/verify-and-strip-chunk-prefixes chunk-line)]
      (is (true? (:ok? res)))
      (is (= payload (:hex res)))
      (is (= payload (light-core/strip-chunk-prefixes chunk-line)))))

  (testing "F-4: verify-and-strip-chunk-prefixes rejects corrupted checksums fail-closed"
    (let [payload "0123456789abcdef"
          corrupted-line (str "L01 [16c sha=deadbeef]: " payload)
          res (light-core/verify-and-strip-chunk-prefixes corrupted-line)]
      (is (false? (:ok? res)))
      (is (= "chunk-checksum-mismatch" (:error res)))
      (is (= "deadbeef" (:expected res)))
      (is (thrown? Exception (light-core/strip-chunk-prefixes corrupted-line)))))

  (testing "F-4: Corrupted chunk in import fails closed with diagnostic"
    (let [alice (test-identity)
          st (light-core/init-light-state (:identity alice) {:epoch 1})
          corrupted "L01 [20c sha=00000000]: 0123456789abcdef0123"
          res (light-core/handle-command st {"cmd" "import" "hex" corrupted} (:privkey-bytes alice))]
      (is (false? (get-in res [:response "ok"])))
      (is (= "chunk-checksum-mismatch" (get-in res [:response "error"])))
      (is (= 1 (get-in (:state res) [:diagnostics :chunk-checksum-mismatch]))))))

(deftest test-f5-outbox-rto-retransmission-and-eviction
  (testing "F-5: Outbox retransmits oldest-first, respects rto-ms, and evicts after 5 retries"
    (let [alice (test-identity)
          bob (test-identity)
          sid "f5-outbox-session"
          t0 1000000
          msg1 {:seq 1 :msg-id "m1" :retries 0 :created-ms (- t0 40000) :last-sent-ms (- t0 40000)
                :env {:type :receive-gossip :body "env1"}}
          msg2 {:seq 2 :msg-id "m2" :retries 1 :created-ms (- t0 35000) :last-sent-ms (- t0 35000)
                :env {:type :receive-gossip :body "env2"}}
          msg-fresh {:seq 3 :msg-id "m3" :retries 0 :created-ms (- t0 10000) :last-sent-ms (- t0 10000)
                     :env {:type :receive-gossip :body "env3"}}
          sess {:session-id sid :state "open" :peer (:pubkey-hex bob)
                :outbox [msg2 msg1 msg-fresh]}
          st (-> (light-core/init-light-state (:identity alice) {:epoch 1})
                 (assoc-in [:sessions sid] sess))
          ;; Retransmit with 30s RTO at t0 (msg1 and msg2 are >= 30s old, msg-fresh is 10s old)
          rx-res (light-core/retransmit-unacked-outbox st sid t0 30000)]
      ;; Envelopes retransmitted oldest-first by seq: msg1 (seq 1), then msg2 (seq 2)
      (is (= 2 (count (:net-envelopes rx-res))))
      (is (= "env1" (:body (first (:net-envelopes rx-res)))))
      (is (= "env2" (:body (second (:net-envelopes rx-res)))))
      ;; Retries incremented
      (let [outbox (get-in (:state rx-res) [:sessions sid :outbox])]
        (is (= 3 (count outbox)))
        (is (= 1 (:retries (get outbox 1))))
        (is (= 2 (:retries (get outbox 2))))
        (is (= 0 (:retries (get outbox 3)))))

      ;; Now test eviction after 5 retries:
      (let [msg-doomed {:seq 9 :msg-id "m-dead" :retries 5 :created-ms (- t0 60000) :last-sent-ms (- t0 60000)
                        :env {:type :receive-gossip :body "env-dead"}}
            st-doomed (assoc-in st [:sessions sid :outbox] [msg-doomed])
            evict-res (light-core/retransmit-unacked-outbox st-doomed sid t0 30000)]
        ;; msg-doomed is evicted from outbox
        (is (empty? (get-in (:state evict-res) [:sessions sid :outbox])))
        (is (= 1 (get-in (:state evict-res) [:diagnostics :outbox-evicted])))
        ;; Actionable event emitted and queued
        (is (some #(= "outbox-evicted" (or (get % "event") (get % :event))) (:stdout-events evict-res)))
        (is (some #(= "outbox-evicted" (or (get % "event") (get % :event))) (:event-queue (:state evict-res))))))))

(deftest test-f6-p2p-auto-reoffer-gating-and-backoff
  (testing "F-6: Shuttle mode never triggers auto-reoffer"
    (let [alice (test-identity)
          bob (test-identity)
          sid "f6-shuttle-session"
          sess {:session-id sid :state "open" :peer (:pubkey-hex bob)
                :p2p {:phase :closed :connected? false}
                :p2p-meta {:mode :shuttle :preferred-candidates ["c1"]}}
          st (-> (light-core/init-light-state (:identity alice) {:epoch 1})
                 (assoc-in [:sessions sid] sess))]
      ;; Even with autonomous daemon flag, shuttle mode sessions NEVER re-offer
      (is (false? (light-core/should-auto-reoffer? st sid 1000000 true)))
      (is (false? (light-core/should-auto-reoffer? st sid 1000000 false)))))

  (testing "F-6: Autonomous mode follows exponential backoff"
    (let [alice (test-identity)
          bob (test-identity)
          ;; Make alice pubkey lexicographically smaller than bob to win tie-breaker
          pk-a (if (neg? (compare (:pubkey-hex alice) (:pubkey-hex bob))) (:pubkey-hex alice) (:pubkey-hex bob))
          pk-b (if (neg? (compare (:pubkey-hex alice) (:pubkey-hex bob))) (:pubkey-hex bob) (:pubkey-hex alice))
          sid "f6-auto-session"
          sess {:session-id sid :state "open" :peer pk-b
                :p2p {:phase :closed :connected? false}
                :p2p-meta {:mode :autonomous :preferred-candidates ["c1"] :reconnect-attempts 0}}
          st (-> (light-core/init-light-state {:pubkey-hex pk-a} {:epoch 1})
                 (assoc-in [:sessions sid] sess))
          t0 1000000]
      ;; Initially ready to re-offer
      (is (true? (light-core/should-auto-reoffer? st sid t0 false)))
      ;; Record re-offer attempt 1 -> next reconnect is t0 + 1000ms
      (let [st1 (light-core/record-reoffer-attempt st sid t0)]
        (is (= 1 (get-in st1 [:sessions sid :p2p-meta :reconnect-attempts])))
        (is (= (+ t0 1000) (get-in st1 [:sessions sid :p2p-meta :next-reconnect-ms])))
        ;; Before backoff deadline -> false
        (is (false? (light-core/should-auto-reoffer? st1 sid (+ t0 500) false)))
        ;; At or after backoff deadline -> true
        (is (true? (light-core/should-auto-reoffer? st1 sid (+ t0 1000) false)))
        ;; Attempt 2 -> next reconnect is +2000ms (t0 + 1000 + 2000 = +3000ms)
        (let [st2 (light-core/record-reoffer-attempt st1 sid (+ t0 1000))]
          (is (= 2 (get-in st2 [:sessions sid :p2p-meta :reconnect-attempts])))
          (is (= (+ t0 3000) (get-in st2 [:sessions sid :p2p-meta :next-reconnect-ms])))
          ;; Attempt 5 -> capped at 30000ms
          (let [st5 (reduce (fn [s t] (light-core/record-reoffer-attempt s sid t))
                            st2
                            [(+ t0 3000) (+ t0 7000) (+ t0 15000) (+ t0 31000)])]
            (is (>= (get-in st5 [:sessions sid :p2p-meta :reconnect-attempts]) 5))
            (is (= 30000 (light-core/calculate-reconnect-backoff-ms 5)))))))))






