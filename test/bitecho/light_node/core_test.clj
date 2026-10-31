(ns bitecho.light-node.core-test
  "Tests and generative invariants for the pure light-node protocol state machine."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.light-node.core :as light-core]
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
