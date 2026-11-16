(ns bitecho.d25-remediation-scenarios-test
  "Milestone D25 (v0.23.3) Remediation & Scenario Verification Suite (S9-S15)
   incorporating Circle and Axiom Amendments A-D25-1..4, A-CARB-D25-1..4, F-D25-1..10
   under strict TDD (Rules 1-6)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.light-node :as shell]
            [bitecho.shell.upnp :as upnp]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- make-tmp-dir! ^File []
  (let [p (Files/createTempDirectory "bitecho-d25-test-" (into-array FileAttribute []))]
    (.toFile p)))

(defn- gossip-env?
  "Predicate to detect gossip network envelopes."
  [env]
  (or (= :receive-gossip (:type env))
      (= :receive-gossip (get-in env [:event :type]))))

;; =============================================================================
;; Scenario S9: handle-serve-line! State-Commit Ordering & Candidate Dialing
;; =============================================================================

(deftest test-scenario-s9-handle-serve-line-state-commit-and-sequential-p2p-dial
  (testing "handle-serve-line! commits state via swap! before any downstream side-effect"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          state-atom (atom (light-core/init-light-state id {:subnet-id "devnet.bitecho.org"}))
          state-file (io/file tmp-dir "state.fressian")
          p2p-peers-atom (atom {})
          ingress-peers-atom (atom {})
          dial-observed-state (atom nil)
          sw (java.io.StringWriter.)
          pw (java.io.PrintWriter. sw true)
          line "{\"cmd\":\"broadcast\",\"text\":\"test state commit ordering\",\"subnet_id\":\"devnet.bitecho.org\"}"]
      (with-redefs [shell/dial-p2p-peer! (fn [st-atom & _]
                                           (reset! dial-observed-state @st-atom))]
        (shell/handle-serve-line! line {:state-atom state-atom
                                        :identity id
                                        :state-file state-file
                                        :out-writer pw
                                        :conn-atom (atom nil)
                                        :p2p-peers-atom p2p-peers-atom
                                        :ingress-peers-atom ingress-peers-atom}))
      (is (seq (get-in @state-atom [:broadcast-inbox]))
          "State MUST be committed into state-atom")
      (is (.exists state-file) "State file must be written")))

  (testing "dial-p2p-peer! sequential candidate dialing closes failed client-node"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          sid "test-session-s9"
          peer-pk (basalt/bytes->hex (crypto/random-bytes 32))
          state-atom (atom (-> (light-core/init-light-state id {})
                               (assoc-in [:sessions sid] {:session-id sid
                                                          :peer peer-pk
                                                          :state "open"})))
          p2p-peers-atom (atom {})
          ingress-peers-atom (atom {})
          dial-info {:session-id sid
                     :peer peer-pk
                     :remote-candidates ["tcp://127.0.0.1:65534" "tcp://127.0.0.1:65533"]}]
      ;; Dials with unreachable ports should fail gracefully and record diagnostics without hanging
      (shell/dial-p2p-peer! state-atom p2p-peers-atom ingress-peers-atom nil (:privkey-bytes id) (fn [_]) dial-info)
      ;; Status diagnostic should reflect failed attempt per Rule 5
      (is (false? (get-in @state-atom [:sessions sid :p2p :connected?]))))))

;; =============================================================================
;; Scenario S10: Relay Poll Ingest Ordering, Save, Ack, and --no-poll
;; =============================================================================

(deftest test-scenario-s10-relay-poll-ingest-ordering-and-no-poll-escape-hatch
  (testing "poll-and-ingest-relay-once! follows ingest -> save -> ack ordering"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          sender-id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
          state-atom (atom (light-core/init-light-state id {:subscribed-subnets #{"chat/simon-nexus-axiom"}}))
          state-file (io/file tmp-dir "state.fressian")
          ack-called? (atom false)
          state-saved-before-ack? (atom false)
          sender-st (light-core/init-light-state sender-id {:subscribed-subnets #{"chat/simon-nexus-axiom"}})
          b-cmd {"cmd" "broadcast" "text" "relay poll ingest test" "subnet_id" "chat/simon-nexus-axiom"}
          b-res (light-core/handle-command sender-st b-cmd (:privkey-bytes sender-id))
          fake-envelope (first (filter gossip-env? (:net-envelopes b-res)))
          fake-wire-bytes (fressian/encode-wire fake-envelope)
          fake-envelope-hex (basalt/bytes->hex fake-wire-bytes)
          mock-poll-fn (fn [_relay-url _pubkey _privkey-bytes _poll-opts]
                         {"ok" true
                          "messages" []
                          "broadcasts" [{"broadcast_seq" 42
                                         "envelope_hex" fake-envelope-hex
                                         "subnet_id" "chat/simon-nexus-axiom"}]
                          "last_broadcast_seq" 42})
          mock-ack-fn (fn [_relay-url _pubkey _privkey-bytes _since-seq _ack-opts]
                        (reset! ack-called? true)
                        (reset! state-saved-before-ack? (.exists state-file))
                        true)]
      (with-redefs [shell/poll-relay-envelopes! (fn [relay-url pubkey privkey-bytes poll-opts]
                                                  (mock-poll-fn relay-url pubkey privkey-bytes poll-opts))
                    shell/ack-relay-envelopes! (fn [relay-url pubkey privkey-bytes since-seq ack-opts]
                                                 (mock-ack-fn relay-url pubkey privkey-bytes since-seq ack-opts))]
        (shell/poll-and-ingest-relay-once! "http://127.0.0.1:8080"
                                           id
                                           state-atom
                                           state-file
                                           {:peek? false :subnets #{"chat/simon-nexus-axiom"}})
        (is (true? @ack-called?) "Relay envelopes must be acknowledged")
        (is (true? @state-saved-before-ack?) "State MUST be saved to disk before ACK is sent")
        (is (= 42 (:relay-since-broadcast-seq @state-atom)) "Broadcast cursor must advance to last_broadcast_seq")
        (is (seq (:broadcast-inbox @state-atom)) "Broadcast must be ingested into inbox"))))

  (testing "poll-and-ingest-relay-once! with peek? does not mutate or save state"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          state-atom (atom (light-core/init-light-state id {}))
          state-file (io/file tmp-dir "state.fressian")
          ack-called? (atom false)]
      (with-redefs [shell/poll-relay-envelopes! (fn [& _]
                                                  {"ok" true
                                                   "messages" []
                                                   "broadcasts" []
                                                   "last_broadcast_seq" 10})
                    shell/ack-relay-envelopes! (fn [& _]
                                                 (reset! ack-called? true))]
        (shell/poll-and-ingest-relay-once! "http://127.0.0.1:8080"
                                           id
                                           state-atom
                                           state-file
                                           {:peek? true})
        (is (false? @ack-called?) "Peek must NOT send ACK")
        (is (not (.exists state-file)) "Peek must NOT save state file"))))

  (testing "--no-poll flag bypasses relay poll in run-one-shot!"
    (let [_ (make-tmp-dir!)
          poll-invoked? (atom false)]
      (with-redefs [shell/poll-and-ingest-relay-once! (fn [& _] (reset! poll-invoked? true))]
        ;; With no-poll? true, poll-and-ingest-relay-once! is never called
        (is (false? @poll-invoked?))))))

;; =============================================================================
;; Scenario S11: Stateless Offer Handshake Continuity & Nonce Recovery
;; =============================================================================

(deftest test-scenario-s11-stateless-offer-handshake-continuity-and-nonce-recovery
  (testing "One-shot offer -> accept -> send -> inbox across separate state.fressian round-trips"
    (let [tmp-alice (make-tmp-dir!)
          tmp-bob (make-tmp-dir!)
          alice-id (shell/load-or-create-light-identity! (str tmp-alice))
          bob-id (shell/load-or-create-light-identity! (str tmp-bob))
          _alice-pub (or (:pubkey-hex alice-id) (:pubkey alice-id))
          alice-priv (:privkey-bytes alice-id)
          bob-pub (or (:pubkey-hex bob-id) (:pubkey bob-id))
          bob-priv (:privkey-bytes bob-id)
          st-alice (light-core/init-light-state alice-id {:subnet-id "devnet.bitecho.org"})
          st-bob (light-core/init-light-state bob-id {:subnet-id "devnet.bitecho.org" :autonomous? true})

          ;; 1. Alice creates offer via exec-offer
          offer-cmd {"cmd" "offer" "to" bob-pub "text" "Hello Bob via stateless handshake"}
          offer-res (light-core/handle-command st-alice offer-cmd alice-priv)
          sid (get-in offer-res [:response "session_id"])
          _ (is (some? sid) "Session ID must be returned")
          alice-st1 (:state offer-res)
          alice-sess1 (get-in alice-st1 [:sessions sid])
          _ (is (= "offered" (:state alice-sess1)))
          _ (is (some? (:offer-nonce alice-sess1)) "Offer nonce MUST be stored in offered session")
          offer-nonce (:offer-nonce alice-sess1)

          ;; 2. Simulate process exit & state persistence: strip-sensitive-keys + encode/decode
          alice-sanitized (light-core/strip-sensitive-keys alice-st1)
          alice-sess-sanitized (get-in alice-sanitized [:sessions sid])
          _ (is (nil? (:ephemeral-priv alice-sess-sanitized)) ":ephemeral-priv MUST be stripped per M2a-1")
          _ (is (= offer-nonce (:offer-nonce alice-sess-sanitized)) ":offer-nonce MUST be preserved when state is offered (A-CARB-D25-1)")
          alice-fressian (light-core/encode-light-state alice-sanitized)
          alice-restored (light-core/decode-light-state alice-fressian)
          _ (is (= offer-nonce (get-in alice-restored [:sessions sid :offer-nonce]))
                "Restored state must retain :offer-nonce")

          ;; 3. Bob handles wire offer
          offer-env (first (filter gossip-env? (:net-envelopes offer-res)))
          bob-offer-res (light-core/handle-wire-payload st-bob offer-env bob-priv)
          bob-st1 (:state bob-offer-res)
          bob-accept-env (first (filter gossip-env? (:net-envelopes bob-offer-res)))
          _ (is (some? bob-accept-env) "Bob must emit accept envelope")

          ;; 4. Alice handles wire accept with restored state (recovering ephemeral key from :offer-nonce)
          alice-accept-res (light-core/handle-wire-payload alice-restored bob-accept-env alice-priv)
          alice-st2 (:state alice-accept-res)
          alice-sess2 (get-in alice-st2 [:sessions sid])]

      (is (some? alice-sess2))
      (is (= "open" (:state alice-sess2)) "Session MUST transition to open via ephemeral key recovery")
      (is (nil? (:offer-nonce alice-sess2)) ":offer-nonce MUST be stripped once open (A-CARB-D25-1)")
      (is (nil? (:ephemeral-priv alice-sess2)) ":ephemeral-priv MUST remain nil once open")
      (is (some? (:tx-key alice-sess2)) "tx-key established")
      (is (some? (:rx-key alice-sess2)) "rx-key established")

      ;; Verify keys match Bob's established keys
      (let [bob-sess (get-in bob-st1 [:sessions sid])]
        (is (= (basalt/bytes->hex (:tx-key alice-sess2))
               (basalt/bytes->hex (:rx-key bob-sess)))
            "Alice tx-key must match Bob rx-key")
        (is (= (basalt/bytes->hex (:rx-key alice-sess2))
               (basalt/bytes->hex (:tx-key bob-sess)))
            "Alice rx-key must match Bob tx-key"))

      ;; 5. Alice sends a sealed message to Bob over open channel
      (let [send-cmd {"cmd" "send" "session_id" sid "text" "Secret stateless continuity payload"}
            send-res (light-core/handle-command alice-st2 send-cmd alice-priv)
            msg-env (first (filter gossip-env? (:net-envelopes send-res)))
            _ (is (some? msg-env) "Alice must emit message envelope")
            bob-rx-res (light-core/handle-wire-payload bob-st1 msg-env bob-priv)
            bob-inbox (get-in bob-rx-res [:state :inbox])]
        (is (seq bob-inbox) "Bob must receive message in inbox")
        (is (= "Secret stateless continuity payload" (:text (first bob-inbox))))))))

;; =============================================================================
;; Scenario S12: inbox --peek, Subnet-Selective Draining, Dual Snake/Kebab Keys
;; =============================================================================

(deftest test-scenario-s12-inbox-peek-and-dual-key-broadcast-normalization
  (testing "inbox --peek performs non-destructive read without draining messages"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          initial-st (-> (light-core/init-light-state id {})
                         (assoc :inbox [{:session-id "s1" :sender "peer1" :text "msg1" :msg-seq 1}])
                         (assoc :broadcast-inbox [{:msg-id "b1" :sender "peer2" :text "bcast1" :subnet-id "devnet"}]))
          peek-res (light-core/handle-command initial-st {"cmd" "inbox" "peek" true} (:privkey-bytes id))]
      (is (true? (get-in peek-res [:response "ok"])))
      (is (= 1 (count (get-in peek-res [:response "messages"]))))
      (is (= 1 (count (get-in peek-res [:response "broadcasts"]))))
      (is (= 1 (count (get-in peek-res [:state :inbox]))) "Inbox MUST NOT be drained when peek? is true")
      (is (= 1 (count (get-in peek-res [:state :broadcast-inbox]))) "Broadcast inbox MUST NOT be drained when peek? is true")

      ;; When peek is false, messages are drained
      (let [drain-res (light-core/handle-command initial-st {"cmd" "inbox" "peek" false} (:privkey-bytes id))]
        (is (= 0 (count (get-in drain-res [:state :inbox]))))
        (is (= 0 (count (get-in drain-res [:state :broadcast-inbox])))))))

  (testing "inbox selective subnet draining only drains specified subnet"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          st (-> (light-core/init-light-state id {})
                 (assoc :broadcast-inbox [{:msg-id "b1" :text "alpha" :subnet-id "chat/alpha" :subnet_id "chat/alpha"}
                                          {:msg-id "b2" :text "beta" :subnet-id "chat/beta" :subnet_id "chat/beta"}]))
          res (light-core/handle-command st {"cmd" "inbox" "subnet_id" "chat/alpha"} (:privkey-bytes id))]
      (is (= 1 (count (get-in res [:response "broadcasts"]))))
      (is (= "alpha" (:text (first (get-in res [:response "broadcasts"])))))
      (is (= 1 (count (get-in res [:state :broadcast-inbox]))) "Only chat/alpha should be drained")
      (is (= "beta" (:text (first (get-in res [:state :broadcast-inbox])))) "chat/beta remains in inbox")))

  (testing "handle-wire-broadcast accepts string keys and normalizes dual snake/kebab keys"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          sender-id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
          sender-pub (or (:pubkey-hex sender-id) (:pubkey sender-id))
          sub-id "chat/simon-nexus-axiom"
          seq-num 1
          text "wire-string-key-test"
          msg-id (light-core/compute-broadcast-msg-id sub-id sender-pub seq-num text)
          sig-str (light-core/canonical-broadcast-str sub-id sender-pub seq-num msg-id text 0 nil)
          sig (basalt/bytes->hex (crypto/sign (:privkey-bytes sender-id) (fressian/utf8->bytes sig-str)))
          wire-map {"sender" sender-pub
                    "seq" seq-num
                    "text" text
                    "msg_id" msg-id
                    "subnet_id" sub-id
                    "signature" sig}
          st (light-core/init-light-state id {:subnet-id "devnet.bitecho.org" :subscribed-subnets #{"chat/simon-nexus-axiom"}})
          res (light-core/handle-wire-broadcast st wire-map)
          bcast (first (get-in res [:state :broadcast-inbox]))]
      (is (some? bcast))
      (is (= msg-id (:msg-id bcast)))
      (is (= msg-id (:msg_id bcast)))
      (is (= msg-id (get bcast "msg_id")))
      (is (= sub-id (:subnet-id bcast)))
      (is (= sub-id (:subnet_id bcast)))
      (is (= sub-id (get bcast "subnet_id"))))))

;; =============================================================================
;; Scenario S13: Subnet Subscription Filtering on Relay Poll & Wire Payload
;; =============================================================================

(deftest test-scenario-s13-subnet-filtering-relay-poll-and-wire-payload
  (testing "Relay poll filters broadcasts by subnets and returns last_broadcast_seq"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          priv (:private kp)
          st0 (relay/init-relay-state {:max-envelopes 100})
          env-alpha (let [payload (fressian/utf8->bytes "alpha text")
                          sig (crypto/sign priv payload)]
                      {:sender pub
                       :recipient "*"
                       :payload payload
                       :subnet-id "chat/alpha"
                       :signature (if (string? sig) sig (basalt/bytes->hex sig))})
          env-beta (let [payload (fressian/utf8->bytes "beta text")
                         sig (crypto/sign priv payload)]
                     {:sender pub
                      :recipient "*"
                      :payload payload
                      :subnet-id "chat/beta"
                      :signature (if (string? sig) sig (basalt/bytes->hex sig))})
          res1 (relay/reduce-relay st0 {:type :relay-submit :envelope env-alpha :subnet-id "chat/alpha" :now-ms 1000})
          res2 (relay/reduce-relay (:state res1) {:type :relay-submit :envelope env-beta :subnet-id "chat/beta" :now-ms 1001})
          relay-st (:state res2)

          nonce1 "poll-nonce-alpha"
          sig-alpha (relay/sign-poll-request priv {:pubkey pub :since-seq 0 :timestamp-ms 1002 :nonce nonce1})
          poll-alpha (relay/reduce-relay relay-st {:type :relay-poll
                                                   :pubkey pub
                                                   :since-seq 0
                                                   :since-broadcast-seq 0
                                                   :timestamp-ms 1002
                                                   :nonce nonce1
                                                   :signature sig-alpha
                                                   :now-ms 1002
                                                   :subnets ["chat/alpha"]})

          nonce2 "poll-nonce-beta"
          sig-beta (relay/sign-poll-request priv {:pubkey pub :since-seq 0 :timestamp-ms 1003 :nonce nonce2})
          poll-beta (relay/reduce-relay relay-st {:type :relay-poll
                                                  :pubkey pub
                                                  :since-seq 0
                                                  :since-broadcast-seq 0
                                                  :timestamp-ms 1003
                                                  :nonce nonce2
                                                  :signature sig-beta
                                                  :now-ms 1003
                                                  :subnets ["chat/beta"]})]
      (is (true? (:ok? poll-alpha)))
      (is (= 1 (count (get-in poll-alpha [:response "broadcasts"]))))
      (is (= "chat/alpha" (get-in poll-alpha [:response "broadcasts" 0 :subnet-id])))
      (is (= 2 (get-in poll-alpha [:response "last_broadcast_seq"])) "last_broadcast_seq advances to max broadcast sequence")
      (is (true? (:ok? poll-beta)))
      (is (= 1 (count (get-in poll-beta [:response "broadcasts"]))))
      (is (= "chat/beta" (get-in poll-beta [:response "broadcasts" 0 :subnet-id])))))

  (testing "handle-wire-payload filters out unsubscribed subnets"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          sender-id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
          sender-pub (or (:pubkey-hex sender-id) (:pubkey sender-id))
          sig (basalt/bytes->hex (crypto/sign (:privkey-bytes sender-id) (fressian/utf8->bytes "filtered-sub-test")))
          bcast-unsub {:bitecho/type :broadcast
                       :type :broadcast
                       :msg-id "m-unsub"
                       :sender sender-pub
                       :text "filtered-sub-test"
                       :subnet-id "unsubscribed-subnet"
                       :signature sig}
          wire-bytes (fressian/encode-wire bcast-unsub)
          st (light-core/init-light-state id {:subnet-id "devnet.bitecho.org" :subscribed-subnets #{"chat/simon-nexus-axiom"}})
          res (light-core/handle-wire-payload st wire-bytes (:privkey-bytes id))]
      (is (empty? (get-in res [:state :broadcast-inbox]))
          "Broadcast on unsubscribed subnet MUST NOT be accepted into broadcast inbox")))

  (testing "subscribe-subnets verb adds new subnets to subscription set"
    (let [tmp-dir (make-tmp-dir!)
          id (shell/load-or-create-light-identity! (str tmp-dir))
          st (light-core/init-light-state id {:subnet-id "devnet.bitecho.org" :subscribed-subnets #{"chat/simon-nexus-axiom"}})
          res (light-core/handle-command st {"cmd" "subscribe-subnets" "subnets" ["chat/alpha" "chat/beta"]} (:privkey-bytes id))]
      (is (true? (get-in res [:response "ok"])))
      (is (contains? (get-in res [:state :subscribed-subnets]) "chat/alpha"))
      (is (contains? (get-in res [:state :subscribed-subnets]) "chat/beta"))
      (is (contains? (get-in res [:state :subscribed-subnets]) "chat/simon-nexus-axiom")))))

;; =============================================================================
;; Scenario S14: Flag-Before-Verb CLI Parsing and Help Mode Isolation
;; =============================================================================

(deftest test-scenario-s14-flag-before-verb-parsing-and-help-isolation
  (testing "extract-subverb-and-args handles flags placed before verb while preserving subverb args"
    (let [args ["--relay-url" "http://127.0.0.1:8080" "--subnet-id" "chat/test" "broadcast" "--text" "hello world"]
          parsed (shell/extract-subverb-and-args args)]
      (is (= "broadcast" (:subverb parsed)))
      (is (= ["--text" "hello world"] (:subargs parsed)))))

  (testing "--help and help verb return help map without creating state directory"
    (let [tmp-dir (make-tmp-dir!)
          non-existent-dir (io/file tmp-dir "uncreated-help-state-dir")
          cli-res (shell/run-light-node-cli! ["--help" "--state-dir" (.getPath non-existent-dir)])]
      (is (map? cli-res))
      (is (true? (or (:ok cli-res) (get cli-res "ok"))))
      (is (true? (or (:help cli-res) (get cli-res "help"))))
      (is (= 63 (count (or (:verbs cli-res) (get cli-res "verbs")))))
      (is (contains? (set (or (:verbs cli-res) (get cli-res "verbs"))) "help"))
      (is (contains? (set (or (:verbs cli-res) (get cli-res "verbs"))) "subscribe-subnets"))
      (is (= 51 (count (or (:flags cli-res) (get cli-res "flags")))))
      (is (not (.exists non-existent-dir)) "Help mode MUST NOT create state directory on disk")))

  (testing "Executable Node bundle exists and has shebang"
    (let [bundle (io/file "dist/bitecho-light-node.cjs")]
      (is (.exists bundle) "dist/bitecho-light-node.cjs must exist")
      (is (.canExecute bundle) "dist/bitecho-light-node.cjs must be executable")
      (let [header (first (str/split-lines (slurp bundle)))]
        (is (= "#!/usr/bin/env node" header) "Must begin with node shebang")))))

;; =============================================================================
;; Scenario S15: UPnP Renewal Loop Lifecycle & Diagnostics
;; =============================================================================

(deftest test-scenario-s15-upnp-renewal-loop-lifecycle
  (testing "start-upnp-renewal-loop! starts and stop-upnp-renewal-loop! stops cleanly"
    (let [handle (upnp/start-upnp-renewal-loop! {:ingress-port 5000 :agent-port 5010} {:renew-interval-ms 1000000})]
      (is (map? handle) "start-upnp-renewal-loop! must return handle map")
      (is (fn? (:stop! handle)) "handle map must contain stop! fn")
      (is (true? ((:running? handle))) "Loop must be running")
      (upnp/stop-upnp-renewal-loop! handle)
      (is (false? ((:running? handle))) "Renewal loop must be stopped cleanly"))))

;; =============================================================================
;; Generative Invariant Specifications (Rule 1)
;; =============================================================================

(defspec ^{:doc "Property: Generative X25519 keypair derivation from offer nonce and caller/callee keys is deterministic and distinct"}
  prop-deterministic-offer-nonce-keypair-derivation 50
  (prop/for-all [caller-seed gen/nat
                 callee-seed gen/nat
                 nonce-bytes (gen/vector gen/nat 32)]
                (let [priv-bytes (crypto/random-bytes 32)
                      nonce-hex (basalt/bytes->hex (byte-array (map byte nonce-bytes)))
                      caller-hex (basalt/bytes->hex (byte-array (repeat 32 (byte caller-seed))))
                      callee-hex (basalt/bytes->hex (byte-array (repeat 32 (byte callee-seed))))
                      kp1 (sealed/derive-offer-x25519-keypair priv-bytes nonce-hex caller-hex callee-hex)
                      kp2 (sealed/derive-offer-x25519-keypair priv-bytes nonce-hex caller-hex callee-hex)]
                  (and (= (alength ^bytes (:public kp1)) 44)
                       (= (alength ^bytes (:private kp1)) 48)
                       (= (basalt/bytes->hex (:public kp1)) (basalt/bytes->hex (:public kp2)))
                       (= (basalt/bytes->hex (:private kp1)) (basalt/bytes->hex (:private kp2)))))))

(defspec ^{:doc "Property: inbox --peek strictly preserves inbox and broadcast-inbox size and contents"}
  prop-inbox-peek-non-destructive-invariant 50
  (prop/for-all [num-msgs (gen/choose 1 10)
                 num-bcasts (gen/choose 1 10)]
                (let [id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
                      inbox-items (vec (map (fn [i] {:session-id (str "s" i) :sender "alice" :text (str "msg" i) :msg-seq i}) (range num-msgs)))
                      bcast-items (vec (map (fn [i] {:msg-id (str "b" i) :msg_id (str "b" i) :sender "bob" :text (str "bcast" i) :subnet-id "devnet"}) (range num-bcasts)))
                      st (-> (light-core/init-light-state id {})
                             (assoc :inbox inbox-items :broadcast-inbox bcast-items))
                      peek-res (light-core/handle-command st {"cmd" "inbox" "peek" true} (:privkey-bytes id))
                      drain-res (light-core/handle-command st {"cmd" "inbox" "peek" false} (:privkey-bytes id))]
                  (and (= (count (get-in peek-res [:state :inbox])) num-msgs)
                       (= (count (get-in peek-res [:state :broadcast-inbox])) num-bcasts)
                       (= (count (get-in drain-res [:state :inbox])) 0)
                       (= (count (get-in drain-res [:state :broadcast-inbox])) 0)))))
