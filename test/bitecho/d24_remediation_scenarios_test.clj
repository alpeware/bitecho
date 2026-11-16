(ns bitecho.d24-remediation-scenarios-test
  "Milestone D24 (v0.23.1) Remediation & Scenario Verification Suite (S1-S7)
   incorporating Circle Amendments A-CARB-D24-1..6 and A-D24-1..5 under strict TDD (Rules 1-6)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.dns :as dns-proto]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.discovery :as discovery]
            [bitecho.shell.http :as http-shell]
            [bitecho.shell.light-node :as shell]
            [bitecho.sim.vopr :as vopr]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- make-tmp-dir! ^File []
  (let [p (Files/createTempDirectory "bitecho-d24-test-" (into-array FileAttribute []))]
    (.toFile p)))

(defn ensure-bootstrap-fixtures!
  "Returns {:edn-path string :txt-path string :fixture-edn-path string :fixture-txt-path string}
   pointing to valid signed bootstrap descriptors. If devnet/bootstrap.edn and devnet/bootstrap.txt
   exist on disk, verifies them and returns their paths. Also generates a self-contained temporary
   DA-signed bootstrap.edn and bootstrap.txt fixture, verifying both to ensure test isolation
   and hermetic execution on clean checkouts without devnet/."
  []
  (let [devnet-edn (io/file "devnet/bootstrap.edn")
        devnet-txt (io/file "devnet/bootstrap.txt")
        tmp-dir (make-tmp-dir!)
        fixture-edn (io/file tmp-dir "bootstrap.edn")
        fixture-txt (io/file tmp-dir "bootstrap.txt")
        kp (crypto/generate-keypair)
        pub (basalt/bytes->hex (:public kp))
        desc {:network :devnet
              :domain "bitecho.org"
              :authority-pubkey pub
              :epoch-duration-ms 10000
              :issued-epoch 0
              :expires-epoch 999999
              :treasury-pubkey pub
              :custody-pubkey pub
              :directory-pubkey pub
              :nodes {:val-1 {:node-id "val-1"
                              :ip "127.0.0.1"
                              :port 5000
                              :agent-port 5010
                              :pubkey pub
                              :fingerprint "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                              :ice-ufrag "testufrag"
                              :ice-pwd "testpwd"}}}
        signed (light-core/sign-bootstrap-descriptor (:private kp) desc)
        txt-content (light-core/format-bootstrap-txt-pure signed)
        edn-content (pr-str signed)]
    (spit fixture-edn edn-content)
    (spit fixture-txt txt-content)
    (if (and (.exists devnet-edn) (.exists devnet-txt))
      {:edn-path (.getPath devnet-edn)
       :txt-path (.getPath devnet-txt)
       :authority-pubkey pub
       :fixture-edn-path (.getPath fixture-edn)
       :fixture-txt-path (.getPath fixture-txt)}
      {:edn-path (.getPath fixture-edn)
       :txt-path (.getPath fixture-txt)
       :authority-pubkey pub
       :fixture-edn-path (.getPath fixture-edn)
       :fixture-txt-path (.getPath fixture-txt)})))

(defn- make-rfc4571-stun-binding-req
  "Constructs an RFC 4571 framed STUN Binding Request packet with USERNAME attribute."
  [^String username]
  (let [uname-bytes (.getBytes username StandardCharsets/UTF_8)
        uname-len (alength uname-bytes)
        padded-len (bit-and (+ uname-len 3) (bit-not 3))
        stun-len (+ 4 padded-len) ;; 2-byte type + 2-byte len + padded value
        rfc4571-len (+ 20 stun-len)
        buf (byte-array (+ 2 20 stun-len))]
    ;; RFC 4571 2-byte frame length
    (aset-byte buf 0 (byte (bit-shift-right rfc4571-len 8)))
    (aset-byte buf 1 (byte (bit-and rfc4571-len 0xff)))
    ;; STUN Message Type: 0x0001 (Binding Request)
    (aset-byte buf 2 (byte 0x00))
    (aset-byte buf 3 (byte 0x01))
    ;; STUN Message Length
    (aset-byte buf 4 (byte (bit-shift-right stun-len 8)))
    (aset-byte buf 5 (byte (bit-and stun-len 0xff)))
    ;; STUN Magic Cookie: 0x2112A442
    (aset-byte buf 6 (byte 0x21))
    (aset-byte buf 7 (byte 0x12))
    (aset-byte buf 8 (unchecked-byte 0xa4))
    (aset-byte buf 9 (byte 0x42))
    ;; 12-byte Transaction ID
    (dotimes [i 12]
      (aset-byte buf (+ 10 i) (byte (+ 1 i))))
    ;; Attribute 0x0006: USERNAME
    (aset-byte buf 22 (byte 0x00))
    (aset-byte buf 23 (byte 0x06))
    (aset-byte buf 24 (byte (bit-shift-right uname-len 8)))
    (aset-byte buf 25 (byte (bit-and uname-len 0xff)))
    (System/arraycopy uname-bytes 0 buf 26 uname-len)
    buf))

;; =============================================================================
;; Scenario S1: P2P Answer Candidate Fallback & :p2p-meta Persistence (Items 1 & 1b)
;; =============================================================================

(deftest test-scenario-s1-p2p-answer-candidate-fallback-and-persistence
  (testing "Responder handles p2p-offer, persists state, restores, and answers with identical candidate"
    (let [alice-id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
          bob-id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
          alice-pub (or (:pubkey-hex alice-id) (:pubkey alice-id))
          alice-priv (:privkey-bytes alice-id)
          bob-pub (or (:pubkey-hex bob-id) (:pubkey bob-id))
          bob-priv (:privkey-bytes bob-id)
          sid (light-core/compute-session-id alice-pub bob-pub (basalt/bytes->hex (crypto/random-bytes 32)))
          cand "connect://nexus.ingress.bitecho.org:443"
          ;; Initial open channel state between Alice and Bob
          st-bob (-> (light-core/init-light-state bob-id {:subnet-id "devnet.bitecho.org"})
                     (assoc-in [:sessions sid] {:session-id sid
                                                :peer alice-pub
                                                :role :responder
                                                :state "open"
                                                :tx-seq 1
                                                :acked-seq 0
                                                :rx-high-seq 0
                                                :contiguous-rx-seq 0
                                                :outbox {}
                                                :outbox-order []
                                                :epoch 0
                                                :tx-key (crypto/random-bytes 32)
                                                :rx-key (crypto/random-bytes 32)}))
          ;; Alice creates p2p-offer
          sig-str (light-core/canonical-p2p-signal-str :offer sid alice-pub bob-pub "connect" [cand] "alice-ufrag" "alice-pwd" "alice-fp" 0 1)
          alice-sig (basalt/bytes->hex (crypto/sign alice-priv (fressian/utf8->bytes sig-str)))
          offer-msg {:bitecho/type :p2p-offer
                     :type :p2p-offer
                     :session-id sid
                     :sender alice-pub
                     :recipient bob-pub
                     :transport "connect"
                     :candidates [cand]
                     :ice-ufrag "alice-ufrag"
                     :ice-pwd "alice-pwd"
                     :fingerprint "alice-fp"
                     :epoch 0
                     :signal-seq 1
                     :signature alice-sig}
          ;; Bob processes wire offer
          bob-offer-res (light-core/handle-wire-payload st-bob offer-msg bob-priv)
          bob-st1 (:state bob-offer-res)
          ;; Verify :p2p-meta stored remote parameters
          _ (is (some? (get-in bob-st1 [:sessions sid :p2p-meta])))
          _ (is (= [cand] (get-in bob-st1 [:sessions sid :p2p-meta :remote-candidates])))
          _ (is (= "alice-ufrag" (get-in bob-st1 [:sessions sid :p2p-meta :remote-ice-ufrag])))
          ;; Simulate state persistence and restart: strip-sensitive-keys + encode/decode round-trip
          sanitized (light-core/strip-sensitive-keys bob-st1)
          persisted-bytes (light-core/encode-light-state sanitized)
          bob-st2 (light-core/decode-light-state persisted-bytes)
          _ (is (nil? (get-in bob-st2 [:sessions sid :p2p :remote-candidates])) "Runtime :p2p candidates stripped per Rule 4")
          _ (is (= [cand] (get-in bob-st2 [:sessions sid :p2p-meta :remote-candidates])) ":p2p-meta preserved across persistence")
          ;; Bob executes exec-p2p-answer specifying candidates identical to Alice's candidate
          ans-cmd {"cmd" "p2p-answer"
                   "session_id" sid
                   "transport" "connect"
                   "candidates" [cand]}
          ans-res (light-core/handle-command bob-st2 ans-cmd bob-priv)
          p2p-dial (:p2p-dial ans-res)]
      (is (true? (get-in ans-res [:response "ok"])))
      (is (some? p2p-dial) "P2P dial MUST be emitted via candidate fallback")
      (is (= [cand] (:remote-candidates p2p-dial)))
      (is (= "alice-ufrag" (:remote-ice-ufrag p2p-dial)))
      (is (= "alice-fp" (:remote-fingerprint p2p-dial)))
      (is (= 1 (get-in ans-res [:state :diagnostics :p2p-answer-candidate-self-filter-fallback]))
          "Diagnostics counter MUST record fallback per Rule 5"))))

(defspec ^{:doc "Property: Generative candidate self-filtering fallback preserves dialable candidate without dropping"}
  prop-s1-p2p-answer-candidate-fallback 50
  (prop/for-all [cand (gen/elements ["connect://ns1.bitecho.org:443"
                                     "connect://nexus.ingress.bitecho.org:443"
                                     "udp://35.212.129.138:5010"])]
                (let [id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
                      peer-pk (basalt/bytes->hex (crypto/random-bytes 32))
                      sid (light-core/compute-session-id (or (:pubkey-hex id) (:pubkey id)) peer-pk "test-eph")
                      st (-> (light-core/init-light-state id {})
                             (assoc-in [:sessions sid] {:session-id sid
                                                        :peer peer-pk
                                                        :state "open"
                                                        :p2p-meta {:remote-candidates [cand]
                                                                   :remote-ice-ufrag "ufrag-test"
                                                                   :remote-ice-pwd "pwd-test"
                                                                   :remote-fingerprint "fp-test"
                                                                   :remote-transport "connect"}}))
                      res (light-core/handle-command st {"cmd" "p2p-answer" "session_id" sid "candidates" [cand]} (:privkey-bytes id))
                      p2p-dial (:p2p-dial res)]
                  (and (true? (get-in res [:response "ok"]))
                       (= [cand] (:remote-candidates p2p-dial))
                       (= 1 (get-in res [:state :diagnostics :p2p-answer-candidate-self-filter-fallback]))))))

;; =============================================================================
;; Scenario S2: Port :443 Passthrough Routing & DA Signatures (Item 2)
;; =============================================================================

(deftest test-scenario-s2-port-443-passthrough-and-signatures
  (testing "devnet/bootstrap.txt and devnet/bootstrap.edn have valid Directory Authority signatures"
    (let [fixtures (ensure-bootstrap-fixtures!)
          edn-desc (discovery/load-bootstrap-descriptor! (:edn-path fixtures))
          txt-desc (discovery/load-bootstrap-descriptor! (:txt-path fixtures))
          fix-edn (discovery/load-bootstrap-descriptor! (:fixture-edn-path fixtures)
                                                        {:expected-authority-pubkey (:authority-pubkey fixtures)
                                                         :verify-signature? false})
          fix-txt (discovery/load-bootstrap-descriptor! (:fixture-txt-path fixtures)
                                                        {:expected-authority-pubkey (:authority-pubkey fixtures)
                                                         :verify-signature? false})]
      (is (map? edn-desc))
      (is (map? txt-desc))
      (is (true? (:ok? (light-core/verify-bootstrap-descriptor (:authority-pubkey edn-desc) edn-desc 0))))
      (is (true? (:ok? (light-core/verify-bootstrap-descriptor (:authority-pubkey txt-desc) txt-desc 0))))
      (is (map? fix-edn))
      (is (map? fix-txt))
      (is (true? (:ok? (light-core/verify-bootstrap-descriptor (:authority-pubkey fix-edn) fix-edn 0))))
      (is (true? (:ok? (light-core/verify-bootstrap-descriptor (:authority-pubkey fix-txt) fix-txt 0))))))

  (testing "dns/extract-stun-target-ufrag extracts target ufrag from RFC 4571 STUN packets"
    (let [pkt1 (make-rfc4571-stun-binding-req "1ec0ae74:localufrag123")
          ufrag1 (dns-proto/extract-stun-target-ufrag pkt1 (alength pkt1))]
      (is (= "1ec0ae74" ufrag1)))
    (let [pkt2 (make-rfc4571-stun-binding-req "4B1D8FC5:anotherlocal")
          ufrag2 (dns-proto/extract-stun-target-ufrag pkt2 (alength pkt2))]
      (is (= "4b1d8fc5" ufrag2)))
    (let [empty-buf (byte-array 15)]
      (is (nil? (dns-proto/extract-stun-target-ufrag empty-buf (alength empty-buf)))))
    (let [non-stun (byte-array [0x00 0x10 0x16 0x03 0x01])]
      (is (nil? (dns-proto/extract-stun-target-ufrag non-stun (alength non-stun))))))

  (testing "http/resolve-connect-backend routes node1..node3 and ns1..ns3 correctly"
    (let [connect-routes {"node1.ingress.bitecho.org:443" {:host "35.212.129.138" :port 5010}
                          "node2.ingress.bitecho.org:443" {:host "35.206.120.143" :port 5010}
                          "node3.ingress.bitecho.org:443" {:host "35.211.71.139" :port 5010}
                          "ns1.bitecho.org:443" {:host "127.0.0.1" :port 5010}}
          connect-targets #{"node1.ingress.bitecho.org:443" "node2.ingress.bitecho.org:443" "node3.ingress.bitecho.org:443" "ns1.bitecho.org:443"}
          ingress-target {:host "127.0.0.1" :port 5010}
          res1 (#'http-shell/resolve-connect-backend {:host "node1.ingress.bitecho.org" :port 443} connect-targets connect-routes ingress-target)
          res2 (#'http-shell/resolve-connect-backend {:host "node2.ingress.bitecho.org" :port 443} connect-targets connect-routes ingress-target)
          res3 (#'http-shell/resolve-connect-backend {:host "node3.ingress.bitecho.org" :port 443} connect-targets connect-routes ingress-target)
          res-ns1 (#'http-shell/resolve-connect-backend {:host "ns1.bitecho.org" :port 443} connect-targets connect-routes ingress-target)]
      (is (= {:host "35.212.129.138" :port 5010} res1))
      (is (= {:host "35.206.120.143" :port 5010} res2))
      (is (= {:host "35.211.71.139" :port 5010} res3))
      (is (= {:host "127.0.0.1" :port 5010} res-ns1)))))

(defspec ^{:doc "Property: RFC 4571 STUN target ufrag extraction parses arbitrary alphanumeric ufrags"}
  prop-stun-ufrag-extraction 50
  (prop/for-all [ufrag-str (gen/such-that #(not (str/blank? %))
                                          (gen/fmap #(apply str %) (gen/vector (gen/elements [\a \b \c \d \0 \1 \2 \3 \4]) 4 16)))]
                (let [pkt (make-rfc4571-stun-binding-req (str ufrag-str ":localpart"))
                      extracted (dns-proto/extract-stun-target-ufrag pkt (alength pkt))]
                  (= (str/lower-case ufrag-str) extracted))))

;; =============================================================================
;; Scenario S3: Cross-Subnet Relay E2E, Out-of-Order Sealed Message Buffering & Voucher Routing (Items 4, 5, 6, 7, 10)
;; =============================================================================

(deftest test-scenario-s3-cross-subnet-relay-and-early-sealed-buffering
  (testing "Rendezvous across global and devnet.bitecho.org over reduce-relay with out-of-order sealed message"
    (let [alice-id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
          bob-id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
          alice-pub (or (:pubkey-hex alice-id) (:pubkey alice-id))
          alice-priv (:privkey-bytes alice-id)
          bob-pub (or (:pubkey-hex bob-id) (:pubkey bob-id))
          bob-priv (:privkey-bytes bob-id)
          ;; Alice on "global", Bob on "devnet.bitecho.org"
          st-alice (light-core/init-light-state alice-id {:subnet-id "global"})
          st-bob (light-core/init-light-state bob-id {:subnet-id "devnet.bitecho.org"
                                                      :rendezvous-policy {:auto-accept? true
                                                                          :min-burn 0
                                                                          :price 10
                                                                          :home-node "ns1"}})
          relay-st (relay/init-relay-state {:min-signaling-burn 0})
          ;; 1. Alice creates offer to Bob with initial message
          offer-res (light-core/handle-command st-alice {"cmd" "rendezvous-offer"
                                                         "to" bob-pub
                                                         "text" "Hello early message!"
                                                         "home_node" "ns1"}
                                               alice-priv)
          st-alice (:state offer-res)
          offer-env (first (:net-envelopes offer-res))
          offer-hash (get-in offer-res [:response "offer_hash"])
          _ (is (some? offer-hash))
          ;; 2. Relay processes offer-env
          r-res1 (relay/reduce-relay relay-st {:type :submit :wire-bytes (fressian/encode-wire offer-env)})
          relay-st (:state r-res1)
          ;; 3. Bob receives offer header from relay
          bob-hdr-res (light-core/handle-wire-payload st-bob offer-env bob-priv)
          st-bob (:state bob-hdr-res)
          voucher-env (first (:net-envelopes bob-hdr-res))
          _ (is (some? voucher-env) "Bob auto-accepted and emitted voucher envelope")
          ;; Verify voucher epoch stamped at max(callee-epoch, header-epoch)
          voucher-wire (light-core/unwrap-wire-message voucher-env)
          _ (is (= :rendezvous-ack-voucher (:type voucher-wire)))
          ;; 4. Submit voucher into relay and verify it is routed to ALICE's mailbox (recipient is :caller)
          r-res2 (relay/reduce-relay relay-st {:type :submit :wire-bytes (fressian/encode-wire voucher-env)})
          relay-st (:state r-res2)
          alice-mailbox (or (get-in relay-st [:mailboxes alice-pub]) (get-in relay-st [:inboxes alice-pub]))
          bob-mailbox (or (get-in relay-st [:mailboxes bob-pub]) (get-in relay-st [:inboxes bob-pub]))
          _ (is (pos? (count alice-mailbox)) "Voucher MUST be delivered to Alice (caller) mailbox!")
          _ (is (not-any? (fn [entry] (= :rendezvous-ack-voucher (:type (light-core/unwrap-wire-message (basalt/hex->bytes (:envelope entry)))))) bob-mailbox)
                "Voucher MUST NOT be delivered to Bob (callee)!")
          ;; 5. Simulate +50 epoch skew on Alice: Alice's clock advanced, but pending voucher is accepted
          st-alice-skewed (assoc st-alice :epoch 50 :epoch-initialized? true)
          alice-ack-res (light-core/handle-wire-payload st-alice-skewed voucher-wire alice-priv)
          st-alice (:state alice-ack-res)
          _ (is (zero? (get-in st-alice [:diagnostics :epoch-skew-dropped] 0))
                "Pending outbound voucher MUST be exempt from epoch-skew drops!")
          out-envs (:net-envelopes alice-ack-res)
          _ (is (= 2 (count out-envs)) "Alice emits [reveal-env msg-env]")
          reveal-env (first out-envs)
          msg-env (second out-envs)
          reveal-wire (light-core/unwrap-wire-message reveal-env)
          sid (:session-id reveal-wire)
          ;; 6. OUT-OF-ORDER TEST: Deliver msg-env (seq 1) to Bob BEFORE reveal-env
          bob-msg-early (light-core/handle-wire-payload st-bob msg-env bob-priv)
          st-bob (:state bob-msg-early)
          _ (is (= 1 (get-in st-bob [:diagnostics :early-sealed-message-buffered]))
                "Early sealed message MUST be buffered when session is not open yet")
          _ (is (= 1 (count (get-in st-bob [:early-sealed-messages sid])))
                "Buffered message MUST reside in :early-sealed-messages")
          ;; 7. Now deliver reveal-env to Bob
          bob-reveal-res (light-core/handle-wire-payload st-bob reveal-env bob-priv)
          st-bob (:state bob-reveal-res)]
      ;; Bob should have established session, replayed seq 1, decrypted the text, and generated session-ack
      (is (= "open" (get-in st-bob [:sessions sid :state])))
      (is (empty? (get-in st-bob [:early-sealed-messages sid])) "Buffered early messages MUST be drained on reveal")
      (is (= 1 (count (:inbox st-bob))) "Seq 1 message MUST be in Bob's inbox")
      (is (= "Hello early message!" (:text (first (:inbox st-bob)))))
      (is (some (fn [evt] (= "message-received" (get evt "event"))) (:stdout-events bob-reveal-res))
          "message-received event MUST be emitted on replay")
      (let [ack-env (first (:net-envelopes bob-reveal-res))]
        (is (some? ack-env) "Session-ack envelope MUST be emitted for replayed message")
        (let [ack-payload (light-core/unwrap-wire-message ack-env)]
          (is (= :session-ack (:bitecho/type ack-payload)))
          (is (= 1 (:acked-seq ack-payload)))
          (is (= "devnet.bitecho.org" (:subnet-id ack-payload))))))))

;; =============================================================================
;; Scenario S4: Wall-Clock now_ms Injection & Offline Shuttle Exemption (Items 8 & 9)
;; =============================================================================

(deftest test-scenario-s4-now-ms-injection-and-offline-shuttle
  (testing "now_ms injection on export-poll passes relay verification"
    (let [id (shell/load-or-create-light-identity! (str (make-tmp-dir!)))
          st (light-core/init-light-state id {})
          cli-map (shell/build-one-shot-cmd-map "export-poll" [])
          _ (is (pos? (get cli-map "now_ms" 0)) "build-one-shot-cmd-map MUST inject now_ms on export-poll")
          ack-map (shell/build-one-shot-cmd-map "export-ack" ["--seq" "5"])
          _ (is (pos? (get ack-map "now_ms" 0)) "build-one-shot-cmd-map MUST inject now_ms on export-ack")
          now (get cli-map "now_ms")
          res (light-core/handle-command st cli-map (:privkey-bytes id))
          poll-req (get-in res [:response "poll_request"])]
      (is (true? (get-in res [:response "ok"])))
      (is (some? poll-req))
      (is (true? (:ok? (relay/verify-poll-request poll-req now))))))

  (testing "export-offer executes offline by default without dialing network"
    (let [tmp-dir (str (make-tmp-dir!))
          _id (shell/load-or-create-light-identity! tmp-dir)
          peer-pk (basalt/bytes->hex (crypto/random-bytes 32))
          start-t (System/currentTimeMillis)
          bootstrap-path (:edn-path (ensure-bootstrap-fixtures!))
          ;; Note: :connect? is omitted, so it defaults to offline (false) for shuttle verbs
          res (shell/run-one-shot! {:state-dir tmp-dir
                                    :bootstrap bootstrap-path
                                    :cmd-map {"cmd" "export-offer" "to" peer-pk}})
          elapsed (- (System/currentTimeMillis) start-t)]
      (is (map? res))
      (is (true? (get res "ok")))
      (is (some? (or (get res "envelope") (get res "envelope_hex"))))
      (is (< elapsed 1500) (str "Offline export-offer took too long: " elapsed "ms")))))

;; =============================================================================
;; Scenario S5: HTTP Relay Replication Auth (F-P0-1) & 16-Thread /ctl Concurrency (F-P0-2)
;; =============================================================================

(deftest test-scenario-s5-replication-auth-and-ctl-concurrency
  (testing "F-P0-1: Spoofed X-Bitecho-Relay-Replicated without HMAC is rejected with 403"
    (let [tmp-dir (make-tmp-dir!)
          shared-secret (.getBytes "cluster-secret-key-123" StandardCharsets/UTF_8)
          tls-mgr (http-shell/init-tls-manager! {:state-dir tmp-dir :domain "localhost"})
          relay-atom (atom (relay/init-relay-state {:min-signaling-burn 0}))
          relay-waiters-atom (atom {})
          cfg {:domain "bitecho.org"
               :state-dir tmp-dir
               :relay-atom relay-atom
               :relay-waiters-atom relay-waiters-atom
               :shared-secret shared-secret
               :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
          srv (http-shell/start-http-servers! cfg tls-mgr nil)]
      (try
        (let [http-port (:http-port srv)
              base-url (str "http://127.0.0.1:" http-port)
              client (HttpClient/newHttpClient)
              alice-kp (crypto/generate-keypair)
              alice-id {:pubkey-hex (basalt/bytes->hex (:public-key alice-kp))
                        :privkey-bytes (:private-key alice-kp)}
              init-a (light-core/init-light-state alice-id {:subnet-id "test/d24-auth" :economy-enabled? false :burn-floor 0 :epoch 1})
              off-res (light-core/handle-command init-a {"cmd" "offer" "callee" (:pubkey-hex alice-id) "price" 0 "burn" 0} (:privkey-bytes alice-id))
              raw-env (first (:net-envelopes off-res))
              wire-hex (basalt/bytes->hex (fressian/encode-canonical raw-env))
              env-bytes (.getBytes (json/write-str {"envelope_hex" wire-hex}) StandardCharsets/UTF_8)
              ;; 1. Spoofed request without HMAC
              spoofed-req (-> (HttpRequest/newBuilder)
                              (.uri (URI/create (str base-url "/relay/v1/send")))
                              (.header "Content-Type" "application/octet-stream")
                              (.header "X-Bitecho-Relay-Replicated" "true")
                              (.POST (HttpRequest$BodyPublishers/ofByteArray env-bytes))
                              (.build))
              spoofed-resp (.send client spoofed-req (HttpResponse$BodyHandlers/ofString))
              spoofed-body (json/read-str (.body spoofed-resp))]
          (is (= 403 (.statusCode spoofed-resp)))
          (is (= "unauthorized-replication" (get spoofed-body "error")))
          (is (= 1 (get-in @relay-atom [:diagnostics :unauthorized-replication])))
          ;; 2. Valid request with HMAC
          (let [auth-hmac (http-shell/compute-relay-auth-hmac shared-secret "/relay/v1/send" env-bytes)
                valid-req (-> (HttpRequest/newBuilder)
                              (.uri (URI/create (str base-url "/relay/v1/send")))
                              (.header "Content-Type" "application/octet-stream")
                              (.header "X-Bitecho-Relay-Replicated" "true")
                              (.header "X-Bitecho-Relay-Auth" auth-hmac)
                              (.POST (HttpRequest$BodyPublishers/ofByteArray env-bytes))
                              (.build))
                valid-resp (.send client valid-req (HttpResponse$BodyHandlers/ofString))
                valid-body (json/read-str (.body valid-resp))]
            (is (= 200 (.statusCode valid-resp)))
            (is (true? (get valid-body "ok")))
            (is (= 1 (get-in @relay-atom [:diagnostics :unauthorized-replication])))))
        (finally
          (http-shell/stop-http-servers! srv)))))

  (testing "F-P0-2: 16 concurrent threads executing /ctl commands maintain strict serialization"
    (let [tmp-dir (str (make-tmp-dir!))
          state-file (str (io/file tmp-dir "state.fressian"))
          id (shell/load-or-create-light-identity! tmp-dir)
          st-atom (atom (light-core/init-light-state id {}))
          conn-atom (atom {:phase :disconnected})
          cmd-lock (Object.)
          ctx {:state-atom st-atom
               :conn-atom conn-atom
               :identity id
               :state-file state-file
               :cmd-lock cmd-lock
               :serve-cmd-lock cmd-lock}
          ctrl-svc (shell/start-control-server! tmp-dir ctx {:control-port 0})
          port (or (:actual-port ctrl-svc) (:port ctrl-svc))
          token (:token ctrl-svc)
          client (HttpClient/newHttpClient)
          n-threads 16
          requests-per-thread 5
          latch (java.util.concurrent.CountDownLatch. n-threads)
          errors-atom (atom [])
          fut-pool (java.util.concurrent.Executors/newFixedThreadPool n-threads)]
      (try
        (dotimes [t n-threads]
          (.submit fut-pool
                   ^Runnable
                   (fn []
                     (try
                       (dotimes [i requests-per-thread]
                         (let [verb (if (zero? (mod (+ t i) 2)) "status" "wait")
                               body (if (= verb "wait")
                                      "{\"cmd\":\"wait\",\"peek\":true}"
                                      "{\"cmd\":\"status\"}")
                               req (-> (HttpRequest/newBuilder)
                                       (.uri (URI/create (str "http://127.0.0.1:" port "/ctl")))
                                       (.header "Authorization" (str "Bearer " token))
                                       (.header "Content-Type" "application/json")
                                       (.POST (HttpRequest$BodyPublishers/ofString body))
                                       (.build))
                               resp (.send client req (HttpResponse$BodyHandlers/ofString))
                               status (.statusCode resp)
                               resp-body (json/read-str (.body resp))]
                           (when-not (and (= 200 status) (true? (get resp-body "ok")))
                             (swap! errors-atom conj {:thread t :status status :resp resp-body}))))
                       (catch Throwable ex
                         (swap! errors-atom conj {:thread t :error (str (class ex) " " (.getMessage ex))}))
                       (finally
                         (.countDown latch))))))
        (.await latch 15 java.util.concurrent.TimeUnit/SECONDS)
        (is (empty? @errors-atom) (str "Concurrent /ctl errors: " @errors-atom))
        (finally
          (.shutdownNow fut-pool)
          (when-let [srv (:server ctrl-svc)]
            (.stop srv 0)))))))

;; =============================================================================
;; Scenario S6: A3 Single-Responder Contract & Hook Newline Discipline (Item 12)
;; =============================================================================

(deftest test-scenario-s6-single-responder-and-newline-discipline
  (testing "split-jsonl-commands splits concatenated JSON objects without newlines"
    (let [text "{\"cmd\":\"status\"}{\"cmd\":\"identity\"}"
          chunks (cli/split-jsonl-commands text)]
      (is (= 2 (count chunks)))
      (is (= "{\"cmd\":\"status\"}" (first chunks)))
      (is (= "{\"cmd\":\"identity\"}" (second chunks))))
    (let [text-with-nl "{\"cmd\":\"status\"}\n{\"cmd\":\"wait\",\"peek\":true}"
          chunks (cli/split-jsonl-commands text-with-nl)]
      (is (= 2 (count chunks)))
      (is (= "{\"cmd\":\"status\"}" (first chunks)))
      (is (= "{\"cmd\":\"wait\",\"peek\":true}" (second chunks)))))

  (testing "read-new-cmd-file-lines! reads trailing bytes without newline if complete balanced JSON"
    (let [tmp-file (File/createTempFile "bitecho-cmd-" ".jsonl")]
      (try
        (spit tmp-file "{\"cmd\":\"status\"}{\"cmd\":\"identity\"}")
        (let [res (shell/read-new-cmd-file-lines! (.getAbsolutePath tmp-file) 0)]
          (is (= 2 (count (:lines res))))
          (is (= "{\"cmd\":\"status\"}" (first (:lines res))))
          (is (= "{\"cmd\":\"identity\"}" (second (:lines res))))
          (is (= (.length tmp-file) (:next-offset res))))
        (finally
          (.delete tmp-file)))))

  (testing "Concurrent ctl wait --peek never steals events from blocking ctl wait"
    (let [tmp-dir (str (make-tmp-dir!))
          state-file (str (io/file tmp-dir "state.fressian"))
          id (shell/load-or-create-light-identity! tmp-dir)
          st-atom (atom (-> (light-core/init-light-state id {})
                            (assoc :event-queue [{"event" "message-received" "seq" 1 "event_id" 1}])))
          cmd-lock (Object.)
          ctx {:state-atom st-atom
               :identity id
               :state-file state-file
               :cmd-lock cmd-lock
               :serve-cmd-lock cmd-lock}
          ;; 1. Peek call
          peek-res (locking cmd-lock (shell/handle-serve-line! {"cmd" "wait" "peek" true} ctx))
          _ (is (true? (get peek-res "ok")))
          _ (is (= 1 (count (get peek-res "events"))))
          _ (is (true? (get peek-res "peek")))
          ;; 2. Event queue must still contain the unread event
          _ (is (= 1 (count (:event-queue @st-atom))) "Peek MUST NOT drain the queue!")
          ;; 3. Blocking watcher consumes the event
          watch-res (locking cmd-lock (shell/handle-serve-line! {"cmd" "wait" "block" true} ctx))]
      (is (true? (get watch-res "ok")))
      (is (= 1 (count (get watch-res "events"))))
      (is (empty? (:event-queue @st-atom)) "Watcher MUST drain the event!"))))

;; =============================================================================
;; Scenario S7: Deterministic VOPR Jepsen & DataChannel Campaigns (Item 13)
;; =============================================================================

(deftest test-scenario-s7-jepsen-and-datachannel-campaigns
  (testing "JEP-01..12: Consensus and Relay Jepsen campaign verifies 0 invariant violations"
    (let [res (vopr/run-jepsen-campaign {:seed 20261113})]
      (is (true? (:ok? res)))
      (is (= 12 (:remediated-count res)))))

  (testing "DCT-01..12: DataChannel transport Jepsen campaign verifies 0 invariant violations"
    (let [res (vopr/run-datachannel-jepsen-campaign {:seed 20261115})]
      (is (true? (:ok? res)))
      (is (= 12 (:remediated-count res))))))

;; =============================================================================
;; Scenario S8: Node.js Bundle Relay E2E, Sequential FIFO Delivery, & Failover (A-CARB-D24-8)
;; =============================================================================

(deftest test-scenario-s8-node-bundle-relay-send-and-failover
  (testing "Node.js light-node bundle executes one-shot offer over HTTP relay sequentially and persists state"
    (let [tmp-dir (make-tmp-dir!)
          tls-mgr (http-shell/init-tls-manager! {:state-dir tmp-dir :domain "localhost"})
          relay-atom (atom (relay/init-relay-state {:min-signaling-burn 0}))
          relay-waiters-atom (atom {})
          cfg {:domain "bitecho.org"
               :state-dir tmp-dir
               :relay-atom relay-atom
               :relay-waiters-atom relay-waiters-atom
               :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
          srv (http-shell/start-http-servers! cfg tls-mgr nil)]
      (try
        (let [http-port (:http-port srv)
              relay-url (str "http://127.0.0.1:" http-port "/relay/v1/send")
              node-bin (or (System/getenv "NODE_BIN")
                           (let [local-node (io/file (System/getProperty "user.home") ".local/bin/node")]
                             (if (.canExecute local-node)
                               (.getAbsolutePath local-node)
                               "node")))
              bundle-file (io/file "dist/bitecho-light-node.cjs")
              _ (is (.exists bundle-file) "dist/bitecho-light-node.cjs must exist")
              peer-pk (basalt/bytes->hex (crypto/random-bytes 32))
              client-dir (make-tmp-dir!)
              pb (doto (ProcessBuilder. ^java.util.List [node-bin (.getPath bundle-file) "offer"
                                                         "--peer" peer-pk
                                                         "--price" "0"
                                                         "--burn" "100"
                                                         "--state-dir" (.getPath client-dir)
                                                         "--relay-url" relay-url])
                   (.redirectErrorStream true))
              proc (.start pb)]
          (try
            (let [out-text (slurp (.getInputStream proc))
                  exit-code (.waitFor proc)
                  res (try (json/read-str out-text) (catch Exception _ nil))
                  state-file (io/file client-dir "state.fressian")]
              (is (= 0 exit-code) (str "Node process exited non-zero: " out-text))
              (is (map? res) (str "Node output is not JSON: " out-text))
              (is (true? (get res "ok")) (str "Offer response not ok: " out-text))
              (is (.exists state-file) "state.fressian must be saved after successful relay submission")
              (is (>= (long (get-in @relay-atom [:diagnostics :submitted] 0)) 2)
                  "Relay atom must record at least 2 submitted envelopes in multi-envelope batch [reveal-env msg-env]")
              (is (pos? (count (or (get-in @relay-atom [:inboxes peer-pk])
                                   (first (vals (:inboxes @relay-atom))))))
                  "Relay recipient inbox must contain deposited offer envelope"))
            (finally
              (try (.destroyForcibly proc) (catch Exception _ nil))
              (try (.waitFor proc) (catch Exception _ nil)))))
        (finally
          (http-shell/stop-http-servers! srv))))))
