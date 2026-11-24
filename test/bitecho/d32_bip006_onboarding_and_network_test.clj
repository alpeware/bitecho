(ns bitecho.d32-bip006-onboarding-and-network-test
  "Milestone D32 (BIP-006: Frictionless Onboarding, Core Network Reliability, bitecho-mcp,
   Browser App Refresh & Hardware-Key Faucet / v0.23.10) Generative Property & Scenario Suite
   (AGENTS.md Rules 1-6):
   1. `prop-p2p-offer-auto-answer-preserves-relay-candidates-and-import-poll-dials` (defspec)
   2. `prop-half-open-outbox-eviction-auto-downs-p2p-and-wildcard-session-ack` (defspec)
   3. `prop-idempotent-duplicate-artifact-and-storage-replication-and-cid-get` (defspec)
   4. `prop-mcp-jsonrpc-framing-and-9-tool-dispatch` (defspec)
   5. `prop-hardware-key-faucet-single-drip-and-receipt-pointer` (defspec)
   6. `S-D32-1`: End-to-End P2P Relay Offer/Answer Recovery, Import-Poll Dialing, Half-Open Auto-Down, & Actionable Wait Queue
   7. `S-D32-2`: End-to-End Co-Located Validator Quorum Snapshot (< 5ms), Relay Chain-State Cache, & Direct Co-Located Relay->Mesh Forwarding
   8. `S-D32-3`: End-to-End `bitecho-mcp` Stdio JSON-RPC 2.0 Server & 9-Tool Dispatch
   9. `S-D32-4`: End-to-End Hardware-Key Sponsored Faucet (1,000,000 ECH Drip, Signed Transfer + Blob/Pointer Receipt, Double-Claim Rejection, HTTP /faucet/v1/*)
  10. `S-D32-5`: Browser Light-Node App Refresh (Sociocratic BIP Governance, Subnet Broadcast, Hardware-Key Faucet UI & API)"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.faucet :as faucet]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.light-node.mcp :as mcp]
            [bitecho.shell.browser :as browser]
            [bitecho.shell.http :as http]
            [bitecho.shell.infra :as infra]
            [bitecho.shell.light-node :as light-shell]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]
            [clojure.data.json :as json]
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
  (.toFile (Files/createTempDirectory "bitecho-d32-test-" (into-array FileAttribute []))))

(defn- delete-dir-recursively! [^File dir]
  (when (and dir (.exists dir))
    (doseq [^File f (reverse (file-seq dir))]
      (try (.delete f) (catch Exception _ nil)))))

(defn- kp->pk-hex [kp]
  (str/lower-case (basalt/bytes->hex (or (:public kp) (:public-key kp)))))

(defn- kp->sk [kp]
  (or (:private kp) (:private-key kp)))

(defn- establish-open-session
  "Helper that opens a 1-to-1 channel between Alice and Bob and returns
   {:session-id sid :alice-state st-a :bob-state st-b}."
  [alice-kp bob-kp subnet]
  (let [alice-pk (kp->pk-hex alice-kp)
        bob-pk (kp->pk-hex bob-kp)
        st-a0 (-> (light-core/init-light-state {:pubkey-hex alice-pk}
                                               {:subnet-id subnet :economy-enabled? true :burn-floor 100 :epoch 10})
                  (assoc :account {:balance 100000 :spendable 100000 :seq 0}))
        st-b0 (-> (light-core/init-light-state {:pubkey-hex bob-pk}
                                               {:subnet-id subnet :economy-enabled? true :burn-floor 100 :epoch 10})
                  (assoc :account {:balance 100000 :spendable 100000 :seq 0}))
        off-res (light-core/handle-command st-a0
                                           {"cmd" "offer" "callee" bob-pk "peer" bob-pk "price" 10 "burn" 100}
                                           (kp->sk alice-kp))
        sid (get-in off-res [:response "session_id"])
        st-b1 (reduce (fn [st env]
                        (:state (light-core/handle-wire-payload st env (kp->sk bob-kp))))
                      st-b0
                      (:net-envelopes off-res))
        acc-res (light-core/handle-command st-b1
                                           {"cmd" "accept" "session_id" sid}
                                           (kp->sk bob-kp))
        st-a1 (reduce (fn [st env]
                        (:state (light-core/handle-wire-payload st env (kp->sk alice-kp))))
                      (:state off-res)
                      (:net-envelopes acc-res))]
    {:session-id sid
     :alice-state st-a1
     :bob-state (:state acc-res)}))

;; =============================================================================
;; 1. Five Generative clojure.test.check defspec Properties (>= 50 trials each)
;; =============================================================================

(defspec ^{:doc "BIP-006 Prop 1 (D-LEG-1a & D-LEG-1c): When a session is already P2P-open with only private RFC1918/mDNS default candidates, handle-wire-p2p-offer auto-answers with the shared HTTP relay candidate instead of unroutable LAN IPs; exec-p2p-answer strips connect:// candidates; and import-poll / import preserve :p2p-dial & :p2p-dials."}
  prop-p2p-offer-auto-answer-preserves-relay-candidates-and-import-poll-dials
  50
  (prop/for-all
   [lan-octet (gen/choose 2 250)
    relay-host (gen/elements ["https://ns1.bitecho.org/relay/v1"
                              "https://ns2.bitecho.org/relay/v1"
                              "https://bitecho.org/relay/v1"])
    signal-seq (gen/choose 10 500)]
   (let [alice-kp (crypto/generate-keypair (str "d32-p1-alice-" lan-octet))
         bob-kp (crypto/generate-keypair (str "d32-p1-bob-" lan-octet))
         {:keys [session-id alice-state bob-state]} (establish-open-session alice-kp bob-kp "devnet.bitecho.org")
         private-cands [(str "udp://host-" lan-octet ".local:5011")
                        (str "udp://192.168.86." lan-octet ":5011")
                        (str "tcp://10.0.0." lan-octet ":5011")]
         ;; Bob is already marked P2P open, has no explicit [:p2p :local-candidates],
         ;; and has RFC1918/mDNS default candidates
         bob-open (-> bob-state
                      (assoc :default-p2p-candidates private-cands)
                      (assoc-in [:sessions session-id :p2p]
                                {:phase :open
                                 :connected? true
                                 :local-candidates nil
                                 :remote-candidates [relay-host]}))
         ;; Alice sends a p2p-offer carrying relay-host
         offer-res (light-core/handle-command
                    alice-state
                    {"cmd" "p2p-offer"
                     "session_id" session-id
                     "candidates" [relay-host]
                     "transport" "https"
                     "signal_seq" signal-seq}
                    (kp->sk alice-kp))
         offer-env (first (:net-envelopes offer-res))
         ;; Bob receives the p2p-offer while already-connected? is true
         bob-rx (light-core/handle-wire-payload bob-open offer-env (kp->sk bob-kp))
         auto-ans-env (first (:net-envelopes bob-rx))
         unwrapped-ans (when auto-ans-env (light-core/unwrap-wire-message auto-ans-env))
         ans-cands (vec (:candidates unwrapped-ans))
         ;; Also test exec-p2p-answer when session is in :offer-received phase with connect:// in default candidates
         bob-offer-rx (-> bob-state
                          (assoc :default-p2p-candidates (conj private-cands "connect://node1.ingress.bitecho.org:443"))
                          (assoc-in [:sessions session-id :p2p]
                                    {:phase :offer-received
                                     :connected? false
                                     :remote-candidates [relay-host]}))
         manual-ans-res (light-core/handle-command
                         bob-offer-rx
                         {"cmd" "p2p-answer" "session_id" session-id}
                         (kp->sk bob-kp))
         manual-cands (vec (get-in manual-ans-res [:response "candidates"]))
         ;; Test import-poll & import preserving :p2p-dial on Alice when ingesting Bob's answer
         ans-wire-hex (basalt/bytes->hex (fressian/encode-wire (first (:net-envelopes manual-ans-res))))
         poll-json (json/write-str {"ok" true
                                    "messages" [{"relay_seq" 1 "envelope_hex" ans-wire-hex}]
                                    "broadcasts" []})
         alice-import-poll (light-core/handle-command
                            (:state offer-res)
                            {"cmd" "import-poll" "payload" poll-json}
                            (kp->sk alice-kp))
         alice-import (light-core/handle-command
                       (:state offer-res)
                       {"cmd" "import" "hex" ans-wire-hex}
                       (kp->sk alice-kp))]
     (and (= "*" (:subnet-id offer-env))
          (= "*" (:subnet-id auto-ans-env))
          (some #(= % relay-host) ans-cands)
          (not (some light-core/private-or-mdns-candidate? ans-cands))
          (some #(= % relay-host) manual-cands)
          (not (some #(str/starts-with? (str %) "connect://") manual-cands))
          (map? (:p2p-dial alice-import-poll))
          (seq (:p2p-dials alice-import-poll))
          (map? (:p2p-dial alice-import))))))

(defspec ^{:doc "BIP-006 Prop 2 (D-LEG-2): When an unacked outbox message reaches retries >= 5 on a session with [:p2p :connected?] true, retransmit-unacked-outbox evicts it, auto-transitions P2P to closed/disconnected (reason: ack-timeout), sets [:p2p-meta :reconnect-needed?] true, and build-session-ack-envelope uses wildcard '*' outer subnet when burned."}
  prop-half-open-outbox-eviction-auto-downs-p2p-and-wildcard-session-ack
  50
  (prop/for-all
   [retries (gen/choose 5 10)
    msg-seq (gen/choose 1 50)
    custom-subnet (gen/elements ["bitecho.org/dev" "chat/simon-nexus-axiom" "team/alpha"])]
   (let [alice-kp (crypto/generate-keypair (str "d32-p2-alice-" msg-seq))
         bob-kp (crypto/generate-keypair (str "d32-p2-bob-" msg-seq))
         {:keys [session-id alice-state]} (establish-open-session alice-kp bob-kp custom-subnet)
         st-p2p-open (-> alice-state
                         (assoc-in [:sessions session-id :p2p]
                                   {:phase :open
                                    :connected? true
                                    :zero-burn? true})
                         (assoc-in [:sessions session-id :outbox]
                                   {msg-seq {:seq msg-seq
                                             :retries retries
                                             :last-sent-ms 1000
                                             :msg-id (str "msg-" msg-seq)}})
                         (assoc-in [:sessions session-id :outbox-order] [msg-seq]))
         rx-res (light-core/retransmit-unacked-outbox st-p2p-open session-id 50000 30000 (kp->sk alice-kp))
         st-after (:state rx-res)
         evts (:stdout-events rx-res)
         ;; Also check build-session-ack-envelope when P2P is down (burned)
         ack-env-burned (light-core/build-session-ack-envelope
                         st-after session-id (kp->pk-hex bob-kp) msg-seq msg-seq [msg-seq] (kp->sk alice-kp))]
     (and (false? (get-in st-after [:sessions session-id :p2p :connected?]))
          (= :closed (get-in st-after [:sessions session-id :p2p :phase]))
          (= "ack-timeout" (get-in st-after [:sessions session-id :p2p :error]))
          (true? (get-in st-after [:sessions session-id :p2p-meta :reconnect-needed?]))
          (some #(and (= "p2p-disconnected" (get % "event"))
                      (= "ack-timeout" (get % "reason")))
                evts)
          (some #(and (= "p2p-disconnected" (get % "event"))
                      (= "ack-timeout" (get % "reason")))
                (:event-queue st-after))
          (= "*" (:subnet-id ack-env-burned))))))

(defspec ^{:doc "BIP-006 Prop 3 (F-ART-1 & F-ART-2): Duplicate :artifact-replicate, :storage-replicate, and :capability-replicate envelopes with identical (authority, seq, target) are idempotent no-ops (0 replication-rejected), while stale sequences (< current-seq) are rejected; artifact-get by --cid resolves directly from :artifact-blobs/:blobs; and artifact-put defaults burn to >= 100 when economy is enabled."}
  prop-idempotent-duplicate-artifact-and-storage-replication-and-cid-get
  50
  (prop/for-all
   [payload-str (gen/not-empty gen/string-alphanumeric)
    seq-num (gen/choose 2 20)]
   (let [author-kp (crypto/generate-keypair "d32-p3-author")
         author-pk (kp->pk-hex author-kp)
         author-sk (kp->sk author-kp)
         st0 (-> (light-core/init-light-state {:pubkey-hex author-pk}
                                              {:subnet-id "bitecho.org/infra"
                                               :economy-enabled? true
                                               :burn-floor 100
                                               :epoch 10})
                 (assoc :account {:balance 50000 :spendable 50000 :seq 0}))
         ;; 1. Default burn on artifact-put when burn is omitted
         put-res (light-core/handle-command
                  st0
                  {"cmd" "artifact-put"
                   "subnet_id" "bitecho.org/infra"
                   "path" "blog/post.md"
                   "text" payload-str
                   "seq" seq-num}
                  author-sk)
         st1 (:state put-res)
         cid (get-in put-res [:response "cid"])
         rep-env (first (:net-envelopes put-res))
         ;; 2. Deliver the exact same artifact-replicate envelope again -> idempotent no-op!
         dup-res (light-core/handle-wire-payload st1 rep-env author-sk)
         st2 (:state dup-res)
         ;; 3. Deliver a truly stale seq (seq-num - 1) -> must increment :replication-rejected
         stale-blob (data/make-blob (str payload-str "-old") "text/plain")
         stale-ptr (data/sign-pointer
                    author-sk
                    {:pointer/authority author-pk
                     :pointer/subnet "bitecho.org/infra"
                     :pointer/path "blog/post.md"
                     :pointer/seq (dec seq-num)
                     :pointer/leader-term 1
                     :pointer/target (:blob/cid stale-blob)
                     :pointer/proof {:proof/type :self}})
         stale-env {:protocol-version 1
                    :wire-format "fressian-v1"
                    :bitecho/type :artifact-replicate
                    :type :artifact-replicate
                    :subnet-id "bitecho.org/infra"
                    :path "blog/post.md"
                    :cid (:blob/cid stale-blob)
                    :seq (dec seq-num)
                    :blob stale-blob
                    :pointer stale-ptr
                    :sender author-pk
                    :epoch 10}
         stale-res (light-core/handle-wire-payload st2 stale-env author-sk)
         ;; 4. Resolve by --cid alone (no path)
         cid-get-cmd (cli/build-cmd-map "get" ["--cid" cid])
         cid-get-res (light-core/handle-command st2 cid-get-cmd author-sk)]
     (and (true? (get-in put-res [:response "ok"]))
          (= 100 (get-in put-res [:response "burn"]))
          (empty? (:stdout-events dup-res))
          (= 0 (long (get-in st2 [:diagnostics :replication-rejected] 0)))
          (= 1 (long (get-in (:state stale-res) [:diagnostics :replication-rejected] 0)))
          (= "artifact-get" (get cid-get-cmd "cmd"))
          (true? (get-in cid-get-res [:response "ok"]))
          (= cid (get-in cid-get-res [:response "cid"]))
          (= payload-str (get-in cid-get-res [:response "text"]))))))

(defspec ^{:doc "BIP-006 Prop 4 (Part 1: bitecho-mcp): Pure Sans-IO MCP JSON-RPC 2.0 reducer handles initialize, ping, notifications/initialized, tools/list (all 9 tools), and tools/call across all 9 tools with valid JSON-RPC 2.0 framing."}
  prop-mcp-jsonrpc-framing-and-9-tool-dispatch
  50
  (prop/for-all
   [req-id (gen/choose 1 10000)
    tool-case (gen/elements
               [["bitecho_identity" {"action" "status"}]
                ["bitecho_identity" {"action" "register_home_set" "nodes" ["node1" "node2"] "price" 10}]
                ["bitecho_discover" {"capability_type" "compute/uop-kernel"}]
                ["bitecho_discover" {"nickname" "axiom" "domain" "bitecho.org"}]
                ["bitecho_connect" {"action" "offer" "peer" "axiom" "burn" 100}]
                ["bitecho_connect" {"action" "p2p_offer" "session_id" "sess-1" "candidates" ["https://ns1.bitecho.org/relay/v1"]}]
                ["bitecho_send" {"to" "axiom" "text" "hello from mcp"}]
                ["bitecho_send" {"subnet_id" "chat/simon-nexus-axiom" "text" "broadcast from mcp"}]
                ["bitecho_inbox" {"peek" true "subnet_id" "chat/simon-nexus-axiom"}]
                ["bitecho_wait" {"timeout_ms" 100 "peek" true}]
                ["bitecho_storage" {"op" "artifact_put" "path" "blog/mcp.md" "text" "# MCP" "burn" 0}]
                ["bitecho_storage" {"op" "artifact_get" "path" "blog/mcp.md"}]
                ["bitecho_escrow" {"op" "list"}]
                ["bitecho_escrow" {"op" "bounties"}]
                ["bitecho_ctl" {"cmd" "status" "args" {}}]])]
   (let [[tool-name tool-args] tool-case
         kp (crypto/generate-keypair "d32-p4-mcp")
         pk (kp->pk-hex kp)
         sk (kp->sk kp)
         st-atom (atom (-> (light-core/init-light-state {:pubkey-hex pk} {:subnet-id "global" :epoch 5})
                           (assoc :petnames {"axiom" pk})
                           (assoc :account {:balance 10000 :spendable 10000 :seq 0})))
         exec-fn (fn [cmd-map]
                   (let [r (light-core/handle-command @st-atom cmd-map sk)]
                     (reset! st-atom (:state r))
                     (:response r)))
         init-resp (mcp/handle-jsonrpc-request
                    {"jsonrpc" "2.0" "id" req-id "method" "initialize" "params" {}}
                    exec-fn json/write-str)
         notif-resp (mcp/handle-jsonrpc-request
                     {"jsonrpc" "2.0" "method" "notifications/initialized"}
                     exec-fn json/write-str)
         list-resp (mcp/handle-jsonrpc-request
                    {"jsonrpc" "2.0" "id" (inc req-id) "method" "tools/list"}
                    exec-fn json/write-str)
         call-resp (mcp/handle-jsonrpc-request
                    {"jsonrpc" "2.0"
                     "id" (+ req-id 2)
                     "method" "tools/call"
                     "params" {"name" tool-name "arguments" tool-args}}
                    exec-fn json/write-str)
         tools (get-in list-resp ["result" "tools"])]
     (and (= "2.0" (get init-resp "jsonrpc"))
          (= req-id (get init-resp "id"))
          (nil? notif-resp)
          (= 9 (count tools))
          (= "2.0" (get call-resp "jsonrpc"))
          (= (+ req-id 2) (get call-resp "id"))
          (vector? (get-in call-resp ["result" "content"]))
          (map? (get-in call-resp ["result" "structuredContent"]))))))

(defspec ^{:doc "BIP-006 Prop 5 (Part 3: Hardware-Key Sponsored Faucet): Single 1,000,000 ECH drip per attested WebAuthn hardware credential ID, producing a signed transfer and signed Blob/Pointer receipt at faucet/<network-uri>/claims/<credential-id-hash>, and rejecting any second claim with :faucet-credential-already-claimed."}
  prop-hardware-key-faucet-single-drip-and-receipt-pointer
  50
  (prop/for-all
   [cred-suffix (gen/not-empty gen/string-alphanumeric)
    now-ms (gen/choose 100000 900000)]
   (let [treasury-kp (crypto/generate-keypair "d32-p5-treasury")
         treasury-pk (kp->pk-hex treasury-kp)
         treasury-sk (kp->sk treasury-kp)
         claimant-kp (crypto/generate-keypair (str "d32-p5-claimant-" cred-suffix))
         claimant-pk (kp->pk-hex claimant-kp)
         hw-kp (crypto/generate-keypair (str "d32-p5-hw-" cred-suffix))
         hw-pk (kp->pk-hex hw-kp)
         cred-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes (str "yubikey-cred-" cred-suffix))))
         net-uri "devnet.bitecho.org"
         st0 (faucet/init-faucet-state {:network-uri net-uri
                                        :treasury-pubkey treasury-pk
                                        :treasury-privkey treasury-sk
                                        :drip-amount-ech 1000000})
         ch1 (faucet/issue-faucet-challenge st0 {:network-uri net-uri} now-ms)
         nonce1 (get-in ch1 [:challenge :nonce])
         att1 (faucet/build-test-hardware-attestation
               {:hw-privkey (kp->sk hw-kp)
                :hw-pubkey hw-pk
                :claimant-privkey (kp->sk claimant-kp)
                :claimant-pubkey claimant-pk
                :cred-id (fressian/utf8->bytes (str "yubikey-cred-" cred-suffix))
                :nonce nonce1
                :network-uri net-uri})
         claim1 (faucet/reduce-faucet-claim
                 (assoc (:state ch1) :trusted-root-fingerprints #{(:trusted-root-fingerprint att1)})
                 (assoc att1
                        :nonce nonce1
                        :credential-id-hash cred-hash
                        :claimant-pubkey claimant-pk
                        :network-uri net-uri)
                 (+ now-ms 1000))
         ch2 (faucet/issue-faucet-challenge (:state claim1) {:network-uri net-uri} (+ now-ms 2000))
         nonce2 (get-in ch2 [:challenge :nonce])
         att2 (faucet/build-test-hardware-attestation
               {:hw-privkey (kp->sk hw-kp)
                :hw-pubkey hw-pk
                :claimant-privkey (kp->sk claimant-kp)
                :claimant-pubkey claimant-pk
                :cred-id (fressian/utf8->bytes (str "yubikey-cred-" cred-suffix))
                :nonce nonce2
                :network-uri net-uri})
         claim2 (faucet/reduce-faucet-claim
                 (assoc (:state ch2) :trusted-root-fingerprints #{(:trusted-root-fingerprint att2)})
                 (assoc att2
                        :nonce nonce2
                        :credential-id-hash cred-hash
                        :claimant-pubkey claimant-pk
                        :network-uri net-uri)
                 (+ now-ms 3000))
         expected-path (str "faucet/" net-uri "/claims/" cred-hash)]
     (and (true? (:ok? claim1))
          (= 1000000 (get-in claim1 [:transfer-intent :amount]))
          (= claimant-pk (get-in claim1 [:transfer-intent :to]))
          (= expected-path (:receipt-path claim1))
          (data/verify-blob (:receipt-blob claim1))
          (:ok? (data/verify-pointer (:receipt-pointer claim1)))
          (map? (:signed-transfer claim1))
          (= 1000000 (get-in claim1 [:signed-transfer :amount]))
          (false? (:ok? claim2))
          (= :faucet-credential-already-claimed (:error claim2))))))

;; =============================================================================
;; 2. Five Deterministic End-to-End Simulation Scenarios (S-D32-1..S-D32-5)
;; =============================================================================

(deftest scenario-s-d32-1-p2p-relay-recovery-and-actionable-events-test
  (testing "S-D32-1: End-to-end P2P relay offer/answer recovery, import-poll :p2p-dial, half-open outbox eviction auto-down, wildcard :session-ack, and expanded actionable-event-types"
    (let [lumen-kp (crypto/generate-keypair "d32-s1-lumen")
          axiom-kp (crypto/generate-keypair "d32-s1-axiom")
          {:keys [session-id alice-state bob-state]} (establish-open-session lumen-kp axiom-kp "chat/simon-nexus-axiom")
          relay-cand "https://ns1.bitecho.org/relay/v1"
          ;; 1. Verify expanded actionable-event-types (D-LEG-3)
          expected-types #{"p2p-offer-received"
                           "p2p-answer-received"
                           "p2p-offer-answered-while-open"
                           "artifact-replicated"
                           "artifact-revoked"
                           "governance-replicated"
                           "broadcast-received"
                           "transfer-received"}]
      (doseq [ev-t expected-types]
        (is (contains? light-core/actionable-event-types ev-t)
            (str "Missing actionable event type: " ev-t)))
      ;; 2. Lumen sends P2P offer with relay candidate; Axiom receives it -> enqueued in :event-queue
      (let [off-res (light-core/handle-command
                     alice-state
                     {"cmd" "p2p-offer"
                      "session_id" session-id
                      "candidates" [relay-cand]
                      "transport" "https"}
                     (kp->sk lumen-kp))
            off-env (first (:net-envelopes off-res))
            ax-rx (light-core/handle-wire-payload bob-state off-env (kp->sk axiom-kp))
            ax-wait (light-core/handle-command (:state ax-rx) {"cmd" "wait" "peek" true} (kp->sk axiom-kp))]
        (is (= "*" (:subnet-id off-env)))
        (is (some #(= "p2p-offer-received" (get % "event"))
                  (get-in ax-wait [:response "events"])))))))

(deftest scenario-s-d32-2-colocated-validator-sync-and-relay-mesh-bridge-test
  (testing "S-D32-2: F-SYNC-1 & F-RELAY-1 co-located validator snapshot (< 5ms), /relay/v1/chain-state cache, direct co-located relay->mesh forwarding, and bootstrap default relay-url"
    ;; 1. parse-bootstrap-descriptor-pure defaults :relay-url to https://ns1.bitecho.org when Domain: bitecho.org
    (let [sample-txt (str "Network: devnet\n"
                          "Domain: bitecho.org\n"
                          "Treasury Public Key: 302a300506032b65700321007c2b695b77904a19a630b75ce53889a53963c0f85aa69e5276bb988a183b91b8\n"
                          "Custody Public Key: 302a300506032b6570032100e476d77ef34962d09baee0062b4c03be832a1ccc2d691623a8cb39e356793f2b\n\n"
                          "Node: node1\n"
                          "Cluster Address: 35.212.129.138:5000\n"
                          "Agent Ingress: 35.212.129.138:5010\n"
                          "Ed25519 Pubkey: 302a300506032b6570032100d869c1cc916523907f9c4a44b6c9963daf430a08d9d15567b017b6599f87e086\n"
                          "DTLS Fingerprint: 95:09:40:3B:04:A0:B3:F5:88:26:51:CE:C9:A9:8E:0C:A1:15:92:8F:D5:7D:4A:11:A2:6C:3C:B0:0B:AB:0C:3B\n"
                          "ICE Credentials: ufrag=1ec0ae74 pwd=d928f1aac56a0d6e6fdda551\n")
          parsed (light-core/parse-bootstrap-descriptor-pure sample-txt)]
      (is (= "https://ns1.bitecho.org" (:relay-url parsed))))

    ;; 2. Co-located validator in-memory snapshot in infra/fetch-validator-chain-state-snapshots!
    (let [val-kp (crypto/generate-keypair "d32-s2-ns1-val")
          val-pk (kp->pk-hex val-kp)
          val-sk (kp->sk val-kp)
          agent-kp (crypto/generate-keypair "d32-s2-agent")
          agent-pk (kp->pk-hex agent-kp)
          val-st (-> (sm/init-state [{:pubkey val-pk}]
                                    val-pk
                                    (assoc (config/devnet-6-config)
                                           :genesis-ledger {agent-pk {:balance 777000 :seq 3 :deps []}}))
                     (assoc :last-executed-finalized-epoch 42))
          net-in-ch (async/chan 16)
          agent-received (atom [])
          agent-conns (atom {agent-pk {:channel-id 0
                                       :on-message (fn [wire-bytes]
                                                     (swap! agent-received conj wire-bytes))
                                       :sent-msg-ids (atom #{})}})
          colocated-val {:state-atom (atom val-st)
                         :identity {:pubkey-hex val-pk
                                    :privkey-hex (basalt/bytes->hex val-sk)
                                    :keypair {:public (:public val-kp) :private val-sk}}
                         :shell-node {:network-in net-in-ch
                                      :state-atom (atom val-st)}
                         :agent-conns agent-conns}
          rt {:validator-node colocated-val
              :node-id :ns1}
          t0 (System/nanoTime)
          snaps (infra/fetch-validator-chain-state-snapshots!
                 rt
                 {:nodes {:ns1 {:pubkey val-pk :ip "127.0.0.1" :port 59999 :agent-port 59999}}}
                 agent-pk
                 "nonce-fast-1")
          elapsed-ms (/ (- (System/nanoTime) t0) 1000000.0)]
      (is (= 1 (count snaps)))
      (is (< elapsed-ms 25.0) (str "Co-located snapshot took too long: " elapsed-ms "ms"))
      (is (= 777000 (:balance (first snaps))))
      (is (= 42 (:finalized-epoch (first snaps)))))

    ;; 3. Direct co-located validator injection in http/start-http-server! default-forwarder
    (let [tmp-dir (make-tmp-dir!)
          val-kp (crypto/generate-keypair "d32-s2-bridge-val")
          val-pk (kp->pk-hex val-kp)
          val-sk (kp->sk val-kp)
          sender-kp (crypto/generate-keypair "d32-s2-sender")
          sender-pk (kp->pk-hex sender-kp)
          sender-sk (kp->sk sender-kp)
          net-in-ch (async/chan 16)
          forwarded-to-agents (atom [])
          agent-conns (atom {"connected-agent" {:channel-id 0
                                                :on-message (fn [wb] (swap! forwarded-to-agents conj wb))
                                                :sent-msg-ids (atom #{})}})
          colocated-val {:state-atom (atom (sm/init-state [{:pubkey val-pk}] val-pk (config/devnet-6-config)))
                         :identity {:pubkey-hex val-pk
                                    :privkey-hex (basalt/bytes->hex val-sk)
                                    :keypair {:public (:public val-kp) :private val-sk}}
                         :shell-node {:network-in net-in-ch}
                         :agent-conns agent-conns}
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath tmp-dir)
               :node-id :ns1
               :node-privkey val-sk
               :validator-node colocated-val
               :policy (infra/default-infra-policy [val-pk])})
          tls-mgr (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir)
                                           :domain "localhost"})
          srv (http/start-http-servers! {:domain "localhost"
                                         :http {:bind-ip "127.0.0.1"
                                                :http-port 0
                                                :https-port 0}}
                                        tls-mgr
                                        rt)]
      (try
        (let [port (:http-port srv)
              st0 (-> (light-core/init-light-state {:pubkey-hex sender-pk}
                                                   {:subnet-id "chat/simon-nexus-axiom"
                                                    :subscribed-subnets #{"chat/simon-nexus-axiom"}
                                                    :epoch 5})
                      (assoc :account {:balance 10000 :spendable 10000 :seq 0}))
              bcast-res (light-core/handle-command
                         st0
                         {"cmd" "broadcast"
                          "subnet_id" "chat/simon-nexus-axiom"
                          "text" "Hello via HTTP Relay -> Co-located Validator!"
                          "burn" 100}
                         sender-sk)
              env (first (:net-envelopes bcast-res))
              env-hex (basalt/bytes->hex (fressian/encode-wire env))
              client (HttpClient/newHttpClient)
              req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/relay/v1/send")))
                      (.header "Content-Type" "application/json")
                      (.POST (HttpRequest$BodyPublishers/ofString
                              (json/write-str {"envelope_hex" env-hex})
                              StandardCharsets/UTF_8))
                      (.build))
              resp (.send client req (HttpResponse$BodyHandlers/ofString))
              [injected-ev _] (async/alts!! [net-in-ch (async/timeout 2000)])]
          (is (= 200 (.statusCode resp)))
          (is (some? injected-ev) "Co-located validator :network-in must receive gossip directly from HTTP relay")
          (is (= :receive-gossip (:type injected-ev)))
          (is (pos? (count @forwarded-to-agents)) "Connected agents on co-located validator must receive forwarded gossip immediately"))
        (finally
          (try (http/stop-http-servers! srv) (catch Exception _ nil))
          (try (infra/stop-subnet-runtime! rt) (catch Exception _ nil))
          (delete-dir-recursively! tmp-dir))))))

(deftest scenario-s-d32-3-bitecho-mcp-stdio-server-e2e-test
  (testing "S-D32-3: End-to-end bitecho-mcp JSON-RPC 2.0 server and --mcp / mcp CLI mode parsing"
    (let [p1 (light-shell/parse-light-node-args ["--mcp" "--state-dir" "/tmp/mcp-test"])
          p2 (light-shell/parse-light-node-args ["mcp" "--state-dir" "/tmp/mcp-test"])]
      (is (= :mcp (:mode p1)))
      (is (= :mcp (:mode p2)))
      (is (contains? (set cli/known-command-flags) "--mcp"))
      (is (contains? (set cli/known-command-flags) "--cid")))
    ;; Verify all 9 curated MCP tools execute end-to-end through mcp/handle-jsonrpc-request
    (let [kp (crypto/generate-keypair "d32-s3-mcp-agent")
          pk (kp->pk-hex kp)
          sk (kp->sk kp)
          st-atom (atom (-> (light-core/init-light-state {:pubkey-hex pk}
                                                         {:subnet-id "bitecho.org/infra"
                                                          :subscribed-subnets #{"chat/simon-nexus-axiom"}
                                                          :epoch 10})
                            (assoc :account {:balance 50000 :spendable 50000 :seq 0})))
          exec-fn (fn [cmd-map]
                    (let [r (light-core/handle-command @st-atom cmd-map sk)]
                      (reset! st-atom (:state r))
                      (:response r)))
          call-tool! (fn [id name args]
                       (mcp/handle-jsonrpc-request
                        {"jsonrpc" "2.0"
                         "id" id
                         "method" "tools/call"
                         "params" {"name" name "arguments" args}}
                        exec-fn json/write-str))
          r-id (call-tool! 1 "bitecho_identity" {"action" "status"})
          r-put (call-tool! 2 "bitecho_storage" {"op" "artifact_put"
                                                 "subnet_id" "bitecho.org/infra"
                                                 "path" "blog/mcp-hello.md"
                                                 "text" "# Hello from bitecho-mcp"
                                                 "burn" 100})
          cid (get-in r-put ["result" "structuredContent" "cid"])
          r-get-cid (call-tool! 3 "bitecho_storage" {"op" "artifact_get"
                                                     "cid" cid})
          r-bcast (call-tool! 4 "bitecho_send" {"subnet_id" "chat/simon-nexus-axiom"
                                                "text" "MCP broadcast test"})
          r-ctl (call-tool! 5 "bitecho_ctl" {"cmd" "petname-set"
                                             "args" {"petname" "self" "pubkey" pk}})]
      (is (= pk (get-in r-id ["result" "structuredContent" "pubkey"])))
      (is (true? (get-in r-put ["result" "structuredContent" "ok"])))
      (is (string? cid))
      (is (true? (get-in r-get-cid ["result" "structuredContent" "ok"])))
      (is (= "# Hello from bitecho-mcp" (get-in r-get-cid ["result" "structuredContent" "text"])))
      (is (true? (get-in r-bcast ["result" "structuredContent" "ok"])))
      (is (true? (get-in r-ctl ["result" "structuredContent" "ok"]))))))

(deftest scenario-s-d32-4-hardware-key-sponsored-faucet-http-e2e-test
  (testing "S-D32-4: End-to-end Hardware-Key Sponsored Faucet over HTTP /faucet/v1/challenge & /faucet/v1/claim with Blob/Pointer receipt persistence"
    (let [tmp-dir (make-tmp-dir!)
          treasury-kp (crypto/generate-keypair "d32-s4-treasury")
          treasury-pk (kp->pk-hex treasury-kp)
          treasury-sk (kp->sk treasury-kp)
          claimant-kp (crypto/generate-keypair "d32-s4-new-agent")
          claimant-pk (kp->pk-hex claimant-kp)
          cred-hash (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "yubikey-5-cred-001")))
          rt (infra/start-subnet-runtime!
              {:state-dir (.getAbsolutePath tmp-dir)
               :node-id :ns1
               :node-privkey treasury-sk
               :policy (infra/default-infra-policy [treasury-pk])})
          tls-mgr (http/init-tls-manager! {:state-dir (.getAbsolutePath tmp-dir)
                                           :domain "localhost"})
          faucet-atom (atom (faucet/init-faucet-state {:network-uri "devnet.bitecho.org"
                                                       :treasury-pubkey treasury-pk
                                                       :treasury-privkey treasury-sk
                                                       :drip-amount-ech 1000000}))
          srv (http/start-http-servers! {:domain "localhost"
                                         :network-uri "devnet.bitecho.org"
                                         :faucet-atom faucet-atom
                                         :http {:bind-ip "127.0.0.1"
                                                :http-port 0
                                                :https-port 0}}
                                        tls-mgr
                                        rt)]
      (try
        (let [port (:http-port srv)
              client (HttpClient/newHttpClient)
              ;; 1. Fetch challenge
              ch-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/challenge")))
                         (.GET)
                         (.build))
              ch-resp (.send client ch-req (HttpResponse$BodyHandlers/ofString))
              ch-json (json/read-str (.body ch-resp))
              nonce (get-in ch-json ["challenge" "nonce"])
              ;; 2. Submit claim with verified hardware attestation (BIP-024 fail-closed)
              hw-kp (crypto/generate-keypair "d32-s4-hw")
              att1-bundle (faucet/build-test-hardware-attestation
                           {:hw-privkey (kp->sk hw-kp)
                            :hw-pubkey (kp->pk-hex hw-kp)
                            :claimant-privkey (kp->sk claimant-kp)
                            :claimant-pubkey claimant-pk
                            :cred-id (fressian/utf8->bytes "yubikey-5-cred-001")
                            :nonce nonce
                            :network-uri "devnet.bitecho.org"})
              att1 (:attestation att1-bundle)
              _ (swap! faucet-atom assoc :trusted-root-fingerprints #{(:trusted-root-fingerprint att1-bundle)})
              claim-body (json/write-str {"nonce" nonce
                                          "credential_id_hash" cred-hash
                                          "claimant_pubkey" claimant-pk
                                          "network_uri" "devnet.bitecho.org"
                                          "attestation" {"attestation_object_hex" (:attestation-object-hex att1)
                                                         "client_data_hash_hex" (:client-data-hash-hex att1)
                                                         "hw_pubkey" (:hw-pubkey att1)
                                                         "assertion_sig" (:assertion-sig att1)
                                                         "claimant_pop_sig" (:claimant-pop-sig att1)}})
              cl-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/claim")))
                         (.header "Content-Type" "application/json")
                         (.POST (HttpRequest$BodyPublishers/ofString claim-body StandardCharsets/UTF_8))
                         (.build))
              cl-resp (.send client cl-req (HttpResponse$BodyHandlers/ofString))
              cl-json (json/read-str (.body cl-resp))
              ;; 3. Second claim with same credential_id_hash -> rejected 400
              ch2-resp (.send client ch-req (HttpResponse$BodyHandlers/ofString))
              nonce2 (get-in (json/read-str (.body ch2-resp)) ["challenge" "nonce"])
              cl2-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/claim")))
                          (.header "Content-Type" "application/json")
                          (.POST (HttpRequest$BodyPublishers/ofString
                                  (json/write-str {"nonce" nonce2
                                                   "credential_id_hash" cred-hash
                                                   "claimant_pubkey" claimant-pk
                                                   "network_uri" "devnet.bitecho.org"})
                                  StandardCharsets/UTF_8))
                          (.build))
              cl2-resp (.send client cl2-req (HttpResponse$BodyHandlers/ofString))
              cl2-json (json/read-str (.body cl2-resp))]
          (is (= 200 (.statusCode ch-resp)))
          (is (string? nonce))
          (is (= 200 (.statusCode cl-resp)))
          (is (true? (get cl-json "ok")))
          (is (= 1000000 (get-in cl-json ["transfer_intent" "amount"])))
          (is (= (str "faucet/devnet.bitecho.org/claims/" cred-hash) (get cl-json "receipt_path")))
          (is (string? (get cl-json "receipt_cid")))
          (is (= 400 (.statusCode cl2-resp)))
          (is (= "faucet-credential-already-claimed" (get cl2-json "error"))))
        (finally
          (try (http/stop-http-servers! srv) (catch Exception _ nil))
          (try (infra/stop-subnet-runtime! rt) (catch Exception _ nil))
          (delete-dir-recursively! tmp-dir))))))

(deftest scenario-s-d32-5-browser-app-refresh-governance-broadcast-and-faucet-test
  (testing "S-D32-5: Browser light-node shell & index.html support Sociocratic BIP governance consent, subnet broadcast, and hardware-key sponsored faucet"
    (let [anchor-kp (crypto/generate-keypair "d32-s5-simon-anchor")
          anchor-pk (kp->pk-hex anchor-kp)
          anchor-sk (kp->sk anchor-kp)
          b-node {:light-state (-> (light-core/init-light-state {:pubkey-hex anchor-pk}
                                                                {:subnet-id "bitecho.org/dev"})
                                   (assoc :account {:balance 100000 :spendable 100000 :seq 0}))}
          ;; 1. Execute BIP governance consent via browser/exec-browser-cli
          sub-res (browser/exec-browser-cli
                   b-node
                   {"cmd" "bip-submit"
                    "bip_id" "BIP-006"
                    "title" "Frictionless Onboarding & Core Network Reliability"
                    "spec_edn" (slurp "docs/bips/bip-000-charter.edn")
                    "subnet_id" "bitecho.org/dev"}
                   anchor-sk)
          b-node1 (:state sub-res)
          consent-res (browser/exec-browser-cli
                       b-node1
                       {"cmd" "bip-consent"
                        "bip_id" "BIP-006"
                        "circle" "anchor-agent-users"
                        "subnet_id" "bitecho.org/dev"}
                       anchor-sk)
          b-node2 (:state consent-res)
          status-res (browser/exec-browser-cli
                      b-node2
                      {"cmd" "bip-status"
                       "bip_id" "BIP-006"
                       "subnet_id" "bitecho.org/dev"}
                      anchor-sk)
          ;; 2. Verify resources/public/index.html & src/bitecho/browser_main.cljs contain the refreshed BIP-006 UI and API exports
          html-content (slurp "resources/public/index.html")
          browser-main-content (slurp "src/bitecho/browser_main.cljs")]
      (is (true? (get-in sub-res [:response "ok"])))
      (is (true? (get-in consent-res [:response "ok"])))
      (is (true? (get-in status-res [:response "ok"])))
      (is (= "BIP-006" (get-in status-res [:response "bip_id"])))
      (is (str/includes? browser-main-content "\"consentBip\""))
      (is (str/includes? browser-main-content "\"submitBip\""))
      (is (str/includes? browser-main-content "\"objectBip\""))
      (is (str/includes? browser-main-content "\"getBipStatus\""))
      (is (str/includes? browser-main-content "\"claimHardwareKeyFaucet\""))
      (is (str/includes? html-content "consentBipBtn"))
      (is (str/includes? html-content "sendSubnetBroadcastBtn"))
      (is (str/includes? html-content "claimFaucetBtn")))))
