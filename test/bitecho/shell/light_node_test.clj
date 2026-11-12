(ns bitecho.shell.light-node-test
  "Unit, integration, and E2E tests for the Bitecho light-node boundary shell."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.agent-sim :as agent-sim]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.light-node :as light-shell]
            [bitecho.shell.mesh :as mesh]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.api :as api]
            [datachannel.core :as dc-core]
            [datachannel.mdns :as mdns]
            [taoensso.nippy :as nippy])
  (:import [java.io PrintWriter StringWriter]
           [java.net ServerSocket Socket]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]
           [java.util Base64]))

(defn- sample-pubkey-hex
  "Returns an 88-character SubjectPublicKeyInfo hex string for testing."
  []
  (basalt/bytes->hex (:public (crypto/generate-keypair))))

;; -----------------------------------------------------------------------------
;; 1. Identity Lifecycle & Fail-Fast Corrupt Test
;; -----------------------------------------------------------------------------

(deftest test-identity-lifecycle-and-failfast-corrupt
  (testing "Identity creation, idempotence, and fail-fast corruption detection"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-id" (into-array FileAttribute []))
          state-dir (str temp-dir)]
      (try
        ;; 1. First creation
        (let [id1 (light-shell/load-or-create-light-identity! state-dir)]
          (is (= 88 (count (:pubkey-hex id1))))
          (is (= 95 (count (:fingerprint id1))))
          (is (some? (:privkey-bytes id1)))
          (is (some? (:ice-creds id1)))
          (is (some? (:cert-data id1)))
          ;; 2. Subsequent load returns identical keys
          (let [id2 (light-shell/load-or-create-light-identity! state-dir)]
            (is (= (:pubkey-hex id1) (:pubkey-hex id2)))
            (is (= (:fingerprint id1) (:fingerprint id2)))
            (is (= (vec (:privkey-bytes id1)) (vec (:privkey-bytes id2)))))
          ;; 3. Corruption test: overwrite identity file with invalid junk
          (let [id-file (io/file state-dir "identity" "node-identity.edn")]
            (spit id-file "JUNK CORRUPTED CONTENT NOT VALID EDN")
            (is (thrown? clojure.lang.ExceptionInfo
                         (light-shell/load-or-create-light-identity! state-dir)))))
        (finally
          ;; Clean up temp directory
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file state-dir)))))))))

;; -----------------------------------------------------------------------------
;; 2. State Persistence Roundtrip & Stripped Private Keys
;; -----------------------------------------------------------------------------

(deftest test-state-persistence-roundtrip-and-stripped-keys
  (testing "State persistence strips ephemeral private keys and enforces 0600 POSIX permissions"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-state" (into-array FileAttribute []))
          state-file (str (io/file (str temp-dir) "state.nippy"))
          session-id "sess-test-persist-1"
          test-state {:pubkey (sample-pubkey-hex)
                      :epoch 5
                      :local-accounting {:burned-ech 1500}
                      :vouchers [{:seq 1 :debit 50}]
                      :sessions {session-id {:session-id session-id
                                             :state "offered"
                                             :ephemeral-priv (byte-array 32)
                                             :ephemeral-pub (byte-array 32)
                                             :price 10
                                             :epoch 5}}}]
      (try
        ;; 1. Save state
        (light-shell/save-light-state! state-file test-state)
        (is (.exists (io/file state-file)))

        ;; 2. Verify POSIX permissions on supported file systems
        (try
          (let [perms (PosixFilePermissions/toString (Files/getPosixFilePermissions (.toPath (io/file state-file)) (into-array java.nio.file.LinkOption [])))]
            (is (= "rw-------" perms)))
          (catch UnsupportedOperationException _ nil))

        ;; 3. Load state back
        (let [loaded (light-shell/load-light-state! state-file)
              loaded-sess (get-in loaded [:sessions session-id])]
          (is (= (:pubkey test-state) (:pubkey loaded)))
          (is (= 5 (:epoch loaded)))
          (is (= 1500 (get-in loaded [:local-accounting :burned-ech])))
          (is (= "offered" (:state loaded-sess)))
          ;; CRITICAL: Ephemeral private keys MUST be stripped
          (is (nil? (:ephemeral-priv loaded-sess)))
          ;; Public metadata remains intact
          (is (some? (:ephemeral-pub loaded-sess)))
          (is (= 10 (:price loaded-sess))))
        (finally
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file (str temp-dir))))))))))

;; -----------------------------------------------------------------------------
;; 3. Distinct Error Codes for Fingerprint Mismatch vs Listener Disabled
;; -----------------------------------------------------------------------------

(deftest test-validator-connection-errors
  (testing "Distinct error maps: :bad-fingerprint vs :listener-disabled"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-conn" (into-array FileAttribute []))
          id (light-shell/load-or-create-light-identity! (str temp-dir))]
      (try
        ;; 1. Bad fingerprint rejection
        (let [bad-desc {:network :devnet
                        :nodes {:node1 {:node-id :node1
                                        :ip "127.0.0.1"
                                        :agent-port 5010
                                        :fingerprint "INVALID:FINGERPRINT:STRING"
                                        :ice-ufrag "u1" :ice-pwd "p1"}}}
              res1 (light-shell/connect-validators! id bad-desc {})]
          (is (= false (:ok? res1)))
          (is (= "bad-fingerprint" (:error res1))))

        ;; 2. Listener disabled (timeout to dead port)
        (let [disabled-desc {:network :devnet
                             :nodes {:node1 {:node-id :node1
                                             :ip "127.0.0.1"
                                             :agent-port 59998
                                             :fingerprint (:fingerprint id)
                                             :ice-ufrag "u1" :ice-pwd "p1"}}}
              res2 (light-shell/connect-validators! id disabled-desc {:timeout-ms 200})]
          (is (= false (:ok? res2)))
          (is (= "listener-disabled" (:error res2))))

        ;; 3. Live DTLS Handshake Fingerprint Mismatch
        (let [val-dir (Files/createTempDirectory "bitecho-val-badfp" (into-array FileAttribute []))
              val-id (identity/load-or-create-node-identity! (str val-dir) :node-fp-val)
              val-agent-port 5430
              val-cfg {:node/id :node-fp-val
                       :state-dir (str val-dir)
                       :transport :datachannel
                       :cluster {:agent-port val-agent-port
                                 :listen-agents? true
                                 :nodes {:node-fp-val {:ip "127.0.0.1"
                                                       :port 5410
                                                       :agent-port val-agent-port
                                                       :pubkey (:pubkey-hex val-id)
                                                       :fingerprint (:fingerprint val-id)
                                                       :ice-ufrag (:ufrag (:ice-creds val-id))
                                                       :ice-pwd (:pwd (:ice-creds val-id))}}}}
              mesh-node (mesh/start-mesh-node! val-cfg {:identity val-id :persist? false})
              mismatched-desc {:network :devnet
                               :nodes {:node-fp-val {:node-id :node-fp-val
                                                     :ip "127.0.0.1"
                                                     :agent-port val-agent-port
                                                     :fingerprint "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                                                     :ice-ufrag (:ufrag (:ice-creds val-id))
                                                     :ice-pwd (:pwd (:ice-creds val-id))}}}]
          (try
            (let [res3 (light-shell/connect-validators! id mismatched-desc {:timeout-ms 2000})]
              (is (= false (:ok? res3)))
              (is (= "bad-fingerprint" (:error res3))))
            (finally
              (when mesh-node (try ((:stop! mesh-node)) (catch Exception _ nil)))
              (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                    (reverse (file-seq (io/file (str val-dir))))))))

        ;; 4. TCP Bad fingerprint rejection
        (let [bad-desc-tcp {:network :devnet
                            :nodes {:node1 {:node-id :node1
                                            :ip "127.0.0.1"
                                            :port 5000
                                            :agent-tcp-port 5010
                                            :fingerprint "INVALID:FINGERPRINT:STRING"
                                            :ice-ufrag "u1" :ice-pwd "p1"}}}
              res-tcp1 (light-shell/connect-validators! id bad-desc-tcp {:transport :tcp})]
          (is (= false (:ok? res-tcp1)))
          (is (= "bad-fingerprint" (:error res-tcp1))))

        ;; 5. TCP Listener disabled (connect refused or timeout to dead port)
        (let [disabled-desc-tcp {:network :devnet
                                 :nodes {:node1 {:node-id :node1
                                                 :ip "127.0.0.1"
                                                 :port 5000
                                                 :agent-tcp-port 5999
                                                 :fingerprint (identity/normalize-fingerprint (:fingerprint id))
                                                 :ice-ufrag "u1" :ice-pwd "p1"}}}
              res-tcp2 (light-shell/connect-validators! id disabled-desc-tcp {:transport :tcp :timeout-ms 200})]
          (is (= false (:ok? res-tcp2)))
          (is (= "listener-disabled" (:error res-tcp2))))
        (finally
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file (str temp-dir))))))))))

;; -----------------------------------------------------------------------------
;; 4. CLI Argument Parser Tests
;; -----------------------------------------------------------------------------

(deftest test-cli-argument-parser
  (testing "CLI parser for serve and one-shot modes with flags, defaults, and json args"
    ;; Defaults
    (let [p-def (light-shell/parse-light-node-args ["status"])]
      (is (= :one-shot (:mode p-def)))
      (is (= (str (System/getProperty "user.home") "/.bitecho/light-node") (:state-dir p-def)))
      (is (= "https://bitecho.org/devnet/bootstrap.txt" (:bootstrap p-def))))

    ;; Leading "light-node" token
    (let [p-leading (light-shell/parse-light-node-args ["light-node" "status"])]
      (is (= :one-shot (:mode p-leading)))
      (is (= "status" (:verb p-leading)))
      (is (= {"cmd" "status"} (:cmd-map p-leading))))

    ;; JSON string args
    (let [p-json (light-shell/parse-light-node-args ["offer" "{\"callee\":\"deadbeef\",\"price\":25}"])]
      (is (= :one-shot (:mode p-json)))
      (is (= "deadbeef" (get-in p-json [:cmd-map "callee"])))
      (is (= 25 (get-in p-json [:cmd-map "price"]))))

    ;; Serve mode
    (let [p-serve (light-shell/parse-light-node-args ["serve" "--state-dir" "custom/dir" "--autonomous"])]
      (is (= :serve (:mode p-serve)))
      (is (= "custom/dir" (:state-dir p-serve)))
      (is (= true (:autonomous? p-serve))))

    ;; One-shot offer
    (let [p-offer (light-shell/parse-light-node-args ["offer" "--callee" "deadbeef" "--price" "25" "--burn" "600"])]
      (is (= :one-shot (:mode p-offer)))
      (is (= "offer" (:verb p-offer)))
      (is (= {"cmd" "offer" "callee" "deadbeef" "price" 25 "burn" 600} (:cmd-map p-offer))))

    ;; One-shot send
    (let [p-send (light-shell/parse-light-node-args ["send" "--session" "sess1" "--text" "hello" "--burn" "500"])]
      (is (= :one-shot (:mode p-send)))
      (is (= "send" (:verb p-send)))
      (is (= {"cmd" "send" "session_id" "sess1" "text" "hello" "burn" 500} (:cmd-map p-send))))

    ;; One-shot status
    (let [p-status (light-shell/parse-light-node-args ["status"])]
      (is (= :one-shot (:mode p-status)))
      (is (= {"cmd" "status"} (:cmd-map p-status))))

    ;; Transport flag
    (let [p-tcp (light-shell/parse-light-node-args ["status" "--transport" "tcp"])
          p-udp (light-shell/parse-light-node-args ["status" "--transport" "udp"])
          p-def (light-shell/parse-light-node-args ["status"])]
      (is (= :tcp (:transport p-tcp)))
      (is (= :udp (:transport p-udp)))
      (is (= :udp (:transport p-def))))))

;; -----------------------------------------------------------------------------
;; 5. Real UDP WebRTC DataChannel End-to-End Two-Party Conversation
;; -----------------------------------------------------------------------------

(deftest test-real-datachannel-two-light-nodes-e2e
  (testing "Two light nodes communicate over real UDP WebRTC DataChannel through a local mesh node validator"
    (let [v-dir (Files/createTempDirectory "bitecho-mesh-val" (into-array FileAttribute []))
          a-dir (Files/createTempDirectory "bitecho-alice-light" (into-array FileAttribute []))
          b-dir (Files/createTempDirectory "bitecho-bob-light" (into-array FileAttribute []))
          val-state-dir (str v-dir)
          val-id (identity/load-or-create-node-identity! val-state-dir :node-val)
          val-agent-port 5420
          val-peer-port 5400
          val-cfg {:node/id :node-val
                   :state-dir val-state-dir
                   :transport :datachannel
                   :cluster {:agent-port val-agent-port
                             :listen-agents? true
                             :nodes {:node-val {:ip "127.0.0.1"
                                                :port val-peer-port
                                                :agent-port val-agent-port
                                                :pubkey (:pubkey-hex val-id)
                                                :fingerprint (:fingerprint val-id)
                                                :ice-ufrag (:ufrag (:ice-creds val-id))
                                                :ice-pwd (:pwd (:ice-creds val-id))}}}}
          mesh-node (mesh/start-mesh-node! val-cfg {:identity val-id :persist? false})
          descriptor {:network :devnet
                      :treasury-pubkey (:pubkey-hex val-id)
                      :custody-pubkey (:pubkey-hex val-id)
                      :nodes {:node-val {:node-id :node-val
                                         :ip "127.0.0.1"
                                         :port val-peer-port
                                         :agent-port val-agent-port
                                         :pubkey (:pubkey-hex val-id)
                                         :fingerprint (:fingerprint val-id)
                                         :ice-ufrag (:ufrag (:ice-creds val-id))
                                         :ice-pwd (:pwd (:ice-creds val-id))}}}
          alice-id (light-shell/load-or-create-light-identity! (str a-dir))
          bob-id (light-shell/load-or-create-light-identity! (str b-dir))
          st-alice (atom (light-core/init-light-state alice-id {:bootstrap descriptor :epoch 1}))
          st-bob (atom (light-core/init-light-state bob-id {:bootstrap descriptor :epoch 1 :autonomous? true}))
          alice-events (atom [])
          bob-events (atom [])
          alice-conn (light-shell/connect-validators! alice-id descriptor {:state-atom st-alice
                                                                           :event-out #(swap! alice-events conj %)
                                                                           :timeout-ms 3000})
          bob-conn (light-shell/connect-validators! bob-id descriptor {:state-atom st-bob
                                                                       :event-out #(swap! bob-events conj %)
                                                                       :timeout-ms 3000})]
      (try
        ;; Verify both connections succeeded over real UDP WebRTC DataChannels
        (is (= true (:ok? alice-conn)))
        (is (= true (:ok? bob-conn)))

        ;; 1. Bob registers rendezvous home set over UDP DataChannel
        (let [hs-res (light-core/handle-command @st-bob
                                                {"cmd" "register-home-set" "price" 10}
                                                (:privkey-bytes bob-id))]
          (reset! st-bob (:state hs-res))
          (is (= true (get-in hs-res [:response "ok"])))
          (doseq [env (:net-envelopes hs-res)]
            ((:send-fn bob-conn) env)))

        ;; 2. Alice creates channel offer to Bob
        (let [offer-res (light-core/handle-command @st-alice
                                                   {"cmd" "offer" "callee" (:pubkey-hex bob-id) "price" 10 "burn" 500}
                                                   (:privkey-bytes alice-id))
              session-id (get-in offer-res [:response "session_id"])]
          (reset! st-alice (:state offer-res))
          (is (some? session-id))
          ;; Alice sends gossip envelope over WebRTC DataChannel to validator
          (doseq [env (:net-envelopes offer-res)]
            ((:send-fn alice-conn) env))

          ;; Wait for Bob to receive offer, autonomous-accept, and send accept back
          (let [deadline (+ (System/currentTimeMillis) 4000)]
            (while (and (not= "open" (get-in @st-alice [:sessions session-id :state]))
                        (< (System/currentTimeMillis) deadline))
              (Thread/sleep 50)))

          ;; Check that both sessions opened
          (let [alice-sess (get-in @st-alice [:sessions session-id])
                bob-sess (get-in @st-bob [:sessions session-id])]
            (is (= "open" (:state alice-sess)))
            (is (= "open" (:state bob-sess))))

          ;; 2. Alice sends a sealed message to Bob
          (let [secret-msg "Secret payload over WebRTC DataChannel"
                send-res (light-core/handle-command @st-alice
                                                    {"cmd" "send" "session_id" session-id "text" secret-msg "burn" 500}
                                                    (:privkey-bytes alice-id))]
            (reset! st-alice (:state send-res))
            (is (= true (get-in send-res [:response "ok"])))
            (doseq [env (:net-envelopes send-res)]
              ((:send-fn alice-conn) env))

            ;; Wait for Bob to receive the sealed message in inbox
            (let [deadline (+ (System/currentTimeMillis) 4000)]
              (while (and (empty? (:inbox @st-bob))
                          (< (System/currentTimeMillis) deadline))
                (Thread/sleep 50)))

            ;; Bob reads inbox
            (let [inbox-res (light-core/handle-command @st-bob {"cmd" "inbox"} (:privkey-bytes bob-id))
                  messages (get-in inbox-res [:response "messages"])]
              (reset! st-bob (:state inbox-res))
              (is (= 1 (count messages)))
              (is (= secret-msg (:text (first messages)))))))

        (finally
          ;; Clean up DataChannels and validator node
          (when-let [n (:node alice-conn)] (try (api/close! n) (catch Exception _ nil)))
          (when-let [n (:node bob-conn)] (try (api/close! n) (catch Exception _ nil)))
          (when mesh-node (try ((:stop! mesh-node)) (catch Exception _ nil)))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file val-state-dir))))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file (str a-dir)))))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file (str b-dir))))))))))

;; -----------------------------------------------------------------------------
;; 6. Real TCP WebRTC DataChannel End-to-End Two-Party Conversation (RFC 4571)
;; -----------------------------------------------------------------------------

(deftest test-real-tcp-datachannel-two-light-nodes-e2e
  (testing "Two light nodes communicate over real TCP WebRTC DataChannel (RFC 4571) through a local mesh node validator"
    (let [v-dir (Files/createTempDirectory "bitecho-mesh-tcp-val" (into-array FileAttribute []))
          a-dir (Files/createTempDirectory "bitecho-alice-tcp" (into-array FileAttribute []))
          b-dir (Files/createTempDirectory "bitecho-bob-tcp" (into-array FileAttribute []))
          val-state-dir (str v-dir)
          val-id (identity/load-or-create-node-identity! val-state-dir :node-val)
          val-agent-tcp-port 5520
          val-agent-port 5510
          val-peer-port 5480
          val-cfg {:node/id :node-val
                   :state-dir val-state-dir
                   :transport :datachannel
                   :cluster {:agent-port val-agent-port
                             :agent-tcp-port val-agent-tcp-port
                             :listen-agents? true
                             :nodes {:node-val {:ip "127.0.0.1"
                                                :port val-peer-port
                                                :agent-port val-agent-port
                                                :agent-tcp-port val-agent-tcp-port
                                                :pubkey (:pubkey-hex val-id)
                                                :fingerprint (:fingerprint val-id)
                                                :ice-ufrag (:ufrag (:ice-creds val-id))
                                                :ice-pwd (:pwd (:ice-creds val-id))}}}}
          mesh-node (mesh/start-mesh-node! val-cfg {:identity val-id :persist? false})
          descriptor {:network :devnet
                      :treasury-pubkey (:pubkey-hex val-id)
                      :custody-pubkey (:pubkey-hex val-id)
                      :nodes {:node-val {:node-id :node-val
                                         :ip "127.0.0.1"
                                         :port val-peer-port
                                         :agent-port val-agent-port
                                         :agent-tcp-port val-agent-tcp-port
                                         :pubkey (:pubkey-hex val-id)
                                         :fingerprint (:fingerprint val-id)
                                         :ice-ufrag (:ufrag (:ice-creds val-id))
                                         :ice-pwd (:pwd (:ice-creds val-id))}}}
          alice-id (light-shell/load-or-create-light-identity! (str a-dir))
          bob-id (light-shell/load-or-create-light-identity! (str b-dir))
          st-alice (atom (light-core/init-light-state alice-id {:bootstrap descriptor :epoch 1}))
          st-bob (atom (light-core/init-light-state bob-id {:bootstrap descriptor :epoch 1 :autonomous? true}))
          alice-events (atom [])
          bob-events (atom [])
          alice-conn (light-shell/connect-validators! alice-id descriptor {:state-atom st-alice
                                                                           :transport :tcp
                                                                           :event-out #(swap! alice-events conj %)
                                                                           :timeout-ms 3000})
          bob-conn (light-shell/connect-validators! bob-id descriptor {:state-atom st-bob
                                                                       :transport :tcp
                                                                       :event-out #(swap! bob-events conj %)
                                                                       :timeout-ms 3000})]
      (try
        ;; Verify both connections succeeded over real TCP WebRTC DataChannels
        (is (= true (:ok? alice-conn)))
        (is (= true (:ok? bob-conn)))

        ;; 1. Bob registers rendezvous home set over TCP DataChannel
        (let [hs-res (light-core/handle-command @st-bob
                                                {"cmd" "register-home-set" "price" 10}
                                                (:privkey-bytes bob-id))]
          (reset! st-bob (:state hs-res))
          (is (= true (get-in hs-res [:response "ok"])))
          (doseq [env (:net-envelopes hs-res)]
            ((:send-fn bob-conn) env)))

        ;; 2. Alice creates channel offer to Bob
        (let [offer-res (light-core/handle-command @st-alice
                                                   {"cmd" "offer" "callee" (:pubkey-hex bob-id) "price" 10 "burn" 500}
                                                   (:privkey-bytes alice-id))
              session-id (get-in offer-res [:response "session_id"])]
          (reset! st-alice (:state offer-res))
          (is (some? session-id))
          ;; Alice sends gossip envelope over TCP DataChannel to validator
          (doseq [env (:net-envelopes offer-res)]
            ((:send-fn alice-conn) env))

          ;; Wait for Bob to receive offer, autonomous-accept, and send accept back
          (let [deadline (+ (System/currentTimeMillis) 4000)]
            (while (and (not= "open" (get-in @st-alice [:sessions session-id :state]))
                        (< (System/currentTimeMillis) deadline))
              (Thread/sleep 50)))

          ;; Check that both sessions opened
          (let [alice-sess (get-in @st-alice [:sessions session-id])
                bob-sess (get-in @st-bob [:sessions session-id])]
            (is (= "open" (:state alice-sess)))
            (is (= "open" (:state bob-sess))))

          ;; 3. Alice sends a sealed message to Bob
          (let [secret-msg "Secret payload over TCP WebRTC DataChannel (RFC 4571)"
                send-res (light-core/handle-command @st-alice
                                                    {"cmd" "send" "session_id" session-id "text" secret-msg "burn" 500}
                                                    (:privkey-bytes alice-id))]
            (reset! st-alice (:state send-res))
            (is (= true (get-in send-res [:response "ok"])))
            (doseq [env (:net-envelopes send-res)]
              ((:send-fn alice-conn) env))

            ;; Wait for Bob to receive the sealed message in inbox
            (let [deadline (+ (System/currentTimeMillis) 4000)]
              (while (and (empty? (:inbox @st-bob))
                          (< (System/currentTimeMillis) deadline))
                (Thread/sleep 50)))

            ;; Bob reads inbox
            (let [inbox-res (light-core/handle-command @st-bob {"cmd" "inbox"} (:privkey-bytes bob-id))
                  messages (get-in inbox-res [:response "messages"])]
              (reset! st-bob (:state inbox-res))
              (is (= 1 (count messages)))
              (is (= secret-msg (:text (first messages)))))))

        (finally
          ;; Clean up DataChannels and validator node
          (when-let [n (:node alice-conn)] (try (api/close! n) (catch Exception _ nil)))
          (when-let [n (:node bob-conn)] (try (api/close! n) (catch Exception _ nil)))
          (when mesh-node (try ((:stop! mesh-node)) (catch Exception _ nil)))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file val-state-dir))))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file (str a-dir)))))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file (str b-dir))))))))))

;; -----------------------------------------------------------------------------
;; 7. HTTP CONNECT Proxy Tunneling & Options Resolution
;; -----------------------------------------------------------------------------

(defn- find-free-port
  "Finds an ephemeral free port for testing."
  []
  (with-open [s (ServerSocket. 0)]
    (.getLocalPort s)))

(defn- handle-proxy-client!
  [^Socket client ^String expected-b64]
  (try
    (let [in (.getInputStream client)
          out (.getOutputStream client)
          buf (byte-array 4096)
          n (.read in buf 0 4096)]
      (when (pos? n)
        (let [req (String. buf 0 n StandardCharsets/UTF_8)
              lines (str/split-lines req)
              first-line (first lines)
              [_ target-host target-port-str] (re-matches #"CONNECT\s+([^:]+):(\d+)\s+HTTP/1\.[01]" (or first-line ""))
              auth-hdr (some (fn [l]
                               (when (str/starts-with? (str/lower-case l) "proxy-authorization:")
                                 (str/trim (subs l (count "proxy-authorization:")))))
                             lines)]
          (cond
            (and expected-b64 (not= (str "Basic " expected-b64) auth-hdr))
            (do
              (.write out (.getBytes "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n" StandardCharsets/UTF_8))
              (.flush out)
              (.close client))

            (and target-host target-port-str)
            (let [target-port (Integer/parseInt target-port-str)
                  target-sock (Socket. ^String target-host (int target-port))
                  t-in (.getInputStream target-sock)
                  t-out (.getOutputStream target-sock)]
              (.write out (.getBytes "HTTP/1.1 200 Connection established\r\n\r\n" StandardCharsets/UTF_8))
              (.flush out)
              (.start (Thread/ofVirtual)
                      (fn []
                        (try (.transferTo in t-out)
                             (catch Exception _ nil)
                             (finally
                               (try (.close client) (catch Exception _ nil))
                               (try (.close target-sock) (catch Exception _ nil))))))
              (.start (Thread/ofVirtual)
                      (fn []
                        (try (.transferTo t-in out)
                             (catch Exception _ nil)
                             (finally
                               (try (.close client) (catch Exception _ nil))
                               (try (.close target-sock) (catch Exception _ nil)))))))

            :else
            (do
              (.write out (.getBytes "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n" StandardCharsets/UTF_8))
              (.flush out)
              (.close client))))))
    (catch Exception _
      (try (.close client) (catch Exception _ nil)))))

(defn- start-mock-connect-proxy!
  "Starts an in-process mock HTTP CONNECT proxy with optional basic auth."
  [port expected-auth]
  (let [server-sock (ServerSocket. (int port))
        running? (atom true)
        expected-b64 (when expected-auth
                       (.encodeToString (Base64/getEncoder) (.getBytes ^String expected-auth StandardCharsets/UTF_8)))
        proxy-fut (future
                    (try
                      (while @running?
                        (let [client (.accept server-sock)]
                          (.start (Thread/ofVirtual) (fn [] (handle-proxy-client! client expected-b64)))))
                      (catch Exception _ nil)))]
    {:port port
     :stop-fn (fn []
                (reset! running? false)
                (try (.close server-sock) (catch Exception _ nil))
                (future-cancel proxy-fut))}))

(deftest test-resolve-proxy-url-and-transport-args
  (testing "resolve-proxy-url resolves explicit URL, or falls back to env vars in order"
    (is (= "http://proxy.example.com:8080" (light-shell/resolve-proxy-url "http://proxy.example.com:8080")))
    (let [env {"HTTPS_PROXY" "http://corp-proxy:3128"
               "HTTP_PROXY" "http://other-proxy:8080"}]
      (is (= "http://corp-proxy:3128" (light-shell/resolve-proxy-url nil #(get env %))))
      (is (= "http://override:9090" (light-shell/resolve-proxy-url "http://override:9090" #(get env %)))))
    (let [env {"http_proxy" "http://fallback:8888"}]
      (is (= "http://fallback:8888" (light-shell/resolve-proxy-url nil #(get env %))))))

  (testing "parse-light-node-args parses --transport connect and --proxy"
    (let [parsed (light-shell/parse-light-node-args ["status" "--transport" "connect" "--proxy" "http://proxy.test:8080"])]
      (is (= :connect (:transport parsed)))
      (is (= "http://proxy.test:8080" (:proxy parsed))))
    (let [parsed-tcp (light-shell/parse-light-node-args ["status" "--transport" "tcp"])]
      (is (= :tcp (:transport parsed-tcp))))
    (let [parsed-udp (light-shell/parse-light-node-args ["status"])]
      (is (= :udp (:transport parsed-udp))))))

(defn- verify-proxy-exchange!
  "Verifies rendezvous home set, channel offer/accept, and sealed message delivery
   between Alice and Bob light nodes over proxy connection."
  [{:keys [alice-conn bob-conn alice-id bob-id st-alice st-bob]}]
  (let [hs-res (light-core/handle-command @st-bob
                                          {"cmd" "register-home-set" "price" 10}
                                          (:privkey-bytes bob-id))]
    (reset! st-bob (:state hs-res))
    (is (= true (get-in hs-res [:response "ok"])))
    (doseq [env (:net-envelopes hs-res)]
      ((:send-fn bob-conn) env)))

  (let [offer-res (light-core/handle-command @st-alice
                                             {"cmd" "offer" "callee" (:pubkey-hex bob-id) "price" 10 "burn" 500}
                                             (:privkey-bytes alice-id))
        session-id (get-in offer-res [:response "session_id"])]
    (reset! st-alice (:state offer-res))
    (is (some? session-id))
    (doseq [env (:net-envelopes offer-res)]
      ((:send-fn alice-conn) env))

    (let [deadline (+ (System/currentTimeMillis) 4000)]
      (while (and (not= "open" (get-in @st-alice [:sessions session-id :state]))
                  (< (System/currentTimeMillis) deadline))
        (Thread/sleep 50)))

    (is (= "open" (get-in @st-alice [:sessions session-id :state])))
    (is (= "open" (get-in @st-bob [:sessions session-id :state])))

    (let [secret-msg "Secret payload over HTTP CONNECT proxy WebRTC DataChannel (RFC 4571)"
          send-res (light-core/handle-command @st-alice
                                              {"cmd" "send" "session_id" session-id "text" secret-msg "burn" 500}
                                              (:privkey-bytes alice-id))]
      (reset! st-alice (:state send-res))
      (is (= true (get-in send-res [:response "ok"])))
      (doseq [env (:net-envelopes send-res)]
        ((:send-fn alice-conn) env))

      (let [deadline (+ (System/currentTimeMillis) 4000)]
        (while (and (empty? (:inbox @st-bob))
                    (< (System/currentTimeMillis) deadline))
          (Thread/sleep 50)))

      (let [inbox-res (light-core/handle-command @st-bob {"cmd" "inbox"} (:privkey-bytes bob-id))
            messages (get-in inbox-res [:response "messages"])]
        (reset! st-bob (:state inbox-res))
        (is (= 1 (count messages)))
        (is (= secret-msg (:text (first messages))))))))

(deftest test-real-connect-proxy-two-light-nodes-e2e
  (testing "Two light nodes communicate over authenticated HTTP CONNECT proxy tunnel via WebRTC DataChannel (RFC 4571) through a local mesh node validator"
    (let [v-dir (Files/createTempDirectory "bitecho-proxy-val" (into-array FileAttribute []))
          a-dir (Files/createTempDirectory "bitecho-proxy-alice" (into-array FileAttribute []))
          b-dir (Files/createTempDirectory "bitecho-proxy-bob" (into-array FileAttribute []))
          proxy-port (find-free-port)
          proxy (start-mock-connect-proxy! proxy-port "agentproxy:secrettoken")
          proxy-url (str "http://agentproxy:secrettoken@127.0.0.1:" proxy-port)
          val-state-dir (str v-dir)
          val-id (identity/load-or-create-node-identity! val-state-dir :node-val)
          val-agent-tcp-port (find-free-port)
          val-agent-port (find-free-port)
          val-peer-port (find-free-port)
          val-cfg {:node/id :node-val
                   :state-dir val-state-dir
                   :transport :datachannel
                   :cluster {:agent-port val-agent-port
                             :agent-tcp-port val-agent-tcp-port
                             :listen-agents? true
                             :nodes {:node-val {:ip "127.0.0.1"
                                                :port val-peer-port
                                                :agent-port val-agent-port
                                                :agent-tcp-port val-agent-tcp-port
                                                :pubkey (:pubkey-hex val-id)
                                                :fingerprint (:fingerprint val-id)
                                                :ice-ufrag (:ufrag (:ice-creds val-id))
                                                :ice-pwd (:pwd (:ice-creds val-id))}}}}
          mesh-node (mesh/start-mesh-node! val-cfg {:identity val-id :persist? false})
          descriptor {:network :devnet
                      :treasury-pubkey (:pubkey-hex val-id)
                      :custody-pubkey (:pubkey-hex val-id)
                      :nodes {:node-val {:node-id :node-val
                                         :ip "127.0.0.1"
                                         :ingress-host "127.0.0.1"
                                         :ingress-port val-agent-tcp-port
                                         :port val-peer-port
                                         :agent-port val-agent-port
                                         :agent-tcp-port val-agent-tcp-port
                                         :pubkey (:pubkey-hex val-id)
                                         :fingerprint (:fingerprint val-id)
                                         :ice-ufrag (:ufrag (:ice-creds val-id))
                                         :ice-pwd (:pwd (:ice-creds val-id))}}}
          alice-id (light-shell/load-or-create-light-identity! (str a-dir))
          bob-id (light-shell/load-or-create-light-identity! (str b-dir))
          st-alice (atom (light-core/init-light-state alice-id {:bootstrap descriptor :epoch 1}))
          st-bob (atom (light-core/init-light-state bob-id {:bootstrap descriptor :epoch 1 :autonomous? true}))
          alice-events (atom [])
          bob-events (atom [])
          alice-conn (light-shell/connect-validators! alice-id descriptor {:state-atom st-alice
                                                                           :transport :connect
                                                                           :proxy proxy-url
                                                                           :event-out #(swap! alice-events conj %)
                                                                           :timeout-ms 5000})
          bob-conn (light-shell/connect-validators! bob-id descriptor {:state-atom st-bob
                                                                       :transport :connect
                                                                       :proxy proxy-url
                                                                       :event-out #(swap! bob-events conj %)
                                                                       :timeout-ms 5000})]
      (try
        (is (= true (:ok? alice-conn)))
        (is (= true (:ok? bob-conn)))
        (verify-proxy-exchange! {:alice-conn alice-conn
                                 :bob-conn bob-conn
                                 :alice-id alice-id
                                 :bob-id bob-id
                                 :st-alice st-alice
                                 :st-bob st-bob})
        (finally
          (when-let [n (:node alice-conn)] (try (api/close! n) (catch Exception _ nil)))
          (when-let [n (:node bob-conn)] (try (api/close! n) (catch Exception _ nil)))
          (when mesh-node (try ((:stop! mesh-node)) (catch Exception _ nil)))
          ((:stop-fn proxy))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file val-state-dir))))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file (str a-dir)))))
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file (str b-dir))))))))))

;; -----------------------------------------------------------------------------
;; 7. Mid-Session Disconnect & Lazy Reconnect Test
;; -----------------------------------------------------------------------------

(defn- run-lazy-reconnect-test!
  "Tests lazy reconnect on post-startup disconnect when command emits envelopes."
  [identity descriptor state-dir]
  (let [state-file (str (io/file state-dir "state.nippy"))
        initial-st (light-core/init-light-state identity {:bootstrap descriptor :epoch 1})
        state-atom (atom initial-st)
        reconnect-count (atom 0)
        sent-envelopes (atom [])
        dialer-mock (fn [_id _desc _opts]
                      (swap! reconnect-count inc)
                      {:ok? true
                       :channel-id (atom "new-cid")
                       :send-fn (fn [env]
                                  (swap! sent-envelopes conj env)
                                  true)})
        conn-opts {:dialer-fn dialer-mock}
        conn-atom (atom {:ok? true
                         :channel-id (atom "initial-cid")
                         :send-fn (fn [env]
                                    (swap! sent-envelopes conj env)
                                    true)})
        sw (StringWriter.)
        out-writer (PrintWriter. sw true)
        ctx {:state-atom state-atom
             :conn-atom conn-atom
             :out-writer out-writer
             :state-file state-file
             :identity identity
             :bootstrap descriptor
             :conn-opts conn-opts}
        callee-pub (sample-pubkey-hex)
        offer-json (json/write-str {"cmd" "offer" "callee" callee-pub "price" 10 "burn" 500})]
    (swap! state-atom assoc :connected? true)
    (is (= true (light-shell/connection-live? @conn-atom @state-atom)))
    ;; Simulate mid-session disconnect
    (reset! (:channel-id @conn-atom) nil)
    (swap! state-atom assoc :connected? false :connection-error "connection-closed")
    (is (= false (light-shell/connection-live? @conn-atom @state-atom)))
    ;; Command requiring network triggers lazy reconnect
    (light-shell/handle-serve-line! offer-json ctx)
    (is (= 1 @reconnect-count))
    (is (= true (:ok? @conn-atom)))
    (is (= true (:connected? @state-atom)))
    (is (nil? (:connection-error @state-atom)))
    (is (pos? (count @sent-envelopes)))
    (let [lines (str/split-lines (.toString sw))
          resp (json/read-str (last lines))]
      (is (= true (get resp "ok")))
      (is (some? (get resp "session_id"))))
    (let [saved-st (light-shell/load-light-state! state-file)]
      (is (some? saved-st))
      (is (= 1 (count (:sessions saved-st)))))))

(defn- run-fail-closed-test!
  "Tests fail-closed handling on reconnect failure: command fails, state not saved."
  [identity descriptor state-dir]
  (let [state-file (str (io/file state-dir "state.nippy"))
        initial-st (light-core/init-light-state identity {:bootstrap descriptor :epoch 1})
        _ (light-shell/save-light-state! state-file initial-st)
        state-atom (atom initial-st)
        reconnect-attempted (atom false)
        dialer-mock (fn [_id _desc _opts]
                      (reset! reconnect-attempted true)
                      {:ok? false :error "listener-disabled"})
        conn-opts {:dialer-fn dialer-mock}
        conn-atom (atom {:ok? false :error "connection-closed"})
        sw (StringWriter.)
        out-writer (PrintWriter. sw true)
        ctx {:state-atom state-atom
             :conn-atom conn-atom
             :out-writer out-writer
             :state-file state-file
             :identity identity
             :bootstrap descriptor
             :conn-opts conn-opts}
        callee-pub (sample-pubkey-hex)
        offer-json (json/write-str {"cmd" "offer" "callee" callee-pub "price" 10 "burn" 500})]
    (light-shell/handle-serve-line! offer-json ctx)
    (is (= true @reconnect-attempted))
    (is (= false (:ok? @conn-atom)))
    (is (= false (:connected? @state-atom)))
    (is (= "listener-disabled" (:connection-error @state-atom)))
    (let [lines (str/split-lines (.toString sw))
          resp (json/read-str (last lines))]
      (is (= false (get resp "ok")))
      (is (= "listener-disabled" (get resp "error"))))
    (let [saved-st (light-shell/load-light-state! state-file)]
      (is (= 0 (count (:sessions saved-st)))))))

(defn- run-failed-send-test!
  "Tests failed send detection: when send-fn returns false, triggers reconnect or fails closed."
  [identity descriptor state-dir]
  (let [state-file (str (io/file state-dir "state.nippy"))
        initial-st (light-core/init-light-state identity {:bootstrap descriptor :epoch 1})
        state-atom (atom (assoc initial-st :connected? true))
        reconn-sent (atom [])
        dialer-mock (fn [_id _desc _opts]
                      {:ok? true
                       :channel-id (atom "reconnected-cid")
                       :send-fn (fn [env]
                                  (swap! reconn-sent conj env)
                                  true)})
        conn-opts {:dialer-fn dialer-mock}
        conn-atom (atom {:ok? true
                         :channel-id (atom "stale-cid")
                         :send-fn (fn [_env] false)})
        sw (StringWriter.)
        out-writer (PrintWriter. sw true)
        ctx {:state-atom state-atom
             :conn-atom conn-atom
             :out-writer out-writer
             :state-file state-file
             :identity identity
             :bootstrap descriptor
             :conn-opts conn-opts}
        callee-pub (sample-pubkey-hex)
        offer-json (json/write-str {"cmd" "offer" "callee" callee-pub "price" 10 "burn" 500})]
    (light-shell/handle-serve-line! offer-json ctx)
    (is (pos? (count @reconn-sent)))
    (is (= true (:ok? @conn-atom)))
    (is (= true (:connected? @state-atom)))
    (let [lines (str/split-lines (.toString sw))
          resp (json/read-str (last lines))]
      (is (= true (get resp "ok"))))))

(defn- run-on-close-callback-test!
  "Tests that make-client-callbacks :on-close resets channel-id, conn-atom, and state-atom."
  []
  (let [cid (atom "active-cid")
        conn-atom (atom {:ok? true :channel-id cid})
        state-atom (atom {:connected? true})
        send-fn-atom (atom (fn [_] true))
        connected? (promise)
        cbs (light-shell/make-client-callbacks nil cid connected? send-fn-atom
                                               {:conn-atom conn-atom
                                                :state-atom state-atom})]
    ((:on-close cbs) nil)
    (is (nil? @cid))
    (is (= false (:ok? @conn-atom)))
    (is (= "connection-closed" (:error @conn-atom)))
    (is (= false (:connected? @state-atom)))
    (is (= "connection-closed" (:connection-error @state-atom)))))

(deftest test-mid-session-disconnect-and-reconnect
  (testing "Mid-session disconnect, lazy reconnect, fail-closed handling, and failed send detection"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-recon" (into-array FileAttribute []))
          state-dir (str temp-dir)
          identity (light-shell/load-or-create-light-identity! state-dir)
          descriptor {:network :devnet
                      :treasury-pubkey (:pubkey-hex identity)
                      :custody-pubkey (:pubkey-hex identity)
                      :nodes {:node1 {:node-id :node1
                                      :ip "127.0.0.1"
                                      :port 5000
                                      :agent-port 5010
                                      :pubkey (:pubkey-hex identity)
                                      :fingerprint (:fingerprint identity)
                                      :ice-ufrag "u1" :ice-pwd "p1"}}}]
      (try
        (run-lazy-reconnect-test! identity descriptor state-dir)
        (run-fail-closed-test! identity descriptor state-dir)
        (run-failed-send-test! identity descriptor state-dir)
        (run-on-close-callback-test!)
        (finally
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file state-dir)))))))))

;; -----------------------------------------------------------------------------
;; 8. Autonomous Flag Overlay on Saved State Test
;; -----------------------------------------------------------------------------

(deftest test-autonomous-flag-overlay-on-saved-state
  (testing "Saved state with autonomous? false gets autonomous? true when loaded with --autonomous"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-auto" (into-array FileAttribute []))
          state-dir (str temp-dir)
          state-file (str (io/file state-dir "state.fressian"))
          identity (light-shell/load-or-create-light-identity! state-dir)
          descriptor {:network :devnet
                      :treasury-pubkey (:pubkey-hex identity)
                      :custody-pubkey (:pubkey-hex identity)
                      :nodes {:node1 {:node-id :node1
                                      :ip "127.0.0.1"
                                      :port 5000
                                      :agent-port 5010
                                      :pubkey (:pubkey-hex identity)
                                      :fingerprint (:fingerprint identity)
                                      :ice-ufrag "u1" :ice-pwd "p1"}}}
          saved-st (assoc (light-core/init-light-state identity {:bootstrap descriptor :epoch 1 :autonomous? false})
                          :autonomous? false)
          bootstrap-file (str (io/file state-dir "bootstrap.edn"))
          _ (spit bootstrap-file (pr-str descriptor))]
      (try
        (light-shell/save-light-state! state-file saved-st)
        (let [raw-loaded (light-shell/load-light-state! state-file)]
          (is (= false (:autonomous? raw-loaded))))

        (let [sw (StringWriter.)
              pw (PrintWriter. sw true)]
          (binding [*out* pw]
            (let [resp (light-shell/run-one-shot! {:state-dir state-dir
                                                   :bootstrap bootstrap-file
                                                   :autonomous? true
                                                   :cmd-map {"cmd" "status"}})]
              (is (= true (get resp "ok")))
              (is (= true (get resp "autonomous")))))

          (let [updated-st (light-shell/load-light-state! state-file)]
            (is (= true (:autonomous? updated-st)))))

        (finally
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file state-dir)))))))))

;; -----------------------------------------------------------------------------
;; 9. Generative Connection Lifecycle State Machine Spec (Rules 1, 4, 5)
;; -----------------------------------------------------------------------------

(def ^:private gen-event-type
  (gen/elements [:dial-started :dial-ok :dial-failed :on-close :send-failed :persist-failed :shutdown]))

(def ^:private gen-gen-mode
  (gen/frequency [[60 (gen/return :current)]
                  [25 (gen/return :stale)]
                  [15 (gen/return :future)]]))

(def ^:private gen-lifecycle-step
  (gen/hash-map :type gen-event-type
                :gen-mode gen-gen-mode
                :error-msg (gen/elements [nil "err-timeout" "err-rst" "err-down"])))

(def ^:private gen-lifecycle-sequence
  (gen/vector gen-lifecycle-step 5 40))

(defspec ^{:doc "Property: Pure single-authority connection lifecycle state machine invariants"}
  conn-lifecycle-state-machine-spec 100
  (prop/for-all [steps gen-lifecycle-sequence]
                (let [initial-conn (light-shell/init-conn-state)]
                  (loop [idx 0
                         conn initial-conn
                         installed-nodes []
                         closed-nodes []]
                    (if (>= idx (count steps))
                      true
                      (let [step (nth steps idx)
                            evt-type (:type step)
                            curr-gen (:generation conn 0)
                            gen-mode (:gen-mode step)
                            evt-gen (case gen-mode
                                      :current (if (= evt-type :dial-started) nil curr-gen)
                                      :stale (if (pos? curr-gen) (max 0 (dec curr-gen)) -1)
                                      :future (inc curr-gen))
                            mock-node (when (= evt-type :dial-ok) {:node-id idx})
                            mock-cid (when (= evt-type :dial-ok) (atom (str "cid-" idx)))
                            mock-send-fn (when (= evt-type :dial-ok) (constantly true))
                            event (cond-> {:type evt-type}
                                    (some? evt-gen) (assoc :generation evt-gen)
                                    (= evt-type :dial-ok) (assoc :node mock-node
                                                                 :channel-id mock-cid
                                                                 :send-fn mock-send-fn)
                                    (:error-msg step) (assoc :error (:error-msg step)))
                            [new-conn effects] (light-shell/transition-conn conn event)
                            stale? (and (some? (:generation event)) (< (:generation event) (:generation conn 0)))
                            new-installed (if (and (= evt-type :dial-ok) (not stale?))
                                            (conj installed-nodes mock-node)
                                            installed-nodes)
                            newly-closed (keep (fn [eff] (when (= :close-node (:effect eff)) (:node eff))) effects)
                            new-closed (into closed-nodes newly-closed)

                ;; Invariant 1 (Liveness Agreement)
                            inv1 (and (= (boolean (:ok? new-conn)) (= :open (:phase new-conn)))
                                      (if (:ok? new-conn)
                                        (and (some? (:send-fn new-conn))
                                             (some? (:channel-id new-conn)))
                                        true))

                ;; Invariant 2 (Stale Generation Isolation)
                            inv2 (if stale?
                                   (and (= (:phase conn) (:phase new-conn))
                                        (= (:ok? conn) (:ok? new-conn))
                                        (= (:channel-id conn) (:channel-id new-conn))
                                        (= (:send-fn conn) (:send-fn new-conn))
                                        (= (:node conn) (:node new-conn))
                                        (= (:ignored-stale new-conn) (inc (:ignored-stale conn 0)))
                                        (= effects [{:effect :ignore-stale :generation (:generation event)}]))
                                   true)

                ;; Invariant 3 (Superseded Node Closed Exactly Once)
                            inv3 (and (= (count new-closed) (count (distinct new-closed)))
                                      (every? (set new-installed) new-closed)
                                      (if-let [active-node (:node new-conn)]
                                        (not (contains? (set new-closed) active-node))
                                        true)
                                      (= (set new-installed)
                                         (set (cond-> new-closed
                                                (:node new-conn) (conj (:node new-conn))))))

                ;; Invariant 4 (No Silent Drops)
                            inv4 (if (and (not stale?) (#{:dial-failed :send-failed :persist-failed} evt-type))
                                   (and (= (:dropped new-conn) (inc (:dropped conn 0)))
                                        (boolean (some (fn [eff] (and (= :diagnose (:effect eff)) (some? (:error eff)))) effects)))
                                   true)]

                        (if (and inv1 inv2 inv3 inv4)
                          (recur (inc idx) new-conn new-installed new-closed)
                          false)))))))

(deftest test-persist-failed-diagnostic-and-drop-counter
  (testing ":persist-failed transition records diagnostic and increments :dropped without closing connection"
    (let [conn0 {:generation 2
                 :phase :open
                 :ok? true
                 :channel-id (atom "cid-1")
                 :send-fn (constantly true)
                 :node {:node-id :n1}
                 :dropped 3
                 :error nil}
          event {:type :persist-failed :error "disk-full"}
          [conn1 effects] (light-shell/transition-conn conn0 event)
          diag-summary (light-shell/conn-diagnostics-summary conn1)]
      (is (= :open (:phase conn1)))
      (is (= true (:ok? conn1)))
      (is (= {:node-id :n1} (:node conn1)))
      (is (= 4 (:dropped conn1)))
      (is (= "disk-full" (:last-error conn1)))
      (is (= 4 (:dropped diag-summary)))
      (is (= "disk-full" (:last_error diag-summary)))
      (is (= [{:effect :diagnose :reason :persist-failed :error "disk-full"}] effects)))))

;; -----------------------------------------------------------------------------
;; 10. Stale Callback Isolation & Superseded Node Cleanup Test (Rule 4, 5)
;; -----------------------------------------------------------------------------

(deftest test-stale-callback-isolation-and-node-cleanup
  (testing "Superseded node closed on reconnect in handle-serve-line!, stale callbacks ignored, sensitive keys stripped on persist"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-stale" (into-array FileAttribute []))
          state-dir (str temp-dir)
          state-file (str (io/file state-dir "state.nippy"))
          identity (light-shell/load-or-create-light-identity! state-dir)
          descriptor {:network :devnet
                      :treasury-pubkey (:pubkey-hex identity)
                      :custody-pubkey (:pubkey-hex identity)
                      :nodes {:node1 {:node-id :node1
                                      :ip "127.0.0.1"
                                      :port 5000
                                      :agent-port 5010
                                      :pubkey (:pubkey-hex identity)
                                      :fingerprint (:fingerprint identity)
                                      :ice-ufrag "u1" :ice-pwd "p1"}}}
          initial-st (assoc (light-core/init-light-state identity {:bootstrap descriptor :epoch 1})
                            :connected? true
                            :connection-error nil
                            :conn-diagnostics {:phase "open" :generation 1 :last_error nil :dropped 0 :ignored_stale 0})
          state-atom (atom initial-st)
          node-gen1 {:id "mock-node-gen1"}
          node-gen2 {:id "mock-node-gen2"}
          closed-nodes (atom [])
          cid1 (atom "cid-1")
          cid2 (atom "cid-2")
          conn-atom (atom {:generation 1
                           :phase :open
                           :ok? true
                           :channel-id cid1
                           :send-fn (fn [_] false)
                           :node node-gen1
                           :error nil
                           :last-error nil
                           :dropped 0
                           :ignored-stale 0})
          dialer-mock (fn [_id _desc _opts]
                        {:ok? true
                         :node node-gen2
                         :channel-id cid2
                         :send-fn (constantly true)})
          conn-opts {:dialer-fn dialer-mock}
          sw (StringWriter.)
          out-writer (PrintWriter. sw true)
          ctx {:state-atom state-atom
               :conn-atom conn-atom
               :out-writer out-writer
               :state-file state-file
               :identity identity
               :bootstrap descriptor
               :conn-opts conn-opts}
          callee-pub (sample-pubkey-hex)
          offer-json (json/write-str {"cmd" "offer" "callee" callee-pub "price" 10 "burn" 500})]
      (try
        (with-redefs [api/close! (fn [node] (swap! closed-nodes conj node))]
          ;; 1. Send failure on gen1 triggers reconnect to gen2
          (light-shell/handle-serve-line! offer-json ctx)

          ;; Superseded node-gen1 must have been closed
          (is (= [node-gen1] @closed-nodes))
          ;; conn-atom must have transitioned to generation 2
          (is (= 2 (:generation @conn-atom)))
          (is (= :open (:phase @conn-atom)))
          (is (= true (:ok? @conn-atom)))
          (is (= node-gen2 (:node @conn-atom)))

          ;; 2. Simulate stale :on-close callback from generation 1
          (let [connected? (promise)
                send-fn-atom (atom (constantly true))
                cbs-gen1 (light-shell/make-client-callbacks node-gen1 cid1 connected? send-fn-atom
                                                            {:identity identity
                                                             :state-atom state-atom
                                                             :conn-atom conn-atom
                                                             :generation 1})]
            ((:on-close cbs-gen1) nil)

            ;; Stale callback must be ignored!
            (is (= 2 (:generation @conn-atom)))
            (is (= :open (:phase @conn-atom)))
            (is (= true (:ok? @conn-atom)))
            (is (= true (:connected? @state-atom)))
            (is (nil? (:connection-error @state-atom)))
            (is (= 1 (:ignored-stale @conn-atom)))
            ;; node-gen2 must NOT be closed by stale callback
            (is (= [node-gen1] @closed-nodes))
            ;; Verify :ignore-stale effect was consumed into :last-diagnostic and summary
            (is (= {:effect :ignore-stale :generation 1} (:last-diagnostic @conn-atom)))
            (is (= {:effect :ignore-stale :generation 1} (:last_diagnostic (light-shell/conn-diagnostics-summary @conn-atom)))))

          ;; Verify :diagnostics-atom and :diagnose-fn consumption in execute-conn-effects! / apply-conn-event!
          (let [diag-log (atom [])]
            (light-shell/apply-conn-event! conn-atom {:type :on-close :generation 1} {:diagnostics-atom diag-log})
            (is (= [{:effect :ignore-stale :generation 1}] @diag-log)))

          ;; Verify that make-client-callbacks and handle-serve-line! wire :diagnostics-atom through to apply-conn-event!
          (let [diag-log (atom [])
                cbs-stale (light-shell/make-client-callbacks node-gen1 cid1 (promise) (atom (constantly true))
                                                             {:identity identity
                                                              :state-atom state-atom
                                                              :conn-atom conn-atom
                                                              :diagnostics-atom diag-log
                                                              :generation 1})]
            ((:on-close cbs-stale) nil)
            (is (= [{:effect :ignore-stale :generation 1}] @diag-log)))

          ;; Verify that pure :diagnostics vector and optional :diagnostics-atom are bounded to 64 entries and expose :diagnostics_buffered
          (let [capped-conn-atom (atom (assoc (light-shell/init-conn-state) :generation 100))
                ext-diag-atom (atom [])]
            (dotimes [i 70]
              (light-shell/apply-conn-event! capped-conn-atom {:type :on-close :generation i} {:diagnostics-atom ext-diag-atom}))
            (is (= 64 (count (:diagnostics @capped-conn-atom))))
            (is (= 64 (count @ext-diag-atom)))
            (let [summary (light-shell/conn-diagnostics-summary @capped-conn-atom)]
              (is (= 64 (:diagnostics_buffered summary)))))

          ;; 3. Verify strip-sensitive-keys and state persistence never save transient runtime liveness
          (swap! state-atom assoc
                 :connected? true
                 :connection-error "transient"
                 :conn-diagnostics {:phase "open" :generation 2 :last_error nil :dropped 0 :ignored_stale 1})
          (light-shell/save-light-state! state-file @state-atom)
          (let [loaded (light-shell/load-light-state! state-file)]
            (is (nil? (:connected? loaded)))
            (is (nil? (:connection-error loaded)))
            (is (nil? (:conn-diagnostics loaded)))
            (is (= (:pubkey @state-atom) (:pubkey loaded)))))
        (finally
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file state-dir)))))))))

;; -----------------------------------------------------------------------------
;; 11. Explicit Home Nodes Validation Test
;; -----------------------------------------------------------------------------

(deftest test-explicit-home-nodes-validation
  (testing "Explicit home_nodes validation against bootstrap descriptor"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-hset" (into-array FileAttribute []))
          state-dir (str temp-dir)
          id (light-shell/load-or-create-light-identity! state-dir)
          desc {:network :devnet
                :nodes {:node1 {:node-id :node1
                                :ip "127.0.0.1"
                                :agent-port 5010
                                :fingerprint (:fingerprint id)
                                :ice-ufrag "u1" :ice-pwd "p1"}}}
          st (light-core/init-light-state id {:bootstrap desc :epoch 1})]
      (try
        ;; 1. Valid explicit node ID succeeds
        (let [res-valid (light-core/handle-command st {"cmd" "register-home-set" "home_nodes" ["node1"]} (:privkey-bytes id))]
          (is (= true (get-in res-valid [:response "ok"])))
          (is (= ["node1"] (get-in res-valid [:response "home_nodes"])))
          (is (seq (:net-envelopes res-valid))))

        ;; 2. Bogus node ID fails closed with "unknown-home-node" and [] envelopes
        (let [res-bogus (light-core/handle-command st {"cmd" "register-home-set" "home_nodes" ["bogus-node-99"]} (:privkey-bytes id))]
          (is (= false (get-in res-bogus [:response "ok"])))
          (is (= "unknown-home-node" (get-in res-bogus [:response "error"])))
          (is (= [] (:net-envelopes res-bogus))))
        (finally
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file state-dir)))))))))

;; -----------------------------------------------------------------------------
;; 12. CLI & skill/SKILL.md Flag/Verb Inventory Test (Rule 6)
;; -----------------------------------------------------------------------------

(deftest test-cli-and-skill-flag-inventory
  (testing "Bidirectional CLI verbs and flags inventory between skill/SKILL.md and parse-light-node-args"
    (let [skill-md (slurp "skill/SKILL.md")
          documented-flags (set (re-seq #"--[a-z][a-z-]*" skill-md))
          verbs ["serve" "wait-event" "identity" "status" "discover" "register-home-set"
                 "offer" "accept" "send" "inbox" "close" "transfer"
                 "account" "sync-account" "settle-intent" "submit-vouchers"
                 "petname-set" "petname-list" "petname-remove" "petname-resolve"
                 "dac-attach" "dac-revoke" "directory-verify"
                 "directory-register" "directory-lookup"
                 "rendezvous-policy" "rendezvous-offer" "rendezvous-accept"
                 "p2p-offer" "p2p-answer" "p2p-channel-state" "broadcast"
                 "lock-intent" "release-intent" "refund-intent" "escrows"]
          flags #{"--state-dir" "--bootstrap" "--autonomous" "--transport" "--proxy"
                  "--ingress-tcp-port"
                  "--timeout-ms" "--callee" "--price" "--price-max" "--burn" "--home-node"
                  "--session" "--session-id" "--text" "--payload-hex" "--receiver"
                  "--recipient" "--amount" "--seq" "--nodes" "--balance" "--sync"
                  "--petname" "--pubkey" "--overwrite" "--directory-pubkey"
                  "--min-burn" "--allowlist" "--auto-accept" "--topic" "--to"
                  "--offer-hash" "--from"
                  "--escrow-id" "--deliverable-hash" "--expires-epoch" "--preimage"
                  "--nickname" "--domain" "--mailbox" "--prev-pubkey" "--prev-privkey"
                  "--subnet-id" "--candidates" "--trusted-dac-anchors"
                  "--connected" "--error"
                  "--auto-sync" "--no-auto-sync" "--sync-interval-ms"
                  "--auto-register-home-set" "--no-auto-register-home-set"
                  "--cmd-file" "--events-out" "--min-seq" "--after-ts"
                  "--turn-server" "--turn-username" "--turn-password" "--turn-realm" "--turn-force-relay"
                  "--relay-url"}]
      ;; All verbs documented in SKILL.md
      (doseq [v verbs]
        (is (str/includes? skill-md v) (str "Verb documented in SKILL.md: " v)))
      ;; Exact bidirectional flag inventory parity between SKILL.md and parser test suite
      (is (= flags documented-flags))
      ;; Handled by parser:
      ;; Verbs
      (is (= :serve (:mode (light-shell/parse-light-node-args ["serve"]))))
      (is (= :wait-event (:mode (light-shell/parse-light-node-args ["wait-event"]))))
      (is (= {"cmd" "identity"} (:cmd-map (light-shell/parse-light-node-args ["identity"]))))
      (is (= {"cmd" "status"} (:cmd-map (light-shell/parse-light-node-args ["status"]))))
      (is (= {"cmd" "discover"} (:cmd-map (light-shell/parse-light-node-args ["discover"]))))
      (is (= "register-home-set" (get-in (light-shell/parse-light-node-args ["register-home-set"]) [:cmd-map "cmd"])))
      (is (= "offer" (get-in (light-shell/parse-light-node-args ["offer"]) [:cmd-map "cmd"])))
      (is (= "accept" (get-in (light-shell/parse-light-node-args ["accept"]) [:cmd-map "cmd"])))
      (is (= "rendezvous-policy" (get-in (light-shell/parse-light-node-args ["rendezvous-policy"]) [:cmd-map "cmd"])))
      (is (= "rendezvous-offer" (get-in (light-shell/parse-light-node-args ["rendezvous-offer" "--to" "bob"]) [:cmd-map "cmd"])))
      (is (= "rendezvous-accept" (get-in (light-shell/parse-light-node-args ["rendezvous-accept" "--from" "alice"]) [:cmd-map "cmd"])))
      (is (= "send" (get-in (light-shell/parse-light-node-args ["send"]) [:cmd-map "cmd"])))
      (is (= {"cmd" "inbox"} (:cmd-map (light-shell/parse-light-node-args ["inbox"]))))
      (is (= "close" (get-in (light-shell/parse-light-node-args ["close"]) [:cmd-map "cmd"])))
      (is (= "transfer" (get-in (light-shell/parse-light-node-args ["transfer"]) [:cmd-map "cmd"])))
      (is (= "account" (get-in (light-shell/parse-light-node-args ["account"]) [:cmd-map "cmd"])))
      (is (= "sync-account" (get-in (light-shell/parse-light-node-args ["sync-account"]) [:cmd-map "cmd"])))
      (is (= "settle-intent" (get-in (light-shell/parse-light-node-args ["settle-intent" "--receiver" "recv-pub" "--amount" "1000"]) [:cmd-map "cmd"])))
      (is (= "submit-vouchers" (get-in (light-shell/parse-light-node-args ["submit-vouchers"]) [:cmd-map "cmd"])))
      (is (= "petname-set" (get-in (light-shell/parse-light-node-args ["petname-set" "--petname" "alice" "--pubkey" "deadbeef" "--overwrite"]) [:cmd-map "cmd"])))
      (is (= "petname-list" (get-in (light-shell/parse-light-node-args ["petname-list"]) [:cmd-map "cmd"])))
      (is (= "petname-remove" (get-in (light-shell/parse-light-node-args ["petname-remove" "--petname" "alice"]) [:cmd-map "cmd"])))
      (is (= "petname-resolve" (get-in (light-shell/parse-light-node-args ["petname-resolve" "--petname" "alice"]) [:cmd-map "cmd"])))
      (is (= "dac-attach" (get-in (light-shell/parse-light-node-args ["dac-attach"]) [:cmd-map "cmd"])))
      (is (= "dac-revoke" (get-in (light-shell/parse-light-node-args ["dac-revoke"]) [:cmd-map "cmd"])))
      (is (= "directory-verify" (get-in (light-shell/parse-light-node-args ["directory-verify"]) [:cmd-map "cmd"])))
      (is (= "lock-intent" (get-in (light-shell/parse-light-node-args ["lock-intent" "--receiver" "bob" "--amount" "100" "--deliverable-hash" "beef" "--expires-epoch" "20" "--escrow-id" "e1"]) [:cmd-map "cmd"])))
      (is (= "release-intent" (get-in (light-shell/parse-light-node-args ["release-intent" "--escrow-id" "e1" "--preimage" "secret"]) [:cmd-map "cmd"])))
      (is (= "refund-intent" (get-in (light-shell/parse-light-node-args ["refund-intent" "--escrow-id" "e1"]) [:cmd-map "cmd"])))
      (is (= "escrows" (get-in (light-shell/parse-light-node-args ["escrows"]) [:cmd-map "cmd"])))
      (is (= "directory-register" (get-in (light-shell/parse-light-node-args ["directory-register"]) [:cmd-map "cmd"])))
      (is (= "directory-lookup" (get-in (light-shell/parse-light-node-args ["directory-lookup"]) [:cmd-map "cmd"])))
      (is (= "p2p-offer" (get-in (light-shell/parse-light-node-args ["p2p-offer" "--session-id" "s1"]) [:cmd-map "cmd"])))
      (is (= "p2p-answer" (get-in (light-shell/parse-light-node-args ["p2p-answer" "--session-id" "s1"]) [:cmd-map "cmd"])))
      (is (= "p2p-channel-state" (get-in (light-shell/parse-light-node-args ["p2p-channel-state" "--session-id" "s1" "--connected"]) [:cmd-map "cmd"])))
      (is (true? (get-in (light-shell/parse-light-node-args ["p2p-channel-state" "--session-id" "s1" "--connected"]) [:cmd-map "connected"])))
      (is (= "broadcast" (get-in (light-shell/parse-light-node-args ["broadcast" "--text" "hi"]) [:cmd-map "cmd"])))
      (is (= ["c1" "c2"] (get-in (light-shell/parse-light-node-args ["p2p-offer" "--session-id" "s1" "--candidates" "c1,c2"]) [:cmd-map "candidates"])))
      (is (= "chat/simon-nexus-axiom" (get-in (light-shell/parse-light-node-args ["broadcast" "--subnet-id" "chat/simon-nexus-axiom" "--text" "hi"]) [:cmd-map "subnet_id"])))
      ;; Flags (all 42 flags tested end-to-end)
      (is (= "alice" (get-in (light-shell/parse-light-node-args ["directory-register" "--nickname" "alice"]) [:cmd-map "nickname"])))
      (is (= "bitecho.org" (get-in (light-shell/parse-light-node-args ["directory-register" "--domain" "bitecho.org"]) [:cmd-map "domain"])))
      (is (= "https://bitecho.org/inbox" (get-in (light-shell/parse-light-node-args ["directory-register" "--mailbox" "https://bitecho.org/inbox"]) [:cmd-map "mailbox"])))
      (is (= "pk1" (get-in (light-shell/parse-light-node-args ["directory-register" "--prev-pubkey" "pk1"]) [:cmd-map "prev_pubkey"])))
      (is (= "sk1" (get-in (light-shell/parse-light-node-args ["directory-register" "--prev-privkey" "sk1"]) [:cmd-map "prev_privkey"])))
      (is (= "e1" (get-in (light-shell/parse-light-node-args ["lock-intent" "--escrow-id" "e1"]) [:cmd-map "escrow_id"])))
      (is (= "beef" (get-in (light-shell/parse-light-node-args ["lock-intent" "--deliverable-hash" "beef"]) [:cmd-map "deliverable_hash"])))
      (is (= 20 (get-in (light-shell/parse-light-node-args ["lock-intent" "--expires-epoch" "20"]) [:cmd-map "expires_epoch"])))
      (is (= "secret" (get-in (light-shell/parse-light-node-args ["release-intent" "--preimage" "secret"]) [:cmd-map "preimage"])))
      (is (= 100 (get-in (light-shell/parse-light-node-args ["rendezvous-policy" "--min-burn" "100"]) [:cmd-map "min_burn"])))
      (is (= ["alice" "bob"] (get-in (light-shell/parse-light-node-args ["rendezvous-policy" "--allowlist" "alice,bob"]) [:cmd-map "allowlist"])))
      (is (true? (get-in (light-shell/parse-light-node-args ["rendezvous-policy" "--auto-accept"]) [:cmd-map "auto_accept"])))
      (is (= "support" (get-in (light-shell/parse-light-node-args ["rendezvous-offer" "--topic" "support"]) [:cmd-map "topic"])))
      (is (= "bob" (get-in (light-shell/parse-light-node-args ["rendezvous-offer" "--to" "bob"]) [:cmd-map "callee"])))
      (is (= "h123" (get-in (light-shell/parse-light-node-args ["rendezvous-accept" "--offer-hash" "h123"]) [:cmd-map "offer_hash"])))
      (is (= "alice" (get-in (light-shell/parse-light-node-args ["rendezvous-accept" "--from" "alice"]) [:cmd-map "from"])))
      (is (= "dir-key-1" (get-in (light-shell/parse-light-node-args ["directory-verify" "--directory-pubkey" "dir-key-1"]) [:cmd-map "directory_pubkey"])))
      (is (= "nexus" (get-in (light-shell/parse-light-node-args ["directory-verify" "--nickname" "nexus"]) [:cmd-map "nickname"])))
      (is (= "bitecho.org" (get-in (light-shell/parse-light-node-args ["directory-verify" "--domain" "bitecho.org"]) [:cmd-map "domain"])))
      (is (= "alice" (get-in (light-shell/parse-light-node-args ["petname-set" "--petname" "alice" "--pubkey" "deadbeef" "--overwrite"]) [:cmd-map "petname"])))
      (is (= "deadbeef" (get-in (light-shell/parse-light-node-args ["petname-set" "--petname" "alice" "--pubkey" "deadbeef" "--overwrite"]) [:cmd-map "pubkey"])))
      (is (true? (get-in (light-shell/parse-light-node-args ["petname-set" "--petname" "alice" "--pubkey" "deadbeef" "--overwrite"]) [:cmd-map "overwrite"])))
      (is (= #{"deadbeef"} (:trusted-dac-anchors (light-shell/parse-light-node-args ["status" "--trusted-dac-anchors" "deadbeef"]))))
      ;; Flags (all 22 flags tested end-to-end)
      (is (= "foo/bar" (:state-dir (light-shell/parse-light-node-args ["status" "--state-dir" "foo/bar"]))))
      (is (= "boot.edn" (:bootstrap (light-shell/parse-light-node-args ["status" "--bootstrap" "boot.edn"]))))
      (is (true? (:autonomous? (light-shell/parse-light-node-args ["serve" "--autonomous"]))))
      (is (true? (:auto-sync? (light-shell/parse-light-node-args ["serve"]))))
      (is (= 15000 (:sync-interval-ms (light-shell/parse-light-node-args ["serve"]))))
      (is (false? (:auto-sync? (light-shell/parse-light-node-args ["serve" "--no-auto-sync"]))))
      (is (true? (:auto-sync? (light-shell/parse-light-node-args ["status" "--auto-sync"]))))
      (is (= 5000 (:sync-interval-ms (light-shell/parse-light-node-args ["serve" "--sync-interval-ms" "5000"]))))
      (is (false? (:auto-register-home-set? (light-shell/parse-light-node-args ["serve"]))))
      (is (true? (:auto-register-home-set? (light-shell/parse-light-node-args ["serve" "--autonomous"]))))
      (is (false? (:auto-register-home-set? (light-shell/parse-light-node-args ["serve" "--autonomous" "--no-auto-register-home-set"]))))
      (is (true? (:auto-register-home-set? (light-shell/parse-light-node-args ["serve" "--auto-register-home-set"]))))
      (is (= "/tmp/cmd.jsonl" (:cmd-file (light-shell/parse-light-node-args ["serve" "--cmd-file" "/tmp/cmd.jsonl"]))))
      (is (= "/tmp/ev.jsonl" (:events-out (light-shell/parse-light-node-args ["serve" "--events-out" "/tmp/ev.jsonl"]))))
      (is (= 258 (:min-seq (light-shell/parse-light-node-args ["wait-event" "--session-id" "s1" "--min-seq" "258"]))))
      (is (= "s1" (:session-id (light-shell/parse-light-node-args ["wait-event" "--session-id" "s1" "--min-seq" "258"]))))
      (is (= 1700000000000 (:after-ts (light-shell/parse-light-node-args ["wait-event" "--after-ts" "1700000000000"]))))
      (is (= :tcp (:transport (light-shell/parse-light-node-args ["status" "--transport" "tcp"]))))
      (is (= 5011 (:ingress-tcp-port (light-shell/parse-light-node-args ["serve" "--ingress-tcp-port" "5011"]))))
      (is (= "http://proxy.internal:8080" (:proxy (light-shell/parse-light-node-args ["status" "--proxy" "http://proxy.internal:8080"]))))
      (is (= 5000 (:timeout-ms (light-shell/parse-light-node-args ["status" "--timeout-ms" "5000"]))))
      (is (= "deadbeef" (get-in (light-shell/parse-light-node-args ["offer" "--callee" "deadbeef"]) [:cmd-map "callee"])))
      (is (= 42 (get-in (light-shell/parse-light-node-args ["offer" "--price" "42"]) [:cmd-map "price"])))
      (is (= 0 (get-in (light-shell/parse-light-node-args ["offer" "--callee" "deadbeef"]) [:cmd-map "price"])))
      (is (= 10 (get-in (light-shell/parse-light-node-args ["register-home-set" "--price" "10" "--price-max" "25"]) [:cmd-map "price"])))
      (is (= 0 (get-in (light-shell/parse-light-node-args ["register-home-set"]) [:cmd-map "price"])))
      (is (= 25 (get-in (light-shell/parse-light-node-args ["register-home-set" "--price" "10" "--price-max" "25"]) [:cmd-map "price_max"])))
      (is (= 700 (get-in (light-shell/parse-light-node-args ["offer" "--burn" "700"]) [:cmd-map "burn"])))
      (is (= "val-node-1" (get-in (light-shell/parse-light-node-args ["offer" "--home-node" "val-node-1"]) [:cmd-map "home_node"])))
      (is (= "sess-abc" (get-in (light-shell/parse-light-node-args ["accept" "--session" "sess-abc"]) [:cmd-map "session_id"])))
      (is (= "sess-123" (get-in (light-shell/parse-light-node-args ["accept" "--session-id" "sess-123"]) [:cmd-map "session_id"])))
      (is (= "hello world" (get-in (light-shell/parse-light-node-args ["send" "--text" "hello world"]) [:cmd-map "text"])))
      (is (= "010203" (get-in (light-shell/parse-light-node-args ["send" "--payload-hex" "010203"]) [:cmd-map "payload_hex"])))
      (is (= "recv-pub" (get-in (light-shell/parse-light-node-args ["transfer" "--receiver" "recv-pub"]) [:cmd-map "receiver"])))
      (is (= "https://bitecho.org/relay/v1" (:relay-url (light-shell/parse-light-node-args ["serve" "--relay-url" "https://bitecho.org/relay/v1"]))))
      (is (= "rcpt-pub" (get-in (light-shell/parse-light-node-args ["transfer" "--recipient" "rcpt-pub"]) [:cmd-map "recipient"])))
      (is (= 100 (get-in (light-shell/parse-light-node-args ["transfer" "--amount" "100"]) [:cmd-map "amount"])))
      (is (= 7 (get-in (light-shell/parse-light-node-args ["transfer" "--seq" "7"]) [:cmd-map "seq"])))
      (is (= ["n1" "n2"] (get-in (light-shell/parse-light-node-args ["register-home-set" "--nodes" "n1,n2"]) [:cmd-map "home_nodes"])))
      (is (= 5000 (get-in (light-shell/parse-light-node-args ["account" "--balance" "5000"]) [:cmd-map "balance"])))
      (is (true? (get-in (light-shell/parse-light-node-args ["account" "--sync"]) [:cmd-map "sync"])))
      (is (= {:server-host "turn.example.com"
              :server-port 3478
              :username "testuser"
              :password "secretpass"
              :realm "bitecho.org"
              :force-relay? true}
             (:turn-config (light-shell/parse-light-node-args ["status"
                                                               "--turn-server" "turn.example.com:3478"
                                                               "--turn-username" "testuser"
                                                               "--turn-password" "secretpass"
                                                               "--turn-realm" "bitecho.org"
                                                               "--turn-force-relay"])))))))

;; -----------------------------------------------------------------------------
;; 13. Candidate Ordering, Failover Rotation & Session Durability Tests (Priority 2)
;; -----------------------------------------------------------------------------

(deftest test-ordered-validator-candidates-and-failover-rotation
  (testing "ordered-validator-candidates prioritizes home-set, sorts remainder deterministically, and rotates with cursor"
    (let [desc {:network :devnet
                :nodes {:node1 {:node-id :node1 :ip "127.0.0.1" :agent-port 5010}
                        :node2 {:node-id :node2 :ip "127.0.0.2" :agent-port 5010}
                        :node3 {:node-id :node3 :ip "127.0.0.3" :agent-port 5010}}}]
      ;; 1. Empty home-set -> sorted by name (:node1, :node2, :node3)
      (let [cands-base (light-shell/ordered-validator-candidates desc [] 0)
            ids-base (mapv :node-id cands-base)]
        (is (= [:node1 :node2 :node3] ids-base)))

      ;; 2. Home-set [:node2] -> :node2 first, then remainder sorted [:node1 :node3]
      (let [cands-hs (light-shell/ordered-validator-candidates desc [:node2] 0)
            ids-hs (mapv :node-id cands-hs)]
        (is (= [:node2 :node1 :node3] ids-hs)))

      ;; 3. Normalization: supports strings and map forms in home-set
      (let [cands-str (light-shell/ordered-validator-candidates desc ["node2"] 0)]
        (is (= [:node2 :node1 :node3] (mapv :node-id cands-str))))
      (let [cands-map (light-shell/ordered-validator-candidates desc [{:node-id :node3}] 0)]
        (is (= [:node3 :node1 :node2] (mapv :node-id cands-map))))

      ;; 4. Cursor rotation
      (let [cands-cur1 (light-shell/ordered-validator-candidates desc [:node2] 1)]
        (is (= [:node1 :node3 :node2] (mapv :node-id cands-cur1))))
      (let [cands-cur2 (light-shell/ordered-validator-candidates desc [:node2] 2)]
        (is (= [:node3 :node2 :node1] (mapv :node-id cands-cur2))))
      (let [cands-cur3 (light-shell/ordered-validator-candidates desc [:node2] 3)]
        (is (= [:node2 :node1 :node3] (mapv :node-id cands-cur3)))))))

(defspec ^{:doc "Property: Multi-peer failover rotation, failover count diagnostics, and cursor tracking"}
  prop-multi-peer-session-failover-convergence 30
  (prop/for-all [attempts (gen/choose 0 5)
                 initial-cursor (gen/choose 0 10)]
                (let [conn0 (assoc (light-shell/init-conn-state) :validator-cursor initial-cursor)
                      failed-nodes (vec (for [i (range attempts)]
                                          {:validator-id (keyword (str "node-" i))
                                           :error "listener-disabled"}))
                      connected-vid :node-connected
                      mock-node {:node-id connected-vid}
                      mock-cid (atom "cid-1")
                      mock-send (constantly true)
                      event {:type :dial-ok
                             :generation 1
                             :validator-id connected-vid
                             :failover-attempts attempts
                             :failed-nodes failed-nodes
                             :node mock-node
                             :channel-id mock-cid
                             :send-fn mock-send}
                      [conn1 effects] (light-shell/transition-conn conn0 event)
                      summary1 (light-shell/conn-diagnostics-summary conn1)]
      ;; Verification of dial-ok failover recording
                  (and (= :open (:phase conn1))
                       (= connected-vid (:validator-id conn1))
                       (= (name connected-vid) (:validator_id summary1))
                       (= attempts (:failover-count conn1))
                       (= attempts (:failover_count summary1))
                       (= attempts (:dropped conn1))
                       (= attempts (:dropped summary1))
                       (= initial-cursor (:validator-cursor conn1))
                       (= initial-cursor (:validator_cursor summary1))
                       (= attempts (count (filter #(= :diagnose (:effect %)) effects)))
           ;; Next: failure event (:on-close or :send-failed or :dial-failed)
                       (let [[conn2 _eff2] (light-shell/transition-conn conn1 {:type :on-close :generation 1})
                             summary2 (light-shell/conn-diagnostics-summary conn2)]
                         (and (= :failed (:phase conn2))
                              (nil? (:validator-id conn2))
                              (nil? (:validator_id summary2))
                              (= (inc initial-cursor) (:validator-cursor conn2))
                              (= (inc initial-cursor) (:validator_cursor summary2))))))))

(deftest test-register-home-set-shell-wiring-replays-unacked-session-envelopes
  (testing "when register-home-set is executed through handle-serve-line! with unacked outbox messages, emits both home-set and replayed envelopes with identical message-ids"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-hs-replay" (into-array FileAttribute []))
          state-dir (str temp-dir)
          state-file (str (io/file state-dir "state.nippy"))
          identity (light-shell/load-or-create-light-identity! state-dir)
          pub-hex (:pubkey-hex identity)
          priv-bytes (:privkey-bytes identity)
          peer-kp (crypto/generate-keypair)
          peer-pub (basalt/bytes->hex (:public peer-kp))
          sid "session-test-hs-replay"
          k1 (byte-array 32 (byte 1))
          k2 (byte-array 32 (byte 2))
          seq-num 1
          sealed-m (sealed/seal-message k1 seq-num (.getBytes "unacked payload" "UTF-8") (.getBytes sid "UTF-8"))
          msg-payload {:bitecho/type :sealed-message
                       :session-id sid
                       :sender pub-hex
                       :recipient peer-pub
                       :epoch 0
                       :seq seq-num
                       :nonce (basalt/bytes->hex (:nonce sealed-m))
                       :ciphertext (basalt/bytes->hex (:ciphertext sealed-m))}
          orig-env (agent-sim/build-gossip-envelope pub-hex priv-bytes (nippy/freeze msg-payload) 500)
          orig-msg-id (get-in orig-env [:event :message :message-id])
          session {:session-id sid
                   :peer peer-pub
                   :state "open"
                   :tx-seq seq-num
                   :acked-seq 0
                   :epoch 0
                   :tx-key k1
                   :rx-key k2
                   :outbox {seq-num {:seq seq-num :msg-payload msg-payload :burn 500 :gossip-env orig-env}}
                   :outbox-order [seq-num]}
          descriptor {:network :devnet
                      :nodes {:node1 {:node-id :node1 :ip "127.0.0.1" :agent-port 5010}}}
          init-st (-> (light-core/init-light-state identity {:bootstrap descriptor :epoch 0})
                      (assoc-in [:sessions sid] session))
          state-atom (atom init-st)
          sent-envelopes (atom [])
          conn-atom (atom {:ok? true
                           :phase :open
                           :channel-id (atom "cid-hs-replay")
                           :send-fn (fn [env] (swap! sent-envelopes conj env) true)})
          sw (StringWriter.)
          out-writer (PrintWriter. sw true)
          ctx {:state-atom state-atom
               :conn-atom conn-atom
               :out-writer out-writer
               :state-file state-file
               :identity identity
               :bootstrap descriptor
               :conn-opts {}}
          cmd-json (json/write-str {"cmd" "register-home-set" "home_nodes" ["node1"] "price" 10 "burn" 500})]
      (swap! state-atom assoc :connected? true)
      (light-shell/handle-serve-line! cmd-json ctx)
      ;; 1. Sent envelopes include both replayed unacked envelope and register-home-set envelopes
      (is (some? orig-msg-id))
      (is (>= (count @sent-envelopes) 2))
      (let [replayed-env (first @sent-envelopes)
            replayed-msg-id (get-in replayed-env [:event :message :message-id])
            resp (json/read-str (first (str/split-lines (.toString sw))))]
        ;; 2. Replayed unacked session envelope has identical message-id (no new envelope, no double-burn)
        (is (= orig-msg-id replayed-msg-id))
        (is (= orig-env replayed-env))
        ;; 3. Command succeeded
        (is (= true (get resp "ok")))
        (is (contains? #{"ok" "degraded"} (get resp "status")))
        (is (= ["node1"] (get resp "home_nodes")))))))

(deftest test-attempt-proactive-reconnect-bounded-retries
  (testing "attempt-proactive-reconnect! retries up to max-attempts and returns on success or exhaustion"
    ;; 1. Fails 2 times then succeeds on 3rd attempt
    (let [attempts (atom 0)
          mock-reconnect (fn []
                           (swap! attempts inc)
                           (if (= @attempts 3)
                             {:ok? true :phase :open}
                             {:ok? false :error "listener-disabled"}))
          res (light-shell/attempt-proactive-reconnect! mock-reconnect {:reconnect-max-attempts 4 :reconnect-backoff-ms 0})]
      (is (= 3 @attempts))
      (is (= true (:ok? res))))

    ;; 2. Fails repeatedly, stops at max-attempts
    (let [attempts (atom 0)
          mock-reconnect (fn []
                           (swap! attempts inc)
                           {:ok? false :error "timeout"})
          res (light-shell/attempt-proactive-reconnect! mock-reconnect {:reconnect-max-attempts 3 :reconnect-backoff-ms 0})]
      (is (= 3 @attempts))
      (is (= false (:ok? res)))
      (is (= "timeout" (:error res))))))

(deftest test-build-reconnect-recovery-envelopes-pure-helper
  (testing "build-reconnect-recovery-envelopes combines register-home-set envelopes and unacked session replay envelopes preserving message-ids"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          priv (:private kp)
          peer-kp (crypto/generate-keypair)
          peer-pub (basalt/bytes->hex (:public peer-kp))
          sid "test-sess-recov"
          msg-payload {:bitecho/type :sealed-message
                       :session-id sid
                       :sender pub
                       :recipient peer-pub
                       :epoch 0
                       :seq 1
                       :nonce "010203"
                       :ciphertext "aabbcc"}
          orig-env (agent-sim/build-gossip-envelope pub priv (nippy/freeze msg-payload) 500)
          orig-msg-id (get-in orig-env [:event :message :message-id])
          st-base {:pubkey pub
                   :epoch 5
                   :home-set [:node1 :node2]
                   :rendezvous-policy {:price 20}
                   :sessions {sid {:session-id sid
                                   :state "open"
                                   :peer peer-pub
                                   :epoch 0
                                   :outbox {1 {:seq 1 :msg-payload msg-payload :burn 500 :gossip-env orig-env}}
                                   :outbox-order [1]}}}]
      (is (some? orig-msg-id))
      ;; With home-set and outbox: returns 2 home-set envelopes + 1 replay envelope
      (let [envs (light-shell/build-reconnect-recovery-envelopes st-base priv)]
        (is (= 3 (count envs)))
        (is (= :register-home-set (:type (:event (first envs)))))
        (is (= :register-home-set (:type (:event (second envs)))))
        (is (= orig-env (nth envs 2)))
        (is (= orig-msg-id (get-in (nth envs 2) [:event :message :message-id]))))

      ;; Without home-set: returns only the replay envelope
      (let [envs-no-hs (light-shell/build-reconnect-recovery-envelopes (assoc st-base :home-set []) priv)]
        (is (= 1 (count envs-no-hs)))
        (is (= orig-env (first envs-no-hs))))

      ;; With nil privkey: returns empty vector
      (is (empty? (light-shell/build-reconnect-recovery-envelopes st-base nil))))))

(deftest test-make-client-callbacks-on-close-proactive-reconnect
  (testing "make-client-callbacks :on-close triggers proactive reconnect for active generation and ignores stale generation"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          priv (:private kp)
          st-atom (atom {:pubkey pub :epoch 0 :connected? true :connection-error nil :autonomous? false})
          conn-atom (atom (assoc (light-shell/init-conn-state) :phase :open :generation 2))
          reconnected? (atom false)
          mock-reconnect (fn []
                           (reset! reconnected? true)
                           {:ok? true :phase :open})
          chan-id (atom "cid-test")
          ctx-stale {:identity {:pubkey-hex pub :privkey-bytes priv}
                     :state-atom st-atom
                     :conn-atom conn-atom
                     :reconnect-fn mock-reconnect
                     :generation 1} ;; stale! gen 1 < gen 2
          cbs-stale (light-shell/make-client-callbacks nil chan-id (promise) (atom nil) ctx-stale)]

      ;; 1. Stale generation :on-close
      ((:on-close cbs-stale) nil)
      (is (false? @reconnected?) "Stale :on-close must never trigger reconnect-fn")
      (is (= 1 (:ignored-stale @conn-atom)) "Stale :on-close must increment :ignored-stale")
      (is (= :open (:phase @conn-atom)) "Stale :on-close must not transition phase from :open")
      (is (= "cid-test" @chan-id) "Channel ID must not be cleared by stale :on-close")

      ;; 2. Active generation :on-close
      (let [ctx-active {:identity {:pubkey-hex pub :privkey-bytes priv}
                        :state-atom st-atom
                        :conn-atom conn-atom
                        :reconnect-fn mock-reconnect
                        :generation 2}
            cbs-active (light-shell/make-client-callbacks nil chan-id (promise) (atom nil) ctx-active)]
        ((:on-close cbs-active) nil)
        (is (true? @reconnected?) "Active generation :on-close must trigger proactive reconnect")
        (is (nil? @chan-id) "Channel ID must be cleared by active :on-close")
        (is (= false (:autonomous? @st-atom)) "Autonomous flag must remain false across reconnect")))))

(defspec ^{:doc "Property: Proactive reconnect on :on-close with bounded retries and envelope invariants"}
  prop-proactive-reconnect-and-lifecycle-invariants 30
  (prop/for-all [cur-gen (gen/choose 1 10)
                 outbox-count (gen/choose 0 5)
                 stale-offset (gen/choose 1 5)]
                (let [kp (crypto/generate-keypair)
                      pub (basalt/bytes->hex (:public kp))
                      priv (:private kp)
                      sid "prop-sess"
                      outbox (into {} (for [i (range 1 (inc outbox-count))]
                                        (let [msg {:bitecho/type :sealed-message
                                                   :session-id sid
                                                   :seq i
                                                   :payload (str "msg-" i)}
                                              env (agent-sim/build-gossip-envelope pub priv (nippy/freeze msg) 500)]
                                          [i {:seq i :msg-payload msg :burn 500 :gossip-env env}])))
                      outbox-order (vec (range 1 (inc outbox-count)))
                      st-init {:pubkey pub
                               :epoch 0
                               :home-set [:node1]
                               :rendezvous-policy {:price 10}
                               :autonomous? false
                               :connected? true
                               :connection-error nil
                               :sessions {sid {:session-id sid :state "open" :outbox outbox :outbox-order outbox-order}}}
                      st-atom (atom st-init)
                      conn-atom (atom (assoc (light-shell/init-conn-state) :phase :open :generation cur-gen))
                      reconn-called (atom 0)
                      mock-reconnect (fn []
                                       (swap! reconn-called inc)
                                       (swap! conn-atom assoc :phase :open)
                                       {:ok? true :phase :open})
                      stale-gen (- cur-gen stale-offset)
                      ctx-stale {:identity {:pubkey-hex pub :privkey-bytes priv}
                                 :state-atom st-atom
                                 :conn-atom conn-atom
                                 :reconnect-fn mock-reconnect
                                 :generation stale-gen}
                      cbs-stale (light-shell/make-client-callbacks nil (atom "cid") (promise) (atom nil) ctx-stale)]

      ;; (a) Stale generation on-close invariant
                  ((:on-close cbs-stale) nil)
                  (and (= 0 @reconn-called)
                       (= 1 (:ignored-stale @conn-atom))
                       (= :open (:phase @conn-atom))
           ;; (b) Active generation on-close invariant
                       (let [ctx-active {:identity {:pubkey-hex pub :privkey-bytes priv}
                                         :state-atom st-atom
                                         :conn-atom conn-atom
                                         :reconnect-fn mock-reconnect
                                         :generation cur-gen}
                             cbs-active (light-shell/make-client-callbacks nil (atom "cid") (promise) (atom nil) ctx-active)]
                         ((:on-close cbs-active) nil)
                         (let [recovery-envs (light-shell/build-reconnect-recovery-envelopes @st-atom priv)]
                           (and (= 1 @reconn-called)
                                (= false (:autonomous? @st-atom))
                    ;; 2 home-set envs + outbox-count replay envs
                                (= (+ 2 outbox-count) (count recovery-envs))
                    ;; Replay envs must preserve original message-ids
                                (every? (fn [i]
                                          (let [expected-env (:gossip-env (get outbox i))
                                                expected-mid (get-in expected-env [:event :message :message-id])
                                                matching-recov (first (filter #(= expected-mid (get-in % [:event :message :message-id]))
                                                                              recovery-envs))]
                                            (and (some? matching-recov)
                                                 (= expected-env matching-recov))))
                                        (range 1 (inc outbox-count))))))))))

(deftest test-duplicate-same-generation-on-close-invokes-reconnect-only-once
  (testing "Post-open (:open) duplicate same-generation :on-close callback invokes reconnect-fn only once"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          priv (:private kp)
          st-atom (atom {:pubkey pub :epoch 1 :home-set [] :autonomous? false :connected? true :connection-error nil})
          conn-atom (atom (assoc (light-shell/init-conn-state) :phase :open :generation 1))
          reconn-count (atom 0)
          mock-reconnect (fn []
                           (swap! reconn-count inc)
                           {:ok? true :phase :open})
          ctx {:identity {:pubkey-hex pub :privkey-bytes priv}
               :state-atom st-atom
               :conn-atom conn-atom
               :reconnect-fn mock-reconnect
               :generation 1}
          callbacks (light-shell/make-client-callbacks nil (atom "cid") (promise) (atom nil) ctx)
          on-close (:on-close callbacks)]
      ;; First :on-close invocation (when :phase is :open)
      (on-close nil)
      (is (= 1 @reconn-count) "First :on-close must trigger reconnect-fn")

      ;; Duplicate same-generation :on-close invocation (when :phase is already :failed or :down)
      (on-close nil)
      (is (= 1 @reconn-count) "Duplicate same-generation :on-close must NOT trigger reconnect-fn a second time")))

  (testing "Pre-open (:dialing) :on-close callback ALSO invokes reconnect-fn once, and duplicate ignores"
    (let [kp (crypto/generate-keypair)
          pub (basalt/bytes->hex (:public kp))
          priv (:private kp)
          st-atom (atom {:pubkey pub :epoch 1 :home-set [] :autonomous? false :connected? false :connection-error nil})
          conn-atom (atom (assoc (light-shell/init-conn-state) :phase :dialing :generation 2))
          reconn-count (atom 0)
          mock-reconnect (fn []
                           (swap! reconn-count inc)
                           {:ok? true :phase :dialing})
          ctx {:identity {:pubkey-hex pub :privkey-bytes priv}
               :state-atom st-atom
               :conn-atom conn-atom
               :reconnect-fn mock-reconnect
               :generation 2}
          callbacks (light-shell/make-client-callbacks nil (atom "cid") (promise) (atom nil) ctx)
          on-close (:on-close callbacks)]
      ;; First :on-close invocation during :dialing
      (on-close nil)
      (is (= 1 @reconn-count) "Pre-open (:dialing) :on-close must trigger reconnect-fn")

      ;; Duplicate same-generation :on-close invocation
      (on-close nil)
      (is (= 1 @reconn-count) "Duplicate pre-open same-generation :on-close must NOT trigger reconnect-fn a second time"))))

(deftest test-inband-chain-state-sync-and-escrows-quorum
  (testing "Milestone 5 (Pillar B): In-band validator quorum sync, fail-closed on tampered snapshots, and CLI verb/flag integration"
    (let [val-kps [(crypto/generate-keypair) (crypto/generate-keypair) (crypto/generate-keypair)]
          val-pubs (mapv #(basalt/bytes->hex (:public %)) val-kps)
          trusted-set (set val-pubs)
          bootstrap {:nodes {"v1" {:pubkey (nth val-pubs 0) :ip "127.0.0.1" :port 5001 :fingerprint "FP1"}
                             "v2" {:pubkey (nth val-pubs 1) :ip "127.0.0.1" :port 5002 :fingerprint "FP2"}
                             "v3" {:pubkey (nth val-pubs 2) :ip "127.0.0.1" :port 5003 :fingerprint "FP3"}}}
          user-kp (crypto/generate-keypair)
          user-pub (basalt/bytes->hex (:public user-kp))
          user-priv (:private user-kp)
          peer-pub (sample-pubkey-hex)
          deliv-hash (basalt/bytes->hex (crypto/sha256 (.getBytes "deliverable-1" "UTF-8")))
          escrows [{:escrow-id "e1"
                    :payer user-pub
                    :receiver peer-pub
                    :amount 500
                    :deliverable-hash deliv-hash
                    :created-epoch 90
                    :expires-epoch 150
                    :status :locked}]
          base-snap {:pubkey user-pub
                     :finalized-epoch 100
                     :balance 5000
                     :spendable 4500
                     :seq 3
                     :deps ["dep-3"]
                     :escrows escrows
                     :nonce "test-nonce"}
          valid-snaps (mapv (fn [i]
                              (light-core/sign-chain-state-snapshot
                               (assoc base-snap :validator-pubkey (nth val-pubs i))
                               (:private (nth val-kps i))))
                            (range 3))
          init-st (assoc (light-core/init-light-state {:identity {:pubkey-hex user-pub}} {:bootstrap bootstrap})
                         :epoch 1)
          st-atom (atom init-st)
          identity {:pubkey-hex user-pub :privkey-bytes user-priv}
          fetcher-ok (fn [_pk] valid-snaps)
          conn-opts {:inband-snapshot-fetcher fetcher-ok}]

      ;; 1. maybe-sync-account-state! with valid quorum updates account state and returns {:ok? true}
      (let [res (light-shell/maybe-sync-account-state! st-atom bootstrap user-pub user-priv conn-opts)]
        (is (true? (:ok? res)))
        (is (= 100 (:epoch @st-atom)))
        (is (= 5000 (get-in @st-atom [:account :balance])))
        (is (= 4500 (get-in @st-atom [:account :spendable])))
        (is (= 3 (get-in @st-atom [:account :seq])))
        (is (= ["dep-3"] (get-in @st-atom [:account :deps])))
        (is (= 1 (count (:escrows @st-atom))))
        (is (= 500 (get-in @st-atom [:escrows "e1" :amount]))))

      ;; 2. maybe-sync-account-state! fails closed on invalid snapshot signature or quorum disagreement
      (let [tampered-snaps (assoc-in valid-snaps [0 :signature] "0000000000000000")
            fetcher-bad (fn [_pk] tampered-snaps)
            bad-opts {:inband-snapshot-fetcher fetcher-bad}
            pre-st @st-atom
            bad-res (light-shell/maybe-sync-account-state! st-atom bootstrap user-pub user-priv bad-opts)]
        (is (false? (:ok? bad-res)))
        (is (= "invalid-snapshot-signature" (:error bad-res)))
        (is (= pre-st @st-atom) "State must not mutate on failed quorum verification"))

      ;; 3. handle-serve-line! with sync-account, account --sync, and escrows --sync
      (let [temp-dir (Files/createTempDirectory "bitecho-test-sync-serve" (into-array FileAttribute []))
            state-file (str (io/file (str temp-dir) "state.nippy"))
            sw (StringWriter.)
            out-w (PrintWriter. sw)
            ctx {:state-atom st-atom
                 :conn-atom (atom (light-shell/init-conn-state))
                 :out-writer out-w
                 :state-file state-file
                 :identity identity
                 :bootstrap bootstrap
                 :conn-opts conn-opts}]
        ;; (a) account --sync
        (light-shell/handle-serve-line! (json/write-str {"cmd" "account" "sync" true}) ctx)
        (let [line (last (str/split-lines (.toString sw)))
              parsed (json/read-str line)]
          (is (= true (get parsed "ok")))
          (is (= 5000 (get parsed "balance")))
          (is (= 4500 (get parsed "spendable"))))

        ;; (b) escrows --sync
        (light-shell/handle-serve-line! (json/write-str {"cmd" "escrows" "sync" true}) ctx)
        (let [line (last (str/split-lines (.toString sw)))
              parsed (json/read-str line)
              esc-list (get parsed "escrows")
              first-esc (first esc-list)]
          (is (= true (get parsed "ok")))
          (is (seq esc-list))
          (is (= "e1" (get first-esc "escrow_id")))
          (is (= 500 (get first-esc "amount"))))

        ;; (c) sync-account
        (light-shell/handle-serve-line! (json/write-str {"cmd" "sync-account"}) ctx)
        (let [line (last (str/split-lines (.toString sw)))
              parsed (json/read-str line)]
          (is (= true (get parsed "ok")))
          (is (= 5000 (get parsed "balance")))
          (is (= 4500 (get parsed "spendable"))))

        ;; (d) Fail-closed on bad sync in handle-serve-line!
        (let [disagree-snap (light-core/sign-chain-state-snapshot
                             (assoc base-snap :validator-pubkey (nth val-pubs 1) :balance 999999)
                             (:private (nth val-kps 1)))
              disagree-snaps [(nth valid-snaps 0) disagree-snap (nth valid-snaps 2)]
              bad-ctx (assoc ctx :conn-opts {:inband-snapshot-fetcher (fn [_pk] disagree-snaps)})]
          (light-shell/handle-serve-line! (json/write-str {"cmd" "account" "sync" true}) bad-ctx)
          (let [line (last (str/split-lines (.toString sw)))
                parsed (json/read-str line)]
            (is (= false (get parsed "ok")))
            (is (= "validator-state-disagreement" (get parsed "error"))))))

      ;; 4. Authenticated :query-chain-state envelope wrap/unwrap and validator snapshot building
      (let [query-env (light-core/build-chain-state-query-envelope user-pub user-priv "nonce-abc")
            unwrapped (mesh/unwrap-authenticated-agent-event query-env)]
        (is (some? unwrapped))
        (is (= :query-chain-state (:type unwrapped)))
        (is (= user-pub (:pubkey unwrapped)))
        (is (= "nonce-abc" (:nonce unwrapped)))

        (let [val-kp (first val-kps)
              val-pub (first val-pubs)
              val-identity {:pubkey-hex val-pub :keypair {:public (:public val-kp) :private (:private val-kp)}}
              val-node-state {:identity val-identity
                              :epoch 120
                              :last-executed-finalized-epoch 120
                              :ledger {user-pub {:balance 7000 :spendable 6800 :seq 5 :deps ["d5"]}}
                              :escrows {"e-v" {:escrow-id "e-v"
                                               :payer user-pub
                                               :receiver peer-pub
                                               :amount 200
                                               :deliverable-hash deliv-hash
                                               :created-epoch 110
                                               :expires-epoch 160
                                               :status :locked}}}
              val-snap (mesh/build-validator-chain-state-snapshot val-node-state val-identity user-pub "nonce-abc")]
          (is (some? val-snap))
          (is (= user-pub (:pubkey val-snap)))
          (is (= val-pub (:validator-pubkey val-snap)))
          (is (= 120 (:finalized-epoch val-snap)))
          (is (= 7000 (:balance val-snap)))
          (is (= 6800 (:spendable val-snap)))
          (is (= 5 (:seq val-snap)))
          (is (= "nonce-abc" (:nonce val-snap)))
          (is (= 1 (count (:escrows val-snap))))
          (let [v-res (light-core/verify-chain-state-snapshot val-snap {:expected-pubkey user-pub :trusted-validators trusted-set})]
            (is (true? (:ok? v-res)))))))))

(deftest test-directory-verify-auto-fetch
  (testing "directory-verify --nickname auto-fetches descriptor via :directory-fetcher in run-one-shot! and handle-serve-line!"
    (let [state-dir (str "/tmp/test-dir-verify-" (System/currentTimeMillis))
          _ (.mkdirs (io/file state-dir))
          user-identity (light-shell/load-or-create-light-identity! state-dir)
          user-pub (or (:pubkey-hex user-identity) (:pubkey user-identity))
          user-priv (:privkey-bytes user-identity)
          dir-kp (crypto/generate-keypair)
          dir-pub (basalt/bytes->hex (:public dir-kp))
          dir-priv (:private dir-kp)
          pop (light-core/create-directory-pop user-priv {:domain "bitecho.org" :nickname "nexus" :pubkey user-pub})
          desc (light-core/sign-directory-descriptor dir-priv dir-pub pop {:issued-epoch 1 :expires-epoch 50})
          fetcher (fn [dom nick]
                    (when (and (= dom "bitecho.org") (= nick "nexus"))
                      desc))
          bootstrap {:network :devnet :directory-pubkey dir-pub :nodes {}}]
      (try
        ;; 1. Test run-one-shot!
        (let [sw (java.io.StringWriter.)
              pw (java.io.PrintWriter. sw true)]
          (binding [*out* pw]
            (let [opts {:state-dir state-dir
                        :bootstrap bootstrap
                        :directory-fetcher fetcher
                        :cmd-map {"cmd" "directory-verify" "nickname" "nexus"}}
                  one-shot-res (light-shell/run-one-shot! opts)]
              (is (true? (get one-shot-res "ok")))
              (is (= "nexus" (get one-shot-res "nickname"))))))
        ;; 2. Test handle-serve-line!
        (let [state-atom (atom (light-core/init-light-state user-identity {:bootstrap bootstrap}))
              conn-atom (atom {:phase :down :send-fn (constantly true)})
              sw (java.io.StringWriter.)
              pw (java.io.PrintWriter. sw true)
              serve-line (json/write-str {"cmd" "directory-verify" "nickname" "nexus"})
              ctx {:state-atom state-atom
                   :conn-atom conn-atom
                   :out-writer pw
                   :identity user-identity
                   :bootstrap bootstrap
                   :conn-opts {:directory-fetcher fetcher}}]
          (light-shell/handle-serve-line! serve-line ctx)
          (let [line (last (str/split-lines (.toString sw)))
                serve-res (json/read-str line)]
            (is (true? (get serve-res "ok")))
            (is (= "nexus" (get serve-res "nickname")))
            (is (contains? (:directory-cache @state-atom) "nexus"))))
        (finally
          (run! #(try (.delete ^java.io.File %) (catch Exception _ nil))
                (reverse (file-seq (io/file state-dir)))))))))

(deftest test-turn-relay-default-enabled-when-turn-config-configured
  (testing "--turn-server without --turn-force-relay enables :use-turn-relay? by default across light-node and mesh call sites (R3-M2)"
    (let [parsed (light-shell/parse-light-node-args ["serve" "--turn-server" "198.51.100.10:3478" "--turn-username" "u" "--turn-password" "p"])
          tc (:turn-config parsed)
          peer-node (mesh/create-peer-datachannel-node 0 "active" nil {:ufrag "u" :pwd "p"} "AA:BB" tc)
          dc-conn (dc-core/create-connection (:opts peer-node) true)
          explicit-off-conn (dc-core/create-connection
                             (:opts (mesh/create-peer-datachannel-node 0 "active" nil {:ufrag "u" :pwd "p"} "AA:BB"
                                                                       (assoc tc :use-turn-relay? false)))
                             true)]
      (is (some? tc))
      (is (false? (:force-relay? tc)))
      (is (not (contains? (:opts peer-node) :use-turn-relay?)))
      (is (true? (:use-turn-relay? dc-conn)))
      (is (false? (:use-turn-relay? explicit-off-conn))))))

(deftest test-light-node-send-rejects-empty-payload-and-accepts-message-alias
  (testing "H-1/A-3: send rejects empty payload with empty-payload error and accepts message and session-id aliases"
    (let [alice-kp (crypto/generate-keypair)
          bob-kp (crypto/generate-keypair)
          alice-pub (basalt/bytes->hex (:public alice-kp))
          bob-pub (basalt/bytes->hex (:public bob-kp))
          st0 (light-core/init-light-state {:pubkey-hex alice-pub} {})
          sess-id "91e4541f458367db92b629c77a07633d4110889590ea707f1c3f740d44eefb68"
          tx-key (byte-array 32 (byte 7))
          rx-key (byte-array 32 (byte 8))
          st-open (assoc-in st0 [:sessions sess-id]
                            {:session-id sess-id
                             :peer bob-pub
                             :state "open"
                             :tx-key tx-key
                             :rx-key rx-key
                             :tx-seq 0
                             :rx-high-seq 0
                             :suite "suite-v1-chacha20poly1305"})
          ;; 1. Missing text/payload_hex/message -> rejected as empty-payload
          res-missing (light-core/handle-command st-open {"cmd" "send" "session_id" sess-id} (:private alice-kp))
          ;; 2. Blank/empty text "" -> rejected as empty-payload
          res-empty (light-core/handle-command st-open {"cmd" "send" "session_id" sess-id "text" ""} (:private alice-kp))
          ;; 3. Valid "message" alias + "session-id" hyphen alias -> succeeds
          res-msg (light-core/handle-command st-open {"cmd" "send" "session-id" sess-id "message" "hello axiom"} (:private alice-kp))]
      (is (false? (get-in res-missing [:response "ok"])))
      (is (= "empty-payload" (get-in res-missing [:response "error"])))
      (is (empty? (:net-envelopes res-missing)))
      (is (false? (get-in res-empty [:response "ok"])))
      (is (= "empty-payload" (get-in res-empty [:response "error"])))
      (is (empty? (:net-envelopes res-empty)))
      (is (true? (get-in res-msg [:response "ok"])))
      (is (= 11 (get-in res-msg [:response "bytes_sent"])))
      (is (= 1 (count (:net-envelopes res-msg)))))))

(deftest test-light-node-encode-or-send-failure-emits-counted-diagnose
  (testing "H-1/A-3: transition-conn tracks :encode-failed and :send-failed with counted :diagnose and :consecutive_send_failures"
    (let [conn-atom (atom (light-shell/init-conn-state))
          diag-atom (atom [])
          opts {:diagnostics-atom diag-atom}
          _ (light-shell/apply-conn-event! conn-atom {:type :dial-started :generation 1} opts)
          _ (light-shell/apply-conn-event! conn-atom {:type :dial-ok :generation 1 :validator-id :node1} opts)
          _ (is (= 0 (:consecutive-send-failures @conn-atom 0)))
          ;; 1. Encode failure increments :dropped and :consecutive-send-failures and emits :diagnose
          after-enc-fail (light-shell/apply-conn-event! conn-atom {:type :encode-failed :error "encode-failed: tag null"} opts)
          summary-1 (light-shell/conn-diagnostics-summary after-enc-fail)
          ;; 2. Send failure increments :dropped and :consecutive-send-failures and transitions to :failed
          after-send-fail (light-shell/apply-conn-event! conn-atom {:type :send-failed :error "send-failed: closed"} opts)
          summary-2 (light-shell/conn-diagnostics-summary after-send-fail)]
      (is (= 1 (:dropped after-enc-fail)))
      (is (= 1 (:consecutive_send_failures summary-1)))
      (is (= "encode-failed: tag null" (:last_error summary-1)))
      (is (= :encode-failed (:reason (first @diag-atom))))
      (is (= 2 (:dropped after-send-fail)))
      (is (= 2 (:consecutive_send_failures summary-2)))
      (is (= "failed" (:phase summary-2)))
      (is (= "send-failed: closed" (:last_error summary-2)))
      (is (= :send-failed (:reason (last @diag-atom)))))))

;; -----------------------------------------------------------------------------
;; Step U0 (Milestone 13A/13B): Self-Sufficient Daemon, Auto-Sync Events & wait-event
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property: Step U0 wait-event filter invariants across incoming and status events"}
  prop-step-u0-wait-event-filter-invariants 50
  (prop/for-all [ev-type (gen/elements ["message-received" "offer-received" "channel-opened"
                                        "session-established" "p2p-offer-received" "p2p-connected" "broadcast-received"
                                        "ready" "auto-sync" "connection-failed"])
                 sid (gen/elements ["sess-a" "sess-b" "sess-c"])
                 target-sid (gen/one-of [(gen/return nil) (gen/elements ["sess-a" "sess-b"])])
                 seq-num (gen/choose 1 500)
                 min-seq (gen/one-of [(gen/return nil) (gen/choose 1 500)])
                 ts (gen/choose 1000 5000)
                 after-ts (gen/one-of [(gen/return nil) (gen/choose 1000 5000)])]
                (let [evt {"event" ev-type
                           "session_id" sid
                           "seq" seq-num
                           "timestamp_ms" ts}
                      opts (cond-> {}
                             target-sid (assoc :session-id target-sid)
                             min-seq (assoc :min-seq min-seq)
                             after-ts (assoc :after-ts after-ts))
                      matched? (light-shell/event-matches-wait-filter? evt opts)
                      waitable? (contains? #{"message-received" "offer-received" "channel-opened"
                                             "session-established" "rendezvous-header-received"
                                             "rendezvous-reveal-received" "p2p-offer-received"
                                             "p2p-connected" "broadcast-received"}
                                           ev-type)
                      sid-ok? (or (nil? target-sid) (= sid target-sid))
                      seq-ok? (or (nil? min-seq) (>= seq-num min-seq))
                      ts-ok? (or (nil? after-ts) (> ts after-ts))]
                  (= matched? (and waitable? sid-ok? seq-ok? ts-ok?)))))

(deftest test-step-u0-auto-sync-stdout-event-and-home-set-renewal
  (testing "Step U0: run-auto-sync-tick! emits structured stdout auto-sync event (ok/error), diagnoses failures, and renews register-home-set"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-u0-sync" (into-array FileAttribute []))
          state-file (str (.resolve temp-dir "state.nippy"))
          id (light-shell/load-or-create-light-identity! (str temp-dir))
          pubkey (:pubkey-hex id)
          val-kp1 (crypto/generate-keypair)
          val-kp2 (crypto/generate-keypair)
          val-kp3 (crypto/generate-keypair)
          v1-pub (basalt/bytes->hex (:public val-kp1))
          v2-pub (basalt/bytes->hex (:public val-kp2))
          v3-pub (basalt/bytes->hex (:public val-kp3))
          bootstrap {:network "devnet"
                     :nodes {:node1 {:node-id "node1" :pubkey v1-pub :ip "127.0.0.1" :agent-port 5010}
                             :node2 {:node-id "node2" :pubkey v2-pub :ip "127.0.0.1" :agent-port 5011}
                             :node3 {:node-id "node3" :pubkey v3-pub :ip "127.0.0.1" :agent-port 5012}}}
          st0 (light-core/init-light-state id {:bootstrap bootstrap :autonomous? true})
          state-atom (atom st0)
          conn-atom (atom (light-shell/init-conn-state))
          sent-envs (atom [])
          emitted-events (atom [])
          diag-atom (atom [])
          _ (light-shell/apply-conn-event! conn-atom {:type :dial-started :generation 1})
          _ (light-shell/apply-conn-event! conn-atom {:type :dial-ok
                                                      :generation 1
                                                      :validator-id :node1
                                                      :send-fn (fn [env] (swap! sent-envs conj env) true)})
          make-snap (fn [v-kp v-pub]
                      (light-core/sign-chain-state-snapshot
                       {:pubkey pubkey
                        :balance 85000
                        :spendable 84500
                        :seq 2
                        :deps []
                        :finalized-epoch 420
                        :escrows []
                        :validator-pubkey v-pub}
                       (:private v-kp)))
          conn-opts-ok {:state-atom state-atom
                        :conn-atom conn-atom
                        :diagnostics-atom diag-atom
                        :event-out (fn [ev] (swap! emitted-events conj ev))
                        :auto-register-home-set? true
                        :home-set-price 10
                        :inband-snapshot-fetcher (fn [_] [(make-snap val-kp1 v1-pub)
                                                          (make-snap val-kp2 v2-pub)
                                                          (make-snap val-kp3 v3-pub)])}
          res-ok (light-shell/run-auto-sync-tick! state-atom bootstrap id state-file conn-opts-ok)
          ev-ok (first @emitted-events)]
      (try
        (is (:ok? res-ok))
        (is (= "auto-sync" (get ev-ok "event")))
        (is (true? (get ev-ok "ok")))
        (is (= 420 (get ev-ok "finalized_epoch")))
        (is (= 85000 (get ev-ok "balance")))
        (is (= 84500 (get ev-ok "spendable")))
        (is (true? (get ev-ok "synced")))
        ;; Verify auto-register-home-set dispatched over open validator channel
        (is (pos? (count @sent-envs)))
        (is (= :register-home-set (get-in (last @sent-envs) [:event :type])))
        (is (= ["node1" "node2" "node3"] (sort (map :node-id (:home-set @state-atom)))))
        ;; 2. Failure tick emits structured {"event":"auto-sync","ok":false,...} and records counted :diagnose (Rule 5)
        (reset! emitted-events [])
        (let [conn-opts-fail (assoc conn-opts-ok
                                    :inband-snapshot-fetcher (fn [_] [(make-snap val-kp1 v1-pub)]))
              res-fail (light-shell/run-auto-sync-tick! state-atom bootstrap id state-file conn-opts-fail)
              ev-fail (first @emitted-events)]
          (is (false? (:ok? res-fail)))
          (is (= "auto-sync" (get ev-fail "event")))
          (is (false? (get ev-fail "ok")))
          (is (false? (get ev-fail "synced")))
          (is (= "insufficient-validator-quorum" (get ev-fail "error")))
          (is (some #(= :auto-sync-failed (:reason %)) @diag-atom)))
        (finally
          (doseq [f (reverse (file-seq (.toFile temp-dir)))]
            (.delete f)))))))

(deftest test-step-u0-events-out-cmd-file-and-wait-event
  (testing "Step U0: --events-out appends timestamped JSONL, wait-event catches historical & live events or times out, and cmd-file tailer processes appended lines"
    (let [temp-dir (Files/createTempDirectory "bitecho-test-u0-io" (into-array FileAttribute []))
          events-path (str (.resolve temp-dir "events.jsonl"))
          cmd-path (str (.resolve temp-dir "cmd.jsonl"))]
      (try
        ;; 1. Pre-existing event in events.jsonl caught immediately via --session-id + --min-seq (zero turn-gap miss!)
        (light-shell/append-event-jsonl! events-path {"event" "ready" "connected" true})
        (light-shell/append-event-jsonl! events-path {"event" "message-received" "session_id" "s-1" "seq" 10 "text" "early"})
        (light-shell/append-event-jsonl! events-path {"event" "message-received" "session_id" "s-1" "seq" 11 "text" "target"})
        (let [sw (StringWriter.)
              pw (PrintWriter. sw true)
              res (light-shell/run-wait-event! {:state-dir (str temp-dir)
                                                :events-out events-path
                                                :session-id "s-1"
                                                :min-seq 11
                                                :timeout-ms 500
                                                :out-writer pw})]
          (is (:ok? res))
          (is (= 11 (get-in res [:event "seq"])))
          (is (= "target" (get (json/read-str (str/trim (str sw))) "text"))))

        ;; 2. Async live arrival while wait-event blocks at EOF (no --min-seq / --after-ts)
        (let [sw (StringWriter.)
              pw (PrintWriter. sw true)
              fut (future
                    (Thread/sleep 80)
                    (light-shell/append-event-jsonl! events-path {"event" "auto-sync" "ok" true "finalized_epoch" 500})
                    (Thread/sleep 40)
                    (light-shell/append-event-jsonl! events-path {"event" "offer-received" "session_id" "s-new" "from" "peer1"}))
              res (light-shell/run-wait-event! {:state-dir (str temp-dir)
                                                :events-out events-path
                                                :timeout-ms 1500
                                                :out-writer pw})]
          @fut
          (is (:ok? res))
          (is (= "offer-received" (get-in res [:event "event"])))
          (is (= "s-new" (get (json/read-str (str/trim (str sw))) "session_id"))))

        ;; 3. Timeout returns {:ok? false :error "timeout"} cleanly
        (let [sw (StringWriter.)
              pw (PrintWriter. sw true)
              res (light-shell/run-wait-event! {:state-dir (str temp-dir)
                                                :events-out events-path
                                                :session-id "s-1"
                                                :min-seq 999
                                                :timeout-ms 120
                                                :out-writer pw})]
          (is (false? (:ok? res)))
          (is (= "timeout" (:error res)))
          (is (= "timeout" (get (json/read-str (str/trim (str sw))) "error"))))

        ;; 4. Incremental cmd-file reader skips pre-existing offset and drains newly appended commands
        (spit cmd-path "{\"cmd\":\"stale\"}\n")
        (let [init-off (.length (io/file cmd-path))
              _ (spit cmd-path "{\"cmd\":\"status\"}\n{\"cmd\":\"inbox\"}\n" :append true)
              {:keys [lines next-offset]} (light-shell/read-new-cmd-file-lines! cmd-path init-off)]
          (is (= ["{\"cmd\":\"status\"}" "{\"cmd\":\"inbox\"}"] lines))
          (is (= (.length (io/file cmd-path)) next-offset)))
        (finally
          (doseq [f (reverse (file-seq (.toFile temp-dir)))]
            (.delete f)))))))

(deftest test-m2a-state-fressian-and-legacy-nippy-migration
  (testing "M2a: state.fressian is written by default and legacy state.nippy is transparently migrated on load"
    (let [temp-dir (Files/createTempDirectory "bitecho-m2a-state-" (into-array FileAttribute []))
          state-dir (str temp-dir)
          fressian-file (str (io/file state-dir "state.fressian"))
          nippy-file (str (io/file state-dir "state.nippy"))
          identity (light-shell/load-or-create-light-identity! state-dir)
          st0 (-> (light-core/init-light-state identity {:epoch 77 :autonomous? false})
                  (assoc-in [:local-accounting :burned-ech] 1500)
                  (assoc :connected? true :connection-error "should-be-stripped"))]
      (try
        ;; 1. Write legacy Nippy bytes directly to state.nippy
        (Files/write (.toPath (io/file nippy-file))
                     ^bytes (nippy/freeze (light-shell/strip-sensitive-keys st0))
                     (into-array java.nio.file.OpenOption []))
        ;; 2. Loading state.fressian transparently falls back to legacy state.nippy
        (let [migrated (light-shell/load-light-state! fressian-file)]
          (is (some? migrated))
          (is (= 77 (:epoch migrated)))
          (is (= 1500 (get-in migrated [:local-accounting :burned-ech])))
          (is (not (contains? migrated :connected?))))
        ;; 3. Saving to state.fressian writes canonical Fressian bytes (non-NPY header) and does NOT overwrite legacy state.nippy (M2a-2)
        (light-shell/save-light-state! fressian-file (assoc st0 :epoch 88))
        (is (.exists (io/file fressian-file)))
        (let [raw-bytes (Files/readAllBytes (.toPath (io/file fressian-file)))
              nippy-bytes (Files/readAllBytes (.toPath (io/file nippy-file)))
              reloaded (light-shell/load-light-state! fressian-file)]
          (is (not (and (= 78 (aget raw-bytes 0))
                        (= 80 (aget raw-bytes 1))
                        (= 89 (aget raw-bytes 2)))))
          (is (and (= 78 (aget nippy-bytes 0))
                   (= 80 (aget nippy-bytes 1))
                   (= 89 (aget nippy-bytes 2)))
              "M2a-2: legacy state.nippy retains original NPY header rather than being overwritten with Fressian bytes")
          (is (= 88 (:epoch reloaded)))
          (is (= 88 (:epoch (light-core/decode-light-state raw-bytes)))))
        (finally
          (doseq [f (reverse (file-seq (.toFile temp-dir)))]
            (.delete f)))))))

(deftest test-m2b-node-light-node-bundle-and-cross-runtime-e2e
  (testing "M2b: dist/bitecho-light-node.cjs CLI flag parity, node-identity.edn + state.fressian cross-runtime interoperability, and live Node.js <-> JVM DataChannel E2E over UDP and TCP"
    (let [bundle-file (io/file "dist/bitecho-light-node.cjs")
          sha-file (io/file "dist/bitecho-light-node.cjs.sha256")
          node-main-src (slurp "src/bitecho/node_main.cljs")
          skill-md (slurp "skill/SKILL.md")
          documented-flags (set (re-seq #"--[a-z][a-z-]*" skill-md))
          node-flags (set (re-seq #"--[a-z][a-z-]*" node-main-src))
          node-bin (or (System/getenv "NODE_BIN")
                       (let [local-node (io/file (System/getProperty "user.home") ".local/bin/node")]
                         (if (.canExecute local-node)
                           (.getAbsolutePath local-node)
                           "node")))
          temp-dir (Files/createTempDirectory "bitecho-m2b-e2e-" (into-array FileAttribute []))
          state-dir (str temp-dir)]
      (is (.exists bundle-file) "dist/bitecho-light-node.cjs must exist")
      (is (.exists sha-file) "dist/bitecho-light-node.cjs.sha256 must exist")
      (doseq [fl documented-flags]
        (is (contains? node-flags fl) (str "M2b Node.js CLI supports flag: " fl)))
      (try
        (let [udp-port (with-open [ds (java.net.DatagramSocket. 0)] (.getLocalPort ds))
              tcp-port (with-open [ss (java.net.ServerSocket. 0)] (.getLocalPort ss))
              udp-msg-p (promise)
              tcp-msg-p (promise)
              srv-udp (api/listen!
                       {:port udp-port}
                       {:on-connection
                        (fn [child-node]
                          (api/set-callbacks!
                           child-node
                           {:on-open (fn [_] nil)
                            :on-message (fn [evt]
                                          (deliver udp-msg-p (light-core/thaw-payload (:payload evt))))}))})
              srv-tcp (api/listen-tcp!
                       {:port tcp-port :host "127.0.0.1"}
                       {:on-connection
                        (fn [child-node]
                          (api/set-callbacks!
                           child-node
                           {:on-open (fn [_] nil)
                            :on-message (fn [evt]
                                          (deliver tcp-msg-p (light-core/thaw-payload (:payload evt))))}))})
              udp-creds (:ice-creds srv-udp)
              udp-fp (get-in srv-udp [:cert-data :fingerprint])
              tcp-creds (:ice-creds srv-tcp)
              tcp-fp (get-in srv-tcp [:cert-data :fingerprint])
              val-kp (crypto/generate-keypair)
              val-pub (basalt/bytes->hex (:public val-kp))
              udp-bootstrap-file (str (io/file state-dir "bootstrap-udp.edn"))
              tcp-bootstrap-file (str (io/file state-dir "bootstrap-tcp.edn"))
              run-node-cli (fn [& cli-args]
                             (let [pb (ProcessBuilder. ^java.util.List (into [node-bin (.getAbsolutePath bundle-file)] cli-args))
                                   proc (.start pb)
                                   out (slurp (.getInputStream proc))
                                   _ (.waitFor proc)]
                               (str/trim out)))]
          (try
            (spit udp-bootstrap-file
                  (pr-str {:network :devnet
                           :treasury-pubkey val-pub
                           :custody-pubkey val-pub
                           :nodes {:node1 {:node-id :node1
                                           :ip "127.0.0.1"
                                           :port udp-port
                                           :agent-port udp-port
                                           :pubkey val-pub
                                           :fingerprint udp-fp
                                           :ice-ufrag (:ufrag udp-creds)
                                           :ice-pwd (:pwd udp-creds)}}}))
            (spit tcp-bootstrap-file
                  (pr-str {:network :devnet
                           :treasury-pubkey val-pub
                           :custody-pubkey val-pub
                           :nodes {:node1 {:node-id :node1
                                           :ip "127.0.0.1"
                                           :port tcp-port
                                           :agent-port tcp-port
                                           :agent-tcp-port tcp-port
                                           :pubkey val-pub
                                           :fingerprint tcp-fp
                                           :ice-ufrag (:ufrag tcp-creds)
                                           :ice-pwd (:pwd tcp-creds)}}}))
            ;; 1. Node.js light node mints identity + state.fressian; JVM loads both cleanly
            (let [id-out (run-node-cli "identity" "--state-dir" state-dir "--bootstrap" udp-bootstrap-file)
                  id-json (json/read-str id-out)
                  jvm-id (light-shell/load-or-create-light-identity! state-dir)
                  jvm-st (light-shell/load-light-state! (str (io/file state-dir "state.fressian")))]
              (is (= true (get id-json "ok")))
              (is (= (get id-json "pubkey") (:pubkey-hex jvm-id)))
              (is (= (get id-json "fingerprint") (:fingerprint jvm-id)))
              (is (= (:pubkey-hex jvm-id) (:pubkey jvm-st))))

            ;; 2. Live E2E over UDP (Node.js DTLS 1.2 + DataChannel -> JVM SSLEngine listener)
            (let [udp-out (run-node-cli "register-home-set"
                                        "--nodes" "node1"
                                        "--price" "15"
                                        "--transport" "udp"
                                        "--state-dir" state-dir
                                        "--bootstrap" udp-bootstrap-file)
                  udp-json (json/read-str udp-out)
                  rx-udp (deref udp-msg-p 5000 :timeout)]
              (is (= true (get udp-json "ok")))
              (is (map? rx-udp))
              (is (= :register-home-set (get-in rx-udp [:event :type])))
              (is (= 15 (get-in rx-udp [:event :price]))))

            ;; 3. Live E2E over RFC 4571 TCP (Node.js DTLS 1.2 + DataChannel -> JVM SSLEngine TCP listener)
            (let [tcp-out (run-node-cli "register-home-set"
                                        "--nodes" "node1"
                                        "--price" "20"
                                        "--transport" "tcp"
                                        "--state-dir" state-dir
                                        "--bootstrap" tcp-bootstrap-file)
                  tcp-json (json/read-str tcp-out)
                  rx-tcp (deref tcp-msg-p 5000 :timeout)
                  reloaded-st (light-shell/load-light-state! (str (io/file state-dir "state.fressian")))]
              (is (= true (get tcp-json "ok")))
              (is (map? rx-tcp))
              (is (= :register-home-set (get-in rx-tcp [:event :type])))
              (is (= 20 (get-in rx-tcp [:event :price])))
              (is (= [{:latency-ms 10 :node-id "node1" :price 20 :responsive? true}] (:home-set reloaded-st))))

            ;; 4. Step 15C: start-ingress-tcp-listener! (--ingress-tcp-port) answers :query-chain-state and handles direct peer session envelopes
            (let [hub-dir (str (.resolve temp-dir "hub-node"))
                  hub-id (light-shell/load-or-create-light-identity! hub-dir)
                  hub-port (let [ss (java.net.ServerSocket. 0)]
                             (try (.getLocalPort ss) (finally (.close ss))))
                  hub-desc {:network :devnet
                            :treasury-pubkey (:pubkey-hex hub-id)
                            :custody-pubkey (:pubkey-hex hub-id)
                            :nodes {:nexus {:node-id :nexus
                                            :ip "127.0.0.1"
                                            :port hub-port
                                            :agent-port hub-port
                                            :agent-tcp-port hub-port
                                            :pubkey (:pubkey-hex hub-id)
                                            :fingerprint (:fingerprint hub-id)
                                            :ice-ufrag (:ufrag (:ice-creds hub-id))
                                            :ice-pwd (:pwd (:ice-creds hub-id))}}}
                  hub-bootstrap-file (str (.resolve temp-dir "hub-bootstrap.edn"))
                  _ (spit hub-bootstrap-file (pr-str hub-desc))
                  hub-events (atom [])
                  hub-state (atom (-> (light-core/init-light-state hub-id {:bootstrap hub-desc :autonomous? true})
                                      (assoc-in [:account :balance] 4200)
                                      (assoc-in [:account :spendable] 4200)
                                      (assoc-in [:account :finalized-epoch] 77)
                                      (assoc :epoch 77)))
                  hub-listener (light-shell/start-ingress-tcp-listener!
                                hub-id
                                {:ingress-tcp-port hub-port
                                 :state-atom hub-state
                                 :event-out #(swap! hub-events conj %)})]
              (try
                (let [sync-out (run-node-cli "sync-account"
                                             "--transport" "tcp"
                                             "--state-dir" state-dir
                                             "--bootstrap" hub-bootstrap-file)
                      sync-json (json/read-str sync-out)
                      offer-out (run-node-cli "offer"
                                              "--callee" (:pubkey-hex hub-id)
                                              "--price" "10"
                                              "--burn" "500"
                                              "--transport" "tcp"
                                              "--state-dir" state-dir
                                              "--bootstrap" hub-bootstrap-file)
                      offer-json (json/read-str offer-out)]
                  (is (= true (get sync-json "ok")))
                  (is (= 4200 (get sync-json "balance")))
                  (is (= true (get offer-json "ok")))
                  (is (some #(= "channel-opened" (get % "event")) @hub-events)
                      "Hub passive ingress TCP listener auto-accepted incoming offer over RFC 4571 DTLS-over-TCP"))
                (finally
                  ((:stop! hub-listener)))))
            (finally
              (try (api/close! srv-udp) (catch Exception _ nil))
              (try (api/close! srv-tcp) (catch Exception _ nil)))))
        (finally
          (doseq [f (reverse (file-seq (.toFile temp-dir)))]
            (.delete f)))))))

(deftest test-p2p-direct-tcp-ingress-and-zero-burn-routing
  (testing "Real TCP ingress + P2P DataChannel transport test exchanging :p2p-link-bind, and sending zero-burn message & broadcast with no validator"
    (let [temp-dir (Files/createTempDirectory "p2p-tcp-test-" (into-array java.nio.file.attribute.FileAttribute []))
          dir-a (str (.resolve temp-dir "node-a"))
          dir-b (str (.resolve temp-dir "node-b"))
          id-a (light-shell/load-or-create-light-identity! dir-a)
          id-b (light-shell/load-or-create-light-identity! dir-b)
          port-a (let [ss (java.net.ServerSocket. 0)]
                   (try (.getLocalPort ss) (finally (.close ss))))
          init-a (light-core/init-light-state id-a {:subnet-id "chat/simon-nexus-axiom" :economy-enabled? false :burn-floor 0 :epoch 10})
          init-b (light-core/init-light-state id-b {:subnet-id "chat/simon-nexus-axiom" :economy-enabled? false :burn-floor 0 :epoch 10})
          off-res (light-core/handle-command init-a
                                             {"cmd" "offer" "callee" (:pubkey-hex id-b) "price" 0 "burn" 0}
                                             (:privkey-bytes id-a))
          sid (get-in off-res [:response "session_id"])
          state-a-off (:state off-res)
          b-off-res (reduce (fn [st env] (:state (light-core/handle-wire-payload st env (:privkey-bytes id-b))))
                            init-b
                            (:net-envelopes off-res))
          b-acc-res (light-core/handle-command b-off-res {"cmd" "accept" "session_id" sid} (:privkey-bytes id-b))
          state-b-open (:state b-acc-res)
          a-acc-res (reduce (fn [st env] (:state (light-core/handle-wire-payload st env (:privkey-bytes id-a))))
                            state-a-off
                            (:net-envelopes b-acc-res))
          state-a-open a-acc-res
          state-atom-a (atom state-a-open)
          state-atom-b (atom state-b-open)
          p2p-peers-a (atom {})
          ingress-peers-a (atom {})
          events-a (atom [])
          p2p-peers-b (atom {})
          ingress-peers-b (atom {})
          events-b (atom [])
          listener (light-shell/start-ingress-tcp-listener! id-a
                                                            {:ingress-tcp-port port-a
                                                             :state-atom state-atom-a
                                                             :p2p-peers-atom p2p-peers-a
                                                             :ingress-peers-atom ingress-peers-a
                                                             :event-out #(swap! events-a conj %)})]
      (try
        (let [p2p-off (light-core/handle-command @state-atom-a
                                                 {"cmd" "p2p-offer"
                                                  "session_id" sid
                                                  "candidates" [(str "tcp://127.0.0.1:" port-a)]}
                                                 (:privkey-bytes id-a))]
          (reset! state-atom-a (:state p2p-off)))
        (let [dial-info {:peer (:pubkey-hex id-a)
                         :session-id sid
                         :role :initiator
                         :transport :tcp
                         :remote-candidates [(str "tcp://127.0.0.1:" port-a)]}]
          (light-shell/dial-p2p-peer! state-atom-b p2p-peers-b ingress-peers-b (atom {}) (:privkey-bytes id-b) #(swap! events-b conj %) dial-info)
          (let [deadline (+ (System/currentTimeMillis) 3000)]
            (while (and (< (System/currentTimeMillis) deadline)
                        (not (and (true? (get-in @state-atom-b [:sessions sid :p2p :connected?]))
                                  (true? (get-in @state-atom-a [:sessions sid :p2p :connected?])))))
              (Thread/sleep 50)))
          (is (true? (get-in @state-atom-b [:sessions sid :p2p :connected?])) "Node B direct P2P connected")
          (is (true? (get-in @state-atom-a [:sessions sid :p2p :connected?])) "Node A direct P2P connected via :p2p-link-bind")
          (is (some #(= "p2p-connected" (get % "event")) @events-b) "Node B emitted p2p-connected event")
          (is (some #(= "p2p-connected" (get % "event")) @events-a) "Node A emitted p2p-connected event")

          (let [send-res (light-core/handle-command @state-atom-b
                                                    {"cmd" "send" "session_id" sid "text" "direct zero burn payload"}
                                                    (:privkey-bytes id-b))]
            (is (= 0 (get-in send-res [:response "burn"])) "Send burned 0 ECH")
            (is (true? (get-in send-res [:response "p2p"])) "Send flagged as direct p2p")
            (is (true? (:p2p-direct? (first (:net-envelopes send-res)))) "Envelope flagged :p2p-direct?")
            (reset! state-atom-b (:state send-res))
            (light-shell/route-net-envelope! (first (:net-envelopes send-res)) nil p2p-peers-b ingress-peers-b state-atom-b (:privkey-bytes id-b))
            (let [deadline (+ (System/currentTimeMillis) 3000)]
              (while (and (< (System/currentTimeMillis) deadline)
                          (empty? (:inbox @state-atom-a)))
                (Thread/sleep 50)))
            (is (= 1 (count (:inbox @state-atom-a))) "Node A received 1:1 message")
            (is (= "direct zero burn payload" (:text (first (:inbox @state-atom-a)))) "Message content matches"))

          (let [bcast-res (light-core/handle-command @state-atom-b
                                                     {"cmd" "broadcast" "text" "mesh broadcast zero burn"}
                                                     (:privkey-bytes id-b))]
            (is (true? (get-in bcast-res [:response "zero_burn"])) "Broadcast flagged zero_burn")
            (is (true? (:p2p-broadcast? (first (:net-envelopes bcast-res)))) "Envelope flagged :p2p-broadcast?")
            (reset! state-atom-b (:state bcast-res))
            (light-shell/route-net-envelope! (first (:net-envelopes bcast-res)) nil p2p-peers-b ingress-peers-b state-atom-b (:privkey-bytes id-b))
            (let [deadline (+ (System/currentTimeMillis) 3000)]
              (while (and (< (System/currentTimeMillis) deadline)
                          (empty? (:broadcast-inbox @state-atom-a)))
                (Thread/sleep 50)))
            (is (= 1 (count (:broadcast-inbox @state-atom-a))) "Node A received broadcast")
            (is (= "mesh broadcast zero burn" (:text (first (:broadcast-inbox @state-atom-a)))) "Broadcast text matches")))
        (finally
          (when-let [stop-fn (:stop! listener)]
            (stop-fn))
          (doseq [f (reverse (file-seq (.toFile temp-dir)))]
            (.delete f)))))))

(deftest test-p2p-dial-seam-and-link-bind-auth
  (testing "handle-serve-line! :p2p-dial dispatch seam, F-R6 ingress link-bind auth, and F-R1 stale close guard"
    (let [temp-dir (Files/createTempDirectory "p2p-seam-test-" (into-array FileAttribute []))
          dir-a (str (.resolve temp-dir "node-a"))
          dir-b (str (.resolve temp-dir "node-b"))
          dir-att (str (.resolve temp-dir "node-att"))
          id-a (light-shell/load-or-create-light-identity! dir-a)
          id-b (light-shell/load-or-create-light-identity! dir-b)
          id-att (light-shell/load-or-create-light-identity! dir-att)
          port-a (let [ss (ServerSocket. 0)]
                   (try (.getLocalPort ss) (finally (.close ss))))
          init-a (light-core/init-light-state id-a {:subnet-id "chat/simon-nexus-axiom" :economy-enabled? false :burn-floor 0 :epoch 10})
          init-b (light-core/init-light-state id-b {:subnet-id "chat/simon-nexus-axiom" :economy-enabled? false :burn-floor 0 :epoch 10})
          off-res (light-core/handle-command init-a
                                             {"cmd" "offer" "callee" (:pubkey-hex id-b) "price" 0 "burn" 0}
                                             (:privkey-bytes id-a))
          sid (get-in off-res [:response "session_id"])
          state-a-off (:state off-res)
          b-off-res (reduce (fn [st env] (:state (light-core/handle-wire-payload st env (:privkey-bytes id-b))))
                            init-b
                            (:net-envelopes off-res))
          b-acc-res (light-core/handle-command b-off-res {"cmd" "accept" "session_id" sid} (:privkey-bytes id-b))
          state-b-open (:state b-acc-res)
          a-acc-res (reduce (fn [st env] (:state (light-core/handle-wire-payload st env (:privkey-bytes id-a))))
                            state-a-off
                            (:net-envelopes b-acc-res))
          state-a-open a-acc-res
          state-atom-a (atom state-a-open)
          state-atom-b (atom state-b-open)
          p2p-peers-a (atom {})
          ingress-peers-a (atom {})
          events-a (atom [])
          p2p-peers-b (atom {})
          ingress-peers-b (atom {})
          events-b (atom [])
          sw-b (StringWriter.)
          pw-b (PrintWriter. sw-b)
          listener (light-shell/start-ingress-tcp-listener! id-a
                                                            {:ingress-tcp-port port-a
                                                             :state-atom state-atom-a
                                                             :p2p-peers-atom p2p-peers-a
                                                             :ingress-peers-atom ingress-peers-a
                                                             :event-out #(swap! events-a conj %)})
          ctx-b {:state-atom state-atom-b
                 :conn-atom (atom {:ok? true :channel-id (atom 1)})
                 :out-writer pw-b
                 :events-out events-b
                 :state-file nil
                 :identity id-b
                 :bootstrap nil
                 :conn-opts nil
                 :ingress-peers-atom ingress-peers-b
                 :p2p-peers-atom p2p-peers-b
                 :mdns-atom (atom (mdns/init-mdns-table))}]
      (try
        ;; 1. Node A offers P2P upgrade with TCP candidate
        (let [p2p-off (light-core/handle-command @state-atom-a
                                                 {"cmd" "p2p-offer"
                                                  "session_id" sid
                                                  "candidates" [(str "tcp://127.0.0.1:" port-a)]}
                                                 (:privkey-bytes id-a))]
          (reset! state-atom-a (:state p2p-off))
          ;; Feed A's offer envelope to Node B
          (doseq [env (:net-envelopes p2p-off)]
            (let [res (light-core/handle-wire-payload @state-atom-b env (:privkey-bytes id-b))]
              (reset! state-atom-b (:state res))))
          (is (= :offer-received (get-in @state-atom-b [:sessions sid :p2p :phase])) "Node B received P2P offer")

          ;; 2. Drive p2p-answer through handle-serve-line! on Node B (the shell dispatch seam!)
          (let [ans-line (json/write-str {"cmd" "p2p-answer" "session_id" sid})]
            (light-shell/handle-serve-line! ans-line ctx-b))

          ;; Wait for automatic P2P DataChannel dial and :p2p-link-bind handshake
          (let [deadline (+ (System/currentTimeMillis) 3000)]
            (while (and (< (System/currentTimeMillis) deadline)
                        (not (and (true? (get-in @state-atom-b [:sessions sid :p2p :connected?]))
                                  (true? (get-in @state-atom-a [:sessions sid :p2p :connected?])))))
              (Thread/sleep 50)))
          (is (true? (get-in @state-atom-b [:sessions sid :p2p :connected?])) "Node B connected via seam")
          (is (true? (get-in @state-atom-a [:sessions sid :p2p :connected?])) "Node A connected via seam")
          (let [b-entry (get @p2p-peers-b (:pubkey-hex id-a))]
            (is (some? b-entry) "Node B registered peer in p2p-peers-atom")
            (is (pos? (:generation b-entry)) "Node B assigned positive generation"))

          ;; 3. F-R6: Attacker attempts unauthorized :p2p-link-bind for sid
          (let [attacker-node (api/create-node {:port 0 :setup "active"})
                attacker-prom (promise)
                attacker-cid (atom nil)
                forged-bind (light-shell/build-p2p-link-bind-envelope (:pubkey-hex id-att) (:privkey-bytes id-att) sid)
                initial-rej (long (or (get-in @state-atom-a [:diagnostics :p2p-signaling-rejected]) 0))]
            (api/set-callbacks!
             attacker-node
             {:on-open (fn [evt]
                         (let [cid (or (:channel-id evt) (:stream-id evt) 0)]
                           (reset! attacker-cid cid)
                           (deliver attacker-prom true)))})
            (api/start-tcp! attacker-node {:ip "127.0.0.1" :port port-a} {})
            (is (= true (deref attacker-prom 2000 :timeout)) "Attacker connected to ingress port")
            (when-let [cid @attacker-cid]
              (api/send! attacker-node (fressian/encode-wire forged-bind) cid))
            (Thread/sleep 200)
            (is (nil? (get @p2p-peers-a (:pubkey-hex id-att))) "Attacker was NOT bound in Node A p2p-peers-atom")
            (is (> (long (or (get-in @state-atom-a [:diagnostics :p2p-signaling-rejected]) 0)) initial-rej)
                "F-R6: Node A incremented :p2p-signaling-rejected on forged link-bind")
            (api/close! attacker-node)

            ;; 4. F-R1: Stale generation :on-close does not evict newer generation in p2p-peers-atom
            (let [norm-b (:pubkey-hex id-b)
                  current-entry (get @p2p-peers-a norm-b)
                  current-gen (:generation current-entry)
                  old-close-fn (:close-fn current-entry)
                  initial-stale (long (or (get-in @state-atom-a [:diagnostics :ignored-stale]) 0))]
              (is (some? current-entry) "Node B currently bound in Node A")
              ;; Bump generation in p2p-peers-a to simulate a newer generation taking over
              (swap! p2p-peers-a assoc-in [norm-b :generation] (+ current-gen 10))
              (when (get @p2p-peers-b (:pubkey-hex id-a))
                (swap! p2p-peers-b update-in [(:pubkey-hex id-a) :generation] #(+ (long (or % 0)) 10)))
              ;; Now close the bound connection using old-close-fn and Node B close-fn
              (when-let [b-close (:close-fn (get @p2p-peers-b (:pubkey-hex id-a)))]
                (b-close))
              (when old-close-fn
                (old-close-fn))
              (let [deadline (+ (System/currentTimeMillis) 2000)]
                (while (and (< (System/currentTimeMillis) deadline)
                            (<= (long (or (get-in @state-atom-a [:diagnostics :ignored-stale]) 0)) initial-stale))
                  (Thread/sleep 50)))
              ;; Verify Node B entry is STILL present in p2p-peers-a with the newer generation
              (is (contains? @p2p-peers-a norm-b) "F-R1: Newer generation entry was NOT evicted by stale close")
              (is (= (+ current-gen 10) (get-in @p2p-peers-a [norm-b :generation]))
                  "F-R1: Newer generation preserved")
              (is (> (long (or (get-in @state-atom-a [:diagnostics :ignored-stale]) 0)) initial-stale)
                  "F-R1: Diagnostic counter strictly incremented on stale bound close"))

            ;; 5. F-G2: nil/zero generation stale close when live entry exists
            (let [norm-b (:pubkey-hex id-b)
                  stale-before (long (or (get-in @state-atom-a [:diagnostics :ignored-stale]) 0))
                  conn2 (api/create-node {:port 0 :setup "active"})
                  conn2-prom (promise)
                  conn2-cid (atom nil)
                  sess-b (get-in @state-atom-b [:sessions sid])
                  tx-k (:tx-key sess-b)
                  suite (or (:suite sess-b) sealed/suite-v1-chacha20poly1305)
                  seq-num (inc (long (or (:tx-seq sess-b) 0)))
                  sealed-m (sealed/seal-message tx-k seq-num (.getBytes "test nil gen" "UTF-8") (.getBytes sid "UTF-8") suite)
                  msg-env {:protocol-version 1
                           :wire-format "fressian-v1"
                           :subnet-id "chat/simon-nexus-axiom"
                           :bitecho/type :sealed-message
                           :type :sealed-message
                           :session-id sid
                           :sender norm-b
                           :recipient (:pubkey-hex id-a)
                           :epoch 10
                           :seq seq-num
                           :suite suite
                           :nonce (basalt/bytes->hex (:nonce sealed-m))
                           :ciphertext (basalt/bytes->hex (:ciphertext sealed-m))}]
              (api/set-callbacks!
               conn2
               {:on-open (fn [evt]
                           (let [cid (or (:channel-id evt) (:stream-id evt) 0)]
                             (reset! conn2-cid cid)
                             (deliver conn2-prom true)))})
              (api/start-tcp! conn2 {:ip "127.0.0.1" :port port-a} {})
              (is (= true (deref conn2-prom 2000 :timeout)) "Conn 2 connected to port A")
              (when-let [cid @conn2-cid]
                (let [payload (if (bytes? msg-env) msg-env (fressian/encode-wire msg-env))]
                  (api/send! conn2 payload cid)))
              (Thread/sleep 150)
              (api/close! conn2)
              (let [deadline (+ (System/currentTimeMillis) 2000)]
                (while (and (< (System/currentTimeMillis) deadline)
                            (<= (long (or (get-in @state-atom-a [:diagnostics :ignored-stale]) 0)) stale-before))
                  (Thread/sleep 50)))
              (is (contains? @p2p-peers-a norm-b) "F-G2: Live entry preserved after nil-generation close")
              (is (> (long (or (get-in @state-atom-a [:diagnostics :ignored-stale]) 0)) stale-before)
                  "F-G2: Diagnostic counter strictly incremented on nil-generation close")
              (try (api/close! conn2) (catch Exception _ nil)))))
        (finally
          (when-let [stop-fn (:stop! listener)]
            (stop-fn))
          (doseq [f (reverse (file-seq (.toFile temp-dir)))]
            (.delete f)))))))


