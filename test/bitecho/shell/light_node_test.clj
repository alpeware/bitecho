(ns bitecho.shell.light-node-test
  "Unit, integration, and E2E tests for the Bitecho light-node boundary shell."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
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
          verbs ["serve" "identity" "status" "discover" "register-home-set"
                 "offer" "accept" "send" "inbox" "close" "transfer"
                 "account" "sync-account" "settle-intent" "submit-vouchers"
                 "petname-set" "petname-list" "petname-remove" "petname-resolve"
                 "dac-attach" "dac-revoke" "directory-verify"
                 "rendezvous-policy" "rendezvous-offer" "rendezvous-accept"
                 "lock-intent" "release-intent" "refund-intent" "escrows"]
          flags #{"--state-dir" "--bootstrap" "--autonomous" "--transport" "--proxy"
                  "--timeout-ms" "--callee" "--price" "--price-max" "--burn" "--home-node"
                  "--session" "--session-id" "--text" "--payload-hex" "--receiver"
                  "--recipient" "--amount" "--seq" "--nodes" "--balance" "--sync"
                  "--petname" "--pubkey" "--overwrite" "--directory-pubkey"
                  "--min-burn" "--allowlist" "--auto-accept" "--topic" "--to"
                  "--offer-hash" "--from"
                  "--escrow-id" "--deliverable-hash" "--expires-epoch" "--preimage"}]
      ;; All verbs documented in SKILL.md
      (doseq [v verbs]
        (is (str/includes? skill-md v) (str "Verb documented in SKILL.md: " v)))
      ;; Exact bidirectional flag inventory parity between SKILL.md and parser test suite
      (is (= flags documented-flags))
      ;; Handled by parser:
      ;; Verbs
      (is (= :serve (:mode (light-shell/parse-light-node-args ["serve"]))))
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
      ;; Flags (all 37 flags tested end-to-end)
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
      (is (= "alice" (get-in (light-shell/parse-light-node-args ["petname-set" "--petname" "alice" "--pubkey" "deadbeef" "--overwrite"]) [:cmd-map "petname"])))
      (is (= "deadbeef" (get-in (light-shell/parse-light-node-args ["petname-set" "--petname" "alice" "--pubkey" "deadbeef" "--overwrite"]) [:cmd-map "pubkey"])))
      (is (true? (get-in (light-shell/parse-light-node-args ["petname-set" "--petname" "alice" "--pubkey" "deadbeef" "--overwrite"]) [:cmd-map "overwrite"])))
      ;; Flags (all 22 flags tested end-to-end)
      (is (= "foo/bar" (:state-dir (light-shell/parse-light-node-args ["status" "--state-dir" "foo/bar"]))))
      (is (= "boot.edn" (:bootstrap (light-shell/parse-light-node-args ["status" "--bootstrap" "boot.edn"]))))
      (is (true? (:autonomous? (light-shell/parse-light-node-args ["serve" "--autonomous"]))))
      (is (= :tcp (:transport (light-shell/parse-light-node-args ["status" "--transport" "tcp"]))))
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
      (is (= "rcpt-pub" (get-in (light-shell/parse-light-node-args ["transfer" "--recipient" "rcpt-pub"]) [:cmd-map "recipient"])))
      (is (= 100 (get-in (light-shell/parse-light-node-args ["transfer" "--amount" "100"]) [:cmd-map "amount"])))
      (is (= 7 (get-in (light-shell/parse-light-node-args ["transfer" "--seq" "7"]) [:cmd-map "seq"])))
      (is (= ["n1" "n2"] (get-in (light-shell/parse-light-node-args ["register-home-set" "--nodes" "n1,n2"]) [:cmd-map "home_nodes"])))
      (is (= 5000 (get-in (light-shell/parse-light-node-args ["account" "--balance" "5000"]) [:cmd-map "balance"])))
      (is (true? (get-in (light-shell/parse-light-node-args ["account" "--sync"]) [:cmd-map "sync"]))))))

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
  (testing "Duplicate same-generation :on-close callback invokes reconnect-fn only once"
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

      ;; Duplicate same-generation :on-close invocation (when :phase is no longer :open)
      (on-close nil)
      (is (= 1 @reconn-count) "Duplicate same-generation :on-close must NOT trigger reconnect-fn a second time"))))

