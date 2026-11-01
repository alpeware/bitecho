(ns bitecho.shell.light-node-test
  "Unit, integration, and E2E tests for the Bitecho light-node boundary shell."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.light-node :as light-shell]
            [bitecho.shell.mesh :as mesh]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [datachannel.api :as api])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

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
