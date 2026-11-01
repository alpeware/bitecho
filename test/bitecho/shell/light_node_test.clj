(ns bitecho.shell.light-node-test
  "Unit, integration, and E2E tests for the Bitecho light-node boundary shell."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.light-node :as light-shell]
            [bitecho.shell.mesh :as mesh]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [datachannel.api :as api])
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
                      :nodes {:node1 {:node-id :node1
                                      :ip "127.0.0.1"
                                      :agent-port 5010
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
