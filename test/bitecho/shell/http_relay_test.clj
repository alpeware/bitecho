(ns bitecho.shell.http-relay-test
  "Integration test suite for HTTP Gateway Relay (/relay/v1/*) endpoints
   verifying end-to-end light-node communication, proof-of-possession auth,
   long-polling, payload limits, and chain-state over cleartext and HTTPS."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http-shell]
            [bitecho.shell.light-node :as light-node]
            [clojure.data.json :as json]
            [clojure.test :refer [deftest is testing]])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(defn- make-tmp-dir! []
  (let [p (Files/createTempDirectory "bitecho-http-relay-test-" (into-array FileAttribute []))]
    (.toFile p)))

(deftest test-relay-chain-state-and-payload-limit
  (let [tmp-dir (make-tmp-dir!)
        tls-mgr (http-shell/init-tls-manager! {:state-dir tmp-dir :domain "localhost"})
        relay-atom (atom (relay/init-relay-state {:max-payload-bytes 65536}))
        relay-waiters-atom (atom {})
        cfg {:domain "bitecho.org"
             :state-dir tmp-dir
             :relay-atom relay-atom
             :relay-waiters-atom relay-waiters-atom
             :http {:bind-ip "127.0.0.1"
                    :http-port 0
                    :https-port 0
                    :cache-max-file-bytes 65536}}
        srv (http-shell/start-http-servers! cfg tls-mgr nil)]
    (try
      (let [http-port (:http-port srv)
            relay-url (str "http://127.0.0.1:" http-port)]

        (testing "chain-state endpoint returns root, epoch, min signaling burn, bootstrap info"
          (let [res (light-node/fetch-relay-chain-state! relay-url)]
            (is (true? (get res "ok")))
            (is (contains? res "snapshots"))
            (is (= 100 (get res "min_signaling_burn")))
            (is (= "bitecho.org" (get res "bootstrap")))))

        (testing "payload exceeding max-payload-bytes (>64KB) returns 413"
          (let [big-bytes (byte-array 70000)
                client (HttpClient/newHttpClient)
                req (-> (HttpRequest/newBuilder)
                        (.uri (URI/create (str relay-url "/relay/v1/send")))
                        (.header "Content-Type" "application/octet-stream")
                        (.POST (HttpRequest$BodyPublishers/ofByteArray big-bytes))
                        (.build))
                resp (.send client req (HttpResponse$BodyHandlers/ofString))
                body (json/read-str (.body resp))]
            (is (= 413 (.statusCode resp)))
            (is (false? (get body "ok")))
            (is (= "payload-too-large" (get body "error"))))))
      (finally
        ((:stop-fn srv))))))

(deftest test-relay-end-to-end-light-node-p2p-and-long-polling
  (let [tmp-dir (make-tmp-dir!)
        tls-mgr (http-shell/init-tls-manager! {:state-dir tmp-dir :domain "localhost"})
        relay-atom (atom (relay/init-relay-state {:min-signaling-burn 0}))
        relay-waiters-atom (atom {})
        chain-fetcher-atom (atom nil)
        cfg {:domain "bitecho.org"
             :state-dir tmp-dir
             :relay-atom relay-atom
             :relay-waiters-atom relay-waiters-atom
             :chain-state-fetcher (fn [pk nonce] (when-let [f @chain-fetcher-atom] (f pk nonce)))
             :http {:bind-ip "127.0.0.1"
                    :http-port 0
                    :https-port 0}}
        srv (http-shell/start-http-servers! cfg tls-mgr nil)]
    (try
      (let [http-port (:http-port srv)
            relay-url (str "http://127.0.0.1:" http-port)
            alice-kp (crypto/generate-keypair)
            bob-kp (crypto/generate-keypair)
            alice-id {:pubkey-hex (basalt/bytes->hex (:public-key alice-kp))
                      :privkey-bytes (:private-key alice-kp)}
            bob-id {:pubkey-hex (basalt/bytes->hex (:public-key bob-kp))
                    :privkey-bytes (:private-key bob-kp)}
            init-a (light-core/init-light-state alice-id {:subnet-id "test/relay-e2e"
                                                          :economy-enabled? false
                                                          :burn-floor 0
                                                          :epoch 1})
            init-b (light-core/init-light-state bob-id {:subnet-id "test/relay-e2e"
                                                        :economy-enabled? false
                                                        :burn-floor 0
                                                        :epoch 1})]

        (testing "Proof-of-possession failure returns 403 on poll"
          (let [bogus-kp (crypto/generate-keypair)
                res (light-node/poll-relay-envelopes! relay-url (:pubkey-hex bob-id) (:private-key bogus-kp))]
            (is (= 403 (get res "status" 403)))
            (is (false? (get res "ok")))
            (is (= "poll-auth-failed" (get res "error")))))

        (testing "End-to-end session offer -> poll -> accept -> ack -> sealed message"
          ;; 1. Alice creates offer
          (let [off-res (light-core/handle-command init-a
                                                   {"cmd" "offer" "callee" (:pubkey-hex bob-id) "price" 0 "burn" 0}
                                                   (:privkey-bytes alice-id))
                sid (get-in off-res [:response "session_id"])
                off-envs (:net-envelopes off-res)]
            (is (seq off-envs))
            (is (string? sid))

            ;; 2. Alice submits offer to relay
            (doseq [env off-envs]
              (let [submit-res (light-node/submit-relay-envelope! relay-url env)]
                (is (true? (get submit-res "ok")))
                (is (contains? #{"accepted" "forwarded"} (get submit-res "status")))))

            ;; 3. Bob polls relay, receives Alice's offer envelopes (both header and gossip)
            (let [poll-b (light-node/poll-relay-envelopes! relay-url (:pubkey-hex bob-id) (:privkey-bytes bob-id))
                  messages (get poll-b "messages" [])
                  bcasts (get poll-b "broadcasts" [])
                  all-b-items (concat messages bcasts)]
              (is (true? (get poll-b "ok")))
              (is (pos? (count all-b-items)))
              (let [b-off-res (reduce (fn [st item]
                                        (let [raw-hex (or (get item "envelope_hex") (get item "envelope"))
                                              env-bytes (basalt/hex->bytes raw-hex)]
                                          (:state (light-core/handle-wire-payload st env-bytes (:privkey-bytes bob-id)))))
                                      init-b
                                      all-b-items)]
                (is (contains? (:pending-offers b-off-res) sid))

                ;; 4. Bob accepts session
                (let [acc-res (light-core/handle-command b-off-res
                                                         {"cmd" "accept" "session_id" sid}
                                                         (:privkey-bytes bob-id))
                      acc-envs (:net-envelopes acc-res)]
                  (is (seq acc-envs))

                  ;; 5. Bob sends accept envelope to relay
                  (doseq [env acc-envs]
                    (let [sub (light-node/submit-relay-envelope! relay-url env)]
                      (is (true? (get sub "ok")))))

                  ;; 6. Bob ACKs processed envelopes if any in inbox
                  (when (seq messages)
                    (let [seq-val (or (get (last messages) "relay_seq") (get (last messages) "relay-seq"))
                          ack-res (light-node/ack-relay-envelopes! relay-url (:pubkey-hex bob-id) (:privkey-bytes bob-id) seq-val)]
                      (is (true? (get ack-res "ok")))
                      (is (= (count messages) (get ack-res "pruned")))))

                  ;; 7. Alice polls relay, receives Bob's accept
                  (let [poll-a (light-node/poll-relay-envelopes! relay-url (:pubkey-hex alice-id) (:privkey-bytes alice-id))
                        a-messages (concat (get poll-a "messages" []) (get poll-a "broadcasts" []))]
                    (is (true? (get poll-a "ok")))
                    (is (pos? (count a-messages)))
                    (let [state-a-open (reduce (fn [st item]
                                                 (let [raw-hex (or (get item "envelope_hex") (get item "envelope"))
                                                       env-bytes (basalt/hex->bytes raw-hex)]
                                                   (:state (light-core/handle-wire-payload st env-bytes (:privkey-bytes alice-id)))))
                                               (:state off-res)
                                               a-messages)]
                      (is (= "open" (get-in state-a-open [:sessions sid :state])))

                      ;; 8. Long-polling verification: Bob drains pending items to obtain the latest seqs,
                      ;; then long-polls with virtual thread parking. Alice submits a sealed message
                      ;; while Bob is parked, and Bob wakes up immediately!
                      (let [pre-poll (light-node/poll-relay-envelopes! relay-url (:pubkey-hex bob-id) (:privkey-bytes bob-id))
                            pre-bcasts (get pre-poll "broadcasts" [])
                            pre-msgs (get pre-poll "messages" [])
                            last-bseq (long (or (get (last pre-bcasts) "broadcast_seq")
                                                (get (last pre-bcasts) "broadcast-seq")
                                                0))
                            last-mseq (long (or (get (last pre-msgs) "relay_seq")
                                                (get (last pre-msgs) "relay-seq")
                                                0))
                            bob-result-box (atom nil)
                            bob-thread (Thread/startVirtualThread
                                        (fn []
                                          (let [r (light-node/poll-relay-envelopes! relay-url
                                                                                    (:pubkey-hex bob-id)
                                                                                    (:privkey-bytes bob-id)
                                                                                    {:timeout-ms 3000
                                                                                     :since-seq last-mseq
                                                                                     :since-broadcast-seq last-bseq})]
                                            (reset! bob-result-box r))))]
                        ;; Brief sleep to ensure Bob is in long-poll wait
                        (Thread/sleep 100)
                        ;; Alice sends sealed message
                        (let [send-res (light-core/handle-command state-a-open
                                                                  {"cmd" "send" "session_id" sid "text" "relay works seamlessly!"}
                                                                  (:privkey-bytes alice-id))
                              msg-envs (:net-envelopes send-res)]
                          (is (seq msg-envs))
                          (doseq [m-env msg-envs]
                            (let [sub (light-node/submit-relay-envelope! relay-url m-env)]
                              (is (true? (get sub "ok"))))))

                        ;; Wait for Bob's virtual thread to finish
                        (.join bob-thread 2000)
                        (let [bob-polled @bob-result-box
                              polled-msgs (concat (get bob-polled "messages" []) (get bob-polled "broadcasts" []))]
                          (is (true? (get bob-polled "ok")))
                          (is (pos? (count polled-msgs)))
                          (let [delivered-events (mapcat (fn [item]
                                                           (let [wire-env (basalt/hex->bytes (or (get item "envelope_hex") (get item "envelope")))
                                                                 r (light-core/handle-wire-payload (:state acc-res) wire-env (:privkey-bytes bob-id))]
                                                             (:stdout-events r)))
                                                         polled-msgs)]
                            (is (some (fn [ev] (and (= "message-received" (get ev "event"))
                                                    (= "relay works seamlessly!" (get ev "text"))))
                                      delivered-events)))))))))))))
      (finally
        ((:stop-fn srv))))))

(deftest test-relay-one-shot-and-account-sync
  (let [tmp-dir (make-tmp-dir!)
        tls-mgr (http-shell/init-tls-manager! {:state-dir tmp-dir :domain "localhost"})
        relay-atom (atom (relay/init-relay-state))
        relay-waiters-atom (atom {})
        chain-fetcher-atom (atom nil)
        cfg {:domain "bitecho.org"
             :state-dir tmp-dir
             :relay-atom relay-atom
             :relay-waiters-atom relay-waiters-atom
             :chain-state-fetcher (fn [pk nonce] (when-let [f @chain-fetcher-atom] (f pk nonce)))
             :http {:bind-ip "127.0.0.1"
                    :http-port 0
                    :https-port 0}}
        srv (http-shell/start-http-servers! cfg tls-mgr nil)]
    (try
      (let [http-port (:http-port srv)
            relay-url (str "http://127.0.0.1:" http-port)
            alice-kp (crypto/generate-keypair)
            alice-id {:pubkey-hex (basalt/bytes->hex (:public-key alice-kp))
                      :privkey-bytes (:private-key alice-kp)}
            v1-kp (crypto/generate-keypair)
            v2-kp (crypto/generate-keypair)
            v3-kp (crypto/generate-keypair)
            v1-pk (basalt/bytes->hex (:public-key v1-kp))
            v2-pk (basalt/bytes->hex (:public-key v2-kp))
            v3-pk (basalt/bytes->hex (:public-key v3-kp))
            dummy-fp "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
            bootstrap {:network :devnet
                       :domain "bitecho.org"
                       :treasury-pubkey (:pubkey-hex alice-id)
                       :custody-pubkey (:pubkey-hex alice-id)
                       :nodes {:v1 {:node-id :v1 :ip "127.0.0.1" :port 5001 :agent-port 5011 :pubkey v1-pk :fingerprint dummy-fp :ice-ufrag "u1" :ice-pwd "p1"}
                               :v2 {:node-id :v2 :ip "127.0.0.1" :port 5002 :agent-port 5012 :pubkey v2-pk :fingerprint dummy-fp :ice-ufrag "u2" :ice-pwd "p2"}
                               :v3 {:node-id :v3 :ip "127.0.0.1" :port 5003 :agent-port 5013 :pubkey v3-pk :fingerprint dummy-fp :ice-ufrag "u3" :ice-pwd "p3"}}}]

        (testing "connect-validators! returns :transport :http-relay when :relay-url is set"
          (let [conn-res (light-node/connect-validators! alice-id bootstrap {:relay-url relay-url})]
            (is (true? (:ok? conn-res)))
            (is (= :http-relay (:transport conn-res)))
            (is (= :http-relay (:validator-id conn-res)))
            (is (fn? (:send-fn conn-res)))))

        (testing "connect-validators! works identically with /relay/v1 suffix in URL"
          (let [conn-res (light-node/connect-validators! alice-id bootstrap {:relay-url (str relay-url "/relay/v1")})]
            (is (true? (:ok? conn-res)))
            (is (= :http-relay (:transport conn-res)))))

        (testing "maybe-sync-account-state! fails closed when relay has snapshots: [] or unsigned snapshots"
          (let [state-atom (atom (light-core/init-light-state alice-id {:subnet-id "test/relay-sync"
                                                                        :economy-enabled? true
                                                                        :burn-floor 0
                                                                        :epoch 0}))
                sync-res (light-node/maybe-sync-account-state! state-atom bootstrap
                                                               (:pubkey-hex alice-id)
                                                               (:privkey-bytes alice-id)
                                                               {:relay-url relay-url})]
            (is (false? (:ok? sync-res)))
            (is (= "no-verified-relay-snapshots" (:error sync-res)))
            (is (= 0 (:burn-floor @state-atom)))
            (is (= 0 (:epoch @state-atom)))
            (is (pos? (get-in @state-atom [:diagnostics :chain-state-sync-failed] 0)))))

        (testing "maybe-sync-account-state! verifies 2f+1 quorum with signed snapshots and works with /relay/v1 suffix"
          (reset! chain-fetcher-atom
                  (fn [pk nonce]
                    [(light-core/sign-chain-state-snapshot
                      {:validator-pubkey v1-pk
                       :pubkey pk
                       :finalized-epoch 15
                       :balance 1000000000
                       :spendable 1000000000
                       :seq 2
                       :nonce nonce}
                      (:private-key v1-kp))
                     (light-core/sign-chain-state-snapshot
                      {:validator-pubkey v2-pk
                       :pubkey pk
                       :finalized-epoch 15
                       :balance 1000000000
                       :spendable 1000000000
                       :seq 2
                       :nonce nonce}
                      (:private-key v2-kp))]))
          (let [state-atom (atom (light-core/init-light-state alice-id {:subnet-id "test/relay-sync"
                                                                        :economy-enabled? true
                                                                        :burn-floor 0
                                                                        :epoch 0}))
                sync-res (light-node/maybe-sync-account-state! state-atom bootstrap
                                                               (:pubkey-hex alice-id)
                                                               (:privkey-bytes alice-id)
                                                               {:relay-url (str relay-url "/relay/v1")})]
            (is (true? (:ok? sync-res)))
            (is (= 15 (:epoch @state-atom)))
            (is (= 1000000000 (get-in @state-atom [:account :balance])))
            (is (= 1000000000 (get-in @state-atom [:account :spendable])))))

        (testing "run-one-shot! submits offer envelope via :relay-url (and /relay/v1 suffix) and succeeds"
          (let [bob-kp (crypto/generate-keypair)
                bob-pk (basalt/bytes->hex (:public-key bob-kp))
                node-state-dir (doto (java.io.File. tmp-dir "node-state") (.mkdirs))
                _ (light-node/load-or-create-light-identity! (str node-state-dir))
                desc-file (java.io.File. tmp-dir "bootstrap.edn")
                _ (spit desc-file (pr-str bootstrap))
                cmd-map {"cmd" "offer" "callee" bob-pk "price" 10 "burn" 100}
                opts {:cmd-map cmd-map
                      :state-dir (str node-state-dir)
                      :bootstrap (str desc-file)
                      :relay-url (str relay-url "/relay/v1")
                      :auto-sync? false}
                res (light-node/run-one-shot! opts)]
            (is (true? (get res "ok")))
            (is (string? (get res "session_id")))
            ;; Verify the envelope was accepted into relay-atom
            (is (pos? (get-in @relay-atom [:diagnostics :submitted] 0)))
            ;; And Bob can poll and ack the envelope from relay using /relay/v1
            (let [poll-b (light-node/poll-relay-envelopes! (str relay-url "/relay/v1") bob-pk (:private-key bob-kp))]
              (is (true? (get poll-b "ok")))
              (is (pos? (+ (count (get poll-b "messages" []))
                           (count (get poll-b "broadcasts" [])))))
              (let [ack-b (light-node/ack-relay-envelopes! (str relay-url "/relay/v1") bob-pk (:private-key bob-kp) 1 {:ack-broadcast-seq 1})]
                (is (true? (get ack-b "ok"))))))))
      (finally
        ((:stop-fn srv))))))

(deftest test-relay-query-pop-rejection-and-waiter-cap
  (let [tmp-dir (make-tmp-dir!)
        tls-mgr (http-shell/init-tls-manager! {:state-dir tmp-dir :domain "localhost"})
        relay-atom (atom (relay/init-relay-state {:min-signaling-burn 0}))
        relay-waiters-atom (atom {})
        cfg {:domain "bitecho.org"
             :state-dir tmp-dir
             :relay-atom relay-atom
             :relay-waiters-atom relay-waiters-atom
             :max-relay-waiters-per-pubkey 4
             :http {:bind-ip "127.0.0.1"
                    :http-port 0
                    :https-port 0}}
        srv (http-shell/start-http-servers! cfg tls-mgr nil)]
    (try
      (let [http-port (:http-port srv)
            relay-url (str "http://127.0.0.1:" http-port)
            alice-kp (crypto/generate-keypair)
            alice-pk (basalt/bytes->hex (:public-key alice-kp))
            client (HttpClient/newHttpClient)]

        (testing "Test 1: Query-string-only PoP rejection returns 403 missing-pop-headers"
          (let [now-ms (System/currentTimeMillis)
                nonce "0123456789abcdef0123456789abcdef"
                sig (relay/sign-poll-request (:private-key alice-kp)
                                             {:pubkey alice-pk
                                              :since-seq 0
                                              :timestamp-ms now-ms
                                              :nonce nonce})
                uri (URI/create (str relay-url "/relay/v1/poll?pubkey=" alice-pk
                                     "&since_seq=0&sig=" sig "&signature=" sig
                                     "&ts=" now-ms "&timestamp_ms=" now-ms
                                     "&nonce=" nonce))
                req (-> (HttpRequest/newBuilder)
                        (.uri uri)
                        (.GET)
                        (.build))
                resp (.send client req (HttpResponse$BodyHandlers/ofString))
                body (json/read-str (.body resp))]
            (is (= 403 (.statusCode resp)))
            (is (false? (get body "ok")))
            (is (= "missing-pop-headers" (get body "error")))))

        (testing "Test 2: Per-client waiter cap returns 429 too-many-client-waiters on 5th poll"
          (let [threads (atom [])
                results (atom [])]
            (dotimes [_ 4]
              (let [th (Thread/startVirtualThread
                        (fn []
                          (let [r (light-node/poll-relay-envelopes! relay-url alice-pk (:private-key alice-kp) {:timeout-ms 2000})]
                            (swap! results conj r))))]
                (swap! threads conj th)))
            ;; Wait briefly so all 4 virtual threads are registered in relay-waiters-atom
            (Thread/sleep 150)
            (is (= 4 (count (get @relay-waiters-atom alice-pk #{}))))
            ;; 5th poll should immediately fail with 429 too-many-client-waiters
            (let [now-ms (System/currentTimeMillis)
                  nonce "fifth-poll-nonce-1234567890123"
                  sig (relay/sign-poll-request (:private-key alice-kp)
                                               {:pubkey alice-pk
                                                :since-seq 0
                                                :timestamp-ms now-ms
                                                :nonce nonce})
                  uri (URI/create (str relay-url "/relay/v1/poll?pubkey=" alice-pk "&since_seq=0"))
                  req (-> (HttpRequest/newBuilder)
                          (.uri uri)
                          (.header "X-Bitecho-Pubkey" alice-pk)
                          (.header "X-Bitecho-Since-Seq" "0")
                          (.header "X-Bitecho-Since-Broadcast-Seq" "0")
                          (.header "X-Bitecho-Timestamp-Ms" (str now-ms))
                          (.header "X-Bitecho-Nonce" nonce)
                          (.header "X-Bitecho-Signature" sig)
                          (.header "X-Bitecho-Wait-Ms" "2000")
                          (.GET)
                          (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))
                  body (json/read-str (.body resp))]
              (is (= 429 (.statusCode resp)))
              (is (false? (get body "ok")))
              (is (= "too-many-client-waiters" (get body "error"))))
            ;; Wake up the parked threads so test completes cleanly
            (doseq [p (get @relay-waiters-atom alice-pk #{})]
              (deliver p :done))
            (doseq [th @threads]
              (.join th 2000)))))
      (finally
        ((:stop-fn srv))))))

(deftest test-relay-peer-replication-ring
  (let [tmp-dir1 (make-tmp-dir!)
        tmp-dir2 (make-tmp-dir!)
        tls-mgr1 (http-shell/init-tls-manager! {:state-dir tmp-dir1 :domain "localhost"})
        tls-mgr2 (http-shell/init-tls-manager! {:state-dir tmp-dir2 :domain "localhost"})
        relay-atom1 (atom (relay/init-relay-state {:min-signaling-burn 0}))
        relay-atom2 (atom (relay/init-relay-state {:min-signaling-burn 0}))
        waiters1 (atom {})
        waiters2 (atom {})
        cfg2-initial {:domain "bitecho.org"
                      :state-dir tmp-dir2
                      :node-id :srv2
                      :relay-atom relay-atom2
                      :relay-waiters-atom waiters2
                      :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
        srv2 (http-shell/start-http-servers! cfg2-initial tls-mgr2 nil)
        port2 (:http-port srv2)
        cfg1 {:domain "bitecho.org"
              :state-dir tmp-dir1
              :node-id :srv1
              :relay-atom relay-atom1
              :relay-waiters-atom waiters1
              :cluster {:nodes {:srv1 {:node-id :srv1 :ip "127.0.0.1" :http-port 0}
                                :srv2 {:node-id :srv2 :ip "127.0.0.1" :http-port port2}}}
              :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
        srv1 (http-shell/start-http-servers! cfg1 tls-mgr1 nil)
        port1 (:http-port srv1)]
    (try
      (let [relay-url1 (str "http://127.0.0.1:" port1)
            relay-url2 (str "http://127.0.0.1:" port2)
            alice-kp (crypto/generate-keypair)
            bob-kp (crypto/generate-keypair)
            alice-id {:pubkey-hex (basalt/bytes->hex (:public-key alice-kp))
                      :privkey-bytes (:private-key alice-kp)}
            bob-id {:pubkey-hex (basalt/bytes->hex (:public-key bob-kp))
                    :privkey-bytes (:private-key bob-kp)}
            init-a (light-core/init-light-state alice-id {:subnet-id "test/repl" :economy-enabled? false :burn-floor 0 :epoch 1})
            off-res (light-core/handle-command init-a
                                               {"cmd" "offer" "callee" (:pubkey-hex bob-id) "price" 0 "burn" 0}
                                               (:privkey-bytes alice-id))
            off-envs (:net-envelopes off-res)]
        (is (seq off-envs))
        ;; Submit offer to Server 1
        (doseq [env off-envs]
          (let [res (light-node/submit-relay-envelope! relay-url1 env)]
            (is (true? (get res "ok")))))
        ;; Brief sleep for parallel replication to deliver to Server 2
        (Thread/sleep 200)
        ;; Bob polls Server 2, verifying envelopes were replicated to Server 2!
        (let [poll-b (light-node/poll-relay-envelopes! relay-url2 (:pubkey-hex bob-id) (:privkey-bytes bob-id))
              msgs (concat (get poll-b "messages" []) (get poll-b "broadcasts" []))]
          (is (true? (get poll-b "ok")))
          (is (pos? (count msgs)))))
      (finally
        ((:stop-fn srv1))
        ((:stop-fn srv2))))))

