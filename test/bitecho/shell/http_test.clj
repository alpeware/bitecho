(ns bitecho.shell.http-test
  "Unit tests for HTTP Gateway Relay replication authentication (F-P0-1 / F-Bb-1).
   Ensures that external requests attempting to spoof X-Bitecho-Relay-Replicated
   are rejected with 403 Forbidden and counted in :unauthorized-replication diagnostics,
   while legitimately authenticated requests with HMAC-SHA256 are accepted."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http-shell]
            [clojure.data.json :as json]
            [clojure.test :refer [deftest is testing]])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(defn- make-tmp-dir! []
  (let [p (Files/createTempDirectory "bitecho-http-test-" (into-array FileAttribute []))]
    (.toFile p)))

(deftest test-f-p0-1-unauthorized-replication-rejection-and-diagnostics
  (let [tmp-dir (make-tmp-dir!)
        shared-secret (.getBytes "super-secret-cluster-token" StandardCharsets/UTF_8)
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
            bob-kp (crypto/generate-keypair)
            alice-id {:pubkey-hex (basalt/bytes->hex (:public-key alice-kp))
                      :privkey-bytes (:private-key alice-kp)}
            bob-id {:pubkey-hex (basalt/bytes->hex (:public-key bob-kp))
                    :privkey-bytes (:private-key bob-kp)}
            init-a (light-core/init-light-state alice-id {:subnet-id "test/http-auth" :economy-enabled? false :burn-floor 0 :epoch 1})
            off-res (light-core/handle-command init-a
                                               {"cmd" "offer" "callee" (:pubkey-hex bob-id) "price" 0 "burn" 0}
                                               (:privkey-bytes alice-id))
            raw-env (first (:net-envelopes off-res))
            wire-hex (basalt/bytes->hex (fressian/encode-canonical raw-env))
            env-bytes (.getBytes (json/write-str {"envelope_hex" wire-hex}) StandardCharsets/UTF_8)]

        (testing "1. Spoofed X-Bitecho-Relay-Replicated on /relay/v1/send without auth returns 403 and counts diagnostic"
          (let [req (-> (HttpRequest/newBuilder)
                        (.uri (URI/create (str base-url "/relay/v1/send")))
                        (.header "Content-Type" "application/octet-stream")
                        (.header "X-Bitecho-Relay-Replicated" "true")
                        (.POST (HttpRequest$BodyPublishers/ofByteArray env-bytes))
                        (.build))
                resp (.send client req (HttpResponse$BodyHandlers/ofString))
                body (json/read-str (.body resp))]
            (is (= 403 (.statusCode resp)))
            (is (false? (get body "ok")))
            (is (= "unauthorized-replication" (get body "error")))
            (is (= 1 (get-in @relay-atom [:diagnostics :unauthorized-replication])))))

        (testing "2. Spoofed X-Bitecho-Relay-Replicated on /relay/v1/send with bogus auth returns 403 and counts diagnostic"
          (let [req (-> (HttpRequest/newBuilder)
                        (.uri (URI/create (str base-url "/relay/v1/send")))
                        (.header "Content-Type" "application/octet-stream")
                        (.header "X-Bitecho-Relay-Replicated" "true")
                        (.header "X-Bitecho-Relay-Auth" "deadbeefcafebabe00112233445566778899aabbccddeeff")
                        (.POST (HttpRequest$BodyPublishers/ofByteArray env-bytes))
                        (.build))
                resp (.send client req (HttpResponse$BodyHandlers/ofString))
                body (json/read-str (.body resp))]
            (is (= 403 (.statusCode resp)))
            (is (false? (get body "ok")))
            (is (= "unauthorized-replication" (get body "error")))
            (is (= 2 (get-in @relay-atom [:diagnostics :unauthorized-replication])))))

        (testing "3. Legitimate intra-ring replication with valid HMAC on /relay/v1/send succeeds with 200"
          (let [auth-hmac (http-shell/compute-relay-auth-hmac shared-secret "/relay/v1/send" env-bytes)
                req (-> (HttpRequest/newBuilder)
                        (.uri (URI/create (str base-url "/relay/v1/send")))
                        (.header "Content-Type" "application/octet-stream")
                        (.header "X-Bitecho-Relay-Replicated" "true")
                        (.header "X-Bitecho-Relay-Auth" auth-hmac)
                        (.POST (HttpRequest$BodyPublishers/ofByteArray env-bytes))
                        (.build))
                resp (.send client req (HttpResponse$BodyHandlers/ofString))
                body (json/read-str (.body resp))]
            (is (= 200 (.statusCode resp)))
            (is (true? (get body "ok")))
            ;; Diagnostic count did not increment
            (is (= 2 (get-in @relay-atom [:diagnostics :unauthorized-replication])))))

        (testing "4. Spoofed X-Bitecho-Relay-Replicated on /relay/v1/ack without auth returns 403"
          (let [ack-body (.getBytes (json/write-str {"pubkey" (:pubkey-hex bob-id) "ack_seq" 1}) StandardCharsets/UTF_8)
                req (-> (HttpRequest/newBuilder)
                        (.uri (URI/create (str base-url "/relay/v1/ack")))
                        (.header "Content-Type" "application/json")
                        (.header "X-Bitecho-Relay-Replicated" "true")
                        (.POST (HttpRequest$BodyPublishers/ofByteArray ack-body))
                        (.build))
                resp (.send client req (HttpResponse$BodyHandlers/ofString))]
            (is (= 403 (.statusCode resp)))
            (is (= 3 (get-in @relay-atom [:diagnostics :unauthorized-replication])))))

        (testing "5. Legitimate intra-ring replication with valid HMAC on /relay/v1/ack succeeds or reaches logic"
          (let [ack-body (.getBytes (json/write-str {"pubkey" (:pubkey-hex bob-id) "ack_seq" 1}) StandardCharsets/UTF_8)
                auth-hmac (http-shell/compute-relay-auth-hmac shared-secret "/relay/v1/ack" ack-body)
                req (-> (HttpRequest/newBuilder)
                        (.uri (URI/create (str base-url "/relay/v1/ack")))
                        (.header "Content-Type" "application/json")
                        (.header "X-Bitecho-Relay-Replicated" "true")
                        (.header "X-Bitecho-Relay-Auth" auth-hmac)
                        (.POST (HttpRequest$BodyPublishers/ofByteArray ack-body))
                        (.build))
                resp (.send client req (HttpResponse$BodyHandlers/ofString))]
            ;; Auth succeeded, so not 403 for unauthorized-replication
            (is (not= "unauthorized-replication" (get (try (json/read-str (.body resp)) (catch Exception _ {})) "error")))
            (is (= 3 (get-in @relay-atom [:diagnostics :unauthorized-replication]))))))
      (finally
        ((:stop-fn srv))))))
