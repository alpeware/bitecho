(ns bitecho.shell.http-test
  "Unit tests for HTTP Gateway Relay replication authentication (F-P0-1 / F-Bb-1).
   Ensures that external requests attempting to spoof X-Bitecho-Relay-Replicated
   are rejected with 403 Forbidden and counted in :unauthorized-replication diagnostics,
   while legitimately authenticated requests with HMAC-SHA256 are accepted."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.relay :as relay]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.http :as http-shell]
            [bitecho.shell.infra :as infra]
            [bitecho.storage.app-release :as app-release]
            [bitecho.storage.chunk-constants :as cc]
            [clojure.data.json :as json]
            [clojure.test :refer [deftest is testing]])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.security SecureRandom]
           [java.security.cert X509Certificate]
           [javax.net.ssl SSLContext TrustManager X509TrustManager]))

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

(deftest test-bip017b-http-atomic-web-app-release-and-fallback
  (let [tmp-dir (make-tmp-dir!)
        kp1 (crypto/generate-keypair 201)
        kp2 (crypto/generate-keypair 202)
        kp3 (crypto/generate-keypair 203)
        pk1 (basalt/bytes->hex (:public-key kp1))
        pk2 (basalt/bytes->hex (:public-key kp2))
        pk3 (basalt/bytes->hex (:public-key kp3))
        pol (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                         :trust-anchors #{pk1 pk2 pk3}
                                         :threshold 2})
        rt (infra/start-subnet-runtime! {:policy pol
                                         :state-dir tmp-dir
                                         :node-id pk1
                                         :node-privkey (:private-key kp1)
                                         :all-nodes #{pk1}
                                         :release-signers #{pk1 pk2 pk3}
                                         :release-threshold 2})
        tls-mgr (http-shell/init-tls-manager! {:state-dir tmp-dir :domain "localhost"})
        cfg {:domain "bitecho.org"
             :state-dir tmp-dir
             :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0 :redirect-http-to-https? false}}
        srv (http-shell/start-http-servers! cfg tls-mgr rt)]
    (try
      (let [base-url (str "https://127.0.0.1:" (:https-port srv))
            tm (reify X509TrustManager
                 (getAcceptedIssuers [_] (into-array X509Certificate []))
                 (checkClientTrusted [_ _ _] nil)
                 (checkServerTrusted [_ _ _] nil))
            ssl-ctx (doto (SSLContext/getInstance "TLS")
                      (.init nil (into-array TrustManager [tm]) (SecureRandom.)))
            client (-> (HttpClient/newBuilder) (.sslContext ssl-ctx) (.build))
            put-blob! (fn [^bytes bs ct]
                        (let [blob (data/make-blob bs ct)]
                          (infra/submit-event! rt {:type :put-blob :blob blob :now-ms (System/currentTimeMillis)})
                          (:blob/cid blob)))
            put-ptr! (fn [path cid seq-n]
                       (let [ptr (data/sign-pointer (:private-key kp1)
                                                    {:pointer/subnet "bitecho.org/infra"
                                                     :pointer/path path
                                                     :pointer/target cid
                                                     :pointer/seq seq-n
                                                     :pointer/authority pk1
                                                     :pointer/term 1})]
                         (infra/submit-event! rt {:type :publish-pointer :pointer ptr :now-ms (System/currentTimeMillis)})))]
        (testing "1. Backwards-compatible fallback to individual web/app/* pointer when web/app/release is absent"
          (let [fallback-bytes (.getBytes "<h1>Legacy Fallback</h1>" StandardCharsets/UTF_8)
                fb-cid (put-blob! fallback-bytes "text/html; charset=utf-8")]
            (put-ptr! "web/app/index.html" fb-cid 1)
            (let [req (-> (HttpRequest/newBuilder (URI/create (str base-url "/app/index.html"))) (.GET) (.build))
                  resp (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode resp)))
              (is (= "<h1>Legacy Fallback</h1>" (.body resp))))))

        (testing "2. Atomic web/app/release serves /app/ and /app/chat.js with strict headers from resolved headers-config CID"
          (let [hdr-cfg (assoc (app-release/default-app-headers-config)
                               "X-Bitecho-Release-Profile" "hive-http-test")
                hdr-bytes (cc/jcs-canonical-bytes hdr-cfg)
                hdr-cid (put-blob! hdr-bytes "application/json")
                chat-js "console.log('hive-chat');"
                chat-bytes (fressian/utf8->bytes chat-js)
                chat-cid (put-blob! chat-bytes "application/javascript; charset=utf-8")
                chat-sri (app-release/compute-sri-sha384 chat-bytes)
                idx-html (str "<!DOCTYPE html><html><body><script src=\"/app/chat.js\" integrity=\"" chat-sri "\" crossorigin=\"anonymous\"></script></body></html>")
                idx-bytes (fressian/utf8->bytes idx-html)
                idx-cid (put-blob! idx-bytes "text/html; charset=utf-8")
                rel {"version" 1
                     "seq" 1
                     "genesis_anchor_cid" (:subnet/genesis-policy-cid pol)
                     "headers_config_cid" hdr-cid
                     "bytes_at_rest" (+ (alength idx-bytes) (alength chat-bytes))
                     "assets" {"index.html" {"cid" idx-cid "size" (alength idx-bytes) "content_type" "text/html; charset=utf-8"}
                               "chat.js" {"cid" chat-cid "size" (alength chat-bytes) "content_type" "application/javascript; charset=utf-8" "sri" chat-sri}}}
                rcid (app-release/release-cid rel)
                env (app-release/sign-release-envelope rcid [{:owner-pubkey pk1 :privkey (:private-key kp1)}
                                                             {:owner-pubkey pk2 :privkey (:private-key kp2)}])
                rel-payload (json/write-str {"release" rel
                                             "envelope" {"release_cid" (:release-cid env)
                                                         "sigs" (mapv (fn [{:keys [owner-pubkey sig]}]
                                                                        {"owner_pubkey" owner-pubkey "sig" sig})
                                                                      (:sigs env))}})
                rel-blob-cid (put-blob! (fressian/utf8->bytes rel-payload) "application/json")]
            (put-ptr! "web/app/release" rel-blob-cid 1)
            (let [r-idx (.send client (-> (HttpRequest/newBuilder (URI/create (str base-url "/app/"))) (.GET) (.build))
                               (HttpResponse$BodyHandlers/ofString))
                  r-chat (.send client (-> (HttpRequest/newBuilder (URI/create (str base-url "/app/chat.js"))) (.GET) (.build))
                                (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode r-idx)))
              (is (= idx-html (.body r-idx)))
              (is (= "same-origin" (.orElse (.firstValue (.headers r-idx) "Cross-Origin-Opener-Policy") nil)))
              (is (= "credentialless" (.orElse (.firstValue (.headers r-idx) "Cross-Origin-Embedder-Policy") nil)))
              (is (= "no-cache" (.orElse (.firstValue (.headers r-idx) "Cache-Control") nil)))
              (is (= "hive-http-test" (.orElse (.firstValue (.headers r-idx) "X-Bitecho-Release-Profile") nil)))
              (is (= rcid (.orElse (.firstValue (.headers r-idx) "X-Bitecho-Release-Cid") nil)))
              (is (= 200 (.statusCode r-chat)))
              (is (= chat-js (.body r-chat)))))))
      (finally
        ((:stop-fn srv))
        (infra/stop-subnet-runtime! rt)))))
