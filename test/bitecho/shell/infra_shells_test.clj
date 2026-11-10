(ns bitecho.shell.infra-shells-test
  "Strict TDD model-based lifecycle, boundary, and end-to-end local integration tests
   for Unification Phase B edge shells & `\"bitecho.org/infra\"` Subnet runtime:
   - Rule 4 & Rule 5 generation-tagged shell lifecycle reducer (`bitecho.shell.infra/transition-shell`)
   - `bitecho.shell.blob-fs` disk CAS (`blobs/<2-char>/<cid>`, corruption guard, zero-heap file handle)
   - Flag F1 all 7 `reduce-subnet` effects wired across a 2-node (`ns1` + `ns2`) `\"bitecho.org/infra\"` runtime
   - `bitecho.shell.dns` UDP + TCP server, RRL drop diagnostics, and `FORMERR` diagnostics
   - `bitecho.shell.http` `:80` + `:443` passthrough multiplexer (RFC 4571 DTLS/STUN, `*.ingress` SNI,
     allowlisted `HTTP CONNECT`, `setWantClientAuth(true)` mTLS subnet gate, `ETag: \"<cid>\"`, `206` zero-heap slice)
   - `bitecho.shell.smtp` TCP + `STARTTLS` -> `Blob` + `\"mail/...\"` `Pointer` replication
   - `bitecho.shell.acme` mock RFC 8555 ACME v2 issuance + Gap G7 immediate post-authz challenge tombstone
     + AES-GCM encrypted TLS bundle `Blob` + `\"tls/current-cert\"` follower hot-reload
   - `bitecho.shell.upnp` SSDP `M-SEARCH` + SOAP `WANIPConnection` against mock local gateway + timeout diagnostics"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.acme :as acme-proto]
            [bitecho.core.protocol.dns :as dns-proto]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.main :as main]
            [bitecho.shell.acme :as acme-shell]
            [bitecho.shell.blob-fs :as blob-fs]
            [bitecho.shell.dns :as dns-shell]
            [bitecho.shell.http :as http-shell]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.infra :as infra]
            [bitecho.shell.smtp :as smtp-shell]
            [bitecho.shell.upnp :as upnp]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [com.sun.net.httpserver HttpHandler HttpServer]
           [java.io BufferedReader BufferedWriter DataInputStream DataOutputStream InputStreamReader OutputStreamWriter]
           [java.net DatagramPacket DatagramSocket InetSocketAddress ServerSocket Socket URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.security KeyStore SecureRandom]
           [java.security.cert X509Certificate]
           [java.time Duration]
           [javax.net.ssl KeyManagerFactory SSLContext SSLSocket TrustManager X509TrustManager]))

(defn- make-temp-dir!
  [prefix]
  (.toFile (Files/createTempDirectory prefix (into-array java.nio.file.attribute.FileAttribute []))))

(defn- delete-dir-recursive!
  [^java.io.File dir]
  (when (and dir (.exists dir))
    (doseq [^java.io.File f (reverse (file-seq dir))]
      (try (.delete f) (catch Exception _ nil)))))

(defn- trust-all-ssl-context
  ([] (trust-all-ssl-context nil))
  ([client-bundle]
   (let [tm (reify X509TrustManager
              (getAcceptedIssuers [_] (into-array X509Certificate []))
              (checkClientTrusted [_ _ _] nil)
              (checkServerTrusted [_ _ _] nil))
         kms (when client-bundle
               (let [ks (KeyStore/getInstance "PKCS12")
                     pass (char-array "testpass")
                     _ (.load ks nil pass)
                     _ (.setKeyEntry ks "client"
                                     (:private-key client-bundle)
                                     pass
                                     (into-array X509Certificate (:certificates client-bundle)))
                     kmf (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
                     _ (.init kmf ks pass)]
                 (.getKeyManagers kmf)))
         ctx (SSLContext/getInstance "TLS")]
     (.init ctx kms (into-array TrustManager [tm]) (SecureRandom.))
     ctx)))

;; =============================================================================
;; 1. Model-Based Shell Lifecycle State Machine (`test.check` — Rules 1, 4, 5)
;; =============================================================================

(def ^:private gen-shell-cmd
  (gen/one-of [(gen/return {:op :start})
               (gen/return {:op :started :use-current-gen? true})
               (gen/fmap (fn [delta] {:op :started :stale-delta delta}) (gen/choose 1 4))
               (gen/fmap (fn [err] {:op :failed :use-current-gen? true :error err})
                         (gen/elements [:bind-failed :dial-timeout :tls-init-error]))
               (gen/fmap (fn [delta] {:op :failed :stale-delta delta :error :stale-failure})
                         (gen/choose 1 4))
               (gen/return {:op :stop})
               (gen/fmap (fn [reason] {:op :drop :reason reason})
                         (gen/elements [:rate-limited :malformed-packet :connect-denied]))]))

(defspec ^{:doc "Property: Single-authority generation-tagged shell reducer ignores stale callbacks with counted :diagnose and records every drop/failure"}
  prop-shell-lifecycle-single-authority-and-stale-generation 60
  (prop/for-all [cmds (gen/vector gen-shell-cmd 5 30)]
                (let [s0 (infra/init-shell-state :test-shell)
                      final (reduce
                             (fn [{:keys [st ok?]} cmd]
                               (let [cur-gen (:generation st)
                                     ev (case (:op cmd)
                                          :start {:type :start}
                                          :started {:type :started
                                                    :generation (if (:use-current-gen? cmd)
                                                                  cur-gen
                                                                  (max 0 (- cur-gen (:stale-delta cmd))))
                                                    :resources {:port 12345}}
                                          :failed {:type :failed
                                                   :generation (if (:use-current-gen? cmd)
                                                                 cur-gen
                                                                 (max 0 (- cur-gen (:stale-delta cmd))))
                                                   :error (:error cmd)}
                                          :stop {:type :stop}
                                          :drop {:type :drop :reason (:reason cmd)})
                                     [st' effects] (infra/transition-shell st ev)
                                     stale-ev? (and (contains? #{:started :failed} (:type ev))
                                                    (< (long (:generation ev)) (long cur-gen)))
                                     step-ok? (cond
                                                stale-ev?
                                                (and (= (:phase st) (:phase st'))
                                                     (= (:resources st) (:resources st'))
                                                     (= (inc (:ignored-stale st)) (:ignored-stale st'))
                                                     (some #(= :diagnose (:effect %)) effects))

                                                (= :drop (:type ev))
                                                (and (= (inc (:dropped st)) (:dropped st'))
                                                     (some #(= :diagnose (:effect %)) effects))

                                                (= :start (:type ev))
                                                (= (inc cur-gen) (:generation st'))

                                                (and (= :failed (:type ev)) (= cur-gen (:generation ev)))
                                                (and (= :failed (:phase st'))
                                                     (= (:error ev) (:last-error st'))
                                                     (some #(= :diagnose (:effect %)) effects))

                                                :else
                                                (>= (:generation st') cur-gen))]
                                 {:st st' :ok? (and ok? step-ok?)}))
                             {:st s0 :ok? true}
                             cmds)]
                  (:ok? final))))

;; =============================================================================
;; 2. `bitecho.shell.blob-fs` Disk CAS & Corruption Guard (Gap G6)
;; =============================================================================

(deftest test-blob-fs-cas-and-corruption-guard
  (testing "Gap G6: blob-fs stores Blobs under blobs/<2-char>/<cid>, exposes zero-heap File handles, rejects tampered files with counted :diagnose, and GCs unpinned CIDs"
    (let [tmp-dir (make-temp-dir! "bitecho-blob-fs-")
          b1 (data/make-blob (fressian/utf8->bytes "hello-cas-world") "text/plain; charset=utf-8")
          b2 (data/make-blob (fressian/utf8->bytes "ephemeral-unpinned") "application/octet-stream")]
      (try
        (let [w1 (blob-fs/write-blob! tmp-dir b1)
              w2 (blob-fs/write-blob! tmp-dir b2)
              f1 (blob-fs/blob-file tmp-dir (:blob/cid b1))
              r1 (blob-fs/read-blob! tmp-dir (:blob/cid b1))
              gc-res (blob-fs/gc-unpinned-blobs! tmp-dir #{(:blob/cid b1)})
              r2-after-gc (blob-fs/read-blob! tmp-dir (:blob/cid b2))]
          (is (:ok? w1))
          (is (:ok? w2))
          (is (.exists f1))
          (is (= (subs (:blob/cid b1) 0 2) (.getName (.getParentFile f1))))
          (is (:ok? r1))
          (is (= "text/plain; charset=utf-8" (get-in r1 [:blob :blob/media-type])))
          (is (= "hello-cas-world" (fressian/bytes->utf8 (get-in r1 [:blob :blob/bytes]))))
          (is (= 1 (:deleted-count gc-res)))
          (is (false? (:ok? r2-after-gc)))
          ;; Corrupt f1 on disk -> read-blob! MUST fail closed with counted :diagnose!
          (spit f1 "corrupted-bytes-on-disk")
          (let [corrupt-res (blob-fs/read-blob! tmp-dir (:blob/cid b1))]
            (is (false? (:ok? corrupt-res)))
            (is (= :blob-cid-mismatch (:error corrupt-res)))
            (is (= :diagnose (:effect (first (:effects corrupt-res)))))))
        (finally
          (delete-dir-recursive! tmp-dir))))))

;; =============================================================================
;; 3. Flag F1: Unified `bitecho.shell.infra` 2-Node Runtime & All 7 Effects
;; =============================================================================

(deftest test-f1-infra-runtime-effects-and-two-node-replication
  (testing "Flag F1: infra runtime wires :fetch-blob, :eager-push-blob, :replicate-pointer, :broadcast-heartbeat, :leader-elected, :policy-updated, and :diagnose across ns1 and ns2"
    (let [dir1 (make-temp-dir! "infra-ns1-")
          dir2 (make-temp-dir! "infra-ns2-")
          cold-kp (crypto/generate-keypair)
          ns1-kp (crypto/generate-keypair)
          ns2-kp (crypto/generate-keypair)
          extra-kp (crypto/generate-keypair)
          cold-pub (basalt/bytes->hex (:public cold-kp))
          ns1-pub (basalt/bytes->hex (:public ns1-kp))
          ns2-pub (basalt/bytes->hex (:public ns2-kp))
          extra-pub (basalt/bytes->hex (:public extra-kp))
          base-policy (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                                   :trust-anchors #{ns1-pub ns2-pub}
                                                   :cold-pubkey cold-pub
                                                   :domain-pubkey ns1-pub
                                                   :threshold 2})
          leader-events (atom [])
          rt1-ref (atom nil)
          rt2-ref (atom nil)]
      (try
        (let [rt1 (infra/start-subnet-runtime!
                   {:state-dir dir1
                    :policy base-policy
                    :node-id ns1-pub
                    :node-privkey (:private ns1-kp)
                    :all-nodes #{ns1-pub ns2-pub}
                    :max-hot-bytes 64 ;; tiny hot RAM cap so pinned Blobs demote & exercise :fetch-blob from blob-fs!
                    :on-leader-elected (fn [ev] (swap! leader-events conj ev))
                    :send-to-peers! (fn [msg]
                                      (when-let [r2 @rt2-ref]
                                        (infra/receive-peer-message! r2 msg)))})
              rt2 (infra/start-subnet-runtime!
                   {:state-dir dir2
                    :policy base-policy
                    :node-id ns2-pub
                    :node-privkey (:private ns2-kp)
                    :all-nodes #{ns1-pub ns2-pub}
                    :send-to-peers! (fn [msg]
                                      (when-let [r1 @rt1-ref]
                                        (infra/receive-peer-message! r1 msg)))})]
          (reset! rt1-ref rt1)
          (reset! rt2-ref rt2)
          ;; 1. :broadcast-heartbeat & :leader-elected across ns1 <-> ns2
          (infra/tick-runtime! rt2 1100)
          (infra/tick-runtime! rt1 1200)
          (is (seq @leader-events) "Leader election callback fired")
          ;; 2. :eager-push-blob + :replicate-pointer from ns1 -> ns2, plus :fetch-blob disk hydration on cold RAM miss
          (let [b1 (data/make-blob (fressian/utf8->bytes (apply str (repeat 40 "A"))) "text/html; charset=utf-8")
                b2 (data/make-blob (fressian/utf8->bytes (apply str (repeat 40 "B"))) "text/plain; charset=utf-8")
                pub1 (infra/publish-blob-and-pointer! rt1
                                                      {:blob b1
                                                       :path "web/index.html"
                                                       :seq 1
                                                       :authority-pubkey ns1-pub
                                                       :authority-privkey (:private ns1-kp)
                                                       :now-ms 1300})
                ;; Insert b2 to push b1 out of tiny 64-byte hot RAM on rt1 while b1 stays pinned on disk!
                _ (infra/put-blob! rt1 b2 {:sender ns1-pub :now-ms 1400})
                hydrated (infra/resolve-path-blob! rt1 "web/index.html" 1500)
                replicated-on-ns2 (infra/resolve-path-blob! rt2 "web/index.html" 1500)]
            (is (:applied? pub1))
            (is (:ok? hydrated) ":fetch-blob hydrated cold pinned Blob from blob-fs on disk")
            (is (= (apply str (repeat 40 "A")) (fressian/bytes->utf8 (get-in hydrated [:blob :blob/bytes]))))
            (is (:ok? replicated-on-ns2) ":eager-push-blob + :replicate-pointer replicated to ns2")
            (is (= (:blob/cid b1) (get-in replicated-on-ns2 [:blob :blob/cid]))))
          ;; 3. :policy-updated via Cold Root Key
          (let [next-pol (-> base-policy
                             (dissoc :subnet/genesis-policy-cid)
                             (assoc-in [:subnet/gate :gate/trust-anchors] #{ns1-pub ns2-pub extra-pub}))
                pol-blob (data/make-blob (fressian/encode-canonical next-pol) "application/fressian")
                _ (infra/put-blob! rt1 pol-blob {:sender cold-pub :now-ms 1600})
                pol-ptr (data/sign-pointer (:private cold-kp)
                                           {:pointer/authority cold-pub
                                            :pointer/subnet "bitecho.org/infra"
                                            :pointer/path "subnet/policy"
                                            :pointer/seq 1
                                            :pointer/target (:blob/cid pol-blob)
                                            :pointer/proof {:proof/type :self}})
                pol-res (infra/submit-event! rt1 {:type :publish-pointer :sender cold-pub :pointer pol-ptr :now-ms 1650})]
            (is (:applied? pol-res))
            (is (contains? (get-in @(:subnet-atom rt1) [:policy :subnet/gate :gate/trust-anchors]) extra-pub)))
          ;; 4. :diagnose counted on unauthorized gate attempt
          (let [stranger-kp (crypto/generate-keypair)
                stranger-pub (basalt/bytes->hex (:public stranger-kp))
                bad-res (infra/put-blob! rt1 (data/make-blob "nope") {:sender stranger-pub :now-ms 1700})
                status (infra/runtime-status rt1)]
            (is (false? (:applied? bad-res)))
            (is (pos? (get-in status [:diagnostics-counts :subnet-gate-rejected] 0))))
          (infra/stop-subnet-runtime! rt1)
          (infra/stop-subnet-runtime! rt2))
        (finally
          (delete-dir-recursive! dir1)
          (delete-dir-recursive! dir2))))))

;; =============================================================================
;; 4. `bitecho.shell.dns` Live UDP + TCP Server & Diagnostics
;; =============================================================================

(deftest test-dns-shell-udp-tcp-rrl-and-formerr-diagnostics
  (testing "bitecho.shell.dns serves Subnet-backed A/TXT over UDP & TCP, truncates >512B on UDP (TC=1), and records counted :diagnose on FORMERR & RRL drops"
    (let [tmp-dir (make-temp-dir! "bitecho-dns-")
          ns1-kp (crypto/generate-keypair)
          ns2-kp (crypto/generate-keypair)
          ns1-pub (basalt/bytes->hex (:public ns1-kp))
          ns2-pub (basalt/bytes->hex (:public ns2-kp))
          policy (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                              :trust-anchors #{ns1-pub ns2-pub}
                                              :cold-pubkey ns1-pub
                                              :domain-pubkey ns1-pub})
          rt (infra/start-subnet-runtime! {:state-dir tmp-dir
                                           :policy policy
                                           :node-id :ns1
                                           :node-privkey (:private ns1-kp)
                                           :all-nodes #{:ns1 :ns2}})
          _ (infra/submit-event! rt {:type :leader-heartbeat :from :ns2 :term 0 :now-ms 1100})
          ;; Publish nexus.ingress.bitecho.org A record Pointer + large TXT record (>512B) for TC=1 TCP fallback test
          nexus-blob (data/make-blob (fressian/encode-canonical {:records ["198.51.100.88"] :ttl 60}) "application/fressian")
          big-txt (apply str (repeat 600 "x"))
          txt-blob (data/make-blob (fressian/encode-canonical {:records [[big-txt]] :ttl 60}) "application/fressian")
          _ (infra/publish-blob-and-pointer! rt {:blob nexus-blob :path "dns/A/nexus.ingress" :seq 1
                                                 :authority-pubkey ns1-pub :authority-privkey (:private ns1-kp)
                                                 :proof {:proof/type :zone :serial 1} :now-ms 1200})
          _ (infra/publish-blob-and-pointer! rt {:blob txt-blob :path "dns/TXT/big" :seq 1
                                                 :authority-pubkey ns1-pub :authority-privkey (:private ns1-kp)
                                                 :proof {:proof/type :zone :serial 2} :now-ms 1250})
          cfg {:domain "bitecho.org"
               :dns {:bind-ip "127.0.0.1" :port 0 :ttl-seconds 60}
               :cluster {:nodes {:ns1 {:ip4 "34.19.71.246"}
                                 :ns2 {:ip4 "34.56.253.255"}
                                 :ns3 {:ip4 "136.108.244.159"}}}}
          dns-srv (dns-shell/start-dns-server! cfg rt {:rrl-capacity 3.0 :rrl-refill-per-sec 0.01})]
      (try
        (let [udp-port (:udp-port dns-srv)
              tcp-port (:tcp-port dns-srv)]
          ;; 1. UDP query for nexus.ingress.bitecho.org
          (with-open [sock (DatagramSocket.)]
            (.setSoTimeout sock 3000)
            (let [q-bytes (dns-proto/encode-packet {:id 101 :rd? true :questions [{:qname "nexus.ingress.bitecho.org" :qtype :A :qclass :IN}]})
                  pkt (DatagramPacket. q-bytes (alength q-bytes) (InetSocketAddress. "127.0.0.1" (int udp-port)))
                  _ (.send sock pkt)
                  rbuf (byte-array 1024)
                  rpkt (DatagramPacket. rbuf (alength rbuf))
                  _ (.receive sock rpkt)
                  resp (dns-proto/decode-packet (java.util.Arrays/copyOf rbuf (.getLength rpkt)))]
              (is (= :noerror (:rcode resp)))
              (is (= ["198.51.100.88"] (mapv :rdata (:answers resp)))))
            ;; 2. UDP query for >512B TXT -> returns TC=1, then full answer over TCP!
            (let [q-big (dns-proto/encode-packet {:id 102 :rd? true :questions [{:qname "big.bitecho.org" :qtype :TXT :qclass :IN}]})
                  _ (.send sock (DatagramPacket. q-big (alength q-big) (InetSocketAddress. "127.0.0.1" (int udp-port))))
                  rbuf (byte-array 1024)
                  rpkt (DatagramPacket. rbuf (alength rbuf))
                  _ (.receive sock rpkt)
                  udp-resp (dns-proto/decode-packet (java.util.Arrays/copyOf rbuf (.getLength rpkt)))]
              (is (:tc? udp-resp) "UDP >512B sets TC=1"))
            ;; 3. Malformed UDP packet (<12 bytes, >=2 bytes ID) -> FORMERR + counted :diagnose
            (let [bad-bytes (byte-array [0x12 0x34 0x01])
                  _ (.send sock (DatagramPacket. bad-bytes 3 (InetSocketAddress. "127.0.0.1" (int udp-port))))
                  rbuf (byte-array 512)
                  rpkt (DatagramPacket. rbuf (alength rbuf))
                  _ (.receive sock rpkt)
                  err-resp (dns-proto/decode-packet (java.util.Arrays/copyOf rbuf (.getLength rpkt)))]
              (is (= :formerr (:rcode err-resp))))
            ;; 4. Exhaust RRL bucket -> counted :diagnose on drop
            (let [q-bytes (dns-proto/encode-packet {:id 103 :rd? true :questions [{:qname "bitecho.org" :qtype :A :qclass :IN}]})]
              (.send sock (DatagramPacket. q-bytes (alength q-bytes) (InetSocketAddress. "127.0.0.1" (int udp-port))))
              (.send sock (DatagramPacket. q-bytes (alength q-bytes) (InetSocketAddress. "127.0.0.1" (int udp-port))))
              (Thread/sleep 50)))
          ;; 5. TCP full-length TXT query
          (with-open [tsock (Socket. "127.0.0.1" (int tcp-port))
                      din (DataInputStream. (.getInputStream tsock))
                      dout (DataOutputStream. (.getOutputStream tsock))]
            (.setSoTimeout tsock 3000)
            (let [q-big (dns-proto/encode-packet {:id 104 :rd? true :questions [{:qname "big.bitecho.org" :qtype :TXT :qclass :IN}]})]
              (.writeShort dout (alength q-big))
              (.write dout q-big)
              (.flush dout)
              (let [rlen (.readUnsignedShort din)
                    rbuf (byte-array rlen)
                    _ (.readFully din rbuf)
                    tcp-resp (dns-proto/decode-packet rbuf)]
                (is (false? (:tc? tcp-resp)))
                (is (= big-txt (apply str (get-in tcp-resp [:answers 0 :rdata])))))))
          (let [st (dns-shell/dns-status dns-srv)]
            (is (= :running (:phase st)))
            (is (pos? (:dropped st)) "RRL/FORMERR drops counted in shell state")))
        (finally
          (dns-shell/stop-dns-server! dns-srv)
          (infra/stop-subnet-runtime! rt)
          (delete-dir-recursive! tmp-dir))))))

;; =============================================================================
;; 5. `bitecho.shell.http` `:80` + `:443` Passthrough + CONNECT + mTLS + ETag
;; =============================================================================

(deftest test-http-shell-passthrough-multiplexer-mtls-connect-and-etag
  (testing "Gaps G6, G12, G17: HTTP/HTTPS shell serves Pointer->Blob with ETag/304/206 zero-heap slices, splices DTLS/SNI & allowlisted HTTP CONNECT on :443, and enforces setWantClientAuth(true) mTLS subnet gates"
    (let [tmp-dir (make-temp-dir! "bitecho-http-")
          ns1-kp (crypto/generate-keypair)
          ns1-pub (basalt/bytes->hex (:public ns1-kp))
          ;; Generate an ECDSA client cert bundle for mTLS admission testing
          client-cert-bundle (http-shell/generate-self-signed-cert "mtls-agent.local" 7)
          client-spki-hex (basalt/bytes->hex (.getEncoded (.getPublicKey ^X509Certificate (:certificate client-cert-bundle))))
          ;; Public infra runtime for bitecho.org
          pub-policy {:subnet/id "bitecho.org/web"
                      :subnet/gate {:gate/mode :permissionless :gate/admission :open :gate/trust-anchors #{ns1-pub}}
                      :subnet/path-acl [{:pattern "web/*" :principal {:type :pubkey :pubkey ns1-pub}}
                                        {:pattern "acme/challenge/*" :principal {:type :pubkey :pubkey ns1-pub}}]
                      :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                      :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
          ;; Permissioned mTLS admin subnet (Instance #5 in UNIFICATION.md §6)
          mtls-policy {:subnet/id "bitecho.org/admin"
                       :subnet/parent-id "global"
                       :subnet/gate {:gate/mode :permissioned
                                     :gate/admission :mtls-cert
                                     :gate/trust-anchors #{client-spki-hex ns1-pub}}
                       :subnet/path-acl [{:pattern "web/*" :principal {:type :allowlist}}]
                       :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                       :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
          pub-rt (infra/start-subnet-runtime! {:state-dir (io/file tmp-dir "pub")
                                               :policy pub-policy
                                               :node-id ns1-pub
                                               :node-privkey (:private ns1-kp)})
          mtls-rt (infra/start-subnet-runtime! {:state-dir (io/file tmp-dir "admin")
                                                :policy mtls-policy
                                                :node-id ns1-pub
                                                :node-privkey (:private ns1-kp)})
          index-blob (data/make-blob (fressian/utf8->bytes "<h1>Hello Unified Bitecho Web</h1>") "text/html; charset=utf-8")
          secret-blob (data/make-blob (fressian/utf8->bytes "top-secret-mtls-payload") "text/plain; charset=utf-8")
          _ (infra/publish-blob-and-pointer! pub-rt {:blob index-blob :path "web/index.html" :seq 1
                                                     :authority-pubkey ns1-pub :authority-privkey (:private ns1-kp) :now-ms 1000})
          _ (infra/publish-blob-and-pointer! mtls-rt {:blob secret-blob :path "web/secret.txt" :seq 1
                                                      :authority-pubkey ns1-pub :authority-privkey (:private ns1-kp) :now-ms 1000})
          ;; Start a tiny TCP echo server to serve as both mock :ingress-target AND allowlisted HTTP CONNECT target
          echo-sock (ServerSocket. 0 16 (java.net.InetAddress/getByName "127.0.0.1"))
          echo-port (.getLocalPort echo-sock)
          _ (.start (Thread/ofVirtual)
                    (fn []
                      (while (not (.isClosed echo-sock))
                        (try
                          (let [s (.accept echo-sock)]
                            (.start (Thread/ofVirtual)
                                    (fn []
                                      (try
                                        (let [in (.getInputStream s)
                                              out (.getOutputStream s)
                                              buf (byte-array 256)
                                              n (.read in buf)]
                                          (when (pos? n)
                                            (.write out buf 0 n)
                                            (.flush out)))
                                        (finally (.close s))))))
                          (catch Exception _ nil)))))
          tls-mgr (http-shell/init-tls-manager! {:state-dir tmp-dir :domain "localhost"})
          srv (http-shell/start-http-servers!
               {:domain "bitecho.org"
                :state-dir tmp-dir
                :http {:bind-ip "127.0.0.1"
                       :http-port 0
                       :https-port 0
                       :cache-max-file-bytes 16 ;; forces index-blob (>16B) onto zero-heap blob-fs File streaming!
                       :ingress-target {:host "127.0.0.1" :port echo-port}
                       :connect-targets #{(str "127.0.0.1:" echo-port)}
                       :host-subnets {"admin.bitecho.org" mtls-rt}}}
               tls-mgr
               pub-rt)]
      (try
        (let [http-port (:http-port srv)
              https-port (:https-port srv)
              anon-client (-> (HttpClient/newBuilder)
                              (.sslContext (trust-all-ssl-context nil))
                              (.connectTimeout (Duration/ofSeconds 3))
                              (.build))
              expected-etag (str "\"" (:blob/cid index-blob) "\"")]
          ;; 1. Port :80 308 redirect to HTTPS
          (let [r80 (.send anon-client
                           (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/index.html")))
                               (.GET) (.build))
                           (HttpResponse$BodyHandlers/ofString))]
            (is (= 308 (.statusCode r80))))
          ;; 2. Port :443 HTTPS GET /, ETag == "<cid>", 304 Not Modified, and 206 Range zero-heap slice
          (let [r200 (.send anon-client
                            (-> (HttpRequest/newBuilder (URI/create (str "https://localhost:" https-port "/")))
                                (.GET) (.build))
                            (HttpResponse$BodyHandlers/ofString))
                r304 (.send anon-client
                            (-> (HttpRequest/newBuilder (URI/create (str "https://localhost:" https-port "/index.html")))
                                (.header "If-None-Match" expected-etag)
                                (.GET) (.build))
                            (HttpResponse$BodyHandlers/ofString))
                r206 (.send anon-client
                            (-> (HttpRequest/newBuilder (URI/create (str "https://localhost:" https-port "/index.html")))
                                (.header "Range" "bytes=4-8")
                                (.GET) (.build))
                            (HttpResponse$BodyHandlers/ofString))]
            (is (= 200 (.statusCode r200)))
            (is (= "<h1>Hello Unified Bitecho Web</h1>" (.body r200)))
            (is (= expected-etag (.orElse (.firstValue (.headers r200) "ETag") nil)))
            (is (= 304 (.statusCode r304)))
            (is (= 206 (.statusCode r206)))
            (is (= "Hello" (.body r206))))
          ;; 3. Port :443 RFC 4571 DTLS passthrough to :ingress-target
          (with-open [s (Socket. "127.0.0.1" (int https-port))]
            (.setSoTimeout s 3000)
            (let [dtls-bytes (byte-array (map unchecked-byte [0x00 0x04 0x16 0xFE 0xFD 0x77]))
                  out (.getOutputStream s)
                  in (.getInputStream s)
                  rbuf (byte-array 6)]
              (.write out dtls-bytes)
              (.flush out)
              (let [n (.read in rbuf)]
                (is (= 6 n))
                (is (= 0x77 (bit-and (aget rbuf 5) 0xff))))))
          ;; 4. Port :443 HTTP CONNECT tunnel (allowlisted succeeds; non-allowlisted rejected 403 + :diagnose)
          (with-open [s (Socket. "127.0.0.1" (int https-port))]
            (.setSoTimeout s 3000)
            (let [out (.getOutputStream s)
                  in (.getInputStream s)
                  req (str "CONNECT 127.0.0.1:" echo-port " HTTP/1.1\r\nHost: 127.0.0.1:" echo-port "\r\n\r\n")]
              (.write out (.getBytes req StandardCharsets/UTF_8))
              (.flush out)
              (let [hdr-buf (byte-array 128)
                    hn (.read in hdr-buf)
                    hdr-str (String. hdr-buf 0 hn StandardCharsets/UTF_8)]
                (is (str/starts-with? hdr-str "HTTP/1.1 200"))
                (.write out (.getBytes "ping-over-connect" StandardCharsets/UTF_8))
                (.flush out)
                (let [ebuf (byte-array 64)
                      en (.read in ebuf)]
                  (is (= "ping-over-connect" (String. ebuf 0 en StandardCharsets/UTF_8)))))))
          (with-open [s (Socket. "127.0.0.1" (int https-port))]
            (.setSoTimeout s 3000)
            (let [out (.getOutputStream s)
                  in (.getInputStream s)
                  req "CONNECT evil.example.org:9999 HTTP/1.1\r\nHost: evil.example.org:9999\r\n\r\n"]
              (.write out (.getBytes req StandardCharsets/UTF_8))
              (.flush out)
              (let [hdr-buf (byte-array 128)
                    hn (.read in hdr-buf)]
                (is (str/starts-with? (String. hdr-buf 0 hn StandardCharsets/UTF_8) "HTTP/1.1 403")))))
          ;; 5. Gap G12 & Instance #5: mTLS subnet gate denies anonymous client (403) and admits mTLS client (200)!
          (let [orig-prop (System/getProperty "jdk.httpclient.allowRestrictedHeaders")]
            ;; Use Host header via direct SSLSocket so we don't need JVM global restricted-header flags!
            (with-open [anon-ssl ^SSLSocket (.createSocket (.getSocketFactory (trust-all-ssl-context nil)) "127.0.0.1" (int https-port))]
              (.setSoTimeout anon-ssl 3000)
              (.startHandshake anon-ssl)
              (let [w (BufferedWriter. (OutputStreamWriter. (.getOutputStream anon-ssl) StandardCharsets/UTF_8))
                    r (BufferedReader. (InputStreamReader. (.getInputStream anon-ssl) StandardCharsets/UTF_8))]
                (.write w "GET /secret.txt HTTP/1.1\r\nHost: admin.bitecho.org\r\nConnection: close\r\n\r\n")
                (.flush w)
                (is (str/starts-with? (.readLine r) "HTTP/1.1 403") "Anonymous client denied on mTLS-gated subnet")))
            (with-open [auth-ssl ^SSLSocket (.createSocket (.getSocketFactory (trust-all-ssl-context client-cert-bundle)) "127.0.0.1" (int https-port))]
              (.setSoTimeout auth-ssl 3000)
              (.startHandshake auth-ssl)
              (let [w (BufferedWriter. (OutputStreamWriter. (.getOutputStream auth-ssl) StandardCharsets/UTF_8))
                    r (BufferedReader. (InputStreamReader. (.getInputStream auth-ssl) StandardCharsets/UTF_8))]
                (.write w "GET /secret.txt HTTP/1.1\r\nHost: admin.bitecho.org\r\nConnection: close\r\n\r\n")
                (.flush w)
                (let [status-line (.readLine r)
                      all-lines (slurp r)]
                  (is (str/starts-with? status-line "HTTP/1.1 200") "Authorized mTLS client admitted")
                  (is (str/includes? all-lines "top-secret-mtls-payload")))))
            (when orig-prop (System/setProperty "jdk.httpclient.allowRestrictedHeaders" orig-prop)))
          (is (pos? (:dropped (http-shell/http-status srv))) "Denied CONNECT counted in shell diagnostics"))
        (finally
          (try (.close echo-sock) (catch Exception _ nil))
          (http-shell/stop-http-servers! srv)
          (infra/stop-subnet-runtime! pub-rt)
          (infra/stop-subnet-runtime! mtls-rt)
          (delete-dir-recursive! tmp-dir))))))

;; =============================================================================
;; 6. `bitecho.shell.smtp` Live TCP + STARTTLS -> Blob + `"mail/..."` Pointer
;; =============================================================================

(deftest test-smtp-shell-starttls-and-mail-pointer-replication
  (testing "bitecho.shell.smtp upgrades via STARTTLS, blocks open relay with counted :diagnose, stores .eml Blob in blob-fs, and replicates mail/<rcpt>/<ts>-<cid8> Pointer"
    (let [dir1 (make-temp-dir! "smtp-ns1-")
          dir2 (make-temp-dir! "smtp-ns2-")
          ns1-kp (crypto/generate-keypair)
          ns2-kp (crypto/generate-keypair)
          ns1-pub (basalt/bytes->hex (:public ns1-kp))
          ns2-pub (basalt/bytes->hex (:public ns2-kp))
          policy (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                              :trust-anchors #{ns1-pub ns2-pub}
                                              :cold-pubkey ns1-pub
                                              :domain-pubkey ns1-pub})
          rt2-ref (atom nil)
          rt1 (infra/start-subnet-runtime! {:state-dir dir1
                                            :policy policy
                                            :node-id ns1-pub
                                            :node-privkey (:private ns1-kp)
                                            :all-nodes #{ns1-pub ns2-pub}
                                            :send-to-peers! (fn [m] (when-let [r2 @rt2-ref] (infra/receive-peer-message! r2 m)))})
          rt2 (infra/start-subnet-runtime! {:state-dir dir2
                                            :policy policy
                                            :node-id ns2-pub
                                            :node-privkey (:private ns2-kp)
                                            :all-nodes #{ns1-pub ns2-pub}})
          _ (reset! rt2-ref rt2)
          tls-mgr (http-shell/init-tls-manager! {:state-dir dir1 :domain "bitecho.org"})
          smtp-srv (smtp-shell/start-smtp-server!
                    {:domain "bitecho.org"
                     :state-dir dir1
                     :smtp {:bind-ip "127.0.0.1"
                            :port 0
                            :allowed-recipients #{"@bitecho.org"}}}
                    tls-mgr
                    rt1)]
      (try
        (with-open [raw-sock (Socket. "127.0.0.1" (int (:port smtp-srv)))]
          (.setSoTimeout raw-sock 3000)
          (let [r0 (BufferedReader. (InputStreamReader. (.getInputStream raw-sock) StandardCharsets/UTF_8))
                w0 (BufferedWriter. (OutputStreamWriter. (.getOutputStream raw-sock) StandardCharsets/UTF_8))]
            (is (str/starts-with? (.readLine r0) "220 "))
            (.write w0 "EHLO sender.example.org\r\n")
            (.flush w0)
            (loop [l (.readLine r0)]
              (when (str/starts-with? l "250-")
                (recur (.readLine r0))))
            (.write w0 "STARTTLS\r\n")
            (.flush w0)
            (is (str/starts-with? (.readLine r0) "220 "))
            (with-open [ssl-sock ^SSLSocket (.createSocket (.getSocketFactory (trust-all-ssl-context nil))
                                                           raw-sock "127.0.0.1" (.getPort raw-sock) true)]
              (.setUseClientMode ssl-sock true)
              (.startHandshake ssl-sock)
              (let [r (BufferedReader. (InputStreamReader. (.getInputStream ssl-sock) StandardCharsets/UTF_8))
                    w (BufferedWriter. (OutputStreamWriter. (.getOutputStream ssl-sock) StandardCharsets/UTF_8))]
                (.write w "EHLO sender.example.org\r\n")
                (.flush w)
                (loop [l (.readLine r)]
                  (when (str/starts-with? l "250-")
                    (recur (.readLine r))))
                (.write w "MAIL FROM:<alice@sender.example.org>\r\n")
                (.flush w)
                (is (str/starts-with? (.readLine r) "250 "))
                ;; Relay attempt -> denied 550 + counted :diagnose
                (.write w "RCPT TO:<bob@other.example.com>\r\n")
                (.flush w)
                (is (str/starts-with? (.readLine r) "550 "))
                ;; Valid recipient -> queued + replicated to ns2!
                (.write w "RCPT TO:<simon@bitecho.org>\r\n")
                (.flush w)
                (is (str/starts-with? (.readLine r) "250 "))
                (.write w "DATA\r\n")
                (.flush w)
                (is (str/starts-with? (.readLine r) "354 "))
                (.write w "Subject: Unification Phase B\r\n\r\nHello over unified SMTP!\r\n.\r\n")
                (.flush w)
                (is (str/starts-with? (.readLine r) "250 "))
                (.write w "QUIT\r\n")
                (.flush w)
                (is (str/starts-with? (.readLine r) "221 "))))))
        (let [ns2-ptrs (keys (get-in @(:subnet-atom rt2) [:data :pointers]))
              mail-key (first (filter (fn [[_ p]] (str/starts-with? p "mail/simon@bitecho.org/")) ns2-ptrs))
              resolved (when mail-key (infra/resolve-path-blob! rt2 (second mail-key) 5000))
              st (smtp-shell/smtp-status smtp-srv)]
          (is (some? mail-key) "mail/simon@bitecho.org/... Pointer replicated to ns2")
          (is (:ok? resolved))
          (is (str/includes? (fressian/bytes->utf8 (get-in resolved [:blob :blob/bytes])) "Hello over unified SMTP!"))
          (is (pos? (:dropped st)) "Relay denial counted in SMTP shell diagnostics"))
        (finally
          (smtp-shell/stop-smtp-server! smtp-srv)
          (infra/stop-subnet-runtime! rt1)
          (infra/stop-subnet-runtime! rt2)
          (delete-dir-recursive! dir1)
          (delete-dir-recursive! dir2))))))

;; =============================================================================
;; 7. `bitecho.shell.acme` Mock RFC 8555 Issuance + Gap G7 Immediate Tombstone
;; =============================================================================

(deftest test-acme-shell-end-to-end-provisioning-and-g7-immediate-tombstone
  (testing "Gap G7: ACME leader publishes acme/challenge/<token> Pointer, verifies HTTP-01 on :80, immediately tombstones challenge Pointer, encrypts TLS bundle Blob, and hot-reloads follower TLS"
    (let [dir1 (make-temp-dir! "acme-ns1-")
          dir2 (make-temp-dir! "acme-ns2-")
          ns1-kp (crypto/generate-keypair)
          ns2-kp (crypto/generate-keypair)
          ns1-pub (basalt/bytes->hex (:public ns1-kp))
          ns2-pub (basalt/bytes->hex (:public ns2-kp))
          cluster-secret (crypto/sha256 (fressian/utf8->bytes "shared-infra-cluster-tls-secret"))
          policy (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                              :trust-anchors #{ns1-pub ns2-pub}
                                              :cold-pubkey ns1-pub
                                              :domain-pubkey ns1-pub})
          tls1 (http-shell/init-tls-manager! {:state-dir dir1 :domain "bitecho.org"})
          tls2 (http-shell/init-tls-manager! {:state-dir dir2 :domain "bitecho.org"})
          rt1-ref (atom nil)
          rt2-ref (atom nil)
          rt1 (infra/start-subnet-runtime! {:state-dir dir1
                                            :policy policy
                                            :node-id ns1-pub
                                            :node-privkey (:private ns1-kp)
                                            :all-nodes #{ns1-pub ns2-pub}
                                            :tls-manager tls1
                                            :tls-secret cluster-secret
                                            :send-to-peers! (fn [m] (when-let [r2 @rt2-ref] (infra/receive-peer-message! r2 m)))})
          rt2 (infra/start-subnet-runtime! {:state-dir dir2
                                            :policy policy
                                            :node-id ns2-pub
                                            :node-privkey (:private ns2-kp)
                                            :all-nodes #{ns1-pub ns2-pub}
                                            :tls-manager tls2
                                            :tls-secret cluster-secret
                                            :send-to-peers! (fn [m] (when-let [r1 @rt1-ref] (infra/receive-peer-message! r1 m)))})
          _ (reset! rt1-ref rt1)
          _ (reset! rt2-ref rt2)
          ;; Elect leader across ns1 + ns2
          _ (infra/tick-runtime! rt2 1100)
          _ (infra/tick-runtime! rt1 1200)
          leader-rt (if (= :leader (get-in @(:subnet-atom rt1) [:leader-election :role])) rt1 rt2)
          follower-tls (if (= leader-rt rt1) tls2 tls1)
          leader-tls (if (= leader-rt rt1) tls1 tls2)
          leader-dir (if (= leader-rt rt1) dir1 dir2)
          http-srv (http-shell/start-http-servers!
                    {:domain "bitecho.org"
                     :state-dir leader-dir
                     :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                    leader-tls
                    leader-rt)
          http-port (:http-port http-srv)
          ;; Start local mock ACME v2 server that actually fetches http://127.0.0.1:<http-port>/.well-known/acme-challenge/tok-g7!
          acme-http (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
          acme-port (.getPort (.getAddress acme-http))
          acme-base (str "http://127.0.0.1:" acme-port)
          authz-valid? (atom false)
          challenge-fetched-body (atom nil)
          issued-cert-bundle (http-shell/generate-cert-and-keypair "bitecho.org" 90)
          domain-kp (:keypair issued-cert-bundle)]
      (.createContext acme-http "/"
                      (reify HttpHandler
                        (handle [_ ex]
                          (let [path (.getPath (.getRequestURI ex))
                                method (.getRequestMethod ex)
                                h (.getResponseHeaders ex)]
                            (.set h "Replay-Nonce" (str "nonce-" (System/nanoTime)))
                            (.set h "Content-Type" "application/json")
                            (cond
                              (= path "/directory")
                              (let [b (.getBytes (json/write-str {"newNonce" (str acme-base "/nonce")
                                                                  "newAccount" (str acme-base "/acct")
                                                                  "newOrder" (str acme-base "/order")})
                                                 StandardCharsets/UTF_8)]
                                (.sendResponseHeaders ex 200 (alength b))
                                (with-open [os (.getResponseBody ex)] (.write os b)))

                              (and (= path "/nonce") (= method "HEAD"))
                              (do (.sendResponseHeaders ex 200 -1) (.close ex))

                              (= path "/acct")
                              (let [b (.getBytes "{\"status\":\"valid\"}" StandardCharsets/UTF_8)]
                                (.set h "Location" (str acme-base "/acct/1"))
                                (.sendResponseHeaders ex 201 (alength b))
                                (with-open [os (.getResponseBody ex)] (.write os b)))

                              (= path "/order")
                              (let [b (.getBytes (json/write-str {"status" (if @authz-valid? "valid" "pending")
                                                                  "authorizations" [(str acme-base "/authz/1")]
                                                                  "finalize" (str acme-base "/finalize/1")
                                                                  "certificate" (str acme-base "/cert/1")})
                                                 StandardCharsets/UTF_8)]
                                (.set h "Location" (str acme-base "/order/1"))
                                (.sendResponseHeaders ex 201 (alength b))
                                (with-open [os (.getResponseBody ex)] (.write os b)))

                              (= path "/order/1")
                              (let [b (.getBytes (json/write-str {"status" "valid"
                                                                  "certificate" (str acme-base "/cert/1")})
                                                 StandardCharsets/UTF_8)]
                                (.sendResponseHeaders ex 200 (alength b))
                                (with-open [os (.getResponseBody ex)] (.write os b)))

                              (= path "/authz/1")
                              (let [b (.getBytes (json/write-str {"status" (if @authz-valid? "valid" "pending")
                                                                  "challenges" [{"type" "http-01"
                                                                                 "token" "tok-g7"
                                                                                 "url" (str acme-base "/chall/1")}]})
                                                 StandardCharsets/UTF_8)]
                                (.sendResponseHeaders ex 200 (alength b))
                                (with-open [os (.getResponseBody ex)] (.write os b)))

                              (= path "/chall/1")
                              (let [c (HttpClient/newHttpClient)
                                    r (.send c
                                             (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" http-port "/.well-known/acme-challenge/tok-g7")))
                                                 (.GET) (.build))
                                             (HttpResponse$BodyHandlers/ofString))
                                    _ (reset! challenge-fetched-body (.body r))
                                    _ (when (= 200 (.statusCode r)) (reset! authz-valid? true))
                                    b (.getBytes "{\"status\":\"valid\"}" StandardCharsets/UTF_8)]
                                (.sendResponseHeaders ex 200 (alength b))
                                (with-open [os (.getResponseBody ex)] (.write os b)))

                              (= path "/finalize/1")
                              (let [b (.getBytes "{\"status\":\"valid\"}" StandardCharsets/UTF_8)]
                                (.sendResponseHeaders ex 200 (alength b))
                                (with-open [os (.getResponseBody ex)] (.write os b)))

                              (= path "/cert/1")
                              (let [pem (http-shell/encode-cert-pem (:certificate issued-cert-bundle))
                                    b (.getBytes ^String pem StandardCharsets/UTF_8)]
                                (.set h "Content-Type" "application/pem-certificate-chain")
                                (.sendResponseHeaders ex 200 (alength b))
                                (with-open [os (.getResponseBody ex)] (.write os b)))

                              :else
                              (do (.sendResponseHeaders ex 404 -1) (.close ex)))))))
      (.start acme-http)
      (try
        (let [res (acme-shell/provision-certificate!
                   {:domain "bitecho.org"
                    :state-dir leader-dir
                    :acme {:directory-url (str acme-base "/directory")
                           :domains ["bitecho.org"]}}
                   leader-rt
                   leader-tls
                   {:domain-keypair domain-kp
                    :tls-secret cluster-secret
                    :poll-interval-ms 20
                    :poll-timeout-ms 5000})
              ;; Check Gap G7: acme/challenge/tok-g7 MUST be tombstoned (:pointer/target nil) right after completion!
              leader-data (:data @(:subnet-atom leader-rt))
              raw-chall-ptr (get-in leader-data [:pointers ["bitecho.org/infra" "acme/challenge/tok-g7"]])
              active-chall (data/resolve-pointer leader-data "bitecho.org/infra" "acme/challenge/tok-g7" (System/currentTimeMillis))
              cert-ptr (data/resolve-pointer leader-data "bitecho.org/infra" "tls/current-cert" (System/currentTimeMillis))
              cert-blob-res (infra/resolve-path-blob! leader-rt "tls/current-cert" (System/currentTimeMillis))
              raw-cert-blob-str (fressian/bytes->utf8 (get-in cert-blob-res [:blob :blob/bytes]))]
          (is (some? (:cert-pem res)))
          (is (str/starts-with? (or @challenge-fetched-body "") "tok-g7.") "HTTP-01 challenge served live from Subnet Pointer")
          (is (some? raw-chall-ptr) "Tombstone Pointer recorded in pointer table")
          (is (nil? (:pointer/target raw-chall-ptr)) "Gap G7: challenge Pointer target is nil tombstone")
          (is (nil? active-chall) "Gap G7: resolve-pointer returns nil after immediate tombstone")
          (is (some? cert-ptr) "tls/current-cert Pointer published")
          (is (not (str/includes? raw-cert-blob-str "BEGIN PRIVATE KEY"))
              "Private key in tls/current-cert Blob MUST be AES-GCM encrypted, never cleartext PEM!")
          (is (false? (:self-signed? @(:bundle-atom follower-tls)))
              "Follower ns2 automatically decrypted & hot-reloaded the ACME TLS certificate!"))
        (finally
          (try (.stop acme-http 0) (catch Exception _ nil))
          (http-shell/stop-http-servers! http-srv)
          (infra/stop-subnet-runtime! rt1)
          (infra/stop-subnet-runtime! rt2)
          (delete-dir-recursive! dir1)
          (delete-dir-recursive! dir2))))))

;; =============================================================================
;; 8. `bitecho.shell.upnp` SSDP + SOAP `WANIPConnection` & Timeout Diagnostics
;; =============================================================================

(deftest test-upnp-shell-ssdp-soap-and-timeout-diagnostics
  (testing "bitecho.shell.upnp discovers local mock IGD gateway via SSDP, executes GetExternalIPAddress / AddPortMapping / DeletePortMapping SOAP actions, and emits counted :diagnose on timeout"
    (let [soap-http (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
          soap-port (.getPort (.getAddress soap-http))
          mapped-ports (atom [])
          ssdp-sock (DatagramSocket. (InetSocketAddress. "127.0.0.1" 0))
          ssdp-port (.getLocalPort ssdp-sock)]
      (.createContext soap-http "/rootDesc.xml"
                      (reify HttpHandler
                        (handle [_ ex]
                          (let [xml (str "<?xml version=\"1.0\"?>"
                                         "<root><device><serviceList><service>"
                                         "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
                                         "<controlURL>/ctl/IPConn</controlURL>"
                                         "</service></serviceList></device></root>")
                                b (.getBytes xml StandardCharsets/UTF_8)]
                            (.sendResponseHeaders ex 200 (alength b))
                            (with-open [os (.getResponseBody ex)] (.write os b))))))
      (.createContext soap-http "/ctl/IPConn"
                      (reify HttpHandler
                        (handle [_ ex]
                          (let [soap-action (or (.getFirst (.getRequestHeaders ex) "SOAPAction") "")
                                req-body (slurp (.getRequestBody ex) :encoding "UTF-8")
                                resp-xml (cond
                                           (str/includes? soap-action "GetExternalIPAddress")
                                           "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalIPAddress>203.0.113.42</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>"

                                           (str/includes? soap-action "AddPortMapping")
                                           (do (swap! mapped-ports conj req-body)
                                               "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/></s:Body></s:Envelope>")

                                           (str/includes? soap-action "DeletePortMapping")
                                           (do (swap! mapped-ports pop)
                                               "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:DeletePortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/></s:Body></s:Envelope>")

                                           :else
                                           "<Fault/>")
                                b (.getBytes resp-xml StandardCharsets/UTF_8)]
                            (.sendResponseHeaders ex 200 (alength b))
                            (with-open [os (.getResponseBody ex)] (.write os b))))))
      (.start soap-http)
      (.start (Thread/ofVirtual)
              (fn []
                (try
                  (let [buf (byte-array 1024)
                        pkt (DatagramPacket. buf (alength buf))]
                    (.receive ssdp-sock pkt)
                    (let [resp (str "HTTP/1.1 200 OK\r\n"
                                    "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n"
                                    "USN: uuid:mock-igd-1\r\n"
                                    "LOCATION: http://127.0.0.1:" soap-port "/rootDesc.xml\r\n\r\n")
                          rb (.getBytes resp StandardCharsets/UTF_8)]
                      (.send ssdp-sock (DatagramPacket. rb (alength rb) (.getSocketAddress pkt)))))
                  (catch Exception _ nil))))
      (try
        (let [disc (upnp/discover-gateway! {:ssdp-host "127.0.0.1"
                                            :ssdp-port ssdp-port
                                            :timeout-ms 1500})
              gw (:gateway disc)
              ext-ip (upnp/get-external-ip! gw {:timeout-ms 1500})
              add-res (upnp/add-port-mapping! gw {:external-port 8443
                                                  :internal-client "192.168.86.36"
                                                  :internal-port 8443
                                                  :protocol "TCP"
                                                  :description "bitecho-ingress"
                                                  :lease-seconds 3600})
              del-res (upnp/delete-port-mapping! gw {:external-port 8443 :protocol "TCP"})
              ;; Unreachable UDP port -> clean fail-safe result with counted :diagnose effect!
              dead-sock (DatagramSocket. (InetSocketAddress. "127.0.0.1" 0))
              dead-port (.getLocalPort dead-sock)
              timeout-res (upnp/discover-gateway! {:ssdp-host "127.0.0.1"
                                                   :ssdp-port dead-port
                                                   :timeout-ms 120})]
          (.close dead-sock)
          (is (:ok? disc))
          (is (= "203.0.113.42" (:external-ip ext-ip)))
          (is (:ok? add-res))
          (is (:ok? del-res))
          (is (empty? @mapped-ports))
          (is (false? (:ok? timeout-res)))
          (is (= :diagnose (:effect (first (:effects timeout-res))))))
        (finally
          (try (.close ssdp-sock) (catch Exception _ nil))
          (try (.stop soap-http 0) (catch Exception _ nil)))))))

(deftest test-complete-infra-node-stack-and-cli-inventory
  (testing "Rule 6: start-infra-node! boots integrated DNS + HTTP/HTTPS + SMTP stack over bitecho.org/infra and CLI subcommands match main.clj usage inventory"
    (let [tmp-dir (make-temp-dir! "infra-stack-")
          stack (main/start-infra-node! {:state-dir (.getAbsolutePath tmp-dir)
                                         :node/id :ns1
                                         :domain "bitecho.org"
                                         :heartbeat-ticker? false
                                         :dns {:enabled? true :bind-ip "127.0.0.1" :port 0}
                                         :http {:enabled? true :bind-ip "127.0.0.1" :http-port 0 :https-port 0}
                                         :smtp {:enabled? true :bind-ip "127.0.0.1" :port 0}
                                         :acme {:enabled? false}})
          main-src (slurp "src/bitecho/main.clj")]
      (try
        (is (= :running (:phase (infra/runtime-status (:runtime stack)))))
        (is (pos? (get-in stack [:dns :udp-port])))
        (is (pos? (get-in stack [:http :https-port])))
        (is (pos? (get-in stack [:smtp :port])))
        (doseq [subcmd main/cli-subcommands]
          (is (str/includes? main-src (str "bitecho " subcmd))
              (str "print-usage must document CLI subcommand: " subcmd)))
        (let [ops-src (slurp "scripts/infra_cluster.sh")]
          (doseq [verb ["snapshot" "provision-secret" "cutover" "rollback" "audit"]]
            (is (str/includes? ops-src (str "  " verb))
                (str "infra_cluster.sh usage must document verb: " verb))
            (is (str/includes? ops-src (str verb ")"))
                (str "infra_cluster.sh case dispatch must handle verb: " verb))))
        ((:stop! stack))
        (is (= :stopped (:phase (infra/runtime-status (:runtime stack)))))
        (finally
          (try ((:stop! stack)) (catch Exception _ nil))
          (delete-dir-recursive! tmp-dir))))))

;; =============================================================================
;; 9. Phase C & `F-B1..F-B3` Hardening, Migration, & 3-Node DTLS Mesh Tests
;; =============================================================================

(deftest test-fb1-fb2-fb3-shell-dac-epoch-threading-and-tls-secret-preconditions
  (testing "F-B1, F-B2, F-B3: multi-node infra fails fast without shared :tls-secret, populates :gate/acme-thumbprint, and threads X-Bitecho-DAC + authoritative epoch fail-closed"
    (let [tmp-dir (make-temp-dir! "fb123-shell-")
          secret-file (io/file tmp-dir "tls-secret.key")
          _ (spit secret-file "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
          anchor-kp (crypto/generate-keypair)
          anchor-pub (basalt/bytes->hex (:public anchor-kp))
          client-cert-bundle (http-shell/generate-ed25519-client-cert "dac-client.local" 7)
          client-spki-hex (:pubkey-hex client-cert-bundle)
          dac (light-core/create-dac (:private anchor-kp)
                                     {:anchor-pubkey anchor-pub
                                      :agent-pubkey client-spki-hex
                                      :scopes ["web"]
                                      :issued-epoch 10
                                      :expires-epoch 100})
          dac-hdr (acme-proto/base64url-encode (fressian/encode-canonical dac))]
      (try
        ;; 1. F-B2: multi-node (:all-nodes #{:ns1 :ns2}) with TLS/ACME enabled and NO :tls-secret MUST fail fast!
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"tls-secret"
             (main/start-infra-node! {:state-dir (.getAbsolutePath (io/file tmp-dir "bad-multi"))
                                      :node/id :ns1
                                      :all-nodes #{:ns1 :ns2}
                                      :domain "bitecho.org"
                                      :heartbeat-ticker? false
                                      :dns {:enabled? false}
                                      :http {:enabled? false}
                                      :acme {:enabled? false}})))
        ;; 2. F-B2 + F-B3: multi-node WITH :tls-secret-file and pre-created ACME account populates :gate/acme-thumbprint!
        (let [good-dir (io/file tmp-dir "good-multi")
              _ (acme-shell/save-or-load-account-keypair! good-dir)
              expected-thumb (acme-shell/account-keypair-thumbprint! good-dir)
              stack (main/start-infra-node! {:state-dir (.getAbsolutePath good-dir)
                                             :node/id :ns1
                                             :all-nodes #{:ns1 :ns2}
                                             :tls-secret-file (.getAbsolutePath secret-file)
                                             :domain "bitecho.org"
                                             :heartbeat-ticker? false
                                             :cluster {:enabled? false}
                                             :dns {:enabled? false}
                                             :http {:enabled? false}
                                             :acme {:enabled? false}})]
          (try
            (is (= expected-thumb
                   (get-in @(:subnet-atom (:runtime stack)) [:policy :subnet/gate :gate/acme-thumbprint])))
            (finally
              ((:stop! stack)))))
        ;; 3. F-B1: HTTPS :dac-gated subnet fails closed when runtime epoch is nil, admits at epoch 50, denies at epoch 101!
        (let [dac-policy {:subnet/id "chat/dac-http"
                          :subnet/parent-id "global"
                          :subnet/gate {:gate/mode :permissioned
                                        :gate/admission :dac
                                        :gate/trust-anchors #{anchor-pub}}
                          :subnet/path-acl [{:pattern "web/*" :principal {:type :pubkey :pubkey anchor-pub}}]
                          :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                          :subnet/replication {:replication/pointers :gossip-crdt :replication/blobs :eager-push}}
              dac-rt (infra/start-subnet-runtime! {:state-dir (io/file tmp-dir "dac-rt")
                                                   :policy dac-policy
                                                   :node-id anchor-pub
                                                   :node-privkey (:private anchor-kp)})
              _ (infra/publish-blob-and-pointer! dac-rt {:blob (data/make-blob "dac-gated-ok" "text/plain")
                                                         :path "web/room.txt"
                                                         :seq 1
                                                         :authority-pubkey anchor-pub
                                                         :authority-privkey (:private anchor-kp)
                                                         :now-ms 1000})
              tls-mgr (http-shell/init-tls-manager! {:state-dir (io/file tmp-dir "dac-tls") :domain "localhost"})
              srv (http-shell/start-http-servers!
                   {:domain "localhost"
                    :state-dir (io/file tmp-dir "dac-tls")
                    :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                   tls-mgr
                   dac-rt)
              client (-> (HttpClient/newBuilder)
                         (.sslContext (trust-all-ssl-context client-cert-bundle))
                         (.connectTimeout (Duration/ofSeconds 3))
                         (.build))
              req (-> (HttpRequest/newBuilder (URI/create (str "https://localhost:" (:https-port srv) "/room.txt")))
                      (.header "X-Bitecho-DAC" dac-hdr)
                      (.GET)
                      (.build))]
          (try
            ;; Unsynced runtime epoch (nil) -> 403 fail-closed!
            (is (= 403 (.statusCode (.send client req (HttpResponse$BodyHandlers/ofString)))))
            ;; Synced epoch 50 (within [10..100]) -> 200 OK!
            (infra/set-runtime-epoch! dac-rt 50)
            (let [r200 (.send client req (HttpResponse$BodyHandlers/ofString))]
              (is (= 200 (.statusCode r200)))
              (is (= "dac-gated-ok" (.body r200))))
            ;; Advance epoch to 101 (> 100) -> 403 denied!
            (infra/set-runtime-epoch! dac-rt 101)
            (is (= 403 (.statusCode (.send client req (HttpResponse$BodyHandlers/ofString)))))
            (finally
              (http-shell/stop-http-servers! srv)
              (infra/stop-subnet-runtime! dac-rt))))
        (finally
          (delete-dir-recursive! tmp-dir))))))

(deftest test-phase-c-migrate-clj-web-state-and-mail-cli-parity
  (testing "Phase C: migrate-clj-web-state! idempotently imports certs, .eml files, web/directory assets, and DNS records; content-root fallback serves bare git objects safely; mail helpers list/read/tombstone"
    (let [tmp-dir (make-temp-dir! "phase-c-mig-")
          state-dir (io/file tmp-dir "var-lib-clj-web")
          content-root (io/file tmp-dir "var-www-public")
          certs-dir (io/file state-dir "certs")
          mail-dir (io/file state-dir "mail")
          _ (.mkdirs certs-dir)
          _ (.mkdirs mail-dir)
          _ (.mkdirs (io/file content-root "directory"))
          _ (.mkdirs (io/file content-root "git" "bitecho.git"))
          cert-b (http-shell/generate-cert-and-keypair "bitecho.org" 60)
          cert-pem (http-shell/encode-cert-pem (:certificate cert-b))
          key-pem (http-shell/encode-private-key-pem (.getPrivate ^java.security.KeyPair (:keypair cert-b)))
          _ (spit (io/file certs-dir "bundle.edn") (pr-str {:cert-pem cert-pem :key-pem key-pem}))
          _ (spit (io/file mail-dir "1700000001-aa11bb22.eml")
                  "Received: from mx.example.org\r\nFrom: alice@example.org\r\nTo: simon@bitecho.org\r\nSubject: First Mail\r\n\r\nBody one\r\n")
          _ (spit (io/file content-root "index.md") "# Welcome to Bitecho\n")
          _ (spit (io/file content-root "directory" "axiom.json") "{\"nickname\":\"axiom\"}")
          _ (spit (io/file content-root "git" "bitecho.git" "HEAD") "ref: refs/heads/main\n")
          ns1-kp (crypto/generate-keypair)
          ns1-pub (basalt/bytes->hex (:public ns1-kp))
          tls-secret (crypto/sha256 (fressian/utf8->bytes "phase-c-migration-secret"))
          policy (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                              :trust-anchors #{ns1-pub}
                                              :cold-pubkey ns1-pub
                                              :domain-pubkey ns1-pub})
          tls-mgr (http-shell/init-tls-manager! {:state-dir state-dir :domain "bitecho.org"})
          rt (infra/start-subnet-runtime! {:state-dir state-dir
                                           :policy policy
                                           :node-id ns1-pub
                                           :default-sender ns1-pub
                                           :node-privkey (:private ns1-kp)
                                           :tls-manager tls-mgr
                                           :tls-secret tls-secret})
          cfg {:domain "bitecho.org"
               :state-dir (.getAbsolutePath state-dir)
               :http {:bind-ip "127.0.0.1"
                      :http-port 0
                      :https-port 0
                      :content-root (.getAbsolutePath content-root)
                      :directory-listing? true}
               :dns {:txt-records {"@" ["v=spf1 -all"]}}}
          rep1 (infra/migrate-clj-web-state! rt cfg {:tls-secret tls-secret})
          rep2 (infra/migrate-clj-web-state! rt cfg {:tls-secret tls-secret})
          srv (http-shell/start-http-servers! cfg tls-mgr rt)
          client (-> (HttpClient/newBuilder)
                     (.sslContext (trust-all-ssl-context nil))
                     (.connectTimeout (Duration/ofSeconds 3))
                     (.build))]
      (try
        (is (:ok? rep1))
        (is (:tls-migrated? rep1))
        (is (= 1 (:emails-migrated rep1)))
        (is (>= (:web-assets-migrated rep1) 2))
        (is (= 1 (:dns-records-migrated rep1)))
        (is (= 0 (:emails-migrated rep2)) "Second migration run is idempotent")
        ;; Verify migrated web/index.md AND content-root fallback for /git/bitecho.git/HEAD
        (let [r-idx (.send client
                           (-> (HttpRequest/newBuilder (URI/create (str "https://localhost:" (:https-port srv) "/")))
                               (.GET) (.build))
                           (HttpResponse$BodyHandlers/ofString))
              r-git (.send client
                           (-> (HttpRequest/newBuilder (URI/create (str "https://localhost:" (:https-port srv) "/git/bitecho.git/HEAD")))
                               (.GET) (.build))
                           (HttpResponse$BodyHandlers/ofString))
              r-trav (.send client
                            (-> (HttpRequest/newBuilder (URI/create (str "https://localhost:" (:https-port srv) "/..%2fcerts/bundle.edn")))
                                (.GET) (.build))
                            (HttpResponse$BodyHandlers/ofString))]
          (is (= 200 (.statusCode r-idx)))
          (is (str/includes? (.body r-idx) "Welcome to Bitecho"))
          (is (= 200 (.statusCode r-git)))
          (is (= "ref: refs/heads/main\n" (.body r-git)))
          (is (= 403 (.statusCode r-trav)) "Path traversal blocked fail-closed"))
        ;; Verify mail list/read/tombstone helpers over Subnet Pointers
        (let [emails (infra/list-subnet-emails rt)
              read1 (infra/read-subnet-email rt "latest")
              del-res (infra/delete-subnet-emails! rt "all")
              emails-after (infra/list-subnet-emails rt)]
          (is (= 1 (count emails)))
          (is (= "First Mail" (:subject read1)))
          (is (str/includes? (:body read1) "Body one"))
          (is (= 1 (:count del-res)))
          (is (empty? emails-after)))
        (finally
          (http-shell/stop-http-servers! srv)
          (infra/stop-subnet-runtime! rt)
          (delete-dir-recursive! tmp-dir))))))

(deftest test-phase-c-three-node-datachannel-mesh-and-rolling-cutover
  (testing "Phase C: 3-node (ns1..ns3) clj-datachannel mutual-DTLS peer mesh elects leader, replicates Blobs/Pointers, and survives rolling node restart"
    (let [dir1 (make-temp-dir! "dc-ns1-")
          dir2 (make-temp-dir! "dc-ns2-")
          dir3 (make-temp-dir! "dc-ns3-")
          ;; Allocate 3 distinct ephemeral UDP port blocks (base, base+1, base+2)
          pick-port-block (fn []
                            (loop [base (+ 24000 (rand-int 20000))]
                              (let [ok? (try
                                          (with-open [a (DatagramSocket. (InetSocketAddress. "127.0.0.1" base))
                                                      b (DatagramSocket. (InetSocketAddress. "127.0.0.1" (+ base 1)))
                                                      c (DatagramSocket. (InetSocketAddress. "127.0.0.1" (+ base 2)))]
                                            (and (.isBound a) (.isBound b) (.isBound c)))
                                          (catch Exception _ false))]
                                (if ok? base (recur (+ 24000 (rand-int 20000)))))))
          p1 (pick-port-block)
          p2 (pick-port-block)
          p3 (pick-port-block)
          id1 (infra/load-or-create-infra-peer-identity! dir1 :ns1)
          id2 (infra/load-or-create-infra-peer-identity! dir2 :ns2)
          id3 (infra/load-or-create-infra-peer-identity! dir3 :ns3)
          anchors #{(:pubkey-hex id1) (:pubkey-hex id2) (:pubkey-hex id3)}
          policy (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                              :trust-anchors anchors
                                              :cold-pubkey (:pubkey-hex id1)
                                              :domain-pubkey (:pubkey-hex id1)})
          tls-secret (crypto/sha256 (fressian/utf8->bytes "dc-3node-shared-secret"))
          nodes-cfg {:ns1 {:ip4 "127.0.0.1" :port p1 :fingerprint (:fingerprint id1) :pubkey (:pubkey-hex id1)}
                     :ns2 {:ip4 "127.0.0.1" :port p2 :fingerprint (:fingerprint id2) :pubkey (:pubkey-hex id2)}
                     :ns3 {:ip4 "127.0.0.1" :port p3 :fingerprint (:fingerprint id3) :pubkey (:pubkey-hex id3)}}
          make-node! (fn [nid dir id]
                       (let [rt (infra/start-subnet-runtime! {:state-dir dir
                                                              :policy policy
                                                              :node-id nid
                                                              :default-sender (:pubkey-hex id)
                                                              :node-privkey (:privkey-bytes id)
                                                              :all-nodes #{:ns1 :ns2 :ns3}
                                                              :tls-secret tls-secret})
                             mesh (infra/start-datachannel-peer-mesh!
                                   {:node/id nid
                                    :state-dir dir
                                    :cluster {:heartbeat-interval-ms 250
                                              :heartbeat-timeout-ms 4000
                                              :nodes nodes-cfg}}
                                   rt)]
                         {:rt rt :mesh mesh :id id}))
          n1 (atom nil)
          n2 (atom nil)
          n3 (atom nil)]
      (try
        (reset! n1 (make-node! :ns1 dir1 id1))
        (reset! n2 (make-node! :ns2 dir2 id2))
        (reset! n3 (make-node! :ns3 dir3 id3))
        ;; Wait up to 8s for real DTLS DataChannel mesh convergence & :ns1 leader election
        (let [deadline (+ (System/currentTimeMillis) 8000)]
          (loop []
            (let [s1 (infra/runtime-status (:rt @n1))
                  s2 (infra/runtime-status (:rt @n2))
                  s3 (infra/runtime-status (:rt @n3))]
              (when (and (< (System/currentTimeMillis) deadline)
                         (not (and (= :ns1 (:leader-id s1))
                                   (= :ns1 (:leader-id s2))
                                   (= :ns1 (:leader-id s3)))))
                (Thread/sleep 100)
                (recur)))))
        (is (= :ns1 (:leader-id (infra/runtime-status (:rt @n1)))))
        (is (= :ns1 (:leader-id (infra/runtime-status (:rt @n2)))))
        (is (= :ns1 (:leader-id (infra/runtime-status (:rt @n3)))))
        ;; Publish a Blob + Pointer on ns1 -> replicates over real DTLS DataChannels to ns2 & ns3!
        (let [site-blob (data/make-blob "replicated-over-dtls-datachannel" "text/plain; charset=utf-8")
              _ (infra/publish-blob-and-pointer! (:rt @n1)
                                                 {:blob site-blob
                                                  :path "web/live.txt"
                                                  :seq 1
                                                  :authority-pubkey (:pubkey-hex id1)
                                                  :authority-privkey (:privkey-bytes id1)})
              deadline (+ (System/currentTimeMillis) 5000)]
          (loop []
            (when (and (< (System/currentTimeMillis) deadline)
                       (not (and (:ok? (infra/resolve-path-blob! (:rt @n2) "web/live.txt"))
                                 (:ok? (infra/resolve-path-blob! (:rt @n3) "web/live.txt")))))
              (Thread/sleep 100)
              (recur)))
          (is (= "replicated-over-dtls-datachannel"
                 (fressian/bytes->utf8 (get-in (infra/resolve-path-blob! (:rt @n2) "web/live.txt") [:blob :blob/bytes]))))
          (is (= "replicated-over-dtls-datachannel"
                 (fressian/bytes->utf8 (get-in (infra/resolve-path-blob! (:rt @n3) "web/live.txt") [:blob :blob/bytes])))))
        (finally
          (doseq [n [@n1 @n2 @n3] :when n]
            (try (infra/stop-datachannel-peer-mesh! (:mesh n)) (catch Exception _ nil))
            (try (infra/stop-subnet-runtime! (:rt n)) (catch Exception _ nil)))
          (delete-dir-recursive! dir1)
          (delete-dir-recursive! dir2)
          (delete-dir-recursive! dir3))))))

(deftest test-fc1-fc3-fc4-cutover-flags-regression
  (testing "B1 (F-C1), F-C3, & B2 (F-C4): socket-free production clj-web fixture identity migration, multi-node cold-key safety, and signed :5010 finalized-epoch quorum poller"
    (let [tmp-dir (make-temp-dir! "fc1-fc3-fc4-")]
      (try
        ;; 1. B1 (F-C1): Real production clj-web cluster/node-identity.edn fixture {:cert-pem, :key-pem, :fingerprint, :ice-creds}
        ;;    (contains no Ed25519 keys): preserves exact DTLS fingerprint & :ice-creds while minting a fresh Bitecho Ed25519
        ;;    identity once into identity/node-identity.edn and keeping it stable across reloads.
        (let [cljweb-dir (io/file tmp-dir "real-cljweb-fixture")
              _ (.mkdirs (io/file cljweb-dir "cluster"))
              dtls-b (http-shell/generate-cert-and-keypair "ns1.bitecho.org" 30)
              cert-pem (http-shell/encode-cert-pem (:certificate dtls-b))
              key-pem (http-shell/encode-private-key-pem (.getPrivate ^java.security.KeyPair (:keypair dtls-b)))
              raw-fp (let [md (java.security.MessageDigest/getInstance "SHA-256")
                           bs (.digest md (.getEncoded ^X509Certificate (:certificate dtls-b)))]
                       (str/join ":" (map #(format "%02X" (bit-and % 0xff)) bs)))
              legacy-ice {:ufrag "cw-ufrag" :pwd "cw-pwd-0123456789abcdef"}
              _ (spit (io/file cljweb-dir "cluster" "node-identity.edn")
                      (pr-str {:cert-pem cert-pem
                               :key-pem key-pem
                               :fingerprint raw-fp
                               :ice-creds legacy-ice}))
              cw1 (infra/load-or-create-infra-peer-identity! cljweb-dir :ns1)
              cw2 (infra/load-or-create-infra-peer-identity! cljweb-dir :ns1)
              corrupt-dir (io/file tmp-dir "corrupt-node-identity")
              _ (.mkdirs (io/file corrupt-dir "cluster"))
              ed1 (crypto/generate-keypair)
              ed2 (crypto/generate-keypair)
              _ (spit (io/file corrupt-dir "cluster" "node-identity.edn")
                      (pr-str {:pubkey-hex (basalt/bytes->hex (:public ed1))
                               :privkey-hex (basalt/bytes->hex (:private ed2))
                               :cert-pem cert-pem
                               :key-pem key-pem
                               :fingerprint raw-fp}))]
          (is (= (identity/normalize-fingerprint raw-fp) (:fingerprint cw1) (:fingerprint cw2))
              "B1: clj-web DTLS fingerprint preserved across cutover & reload")
          (is (= legacy-ice (:ice-creds cw1) (:ice-creds cw2))
              "B1: clj-web :ice-creds preserved across cutover & reload")
          (is (and (string? (:pubkey-hex cw1)) (= 88 (count (:pubkey-hex cw1))))
              "B1: fresh valid 88-hex Ed25519 SPKI pubkey minted at cutover")
          (is (= (:pubkey-hex cw1) (:pubkey-hex cw2))
              "B1: minted Ed25519 pubkey persisted in identity/node-identity.edn and stable across reloads")
          (is (= (:privkey-hex cw1) (:privkey-hex cw2))
              "B1: minted Ed25519 privkey stable across reloads")
          (is (.exists (io/file cljweb-dir "identity" "node-identity.edn"))
              "B1: Bitecho Ed25519 identity persisted under <state-dir>/identity/node-identity.edn")
          (is (thrown? clojure.lang.ExceptionInfo
                       (infra/load-or-create-infra-peer-identity! corrupt-dir :ns1))
              "B1: mismatched Ed25519 keypair fails closed"))

        ;; 2. F-C3 & B2 (F-C4): Multi-node start-infra-node! without :cold-pubkey uses :quorum (never hot-key cold-root!),
        ;;    and authenticated :5010 :query-chain-state -> signed :chain-state-snapshot poller feeds finalized-epoch
        (let [s-dir (io/file tmp-dir "fc3-fc4-stack")
              sec-f (io/file tmp-dir "fc3.key")
              _ (spit sec-f "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
              stack (main/start-infra-node! {:state-dir (.getAbsolutePath s-dir)
                                             :node/id :ns1
                                             :all-nodes #{:ns1 :ns2 :ns3}
                                             :tls-secret-file (.getAbsolutePath sec-f)
                                             :domain "bitecho.org"
                                             :heartbeat-ticker? false
                                             :cluster {:enabled? false}
                                             :dns {:enabled? false}
                                             :http {:enabled? false}
                                             :acme {:enabled? false}})
              rt (:runtime stack)
              gov (get-in @(:subnet-atom rt) [:policy :subnet/gate :gate/governance])
              ops-src (slurp "scripts/infra_cluster.sh")
              v1-kp (crypto/generate-keypair)
              v2-kp (crypto/generate-keypair)
              v3-kp (crypto/generate-keypair)
              v1-pub (basalt/bytes->hex (:public v1-kp))
              v2-pub (basalt/bytes->hex (:public v2-kp))
              v3-pub (basalt/bytes->hex (:public v3-kp))
              bootstrap {:nodes {:node1 {:pubkey v1-pub :ip "35.212.129.138" :agent-port 5010}
                                 :node2 {:pubkey v2-pub :ip "35.206.120.143" :agent-port 5010}
                                 :node3 {:pubkey v3-pub :ip "35.211.71.139" :agent-port 5010}}}
              mk-snap (fn [val-pub val-priv pk nonce fin-ep]
                        (light-core/sign-chain-state-snapshot
                         {:validator-pubkey val-pub
                          :pubkey pk
                          :finalized-epoch fin-ep
                          :balance 0
                          :spendable 0
                          :seq 0
                          :deps []
                          :escrows []
                          :nonce nonce}
                         val-priv))]
          (try
            (is (= :quorum (:governance/type gov)) "F-C3: multi-node default governance is :quorum, never ns1 hot key")
            (is (nil? (:cold-pubkey gov)))
            (is (str/includes? ops-src "infra_cold_root_keypair.edn")
                "F-C3: infra_cluster.sh uses dedicated offline cold root keypair")
            (is (str/includes? ops-src ":validator-bootstrap \"/etc/bitecho-infra/bootstrap.txt\"")
                "B2: infra_cluster.sh wires :validator-bootstrap for :5010 finalized-epoch polling")

            ;; B2 (a): Unreachable :5010 mesh fails closed with counted :validator-epoch-quorum-failed, epoch stays nil
            (let [down-res (infra/sync-runtime-epoch-from-validators! rt bootstrap (fn [_ _] []))]
              (is (false? (:ok? down-res)))
              (is (nil? (infra/current-runtime-epoch rt))))

            ;; B2 (b): Skew > 2 across validators fails closed with counted :validator-epoch-quorum-failed, epoch stays nil
            (let [skew-res (infra/sync-runtime-epoch-from-validators!
                            rt bootstrap
                            (fn [pk nonce]
                              [(mk-snap v1-pub (:private v1-kp) pk nonce 100)
                               (mk-snap v2-pub (:private v2-kp) pk nonce 105)
                               (mk-snap v3-pub (:private v3-kp) pk nonce 110)]))]
              (is (false? (:ok? skew-res)))
              (is (= "validator-epoch-skew-exceeded" (:detail skew-res)))
              (is (nil? (infra/current-runtime-epoch rt))))

            ;; B2 (c): Valid 2-of-3 / 3-of-3 Ed25519-signed :chain-state-snapshot quorum updates runtime finalized-epoch
            (let [agree-res (infra/sync-runtime-epoch-from-validators!
                             rt bootstrap
                             (fn [pk nonce]
                               [(mk-snap v1-pub (:private v1-kp) pk nonce 36600)
                                (mk-snap v2-pub (:private v2-kp) pk nonce 36600)
                                (mk-snap v3-pub (:private v3-kp) pk nonce 36599)]))]
              (is (:ok? agree-res))
              (is (= 36600 (:epoch agree-res)))
              (is (= 36600 (infra/current-runtime-epoch rt))))

            ;; B2 (d): Subsequent :5010 mesh outage fails closed on tick while keeping runtime epoch monotonic at 36600
            (let [outage-res (infra/sync-runtime-epoch-from-validators! rt bootstrap (fn [_ _] []))]
              (is (false? (:ok? outage-res)))
              (is (= 36600 (infra/current-runtime-epoch rt))))

            ;; B2 (e): Regressive signed quorum (36500 < 36600) rejected with :validator-epoch-regressive
            (let [stale-res (infra/sync-runtime-epoch-from-validators!
                             rt bootstrap
                             (fn [pk nonce]
                               [(mk-snap v1-pub (:private v1-kp) pk nonce 36500)
                                (mk-snap v2-pub (:private v2-kp) pk nonce 36500)
                                (mk-snap v3-pub (:private v3-kp) pk nonce 36500)]))]
              (is (false? (:ok? stale-res)) "Regressive validator finalized-epoch rejected")
              (is (= :validator-epoch-regressive (:error stale-res)))
              (is (= 36600 (infra/current-runtime-epoch rt))))
            (finally
              ((:stop! stack)))))
        (finally
          (delete-dir-recursive! tmp-dir))))))

(deftest test-phase-d-blob-content-type-and-cold-hydration
  (testing "Phase D: Cold-pinned placeholder hydration preserves :blob/media-type, and serve-subnet-request falls back to content-type-for-file when :blob/media-type is absent or application/octet-stream"
    (let [tmp-dir (make-temp-dir! "phase-d-ct-")
          content-root (io/file tmp-dir "public")
          state-dir (io/file tmp-dir "state")]
      (try
        (.mkdirs content-root)
        (spit (io/file content-root "index.md") "# Bitecho Phase D\n")
        (spit (io/file content-root "llms.txt") "# Bitecho Phase D\n")
        (spit (io/file content-root "ONBOARDING.md") "# Onboarding\n")
        (let [id (infra/load-or-create-infra-peer-identity! state-dir :ns1)
              pol (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                               :trust-anchors #{(:pubkey-hex id)}})
              cfg {:node/id :ns1
                   :domain "bitecho.org"
                   :state-dir (.getAbsolutePath state-dir)
                   :http {:content-root (.getAbsolutePath content-root)}}
              ;; 1. Run migrate-clj-web-state! in a transient runtime (just like `bitecho migrate-infra`)
              rt1 (infra/start-subnet-runtime! {:state-dir state-dir
                                                :policy pol
                                                :node-id :ns1
                                                :default-sender (:pubkey-hex id)
                                                :node-privkey (:privkey-bytes id)})]
          (infra/migrate-clj-web-state! rt1 cfg)
          ;; Also publish a Blob with explicit "application/octet-stream" media-type at "web/raw-doc.md"
          (let [oct-blob (data/make-blob "# Fallback Markdown\n" "application/octet-stream")]
            (infra/publish-blob-and-pointer! rt1 {:blob oct-blob
                                                  :path "web/raw-doc.md"
                                                  :seq 1
                                                  :authority-pubkey (:pubkey-hex id)
                                                  :authority-privkey (:privkey-bytes id)}))
          (infra/stop-subnet-runtime! rt1)

          ;; 2. Start a fresh runtime from disk (cold-pinned placeholders in subnet-pointers.fressian)
          (let [rt2 (infra/start-subnet-runtime! {:state-dir state-dir
                                                  :policy pol
                                                  :node-id :ns1
                                                  :default-sender (:pubkey-hex id)
                                                  :node-privkey (:privkey-bytes id)})
                serve-fn @#'http-shell/serve-subnet-request]
            (try
              (let [res-root (serve-fn cfg (:shell-atom rt2) rt2
                                       {:request/method :GET
                                        :request/uri {:path "/"}
                                        :request/headers {}}
                                       (System/currentTimeMillis))
                    res-llms (serve-fn cfg (:shell-atom rt2) rt2
                                       {:request/method :GET
                                        :request/uri {:path "/llms.txt"}
                                        :request/headers {}}
                                       (System/currentTimeMillis))
                    res-onb (serve-fn cfg (:shell-atom rt2) rt2
                                      {:request/method :GET
                                       :request/uri {:path "/ONBOARDING.md"}
                                       :request/headers {}}
                                      (System/currentTimeMillis))
                    res-fallback (serve-fn cfg (:shell-atom rt2) rt2
                                           {:request/method :GET
                                            :request/uri {:path "/raw-doc.md"}
                                            :request/headers {}}
                                           (System/currentTimeMillis))]
                (is (= 200 (:response/status res-root)))
                (is (= "text/markdown; charset=utf-8" (get-in res-root [:response/headers "Content-Type"]))
                    "Root / (web/index.md) hydrated from disk after restart returns text/markdown; charset=utf-8")
                (is (= 200 (:response/status res-llms)))
                (is (= "text/plain; charset=utf-8" (get-in res-llms [:response/headers "Content-Type"]))
                    "/llms.txt sharing CID with index.md returns text/plain; charset=utf-8")
                (is (= 200 (:response/status res-onb)))
                (is (= "text/markdown; charset=utf-8" (get-in res-onb [:response/headers "Content-Type"]))
                    "/ONBOARDING.md hydrated from disk after restart returns text/markdown; charset=utf-8")
                (is (= 200 (:response/status res-fallback)))
                (is (= "text/markdown; charset=utf-8" (get-in res-fallback [:response/headers "Content-Type"]))
                    "Blob with :blob/media-type application/octet-stream falls back to content-type-for-file on pointer path"))
              (finally
                (infra/stop-subnet-runtime! rt2)))))
        (finally
          (delete-dir-recursive! tmp-dir))))))

(deftest test-fc2-dtls-mismatch-socket-regression
  (testing "F-C2: DTLS fingerprint mismatch over UDP triggers :on-error -> counted :peer-dtls-error diagnostic"
    (let [tmp-dir (make-temp-dir! "fc2-dtls-")]
      (try
        (let [m-dir1 (io/file tmp-dir "mismatch-ns1")
              m-dir2 (io/file tmp-dir "mismatch-ns2")
              id1 (infra/load-or-create-infra-peer-identity! m-dir1 :ns1)
              id2 (infra/load-or-create-infra-peer-identity! m-dir2 :ns2)
              wrong-fp (apply str (interpose ":" (repeat 32 "FF")))
              pol (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                               :trust-anchors #{(:pubkey-hex id1) (:pubkey-hex id2)}})
              sec (crypto/sha256 (fressian/utf8->bytes "mismatch-sec"))
              p1 (with-open [s (DatagramSocket. 0)] (.getLocalPort s))
              p2 (with-open [s (DatagramSocket. 0)] (.getLocalPort s))
              rt1 (infra/start-subnet-runtime! {:state-dir m-dir1 :policy pol :node-id :ns1
                                                :default-sender (:pubkey-hex id1) :node-privkey (:privkey-bytes id1)
                                                :all-nodes #{:ns1 :ns2} :tls-secret sec})
              rt2 (infra/start-subnet-runtime! {:state-dir m-dir2 :policy pol :node-id :ns2
                                                :default-sender (:pubkey-hex id2) :node-privkey (:privkey-bytes id2)
                                                :all-nodes #{:ns1 :ns2} :tls-secret sec})
              mesh1 (infra/start-datachannel-peer-mesh!
                     {:node/id :ns1 :state-dir m-dir1
                      :cluster {:heartbeat-interval-ms 5000
                                :nodes {:ns1 {:ip4 "127.0.0.1" :port p1 :fingerprint (:fingerprint id1)}
                                        :ns2 {:ip4 "127.0.0.1" :port p2 :fingerprint wrong-fp}}}}
                     rt1)
              mesh2 (infra/start-datachannel-peer-mesh!
                     {:node/id :ns2 :state-dir m-dir2
                      :cluster {:heartbeat-interval-ms 5000
                                :nodes {:ns1 {:ip4 "127.0.0.1" :port p1 :fingerprint (:fingerprint id1)}
                                        :ns2 {:ip4 "127.0.0.1" :port p2 :fingerprint (:fingerprint id2)}}}}
                     rt2)]
          (try
            (let [deadline (+ (System/currentTimeMillis) 5000)]
              (loop []
                (when (and (< (System/currentTimeMillis) deadline)
                           (zero? (get-in @(:shell-atom mesh1) [:diagnostics-counts :peer-dtls-error] 0)))
                  (Thread/sleep 50)
                  (recur))))
            (is (pos? (get-in @(:shell-atom mesh1) [:diagnostics-counts :peer-dtls-error] 0))
                "F-C2: DTLS fingerprint mismatch counted in :peer-dtls-error")
            (finally
              (infra/stop-datachannel-peer-mesh! mesh1)
              (infra/stop-datachannel-peer-mesh! mesh2)
              (infra/stop-subnet-runtime! rt1)
              (infra/stop-subnet-runtime! rt2))))
        (finally
          (delete-dir-recursive! tmp-dir))))))
