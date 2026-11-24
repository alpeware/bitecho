(ns bitecho.d54-bip024-integration-test
  "JVM integration tests for BIP-024:
   - Multi-segment `/directory/v1/<net>/<path...>` HTTP routing + `application/fressian` support
   - Fail-closed `/faucet/v1/claim` HTTP endpoint (rejecting forged `authenticator_verified: true`)
   - `state_machine/compute-checkpoint-state-digest` commitment to `:vaults` & `:validator-set-history`
   - `streamlet/verify-ancestor-quorum` historical catchup across 3+ consecutive validator rotations."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.circle :as circle]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.faucet :as faucet]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.shell.http :as http]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.data.json :as json]
            [clojure.test :refer [deftest is testing]])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(defn- gen-kp
  []
  (let [kp (crypto/generate-keypair)]
    (assoc kp :spki-hex (circle/normalize-spki-pubkey (basalt/bytes->hex (:public kp))))))

(deftest test-bip024-http-multisegment-directory-and-fail-closed-faucet
  (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-bip024-http-" (into-array FileAttribute [])))
        treasury (gen-kp)
        claimant (gen-kp)
        hw-kp (gen-kp)
        auth-kp (gen-kp)
        faucet-atom (atom (faucet/init-faucet-state {:network-uri "devnet.bitecho.org"
                                                     :treasury-privkey (:private treasury)
                                                     :treasury-pubkey (:spki-hex treasury)
                                                     :drip-amount-ech 1000000}))
        ;; Prepare a multi-segment directory blob at dir/devnet.bitecho.org/root/protocol
        desc-bytes (fressian/encode-canonical {:bitecho/type :directory/entity-descriptor
                                               :uri "devnet.bitecho.org/root/protocol"
                                               :purpose-cid (apply str (repeat 64 "1"))})
        desc-blob (data/make-blob desc-bytes "application/fressian")
        dir-ptr (data/sign-pointer
                 (:private auth-kp)
                 {:pointer/authority (:spki-hex auth-kp)
                  :pointer/subnet "devnet.bitecho.org"
                  :pointer/path "dir/devnet.bitecho.org/root/protocol"
                  :pointer/seq 1
                  :pointer/target (:blob/cid desc-blob)
                  :pointer/expires-epoch 99999
                  :pointer/proof {:proof/type :self}})
        inst0 (assoc (subnet/init-subnet-instance {:subnet-id "devnet.bitecho.org"}) :subnet-id "devnet.bitecho.org")
        blobs1 (data/pin-blob (:store (data/put-blob (get-in inst0 [:data :blobs]) desc-blob 1000)) (:blob/cid desc-blob))
        inst1 (-> inst0
                  (assoc-in [:data :blobs] blobs1)
                  (assoc-in [:data :pointers ["devnet.bitecho.org" "dir/devnet.bitecho.org/root/protocol"]] dir-ptr))
        rt {:subnet-id "devnet.bitecho.org"
            :subnet-atom (atom inst1)
            :state-dir (.getAbsolutePath temp-dir)}
        srv (http/start-http-servers!
             {:domain "devnet.bitecho.org"
              :network-uri "devnet.bitecho.org"
              :faucet-atom faucet-atom
              :http {:bind-ip "127.0.0.1"
                     :http-port 0
                     :https-port 0}}
             (http/init-tls-manager! {:state-dir (.getAbsolutePath temp-dir) :domain "localhost"})
             rt)]
    (try
      (let [port (:http-port srv)
            client (HttpClient/newHttpClient)]
        (testing "Multi-segment /directory/v1/devnet.bitecho.org/root/protocol resolves with application/fressian"
          (let [req (-> (HttpRequest/newBuilder
                         (URI/create (str "http://127.0.0.1:" port "/directory/v1/devnet.bitecho.org/root/protocol")))
                        (.GET)
                        (.build))
                resp (.send client req (HttpResponse$BodyHandlers/ofByteArray))
                ct (.orElse (.firstValue (.headers resp) "content-type") "")]
            (is (= 200 (.statusCode resp)))
            (is (= "application/fressian" ct))
            (is (= "devnet.bitecho.org/root/protocol"
                   (:uri (fressian/decode-wire (.body resp)))))))

        (testing "MUT-11: /faucet/v1/claim rejects client-supplied authenticator_verified=true without valid attestation"
          (let [ch-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/challenge")))
                           (.GET)
                           (.build))
                ch-resp (.send client ch-req (HttpResponse$BodyHandlers/ofString))
                nonce (get-in (json/read-str (.body ch-resp)) ["challenge" "nonce"])
                forged-body (json/write-str {"nonce" nonce
                                             "credential_id_hash" "cred-forged"
                                             "claimant_pubkey" (:spki-hex claimant)
                                             "network_uri" "devnet.bitecho.org"
                                             "authenticator_verified" true})
                cl-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/claim")))
                           (.header "Content-Type" "application/json")
                           (.POST (HttpRequest$BodyPublishers/ofString forged-body StandardCharsets/UTF_8))
                           (.build))
                cl-resp (.send client cl-req (HttpResponse$BodyHandlers/ofString))
                cl-json (json/read-str (.body cl-resp))]
            (is (= 400 (.statusCode cl-resp)))
            (is (false? (get cl-json "ok")))
            (is (= "faucet-attestation-required" (get cl-json "error")))))

        (testing "Valid hardware attestation over /faucet/v1/claim succeeds with 200"
          (let [ch-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/challenge")))
                           (.GET)
                           (.build))
                ch-resp (.send client ch-req (HttpResponse$BodyHandlers/ofString))
                nonce (get-in (json/read-str (.body ch-resp)) ["challenge" "nonce"])
                att (:attestation (faucet/build-test-hardware-attestation
                                   {:hw-privkey (:private hw-kp)
                                    :hw-pubkey (:spki-hex hw-kp)
                                    :claimant-privkey (:private claimant)
                                    :claimant-pubkey (:spki-hex claimant)
                                    :nonce nonce
                                    :network-uri "devnet.bitecho.org"}))
                valid-body (json/write-str {"nonce" nonce
                                            "credential_id_hash" "cred-valid-1"
                                            "claimant_pubkey" (:spki-hex claimant)
                                            "network_uri" "devnet.bitecho.org"
                                            "attestation" {"fmt" (:fmt att)
                                                           "aaguid" (:aaguid att)
                                                           "x5c" (:x5c att)
                                                           "hw_pubkey" (:hw-pubkey att)
                                                           "assertion_sig" (:assertion-sig att)
                                                           "claimant_pop_sig" (:claimant-pop-sig att)}})
                cl-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/claim")))
                           (.header "Content-Type" "application/json")
                           (.POST (HttpRequest$BodyPublishers/ofString valid-body StandardCharsets/UTF_8))
                           (.build))
                cl-resp (.send client cl-req (HttpResponse$BodyHandlers/ofString))
                cl-json (json/read-str (.body cl-resp))]
            (is (= 200 (.statusCode cl-resp)))
            (is (true? (get cl-json "ok"))))))
      (finally
        (http/stop-http-servers! srv)))))

(deftest test-bip024-checkpoint-digest-and-multi-rotation-ancestor-catchup
  (testing "compute-checkpoint-state-digest commits :vaults and :validator-set-history"
    (let [base-snap {:ledger {} :escrows {} :validators ["v1" "v2"] :mesh-nodes {}}
          d0 (sm/compute-checkpoint-state-digest base-snap)
          d1 (sm/compute-checkpoint-state-digest
              (assoc base-snap :vaults {"vault:root" {:balance 5000 :vault-seq 1}}))
          d2 (sm/compute-checkpoint-state-digest
              (assoc base-snap :validator-set-history {10 {:committee ["v1" "v2" "v3" "v4"] :quorum-threshold 3 :descriptor-cid "abc"}}))]
      (is (not= d0 d1))
      (is (not= d0 d2))
      (is (not= d1 d2))))

  (testing "verify-ancestor-quorum catches up across 3 consecutive committee rotations using :validator-set-history"
    (let [kps (vec (repeatedly 7 gen-kp))
          ;; 3 rotated committees of 4 validators each (quorum = 3)
          c0 (subvec kps 0 4)
          c1 (subvec kps 1 5)
          c2 (subvec kps 2 6)
          c3 (subvec kps 3 7)
          peers-map (into {} (map (fn [kp] [(:spki-hex kp) (:public kp)]) kps))
          history {0 {:committee (mapv :spki-hex c0) :quorum-threshold 3}
                   10 {:committee (mapv :spki-hex c1) :quorum-threshold 3}
                   20 {:committee (mapv :spki-hex c2) :quorum-threshold 3}
                   30 {:committee (mapv :spki-hex c3) :quorum-threshold 3}}
          st {:epoch 35
              :validators (mapv :spki-hex c3)
              :validator-set-history history
              :peers-map peers-map}
          make-ancestor (fn [ep comm]
                          (let [sorted-comm (vec (sort-by :spki-hex comm))
                                proposer (nth sorted-comm (mod ep (count sorted-comm)))
                                blk (streamlet/map->Block {:epoch ep
                                                           :parent-hash "genesis"
                                                           :transactions []
                                                           :proposer (:spki-hex proposer)
                                                           :signature nil})
                                blk-signed (streamlet/sign-block blk (:private proposer))
                                b-hash (streamlet/hash-block blk-signed)
                                votes (into {}
                                            (map (fn [vkp]
                                                   (let [sig (basalt/bytes->hex (crypto/sign (:private vkp) (fressian/utf8->bytes b-hash)))
                                                         vote (streamlet/->Vote b-hash ep sig)]
                                                     [(:spki-hex vkp) vote])))
                                            (take 3 sorted-comm))]
                            {:block blk-signed :votes votes}))]
      ;; Ancestor from epoch 5 (signed by c0), epoch 15 (signed by c1), epoch 25 (signed by c2) all verify!
      (is (:valid? (streamlet/verify-ancestor-quorum st (make-ancestor 5 c0))))
      (is (:valid? (streamlet/verify-ancestor-quorum st (make-ancestor 15 c1))))
      (is (:valid? (streamlet/verify-ancestor-quorum st (make-ancestor 25 c2))))
      ;; Forging an epoch 5 block with c3's votes MUST fail!
      (is (false? (:valid? (streamlet/verify-ancestor-quorum st (make-ancestor 5 c3))))))))
