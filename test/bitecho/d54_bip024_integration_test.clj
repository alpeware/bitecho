(ns bitecho.d54-bip024-integration-test
  "JVM integration tests for BIP-024:
   - Multi-segment `/directory/v1/<net>/<path...>` HTTP routing + `application/fressian` support
   - Fail-closed `/faucet/v1/claim` HTTP endpoint (rejecting forged `authenticator_verified: true`)
   - `state_machine/compute-checkpoint-state-digest` commitment to `:vaults` & `:validator-set-history`
   - `streamlet/verify-ancestor-quorum` historical catchup across 3+ consecutive validator rotations."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.circles.vault :as vault]
            [bitecho.config :as config]
            [bitecho.core.circle :as circle]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.faucet :as faucet]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [bitecho.main :as main]
            [bitecho.shell.http :as http]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [clojure.data.json :as json]
            [clojure.string :as str]
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

        (testing "Valid real CBOR + X.509 x5c hardware attestation over /faucet/v1/claim succeeds with 200 (F1)"
          (let [ch-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/challenge")))
                           (.GET)
                           (.build))
                ch-resp (.send client ch-req (HttpResponse$BodyHandlers/ofString))
                nonce (get-in (json/read-str (.body ch-resp)) ["challenge" "nonce"])
                att-bundle (faucet/build-test-hardware-attestation
                            {:hw-privkey (:private hw-kp)
                             :hw-pubkey (:spki-hex hw-kp)
                             :claimant-privkey (:private claimant)
                             :claimant-pubkey (:spki-hex claimant)
                             :cred-hash "cred-valid-1"
                             :nonce nonce
                             :network-uri "devnet.bitecho.org"})
                att (:attestation att-bundle)
                _ (swap! faucet-atom assoc :trusted-root-fingerprints #{(:trusted-root-fingerprint att-bundle)})
                valid-body (json/write-str {"nonce" nonce
                                            "credential_id_hash" (:credential-id-hash att-bundle)
                                            "claimant_pubkey" (:spki-hex claimant)
                                            "network_uri" "devnet.bitecho.org"
                                            "attestation" {"attestation_object_hex" (:attestation-object-hex att)
                                                           "client_data_hash_hex" (:client-data-hash-hex att)
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
            (is (true? (get cl-json "ok")))))

        (testing "F10: Blinded voucher /faucet/v1/claim issues blinded_voucher & publishes ONLY unlinkable nullifier blob"
          (let [hw-kp2 (gen-kp)
                claimant2 (gen-kp)
                blinding-secret "blind-secret-http-001"
                voucher-comm (faucet/blind-voucher-commitment blinding-secret (:spki-hex claimant2))
                ch-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/challenge")))
                           (.GET)
                           (.build))
                ch-resp (.send client ch-req (HttpResponse$BodyHandlers/ofString))
                nonce (get-in (json/read-str (.body ch-resp)) ["challenge" "nonce"])
                att-bundle (faucet/build-test-hardware-attestation
                            {:hw-privkey (:private hw-kp2)
                             :hw-pubkey (:spki-hex hw-kp2)
                             :voucher-commitment voucher-comm
                             :cred-hash "cred-blinded-1"
                             :nonce nonce
                             :network-uri "devnet.bitecho.org"})
                att (:attestation att-bundle)
                _ (swap! faucet-atom update :trusted-root-fingerprints (fnil conj #{}) (:trusted-root-fingerprint att-bundle))
                blind-body (json/write-str {"nonce" nonce
                                            "voucher_commitment" voucher-comm
                                            "network_uri" "devnet.bitecho.org"
                                            "attestation" {"attestation_object_hex" (:attestation-object-hex att)
                                                           "client_data_hash_hex" (:client-data-hash-hex att)
                                                           "hw_pubkey" (:hw-pubkey att)
                                                           "assertion_sig" (:assertion-sig att)}})
                cl-req (-> (HttpRequest/newBuilder (URI/create (str "http://127.0.0.1:" port "/faucet/v1/claim")))
                           (.header "Content-Type" "application/json")
                           (.POST (HttpRequest$BodyPublishers/ofString blind-body StandardCharsets/UTF_8))
                           (.build))
                cl-resp (.send client cl-req (HttpResponse$BodyHandlers/ofString))
                cl-json (json/read-str (.body cl-resp))
                nullifier-cid (get cl-json "nullifier_cid")
                stored-blob (:blob (data/get-blob (get-in @(:subnet-atom rt) [:data :blobs]) nullifier-cid))
                stored-text (when stored-blob (String. ^bytes (:blob/bytes stored-blob) StandardCharsets/UTF_8))]
            (is (= 200 (.statusCode cl-resp)))
            (is (true? (get cl-json "ok")))
            (is (= "blinded-voucher" (get cl-json "mode")))
            (is (map? (get cl-json "blinded_voucher")))
            (is (nil? (get cl-json "receipt_path")))
            (is (string? stored-text))
            (is (str/includes? stored-text ":hardware-nullifier"))
            (is (not (str/includes? stored-text ":claimant")))
            (is (not (str/includes? stored-text ":credential-id-hash")))
            (is (not (str/includes? stored-text (:spki-hex claimant2)))))))
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

(deftest test-v2-6node-vopr-partition-validator-rotation-and-vault-race
  (testing "V2 (§6 item 1): Deterministic 6-node VOPR partition/heal + in-band :rotate-validator-set + concurrent :vault-seq race + 7-bucket INV-C1"
    (let [;; 7 deterministic keypairs: 6 initial validators (n0..n5) + 1 replacement validator (n6)
          kps (vec (repeatedly 7 gen-kp))
          init-comm (subvec kps 0 6)
          rot-comm (conj (subvec kps 0 5) (nth kps 6))
          r1 (gen-kp)
          r2 (gen-kp)
          recv1 (gen-kp)
          recv2 (gen-kp)
          root-ms {:threshold 2 :pubkeys [(:spki-hex r1) (:spki-hex r2)]}
          net-uri "devnet.bitecho.org"
          gen-cid (apply str (repeat 64 "a"))
          p-src (vault/canonical-multisig-treasury-puzzle-source 2 [(:spki-hex r1) (:spki-hex r2)])
          p-hash (puzzle/puzzle-cid p-src)
          peers-map (into {} (map (fn [kp] [(:spki-hex kp) (:public kp)]) kps))
          init-vals (vec (sort (map :spki-hex init-comm)))
          rot-vals (vec (sort (map :spki-hex rot-comm)))
          kp-by-hex (into {} (map (fn [kp] [(:spki-hex kp) kp]) kps))
          ;; Initialize 6 validator states with identical genesis custody supply = 100,000 ECHO
          init-node (fn [kp]
                      (-> (sm/init-state kp (config/make-config
                                             {:network-uri net-uri
                                              :network-genesis-cid gen-cid
                                              :validators init-vals
                                              :root-owner-multisig root-ms
                                              :validator-activation-lead-epochs 6
                                              :economy-enabled? true}))
                          (assoc :network-uri net-uri
                                 :network-genesis-cid gen-cid
                                 :validators init-vals
                                 :root-owner-multisig root-ms
                                 :peers-map peers-map
                                 :genesis-custody-supply 100000
                                 :root-unallocated 100000
                                 :total-burned 0
                                 :sunset-custody-burned 0
                                 :validator-set-history {0 {:committee init-vals :quorum-threshold 4 :descriptor-cid gen-cid}})))
          nodes0 (into {} (map (fn [kp] [(:spki-hex kp) (init-node kp)]) init-comm))
          ;; Helper to finalize one Streamlet epoch on a given active partition of nodes
          finalize-epoch!
          (fn [nodes-map active-pks ep parent-hash receipts]
            (let [ref-st (get nodes-map (first active-pks))
                  hist-entry (streamlet/committee-at-epoch (:validator-set-history ref-st) ep)
                  comm (vec (sort (or (:committee hist-entry) (:validators ref-st))))
                  leader (nth comm (mod ep (count comm)))
                  leader-kp (get kp-by-hex leader)
                  blk (streamlet/sign-block (streamlet/->Block ep parent-hash receipts leader) (:private leader-kp))
                  b-hash (streamlet/hash-block blk)
                  ;; Deliver propose to active partition and collect 4-of-6 votes
                  after-propose (reduce (fn [m pk]
                                          (let [st (get m pk)
                                                st' (assoc st :epoch ep)
                                                res (sm/handle-event st' {:type :receive-propose :sender leader :block blk})]
                                            (assoc m pk (:state res))))
                                        nodes-map
                                        active-pks)
                  votes (keep (fn [pk]
                                (when (contains? (set comm) pk)
                                  (let [vkp (get kp-by-hex pk)
                                        sig (basalt/bytes->hex (crypto/sign (:private vkp) (fressian/utf8->bytes b-hash)))]
                                    [pk (streamlet/->Vote b-hash ep sig)])))
                              active-pks)
                  after-votes (reduce (fn [m pk]
                                        (reduce (fn [m2 [vpk vote]]
                                                  (let [res (sm/handle-event (get m2 pk) {:type :receive-vote :sender vpk :vote vote})]
                                                    (assoc m2 pk (:state res))))
                                                m
                                                votes))
                                      after-propose
                                      active-pks)]
              {:nodes after-votes :block blk :block-hash b-hash :votes (into {} votes)}))
          ;; Partition: 4-node majority (init-vals[0..3]) active; 2-node minority (init-vals[4..5]) isolated
          majority-pks (subvec init-vals 0 4)
          minority-pk (nth init-vals 4)
          ;; Epoch 1: Create persistent vault with 100,000 ECHO (Root-signed & funded from :root-unallocated)
          r-create-base {:type :vault-create
                         :receipt-id "v-create-1"
                         :vault-id "vault:devnet.bitecho.org/root"
                         :entity-uri "devnet.bitecho.org/root"
                         :custody-bucket :bootstrap
                         :puzzle-hash p-hash
                         :balance 100000
                         :created-epoch 0
                         :funding-source :root-unallocated}
          r-create-tuple (vault/vault-create-signing-tuple
                          (assoc r-create-base :network-uri net-uri :network-genesis-cid gen-cid))
          r-create (assoc r-create-base
                          :root-signatures {(:spki-hex r1) (basalt/bytes->hex (crypto/sign-canonical (:private r1) r-create-tuple))
                                            (:spki-hex r2) (basalt/bytes->hex (crypto/sign-canonical (:private r2) r-create-tuple))})
          ;; Epoch 2: Concurrent :vault-seq 1 spend race (2 conflicting spends in same block!)
          out-a [{:type :release :receiver (:spki-hex recv1) :amount 10000}
                 {:type :relock :amount 90000 :next-puzzle-hash p-hash}]
          dig-a (vault/treasury-spend-digest {:network-uri net-uri :network-genesis-cid gen-cid
                                              :vault-id "vault:devnet.bitecho.org/root" :puzzle-hash p-hash
                                              :vault-seq 1 :outputs out-a :next-puzzle-hash p-hash})
          r-spend-a {:type :vault-spend
                     :receipt-id "v-spend-a"
                     :vault-id "vault:devnet.bitecho.org/root"
                     :vault-seq 1
                     :puzzle-source p-src
                     :solution {:outputs out-a :next-puzzle-hash p-hash
                                :signatures {(:spki-hex r1) (basalt/bytes->hex (crypto/sign (:private r1) dig-a))
                                             (:spki-hex r2) (basalt/bytes->hex (crypto/sign (:private r2) dig-a))}}}
          out-b [{:type :release :receiver (:spki-hex recv2) :amount 20000}
                 {:type :relock :amount 80000 :next-puzzle-hash p-hash}]
          dig-b (vault/treasury-spend-digest {:network-uri net-uri :network-genesis-cid gen-cid
                                              :vault-id "vault:devnet.bitecho.org/root" :puzzle-hash p-hash
                                              :vault-seq 1 :outputs out-b :next-puzzle-hash p-hash})
          r-spend-b {:type :vault-spend
                     :receipt-id "v-spend-b"
                     :vault-id "vault:devnet.bitecho.org/root"
                     :vault-seq 1
                     :puzzle-source p-src
                     :solution {:outputs out-b :next-puzzle-hash p-hash
                                :signatures {(:spki-hex r1) (basalt/bytes->hex (crypto/sign (:private r1) dig-b))
                                             (:spki-hex r2) (basalt/bytes->hex (crypto/sign (:private r2) dig-b))}}}
          ;; Epoch 3: In-band :rotate-validator-set effective at epoch 9 (satisfying default 6-epoch activation lead: 3 + 6 = 9)
          rot-desc (circle/create-validator-set-descriptor
                    {:network-uri net-uri
                     :network-genesis-cid gen-cid
                     :version 1
                     :not-before-epoch 9
                     :epoch-finalized 3
                     :epoch-effective 9
                     :quorum-threshold 4
                     :delegated-operator-circle "devnet.bitecho.org/root/protocol"
                     :consent-round-cid (apply str (repeat 64 "2"))
                     :committee (mapv (fn [pk] {:pubkey pk :role :core-validator :operator-circle "devnet.bitecho.org/root/protocol"}) rot-vals)
                     :retention-policy {:max-entries 128 :max-bytes 1048576 :rotate-every-entries 32 :ttl-epochs 52560}
                     :storage-accounting {:bytes-at-rest 2048 :cache-incentive :free-self-hosted :payer-pubkey (:spki-hex r1) :fee-ech 0}}
                    [{:pubkey (:spki-hex r1) :privkey (:private r1)}
                     {:pubkey (:spki-hex r2) :privkey (:private r2)}])
          r-rotate {:type :rotate-validator-set :receipt-id "v-rot-1" :descriptor rot-desc}
          ;; Run majority epochs 1, 2, 3 (leaders 1,2,3 all in majority-pks -> finalizes ep 1 & 2)
          ;; Skip isolated minority leader slots 4 & 5, then run consecutive majority epochs 6, 7, 8 (finalizes ep 3 & records rotation at ep 9!)
          e1 (finalize-epoch! nodes0 majority-pks 1 "genesis" [r-create])
          e2 (finalize-epoch! (:nodes e1) majority-pks 2 (:block-hash e1) [r-spend-a r-spend-b])
          e3 (finalize-epoch! (:nodes e2) majority-pks 3 (:block-hash e2) [r-rotate])
          e6 (finalize-epoch! (:nodes e3) majority-pks 6 (:block-hash e3) [])
          e7 (finalize-epoch! (:nodes e6) majority-pks 7 (:block-hash e6) [])
          e8 (finalize-epoch! (:nodes e7) majority-pks 8 (:block-hash e7) [])
          ;; Also produce post-rotation epoch 9 block signed by 4-of-6 of the rotated committee (rot-vals)
          e9 (finalize-epoch! (:nodes e8) (subvec rot-vals 0 4) 9 (:block-hash e8) [])
          maj-st (get (:nodes e8) (first majority-pks))
          ;; Verify vault race: exactly 1 spend committed (90,000 relocked, vault-seq = 2), 2nd rejected with counted :diagnose
          v-final (get-in maj-st [:vaults "vault:devnet.bitecho.org/root"])
          ;; Verify 7-bucket INV-C1 conservation on finalized majority state
          cons-res (vault/verify-7-bucket-conservation maj-st)
          ;; Partition heal: lagging minority follower catches up using epoch-indexed :validator-set-history
          healed-minority (assoc (get (:nodes e8) minority-pk)
                                 :epoch 9
                                 :validator-set-history (:validator-set-history maj-st))]
      (is (= 2 (:vault-seq v-final)))
      (is (= 90000 (:balance v-final)))
      (is (= 1 (get-in maj-st [:diagnostics :vault-seq-mismatch])))
      (is (:ok? cons-res) (str "INV-C1 conservation must hold after concurrent vault race: " cons-res))
      (is (= (set rot-vals) (set (get-in maj-st [:validator-set-history 9 :committee]))))
      ;; Lagging minority follower verifies pre-rotation (epoch 2) AND post-rotation (epoch 9) ancestors!
      (is (:valid? (streamlet/verify-ancestor-quorum healed-minority {:block (:block e2) :votes (:votes e2)})))
      (is (:valid? (streamlet/verify-ancestor-quorum healed-minority {:block (:block e9) :votes (:votes e9)})))
      ;; F11: :rotate-validator-set mirrors to "root/validators" with epoch-anchored :supply-merkle-root
      (is (= "root/validators" (get-in maj-st [:validator-set-mirror :pointer/path])))
      (is (string? (get-in maj-st [:validator-set-mirror :supply-merkle-root]))))))

(deftest test-axiom-f3-f4-f5-governance-cold-root-startup-and-reconfigure-gate
  (testing "F3: State-machine executes :register-entity-descriptor, :register-advisory-twin, :initiate-recovery, :cancel-recovery, and :dissolve-circle"
    (let [v1 (gen-kp)
          r1 (gen-kp)
          r2 (gen-kp)
          g1 (gen-kp)
          twin (gen-kp)
          net "devnet.bitecho.org"
          gen-cid (apply str (repeat 64 "a"))
          p-cid (apply str (repeat 64 "1"))
          c-cid (apply str (repeat 64 "2"))
          root-ms {:threshold 2 :pubkeys [(:spki-hex r1) (:spki-hex r2)]}
          peers {(:spki-hex v1) (:public v1)}
          st0 (-> (sm/init-state v1 (config/make-config {:network-uri net :network-genesis-cid gen-cid
                                                         :validators [(:spki-hex v1)] :root-owner-multisig root-ms}))
                  (assoc :network-uri net :network-genesis-cid gen-cid :validators [(:spki-hex v1)]
                         :root-owner-multisig root-ms :peers-map peers))
          root-desc (circle/create-entity-descriptor
                     {:network-uri net :network-genesis-cid gen-cid :entity-kind :circle :visibility :public
                      :path "root" :owner-multisig root-ms :purpose-cid p-cid :consent-round-cid c-cid
                      :policy {:recovery-policy {:guardians [(:spki-hex g1)] :threshold 1 :timelock-epochs 168}}
                      :retention-policy {:max-entries 256 :max-bytes 4194304 :rotate-every-entries 64 :ttl-epochs 26280}
                      :storage-accounting {:bytes-at-rest 2048 :cache-incentive :free-self-hosted :payer-pubkey (:spki-hex r1) :fee-ech 0}
                      :issued-epoch 1 :expires-epoch 27280}
                     [{:pubkey (:spki-hex r1) :privkey (:private r1)}
                      {:pubkey (:spki-hex r2) :privkey (:private r2)}])
          rec-tuple ["bitecho-recovery-v1" (:uri root-desc) {:threshold 1 :pubkeys [(:spki-hex g1)]} 1]
          g-sig (basalt/bytes->hex (crypto/sign-canonical (:private g1) rec-tuple))
          cancel-tuple (circle/cancel-recovery-signing-tuple root-desc {:initiated-epoch 1})
          r1-csig (basalt/bytes->hex (crypto/sign-canonical (:private r1) cancel-tuple))
          r2-csig (basalt/bytes->hex (crypto/sign-canonical (:private r2) cancel-tuple))
          ;; Drive 3-chain (ep 1, 2, 3) to finalize ep 1 governance receipts in state_machine!
          run-ep (fn [st ep parent rcpts]
                   (let [blk (streamlet/sign-block (streamlet/->Block ep parent rcpts (:spki-hex v1)) (:private v1))
                         bh (streamlet/hash-block blk)
                         st1 (:state (sm/handle-event (assoc st :epoch ep) {:type :receive-propose :sender (:spki-hex v1) :block blk}))
                         sig (basalt/bytes->hex (crypto/sign (:private v1) (fressian/utf8->bytes bh)))
                         st2 (:state (sm/handle-event st1 {:type :receive-vote :sender (:spki-hex v1) :vote (streamlet/->Vote bh ep sig)}))]
                     [st2 bh]))
          [s1 h1] (run-ep st0 1 "genesis"
                          [{:type :register-entity-descriptor :receipt-id "gov-1" :descriptor root-desc}
                           {:type :register-advisory-twin :receipt-id "gov-2" :pubkey (:spki-hex twin)}
                           {:type :initiate-recovery :receipt-id "gov-3" :path "root"
                            :new-owner-multisig {:threshold 1 :pubkeys [(:spki-hex g1)]}
                            :guardian-signatures {(:spki-hex g1) g-sig}}
                           {:type :cancel-recovery :receipt-id "gov-4" :path "root"
                            :owner-signatures {(:spki-hex r1) r1-csig (:spki-hex r2) r2-csig}}])
          [s2 h2] (run-ep s1 2 h1 [{:type :dissolve-circle :receipt-id "gov-5" :circle-path "root"
                                    :consent-round {:proposal-cid c-cid
                                                    :lead-link-pubkey (:spki-hex r1)
                                                    :ballots {(:spki-hex r1) (circle/sign-consent-ballot (:private r1) (:spki-hex r1) c-cid :consent)
                                                              (:spki-hex r2) (circle/sign-consent-ballot (:private r2) (:spki-hex r2) c-cid :consent)}
                                                    :quorum-size 2}}])
          [s3 h3] (run-ep s2 3 h2 [])
          [s4 _] (run-ep s3 4 h3 [])]
      (is (some? (get-in s4 [:entity-descriptors "root"])))
      (is (= :dissolved (get-in s4 [:entity-descriptors "root" :status])))
      (is (circle/advisory-twin? (:advisory-twin-pubkeys s4) (:spki-hex twin)))
      (is (= :cancelled (get-in s4 [:pending-recoveries "root" :status])))))

  (testing "F4: main/apply-startup-cold-root-recovery! loads & verifies bundle by CID from disk and fails closed on mismatch"
    (let [tmp-dir (.toFile (Files/createTempDirectory "bitecho-f4-rec-" (into-array FileAttribute [])))
          blobs-dir (doto (java.io.File. tmp-dir "blobs") (.mkdirs))
          r1 (gen-kp)
          r2 (gen-kp)
          v1 (gen-kp)
          root-ms {:threshold 2 :pubkeys [(:spki-hex r1) (:spki-hex r2)]}
          net "devnet.bitecho.org"
          gen-cid (apply str (repeat 64 "a"))
          bundle (circle/create-cold-root-recovery-bundle
                  {:network-uri net :network-genesis-cid gen-cid :recovery-seq 25
                   :last-known-finalized-block-hash gen-cid
                   :committee [{:pubkey (:spki-hex v1) :role :core-validator}]
                   :quorum-threshold 1}
                  [{:pubkey (:spki-hex r1) :privkey (:private r1)}
                   {:pubkey (:spki-hex r2) :privkey (:private r2)}])
          raw-bytes (fressian/encode-canonical bundle)
          cid (basalt/bytes->hex (crypto/sha256 raw-bytes))
          _ (Files/write (.toPath (java.io.File. blobs-dir cid)) ^bytes raw-bytes (into-array java.nio.file.OpenOption []))
          sa (atom {:last-finalized-epoch 10 :validator-set-history {} :diagnostics {}})
          cfg {:root-owner-multisig root-ms :network-uri net :network-genesis-cid gen-cid}
          bad-res (main/apply-startup-cold-root-recovery! sa (.getAbsolutePath tmp-dir) (apply str (repeat 64 "f")) cfg)
          ok-res (main/apply-startup-cold-root-recovery! sa (.getAbsolutePath tmp-dir) cid cfg)]
      (is (false? (:ok? bad-res)))
      (is (= :cold-root-recovery-bundle-missing (:error bad-res)))
      (is (:ok? ok-res))
      (is (= 1 (get-in @sa [:diagnostics :cold-root-recovery-activated])))
      (is (= [(:spki-hex v1)] (get-in @sa [:validator-set-history 25 :committee])))))

  (testing "F5: Single-key :reconfigure-membership is rejected when :root-owner-multisig is configured, requiring Root quorum"
    (let [treasury (gen-kp)
          r1 (gen-kp)
          r2 (gen-kp)
          v1 (gen-kp)
          root-ms {:threshold 2 :pubkeys [(:spki-hex r1) (:spki-hex r2)]}
          st {:treasury-pubkey (:spki-hex treasury) :root-owner-multisig root-ms}
          single-key-sig (sm/sign-reconfigure-membership (:private treasury) "rc-1" 10 [(:spki-hex v1)] {(:spki-hex v1) "127.0.0.1:5000"})
          rcpt-single {:receipt-id "rc-1" :effective-epoch 10 :validators [(:spki-hex v1)]
                       :mesh-nodes {(:spki-hex v1) "127.0.0.1:5000"} :signature single-key-sig}
          msg-bs (sm/reconfigure-membership-signing-bytes "rc-1" 10 [(:spki-hex v1)] {(:spki-hex v1) "127.0.0.1:5000"})
          rcpt-quorum (assoc rcpt-single :root-signatures
                             {(:spki-hex r1) (basalt/bytes->hex (crypto/sign (:private r1) msg-bs))
                              (:spki-hex r2) (basalt/bytes->hex (crypto/sign (:private r2) msg-bs))})]
      (is (false? (sm/verify-reconfigure-membership? st rcpt-single)))
      (is (true? (sm/verify-reconfigure-membership? st rcpt-quorum))))))
