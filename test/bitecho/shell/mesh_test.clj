(ns bitecho.shell.mesh-test
  "Unit and generative tests for Bitecho mesh, node identity, and transport boundary."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.mesh :as mesh]
            [bitecho.shell.persistence :as persistence]
            [bitecho.sieve.core :as sieve]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.api :as api]
            [datachannel.dtls :as dtls]
            [taoensso.nippy :as nippy])
  (:import [java.io File]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

;; ---------------------------------------------------------------------------
;; Generators
;; ---------------------------------------------------------------------------

(def gen-hex-byte
  "Generates a 2-character uppercase hex byte string."
  (gen/fmap (fn [b] (format "%02X" (bit-and b 0xFF))) gen/byte))

(def gen-fingerprint-str
  "Generates a valid 32-byte colon-separated hex fingerprint string."
  (gen/fmap (fn [hex-pairs] (str/join ":" hex-pairs))
            (gen/vector gen-hex-byte 32)))

(def gen-raw-fingerprint
  "Generates a raw fingerprint string with random prefix, casing, and whitespace padding."
  (gen/let [fp gen-fingerprint-str
            prefix (gen/elements ["" "SHA-256:" "sha-256:" "Sha-256:"])
            case-fn (gen/elements [identity str/lower-case str/upper-case])
            pad-left (gen/elements ["" " " "  "])
            pad-right (gen/elements ["" " " "  "])]
    (str pad-left prefix (case-fn fp) pad-right)))

(def gen-cmd-type
  "Generates supported outbound network command types."
  (gen/elements [:send-push-view
                 :send-summary
                 :send-pull-request
                 :send-gossip
                 :send-sieve-echo
                 :send-contagion-ready
                 :send-subscribe
                 :send-propose
                 :send-vote]))

;; ---------------------------------------------------------------------------
;; Generative Properties
;; ---------------------------------------------------------------------------

(defspec ^{:doc "Verifies fingerprint normalization invariants and idempotence."}
  test-prop-normalize-fingerprint
  100
  (prop/for-all [raw gen-raw-fingerprint]
                (let [norm (identity/normalize-fingerprint raw)]
                  (and (string? norm)
                       (= 95 (count norm))
                       (re-matches #"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$" norm)
                       (= (identity/normalize-fingerprint norm) norm)))))

(defspec ^{:doc "Verifies deterministic ICE credential generation format and idempotence."}
  test-prop-deterministic-ice-creds
  100
  (prop/for-all [node-id (gen/elements [:node-1 :node-2 "validator-a" "node-b"])
                 fp (gen/one-of [(gen/return nil) gen-fingerprint-str])]
                (let [creds1 (if fp
                               (identity/deterministic-ice-creds node-id fp)
                               (identity/deterministic-ice-creds node-id))
                      creds2 (if fp
                               (identity/deterministic-ice-creds node-id fp)
                               (identity/deterministic-ice-creds node-id))]
                  (and (= creds1 creds2)
                       (string? (:ufrag creds1))
                       (string? (:pwd creds1))
                       (= 8 (count (:ufrag creds1)))
                       (= 24 (count (:pwd creds1)))
                       (re-matches #"^[0-9a-f]{8}$" (:ufrag creds1))
                       (re-matches #"^[0-9a-f]{24}$" (:pwd creds1))))))

(defspec ^{:doc "Verifies command to network event translation invariants."}
  test-prop-command-to-network-event
  100
  (prop/for-all [cmd-type gen-cmd-type
                 sender-hex (gen/fmap (fn [_] (basalt/bytes->hex (:public (crypto/generate-keypair)))) gen/nat)
                 payload-val gen/string-alphanumeric]
                (let [cmd {:type cmd-type
                           :targets ["target-hex-1" "target-hex-2"]
                           :target "target-hex-1"
                           :payload payload-val}
                      evt (mesh/command->network-event cmd sender-hex)
                      expected-type (keyword (str "receive-" (subs (name cmd-type) 5)))]
                  (and (= (:type evt) expected-type)
                       (= (:sender evt) sender-hex)
                       (= (:payload evt) payload-val)
                       (nil? (:targets evt))
                       (nil? (:target evt))))))

(def gen-byte-array
  "Generates non-empty primitive byte arrays."
  (gen/fmap (fn [bytes-vec] (byte-array (map byte bytes-vec)))
            (gen/not-empty (gen/vector gen/byte 1 32))))

(def gen-sieve-gossip-event
  "Generates real Sieve gossip messages."
  (gen/let [payload gen-byte-array
            burn-amount (gen/elements [nil 100 250])
            kp (gen/fmap (fn [_] (crypto/generate-keypair)) gen/nat)]
    (let [sieve-msg (if burn-amount
                      (sieve/wrap-message payload (:private kp) (:public kp) burn-amount)
                      (sieve/wrap-message payload (:private kp) (:public kp)))]
      {:type :receive-gossip
       :message sieve-msg})))

(def gen-nested-bytes-event
  "Generates events containing nested maps, vectors, and sets of byte arrays."
  (gen/let [ba gen-byte-array
            sieve-event gen-sieve-gossip-event]
    (assoc sieve-event
           :extra {:raw-bytes ba
                   :vec-bytes [ba]
                   :set-bytes #{ba}})))

(def gen-allowed-agent-event
  "Generates realistic allowed agent events including byte[] payloads, Sieve messages, and nested structures."
  (gen/one-of [gen-sieve-gossip-event
               gen-nested-bytes-event
               (gen/elements [{:type :receive-gossip :topic "discovery" :data "alpha"}
                              {:type :receive-summary :epoch 1 :summary "digest-1"}
                              {:type :receive-pull-request :missing-ids ["msg-1" "msg-2"]}
                              {:type :register-home-set :client-id "client-1" :home-set ["h1" "h2"]}
                              {:type :receive-offer-header :caller "caller-hex" :offer-id "off-1"}])]))

(def gen-disallowed-agent-event
  "Generates disallowed agent events."
  (gen/elements [{:type :receive-propose :block {:epoch 1}}
                 {:type :receive-vote :vote {:epoch 1}}
                 {:type :tick}
                 {:type :custom-injection :data "malicious"}]))

(defspec ^{:doc "Verifies authenticated agent envelope signing, verification, and fail-closed security properties across nippy round-trips."}
  test-prop-authenticated-agent-envelope
  50
  (prop/for-all [event gen-allowed-agent-event
                 disallowed-evt gen-disallowed-agent-event
                 tampered-key gen/string-alphanumeric]
                (let [kp (crypto/generate-keypair)
                      agent-pub (basalt/bytes->hex (:public kp))
                      agent-priv (:private kp)
                      other-kp (crypto/generate-keypair)
                      env (mesh/wrap-agent-event event agent-pub agent-priv)
                      frozen-bytes (nippy/freeze env)
                      thawed-env (nippy/thaw frozen-bytes)
                      unwrapped (mesh/unwrap-authenticated-agent-event env)
                      unwrapped-frozen (mesh/unwrap-authenticated-agent-event frozen-bytes)
                      unwrapped-thawed (mesh/unwrap-authenticated-agent-event thawed-env)
                      tampered-env (assoc-in env [:event :tampered] tampered-key)
                      wrong-sig-env (assoc env :signature (basalt/bytes->hex (crypto/sign (:private other-kp) (mesh/agent-event-signing-bytes agent-pub (:event env)))))
                      disallowed-env (mesh/wrap-agent-event disallowed-evt agent-pub agent-priv)
                      mutated-payload-env (when-let [payload (get-in env [:event :message :payload])]
                                            (when (bytes? payload)
                                              (let [cloned (byte-array payload)]
                                                (aset cloned 0 (unchecked-byte (bit-xor (aget cloned 0) 1)))
                                                (assoc-in (nippy/thaw (nippy/freeze env)) [:event :message :payload] cloned))))]
                  (and (= (:type unwrapped) (:type event))
                       (= (:sender unwrapped) agent-pub)
                       (= (vec (:sender-pubkey-bytes unwrapped)) (vec (:public kp)))
                       (some? unwrapped-frozen)
                       (some? unwrapped-thawed)
                       (= (:type unwrapped-frozen) (:type event))
                       (= (:type unwrapped-thawed) (:type event))
                       (= (:sender unwrapped-frozen) agent-pub)
                       (= (:sender unwrapped-thawed) agent-pub)
                       (if-let [orig-pl (get-in event [:message :payload])]
                         (and (bytes? (get-in unwrapped-frozen [:message :payload]))
                              (bytes? (get-in unwrapped-thawed [:message :payload]))
                              (java.util.Arrays/equals ^bytes orig-pl ^bytes (get-in unwrapped-frozen [:message :payload]))
                              (java.util.Arrays/equals ^bytes orig-pl ^bytes (get-in unwrapped-thawed [:message :payload])))
                         true)
                       (if mutated-payload-env
                         (nil? (mesh/unwrap-authenticated-agent-event mutated-payload-env))
                         true)
                       (nil? (mesh/unwrap-authenticated-agent-event tampered-env))
                       (nil? (mesh/unwrap-authenticated-agent-event wrong-sig-env))
                       (nil? (mesh/unwrap-authenticated-agent-event disallowed-env))
                       (nil? (mesh/unwrap-authenticated-agent-event (dissoc env :signature)))
                       (nil? (mesh/unwrap-authenticated-agent-event (dissoc env :agent-pubkey)))
                       (nil? (mesh/unwrap-authenticated-agent-event nil))))))

;; ---------------------------------------------------------------------------
;; Unit Tests
;; ---------------------------------------------------------------------------

(deftest test-normalize-fingerprint-unit
  (testing "valid uppercase colon-separated fingerprint"
    (let [fp "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"]
      (is (= fp (identity/normalize-fingerprint fp)))
      (is (= fp (identity/normalize-fingerprint (str "sha-256:" fp))))
      (is (= fp (identity/normalize-fingerprint (str "  " fp "  "))))))
  (testing "invalid fingerprints throw ExceptionInfo"
    (is (thrown? clojure.lang.ExceptionInfo (identity/normalize-fingerprint nil)))
    (is (thrown? clojure.lang.ExceptionInfo (identity/normalize-fingerprint "")))
    (is (thrown? clojure.lang.ExceptionInfo (identity/normalize-fingerprint "not-a-fingerprint")))
    (is (thrown? clojure.lang.ExceptionInfo (identity/normalize-fingerprint "11:22:33")))))

(deftest test-verify-peer-fingerprint
  (let [fp1 "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
        fp2 "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"]
    (testing "matching fingerprints return true"
      (is (true? (identity/verify-peer-fingerprint? fp1 fp1)))
      (is (true? (identity/verify-peer-fingerprint? (str "SHA-256:" (str/lower-case fp1)) fp1))))
    (testing "mismatch returns false"
      (is (false? (identity/verify-peer-fingerprint? fp1 fp2))))
    (testing "nil/blank/invalid returns false without throwing"
      (is (false? (identity/verify-peer-fingerprint? nil fp1)))
      (is (false? (identity/verify-peer-fingerprint? fp1 nil)))
      (is (false? (identity/verify-peer-fingerprint? "invalid" fp1))))))

(deftest test-pem-roundtrip
  (testing "PEM encode/decode round-trip with DTLS cert and key"
    (let [cert-data (dtls/generate-cert)
          cert (:cert cert-data)
          key (:key cert-data)
          cert-pem (identity/encode-cert-pem cert)
          key-pem (identity/encode-private-key-pem key)
          parsed-cert (identity/parse-cert-pem cert-pem)
          parsed-key (identity/parse-private-key-pem key-pem)]
      (is (string? cert-pem))
      (is (str/includes? cert-pem "-----BEGIN CERTIFICATE-----"))
      (is (string? key-pem))
      (is (str/includes? key-pem "-----BEGIN PRIVATE KEY-----"))
      (is (some? parsed-cert))
      (is (some? parsed-key))
      (is (= (vec (.getEncoded cert)) (vec (.getEncoded parsed-cert))))
      (is (= (vec (.getEncoded key)) (vec (.getEncoded parsed-key)))))))

(deftest test-load-or-create-node-identity
  (testing "persistence lifecycle of node identity"
    (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-test-id-" (into-array FileAttribute [])))
          state-dir (.getAbsolutePath temp-dir)
          id-file (io/file state-dir "identity" "node-identity.edn")]
      (try
        (is (not (.exists id-file)))
        (let [id1 (identity/load-or-create-node-identity! state-dir :node-1)]
          (is (.exists id-file))
          (is (= :node-1 (:node-id id1)))
          (is (string? (:pubkey-hex id1)))
          (is (string? (:privkey-hex id1)))
          (is (= 88 (count (:pubkey-hex id1))))
          (is (bytes? (get-in id1 [:keypair :public])))
          (is (bytes? (get-in id1 [:keypair :private])))
          (is (re-matches #"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$" (:fingerprint id1)))
          (is (some? (:ice-creds id1)))
          (is (some? (get-in id1 [:cert-data :cert])))
          (is (some? (get-in id1 [:cert-data :key])))

          ;; Second call loads exact same identity
          (let [id2 (identity/load-or-create-node-identity! state-dir :node-1)]
            (is (= (:pubkey-hex id1) (:pubkey-hex id2)))
            (is (= (:privkey-hex id1) (:privkey-hex id2)))
            (is (= (:fingerprint id1) (:fingerprint id2)))
            (is (= (:ice-creds id1) (:ice-creds id2)))))
        (finally
          (doseq [f (reverse (file-seq temp-dir))]
            (.delete ^File f)))))))

(deftest test-ice-random-credentials-generation-and-rotation
  (testing "HIGH 1: random ICE credential generation and automatic rotation of legacy deterministic credentials"
    (let [rnd1 (identity/generate-random-ice-creds)
          rnd2 (identity/generate-random-ice-creds)
          det (identity/deterministic-ice-creds :node-1)]
      ;; 1. Random generator shapes and entropy
      (is (= 8 (count (:ufrag rnd1))))
      (is (= 24 (count (:pwd rnd1))))
      (is (re-matches #"^[0-9a-f]{8}$" (:ufrag rnd1)))
      (is (re-matches #"^[0-9a-f]{24}$" (:pwd rnd1)))
      (is (not= (:pwd rnd1) (:pwd rnd2)) "Consecutive random ICE creds must be distinct")
      (is (not= (:pwd rnd1) (:pwd det)) "Random ICE creds must not equal deterministic creds")

      ;; 2. New identity gets random ICE creds and persists across reload
      (let [temp-dir1 (.toFile (Files/createTempDirectory "bitecho-test-rnd-id1-" (into-array FileAttribute [])))
            temp-dir2 (.toFile (Files/createTempDirectory "bitecho-test-rnd-id2-" (into-array FileAttribute [])))
            sd1 (.getAbsolutePath temp-dir1)
            sd2 (.getAbsolutePath temp-dir2)]
        (try
          (let [id-fresh1 (identity/load-or-create-node-identity! sd1 :node-rnd-1)
                id-fresh2 (identity/load-or-create-node-identity! sd2 :node-rnd-2)]
            (is (= 24 (count (get-in id-fresh1 [:ice-creds :pwd]))))
            (is (not= (get-in id-fresh1 [:ice-creds :pwd]) (get-in id-fresh2 [:ice-creds :pwd])))
            ;; Reload same dir
            (let [reloaded (identity/load-or-create-node-identity! sd1 :node-rnd-1)]
              (is (= (:ice-creds id-fresh1) (:ice-creds reloaded)))))

          ;; 3. Legacy deterministic credentials upgrade/rotate on read
          (let [legacy-kp (identity/generate-ed25519-keypair-map)
                cert-data (dtls/generate-cert)
                fp (identity/normalize-fingerprint (:fingerprint cert-data))
                legacy-creds (identity/deterministic-ice-creds :node-legacy fp)
                cert-pem (identity/encode-cert-pem (:cert cert-data))
                key-pem (identity/encode-private-key-pem (:key cert-data))
                legacy-file (io/file sd1 "identity" "node-identity.edn")
                legacy-data {:node-id :node-legacy
                             :pubkey-hex (:pubkey-hex legacy-kp)
                             :privkey-hex (:privkey-hex legacy-kp)
                             :cert-pem cert-pem
                             :key-pem key-pem
                             :fingerprint fp
                             :ice-creds legacy-creds
                             :ice-ufrag (:ufrag legacy-creds)
                             :ice-pwd (:pwd legacy-creds)}]
            (spit legacy-file (pr-str legacy-data))
            ;; Call load-or-create-node-identity! on state-dir containing legacy identity
            (let [upgraded (identity/load-or-create-node-identity! sd1 :node-legacy)
                  upgraded-creds (:ice-creds upgraded)]
              (is (not= (:pwd legacy-creds) (:pwd upgraded-creds))
                  "Legacy deterministic ICE password must be automatically rotated")
              (is (= 24 (count (:pwd upgraded-creds))))
              ;; Verify on-disk file was updated
              (let [on-disk (edn/read-string (slurp legacy-file))]
                (is (= (:pwd upgraded-creds) (get-in on-disk [:ice-creds :pwd])))
                (is (= (:pwd upgraded-creds) (:ice-pwd on-disk))))
              ;; Second read retains the newly rotated random credentials
              (let [reloaded (identity/load-or-create-node-identity! sd1 :node-legacy)]
                (is (= upgraded-creds (:ice-creds reloaded))))))
          (finally
            (doseq [f (reverse (file-seq temp-dir1))] (.delete ^File f))
            (doseq [f (reverse (file-seq temp-dir2))] (.delete ^File f))))))))

(deftest test-generate-ed25519-keypair-map
  (testing "generate-ed25519-keypair-map creates verifiable keypair"
    (let [kp-map (identity/generate-ed25519-keypair-map)
          pub-bytes (basalt/hex->bytes (:pubkey-hex kp-map))
          priv-bytes (basalt/hex->bytes (:privkey-hex kp-map))
          msg (.getBytes "bitecho-test-message")
          sig (crypto/sign priv-bytes msg)]
      (is (= 88 (count (:pubkey-hex kp-map))))
      (is (true? (crypto/verify pub-bytes msg sig))))))

(deftest test-extract-command-target-hexes
  (testing "extracts target hexes from commands"
    (let [pub-bytes (:public (crypto/generate-keypair))
          pub-hex (basalt/bytes->hex pub-bytes)]
      (is (= ["hex-a" "hex-b"]
             (mesh/extract-command-target-hexes {:type :send-gossip :targets ["hex-a" "hex-b"]})))
      (is (= ["hex-a"]
             (mesh/extract-command-target-hexes {:type :send-gossip :target "hex-a"})))
      (is (= [pub-hex]
             (mesh/extract-command-target-hexes {:type :send-push-view :targets [{:pubkey pub-bytes}]})))
      (is (= ["hex-c"]
             (mesh/extract-command-target-hexes {:type :send-push-view :targets [{:pubkey "hex-c"}]})))
      (is (= []
             (mesh/extract-command-target-hexes {:type :send-gossip}))))))

(deftest test-build-initial-node-state
  (testing "build-initial-node-state shapes treasury, custody, validators, and mesh-nodes"
    (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-test-init-state-" (into-array FileAttribute [])))
          state-dir (.getAbsolutePath temp-dir)
          id (identity/load-or-create-node-identity! state-dir :node-1)
          treasury-kp (identity/generate-ed25519-keypair-map)
          cfg {:node/id :node-1
               :treasury-pubkey (:pubkey-hex treasury-kp)
               :treasury-privkey (:privkey-hex treasury-kp)
               :cluster {:nodes {:node-1 {:pubkey (:pubkey-hex id) :fingerprint (:fingerprint id)}}
                         :validators [:node-1]}}
          state (mesh/build-initial-node-state cfg id)]
      (try
        (is (= [(:pubkey-hex id)] (:validators state)))
        (is (= {(:pubkey-hex id) 1.0} (:mesh-nodes state)))
        (is (bytes? (:treasury-privkey state)))
        (is (= (:pubkey-hex treasury-kp) (:treasury-pubkey state)))
        ;; Verify state machine handles :tick with burns and treasury without throwing
        (let [state-with-burns (assoc state
                                      :epoch-burns {(:pubkey-hex id) 500}
                                      :total-minted 0)
              res (sm/handle-event state-with-burns {:type :tick :rng (java.util.Random.)})]
          (is (map? (:state res)))
          (is (= 1 (:epoch (:state res)))))
        (finally
          (doseq [f (reverse (file-seq temp-dir))]
            (.delete ^File f)))))))

(deftest test-render-statusz
  (testing "statusz line format"
    (let [state {:epoch 5
                 :node-pubkey "abc1234567890abcdef"
                 :head-hash "hash1"
                 :notarized-blocks #{"h1" "h2"}
                 :finalized-blocks #{"h1"}
                 :validators ["abc1234567890abcdef"]
                 :ledger {"abc1234567890abcdef" {:balance 1000}}
                 :total-minted 2000
                 :epoch-burns {"abc1234567890abcdef" 50}}
          out (mesh/render-statusz state 2 3)]
      (is (string? out))
      (is (str/starts-with? out "role=validator"))
      (is (str/includes? out "epoch=5"))
      (is (str/includes? out "head=hash1"))
      (is (str/includes? out "notarized=2"))
      (is (str/includes? out "finalized=1"))
      (is (str/includes? out "peers=2/3"))
      (is (str/includes? out "supply=1000"))
      (is (str/includes? out "minted=2000"))
      (is (str/includes? out "burns=50"))
      (is (str/includes? out "finalized_epoch=0"))
      (is (str/includes? out "burn_digest="))
      (is (str/includes? out "pending_receipts=0"))
      (is (str/includes? out "failed_receipts=0"))
      (is (str/includes? out "conn_dropped=0"))
      (is (str/includes? out "conn_stale=0"))
      (is (str/ends-with? out "\n"))))

  (testing "statusz line format accounts for pruned counts"
    (let [state {:epoch 500
                 :node-pubkey "abc1234567890abcdef"
                 :head-hash "hash500"
                 :notarized-blocks #{"h500"}
                 :finalized-blocks #{"h499"}
                 :pruned-notarized-count 450
                 :pruned-finalized-count 440
                 :validators ["abc1234567890abcdef"]
                 :ledger {"abc1234567890abcdef" {:balance 1000}}
                 :total-minted 2000}
          out (mesh/render-statusz state 2 3)]
      (is (str/includes? out "notarized=451"))
      (is (str/includes? out "finalized=441")))))

(deftest test-in-memory-mesh-lifecycle
  (testing "start, run consensus ticks, and stop 3-node in-memory cluster"
    (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-mesh-cluster-" (into-array FileAttribute [])))
          state-root (.getAbsolutePath temp-dir)
          id-a (identity/load-or-create-node-identity! (str state-root "/a") :node-a)
          id-b (identity/load-or-create-node-identity! (str state-root "/b") :node-b)
          id-c (identity/load-or-create-node-identity! (str state-root "/c") :node-c)
          cfg-nodes {:node-a {:pubkey (:pubkey-hex id-a) :fingerprint (:fingerprint id-a)}
                     :node-b {:pubkey (:pubkey-hex id-b) :fingerprint (:fingerprint id-b)}
                     :node-c {:pubkey (:pubkey-hex id-c) :fingerprint (:fingerprint id-c)}}
          base-cfg {:network :devnet
                    :cluster {:network :devnet
                              :nodes cfg-nodes
                              :validators #{(:pubkey-hex id-a) (:pubkey-hex id-b) (:pubkey-hex id-c)}}
                    :transport :in-memory
                    :http {:enabled? false}}
          node-a-cfg (assoc base-cfg :node/id :node-a :state-dir (str state-root "/a"))
          node-b-cfg (assoc base-cfg :node/id :node-b :state-dir (str state-root "/b"))
          node-c-cfg (assoc base-cfg :node/id :node-c :state-dir (str state-root "/c"))
          node-a (mesh/start-mesh-node! node-a-cfg {:identity id-a})
          node-b (mesh/start-mesh-node! node-b-cfg {:identity id-b})
          node-c (mesh/start-mesh-node! node-c-cfg {:identity id-c})]
      (try
        (is (some? node-a))
        (is (some? node-b))
        (is (some? node-c))
        ;; Inject ticks across 4 epochs so leaders propose, peers vote, and 3-epoch chain finalizes
        (doseq [_ (range 4)]
          (doseq [n [node-a node-b node-c]]
            (async/put! (:events-in (:shell-node n)) {:type :tick :rng (java.util.Random.)}))
          (Thread/sleep 50))
        (let [deadline (+ (System/currentTimeMillis) 2000)
              [st-a st-b st-c] (loop []
                                 (let [sa (#'mesh/query-node-state (:shell-node node-a) 500)
                                       sb (#'mesh/query-node-state (:shell-node node-b) 500)
                                       sc (#'mesh/query-node-state (:shell-node node-c) 500)]
                                   (if (and sa sb sc
                                            (seq (:finalized-blocks sa))
                                            (seq (:finalized-blocks sb))
                                            (seq (:finalized-blocks sc))
                                            (pos? (long (or (:last-executed-finalized-epoch sa) 0)))
                                            (= (sm/compute-burn-map-digest sa)
                                               (sm/compute-burn-map-digest sb)
                                               (sm/compute-burn-map-digest sc)))
                                     [sa sb sc]
                                     (if (< (System/currentTimeMillis) deadline)
                                       (do (Thread/sleep 25) (recur))
                                       [sa sb sc]))))]
          (is (some? st-a))
          (is (some? st-b))
          (is (some? st-c))
          (is (>= (:epoch st-a) 4))
          (is (seq (:blocks st-a)))
          (is (seq (:notarized-blocks st-a)))
          (is (seq (:notarized-blocks st-b)))
          (is (seq (:notarized-blocks st-c)))
          (is (seq (:finalized-blocks st-a)))
          (is (seq (:finalized-blocks st-b)))
          (is (seq (:finalized-blocks st-c)))
          (is (= (sm/compute-burn-map-digest st-a)
                 (sm/compute-burn-map-digest st-b)
                 (sm/compute-burn-map-digest st-c)))
          (is (string? (sm/compute-burn-map-digest st-a)))
          (is (= 16 (count (sm/compute-burn-map-digest st-a)))))
        (finally
          ((:stop! node-a))
          ((:stop! node-b))
          ((:stop! node-c))
          (doseq [f (reverse (file-seq temp-dir))]
            (.delete ^File f)))))))

(deftest test-agent-envelope-allowed-and-disallowed
  (let [kp (crypto/generate-keypair)
        pub (basalt/bytes->hex (:public kp))
        priv (:private kp)]
    (testing "all allowed event types successfully authenticate and unwrap"
      (doseq [t mesh/allowed-agent-events]
        (let [evt (case t
                    :settle-intent {:type t :payer pub :receiver "302a300506032b6570032100" :amount 100}
                    :lock-intent {:type t :payer pub :receiver "302a300506032b6570032100" :amount 100
                                  :deliverable-hash "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                  :expires-epoch 10 :created-epoch 0}
                    :release-intent {:type t :escrow-id "escrow-123"}
                    :refund-intent {:type t :escrow-id "escrow-123"}
                    :on-deliver (let [tf (account/create-transfer priv {:sender pub :receiver "302a300506032b6570032100" :amount 50 :seq 1 :deps []})
                                      p (vec (.getBytes ^String (pr-str {:transfer (into {} tf)}) "UTF-8"))]
                                  {:type t :payload p :message-id "msg-1"})
                    :submit-vouchers (let [ack (rendezvous/create-delivery-ack priv pub :node1 1 "offer-hash" 1 10)]
                                       {:type t :vouchers [ack]})
                    {:type t :sample "data"})
              env (mesh/wrap-agent-event evt pub priv)
              res (mesh/unwrap-authenticated-agent-event env)]
          (is (some? res))
          (is (= t (:type res)))
          (is (= pub (:sender res)))
          (is (= (vec (:public kp)) (vec (:sender-pubkey-bytes res)))))))
    (testing "disallowed consensus events return nil fail-closed"
      (doseq [t [:receive-propose :receive-vote :tick :other-arbitrary]]
        (let [evt {:type t :sample "data"}
              env (mesh/wrap-agent-event evt pub priv)
              res (mesh/unwrap-authenticated-agent-event env)]
          (is (nil? res)))))))

(deftest test-http-server-loopback-host
  (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-http-test-" (into-array FileAttribute [])))
        state-root (.getAbsolutePath temp-dir)
        id (identity/load-or-create-node-identity! state-root :node-1)
        cfg {:node/id :node-1
             :state-dir state-root
             :http {:enabled? true :port 0 :host "127.0.0.1"}
             :transport :in-memory}
        node (mesh/start-mesh-node! cfg {:identity id})]
    (try
      (is (some? (:http-server node)))
      (let [addr (.getAddress ^com.sun.net.httpserver.HttpServer (:http-server node))]
        (is (= "127.0.0.1" (.getHostString addr))))
      (finally
        ((:stop! node))
        (doseq [f (reverse (file-seq temp-dir))]
          (.delete ^File f))))))

(deftest test-http-accountz-endpoint
  (testing "/accountz and /accountz?pubkey=<hex> query functionality"
    (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-http-acc-test-" (into-array FileAttribute [])))
          state-root (.getAbsolutePath temp-dir)
          id (identity/load-or-create-node-identity! state-root :node-1)
          pk-alice "302a300506032b6570032100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          pk-bob   "302a300506032b6570032100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cfg {:node/id :node-1
               :state-dir state-root
               :genesis-ledger {pk-alice {:balance 5000 :seq 1 :deps ["dep-a"]}
                                pk-bob   {:balance 2000 :seq 0 :deps []}}
               :http {:enabled? true :port 0 :host "127.0.0.1"}
               :transport :in-memory}
          node (mesh/start-mesh-node! cfg {:identity id})]
      (try
        (let [server ^com.sun.net.httpserver.HttpServer (:http-server node)
              port (.getPort (.getAddress server))
              base-url (str "http://127.0.0.1:" port)

              ;; 1. GET /accountz returns all accounts
              all-resp (edn/read-string (slurp (str base-url "/accountz")))
              _ (do
                  (is (map? all-resp))
                  (is (= 0 (:finalized-epoch all-resp)))
                  (is (contains? (:accounts all-resp) pk-alice))
                  (is (= 5000 (get-in all-resp [:accounts pk-alice :balance])))
                  (is (= 2000 (get-in all-resp [:accounts pk-bob :balance]))))

              ;; 2. GET /accountz?pubkey=pk-alice returns single account with spendable balance
              alice-resp (edn/read-string (slurp (str base-url "/accountz?pubkey=" pk-alice)))
              _ (do
                  (is (= pk-alice (:pubkey alice-resp)))
                  (is (= 5000 (:spendable alice-resp)))
                  (is (= 1 (get-in alice-resp [:account :seq])))
                  (is (= ["dep-a"] (get-in alice-resp [:account :deps])))
                  (is (= 0 (:finalized-epoch alice-resp))))

              ;; 3. GET /accountz?pubkey=unknown returns nil account and 0 spendable
              unknown-resp (edn/read-string (slurp (str base-url "/accountz?pubkey=unknown-hex")))]
          (is (= "unknown-hex" (:pubkey unknown-resp)))
          (is (nil? (:account unknown-resp)))
          (is (= 0 (:spendable unknown-resp)))
          (is (= 0 (:finalized-epoch unknown-resp))))
        (finally
          ((:stop! node))
          (doseq [f (reverse (file-seq temp-dir))]
            (.delete ^File f)))))))

(deftest test-snapshot-strips-secrets-and-rebinds-on-restore
  (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-snap-test-" (into-array FileAttribute [])))
        snap-file (io/file temp-dir "snapshot.bin")
        kp (crypto/generate-keypair)
        id-map {:node-id :node-1
                :pubkey-hex (basalt/bytes->hex (:public kp))
                :privkey-hex (basalt/bytes->hex (:private kp))
                :keypair kp
                :fingerprint "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                :ice-creds (identity/deterministic-ice-creds :node-1)}
        cfg {:node/id :node-1
             :cluster {:network :devnet
                       :nodes {:node-1 {:pubkey (:pubkey-hex id-map) :fingerprint (:fingerprint id-map)}}}
             :treasury-privkey (basalt/bytes->hex (:private kp))
             :custody-privkey (basalt/bytes->hex (:private kp))}
        init-st (mesh/build-initial-node-state cfg id-map)
        state-to-save (assoc init-st
                             :epoch 7
                             :head-hash "h7"
                             :notarized-blocks #{"h7"})]
    (try
      (is (true? (persistence/save-state-to-disk (.getAbsolutePath snap-file) state-to-save)))
      (is (.exists snap-file))
      (let [perms (Files/getPosixFilePermissions (.toPath snap-file) (into-array java.nio.file.LinkOption []))]
        (is (= "rw-------" (PosixFilePermissions/toString perms))))
      (let [loaded (persistence/load-state-from-disk (.getAbsolutePath snap-file))]
        (is (= 7 (:epoch loaded)))
        (is (nil? (:keypair loaded)))
        (is (nil? (:node-private-key loaded)))
        (is (nil? (:treasury-privkey loaded)))
        (is (nil? (:custody-privkey loaded)))
        (let [rebound (mesh/rebind-restored-state loaded cfg id-map)]
          (is (= 7 (:epoch rebound)))
          (is (some? (:keypair rebound)))
          (is (some? (:node-private-key rebound)))
          (is (some? (:treasury-privkey rebound)))
          (is (= (:pubkey-hex id-map) (:node-pubkey rebound)))))
      (finally
        (doseq [f (reverse (file-seq temp-dir))]
          (.delete ^File f))))))

(deftest test-rebind-restored-state-upgrade-safety-and-genesis-ledger-merge
  (testing "rebind-restored-state initializes missing finalized epoch & blocks and merges new genesis accounts safely"
    (let [kp (crypto/generate-keypair)
          id-map {:node-id :node-1
                  :pubkey-hex (basalt/bytes->hex (:public kp))
                  :privkey-hex (basalt/bytes->hex (:private kp))
                  :keypair kp}
          pk-custody "302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111"
          pk-new-agent "302a300506032b65700321002222222222222222222222222222222222222222222222222222222222222222"
          ;; Legacy state loaded from disk missing :last-executed-finalized-epoch and :executed-finalized-blocks
          loaded-state {:epoch 14
                        :head-hash "h14"
                        :finalized-blocks #{"b10" "b11" "b12"}
                        :last-executed-finalized-epoch nil
                        :executed-finalized-blocks nil
                        :ledger {pk-custody (account/map->AccountState {:balance 4190000000 :seq 5 :deps ["prev-tx"]})}}
          ;; Config with genesis ledger containing both an update for custody (which must be ignored!) and a new agent
          cfg {:node/id :node-1
               :genesis-ledger {pk-custody {:balance 4197000000 :seq 0 :deps []}
                                pk-new-agent {:balance 1000000 :seq 0 :deps []}}}
          rebound (mesh/rebind-restored-state loaded-state cfg id-map)]

      ;; Upgrade safety: missing finalized epoch initialized to loaded epoch (not 0!)
      (is (= 14 (:last-executed-finalized-epoch rebound)))
      ;; Upgrade safety: missing executed blocks initialized to finalized-blocks
      (is (= #{"b10" "b11" "b12"} (:executed-finalized-blocks rebound)))

      ;; Non-destructive merge: existing account state preserved exactly as-is
      (is (= 4190000000 (get-in rebound [:ledger pk-custody :balance])))
      (is (= 5 (get-in rebound [:ledger pk-custody :seq])))
      (is (= ["prev-tx"] (get-in rebound [:ledger pk-custody :deps])))

      ;; Additive merge: new agent seeded from genesis-ledger as AccountState
      (is (instance? bitecho.economy.account.AccountState (get-in rebound [:ledger pk-new-agent])))
      (is (= 1000000 (get-in rebound [:ledger pk-new-agent :balance])))
      (is (= 0 (get-in rebound [:ledger pk-new-agent :seq])))
      (is (= [] (get-in rebound [:ledger pk-new-agent :deps]))))))

(deftest test-peer-init-malformed-fingerprint-resilient
  (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-malformed-peer-" (into-array FileAttribute [])))
        state-root (.getAbsolutePath temp-dir)
        id (identity/load-or-create-node-identity! state-root :node-1)
        cfg {:node/id :node-1
             :state-dir state-root
             :cluster {:nodes {:node-1 {:pubkey (:pubkey-hex id) :fingerprint (:fingerprint id)}
                               :node-bad {:pubkey "bad-hex" :fingerprint "NOT-A-FINGERPRINT"}}}
             :transport :in-memory
             :http {:enabled? false}}
        node (mesh/start-mesh-node! cfg {:identity id})]
    (try
      (is (some? node))
      (is (fn? (:stop! node)))
      (finally
        ((:stop! node))
        (doseq [f (reverse (file-seq temp-dir))]
          (.delete ^File f))))))

(deftest test-build-initial-node-state-network-preset
  (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-preset-test-" (into-array FileAttribute [])))
        state-root (.getAbsolutePath temp-dir)
        id (identity/load-or-create-node-identity! state-root :node-1)]
    (try
      (let [dev-st (mesh/build-initial-node-state {:node/id :node-1 :network :devnet} id)
            def-st (mesh/build-initial-node-state {:node/id :node-1} id)]
        (is (= 10000 (get-in dev-st [:config :tick-interval-ms])))
        (is (= 3600000 (get-in def-st [:config :tick-interval-ms]))))
      (finally
        (doseq [f (reverse (file-seq temp-dir))]
          (.delete ^File f))))))

(deftest test-write-keypair-file
  (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-kp-file-test-" (into-array FileAttribute [])))
        kp-file (io/file temp-dir "secret-keypair.edn")
        kp-map (identity/generate-ed25519-keypair-map)]
    (try
      (is (true? (identity/write-keypair-file! (.getAbsolutePath kp-file) kp-map)))
      (is (.exists kp-file))
      (let [perms (Files/getPosixFilePermissions (.toPath kp-file) (into-array java.nio.file.LinkOption []))]
        (is (= "rw-------" (PosixFilePermissions/toString perms))))
      (let [read-kp (edn/read-string (slurp kp-file))]
        (is (= (:pubkey-hex kp-map) (:pubkey-hex read-kp)))
        (is (= (:privkey-hex kp-map) (:privkey-hex read-kp))))
      (finally
        (doseq [f (reverse (file-seq temp-dir))]
          (.delete ^File f))))))

(deftest test-validate-node-config
  (let [valid-peer-fp "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF"
        base-cfg {:node/id :node-1
                  :state-dir "/tmp/bitecho"
                  :cluster {:network :devnet
                            :nodes {:node-1 {:ip "127.0.0.1"
                                             :port 5000
                                             :pubkey (apply str (repeat 88 "a"))
                                             :fingerprint valid-peer-fp
                                             :ice-ufrag "ufrag1"
                                             :ice-pwd "pwd12345678901234567890"}
                                    :node-2 {:ip "127.0.0.1"
                                             :port 5001
                                             :pubkey (apply str (repeat 88 "b"))
                                             :fingerprint valid-peer-fp
                                             :ice-ufrag "ufrag2"
                                             :ice-pwd "pwd22345678901234567890"}}}}
        res (mesh/validate-node-config base-cfg)]
    (is (true? (:valid? res)))
    (is (nil? (:error res)))

    (testing "fails when config is not a map"
      (let [r (mesh/validate-node-config "not-a-map")]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) "map"))))

    (testing "fails when node-id is missing or not a keyword"
      (let [r (mesh/validate-node-config (dissoc base-cfg :node/id))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) "keyword"))))

    (testing "fails when state-dir is missing or blank"
      (let [r (mesh/validate-node-config (assoc base-cfg :state-dir ""))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) ":state-dir"))))

    (testing "fails when cluster configuration is not a map"
      (let [r (mesh/validate-node-config (assoc base-cfg :cluster "invalid"))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) "Cluster"))))

    (testing "fails when peer has invalid or missing ip"
      (let [r (mesh/validate-node-config (assoc-in base-cfg [:cluster :nodes :node-2 :ip] ""))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) ":ip"))))

    (testing "fails when peer has invalid or non-positive port"
      (let [r (mesh/validate-node-config (assoc-in base-cfg [:cluster :nodes :node-2 :port] 0))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) ":port"))))

    (testing "fails when peer has invalid pubkey hex"
      (let [r (mesh/validate-node-config (assoc-in base-cfg [:cluster :nodes :node-2 :pubkey] "not-hex-88"))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) ":pubkey"))))

    (testing "fails when peer has malformed fingerprint"
      (let [r (mesh/validate-node-config (assoc-in base-cfg [:cluster :nodes :node-2 :fingerprint] "bad-fingerprint"))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) ":fingerprint"))))

    (testing "fails when peer is missing ice credentials"
      (let [r (mesh/validate-node-config (assoc-in base-cfg [:cluster :nodes :node-2 :ice-ufrag] ""))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) ":ice-ufrag")))
      (let [r (mesh/validate-node-config (assoc-in base-cfg [:cluster :nodes :node-2 :ice-pwd] ""))]
        (is (false? (:valid? r)))
        (is (str/includes? (:error r) ":ice-pwd"))))))

(deftest test-agent-gossip-sieve-nippy-roundtrip
  (let [kp (crypto/generate-keypair)
        agent-pub (basalt/bytes->hex (:public kp))
        agent-priv (:private kp)
        payload (.getBytes "gossip-payload-123" StandardCharsets/UTF_8)
        raw-sieve-msg (sieve/wrap-message payload agent-priv (:public kp) 100)
        sieve-msg (assoc raw-sieve-msg :message-id "msg-sieve-1")
        event {:type :receive-gossip :message sieve-msg}
        envelope (mesh/wrap-agent-event event agent-pub agent-priv)
        frozen (nippy/freeze envelope)
        unwrapped (mesh/unwrap-authenticated-agent-event frozen)]
    (is (some? unwrapped))
    (is (= (:sender unwrapped) agent-pub))
    (is (bytes? (:sender-pubkey-bytes unwrapped)))
    (is (bytes? (get-in unwrapped [:message :payload])))
    (is (bytes? (get-in unwrapped [:message :signature])))
    (is (or (bytes? (get-in unwrapped [:message :sender]))
            (string? (get-in unwrapped [:message :sender]))))

    (testing "unwrapped event processed by state-machine/handle-event debits balance by 100"
      (let [peer (basalt/make-peer "127.0.0.1" 8000 (:public (crypto/generate-keypair)))
            initial-balance 1000
            genesis-ledger {agent-pub (account/map->AccountState {:balance initial-balance :seq 0 :deps []})}
            cfg (assoc config/default-config :genesis-ledger genesis-ledger)
            state (assoc (sm/init-state [peer] "local-node" cfg) :epoch 0)
            res (sm/handle-event state unwrapped)
            new-state (:state res)
            sender-bal (get-in new-state [:ledger agent-pub :balance])]
        (is (= 900 sender-bal))
        (is (= 100 (get-in new-state [:epoch-burns 0])))
        (is (contains? (:messages new-state) (basalt/bytes->hex (crypto/sha256 payload))))))

    (testing "mutating 1 byte of payload causes unwrap to return nil"
      (let [thawed (nippy/thaw frozen)
            pl (get-in thawed [:event :message :payload])
            mutated-pl (byte-array pl)]
        (aset mutated-pl 0 (unchecked-byte (bit-xor (aget mutated-pl 0) 1)))
        (let [tampered (assoc-in thawed [:event :message :payload] mutated-pl)]
          (is (nil? (mesh/unwrap-authenticated-agent-event tampered))))))))

(deftest test-send-peer-keepalives
  (let [sent (atom [])
        mock-node-1 {:id 1}
        mock-node-2 {:id 2}
        mock-node-3 {:id 3}
        peer-conns (atom {"peer-1" {:node mock-node-1 :channel-id (atom 10)}
                          "peer-2" {:node mock-node-2 :channel-id (atom nil)}
                          "peer-3" {:node mock-node-3 :channel-id (atom 20)}})]
    (with-redefs [api/send! (fn [node data cid]
                              (swap! sent conj {:node node :data (nippy/thaw data) :cid cid}))]
      (mesh/send-peer-keepalives! peer-conns)
      (is (= 2 (count @sent)))
      (is (= #{1 3} (set (map #(get-in % [:node :id]) @sent))))
      (is (= #{10 20} (set (map :cid @sent))))
      (is (every? #(= {:type :keepalive} (:data %)) @sent)))

    (testing "send error is caught and does not throw"
      (with-redefs [api/send! (fn [_ _ _] (throw (RuntimeException. "send failed")))]
        (is (nil? (mesh/send-peer-keepalives! peer-conns)))))))

(defspec ^{:doc "Verifies check-and-reconnect-peers! reconnects peers strictly when closed, stalled, or timed out."}
  prop-check-and-reconnect-peers-invariants
  100
  (prop/for-all [conn-exists? gen/boolean
                 cid-val (gen/elements [nil 0 1 2])
                 elapsed-created (gen/choose 0 30000)
                 elapsed-rx (gen/choose 0 60000)
                 st (gen/elements [:connected :connecting :closed])
                 timeout-ms (gen/choose 10000 40000)]
                (let [now-ms 100000
                      created-at (- now-ms (long elapsed-created))
                      last-rx-at (- now-ms (long elapsed-rx))
                      mock-node {:mock true}
                      peer-conn (when conn-exists?
                                  {:node mock-node
                                   :channel-id (atom cid-val)
                                   :created-at created-at
                                   :last-rx-at (atom last-rx-at)})
                      reconnected (atom [])
                      peer-conns (atom (if conn-exists? {"peer-hex" peer-conn} {}))
                      ctx {:node-id :node-local
                           :nodes-cfg {:node-local {:pubkey "local-hex"}
                                       :node-remote {:pubkey "peer-hex"}}
                           :peer-conns peer-conns}
                      expected-reconnect? (or (not conn-exists?)
                                              (= st :closed)
                                              (and (nil? cid-val) (> (long elapsed-created) 12000))
                                              (and (some? cid-val) (> (long elapsed-rx) (long timeout-ms))))]
                  (with-redefs [mesh/init-datachannel-peer! (fn [_ pid _] (swap! reconnected conj pid))
                                api/get-state (fn [_] st)]
                    (mesh/check-and-reconnect-peers! ctx timeout-ms now-ms)
                    (= expected-reconnect? (contains? (set @reconnected) :node-remote))))))

(deftest test-datachannel-keepalive-message-handling
  (let [captured-callbacks (atom nil)
        network-in (async/chan 10)
        shell-node {:network-in network-in}
        peer-conns (atom {})
        ctx {:node-id :node-local
             :identity {:pubkey-hex (apply str (repeat 88 "a"))
                        :fingerprint "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                        :cert-data {}
                        :ice-creds {:ufrag "ufragloc" :pwd "pwdlocal12345678901234"}}
             :node-idx {:node-local 0 :node-remote 1}
             :nodes-cfg {:node-local {:port 5000}
                         :node-remote {:ip "127.0.0.1"
                                       :port 5001
                                       :pubkey (apply str (repeat 88 "b"))
                                       :fingerprint "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
                                       :ice-creds {:ufrag "ufragrem" :pwd "pwdremote12345678901234"}}}
             :shell-node shell-node
             :peer-conns peer-conns}]
    (with-redefs [api/start! (fn [_ _ cbs] (reset! captured-callbacks cbs))
                  api/create-data-channel! (fn [_ _ _] 0)]
      (#'mesh/init-datachannel-peer! ctx :node-remote (get-in ctx [:nodes-cfg :node-remote]))
      (is (some? @captured-callbacks))
      (let [peer-pk (get-in ctx [:nodes-cfg :node-remote :pubkey])
            conn (get @peer-conns peer-pk)
            on-msg (:on-message @captured-callbacks)
            on-open (:on-open @captured-callbacks)
            on-close (:on-close @captured-callbacks)]
        (is (some? conn))
        (is (some? (mesh/conn-last-rx-at conn)))

        ;; Test on-open updates last-rx-at and sets channel-id
        (let [t0 (mesh/conn-last-rx-at conn)]
          (Thread/sleep 2)
          (on-open {})
          (let [c (get @peer-conns peer-pk)]
            (is (> (mesh/conn-last-rx-at c) t0))
            (is (= 0 (mesh/conn-channel-id c)))
            (is (= :open (:phase c)))
            (is (true? (:ok? c)))))

        ;; Test on-message with :keepalive updates last-rx-at and does not put to network-in
        (let [t1 (mesh/conn-last-rx-at (get @peer-conns peer-pk))]
          (Thread/sleep 2)
          (on-msg {:payload (nippy/freeze {:type :keepalive})})
          (let [c (get @peer-conns peer-pk)]
            (is (> (mesh/conn-last-rx-at c) t1))
            (is (nil? (async/poll! network-in)))))

        ;; Test on-message with regular event puts to network-in
        (let [t2 (mesh/conn-last-rx-at (get @peer-conns peer-pk))]
          (Thread/sleep 2)
          (on-msg {:payload (nippy/freeze {:type :receive-gossip :data "hello"})})
          (let [c (get @peer-conns peer-pk)]
            (is (> (mesh/conn-last-rx-at c) t2))
            (let [received (async/poll! network-in)]
              (is (some? received))
              (is (= :receive-gossip (:type received)))
              (is (= "hello" (:data received))))))

        ;; Test malformed frame increments dropped count (Rule 5: Zero Silent Failures)
        (let [d0 (:dropped (get @peer-conns peer-pk))]
          (on-msg {:payload (byte-array [1 2 3 4 5 6])})
          (let [c (get @peer-conns peer-pk)]
            (is (= (inc d0) (:dropped c)))))

        ;; Test on-close clears channel-id and sets phase to :failed
        (on-close {})
        (let [c (get @peer-conns peer-pk)]
          (is (nil? (mesh/conn-channel-id c)))
          (is (= :failed (:phase c)))
          (is (false? (:ok? c))))))))

(def ^:private gen-mesh-event-type
  (gen/elements [:dial-started
                 :accept-started
                 :on-open
                 :on-data-channel
                 :on-message
                 :send-failed
                 :invalid-frame
                 :dial-failed
                 :on-close
                 :shutdown]))

(def ^:private gen-mesh-gen-mode
  (gen/frequency [[60 (gen/return :current)]
                  [25 (gen/return :stale)]
                  [15 (gen/return :future)]]))

(def ^:private gen-mesh-node-mode
  (gen/frequency [[70 (gen/return :same)]
                  [15 (gen/return :new)]
                  [15 (gen/return :superseded)]]))

(def ^:private gen-mesh-step
  (gen/hash-map :type gen-mesh-event-type
                :gen-mode gen-mesh-gen-mode
                :node-mode gen-mesh-node-mode
                :has-cid? gen/boolean
                :error-msg (gen/elements [nil "err-timeout" "err-rst" "err-down"])))

(def ^:private gen-mesh-sequence
  (gen/vector gen-mesh-step 5 40))

(defspec ^{:doc "Property: Pure single-authority mesh connection lifecycle state machine invariants"}
  mesh-conn-lifecycle-state-machine-spec 100
  (prop/for-all [steps gen-mesh-sequence]
                (let [initial-conn (mesh/init-mesh-conn-state)]
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
                                      :current (if (#{:dial-started :accept-started} evt-type) nil curr-gen)
                                      :stale (if (pos? curr-gen) (max 0 (dec curr-gen)) -1)
                                      :future (inc curr-gen))
                            active-node (:node conn)
                            node-mode (:node-mode step)
                            evt-node (if (#{:dial-started :accept-started} evt-type)
                                       {:mock-id (str "node-" idx)}
                                       (case node-mode
                                         :same active-node
                                         :new active-node
                                         :superseded (when (seq closed-nodes) (last closed-nodes))))
                            evt-cid (when (:has-cid? step) (str "cid-" idx))
                            event (cond-> {:type evt-type}
                                    (some? evt-gen) (assoc :generation evt-gen)
                                    (some? evt-node) (assoc :node evt-node)
                                    (some? evt-cid) (assoc :channel-id evt-cid)
                                    (:error-msg step) (assoc :error (:error-msg step)))
                            [new-conn effects] (mesh/transition-mesh-conn conn event)
                            stale-gen? (and (some? (:generation event)) (< (long (:generation event)) (long (:generation conn 0))))
                            superseded-node? (and (not (#{:dial-started :accept-started} evt-type))
                                                  (some? (:node event))
                                                  (not= (:node event) (:node conn)))
                            stale? (or stale-gen? superseded-node?)
                            newly-closed (keep (fn [eff] (when (= :close-node (:effect eff)) (:node eff))) effects)
                            new-closed (into closed-nodes newly-closed)
                            new-installed (if (and (not stale?)
                                                   (#{:dial-started :accept-started} evt-type)
                                                   (:node new-conn))
                                            (conj installed-nodes (:node new-conn))
                                            installed-nodes)

                ;; Invariant 1 (Liveness Agreement)
                            inv1 (= (boolean (:ok? new-conn))
                                    (and (= :open (:phase new-conn))
                                         (some? (:channel-id new-conn))))

                ;; Invariant 2 (Stale Generation & Superseded Node Isolation)
                            inv2 (if stale?
                                   (and (= (:phase conn) (:phase new-conn))
                                        (= (:ok? conn) (:ok? new-conn))
                                        (= (:node conn) (:node new-conn))
                                        (= (:channel-id conn) (:channel-id new-conn))
                                        (= (:last-rx-at conn) (:last-rx-at new-conn))
                                        (= (:ignored-stale new-conn) (inc (:ignored-stale conn 0)))
                                        (= (first effects) {:effect :ignore-stale
                                                            :generation (or (:generation event) (:generation conn 0))}))
                                   true)

                ;; Invariant 3 (Superseded Node Closed Exactly Once)
                            inv3 (and (= (count new-closed) (count (distinct new-closed)))
                                      (every? (set new-installed) new-closed)
                                      (if-let [n (:node new-conn)]
                                        (not (contains? (set new-closed) n))
                                        true))

                ;; Invariant 4 (No Silent Failures)
                            inv4 (if (and (not stale?) (#{:dial-failed :send-failed :invalid-frame} evt-type))
                                   (and (= (:dropped new-conn) (inc (:dropped conn 0)))
                                        (boolean (some (fn [eff] (and (= :diagnose (:effect eff)) (some? (:error eff)))) effects)))
                                   true)]
                        (if (and inv1 inv2 inv3 inv4)
                          (recur (inc idx) new-conn new-installed new-closed)
                          false)))))))

(defspec ^{:doc "Property: Agent connection re-keying from anon to sender, superseded node closing, and delayed stale callback isolation"}
  agent-conn-rebind-and-stale-close-spec 50
  (prop/for-all [sender-pk (gen/elements ["agent-pub-1" "agent-pub-2" "agent-pub-3"])
                 cid-num (gen/choose 1 10)]
                (let [conns-atom (atom {})
                      anon-key-1 [:anon 1001]
                      node-1 {:agent-node 1}
                      now1 1000
          ;; 1. Accept started under anon-key-1
                      _ (mesh/apply-mesh-conn-event! conns-atom anon-key-1
                                                     {:type :accept-started :generation 1 :node node-1 :channel-id 0 :now-ms now1})
                      conn1 (get @conns-atom anon-key-1)
                      _ (assert (= :open (:phase conn1)))
                      _ (assert (= node-1 (:node conn1)))

          ;; 2. Rebind to sender-pk
                      _ (mesh/apply-agent-sender-rebind! conns-atom anon-key-1 sender-pk cid-num now1)
                      rebound1 (get @conns-atom sender-pk)
                      _ (assert (nil? (get @conns-atom anon-key-1)))
                      _ (assert (= node-1 (:node rebound1)))
                      _ (assert (= 2 (:generation rebound1)))
                      _ (assert (> (:generation rebound1) (:generation conn1)))

          ;; 3. Second connection from same sender under new anon-key-2
                      anon-key-2 [:anon 1002]
                      node-2 {:agent-node 2}
                      now2 2000
                      closed-nodes (atom [])
                      _ (mesh/apply-mesh-conn-event! conns-atom anon-key-2
                                                     {:type :accept-started :generation 2 :node node-2 :channel-id 0 :now-ms now2})
          ;; Rebind anon-key-2 to the same sender-pk with custom close-node tracker
                      rebound-res (mesh/rebind-agent-conn-sender @conns-atom anon-key-2 sender-pk cid-num now2)
                      [new-conns-map effects] rebound-res
                      _ (doseq [eff effects]
                          (when (= :close-node (:effect eff))
                            (swap! closed-nodes conj (:node eff))))
                      _ (reset! conns-atom new-conns-map)
                      rebound2 (get @conns-atom sender-pk)]

      ;; Verification: node-1 closed on rebind, node-2 active with higher generation
                  (and (= [node-1] @closed-nodes)
                       (= node-2 (:node rebound2))
                       (> (:generation rebound2) (:generation rebound1))
                       (nil? (get @conns-atom anon-key-2))

           ;; 4. Delayed stale callbacks from superseded node-1 arrive
                       (let [[after-stale-close eff-close] (mesh/transition-mesh-conn rebound2
                                                                                      {:type :on-close :node node-1 :generation 1})
                             [after-stale-msg eff-msg] (mesh/transition-mesh-conn after-stale-close
                                                                                  {:type :on-message :node node-1 :generation 1})]
             ;; Both stale callbacks ignored! Node-2 remains active and open!
                         (and (= :open (:phase after-stale-msg))
                              (= node-2 (:node after-stale-msg))
                              (= true (:ok? after-stale-msg))
                              (= cid-num (:channel-id after-stale-msg))
                              (= 2 (:ignored-stale after-stale-msg))
                              (= :ignore-stale (:effect (first eff-close)))
                              (= :ignore-stale (:effect (first eff-msg)))))))))

(deftest test-http-connz-endpoint
  (testing "GET /connz and GET /statusz return structured EDN diagnostics and counters for peers and agents"
    (let [peer-conns (atom {"peer1" (assoc (mesh/init-mesh-conn-state) :phase :open :ok? true :generation 1 :dropped 2 :ignored-stale 1)})
          agent-conns (atom {"agent1" (assoc (mesh/init-mesh-conn-state) :phase :open :ok? true :generation 2 :dropped 1 :ignored-stale 0)})
          summary (mesh/mesh-conn-diagnostics-summary @peer-conns @agent-conns)]
      (is (= 3 (:conn_dropped summary)))
      (is (= 1 (:conn_stale summary)))
      (is (contains? (:peers summary) "peer1"))
      (is (contains? (:agents summary) "agent1"))
      (is (= "open" (get-in summary [:peers "peer1" :phase])))
      (is (= 2 (get-in summary [:peers "peer1" :dropped])))
      (is (= 1 (get-in summary [:peers "peer1" :ignored_stale]))))
    (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-http-connz-test-" (into-array FileAttribute [])))
          state-root (.getAbsolutePath temp-dir)
          id (identity/load-or-create-node-identity! state-root :node-1)
          cfg {:node/id :node-1
               :state-dir state-root
               :http {:enabled? true :port 0 :host "127.0.0.1"}
               :transport :in-memory}
          node (mesh/start-mesh-node! cfg {:identity id})]
      (try
        (reset! (:peer-conns node) {"peer1" (assoc (mesh/init-mesh-conn-state) :phase :open :ok? true :channel-id 0 :generation 1 :dropped 2 :ignored-stale 1)})
        (reset! (:agent-conns node) {"agent1" (assoc (mesh/init-mesh-conn-state) :phase :open :ok? true :channel-id 0 :generation 2 :dropped 1 :ignored-stale 3)})
        (let [server ^com.sun.net.httpserver.HttpServer (:http-server node)
              port (.getPort (.getAddress server))
              base-url (str "http://127.0.0.1:" port)
              connz-resp (edn/read-string (slurp (str base-url "/connz")))
              statusz-resp (slurp (str base-url "/statusz"))]
          (is (= 3 (:conn_dropped connz-resp)))
          (is (= 4 (:conn_stale connz-resp)))
          (is (= "open" (get-in connz-resp [:peers "peer1" :phase])))
          (is (= "open" (get-in connz-resp [:agents "agent1" :phase])))
          (is (str/includes? statusz-resp "conn_dropped=3"))
          (is (str/includes? statusz-resp "conn_stale=4")))
        (finally
          ((:stop! node))
          (doseq [f (reverse (file-seq temp-dir))]
            (.delete ^File f)))))))

(deftest test-agent-connection-handler-rebind-and-stale-callback-isolation
  (testing "make-agent-connection-handler rebinds sender, closes superseded node, and isolates delayed stale callbacks"
    (let [kp (crypto/generate-keypair)
          agent-pub (basalt/bytes->hex (:public kp))
          agent-priv (:private kp)
          network-in (async/chan 10)
          shell-node {:network-in network-in
                      :state-atom (atom {:messages {} :message-epochs {}})}
          agent-conns (atom {})
          cbs-map (atom {})
          closed-nodes (atom [])
          handler (#'mesh/make-agent-connection-handler shell-node agent-conns)
          node-1 {:id :agent-node-1}
          node-2 {:id :agent-node-2}
          valid-env (nippy/freeze (mesh/wrap-agent-event {:type :receive-summary :epoch 1 :summary "s1"} agent-pub agent-priv))
          valid-env-2 (nippy/freeze (mesh/wrap-agent-event {:type :receive-summary :epoch 2 :summary "s2"} agent-pub agent-priv))]
      (with-redefs [api/set-callbacks! (fn [n cbs] (swap! cbs-map assoc n cbs))
                    api/close! (fn [n] (swap! closed-nodes conj n))]
        ;; 1. First agent connection accepted and authenticates
        (handler node-1)
        ((:on-message (get @cbs-map node-1)) {:channel-id 1 :payload valid-env})
        (is (= node-1 (get-in @agent-conns [agent-pub :node])))
        (is (= :open (get-in @agent-conns [agent-pub :phase])))
        (is (some? (async/poll! network-in)))

        ;; 2. Second agent connection from same sender accepted and authenticates
        (handler node-2)
        ((:on-message (get @cbs-map node-2)) {:channel-id 2 :payload valid-env-2})
        (is (= [node-1] @closed-nodes))
        (is (= node-2 (get-in @agent-conns [agent-pub :node])))
        (is (= :open (get-in @agent-conns [agent-pub :phase])))
        (is (some? (async/poll! network-in)))

        ;; 3. Delayed :on-close and :on-message from superseded node-1 must be ignored without evicting node-2 or delivering duplicate events
        ((:on-close (get @cbs-map node-1)) {})
        ((:on-message (get @cbs-map node-1)) {:channel-id 1 :payload valid-env})
        (is (= node-2 (get-in @agent-conns [agent-pub :node])))
        (is (= :open (get-in @agent-conns [agent-pub :phase])))
        (is (true? (get-in @agent-conns [agent-pub :ok?])))
        (is (= 2 (get-in @agent-conns [agent-pub :ignored-stale])))
        (is (nil? (async/poll! network-in)))))))

(deftest test-record-sent-msg-fifo-eviction-at-1024-cap
  (testing "inserting the 1025th message ID evicts only the 1st message ID while retaining 2..1025"
    (let [initial-conn (mesh/init-mesh-conn-state)
          ;; Record 1024 message IDs: "msg-1" .. "msg-1024"
          conn-1024 (reduce (fn [c i]
                              (first (mesh/transition-mesh-conn c {:type :record-sent-msg :msg-id (str "msg-" i)})))
                            initial-conn
                            (range 1 1025))]
      (is (= 1024 (count (:sent-msg-ids conn-1024))))
      (is (= 1024 (count (:sent-msg-order conn-1024))))
      (is (contains? (:sent-msg-ids conn-1024) "msg-1"))
      (is (contains? (:sent-msg-ids conn-1024) "msg-1024"))
      ;; Now insert the 1025th message ID: "msg-1025"
      (let [[conn-1025 _] (mesh/transition-mesh-conn conn-1024 {:type :record-sent-msg :msg-id "msg-1025"})]
        (is (= 1024 (count (:sent-msg-ids conn-1025))))
        (is (= 1024 (count (:sent-msg-order conn-1025))))
        ;; First message ID evicted
        (is (not (contains? (:sent-msg-ids conn-1025) "msg-1")))
        ;; Newest message ID present
        (is (contains? (:sent-msg-ids conn-1025) "msg-1025"))
        ;; Message IDs 2 through 1024 still retained
        (is (every? #(contains? (:sent-msg-ids conn-1025) (str "msg-" %)) (range 2 1026)))
        (is (= "msg-2" (first (:sent-msg-order conn-1025))))
        (is (= "msg-1025" (last (:sent-msg-order conn-1025))))))))

(deftest test-prune-closed-agent-tombstones-preserves-diagnostics
  (testing ">64 closed anonymous agent connections are pruned to bounded size while preserving cumulative dropped and stale counts"
    (let [conns-atom (atom {})]
      ;; Create 80 agent connections, simulate drops/stales on each, then close each
      (doseq [i (range 1 81)]
        (let [anon-key [:anon i]
              mock-node {:agent-id i}
              t (long (* i 1000))]
          (mesh/apply-mesh-conn-event! conns-atom anon-key
                                       {:type :accept-started :generation 1 :node mock-node :channel-id 1 :now-ms t})
          ;; 1 drop event
          (mesh/apply-mesh-conn-event! conns-atom anon-key
                                       {:type :invalid-frame :generation 1 :node mock-node :error "bad-frame"})
          ;; 1 stale event
          (mesh/apply-mesh-conn-event! conns-atom anon-key
                                       {:type :on-message :generation 0 :node mock-node})
          ;; close
          (mesh/apply-mesh-conn-event! conns-atom anon-key
                                       {:type :on-close :generation 1 :node mock-node :now-ms (inc t)})))
      ;; Total closed tombstones in @conns-atom must be capped at 64
      (let [closed-entries (filter (fn [[_ c]] (#{:down :failed} (:phase c))) @conns-atom)]
        (is (<= (count closed-entries) 64))
        (is (= 64 (count @conns-atom))))
      ;; Diagnostics summary must preserve all 80 dropped and 80 stale counts exactly
      (let [diag (mesh/mesh-conn-diagnostics-summary {} @conns-atom)]
        (is (= 80 (:conn_dropped diag)))
        (is (= 80 (:conn_stale diag)))))))

(deftest test-agent-gossip-dedup-when-api-send-returns-nil
  (testing "replay-cached-gossip-to-agent! and forward-gossip-to-agents! deduplicate when api/send! returns nil"
    (let [sends (atom [])
          shell-node {:state-atom (atom {:messages {"m1" {:content "hello-1"}
                                                    "m2" {:content "hello-2"}}
                                         :message-epochs {"m1" 1 "m2" 1}})}
          agent-pub "agent-pk-1"
          mock-node {:agent-node 1}
          agent-conns (atom {agent-pub (assoc (mesh/init-mesh-conn-state)
                                              :phase :open
                                              :ok? true
                                              :node mock-node
                                              :channel-id 1)})]
      (with-redefs [api/send! (fn [_node data _cid]
                                (swap! sends conj data)
                                nil)] ; returns nil on success, matching datachannel.api/send!
        ;; 1. Replay cached gossip to agent
        (#'mesh/replay-cached-gossip-to-agent! shell-node agent-conns agent-pub)
        (is (= 2 (count @sends)) "Both messages m1 and m2 should be sent on first replay")
        (is (= #{"m1" "m2"} (mesh/conn-sent-msg-ids (get @agent-conns agent-pub))))

        ;; 2. Second replay to same agent must be a complete no-op (no duplicates!)
        (#'mesh/replay-cached-gossip-to-agent! shell-node agent-conns agent-pub)
        (is (= 2 (count @sends)) "No duplicate messages sent on second replay")

        ;; 3. Forward new gossip to agents
        (let [frozen-m3 (nippy/freeze {:type :receive-gossip :message {:message-id "m3" :content "hello-3"}})]
          (#'mesh/forward-gossip-to-agents! agent-conns frozen-m3 nil)
          (is (= 3 (count @sends)) "m3 sent on first forward")
          (is (contains? (mesh/conn-sent-msg-ids (get @agent-conns agent-pub)) "m3"))

          ;; 4. Forward same m3 again: must be deduped (no duplicate sent!)
          (#'mesh/forward-gossip-to-agents! agent-conns frozen-m3 nil)
          (is (= 3 (count @sends)) "No duplicate gossip forwarded on second call"))))))

(def ^:private gen-cluster-node-snapshot
  (gen/let [role (gen/elements ["validator" "mesh"])
            epoch (gen/choose 10 200)
            fin-epoch (gen/choose 5 50)
            minted (gen/elements [1000 2000 5000])
            burns (gen/choose 100 500)
            bdig (gen/elements ["d-alpha" "d-beta" "d-gamma"])
            failed-rcpts (gen/elements [0 0 0 1 3])
            conn-drop (gen/choose 0 5)
            conn-stale (gen/choose 0 5)
            win-burns (gen/choose 10 50)
            win-takes (gen/choose 0 10)]
    {:statusz {:role role :epoch epoch :notarized epoch :finalized fin-epoch
               :peers "2/2" :supply 18900000000 :minted minted :burns burns
               :finalized_epoch fin-epoch :burn_digest bdig
               :pending_receipts 0 :failed_receipts failed-rcpts
               :conn_dropped conn-drop :conn_stale conn-stale}
     :burnsz {:anchor-epoch fin-epoch
              :window [[(max 0 (dec fin-epoch)) win-burns win-takes]
                       [fin-epoch win-burns win-takes]]}
     :connz {:conn_dropped conn-drop :conn_stale conn-stale}}))

(defspec ^{:doc "Property: Pure cluster convergence evaluator invariants"}
  prop-evaluate-cluster-convergence-invariants 50
  (prop/for-all [snap1 gen-cluster-node-snapshot
                 snap2 gen-cluster-node-snapshot
                 snap3 gen-cluster-node-snapshot]
                (let [snapshots {"node1" snap1 "node2" snap2 "node3" snap3}
                      result (mesh/evaluate-cluster-convergence snapshots)
                      fin-epochs (mapv #(get-in % [1 :statusz :finalized_epoch]) snapshots)
                      min-fin (apply min fin-epochs)
                      max-fin (apply max fin-epochs)
                      expected-skew (- max-fin min-fin)
                      max-failed (apply max (mapv #(get-in % [1 :statusz :failed_receipts]) snapshots))]
                  (and (boolean? (:converged? result))
                       (boolean? (:burn-digest-converged? result))
                       (boolean? (:window-burns-converged? result))
                       (= min-fin (:common-finalized-epoch result))
                       (= expected-skew (:finalized-epoch-skew result))
                       (= max-failed (get-in result [:soak-summary :max_failed_receipts]))
                       (= (<= expected-skew 2) (get-in result [:soak-summary :finality_healthy?]))
                       (= (:converged? result)
                          (and (:window-burns-converged? result)
                               (:burn-digest-converged? result)
                               (<= expected-skew 2)
                               (zero? max-failed)
                               (:accountz-converged? result)))))))

(deftest test-parse-statusz-and-evaluate-cluster-convergence
  (testing "parse-statusz-line parses render-statusz format into typed map"
    (let [line "role=validator epoch=100 head=b-hash notarized=95 finalized=90 peers=2/2 supply=18900000000 minted=5000 burns=250 finalized_epoch=88 burn_digest=d-abc pending_receipts=4 failed_receipts=0 conn_dropped=1 conn_stale=0\n"
          parsed (mesh/parse-statusz-line line)]
      (is (= "validator" (:role parsed)))
      (is (= 100 (:epoch parsed)))
      (is (= "b-hash" (:head parsed)))
      (is (= 95 (:notarized parsed)))
      (is (= 90 (:finalized parsed)))
      (is (= "2/2" (:peers parsed)))
      (is (= 18900000000 (:supply parsed)))
      (is (= 5000 (:minted parsed)))
      (is (= 250 (:burns parsed)))
      (is (= 88 (:finalized_epoch parsed)))
      (is (= "d-abc" (:burn_digest parsed)))
      (is (= 4 (:pending_receipts parsed)))
      (is (= 0 (:failed_receipts parsed)))
      (is (= 1 (:conn_dropped parsed)))
      (is (= 0 (:conn_stale parsed)))))

  (testing "evaluate-cluster-convergence on 3 100% converged nodes"
    (let [statusz-str "role=validator epoch=10 head=genesis notarized=8 finalized=8 peers=2/2 supply=18900000000 minted=0 burns=100 finalized_epoch=8 burn_digest=digest-1 pending_receipts=0 failed_receipts=0 conn_dropped=0 conn_stale=0"
          burn-window [[6 50 0] [7 25 0] [8 25 0]]
          snapshots {"node1" {:statusz statusz-str :burnsz {:anchor-epoch 8 :window burn-window} :connz {:conn_dropped 0 :conn_stale 0}}
                     "node2" {:statusz statusz-str :burnsz {:anchor-epoch 8 :window burn-window} :connz {:conn_dropped 0 :conn_stale 0}}
                     "node3" {:statusz statusz-str :burnsz {:anchor-epoch 8 :window burn-window} :connz {:conn_dropped 0 :conn_stale 0}}}
          res (mesh/evaluate-cluster-convergence snapshots)]
      (is (true? (:converged? res)))
      (is (true? (:window-burns-converged? res)))
      (is (true? (:burn-digest-converged? res)))
      (is (true? (:accountz-converged? res)))
      (is (= 8 (:common-finalized-epoch res)))
      (is (= 0 (:finalized-epoch-skew res)))
      (is (empty? (:epoch-mismatches res)))
      (is (= 0 (:minted-skew res)))
      (is (= 0 (get-in res [:soak-summary :max_failed_receipts])))
      (is (true? (get-in res [:soak-summary :finality_healthy?])))))

  (testing "evaluate-cluster-convergence detects accountz ledger mismatch at same finalized-epoch (fin-epoch-skew == 0)"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}
              :accountz {:accounts {"alice" {:balance 100 :seq 0 :deps []}}}}
          s2 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}
              :accountz {:accounts {"alice" {:balance 90 :seq 0 :deps []}}}}
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (false? (:converged? res)))
      (is (false? (:accountz-converged? res)))))

  (testing "evaluate-cluster-convergence passes with identical accountz (both as EDN string and map)"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}
              :accountz "{:accounts {\"alice\" {:balance 100, :seq 0, :deps []}}}"}
          s2 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}
              :accountz {:accounts {"alice" {:balance 100 :seq 0 :deps []}}}}
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (true? (:converged? res)))
      (is (true? (:accountz-converged? res)))))

  (testing "evaluate-cluster-convergence detects burn window mismatch at ep <= common-finalized-epoch"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[8 100 0] [9 200 0] [10 300 0]]}}
          s2 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[8 100 0] [9 999 0] [10 300 0]]}} ; mismatch at epoch 9!
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (false? (:converged? res)))
      (is (false? (:window-burns-converged? res)))
      (is (= [9] (:epoch-mismatches res)))))

  (testing "evaluate-cluster-convergence detects burn digest mismatch at same finalized-epoch"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}}
          s2 {:statusz {:finalized_epoch 10 :burn_digest "d2" :failed_receipts 0} ; digest mismatch!
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}}
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (false? (:converged? res)))
      (is (false? (:burn-digest-converged? res)))))

  (testing "evaluate-cluster-convergence detects excessive finalized-epoch skew > 2"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}}
          s2 {:statusz {:finalized_epoch 13 :burn_digest "d2" :failed_receipts 0} ; skew = 3!
              :burnsz {:anchor-epoch 13 :window [[10 100 0]]}}
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (false? (:converged? res)))
      (is (= 3 (:finalized-epoch-skew res)))
      (is (false? (get-in res [:soak-summary :finality_healthy?])))))

  (testing "evaluate-cluster-convergence detects failed receipts > 0"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 2} ; failed = 2!
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}}
          s2 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}}
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (false? (:converged? res)))
      (is (= 2 (get-in res [:soak-summary :max_failed_receipts]))))))

(deftest test-evaluate-cluster-convergence-edge-cases
  (testing "Single-node-epoch silence: flags candidate epoch if present on node1 but absent on node2"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[8 100 0] [10 300 0]]}}
          s2 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 300 0]]}} ; silent at epoch 8!
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (false? (:converged? res)))
      (is (false? (:window-burns-converged? res)))
      (is (= [8] (:epoch-mismatches res)))))

  (testing "Fail-closed on unparseable /accountz"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}
              :accountz "not-valid-edn {{"}
          s2 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}
              :accountz {:accounts {"alice" {:balance 100 :seq 0 :deps []}}}}
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (false? (:converged? res)))
      (is (false? (:accountz-converged? res)))))

  (testing "Fail-closed on empty accounts when another node has accounts"
    (let [s1 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}
              :accountz {:accounts {}}}
          s2 {:statusz {:finalized_epoch 10 :burn_digest "d1" :failed_receipts 0}
              :burnsz {:anchor-epoch 10 :window [[10 100 0]]}
              :accountz {:accounts {"alice" {:balance 100 :seq 0 :deps []}}}}
          res (mesh/evaluate-cluster-convergence {"node1" s1 "node2" s2})]
      (is (false? (:converged? res)))
      (is (false? (:accountz-converged? res))))))

(deftest test-unwrap-authenticated-agent-event-spoofing-rejection
  (let [alice-kp (crypto/generate-keypair)
        alice-pub-hex (basalt/bytes->hex (:public alice-kp))
        alice-priv (:private alice-kp)
        bob-kp (crypto/generate-keypair)
        bob-pub-hex (basalt/bytes->hex (:public bob-kp))
        bob-priv (:private bob-kp)]

    (testing ":settle-intent rejects spoofed payer != signer"
      (let [spoofed-intent {:type :settle-intent
                            :payer bob-pub-hex
                            :receiver alice-pub-hex
                            :amount 1000
                            :epoch 1}
            env (mesh/wrap-agent-event spoofed-intent alice-pub-hex alice-priv)]
        (is (nil? (mesh/unwrap-authenticated-agent-event env)))))

    (testing ":settle-intent accepts valid intent matching signer"
      (let [valid-intent {:type :settle-intent
                          :payer alice-pub-hex
                          :receiver bob-pub-hex
                          :amount 1000
                          :epoch 1}
            env (mesh/wrap-agent-event valid-intent alice-pub-hex alice-priv)
            unwrapped (mesh/unwrap-authenticated-agent-event env)]
        (is (some? unwrapped))
        (is (= alice-pub-hex (:sender unwrapped)))
        (is (= alice-pub-hex (:payer unwrapped)))))

    (testing ":on-deliver rejects inner transfer sender != outer signer"
      (let [tf (account/create-transfer bob-priv {:sender bob-pub-hex :receiver alice-pub-hex :amount 100 :seq 1 :deps []})
            payload (vec (.getBytes ^String (pr-str {:transfer (into {} tf)}) "UTF-8"))
            env (mesh/wrap-agent-event {:type :on-deliver :payload payload :message-id "msg-1"} alice-pub-hex alice-priv)]
        (is (nil? (mesh/unwrap-authenticated-agent-event env)))))

    (testing ":on-deliver accepts inner transfer matching outer signer"
      (let [tf (account/create-transfer alice-priv {:sender alice-pub-hex :receiver bob-pub-hex :amount 100 :seq 1 :deps []})
            payload (vec (.getBytes ^String (pr-str {:transfer (into {} tf)}) "UTF-8"))
            env (mesh/wrap-agent-event {:type :on-deliver :payload payload :message-id "msg-1"} alice-pub-hex alice-priv)
            unwrapped (mesh/unwrap-authenticated-agent-event env)]
        (is (some? unwrapped))
        (is (= alice-pub-hex (:sender unwrapped)))))

    (testing ":register-home-set rejects callee != signer"
      (let [spoofed {:type :register-home-set :callee bob-pub-hex :home-nodes [:node1 :node2 :node3] :price 10}
            env (mesh/wrap-agent-event spoofed alice-pub-hex alice-priv)]
        (is (nil? (mesh/unwrap-authenticated-agent-event env)))))

    (testing ":register-home-set accepts callee matching signer"
      (let [valid {:type :register-home-set :callee alice-pub-hex :home-nodes [:node1 :node2 :node3] :price 10}
            env (mesh/wrap-agent-event valid alice-pub-hex alice-priv)
            unwrapped (mesh/unwrap-authenticated-agent-event env)]
        (is (some? unwrapped))
        (is (= alice-pub-hex (:sender unwrapped)))
        (is (= alice-pub-hex (:callee unwrapped)))))

    (testing ":submit-vouchers rejects forged or invalid DeliveryAck signature"
      (let [forged-ack (rendezvous/create-delivery-ack bob-priv alice-pub-hex :node1 1 "offer-hash" 1 10)
            tampered-ack (assoc forged-ack :cumulative-debit 999999)
            env (mesh/wrap-agent-event {:type :submit-vouchers :vouchers [tampered-ack] :epoch 1} alice-pub-hex alice-priv)]
        (is (nil? (mesh/unwrap-authenticated-agent-event env)))))

    (testing ":submit-vouchers accepts valid signed DeliveryAck vouchers"
      (let [valid-ack (rendezvous/create-delivery-ack alice-priv alice-pub-hex :node1 1 "offer-hash" 1 10)
            env (mesh/wrap-agent-event {:type :submit-vouchers :vouchers [valid-ack] :epoch 1} alice-pub-hex alice-priv)
            unwrapped (mesh/unwrap-authenticated-agent-event env)]
        (is (some? unwrapped))
        (is (= alice-pub-hex (:sender unwrapped)))
        (is (= 1 (count (:vouchers unwrapped))))))))



