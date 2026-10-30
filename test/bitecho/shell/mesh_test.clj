(ns bitecho.shell.mesh-test
  "Unit and generative tests for Bitecho mesh, node identity, and transport boundary."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.shell.identity :as identity]
            [bitecho.shell.mesh :as mesh]
            [bitecho.shell.persistence :as persistence]
            [bitecho.state-machine :as sm]
            [clojure.core.async :as async]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.dtls :as dtls])
  (:import [java.io File]
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

(def gen-allowed-agent-event
  "Generates realistic allowed agent events."
  (gen/elements [{:type :receive-gossip :topic "discovery" :data "alpha"}
                 {:type :receive-summary :epoch 1 :summary "digest-1"}
                 {:type :receive-pull-request :missing-ids ["msg-1" "msg-2"]}
                 {:type :register-home-set :client-id "client-1" :home-set ["h1" "h2"]}
                 {:type :receive-offer-header :caller "caller-hex" :offer-id "off-1"}]))

(def gen-disallowed-agent-event
  "Generates disallowed agent events."
  (gen/elements [{:type :receive-propose :block {:epoch 1}}
                 {:type :receive-vote :vote {:epoch 1}}
                 {:type :tick}
                 {:type :custom-injection :data "malicious"}]))

(defspec ^{:doc "Verifies authenticated agent envelope signing, verification, and fail-closed security properties."}
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
                      unwrapped (mesh/unwrap-authenticated-agent-event env)
                      tampered-env (assoc-in env [:event :tampered] tampered-key)
                      wrong-sig-env (assoc env :signature (basalt/bytes->hex (crypto/sign (:private other-kp) (mesh/agent-event-signing-bytes agent-pub (:event env)))))
                      disallowed-env (mesh/wrap-agent-event disallowed-evt agent-pub agent-priv)]
                  (and (= (:type unwrapped) (:type event))
                       (= (:sender unwrapped) agent-pub)
                       (= (vec (:sender-pubkey-bytes unwrapped)) (vec (:public kp)))
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
      (is (str/ends-with? out "\n")))))

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
          (Thread/sleep 150))
        (let [st-a (#'mesh/query-node-state (:shell-node node-a) 1000)
              st-b (#'mesh/query-node-state (:shell-node node-b) 1000)
              st-c (#'mesh/query-node-state (:shell-node node-c) 1000)]
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
          (is (seq (:finalized-blocks st-c))))
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
        (let [evt {:type t :sample "data"}
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
