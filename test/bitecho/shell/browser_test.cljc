(ns bitecho.shell.browser-test
  "Cross-runtime generative tests for the CLJS browser shell boundary (Rules 1-6).
   - Rule 1: Model-based generative property test (prop-browser-shell-lifecycle-state-machine).
   - Rule 4: Single-authority lifecycle state, zero persistent derived liveness.
   - Rule 5: Zero silent failures, counted diagnose effects on stale/dropped events.
   - Browser IndexedDB persistence sanitization & roundtrip.
   - Deterministic multi-peer browser subnet demo verification."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.anchor.core :as anchor]
            #?(:cljs [bitecho.browser-main :as browser-main])
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.browser :as browser]
            [bitecho.state-machine :as state-machine]
            [clojure.string :as str]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Generative Command Generator for Lifecycle State Machine (Rule 1)
;; =============================================================================

(def gen-lifecycle-command
  "Generator for individual shell lifecycle transition commands."
  (gen/let [op (gen/elements [:dial :open :send :message-valid :message-invalid :close :dial-failed :visibility :stale])
            target (gen/elements ["rtc://peer-a" "rtc://peer-b" "rtc://node-1"])
            vis (gen/elements ["visible" "hidden"])
            err-msg (gen/elements ["timeout" "network-error" "peer-reset"])]
    {:op op
     :target target
     :visibility vis
     :error-msg err-msg}))

(def gen-command-sequence
  "Generator for variable-length lifecycle command sequences."
  (gen/vector gen-lifecycle-command 5 35))

(defspec ^{:doc "Model-based property test verifying single-authority reducer transitions (Rule 4),
                 stale-generation callback counted diagnostics (Rule 5), and zero silent failures."}
  prop-browser-shell-lifecycle-state-machine 50
  (prop/for-all [cmds gen-command-sequence]
                (let [initial-state (browser/initial-conn-state {:peer-id "test-peer" :subnet-id "test-subnet"})
                      final-result
                      (reduce
                       (fn [{:keys [conn all-effects valid?] :as acc} cmd]
                         (if-not valid?
                           acc
                           (let [curr-gen (:generation conn)
                                 curr-phase (:phase conn)
                                 event (case (:op cmd)
                                         :dial {:type :dial :target-url (:target cmd)}
                                         :open {:type :open :generation curr-gen :channel :mock-ch}
                                         :send {:type :send :generation curr-gen :envelope {:type :ping :seq 1 :wire-format "fressian-v1"}}
                                         :message-valid {:type :message :generation curr-gen :envelope {:type :pong :wire-format "fressian-v1"}}
                                         :message-invalid {:type :message :generation curr-gen :envelope {:type :bad :wire-format "unsupported-wire-format-xyz"}}
                                         :close {:type :close :generation curr-gen :cause "user-disconnect"}
                                         :dial-failed {:type :dial-failed :generation curr-gen :error (:error-msg cmd)}
                                         :visibility {:type :visibility-change :state (:visibility cmd)}
                                         :stale {:type :message :generation (dec curr-gen) :envelope {:type :stale-payload}})
                                 [new-conn effects] (browser/transition-conn conn event)
                                 new-gen (:generation new-conn)
                                 diag (:diagnostics new-conn)]

                 ;; Rule 4: Monotonic non-decreasing generation
                             (if-not (>= (long new-gen) (long curr-gen))
                               (assoc acc :valid? false :reason :non-monotonic-generation)

                   ;; Rule 4: Single authority - no competing atoms or derived keys in conn
                               (if (or (contains? new-conn :connected?)
                                       (contains? new-conn :connection-error)
                                       (contains? new-conn :ephemeral-priv))
                                 (assoc acc :valid? false :reason :illegal-keys-in-conn)

                     ;; Rule 5: Zero silent failures on stale callbacks
                                 (if (and (= (:op cmd) :stale) (pos? curr-gen))
                                   (let [diag-effect (first (filter #(= (:kind %) :ignored-stale) effects))]
                                     (if-not (and diag-effect
                                                  (pos? (:ignored-stale diag))
                                                  (= (:generation new-conn) curr-gen)
                                                  (= (:phase new-conn) curr-phase))
                                       (assoc acc :valid? false :reason :stale-callback-not-counted)
                                       (assoc acc :conn new-conn :all-effects (into all-effects effects))))

                       ;; Rule 5: Unsupported wire format emits counted diagnose effect
                                   (if (= (:op cmd) :message-invalid)
                                     (if (= curr-phase :open)
                                       (let [diag-effect (first (filter #(= (:kind %) :unsupported-format) effects))]
                                         (if-not (and diag-effect (pos? (:unsupported-format-dropped diag)))
                                           (assoc acc :valid? false :reason :unsupported-format-not-counted)
                                           (assoc acc :conn new-conn :all-effects (into all-effects effects))))
                                       (assoc acc :conn new-conn :all-effects (into all-effects effects)))

                         ;; Normal transition
                                     (assoc acc :conn new-conn :all-effects (into all-effects effects)))))))))
                       {:conn initial-state :all-effects [] :valid? true}
                       cmds)]
                  (:valid? final-result))))

;; =============================================================================
;; Persistence Sanitization & Roundtrip Tests (Rule 4)
;; =============================================================================

(deftest test-persistence-sanitization-and-roundtrip
  (testing "Sanitizes state stripping ephemeral secrets and derived liveness per Rule 4"
    (let [raw-state {:peer-id "node-alice"
                     :ephemeral-priv "super-secret-x25519-seed"
                     :connected? true
                     :connection-error "connection-timed-out"
                     :channel :raw-webrtc-channel
                     :transport :raw-transport-object
                     :sessions {"peer-bob" {:ephemeral-priv "bob-session-secret"
                                            :connected? true
                                            :suite "suite-v1-aes256gcm"
                                            :seq 5}}
                     :burned-ech 100
                     :inbox [{:from "peer-bob" :text "hello"}]}
          sanitized (browser/sanitize-state-for-persistence raw-state)]

      (is (nil? (:ephemeral-priv sanitized)))
      (is (nil? (:connected? sanitized)))
      (is (nil? (:connection-error sanitized)))
      (is (nil? (:channel sanitized)))
      (is (nil? (:transport sanitized)))
      (is (= "node-alice" (:peer-id sanitized)))
      (is (= 100 (:burned-ech sanitized)))
      (is (= 1 (count (:inbox sanitized))))

      ;; Sessions inner map also sanitized
      (let [bob-sess (get-in sanitized [:sessions "peer-bob"])]
        (is (some? bob-sess))
        (is (nil? (:ephemeral-priv bob-sess)))
        (is (nil? (:connected? bob-sess)))
        (is (= "suite-v1-aes256gcm" (:suite bob-sess)))
        (is (= 5 (:seq bob-sess))))

      (testing "Storage persistence roundtrip preserves sanitized state"
        (let [p-result (atom nil)
              l-result (atom nil)]
          (browser/persist-state! sanitized (fn [err res] (reset! p-result (or err res))))
          (is (some? @p-result))
          (is (true? (:ok? @p-result)))

          (browser/load-persisted-state (fn [err res] (reset! l-result (or err res))))
          (is (some? @l-result))
          (is (= (:peer-id sanitized) (:peer-id @l-result)))
          (is (= (:burned-ech sanitized) (:burned-ech @l-result)))
          (is (= (get-in sanitized [:sessions "peer-bob" :suite])
                 (get-in @l-result [:sessions "peer-bob" :suite]))))))))

;; =============================================================================
;; Browser-Only Subnet Demo Invariants Test (Step 10C)
;; =============================================================================

(deftest test-run-browser-subnet-demo-invariants
  (testing "Executes deterministic 3-node browser subnet simulation"
    (let [res (browser/run-browser-subnet-demo)]
      (is (true? (:ok? res)))
      (is (= 3 (:nodes-count res)))
      (is (= "browser-subnet-v1" (:demo res)))
      (is (= "fressian-v1" (:wire-format res)))
      (is (= "suite-v1-aes256gcm" (:crypto-suite res)))
      (is (true? (:autonomous-off? res)))
      (is (= 2 (:messages-exchanged res)))
      (is (= 2000 (:total-burned-ech res)))
      (is (= 2 (:background-throttled-events res)))
      (is (= 1 (:stale-generation-ignored res)))
      (is (= :open (get-in res [:diagnostics :phase]))))))

;; =============================================================================
;; Pure Browser Crypto Primitives Golden Vectors
;; =============================================================================

(deftest test-browser-crypto-boundary-and-pure-fallbacks
  (testing "browser-crypto-boundary implements ICryptoBoundary"
    (let [boundary (browser/browser-crypto-boundary)
          alice-keys (crypto/generate-keypair)
          alice-pub-hex (fressian/bytes->hex (:public-key alice-keys))
          payload {:transfer {:from "alice" :to "bob" :amount 100 :seq 1}}
          signing-payload [alice-pub-hex payload]
          sig (crypto/sign-canonical (:private-key alice-keys) signing-payload)
          env {:type :agent-event
               :agent-pubkey alice-pub-hex
               :event payload
               :signature (fressian/bytes->hex sig)}
          pre-verified (crypto/pre-verify-envelope boundary env)]
      (is (true? (:crypto/verified? pre-verified)))))

  (testing "Pure SHA-512 and RFC 8032 Ed25519 keypair, sign, and verify match RFC 8032 §7.1 test vector 1"
    (let [abc-sha512 (crypto/sha512 "abc")
          seed (fressian/hex->bytes "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
          kp (crypto/pure-ed25519-keypair seed)
          expected-pub-der "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
          expected-sig-hex (str "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
          empty-msg (fressian/hex->bytes "")
          sig (crypto/pure-ed25519-sign (:private kp) empty-msg)]
      (is (= (str "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
             (fressian/bytes->hex abc-sha512)))
      (is (= expected-pub-der (fressian/bytes->hex (:public kp))))
      (is (= expected-sig-hex (fressian/bytes->hex sig)))
      (is (true? (crypto/pure-ed25519-verify (:public kp) empty-msg sig)))
      (is (true? (crypto/verify (:public kp) empty-msg sig)))
      (is (false? (crypto/pure-ed25519-verify (:public kp) (fressian/utf8->bytes "tampered") sig)))))

  (testing "Pure X25519 Montgomery ladder fallback matches expected shared secret"
    (let [alice-priv (fressian/hex->bytes "77076d0a7318a57d3c16c17251525302a50f354c0307c2cb071e649b5c328559")
          bob-pub (fressian/hex->bytes "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
          ss (sealed/pure-x25519-shared-secret alice-priv bob-pub)]
      (is (= "61897f186837199212de3506429b0e74b202b5336b3ee24851147eea9742f211"
             (fressian/bytes->hex ss)))))

  (testing "Pure HMAC-SHA256 and HKDF-SHA256 match RFC 5869 test vectors"
    (let [salt (fressian/hex->bytes "000102030405060708090a0b0c")
          ikm (fressian/hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
          prk (sealed/pure-hkdf-extract salt ikm)
          info (fressian/hex->bytes "f0f1f2f3f4f5f6f7f8f9")
          okm (sealed/pure-hkdf-expand prk info 42)]
      (is (= "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
             (fressian/bytes->hex prk)))
      (is (= "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
             (fressian/bytes->hex okm)))))

  (testing "Pure AES-256-GCM AEAD seals and opens with tamper detection"
    (let [key (fressian/hex->bytes "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
          nonce (fressian/hex->bytes "000000000000000000000001")
          pt (fressian/utf8->bytes "Deterministic pure AES-256-GCM test in CLJS")
          aad (fressian/utf8->bytes "bitecho-browser-aad")
          ct (sealed/pure-aes-gcm-seal key nonce pt aad)
          opened (sealed/pure-aes-gcm-open key nonce ct aad)]
      (is (some? ct))
      (is (= (fressian/bytes->utf8 opened) "Deterministic pure AES-256-GCM test in CLJS"))
      ;; Tamper detection: modifying 1 byte causes verification failure (nil)
      (let [tampered (let [b (fressian/concat-bytes ct (fressian/hex->bytes ""))]
                       #?(:clj (aset-byte ^bytes b 0 (unchecked-byte (bit-xor (aget ^bytes b 0) 0x01)))
                          :cljs (aset b 0 (bit-xor (int (aget b 0)) 0x01)))
                       b)]
        (is (nil? (sealed/pure-aes-gcm-open key nonce tampered aad))))))

  (testing "Recursive persistence sanitizer strips all private keys, x25519, seeds, and session keys at all nesting levels"
    (let [node-state {:peer-id "browser-test"
                      :keypair {:public-key "pub" :private-key "SECRET-ED25519-PRIV"}
                      :x25519 {:public-key "xpub" :private-key "SECRET-X25519-PRIV"}
                      :seed "SECRET-SEED"
                      :privkey-bytes "SECRET-PRIVKEY-BYTES"
                      :cold-privkey "SECRET-COLD-PRIV"
                      :conn {:phase :open :generation 3}
                      :active-channels {"node1" :mock-dc}
                      :light-state {:pubkey "pub-hex"
                                    :private-key "NESTED-PRIV"
                                    :sessions {"sess-1" {:peer "axiom"
                                                         :status :open
                                                         :ephemeral-priv "SECRET-EPH-PRIV"
                                                         :tx-key "SECRET-TX-KEY"
                                                         :rx-key "SECRET-RX-KEY"
                                                         :session-keys {:tx "k1" :rx "k2"}
                                                         :shared-secret "SECRET-SHARED"}}}}
          sanitized (browser/sanitize-state-for-persistence node-state)]
      (is (nil? (:keypair sanitized)))
      (is (nil? (:x25519 sanitized)))
      (is (nil? (:seed sanitized)))
      (is (nil? (:privkey-bytes sanitized)))
      (is (nil? (:cold-privkey sanitized)))
      (is (nil? (:conn sanitized)))
      (is (nil? (:active-channels sanitized)))
      (is (nil? (get-in sanitized [:light-state :private-key])))
      (is (= :open (get-in sanitized [:light-state :sessions "sess-1" :status])))
      (is (nil? (get-in sanitized [:light-state :sessions "sess-1" :ephemeral-priv])))
      (is (nil? (get-in sanitized [:light-state :sessions "sess-1" :tx-key])))
      (is (nil? (get-in sanitized [:light-state :sessions "sess-1" :rx-key])))
      (is (nil? (get-in sanitized [:light-state :sessions "sess-1" :session-keys])))
      (is (nil? (get-in sanitized [:light-state :sessions "sess-1" :shared-secret])))))

  (testing "canonical-key-name converts camelCase, snake_case, and kebab-case"
    (is (= "seed-bytes" (browser/canonical-key-name :seedBytes)))
    (is (= "seed-bytes" (browser/canonical-key-name "seed_bytes")))
    (is (= "seed-bytes" (browser/canonical-key-name :seed-bytes)))
    (is (= "privkey-bytes" (browser/canonical-key-name :privkeyBytes)))
    (is (= "private-key" (browser/canonical-key-name "privateKey")))
    (is (= "private-key" (browser/canonical-key-name :private_key)))
    (is (= "user-handle" (browser/canonical-key-name :userHandle)))
    (is (= "raw-id" (browser/canonical-key-name "raw_id")))
    (is (= "prf-output" (browser/canonical-key-name :prfOutput)))
    (is (= "backup-seed" (browser/canonical-key-name "backupSeed")))
    (is (= "first" (browser/canonical-key-name :first)))
    (is (= "eval" (browser/canonical-key-name :eval))))

  (testing "forbidden-persistence-key? recognizes all casing variants"
    (doseq [k [:seedBytes "seed_bytes" :seed-bytes
               :privkeyBytes "privkey_bytes" :privkey-bytes
               :privateKey "private_key" :private-key
               :coldPrivkey "cold_privkey" :cold-privkey
               :userHandle "user_handle" :user-handle
               :rawId "raw_id" :raw-id
               :prfOutput "prf_output" :prf-output
               :backupSeed "backup_seed" :backup-seed
               :mnemonic "mnemonic"
               :first "first"
               :eval "eval"
               :ephemeralPriv "ephemeral_priv" :ephemeral-priv
               :sharedSecret "shared_secret" :shared-secret
               :sessionKeys "session_keys" :session-keys
               :txKey "tx_key" :tx-key
               :rxKey "rx_key" :rx-key
               :connected? "connected?"
               :connectionError "connection_error" :connection-error
               :lastError "last_error" :last-error]]
      (is (true? (browser/forbidden-persistence-key? k)) (str "Should be forbidden: " k)))
    (is (false? (browser/forbidden-persistence-key? :public-key)))
    (is (false? (browser/forbidden-persistence-key? :pubkey)))
    (is (false? (browser/forbidden-persistence-key? :node-id)))
    (is (false? (browser/forbidden-persistence-key? "address"))))

  (testing "Sanitization recursively purges sensitive variants inside maps, vectors, sets, and lists"
    (let [input {:safe-field "safe"
                 :seedBytes "SECRET-1"
                 "private_key" "SECRET-2"
                 :nested-map {:userHandle "SECRET-3"
                              :keep-me 42
                              "raw_id" "SECRET-4"}
                 :nested-vec [{:prfOutput "SECRET-5" :val 1}
                              {:backupSeed "SECRET-6" :val 2}]
                 :nested-set #{{:first "SECRET-7" :id :a}
                               {:eval "SECRET-8" :id :b}}
                 :nested-list (list {:mnemonic "SECRET-9" :id :c})}
          sanitized (browser/sanitize-state-for-persistence input)]
      (is (= "safe" (:safe-field sanitized)))
      (is (nil? (:seedBytes sanitized)))
      (is (nil? (get sanitized "private_key")))
      (is (= {:keep-me 42} (:nested-map sanitized)))
      (is (= [{:val 1} {:val 2}] (:nested-vec sanitized)))
      (is (= #{{:id :a} {:id :b}} (:nested-set sanitized)))
      (is (= [{:id :c}] (vec (:nested-list sanitized))))))

  (testing "Allowlist-only persistence (allowed-persistence-key?) strips all known secret/ephemeral keys and unlisted keys while preserving the complete state schema (R9-M1, R9-L1, R9-L3)"
    (let [known-secret-and-ephemeral-stems
          ["private" "private-key" "private-key-bytes" "private-key-hex"
           "privkey" "privkey-bytes" "privkey-hex"
           "seed" "seed-bytes" "seed-hex" "backup-seed" "backup-seed-bytes" "backup-seed-hex"
           "secret" "secret-key" "shared-secret" "shared-secret-bytes"
           "session-key" "session-keys" "session-id"
           "ephemeral-priv" "ephemeral-privkey" "caller-x25519-priv" "callee-x25519-priv"
           "x25519" "x25519-priv" "x25519-privkey" "x25519-private-key"
           "cold-privkey" "cold-private-key" "keypair" "tx-key" "rx-key" "tx" "rx"
           "prf" "prf-output" "user-handle" "raw-id" "credential-id"
           "ice-pwd" "pwd" "password" "passphrase" "mnemonic" "first" "eval"
           "connected?" "connected" "connection-error" "conn-diagnostics" "conn-atom" "conn"
           "channel" "active-channels" "connections" "transport" "socket" "last-error"]
          to-camel (fn [s]
                     (let [parts (str/split s #"-")]
                       (apply str (first parts) (map str/capitalize (rest parts)))))
          to-pascal (fn [s]
                      (apply str (map str/capitalize (str/split s #"-"))))
          casings (fn [s]
                    [s
                     (str/replace s "-" "_")
                     (to-camel s)
                     (to-pascal s)
                     (str/upper-case (str/replace s "-" "_"))
                     (str/replace s "-" "")])
          all-forbidden-keys (vec (distinct (for [stem known-secret-and-ephemeral-stems
                                                  cased (casings stem)
                                                  k [cased (keyword cased) (symbol cased)]]
                                              k)))
          unlisted-keys [:kennwort :mot-de-passe :contrasena :cle-privee :wachtwoord
                         :passw0rd :s3cr3t :unlisted-custom-credential
                         :sess-kennwort :kennwort-pubkey]
          independent-allowed-schema
          #{"pubkey" "pubkeys" "public-key" "public-keys" "public" "public-hex"
            "pubkey-hex" "public-key-hex" "pubkey-bytes" "public-key-bytes"
            "x25519-pubkey" "x25519-public-key" "ed25519-pubkey" "ed25519-public-key"
            "ed25519" "xpub" "ypub" "zpub" "tpub" "vpub" "upub" "vk" "verification-key"
            "peer-pubkey" "agent-pubkey" "hot-pubkey" "anchor-pubkey" "authority-pubkey"
            "directory-pubkey" "trusted-directory-pubkey" "caller-pubkey" "callee-pubkey"
            "treasury-pubkey" "custody-pubkey" "alice-pubkey" "bob-pubkey" "carol-pubkey"
            "validator-pubkey" "node-pubkey" "sender-pubkey" "recipient-pubkey" "remote-pubkey"
            "local-pubkey" "target-pubkey" "signer-pubkey" "owner-pubkey" "issuer-pubkey"
            "subject-pubkey" "delegate-pubkey" "ephemeral-pubkey" "caller-x25519-pub" "callee-x25519-pub"
            "caller-x25519" "callee-x25519" "coordinator-pubkey" "expected-agent-pubkey" "expected-pubkey"
            "prev-pubkey" "sender-pubkey-bytes" "key-protection"
            "ephemeral-pub" "caller-ephemeral-pub" "callee-ephemeral-pub" "spki" "cose-key" "cose-pubkey"
            "key-mode" "keys-verified?" "keys-verified" "key-count" "keys-count"
            "key-type" "key-types" "key-id" "key-ids" "api-key-id" "api-key-ids"
            "session-key-id" "signing-key-id" "encryption-key-id" "master-key-id" "public-key-id"
            "key-rotation" "key-rotations" "key-rotation-epoch" "key-rotation-interval" "key-rotation-period"
            "key-schedule" "key-policy" "key-ceremony" "key-holder" "key-owner" "key-age" "key-ttl" "key-epoch"
            "key-algorithm" "key-algo" "key-metadata"
            "key-length" "key-size" "key-bits" "key-format" "key-usage" "key-usages" "key-ops"
            "key-version" "key-index" "key-name" "key-label" "key-path" "key-uri" "key-url"
            "key-status" "key-state" "key-created-at" "key-expires-at" "key-expired?" "key-rotated-at"
            "key-fingerprint" "key-hash" "primary-key" "foreign-key" "sort-key" "partition-key"
            "routing-key" "cache-key" "lookup-key" "safe-key" "innocent-key" "control-key" "allowed-key"
            "resident-key" "require-resident-key" "pub-key-cred-params" "cred-props"
            "cred-protect" "credential-protection-policy" "allow-credentials" "backup-available?"
            "authenticator-selection" "authenticator-attachment" "authenticator-type"
            "sessions" "session-count" "sessions-count" "session-state" "session-status"
            "session-role" "session-epoch" "session-timeout" "session-duration"
            "session-created-at" "session-expires-at" "session-active?" "is-session-active"
            "channel-count" "channels-count" "channel-id" "channel-name" "channel-type"
            "channel-state" "channel-status" "channel-capacity" "channel-balance"
            "ice-creds"
            "a" "b" "c" "x" "y" "z" "k" "v" "foo" "bar" "baz" "qux"
            "ok" "ok?" "safe" "safe-field" "safe-val" "safe-value" "safe-data" "safe-map"
            "keep" "keep-me" "innocent" "control" "allowed"
            "harmless" "benign" "normal" "regular" "pub" "label" "name" "title" "description"
            "text" "message" "msg" "memo" "note" "notes" "comment" "summary" "count" "total" "index" "idx"
            "num" "number" "amount" "burn-amount" "balance" "spendable" "price" "burn" "burn-floor" "fee"
            "epoch" "epoch-initialized?" "created-epoch" "issued-epoch" "expires-epoch" "finalized-epoch" "revoked-epoch"
            "seq" "tx-seq" "acked-seq" "rx-high-seq" "contiguous-rx-seq" "transfer-seq" "intent-seq" "voucher-seqs"
            "unacked-count" "replays-deduped" "outbox-evicted" "outbox-order" "deps"
            "replay-window" "highest-seq" "seen" "window-size"
            "status" "state" "phase" "generation" "visibility-state" "role" "mode" "type" "kind" "version" "protocol-version"
            "suite" "crypto-suite" "crypto-suites" "format" "wire-format" "wire-protocol" "wire-version-diagnostics"
            "supported-formats" "min-supported" "max-supported"
            "unsupported-dropped" "unsupported-format-dropped" "last-unsupported-version" "last-unsupported-format"
            "background-throttled-events" "ignored-stale" "dropped" "failover-count" "diagnostics-buffered"
            "validator-cursor" "validator-id" "diagnostics"
            "peer" "peers" "peer-id" "peer-petname" "petname" "petnames" "petnames-count"
            "node" "nodes" "node-id" "nodes-count" "node1" "node2" "node3" "ns1" "ns2" "ns3"
            "subnet" "subnet-id" "domain" "network" "address" "anchor-address" "hot-address"
            "ip" "port" "agent-port" "agent-tcp-port" "ingress-host" "ingress-port"
            "host" "hostname" "url" "uri" "path" "fingerprint" "ice-ufrag"
            "created-at" "updated-at" "expires-at" "queued-at" "accepted-at" "registered-at" "logged-at"
            "timestamp" "time" "date" "duration" "timeout" "direction" "sender" "recipient" "payer" "receiver"
            "caller" "callee" "from" "to" "from-petname"
            "offer" "offers" "offer-id" "offer-hash" "pending-offers" "pending-offers-count"
            "outbound-rendezvous" "pending-rendezvous" "pending-rendezvous-count" "pending-rendezvous-accepts"
            "offers-approved" "offers-denied" "last-denied-reason"
            "service-offers" "service-id" "service-types" "rendezvous-policy" "auto-accept" "auto-accept?" "min-burn"
            "allowlist" "home-node" "home-nodes" "home-set"
            "inbox" "inbox-count" "outbox" "chat-history" "messages" "messages-exchanged" "messages-received" "last-message"
            "msg-payload" "gossip-env" "message-id" "payload" "payload-hex" "frame-type" "nonce" "ciphertext" "sealed-frame"
            "burned-ech" "total-burned-ech" "alice-burned" "bob-burned" "vouchers" "vouchers-count" "voucher-id"
            "escrows" "escrows-count" "escrow-id" "deliverable-hash" "last-transfer-hash"
            "settled-epoch" "net-amount" "settlement-mode" "take-amount" "take-burned"
            "refund-amount" "refund-reason" "payer-signature" "preimage" "deliverable"
            "release-submitted" "refund-submitted" "settled-escrow-ids" "settled-escrow-order" "canonical-escrows"
            "payer-petname" "receiver-petname" "recipient-petname" "caller-petname" "callee-petname"
            "chain-state-snapshots" "max-outbox-size" "ufrag" "spent" "delivery-ack" "header"
            "initial-text" "topic" "cumulative-debit" "selected-suite" "ack-seq" "seen-seqs"
            "receipt-id" "nickname" "mailbox" "pop-signature" "directory-signature" "rotation-signature"
            "responsive?" "latency-ms" "price-max" "subnets" "dac-001"
            "local-accounting" "accounting" "scope" "scopes" "permissions" "max-spend" "max-spend-per-epoch"
            "dac" "dac-id" "dac-spend" "active-dac" "active-dac-id" "revoked-dacs" "revoked-dacs-count" "revoked-dac-ids"
            "revocation" "revocation-reason" "denial-reason" "reason"
            "agent" "agents" "agent-id" "supervised-agents" "supervised-agents-count" "supervised-agent-revoked"
            "activity-log" "activity-count" "team-call-subnet" "topic-name" "ai-inference"
            "directory-cache" "directory-cache-count" "bootstrap" "signature"
            "domain-a" "domain-a-verified?" "domain-b" "domain-b-verified?"
            "advertisement-verified?" "inter-subnet-routed?" "subnet-mismatch-dropped" "unroutable-dropped"
            "autonomous" "autonomous?" "autonomous-off?" "economy-enabled" "economy-enabled?"
            "light-state" "account" "accounts" "identity" "recovery-source"
            "fido-strength" "fido-authenticator" "fido-security" "strength" "score" "verification-status"
            "warning" "yubico-enrollment" "aaguid" "up?" "uv?" "be?" "bs?" "at?" "ed?" "flags" "sign-count"
            "rp-id-hash-hex" "strength-hint" "fmt" "att-stmt"
            "vendor" "user-verification-details" "attestation-types" "certification-level"
            "trust-boundary" "origin-scoping" "rp" "rp-id" "rp-name" "user" "user-id" "username" "display-name" "email"
            "challenge" "alg"
            "user-verification" "attestation" "extensions"
            "extractable" "extractable?" "usages" "algorithm" "named-curve" "hash" "length"
            "val" "value" "id" "ids" "item" "items" "list" "vec" "set" "map" "data" "meta" "metadata"
            "config" "options" "settings" "profile" "result" "results" "response" "effect" "effects" "event" "events" "cmd" "command"
            "nested" "nested-map" "nested-vec" "nested-set" "nested-list" "child" "children" "parent" "root" "leaf" "branch"
            "level" "depth" "size" "width" "height" "offset" "limit" "page" "cursor" "tag" "tags" "flag"
            "enabled" "enabled?" "active" "active?" "verified" "verified?" "valid" "valid?" "open" "closed" "idle" "dialing"
            "mesh-connected" "connected-nodes" "demo" "stale-generation-ignored" "in-memory?" "bytes-stored"
            "sess-1" "sess-2" "axiom" "nexus" "alice" "bob" "carol"
            "peer-alice" "peer-bob" "peer-carol" "node-alice" "node-bob" "node-carol"
            "browser-alice" "browser-bob" "browser-carol" "rt-node" "browser-test" "browser-guard-test" "test-peer" "test-subnet" "global"
            "sub-agent-alpha" "worker-node-1" "off-demo-1" "core-devs"}
          test-map (into {}
                         (concat (map (fn [k] [k "SENSITIVE"]) all-forbidden-keys)
                                 (map (fn [k] [k "UNLISTED"]) unlisted-keys)
                                 (map (fn [k] [k "SCHEMA-OK"]) independent-allowed-schema)))
          sanitized (browser/sanitize-state-for-persistence test-map)
          survivors (remove independent-allowed-schema (keys sanitized))
          false-positives (remove #(contains? sanitized %) independent-allowed-schema)]
      (is (= independent-allowed-schema browser/allowed-persistence-keys))
      (is (every? #(and (browser/allowed-persistence-key? %)
                        (not (browser/forbidden-persistence-key? %)))
                  browser/allowed-persistence-keys))
      (is (every? #(false? (browser/allowed-persistence-key? %)) all-forbidden-keys))
      (is (every? #(false? (browser/allowed-persistence-key? %)) unlisted-keys))
      (is (empty? survivors))
      (is (empty? false-positives))
      ;; R9-L1: 2-tuple [string int] branch requires first element to satisfy allowed-persistence-key?
      (is (false? (browser/allowed-persistence-key? ["kennwort" 5])))
      (is (false? (browser/allowed-persistence-key? ["passw0rd" 5])))
      (is (false? (browser/allowed-persistence-key? ["mot-de-passe" 5])))
      (is (false? (browser/allowed-persistence-key? ["private-key" 5])))
      (is (true? (browser/allowed-persistence-key? ["node1" 42])))
      (is (true? (browser/allowed-persistence-key? ["dac-001" 42]))))

    (testing "R8-M2, R9-M1, R9-L3: Real-state roundtrip preserves all 35 init-light-state keys, locked/released/refunded escrows from state-machine, sessions, replay-window, outbox, voucher-seqs, and init-anchor-state while stripping secrets"
      (let [pub1 "302a300506032b65700321009b33a9ebd1866d6db419edabe2de9ee74c884dc86b4214f60e3a26f04cbd9cfc"
            pub2 "302a300506032b6570032100b53afd55492fe17fca9d0ef0e07b367bf8333490e43b4ecd3610c12c8e6a79f8"
            sid "91e4541f458367db92b629c77a07633d4110889590ea707f1c3f740d44eefb68"
            esc-id-locked "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            esc-id-released "a1b2c3d498fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
            esc-id-refunded "f5e6d7c898fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b857"
            deliv-hash "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
            ;; R9-M1 & R9-L3: Construct locked, released, and refunded escrows using real state-machine reducer
            sm0 {:epoch 40
                 :ledger {pub1 {:balance 10000 :seq 0 :deps []}
                          pub2 {:balance 1000 :seq 0 :deps []}}}
            sm1 (:state (state-machine/handle-event sm0 {:type :lock-intent
                                                         :escrow-id esc-id-locked
                                                         :payer pub1
                                                         :receiver pub2
                                                         :amount 500
                                                         :deliverable-hash deliv-hash
                                                         :created-epoch 40
                                                         :expires-epoch 60
                                                         :sender pub1}))
            sm2 (:state (state-machine/handle-event sm1 {:type :lock-intent
                                                         :escrow-id esc-id-released
                                                         :payer pub1
                                                         :receiver pub2
                                                         :amount 1000
                                                         :deliverable-hash deliv-hash
                                                         :created-epoch 40
                                                         :expires-epoch 60
                                                         :sender pub1}))
            sm3 (:state (state-machine/handle-event sm2 {:type :release-intent
                                                         :escrow-id esc-id-released
                                                         :epoch 42
                                                         :sender pub1}))
            sm4 (:state (state-machine/handle-event sm3 {:type :lock-intent
                                                         :escrow-id esc-id-refunded
                                                         :payer pub1
                                                         :receiver pub2
                                                         :amount 800
                                                         :deliverable-hash deliv-hash
                                                         :created-epoch 40
                                                         :expires-epoch 45
                                                         :sender pub1}))
            sm5 (:state (state-machine/handle-event sm4 {:type :refund-intent
                                                         :escrow-id esc-id-refunded
                                                         :epoch 46
                                                         :sender pub2}))
            locked-escrow (assoc (get-in sm5 [:escrows esc-id-locked]) :finalized-epoch nil :subnet-id "global")
            released-escrow (get-in sm5 [:escrows esc-id-released])
            refunded-escrow (get-in sm5 [:escrows esc-id-refunded])
            base-light (light-core/init-light-state {:pubkey-hex pub1}
                                                    {:economy-enabled? true
                                                     :burn-floor 100
                                                     :autonomous? false})
            populated-light (assoc base-light
                                   :epoch 42
                                   :epoch-initialized? true
                                   :account {:balance 9500 :spendable 9000}
                                   :dac-spend {["dac-001" 42] 500
                                               sid {:epoch 42 :spent 500}}
                                   :home-set {:nodes ["node1" "node2" "node3"] :price 10 :signature "sig-hex"}
                                   :ice-creds {"node1" {:ice-ufrag "1ec0ae74" :ice-pwd "SECRET-ICE-PWD"}}
                                   :transfer-seq 7
                                   :intent-seq 3
                                   :voucher-seqs {["node1" 42] 2
                                                  [sid 42] 1}
                                   :last-transfer-hash deliv-hash
                                   :outbound-rendezvous {sid {:peer pub2 :price 10 :burn 100 :epoch 42
                                                              :caller-x25519-priv "SECRET-CALLER-X25519"}}
                                   :pending-rendezvous-accepts [sid]
                                   :escrows {esc-id-locked locked-escrow
                                             esc-id-released released-escrow
                                             esc-id-refunded refunded-escrow}
                                   :sessions {sid {:peer pub2
                                                   :role :caller
                                                   :status :open
                                                   :suite "suite-v1-aes256gcm"
                                                   :tx-seq 12
                                                   :acked-seq 11
                                                   :rx-high-seq 9
                                                   :contiguous-rx-seq 9
                                                   :replay-window {:highest-seq 9
                                                                   :seen #{8 9}
                                                                   :window-size 64}
                                                   :outbox {12 {:seq 12
                                                                :burn 100
                                                                :msg-payload {:protocol-version 1
                                                                              :suite "suite-v1-aes256gcm"
                                                                              :seq 12
                                                                              :nonce "000102030405060708090a0b"
                                                                              :ciphertext "deadbeef"}
                                                                :gossip-env {:type :gossip-message
                                                                             :frame-type :session-message
                                                                             :message-id "msg-12"
                                                                             :burn-amount 100
                                                                             :payload "cafebabe"
                                                                             :payload-hex "cafebabe"}}}
                                                   :outbox-order [12]
                                                   :replays-deduped 1
                                                   :outbox-evicted 0
                                                   :subnet-id "global"
                                                   :ephemeral-priv "SECRET-EPH-PRIV"
                                                   :caller-x25519-priv "SECRET-CALLER-PRIV"
                                                   :callee-x25519-priv "SECRET-CALLEE-PRIV"
                                                   :shared-secret "SECRET-SHARED"
                                                   :session-keys {:tx "SECRET-TX" :rx "SECRET-RX"}}})
            sanitized-light (browser/sanitize-state-for-persistence populated-light)
            base-anchor (anchor/init-anchor-state {:pubkey pub1} {:privkey-bytes "SECRET-ANCHOR-PRIV"})
            sanitized-anchor (browser/sanitize-state-for-persistence base-anchor)
            base-conn (browser/initial-conn-state {:peer-id "node1" :subnet-id "global"})
            sanitized-conn (browser/sanitize-state-for-persistence base-conn)
            ;; R9-L3: Recursively collect all keys from real code-constructed state shapes
            collect-keys (fn collect-keys [x]
                           (cond
                             (map? x) (into (set (keys x)) (mapcat collect-keys (vals x)))
                             (coll? x) (into #{} (mapcat collect-keys x))
                             :else #{}))
            intentional-drops #{:privkey-bytes :caller-x25519-priv :callee-x25519-priv :ephemeral-priv
                                :tx-key :rx-key :shared-secret :session-keys :tx :rx :ice-pwd :pwd
                                :session-id :channel :transport :last-error}
            real-code-keys (disj (into #{} (concat (collect-keys base-light)
                                                   (collect-keys populated-light)
                                                   (collect-keys base-anchor)
                                                   (collect-keys base-conn)
                                                   (collect-keys (:escrows sm5))))
                                 :privkey-bytes :caller-x25519-priv :callee-x25519-priv :ephemeral-priv
                                 :tx-key :rx-key :shared-secret :session-keys :tx :rx :ice-pwd :pwd
                                 :session-id :channel :transport :last-error)
            loaded-light (atom nil)]
        (browser/persist-state! populated-light nil)
        (browser/load-persisted-state (fn [_err st] (reset! loaded-light st)))
        ;; R9-L3: Every non-secret key produced by real state constructors and reducers is allowed
        (is (every? browser/allowed-persistence-key? real-code-keys)
            (str "Disallowed real-code keys: " (pr-str (remove browser/allowed-persistence-key? real-code-keys))))
        (is (every? intentional-drops
                    (remove browser/allowed-persistence-key?
                            (concat (collect-keys base-light)
                                    (collect-keys populated-light)
                                    (collect-keys base-anchor)
                                    (collect-keys base-conn)))))
        ;; All 35 top-level init-light-state keys and all non-secret init-anchor-state / initial-conn-state keys survive intact
        (is (= 35 (count (keys base-light))))
        (is (= (set (keys base-light)) (set (keys sanitized-light))))
        (is (= (set (keys base-light)) (set (keys @loaded-light))))
        (is (= (disj (set (keys base-anchor)) :privkey-bytes)
               (set (keys sanitized-anchor))))
        (is (= (disj (set (keys base-conn)) :channel :transport)
               (set (keys sanitized-conn))))
        ;; Non-secret nested structures survive intact
        (is (= {["dac-001" 42] 500
                sid {:epoch 42 :spent 500}}
               (:dac-spend @loaded-light)))
        (is (= {:nodes ["node1" "node2" "node3"] :price 10 :signature "sig-hex"} (:home-set @loaded-light)))
        (is (= {"node1" {:ice-ufrag "1ec0ae74"}} (:ice-creds @loaded-light)))
        (is (= 7 (:transfer-seq @loaded-light)))
        (is (= 3 (:intent-seq @loaded-light)))
        (is (= {["node1" 42] 2
                [sid 42] 1}
               (:voucher-seqs @loaded-light)))
        (is (= deliv-hash (:last-transfer-hash @loaded-light)))
        (is (= [sid] (:pending-rendezvous-accepts @loaded-light)))
        (is (= {:peer pub2 :price 10 :burn 100 :epoch 42}
               (get-in @loaded-light [:outbound-rendezvous sid])))
        ;; R9-M1: Locked, settled (:released), and refunded (:refunded) escrows survive with all fields intact
        (is (= :locked (:status locked-escrow)))
        (is (= :released (:status released-escrow)))
        (is (= 42 (:settled-epoch released-escrow)))
        (is (pos? (:take-amount released-escrow)))
        (is (pos? (:net-amount released-escrow)))
        (is (= :payer-authorized (:settlement-mode released-escrow)))
        (is (= :refunded (:status refunded-escrow)))
        (is (= 46 (:settled-epoch refunded-escrow)))
        (is (= 800 (:refund-amount refunded-escrow)))
        (is (= :receiver-voluntary (:refund-reason refunded-escrow)))
        (is (= locked-escrow (get-in @loaded-light [:escrows esc-id-locked])))
        (is (= released-escrow (get-in @loaded-light [:escrows esc-id-released])))
        (is (= refunded-escrow (get-in @loaded-light [:escrows esc-id-refunded])))
        ;; Session record preserves replay-window, contiguous-rx-seq, outbox-order, and outbox while stripping secrets
        (let [sess (get-in @loaded-light [:sessions sid])]
          (is (= pub2 (:peer sess)))
          (is (= :caller (:role sess)))
          (is (= :open (:status sess)))
          (is (= 12 (:tx-seq sess)))
          (is (= 11 (:acked-seq sess)))
          (is (= 9 (:rx-high-seq sess)))
          (is (= 9 (:contiguous-rx-seq sess)))
          (is (= {:highest-seq 9 :seen #{8 9} :window-size 64} (:replay-window sess)))
          (is (= [12] (:outbox-order sess)))
          (is (= (get-in populated-light [:sessions sid :outbox 12])
                 (get-in sess [:outbox 12])))
          (is (nil? (:ephemeral-priv sess)))
          (is (nil? (:caller-x25519-priv sess)))
          (is (nil? (:callee-x25519-priv sess)))
          (is (nil? (:shared-secret sess)))
          (is (nil? (:session-keys sess))))))

    (let [roundtrip-input {:peer-id "rt-node"
                           :x25519-pubkey "PUB-X25519-OK"
                           :x25519Pubkey "PUB-X25519-CAMEL-OK"
                           :public-key "PUB-ED25519-OK"
                           :key-count 2
                           :api-key-id "API-KEY-ID-OK"
                           :key-rotation "ROTATION-OK"
                           :privateKeyBytes "LEAK-1"
                           :x25519Privkey "LEAK-2"
                           :x25519-private-key "LEAK-3"
                           :api-key "LEAK-4"
                           :jwt "LEAK-5"
                           :access-token "LEAK-6"
                           :session-token "LEAK-7"
                           :passcode "LEAK-8"
                           :kek "LEAK-9"
                           :recovery-code "LEAK-10"
                           :session-id "LEAK-11"
                           :walletkey "LEAK-12"
                           :session-handle "LEAK-13"
                           :entropy "LEAK-14"
                           :xprv "LEAK-15"
                           :tprv "LEAK-16"
                           :wif "LEAK-17"
                           :recovery-phrase "LEAK-18"
                           :backup-phrase "LEAK-19"
                           :recovery-words "LEAK-20"
                           :pk "LEAK-21"
                           :pw "LEAK-22"
                           :pass "LEAK-23"
                           :pepper "LEAK-24"
                           :derivation-path "LEAK-25"
                           :pkcs8 "LEAK-26"
                           :pkcs12 "LEAK-27"
                           :password-hint "LEAK-28"
                           :refresh-code "LEAK-29"
                           :email-code "LEAK-30"
                           :private-key-id "LEAK-31"
                           :secret-key-id "LEAK-32"
                           :passkey-rotation "LEAK-33"
                           :key-backup "LEAK-34"
                           :otpauth-url "LEAK-35"
                           :session-ticket "LEAK-36"
                           :puk "LEAK-37"
                           :service-account-json "LEAK-38"
                           :dotenv "LEAK-39"
                           :brainwallet "LEAK-40"
                           :recovery-sentence "LEAK-41"
                           :backup-file "LEAK-42"
                           :nested {:privateKeyBytes "LEAK-43"
                                    :x25519Privkey "LEAK-44"
                                    :api-token "LEAK-45"
                                    :session-handle "LEAK-46"
                                    :refresh-code "LEAK-47"
                                    :key-backup "LEAK-48"
                                    :private-key-id "LEAK-49"
                                    :otpauth-url "LEAK-50"
                                    :x25519-pubkey "NESTED-PUB-OK"
                                    :safe-val 99}}
          loaded-atom (atom nil)]
      (browser/persist-state! roundtrip-input nil)
      (browser/load-persisted-state (fn [_err st] (reset! loaded-atom st)))
      (is (= {:peer-id "rt-node"
              :x25519-pubkey "PUB-X25519-OK"
              :x25519Pubkey "PUB-X25519-CAMEL-OK"
              :public-key "PUB-ED25519-OK"
              :key-count 2
              :api-key-id "API-KEY-ID-OK"
              :key-rotation "ROTATION-OK"
              :nested {:x25519-pubkey "NESTED-PUB-OK"
                       :safe-val 99}}
             @loaded-atom)))))

#?(:cljs
   (deftest browser-main-accept-offer-and-send-sealed-message-guards-test
     (testing "accept-offer and send-sealed-message nil/blank/1-arity/fallback argument guards and happy path (R5-L1, R6-L6)"
       (let [node-atom (browser-main/init-node {:peer-id "browser-guard-test"})
             caller-kp (crypto/generate-keypair)
             caller-x (sealed/generate-x25519-keypair)
             caller-pub-hex (fressian/bytes->hex (:public-key caller-kp))
             offer-hash "offer-hash-r5-l1"
             sig-hex (fressian/bytes->hex (crypto/sign (:private-key caller-kp)
                                                       (fressian/utf8->bytes offer-hash)))
             valid-offer {:caller-pubkey caller-pub-hex
                          :caller-x25519 (fressian/bytes->hex (:public-key caller-x))
                          :offer-hash offer-hash
                          :signature sig-hex
                          :burn 100}
             r-nil-1 (js->clj (browser-main/accept-offer nil) :keywordize-keys true)
             r-nil-2 (js->clj (browser-main/accept-offer node-atom nil) :keywordize-keys true)
             r-send-1-arity (js->clj (browser-main/send-sealed-message caller-pub-hex) :keywordize-keys true)
             r-send-nil-peer-1 (js->clj (browser-main/send-sealed-message nil "hi") :keywordize-keys true)
             r-send-nil-peer-2 (js->clj (browser-main/send-sealed-message node-atom nil "hi") :keywordize-keys true)
             r-send-blank-peer-1 (js->clj (browser-main/send-sealed-message "" "hi") :keywordize-keys true)
             r-send-blank-peer-2 (js->clj (browser-main/send-sealed-message node-atom "   " "hi") :keywordize-keys true)
             r-send-nil-msg-1 (js->clj (browser-main/send-sealed-message caller-pub-hex nil) :keywordize-keys true)
             r-send-nil-msg-2 (js->clj (browser-main/send-sealed-message node-atom caller-pub-hex nil) :keywordize-keys true)
             r-send-no-sess (js->clj (browser-main/send-sealed-message node-atom caller-pub-hex "hi") :keywordize-keys true)
             r-send-empty-no-sess (js->clj (browser-main/send-sealed-message nil caller-pub-hex "") :keywordize-keys true)]
         (is (= {:ok false :accepted false :error "invalid-offer"} r-nil-1))
         (is (= {:ok false :accepted false :error "invalid-offer"} r-nil-2))
         (is (= {:ok false :sent false :error "invalid-message"} r-send-1-arity))
         (is (= {:ok false :sent false :error "invalid-peer"} r-send-nil-peer-1))
         (is (= {:ok false :sent false :error "invalid-peer"} r-send-nil-peer-2))
         (is (= {:ok false :sent false :error "invalid-peer"} r-send-blank-peer-1))
         (is (= {:ok false :sent false :error "invalid-peer"} r-send-blank-peer-2))
         (is (= {:ok false :sent false :error "invalid-message"} r-send-nil-msg-1))
         (is (= {:ok false :sent false :error "invalid-message"} r-send-nil-msg-2))
         (is (= {:ok false :sent false :error "no-open-session"} r-send-no-sess))
         (is (= {:ok false :sent false :error "no-open-session"} r-send-empty-no-sess))
         (is (empty? (:sessions @node-atom)))
         (is (empty? (:outbox @node-atom)))
         (let [r-acc (js->clj (browser-main/accept-offer nil valid-offer) :keywordize-keys true)
               r-send-ok-1 (js->clj (browser-main/send-sealed-message nil caller-pub-hex "hello-r5") :keywordize-keys true)
               r-send-ok-2 (js->clj (browser-main/send-sealed-message caller-pub-hex "") :keywordize-keys true)]
           (is (true? (:ok r-acc)))
           (is (true? (:accepted r-acc)))
           (is (true? (:ok r-send-ok-1)))
           (is (true? (:sent r-send-ok-1)))
           (is (= 1 (:seq r-send-ok-1)))
           (is (true? (:ok r-send-ok-2)))
           (is (true? (:sent r-send-ok-2)))
           (is (= 2 (:seq r-send-ok-2))))))))

#?(:cljs
   (deftest browser-refresh-identity-continuity-and-no-private-key-persistence-test
     (testing "H-5 & A-5: Browser refresh preserves public identity (pubkey & ech1 address) without Frankenstein keypair state and never persists private keys"
       (reset! browser/*in-memory-idb-store* {})
       (let [node1 (browser-main/init-node {:peer-id "refresh-node-1" :persist? true})
             _dash1 (browser-main/init-anchor {:pubkey (get-in @node1 [:light-state :pubkey])})
             status1 (js->clj (browser-main/get-status node1) :keywordize-keys true)
             orig-pub (:pubkey status1)
             orig-addr (get-in (js->clj (browser-main/get-anchor-dashboard) :keywordize-keys true)
                               [:identity :address])
             ;; Verify A-5: raw persisted state in IDB has zero private keys
             raw-stored-bytes (get @browser/*in-memory-idb-store* "light-node-state")
             decoded-stored (fressian/decode-wire raw-stored-bytes)]
         (is (string? orig-pub))
         (is (str/starts-with? (str orig-addr) "ech1"))
         (is (nil? (:keypair decoded-stored)))
         (is (nil? (:x25519 decoded-stored)))
         (is (nil? (get-in decoded-stored [:light-state :private-key])))
         ;; Simulate browser refresh: a new page load calls init-node + init-anchor, then restores from IndexedDB
         (let [node2 (browser-main/init-node {:peer-id "refresh-node-2"})
               _dash2 (browser-main/init-anchor)
               _ (browser-main/restore-from-indexed-db! node2)
               status2 (js->clj (browser-main/get-status node2) :keywordize-keys true)
               dash2-after (js->clj (browser-main/get-anchor-dashboard) :keywordize-keys true)]
           ;; Public identity (pubkey + ech1 address) must match original identity across refresh
           (is (= orig-pub (:pubkey status2)))
           (is (= orig-pub (get-in @node2 [:light-state :pubkey])))
           (is (= orig-pub (get-in dash2-after [:identity :anchor-pubkey])))
           (is (= orig-addr (get-in dash2-after [:identity :address])))
           ;; No Frankenstein state: private-key is nil until hardware recovery
           (is (nil? (get-in @node2 [:keypair :private-key])))
           (is (true? (:hardwareLocked status2)))
           ;; Signing operations fail closed with hardware-unlock-required until unlocked
           (swap! node2 assoc-in [:conn :phase] :open)
           (let [offer-locked (js->clj (browser-main/open-channel node2 "axiom" 10 100) :keywordize-keys true)]
             (is (false? (:ok offer-locked)))
             (is (= "hardware-unlock-required" (:error offer-locked))))
           ;; Unlock via YubiKey seed recovery -> updates identity, unlocks signing, and persists new public identity
           (let [hw-seed (fressian/hex->bytes "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                 rec-res (js->clj (browser-main/recover-from-yubikey hw-seed) :keywordize-keys true)
                 hw-pub (:public-hex rec-res)
                 hw-addr (:address rec-res)
                 ;; Simulate another browser refresh after hardware enrollment
                 node3 (browser-main/init-node {:peer-id "refresh-node-3"})
                 _ (browser-main/init-anchor)
                 _ (browser-main/restore-from-indexed-db! node3)
                 status3 (js->clj (browser-main/get-status node3) :keywordize-keys true)
                 dash3 (js->clj (browser-main/get-anchor-dashboard) :keywordize-keys true)
                 stored-after-hw (fressian/decode-wire (get @browser/*in-memory-idb-store* "light-node-state"))]
             (is (true? (:ok rec-res)))
             (is (= hw-pub (:pubkey status3)))
             (is (= hw-addr (get-in dash3 [:identity :address])))
             (is (nil? (:keypair stored-after-hw)))
             (is (nil? (:x25519 stored-after-hw)))))))))
