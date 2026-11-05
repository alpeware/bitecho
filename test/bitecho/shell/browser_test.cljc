(ns bitecho.shell.browser-test
  "Cross-runtime generative tests for the CLJS browser shell boundary (Rules 1-6).
   - Rule 1: Model-based generative property test (prop-browser-shell-lifecycle-state-machine).
   - Rule 4: Single-authority lifecycle state, zero persistent derived liveness.
   - Rule 5: Zero silent failures, counted diagnose effects on stale/dropped events.
   - Browser IndexedDB persistence sanitization & roundtrip.
   - Deterministic multi-peer browser subnet demo verification."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.shell.browser :as browser]
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

  (testing "4,320+ combo enumeration across 100% of forbidden-persistence-keys, 30+ credential/token/key stems, 9 casings, and 3 key types + public-key carve-out (0 survivors AND 0 false positives) + persist->load roundtrip (R4-M1)"
    (let [extra-stems ["api-key" "api-token" "api-secret" "jwt" "jwt-token"
                       "access-token" "refresh-token" "session-token" "auth-token" "bearer-token"
                       "id-token" "csrf-token" "oauth-token" "token" "tokens"
                       "bearer" "authorization" "auth-secret" "auth-key" "client-secret" "server-secret"
                       "signing-key" "encryption-key" "decryption-key" "master-key" "hmac-key"
                       "symmetric-key" "aes-key" "chacha-key" "wrapping-key" "derived-key"
                       "hkdf-key" "kdf-key" "mac-key" "backup-key" "recovery-key" "identity-key"
                       "node-key" "host-key" "peer-key" "hot-key" "cold-key" "device-key"
                       "credential" "credentials" "cookie" "cookies" "pin" "otp" "totp"]
          stems (vec (distinct (concat (sort browser/forbidden-persistence-keys)
                                       extra-stems
                                       (for [s ["private-key" "privkey" "seed" "secret-key" "session-key"
                                                "api-key" "access-token" "session-token" "signing-key"
                                                "x25519-privkey" "ed25519-privkey" "prf-output" "user-handle"]
                                             sfx ["-bytes" "-hex" "-raw" "-b64"]]
                                         (str s sfx)))))
          to-camel (fn [s]
                     (let [parts (str/split s #"-")]
                       (apply str (first parts) (map str/capitalize (rest parts)))))
          to-pascal (fn [s]
                      (apply str (map str/capitalize (str/split s #"-"))))
          to-title-snake (fn [s]
                           (str/join "_" (map str/capitalize (str/split s #"-"))))
          casings (fn [s]
                    [s
                     (str/replace s "-" "_")
                     (to-camel s)
                     (to-pascal s)
                     (str/upper-case (str/replace s "-" "_"))
                     (str/upper-case s)
                     (str/replace s "-" "")
                     (str/replace s "-" ".")
                     (to-title-snake s)])
          all-forbidden-keys (for [stem stems
                                   cased (casings stem)
                                   k [cased (keyword cased) (symbol cased)]]
                               k)
          carve-out-stems ["pubkey" "public-key" "x25519-pubkey" "x25519-public-key"
                           "ed25519-pubkey" "ed25519-public-key" "peer-pubkey" "agent-pubkey"
                           "hot-pubkey" "anchor-pubkey" "authority-pubkey" "directory-pubkey"
                           "caller-pubkey" "callee-pubkey" "key-mode" "keys-verified?"]
          all-carve-out-keys (vec (distinct (for [stem carve-out-stems
                                                  cased (casings stem)
                                                  k [cased (keyword cased) (symbol cased)]]
                                              k)))
          test-map (into {}
                         (concat (map (fn [k] [k "SENSITIVE"]) all-forbidden-keys)
                                 (map (fn [k] [k "PUBLIC-OK"]) all-carve-out-keys)))
          sanitized (browser/sanitize-state-for-persistence test-map)
          survivors (remove (set all-carve-out-keys) (keys sanitized))
          false-positives (remove #(contains? sanitized %) all-carve-out-keys)]
      (is (every? (set stems) browser/forbidden-persistence-keys))
      (is (>= (count all-forbidden-keys) 4320))
      (is (empty? survivors) (str "Forbidden survivors found: " (pr-str (take 10 survivors))))
      (is (empty? false-positives) (str "Carve-out false positives found: " (pr-str (take 10 false-positives)))))

    (let [roundtrip-input {:peer-id "rt-node"
                           :x25519-pubkey "PUB-X25519-OK"
                           :x25519Pubkey "PUB-X25519-CAMEL-OK"
                           :public-key "PUB-ED25519-OK"
                           :privateKeyBytes "LEAK-1"
                           :x25519Privkey "LEAK-2"
                           :x25519-private-key "LEAK-3"
                           :api-key "LEAK-4"
                           :jwt "LEAK-5"
                           :access-token "LEAK-6"
                           :session-token "LEAK-7"
                           :nested {:privateKeyBytes "LEAK-8"
                                    :x25519Privkey "LEAK-9"
                                    :api-token "LEAK-10"
                                    :x25519-pubkey "NESTED-PUB-OK"
                                    :safe-val 99}}
          loaded-atom (atom nil)]
      (browser/persist-state! roundtrip-input nil)
      (browser/load-persisted-state (fn [_err st] (reset! loaded-atom st)))
      (is (= {:peer-id "rt-node"
              :x25519-pubkey "PUB-X25519-OK"
              :x25519Pubkey "PUB-X25519-CAMEL-OK"
              :public-key "PUB-ED25519-OK"
              :nested {:x25519-pubkey "NESTED-PUB-OK"
                       :safe-val 99}}
             @loaded-atom)))))
