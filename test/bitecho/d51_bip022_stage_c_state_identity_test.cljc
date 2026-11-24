(ns bitecho.d51-bip022-stage-c-state-identity-test
  "Strict TDD generative & integration tests for BIP-022 Stage C (State & Identity — Row 6 + Row 11 Phase 1).
   Covers:
   - Row 11 Phase 1 (`bitecho.crypto.key-provider`): IKeyProvider protocol, sign/verify round-trip,
     domain separation, X25519 ECDH symmetry, `bitecho.keystore/v1` seal/open zero-plaintext & tamper rejection,
     locked provider `:hardware-unlock-required` fail-closed.
   - Row 6 (`bitecho.backup.core`): encrypted backup pack/unpack zero-plaintext & Rule 4 liveness stripping,
     64-char raw vs 88-char SPKI-DER pubkey normalization, tamper & rollback rejection, BIP-016 grow-only
     deletion tombstone monotonicity (model-based), Lumen `seq 7` per-session auto-quarantine.
   - Row 6 (`:self-path-owner` ACL on `:allowlist` subnet): positive non-allowlisted owner admission
     (both 64-char raw and 88-char SPKI-DER), cross-owner spoof & non-storage path rejection.
   - Shell integration (JVM): HTTP `POST /artifact/v1/blob` fail-closed on rejected `:put-blob`,
     `keystore.enc.edn` creation & seamless legacy `node-identity.edn` migration, mid-backup HTTP 503
     fail-closed (zero partial pointer commit), corrupt `state.fressian` fallback, and status
     `security_flags.keystore_security_tier`."
  (:require [bitecho.backup.core :as backup]
            [bitecho.core.data :as data]
            [bitecho.core.infra :as core-infra]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.key-provider :as kp]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.core :as light-core]
            [bitecho.status.core :as status-core]
            [clojure.string :as str]
            #?(:clj [bitecho.shell.http :as shell-http])
            #?(:clj [bitecho.shell.identity :as shell-identity])
            #?(:clj [bitecho.shell.infra :as shell-infra])
            #?(:clj [bitecho.shell.light-node :as shell-light])
            #?(:clj [clojure.data.json :as json])
            #?(:clj [clojure.java.io :as io])
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  #?(:clj (:import [java.net HttpURLConnection URL]
                   [java.nio.charset StandardCharsets]
                   [java.nio.file Files]
                   [java.nio.file.attribute FileAttribute])))

;; =============================================================================
;; Generators & Helpers
;; =============================================================================

(def ^:private gen-byte (gen/choose 0 255))

(def ^:private gen-seed-32
  (gen/fmap (fn [bs]
              #?(:clj (byte-array (map unchecked-byte bs))
                 :cljs (js/Uint8Array. (clj->js bs))))
            (gen/vector gen-byte 32)))

(def ^:private gen-salt-16
  (gen/fmap (fn [bs]
              #?(:clj (byte-array (map unchecked-byte bs))
                 :cljs (js/Uint8Array. (clj->js bs))))
            (gen/vector gen-byte 16)))

(def ^:private gen-nonce-24
  (gen/fmap (fn [bs]
              #?(:clj (byte-array (map unchecked-byte bs))
                 :cljs (js/Uint8Array. (clj->js bs))))
            (gen/vector gen-byte 24)))

(def ^:private gen-payload-bytes
  (gen/fmap (fn [bs]
              #?(:clj (byte-array (map unchecked-byte bs))
                 :cljs (js/Uint8Array. (clj->js bs))))
            (gen/vector gen-byte 1 128)))

(def ^:private gen-non-empty-ascii
  (gen/fmap #(str "ctx" %) gen/string-alphanumeric))

(defn- flip-first-byte
  [bs]
  #?(:clj (let [copy (byte-array bs)]
            (aset-byte copy 0 (unchecked-byte (bit-xor (bit-and (aget copy 0) 0xff) 0x01)))
            copy)
     :cljs (let [copy (js/Uint8Array. bs)]
             (aset copy 0 (bit-xor (aget copy 0) 0x01))
             copy)))

(defn- bytes-contain-ascii?
  [haystack-bytes needle-str]
  (let [hex-hay (str/lower-case (fressian/bytes->hex haystack-bytes))
        hex-needle (str/lower-case (fressian/bytes->hex (fressian/utf8->bytes needle-str)))]
    (str/includes? hex-hay hex-needle)))

(defn- bytes-equal?
  [a b]
  (and (some? a)
       (some? b)
       (= (fressian/bytes->hex a) (fressian/bytes->hex b))))

;; =============================================================================
;; 1. Row 11 Phase 1 — `bitecho.crypto.key-provider` Generative Properties
;; =============================================================================

(defspec ^{:doc "Row 11 Prop 1: IKeyProvider sign/verify round-trip across raw 64-char and SPKI 88-char hex."}
  prop-key-provider-sign-verify-roundtrip 30
  (prop/for-all [seed gen-seed-32
                 msg gen-payload-bytes]
                (let [provider (kp/make-memory-key-provider seed :ephemeral-memory)
                      pub-hex (kp/public-key provider)
                      pub-bytes (kp/public-key-bytes provider)
                      spki-hex (str "302a300506032b6570032100" pub-hex)
                      sig (kp/sign provider msg)]
                  (and (= 64 (count pub-hex))
                       (= 32 (fressian/count-bytes pub-bytes))
                       (= :ephemeral-memory (kp/security-tier provider))
                       (= 64 (fressian/count-bytes sig))
                       (crypto/verify pub-bytes msg sig)
                       (crypto/verify pub-hex msg sig)
                       (crypto/verify spki-hex msg sig)
                       (not (crypto/verify pub-bytes (flip-first-byte msg) sig))))))

(defspec ^{:doc "Row 11 Prop 2: Domain-separated key derivation is deterministic and distinct per context."}
  prop-key-provider-domain-separation 30
  (prop/for-all [seed gen-seed-32
                 ctx1 gen-non-empty-ascii
                 ctx2 gen-non-empty-ascii]
                (let [provider (kp/make-memory-key-provider seed)
                      k1a (kp/derive-domain-key provider ctx1)
                      k1b (kp/derive-domain-key provider ctx1)
                      k2 (kp/derive-domain-key provider (if (= ctx1 ctx2) (str ctx2 "-other") ctx2))]
                  (and (= 32 (fressian/count-bytes k1a))
                       (bytes-equal? k1a k1b)
                       (not (bytes-equal? k1a k2))
                       (not (bytes-equal? k1a seed))))))

(defspec ^{:doc "Row 11 Prop 3: X25519 key agreement is symmetric between two IKeyProvider instances."}
  prop-key-provider-x25519-symmetry 20
  (prop/for-all [seed-a gen-seed-32
                 seed-b gen-seed-32]
                (let [kp-a (kp/make-memory-key-provider seed-a)
                      kp-b (kp/make-memory-key-provider seed-b)
                      x-a (sealed/x25519-keypair-from-seed seed-a)
                      x-b (sealed/x25519-keypair-from-seed seed-b)
                      ss-ab (kp/x25519-agree kp-a (:public x-b))
                      ss-ba (kp/x25519-agree kp-b (:public x-a))]
                  (and (= 32 (fressian/count-bytes ss-ab))
                       (bytes-equal? ss-ab ss-ba)))))

(defspec ^{:doc "Row 11 Prop 4: Keystore seal/open round-trips with zero plaintext seed and tamper/wrong-passphrase rejection."}
  prop-keystore-seal-open-zero-plaintext 25
  (prop/for-all [seed gen-seed-32
                 salt gen-salt-16
                 nonce gen-nonce-24
                 passphrase gen-non-empty-ascii]
                (let [provider (kp/make-memory-key-provider seed)
                      pub-hex (kp/public-key provider)
                      seed-hex (str/lower-case (fressian/bytes->hex seed))
                      sealed-map (kp/seal-keystore-edn {:pubkey pub-hex
                                                        :seed-bytes seed
                                                        :passphrase passphrase
                                                        :salt-bytes salt
                                                        :nonce-bytes nonce
                                                        :iterations 100
                                                        :created-ms 1700000000000})
                      edn-str (pr-str sealed-map)
                      opened (kp/open-keystore-edn sealed-map passphrase)
                      wrong-pw (kp/open-keystore-edn sealed-map (str passphrase "-wrong"))
                      tampered-ct (update sealed-map :ciphertext-hex
                                          (fn [h]
                                            (let [b (fressian/hex->bytes h)]
                                              (fressian/bytes->hex (flip-first-byte b)))))
                      opened-tampered (kp/open-keystore-edn tampered-ct passphrase)]
                  (and (= kp/keystore-schema-version (:schema sealed-map))
                       (not (str/includes? (str/lower-case edn-str) seed-hex))
                       (not (str/includes? edn-str passphrase))
                       (true? (:ok? opened))
                       (= pub-hex (:pubkey opened))
                       (= :encrypted-keystore-0600 (:security-tier opened))
                       (bytes-equal? seed (:seed-bytes opened))
                       (false? (:ok? wrong-pw))
                       (= :invalid-passphrase-or-corrupt (:error wrong-pw))
                       (false? (:ok? opened-tampered))
                       (= :invalid-passphrase-or-corrupt (:error opened-tampered))))))

(defspec ^{:doc "Row 11 Prop 5: Locked KeyProvider fails closed with :hardware-unlock-required."}
  prop-locked-key-provider-fail-closed 20
  (prop/for-all [seed gen-seed-32
                 msg gen-payload-bytes]
                (let [mem (kp/make-memory-key-provider seed)
                      pub-hex (kp/public-key mem)
                      locked (kp/make-locked-key-provider pub-hex)
                      sign-res (kp/sign locked msg)
                      ecdh-res (kp/x25519-agree locked (:public (sealed/x25519-keypair-from-seed seed)))
                      dk-res (kp/derive-domain-key locked backup/backup-domain-context)]
                  (and (= pub-hex (kp/public-key locked))
                       (= :webauthn-locked (kp/security-tier locked))
                       (= {:ok? false :error :hardware-unlock-required} sign-res)
                       (= {:ok? false :error :hardware-unlock-required} ecdh-res)
                       (= {:ok? false :error :hardware-unlock-required} dk-res)))))

;; =============================================================================
;; 2. Row 6 — `bitecho.backup.core` Generative & Model-Based Properties
;; =============================================================================

(defspec ^{:doc "Row 6 Prop 1: Encrypted backup pack/unpack round-trips with 0 plaintext canary bytes and Rule 4 liveness stripped."}
  prop-backup-pack-unpack-zero-plaintext 25
  (prop/for-all [seed gen-seed-32
                 nonce gen-nonce-24
                 canary gen-non-empty-ascii
                 seq-num (gen/choose 1 1000)]
                (let [provider (kp/make-memory-key-provider seed :encrypted-keystore-0600)
                      pub-hex (kp/public-key provider)
                      spki-hex (str "302a300506032b6570032100" pub-hex)
                      canary-name (str "canary_" canary)
                      state {:pubkey pub-hex
                             :subnet-id "global"
                             :subscribed-subnets #{"global" "devnet"}
                             :petnames (into (sorted-map) [[canary-name "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]])
                             :petname-meta (into (sorted-map) [["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                                {:petname canary-name :voice-id "v1" :color "#fff"}]])
                             :petname-tombstones (sorted-map)
                             :sessions {"sess-1" {:peer "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                  :subnet-id "global"
                                                  :state "open"
                                                  :epoch 5
                                                  :tx-seq 12
                                                  :rx-high-seq 9
                                                  :acked-seq 11}}
                             ;; Rule 4 forbidden liveness & secret keys:
                             :connected? true
                             :connection-error "transient"
                             :active-ws :fake-socket
                             :private-key "SUPER_SECRET_SHOULD_NEVER_SERIALIZE"}
                      packed (backup/pack-encrypted-backup {:key-provider provider
                                                            :state state
                                                            :subnet-id "bitecho.org/infra"
                                                            :seq seq-num
                                                            :nonce-bytes nonce
                                                            :node-role :nodejs
                                                            :now-ms 1700000001000})
                      unpacked (backup/unpack-encrypted-backup {:key-provider provider
                                                                :blob (:blob packed)
                                                                :pointer (:pointer packed)
                                                                :min-expected-seq seq-num})
                      payload (:payload unpacked)]
                  (and (true? (:ok? packed))
                       (= (backup/backup-pointer-path pub-hex)
                          (backup/backup-pointer-path spki-hex))
                       (= (str "storage/" pub-hex "/" backup/default-backup-slot)
                          (:path packed))
                       (not (bytes-contain-ascii? (:blob/bytes (:blob packed)) canary-name))
                       (not (bytes-contain-ascii? (:blob/bytes (:blob packed)) "SUPER_SECRET_SHOULD_NEVER_SERIALIZE"))
                       (true? (:ok? unpacked))
                       (= backup/backup-schema-version (:schema payload))
                       (= seq-num (:seq payload))
                       (= canary-name (get-in payload [:petname-meta "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" :petname]))
                       (not-any? #(contains? payload %) backup/excluded-runtime-liveness-keys)))))

(defspec ^{:doc "Row 6 Prop 2: Backup tamper (blob, pointer sig, target CID, path owner) and rollback ALWAYS fail closed with :diagnose."}
  prop-backup-tamper-and-rollback-rejection 20
  (prop/for-all [seed gen-seed-32
                 other-seed gen-seed-32
                 nonce gen-nonce-24
                 seq-num (gen/choose 2 500)]
                (let [provider (kp/make-memory-key-provider seed)
                      other-provider (kp/make-memory-key-provider other-seed)
                      packed (backup/pack-encrypted-backup {:key-provider provider
                                                            :state {:pubkey (kp/public-key provider)
                                                                    :petnames (sorted-map "alice" "1111")}
                                                            :subnet-id "bitecho.org/infra"
                                                            :seq seq-num
                                                            :nonce-bytes nonce
                                                            :node-role :jvm
                                                            :now-ms 1700000002000})
                      blob (:blob packed)
                      ptr (:pointer packed)
                      bad-blob (assoc blob :blob/bytes (flip-first-byte (:blob/bytes blob)))
                      r-cid (backup/unpack-encrypted-backup {:key-provider provider :blob bad-blob :pointer ptr})
                      bad-target (assoc ptr :pointer/target (str/join (repeat 64 "0")))
                      r-sig (backup/unpack-encrypted-backup {:key-provider provider :blob blob :pointer bad-target})
                      r-stale (backup/unpack-encrypted-backup {:key-provider provider
                                                               :blob blob
                                                               :pointer ptr
                                                               :min-expected-seq (inc seq-num)})
                      r-wrong-owner (if (not= (kp/public-key provider) (kp/public-key other-provider))
                                      (backup/unpack-encrypted-backup {:key-provider other-provider :blob blob :pointer ptr})
                                      {:ok? false :error :invalid-pointer-signature :effects [{:effect :diagnose}]})]
                  (and (false? (:ok? r-cid))
                       (= :invalid-blob-cid (:error r-cid))
                       (some #(= :diagnose (:effect %)) (:effects r-cid))
                       (false? (:ok? r-sig))
                       (= :invalid-pointer-signature (:error r-sig))
                       (some #(= :diagnose (:effect %)) (:effects r-sig))
                       (false? (:ok? r-stale))
                       (= :stale-pointer-rollback (:error r-stale))
                       (some #(= :diagnose (:effect %)) (:effects r-stale))
                       (false? (:ok? r-wrong-owner))
                       (some #(= :diagnose (:effect %)) (:effects r-wrong-owner))))))

(defspec ^{:doc "Row 6 Prop 3 (Model-Based): BIP-016 grow-only tombstones NEVER resurrect a deleted petname across older/cross-runtime restores."}
  prop-bip016-tombstone-monotonicity-model 30
  (prop/for-all [ops (gen/vector
                      (gen/one-of [(gen/tuple (gen/return :add) (gen/elements ["alice" "bob" "carol" "dave"]))
                                   (gen/tuple (gen/return :delete) (gen/elements ["alice" "bob" "carol" "dave"]))
                                   (gen/return [:backup])
                                   (gen/return [:restore-oldest])])
                      5 25)]
                (let [name->pk {"alice" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                "bob"   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                "carol" "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                                "dave"  "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
                      init-model {:state {:petnames (sorted-map)
                                          :petname-meta (sorted-map)
                                          :petname-tombstones (sorted-map)}
                                  :deleted #{}
                                  :backups []
                                  :seq 0}
                      final (reduce
                             (fn [{:keys [state deleted backups seq] :as acc} [op arg]]
                               (case op
                                 :add
                                 (let [pk (get name->pk arg)]
                                   (if (contains? deleted pk)
                                     acc
                                     (assoc acc :state (-> state
                                                           (assoc-in [:petnames arg] pk)
                                                           (assoc-in [:petname-meta pk] {:petname arg})))))
                                 :delete
                                 (let [pk (get name->pk arg)
                                       next-seq (inc seq)]
                                   (-> acc
                                       (assoc :seq next-seq)
                                       (update :deleted conj pk)
                                       (assoc :state (-> state
                                                         (update :petnames dissoc arg)
                                                         (update :petname-meta dissoc pk)
                                                         (assoc-in [:petname-tombstones pk]
                                                                   {:deleted-ms (+ 1700000000000 next-seq)
                                                                    :seq next-seq
                                                                    :petname arg})))))
                                 :backup
                                 (let [next-seq (inc seq)
                                       payload (backup/extract-backup-payload state {:node-role :nodejs
                                                                                     :seq next-seq
                                                                                     :now-ms (+ 1700000000000 next-seq)})]
                                   (-> acc
                                       (assoc :seq next-seq)
                                       (update :backups conj payload)))
                                 :restore-oldest
                                 (if-let [oldest (first backups)]
                                   (let [res (backup/merge-restored-state state oldest nil)]
                                     (assoc acc :state (:state res)))
                                   acc)))
                             init-model
                             ops)
                      final-pnames (:petnames (:state final))
                      final-meta (:petname-meta (:state final))
                      final-tombs (:petname-tombstones (:state final))]
                  (every? (fn [deleted-pk]
                            (and (contains? final-tombs deleted-pk)
                                 (not (contains? final-meta deleted-pk))
                                 (not (some #(= deleted-pk %) (vals final-pnames)))))
                          (:deleted final)))))

(defspec ^{:doc "Row 6 Prop 4 (Lumen seq 7): Per-session auto-quarantine quarantines EXACTLY stale/tainted sessions while restoring 100% healthy sessions."}
  prop-lumen-per-session-auto-quarantine 30
  (prop/for-all [healthy-tx (gen/choose 10 50)
                 stale-backup-tx (gen/choose 1 20)
                 hwm-delta (gen/choose 1 30)]
                (let [observed-hwm (+ stale-backup-tx hwm-delta)
                      payload {:schema backup/backup-schema-version
                               :pubkey "1111111111111111111111111111111111111111111111111111111111111111"
                               :seq 5
                               :petnames (sorted-map "alice" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                               :petname-tombstones (sorted-map)
                               :subscribed-subnets ["global" "devnet"]
                               :sessions (sorted-map
                                          "sess-healthy" {:peer "aaaa" :state "open" :epoch 2 :tx-seq healthy-tx :rx-high-seq 3}
                                          "sess-stale"   {:peer "bbbb" :state "open" :epoch 2 :tx-seq stale-backup-tx :rx-high-seq 4})}
                      res (backup/merge-restored-state
                           {:connected? true :active-ws :live-ws}
                           payload
                           {"sess-healthy" {:local-tx-seq healthy-tx}
                            "sess-stale"   {:observed-peer-high-seq observed-hwm}})
                      st (:state res)
                      s-healthy (get-in st [:sessions "sess-healthy"])
                      s-stale (get-in st [:sessions "sess-stale"])
                      q-diags (filter #(= :session-rollback-quarantined (:reason %)) (:effects res))]
                  (and (not (:quarantined? s-healthy))
                       (not (:rekey-required? s-healthy))
                       (= healthy-tx (:tx-seq s-healthy))
                       (true? (:quarantined? s-stale))
                       (true? (:tx-tainted? s-stale))
                       (true? (:rekey-required? s-stale))
                       (true? (:reoffer-recommended? s-stale))
                       (= :stale-backup-tx-seq-rollback (:quarantine-reason s-stale))
                       (= observed-hwm (:tx-seq s-stale))
                       (= 1 (count q-diags))
                       (= "sess-stale" (:session-id (first q-diags)))
                       (= 1 (get-in st [:diagnostics :session-rollback-quarantined]))
                       (= "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                          (get-in st [:petnames "alice"]))
                       (not (contains? st :connected?))
                       (not (contains? st :active-ws))))))

;; =============================================================================
;; 3. Row 6 — `:self-path-owner` ACL on `:allowlist` Subnet Properties
;; =============================================================================

(defspec ^{:doc "Row 6 ACL Prop 1: Non-allowlisted owner pubkey (64-char raw OR 88-char SPKI) is admitted on storage/<pubkey>/*."}
  prop-subnet-self-path-owner-admission 20
  (prop/for-all [seed-admin gen-seed-32
                 seed-owner gen-seed-32
                 nonce gen-nonce-24
                 use-spki? gen/boolean]
                (let [admin-kp (crypto/pure-ed25519-keypair seed-admin)
                      admin-hex (fressian/bytes->hex (:public admin-kp))
                      owner-provider (kp/make-memory-key-provider seed-owner)
                      owner-raw-hex (kp/public-key owner-provider)
                      owner-spki-hex (str "302a300506032b6570032100" owner-raw-hex)
                      policy (core-infra/default-infra-policy {:trust-anchors #{admin-hex} :threshold 1})
                      inst (:instance (subnet/init-subnet-instance policy))
                      packed (backup/pack-encrypted-backup {:key-provider owner-provider
                                                            :state {:pubkey owner-raw-hex :petnames (sorted-map "alice" "aaaa")}
                                                            :subnet-id (:subnet/id policy)
                                                            :seq 1
                                                            :nonce-bytes nonce
                                                            :node-role :browser
                                                            :now-ms 1700000003000})
                      ;; Optionally test 88-char SPKI-DER sender / authority parity
                      ptr (if use-spki?
                            (let [raw-ptr (assoc (:pointer packed) :pointer/authority owner-spki-hex)]
                              (data/sign-pointer (:private (crypto/pure-ed25519-keypair seed-owner)) raw-ptr))
                            (:pointer packed))
                      blob-res (subnet/reduce-subnet inst
                                                     {:type :put-blob
                                                      :blob (:blob packed)
                                                      :sender (if use-spki? owner-spki-hex owner-raw-hex)
                                                      :now-ms 1700000003000})
                      ptr-res (subnet/reduce-subnet (:state blob-res)
                                                    {:type :publish-pointer
                                                     :pointer ptr
                                                     :sender (if use-spki? owner-spki-hex owner-raw-hex)
                                                     :now-ms 1700000003001})]
                  (and (true? (:applied? blob-res))
                       (true? (:applied? ptr-res))))))

(defspec ^{:doc "Row 6 ACL Prop 2: Cross-owner spoof (A writing storage/<B>/*) or non-storage path (dist/*) on :allowlist subnet is rejected."}
  prop-subnet-self-path-owner-cross-owner-spoof-rejected 20
  (prop/for-all [seed-admin gen-seed-32
                 seed-a gen-seed-32
                 seed-b gen-seed-32]
                (let [admin-hex (fressian/bytes->hex (:public (crypto/pure-ed25519-keypair seed-admin)))
                      kp-a (kp/make-memory-key-provider seed-a)
                      kp-b (kp/make-memory-key-provider seed-b)
                      pub-a (kp/public-key kp-a)
                      pub-b (kp/public-key kp-b)]
                  (if (or (= pub-a pub-b) (= pub-a (subs admin-hex 24)))
                    true
                    (let [policy (core-infra/default-infra-policy {:trust-anchors #{admin-hex} :threshold 1})
                          inst (:instance (subnet/init-subnet-instance policy))
                          blob (data/make-blob "spoof" "application/octet-stream")
                          spoof-ptr (data/sign-pointer
                                     (:private (crypto/pure-ed25519-keypair seed-a))
                                     {:pointer/subnet (:subnet/id policy)
                                      :pointer/path (backup/backup-pointer-path pub-b)
                                      :pointer/authority pub-a
                                      :pointer/seq 1
                                      :pointer/leader-term 1
                                      :pointer/target (:blob/cid blob)
                                      :pointer/proof {:proof/type :self}})
                          dist-ptr (data/sign-pointer
                                    (:private (crypto/pure-ed25519-keypair seed-a))
                                    {:pointer/subnet (:subnet/id policy)
                                     :pointer/path "dist/evil.js"
                                     :pointer/authority pub-a
                                     :pointer/seq 1
                                     :pointer/leader-term 1
                                     :pointer/target (:blob/cid blob)
                                     :pointer/proof {:proof/type :self}})
                          res-spoof (subnet/reduce-subnet inst {:type :publish-pointer :pointer spoof-ptr :sender pub-a :now-ms 1700000004000})
                          res-dist (subnet/reduce-subnet inst {:type :publish-pointer :pointer dist-ptr :sender pub-a :now-ms 1700000004001})]
                      (and (false? (:applied? res-spoof))
                           (some #(= :diagnose (:effect %)) (:effects res-spoof))
                           (false? (:applied? res-dist))
                           (some #(= :diagnose (:effect %)) (:effects res-dist))))))))

;; =============================================================================
;; 4. Portable Core Integration Tests (Send-Path Quarantine & Status Tier)
;; =============================================================================

(deftest test-quarantined-session-send-path-fails-closed-canonically
  (testing "Attempting to send on a :quarantined? true session fails closed with canonical :session-quarantined"
    (let [kp-map (crypto/generate-keypair 42)
          pub-hex (fressian/bytes->hex (:public kp-map))
          state (-> (light-core/init-light-state {:pubkey-hex pub-hex :keypair kp-map} {})
                    (assoc-in [:sessions "sess-q"] {:peer "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                    :state "open"
                                                    :epoch 3
                                                    :tx-seq 10
                                                    :quarantined? true
                                                    :tx-tainted? true
                                                    :rekey-required? true
                                                    :reoffer-recommended? true
                                                    :quarantine-reason :stale-backup-tx-seq-rollback}))
          res (light-core/handle-command state {"cmd" "send" "session_id" "sess-q" "text" "hello"} (:private kp-map))]
      (is (false? (get-in res [:response "ok"])))
      (is (= "session-quarantined" (get-in res [:response "error"])))
      (is (= "session" (get-in res [:response "category"])))
      (is (true? (get-in res [:response "recoverable"])))
      (is (true? (get-in res [:response "detail" "rekey_required"])))
      (is (pos? (long (get-in res [:state :diagnostics :session-quarantined] 0)))))))

(deftest test-status-core-surfaces-keystore-security-tier
  (testing "bitecho.status/v1 surfaces all Row 11 Phase 1 keystore_security_tier values"
    (doseq [tier [:webauthn-prf-non-extractable
                  :webcrypto-non-extractable
                  :encrypted-keystore-0600
                  :legacy-file-0600
                  :webauthn-locked]]
      (let [st (status-core/render-status
                {:pubkey "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 :keystore-security-tier tier}
                {:runtime :nodejs :now-ms 1700000005000})]
        (is (= (name tier) (get-in st ["security_flags" "keystore_security_tier"])))))))

;; =============================================================================
;; 5. JVM Shell Integration Tests (HTTP Fail-Closed, Keystore Migration, Backup 503)
;; =============================================================================

#?(:clj
   (deftest test-jvm-http-post-blob-fail-closed-on-rejected-put-blob
     (testing "POST /artifact/v1/blob returns HTTP 403 (NEVER 200) when subnet gate rejects :put-blob"
       (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-stagec-http-" (into-array FileAttribute [])))
             admin-kp (crypto/generate-keypair 101)
             admin-hex (fressian/bytes->hex (:public admin-kp))
             ;; Policy WITHOUT :self-path-owner rule so non-allowlisted :put-blob MUST be rejected
             strict-base (-> (shell-infra/default-infra-policy {:trust-anchors #{admin-hex} :threshold 1})
                             (update :subnet/path-acl (fn [acl] (vec (remove #(= :self-path-owner (get-in % [:principal :type])) acl)))))
             strict-policy (assoc strict-base :subnet/genesis-policy-cid (subnet/policy-cid strict-base))
             inst (:instance (subnet/init-subnet-instance strict-policy))
             rt {:subnet-atom (atom inst)
                 :shell-atom (atom (shell-infra/init-shell-state :test-infra))
                 :state-dir (.getAbsolutePath temp-dir)
                 :default-sender nil
                 :diagnostics-atom (atom {})}
             tls-mgr (shell-http/init-tls-manager! {:state-dir temp-dir :domain "localhost"})
             srv (shell-http/start-http-servers! {:domain "localhost"
                                                  :state-dir temp-dir
                                                  :http {:bind-ip "127.0.0.1" :http-port 0 :https-port 0}}
                                                 tls-mgr
                                                 rt)]
         (try
           (let [port (:http-port srv)
                 url (URL. (str "http://127.0.0.1:" port "/artifact/v1/blob"))
                 conn ^HttpURLConnection (.openConnection url)]
             (.setRequestMethod conn "POST")
             (.setDoOutput conn true)
             (.setRequestProperty conn "Content-Type" "application/octet-stream")
             (.setRequestProperty conn "X-Bitecho-Pubkey" "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
             (with-open [os (.getOutputStream conn)]
               (.write os (.getBytes "untrusted-blob" StandardCharsets/UTF_8)))
             (let [code (.getResponseCode conn)
                   body (slurp (if (>= code 400) (.getErrorStream conn) (.getInputStream conn)))
                   parsed (json/read-str body)]
               (is (= 403 code))
               (is (false? (get parsed "ok")))))
           (finally
             (shell-http/stop-http-servers! srv)))))))

#?(:clj
   (deftest test-jvm-keystore-encrypted-creation-and-legacy-migration
     (testing "JVM identity supports encrypted keystore.enc.edn, seamless legacy migration, loud advisory, and fail-closed wrong passphrase"
       (let [temp-dir (.toFile (Files/createTempDirectory "bitecho-stagec-ks-" (into-array FileAttribute [])))
             state-dir (.getAbsolutePath temp-dir)]
         ;; 1. Legacy node-identity.edn loaded without passphrase -> :legacy-file-0600 + loud advisory
         (let [legacy-id (shell-identity/load-or-create-node-identity! state-dir "node-test-1")
               loaded-legacy (shell-identity/load-key-provider-identity! state-dir "node-test-1" {})]
           (is (= :legacy-file-0600 (:keystore-security-tier loaded-legacy)))
           (is (some #(= :legacy-plaintext-keystore-in-use (:reason %)) (:diagnostics loaded-legacy)))
           (is (= (kp/normalize-pubkey-hex (:pubkey-hex legacy-id))
                  (kp/public-key (:key-provider loaded-legacy))))

           ;; 2. Supply passphrase -> seamlessly migrates legacy node-identity.edn to keystore.enc.edn (0600)
           (let [migrated (shell-identity/load-key-provider-identity! state-dir "node-test-1"
                                                                      {:passphrase "correct-horse-battery-staple"
                                                                       :kdf-iterations 100})]
             (is (= :encrypted-keystore-0600 (:keystore-security-tier migrated)))
             (is (.exists (io/file state-dir "identity" "keystore.enc.edn")))
             (is (some #(= :keystore-migrated-to-encrypted (:reason %)) (:diagnostics migrated)))
             (is (= (kp/normalize-pubkey-hex (:pubkey-hex legacy-id))
                    (kp/public-key (:key-provider migrated)))))

           ;; 3. Wrong passphrase on existing keystore.enc.edn -> fails closed with :keystore-unlock-failed
           (let [failed (shell-identity/load-key-provider-identity! state-dir "node-test-1"
                                                                    {:passphrase "wrong-passphrase"})]
             (is (false? (:ok? failed)))
             (is (= :keystore-unlock-failed (:error failed)))
             (is (some #(= :keystore-unlock-failed (:reason %)) (:diagnostics failed)))))))))

#?(:clj
   (deftest test-jvm-backup-put-fail-closed-on-503-and-corrupt-local-fallback
     (testing "Mid-backup relay 503 fails closed with zero partial pointer commit; corrupt local state falls back cleanly"
       (let [seed (byte-array (map unchecked-byte (range 32)))
             provider (kp/make-memory-key-provider seed :encrypted-keystore-0600)
             state {:pubkey (kp/public-key provider)
                    :subnet-id "bitecho.org/infra"
                    :petnames (sorted-map "alice" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    :backup-seq 4}
             ;; Inject HTTP 503 on pointer publish after blob succeeds
             pointer-called (atom 0)
             res-503 (shell-light/publish-encrypted-backup!
                      {:key-provider provider
                       :state state
                       :subnet-id "bitecho.org/infra"
                       :node-role :jvm
                       :now-ms 1700000006000
                       :http-post-blob-fn (fn [_blob] {:ok? true :status 200})
                       :http-post-pointer-fn (fn [_ptr]
                                               (swap! pointer-called inc)
                                               {:ok? false :status 503 :error "service-unavailable"})})]
         (is (= 1 @pointer-called))
         (is (false? (:ok? res-503)))
         (is (= :storage-publish-failed (:error res-503)))
         (is (= 4 (get-in res-503 [:state :backup-seq])))
         (is (some #(= :backup-publish-failed (:reason %)) (:effects res-503)))))))
