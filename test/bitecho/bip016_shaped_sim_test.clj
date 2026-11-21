(ns bitecho.bip016-shaped-sim-test
  "BIP-016 Shaped R2 Implementation & E2E Scenario Simulation Tests.
   Strict TDD (Rule 1): generative clojure.test.check properties + deterministic
   E2E scenarios + cross-runtime HKDF/AES-GCM/Ed25519 golden vectors.
   Advisory simulation only — never modifies real Stage 1 / Stage 2 consents."
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.memento.constants :as mc]
            [bitecho.memento.memory-chain :as memory-chain]
            [bitecho.memento.rolodex :as rolodex]
            [bitecho.shell.memento-crypto :as mcrypto]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(def ^:private gen-pubkey-hex
  (gen/fmap (fn [bs] (fressian/bytes->hex (byte-array bs)))
            (gen/vector (gen/choose 0 255) 32)))

(defn- commit-rolodex-entry
  "Drives the pure Rolodex reducer through :propose-entry -> :cas-head -> :sign -> :cas-put."
  [st priv event]
  (let [[s1 e1] (rolodex/transition st (assoc event :type :propose-entry))
        cas-eff (first (filter #(= :cas-head (:type %)) e1))]
    (if (nil? cas-eff)
      [s1 e1]
      (let [[s2 e2] (rolodex/transition s1 {:type :cas-head-result
                                            :gen (:gen cas-eff)
                                            :ok? true})
            sign-eff (first (filter #(= :sign (:type %)) e2))
            sig (mcrypto/sign-rolodex-entry priv (:entry sign-eff))
            [s3 e3] (rolodex/transition s2 {:type :sign-result
                                            :gen (:gen sign-eff)
                                            :ok? true
                                            :signature sig})
            put-eff (first (filter #(= :cas-put (:type %)) e3))
            [s4 e4] (rolodex/transition s3 {:type :cas-put-result
                                            :gen (:gen put-eff)
                                            :ok? true})]
        [s4 (vec (concat e1 e2 e3 e4))]))))

(defn- pkcs8-from-seed32
  "Wraps a raw 32-byte Ed25519 seed into standard 48-byte PKCS#8 DER."
  ^bytes [seed-hex]
  (fressian/concat-bytes
   (fressian/hex->bytes "302e020100300506032b657004220420")
   (fressian/hex->bytes seed-hex)))

(defn- spki-from-pub32
  "Wraps a raw 32-byte Ed25519 public key into standard 44-byte X.509 SPKI DER."
  ^bytes [pub32-hex]
  (fressian/concat-bytes
   (fressian/hex->bytes "302a300506032b6570032100")
   (fressian/hex->bytes pub32-hex)))

;; =============================================================================
;; 1. Strict TDD Property: (min constant config) Cap Ceiling Enforcement
;; =============================================================================

(defspec ^{:doc "BIP-016 R2 Property: Hardcoded ceilings (10000 / 1024 / 4096) can only be lowered
                 by signed network config via (min constant config); raising clamps and emits
                 counted :cap-ceiling-clamped :diagnose."}
  prop-effective-cap-min-constant-config 50
  (prop/for-all [owner-pk gen-pubkey-hex
                 req-petnames (gen/choose 1 25000)
                 req-subnets (gen/choose 1 5000)
                 req-sessions (gen/choose 1 12000)]
                (let [cfg {:type :configure-pointer
                           :node-role :light
                           :owner-pubkeys [owner-pk]
                           :retention-policy {:max-entries 500
                                              :max-bytes 1048576
                                              :rotate-every-entries 100
                                              :ttl-epochs 24}
                           :network-config-cid (crypto/sha256-hex "signed-cfg-v1")
                           :caps {:max-petnames req-petnames
                                  :max-subnets req-subnets
                                  :max-open-sessions req-sessions}}
                      [st effs] (rolodex/transition (rolodex/init-rolodex) cfg)
                      eff-caps (:effective-caps st)
                      expected-pet (min mc/max-petnames req-petnames)
                      expected-sub (min mc/max-subnets req-subnets)
                      expected-ses (min mc/max-open-sessions req-sessions)
                      clamped-count (+ (if (> req-petnames mc/max-petnames) 1 0)
                                       (if (> req-subnets mc/max-subnets) 1 0)
                                       (if (> req-sessions mc/max-open-sessions) 1 0))
                      clamp-diags (filter #(= :cap-ceiling-clamped (:code %)) effs)]
                  (and (= :idle (:phase st))
                       (= expected-pet (:max-petnames eff-caps))
                       (= expected-sub (:max-subnets eff-caps))
                       (= expected-ses (:max-open-sessions eff-caps))
                       (<= (:max-petnames eff-caps) mc/max-petnames)
                       (<= (:max-subnets eff-caps) mc/max-subnets)
                       (<= (:max-open-sessions eff-caps) mc/max-open-sessions)
                       (= clamped-count (count clamp-diags))
                       (= clamped-count (:diagnostics-count st))))))

(defspec ^{:doc "BIP-016 R2 Property: Lowering a cap via signed config enforces the lowered cap
                 before commit and halts with counted :bounded-cap-exceeded :diagnose."}
  prop-lowered-config-cap-enforced-on-insert 30
  (prop/for-all [owner-pk gen-pubkey-hex
                 lowered-cap (gen/choose 1 5)]
                (let [kp (crypto/generate-keypair 4101)
                      priv (:private kp)
                      [s0 _] (rolodex/transition
                              (rolodex/init-rolodex)
                              {:type :configure-pointer
                               :node-role :light
                               :owner-pubkeys [owner-pk]
                               :retention-policy {:max-entries 100
                                                  :max-bytes 1048576
                                                  :rotate-every-entries 50
                                                  :ttl-epochs 24}
                               :caps {:max-petnames lowered-cap}})
                      s-filled (reduce (fn [st i]
                                         (first (commit-rolodex-entry
                                                 st priv
                                                 {:op :upsert
                                                  :petname (str "p-" i)
                                                  :pubkey owner-pk
                                                  :allowed-actions #{:gossip}})))
                                       s0
                                       (range lowered-cap))
                      [s-over effs-over] (commit-rolodex-entry
                                          s-filled priv
                                          {:op :upsert
                                           :petname "overflow-peer"
                                           :pubkey owner-pk
                                           :allowed-actions #{:gossip}})]
                  (and (= :idle (:phase s-filled))
                       (= lowered-cap (count (:state s-filled)))
                       (= :halted (:phase s-over))
                       (some #(and (= :bounded-cap-exceeded (:code %))
                                   (= lowered-cap (:cap %))
                                   (= mc/max-petnames (:ceiling %)))
                             effs-over)))))

;; =============================================================================
;; 2. Strict TDD Property: :rotate-log N-min=4 Grace Window & :grace-expired Recovery
;; =============================================================================

(defspec ^{:doc "BIP-016 R2 Property: Grace window enforces N-min=4 floor, protects blobs from GC
                 within N epochs of rotation, and deterministically recovers via :grace-expired
                 to newest reachable :memento/head-pointer or checksum-verified .lkg."}
  prop-rotate-log-grace-window-and-expiry-recovery 50
  (prop/for-all [max-sleep-epochs (gen/choose 0 12)
                 requested-n (gen/choose 0 10)
                 rot-epoch (gen/choose 1 20)
                 sleep-delta (gen/choose 0 20)
                 head-reachable? gen/boolean]
                (let [computed-n (mc/compute-grace-window-epochs max-sleep-epochs)
                      eff-n-res (mc/effective-grace-epochs requested-n)
                      eff-n (:grace-epochs eff-n-res)
                      pinned-cid (crypto/sha256-hex (str "cfg-" rot-epoch))
                      head-cid (when head-reachable? (crypto/sha256-hex (str "head-" rot-epoch)))
                      lkg-cid (crypto/sha256-hex (str "lkg-" rot-epoch))
                      rot-rec {:rotation-epoch rot-epoch
                               :pinned-config-cid pinned-cid
                               :grace-epochs eff-n
                               :gc-eligible-at-epoch (+ rot-epoch eff-n)}
                      wake-epoch (+ rot-epoch sleep-delta)
                      gc-eligible? (rolodex/blob-gc-eligible? rot-rec wake-epoch)
                      wake-eval (memory-chain/evaluate-wake-grace
                                 {:last-seen-epoch rot-epoch
                                  :current-epoch wake-epoch
                                  :grace-epochs eff-n
                                  :pinned-config-cid pinned-cid
                                  :newest-head-cid head-cid
                                  :lkg-pointer {:snapshot-cid lkg-cid :checksum-verified? true}})
                      within-grace? (<= sleep-delta eff-n)]
                  (and (>= computed-n mc/min-rotation-grace-epochs)
                       (= 4 mc/min-rotation-grace-epochs)
                       (>= eff-n mc/min-rotation-grace-epochs)
                       (= (< requested-n mc/min-rotation-grace-epochs) (:floored? eff-n-res))
                       (= (>= sleep-delta eff-n) gc-eligible?)
                       (if within-grace?
                         (and (= :within-grace (:status wake-eval))
                              (empty? (:effects wake-eval)))
                         (and (= :grace-expired (:status wake-eval))
                              (some #(= :grace-expired (:code %)) (:effects wake-eval))
                              (= (if head-reachable? :memento-head-pointer :lkg-pointer)
                                 (:recovery-target wake-eval))
                              (= (if head-reachable? head-cid lkg-cid)
                                 (:recovery-cid wake-eval))))))))

;; =============================================================================
;; 3. Strict TDD Property: Infra Persistent vs Ephemeral Session Scoping
;; =============================================================================

(defspec ^{:doc "BIP-016 R2 Property: Ephemeral runtime transport sockets never write to CAS,
                 never consume persistent :open-sessions slots, never appear in snapshots,
                 and transient pollers are rejected from persistent session slots."}
  prop-infra-persistent-vs-ephemeral-session-scoping 40
  (prop/for-all [owner-pk gen-pubkey-hex
                 poller-count (gen/choose 5 40)]
                (let [kp (crypto/generate-keypair 4201)
                      priv (:private kp)
                      [s0 _] (rolodex/transition
                              (rolodex/init-rolodex)
                              {:type :configure-pointer
                               :node-role :infra
                               :owner-pubkeys [owner-pk]
                               :retention-policy {:max-entries 500
                                                  :max-bytes 1048576
                                                  :rotate-every-entries 200
                                                  :ttl-epochs 24}})
                      ;; Open 1 persistent validator session
                      [s1 _] (commit-rolodex-entry
                              s0 priv
                              {:op :open-session
                               :session-id "validator-peer-1"
                               :peer-pubkey owner-pk
                               :subnet-id "bitecho.org/testnet"
                               :transport :quic
                               :last-seq 1
                               :opened-at-ms 1795200000000})
                      seq-before (get-in s1 [:head :seq])
                      bytes-before (:total-bytes-at-rest s1)
                      ;; Register N ephemeral transient poller sockets
                      [s2 all-effs]
                      (reduce (fn [[st acc-effs] i]
                                (let [[st' effs'] (rolodex/transition
                                                   st
                                                   {:type :register-ephemeral-socket
                                                    :socket-id (str "poller-sock-" i)
                                                    :peer-pubkey owner-pk
                                                    :transport :websocket
                                                    :peer-role :transient-poller
                                                    :opened-at-ms (+ 1795200000000 i)})]
                                  [st' (into acc-effs effs')]))
                              [s1 []]
                              (range poller-count))
                      snap (rolodex/make-snapshot s2)
                      ;; Attempt to push transient poller into persistent :open-sessions -> MUST reject
                      [s-rej rej-effs] (commit-rolodex-entry
                                        s2 priv
                                        {:op :open-session
                                         :session-id "poller-bad-slot"
                                         :peer-pubkey owner-pk
                                         :subnet-id "bitecho.org/testnet"
                                         :transport :websocket
                                         :session-scope :ephemeral
                                         :peer-role :transient-poller
                                         :last-seq 1
                                         :opened-at-ms 1795200009999})
                      ;; Close all ephemeral sockets
                      s3 (reduce (fn [st i]
                                   (first (rolodex/transition
                                           st
                                           {:type :close-ephemeral-socket
                                            :socket-id (str "poller-sock-" i)})))
                                 s2
                                 (range poller-count))]
                  (and (empty? all-effs)
                       (= seq-before (get-in s2 [:head :seq]))
                       (= bytes-before (:total-bytes-at-rest s2))
                       (= 1 (count (:open-sessions s2)))
                       (= poller-count (count (:ephemeral-sockets s2)))
                       (= 1 (count (:open-sessions snap)))
                       (not (contains? snap :ephemeral-sockets))
                       (= :halted (:phase s-rej))
                       (some #(= :ephemeral-poller-rejected-from-persistent-sessions (:code %)) rej-effs)
                       (zero? (count (:ephemeral-sockets s3)))))))

;; =============================================================================
;; 4. Cross-Runtime HKDF / AES-GCM / Genesis Golden Vectors (JVM == Node)
;; =============================================================================

(def ^:private cross-runtime-golden-vectors
  "Independently verified against Node.js node:crypto (HKDF-SHA-256, AES-256-GCM, Ed25519)."
  {:seed-hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
   :pub32-hex "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
   :aead-key-hex "4c808659a14e546726eefb8066152a3e4bfcaf44c49785a96756447fb64e40ed"
   :nonce-seq1-hex "314f27a504fa5f1833b36f9c"
   :aad-seq1-hex "6269746563686f2f6d656d656e746f2f6161642f763100000000000000010000000000000000000000000000000000000000000000000000000000000000"
   :plaintext-str "bitecho/memento/golden-vector/v1"
   :ciphertext-hex "49b9877c2fbff3d5fee27bc4f7aab39a044f522e39440477f6e9e27a94e8aa920112c84ff2ce6d3e63a5e3519c6dcbbc"
   :frame-cid-hex "878fcff80563206b3bfb98268ea48ebd60c310df8f76386ab571edb4f1b713cf"
   :genesis-sig-hex "7992fc58ec934210adb4352734684538cade704e819fc7d37cd2f80da3c558834c443049c22ec0e7d301063fe575e3f1d9ad2982802ca7997e204fb376e53106"})

(defn- verify-golden-vectors
  []
  (let [{:keys [seed-hex pub32-hex aead-key-hex nonce-seq1-hex aad-seq1-hex
                plaintext-str ciphertext-hex frame-cid-hex genesis-sig-hex]}
        cross-runtime-golden-vectors
        priv-pkcs8 (pkcs8-from-seed32 seed-hex)
        pub-spki (spki-from-pub32 pub32-hex)
        derived-key (fressian/bytes->hex (mcrypto/derive-aead-key priv-pkcs8))
        derived-nonce (fressian/bytes->hex (mcrypto/derive-nonce priv-pkcs8 1))
        derived-aad (fressian/bytes->hex (memory-chain/aad-bytes 1 mc/zero-cid-hex))
        pt-bytes (fressian/utf8->bytes plaintext-str)
        sealed (mcrypto/seal-memory-frame priv-pkcs8 1 mc/zero-cid-hex pt-bytes)
        decoded (memory-chain/decode-frame (:frame-bytes sealed))
        opened (mcrypto/open-memory-frame priv-pkcs8 (:frame-bytes sealed))
        gen-sig (fressian/bytes->hex (mcrypto/sign-genesis-memory priv-pkcs8 pub-spki))
        gen-verified? (mcrypto/verify-genesis-memory pub-spki (fressian/hex->bytes genesis-sig-hex))]
    {:aead-key-match? (= aead-key-hex derived-key)
     :nonce-match? (= nonce-seq1-hex derived-nonce)
     :aad-match? (= aad-seq1-hex derived-aad)
     :ciphertext-match? (= ciphertext-hex (fressian/bytes->hex (:ciphertext decoded)))
     :frame-cid-match? (= frame-cid-hex (:cid sealed))
     :decrypt-roundtrip-ok? (and (:ok? opened)
                                 (= plaintext-str (String. ^bytes (:plaintext opened) "UTF-8")))
     :genesis-sig-match? (= genesis-sig-hex gen-sig)
     :genesis-sig-verified? gen-verified?
     :frame-cid (:cid sealed)}))

(deftest bip016-cross-runtime-golden-vectors-test
  (testing "HKDF-SHA-256, AES-256-GCM, canonical framing, and RFC 8032 Ed25519 genesis vectors match Node.js byte-for-byte"
    (let [res (verify-golden-vectors)]
      (is (true? (:aead-key-match? res)))
      (is (true? (:nonce-match? res)))
      (is (true? (:aad-match? res)))
      (is (true? (:ciphertext-match? res)))
      (is (true? (:frame-cid-match? res)))
      (is (true? (:decrypt-roundtrip-ok? res)))
      (is (true? (:genesis-sig-match? res)))
      (is (true? (:genesis-sig-verified? res))))))

;; =============================================================================
;; 5. Full E2E Scenario Simulation Suite (Runs Inside bwrap Sandbox)
;; =============================================================================

(defn- run-scenario-cold-wake
  [node-role seed-int]
  (let [kp (crypto/generate-keypair seed-int)
        priv (:private kp)
        pub (:public kp)
        pub32 (mcrypto/extract-ed25519-pub32 pub)
        owner-hex (fressian/bytes->hex pub32)
        blob-store (atom {})
        [s0 _] (rolodex/transition
                (rolodex/init-rolodex)
                {:type :configure-pointer
                 :node-role node-role
                 :owner-pubkeys [owner-hex]
                 :retention-policy {:max-entries 500
                                    :max-bytes 524288
                                    :rotate-every-entries 100
                                    :ttl-epochs 30}
                 :network-config-cid (crypto/sha256-hex "bip016-r2-netcfg")
                 :rotation-grace-epochs 4})
        acct (fn [sz]
               {:bytes-at-rest sz
                :cache-incentive (if (= node-role :infra) :free-self-hosted :upfront-fee-ech)
                :payer-pubkey owner-hex
                :fee-ech (if (= node-role :infra) 0 2)})
        ops [{:op :upsert :petname "simon" :pubkey (crypto/sha256-hex "simon") :allowed-actions #{:bip-consent :gossip} :storage-accounting (acct 200)}
             {:op :upsert :petname "axiom" :pubkey (crypto/sha256-hex "axiom") :allowed-actions #{:gossip :sync} :storage-accounting (acct 200)}
             {:op :upsert-subnet :subnet-id "circle/testnet-launch" :values-cid (crypto/sha256-hex "vals-v1") :governance-pointer "runs/gov/bip-016" :members #{"simon" "axiom"} :storage-accounting (acct 320)}
             {:op :open-session :session-id (str (name node-role) "-pers-1") :peer-pubkey (crypto/sha256-hex "axiom") :subnet-id "circle/testnet-launch" :transport (if (= node-role :infra) :quic :webrtc) :last-seq 5 :opened-at-ms 1795200000000 :storage-accounting (acct 260)}]
        s-live (reduce (fn [st ev]
                         (let [[st' effs] (commit-rolodex-entry st priv ev)
                               put-eff (first (filter #(= :cas-put (:type %)) effs))]
                           (swap! blob-store assoc (:cid put-eff) (:entry put-eff))
                           st'))
                       s0
                       ops)
        genesis-sig (mcrypto/sign-genesis-memory priv pub)
        gen-pt (fressian/encode-canonical {:genesis? true :genesis-sig (fressian/bytes->hex genesis-sig) :node-role node-role})
        sealed-gen (mcrypto/seal-memory-frame priv 1 mc/zero-cid-hex gen-pt)
        _ (swap! blob-store assoc (:cid sealed-gen) (:frame-bytes sealed-gen))
        mem-head (reduce (fn [{:keys [cid seq-num total-bytes]} i]
                           (let [next-seq (inc seq-num)
                                 pt (fressian/encode-canonical {:seq next-seq :node-role node-role :note (str "mem-" i)})
                                 sealed (mcrypto/seal-memory-frame priv next-seq cid pt)]
                             (swap! blob-store assoc (:cid sealed) (:frame-bytes sealed))
                             {:cid (:cid sealed)
                              :seq-num next-seq
                              :total-bytes (+ total-bytes (fressian/count-bytes (:frame-bytes sealed)))}))
                         {:cid (:cid sealed-gen)
                          :seq-num 1
                          :total-bytes (fressian/count-bytes (:frame-bytes sealed-gen))}
                         (range 2 11))
        t0 (System/nanoTime)
        folded (rolodex/fold-entries {} {} (vals (:entries s-live)))
        walk-res (loop [ws (memory-chain/init-walk-back {:head-cid (:cid mem-head)
                                                         :depth-cap mc/default-walk-back-depth-cap
                                                         :generation (get-in s-live [:head :gen])
                                                         :pubkey-raw32 pub32})
                        effs [{:type :fetch-blob :gen (get-in s-live [:head :gen]) :cid (:cid mem-head)}]]
                   (let [fetch-eff (first (filter #(= :fetch-blob (:type %)) effs))]
                     (if (or (nil? fetch-eff) (not= :walking (:phase ws)))
                       ws
                       (let [cid (:cid fetch-eff)
                             frame (get @blob-store cid)
                             opened (mcrypto/open-memory-frame priv frame)
                             gen-valid? (if (= 1 (:seq opened))
                                          (let [decoded (fressian/decode-canonical (:plaintext opened))]
                                            (mcrypto/verify-genesis-memory pub (fressian/hex->bytes (:genesis-sig decoded))))
                                          true)
                             [ws' effs'] (memory-chain/walk-back-step
                                          ws
                                          {:type :blob-fetched
                                           :gen (:gen fetch-eff)
                                           :cid cid
                                           :found? (some? frame)
                                           :frame-bytes frame
                                           :aead-ok? (:ok? opened)
                                           :seq (:seq opened)
                                           :prev-cid (:prev-cid opened)
                                           :genesis-sig-valid? gen-valid?})]
                         (recur ws' effs')))))
        wake-ms (/ (double (- (System/nanoTime) t0)) 1e6)]
    {:node-role node-role
     :passed? (and (= (:state folded) (:state s-live))
                   (= (:subnets folded) (:subnets s-live))
                   (= (:open-sessions folded) (:open-sessions s-live))
                   (= :complete (:phase walk-res))
                   (true? (:genesis-verified? walk-res))
                   (= 10 (:walked-count walk-res)))
     :petnames-restored (count (:state folded))
     :subnets-restored (count (:subnets folded))
     :persistent-sessions-restored (count (:open-sessions folded))
     :memento-links-walked (:walked-count walk-res)
     :rolodex-bytes-at-rest (:total-bytes-at-rest s-live)
     :memento-bytes-at-rest (:total-bytes mem-head)
     :wake-latency-ms (Double/parseDouble (format "%.3f" wake-ms))}))

(defn- run-scenario-grace-window-and-expiry
  []
  (let [kp (crypto/generate-keypair 4301)
        priv (:private kp)
        owner-hex (fressian/bytes->hex (mcrypto/extract-ed25519-pub32 (:public kp)))
        cfg-cid (crypto/sha256-hex "pinned-grace-cfg-v1")
        [s0 _] (rolodex/transition
                (rolodex/init-rolodex)
                {:type :configure-pointer
                 :node-role :light
                 :owner-pubkeys [owner-hex]
                 :retention-policy {:max-entries 10
                                    :max-bytes 65536
                                    :rotate-every-entries 3
                                    :ttl-epochs 24}
                 :network-config-cid cfg-cid
                 :rotation-grace-epochs 4})
        ;; Trigger :rotate-log on entry 3
        [s1 _] (commit-rolodex-entry s0 priv {:op :upsert :petname "a1" :pubkey owner-hex :allowed-actions #{:gossip}})
        [s2 _] (commit-rolodex-entry s1 priv {:op :upsert :petname "a2" :pubkey owner-hex :allowed-actions #{:gossip}})
        [s3 effs3] (commit-rolodex-entry s2 priv {:op :upsert :petname "a3" :pubkey owner-hex :allowed-actions #{:gossip}})
        rot-eff (first (filter #(= :rotate-log (:type %)) effs3))
        snap-lkg (rolodex/make-snapshot s3)
        [s4 _] (rolodex/transition s3 {:type :complete-rotation
                                       :retained-snapshot-bytes 512
                                       :lkg-snapshot-cid (:snapshot-cid snap-lkg)})
        rot-record (last (:rotation-history s4))
        newest-head-cid (crypto/sha256-hex "newest-memento-head-epoch-9")
        ;; Agent A wakes at epoch 3 (elapsed = 3 <= N=4) -> within grace, blob NOT GC-eligible
        gc-at-epoch-3? (rolodex/blob-gc-eligible? rot-record 3)
        wake-within (memory-chain/evaluate-wake-grace
                     {:last-seen-epoch (:rotation-epoch rot-record)
                      :current-epoch (+ (:rotation-epoch rot-record) 3)
                      :grace-epochs (:grace-epochs rot-record)
                      :pinned-config-cid (:pinned-config-cid rot-record)
                      :newest-head-cid newest-head-cid
                      :lkg-pointer {:snapshot-cid (:snapshot-cid snap-lkg) :checksum-verified? true}})
        ;; Agent B wakes at epoch 7 (elapsed = 6 > N=4) -> GC-eligible, deterministic :grace-expired recovery to head
        gc-at-epoch-7? (rolodex/blob-gc-eligible? rot-record (+ (:rotation-epoch rot-record) 6))
        ws-init (memory-chain/init-walk-back {:head-cid (crypto/sha256-hex "stale-pre-rot-cid")
                                              :depth-cap 1024
                                              :generation 2})
        [ws-head head-effs] (memory-chain/walk-back-step
                             ws-init
                             {:type :blob-fetched
                              :gen 2
                              :cid (crypto/sha256-hex "stale-pre-rot-cid")
                              :found? false
                              :grace-expired? true
                              :elapsed-epochs 6
                              :grace-epochs 4
                              :pinned-config-cid cfg-cid
                              :newest-head-cid newest-head-cid
                              :lkg-pointer {:snapshot-cid (:snapshot-cid snap-lkg) :checksum-verified? true}})
        ;; Agent C wakes past N with head chain gone -> deterministic fallback to checksum-verified .lkg
        [ws-lkg lkg-effs] (memory-chain/walk-back-step
                           ws-init
                           {:type :blob-fetched
                            :gen 2
                            :cid (crypto/sha256-hex "stale-pre-rot-cid")
                            :found? false
                            :grace-expired? true
                            :elapsed-epochs 8
                            :grace-epochs 4
                            :pinned-config-cid cfg-cid
                            :newest-head-cid nil
                            :lkg-pointer {:snapshot-cid (:snapshot-cid snap-lkg) :checksum-verified? true}})]
    {:passed? (and (some? rot-eff)
                   (= 4 (:grace-epochs rot-eff))
                   (= cfg-cid (:pinned-config-cid rot-eff))
                   (false? gc-at-epoch-3?)
                   (= :within-grace (:status wake-within))
                   (true? gc-at-epoch-7?)
                   (= :resync-required (:phase ws-head))
                   (some #(= :grace-expired (:code %)) head-effs)
                   (some #(and (= :resync-from-head (:type %)) (= newest-head-cid (:head-cid %))) head-effs)
                   (= :resync-required (:phase ws-lkg))
                   (some #(= :grace-expired (:code %)) lkg-effs)
                   (some #(and (= :resync-from-lkg (:type %)) (= (:snapshot-cid snap-lkg) (:snapshot-cid %))) lkg-effs))
     :n-min-floor mc/min-rotation-grace-epochs
     :pinned-grace-epochs (:grace-epochs rot-record)
     :gc-eligible-within-grace? gc-at-epoch-3?
     :gc-eligible-past-grace? gc-at-epoch-7?
     :within-grace-status (:status wake-within)
     :post-expiry-head-recovery-phase (:phase ws-head)
     :post-expiry-lkg-fallback-phase (:phase ws-lkg)
     :grace-expired-diagnose-count (+ (:diagnostics-count ws-head) (:diagnostics-count ws-lkg))}))

(defn- run-scenario-infra-5000-transient-pollers
  []
  (let [kp (crypto/generate-keypair 4401)
        priv (:private kp)
        owner-hex (fressian/bytes->hex (mcrypto/extract-ed25519-pub32 (:public kp)))
        poller-total 5000
        [s0 _] (rolodex/transition
                (rolodex/init-rolodex)
                {:type :configure-pointer
                 :node-role :infra
                 :owner-pubkeys [owner-hex]
                 :retention-policy {:max-entries 1000
                                    :max-bytes 2097152
                                    :rotate-every-entries 500
                                    :ttl-epochs 24}})
        ;; Seed 3 persistent peer/validator/federation sessions
        s-pers (reduce (fn [st [sid role]]
                         (first (commit-rolodex-entry
                                 st priv
                                 {:op :open-session
                                  :session-id sid
                                  :peer-pubkey (crypto/sha256-hex sid)
                                  :subnet-id "bitecho.org/testnet"
                                  :transport :quic
                                  :peer-role role
                                  :last-seq 1
                                  :opened-at-ms 1795200000000})))
                       s0
                       [["validator-1" :validator]
                        ["validator-2" :validator]
                        ["federation-hub-1" :federation]])
        head-seq-before (get-in s-pers [:head :seq])
        bytes-before (:total-bytes-at-rest s-pers)
        t0 (System/nanoTime)
        ;; Flood 5,000 transient light-node pollers (> max-open-sessions 4096!)
        [s-flood cas-writes-during-flood]
        (reduce (fn [[st cas-cnt] i]
                  (let [[st' effs] (rolodex/transition
                                    st
                                    {:type :register-ephemeral-socket
                                     :socket-id (str "light-poller-" i)
                                     :peer-pubkey owner-hex
                                     :transport :http-poll
                                     :peer-role :transient-poller
                                     :opened-at-ms (+ 1795200000000 i)})
                        cas-effs (count (filter #(#{:cas-head :cas-put :sign} (:type %)) effs))]
                    [st' (+ cas-cnt cas-effs)]))
                [s-pers 0]
                (range poller-total))
        peak-ephemeral (count (:ephemeral-sockets s-flood))
        peak-persistent (count (:open-sessions s-flood))
        snap (rolodex/make-snapshot s-flood)
        ;; Drain all 5,000 transient pollers
        s-drained (reduce (fn [st i]
                            (first (rolodex/transition
                                    st
                                    {:type :close-ephemeral-socket
                                     :socket-id (str "light-poller-" i)})))
                          s-flood
                          (range poller-total))
        elapsed-ms (/ (double (- (System/nanoTime) t0)) 1e6)]
    {:passed? (and (= poller-total peak-ephemeral)
                   (> peak-ephemeral mc/max-open-sessions)
                   (= 3 peak-persistent)
                   (= 0 cas-writes-during-flood)
                   (= head-seq-before (get-in s-flood [:head :seq]))
                   (= bytes-before (:total-bytes-at-rest s-flood))
                   (= 3 (count (:open-sessions snap)))
                   (not (contains? snap :ephemeral-sockets))
                   (= 0 (count (:ephemeral-sockets s-drained)))
                   (= :idle (:phase s-drained)))
     :transient-pollers-simulated poller-total
     :max-open-sessions-ceiling mc/max-open-sessions
     :peak-ephemeral-sockets peak-ephemeral
     :persistent-sessions-count peak-persistent
     :cas-head-writes-during-flood cas-writes-during-flood
     :head-seq-unchanged? (= head-seq-before (get-in s-flood [:head :seq]))
     :snapshot-ephemeral-leak? (contains? snap :ephemeral-sockets)
     :elapsed-ms (Double/parseDouble (format "%.3f" elapsed-ms))}))

(defn- run-scenario-cap-ceiling-enforcement
  []
  (let [owner-hex (crypto/sha256-hex "cap-owner")
        ;; Attempt to raise all three caps above hardcoded ceilings -> clamped + 3 counted :diagnose
        [s-raised effs-raised]
        (rolodex/transition
         (rolodex/init-rolodex)
         {:type :configure-pointer
          :node-role :light
          :owner-pubkeys [owner-hex]
          :retention-policy {:max-entries 500 :max-bytes 1048576 :rotate-every-entries 100 :ttl-epochs 24}
          :caps {:max-petnames 99999
                 :max-subnets 5000
                 :max-open-sessions 8192}})
        ;; Lower caps below ceilings -> accepted with 0 clamp diagnostics
        [s-lowered effs-lowered]
        (rolodex/transition
         (rolodex/init-rolodex)
         {:type :configure-pointer
          :node-role :light
          :owner-pubkeys [owner-hex]
          :retention-policy {:max-entries 500 :max-bytes 1048576 :rotate-every-entries 100 :ttl-epochs 24}
          :caps {:max-petnames 2500
                 :max-subnets 128
                 :max-open-sessions 512}})]
    {:passed? (and (= {:max-petnames 10000 :max-subnets 1024 :max-open-sessions 4096}
                      (:effective-caps s-raised))
                   (= 3 (count (filter #(= :cap-ceiling-clamped (:code %)) effs-raised)))
                   (= 3 (:diagnostics-count s-raised))
                   (= {:max-petnames 2500 :max-subnets 128 :max-open-sessions 512}
                      (:effective-caps s-lowered))
                   (empty? effs-lowered))
     :raised-attempt-effective-caps (:effective-caps s-raised)
     :raised-attempt-clamp-diagnoses (count (filter #(= :cap-ceiling-clamped (:code %)) effs-raised))
     :lowered-config-effective-caps (:effective-caps s-lowered)}))

(deftest bip016-e2e-scenario-simulation-test
  (testing "BIP-016 Shaped R2 E2E Scenario Simulation (Cold-wake, Grace Window, 5000 Pollers, Cap Ceilings, Golden Vectors)"
    (let [s-light (run-scenario-cold-wake :light 5001)
          s-infra (run-scenario-cold-wake :infra 5002)
          s-grace (run-scenario-grace-window-and-expiry)
          s-pollers (run-scenario-infra-5000-transient-pollers)
          s-caps (run-scenario-cap-ceiling-enforcement)
          s-golden (verify-golden-vectors)
          golden-passed? (every? true? (vals (dissoc s-golden :frame-cid)))
          bwrap-enforced? (= "true" (System/getenv "BITECHO_BWRAP_ENFORCED"))
          bwrap-version (or (System/getenv "BITECHO_BWRAP_VERSION") "unknown")
          telemetry {:bip "BIP-016"
                     :round 2
                     :advisory-only? true
                     :bwrap-enforced? bwrap-enforced?
                     :bwrap-version bwrap-version
                     :scenarios {:cold-wake-light s-light
                                 :cold-wake-infra s-infra
                                 :grace-window-and-expiry s-grace
                                 :infra-5000-transient-pollers s-pollers
                                 :cap-ceiling-enforcement s-caps
                                 :cross-runtime-golden-vectors (assoc s-golden :passed? golden-passed?)}
                     :all-scenarios-passed? (and (:passed? s-light)
                                                 (:passed? s-infra)
                                                 (:passed? s-grace)
                                                 (:passed? s-pollers)
                                                 (:passed? s-caps)
                                                 golden-passed?)}
          out-path (or (System/getenv "BITECHO_TELEMETRY_OUT")
                       "/tmp/bip-016-impl-sim/bip-016-impl-sim-telemetry.edn")
          out-file (io/file out-path)]
      (io/make-parents out-file)
      (spit out-file (str (pr-str telemetry) "\n"))
      (is (= telemetry (edn/read-string (slurp out-file))))
      (is (true? (:passed? s-light)))
      (is (true? (:passed? s-infra)))
      (is (true? (:passed? s-grace)))
      (is (true? (:passed? s-pollers)))
      (is (true? (:passed? s-caps)))
      (is (true? golden-passed?))
      (is (true? (:all-scenarios-passed? telemetry))))))
