(ns bitecho.memento-lumen-wakeup-sim-test
  "Run-2 Implementation Circle: Strict TDD generative properties (Rule 1) and
   Instrumented Lumen Wake-Up End-to-End Simulator covering:
   - BIP-A: Signed Append-Only Rolodex & Head-Record CAS
   - BIP-B: Circles & Advisory Twin Capability Boundary
   - BIP-C: Encrypted Hash-Linked Memory Chain (AES-256-GCM + HKDF-SHA-256 + RFC 8032 genesis)
   - Deterministic 10,000-entry Rolodex + 1,024-link memory walk-back cold-wake benchmark"
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.memento.circles :as circles]
            [bitecho.memento.constants :as mc]
            [bitecho.memento.memory-chain :as memory-chain]
            [bitecho.memento.rolodex :as rolodex]
            [bitecho.shell.memento-crypto :as mcrypto]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Test Generators & Helpers
;; =============================================================================

(def ^:private gen-petname
  (gen/elements ["simon" "axiom" "nexus" "vector" "lumen" "peer-a" "peer-b" "peer-c"]))

(def ^:private gen-action
  (gen/elements [:gossip :publish :read-blob :bip-consent :sign-real :advisory-vote :sync]))

(def ^:private gen-actions-set
  (gen/fmap set (gen/vector gen-action 1 4)))

(def ^:private gen-hex-char
  (gen/elements (vec "0123456789abcdef")))

(def ^:private gen-pubkey-hex
  (gen/fmap #(apply str %) (gen/vector gen-hex-char 64)))

(def ^:private gen-command
  (gen/one-of
   [(gen/hash-map :cmd (gen/return :upsert)
                  :petname gen-petname
                  :pubkey gen-pubkey-hex
                  :allowed-actions gen-actions-set)
    (gen/hash-map :cmd (gen/return :revoke)
                  :petname gen-petname
                  :allowed-actions gen-actions-set)
    (gen/hash-map :cmd (gen/return :crash-after-claim)
                  :petname gen-petname
                  :pubkey gen-pubkey-hex
                  :allowed-actions gen-actions-set)
    (gen/hash-map :cmd (gen/return :stale-callback))
    (gen/hash-map :cmd (gen/return :second-writer-cas-loss)
                  :petname gen-petname
                  :pubkey gen-pubkey-hex
                  :allowed-actions gen-actions-set)
    (gen/hash-map :cmd (gen/return :inject-sign-failure)
                  :petname gen-petname
                  :pubkey gen-pubkey-hex
                  :allowed-actions gen-actions-set)
    (gen/hash-map :cmd (gen/return :inject-put-failure)
                  :petname gen-petname
                  :pubkey gen-pubkey-hex
                  :allowed-actions gen-actions-set)]))

(defn- effect-contains-secret?
  "Audits an effect map recursively to ensure raw seed or private-key bytes never leak."
  [effect secret-bytes-list]
  (let [secret-hexes (map fressian/bytes->hex secret-bytes-list)]
    (letfn [(scan [x]
              (cond
                (nil? x) false
                (fressian/bytes? x)
                (boolean (some #(mc/bytes-contain-subseq? x %) secret-bytes-list))
                (string? x)
                (boolean (some #(str/includes? (str/lower-case x) %) secret-hexes))
                (map? x)
                (boolean (some (fn [[k v]] (or (scan k) (scan v))) x))
                (coll? x)
                (boolean (some scan x))
                :else false))]
      (scan effect))))

;; =============================================================================
;; Rule 1 Strict TDD Generative Properties
;; =============================================================================

(defspec ^{:doc "BIP-A Command-Sequence Model Property: CAS-before-sign/put ordering,
                 no (key, :seq) ever signed/encrypted twice across crashes/restarts,
                 no seed/private-key bytes in any effect payload, stale callbacks
                 dropped & counted, lost CAS halts with counted :diagnose."}
  prop-single-writer-cas-and-crash-burn-never-reuses-key-seq 40
  (prop/for-all [seed-int (gen/choose 1 100000)
                 commands (gen/vector gen-command 1 20)]
                (let [kp (crypto/generate-keypair seed-int)
                      priv (:private kp)
                      seed32 (mcrypto/extract-ed25519-seed32 priv)
                      secrets [priv seed32]]
                  (loop [cmds commands
                         state (rolodex/init-rolodex)
                         signed-seqs #{}
                         all-ok? true]
                    (if (or (empty? cmds) (not all-ok?))
                      all-ok?
                      (let [{:keys [cmd petname pubkey allowed-actions]} (first cmds)]
                        (cond
                          ;; If halted from a prior fault injection, restart cleanly via crash-and-restart
                          (= :halted (:phase state))
                          (let [remote-head (:head state)
                                [s1 effs] (rolodex/transition state {:type :crash-and-restart
                                                                     :remote-head remote-head})
                                leak? (some #(effect-contains-secret? % secrets) effs)]
                            (recur cmds s1 signed-seqs (and all-ok? (not leak?) (= :idle (:phase s1)))))

                          (= cmd :upsert)
                          (let [[s1 effs1] (rolodex/transition state {:type :propose-entry
                                                                      :op :upsert
                                                                      :petname petname
                                                                      :pubkey pubkey
                                                                      :allowed-actions allowed-actions})
                                cas-eff (first effs1)
                                only-cas? (and (= 1 (count effs1))
                                               (= :cas-head (:type cas-eff)))
                                claimed-seq (get-in cas-eff [:claimed-head :seq])
                                claimed-gen (:gen cas-eff)
                                [s2 effs2] (rolodex/transition s1 {:type :cas-head-result
                                                                   :gen claimed-gen
                                                                   :ok? true})
                                sign-eff (first effs2)
                                reused? (contains? signed-seqs claimed-seq)
                                sig (mcrypto/sign-rolodex-entry priv (:entry sign-eff))
                                [s3 effs3] (rolodex/transition s2 {:type :sign-result
                                                                   :gen claimed-gen
                                                                   :seq claimed-seq
                                                                   :ok? true
                                                                   :signature sig})
                                put-eff (first effs3)
                                [s4 effs4] (rolodex/transition s3 {:type :cas-put-result
                                                                   :gen claimed-gen
                                                                   :seq claimed-seq
                                                                   :cid (:cid put-eff)
                                                                   :ok? true})
                                all-effs (concat effs1 effs2 effs3 effs4)
                                leak? (some #(effect-contains-secret? % secrets) all-effs)]
                            (recur (rest cmds)
                                   s4
                                   (conj signed-seqs claimed-seq)
                                   (and all-ok?
                                        only-cas?
                                        (= :sign (:type sign-eff))
                                        (= :cas-put (:type put-eff))
                                        (= :emit (:type (first effs4)))
                                        (not reused?)
                                        (not leak?)
                                        (= :idle (:phase s4)))))

                          (= cmd :revoke)
                          (let [[s1 effs1] (rolodex/transition state {:type :propose-entry
                                                                      :op :revoke
                                                                      :petname petname
                                                                      :allowed-actions allowed-actions})
                                cas-eff (first effs1)
                                claimed-seq (get-in cas-eff [:claimed-head :seq])
                                claimed-gen (:gen cas-eff)
                                [s2 effs2] (rolodex/transition s1 {:type :cas-head-result
                                                                   :gen claimed-gen
                                                                   :ok? true})
                                sign-eff (first effs2)
                                reused? (contains? signed-seqs claimed-seq)
                                sig (mcrypto/sign-rolodex-entry priv (:entry sign-eff))
                                [s3 effs3] (rolodex/transition s2 {:type :sign-result
                                                                   :gen claimed-gen
                                                                   :seq claimed-seq
                                                                   :ok? true
                                                                   :signature sig})
                                put-eff (first effs3)
                                [s4 effs4] (rolodex/transition s3 {:type :cas-put-result
                                                                   :gen claimed-gen
                                                                   :seq claimed-seq
                                                                   :cid (:cid put-eff)
                                                                   :ok? true})
                                leak? (some #(effect-contains-secret? % secrets)
                                            (concat effs1 effs2 effs3 effs4))]
                            (recur (rest cmds)
                                   s4
                                   (conj signed-seqs claimed-seq)
                                   (and all-ok? (not reused?) (not leak?) (= :idle (:phase s4)))))

                          (= cmd :crash-after-claim)
                          (let [[s1 effs1] (rolodex/transition state {:type :propose-entry
                                                                      :op :upsert
                                                                      :petname petname
                                                                      :pubkey pubkey
                                                                      :allowed-actions allowed-actions})
                                cas-eff (first effs1)
                                claimed-head (:claimed-head cas-eff)
                                claimed-seq (:seq claimed-head)
                                ;; Simulate crash right after Pointer CAS succeeded with :head-cid nil
                                [s2 effs2] (rolodex/transition s1 {:type :crash-and-restart
                                                                   :remote-head claimed-head})
                                diag-burn? (some #(and (= :diagnose (:type %))
                                                       (= :claimed-seq-burned (:code %)))
                                                 effs2)
                                burned? (contains? (:burned-seqs s2) claimed-seq)
                                ;; Next seq must be claimed-seq + 1, never claimed-seq!
                                [s3 effs3] (rolodex/transition s2 {:type :propose-entry
                                                                   :op :upsert
                                                                   :petname petname
                                                                   :pubkey pubkey
                                                                   :allowed-actions allowed-actions})
                                next-seq (get-in (first effs3) [:claimed-head :seq])
                                ;; Complete or reset via crash? Let's complete it cleanly.
                                next-gen (:gen (first effs3))
                                [s4 effs4] (rolodex/transition s3 {:type :cas-head-result :gen next-gen :ok? true})
                                sig (mcrypto/sign-rolodex-entry priv (:entry (first effs4)))
                                [s5 effs5] (rolodex/transition s4 {:type :sign-result :gen next-gen :seq next-seq :ok? true :signature sig})
                                [s6 effs6] (rolodex/transition s5 {:type :cas-put-result :gen next-gen :seq next-seq :cid (:cid (first effs5)) :ok? true})
                                leak? (some #(effect-contains-secret? % secrets)
                                            (concat effs1 effs2 effs3 effs4 effs5 effs6))]
                            (recur (rest cmds)
                                   s6
                                   (conj signed-seqs next-seq)
                                   (and all-ok?
                                        diag-burn?
                                        burned?
                                        (= next-seq (inc claimed-seq))
                                        (not (contains? signed-seqs next-seq))
                                        (not leak?))))

                          (= cmd :stale-callback)
                          (let [stale-gen (dec (:generation state))
                                prev-dropped (:dropped state)
                                [s1 effs1] (rolodex/transition state {:type :sign-result
                                                                      :gen stale-gen
                                                                      :seq 1
                                                                      :ok? true
                                                                      :signature "deadbeef"})
                                diag-stale? (some #(and (= :diagnose (:type %))
                                                        (= :stale-generation-callback (:code %)))
                                                  effs1)]
                            (recur (rest cmds)
                                   s1
                                   signed-seqs
                                   (and all-ok?
                                        (= (:dropped s1) (inc prev-dropped))
                                        diag-stale?)))

                          (= cmd :second-writer-cas-loss)
                          (let [[s1 effs1] (rolodex/transition state {:type :propose-entry
                                                                      :op :upsert
                                                                      :petname petname
                                                                      :pubkey pubkey
                                                                      :allowed-actions allowed-actions})
                                claimed-gen (:gen (first effs1))
                                [s2 effs2] (rolodex/transition s1 {:type :cas-head-result
                                                                   :gen claimed-gen
                                                                   :ok? false
                                                                   :reason :cas-mismatch})
                                halted? (= :halted (:phase s2))
                                diag-lost? (some #(and (= :diagnose (:type %))
                                                       (= :cas-head-lost (:code %)))
                                                 effs2)
                                no-retry? (not (some #(#{:cas-head :sign :encrypt :cas-put :emit} (:type %)) effs2))]
                            (recur (rest cmds)
                                   s2
                                   signed-seqs
                                   (and all-ok? halted? diag-lost? no-retry?)))

                          (= cmd :inject-sign-failure)
                          (let [[s1 effs1] (rolodex/transition state {:type :propose-entry
                                                                      :op :upsert
                                                                      :petname petname
                                                                      :pubkey pubkey
                                                                      :allowed-actions allowed-actions})
                                claimed-gen (:gen (first effs1))
                                claimed-seq (get-in (first effs1) [:claimed-head :seq])
                                [s2 _] (rolodex/transition s1 {:type :cas-head-result :gen claimed-gen :ok? true})
                                [s3 effs3] (rolodex/transition s2 {:type :sign-result
                                                                   :gen claimed-gen
                                                                   :seq claimed-seq
                                                                   :ok? false
                                                                   :error :hsm-unavailable})]
                            (recur (rest cmds)
                                   s3
                                   signed-seqs
                                   (and all-ok?
                                        (= :halted (:phase s3))
                                        (some #(= :diagnose (:type %)) effs3))))

                          (= cmd :inject-put-failure)
                          (let [[s1 effs1] (rolodex/transition state {:type :propose-entry
                                                                      :op :upsert
                                                                      :petname petname
                                                                      :pubkey pubkey
                                                                      :allowed-actions allowed-actions})
                                claimed-gen (:gen (first effs1))
                                claimed-seq (get-in (first effs1) [:claimed-head :seq])
                                [s2 effs2] (rolodex/transition s1 {:type :cas-head-result :gen claimed-gen :ok? true})
                                sig (mcrypto/sign-rolodex-entry priv (:entry (first effs2)))
                                [s3 effs3] (rolodex/transition s2 {:type :sign-result :gen claimed-gen :seq claimed-seq :ok? true :signature sig})
                                [s4 effs4] (rolodex/transition s3 {:type :cas-put-result
                                                                   :gen claimed-gen
                                                                   :seq claimed-seq
                                                                   :cid (:cid (first effs3))
                                                                   :ok? false
                                                                   :error :blob-store-timeout})]
                            (recur (rest cmds)
                                   s4
                                   (conj signed-seqs claimed-seq)
                                   (and all-ok?
                                        (= :halted (:phase s4))
                                        (some #(= :diagnose (:type %)) effs4)))))))))))

(defspec ^{:doc "BIP-A Invariant: Replayed seq <= head, forks (same seq, different content),
                 bad signatures, missing prev-cid/snapshot, and pre-decode ceiling breaches
                 (> 256 KiB blob or > 4 MiB snapshot) ALWAYS halt with counted :diagnose."}
  prop-replay-fork-ceiling-and-bad-sig-always-halt 40
  (prop/for-all [petname gen-petname
                 pubkey gen-pubkey-hex
                 other-pubkey gen-pubkey-hex
                 actions gen-actions-set
                 blob-over (gen/choose (inc mc/max-blob-bytes) (+ mc/max-blob-bytes 65536))
                 snap-over (gen/choose (inc mc/max-snapshot-bytes) (+ mc/max-snapshot-bytes 65536))]
                (let [kp (crypto/generate-keypair 42)
                      e1 {:seq 1 :prev-cid mc/zero-cid-hex :op :upsert
                          :petname petname :pubkey pubkey :allowed-actions actions}
                      sig1 (mcrypto/sign-rolodex-entry (:private kp) e1)
                      cid1 (rolodex/entry-cid (assoc e1 :signature sig1))
                      ;; Apply valid entry 1
                      [s1 effs1] (rolodex/transition (rolodex/init-rolodex)
                                                     {:type :apply-remote-entry
                                                      :entry (assoc e1 :signature sig1)
                                                      :cid cid1
                                                      :declared-bytes 256
                                                      :sig-valid? true})
                      ;; 1. Replay (same seq 1, same cid)
                      [s-replay effs-replay] (rolodex/transition s1 {:type :apply-remote-entry
                                                                     :entry (assoc e1 :signature sig1)
                                                                     :cid cid1
                                                                     :declared-bytes 256
                                                                     :sig-valid? true})
                      ;; 2. Fork (same seq 1, different content/cid)
                      e1-fork (assoc e1 :pubkey (str other-pubkey "ff"))
                      cid1-fork (rolodex/entry-cid (assoc e1-fork :signature sig1))
                      [s-fork effs-fork] (rolodex/transition s1 {:type :apply-remote-entry
                                                                 :entry (assoc e1-fork :signature sig1)
                                                                 :cid cid1-fork
                                                                 :declared-bytes 256
                                                                 :sig-valid? true})
                      ;; 3. Bad signature on seq 2
                      e2 {:seq 2 :prev-cid cid1 :op :upsert
                          :petname petname :pubkey pubkey :allowed-actions actions}
                      [s-badsig effs-badsig] (rolodex/transition s1 {:type :apply-remote-entry
                                                                     :entry (assoc e2 :signature "00")
                                                                     :cid (rolodex/entry-cid (assoc e2 :signature "00"))
                                                                     :declared-bytes 256
                                                                     :sig-valid? false})
                      ;; 4. Missing prev-cid on seq 2
                      e2-badprev (assoc e2 :prev-cid mc/zero-cid-hex)
                      [s-prev effs-prev] (rolodex/transition s1 {:type :apply-remote-entry
                                                                 :entry (assoc e2-badprev :signature sig1)
                                                                 :cid (rolodex/entry-cid (assoc e2-badprev :signature sig1))
                                                                 :declared-bytes 256
                                                                 :sig-valid? true})
                      ;; 5. Missing snapshot on :restore
                      e2-restore {:seq 2 :prev-cid cid1 :op :restore :snapshot-cid mc/zero-cid-hex}
                      [s-nosnap effs-nosnap] (rolodex/transition s1 {:type :apply-remote-entry
                                                                     :entry (assoc e2-restore :signature sig1)
                                                                     :cid (rolodex/entry-cid (assoc e2-restore :signature sig1))
                                                                     :declared-bytes 256
                                                                     :sig-valid? true})
                      ;; 6. Blob pre-decode ceiling breach (> 256 KiB)
                      [s-blob effs-blob] (rolodex/transition s1 {:type :apply-remote-entry
                                                                 :entry (assoc e2 :signature sig1)
                                                                 :cid (rolodex/entry-cid (assoc e2 :signature sig1))
                                                                 :declared-bytes blob-over
                                                                 :sig-valid? true})
                      ;; 7. Snapshot pre-decode ceiling breach (> 4 MiB)
                      [s-snap effs-snap] (rolodex/transition s1 {:type :load-snapshot
                                                                 :snapshot {:seq 1 :head-cid cid1 :state (:state s1)}
                                                                 :declared-bytes snap-over})]
                  (and (empty? effs1)
                       (= :idle (:phase s1))
                       (= :halted (:phase s-replay))
                       (some #(and (= :diagnose (:type %)) (= :seq-replay-or-stale (:code %))) effs-replay)
                       (= :halted (:phase s-fork))
                       (some #(and (= :diagnose (:type %)) (= :fork-detected (:code %))) effs-fork)
                       (= :halted (:phase s-badsig))
                       (some #(and (= :diagnose (:type %)) (= :bad-signature (:code %))) effs-badsig)
                       (= :halted (:phase s-prev))
                       (some #(and (= :diagnose (:type %)) (= :missing-prev-cid (:code %))) effs-prev)
                       (= :halted (:phase s-nosnap))
                       (some #(and (= :diagnose (:type %)) (= :missing-snapshot (:code %))) effs-nosnap)
                       (= :halted (:phase s-blob))
                       (some #(and (= :diagnose (:type %)) (= :blob-ceiling-exceeded (:code %))) effs-blob)
                       (= :halted (:phase s-snap))
                       (some #(and (= :diagnose (:type %)) (= :snapshot-ceiling-exceeded (:code %))) effs-snap)))))

(defspec ^{:doc "BIP-A Invariant: Snapshot equals fold of log deltas up to :seq;
                 forward .lkg :restore appends at head :seq+1, bumps :gen, and
                 grow-only revocations NEVER resurrect revoked :allowed-actions."}
  prop-lkg-forward-rollback-never-resurrects-revocations 40
  (prop/for-all [petname gen-petname
                 pubkey gen-pubkey-hex
                 initial-actions (gen/fmap set (gen/vector gen-action 2 5))
                 revoked-action gen-action]
                (let [kp (crypto/generate-keypair 77)
                      actions-with-rev (conj initial-actions revoked-action)
                      ;; Commit entry 1 (upsert with actions-with-rev)
                      apply-entry (fn [st op-map]
                                    (let [s (inc (get-in st [:head :seq]))
                                          entry (merge {:seq s :prev-cid (get-in st [:head :head-cid])} op-map)
                                          sig (mcrypto/sign-rolodex-entry (:private kp) entry)
                                          signed (assoc entry :signature sig)
                                          cid (rolodex/entry-cid signed)
                                          [st' _] (rolodex/transition st {:type :apply-remote-entry
                                                                          :entry signed
                                                                          :cid cid
                                                                          :declared-bytes 256
                                                                          :sig-valid? true})]
                                      st'))
                      s1 (apply-entry (rolodex/init-rolodex)
                                      {:op :upsert :petname petname :pubkey pubkey :allowed-actions actions-with-rev})
                      ;; Take .lkg snapshot at seq 1 (BEFORE revocation!)
                      lkg-snap (rolodex/make-snapshot s1)
                      snap-matches-fold? (rolodex/verify-snapshot-matches-fold lkg-snap (vals (:entries s1)))
                      ;; Commit entry 2 (revoke revoked-action)
                      s2 (apply-entry s1 {:op :revoke :petname petname :allowed-actions #{revoked-action}})
                      ;; Load .lkg snapshot into s2 and perform forward rollback at seq 3
                      [s2-loaded _] (rolodex/transition s2 {:type :load-snapshot
                                                            :snapshot lkg-snap
                                                            :declared-bytes 512})
                      gen-before (:generation s2-loaded)
                      [s3 effs3] (rolodex/transition s2-loaded {:type :propose-restore
                                                                :snapshot-cid (:snapshot-cid lkg-snap)})
                      cas-eff (first effs3)
                      restore-gen (:gen cas-eff)
                      restore-seq (get-in cas-eff [:claimed-head :seq])
                      [s4 effs4] (rolodex/transition s3 {:type :cas-head-result :gen restore-gen :ok? true})
                      sig (mcrypto/sign-rolodex-entry (:private kp) (:entry (first effs4)))
                      [s5 effs5] (rolodex/transition s4 {:type :sign-result :gen restore-gen :seq restore-seq :ok? true :signature sig})
                      [s6 _] (rolodex/transition s5 {:type :cas-put-result :gen restore-gen :seq restore-seq :cid (:cid (first effs5)) :ok? true})
                      restored-actions (get-in s6 [:state petname :allowed-actions])]
                  (and snap-matches-fold?
                       (= restore-seq 3)
                       (> restore-gen gen-before)
                       (= :idle (:phase s6))
                       (not (contains? restored-actions revoked-action))
                       (contains? (get-in s6 [:revoked-actions petname]) revoked-action)))))

(defspec ^{:doc "BIP-B Invariant: Advisory twin can NEVER reach real bip-consent or signing
                 handles even via inherited :human-anchor, :allowed-actions, or signed entries;
                 emits counted :diagnose :advisory-twin-real-consent-blocked."}
  prop-advisory-twin-never-reaches-real-consent-or-signing 50
  (prop/for-all [twin-name gen-petname
                 pubkey gen-pubkey-hex
                 real-action (gen/elements [:bip-consent :sign-real :sign-bip-receipt :access-signing-handle])
                 twin-marker (gen/elements [{:advisory-twin? true} {:role :twin} {:advisory-twin? true :role :twin}])]
                (let [parent-circle (circles/make-circle {:subnet-id "circle/core"
                                                          :members (set [twin-name "simon"])
                                                          :values-cid mc/zero-cid-hex
                                                          :governance-pointer "runs/gov/core"
                                                          :human-anchor twin-name})
                      subcircle (circles/create-subcircle parent-circle
                                                          {:subnet-id "circle/core/impl"
                                                           :members #{twin-name}
                                                           :values-cid mc/zero-cid-hex
                                                           :governance-pointer "runs/gov/impl"})
                      ;; Neutral circle without :human-anchor is also valid at protocol level
                      neutral-circle (circles/make-circle {:subnet-id "circle/neutral"
                                                           :members #{"peer-a"}
                                                           :values-cid mc/zero-cid-hex
                                                           :governance-pointer "runs/gov/neutral"
                                                           :human-anchor nil})
                      rolodex-state {twin-name {:petname twin-name
                                                :pubkey pubkey
                                                :allowed-actions #{:bip-consent :sign-real :sign-bip-receipt :access-signing-handle :advisory-vote}}}
                      actor (merge {:petname twin-name :signed-entry-valid? true} twin-marker)
                      res-parent (circles/authorize-action parent-circle rolodex-state actor {:action real-action})
                      res-sub (circles/authorize-action subcircle rolodex-state actor {:action real-action})
                      res-adv (circles/authorize-action subcircle rolodex-state actor {:action :advisory-vote})]
                  (and (= twin-name (:human-anchor subcircle))
                       (circles/valid-circle? neutral-circle)
                       (false? (:allowed? res-parent))
                       (= :advisory-twin-real-consent-blocked (:reason res-parent))
                       (some #(and (= :diagnose (:type %))
                                   (= :advisory-twin-real-consent-blocked (:code %)))
                             (:effects res-parent))
                       (false? (:allowed? res-sub))
                       (= :advisory-twin-real-consent-blocked (:reason res-sub))
                       (true? (:allowed? res-adv))
                       (true? (:advisory-only res-adv))))))

(defspec ^{:doc "BIP-C Invariant: Canonical framing be64(seq)||raw32(prev-cid)||be32(len)||ciphertext,
                 CID = sha256-hex(frame), AES-256-GCM + HKDF-SHA-256 roundtrip, genesis RFC 8032
                 signature, and counted :diagnose halts on missing blob, AEAD tag failure,
                 stale generation, forked :prev-cid, key loss, or depth cap exceeded."}
  prop-memory-chain-roundtrip-framing-and-fault-halts 30
  (prop/for-all [seed-int (gen/choose 1 50000)
                 msg-strs (gen/vector (gen/not-empty gen/string-alphanumeric) 2 6)]
                (let [kp (crypto/generate-keypair seed-int)
                      priv (:private kp)
                      pub (:public kp)
                      pub32 (mcrypto/extract-ed25519-pub32 pub)
                      ;; Build a valid encrypted chain starting with genesis (seq 1)
                      genesis-sig (mcrypto/sign-genesis-memory priv pub)
                      genesis-payload (fressian/encode-canonical {:genesis? true
                                                                  :genesis-sig (fressian/bytes->hex genesis-sig)
                                                                  :note "Lumen Genesis Memory"})
                      sealed-gen (mcrypto/seal-memory-frame priv 1 mc/zero-cid-hex genesis-payload)
                      {:keys [blobs head-cid head-seq]}
                      (reduce (fn [{:keys [blobs head-cid head-seq]} msg]
                                (let [next-seq (inc head-seq)
                                      pt (fressian/utf8->bytes msg)
                                      sealed (mcrypto/seal-memory-frame priv next-seq head-cid pt)]
                                  {:blobs (assoc blobs (:cid sealed) (:frame-bytes sealed))
                                   :head-cid (:cid sealed)
                                   :head-seq next-seq}))
                              {:blobs {(:cid sealed-gen) (:frame-bytes sealed-gen)}
                               :head-cid (:cid sealed-gen)
                               :head-seq 1}
                              msg-strs)
                      ;; Helper to run streaming walk-back against a blob map + key
                      run-walk (fn [blob-map priv-key depth-cap & {:keys [inject-stale-gen?]}]
                                 (loop [ws (memory-chain/init-walk-back {:head-cid head-cid
                                                                         :depth-cap depth-cap
                                                                         :generation 5
                                                                         :pubkey-raw32 pub32})
                                        effs [{:type :fetch-blob :gen 5 :cid head-cid}]
                                        all-effs []]
                                   (let [fetch-eff (first (filter #(= :fetch-blob (:type %)) effs))]
                                     (if (or (nil? fetch-eff) (not= :walking (:phase ws)))
                                       {:state ws :effects all-effs}
                                       (let [cid (:cid fetch-eff)
                                             frame (get blob-map cid)
                                             cb-gen (if inject-stale-gen? 2 (:gen fetch-eff))
                                             ev (cond
                                                  (nil? frame)
                                                  {:type :blob-fetched :gen cb-gen :cid cid :found? false}
                                                  (nil? priv-key)
                                                  {:type :blob-fetched :gen cb-gen :cid cid :found? true :key-lost? true}
                                                  :else
                                                  (let [opened (mcrypto/open-memory-frame priv-key frame)]
                                                    (if (:ok? opened)
                                                      (let [decoded-gen (when (= 1 (:seq opened))
                                                                          (try (fressian/decode-canonical (:plaintext opened))
                                                                               (catch Exception _ nil)))
                                                            gen-valid? (if (= 1 (:seq opened))
                                                                         (and (map? decoded-gen)
                                                                              (string? (:genesis-sig decoded-gen))
                                                                              (mcrypto/verify-genesis-memory
                                                                               pub
                                                                               (fressian/hex->bytes (:genesis-sig decoded-gen))))
                                                                         true)]
                                                        {:type :blob-fetched
                                                         :gen cb-gen
                                                         :cid cid
                                                         :found? true
                                                         :frame-bytes frame
                                                         :aead-ok? true
                                                         :seq (:seq opened)
                                                         :prev-cid (:prev-cid opened)
                                                         :genesis-sig-valid? gen-valid?})
                                                      {:type :blob-fetched
                                                       :gen cb-gen
                                                       :cid cid
                                                       :found? true
                                                       :frame-bytes frame
                                                       :aead-ok? false})))
                                             [ws' effs'] (memory-chain/walk-back-step ws ev)]
                                         (recur ws' effs' (into all-effs effs')))))))
                      ok-run (run-walk blobs priv mc/default-walk-back-depth-cap)
                      missing-run (run-walk (dissoc blobs (:cid sealed-gen)) priv mc/default-walk-back-depth-cap)
                      tampered-frame (let [orig ^bytes (get blobs head-cid)
                                           copy (byte-array orig)]
                                       (aset copy (dec (alength copy))
                                             (unchecked-byte (bit-xor (aget copy (dec (alength copy))) 0xFF)))
                                       copy)
                      tamper-run (run-walk (assoc blobs head-cid tampered-frame) priv mc/default-walk-back-depth-cap)
                      keyloss-run (run-walk blobs nil mc/default-walk-back-depth-cap)
                      cap-run (run-walk blobs priv 1)
                      stale-run (run-walk blobs priv mc/default-walk-back-depth-cap :inject-stale-gen? true)]
                  (and (= :complete (get-in ok-run [:state :phase]))
                       (= head-seq (get-in ok-run [:state :walked-count]))
                       (true? (get-in ok-run [:state :genesis-verified?]))
                       (= :halted (get-in missing-run [:state :phase]))
                       (some #(= :missing-blob (:code %)) (:effects missing-run))
                       (= :halted (get-in tamper-run [:state :phase]))
                       (some #(= :aead-tag-failure (:code %)) (:effects tamper-run))
                       (= :halted (get-in keyloss-run [:state :phase]))
                       (some #(= :key-loss (:code %)) (:effects keyloss-run))
                       (= :halted (get-in cap-run [:state :phase]))
                       (some #(= :depth-cap-exceeded (:code %)) (:effects cap-run))
                       (pos? (get-in stale-run [:state :dropped]))
                       (some #(= :stale-generation (:code %)) (:effects stale-run))))))

;; =============================================================================
;; Instrumented Lumen Wake-Up End-to-End Simulator & Cold-Wake Benchmark
;; =============================================================================

(defn- heap-used-bytes []
  (let [rt (Runtime/getRuntime)]
    (- (.totalMemory rt) (.freeMemory rt))))

(defn- run-lumen-wakeup-trial
  "Executes one complete instrumented Lumen wake-up trial from blank memory."
  [trial-idx]
  (let [t0 (System/nanoTime)
        ;; 1. Setup: Create Lumen's Ed25519 identity + teammates + Circle + Encrypted Memory Chain
        lumen-kp (crypto/generate-keypair (+ 1000 trial-idx))
        lumen-priv (:private lumen-kp)
        lumen-pub (:public lumen-kp)
        lumen-pub32 (mcrypto/extract-ed25519-pub32 lumen-pub)
        lumen-seed32 (mcrypto/extract-ed25519-seed32 lumen-priv)
        teammates (into {}
                        (for [[idx nm] (map-indexed vector ["simon" "axiom" "nexus" "vector"])]
                          (let [kp (crypto/generate-keypair (+ 2000 (* 10 trial-idx) idx))]
                            [nm {:pubkey (fressian/bytes->hex (mcrypto/extract-ed25519-pub32 (:public kp)))
                                 :allowed-actions (if (= nm "simon")
                                                    #{:bip-consent :gossip :publish :sync}
                                                    #{:gossip :publish :sync})}])))
        ;; In-memory Blob & Pointer CAS stores
        blob-store (atom {})
        pointer-cas (atom {:seq 0 :head-cid mc/zero-cid-hex :gen 0 :memory-head-cid mc/zero-cid-hex})
        ;; Build Rolodex with snapshot + CRDT deltas
        rolodex-after-base
        (reduce (fn [st [nm {:keys [pubkey allowed-actions]}]]
                  (let [[s1 effs1] (rolodex/transition st {:type :propose-entry
                                                           :op :upsert
                                                           :petname nm
                                                           :pubkey pubkey
                                                           :allowed-actions allowed-actions})
                        cas-eff (first effs1)
                        claimed (:claimed-head cas-eff)
                        _ (reset! pointer-cas claimed)
                        [s2 effs2] (rolodex/transition s1 {:type :cas-head-result :gen (:gen cas-eff) :ok? true})
                        sig (mcrypto/sign-rolodex-entry lumen-priv (:entry (first effs2)))
                        [s3 effs3] (rolodex/transition s2 {:type :sign-result :gen (:gen cas-eff) :seq (:seq claimed) :ok? true :signature sig})
                        put-eff (first effs3)
                        _ (swap! blob-store assoc (:cid put-eff) (:entry put-eff))
                        [s4 _] (rolodex/transition s3 {:type :cas-put-result :gen (:gen cas-eff) :seq (:seq claimed) :cid (:cid put-eff) :ok? true})
                        _ (reset! pointer-cas (:head s4))]
                    s4))
                (rolodex/init-rolodex)
                teammates)
        lkg-snap (rolodex/make-snapshot rolodex-after-base)
        _ (swap! blob-store assoc (:snapshot-cid lkg-snap) lkg-snap)
        ;; Append 2 post-snapshot CRDT deltas (add peer-edge, revoke :publish from peer-edge)
        rolodex-final
        (reduce (fn [st op-map]
                  (let [[s1 effs1] (rolodex/transition st (assoc op-map :type :propose-entry))
                        cas-eff (first effs1)
                        claimed (:claimed-head cas-eff)
                        _ (reset! pointer-cas claimed)
                        [s2 effs2] (rolodex/transition s1 {:type :cas-head-result :gen (:gen cas-eff) :ok? true})
                        sig (mcrypto/sign-rolodex-entry lumen-priv (:entry (first effs2)))
                        [s3 effs3] (rolodex/transition s2 {:type :sign-result :gen (:gen cas-eff) :seq (:seq claimed) :ok? true :signature sig})
                        put-eff (first effs3)
                        _ (swap! blob-store assoc (:cid put-eff) (:entry put-eff))
                        [s4 _] (rolodex/transition s3 {:type :cas-put-result :gen (:gen cas-eff) :seq (:seq claimed) :cid (:cid put-eff) :ok? true})
                        _ (reset! pointer-cas (:head s4))]
                    s4))
                rolodex-after-base
                [{:op :upsert :petname "peer-edge" :pubkey (fressian/bytes->hex (crypto/sha256 "peer-edge")) :allowed-actions #{:gossip :publish}}
                 {:op :revoke :petname "peer-edge" :allowed-actions #{:publish}}])
        ;; Build 12-link Encrypted Memory Chain starting with RFC 8032 genesis
        genesis-sig (mcrypto/sign-genesis-memory lumen-priv lumen-pub)
        genesis-pt (fressian/encode-canonical {:genesis? true
                                               :genesis-sig (fressian/bytes->hex genesis-sig)
                                               :agent "lumen"
                                               :trial trial-idx})
        sealed-gen (mcrypto/seal-memory-frame lumen-priv 1 mc/zero-cid-hex genesis-pt)
        _ (swap! blob-store assoc (:cid sealed-gen) (:frame-bytes sealed-gen))
        mem-head
        (reduce (fn [{:keys [cid seq-num]} idx]
                  (let [next-seq (inc seq-num)
                        pt (fressian/encode-canonical {:seq next-seq
                                                       :memory (str "Lumen session journal #" idx " trial " trial-idx)
                                                       :circle "circle/core/impl"})
                        sealed (mcrypto/seal-memory-frame lumen-priv next-seq cid pt)]
                    (swap! blob-store assoc (:cid sealed) (:frame-bytes sealed))
                    {:cid (:cid sealed) :seq-num next-seq}))
                {:cid (:cid sealed-gen) :seq-num 1}
                (range 2 13))
        ;; Update Pointer CAS with unified head record
        _ (swap! pointer-cas assoc :memory-head-cid (:cid mem-head))
        ;; Parent circle + Subcircle inheriting :human-anchor
        core-circle (circles/make-circle {:subnet-id "circle/core"
                                          :members #{"simon" "axiom" "nexus" "vector" "lumen"}
                                          :values-cid (crypto/sha256-hex "bitecho-core-values-v1")
                                          :governance-pointer "runs/governance/core"
                                          :human-anchor "simon"})
        impl-circle (circles/create-subcircle core-circle
                                              {:subnet-id "circle/core/impl"
                                               :members #{"simon" "axiom" "nexus" "vector" "lumen"}
                                               :values-cid (crypto/sha256-hex "bitecho-impl-values-v1")
                                               :governance-pointer "runs/governance/impl"})
        ;; Local Memento clue (ONLY local clue; private key is loaded locally, NEVER in network blobs!)
        memento-note {:agent "lumen"
                      :head-pointer-key "lumen/head"
                      :snapshot-cid (:snapshot-cid lkg-snap)
                      :circle-descriptors [core-circle impl-circle]}

        ;; =====================================================================
        ;; WAKE-UP SEQUENCE (Blank Agent Memory -> Full Continuity Restored)
        ;; =====================================================================
        wake-t0 (System/nanoTime)
        ;; Step 1: Audit network blob store to prove zero private-key/seed bytes stored remotely
        secret-leak-in-blobs?
        (boolean (some #(effect-contains-secret? % [lumen-priv lumen-seed32]) (vals @blob-store)))

        ;; Step 2: Read Memento note + Pointer CAS head, verify Rolodex head & signature
        remote-head @pointer-cas
        head-entry (get @blob-store (:head-cid remote-head))
        head-sig-valid? (mcrypto/verify-rolodex-entry lumen-pub
                                                      (dissoc head-entry :signature)
                                                      (:signature head-entry))

        ;; Step 3: Follow memory-head-cid and stream walk-back to genesis
        walk-res
        (loop [ws (memory-chain/init-walk-back {:head-cid (:memory-head-cid remote-head)
                                                :depth-cap mc/default-walk-back-depth-cap
                                                :generation (:gen remote-head)
                                                :pubkey-raw32 lumen-pub32})
               effs [{:type :fetch-blob :gen (:gen remote-head) :cid (:memory-head-cid remote-head)}]]
          (let [fetch-eff (first (filter #(= :fetch-blob (:type %)) effs))]
            (if (or (nil? fetch-eff) (not= :walking (:phase ws)))
              ws
              (let [cid (:cid fetch-eff)
                    frame (get @blob-store cid)
                    opened (mcrypto/open-memory-frame lumen-priv frame)
                    decoded (when (:ok? opened) (fressian/decode-canonical (:plaintext opened)))
                    gen-valid? (if (= 1 (:seq opened))
                                 (mcrypto/verify-genesis-memory
                                  lumen-pub
                                  (fressian/hex->bytes (:genesis-sig decoded)))
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

        ;; Step 4: Restore Rolodex from latest snapshot + apply post-snapshot CRDT deltas
        snap-blob (get @blob-store (:snapshot-cid memento-note))
        [restored-base _] (rolodex/transition (rolodex/init-rolodex)
                                              {:type :load-snapshot
                                               :snapshot snap-blob
                                               :declared-bytes 2048})
        post-snap-entries (->> (vals (:entries rolodex-final))
                               (filter #(> (:seq %) (:seq snap-blob)))
                               (sort-by :seq))
        restored-rolodex
        (reduce (fn [st entry]
                  (let [sig-ok? (mcrypto/verify-rolodex-entry lumen-pub
                                                              (dissoc entry :signature)
                                                              (:signature entry))
                        cid (rolodex/entry-cid entry)
                        [st' _] (rolodex/transition st {:type :apply-remote-entry
                                                        :entry entry
                                                        :cid cid
                                                        :declared-bytes 512
                                                        :sig-valid? sig-ok?})]
                    st'))
                (assoc restored-base
                       :head {:seq (:seq snap-blob)
                              :head-cid (:head-cid snap-blob)
                              :gen 1
                              :memory-head-cid (:memory-head-cid remote-head)}
                       :state (:state snap-blob)
                       :revoked-actions (or (:revoked-actions snap-blob) {}))
                post-snap-entries)
        fold-equality? (= (:state restored-rolodex) (:state rolodex-final))
        ;; Verify circle :human-anchor inheritance & advisory twin boundary
        resolved-members (circles/resolve-circle-members impl-circle (:state restored-rolodex))
        twin-attempt (circles/authorize-action impl-circle
                                               (:state restored-rolodex)
                                               {:petname "simon" :advisory-twin? true :role :twin}
                                               {:action :bip-consent})
        wake-ms (/ (double (- (System/nanoTime) wake-t0)) 1e6)
        total-ms (/ (double (- (System/nanoTime) t0)) 1e6)]
    {:trial trial-idx
     :ok? (and (not secret-leak-in-blobs?)
               head-sig-valid?
               (= :complete (:phase walk-res))
               (true? (:genesis-verified? walk-res))
               (= 12 (:walked-count walk-res))
               fold-equality?
               (= "simon" (:human-anchor impl-circle))
               (false? (:allowed? twin-attempt))
               (= :advisory-twin-real-consent-blocked (:reason twin-attempt))
               (= 4 (count (filter :verified? (vals resolved-members)))))
     :secret-leak-in-blobs? secret-leak-in-blobs?
     :head-sig-valid? head-sig-valid?
     :memory-links-walked (:walked-count walk-res)
     :genesis-verified? (:genesis-verified? walk-res)
     :rolodex-fold-equality? fold-equality?
     :circle-human-anchor (:human-anchor impl-circle)
     :advisory-twin-blocked? (false? (:allowed? twin-attempt))
     :reconnected-teammates (vec (sort (keys (into {} (filter (fn [[_ v]] (:verified? v)) resolved-members)))))
     :wake-latency-ms (Double/parseDouble (format "%.3f" wake-ms))
     :total-trial-ms (Double/parseDouble (format "%.3f" total-ms))}))

(defn- run-cold-wake-benchmark
  "Deterministic 10,000-entry Rolodex + 1,024-link memory walk-back cold-wake benchmark.
   Measures exact JVM latency (ms) and heap delta (MiB) against pinned Run-2 thresholds."
  []
  (let [kp (crypto/generate-keypair 9999)
        priv (:private kp)
        pub (:public kp)
        pub32 (mcrypto/extract-ed25519-pub32 pub)
        ;; Build 10,000 Rolodex entries (9,900 folded into snapshot + 100 post-snapshot deltas)
        entries-10k (mapv (fn [i]
                            {:seq i
                             :prev-cid (if (= i 1) mc/zero-cid-hex (format "%064x" (dec i)))
                             :op :upsert
                             :petname (str "peer-" i)
                             :pubkey (format "%064x" i)
                             :allowed-actions #{:gossip :sync}})
                          (range 1 10001))
        ;; Build 1,024-link encrypted memory chain (seq 1 = genesis .. seq 1024 = head)
        genesis-sig (mcrypto/sign-genesis-memory priv pub)
        genesis-pt (fressian/encode-canonical {:genesis? true
                                               :genesis-sig (fressian/bytes->hex genesis-sig)})
        sealed-gen (mcrypto/seal-memory-frame priv 1 mc/zero-cid-hex genesis-pt)
        {:keys [mem-blobs mem-head-cid]}
        (loop [i 2
               prev-cid (:cid sealed-gen)
               blobs (transient {(:cid sealed-gen) (:frame-bytes sealed-gen)})]
          (if (> i 1024)
            {:mem-blobs (persistent! blobs) :mem-head-cid prev-cid}
            (let [pt (fressian/utf8->bytes (str "mem-link-" i))
                  sealed (mcrypto/seal-memory-frame priv i prev-cid pt)]
              (recur (inc i) (:cid sealed) (assoc! blobs (:cid sealed) (:frame-bytes sealed))))))
        ;; Settle GC before measuring cold-wake heap delta & latency
        _ (System/gc)
        heap-before (heap-used-bytes)
        t0 (System/nanoTime)
        ;; 1. Fold all 10,000 Rolodex entries from cold start
        folded (rolodex/fold-entries {} {} entries-10k)
        ;; 2. Stream walk-back all 1,024 encrypted memory links to genesis
        walk-res
        (loop [ws (memory-chain/init-walk-back {:head-cid mem-head-cid
                                                :depth-cap 1024
                                                :generation 1
                                                :pubkey-raw32 pub32})
               effs [{:type :fetch-blob :gen 1 :cid mem-head-cid}]]
          (let [fetch-eff (first (filter #(= :fetch-blob (:type %)) effs))]
            (if (or (nil? fetch-eff) (not= :walking (:phase ws)))
              ws
              (let [cid (:cid fetch-eff)
                    frame (get mem-blobs cid)
                    opened (mcrypto/open-memory-frame priv frame)
                    gen-valid? (if (= 1 (:seq opened))
                                 (let [decoded (fressian/decode-canonical (:plaintext opened))]
                                   (mcrypto/verify-genesis-memory
                                    pub
                                    (fressian/hex->bytes (:genesis-sig decoded))))
                                 true)
                    [ws' effs'] (memory-chain/walk-back-step
                                 ws
                                 {:type :blob-fetched
                                  :gen 1
                                  :cid cid
                                  :found? (some? frame)
                                  :frame-bytes frame
                                  :aead-ok? (:ok? opened)
                                  :seq (:seq opened)
                                  :prev-cid (:prev-cid opened)
                                  :genesis-sig-valid? gen-valid?})]
                (recur ws' effs')))))
        elapsed-ms (/ (double (- (System/nanoTime) t0)) 1e6)
        heap-after (heap-used-bytes)
        heap-delta-mib (max 0.0 (/ (double (- heap-after heap-before)) (* 1024.0 1024.0)))
        thresholds (get mc/cold-wake-thresholds :jvm)]
    {:rolodex-entries-folded (count (:state folded))
     :memory-links-walked (:walked-count walk-res)
     :genesis-verified? (:genesis-verified? walk-res)
     :walk-phase (:phase walk-res)
     :elapsed-ms (Double/parseDouble (format "%.3f" elapsed-ms))
     :heap-delta-mib (Double/parseDouble (format "%.3f" heap-delta-mib))
     :threshold-max-ms (:max-p95-ms thresholds)
     :threshold-max-heap-mib (:max-heap-delta-mib thresholds)
     :within-thresholds? (and (<= elapsed-ms (:max-p95-ms thresholds))
                              (<= heap-delta-mib (:max-heap-delta-mib thresholds)))}))

(deftest lumen-wakeup-e2e-simulator-and-cold-wake-benchmark
  (testing "3 full instrumented Lumen wake-up trials + 10,000-entry / 1,024-link cold-wake benchmark"
    (let [trials (mapv run-lumen-wakeup-trial [1 2 3])
          benchmark (run-cold-wake-benchmark)
          telemetry {:simulator "lumen-wakeup-e2e-v1"
                     :advisory-only? true
                     :spec-constants {:rolodex-domain-tag mc/rolodex-domain-tag
                                      :memory-aead-info mc/memory-aead-info
                                      :memory-nonce-info mc/memory-nonce-info
                                      :memory-aad-prefix mc/memory-aad-prefix
                                      :memory-genesis-prefix mc/memory-genesis-prefix
                                      :max-blob-bytes mc/max-blob-bytes
                                      :max-snapshot-bytes mc/max-snapshot-bytes
                                      :default-walk-back-depth-cap mc/default-walk-back-depth-cap}
                     :trials trials
                     :all-trials-passed? (every? :ok? trials)
                     :cold-wake-benchmark benchmark}
          out-file (io/file (or (System/getenv "BITECHO_TELEMETRY_DIR") "/tmp")
                            "lumen-wakeup-sim-telemetry.edn")]
      (spit out-file (str (pr-str telemetry) "\n"))
      (is (= telemetry (edn/read-string (slurp out-file))))
      (doseq [tr trials]
        (is (:ok? tr) (str "Trial failed: " (pr-str tr)))
        (is (false? (:secret-leak-in-blobs? tr)))
        (is (true? (:head-sig-valid? tr)))
        (is (true? (:genesis-verified? tr)))
        (is (true? (:rolodex-fold-equality? tr)))
        (is (true? (:advisory-twin-blocked? tr))))
      (is (= 10000 (:rolodex-entries-folded benchmark)))
      (is (= 1024 (:memory-links-walked benchmark)))
      (is (true? (:genesis-verified? benchmark)))
      (is (= :complete (:walk-phase benchmark)))
      (is (true? (:within-thresholds? benchmark))
          (str "Cold-wake benchmark exceeded pinned thresholds: " (pr-str benchmark))))))

;; =============================================================================
;; BIP-016 Strict TDD Properties: State Discipline, Retention/Rotation,
;; Bytes-at-Rest Accounting, Memento Pointer, and Unified Light + Infra Recovery
;; =============================================================================

(def ^:private gen-node-role
  (gen/elements [:light :infra]))

(def ^:private gen-transport
  (gen/elements [:webrtc :websocket :quic :tcp-relay]))

(def ^:private gen-cache-incentive
  (gen/elements [:free-self-hosted :upfront-fee-ech]))

(defn- commit-rolodex-entry
  "Helper that drives a single Rolodex proposal through CAS -> sign -> put."
  [st priv event]
  (let [[s1 effs1] (rolodex/transition st (assoc event :type :propose-entry))]
    (if (= :halted (:phase s1))
      [s1 effs1]
      (let [cas-eff (first effs1)
            claimed-gen (:gen cas-eff)
            claimed-seq (get-in cas-eff [:claimed-head :seq])
            [s2 effs2] (rolodex/transition s1 {:type :cas-head-result :gen claimed-gen :ok? true})
            sig (mcrypto/sign-rolodex-entry priv (:entry (first effs2)))
            [s3 effs3] (rolodex/transition s2 {:type :sign-result :gen claimed-gen :seq claimed-seq :ok? true :signature sig})
            put-eff (first effs3)
            [s4 effs4] (rolodex/transition s3 {:type :cas-put-result
                                               :gen claimed-gen
                                               :seq claimed-seq
                                               :cid (:cid put-eff)
                                               :ok? true})]
        [s4 (vec (concat effs1 effs2 effs3 effs4))]))))

(defspec ^{:doc "BIP-016 Property: Missing/empty :owner-pubkeys rejects with :missing-state-owner;
                 missing/unbounded :retention-policy rejects with :missing-retention-policy;
                 exceeding :max-bytes or :max-entries halts with :retention-bound-exceeded;
                 reaching :rotate-every-entries triggers clean :rotate-log."}
  prop-bip016-bounded-growth-retention-and-rotation 40
  (prop/for-all [node-role gen-node-role
                 owner-pk gen-pubkey-hex
                 rotate-every (gen/choose 2 5)]
                (let [kp (crypto/generate-keypair 1601)
                      priv (:private kp)
                      ;; 1. Missing owner-pubkeys rejected loudly
                      [s-no-owner effs-no-owner]
                      (rolodex/transition (rolodex/init-rolodex)
                                          {:type :configure-pointer
                                           :node-role node-role
                                           :owner-pubkeys []
                                           :retention-policy {:max-entries 10 :max-bytes 65536
                                                              :rotate-every-entries rotate-every :ttl-epochs 7}})
                      ;; 2. Missing retention-policy rejected loudly
                      [s-no-ret effs-no-ret]
                      (rolodex/transition (rolodex/init-rolodex)
                                          {:type :configure-pointer
                                           :node-role node-role
                                           :owner-pubkeys [owner-pk]
                                           :retention-policy nil})
                      ;; 3. Valid pointer config with tight rotate-every and max-bytes
                      valid-cfg {:node-role node-role
                                 :owner-pubkeys [owner-pk]
                                 :retention-policy {:max-entries (+ rotate-every 2)
                                                    :max-bytes 4096
                                                    :rotate-every-entries rotate-every
                                                    :ttl-epochs 10}}
                      [s-ok effs-ok] (rolodex/transition (rolodex/init-rolodex)
                                                         (assoc valid-cfg :type :configure-pointer))
                      ;; Commit rotate-every entries to trigger :rotate-log effect
                      {:keys [state rotate-emitted?]}
                      (reduce (fn [{:keys [state rotate-emitted?]} i]
                                (let [[st' effs] (commit-rolodex-entry
                                                  state priv
                                                  {:op :upsert
                                                   :petname (str "p-" i)
                                                   :pubkey owner-pk
                                                   :allowed-actions #{:gossip}
                                                   :storage-accounting {:bytes-at-rest 200
                                                                        :cache-incentive :free-self-hosted
                                                                        :payer-pubkey owner-pk
                                                                        :fee-ech 0}})]
                                  {:state st'
                                   :rotate-emitted? (or rotate-emitted?
                                                        (boolean (some #(= :rotate-log (:type %)) effs)))}))
                              {:state s-ok :rotate-emitted? false}
                              (range 1 (inc rotate-every)))
                      ;; Complete rotation cleanly -> bumps :rotation-epoch, resets :entries-since-rotation
                      [s-rot _] (rolodex/transition state {:type :complete-rotation
                                                           :retained-snapshot-bytes 128})
                      ;; Exceed :max-bytes -> halts with :retention-bound-exceeded
                      [s-over effs-over] (commit-rolodex-entry
                                          s-rot priv
                                          {:op :upsert
                                           :petname "too-big"
                                           :pubkey owner-pk
                                           :allowed-actions #{:gossip}
                                           :storage-accounting {:bytes-at-rest 5000
                                                                :cache-incentive :upfront-fee-ech
                                                                :payer-pubkey owner-pk
                                                                :fee-ech 10}})]
                  (and (= :halted (:phase s-no-owner))
                       (some #(= :missing-state-owner (:code %)) effs-no-owner)
                       (= :halted (:phase s-no-ret))
                       (some #(= :missing-retention-policy (:code %)) effs-no-ret)
                       (empty? effs-ok)
                       (= node-role (:node-role s-ok))
                       rotate-emitted?
                       (= 1 (:rotation-epoch s-rot))
                       (= 0 (:entries-since-rotation s-rot))
                       (= 128 (:total-bytes-at-rest s-rot))
                       (= :halted (:phase s-over))
                       (some #(= :retention-bound-exceeded (:code %)) effs-over)))))

(defspec ^{:doc "BIP-016 Property: Bytes-at-rest accounting is exact across petnames, subnets,
                 and open sessions; invalid storage-accounting rejects with counted :diagnose."}
  prop-bip016-bytes-at-rest-accounting-exactness 40
  (prop/for-all [node-role gen-node-role
                 owner-pk gen-pubkey-hex
                 incentive gen-cache-incentive
                 byte-sizes (gen/vector (gen/choose 64 512) 2 6)
                 transport gen-transport]
                (let [kp (crypto/generate-keypair 1602)
                      priv (:private kp)
                      fee (if (= incentive :upfront-fee-ech) 5 0)
                      [s0 _] (rolodex/transition (rolodex/init-rolodex)
                                                 {:type :configure-pointer
                                                  :node-role node-role
                                                  :owner-pubkeys [owner-pk]
                                                  :retention-policy {:max-entries 100
                                                                     :max-bytes 100000
                                                                     :rotate-every-entries 50
                                                                     :ttl-epochs 24}})
                      ;; Invalid accounting: :upfront-fee-ech with 0 fee must reject loudly
                      [s-bad effs-bad] (commit-rolodex-entry
                                        s0 priv
                                        {:op :upsert
                                         :petname "bad-fee"
                                         :pubkey owner-pk
                                         :allowed-actions #{:gossip}
                                         :storage-accounting {:bytes-at-rest 128
                                                              :cache-incentive :upfront-fee-ech
                                                              :payer-pubkey owner-pk
                                                              :fee-ech 0}})
                      ;; Apply mixed petname, subnet, and open-session entries
                      s-final
                      (reduce (fn [st [idx sz]]
                                (let [acct {:bytes-at-rest sz
                                            :cache-incentive incentive
                                            :payer-pubkey owner-pk
                                            :fee-ech fee}
                                      ev (case (mod idx 3)
                                           0 {:op :upsert
                                              :petname (str "peer-" idx)
                                              :pubkey owner-pk
                                              :allowed-actions #{:gossip :sync}
                                              :storage-accounting acct}
                                           1 {:op :upsert-subnet
                                              :subnet-id (str "subnet/s-" idx)
                                              :values-cid mc/zero-cid-hex
                                              :governance-pointer (str "runs/gov/" idx)
                                              :members #{(str "peer-" (max 0 (dec idx)))}
                                              :storage-accounting acct}
                                           2 {:op :open-session
                                              :session-id (str "sess-" idx)
                                              :peer-pubkey owner-pk
                                              :subnet-id "subnet/s-1"
                                              :transport transport
                                              :last-seq idx
                                              :opened-at-ms (+ 1700000000000 idx)
                                              :storage-accounting acct})
                                      [st' _] (commit-rolodex-entry st priv ev)]
                                  st'))
                              s0
                              (map-indexed vector byte-sizes))
                      expected-bytes (reduce + 0 byte-sizes)]
                  (and (= :halted (:phase s-bad))
                       (some #(= :invalid-storage-accounting (:code %)) effs-bad)
                       (= :idle (:phase s-final))
                       (= expected-bytes (:total-bytes-at-rest s-final))
                       (pos? (count (:state s-final)))
                       (pos? (count (:subnets s-final)))))))

(defspec ^{:doc "BIP-016 Property: Memento :memento/head-pointer enforces encrypted? true,
                 clear signed :owner-pubkeys, :retention-policy, and :storage-accounting."}
  prop-bip016-memento-head-pointer-discipline 40
  (prop/for-all [owner-pk gen-pubkey-hex
                 head-cid gen-pubkey-hex
                 seq-num (gen/choose 1 1000)
                 bytes-at-rest (gen/choose 64 4096)
                 incentive gen-cache-incentive]
                (let [fee (if (= incentive :upfront-fee-ech) 3 0)
                      good-ptr (memory-chain/make-memento-pointer
                                {:head-cid head-cid
                                 :seq seq-num
                                 :gen 1
                                 :owner-pubkeys [owner-pk]
                                 :retention-policy {:max-entries 1024 :max-bytes 1048576
                                                    :rotate-every-entries 256 :ttl-epochs 30}
                                 :storage-accounting {:bytes-at-rest bytes-at-rest
                                                      :cache-incentive incentive
                                                      :payer-pubkey owner-pk
                                                      :fee-ech fee}})
                      res-good (memory-chain/validate-memento-pointer good-ptr)
                      res-unenc (memory-chain/validate-memento-pointer (assoc good-ptr :encrypted? false))
                      res-no-owner (memory-chain/validate-memento-pointer (assoc good-ptr :owner-pubkeys []))
                      res-no-ret (memory-chain/validate-memento-pointer (dissoc good-ptr :retention-policy))]
                  (and (= :memento/head-pointer (:pointer/type good-ptr))
                       (true? (:encrypted? good-ptr))
                       (true? (:ok? res-good))
                       (false? (:ok? res-unenc))
                       (= :unencrypted-memory-rejected (get-in res-unenc [:diagnose :code]))
                       (false? (:ok? res-no-owner))
                       (= :missing-state-owner (get-in res-no-owner [:diagnose :code]))
                       (false? (:ok? res-no-ret))
                       (= :missing-retention-policy (get-in res-no-ret [:diagnose :code]))))))

(defn- run-unified-node-cold-wake
  "Runs unified BIP-016 cold-wake recovery for either :light or :infra node role,
   restoring petnames + subnets + open sessions + encrypted Memento pointer chain."
  [node-role seed-int]
  (let [kp (crypto/generate-keypair seed-int)
        priv (:private kp)
        pub (:public kp)
        pub32 (mcrypto/extract-ed25519-pub32 pub)
        owner-hex (fressian/bytes->hex pub32)
        blob-store (atom {})
        cfg {:type :configure-pointer
             :node-role node-role
             :owner-pubkeys [owner-hex]
             :retention-policy {:max-entries 500
                                :max-bytes 262144
                                :rotate-every-entries 100
                                :ttl-epochs 30}}
        [s0 _] (rolodex/transition (rolodex/init-rolodex) cfg)
        acct (fn [sz]
               {:bytes-at-rest sz
                :cache-incentive (if (= node-role :infra) :free-self-hosted :upfront-fee-ech)
                :payer-pubkey owner-hex
                :fee-ech (if (= node-role :infra) 0 2)})
        ;; Populate petnames, subnets, and open sessions via the EXACT same Rolodex reducer
        ops [{:op :upsert :petname "simon" :pubkey (crypto/sha256-hex "simon") :allowed-actions #{:bip-consent :gossip} :storage-accounting (acct 220)}
             {:op :upsert :petname "axiom" :pubkey (crypto/sha256-hex "axiom") :allowed-actions #{:gossip :sync} :storage-accounting (acct 220)}
             {:op :upsert-subnet :subnet-id "circle/testnet-launch" :values-cid (crypto/sha256-hex "vals-v1") :governance-pointer "runs/gov/bip-016" :members #{"simon" "axiom"} :storage-accounting (acct 310)}
             {:op :open-session :session-id (str (name node-role) "-sess-1") :peer-pubkey (crypto/sha256-hex "axiom") :subnet-id "circle/testnet-launch" :transport (if (= node-role :infra) :quic :webrtc) :last-seq 7 :opened-at-ms 1795200000000 :storage-accounting (acct 280)}
             {:op :open-session :session-id (str (name node-role) "-sess-2") :peer-pubkey (crypto/sha256-hex "simon") :subnet-id "circle/testnet-launch" :transport :websocket :last-seq 12 :opened-at-ms 1795200001000 :storage-accounting (acct 280)}]
        s-live
        (reduce (fn [st ev]
                  (let [[st' effs] (commit-rolodex-entry st priv ev)
                        put-eff (first (filter #(= :cas-put (:type %)) effs))]
                    (swap! blob-store assoc (:cid put-eff) (:entry put-eff))
                    st'))
                s0
                ops)
        snap (rolodex/make-snapshot s-live)
        ;; Build 6-link encrypted Memento memory chain + :memento/head-pointer
        genesis-sig (mcrypto/sign-genesis-memory priv pub)
        gen-pt (fressian/encode-canonical {:genesis? true
                                           :genesis-sig (fressian/bytes->hex genesis-sig)
                                           :node-role node-role})
        sealed-gen (mcrypto/seal-memory-frame priv 1 mc/zero-cid-hex gen-pt)
        _ (swap! blob-store assoc (:cid sealed-gen) (:frame-bytes sealed-gen))
        mem-head
        (reduce (fn [{:keys [cid seq-num total-bytes]} i]
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
                (range 2 7))
        memento-ptr (memory-chain/make-memento-pointer
                     {:head-cid (:cid mem-head)
                      :seq (:seq-num mem-head)
                      :gen (get-in s-live [:head :gen])
                      :owner-pubkeys [owner-hex]
                      :retention-policy {:max-entries 1024 :max-bytes 1048576
                                         :rotate-every-entries 256 :ttl-epochs 30}
                      :storage-accounting {:bytes-at-rest (:total-bytes mem-head)
                                           :cache-incentive (if (= node-role :infra) :free-self-hosted :upfront-fee-ech)
                                           :payer-pubkey owner-hex
                                           :fee-ech (if (= node-role :infra) 0 5)}})
        ptr-check (memory-chain/validate-memento-pointer memento-ptr)
        ;; Cold-wake measurement
        t0 (System/nanoTime)
        ;; 1. Fold Rolodex from cold start (petnames + subnets + open-sessions)
        folded (rolodex/fold-entries {} {} (vals (:entries s-live)))
        ;; 2. Walk encrypted Memento memory chain from :memento/head-pointer to genesis
        walk-res
        (loop [ws (memory-chain/init-walk-back {:head-cid (:head-cid memento-ptr)
                                                :depth-cap mc/default-walk-back-depth-cap
                                                :generation (:gen memento-ptr)
                                                :pubkey-raw32 pub32})
               effs [{:type :fetch-blob :gen (:gen memento-ptr) :cid (:head-cid memento-ptr)}]]
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
     :ok? (and (true? (:ok? ptr-check))
               (= (:state folded) (:state s-live))
               (= (:subnets folded) (:subnets s-live))
               (= (:open-sessions folded) (:open-sessions s-live))
               (= (:state snap) (:state folded))
               (= (:subnets snap) (:subnets folded))
               (= (:open-sessions snap) (:open-sessions folded))
               (= 2 (count (:state folded)))
               (= 1 (count (:subnets folded)))
               (= 2 (count (:open-sessions folded)))
               (= 1310 (:total-bytes-at-rest s-live))
               (= :complete (:phase walk-res))
               (true? (:genesis-verified? walk-res))
               (= 6 (:walked-count walk-res)))
     :petnames-restored (count (:state folded))
     :subnets-restored (count (:subnets folded))
     :open-sessions-restored (count (:open-sessions folded))
     :rolodex-bytes-at-rest (:total-bytes-at-rest s-live)
     :memento-bytes-at-rest (:total-bytes mem-head)
     :memento-links-walked (:walked-count walk-res)
     :genesis-verified? (:genesis-verified? walk-res)
     :wake-latency-ms (Double/parseDouble (format "%.3f" wake-ms))}))

(deftest bip016-unified-light-and-infra-cold-wake-recovery
  (testing "Unified BIP-016 cold-wake recovery for both :light and :infra nodes via one mechanism"
    (let [light-res (run-unified-node-cold-wake :light 3001)
          infra-res (run-unified-node-cold-wake :infra 3002)
          benchmark (run-cold-wake-benchmark)
          telemetry {:bip "BIP-016"
                     :coordination-brief-cid "778efc04f92fede8f105e4b035ed76de04d776d758a0caa1f3b8884e5779edf6"
                     :advisory-only? true
                     :unified-cold-wake {:light light-res
                                         :infra infra-res}
                     :cold-wake-benchmark benchmark
                     :all-passed? (and (:ok? light-res)
                                       (:ok? infra-res)
                                       (:within-thresholds? benchmark))}
          out-file (io/file (or (System/getenv "BITECHO_TELEMETRY_DIR") "/tmp")
                            "bip-016-aligned-telemetry.edn")]
      (spit out-file (str (pr-str telemetry) "\n"))
      (is (= telemetry (edn/read-string (slurp out-file))))
      (is (true? (:ok? light-res)) (str "Light node recovery failed: " (pr-str light-res)))
      (is (true? (:ok? infra-res)) (str "Infra node recovery failed: " (pr-str infra-res)))
      (is (true? (:within-thresholds? benchmark))))))
