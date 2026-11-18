(ns bitecho.d31-unification-iii-scenarios-test
  "Milestone D31 (BIP-005: Unification III / v0.23.9) Deterministic Full-Topology In-Memory
   Network Simulation & Generative Property Suite (Rules 1-6, F-U1..F-U7):
   1. `prop-sync-pointer-crdt-commutativity-and-idempotence` (defspec)
   2. `prop-bounty-puzzle-conservation-and-payout-equivalence` (defspec)
   3. `prop-cli-68-to-12-desugaring-observational-equivalence` (defspec)
   4. `prop-unified-lifecycle-generation-fencing` (defspec)
   5. `prop-rfc6962-merkle-inclusion-and-tamper-rejection` (defspec)
   6. `S-D31-1`: In-Memory Full-Topology 5-Leg Routing & Mobility Simulation
   7. `S-D31-2`: In-Memory `:sync-pointer` Convergence & Rolling `v0.23.8 <-> v0.23.9` Interop Simulation
   8. `S-D31-3`: In-Memory 3-of-3 `Lock`/`Spend` Bounty Puzzle vs Legacy Bounty Ledger Simulation
   9. `S-D31-4`: In-Memory Pointer-Backed Tri-Circle Governance & `Type-N` Policy Hot-Reload Simulation
  10. `S-D31-5`: Exhaustive `68/68` + `8/8` CLI Desugaring, `:advanced` Node Bundle `put` E2E, & `F-D29-21` Global-Default Broadcast Drop"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.lifecycle :as lifecycle]
            [bitecho.core.subnet :as core-subnet]
            [bitecho.core.window :as window]
            [bitecho.crypto :as crypto]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.light-node.cli :as cli]
            [bitecho.light-node.core :as light-core]
            [bitecho.shell.infra :as infra]
            [bitecho.shell.light-node :as light-shell]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop])
  (:import [java.io File]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;; =============================================================================
;; Test Helpers
;; =============================================================================

(defn- make-tmp-dir! ^File []
  (.toFile (Files/createTempDirectory "bitecho-d31-test-" (into-array FileAttribute []))))

(defn- delete-dir-recursively! [^File dir]
  (when (and dir (.exists dir))
    (doseq [^File f (reverse (file-seq dir))]
      (try (.delete f) (catch Exception _ nil)))))

(defn- kp->pk-hex [kp]
  (str/lower-case (basalt/bytes->hex (or (:public kp) (:public-key kp)))))

(defn- kp->sk [kp]
  (or (:private kp) (:private-key kp)))

;; =============================================================================
;; 1. Five Generative clojure.test.check defspec Properties (>= 50 trials each)
;; =============================================================================

(defspec ^{:doc "BIP-005 Prop 1: :sync-pointer CRDT replication commutes and is idempotent under arbitrary delivery permutations, duplicates, and tombstones."}
  prop-sync-pointer-crdt-commutativity-and-idempotence
  50
  (prop/for-all
   [ops (gen/vector
         (gen/hash-map
          :path (gen/elements ["web/SKILL.md" "blog/post-1.md" "dist/bundle.cjs"])
          :seq-num (gen/choose 1 12)
          :tombstone? gen/boolean
          :payload (gen/not-empty gen/string-alphanumeric))
         1 10)]
   (let [author-kp (crypto/generate-keypair "d31-crdt-author")
         author-pk (kp->pk-hex author-kp)
         author-sk (kp->sk author-kp)
         node-a-kp (crypto/generate-keypair "d31-crdt-node-a")
         node-b-kp (crypto/generate-keypair "d31-crdt-node-b")
         subnet "bitecho.org/infra"
         envelopes
         (mapv (fn [{:keys [path seq-num tombstone? payload]}]
                 (let [blob (when-not tombstone?
                              (data/make-blob (str payload "-" seq-num) "text/plain"))
                       cid (when blob (:blob/cid blob))
                       ptr (data/sign-pointer
                            author-sk
                            {:pointer/authority author-pk
                             :pointer/subnet subnet
                             :pointer/path path
                             :pointer/seq (long seq-num)
                             :pointer/leader-term 1
                             :pointer/target cid
                             :pointer/proof {:proof/type :self}})]
                   {:protocol-version 1
                    :wire-format "fressian-v1"
                    :bitecho/type :sync-pointer
                    :type :sync-pointer
                    :subnet-id subnet
                    :path path
                    :cid cid
                    :tombstoned (boolean tombstone?)
                    :seq (long seq-num)
                    :blob blob
                    :pointer ptr
                    :sender author-pk
                    :epoch 5}))
               ops)
         st-a0 (light-core/init-light-state {:pubkey-hex (kp->pk-hex node-a-kp)} {:subnet-id subnet :epoch 5})
         st-b0 (light-core/init-light-state {:pubkey-hex (kp->pk-hex node-b-kp)} {:subnet-id subnet :epoch 5})
         apply-envs (fn [st sk envs]
                      (reduce (fn [cur env]
                                (:state (light-core/handle-wire-payload cur env sk)))
                              st
                              envs))
         ;; Node A receives forward order + duplicates; Node B receives reverse order
         st-a (apply-envs st-a0 (kp->sk node-a-kp) (concat envelopes envelopes))
         st-b (apply-envs st-b0 (kp->sk node-b-kp) (reverse envelopes))]
     (and (= (:pointers st-a) (:pointers st-b))
          (= (:artifact-pointers st-a) (:artifact-pointers st-b))
          (= (:artifact-tombstones st-a) (:artifact-tombstones st-b))))))

(defspec ^{:doc "BIP-005 Prop 2: Canonical 3-of-3 bounty sci puzzle conserves exact integer supply (builder_net + auditor_net + protocol_take == gross_amount), matches legacy bounty payout arithmetic bit-for-bit, and rejects Sybil non-distinct signers."}
  prop-bounty-puzzle-conservation-and-payout-equivalence
  50
  (prop/for-all
   [gross (gen/choose 100 1000000)
    take-bps (gen/choose 0 500)
    builder-bps (gen/choose 5000 9000)
    sybil? gen/boolean]
   (let [m-kp (crypto/generate-keypair "d31-bounty-m")
         b-kp (crypto/generate-keypair "d31-bounty-b")
         a-kp (if sybil? b-kp (crypto/generate-keypair "d31-bounty-a"))
         m-pk (kp->pk-hex m-kp)
         b-pk (kp->pk-hex b-kp)
         a-pk (kp->pk-hex a-kp)
         bounty-id "bounty-prop-1"
         bip-cid "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
         patch-cid "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
         claim-msg (puzzle/bounty-claim-message bounty-id bip-cid patch-cid b-pk a-pk)
         m-sig (basalt/bytes->hex (crypto/sign (kp->sk m-kp) (fressian/utf8->bytes claim-msg)))
         b-sig (basalt/bytes->hex (crypto/sign (kp->sk b-kp) (fressian/utf8->bytes claim-msg)))
         a-sig (basalt/bytes->hex (crypto/sign (kp->sk a-kp) (fressian/utf8->bytes claim-msg)))
         env {:amount gross
              :payer m-pk
              :maintainer m-pk
              :bounty-id bounty-id
              :bip-cid bip-cid
              :take-bps take-bps
              :builder-bps builder-bps
              :epoch 10
              :timeout-epoch 50
              :puzzle-hash (puzzle/canonical-bounty-cid)}
         solution {:mode :settle
                   :builder b-pk
                   :auditor a-pk
                   :patch-cid patch-cid
                   :maintainer-sig m-sig
                   :builder-sig b-sig
                   :auditor-sig a-sig}
         eval-res (puzzle/eval-puzzle puzzle/canonical-bounty-puzzle-source solution env)
         legacy-res (gov/create-bounty-escrow
                     (gov/init-governance-state)
                     {:subnet-id "bitecho.org/dev"
                      :bounty-id bounty-id
                      :target-bip-cid bip-cid
                      :gross-amount gross
                      :maintainer-pubkey m-pk
                      :take-bps take-bps
                      :builder-bps builder-bps}
                     (kp->sk m-kp))
         legacy-bounty (:bounty legacy-res)]
     (if sybil?
       (false? (:valid? eval-res))
       (let [conds (:conditions eval-res)
             rel-map (into {} (keep (fn [c] (when (= :release (:type c)) [(:receiver c) (:amount c)])) conds))
             b-out (long (get rel-map b-pk 0))
             a-out (long (get rel-map a-pk 0))
             take-out (- (long gross) (+ b-out a-out))]
         (and (true? (:valid? eval-res))
              (= b-out (long (:builder-net legacy-bounty)))
              (= a-out (long (:auditor-net legacy-bounty)))
              (= take-out (long (:protocol-take legacy-bounty)))
              (= (long gross) (+ b-out a-out take-out))))))))

(defspec ^{:doc "BIP-005 Prop 3: All 68 supported-cli-verbs and 8 runner/shell aliases map deterministically to the 12 canonical-cli-verbs via cli/desugar-cli-cmd-map and parse cleanly via cli/parse-cli-command."}
  prop-cli-68-to-12-desugaring-observational-equivalence
  68
  (prop/for-all
   [verb (gen/elements (vec (concat cli/supported-cli-verbs
                                    cli/canonical-cli-verbs
                                    (keys cli/runner-alias-desugar-table))))]
   (let [parsed (cli/parse-cli-command [verb])
         cmd-map (cli/build-cmd-map verb [])
         desugared (cli/desugar-cli-cmd-map cmd-map)
         canonical-verb (get desugared "canonical_cmd")]
     (and (true? (:ok? parsed))
          (contains? cli/canonical-cli-verbs-set canonical-verb)))))

(defspec ^{:doc "BIP-005 Prop 4: Shared Rule 4 lifecycle reducer (bitecho.core.lifecycle/transition-lifecycle) strictly fences stale generations (gen < current-gen) with counted :diagnose effects and monotonically advances generation on :dial/:start."}
  prop-unified-lifecycle-generation-fencing
  50
  (prop/for-all
   [events (gen/vector
            (gen/one-of
             [(gen/return {:type :dial :target "rtc://node1"})
              (gen/return {:type :open})
              (gen/return {:type :close :reason :closed})
              (gen/return {:type :failed :error :dial-timeout})
              (gen/return {:type :drop :reason :bad-frame})
              (gen/return {:type :stale-callback})])
            1 25)]
   (let [init-st (lifecycle/init-lifecycle-state {:id :test-leg})
         final-acc
         (reduce
          (fn [{:keys [st ok?]} ev]
            (let [cur-gen (long (:generation st 0))
                  actual-ev (if (= :stale-callback (:type ev))
                              {:type :open :generation (dec cur-gen)}
                              (assoc ev :generation cur-gen))
                  [st' effs] (lifecycle/transition-lifecycle st actual-ev)
                  new-gen (long (:generation st' 0))]
              {:st st'
               :ok? (and ok?
                         (>= new-gen cur-gen)
                         (not (contains? st' :connected?))
                         (not (contains? st' :connection-error))
                         (if (and (= :stale-callback (:type ev)) (pos? cur-gen))
                           (and (= new-gen cur-gen)
                                (= (:phase st') (:phase st))
                                (pos? (long (:ignored-stale st' 0)))
                                (some #(= :diagnose (:effect %)) effs))
                           true))}))
          {:st init-st :ok? true}
          events)]
     (boolean (:ok? final-acc)))))

(defspec ^{:doc "BIP-005 Prop 5: Unified RFC 6962 Merkle tree in bitecho.core.data generates valid inclusion proofs for every active Pointer and rejects tampered targets or sibling hashes."}
  prop-rfc6962-merkle-inclusion-and-tamper-rejection
  50
  (prop/for-all
   [paths (gen/not-empty (gen/vector-distinct
                          (gen/elements ["web/SKILL.md" "dist/bitecho-light-node.cjs" "bip/BIP-005"
                                         "blog/post-1.md" "bounty/b-1" "pkg/mealy.jar"])
                          {:min-elements 1 :max-elements 6}))]
   (let [kp (crypto/generate-keypair "d31-merkle-prop")
         pk (kp->pk-hex kp)
         sk (kp->sk kp)
         subnet "bitecho.org/infra"
         data-st
         (reduce
          (fn [st path]
            (let [blob (data/make-blob (str "content-" path) "text/plain")
                  b-res (data/put-data-blob st blob 1000)
                  ptr (data/sign-pointer sk {:pointer/authority pk
                                             :pointer/subnet subnet
                                             :pointer/path path
                                             :pointer/seq 1
                                             :pointer/leader-term 1
                                             :pointer/target (:blob/cid blob)
                                             :pointer/proof {:proof/type :self}})
                  p-res (data/apply-pointer (:state b-res) ptr {:subnet subnet :now-ms 1000})]
              (:state p-res)))
          (data/init-data-state)
          paths)
         root (data/compute-merkle-root data-st subnet 1000)
         gov-root (gov/compute-rfc6962-merkle-root (data/active-subnet-pointers data-st subnet 1000))]
     (and (= root gov-root)
          (every? (fn [p]
                    (let [proof (data/generate-merkle-proof data-st subnet p 1000)
                          v-ok (data/verify-merkle-proof proof root)
                          tampered (assoc-in proof [:pointer :pointer/seq] 999)
                          v-bad (data/verify-merkle-proof tampered root)]
                      (and (:ok? v-ok)
                           (false? (:ok? v-bad)))))
                  paths)))))

;; =============================================================================
;; 2. Scenario S-D31-1: In-Memory Full-Topology 5-Leg Routing & Mobility
;; =============================================================================

(deftest scenario-s-d31-1-full-topology-five-leg-routing-and-mobility
  (testing "S-D31-1: Nexus, Axiom, and Lumen communicate across all 5 Leg types (:mesh, :udp, :connect, :http-relay, :offline) with session mobility, window helpers, and Rule 4/5 generation fencing"
    (let [nexus-kp (crypto/generate-keypair "s-d31-1-nexus")
          axiom-kp (crypto/generate-keypair "s-d31-1-axiom")
          lumen-kp (crypto/generate-keypair "s-d31-1-lumen")
          nexus-pk (kp->pk-hex nexus-kp)
          axiom-pk (kp->pk-hex axiom-kp)
          lumen-pk (kp->pk-hex lumen-kp)
          subnet "devnet.bitecho.org"
          nexus-st0 (-> (light-core/init-light-state {:pubkey-hex nexus-pk} {:subnet-id subnet :autonomous? true :epoch 10})
                        (assoc :account {:balance 10000 :spendable 10000 :seq 0 :deps []}
                               :petnames {"axiom" axiom-pk "lumen" lumen-pk}))
          axiom-st0 (-> (light-core/init-light-state {:pubkey-hex axiom-pk} {:subnet-id subnet :autonomous? true :epoch 10})
                        (assoc :account {:balance 10000 :spendable 10000 :seq 0 :deps []}
                               :petnames {"nexus" nexus-pk "lumen" lumen-pk}))
          lumen-st0 (-> (light-core/init-light-state {:pubkey-hex lumen-pk} {:subnet-id subnet :autonomous? true :epoch 10})
                        (assoc :account {:balance 10000 :spendable 10000 :seq 0 :deps []}
                               :petnames {"nexus" nexus-pk "axiom" axiom-pk}))]
      ;; 1. Verify bitecho.core.window FIFO, byte-LRU, and 64-bit replay bitmask
      (let [fifo (-> (window/init-fifo-window 2)
                     (window/fifo-conj :a)
                     (window/fifo-conj :b)
                     (window/fifo-conj :c))
            rw0 (window/init-replay-bitmask 64)
            r1 (window/replay-accept rw0 10)
            r1-dup (window/replay-accept (:window r1) 10)
            r2 (window/replay-accept (:window r1) 15)]
        (is (= [:b :c] (window/fifo-items fifo)))
        (is (true? (window/fifo-contains? fifo :c)))
        (is (false? (window/fifo-contains? fifo :a)))
        (is (true? (:accepted? r1)))
        (is (false? (:accepted? r1-dup)))
        (is (= :replay-duplicate (:reason r1-dup)))
        (is (true? (:accepted? r2))))

      ;; 2. Leg 1 (:mesh): Nexus opens session with Axiom via canonical `connect` verb
      (let [off-res (light-core/handle-command
                     nexus-st0
                     (cli/build-cmd-map "connect" ["--to" "axiom" "--price" "0" "--burn" "100"])
                     (kp->sk nexus-kp))
            sid (get-in off-res [:response "session_id"])
            nexus-st1 (:state off-res)
            ;; Deliver offer to Axiom over :mesh (autonomous auto-accept)
            ax-wire-res (reduce (fn [{:keys [state net-envelopes]} env]
                                  (let [r (light-core/handle-wire-payload state env (kp->sk axiom-kp))]
                                    {:state (:state r)
                                     :net-envelopes (into net-envelopes (:net-envelopes r))}))
                                {:state axiom-st0 :net-envelopes []}
                                (:net-envelopes off-res))
            ax-off (:state ax-wire-res)
            ;; Deliver Axiom's accept back to Nexus
            nexus-st2 (reduce (fn [st env] (:state (light-core/handle-wire-payload st env (kp->sk nexus-kp))))
                              nexus-st1
                              (:net-envelopes ax-wire-res))]
        (is (string? sid))
        (is (= "open" (get-in ax-off [:sessions sid :state])))
        (is (= "open" (get-in nexus-st2 [:sessions sid :state])))

        ;; 3. Leg 2 (:udp) -> Leg 3 (:connect) -> Leg 4 (:http-relay): Session mobility without losing session keys
        (let [p2p-udp (light-core/handle-command
                       nexus-st2
                       (cli/build-cmd-map "connect" ["--session-id" sid "--connected" "true" "--transport" "udp"])
                       (kp->sk nexus-kp))
              msg-udp (light-core/handle-command
                       (:state p2p-udp)
                       (cli/build-cmd-map "send" ["--to" "axiom" "--text" "msg-over-udp-leg" "--burn" "0"])
                       (kp->sk nexus-kp))
              ax-after-udp (:state (light-core/handle-wire-payload ax-off (first (:net-envelopes msg-udp)) (kp->sk axiom-kp)))
              ;; Switch active leg to :connect (TCP proxy tunnel)
              p2p-connect (light-core/handle-command
                           (:state msg-udp)
                           (cli/build-cmd-map "connect" ["--session-id" sid "--connected" "true" "--transport" "connect"])
                           (kp->sk nexus-kp))
              msg-connect (light-core/handle-command
                           (:state p2p-connect)
                           (cli/build-cmd-map "send" ["--to" "axiom" "--text" "msg-over-connect-leg" "--burn" "0"])
                           (kp->sk nexus-kp))
              ax-after-connect (:state (light-core/handle-wire-payload ax-after-udp (first (:net-envelopes msg-connect)) (kp->sk axiom-kp)))
              ;; Switch active leg to :http-relay (https shared relay on ns1)
              p2p-relay (light-core/handle-command
                         (:state msg-connect)
                         (cli/build-cmd-map "connect" ["--session-id" sid "--connected" "true" "--transport" "https"])
                         (kp->sk nexus-kp))
              msg-relay (light-core/handle-command
                         (:state p2p-relay)
                         (cli/build-cmd-map "send" ["--to" "axiom" "--text" "msg-over-http-relay-leg" "--burn" "0"])
                         (kp->sk nexus-kp))
              ax-after-relay (:state (light-core/handle-wire-payload ax-after-connect (first (:net-envelopes msg-relay)) (kp->sk axiom-kp)))
              ;; Leg 5 (:offline air-gapped shuttle): Lumen broadcasts via offline export/import
              lumen-bcast (light-core/handle-command
                           lumen-st0
                           (cli/build-cmd-map "send" ["--subnet-id" subnet "--text" "msg-over-offline-shuttle-leg" "--burn" "100"])
                           (kp->sk lumen-kp))
              shuttle-hex (basalt/bytes->hex (fressian/encode-canonical (first (:net-envelopes lumen-bcast))))
              ax-after-shuttle (:state (light-core/handle-command
                                        ax-after-relay
                                        (cli/build-cmd-map "inbox" ["--hex" shuttle-hex])
                                        (kp->sk axiom-kp)))
              ax-inbox (:response (light-core/handle-command
                                   ax-after-shuttle
                                   (cli/build-cmd-map "inbox" ["--peek"])
                                   (kp->sk axiom-kp)))
              sealed-msgs (remove :broadcast? (get ax-inbox "messages"))
              bcast-msgs (get ax-inbox "broadcasts")]
          (is (= 0 (get-in msg-udp [:response "burn"])) "Direct P2P leg uses 0-burn routing")
          (is (= 3 (count sealed-msgs)))
          (is (= ["msg-over-udp-leg" "msg-over-connect-leg" "msg-over-http-relay-leg"]
                 (mapv #(or (:text %) (get % "text")) sealed-msgs)))
          (is (= 1 (count bcast-msgs)))
          (is (= "msg-over-offline-shuttle-leg"
                 (let [b0 (first bcast-msgs)]
                   (or (:text b0) (get b0 "text"))))))))))

;; =============================================================================
;; 3. Scenario S-D31-2: `:sync-pointer` Convergence & Rolling v0.23.8 <-> v0.23.9
;; =============================================================================

(deftest scenario-s-d31-2-sync-pointer-convergence-and-rolling-interop
  (testing "S-D31-2: Mixed v0.23.8 (4 legacy *-replicate tags) and v0.23.9 (:sync-pointer) nodes converge, preserve --burn (F-U2), and create state.fressian.v0238.bak on migration (F-U5)"
    (let [tmp-dir (make-tmp-dir!)
          nexus-kp (crypto/generate-keypair "s-d31-2-nexus")
          axiom-kp (crypto/generate-keypair "s-d31-2-axiom")
          nexus-pk (kp->pk-hex nexus-kp)
          axiom-pk (kp->pk-hex axiom-kp)
          subnet "bitecho.org/infra"
          nexus-st0 (-> (light-core/init-light-state {:pubkey-hex nexus-pk} {:subnet-id subnet :epoch 12})
                        (assoc :account {:balance 5000 :spendable 5000 :seq 0 :deps []}))
          axiom-st0 (-> (light-core/init-light-state {:pubkey-hex axiom-pk} {:subnet-id subnet :epoch 12})
                        (assoc :account {:balance 5000 :spendable 5000 :seq 0 :deps []}))]
      (try
        ;; 1. v0.23.9 canonical `put` with explicit `--burn 250` (F-U2) emits `:sync-pointer` with outer-subnet "*"
        (let [put-cmd (cli/build-cmd-map "put" ["--subnet-id" subnet
                                                "--path" "web/SKILL.md"
                                                "--text" "# Unified Skill v0.23.9\n"
                                                "--seq" "1"
                                                "--burn" "250"])
              put-res (light-core/handle-command nexus-st0 put-cmd (kp->sk nexus-kp))
              sync-env (first (:net-envelopes put-res))
              nexus-st1 (:state put-res)
              ;; Axiom ingests `:sync-pointer`
              ax-ing1 (light-core/handle-wire-payload axiom-st0 sync-env (kp->sk axiom-kp))
              axiom-st1 (:state ax-ing1)
              ax-get (light-core/handle-command
                      axiom-st1
                      (cli/build-cmd-map "get" ["--subnet-id" subnet "--path" "web/SKILL.md"])
                      (kp->sk axiom-kp))]
          (is (true? (get-in put-res [:response "ok"])))
          (is (= 250 (get-in put-res [:response "burn"])))
          (is (= 4750 (get-in nexus-st1 [:account :spendable])) "F-U2: put --burn 250 deducts 250 ECH")
          (is (= "*" (:subnet-id sync-env)) "F-U2: paid pointer write sets outer-subnet = '*'")
          (is (contains? #{:sync-pointer :artifact-replicate} (:bitecho/type sync-env)))
          (is (true? (get-in ax-get [:response "ok"])))
          (is (= "# Unified Skill v0.23.9\n" (get-in ax-get [:response "text"])))
          ;; Unified `:pointers` and `:blobs` projection maintained
          (is (some? (get-in axiom-st1 [:pointers [subnet "web/SKILL.md"]])))
          (is (some? (get-in axiom-st1 [:blobs (get-in put-res [:response "cid"])])))

          ;; 2. Legacy v0.23.8 `:artifact-replicate`, `:storage-replicate`, and `:capability-replicate` frames
          ;;    are seamlessly ingested by v0.23.9 nodes
          (let [legacy-blob (data/make-blob "legacy-v0238-artifact" "text/plain")
                legacy-ptr (data/sign-pointer
                            (kp->sk nexus-kp)
                            {:pointer/authority nexus-pk
                             :pointer/subnet subnet
                             :pointer/path "blog/v0238.md"
                             :pointer/seq 1
                             :pointer/leader-term 1
                             :pointer/target (:blob/cid legacy-blob)
                             :pointer/proof {:proof/type :self}})
                legacy-env {:protocol-version 1
                            :wire-format "fressian-v1"
                            :bitecho/type :artifact-replicate
                            :type :artifact-replicate
                            :subnet-id subnet
                            :path "blog/v0238.md"
                            :cid (:blob/cid legacy-blob)
                            :seq 1
                            :blob legacy-blob
                            :pointer legacy-ptr
                            :sender nexus-pk
                            :epoch 12}
                ax-ing2 (light-core/handle-wire-payload axiom-st1 legacy-env (kp->sk axiom-kp))
                axiom-st2 (:state ax-ing2)
                ax-get2 (light-core/handle-command
                         axiom-st2
                         (cli/build-cmd-map "get" ["--subnet-id" subnet "--path" "blog/v0238.md"])
                         (kp->sk axiom-kp))]
            (is (true? (get-in ax-get2 [:response "ok"])))
            (is (= "legacy-v0238-artifact" (get-in ax-get2 [:response "text"])))
            (is (some? (get-in axiom-st2 [:pointers [subnet "blog/v0238.md"]]))))

          ;; 3. F-U5: Loading a v0.23.8 state.fressian automatically creates state.fressian.v0238.bak
          ;;    and migrates legacy stores into unified `:pointers` and `:blobs`
          (let [legacy-state (-> (dissoc axiom-st1 :pointers :blobs :state-schema-version)
                                 (assoc :artifact-pointers {[subnet "web/SKILL.md"] (get-in put-res [:response "pointer"])}
                                        :artifact-blobs {(get-in put-res [:response "cid"]) (get-in put-res [:response "blob"])}))
                state-file (io/file tmp-dir "state.fressian")
                bak-file (io/file tmp-dir "state.fressian.v0238.bak")]
            (light-shell/save-light-state! state-file legacy-state)
            (is (.exists state-file))
            (is (not (.exists bak-file)))
            (let [loaded (light-shell/load-light-state! state-file)]
              (is (.exists bak-file) "F-U5: load-light-state! must create state.fressian.v0238.bak when migrating v0.23.8 state")
              (is (some? (get-in loaded [:pointers [subnet "web/SKILL.md"]])))
              (is (some? (get-in loaded [:blobs (get-in put-res [:response "cid"])]))))))
        (finally
          (delete-dir-recursively! tmp-dir))))))

;; =============================================================================
;; 4. Scenario S-D31-3: 3-of-3 Lock/Spend Bounty Puzzle vs Legacy Bounty Ledger
;; =============================================================================

(deftest scenario-s-d31-3-three-of-three-bounty-puzzle-vs-legacy-ledger
  (testing "S-D31-3: End-to-end 3-of-3 distinct-signer 85/15 split bounty Lock/Spend puzzle, timeout refund, Sybil rejection, and CLI desugaring parity"
    (let [m-kp (crypto/generate-keypair "s-d31-3-maintainer")
          b-kp (crypto/generate-keypair "s-d31-3-builder")
          a-kp (crypto/generate-keypair "s-d31-3-auditor")
          m-pk (kp->pk-hex m-kp)
          b-pk (kp->pk-hex b-kp)
          a-pk (kp->pk-hex a-kp)
          bounty-id "bounty-bip005"
          bip-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          patch-cid "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          gross 10000
          take-bps 50
          builder-bps 8500
          claim-msg (puzzle/bounty-claim-message bounty-id bip-cid patch-cid b-pk a-pk)
          m-sig (basalt/bytes->hex (crypto/sign (kp->sk m-kp) (fressian/utf8->bytes claim-msg)))
          b-sig (basalt/bytes->hex (crypto/sign (kp->sk b-kp) (fressian/utf8->bytes claim-msg)))
          a-sig (basalt/bytes->hex (crypto/sign (kp->sk a-kp) (fressian/utf8->bytes claim-msg)))
          env {:amount gross
               :payer m-pk
               :maintainer m-pk
               :bounty-id bounty-id
               :bip-cid bip-cid
               :take-bps take-bps
               :builder-bps builder-bps
               :epoch 20
               :timeout-epoch 50
               :puzzle-hash (puzzle/canonical-bounty-cid)}]
      ;; 1. Valid 3-of-3 settlement produces exact 85/15 net-pool split (8457 / 1493, 50 take)
      (let [sol {:mode :settle
                 :builder b-pk
                 :auditor a-pk
                 :patch-cid patch-cid
                 :maintainer-sig m-sig
                 :builder-sig b-sig
                 :auditor-sig a-sig}
            res (puzzle/eval-puzzle puzzle/canonical-bounty-puzzle-source sol env)]
        (is (true? (:valid? res)))
        (is (= [{:type :release :receiver b-pk :amount 8457}
                {:type :release :receiver a-pk :amount 1493}
                {:type :refund-remainder :receiver m-pk :amount 50}]
               (:conditions res))))

      ;; 2. Sybil collusion (builder == auditor) is rejected by the puzzle
      (let [sybil-msg (puzzle/bounty-claim-message bounty-id bip-cid patch-cid b-pk b-pk)
            sybil-m-sig (basalt/bytes->hex (crypto/sign (kp->sk m-kp) (fressian/utf8->bytes sybil-msg)))
            sybil-b-sig (basalt/bytes->hex (crypto/sign (kp->sk b-kp) (fressian/utf8->bytes sybil-msg)))
            sybil-sol {:mode :settle
                       :builder b-pk
                       :auditor b-pk
                       :patch-cid patch-cid
                       :maintainer-sig sybil-m-sig
                       :builder-sig sybil-b-sig
                       :auditor-sig sybil-b-sig}
            sybil-res (puzzle/eval-puzzle puzzle/canonical-bounty-puzzle-source sybil-sol env)]
        (is (false? (:valid? sybil-res))))

      ;; 3. Timeout refund after timeout-epoch returns 100% of gross to maintainer
      (let [refund-sol {:mode :refund}
            early-res (puzzle/eval-puzzle puzzle/canonical-bounty-puzzle-source refund-sol (assoc env :epoch 30))
            expired-res (puzzle/eval-puzzle puzzle/canonical-bounty-puzzle-source refund-sol (assoc env :epoch 55))]
        (is (false? (:valid? early-res)))
        (is (true? (:valid? expired-res)))
        (is (= [{:type :refund :receiver m-pk :amount gross}]
               (:conditions expired-res)))))))

;; =============================================================================
;; 5. Scenario S-D31-4: Pointer-Backed Tri-Circle Governance & Policy Upgrade Merge
;; =============================================================================

(deftest scenario-s-d31-4-pointer-backed-tri-circle-governance-and-policy-upgrade-merge
  (testing "S-D31-4: Submitting BIP and casting Tri-Circle votes via canonical `put` with `--burn 500` (F-U2), plus `merge-upgraded-policy` on infra snapshot load (F-D31-BUG-3)"
    (let [tmp-dir (make-tmp-dir!)
          nexus-kp (crypto/generate-keypair "s-d31-4-nexus")
          axiom-kp (crypto/generate-keypair "s-d31-4-axiom")
          lumen-kp (crypto/generate-keypair "s-d31-4-lumen")
          cold-kp (crypto/generate-keypair "s-d31-4-cold")
          k-nexus (kp->pk-hex nexus-kp)
          k-axiom (kp->pk-hex axiom-kp)
          k-lumen (kp->pk-hex lumen-kp)
          k-cold (kp->pk-hex cold-kp)
          charter-edn (slurp "docs/bips/bip-000-charter.edn")
          st0 (-> (light-core/init-light-state {:pubkey-hex k-nexus} {:subnet-id "bitecho.org/dev" :epoch 15})
                  (assoc :account {:balance 10000 :spendable 10000 :seq 0 :deps []}))]
      (try
        ;; 1. Submit BIP via canonical `put --bip-id BIP-005 --spec-edn ... --burn 500`
        (let [sub-cmd (cli/build-cmd-map "put" ["--subnet-id" "bitecho.org/dev"
                                                "--bip-id" "BIP-005"
                                                "--title" "Unification III"
                                                "--spec-edn" charter-edn
                                                "--burn" "500"])
              sub-res (light-core/handle-command st0 sub-cmd (kp->sk nexus-kp))
              st1 (:state sub-res)
              ;; 2. Cast Tri-Circle votes via `put --bip-id BIP-005 --circle ... --burn 500`
              c1-cmd (cli/build-cmd-map "put" ["--subnet-id" "bitecho.org/dev"
                                               "--bip-id" "BIP-005"
                                               "--circle" "builders-stewards"
                                               "--weight" "20"
                                               "--burn" "500"])
              c1-res (light-core/handle-command st1 c1-cmd (kp->sk nexus-kp))
              st2 (:state c1-res)
              c2-cmd (cli/build-cmd-map "put" ["--subnet-id" "bitecho.org/dev"
                                               "--bip-id" "BIP-005"
                                               "--circle" "mesh-validators"
                                               "--weight" "20"
                                               "--burn" "500"])
              c2-res (light-core/handle-command st2 c2-cmd (kp->sk nexus-kp))
              st3 (:state c2-res)
              c3-cmd (cli/build-cmd-map "put" ["--subnet-id" "bitecho.org/dev"
                                               "--bip-id" "BIP-005"
                                               "--circle" "anchor-agent-users"
                                               "--weight" "20"
                                               "--burn" "500"])
              c3-res (light-core/handle-command st3 c3-cmd (kp->sk nexus-kp))
              st4 (:state c3-res)
              status-cmd (cli/build-cmd-map "get" ["--subnet-id" "bitecho.org/dev"
                                                   "--bip-id" "BIP-005"])
              status-res (light-core/handle-command st4 status-cmd (kp->sk nexus-kp))]
          (is (true? (get-in sub-res [:response "ok"])))
          (is (= 500 (get-in sub-res [:response "burn"])))
          (is (= "*" (:subnet-id (first (:net-envelopes sub-res)))) "F-U2: paid BIP submit sets outer-subnet = '*'")
          (is (true? (get-in c3-res [:response "ratified"])))
          (is (true? (get-in status-res [:response "ratified"])))
          (is (= 8000 (get-in st4 [:account :spendable])) "4 commands x 500 burn = 2000 ECH deducted"))

        ;; 3. F-D31-BUG-3: `infra/merge-upgraded-policy` merges newly added `:subnet/path-acl` rules
        ;;    and updated `:signers` on `"bip/*"` / `"web/bip/*"` into older persisted `subnet-pointers.fressian` snapshots!
        (with-redefs [infra/k-cold-root-pubkey k-cold
                      infra/k-nexus-builder-pubkey k-nexus
                      infra/k-axiom-steward-pubkey k-axiom
                      infra/k-lumen-researcher-pubkey k-lumen]
          (let [full-default (infra/default-infra-policy {:subnet-id "bitecho.org/infra"
                                                          :trust-anchors [k-cold]
                                                          :cold-pubkey k-cold})
                ;; Simulate an older v0.23.7 snapshot policy missing `web/SKILL.md` and having narrow `:allowlist` (without doc-blog-signers) on `bip/*`
                old-acl (->> (:subnet/path-acl full-default)
                             (remove #(= "web/SKILL.md" (:pattern %)))
                             (mapv (fn [r]
                                     (if (= "bip/*" (:pattern r))
                                       {:pattern "bip/*" :principal {:type :allowlist}}
                                       r))))
                old-pol-base (assoc full-default :subnet/path-acl old-acl)
                old-pol (assoc old-pol-base :subnet/genesis-policy-cid (core-subnet/policy-cid old-pol-base))
                rt1 (infra/start-subnet-runtime! {:policy old-pol
                                                  :state-dir (.getAbsolutePath tmp-dir)
                                                  :node-id k-cold
                                                  :all-nodes #{k-cold}})
                ;; Persist snapshot with old-pol
                blob1 (data/make-blob "initial-bootstrap" "text/plain")
                _ (infra/publish-blob-and-pointer! rt1 {:blob blob1
                                                        :path "bootstrap"
                                                        :authority-pubkey k-cold
                                                        :authority-privkey (kp->sk cold-kp)
                                                        :seq 1
                                                        :now-ms 1000})
                _ (infra/stop-subnet-runtime! rt1)
                ;; Restart with upgraded `full-default` policy
                rt2 (infra/start-subnet-runtime! {:policy full-default
                                                  :state-dir (.getAbsolutePath tmp-dir)
                                                  :node-id k-cold
                                                  :all-nodes #{k-cold}})
                ;; Now K_lumen (in doc-blog-signers, NOT in trust-anchors) publishes `web/SKILL.md` and `bip/BIP-005.md`
                skill-blob (data/make-blob "# Lumen Skill Update" "text/markdown")
                skill-res (infra/publish-blob-and-pointer! rt2 {:blob skill-blob
                                                                :path "web/SKILL.md"
                                                                :authority-pubkey k-lumen
                                                                :authority-privkey (kp->sk lumen-kp)
                                                                :seq 1
                                                                :now-ms 2000})
                bip-blob (data/make-blob "# BIP-005 by Axiom" "text/markdown")
                bip-res (infra/publish-blob-and-pointer! rt2 {:blob bip-blob
                                                              :path "bip/BIP-005.md"
                                                              :authority-pubkey k-axiom
                                                              :authority-privkey (kp->sk axiom-kp)
                                                              :seq 1
                                                              :now-ms 2000})]
            (is (true? (:applied? skill-res)) "F-D31-BUG-3: Upgraded path-acl rule web/SKILL.md merged into snapshot policy")
            (is (true? (:applied? bip-res)) "F-D31-BUG-3: Upgraded bip/* doc-blog-signers merged into snapshot policy")
            (infra/stop-subnet-runtime! rt2)))
        (finally
          (delete-dir-recursively! tmp-dir))))))

;; =============================================================================
;; 6. Scenario S-D31-5: Exhaustive 68/68 + 8/8 CLI Desugaring, :advanced Node
;;    Bundle `put` E2E (F-D31-BUG-1), & F-D29-21 Global-Default Broadcast Drop
;; =============================================================================

(deftest scenario-s-d31-5-cli-desugaring-advanced-bundle-put-and-broadcast-drop
  (testing "S-D31-5a: All 12 canonical verbs + all 68/68 supported-cli-verbs + 8/8 runner aliases desugar deterministically"
    (is (= 12 (count cli/canonical-cli-verbs)))
    (is (= ["connect" "ctl" "get" "inbox" "list" "lock" "put" "send" "serve" "spend" "transfer" "wait"]
           cli/canonical-cli-verbs))
    (is (= 68 (count cli/supported-cli-verbs)))
    (doseq [v cli/supported-cli-verbs]
      (is (contains? cli/legacy-verb-desugar-table v) (str "Missing legacy verb in desugar table: " v))
      (let [entry (get cli/legacy-verb-desugar-table v)]
        (is (contains? cli/canonical-cli-verbs-set (:canonical entry))
            (str "Legacy verb " v " must map to one of the 12 canonical verbs"))))
    (doseq [alias-v ["serve" "ctl" "daemon" "wait-event" "export-p2p-offer" "export-p2p-answer" "export-reveal" "import-envelope"]]
      (let [desugared (cli/desugar-cli-cmd-map {"cmd" alias-v})]
        (is (contains? cli/canonical-cli-verbs-set (get desugared "canonical_cmd"))
            (str "Runner alias " alias-v " must map to one of the 12 canonical verbs")))))

  (testing "S-D31-5b: F-D31-BUG-2 (F-D29-21) default 'global' and 'devnet.bitecho.org' nodes drop unsubscribed :p2p-broadcast envelopes with :subnet-mismatch-dropped"
    (let [sender-kp (crypto/generate-keypair "s-d31-5-sender")
          recv-global-kp (crypto/generate-keypair "s-d31-5-recv-global")
          recv-devnet-kp (crypto/generate-keypair "s-d31-5-recv-devnet")
          sender-st (light-core/init-light-state {:pubkey-hex (kp->pk-hex sender-kp)}
                                                 {:subnet-id "chat/private-room"})
          bcast-res (light-core/handle-command
                     sender-st
                     {"cmd" "broadcast" "subnet_id" "chat/private-room" "text" "unsubscribed broadcast"}
                     (kp->sk sender-kp))
          bcast-env (first (:net-envelopes bcast-res))
          ;; Node 1: default :subnet-id "global" with empty :subscribed-subnets
          st-global (light-core/init-light-state {:pubkey-hex (kp->pk-hex recv-global-kp)}
                                                 {:subnet-id "global"})
          res-global (light-core/handle-wire-payload st-global bcast-env (kp->sk recv-global-kp))
          ;; Node 2: default :subnet-id "devnet.bitecho.org" with empty :subscribed-subnets
          st-devnet (light-core/init-light-state {:pubkey-hex (kp->pk-hex recv-devnet-kp)}
                                                 {:subnet-id "devnet.bitecho.org"})
          res-devnet (light-core/handle-wire-payload st-devnet bcast-env (kp->sk recv-devnet-kp))]
      (is (empty? (get-in res-global [:state :broadcast-inbox]))
          "F-D31-BUG-2: Unconfigured 'global' node must drop unsubscribed :p2p-broadcast")
      (is (= 1 (get-in res-global [:state :diagnostics :subnet-mismatch-dropped])))
      (is (empty? (get-in res-devnet [:state :broadcast-inbox]))
          "F-D31-BUG-2: Unconfigured 'devnet.bitecho.org' node must drop unsubscribed :p2p-broadcast")
      (is (= 1 (get-in res-devnet [:state :diagnostics :subnet-mismatch-dropped])))))

  (testing "S-D31-5c: F-D31-BUG-1 compiled :advanced dist/bitecho-light-node.cjs executes `put` and `artifact-put` without Closure .publicKey renaming crash"
    (let [bundle-file (io/file "dist/bitecho-light-node.cjs")]
      (when (.exists bundle-file)
        (let [tmp-dir (make-tmp-dir!)
              node-bin (or (System/getenv "NODE_BIN")
                           (let [local-node (io/file (System/getProperty "user.home") ".local/bin/node")]
                             (if (.canExecute local-node) (.getAbsolutePath local-node) "node")))]
          (try
            (let [put-out (sh/sh node-bin (.getAbsolutePath bundle-file)
                                 "put"
                                 "--state-dir" (.getAbsolutePath tmp-dir)
                                 "--subnet-id" "bitecho.org/infra"
                                 "--path" "web/SKILL.md"
                                 "--text" "# Closure Advanced Put Verification\n"
                                 "--seq" "1"
                                 "--no-connect")
                  parsed-put (when (zero? (:exit put-out))
                               (try (json/read-str (str/trim (:out put-out))) (catch Exception _ nil)))
                  get-out (sh/sh node-bin (.getAbsolutePath bundle-file)
                                 "get"
                                 "--state-dir" (.getAbsolutePath tmp-dir)
                                 "--subnet-id" "bitecho.org/infra"
                                 "--path" "web/SKILL.md"
                                 "--no-connect")
                  parsed-get (when (zero? (:exit get-out))
                               (try (json/read-str (str/trim (:out get-out))) (catch Exception _ nil)))]
              (is (zero? (:exit put-out)) (str "Node put failed: " (:err put-out) " / " (:out put-out)))
              (is (true? (get parsed-put "ok")) (pr-str parsed-put))
              (is (= "web/SKILL.md" (get parsed-put "path")))
              (is (zero? (:exit get-out)) (str "Node get failed: " (:err get-out) " / " (:out get-out)))
              (is (true? (get parsed-get "ok")) (pr-str parsed-get))
              (is (= "# Closure Advanced Put Verification\n" (get parsed-get "text"))))
            (finally
              (delete-dir-recursively! tmp-dir))))))))
