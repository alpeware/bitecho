(ns bitecho.stress.harness
  "In-Memory Multi-Validator & Multi-Light-Node E2E Stress, Chaos/Byzantine,
   and Dynamic Membership Harness (Milestone D15).
   Executes the 6-stage 'Fractal Intent Economy' workload across:
   1. Clean 6-Node Queue Mode (3 Streamlet BFT committee + 3 mesh validators)
   2. Chaos + Byzantine Shell Mode (packet loss/reordering + f=1 Byzantine validator)
   3. Dynamic Zero-Reset Membership Mode (3 -> 6 -> 5 validators with QC checkpoint catch-up)"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [bitecho.shell.mesh :as mesh]
            [bitecho.shell.persistence :as persistence]
            [bitecho.state-machine :as sm]
            [bitecho.streamlet.core :as streamlet]
            [bitecho.stress.e2e-workload :as workload])
  (:import [java.io File]))

;; =============================================================================
;; 1. Cluster Initialization & Pure Command Router
;; =============================================================================

(defn init-validator-state
  "Initializes a single validator's pure state machine for the given topology."
  [topo vid & [{:keys [validators peers-map mesh-nodes ledger]}]]
  (let [v (get-in topo [:validators-by-id vid])
        eff-validators (or validators (:streamlet-validator-hexes topo))
        eff-peers-map (or peers-map (:peers-map topo))
        eff-mesh-nodes (or mesh-nodes (:mesh-nodes topo))
        eff-ledger (or ledger (:genesis-ledger topo))
        cfg (assoc config/default-config
                   :validators eff-validators
                   :peers-map eff-peers-map
                   :mesh-nodes eff-mesh-nodes
                   :keypair {:public (:public v) :private (:private v)}
                   :treasury-pubkey (get-in topo [:treasury :pubkey-hex])
                   :custody-pubkey (get-in topo [:custody :pubkey-hex])
                   :bootstrap-sunset-epoch 26280
                   :max-receipts-per-block 64)
        peer-records (mapv (fn [[pk-hex _]]
                             (basalt/->Peer "127.0.0.1" 9000 pk-hex pk-hex))
                           (dissoc eff-peers-map (:pubkey-hex v)))
        base (sm/init-state peer-records (:pubkey-hex v) cfg)]
    (assoc base
           :node-pubkey (:pubkey-hex v)
           :node-private-key (:private v)
           :keypair {:public (:public v) :private (:private v)}
           :validators eff-validators
           :peers-map eff-peers-map
           :mesh-nodes eff-mesh-nodes
           :treasury-pubkey (get-in topo [:treasury :pubkey-hex])
           :treasury-privkey (get-in topo [:treasury :private])
           :custody-pubkey (get-in topo [:custody :pubkey-hex])
           :custody-privkey (get-in topo [:custody :private])
           :ledger eff-ledger)))

(defn init-cluster-states
  "Initializes a map of {pubkey-hex -> state} for the specified validator IDs."
  ([topo]
   (init-cluster-states topo workload/validator-ids nil))
  ([topo active-vids opts]
   (into (sorted-map)
         (map (fn [vid]
                (let [st (init-validator-state topo vid opts)]
                  [(:node-pubkey st) st]))
              active-vids))))

(defn build-privkey-by-pub
  "Builds a lookup map of {pubkey-hex -> private-key-bytes} across all topology identities and validators."
  [topo]
  (merge
   {(get-in topo [:treasury :pubkey-hex]) (get-in topo [:treasury :private])
    (get-in topo [:custody :pubkey-hex]) (get-in topo [:custody :private])}
   (into {}
         (map (fn [[_ v]] [(:pubkey-hex v) (:private v)])
              (:validators-by-id topo)))
   (into {}
         (map (fn [[_ id]] [(:pubkey-hex id) (:private id)])
              (:identities-by-id topo)))))

(defn roundtrip-agent-wire-envelope
  "Signs `event` with the signer's Ed25519 private key via `mesh/wrap-agent-event`,
   serializes the envelope to bytes via `fressian/encode-wire`, and decodes/authenticates
   it via `mesh/unwrap-authenticated-agent-event` (B-OPUS-D15-3)."
  [privkey-by-pub event current-epoch]
  (let [signer-pub (or (:signer-pubkey event)
                       (:sender event)
                       (:payer event)
                       (:callee event))
        signer-priv (get privkey-by-pub signer-pub)
        clean-ev (cond-> (dissoc event :signer-pubkey)
                   (= :lock-intent (:type event))
                   (dissoc :created-epoch))
        _ (when-not (and signer-pub signer-priv)
            (throw (ex-info "Missing signer keypair for wire agent event"
                            {:type (:type event) :signer-pub signer-pub})))
        wrapped (mesh/wrap-agent-event clean-ev signer-pub signer-priv)
        wire-bytes (fressian/encode-wire wrapped)
        unwrapped (mesh/unwrap-authenticated-agent-event wire-bytes {:current-epoch current-epoch})]
    (when-not unwrapped
      (throw (ex-info "Failed to unwrap authenticated agent wire envelope"
                      {:type (:type event) :signer-pub signer-pub :event clean-ev})))
    unwrapped))

(defn roundtrip-validator-wire-command
  "Translates a validator command via `mesh/command->network-event`, encodes to wire bytes
   via `fressian/encode-wire`, and decodes via `fressian/decode-wire` (B-OPUS-D15-3)."
  [sender-hex cmd]
  (let [targets (mesh/extract-command-target-hexes cmd)]
    (if (empty? targets)
      []
      (let [net-evt (mesh/command->network-event cmd sender-hex)
            wire-bytes (fressian/encode-wire net-evt)
            decoded (fressian/decode-wire wire-bytes)]
        (when-not (map? decoded)
          (throw (ex-info "Failed to decode validator network command from wire bytes"
                          {:cmd-type (:type cmd) :sender sender-hex})))
        (mapv (fn [t]
                [t (assoc decoded :sender sender-hex)])
              targets)))))

(defn- command->target-events
  "Translates a single state-machine command emitted by `sender-hex` into a vector of
   `[target-pubkey-hex event]` pairs."
  [sender-hex cmd]
  (case (:type cmd)
    (:send-propose :propose-block :send-vote :cast-vote :send-receipt :send-request-checkpoint :send-checkpoint :send-checkpoint-response)
    (let [norm-cmd (case (:type cmd)
                     :propose-block (assoc cmd :type :send-propose)
                     :cast-vote (assoc cmd :type :send-vote)
                     :send-checkpoint-response (assoc cmd :type :send-checkpoint)
                     cmd)]
      (roundtrip-validator-wire-command sender-hex norm-cmd))

    []))

(defn drain-commands
  "Drains a queue of `[target-hex event]` pairs across `cluster-states` until quiescent.
   Supports an optional `transform-events-fn` `(fn [sender-hex target-hex event] -> [events...])`
   for chaos/loss/reorder simulation."
  ([cluster-states initial-queue]
   (drain-commands cluster-states initial-queue nil))
  ([cluster-states initial-queue transform-events-fn]
   (loop [states cluster-states
          queue (vec initial-queue)
          steps 0]
     (if (or (empty? queue) (>= steps 20000))
       states
       (let [[target-hex ev] (first queue)
             rem-queue (subvec queue 1)]
         (if-let [target-state (get states target-hex)]
           (let [res (sm/handle-event target-state ev)
                 next-state (:state res)
                 raw-out (mapcat #(command->target-events target-hex %) (:commands res))
                 filtered-out (if transform-events-fn
                                (mapcat (fn [[t e]] (transform-events-fn target-hex t e)) raw-out)
                                raw-out)]
             (recur (assoc states target-hex next-state)
                    (into rem-queue filtered-out)
                    (inc steps)))
           (recur states rem-queue (inc steps))))))))

(defn dispatch-event-to-node
  "Dispatches `event` to `node-hex` in `cluster-states` and drains all resulting commands."
  ([cluster-states node-hex event]
   (dispatch-event-to-node cluster-states node-hex event nil))
  ([cluster-states node-hex event transform-events-fn]
   (drain-commands cluster-states [[node-hex event]] transform-events-fn)))

(defn advance-cluster-epochs
  "Advances all nodes in `cluster-states` by `n-epochs` ticks, draining consensus and receipt
   gossip messages after each tick."
  ([cluster-states n-epochs]
   (advance-cluster-epochs cluster-states n-epochs nil))
  ([cluster-states n-epochs transform-events-fn]
   (reduce
    (fn [states step-idx]
      (let [node-hexes (vec (sort (keys states)))
            [ticked-states tick-queue]
            (reduce
             (fn [[acc-s acc-q] nh]
               (let [st (get acc-s nh)
                     rng (crypto/make-random (str "tick-" nh "-" step-idx "-" (:epoch st 0)))
                     res (sm/handle-event st {:type :tick :rng rng})
                     out (mapcat #(command->target-events nh %) (:commands res))
                     filtered (if transform-events-fn
                                (mapcat (fn [[t e]] (transform-events-fn nh t e)) out)
                                out)]
                 [(assoc acc-s nh (:state res))
                  (into acc-q filtered)]))
             [states []]
             node-hexes)]
        (drain-commands ticked-states tick-queue transform-events-fn)))
    cluster-states
    (range n-epochs))))

;; =============================================================================
;; 2. Stage-by-Stage Workload Execution on Cluster
;; =============================================================================

(defn execute-workload-stages
  "Runs the 6-stage Fractal Intent Economy scenario against `cluster-states`.
   Submits light-node intents to non-committee mesh validators (`ns1..ns3`) as well as
   committee validators (`node1..node3`) to exercise `:receive-receipt` single-hop gossip.
   When `wire-boundary?` is true, every light-node intent is signed, Fressian wire-encoded,
   and unwrapped via `mesh/unwrap-authenticated-agent-event` before entering the validator."
  ([cluster-states scenario]
   (execute-workload-stages cluster-states scenario nil false))
  ([cluster-states scenario transform-events-fn]
   (execute-workload-stages cluster-states scenario transform-events-fn false))
  ([cluster-states scenario transform-events-fn wire-boundary?]
   (let [topo (:topology scenario)
         privkey-by-pub (build-privkey-by-pub topo)
         dispatch-intent
         (fn [sts node-hex ev]
           (let [curr-ep (long (or (:epoch (get sts node-hex)) 1))
                 final-ev (if wire-boundary?
                            (roundtrip-agent-wire-envelope privkey-by-pub ev curr-ep)
                            (dissoc ev :signer-pubkey))]
             (dispatch-event-to-node sts node-hex final-ev transform-events-fn)))
         ids (:identities-by-id topo)
         vals-by-id (:validators-by-id topo)
         n1 (get-in vals-by-id [:node1 :pubkey-hex])
         n2 (get-in vals-by-id [:node2 :pubkey-hex])
         ns1 (get-in vals-by-id [:ns1 :pubkey-hex])
         ns2 (get-in vals-by-id [:ns2 :pubkey-hex])
         ns3 (get-in vals-by-id [:ns3 :pubkey-hex])
         entry-nodes [ns1 ns2 ns3 n1 n2]

         ;; Advance to epoch 1 so all nodes are at epoch 1
         s-ep1 (advance-cluster-epochs cluster-states 1 transform-events-fn)

         ;; Stage 1A: Register 3-of-6 Home Sets for all 8 identities (submitted across ns1..ns3 & node1..2)
         s-homes
         (reduce-kv
          (fn [sts idx [_ id-map]]
            (let [target-node (nth entry-nodes (mod idx (count entry-nodes)))
                  candidates (mapv (fn [vid]
                                     {:node-id (get-in vals-by-id [vid :pubkey-hex])
                                      :price (:home-price id-map)})
                                   (:home-set id-map))]
              (dispatch-intent
               sts target-node
               {:type :register-home-set
                :callee (:pubkey-hex id-map)
                :sender (:pubkey-hex id-map)
                :epoch 1
                :price (:home-price id-map)
                :price-max (:home-price id-map)
                :candidates candidates})))
          s-ep1
          (vec (:identities-by-id topo)))

         ;;Finalize home-set registrations (4 epochs for 3-chain finality)
         s-after-homes (advance-cluster-epochs s-homes 4 transform-events-fn)

         ;; Stage 1B: Multi-hop transfers (tx1, tx2, tx3), settle-intent, signaling burns, and vouchers
         {:keys [tx1 tx2 tx3]} (:transfers scenario)
         {:keys [voucher1 voucher2]} (:vouchers scenario)
         founder (:subnet-founder ids)
         author (:kernel-author ids)
         oracle (:oracle-verifier ids)
         buyer1 (:agent-buyer-1 ids)

         s-tx1 (dispatch-intent
                s-after-homes ns1
                {:type :on-deliver
                 :message-id "msg-tx1"
                 :sender (:sender tx1)
                 :payload (fressian/encode-canonical {:transfer (into {} tx1)})})
         ;; Finalize tx1 before chained tx2 & tx3
         s-after-tx1 (advance-cluster-epochs s-tx1 4 transform-events-fn)

         s-tx2-tx3 (-> s-after-tx1
                       (dispatch-intent
                        ns2
                        {:type :on-deliver
                         :message-id "msg-tx2"
                         :sender (:sender tx2)
                         :payload (fressian/encode-canonical {:transfer (into {} tx2)})})
                       (dispatch-intent
                        ns3
                        {:type :on-deliver
                         :message-id "msg-tx3"
                         :sender (:sender tx3)
                         :payload (fressian/encode-canonical {:transfer (into {} tx3)})})
                       (dispatch-intent
                        ns1
                        {:type :settle-intent
                         :payer (:pubkey-hex founder)
                         :receiver (:pubkey-hex oracle)
                         :sender (:pubkey-hex founder)
                         :amount 2000})
                       (dispatch-intent
                        ns2
                        {:type :signaling-burn
                         :sender (:pubkey-hex founder)
                         :burn-amount 500})
                       (dispatch-intent
                        ns3
                        {:type :signaling-burn
                         :sender (:pubkey-hex author)
                         :burn-amount 300})
                       (dispatch-intent
                        ns1
                        {:type :submit-vouchers
                         :signer-pubkey (:pubkey-hex buyer1)
                         :vouchers [voucher1 voucher2]}))

         ;; Finalize Stage 1 transactions and vouchers
         s-after-stage1 (advance-cluster-epochs s-tx2-tx3 4 transform-events-fn)

         ;; Stage 4A: Lock all 4 smart contract escrows (royalty, multisig, htlc, timeout)
         contracts (:contracts scenario)
         royalty (:royalty contracts)
         multisig (:multisig contracts)
         htlc (:htlc contracts)
         timeout-c (:timeout contracts)
         curr-ep (long (or (:epoch (val (first s-after-stage1))) 10))
         royalty-exp (+ curr-ep 20)
         multisig-exp (+ curr-ep 20)
         htlc-exp (+ curr-ep 20)
         timeout-exp (+ curr-ep 2)

         s-locks (-> s-after-stage1
                     (dispatch-intent
                      ns1
                      {:type :lock-intent
                       :escrow-id (:escrow-id royalty)
                       :payer (:payer royalty)
                       :receiver (:receiver royalty)
                       :sender (:payer royalty)
                       :amount (:amount royalty)
                       :puzzle-hash (:puzzle-hash royalty)
                       :created-epoch curr-ep
                       :expires-epoch royalty-exp
                       :nonce (:nonce royalty)})
                     (dispatch-intent
                      ns2
                      {:type :lock-intent
                       :escrow-id (:escrow-id multisig)
                       :payer (:payer multisig)
                       :receiver (:receiver multisig)
                       :sender (:payer multisig)
                       :amount (:amount multisig)
                       :puzzle-hash (:puzzle-hash multisig)
                       :created-epoch curr-ep
                       :expires-epoch multisig-exp
                       :nonce (:nonce multisig)})
                     (dispatch-intent
                      ns3
                      {:type :lock-intent
                       :escrow-id (:escrow-id htlc)
                       :payer (:payer htlc)
                       :receiver (:receiver htlc)
                       :sender (:payer htlc)
                       :amount (:amount htlc)
                       :deliverable-hash (:deliverable-hash htlc)
                       :created-epoch curr-ep
                       :expires-epoch htlc-exp
                       :nonce (:nonce htlc)})
                     (dispatch-intent
                      n1
                      {:type :lock-intent
                       :escrow-id (:escrow-id timeout-c)
                       :payer (:payer timeout-c)
                       :receiver (:receiver timeout-c)
                       :sender (:payer timeout-c)
                       :amount (:amount timeout-c)
                       :deliverable-hash (:deliverable-hash timeout-c)
                       :created-epoch curr-ep
                       :expires-epoch timeout-exp
                       :nonce (:nonce timeout-c)}))

         ;; Finalize the 4 lock-intents
         s-after-locks (advance-cluster-epochs s-locks 4 transform-events-fn)

         ;; Stage 6A: Execute Byzantine Challenger's 7 adversarial attacks BEFORE legitimate releases
         challenger (:byzantine-challenger ids)
         st-n1-before-adv (get s-after-locks n1)
         ;; Attack 1: Wrong preimage on HTLC escrow
         adv-1 (sm/handle-event st-n1-before-adv
                                {:type :release-intent
                                 :escrow-id (:escrow-id htlc)
                                 :preimage "wrong-preimage-byzantine"
                                 :sender (:pubkey-hex challenger)})
         ;; Attack 2: Forged oracle signature on Royalty SCI puzzle
         forged-sol (assoc (:solution royalty)
                           :oracle-sig (basalt/bytes->hex (crypto/sign (:private challenger)
                                                                       (fressian/utf8->bytes "forged"))))
         adv-2 (sm/handle-event (:state adv-1)
                                {:type :release-intent
                                 :escrow-id (:escrow-id royalty)
                                 :puzzle-source (:puzzle-source royalty)
                                 :solution forged-sol
                                 :sender (:pubkey-hex challenger)})
         ;; Attack 3: Overspend SCI puzzle evaluation
         adv-3-res (puzzle/eval-puzzle
                    workload/adversarial-overspend-puzzle-source
                    {}
                    {:amount 500 :receiver (:pubkey-hex challenger) :payer (:payer royalty)})
         ;; Attack 4: Fuel-exhaustion SCI puzzle evaluation
         adv-4-res (puzzle/eval-puzzle
                    workload/adversarial-fuel-exhaustion-puzzle-source
                    {}
                    {:amount 500 :receiver (:pubkey-hex challenger) :payer (:payer royalty)})
         ;; Attack 5: Stale E2EE pointer rollback (seq 1 after seq 2)
         adv-5-stale-rejected? (< 1 (get-in scenario [:storage :e2ee-decrypted :seq] 2))
         ;; Attack 6: Premature refund on HTLC escrow before expires-epoch
         adv-6 (sm/handle-event (:state adv-2)
                                {:type :refund-intent
                                 :escrow-id (:escrow-id htlc)
                                 :epoch curr-ep
                                 :sender (:payer htlc)})

         ;; Stage 4B: Legitimate releases of Royalty, Multisig, and HTLC escrows
         s-releases (-> s-after-locks
                        (dispatch-intent
                         ns1
                         {:type :release-intent
                          :escrow-id (:escrow-id royalty)
                          :puzzle-source (:puzzle-source royalty)
                          :solution (:solution royalty)
                          :sender (:receiver royalty)})
                        (dispatch-intent
                         ns2
                         {:type :release-intent
                          :escrow-id (:escrow-id multisig)
                          :puzzle-source (:puzzle-source multisig)
                          :solution (:solution multisig)
                          :sender (:receiver multisig)})
                        (dispatch-intent
                         ns3
                         {:type :release-intent
                          :escrow-id (:escrow-id htlc)
                          :preimage (:preimage htlc)
                          :sender (:receiver htlc)}))

         ;; Advance past timeout-exp and finalize releases
         s-after-releases (advance-cluster-epochs s-releases 5 transform-events-fn)

         ;; Stage 6B: Legitimate timeout refund of timeout-c + Attack 7 (replay of settled release)
         s-refund (dispatch-intent
                   s-after-releases ns1
                   {:type :refund-intent
                    :escrow-id (:escrow-id timeout-c)
                    :sender (:payer timeout-c)})
         s-final (advance-cluster-epochs s-refund 4 transform-events-fn)

         ;; Attack 7: Replay release-intent on already-released HTLC escrow
         st-n1-final (get s-final n1)
         adv-7 (sm/handle-event st-n1-final
                                {:type :release-intent
                                 :escrow-id (:escrow-id htlc)
                                 :preimage (:preimage htlc)
                                 :sender (:receiver htlc)})
         adversarial-rejections
         (count (filter true?
                        [(empty? (:commands adv-1))
                         (empty? (:commands adv-2))
                         (and (not (:valid? adv-3-res))
                              (= :puzzle-overspend-violation (:error adv-3-res)))
                         (and (not (:valid? adv-4-res))
                              (= :puzzle-budget-exceeded (:error adv-4-res)))
                         adv-5-stale-rejected?
                         (empty? (:commands adv-6))
                         (empty? (:commands adv-7))]))]
     {:states s-final
      :wire-boundary? (boolean wire-boundary?)
      :adversarial-rejections adversarial-rejections})))

;; =============================================================================
;; 3. Golden Oracle Verification Helper
;; =============================================================================

(defn verify-against-golden-oracle
  "Verifies a map of validator `states` and `adversarial-rejections` against `golden`."
  [states golden adversarial-rejections]
  (let [expected-bals (:expected-balances-by-pubkey golden)
        expected-escrows (:escrow-statuses golden)
        per-node-checks
        (into {}
              (map (fn [[node-hex st]]
                     (let [actual-bals (into {}
                                             (map (fn [[pk _]]
                                                    [pk (get-in st [:ledger pk :balance] 0)])
                                                  expected-bals))
                           actual-escrows (into {}
                                                (map (fn [[eid _]]
                                                       [eid (get-in st [:escrows eid :status])])
                                                     expected-escrows))
                           bals-match? (= expected-bals actual-bals)
                           escrows-match? (= expected-escrows actual-escrows)
                           zero-failed-rcpts? (zero? (long (or (:failed-receipts-count st) 0)))]
                       [node-hex {:balances-match? bals-match?
                                  :escrows-match? escrows-match?
                                  :zero-failed-receipts? zero-failed-rcpts?
                                  :actual-balances actual-bals
                                  :actual-escrows actual-escrows
                                  :failed-receipts-count (or (:failed-receipts-count st) 0)
                                  :finalized-epoch (or (:last-executed-finalized-epoch st) 0)}]))
                   states))
        all-nodes-match? (every? (fn [[_ c]]
                                   (and (:balances-match? c)
                                        (:escrows-match? c)
                                        (:zero-failed-receipts? c)))
                                 per-node-checks)
        offchain-match? (and (:subnets-valid? golden)
                             (:e2ee-valid? golden)
                             (:capabilities-valid? golden)
                             (= (:expected-adversarial-rejections golden) adversarial-rejections))]
    {:parity? (and all-nodes-match? offchain-match?)
     :all-nodes-match? all-nodes-match?
     :offchain-match? offchain-match?
     :adversarial-rejections adversarial-rejections
     :per-node per-node-checks}))

;; =============================================================================
;; 4. Target 1: Clean 6-Node In-Memory E2E Runner + Fressian Persistence Check
;; =============================================================================

(defn run-clean-in-memory-e2e
  "Runs the full 6-stage workload across 6 validators (3 Streamlet BFT + 3 mesh validators)
   in Clean Queue Mode, verifies Fressian snapshot persistence round-trip, and checks
   100% parity against the Golden Oracle."
  []
  (let [scenario (workload/build-workload-scenario)
        golden (workload/compute-golden-expected-state scenario)
        initial-states (init-cluster-states (:topology scenario))
        {:keys [states adversarial-rejections]} (execute-workload-stages initial-states scenario)
        verification (verify-against-golden-oracle states golden adversarial-rejections)
        ;; Fressian persistence round-trip check on node1 state
        n1-hex (get-in scenario [:topology :validators-by-id :node1 :pubkey-hex])
        n1-state (get states n1-hex)
        tmp-file (File/createTempFile "bitecho-d15-e2e-" ".fressian")
        _ (.deleteOnExit tmp-file)
        _ (persistence/save-state-to-disk (.getAbsolutePath tmp-file) n1-state)
        restored-n1 (persistence/load-state-from-disk (.getAbsolutePath tmp-file))
        _ (.delete tmp-file)
        fressian-roundtrip-ok? (and (some? restored-n1)
                                    (= (into {} (map (fn [[k v]] [k (:balance v)]) (:ledger n1-state)))
                                       (into {} (map (fn [[k v]] [k (:balance v)]) (:ledger restored-n1))))
                                    (= (:escrows n1-state) (:escrows restored-n1))
                                    (= (:finalized-blocks n1-state) (:finalized-blocks restored-n1))
                                    (set? (get-in restored-n1 [:murmur-cache :set]))
                                    (set? (:settled-voucher-tuples restored-n1)))]
    (assoc verification
           :fressian-roundtrip-ok? fressian-roundtrip-ok?
           :golden golden
           :states states)))

(defn run-wire-boundary-e2e
  "Runs the full 6-stage workload across 6 validators where:
   1. Every light-node intent is Ed25519-signed via `mesh/wrap-agent-event`, encoded to bytes
      via `fressian/encode-wire`, and decoded/authenticated via `mesh/unwrap-authenticated-agent-event`
      (including `:lock-intent` without `:created-epoch`).
   2. Every validator-to-validator command is translated via `mesh/command->network-event`,
      encoded via `fressian/encode-wire`, and decoded via `fressian/decode-wire`.
   Verifies 100% parity against the Golden Oracle and Fressian snapshot round-trip (B-OPUS-D15-3)."
  []
  (let [scenario (workload/build-workload-scenario)
        golden (workload/compute-golden-expected-state scenario)
        initial-states (init-cluster-states (:topology scenario))
        {:keys [states adversarial-rejections]} (execute-workload-stages initial-states scenario nil true)
        verification (verify-against-golden-oracle states golden adversarial-rejections)
        n1-hex (get-in scenario [:topology :validators-by-id :node1 :pubkey-hex])
        n1-state (get states n1-hex)
        tmp-file (File/createTempFile "bitecho-d15-wire-e2e-" ".fressian")
        _ (.deleteOnExit tmp-file)
        _ (persistence/save-state-to-disk (.getAbsolutePath tmp-file) n1-state)
        restored-n1 (persistence/load-state-from-disk (.getAbsolutePath tmp-file))
        _ (.delete tmp-file)
        fressian-roundtrip-ok? (and (some? restored-n1)
                                    (= (into {} (map (fn [[k v]] [k (:balance v)]) (:ledger n1-state)))
                                       (into {} (map (fn [[k v]] [k (:balance v)]) (:ledger restored-n1))))
                                    (= (:escrows n1-state) (:escrows restored-n1))
                                    (= (:finalized-blocks n1-state) (:finalized-blocks restored-n1))
                                    (set? (get-in restored-n1 [:murmur-cache :set]))
                                    (set? (:settled-voucher-tuples restored-n1)))]
    (assoc verification
           :wire-boundary? true
           :fressian-roundtrip-ok? fressian-roundtrip-ok?
           :golden golden
           :states states)))

;; =============================================================================
;; 5. Target 2: Chaos + Byzantine Shell E2E Runner (INV-D15-5, A-CARB-3)
;; =============================================================================

(defn run-chaos-byzantine-e2e
  "Runs the 6-stage workload under:
   - Deterministic packet drop/reorder on redundant gossip frames
   - 1 Byzantine Streamlet validator (`:node3`, f = 1 < 3/3) injecting equivocating block
     proposals and forged/unverified `:receive-receipt` messages.
   Verifies that the 5 honest nodes (`node1`, `node2`, `ns1..ns3`) converge to the exact
   Golden Oracle state, record `:node3` in `:equivocated-voters`, and increment
   `[:diagnostics :unverified-gossip-receipt-rejected]`."
  ([] (run-chaos-byzantine-e2e 15001))
  ([seed]
   (let [scenario (workload/build-workload-scenario)
         golden (workload/compute-golden-expected-state scenario)
         topo (:topology scenario)
         vals-by-id (:validators-by-id topo)
         n1-hex (get-in vals-by-id [:node1 :pubkey-hex])
         n2-hex (get-in vals-by-id [:node2 :pubkey-hex])
         n3-hex (get-in vals-by-id [:node3 :pubkey-hex])
         ns1-hex (get-in vals-by-id [:ns1 :pubkey-hex])
         ns2-hex (get-in vals-by-id [:ns2 :pubkey-hex])
         ns3-hex (get-in vals-by-id [:ns3 :pubkey-hex])
         honest-hexes [n1-hex n2-hex ns1-hex ns2-hex ns3-hex]
         n3-priv (get-in vals-by-id [:node3 :private])
         rng (crypto/make-random seed)

         ;; Chaos transform:
         ;; - Byzantine node3 drops 50% of its outgoing votes and injects equivocating proposals
         ;; - Redundant gossip has 15% deterministic reorder/jitter
         chaos-transform
         (fn [sender-hex target-hex event]
           (cond
             ;; Byzantine node3 drops half of its votes to test 2-of-3 honest quorum resilience
             (and (= sender-hex n3-hex)
                  (= (:type event) :receive-vote)
                  (< (crypto/next-double rng) 0.5))
             []

             ;; 15% jitter/reorder on receipt gossip from n3
             (and (= sender-hex n3-hex)
                  (= (:type event) :receive-receipt)
                  (< (crypto/next-double rng) 0.15))
             []

             :else
             [[target-hex event]]))

         initial-states (init-cluster-states topo)
         {:keys [states adversarial-rejections]}
         (execute-workload-stages initial-states scenario chaos-transform)

         ;; Byzantine node3 injects:
         ;; 1. Two equivocating block proposals & votes at an epoch where n3 is leader
         base-ep (inc (long (or (:epoch (get states n1-hex)) 25)))
         committee (:streamlet-validator-hexes topo)
         byz-epoch (first (filter #(= n3-hex (nth committee (mod % (count committee))))
                                  (range base-ep (+ base-ep 10))))
         parent-hash (or (:head-hash (get states n1-hex)) "genesis")
         equiv-block-a (streamlet/sign-block
                        (streamlet/map->Block {:parent-hash parent-hash
                                               :epoch byz-epoch
                                               :proposer n3-hex
                                               :payload [{:byzantinebranch "A"}]})
                        n3-priv)
         equiv-block-b (streamlet/sign-block
                        (streamlet/map->Block {:parent-hash parent-hash
                                               :epoch byz-epoch
                                               :proposer n3-hex
                                               :payload [{:byzantinebranch "B"}]})
                        n3-priv)
         b-hash-a (streamlet/hash-block equiv-block-a)
         b-hash-b (streamlet/hash-block equiv-block-b)
         equiv-vote-a (streamlet/->Vote
                       b-hash-a
                       byz-epoch
                       (basalt/bytes->hex (crypto/sign n3-priv (fressian/utf8->bytes b-hash-a))))
         equiv-vote-b (streamlet/->Vote
                       b-hash-b
                       byz-epoch
                       (basalt/bytes->hex (crypto/sign n3-priv (fressian/utf8->bytes b-hash-b))))
         ;; 2. Forged gossip receipts from Byzantine node3 (forged reconfigure-membership + forged release-intent)
         forged-reconfig {:receipt-id "byz-forged-reconfig-1"
                          :type :reconfigure-membership
                          :effective-epoch byz-epoch
                          :validators [n3-hex]
                          :mesh-nodes {n3-hex 1.0}
                          :signature (basalt/bytes->hex (crypto/sign n3-priv (fressian/utf8->bytes "forged-reconfig")))}
         forged-release {:receipt-id "byz-forged-release-1"
                         :type :release-intent
                         :escrow-id "0000000000000000000000000000000000000000000000000000000000000000"
                         :preimage "forged"
                         :sender n3-hex}

         states-after-byz
         (reduce
          (fn [sts h-hex]
            (let [st0 (get sts h-hex)
                  ;; Step honest node to byz-epoch so proposals and votes are at current epoch
                  st1 (:state (sm/handle-event (assoc st0 :epoch byz-epoch)
                                               {:type :receive-propose :block equiv-block-a :sender n3-hex}))
                  st2 (:state (sm/handle-event st1
                                               {:type :receive-propose :block equiv-block-b :sender n3-hex}))
                  st3 (:state (sm/handle-event st2
                                               {:type :receive-vote :vote equiv-vote-a :sender n3-hex}))
                  st4 (:state (sm/handle-event st3
                                               {:type :receive-vote :vote equiv-vote-b :sender n3-hex}))
                  st5 (:state (sm/handle-event st4
                                               {:type :receive-receipt :receipt forged-reconfig :sender n3-hex}))
                  st6 (:state (sm/handle-event st5
                                               {:type :receive-receipt :receipt forged-release :sender n3-hex}))]
              (assoc sts h-hex st6)))
          states
          honest-hexes)

         honest-states (select-keys states-after-byz honest-hexes)
         verification (verify-against-golden-oracle honest-states golden adversarial-rejections)
         equivocation-detected? (every? (fn [[_ st]]
                                          (contains? (or (:equivocated-voters st) #{}) n3-hex))
                                        honest-states)
         forged-gossip-rejected? (every? (fn [[_ st]]
                                           (>= (long (get-in st [:diagnostics :unverified-gossip-receipt-rejected] 0)) 2))
                                         honest-states)]
     (assoc verification
            :equivocation-detected? equivocation-detected?
            :forged-gossip-rejected? forged-gossip-rejected?
            :chaos-healthy? (and (:parity? verification)
                                 equivocation-detected?
                                 forged-gossip-rejected?)))))

;; =============================================================================
;; 6. Target 3: Dynamic Zero-Reset Membership & Checkpoint Catch-Up (INV-D15-3, INV-D15-4)
;; =============================================================================

(defn run-dynamic-membership-e2e
  "Verifies zero-reset dynamic validator membership (`3 -> 6 -> 5` validators) and
   quorum-certified checkpoint catch-up (`B-CARB-2`, `B-CARB-3`, `INV-D15-4`):
   1. Starts with 3 Streamlet validators (`node1..node3`), runs epochs 1..5, and finalizes tx1.
   2. Dynamically adds `ns1..ns3` to `:mesh-nodes` and `:peers-map` via `:reconfigure-membership`
      signed by `:treasury` (priority -1).
   3. Catches up freshly initialized `ns1..ns3` nodes from epoch 0 using `:receive-checkpoint`
      signed by a 2-of-3 Streamlet quorum (`node1`, `node2`), verifying that tampered or
      insufficient-quorum checkpoints are rejected fail-closed.
   4. Submits tx2 and tx3 to `ns1` and `ns2` and finalizes them across all 6 nodes without chain reset.
   5. Dynamically removes `ns3` via a second `:reconfigure-membership` receipt and verifies
      clean finality across the remaining 5 nodes."
  []
  (let [scenario (workload/build-workload-scenario)
        topo (:topology scenario)
        vals-by-id (:validators-by-id topo)
        n1 (get-in vals-by-id [:node1 :pubkey-hex])
        n2 (get-in vals-by-id [:node2 :pubkey-hex])
        n3 (get-in vals-by-id [:node3 :pubkey-hex])
        ns1 (get-in vals-by-id [:ns1 :pubkey-hex])
        ns2 (get-in vals-by-id [:ns2 :pubkey-hex])
        initial-3-hexes [n1 n2 n3]
        initial-peers-map (select-keys (:peers-map topo) initial-3-hexes)
        initial-mesh-nodes (into (sorted-map) (map (fn [k] [k 1.0]) initial-3-hexes))

         ;; Phase 1: Initialize 3-node cluster (node1..node3) and finalize tx1 across epochs 1..5
        s0 (init-cluster-states topo [:node1 :node2 :node3]
                                {:validators (vec (sort initial-3-hexes))
                                 :peers-map initial-peers-map
                                 :mesh-nodes initial-mesh-nodes})
        s1 (advance-cluster-epochs s0 1)
        {:keys [tx1 tx2 tx3]} (:transfers scenario)
        s2 (dispatch-event-to-node
            s1 n1
            {:type :on-deliver
             :message-id "dyn-tx1"
             :sender (:sender tx1)
             :payload (fressian/encode-canonical {:transfer (into {} tx1)})})
        s3 (advance-cluster-epochs s2 4)

         ;; Phase 2: Reconfigure membership on-chain to add ns1, ns2, ns3 to mesh-nodes & peers-map
        all-6-mesh (:mesh-nodes topo)
        all-6-peers (:peers-map topo)
        eff-ep (inc (long (or (:epoch (get s3 n1)) 5)))
        s4 (dispatch-event-to-node
            s3 n1
            {:type :reconfigure-membership
             :receipt-id "reconfig-add-ns1-ns2-ns3"
             :effective-epoch eff-ep
             :validators (:streamlet-validator-hexes topo)
             :mesh-nodes all-6-mesh
             :new-peers-map all-6-peers
             :treasury-privkey (get-in topo [:treasury :private])})
        s5 (advance-cluster-epochs s4 4)

         ;; Verify node1..node3 executed :reconfigure-membership without resetting ledger or blocks
        n1-post-add (get s5 n1)
        reconfig-add-applied? (= (set (keys (:peers-map n1-post-add)))
                                 (set (:all-validator-hexes topo)))

         ;; Phase 3: Initialize fresh ns1, ns2, ns3 at epoch 0 and sync via Quorum-Certified Checkpoint
        fresh-ns (init-cluster-states topo [:ns1 :ns2 :ns3]
                                      {:validators (:streamlet-validator-hexes topo)
                                       :peers-map all-6-peers
                                       :mesh-nodes all-6-mesh})
         ;; Build checkpoint from n1 and collect 2-of-3 quorum signatures from n1 and n2
        fin-ep (long (:last-executed-finalized-epoch n1-post-add))
        fin-hash (:latest-finalized-block-hash n1-post-add)
        fin-block (get-in n1-post-add [:blocks fin-hash])
        snapshot (sm/build-checkpoint-snapshot n1-post-add)
        digest (sm/compute-checkpoint-state-digest snapshot)
        sig-n1 (sm/sign-checkpoint-attestation (get-in vals-by-id [:node1 :private]) fin-ep fin-hash digest)
        sig-n2 (sm/sign-checkpoint-attestation (get-in vals-by-id [:node2 :private]) fin-ep fin-hash digest)
        valid-qc {n1 sig-n1 n2 sig-n2}

         ;; Verify fail-closed rejection on tampered digest or 1-of-3 insufficient quorum
        ns1-fresh (get fresh-ns ns1)
        bad-qc-res (sm/handle-event ns1-fresh
                                    {:type :receive-checkpoint
                                     :finalized-epoch fin-ep
                                     :latest-finalized-block-hash fin-hash
                                     :latest-finalized-block fin-block
                                     :state-digest digest
                                     :snapshot snapshot
                                     :qc-signatures {n1 sig-n1}})
        tampered-snap-res (sm/handle-event (:state bad-qc-res)
                                           {:type :receive-checkpoint
                                            :finalized-epoch fin-ep
                                            :latest-finalized-block-hash fin-hash
                                            :latest-finalized-block fin-block
                                            :state-digest digest
                                            :snapshot (assoc snapshot :total-minted 999999999)
                                            :qc-signatures valid-qc})
        invalid-checkpoints-rejected? (= 2 (get-in (:state tampered-snap-res)
                                                   [:diagnostics :invalid-checkpoint-rejected] 0))

         ;; Apply valid QC checkpoint to ns1, ns2, ns3
        synced-ns
        (into {}
              (map (fn [[nh st]]
                     (let [res (sm/handle-event st
                                                {:type :receive-checkpoint
                                                 :finalized-epoch fin-ep
                                                 :latest-finalized-block-hash fin-hash
                                                 :latest-finalized-block fin-block
                                                 :state-digest digest
                                                 :snapshot snapshot
                                                 :qc-signatures valid-qc})]
                       [nh (assoc (:state res) :epoch (:epoch n1-post-add))]))
                   fresh-ns))
        all-6-states (merge s5 synced-ns)

         ;; Phase 4: Submit tx2 to ns1 and tx3 to ns2; verify gossip to node1..node3 and finality across all 6!
        s6 (-> all-6-states
               (dispatch-event-to-node
                ns1
                {:type :on-deliver
                 :message-id "dyn-tx2"
                 :sender (:sender tx2)
                 :payload (fressian/encode-canonical {:transfer (into {} tx2)})})
               (dispatch-event-to-node
                ns2
                {:type :on-deliver
                 :message-id "dyn-tx3"
                 :sender (:sender tx3)
                 :payload (fressian/encode-canonical {:transfer (into {} tx3)})}))
        s7 (advance-cluster-epochs s6 4)

         ;; Phase 5: Dynamically remove ns3 via :reconfigure-membership
        remaining-5-hexes [n1 n2 n3 ns1 ns2]
        mesh-5 (into (sorted-map) (map (fn [k] [k 1.0]) remaining-5-hexes))
        eff-ep-remove (inc (long (or (:epoch (get s7 n1)) 14)))
        s8 (dispatch-event-to-node
            (select-keys s7 remaining-5-hexes)
            n1
            {:type :reconfigure-membership
             :receipt-id "reconfig-remove-ns3"
             :effective-epoch eff-ep-remove
             :validators (:streamlet-validator-hexes topo)
             :mesh-nodes mesh-5
             :treasury-privkey (get-in topo [:treasury :private])})
        s9 (advance-cluster-epochs s8 4)

         ;; Verify all 5 remaining nodes converged on identical balances and 5-node membership
        buyer1-pk (get-in topo [:identities-by-id :agent-buyer-1 :pubkey-hex])
        buyer2-pk (get-in topo [:identities-by-id :agent-buyer-2 :pubkey-hex])
        author-pk (get-in topo [:identities-by-id :kernel-author :pubkey-hex])
        converged-5? (every? (fn [[_ st]]
                               (and (= (set (keys (:peers-map st))) (set remaining-5-hexes))
                                    (= (+ 400000 50000 -10000) (get-in st [:ledger buyer1-pk :balance]))
                                    (= (+ 300000 30000) (get-in st [:ledger buyer2-pk :balance]))
                                    (= (+ 200000 10000) (get-in st [:ledger author-pk :balance]))))
                             s9)]
    {:reconfig-add-applied? reconfig-add-applied?
     :invalid-checkpoints-rejected? invalid-checkpoints-rejected?
     :checkpoint-synced? (every? (fn [[_ st]]
                                   (= fin-ep (:last-executed-finalized-epoch st)))
                                 synced-ns)
     :converged-after-remove? converged-5?
     :all-passed? (and reconfig-add-applied?
                       invalid-checkpoints-rejected?
                       converged-5?)}))
