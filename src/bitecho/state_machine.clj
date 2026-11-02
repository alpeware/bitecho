(ns bitecho.state-machine
  "The pure root reducer that integrates Basalt, Murmur, Sieve, and Contagion.
   Accepts `state` and `event` inputs and emits a map of `{:state new-state :commands [...]}`."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.contagion.core :as contagion]
            [bitecho.crypto :as crypto]
            [bitecho.economy.account :as account]
            [bitecho.economy.attestation :as attestation]
            [bitecho.economy.bundle :as bundle]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.treasury :as treasury]
            [bitecho.murmur.core :as murmur]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.sieve.core :as sieve]
            [bitecho.streamlet.core :as streamlet]
            [clojure.edn :as edn]
            [clojure.set :as set]
            [clojure.string :as string])
  (:import [java.nio.charset StandardCharsets]))

(declare apply-payload-to-ledger execute-finalized-blocks derive-authoritative-roles)

(defn- peer-hex
  "Normalizes a peer's pubkey to a hex string."
  [peer]
  (let [pk (:pubkey peer)]
    (if (string? pk) pk (basalt/bytes->hex pk))))

(defn- attach-control-frame-signature
  "If node private key is present in state, signs the control frame and attaches :sender and :signature."
  [state cmd frame-type message-id]
  (if-let [priv (or (:node-private-key state)
                    (get-in state [:config :node-private-key])
                    (get-in state [:keypair :private])
                    (get-in state [:keys :private]))]
    (let [pub (:node-pubkey state)
          signed (sieve/sign-control-frame frame-type message-id priv pub)]
      (assoc cmd :sender pub :signature (:signature signed)))
    cmd))

(defn init-state
  "Initializes the pure Bitecho state map.
   node-pubkey should be the hex-encoded public key of this node.
   config is an optional protocol-parameter map (defaults to `config/default-config`)."
  ([initial-peers node-pubkey]
   (init-state initial-peers node-pubkey config/default-config))
  ([initial-peers node-pubkey cfg]
   (let [genesis-ledger (when-let [gl (:genesis-ledger cfg)]
                          (into {} (map (fn [[k v]] [k (if (instance? bitecho.economy.account.AccountState v)
                                                         v
                                                         (account/map->AccountState v))]))
                                gl))
         epoch-entropy (or (:epoch-entropy cfg) "genesis")
         view-size (:basalt-max-view-size cfg)]
     {:node-pubkey node-pubkey
      :config cfg
      :epoch 0
      :epoch-entropy epoch-entropy
      :epoch-burns {}
      :epoch-settlement-takes {}
      :basalt-index 0
      :basalt-view (basalt/init-view initial-peers view-size epoch-entropy node-pubkey)
      :murmur-cache {:set #{} :queue clojure.lang.PersistentQueue/EMPTY}
      :contagion-known-ids #{}
      :messages {} :message-epochs {}
      :epoch-to-messages {} :epoch-to-message-roles {}
      :global-echo-sample #{} :global-ready-sample #{} :global-delivery-sample #{}
      :echo-subscribers #{} :ready-subscribers #{} :delivery-subscribers #{}
      :received-echoes {} :received-readies {}
      :echo-vote-counts {} :ready-vote-counts {} :delivery-vote-counts {}
      :sieve-delivered-set #{} :local-ready-set #{} :delivered-set #{}
      :total-minted 0 :minted-epochs #{} :mint-dust 0 :epoch-mint-dust {}
      :unclaimed-mint 0 :epoch-unclaimed-mint {}
      :frozen-epoch-messages {} :frozen-epoch-message-roles {}
      :settled-transcript-pairs #{} :epoch-participation {}
      :attested-participation {} :peer-frozen-logs {}
      :fault-strikes {} :home-sets {} :voucher-seqs {}
      :pending-vouchers [] :settled-voucher-tuples #{} :failed-vouchers []
      :skipped-custody-allocations []
      :ledger (or genesis-ledger {})
      ;; Streamlet BFT state
      :blocks {} :notarized-blocks #{} :finalized-blocks #{}
      :block-votes {} :voted-epochs #{} :head-hash "genesis" :mempool []
      :peers-map (or (:peers-map cfg) {})
      :keypair (or (:keypair cfg) nil)
      :pending-receipts []
      :known-receipt-ids #{}
      :known-receipt-order []
      :executed-receipt-ids #{}
      :executed-receipt-order []
      :executed-finalized-blocks #{}
      :executed-finalized-blocks-order []
      :last-executed-finalized-epoch 0
      :receipt-seq 0
      :failed-receipts-count 0
      :escrows {}
      :settled-escrow-ids #{}
      :settled-escrow-order []})))

(defn fifo-track
  "Maintains a bounded set and order vector with deterministic FIFO eviction.
   Returns [new-set new-order]."
  [set-val order-vec item max-tracked]
  (let [s (or set-val #{})
        ord (or order-vec [])
        max-cap (long (max 1 (or max-tracked 10000)))]
    (if (contains? s item)
      [s ord]
      (let [next-set (conj s item)
            next-order (conj ord item)]
        (if (> (count next-order) max-cap)
          (let [overflow (- (count next-order) max-cap)
                evicted (subvec next-order 0 overflow)
                kept (subvec next-order overflow)]
            [(reduce disj next-set evicted) kept])
          [next-set next-order])))))

(defn consensus-mode?
  "Returns true if the node is operating in Streamlet BFT consensus mode with configured peers."
  [state]
  (boolean (seq (:peers-map state))))

(defn spendable-balance
  "Computes spendable balance for pubkey in consensus mode by subtracting unfinalized pending debits."
  [state pubkey]
  (let [pk (if (string? pubkey) pubkey (when pubkey (basalt/bytes->hex pubkey)))
        auth-bal (long (or (get-in state [:ledger pk :balance]) 0))
        pending (or (:pending-receipts state) [])
        burn-debit (reduce (fn [acc r]
                             (if (and (= (:type r) :burn) (= (:sender r) pk))
                               (+ acc (long (or (:amount r) 0)))
                               acc))
                           0 pending)
        transfer-debit (reduce (fn [acc r]
                                 (if (and (= (:type r) :transfer) (= (:sender r) pk))
                                   (+ acc (long (or (:amount r) 0)))
                                   acc))
                               0 pending)
        intent-debit (reduce (fn [acc r]
                               (if (and (= (:type r) :settle-intent) (= (:payer r) pk))
                                 (+ acc (long (or (:amount r) 0)))
                                 acc))
                             0 pending)
        lock-debit (reduce (fn [acc r]
                             (if (and (= (:type r) :lock-intent) (= (:payer r) pk))
                               (+ acc (long (or (:amount r) 0)))
                               acc))
                           0 pending)
        voucher-tuples (reduce (fn [acc r]
                                 (if (and (= (:type r) :voucher) (= (:callee r) pk))
                                   (let [k [(:callee r) (rendezvous/normalize-home-node (:home-node r)) (:epoch r)]
                                         prev (get acc k 0)
                                         curr (long (or (:cumulative-debit r) 0))]
                                     (assoc acc k (max prev curr)))
                                   acc))
                               {} pending)
        voucher-debit (reduce + 0 (vals voucher-tuples))
        total-debit (+ burn-debit transfer-debit intent-debit lock-debit voucher-debit)]
    (- auth-bal total-debit)))

(defn stage-receipt
  "Stages a receipt into :pending-receipts bounded by :max-pending-receipts.
   Returns {:ok? true/false :state state}."
  [state receipt]
  (let [max-cap (long (or (get-in state [:config :max-pending-receipts]) 4096))
        max-tracked (long (or (get-in state [:config :max-tracked-receipts]) 10000))
        rid (:receipt-id receipt)]
    (cond
      (or (contains? (or (:known-receipt-ids state) #{}) rid)
          (contains? (or (:executed-receipt-ids state) #{}) rid))
      {:ok? true :state state}

      (>= (count (or (:pending-receipts state) [])) max-cap)
      {:ok? false :state state}

      :else
      (let [[next-known next-known-ord] (fifo-track (:known-receipt-ids state)
                                                    (:known-receipt-order state)
                                                    rid
                                                    max-tracked)]
        {:ok? true
         :state (-> state
                    (update :pending-receipts (fnil conj []) receipt)
                    (assoc :known-receipt-ids next-known
                           :known-receipt-order next-known-ord)
                    (update :receipt-seq (fnil inc 0)))}))))

(defn extract-burn-window
  "Extracts the trailing burn and settlement take window up to the authoritative anchor epoch,
   bounded by at most n entries."
  [state]
  (let [anchor-epoch (long (if (consensus-mode? state)
                             (or (:last-executed-finalized-epoch state) 0)
                             (or (:epoch state) 0)))
        n (long (or (get-in state [:config :treasury-trailing-epochs]) 168))
        start-ep (max 0 (inc (- anchor-epoch (max 1 n))))
        window (mapv (fn [ep]
                       [ep
                        (long (or (get-in state [:epoch-burns ep]) 0))
                        (long (or (get-in state [:epoch-settlement-takes ep]) 0))])
                     (range start-ep (inc anchor-epoch)))]
    {:anchor-epoch anchor-epoch
     :window window}))

(defn compute-burn-map-digest
  "Computes a 16-hex-character digest of the trailing burn and settlement take window."
  [state]
  (let [w (extract-burn-window state)
        s (pr-str w)
        b (.getBytes ^String s StandardCharsets/UTF_8)
        h (basalt/bytes->hex (crypto/sha256 b))]
    (subs h 0 16)))

(defn- build-tick-treasury-ctx
  "Extracts trailing revenues and builds the treasury context for an epoch tick boundary."
  [state new-epoch cfg]
  (let [n (or (:treasury-trailing-epochs cfg) 168)
        trailing-revs (treasury/extract-trailing-revenues state new-epoch n)
        custody-pk (or (:custody-pubkey state) (:custody-pubkey cfg))
        custody-sk (or (:custody-privkey state) (:custody-privkey cfg))]
    {:epoch new-epoch
     :n-epochs n
     :trailing-burns trailing-revs
     :total-minted (or (:total-minted state) 0)
     :ledger (or (:ledger state) {})
     :carry-dust (or (:mint-dust state) 0)
     :validators (or (:validators state) (:validators cfg))
     :mesh-nodes (or (:mesh-nodes state) (:mesh-nodes cfg))
     :custody-pubkey custody-pk
     :custody-privkey custody-sk
     :custody-allocations (or (:custody-allocations state) (:custody-allocations cfg))
     :bootstrap-sunset-epoch (or (:bootstrap-sunset-epoch state)
                                 (:bootstrap-sunset-epoch cfg)
                                 treasury/default-bootstrap-sunset-epoch)
     :treasury-pubkey (or (:treasury-pubkey state) (:treasury-pubkey cfg))
     :treasury-privkey (or (:treasury-privkey state) (:treasury-privkey cfg))}))

(defn- node-in-home-set?
  "Checks if a home-node is present in the registered home set."
  [home-node home-set]
  (let [nodes (or (:home-nodes home-set) (:nodes home-set) (:candidates home-set))
        norm rendezvous/normalize-home-node]
    (boolean
     (some (fn [n]
             (let [id (cond
                        (map? n) (or (:node-id n) (:pubkey n) (:id n) (:address n))
                        :else n)]
               (= (norm id) (norm home-node))))
           nodes))))

(defn- settle-single-voucher
  "Settles a single compacted DeliveryAck voucher against state, updating ledger and settled tuples.
   Fails closed: requires callee balance >= debit; records failure in :failed-vouchers and queues valid
   underfunded vouchers in :retry-vouchers for retry in subsequent epochs."
  [acc ack closing-epoch min-epoch]
  (let [callee (:callee ack)
        home-node (rendezvous/normalize-home-node (:home-node ack))
        ack (if (contains? ack :home-node) (assoc ack :home-node home-node) ack)
        ack-epoch (:epoch ack)
        tuple [callee home-node ack-epoch]
        reg-set (get-in acc [:home-sets [callee ack-epoch]])
        reg-price (:price reg-set)]
    (cond
      (if (some? min-epoch)
        (or (nil? ack-epoch)
            (< ack-epoch min-epoch)
            (and (some? closing-epoch) (> ack-epoch closing-epoch)))
        (and (some? closing-epoch) (not= ack-epoch closing-epoch)))
      (update acc :failed-vouchers (fnil conj [])
              {:voucher ack
               :epoch ack-epoch
               :reason :expired-epoch})

      (or (nil? reg-set)
          (= :rejected (:status reg-set))
          (not (node-in-home-set? home-node reg-set))
          (nil? reg-price)
          (not (integer? reg-price))
          (neg? (long reg-price)))
      (update acc :failed-vouchers (fnil conj [])
              {:voucher ack
               :epoch ack-epoch
               :reason :unregistered-home-set})

      :else
      (let [v-res (rendezvous/verify-ack-for-settlement
                   ack
                   {:settlement-epoch closing-epoch
                    :min-settlement-epoch min-epoch
                    :registered-price reg-price
                    :settled-tuples (:settled-voucher-tuples acc)})]
        (if (:valid? v-res)
          (let [debit (:debit v-res)
                ledger (:ledger acc)
                callee-st (get ledger callee (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                callee-bal (or (:balance callee-st) 0)]
            (if (>= callee-bal debit)
              (let [home-st (get ledger home-node (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                    new-callee (assoc callee-st :balance (- callee-bal debit))
                    new-home (assoc home-st :balance (+ (or (:balance home-st) 0) debit))
                    new-ledger (assoc ledger callee new-callee home-node new-home)]
                (-> acc
                    (assoc :ledger new-ledger)
                    (update :settled-voucher-tuples conj tuple)))
              (-> acc
                  (update :failed-vouchers (fnil conj [])
                          {:voucher ack
                           :epoch ack-epoch
                           :debit debit
                           :callee-balance callee-bal
                           :reason :insufficient-callee-balance})
                  (update :retry-vouchers (fnil conj []) ack))))
          (update acc :failed-vouchers (fnil conj [])
                  {:voucher ack
                   :epoch ack-epoch
                   :reason (or (:reason v-res) (:error v-res) :invalid-voucher)}))))))

(defn- apply-epoch-voucher-settlement
  "Compacts pending vouchers from epoch 0 through closing-epoch and settles valid vouchers within [min-epoch, closing-epoch], recording and evicting expired vouchers."
  [state closing-epoch]
  (let [pending (or (:pending-vouchers state) [])
        retention (or (get-in state [:config :frozen-log-retention-epochs]) 168)
        min-epoch (max 0 (- closing-epoch retention))
        compacted (bundle/compact-vouchers pending closing-epoch 0)
        settled-tuples (or (:settled-voucher-tuples state) #{})
        ledger (or (:ledger state) {})
        init-acc (assoc state
                        :settled-voucher-tuples settled-tuples
                        :ledger ledger
                        :failed-vouchers []
                        :retry-vouchers [])
        final-acc (reduce (fn [acc ack] (settle-single-voucher acc ack closing-epoch min-epoch))
                          init-acc
                          compacted)
        future-pending (filterv #(and (integer? (:epoch %)) (> (:epoch %) closing-epoch)) pending)
        retained-pending (into (or (:retry-vouchers final-acc) []) future-pending)]
    (-> final-acc
        (assoc :pending-vouchers retained-pending)
        (dissoc :retry-vouchers))))

(defn- apply-epoch-treasury-boundary
  "Executes treasury epoch boundary calculations, applying demand-gated mint
   and custody drawdowns or sunset burns to the state."
  [state new-epoch]
  (let [cfg (:config state)
        treasury-ctx (build-tick-treasury-ctx state new-epoch cfg)
        res (treasury/process-treasury-epoch treasury-ctx)
        actual-minted (or (:actual-minted res) 0)
        epoch-mint (or (:epoch-mint res) 0)
        mint-dust (or (:mint-dust res) 0)
        unclaimed-mint (or (:unclaimed-mint res) 0)
        all-mint-shares (or (:all-mint-shares res) {})
        state-with-custody (-> (if-let [l (:ledger res)]
                                 (assoc state :ledger l)
                                 state)
                               (assoc :skipped-custody-allocations
                                      (or (:skipped-allocations res) [])))
        t-priv (or (:treasury-privkey state) (get-in state [:config :treasury-privkey]))
        t-pub (or (:treasury-pubkey state) (get-in state [:config :treasury-pubkey]))]
    (cond
      (and (seq all-mint-shares) (pos? actual-minted) t-priv t-pub)
      (let [sig (treasury/sign-epoch-mint t-priv new-epoch all-mint-shares mint-dust)]
        (treasury/apply-epoch-mint state-with-custody
                                   {:epoch new-epoch
                                    :epoch-gate epoch-mint
                                    :mint-dust mint-dust
                                    :unclaimed-mint unclaimed-mint
                                    :allocations all-mint-shares
                                    :treasury-pubkey t-pub
                                    :signature sig}))

      (and (pos? epoch-mint) (zero? actual-minted) t-priv t-pub)
      (-> state-with-custody
          (assoc :mint-dust mint-dust)
          (assoc-in [:epoch-mint-dust new-epoch] mint-dust)
          (update :unclaimed-mint (fnil + 0) unclaimed-mint)
          (assoc-in [:epoch-unclaimed-mint new-epoch] unclaimed-mint))

      :else
      state-with-custody)))

(defn- block->hash-str
  "Extracts or computes the SHA-256 hash string of a block, hash string, or map."
  [b]
  (cond
    (and (string? b) (not (string/blank? b))) b
    (bytes? b) (basalt/bytes->hex b)
    (map? b) (or (when (and (string? (:hash b)) (not (string/blank? (:hash b)))) (:hash b))
                 (streamlet/hash-block b))
    :else nil))

(defn derive-epoch-entropy
  "Derives the epoch entropy string strictly from finalized block hashes, state, or config.
   Prioritizes :latest-finalized-block-hash, then :latest-finalized-block,
   then latest from :finalized-blocks (hashing block maps if needed),
   falling back to :epoch-entropy in state or cfg, or 'genesis'.
   Guarantees a valid non-empty string is returned without ever stringifying a map."
  [state cfg]
  (let [cand (or (when-let [h (:latest-finalized-block-hash state)]
                   (block->hash-str h))
                 (when-let [b (:latest-finalized-block state)]
                   (block->hash-str b))
                 (when-let [fb (seq (:finalized-blocks state))]
                   (let [sorted-blocks (sort-by (fn [x]
                                                  (if (map? x)
                                                    (or (:epoch x) 0)
                                                    x))
                                                fb)]
                     (block->hash-str (last sorted-blocks))))
                 (when-let [e (:epoch-entropy state)]
                   (when-not (and (string? e) (string/blank? e)) (str e)))
                 (when-let [e (:epoch-entropy cfg)]
                   (when-not (and (string? e) (string/blank? e)) (str e)))
                 "genesis")]
    (if (and (string? cand) (not (string/blank? cand)))
      cand
      "genesis")))

(defn- sample-peer-roles
  "Selects background peer samples for echo, ready, and delivery roles deterministically,
   returning updated sets and subscribe commands."
  [state cfg epoch-entropy new-epoch extracted-peers]
  (let [E-size (:echo-sample-size cfg)
        R-size (:ready-sample-size cfg)
        D-size (:delivery-sample-size cfg)
        my-pubkey (:node-pubkey state)
        peer-hexes (mapv peer-hex extracted-peers)
        needed-echo (max 0 (- E-size (count (:global-echo-sample state))))
        needed-ready (max 0 (- R-size (count (:global-ready-sample state))))
        needed-delivery (max 0 (- D-size (count (:global-delivery-sample state))))
        exclude-fn (fn [sample-set p-hex]
                     (or (= p-hex my-pubkey) (contains? sample-set p-hex)))
        avail-idx-for (fn [sample-set]
                        (filterv #(not (exclude-fn sample-set (nth peer-hexes %)))
                                 (range (count extracted-peers))))
        echo-avail-idxs (avail-idx-for (:global-echo-sample state))
        echo-avail-peers (mapv #(nth extracted-peers %) echo-avail-idxs)
        new-echo-peers (basalt/select-peers-deterministic (str epoch-entropy ":echo:" new-epoch) my-pubkey echo-avail-peers needed-echo)
        new-echo-hexes (set (mapv peer-hex new-echo-peers))
        ready-avail-idxs (avail-idx-for (:global-ready-sample state))
        ready-avail-peers (mapv #(nth extracted-peers %) ready-avail-idxs)
        new-ready-peers (basalt/select-peers-deterministic (str epoch-entropy ":ready:" new-epoch) my-pubkey ready-avail-peers needed-ready)
        new-ready-hexes (set (mapv peer-hex new-ready-peers))
        delivery-avail-idxs (avail-idx-for (:global-delivery-sample state))
        delivery-avail-peers (mapv #(nth extracted-peers %) delivery-avail-idxs)
        new-delivery-peers (basalt/select-peers-deterministic (str epoch-entropy ":delivery:" new-epoch) my-pubkey delivery-avail-peers needed-delivery)
        new-delivery-hexes (set (mapv peer-hex new-delivery-peers))
        updated-echo-sample (set/union (:global-echo-sample state) new-echo-hexes)
        updated-ready-sample (set/union (:global-ready-sample state) new-ready-hexes)
        updated-delivery-sample (set/union (:global-delivery-sample state) new-delivery-hexes)
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :echo)) {} updated-echo-sample)
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :ready)) new-roles-by-peer updated-ready-sample)
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :delivery)) new-roles-by-peer updated-delivery-sample)
        subscribe-commands (mapv (fn [[peer roles]]
                                   {:type :send-subscribe
                                    :target peer
                                    :roles roles})
                                 new-roles-by-peer)]
    {:echo-sample updated-echo-sample
     :ready-sample updated-ready-sample
     :delivery-sample updated-delivery-sample
     :subscribe-commands subscribe-commands}))

(defn update-attested-mesh-weights
  "Updates epoch and windowed attested participation for credited-peers,
   recomputing mesh-nodes weights using continuous linear stake scaling
   when any attested participation exists."
  [state epoch credited-peers role-count]
  (let [weight-delta (max 1 (long (or role-count 1)))
        new-epoch-part (reduce (fn [ep-map p]
                                 (update-in ep-map [epoch p] (fnil + 0) weight-delta))
                               (or (:epoch-participation state) {})
                               credited-peers)
        new-attested (reduce (fn [acc [_ peer-counts]]
                               (reduce-kv (fn [a p cnt]
                                            (update a p (fnil + 0) cnt))
                                          acc
                                          peer-counts))
                             {}
                             new-epoch-part)
        state' (assoc state
                      :epoch-participation new-epoch-part
                      :attested-participation new-attested)
        base-peers (set/union (set (keys new-attested))
                              (let [mn (or (:mesh-nodes state') (get-in state' [:config :mesh-nodes]))]
                                (cond
                                  (map? mn) (set (keys mn))
                                  (coll? mn) (set mn)
                                  :else #{}))
                              (set (keys (:peers-map state'))))
        s-min (double (or (get-in state' [:config :min-stake]) attestation/default-min-stake))
        weights (reduce (fn [acc p]
                          (let [part (double (get new-attested p 0))
                                bal (get-in state' [:ledger p :balance])
                                stake (double (max 1 (long (or bal attestation/default-min-stake))))
                                w (attestation/calculate-node-weight part stake s-min)]
                            (assoc acc p w)))
                        {}
                        base-peers)]
    (if (some (fn [[_ w]] (pos? (double w))) weights)
      (assoc state' :mesh-nodes weights)
      state')))

(defn- prune-rendezvous-retention-state
  "Prunes :home-sets and :voucher-seqs entries strictly older than rdv-cutoff,
   preserving entries within the active voucher retry window."
  [state rdv-cutoff]
  (let [hs (or (:home-sets state) {})
        vs (or (:voucher-seqs state) {})
        pruned-hs (reduce-kv (fn [m k v]
                               (let [ep (second k)]
                                 (if (and (integer? ep) (< ep rdv-cutoff))
                                   m
                                   (assoc m k v))))
                             {}
                             hs)
        pruned-vs (reduce-kv (fn [m k v]
                               (let [ep (nth k 2 nil)]
                                 (if (and (integer? ep) (< ep rdv-cutoff))
                                   m
                                   (assoc m k v))))
                             {}
                             vs)]
    (assoc state
           :home-sets pruned-hs
           :voucher-seqs pruned-vs)))

(defn- prune-expired-tick-state
  "Prunes state message and role entries for epochs older than the TTL cutoff,
   and bounds frozen epoch message and role snapshots to frozen-log-retention-epochs."
  [state new-epoch cfg]
  (let [gossip-ttl-epochs (or (:gossip-ttl-epochs cfg) 10)
        cutoff-epoch (- new-epoch gossip-ttl-epochs)
        frozen-retention (or (:frozen-log-retention-epochs cfg) 168)
        frozen-cutoff (- new-epoch frozen-retention)
        epoch-to-messages (or (:epoch-to-messages state) {})
        expired-epochs (filterv #(< % cutoff-epoch) (keys epoch-to-messages))
        expired-ids (reduce (fn [acc ep] (set/union acc (get epoch-to-messages ep #{})))
                            #{} expired-epochs)
        pruned-epoch-to-messages (reduce dissoc epoch-to-messages expired-epochs)
        pruned-epoch-to-roles (reduce dissoc (or (:epoch-to-message-roles state) {}) expired-epochs)
        pruned-epochs (reduce dissoc (or (:message-epochs state) {}) expired-ids)
        pruned-messages (reduce dissoc (:messages state) expired-ids)
        pruned-known-ids (set/difference (:contagion-known-ids state) expired-ids)
        pruned-received-echoes (reduce dissoc (or (:received-echoes state) {}) expired-ids)
        pruned-received-readies (reduce dissoc (or (:received-readies state) {}) expired-ids)
        pruned-echo-vote-counts (reduce dissoc (or (:echo-vote-counts state) {}) expired-ids)
        pruned-ready-vote-counts (reduce dissoc (or (:ready-vote-counts state) {}) expired-ids)
        pruned-delivery-vote-counts (reduce dissoc (or (:delivery-vote-counts state) {}) expired-ids)
        pruned-sieve-delivered-set (set/difference (:sieve-delivered-set state) expired-ids)
        pruned-local-ready-set (set/difference (:local-ready-set state) expired-ids)
        pruned-delivered-set (set/difference (:delivered-set state) expired-ids)
        expired-frozen-epochs (filterv #(< % frozen-cutoff) (keys (or (:frozen-epoch-messages state) {})))
        pruned-frozen-messages (reduce dissoc (or (:frozen-epoch-messages state) {}) expired-frozen-epochs)
        pruned-frozen-roles (reduce dissoc (or (:frozen-epoch-message-roles state) {}) expired-frozen-epochs)
        rdv-cutoff (- (dec new-epoch) frozen-retention)
        pruned-settled-transcripts (into #{}
                                         (filter (fn [t]
                                                   (let [ep (first t)]
                                                     (and (integer? ep) (>= ep frozen-cutoff))))
                                                 (or (:settled-transcript-pairs state) #{})))
        pruned-epoch-part (reduce-kv (fn [m ep v]
                                       (if (and (integer? ep) (< ep frozen-cutoff))
                                         m
                                         (assoc m ep v)))
                                     {}
                                     (or (:epoch-participation state) {}))
        recomputed-attested-part (reduce (fn [acc [_ peer-counts]]
                                           (reduce-kv (fn [a p cnt]
                                                        (update a p (fnil + 0) cnt))
                                                      acc
                                                      peer-counts))
                                         {}
                                         pruned-epoch-part)
        pruned-peer-frozen-logs (reduce-kv (fn [m k v]
                                             (let [ep (first k)]
                                               (if (and (integer? ep) (< ep frozen-cutoff))
                                                 m
                                                 (assoc m k v))))
                                           {}
                                           (or (:peer-frozen-logs state) {}))
        max-tracked (long (or (:max-tracked-receipts cfg) 10000))
        [pruned-tracked-known pruned-known-ord]
        (let [k (or (:known-receipt-ids state) #{})
              ord (or (:known-receipt-order state) [])]
          (if (> (count ord) max-tracked)
            (let [overflow (- (count ord) max-tracked)
                  evicted (subvec ord 0 overflow)
                  kept (subvec ord overflow)]
              [(reduce disj k evicted) kept])
            [k ord]))
        [pruned-tracked-exec pruned-exec-ord]
        (let [e (or (:executed-receipt-ids state) #{})
              ord (or (:executed-receipt-order state) [])]
          (if (> (count ord) max-tracked)
            (let [overflow (- (count ord) max-tracked)
                  evicted (subvec ord 0 overflow)
                  kept (subvec ord overflow)]
              [(reduce disj e evicted) kept])
            [e ord]))
        [pruned-exec-blocks pruned-exec-blocks-ord]
        (let [cutoff (- new-epoch frozen-retention)
              blocks (or (:blocks state) {})
              eb (or (:executed-finalized-blocks state) #{})
              ord (or (:executed-finalized-blocks-order state) [])
              filtered-set (into #{}
                                 (filter (fn [h]
                                           (if-let [b (get blocks h)]
                                             (>= (long (or (:epoch b) 0)) cutoff)
                                             false))
                                         eb))
              filtered-ord (filterv #(contains? filtered-set %) ord)]
          (if (> (count filtered-ord) max-tracked)
            (let [overflow (- (count filtered-ord) max-tracked)
                  evicted (subvec filtered-ord 0 overflow)
                  kept (subvec filtered-ord overflow)]
              [(reduce disj filtered-set evicted) kept])
            [filtered-set filtered-ord]))
        escrow-horizon (long (or (:max-escrow-horizon cfg) 168))
        escrow-cutoff (- new-epoch escrow-horizon)
        pruned-escrows (reduce-kv (fn [m eid v]
                                    (if (and (contains? #{:released :refunded} (:status v))
                                             (<= (long (or (:settled-epoch v) (:expires-epoch v) 0)) escrow-cutoff))
                                      m
                                      (assoc m eid v)))
                                  {}
                                  (or (:escrows state) {}))
        [pruned-tracked-settled-escrows pruned-settled-escrows-ord]
        (let [s (or (:settled-escrow-ids state) #{})
              ord (or (:settled-escrow-order state) [])]
          (if (> (count ord) max-tracked)
            (let [overflow (- (count ord) max-tracked)
                  evicted (subvec ord 0 overflow)
                  kept (subvec ord overflow)]
              [(reduce disj s evicted) kept])
            [s ord]))]
    (-> (assoc state
               :epoch-to-messages pruned-epoch-to-messages
               :epoch-to-message-roles pruned-epoch-to-roles
               :message-epochs pruned-epochs
               :messages pruned-messages
               :contagion-known-ids pruned-known-ids
               :received-echoes pruned-received-echoes
               :received-readies pruned-received-readies
               :echo-vote-counts pruned-echo-vote-counts
               :ready-vote-counts pruned-ready-vote-counts
               :delivery-vote-counts pruned-delivery-vote-counts
               :sieve-delivered-set pruned-sieve-delivered-set
               :local-ready-set pruned-local-ready-set
               :delivered-set pruned-delivered-set
               :frozen-epoch-messages pruned-frozen-messages
               :frozen-epoch-message-roles pruned-frozen-roles
               :settled-transcript-pairs pruned-settled-transcripts
               :epoch-participation pruned-epoch-part
               :attested-participation recomputed-attested-part
               :peer-frozen-logs pruned-peer-frozen-logs
               :known-receipt-ids pruned-tracked-known
               :known-receipt-order pruned-known-ord
               :executed-receipt-ids pruned-tracked-exec
               :executed-receipt-order pruned-exec-ord
               :executed-finalized-blocks pruned-exec-blocks
               :executed-finalized-blocks-order pruned-exec-blocks-ord
               :escrows pruned-escrows
               :settled-escrow-ids pruned-tracked-settled-escrows
               :settled-escrow-order pruned-settled-escrows-ord)
        (prune-rendezvous-retention-state rdv-cutoff))))

(defn- collect-ancestor-receipt-ids
  "Collects receipt IDs present in notarized ancestor blocks along the chain back to genesis,
   stopping at genesis, missing blocks, or executed finalized blocks."
  [state]
  (let [blocks (:blocks state)
        executed-blocks (or (:executed-finalized-blocks state) #{})]
    (loop [curr (get state :head-hash "genesis")
           visited #{}
           acc #{}]
      (cond
        (= curr "genesis") acc
        (contains? visited curr) acc
        (contains? executed-blocks curr) acc
        :else
        (if-let [block (get blocks curr)]
          (let [payload (:payload block)
                rids (set (keep (fn [x] (when (and (map? x) (:receipt-id x)) (:receipt-id x)))
                                (when (sequential? payload) payload)))]
            (recur (:parent-hash block) (conj visited curr) (into acc rids)))
          acc)))))

(defn- apply-streamlet-tick
  "Steps Streamlet BFT tick if peers-map is configured, advancing consensus state and commands."
  [state commands closing-epoch]
  (if (consensus-mode? state)
    (let [ancestor-rids (collect-ancestor-receipt-ids state)
          exec-rids (or (:executed-receipt-ids state) #{})
          filtered-receipts (->> (or (:pending-receipts state) [])
                                 (remove (fn [r]
                                           (let [rid (:receipt-id r)]
                                             (or (contains? exec-rids rid)
                                                 (contains? ancestor-rids rid)))))
                                 (sort-by (fn [r]
                                            [(case (:type r)
                                               :register-home-set 0
                                               :burn 1
                                               :transfer 2
                                               :settle-intent 3
                                               :lock-intent 4
                                               :release-intent 5
                                               :refund-intent 6
                                               :voucher 7
                                               :transcript 8
                                               9)
                                             (long (or (:seq r) 0))
                                             (str (:receipt-id r))]))
                                 vec)
          should-set-mempool? (or (seq filtered-receipts)
                                  (empty? (:mempool state))
                                  (boolean (seq (filter #(and (map? %) (:receipt-id %)) (:mempool state)))))
          tick-state (cond-> (assoc state :epoch closing-epoch)
                       should-set-mempool? (assoc :mempool filtered-receipts))
          streamlet-res (streamlet/handle-streamlet-event tick-state {:type :tick})
          post-exec-state (execute-finalized-blocks (:state streamlet-res))]
      {:state post-exec-state
       :commands (into (or commands []) (:commands streamlet-res))})
    {:state state
     :commands commands}))

(defn- peer-pubkey-hex
  "Normalizes a Peer record, map, hex string, or byte array into a hex pubkey string."
  [peer]
  (let [pk (if (map? peer) (:pubkey peer) peer)]
    (cond
      (string? pk) pk
      (bytes? pk) (basalt/bytes->hex pk)
      :else nil)))

(defn- exclude-self-peers
  "Filters out any peer entry matching the state's :node-pubkey."
  [state peers]
  (if-let [self-hex (peer-pubkey-hex (:node-pubkey state))]
    (filterv #(not= (peer-pubkey-hex %) self-hex) peers)
    (vec peers)))

(defn- sanitize-basalt-view
  "Strips any slot whose :peer matches (:node-pubkey state) by setting :peer to nil."
  [state view]
  (if-let [self-hex (peer-pubkey-hex (:node-pubkey state))]
    (mapv (fn [slot]
            (if (= (peer-pubkey-hex (:peer slot)) self-hex)
              (assoc slot :peer nil)
              slot))
          view)
    view))

(defn- handle-tick
  "Handles a periodic tick event to drive Basalt reseeding and Contagion anti-entropy."
  [state event]
  (let [cfg (:config state)
        new-epoch (inc (or (:epoch state) 0))
        epoch-entropy (derive-epoch-entropy state cfg)
        view (sanitize-basalt-view state (:basalt-view state))
        rng (:rng event)
        reset-result (basalt/reset-slots-deterministic view epoch-entropy (:node-pubkey state) (:basalt-index state) 1)
        new-view (sanitize-basalt-view state (:view reset-result))
        new-index (:next-r reset-result)
        extracted-peers (exclude-self-peers state (basalt/extract-peers new-view))
        push-targets (basalt/select-peers-deterministic (str epoch-entropy ":push:" new-epoch) (:node-pubkey state) new-view 1)
        push-command (when (seq push-targets)
                       {:type :send-push-view
                        :targets push-targets
                        :view extracted-peers})
        summary (contagion/generate-summary rng extracted-peers (:contagion-known-ids state))
        summary-command (when summary
                          {:type :send-summary
                           :target (:target summary)
                           :summary (:summary summary)})
        sampling-res (sample-peer-roles state cfg epoch-entropy new-epoch extracted-peers)
        echo-subs (:echo-subscribers state)
        pending-echo-ids (set/difference (:contagion-known-ids state)
                                         (:sieve-delivered-set state))
        echo-ae-commands (when (seq echo-subs)
                           (mapv (fn [mid]
                                   (attach-control-frame-signature
                                    state
                                    {:type :send-sieve-echo
                                     :targets echo-subs
                                     :message-id mid}
                                    :sieve-echo
                                    mid))
                                 pending-echo-ids))
        commands (into (filterv some? (concat [push-command summary-command] (:subscribe-commands sampling-res)))
                       echo-ae-commands)
        closing-epoch (or (:epoch state) 0)
        closing-messages (get (:epoch-to-messages state) closing-epoch #{})
        closing-roles (get (:epoch-to-message-roles state) closing-epoch {})
        frozen-epoch-messages (assoc (or (:frozen-epoch-messages state) {}) closing-epoch closing-messages)
        frozen-epoch-roles (assoc (or (:frozen-epoch-message-roles state) {}) closing-epoch closing-roles)
        base-state (assoc state
                          :epoch new-epoch
                          :epoch-entropy epoch-entropy
                          :basalt-view new-view
                          :basalt-index new-index
                          :frozen-epoch-messages frozen-epoch-messages
                          :frozen-epoch-message-roles frozen-epoch-roles
                          :fault-strikes (or (:fault-strikes state) {})
                          :global-echo-sample (:echo-sample sampling-res)
                          :global-ready-sample (:ready-sample sampling-res)
                          :global-delivery-sample (:delivery-sample sampling-res))
        pruned-state (prune-expired-tick-state base-state new-epoch cfg)
        transcript-commands (when (and (consensus-mode? pruned-state)
                                       (seq closing-messages)
                                       (or (:node-private-key pruned-state)
                                           (get-in pruned-state [:keypair :private])))
                              (let [my-pub (:node-pubkey pruned-state)
                                    my-priv (or (:node-private-key pruned-state)
                                                (get-in pruned-state [:keypair :private]))
                                    auth-roles (attestation/canonicalize-message-roles
                                                (derive-authoritative-roles closing-messages closing-roles))
                                    my-frozen-log (attestation/sign-frozen-log closing-epoch my-pub closing-messages my-priv)
                                    peer-pubs (sort (disj (set (keys (:peers-map pruned-state))) my-pub))]
                                (mapv (fn [peer-pub]
                                        (let [half-tx (attestation/create-transcript closing-epoch my-pub peer-pub auth-roles my-priv)]
                                          {:type :send-transcript-sig
                                           :target peer-pub
                                           :epoch closing-epoch
                                           :transcript (into {} half-tx)
                                           :frozen-log my-frozen-log}))
                                      peer-pubs)))
        all-commands (into commands transcript-commands)]
    (if (consensus-mode? pruned-state)
      (apply-streamlet-tick pruned-state all-commands closing-epoch)
      (let [tick-state-settled (apply-epoch-voucher-settlement pruned-state closing-epoch)
            treasury-state (apply-epoch-treasury-boundary tick-state-settled new-epoch)]
        (apply-streamlet-tick treasury-state all-commands closing-epoch)))))

(defn- apply-broadcast-burn
  "Enforces a mandatory signaling burn (>= burn/min-signaling-burn) on every broadcast.
   Deducts burn from sender's ledger account and updates epoch-burns.
   Returns {:state updated-state :burn-amount burn-amt} or nil if deduction failed or burn invalid."
  [state event current-epoch]
  (let [burn-spec (if (contains? event :burn)
                    (:burn event)
                    (:signaling-burn event))
        burn-amt (cond
                   (number? burn-spec) (when (>= burn-spec burn/min-signaling-burn) burn-spec)
                   (false? burn-spec) nil
                   :else burn/min-signaling-burn)]
    (when burn-amt
      (let [sender (or (:sender event)
                       (when-let [pk (:public-key event)]
                         (if (string? pk) pk (basalt/bytes->hex pk)))
                       (:node-pubkey state))]
        (when-let [res (burn/deduct-signaling-burn (:ledger state) sender burn-amt)]
          {:state (-> state
                      (assoc :ledger (:ledger res))
                      (update-in [:epoch-burns current-epoch] (fnil + 0) (:burn-amount res)))
           :burn-amount (:burn-amount res)})))))

(defn- handle-broadcast
  "Handles an internal request to broadcast a payload.
   Deducts mandatory signaling burn; drops broadcast if burn deduction fails."
  [state event]
  (let [current-epoch (or (:epoch state) 0)
        burn-spec (if (contains? event :burn) (:burn event) (:signaling-burn event))
        burn-amt (cond
                   (number? burn-spec) (when (>= burn-spec burn/min-signaling-burn) burn-spec)
                   (false? burn-spec) nil
                   :else burn/min-signaling-burn)
        sender (or (:sender event)
                   (when-let [pk (:public-key event)]
                     (if (string? pk) pk (basalt/bytes->hex pk)))
                   (:node-pubkey state))
        sender-hex (when sender (if (string? sender) sender (basalt/bytes->hex sender)))]
    (if (consensus-mode? state)
      (if (and burn-amt
               sender-hex
               (get-in state [:ledger sender-hex])
               (>= (spendable-balance state sender-hex) burn-amt))
        (let [cfg (:config state)
              murmur-k (:murmur-k cfg)
              murmur-max-cache-size (:murmur-max-cache-size cfg)
              payload (:payload event)
              rng (:rng event)
              extracted-peers (exclude-self-peers state (basalt/extract-peers (:basalt-view state)))
              sieve-message (if (and (:private-key event) (:public-key event))
                              (sieve/wrap-message payload (:private-key event) (:public-key event) burn-amt)
                              {:payload payload :sender "local" :signature (byte-array 0) :burn-amount burn-amt})
              broadcast-result (murmur/initiate-broadcast payload rng extracted-peers murmur-k)
              message-id (:message-id broadcast-result)
              message (assoc sieve-message :message-id message-id :burn-amount burn-amt)
              staged (stage-receipt state {:receipt-id (str "gossip-burn:" message-id)
                                           :type :burn
                                           :sender sender-hex
                                           :amount burn-amt})]
          (if (:ok? staged)
            (let [staged-state (:state staged)
                  commands (if (seq (:targets broadcast-result))
                             [{:type :send-gossip
                               :targets (:targets broadcast-result)
                               :message message}]
                             [])
                  new-cache-set (conj (:set (:murmur-cache staged-state)) message-id)
                  new-cache-queue (conj (:queue (:murmur-cache staged-state)) message-id)
                  new-cache-queue-evicted (if (> (count new-cache-queue) murmur-max-cache-size)
                                            (pop new-cache-queue)
                                            new-cache-queue)
                  new-cache-set-evicted (if (> (count new-cache-queue) murmur-max-cache-size)
                                          (disj new-cache-set (peek new-cache-queue))
                                          new-cache-set)
                  new-cache {:set new-cache-set-evicted :queue new-cache-queue-evicted}
                  new-known-ids (conj (:contagion-known-ids staged-state) message-id)
                  new-messages (assoc (:messages staged-state) message-id message)
                  new-epochs (assoc (or (:message-epochs staged-state) {}) message-id current-epoch)
                  new-epoch-to-messages (update (or (:epoch-to-messages staged-state) {})
                                                current-epoch (fnil conj #{}) message-id)
                  new-epoch-to-roles (assoc-in (or (:epoch-to-message-roles staged-state) {})
                                               [current-epoch message-id] :gossip)]
              {:state (assoc staged-state
                             :murmur-cache new-cache
                             :contagion-known-ids new-known-ids
                             :messages new-messages
                             :message-epochs new-epochs
                             :epoch-to-messages new-epoch-to-messages
                             :epoch-to-message-roles new-epoch-to-roles)
               :commands commands})
            {:state state :commands []}))
        {:state state :commands []})
      ;; Non-consensus standalone mode
      (if-let [burn-res (apply-broadcast-burn state event current-epoch)]
        (let [state (:state burn-res)
              burn-amt (:burn-amount burn-res)
              cfg (:config state)
              murmur-k (:murmur-k cfg)
              murmur-max-cache-size (:murmur-max-cache-size cfg)
              payload (:payload event)
              rng (:rng event)
              extracted-peers (exclude-self-peers state (basalt/extract-peers (:basalt-view state)))
              sieve-message (if (and (:private-key event) (:public-key event))
                              (sieve/wrap-message payload (:private-key event) (:public-key event) burn-amt)
                              {:payload payload :sender "local" :signature (byte-array 0) :burn-amount burn-amt})
              broadcast-result (murmur/initiate-broadcast payload rng extracted-peers murmur-k)
              message-id (:message-id broadcast-result)
              message (assoc sieve-message :message-id message-id :burn-amount burn-amt)
              commands (if (seq (:targets broadcast-result))
                         [{:type :send-gossip
                           :targets (:targets broadcast-result)
                           :message message}]
                         [])
              new-cache-set (conj (:set (:murmur-cache state)) message-id)
              new-cache-queue (conj (:queue (:murmur-cache state)) message-id)
              new-cache-queue-evicted (if (> (count new-cache-queue) murmur-max-cache-size)
                                        (pop new-cache-queue)
                                        new-cache-queue)
              new-cache-set-evicted (if (> (count new-cache-queue) murmur-max-cache-size)
                                      (disj new-cache-set (peek new-cache-queue))
                                      new-cache-set)
              new-cache {:set new-cache-set-evicted :queue new-cache-queue-evicted}
              new-known-ids (conj (:contagion-known-ids state) message-id)
              new-messages (assoc (:messages state) message-id message)
              new-epochs (assoc (or (:message-epochs state) {}) message-id current-epoch)
              new-epoch-to-messages (update (or (:epoch-to-messages state) {})
                                            current-epoch (fnil conj #{}) message-id)
              new-epoch-to-roles (assoc-in (or (:epoch-to-message-roles state) {})
                                           [current-epoch message-id] :gossip)]
          {:state (assoc state
                         :murmur-cache new-cache
                         :contagion-known-ids new-known-ids
                         :messages new-messages
                         :message-epochs new-epochs
                         :epoch-to-messages new-epoch-to-messages
                         :epoch-to-message-roles new-epoch-to-roles)
           :commands commands})
        {:state state :commands []}))))

(declare handle-event)

(defn- handle-contagion-broadcast
  "Handles an internal request to broadcast a payload, specifically emitting :on-deliver for simulator E2E."
  [state event]
  (let [{new-state :state commands :commands} (handle-broadcast state (assoc event :type :broadcast))
        ;; Find the message-id just created (last added to known-ids)
        message-id (first (set/difference (:contagion-known-ids new-state)
                                          (:contagion-known-ids state)))]
    (if message-id
      (let [delivery-result (handle-event new-state {:type :on-deliver
                                                     :payload (:payload event)
                                                     :message-id message-id})]
        {:state (:state delivery-result)
         :commands (into commands (:commands delivery-result))})
      {:state state :commands []})))

(defn- handle-receive-push-view
  "Handles an incoming Basalt view exchange."
  [state event]
  (let [clean-view (sanitize-basalt-view state (:basalt-view state))
        received-peers (exclude-self-peers state (:view event))
        new-view (sanitize-basalt-view state (basalt/update-view clean-view received-peers))]
    {:state (assoc state :basalt-view new-view)
     :commands []}))

(defn- handle-receive-summary
  "Handles an incoming Contagion anti-entropy summary."
  [state event]
  (let [remote-summary (:summary event)
        known-ids (set/union (:contagion-known-ids state) (get-in state [:murmur-cache :set] #{}))
        missing-ids (contagion/lazy-pull known-ids remote-summary)
        commands (if (seq missing-ids)
                   [{:type :send-pull-request
                     :target (:sender event)
                     :missing-ids missing-ids}]
                   [])]
    {:state state
     :commands commands}))

(defn- handle-receive-subscribe
  "Handles an incoming subscription request from a peer.
   Adds the peer to the corresponding subscriber sets."
  [state event]
  (let [sender (:sender event)
        roles (:roles event)
        new-echo-subscribers (if (contains? roles :echo)
                               (conj (:echo-subscribers state) sender)
                               (:echo-subscribers state))
        new-ready-subscribers (if (contains? roles :ready)
                                (conj (:ready-subscribers state) sender)
                                (:ready-subscribers state))
        new-delivery-subscribers (if (contains? roles :delivery)
                                   (conj (:delivery-subscribers state) sender)
                                   (:delivery-subscribers state))]
    {:state (assoc state
                   :echo-subscribers new-echo-subscribers
                   :ready-subscribers new-ready-subscribers
                   :delivery-subscribers new-delivery-subscribers)
     :commands []}))

(defn- handle-receive-pull-request
  "Handles an incoming Contagion lazy pull request.
   Looks up requested IDs in the local message store and returns
   individual :send-gossip commands targeting the requester for each found message."
  [state event]
  (let [missing-ids (:missing-ids event)
        requester (:sender event)
        messages-map (:messages state)
        found-messages (keep #(get messages-map %) missing-ids)
        commands (map (fn [msg]
                        {:type :send-gossip
                         :target requester
                         :message msg})
                      found-messages)]
    {:state state
     :commands (vec commands)}))

(defn- record-accepted-gossip
  "Constructs updated state and outgoing commands for an accepted gossip message."
  [state message gossip-result new-message? current-epoch]
  (let [gossip-commands (if (seq (:forward-targets gossip-result))
                          [{:type :send-gossip
                            :targets (:forward-targets gossip-result)
                            :message (:message gossip-result)}]
                          [])
        message-id (:message-id message)
        sieve-targets (:echo-subscribers state)
        sieve-echo-command (when (and new-message? (seq sieve-targets))
                             (attach-control-frame-signature
                              state
                              {:type :send-sieve-echo
                               :targets sieve-targets
                               :message-id message-id}
                              :sieve-echo
                              message-id))
        commands (if new-message?
                   (filterv some? (into gossip-commands [sieve-echo-command]))
                   gossip-commands)
        new-known-ids (if new-message?
                        (conj (:contagion-known-ids state) message-id)
                        (:contagion-known-ids state))
        new-messages (if new-message?
                       (assoc (:messages state) message-id message)
                       (:messages state))
        new-epochs (if new-message?
                     (assoc (or (:message-epochs state) {}) message-id current-epoch)
                     (:message-epochs state))
        new-epoch-to-messages (if new-message?
                                (update (or (:epoch-to-messages state) {})
                                        current-epoch (fnil conj #{}) message-id)
                                (or (:epoch-to-messages state) {}))
        new-epoch-to-roles (if new-message?
                             (assoc-in (or (:epoch-to-message-roles state) {})
                                       [current-epoch message-id] :gossip)
                             (or (:epoch-to-message-roles state) {}))]
    {:state (assoc state
                   :murmur-cache (:cache gossip-result)
                   :contagion-known-ids new-known-ids
                   :messages new-messages
                   :message-epochs new-epochs
                   :epoch-to-messages new-epoch-to-messages
                   :epoch-to-message-roles new-epoch-to-roles)
     :commands commands}))

(defn- handle-receive-gossip
  "Handles an incoming Murmur gossip message.
   Validates Sieve signature and burn-amount before accepting into the cache.
   If new, initializes Sieve and Contagion sampling and deducts burn from funded sender."
  [state event]
  (let [cfg (:config state)
        murmur-k (:murmur-k cfg)
        murmur-max-cache-size (:murmur-max-cache-size cfg)
        raw-message (:message event)
        payload (when (map? raw-message) (:payload raw-message))
        msg-id (when (bytes? payload)
                 (basalt/bytes->hex (crypto/sha256 payload)))
        message (when msg-id (assoc raw-message :message-id msg-id))
        rng (:rng event)
        burn-amt (:burn-amount message)
        valid-burn? (and (number? burn-amt) (>= burn-amt burn/min-signaling-burn))
        valid-signature? (when (and valid-burn? message) (sieve/validate-message message))]
    (if (and (some? msg-id) valid-burn? valid-signature?)
      (let [non-self-peers (exclude-self-peers state (basalt/extract-peers (:basalt-view state)))
            hop-sender-hex (peer-pubkey-hex (:sender event))
            non-sender-peers (if hop-sender-hex
                               (filterv #(not= (peer-pubkey-hex %) hop-sender-hex) non-self-peers)
                               non-self-peers)
            extracted-peers (if (seq non-sender-peers) non-sender-peers non-self-peers)
            gossip-result (murmur/receive-gossip (:murmur-cache state) message rng extracted-peers murmur-k murmur-max-cache-size)
            new-message? (some? (:message gossip-result))
            sender (when-let [s (:sender message)] (if (string? s) s (basalt/bytes->hex s)))
            node-pk (when-let [np (:node-pubkey state)] (if (string? np) np (basalt/bytes->hex np)))
            current-epoch (or (:epoch state) 0)]
        (if (consensus-mode? state)
          (if new-message?
            (if (and (not= sender node-pk) sender)
              (if (and (get-in state [:ledger sender])
                       (>= (spendable-balance state sender) burn-amt))
                (let [staged (stage-receipt state {:receipt-id (str "gossip-burn:" msg-id)
                                                   :type :burn
                                                   :sender sender
                                                   :amount burn-amt})]
                  (if (:ok? staged)
                    (record-accepted-gossip (:state staged) message gossip-result new-message? current-epoch)
                    {:state state :commands []}))
                {:state state :commands []})
              (let [staged (stage-receipt state {:receipt-id (str "gossip-burn:" msg-id)
                                                 :type :burn
                                                 :sender sender
                                                 :amount burn-amt})]
                (if (:ok? staged)
                  (record-accepted-gossip (:state staged) message gossip-result new-message? current-epoch)
                  {:state state :commands []})))
            (record-accepted-gossip state message gossip-result new-message? current-epoch))
          ;; Standalone non-consensus mode
          (let [burn-deduction (when (and new-message? (not= sender node-pk) sender)
                                 (burn/deduct-signaling-burn (:ledger state) sender burn-amt))]
            (if (and new-message? (not= sender node-pk) (nil? burn-deduction))
              {:state state :commands []}
              (let [state-with-burn (if burn-deduction
                                      (-> state
                                          (assoc :ledger (:ledger burn-deduction))
                                          (update-in [:epoch-burns current-epoch] (fnil + 0) burn-amt))
                                      state)]
                (record-accepted-gossip state-with-burn message gossip-result new-message? current-epoch))))))
      {:state state :commands []})))

(defn- transition-to-ready
  "Transitions node to Ready for message-id and emits signed :send-contagion-ready."
  [state message-id]
  (if-not (contains? (:local-ready-set state) message-id)
    (let [ready-targets (set/union (:ready-subscribers state) (:delivery-subscribers state))
          cmd (when (seq ready-targets)
                (attach-control-frame-signature
                 state
                 {:type :send-contagion-ready
                  :targets ready-targets
                  :message-id message-id}
                 :contagion-ready
                 message-id))]
      {:state (update state :local-ready-set conj message-id)
       :commands (filterv some? [cmd])})
    {:state state :commands []}))

(defn- handle-receive-sieve-echo
  "Handles an incoming Sieve Echo message.
   Validates control frame signature before recording vote.
   Uses integer vote counters instead of set intersection for threshold checks.
   If E-hat is reached, transitions to Sieve-Delivered and broadcasts Contagion Ready."
  [state event]
  (let [cfg (:config state)
        require-signed? (get cfg :require-signed-control-frames true)
        valid-frame? (sieve/validate-control-frame event :sieve-echo require-signed?)]
    (if-not valid-frame?
      {:state state :commands []}
      (let [E-hat (:echo-threshold cfg)
            sender (:sender event)
            message-id (:message-id event)
            echo-sample (:global-echo-sample state)
            received-echoes (get (:received-echoes state) message-id #{})
            sieve-delivered-set (:sieve-delivered-set state)]
        (if (and (contains? echo-sample sender)
                 (not (contains? received-echoes sender)))
          (let [current-epoch (or (:epoch state) 0)
                new-received-echoes (conj received-echoes sender)
                old-count (get-in state [:echo-vote-counts message-id] 0)
                new-count (inc old-count)
                state-with-echo (-> state
                                    (assoc-in [:received-echoes message-id] new-received-echoes)
                                    (assoc-in [:echo-vote-counts message-id] new-count)
                                    (assoc-in [:epoch-to-message-roles current-epoch message-id] :echo))]
            (if (and (>= new-count E-hat)
                     (not (contains? sieve-delivered-set message-id)))
              (let [state-sieve-delivered (update state-with-echo :sieve-delivered-set conj message-id)]
                (transition-to-ready state-sieve-delivered message-id))
              {:state state-with-echo :commands []}))
          {:state state :commands []})))))

(defn- apply-transfer-payload-to-ledger
  "Deserializes a transfer from payload-bytes and applies it to ledger if valid.
   Returns the updated ledger map, or nil if invalid/failed."
  [ledger payload-bytes]
  (try
    (let [payload-str (String. ^bytes payload-bytes "UTF-8")
          payload-edn (edn/read-string {:default tagged-literal
                                        :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                  'bitecho.economy.account.AccountState account/map->AccountState}} payload-str)
          transfer-map (cond
                         (and (map? payload-edn) (:transfer payload-edn)) (:transfer payload-edn)
                         (instance? bitecho.economy.account.Transfer payload-edn) payload-edn
                         :else nil)]
      (if transfer-map
        (let [transfer-map (if (instance? clojure.lang.TaggedLiteral transfer-map)
                             (:form transfer-map)
                             (into {} transfer-map))
              sig (cond
                    (vector? (:signature transfer-map)) (byte-array (map byte (:signature transfer-map)))
                    (string? (:signature transfer-map)) (.getBytes ^String (:signature transfer-map) "UTF-8")
                    (and (seqable? (:signature transfer-map)) (every? number? (:signature transfer-map))) (byte-array (map byte (:signature transfer-map)))
                    (bytes? (:signature transfer-map)) (:signature transfer-map)
                    :else (byte-array 0))
              transfer-map (assoc transfer-map :signature sig)
              transfer (account/map->Transfer transfer-map)
              sender (:sender transfer)
              sender-state (get ledger sender)]
          (if (and sender-state (account/validate-transfer sender-state transfer))
            (let [ledger-with-receiver (if (and (:receiver transfer) (not (contains? ledger (:receiver transfer))))
                                         (assoc ledger (:receiver transfer) (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                                         ledger)]
              (account/apply-transfer ledger-with-receiver transfer))
            nil))
        nil))
    (catch Exception _
      nil)))

(defn- apply-payload-to-ledger
  "Attempts to parse a payload and apply any transfer to the ledger.
   Returns the updated state if successful, or the original state on failure."
  [state payload-bytes]
  (if-let [new-ledger (apply-transfer-payload-to-ledger (:ledger state) payload-bytes)]
    (assoc state :ledger new-ledger)
    state))

(defn- projected-ledger
  "Projects pending receipts (:burn, :settle-intent, :transfer) onto (:ledger state)
   so sequential pipelined transactions validate against uncommitted sender state."
  [state]
  (let [base-ledger (or (:ledger state) {})
        pending (or (:pending-receipts state) [])]
    (reduce
     (fn [ledger r]
       (case (:type r)
         :burn
         (let [sender (:sender r)
               amt (:amount r)
               sender-hex (when sender (if (string? sender) sender (basalt/bytes->hex sender)))]
           (if-let [res (when (and sender-hex amt) (burn/deduct-signaling-burn ledger sender-hex amt))]
             (:ledger res)
             ledger))

         :settle-intent
         (let [payer (:payer r)
               receiver (:receiver r)
               amount (:amount r)
               payer-hex (when payer (if (string? payer) payer (basalt/bytes->hex payer)))
               receiver-hex (when receiver (if (string? receiver) receiver (basalt/bytes->hex receiver)))
               payer-acct (when payer-hex (get ledger payer-hex))
               payer-bal (or (:balance payer-acct) 0)]
           (if (and payer-hex receiver-hex (integer? amount) (pos? amount) payer-acct (>= payer-bal amount))
             (let [configured-bps (or (:settlement-take-bps state)
                                      (get-in state [:config :settlement-take-bps])
                                      burn/default-settlement-take-bps)
                   take-bps (max 1 configured-bps)
                   take-amt (burn/calculate-settlement-take amount take-bps)
                   net-amt (- amount take-amt)
                   receiver-acct (get ledger receiver-hex (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                   new-payer (assoc payer-acct :balance (- payer-bal amount))
                   new-receiver (assoc receiver-acct :balance (+ (or (:balance receiver-acct) 0) net-amt))]
               (assoc ledger payer-hex new-payer receiver-hex new-receiver))
             ledger))

         :transfer
         (if-let [pb (:payload-bytes r)]
           (if-let [new-ledger (apply-transfer-payload-to-ledger ledger (byte-array (map byte pb)))]
             new-ledger
             ledger)
           ledger)

         ledger))
     base-ledger
     pending)))

(defn- canonical-unexecuted-finalized-chain
  "Walks the canonical ancestor chain from :latest-finalized-block-hash backwards via :parent-hash,
   stopping at genesis or an executed finalized block.
   Returns unexecuted canonical blocks in oldest-first order."
  [state]
  (let [latest-hash (:latest-finalized-block-hash state)
        executed-hashes (or (:executed-finalized-blocks state) #{})
        blocks (or (:blocks state) {})
        genesis-equiv? (fn [h]
                         (or (nil? h)
                             (= h "genesis")
                             (= h "0000000000000000000000000000000000000000000000000000000000000000")))
        valid-root? (fn [h]
                      (or (genesis-equiv? h)
                          (contains? executed-hashes h)))
        walk-rooted-chain (fn [start-hash]
                            (loop [curr start-hash
                                   visited #{}
                                   acc ()]
                              (cond
                                (valid-root? curr)
                                (vec acc)

                                (contains? visited curr)
                                []

                                :else
                                (if-let [b (get blocks curr)]
                                  (recur (:parent-hash b)
                                         (conj visited curr)
                                         (cons (assoc b :hash curr) acc))
                                  []))))]
    (if (and latest-hash (get blocks latest-hash))
      (walk-rooted-chain latest-hash)
      ;; Fallback if :latest-finalized-block-hash not set or not in :blocks
      (let [pending-hashes (set/difference (or (:finalized-blocks state) #{}) executed-hashes)]
        (->> pending-hashes
             (keep (fn [h]
                     (when (seq (walk-rooted-chain h))
                       (when-let [b (get blocks h)]
                         (assoc b :hash h)))))
             (sort-by (juxt (comp long :epoch) :hash))
             vec)))))

(defn execute-finalized-blocks
  "Executes finalized Streamlet blocks along the canonical chain in ascending order.
   Applies receipts, advances epoch vouchers, and executes treasury boundaries."
  [state]
  (let [unexecuted-blocks (canonical-unexecuted-finalized-chain state)
        max-tracked (long (or (get-in state [:config :max-tracked-receipts]) 10000))]
    (reduce
     (fn [st b]
       (let [b-hash (:hash b)
             b-epoch (long (:epoch b))
             last-exec (long (or (:last-executed-finalized-epoch st) 0))
             closing-ep (max 0 (dec b-epoch))
             st-skipped (if (> b-epoch last-exec)
                          (reduce (fn [s ep]
                                    (let [s-v (apply-epoch-voucher-settlement s (dec ep))]
                                      (apply-epoch-treasury-boundary s-v ep)))
                                  st
                                  (range (inc last-exec) b-epoch))
                          st)
             payload (:payload b)
             receipts (filter #(and (map? %) (:receipt-id %)) (when (sequential? payload) payload))
             st-applied (reduce
                         (fn [s r]
                           (let [rid (:receipt-id r)]
                             (if (contains? (or (:executed-receipt-ids s) #{}) rid)
                               s
                               (let [s-effect
                                     (case (:type r)
                                       :burn
                                       (let [sender (:sender r)
                                             amt (:amount r)
                                             sender-hex (when sender (if (string? sender) sender (basalt/bytes->hex sender)))]
                                         (if-let [res (when (and sender-hex amt) (burn/deduct-signaling-burn (:ledger s) sender-hex amt))]
                                           (-> s
                                               (assoc :ledger (:ledger res))
                                               (update-in [:epoch-burns closing-ep] (fnil + 0) (:burn-amount res)))
                                           (update s :failed-receipts-count (fnil inc 0))))

                                       :transfer
                                       (if-let [pb (:payload-bytes r)]
                                         (if-let [new-ledger (apply-transfer-payload-to-ledger (:ledger s) (byte-array (map byte pb)))]
                                           (assoc s :ledger new-ledger)
                                           (update s :failed-receipts-count (fnil inc 0)))
                                         (update s :failed-receipts-count (fnil inc 0)))

                                       :settle-intent
                                       (let [payer (:payer r)
                                             receiver (:receiver r)
                                             amount (:amount r)
                                             payer-hex (when payer (if (string? payer) payer (basalt/bytes->hex payer)))
                                             receiver-hex (when receiver (if (string? receiver) receiver (basalt/bytes->hex receiver)))
                                             payer-acct (when payer-hex (get-in s [:ledger payer-hex]))
                                             payer-bal (or (:balance payer-acct) 0)]
                                         (if (and payer-hex receiver-hex (integer? amount) (pos? amount) payer-acct (>= payer-bal amount))
                                           (let [configured-bps (or (:settlement-take-bps s)
                                                                    (get-in s [:config :settlement-take-bps])
                                                                    burn/default-settlement-take-bps)
                                                 take-bps (max 1 configured-bps)
                                                 take-amt (burn/calculate-settlement-take amount take-bps)
                                                 net-amt (- amount take-amt)
                                                 receiver-acct (get-in s [:ledger receiver-hex]
                                                                       (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                                                 new-payer (assoc payer-acct :balance (- payer-bal amount))
                                                 new-receiver (assoc receiver-acct :balance (+ (or (:balance receiver-acct) 0) net-amt))
                                                 new-ledger (assoc (:ledger s)
                                                                   payer-hex new-payer
                                                                   receiver-hex new-receiver)]
                                             (-> s
                                                 (assoc :ledger new-ledger)
                                                 (update-in [:epoch-settlement-takes closing-ep] (fnil + 0) take-amt)))
                                           (update s :failed-receipts-count (fnil inc 0))))

                                       :lock-intent
                                       (let [escrow-id (:escrow-id r)
                                             payer (:payer r)
                                             receiver (:receiver r)
                                             amount (if (integer? (:amount r)) (long (:amount r)) 0)
                                             deliverable-hash (:deliverable-hash r)
                                             created-epoch (if (integer? (:created-epoch r)) (long (:created-epoch r)) closing-ep)
                                             expires-epoch (if (integer? (:expires-epoch r)) (long (:expires-epoch r)) 0)
                                             payer-hex (when payer (if (string? payer) payer (basalt/bytes->hex payer)))
                                             receiver-hex (when receiver (if (string? receiver) receiver (basalt/bytes->hex receiver)))
                                             payer-acct (when payer-hex (get-in s [:ledger payer-hex]))
                                             payer-bal (or (:balance payer-acct) 0)
                                             already-exists? (or (contains? (or (:escrows s) #{}) escrow-id)
                                                                 (contains? (or (:settled-escrow-ids s) #{}) escrow-id))]
                                         (if (and (string? escrow-id)
                                                  (not (string/blank? escrow-id))
                                                  (not already-exists?)
                                                  payer-hex receiver-hex (not= payer-hex receiver-hex)
                                                  (pos? amount)
                                                  (escrow/valid-deliverable-hash? deliverable-hash)
                                                  (integer? (:expires-epoch r))
                                                  (> expires-epoch created-epoch)
                                                  (>= created-epoch (- closing-ep 168))
                                                  (<= (- expires-epoch created-epoch) 168)
                                                  payer-acct (>= payer-bal amount))
                                           (let [new-payer (assoc payer-acct :balance (- payer-bal amount))
                                                 escrow-entry {:escrow-id escrow-id
                                                               :payer payer-hex
                                                               :receiver receiver-hex
                                                               :amount amount
                                                               :deliverable-hash (escrow/normalize-hex deliverable-hash)
                                                               :created-epoch created-epoch
                                                               :expires-epoch expires-epoch
                                                               :status :locked}]
                                             (-> s
                                                 (assoc-in [:ledger payer-hex] new-payer)
                                                 (assoc-in [:escrows escrow-id] escrow-entry)))
                                           (update s :failed-receipts-count (fnil inc 0))))

                                       :release-intent
                                       (let [escrow-id (:escrow-id r)
                                             escrow (get-in s [:escrows escrow-id])
                                             preimage (:preimage r)
                                             payer-sig (:payer-signature r)
                                             sender (:sender r)
                                             sender-hex (when sender (if (string? sender) sender (basalt/bytes->hex sender)))
                                             configured-bps (or (:settlement-take-bps s)
                                                                (get-in s [:config :settlement-take-bps])
                                                                burn/default-settlement-take-bps)]
                                         (if (and escrow (= :locked (:status escrow)))
                                           (let [payer (:payer escrow)
                                                 receiver (:receiver escrow)
                                                 d-hash (:deliverable-hash escrow)
                                                 expires-epoch (long (or (:expires-epoch escrow) 0))
                                                 amount (long (:amount escrow))
                                                 payer-auth? (or (= sender-hex payer)
                                                                 (and (string? payer-sig)
                                                                      (escrow/verify-escrow-release-sig payer escrow-id d-hash payer-sig)))
                                                 preimage-auth? (and (string? preimage)
                                                                     (escrow/verify-deliverable-preimage preimage d-hash)
                                                                     (<= closing-ep expires-epoch)
                                                                     (or (nil? sender-hex) (= sender-hex receiver) (= sender-hex payer)))]
                                             (if (or payer-auth? preimage-auth?)
                                               (let [take-amt (escrow/calculate-escrow-settlement-take amount configured-bps)
                                                     net-amt (- amount take-amt)
                                                     receiver-acct (get-in s [:ledger receiver]
                                                                           (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                                                     new-receiver (assoc receiver-acct :balance (+ (or (:balance receiver-acct) 0) net-amt))
                                                     updated-escrow (assoc escrow
                                                                           :status :released
                                                                           :settled-epoch closing-ep
                                                                           :take-amount take-amt
                                                                           :net-amount net-amt
                                                                           :settlement-mode (if payer-auth? :payer-authorized :preimage-verified))
                                                     [next-settled-ids next-settled-ord] (fifo-track (:settled-escrow-ids s)
                                                                                                     (:settled-escrow-order s)
                                                                                                     escrow-id
                                                                                                     max-tracked)]
                                                 (-> s
                                                     (assoc-in [:ledger receiver] new-receiver)
                                                     (assoc-in [:escrows escrow-id] updated-escrow)
                                                     (assoc :settled-escrow-ids next-settled-ids
                                                            :settled-escrow-order next-settled-ord)
                                                     (update-in [:epoch-settlement-takes closing-ep] (fnil + 0) take-amt)))
                                               (update s :failed-receipts-count (fnil inc 0))))
                                           (update s :failed-receipts-count (fnil inc 0))))

                                       :refund-intent
                                       (let [escrow-id (:escrow-id r)
                                             escrow (get-in s [:escrows escrow-id])
                                             sender (:sender r)
                                             sender-hex (when sender (if (string? sender) sender (basalt/bytes->hex sender)))]
                                         (if (and escrow (= :locked (:status escrow)))
                                           (let [payer (:payer escrow)
                                                 receiver (:receiver escrow)
                                                 expires-epoch (long (or (:expires-epoch escrow) 0))
                                                 amount (long (:amount escrow))
                                                 timeout? (and (> closing-ep expires-epoch)
                                                               (or (nil? sender-hex) (contains? #{payer receiver} sender-hex)))
                                                 receiver-voluntary? (= sender-hex receiver)]
                                             (if (or timeout? receiver-voluntary?)
                                               (let [payer-acct (get-in s [:ledger payer]
                                                                        (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                                                     new-payer (assoc payer-acct :balance (+ (or (:balance payer-acct) 0) amount))
                                                     updated-escrow (assoc escrow
                                                                           :status :refunded
                                                                           :settled-epoch closing-ep
                                                                           :refund-amount amount
                                                                           :refund-reason (if receiver-voluntary? :receiver-voluntary :timeout))
                                                     [next-settled-ids next-settled-ord] (fifo-track (:settled-escrow-ids s)
                                                                                                     (:settled-escrow-order s)
                                                                                                     escrow-id
                                                                                                     max-tracked)]
                                                 (-> s
                                                     (assoc-in [:ledger payer] new-payer)
                                                     (assoc-in [:escrows escrow-id] updated-escrow)
                                                     (assoc :settled-escrow-ids next-settled-ids
                                                            :settled-escrow-order next-settled-ord)))
                                               (update s :failed-receipts-count (fnil inc 0))))
                                           (update s :failed-receipts-count (fnil inc 0))))

                                       :register-home-set
                                       (let [tuple [(:callee r) (or (:epoch r) closing-ep)]
                                             cands (mapv (fn [c] (if (contains? c :node-id) (assoc c :node-id (rendezvous/normalize-home-node (:node-id c))) c)) (:candidates r))
                                             reg-res (rendezvous/register-home-set cands (:price r) (or (:price-max r) (:price r)))]
                                         (assoc-in s [:home-sets tuple] reg-res))

                                       :voucher
                                       (let [home-node (rendezvous/normalize-home-node (:home-node r))
                                             tuple [(:callee r) home-node (:epoch r)]
                                             raw (:ack r)
                                             raw-ack (when raw
                                                       (if (instance? bitecho.rendezvous.core.DeliveryAck raw)
                                                         raw
                                                         (try (rendezvous/map->DeliveryAck raw)
                                                              (catch Exception _ nil))))
                                             ack (when raw-ack
                                                   (if (contains? raw-ack :home-node)
                                                     (assoc raw-ack :home-node (rendezvous/normalize-home-node (:home-node raw-ack)))
                                                     raw-ack))
                                             home-set (get-in s [:home-sets [(:callee r) (:epoch r)]])
                                             price (:price home-set)
                                             seq-val (long (or (:seq ack) (:seq r) 0))
                                             debit (long (or (:cumulative-debit ack) (:cumulative-debit r) 0))
                                             prev-seq (long (get-in s [:voucher-seqs tuple] 0))]
                                         (if (and ack
                                                  (rendezvous/verify-delivery-ack ack)
                                                  (some? home-set)
                                                  (not= :rejected (:status home-set))
                                                  (node-in-home-set? home-node home-set)
                                                  (integer? price)
                                                  (not (neg? (long price)))
                                                  (= debit (* seq-val (long price)))
                                                  (> seq-val prev-seq))
                                           (-> s
                                               (assoc-in [:voucher-seqs tuple] seq-val)
                                               (update :pending-vouchers (fnil conj []) ack))
                                           (update s :failed-receipts-count (fnil inc 0))))

                                       :transcript
                                       (let [raw-tx (:transcript r)
                                             tx (if (instance? bitecho.economy.attestation.EpochTranscript raw-tx)
                                                  raw-tx
                                                  (try (attestation/map->EpochTranscript raw-tx) (catch Exception _ nil)))
                                             ep (long (or (when tx (:epoch tx)) (:epoch r) 0))
                                             pa (when tx (:peer-a tx))
                                             pb (when tx (:peer-b tx))
                                             valid-shape? (and (string? pa)
                                                               (string? pb)
                                                               (not= pa pb)
                                                               (seq (:message-roles tx)))
                                             p1 (when (and pa pb) (first (sort [pa pb])))
                                             p2 (when (and pa pb) (second (sort [pa pb])))
                                             pair-tuple (when (and p1 p2) [ep p1 p2])]
                                         (cond
                                           (or (nil? tx) (not valid-shape?))
                                           (update s :failed-receipts-count (fnil inc 0))

                                           (contains? (or (:settled-transcript-pairs s) #{}) pair-tuple)
                                           s

                                           (attestation/mutually-signed? tx)
                                           (let [credited #{pa pb}
                                                 role-cnt (count (:message-roles tx))]
                                             (-> s
                                                 (update :settled-transcript-pairs (fnil conj #{}) pair-tuple)
                                                 (update-attested-mesh-weights ep credited role-cnt)))

                                           (attestation/half-signed? tx)
                                           (let [prover-log (:prover-frozen-log r)
                                                 cp-log (:counterparty-frozen-log r)
                                                 prover-ok? (boolean
                                                             (and prover-log
                                                                  (attestation/verify-frozen-log prover-log)
                                                                  (= ep (:epoch prover-log))
                                                                  (= pa (:peer prover-log))))
                                                 cp-ok? (if cp-log
                                                          (boolean
                                                           (and (attestation/verify-frozen-log cp-log)
                                                                (= ep (:epoch cp-log))
                                                                (= pb (:peer cp-log))))
                                                          true)
                                                 valid-proofs? (and prover-ok? cp-ok?)]
                                             (if-not valid-proofs?
                                               (update s :failed-receipts-count (fnil inc 0))
                                               (let [ids-a (set (:frozen-ids prover-log))
                                                     ids-b (if cp-log (set (:frozen-ids cp-log)) ids-a)
                                                     reconciled (attestation/reconcile-message-roles ids-a ids-b (:message-roles tx))
                                                     tx-valid? (attestation/verify-transcript-against-log tx reconciled)]
                                                 (if tx-valid?
                                                   (let [credited #{pa}
                                                         strike-peer pb
                                                         role-cnt (count (:message-roles tx))]
                                                     (-> s
                                                         (update :settled-transcript-pairs (fnil conj #{}) pair-tuple)
                                                         (update-in [:fault-strikes strike-peer] (fnil inc 0))
                                                         (update-attested-mesh-weights ep credited role-cnt)))
                                                   (update s :failed-receipts-count (fnil inc 0))))))

                                           :else
                                           (update s :failed-receipts-count (fnil inc 0))))

                                       s)
                                     [next-exec next-exec-ord] (fifo-track (:executed-receipt-ids s-effect)
                                                                           (:executed-receipt-order s-effect)
                                                                           rid
                                                                           max-tracked)
                                     [next-known next-known-ord] (fifo-track (:known-receipt-ids s-effect)
                                                                             (:known-receipt-order s-effect)
                                                                             rid
                                                                             max-tracked)]
                                 (assoc s-effect
                                        :executed-receipt-ids next-exec
                                        :executed-receipt-order next-exec-ord
                                        :known-receipt-ids next-known
                                        :known-receipt-order next-known-ord)))))
                         st-skipped
                         receipts)
             exec-rids (or (:executed-receipt-ids st-applied) #{})
             st-clean (assoc st-applied
                             :pending-receipts (filterv #(not (contains? exec-rids (:receipt-id %)))
                                                        (or (:pending-receipts st-applied) []))
                             :mempool (filterv #(if (and (map? %) (:receipt-id %))
                                                  (not (contains? exec-rids (:receipt-id %)))
                                                  true)
                                               (or (:mempool st-applied) [])))
             st-advanced (if (> b-epoch last-exec)
                           (let [st-settled (apply-epoch-voucher-settlement st-clean closing-ep)
                                 st-treasury (apply-epoch-treasury-boundary st-settled b-epoch)]
                             (assoc st-treasury :last-executed-finalized-epoch b-epoch))
                           st-clean)
             [next-blocks next-blocks-ord] (fifo-track (:executed-finalized-blocks st-advanced)
                                                       (:executed-finalized-blocks-order st-advanced)
                                                       b-hash
                                                       max-tracked)]
         (assoc st-advanced
                :executed-finalized-blocks next-blocks
                :executed-finalized-blocks-order next-blocks-ord)))
     state
     unexecuted-blocks)))

(defn- check-contagion-delivery
  "Checks if D-hat is reached, transitioning to delivered and calling on-deliver."
  [state message-id delivery-votes D-hat]
  (if (and (>= delivery-votes D-hat)
           (not (contains? (:delivered-set state) message-id)))
    (let [state-delivered (update state :delivered-set conj message-id)
          message (get (:messages state) message-id)]
      (if message
        (handle-event state-delivered
                      {:type :on-deliver
                       :payload (:payload message)
                       :message-id message-id})
        {:state state-delivered :commands []}))
    {:state state :commands []}))

(defn- handle-receive-contagion-ready
  "Handles an incoming Contagion Ready message.
   Validates control frame signature before recording vote.
   Uses integer vote counters instead of set intersection for threshold checks.
   If R-hat is reached, transitions to Ready and broadcasts Contagion Ready.
   If D-hat is reached, transitions to Delivered and emits :on-deliver."
  [state event]
  (let [cfg (:config state)
        require-signed? (get cfg :require-signed-control-frames true)
        valid-frame? (sieve/validate-control-frame event :contagion-ready require-signed?)]
    (if-not valid-frame?
      {:state state :commands []}
      (let [R-hat (:ready-threshold cfg)
            D-hat (:delivery-threshold cfg)
            sender (:sender event)
            message-id (:message-id event)
            ready-sample (:global-ready-sample state)
            delivery-sample (:global-delivery-sample state)
            received-readies (get (:received-readies state) message-id #{})
            in-ready? (contains? ready-sample sender)
            in-delivery? (contains? delivery-sample sender)]
        (if (and (not (contains? received-readies sender))
                 (or in-ready? in-delivery?))
          (let [current-epoch (or (:epoch state) 0)
                new-readies (conj received-readies sender)
                new-r-votes (cond-> (get-in state [:ready-vote-counts message-id] 0)
                              in-ready? inc)
                new-d-votes (cond-> (get-in state [:delivery-vote-counts message-id] 0)
                              in-delivery? inc)
                state-with-ready (-> state
                                     (assoc-in [:received-readies message-id] new-readies)
                                     (assoc-in [:ready-vote-counts message-id] new-r-votes)
                                     (assoc-in [:delivery-vote-counts message-id] new-d-votes)
                                     (assoc-in [:epoch-to-message-roles current-epoch message-id] :ready))
                ready-res (if (>= new-r-votes R-hat)
                            (transition-to-ready state-with-ready message-id)
                            {:state state-with-ready :commands []})
                delivery-res (check-contagion-delivery (:state ready-res) message-id new-d-votes D-hat)]
            {:state (:state delivery-res)
             :commands (into (:commands ready-res) (:commands delivery-res))})
          {:state state :commands []})))))

(defn- handle-on-deliver
  "Handles the internal delivery event, updating the ledger with the payload and emitting an app-event."
  [state event]
  (let [p (:payload event)
        payload-bytes (cond
                        (bytes? p) p
                        (sequential? p) (byte-array (map byte p))
                        :else (byte-array 0))
        message-id (:message-id event)
        event-sender (:sender event)]
    (if (consensus-mode? state)
      (let [payload-str (try (String. ^bytes payload-bytes StandardCharsets/UTF_8) (catch Exception _ nil))
            payload-edn (try (when payload-str
                               (edn/read-string {:default tagged-literal
                                                 :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                           'bitecho.economy.account.AccountState account/map->AccountState}} payload-str))
                             (catch Exception _ nil))
            raw-transfer (when (and (map? payload-edn) (:transfer payload-edn))
                           (:transfer payload-edn))
            transfer-map (when raw-transfer
                           (let [m (if (instance? clojure.lang.TaggedLiteral raw-transfer)
                                     (:form raw-transfer)
                                     (into {} raw-transfer))
                                 sig (cond
                                       (vector? (:signature m)) (byte-array (map byte (:signature m)))
                                       (string? (:signature m)) (.getBytes ^String (:signature m) "UTF-8")
                                       (and (seqable? (:signature m)) (every? number? (:signature m))) (byte-array (map byte (:signature m)))
                                       (bytes? (:signature m)) (:signature m)
                                       :else (byte-array 0))]
                             (assoc m :signature sig)))
            transfer (when transfer-map (account/map->Transfer transfer-map))
            sender (when transfer (:sender transfer))
            sender-authorized? (or (nil? event-sender) (= sender event-sender))
            proj-ledger (projected-ledger state)
            sender-state (when (and sender proj-ledger) (get proj-ledger sender))
            valid-transfer? (and transfer
                                 sender-authorized?
                                 sender-state
                                 (account/validate-transfer sender-state transfer)
                                 (>= (spendable-balance state sender) (long (or (:amount transfer) 0))))
            state-staged (if valid-transfer?
                           (let [rid (str "transfer:" (or (account/transfer-hash transfer)
                                                          message-id
                                                          (basalt/bytes->hex (crypto/sha256 payload-bytes))))
                                 staged (stage-receipt state {:receipt-id rid
                                                              :type :transfer
                                                              :sender sender
                                                              :seq (:seq transfer)
                                                              :amount (:amount transfer)
                                                              :payload-bytes (vec payload-bytes)})]
                             (if (:ok? staged) (:state staged) state))
                           state)]
        {:state state-staged
         :commands [{:type :app-event :event-name :on-deliver
                     :payload (:payload event) :message-id message-id}]})
      (let [sender-authorized? (or (nil? event-sender)
                                   (let [payload-str (try (String. ^bytes payload-bytes StandardCharsets/UTF_8) (catch Exception _ nil))
                                         payload-edn (try (when payload-str
                                                            (edn/read-string {:default tagged-literal
                                                                              :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                                                        'bitecho.economy.account.AccountState account/map->AccountState}} payload-str))
                                                          (catch Exception _ nil))
                                         raw-transfer (when (and (map? payload-edn) (:transfer payload-edn))
                                                        (:transfer payload-edn))
                                         transfer-map (when raw-transfer
                                                        (if (instance? clojure.lang.TaggedLiteral raw-transfer)
                                                          (:form raw-transfer)
                                                          (into {} raw-transfer)))]
                                     (= (:sender transfer-map) event-sender)))
            state-with-applied-ledger (if sender-authorized?
                                        (apply-payload-to-ledger state payload-bytes)
                                        state)]
        {:state state-with-applied-ledger
         :commands [{:type :app-event :event-name :on-deliver
                     :payload (:payload event) :message-id message-id}]}))))

(defn- handle-signaling-burn
  "Handles a direct signaling burn event, deducting burn from the sender's account
   and incrementing the epoch's burn accumulator."
  [state event]
  (let [sender (:sender event)
        sender-hex (when sender (if (string? sender) sender (basalt/bytes->hex sender)))
        burn-amt (or (:burn event) (:burn-amount event) burn/min-signaling-burn)]
    (if (consensus-mode? state)
      (let [sender-acct (when sender-hex (get-in state [:ledger sender-hex]))]
        (if (and sender-hex
                 sender-acct
                 (number? burn-amt)
                 (>= burn-amt burn/min-signaling-burn)
                 (>= (spendable-balance state sender-hex) burn-amt))
          (let [rid (or (:receipt-id event)
                        (str "burn:" sender-hex ":" (or (:epoch state) 0) ":" (:receipt-seq state 0)))
                staged (stage-receipt state {:receipt-id rid :type :burn :sender sender-hex :amount burn-amt})]
            (if (:ok? staged)
              {:state (:state staged) :commands []}
              {:state state :commands []}))
          {:state state :commands []}))
      (let [ledger (or (:ledger state) {})
            res (when sender-hex (burn/deduct-signaling-burn ledger sender-hex burn-amt))]
        (if res
          (let [current-epoch (or (:epoch state) 0)]
            {:state (-> state
                        (assoc :ledger (:ledger res))
                        (update-in [:epoch-burns current-epoch] (fnil + 0) (:burn-amount res)))
             :commands []})
          {:state state :commands []})))))

(defn- handle-epoch-mint
  "Handles an authorized epoch mint event, applying demand-gated mint allocations."
  [state event]
  (let [new-state (treasury/apply-epoch-mint state event)]
    {:state new-state :commands []}))

(defn- derive-authoritative-roles
  "Derives authoritative message-role entries for dispute reconciliation.
   For each message ID in local-frozen-ids or local-frozen-roles-map, looks up
   the role in local-frozen-roles-map, defaulting to :gossip if unmapped."
  [local-frozen-ids local-frozen-roles-map]
  (let [candidate-ids (set/union (set local-frozen-ids) (set (keys local-frozen-roles-map)))]
    (attestation/canonicalize-message-roles
     (reduce (fn [acc mid]
               (conj acc [mid (get local-frozen-roles-map mid :gossip)]))
             []
             candidate-ids))))

(defn- resolve-counterparty-frozen-ids
  "Resolves counterparty frozen message IDs for transcript submission.
   Enforces cryptographic verification of :counterparty-frozen-log.
   Rejects submission if unauthenticated counterparty IDs are provided,
   or if the signed log is invalid / mismatched.
   Returns {:ok? true :ids ids} or {:ok? false}."
  [event transcript state]
  (let [has-raw? (or (contains? event :counterparty-frozen-ids)
                     (contains? event :peer-frozen-ids))
        epoch (:epoch transcript)
        node-pub (:node-pubkey state)
        pa (:peer-a transcript)
        pb (:peer-b transcript)
        expected-cp (if (= node-pub pb) pa pb)
        cp-log (or (:counterparty-frozen-log event)
                   (:peer-frozen-log event)
                   (get-in state [:peer-frozen-logs [epoch expected-cp]]))]
    (cond
      (and has-raw? (nil? cp-log))
      {:ok? false}

      (some? cp-log)
      (if (and (attestation/verify-frozen-log cp-log)
               (= epoch (:epoch cp-log))
               (if (contains? #{pa pb} node-pub)
                 (= expected-cp (:peer cp-log))
                 (contains? #{pa pb} (:peer cp-log))))
        {:ok? true :ids (set (:frozen-ids cp-log))}
        {:ok? false})

      :else
      {:ok? true :ids (or (get-in state [:frozen-epoch-messages epoch])
                          (get-in state [:epoch-to-messages epoch])
                          #{})})))

(defn- handle-submit-transcript
  "Handles bilateral transcript submission and dispute resolution.
   Evaluates the transcript against the frozen epoch message set,
   stages consensus receipt or updates standalone state and mesh weights."
  [state event]
  (let [raw (or (:transcript event) (:payload event) event)
        transcript (if (instance? bitecho.economy.attestation.EpochTranscript raw)
                     raw
                     (try (attestation/map->EpochTranscript raw) (catch Exception _ nil)))
        event-sender (:sender event)
        sender-hex (when event-sender (if (string? event-sender) event-sender (basalt/bytes->hex event-sender)))
        pa (when transcript (:peer-a transcript))
        pb (when transcript (:peer-b transcript))]
    (if-not (and transcript
                 (string? pa)
                 (string? pb)
                 (not= pa pb)
                 (seq (:message-roles transcript))
                 (or (nil? sender-hex) (contains? #{pa pb} sender-hex)))
      {:state state :commands []}
      (let [resolved-cp (resolve-counterparty-frozen-ids event transcript state)]
        (if-not (:ok? resolved-cp)
          {:state state :commands []}
          (let [epoch (:epoch transcript)
                local-frozen-ids (or (get-in state [:frozen-epoch-messages epoch])
                                     (get-in state [:epoch-to-messages epoch])
                                     #{})
                node-pub (:node-pubkey state)
                local-is-party? (contains? #{pa pb} node-pub)
                dispute-res (if (and (attestation/mutually-signed? transcript)
                                     (or (empty? local-frozen-ids) (not local-is-party?)))
                              {:status :settled :credit #{pa pb} :strike nil}
                              (let [counterparty-frozen-ids (:ids resolved-cp)
                                    local-frozen-roles-map (or (get-in state [:frozen-epoch-message-roles epoch])
                                                               (get-in state [:epoch-to-message-roles epoch])
                                                               {})
                                    auth-roles (derive-authoritative-roles local-frozen-ids local-frozen-roles-map)
                                    frozen-log-roles (attestation/reconcile-message-roles
                                                      local-frozen-ids
                                                      counterparty-frozen-ids
                                                      auth-roles)]
                                (attestation/evaluate-transcript-dispute transcript frozen-log-roles)))
                p1 (first (sort [pa pb]))
                p2 (second (sort [pa pb]))
                pair-tuple [epoch p1 p2]]
            (if (contains? (or (:settled-transcript-pairs state) #{}) pair-tuple)
              {:state state :commands []}
              (case (:status dispute-res)
                (:settled :half-signed-fault)
                (if (consensus-mode? state)
                  (let [rid (str "transcript:" epoch ":" p1 ":" p2 ":" (:digest transcript))
                        expected-cp (if (= node-pub pb) pa pb)
                        cp-log (or (:counterparty-frozen-log event)
                                   (:peer-frozen-log event)
                                   (get-in state [:peer-frozen-logs [epoch expected-cp]]))
                        prover-log (or (:prover-frozen-log event)
                                       (when-let [priv (or (:node-private-key state) (get-in state [:keypair :private]))]
                                         (when (and (= node-pub pa) (seq local-frozen-ids))
                                           (attestation/sign-frozen-log epoch node-pub local-frozen-ids priv))))
                        rcpt {:receipt-id rid
                              :type :transcript
                              :epoch epoch
                              :peer-a pa
                              :peer-b pb
                              :transcript (into {} transcript)
                              :counterparty-frozen-log cp-log
                              :prover-frozen-log prover-log}
                        staged (stage-receipt state rcpt)]
                    (if (:ok? staged)
                      {:state (:state staged) :commands []}
                      {:state state :commands []}))
                  (let [strike-peer (:strike dispute-res)
                        s1 (if strike-peer
                             (update-in state [:fault-strikes strike-peer] (fnil inc 0))
                             state)
                        s2 (update s1 :settled-transcript-pairs (fnil conj #{}) pair-tuple)
                        credited (:credit dispute-res)
                        role-cnt (count (:message-roles transcript))
                        s3 (update-attested-mesh-weights s2 epoch credited role-cnt)]
                    {:state s3 :commands []}))
                {:state state :commands []}))))))))

(defn- handle-receive-transcript-sig
  "Handles incoming peer transcript signature or cosignature requests."
  [state event]
  (let [sender (:sender event)
        raw-tx (:transcript event)
        ep (long (or (:epoch event)
                     (when (map? raw-tx) (:epoch raw-tx))
                     0))
        cp-log (or (:frozen-log event) (:peer-frozen-log event))
        my-pub (:node-pubkey state)
        my-priv (or (:node-private-key state) (get-in state [:keypair :private]))
        known-peers (let [pm (:peers-map state)
                          mn (or (:mesh-nodes state) (get-in state [:config :mesh-nodes]))]
                      (set/union (when (seq pm) (set (keys pm)))
                                 (cond
                                   (map? mn) (set (keys mn))
                                   (coll? mn) (set mn)
                                   :else #{})))
        sender-valid? (or (empty? known-peers)
                          (contains? known-peers sender))
        tx-valid-map? (map? raw-tx)
        cp-log-valid? (if cp-log
                        (boolean
                         (and (attestation/verify-frozen-log cp-log)
                              (= ep (:epoch cp-log))
                              (= sender (:peer cp-log))))
                        true)]
    (if-not (and sender-valid? tx-valid-map? cp-log-valid?)
      {:state state :commands []}
      (let [state-with-log (if cp-log
                             (assoc-in state [:peer-frozen-logs [ep sender]] cp-log)
                             state)
            tx (if (instance? bitecho.economy.attestation.EpochTranscript raw-tx)
                 raw-tx
                 (try (attestation/map->EpochTranscript raw-tx) (catch Exception _ nil)))
            pa (when tx (:peer-a tx))
            pb (when tx (:peer-b tx))]
        (if-not (and tx
                     (string? pa)
                     (string? pb)
                     (not= pa pb)
                     (seq (:message-roles tx)))
          {:state state-with-log :commands []}
          (cond
            ;; Case 1: Mutually-signed transcript involving my-pub and sender
            (and (attestation/mutually-signed? tx)
                 (contains? #{(:peer-a tx) (:peer-b tx)} my-pub)
                 (contains? #{(:peer-a tx) (:peer-b tx)} sender))
            (handle-submit-transcript state-with-log
                                      {:type :submit-transcript
                                       :transcript tx
                                       :counterparty-frozen-log (get-in state-with-log [:peer-frozen-logs [ep sender]])})

            ;; Case 2: Half-signed transcript from sender to my-pub
            (and (attestation/half-signed? tx)
                 (= (:peer-a tx) sender)
                 (= (:peer-b tx) my-pub)
                 (some? my-priv))
            (let [local-frozen-ids (or (get-in state-with-log [:frozen-epoch-messages ep])
                                       (get-in state-with-log [:epoch-to-messages ep])
                                       #{})
                  local-roles-map (or (get-in state-with-log [:frozen-epoch-message-roles ep])
                                      (get-in state-with-log [:epoch-to-message-roles ep])
                                      {})
                  auth-roles (derive-authoritative-roles local-frozen-ids local-roles-map)
                  cp-ids (if-let [l (get-in state-with-log [:peer-frozen-logs [ep sender]])]
                           (set (:frozen-ids l))
                           local-frozen-ids)
                  reconciled-roles (attestation/reconcile-message-roles local-frozen-ids cp-ids auth-roles)]
              (cond
                (and (seq reconciled-roles)
                     (attestation/verify-transcript-against-log tx reconciled-roles))
                (let [cosigned (attestation/cosign-transcript tx my-priv)
                      sub-res (handle-submit-transcript state-with-log
                                                        {:type :submit-transcript
                                                         :transcript cosigned
                                                         :counterparty-frozen-log (get-in state-with-log [:peer-frozen-logs [ep sender]])})
                      reply-cmd {:type :send-transcript-sig
                                 :target sender
                                 :epoch ep
                                 :transcript (into {} cosigned)}]
                  {:state (:state sub-res)
                   :commands (conj (vec (:commands sub-res)) reply-cmd)})

                (and (seq reconciled-roles)
                     (not (:reconciled? event))
                     (some? (get-in state-with-log [:peer-frozen-logs [ep sender]])))
                (let [reconciled-half (attestation/create-transcript ep my-pub sender reconciled-roles my-priv)
                      my-log (attestation/sign-frozen-log ep my-pub local-frozen-ids my-priv)
                      reply-cmd {:type :send-transcript-sig
                                 :target sender
                                 :epoch ep
                                 :transcript (into {} reconciled-half)
                                 :frozen-log my-log
                                 :reconciled? true}]
                  {:state state-with-log
                   :commands [reply-cmd]})

                :else
                {:state state-with-log :commands []}))

            :else
            {:state state-with-log :commands []}))))))

(defn- handle-register-home-set
  "Registers a home set of nodes for Callee B for an epoch.
   Enforces fixed price p_B per (callee, epoch): mid-epoch re-registration
   at a different price is rejected unless targeting a new epoch."
  [state event]
  (let [callee (:callee event)
        event-sender (:sender event)
        sender-hex (when event-sender (if (string? event-sender) event-sender (basalt/bytes->hex event-sender)))
        callee-hex (when callee (if (string? callee) callee (basalt/bytes->hex callee)))]
    (if-not (or (nil? sender-hex) (= callee-hex sender-hex))
      {:state state :commands []}
      (let [current-epoch (or (:epoch event) (:epoch state) 0)
            raw-candidates (or (:candidates event) [])
            candidates (mapv (fn [c] (if (contains? c :node-id) (assoc c :node-id (rendezvous/normalize-home-node (:node-id c))) c)) raw-candidates)
            p-b (or (:price event) (:p-b event) 0)
            p-b-max (or (:price-max event) (:p-b-max event) p-b)
            tuple [callee current-epoch]
            existing (get-in state [:home-sets tuple])]
        (if (and existing (some? (:price existing)) (not= (:price existing) p-b))
          {:state state :commands []}
          (let [reg-result (rendezvous/register-home-set candidates p-b p-b-max)]
            (if (consensus-mode? state)
              (let [rid (str "home-set:" callee ":" current-epoch)
                    staged (stage-receipt state
                                          {:receipt-id rid
                                           :type :register-home-set
                                           :callee callee
                                           :epoch current-epoch
                                           :candidates candidates
                                           :price p-b
                                           :price-max p-b-max})]
                (if (:ok? staged)
                  {:state (assoc-in (:state staged) [:home-sets tuple] reg-result)
                   :commands []}
                  {:state state
                   :commands []}))
              {:state (assoc-in state [:home-sets tuple] reg-result)
               :commands []})))))))

(defn- pending-tuple-voucher-debit
  "Returns the maximum cumulative debit already staged in :pending-receipts for a given [callee home-node epoch] tuple."
  [state tuple]
  (let [[callee home-node epoch] tuple
        norm-tuple [callee (rendezvous/normalize-home-node home-node) epoch]]
    (reduce (fn [mx r]
              (if (and (= (:type r) :voucher)
                       (= [(:callee r) (rendezvous/normalize-home-node (:home-node r)) (:epoch r)] norm-tuple))
                (max mx (long (or (:cumulative-debit r) 0)))
                mx))
            0
            (or (:pending-receipts state) []))))

(defn- pending-tuple-voucher-seq
  "Returns the maximum sequence number already staged in :pending-receipts for a given [callee home-node epoch] tuple."
  [state tuple]
  (let [[callee home-node epoch] tuple
        norm-tuple [callee (rendezvous/normalize-home-node home-node) epoch]]
    (reduce (fn [mx r]
              (if (and (= (:type r) :voucher)
                       (= [(:callee r) (rendezvous/normalize-home-node (:home-node r)) (:epoch r)] norm-tuple))
                (max mx (long (or (:seq r) 0)))
                mx))
            0
            (or (:pending-receipts state) []))))

(defn- handle-receive-offer-header
  "Processes an incoming offer header, validating home set membership and
   sequence monotonicity, and appending the generated DeliveryAck to pending vouchers.
   Rejects offer header if callee is absent from ledger or underfunded for cumulative debit."
  [state event]
  (let [callee (:callee event)
        home-node (rendezvous/normalize-home-node (:home-node event))
        current-epoch (or (:epoch event) (:epoch state) 0)
        home-set (get-in state [:home-sets [callee current-epoch]])
        tuple [callee home-node current-epoch]
        last-seq (get-in state [:voucher-seqs tuple] 0)
        seq-num (:seq event)
        expected-seq (inc last-seq)]
    (if (or (nil? home-set)
            (= :rejected (:status home-set))
            (not (node-in-home-set? home-node home-set))
            (not= seq-num expected-seq))
      {:state state :commands []}
      (let [price (:price home-set)
            cum-debit (* seq-num price)
            callee-bal (if (consensus-mode? state)
                         (+ (spendable-balance state callee)
                            (pending-tuple-voucher-debit state tuple))
                         (or (get-in state [:ledger callee :balance]) 0))]
        (if (< callee-bal cum-debit)
          {:state state :commands []}
          (let [offer-ctx (assoc event
                                 :home-node home-node
                                 :last-seq last-seq
                                 :p-b price
                                 :cumulative-debit cum-debit
                                 :epoch current-epoch)
                res (rendezvous/process-offer-header offer-ctx)]
            (if (= :ok (:status res))
              (let [ack (:delivery-ack res)]
                (if (consensus-mode? state)
                  (let [rid (str "voucher:" callee ":" home-node ":" current-epoch ":" seq-num)
                        staged (stage-receipt state
                                              {:receipt-id rid
                                               :type :voucher
                                               :callee callee
                                               :home-node home-node
                                               :epoch current-epoch
                                               :seq seq-num
                                               :cumulative-debit cum-debit
                                               :ack ack})]
                    (if (:ok? staged)
                      {:state (assoc-in (:state staged) [:voucher-seqs tuple] seq-num)
                       :commands []}
                      {:state state
                       :commands []}))
                  {:state (-> state
                              (assoc-in [:voucher-seqs tuple] seq-num)
                              (update :pending-vouchers (fnil conj []) ack))
                   :commands []}))
              {:state state :commands []})))))))

(defn- handle-submit-vouchers
  "Processes an incoming :submit-vouchers event from an agent or node.
   Validates signatures, sequence monotonicity, home-set membership, and balances,
   staging valid vouchers into :pending-receipts (consensus mode) or :pending-vouchers (standalone mode)."
  [state event]
  (let [raw-vouchers (or (:vouchers event) [])
        compacted (->> raw-vouchers
                       (keep (fn [raw]
                               (let [ack (if (instance? bitecho.rendezvous.core.DeliveryAck raw)
                                           raw
                                           (try (rendezvous/map->DeliveryAck raw)
                                                (catch Exception _ nil)))]
                                 (when (and ack (rendezvous/verify-delivery-ack ack))
                                   (assoc ack :home-node (rendezvous/normalize-home-node (:home-node ack)))))))
                       (group-by (fn [ack] [(:callee ack) (rendezvous/normalize-home-node (:home-node ack)) (long (or (:epoch ack) 0))]))
                       vals
                       (mapv (fn [group] (apply max-key (comp long :seq) group)))
                       (sort-by (juxt (comp long :epoch) (comp str :callee) (comp str rendezvous/normalize-home-node :home-node) (comp long :seq))))
        final-state
        (reduce
         (fn [curr-st ack]
           (let [callee (:callee ack)
                 home-node (rendezvous/normalize-home-node (:home-node ack))
                 ack-epoch (long (or (:epoch ack) 0))
                 seq-num (long (or (:seq ack) 0))
                 debit (long (or (:cumulative-debit ack) 0))
                 tuple [callee home-node ack-epoch]
                 last-seq (if (consensus-mode? curr-st)
                            (max (long (get-in curr-st [:voucher-seqs tuple] 0))
                                 (pending-tuple-voucher-seq curr-st tuple))
                            (long (get-in curr-st [:voucher-seqs tuple] 0)))
                 settled? (contains? (or (:settled-voucher-tuples curr-st) #{}) tuple)
                 home-set (get-in curr-st [:home-sets [callee ack-epoch]])
                 home-set-ok? (and (some? home-set)
                                   (not= :rejected (:status home-set))
                                   (node-in-home-set? home-node home-set)
                                   (integer? (:price home-set))
                                   (not (neg? (long (:price home-set))))
                                   (= debit (* seq-num (long (:price home-set)))))
                 balance-ok? (if (consensus-mode? curr-st)
                               (>= (+ (spendable-balance curr-st callee)
                                      (pending-tuple-voucher-debit curr-st tuple))
                                   debit)
                               (>= (or (get-in curr-st [:ledger callee :balance]) 0) debit))
                 valid? (and (string? callee)
                             (some? home-node)
                             (>= ack-epoch 0)
                             (pos? seq-num)
                             (> seq-num last-seq)
                             (pos? debit)
                             (not settled?)
                             home-set-ok?
                             balance-ok?)]
             (if valid?
               (if (consensus-mode? curr-st)
                 (let [rid (str "voucher:" callee ":" home-node ":" ack-epoch ":" seq-num)
                       staged (stage-receipt curr-st
                                             {:receipt-id rid
                                              :type :voucher
                                              :callee callee
                                              :home-node home-node
                                              :epoch ack-epoch
                                              :seq seq-num
                                              :cumulative-debit debit
                                              :ack (into {} ack)})]
                   (if (:ok? staged)
                     (:state staged)
                     curr-st))
                 (-> curr-st
                     (assoc-in [:voucher-seqs tuple] seq-num)
                     (update :pending-vouchers (fnil conj []) ack)))
               curr-st)))
         state
         compacted)]
    {:state final-state :commands []}))

(defn- handle-settle-intent
  "Handles an internal or external request to settle a payment intent with protocol take.
   Accepts {:type :settle-intent :payer payer :receiver receiver :amount amount}.
   Validates payer, receiver, amount (positive integer), and payer balance >= amount.
   Deducts amount from payer, credits (- amount take-amt) to receiver,
   and records take-amt in [:epoch-settlement-takes current-epoch]."
  [state event]
  (let [payer (:payer event)
        receiver (:receiver event)
        amount (:amount event)
        event-sender (:sender event)
        sender-hex (when event-sender (if (string? event-sender) event-sender (basalt/bytes->hex event-sender)))
        payer-hex (when payer (if (string? payer) payer (basalt/bytes->hex payer)))
        receiver-hex (when receiver (if (string? receiver) receiver (basalt/bytes->hex receiver)))]
    (if-not (or (nil? sender-hex) (= payer-hex sender-hex))
      {:state state :commands []}
      (if (consensus-mode? state)
        (let [payer-acct (when payer-hex (get-in state [:ledger payer-hex]))]
          (if (and payer-hex
                   receiver-hex
                   (integer? amount)
                   (pos? amount)
                   payer-acct
                   (>= (spendable-balance state payer-hex) amount))
            (let [rid (or (:receipt-id event)
                          (str "intent:" payer-hex ":" receiver-hex ":" amount ":" (or (:epoch state) 0) ":" (:receipt-seq state 0)))
                  staged (stage-receipt state {:receipt-id rid
                                               :type :settle-intent
                                               :payer payer-hex
                                               :receiver receiver-hex
                                               :amount amount})]
              (if (:ok? staged)
                {:state (:state staged) :commands []}
                {:state state :commands []}))
            {:state state :commands []}))
        (let [payer-acct (when payer-hex (get-in state [:ledger payer-hex]))
              payer-bal (or (:balance payer-acct) 0)]
          (if (and payer-hex
                   receiver-hex
                   (integer? amount)
                   (pos? amount)
                   payer-acct
                   (>= payer-bal amount))
            (let [configured-bps (or (:settlement-take-bps state)
                                     (get-in state [:config :settlement-take-bps])
                                     burn/default-settlement-take-bps)
                  take-bps (max 1 configured-bps)
                  take-amt (burn/calculate-settlement-take amount take-bps)
                  net-amt (- amount take-amt)
                  current-epoch (or (:epoch event) (:epoch state) 0)
                  receiver-acct (get-in state [:ledger receiver-hex]
                                        (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                  new-payer (assoc payer-acct :balance (- payer-bal amount))
                  new-receiver (assoc receiver-acct :balance (+ (or (:balance receiver-acct) 0) net-amt))
                  new-ledger (assoc (:ledger state)
                                    payer-hex new-payer
                                    receiver-hex new-receiver)]
              {:state (-> state
                          (assoc :ledger new-ledger)
                          (update-in [:epoch-settlement-takes current-epoch] (fnil + 0) take-amt))
               :commands []})
            {:state state :commands []}))))))

(defn- handle-lock-intent
  "Handles request to lock funds into deterministic verified-outcome escrow.
   Enforces sender authentication, positive integer amount, valid deliverable-hash,
   expires-epoch > created-epoch, and sufficient payer balance."
  [state event]
  (if-not (and (or (nil? (:epoch event)) (integer? (:epoch event)))
               (or (nil? (:created-epoch event)) (integer? (:created-epoch event)))
               (integer? (:expires-epoch event)))
    {:state state :commands []}
    (let [payer (:payer event)
          receiver (:receiver event)
          amount (:amount event)
          deliverable-hash (:deliverable-hash event)
          current-epoch (long (if (and (consensus-mode? state) (pos? (long (or (:epoch state) 0))))
                                (:epoch state)
                                (or (:epoch event) (:epoch state) 0)))
          created-epoch (long (if (and (consensus-mode? state) (pos? (long (or (:epoch state) 0))))
                                (max (long (or (:created-epoch event) current-epoch)) (- current-epoch 168))
                                (or (:created-epoch event) current-epoch)))
          expires-epoch (long (:expires-epoch event))
          nonce (str (or (:nonce event) "0"))
          event-sender (:sender event)
          sender-hex (when event-sender (if (string? event-sender) event-sender (basalt/bytes->hex event-sender)))
          payer-hex (when payer (if (string? payer) payer (basalt/bytes->hex payer)))
          receiver-hex (when receiver (if (string? receiver) receiver (basalt/bytes->hex receiver)))
          escrow-id (or (:escrow-id event)
                        (when (and payer-hex receiver-hex (integer? amount) (pos? amount)
                                   deliverable-hash (escrow/valid-deliverable-hash? deliverable-hash)
                                   (> expires-epoch created-epoch))
                          (escrow/compute-escrow-id payer-hex receiver-hex amount deliverable-hash created-epoch expires-epoch nonce)))
          already-exists? (or (contains? (or (:escrows state) #{}) escrow-id)
                              (contains? (or (:settled-escrow-ids state) #{}) escrow-id))]
      (if-not (or (nil? sender-hex) (= payer-hex sender-hex))
        {:state state :commands []}
        (if (or (nil? payer-hex) (nil? receiver-hex) (= payer-hex receiver-hex)
                (not (integer? amount)) (not (pos? amount))
                (not (escrow/valid-deliverable-hash? deliverable-hash))
                (<= expires-epoch created-epoch)
                (< created-epoch (- current-epoch 168))
                (> (- expires-epoch created-epoch) 168)
                (nil? escrow-id)
                already-exists?)
          {:state state :commands []}
          (if (consensus-mode? state)
            (let [payer-acct (get-in state [:ledger payer-hex])]
              (if (and payer-acct (>= (spendable-balance state payer-hex) amount))
                (let [rid (or (:receipt-id event) (str "lock:" escrow-id))
                      staged (stage-receipt state {:receipt-id rid
                                                   :type :lock-intent
                                                   :escrow-id escrow-id
                                                   :payer payer-hex
                                                   :receiver receiver-hex
                                                   :amount amount
                                                   :deliverable-hash (escrow/normalize-hex deliverable-hash)
                                                   :created-epoch created-epoch
                                                   :expires-epoch expires-epoch})]
                  (if (:ok? staged)
                    {:state (:state staged) :commands []}
                    {:state state :commands []}))
                {:state state :commands []}))
            (let [payer-acct (get-in state [:ledger payer-hex])
                  payer-bal (or (:balance payer-acct) 0)]
              (if (and payer-acct (>= payer-bal amount))
                (let [new-payer (assoc payer-acct :balance (- payer-bal amount))
                      escrow-entry {:escrow-id escrow-id
                                    :payer payer-hex
                                    :receiver receiver-hex
                                    :amount amount
                                    :deliverable-hash (escrow/normalize-hex deliverable-hash)
                                    :created-epoch created-epoch
                                    :expires-epoch expires-epoch
                                    :status :locked}]
                  {:state (-> state
                              (assoc-in [:ledger payer-hex] new-payer)
                              (assoc-in [:escrows escrow-id] escrow-entry))
                   :commands []})
                {:state state :commands []}))))))))

(defn- handle-release-intent
  "Handles request to release escrowed funds upon verified outcome or payer authorization."
  [state event]
  (if-not (or (nil? (:epoch event)) (integer? (:epoch event)))
    {:state state :commands []}
    (let [escrow-id (:escrow-id event)
          escrow (get-in state [:escrows escrow-id])
          preimage (:preimage event)
          payer-sig (:payer-signature event)
          event-sender (:sender event)
          sender-hex (when event-sender (if (string? event-sender) event-sender (basalt/bytes->hex event-sender)))
          current-epoch (long (if (and (consensus-mode? state) (pos? (long (or (:epoch state) 0))))
                                (:epoch state)
                                (or (:epoch event) (:epoch state) 0)))]
      (if-not (and escrow (= :locked (:status escrow)))
        {:state state :commands []}
        (let [payer (:payer escrow)
              receiver (:receiver escrow)
              d-hash (:deliverable-hash escrow)
              expires-epoch (long (or (:expires-epoch escrow) 0))
              amount (long (:amount escrow))
              payer-auth? (or (= sender-hex payer)
                              (and (string? payer-sig)
                                   (escrow/verify-escrow-release-sig payer escrow-id d-hash payer-sig)))
              preimage-auth? (and (string? preimage)
                                  (escrow/verify-deliverable-preimage preimage d-hash)
                                  (<= current-epoch expires-epoch)
                                  (or (nil? sender-hex) (= sender-hex receiver) (= sender-hex payer)))]
          (if-not (or payer-auth? preimage-auth?)
            {:state state :commands []}
            (if (consensus-mode? state)
              (let [rid (or (:receipt-id event) (str "release:" escrow-id))
                    staged (stage-receipt state {:receipt-id rid
                                                 :type :release-intent
                                                 :escrow-id escrow-id
                                                 :preimage preimage
                                                 :payer-signature payer-sig
                                                 :sender sender-hex})]
                (if (:ok? staged)
                  {:state (:state staged) :commands []}
                  {:state state :commands []}))
              (let [configured-bps (or (:settlement-take-bps state)
                                       (get-in state [:config :settlement-take-bps])
                                       burn/default-settlement-take-bps)
                    take-amt (escrow/calculate-escrow-settlement-take amount configured-bps)
                    net-amt (- amount take-amt)
                    receiver-acct (get-in state [:ledger receiver]
                                          (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                    new-receiver (assoc receiver-acct :balance (+ (or (:balance receiver-acct) 0) net-amt))
                    updated-escrow (assoc escrow
                                          :status :released
                                          :settled-epoch current-epoch
                                          :take-amount take-amt
                                          :net-amount net-amt
                                          :settlement-mode (if payer-auth? :payer-authorized :preimage-verified))
                    max-tracked (long (or (get-in state [:config :max-tracked-receipts]) 10000))
                    [next-settled-ids next-settled-ord] (fifo-track (:settled-escrow-ids state)
                                                                    (:settled-escrow-order state)
                                                                    escrow-id
                                                                    max-tracked)]
                {:state (-> state
                            (assoc-in [:ledger receiver] new-receiver)
                            (assoc-in [:escrows escrow-id] updated-escrow)
                            (assoc :settled-escrow-ids next-settled-ids
                                   :settled-escrow-order next-settled-ord)
                            (update-in [:epoch-settlement-takes current-epoch] (fnil + 0) take-amt))
                 :commands []}))))))))

(defn- handle-refund-intent
  "Handles request to refund escrowed funds on timeout or receiver voluntary refund."
  [state event]
  (if-not (or (nil? (:epoch event)) (integer? (:epoch event)))
    {:state state :commands []}
    (let [escrow-id (:escrow-id event)
          escrow (get-in state [:escrows escrow-id])
          event-sender (:sender event)
          sender-hex (when event-sender (if (string? event-sender) event-sender (basalt/bytes->hex event-sender)))
          current-epoch (long (if (and (consensus-mode? state) (pos? (long (or (:epoch state) 0))))
                                (:epoch state)
                                (or (:epoch event) (:epoch state) 0)))]
      (if-not (and escrow (= :locked (:status escrow)))
        {:state state :commands []}
        (let [payer (:payer escrow)
              receiver (:receiver escrow)
              expires-epoch (long (or (:expires-epoch escrow) 0))
              amount (long (:amount escrow))
              timeout? (and (> current-epoch expires-epoch)
                            (or (nil? sender-hex) (contains? #{payer receiver} sender-hex)))
              receiver-voluntary? (= sender-hex receiver)]
          (if-not (or timeout? receiver-voluntary?)
            {:state state :commands []}
            (if (consensus-mode? state)
              (let [rid (or (:receipt-id event) (str "refund:" escrow-id))
                    staged (stage-receipt state {:receipt-id rid
                                                 :type :refund-intent
                                                 :escrow-id escrow-id
                                                 :sender sender-hex})]
                (if (:ok? staged)
                  {:state (:state staged) :commands []}
                  {:state state :commands []}))
              (let [payer-acct (get-in state [:ledger payer]
                                       (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                    new-payer (assoc payer-acct :balance (+ (or (:balance payer-acct) 0) amount))
                    updated-escrow (assoc escrow
                                          :status :refunded
                                          :settled-epoch current-epoch
                                          :refund-amount amount
                                          :refund-reason (if receiver-voluntary? :receiver-voluntary :timeout))
                    max-tracked (long (or (get-in state [:config :max-tracked-receipts]) 10000))
                    [next-settled-ids next-settled-ord] (fifo-track (:settled-escrow-ids state)
                                                                    (:settled-escrow-order state)
                                                                    escrow-id
                                                                    max-tracked)]
                {:state (-> state
                            (assoc-in [:ledger payer] new-payer)
                            (assoc-in [:escrows escrow-id] updated-escrow)
                            (assoc :settled-escrow-ids next-settled-ids
                                   :settled-escrow-order next-settled-ord))
                 :commands []}))))))))

(defn handle-event
  "Pure root reducer. Takes the current state and an event,
   returns a map with :state (new state) and :commands (side-effects to perform)."
  [state event]
  (case (:type event)
    :contagion-broadcast (handle-contagion-broadcast state event)
    :tick (handle-tick state event)
    :broadcast (handle-broadcast state event)
    :signaling-burn (handle-signaling-burn state event)
    :settle-intent (handle-settle-intent state event)
    :lock-intent (handle-lock-intent state event)
    :release-intent (handle-release-intent state event)
    :refund-intent (handle-refund-intent state event)
    :epoch-mint (handle-epoch-mint state event)
    :apply-epoch-mint (handle-epoch-mint state event)
    :submit-transcript (handle-submit-transcript state event)
    :register-home-set (handle-register-home-set state event)
    :receive-offer-header (handle-receive-offer-header state event)
    :receive-push-view (handle-receive-push-view state event)
    :receive-summary (handle-receive-summary state event)
    :receive-subscribe (handle-receive-subscribe state event)
    :receive-pull-request (handle-receive-pull-request state event)
    :receive-gossip (handle-receive-gossip state event)
    :receive-sieve-echo (handle-receive-sieve-echo state event)
    :receive-contagion-ready (handle-receive-contagion-ready state event)
    :receive-propose (let [res (streamlet/handle-streamlet-event state event)]
                       {:state (execute-finalized-blocks (:state res))
                        :commands (:commands res)})
    :receive-vote (let [res (streamlet/handle-streamlet-event state event)]
                    {:state (execute-finalized-blocks (:state res))
                     :commands (:commands res)})
    :on-deliver (handle-on-deliver state event)
    :submit-vouchers (handle-submit-vouchers state event)
    :receive-transcript-sig (handle-receive-transcript-sig state event)
    {:state state :commands []}))