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
            [bitecho.economy.treasury :as treasury]
            [bitecho.murmur.core :as murmur]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.sieve.core :as sieve]
            [bitecho.streamlet.core :as streamlet]
            [clojure.edn :as edn]
            [clojure.set :as set]
            [clojure.string :as string]))

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
      :fault-strikes {} :home-sets {} :voucher-seqs {}
      :pending-vouchers [] :settled-voucher-tuples #{} :failed-vouchers []
      :skipped-custody-allocations []
      :ledger (or genesis-ledger {})
      ;; Streamlet BFT state
      :blocks {} :notarized-blocks #{} :finalized-blocks #{}
      :block-votes {} :voted-epochs #{} :head-hash "genesis" :mempool []
      :peers-map (or (:peers-map cfg) {})
      :keypair (or (:keypair cfg) nil)})))

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

(defn- settle-single-voucher
  "Settles a single compacted DeliveryAck voucher against state, updating ledger and settled tuples.
   Fails closed: requires callee balance >= debit; records failure in :failed-vouchers and queues valid
   underfunded vouchers in :retry-vouchers for retry in subsequent epochs."
  [acc ack closing-epoch min-epoch]
  (let [callee (:callee ack)
        home-node (:home-node ack)
        ack-epoch (:epoch ack)
        tuple [callee home-node ack-epoch]
        reg-set (get-in acc [:home-sets [callee ack-epoch]])
        reg-price (:price reg-set)
        v-res (rendezvous/verify-ack-for-settlement
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
               :reason (or (:reason v-res) (:error v-res) :invalid-voucher)}))))

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
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :echo)) {} new-echo-hexes)
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :ready)) new-roles-by-peer new-ready-hexes)
        new-roles-by-peer (reduce (fn [acc peer] (update acc peer (fnil conj #{}) :delivery)) new-roles-by-peer new-delivery-hexes)
        subscribe-commands (mapv (fn [[peer roles]]
                                   {:type :send-subscribe
                                    :target peer
                                    :roles roles})
                                 new-roles-by-peer)]
    {:echo-sample updated-echo-sample
     :ready-sample updated-ready-sample
     :delivery-sample updated-delivery-sample
     :subscribe-commands subscribe-commands}))

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
        pruned-murmur-cache-set (set/difference (:set (:murmur-cache state)) expired-ids)
        pruned-murmur-cache-queue (if (seq expired-ids)
                                    (into clojure.lang.PersistentQueue/EMPTY
                                          (remove expired-ids (:queue (:murmur-cache state))))
                                    (:queue (:murmur-cache state)))
        pruned-murmur-cache {:set pruned-murmur-cache-set :queue pruned-murmur-cache-queue}
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
        rdv-cutoff (- (dec new-epoch) frozen-retention)]
    (-> (assoc state
               :epoch-to-messages pruned-epoch-to-messages
               :epoch-to-message-roles pruned-epoch-to-roles
               :message-epochs pruned-epochs
               :messages pruned-messages
               :contagion-known-ids pruned-known-ids
               :murmur-cache pruned-murmur-cache
               :received-echoes pruned-received-echoes
               :received-readies pruned-received-readies
               :echo-vote-counts pruned-echo-vote-counts
               :ready-vote-counts pruned-ready-vote-counts
               :delivery-vote-counts pruned-delivery-vote-counts
               :sieve-delivered-set pruned-sieve-delivered-set
               :local-ready-set pruned-local-ready-set
               :delivered-set pruned-delivered-set
               :frozen-epoch-messages pruned-frozen-messages
               :frozen-epoch-message-roles pruned-frozen-roles)
        (prune-rendezvous-retention-state rdv-cutoff))))

(defn- apply-streamlet-tick
  "Steps Streamlet BFT tick if peers-map is configured, advancing consensus state and commands."
  [treasury-state commands closing-epoch]
  (if (seq (:peers-map treasury-state))
    (let [streamlet-res (streamlet/handle-streamlet-event
                         (assoc treasury-state :epoch closing-epoch)
                         {:type :tick})]
      {:state (:state streamlet-res)
       :commands (into (or commands []) (:commands streamlet-res))})
    {:state treasury-state
     :commands commands}))

(defn- handle-tick
  "Handles a periodic tick event to drive Basalt reseeding and Contagion anti-entropy."
  [state event]
  (let [cfg (:config state)
        new-epoch (inc (or (:epoch state) 0))
        epoch-entropy (derive-epoch-entropy state cfg)
        view (:basalt-view state)
        rng (:rng event)
        reset-result (basalt/reset-slots-deterministic view epoch-entropy (:node-pubkey state) (:basalt-index state) 1)
        new-view (:view reset-result)
        new-index (:next-r reset-result)
        extracted-peers (basalt/extract-peers new-view)
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
        tick-state-settled (apply-epoch-voucher-settlement pruned-state closing-epoch)
        treasury-state (apply-epoch-treasury-boundary tick-state-settled new-epoch)]
    (apply-streamlet-tick treasury-state commands closing-epoch)))

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
  (let [current-epoch (or (:epoch state) 0)]
    (if-let [burn-res (apply-broadcast-burn state event current-epoch)]
      (let [state (:state burn-res)
            burn-amt (:burn-amount burn-res)
            cfg (:config state)
            murmur-k (:murmur-k cfg)
            murmur-max-cache-size (:murmur-max-cache-size cfg)
            payload (:payload event)
            rng (:rng event)
            extracted-peers (basalt/extract-peers (:basalt-view state))
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
            ;; We implicitly add our own broadcasts to the known ids and cache
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
      {:state state :commands []})))

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
  (let [received-peers (:view event)
        new-view (basalt/update-view (:basalt-view state) received-peers)]
    {:state (assoc state :basalt-view new-view)
     :commands []}))

(defn- handle-receive-summary
  "Handles an incoming Contagion anti-entropy summary."
  [state event]
  (let [remote-summary (:summary event)
        missing-ids (contagion/lazy-pull (:contagion-known-ids state) remote-summary)
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
      (let [extracted-peers (basalt/extract-peers (:basalt-view state))
            gossip-result (murmur/receive-gossip (:murmur-cache state) message rng extracted-peers murmur-k murmur-max-cache-size)
            new-message? (some? (:message gossip-result))
            sender (when-let [s (:sender message)] (if (string? s) s (basalt/bytes->hex s)))
            node-pk (when-let [np (:node-pubkey state)] (if (string? np) np (basalt/bytes->hex np)))
            burn-deduction (when (and new-message? (not= sender node-pk) sender)
                             (burn/deduct-signaling-burn (:ledger state) sender burn-amt))]
        (if (and new-message? (not= sender node-pk) (nil? burn-deduction))
          {:state state :commands []}
          (let [current-epoch (or (:epoch state) 0)
                state-with-burn (if burn-deduction
                                  (-> state
                                      (assoc :ledger (:ledger burn-deduction))
                                      (update-in [:epoch-burns current-epoch] (fnil + 0) burn-amt))
                                  state)]
            (record-accepted-gossip state-with-burn message gossip-result new-message? current-epoch))))
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

(defn- apply-payload-to-ledger
  "Attempts to parse a payload and apply any transfer to the ledger.
   Returns the updated state if successful, or the original state on failure."
  [state payload-bytes]
  (let [payload-str (try (String. ^bytes payload-bytes "UTF-8") (catch Exception _ nil))
        payload-edn (try (when payload-str
                           (edn/read-string {:default tagged-literal
                                             :readers {'bitecho.economy.account.Transfer account/map->Transfer
                                                       'bitecho.economy.account.AccountState account/map->AccountState}} payload-str))
                         (catch Exception _ nil))]
    (if (and (map? payload-edn) (:transfer payload-edn))
      (try
        (let [raw-transfer (:transfer payload-edn)
              transfer-map (if (instance? clojure.lang.TaggedLiteral raw-transfer)
                             (:form raw-transfer)
                             (if (map? raw-transfer)
                               (into {} raw-transfer)
                               (into {} raw-transfer)))
              transfer-map (if (vector? (:signature transfer-map))
                             (assoc transfer-map :signature (byte-array (map byte (:signature transfer-map))))
                             transfer-map)
              transfer-map (if (string? (:signature transfer-map))
                             (assoc transfer-map :signature (.getBytes ^String (:signature transfer-map) "UTF-8"))
                             transfer-map)
              transfer-map (if (and (seqable? (:signature transfer-map))
                                    (every? number? (:signature transfer-map)))
                             (assoc transfer-map :signature (byte-array (map byte (:signature transfer-map))))
                             transfer-map)
              transfer-map (if (not (bytes? (:signature transfer-map)))
                             (assoc transfer-map :signature (byte-array 0))
                             transfer-map)
              transfer (account/map->Transfer transfer-map)
              ledger (or (:ledger state) {})
              sender (:sender transfer)
              sender-state (get ledger sender)]
          (if (and sender-state (account/validate-transfer sender-state transfer))
            (let [ledger-with-receiver (if (and (:receiver transfer) (not (contains? ledger (:receiver transfer))))
                                         (assoc ledger (:receiver transfer) (account/map->AccountState {:balance 0 :seq 0 :deps []}))
                                         ledger)
                  new-ledger (account/apply-transfer ledger-with-receiver transfer)]
              (assoc state :ledger new-ledger))
            state))
        (catch Exception _
          state))
      state)))

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
  (let [payload-bytes (or (:payload event) (byte-array 0))
        message-id (:message-id event)
        state-with-applied-ledger (apply-payload-to-ledger state payload-bytes)]
    {:state state-with-applied-ledger
     :commands [{:type :app-event :event-name :on-deliver
                 :payload (:payload event) :message-id message-id}]}))

(defn- handle-signaling-burn
  "Handles a direct signaling burn event, deducting burn from the sender's account
   and incrementing the epoch's burn accumulator."
  [state event]
  (let [sender (:sender event)
        burn-amt (or (:burn event) (:burn-amount event) burn/min-signaling-burn)
        ledger (or (:ledger state) {})
        res (burn/deduct-signaling-burn ledger sender burn-amt)]
    (if res
      (let [current-epoch (or (:epoch state) 0)]
        {:state (-> state
                    (assoc :ledger (:ledger res))
                    (update-in [:epoch-burns current-epoch] (fnil + 0) (:burn-amount res)))
         :commands []})
      {:state state :commands []})))

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
    (reduce (fn [acc mid]
              (conj acc [mid (get local-frozen-roles-map mid :gossip)]))
            []
            candidate-ids)))

(defn- resolve-counterparty-frozen-ids
  "Resolves counterparty frozen message IDs for transcript submission.
   Enforces cryptographic verification of :counterparty-frozen-log.
   Rejects submission if unauthenticated counterparty IDs are provided,
   or if the signed log is invalid / mismatched.
   Returns {:ok? true :ids ids} or {:ok? false}."
  [event transcript state]
  (let [has-raw? (or (contains? event :counterparty-frozen-ids)
                     (contains? event :peer-frozen-ids))
        cp-log (or (:counterparty-frozen-log event)
                   (:peer-frozen-log event))]
    (cond
      (and has-raw? (nil? cp-log))
      {:ok? false}

      (some? cp-log)
      (let [epoch (:epoch transcript)
            node-pub (:node-pubkey state)
            pa (:peer-a transcript)
            pb (:peer-b transcript)
            expected-cp (if (= node-pub pb) pa pb)]
        (if (and (attestation/verify-frozen-log cp-log)
                 (= epoch (:epoch cp-log))
                 (= expected-cp (:peer cp-log)))
          {:ok? true :ids (set (:frozen-ids cp-log))}
          {:ok? false}))

      :else
      {:ok? true :ids (get-in state [:frozen-epoch-messages (:epoch transcript)] #{})})))

(defn- handle-submit-transcript
  "Handles bilateral transcript submission and dispute resolution.
   Evaluates the transcript against the frozen epoch message set,
   and records faults in :fault-strikes if a counterparty has faulted."
  [state event]
  (let [transcript (or (:transcript event) (:payload event) event)
        resolved-cp (resolve-counterparty-frozen-ids event transcript state)]
    (if-not (:ok? resolved-cp)
      {:state state :commands []}
      (let [epoch (:epoch transcript)
            local-frozen-ids (get-in state [:frozen-epoch-messages epoch] #{})
            counterparty-frozen-ids (:ids resolved-cp)
            local-frozen-roles-map (get-in state [:frozen-epoch-message-roles epoch] {})
            auth-roles (derive-authoritative-roles local-frozen-ids local-frozen-roles-map)
            frozen-log-roles (attestation/reconcile-message-roles
                              local-frozen-ids
                              counterparty-frozen-ids
                              auth-roles)
            dispute-res (attestation/evaluate-transcript-dispute transcript frozen-log-roles)
            strike-peer (:strike dispute-res)
            new-strikes (if strike-peer
                          (update (or (:fault-strikes state) {}) strike-peer (fnil inc 0))
                          (or (:fault-strikes state) {}))]
        {:state (assoc state :fault-strikes new-strikes)
         :commands []}))))

(defn- handle-register-home-set
  "Registers a home set of nodes for Callee B for an epoch.
   Enforces fixed price p_B per (callee, epoch): mid-epoch re-registration
   at a different price is rejected unless targeting a new epoch."
  [state event]
  (let [callee (:callee event)
        epoch (or (:epoch event) (:epoch state) 0)
        candidates (or (:candidates event) [])
        p-b (or (:price event) (:p-b event) 0)
        p-b-max (or (:price-max event) (:p-b-max event) p-b)
        tuple [callee epoch]
        existing (get-in state [:home-sets tuple])]
    (if (and existing (some? (:price existing)) (not= (:price existing) p-b))
      {:state state :commands []}
      (let [reg-result (rendezvous/register-home-set candidates p-b p-b-max)]
        {:state (assoc-in state [:home-sets tuple] reg-result)
         :commands []}))))

(defn- node-in-home-set?
  "Checks if a home-node is present in the registered home set."
  [home-node home-set]
  (let [nodes (:home-nodes home-set)]
    (boolean
     (some (fn [n]
             (let [id (cond
                        (map? n) (or (:node-id n) (:pubkey n) (:id n) (:address n))
                        :else n)]
               (= id home-node)))
           nodes))))

(defn- handle-receive-offer-header
  "Processes an incoming offer header, validating home set membership and
   sequence monotonicity, and appending the generated DeliveryAck to pending vouchers.
   Rejects offer header if callee is absent from ledger or underfunded for cumulative debit."
  [state event]
  (let [callee (:callee event)
        home-node (:home-node event)
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
            callee-bal (or (get-in state [:ledger callee :balance]) 0)]
        (if (< callee-bal cum-debit)
          {:state state :commands []}
          (let [offer-ctx (assoc event
                                 :last-seq last-seq
                                 :p-b price
                                 :cumulative-debit cum-debit
                                 :epoch current-epoch)
                res (rendezvous/process-offer-header offer-ctx)]
            (if (= :ok (:status res))
              {:state (-> state
                          (assoc-in [:voucher-seqs tuple] seq-num)
                          (update :pending-vouchers (fnil conj []) (:delivery-ack res)))
               :commands []}
              {:state state :commands []})))))))

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
        payer-hex (when payer (if (string? payer) payer (basalt/bytes->hex payer)))
        receiver-hex (when receiver (if (string? receiver) receiver (basalt/bytes->hex receiver)))
        payer-acct (when payer-hex (get-in state [:ledger payer-hex]))
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
      {:state state :commands []})))

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
    :receive-propose (streamlet/handle-streamlet-event state event)
    :receive-vote (streamlet/handle-streamlet-event state event)
    :on-deliver (handle-on-deliver state event)
    {:state state :commands []}))