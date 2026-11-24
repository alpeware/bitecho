(ns bitecho.circles.vault
  "Pure Sans-IO Persistent Circle Vaults, Anti-Malleability Spend Digest,
   Dedicated `:vault-spend-dac` With Atomic Revocation & Full 7-Bucket `INV-C1` (BIP-024 §2.8.2).

   Strictly adheres to AGENTS.md Rule 2 (Pure Functions / Sans-IO) and Rule 5 (Zero Silent Failures)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.circle :as circle]
            [bitecho.crypto :as crypto]
            [bitecho.economy.escrow :as escrow]
            [bitecho.economy.puzzle :as puzzle]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def max-supply-cap-ech
  "Absolute 42B ECHO supply conservation cap (`INV-C1`)."
  42000000000)

(def default-max-vaults
  "Default maximum number of concurrent persistent vaults (`BIP-024 §2.8.2`)."
  4096)

(def default-min-vault-balance-ech
  "Default minimum balance dust floor (1,000 ECHO) for TTL-exempt persistent vaults."
  1000)

(def default-max-dac-spend-per-epoch-bps
  "Default per-epoch `:vault-spend-dac` cap (500 bps = 5% of vault balance per epoch)."
  500)

(def default-settlement-take-bps
  "Non-waivable commercial `:release` settlement take (50 bps)."
  50)

(def default-bootstrap-sunset-epoch
  "Epoch 26,280 sunset burning strictly unspent `:custody-bucket :bootstrap` balances."
  26280)

(defn- diag-fail
  ([state reason]
   (diag-fail state reason {}))
  ([state reason detail]
   {:ok? false
    :error reason
    :state (update-in state [:diagnostics reason] (fnil inc 0))
    :effects [(merge {:effect :diagnose :reason reason} detail)]}))

(defn treasury-spend-digest-tuple
  "Returns the domain-separated Canonical Fressian tuple for a persistent vault spend (BIP-024 §2.8.2):
   [\"bitecho-treasury-spend-v1\" network-uri network-genesis-cid vault-id puzzle-hash vault-seq outputs-hash]."
  [{:keys [network-uri network-genesis-cid vault-id puzzle-hash vault-seq outputs next-puzzle-hash]}]
  (let [outputs-hash (str/lower-case
                      (basalt/bytes->hex
                       (crypto/sha256
                        (fressian/encode-canonical {:outputs (vec (or outputs []))
                                                    :next-puzzle-hash (str/lower-case (str next-puzzle-hash))}))))]
    ["bitecho-treasury-spend-v1"
     (str network-uri)
     (str/lower-case (str network-genesis-cid))
     (str vault-id)
     (str/lower-case (str puzzle-hash))
     (long vault-seq)
     outputs-hash]))

(defn treasury-spend-digest
  "Returns the Canonical Fressian bytes of `treasury-spend-digest-tuple` for signing/verification."
  [params]
  (fressian/encode-canonical (treasury-spend-digest-tuple params)))

(defn canonical-multisig-treasury-puzzle-source
  "Returns a canonical SCI multisig treasury puzzle source for `threshold`-of-`pubkeys`
   that verifies `>= threshold` distinct canonical 88-char SPKI signatures over the full
   anti-malleability spend digest bound to `outputs`, `next-puzzle-hash`, `vault-id`,
   `puzzle-hash`, `vault-seq`, `network-uri`, and `network-genesis-cid`."
  [threshold pubkeys]
  (let [canon-pks (circle/dedup-spki-pubkeys pubkeys)
        k (long threshold)]
    (pr-str
     (list 'fn ['env 'solution]
           (list 'let ['allowed (set canon-pks)
                       'sigs (list 'or (list :signatures 'solution) {})
                       'digest (list :spend-digest 'env)
                       'outputs (list :outputs 'solution)
                       'valid-signers (list 'distinct
                                            (list 'filter
                                                  (list 'fn ['pk]
                                                        (list 'and
                                                              (list 'contains? 'allowed 'pk)
                                                              (list 'let ['s (list 'get 'sigs 'pk)]
                                                                    (list 'and
                                                                          (list 'string? 's)
                                                                          (list 'verify-sig 'pk 'digest 's)))))
                                                  (list 'keys 'sigs)))]
                 (list 'if (list '>= (list 'count 'valid-signers) k)
                       'outputs
                       false))))))

(defn init-vaults-state
  "Initializes pure Sans-IO persistent vaults & 7-bucket conservation state."
  ([] (init-vaults-state {}))
  ([opts]
   {:network-uri            (or (:network-uri opts) "devnet.bitecho.org")
    :network-genesis-cid    (or (:network-genesis-cid opts) "")
    :max-vaults             (long (or (:max-vaults opts) default-max-vaults))
    :min-vault-balance-ech  (long (or (:min-vault-balance-ech opts) default-min-vault-balance-ech))
    :settlement-take-bps    (long (or (:settlement-take-bps opts) default-settlement-take-bps))
    :bootstrap-sunset-epoch (long (or (:bootstrap-sunset-epoch opts) default-bootstrap-sunset-epoch))
    :genesis-custody-supply (long (or (:genesis-custody-supply opts) 0))
    :total-minted           (long (or (:total-minted opts) 0))
    :root-unallocated       (long (or (:root-unallocated opts) 0))
    :total-burned           (long (or (:total-burned opts) 0))
    :sunset-custody-burned  (long (or (:sunset-custody-burned opts) 0))
    :ledger                 (or (:ledger opts) {})
    :escrows                (or (:escrows opts) {})
    :bounty-escrows         (or (:bounty-escrows opts) {})
    :vaults                 (or (:vaults opts) {})
    :chartered-vaults       (set (or (:chartered-vaults opts) #{}))
    :vault-spend-dacs       (or (:vault-spend-dacs opts) {})
    :diagnostics            (or (:diagnostics opts) {})}))

(defn create-vault
  "Creates a new persistent vault in dedicated `[:vaults vault-id]` state map.
   Enforces `:max-vaults` cap and `:min-vault-balance-ech` dust floor."
  [state {:keys [vault-id entity-uri custody-bucket puzzle-hash balance created-epoch]}]
  (let [bal (long (or balance 0))
        max-v (long (or (:max-vaults state) default-max-vaults))
        min-bal (long (or (:min-vault-balance-ech state) default-min-vault-balance-ech))
        active-count (count (filter #(= :active (:status (val %))) (:vaults state)))]
    (cond
      (or (not (string? vault-id)) (str/blank? vault-id))
      (diag-fail state :invalid-vault-id)

      (contains? (:vaults state) vault-id)
      (diag-fail state :vault-already-exists {:vault-id vault-id})

      (>= active-count max-v)
      (diag-fail state :max-vaults-exceeded {:active active-count :max max-v})

      (< bal min-bal)
      (diag-fail state :vault-below-min-balance {:balance bal :min-balance min-bal})

      (not (and (string? puzzle-hash) (re-matches #"[0-9a-f]{64}" (str/lower-case (str/trim puzzle-hash)))))
      (diag-fail state :invalid-vault-puzzle-hash)

      (not (contains? circle/valid-custody-buckets custody-bucket))
      (diag-fail state :invalid-custody-bucket)

      :else
      (let [entry {:vault-id vault-id
                   :entity-uri (str entity-uri)
                   :custody-bucket custody-bucket
                   :puzzle-hash (str/lower-case (str/trim puzzle-hash))
                   :balance bal
                   :vault-seq 1
                   :created-epoch (long (or created-epoch 0))
                   :status :active}]
        {:ok? true
         :vault entry
         :state (assoc-in state [:vaults vault-id] entry)
         :effects []}))))

(defn reject-vault-refund
  "BIP-024 §2.8.2 (MUT-10): `:refund-intent` is unconditionally forbidden on persistent vaults."
  [state vault-id]
  (diag-fail state :vault-refund-forbidden {:vault-id vault-id}))

(defn- revoke-dacs-for-vault
  [dacs vault-id]
  (into {}
        (map (fn [[dac-id dac]]
               [dac-id (if (= vault-id (:vault-id dac))
                         (assoc dac :revoked? true)
                         dac)]))
        (or dacs {})))

(defn spend-vault
  "Executes an in-place persistent vault spend against `[:vaults vault-id]`:
   - Matches exact `:vault-seq` and atomically increments `:vault-seq` in place.
   - Evaluates SCI puzzle in `:vault-mode? true` (forbids `:refund`/`:refund-remainder`, enforces exact conservation).
   - Restricts `0-take :allocate` strictly to Root-chartered custody-bucket vaults transferring
     into registered chartered circle vaults preserving `:custody-bucket`.
   - Charges non-waivable `:settlement-take-bps` (`50 bps`) on all `:release` outputs.
   - Atomically revokes any `:vault-spend-dac`s on `:puzzle-hash` rotation."
  [state {:keys [vault-id vault-seq puzzle-source solution epoch]}]
  (let [v (get-in state [:vaults vault-id])
        take-bps (long (or (:settlement-take-bps state) default-settlement-take-bps))
        min-bal (long (or (:min-vault-balance-ech state) default-min-vault-balance-ech))
        chartered (or (:chartered-vaults state) #{})]
    (cond
      (nil? v)
      (diag-fail state :vault-not-found {:vault-id vault-id})

      (not= :active (:status v))
      (diag-fail state :vault-not-active {:vault-id vault-id :status (:status v)})

      (not= (long (or vault-seq -1)) (long (:vault-seq v)))
      (diag-fail state :vault-seq-mismatch {:vault-id vault-id :expected (:vault-seq v) :actual vault-seq})

      :else
      (let [outputs (:outputs solution)
            next-ph (or (:next-puzzle-hash solution) (:puzzle-hash v))
            digest (treasury-spend-digest
                    {:network-uri (:network-uri state)
                     :network-genesis-cid (:network-genesis-cid state)
                     :vault-id vault-id
                     :puzzle-hash (:puzzle-hash v)
                     :vault-seq (:vault-seq v)
                     :outputs outputs
                     :next-puzzle-hash next-ph})
            env-ctx {:vault-mode? true
                     :amount (:balance v)
                     :puzzle-hash (:puzzle-hash v)
                     :vault-id vault-id
                     :vault-seq (:vault-seq v)
                     :epoch (long (or epoch 0))
                     :spend-digest digest}
            eval-res (puzzle/eval-puzzle puzzle-source solution env-ctx)]
        (if-not (:valid? eval-res)
          (diag-fail state (or (:error eval-res) :vault-puzzle-rejected) {:vault-id vault-id})
          (let [conds (:conditions eval-res)
                relocks (filter #(= :relock (:type %)) conds)
                allocs (filter #(= :allocate (:type %)) conds)
                releases (filter #(= :release (:type %)) conds)
                relock-amt (reduce + 0 (map (comp long :amount) relocks))
                next-puzzle-hash (or (:next-puzzle-hash (first relocks)) (:puzzle-hash v))
                alloc-valid? (every? (fn [a]
                                       (let [tid (:target-vault-id a)
                                             tv (get-in state [:vaults tid])]
                                         (and (contains? chartered vault-id)
                                              (some? (:custody-bucket v))
                                              (contains? chartered tid)
                                              (some? tv)
                                              (= :active (:status tv)))))
                                     allocs)]
            (cond
              (> (count relocks) 1)
              (diag-fail state :multiple-relock-conditions {:vault-id vault-id})

              (and (pos? relock-amt) (< relock-amt min-bal))
              (diag-fail state :vault-relock-below-min-balance {:vault-id vault-id :relock-amount relock-amt :min-balance min-bal})

              (and (seq allocs) (not alloc-valid?))
              (diag-fail state :unauthorized-zero-take-allocate {:vault-id vault-id})

              :else
              (let [;; Apply commercial :release outputs (always paying non-waivable settlement-take-bps)
                    rel-applied (reduce (fn [acc r]
                                          (let [amt (long (:amount r))
                                                take-amt (escrow/calculate-escrow-settlement-take amt take-bps)
                                                net-amt (- amt take-amt)
                                                rec (or (circle/normalize-spki-pubkey (:receiver r)) (:receiver r))]
                                            (-> acc
                                                (update-in [:ledger rec :balance] (fnil + 0) net-amt)
                                                (update :total-burned (fnil + 0) take-amt))))
                                        state
                                        releases)
                    ;; Apply chartered 0-take :allocate outputs preserving :custody-bucket
                    alloc-applied (reduce (fn [acc a]
                                            (let [tid (:target-vault-id a)
                                                  amt (long (:amount a))]
                                              (-> acc
                                                  (update-in [:vaults tid :balance] (fnil + 0) amt)
                                                  (assoc-in [:vaults tid :custody-bucket]
                                                            (or (get-in acc [:vaults tid :custody-bucket])
                                                                (:custody-bucket v))))))
                                          rel-applied
                                          allocs)
                    rotated? (not= next-puzzle-hash (:puzzle-hash v))
                    updated-v (assoc v
                                     :balance relock-amt
                                     :vault-seq (inc (long (:vault-seq v)))
                                     :puzzle-hash next-puzzle-hash
                                     :status (if (zero? relock-amt) :closed :active))
                    st' (-> alloc-applied
                            (assoc-in [:vaults vault-id] updated-v)
                            (cond-> rotated?
                              (update :vault-spend-dacs revoke-dacs-for-vault vault-id)))]
                {:ok? true
                 :vault updated-v
                 :state st'
                 :effects []}))))))))

(defn issue-vault-spend-dac
  "Issues a dedicated `:vault-spend-dac` bounded by `:max-per-epoch-bps` (default 500 bps)."
  [state {:keys [dac-id vault-id holder-pubkey max-per-epoch-bps issued-epoch expires-epoch]}]
  (let [v (get-in state [:vaults vault-id])
        bps (long (or max-per-epoch-bps default-max-dac-spend-per-epoch-bps))
        norm-holder (circle/normalize-spki-pubkey holder-pubkey)]
    (cond
      (nil? v) (diag-fail state :vault-not-found {:vault-id vault-id})
      (not= :active (:status v)) (diag-fail state :vault-not-active {:vault-id vault-id})
      (nil? norm-holder) (diag-fail state :invalid-dac-holder-pubkey)
      (or (<= bps 0) (> bps 10000)) (diag-fail state :invalid-dac-bps)
      :else
      (let [dac {:dac-id dac-id
                 :vault-id vault-id
                 :holder-pubkey norm-holder
                 :max-per-epoch-bps bps
                 :issued-epoch (long (or issued-epoch 0))
                 :expires-epoch (long (or expires-epoch 0))
                 :epoch-spent {}
                 :revoked? false}]
        {:ok? true
         :dac dac
         :state (assoc-in state [:vault-spend-dacs dac-id] dac)
         :effects []}))))

(defn revoke-vault-spend-dac
  "Atomically revokes a `:vault-spend-dac`."
  [state dac-id]
  (if-not (contains? (:vault-spend-dacs state) dac-id)
    (diag-fail state :vault-dac-not-found {:dac-id dac-id})
    {:ok? true
     :state (assoc-in state [:vault-spend-dacs dac-id :revoked?] true)
     :effects []}))

(defn spend-via-vault-dac
  "Debits a vault via a non-revoked, non-expired `:vault-spend-dac` within its per-epoch bps cap."
  [state {:keys [dac-id receiver amount epoch]}]
  (let [dac (get-in state [:vault-spend-dacs dac-id])
        v (when dac (get-in state [:vaults (:vault-id dac)]))
        ep (long (or epoch 0))
        amt (long (or amount 0))
        take-bps (long (or (:settlement-take-bps state) default-settlement-take-bps))]
    (cond
      (nil? dac) (diag-fail state :vault-dac-not-found {:dac-id dac-id})
      (:revoked? dac) (diag-fail state :vault-dac-revoked {:dac-id dac-id})
      (>= ep (long (:expires-epoch dac))) (diag-fail state :vault-dac-expired {:dac-id dac-id})
      (or (nil? v) (not= :active (:status v))) (diag-fail state :vault-not-active {:vault-id (:vault-id dac)})
      (<= amt 0) (diag-fail state :invalid-dac-spend-amount)
      :else
      (let [already-spent (long (get-in dac [:epoch-spent ep] 0))
            epoch-start-bal (+ (long (:balance v)) already-spent)
            epoch-cap (quot (* epoch-start-bal (long (:max-per-epoch-bps dac))) 10000)]
        (cond
          (> (+ already-spent amt) epoch-cap)
          (diag-fail state :vault-dac-epoch-cap-exceeded {:spent (+ already-spent amt) :cap epoch-cap})

          (> amt (long (:balance v)))
          (diag-fail state :insufficient-vault-balance)

          :else
          (let [take-amt (escrow/calculate-escrow-settlement-take amt take-bps)
                net-amt (- amt take-amt)
                rec (or (circle/normalize-spki-pubkey receiver) receiver)
                st' (-> state
                        (update-in [:vaults (:vault-id dac) :balance] - amt)
                        (update-in [:vault-spend-dacs dac-id :epoch-spent ep] (fnil + 0) amt)
                        (update-in [:ledger rec :balance] (fnil + 0) net-amt)
                        (update :total-burned (fnil + 0) take-amt))]
            {:ok? true :state st' :net-amount net-amt :take-amount take-amt :effects []}))))))

(defn apply-bootstrap-sunset
  "At `current-epoch >= bootstrap-sunset-epoch` (default 26,280), burns strictly unspent
   `:custody-bucket :bootstrap` vault balances into `:sunset-custody-burned` (preserving `INV-C1`)."
  [state current-epoch]
  (let [sunset-ep (long (or (:bootstrap-sunset-epoch state) default-bootstrap-sunset-epoch))]
    (if (< (long current-epoch) sunset-ep)
      {:ok? true :burned 0 :state state :effects []}
      (let [[vaults' burned]
            (reduce (fn [[vm acc-burned] [vid v]]
                      (if (and (= :bootstrap (:custody-bucket v))
                               (pos? (long (or (:balance v) 0))))
                        (let [b (long (:balance v))]
                          [(assoc vm vid (assoc v :balance 0 :status :sunset-burned))
                           (+ acc-burned b)])
                        [(assoc vm vid v) acc-burned]))
                    [{} 0]
                    (:vaults state))]
        {:ok? true
         :burned burned
         :state (-> state
                    (assoc :vaults vaults')
                    (update :sunset-custody-burned (fnil + 0) burned))
         :effects []}))))

(defn verify-7-bucket-conservation
  "Enforces the full 7-bucket 42B `INV-C1` conservation law:
   sum(liquid_ledger) + sum(escrows) + sum(bounty_escrows) + sum(vaults)
   + root_unallocated + total_burned + sunset_custody_burned
   == genesis_custody_supply + total_minted <= 42B."
  [state]
  (let [sum-bal (fn [m] (reduce + 0 (map (fn [[_ v]] (long (or (:balance v) (:amount v) 0))) (or m {}))))
        liquid (sum-bal (:ledger state))
        escrows (reduce + 0 (keep (fn [[_ e]] (when (= :locked (:status e)) (long (or (:amount e) 0)))) (or (:escrows state) {})))
        bounties (reduce + 0 (keep (fn [[_ b]] (when (= :open (:status b)) (long (or (:reward-amount b) (:amount b) 0)))) (or (:bounty-escrows state) {})))
        vaults (sum-bal (:vaults state))
        unalloc (long (or (:root-unallocated state) 0))
        burned (long (or (:total-burned state) 0))
        sunset (long (or (:sunset-custody-burned state) 0))
        lhs (+ liquid escrows bounties vaults unalloc burned sunset)
        rhs (+ (long (or (:genesis-custody-supply state) 0))
               (long (or (:total-minted state) 0)))]
    (cond
      (> rhs max-supply-cap-ech)
      {:ok? false :error :supply-cap-exceeded :lhs lhs :rhs rhs}

      (not= lhs rhs)
      {:ok? false :error :conservation-law-violated :lhs lhs :rhs rhs
       :buckets {:liquid liquid :escrows escrows :bounties bounties :vaults vaults
                 :root-unallocated unalloc :total-burned burned :sunset-custody-burned sunset}}

      :else
      {:ok? true :total-supply rhs})))
