(ns bitecho.circles.mc-harness
  "Pure Sans-IO Deterministic Monte Carlo CRN & Time-Compression Harness for BIP-024 (§3.2.2).

   Eliminates all wall-clock and unseeded randomness by injecting `crypto/fork-random`
   and explicit epoch clocks, consistently scaling all epoch constants by
   `:time-compression-factor C` and verifying 7-bucket `INV-C1` conservation on every step."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.circles.vault :as vault]
            [bitecho.config :as config]
            [bitecho.core.circle :as circle]
            [bitecho.core.protocol.faucet :as faucet]
            [bitecho.crypto :as crypto]
            [bitecho.economy.puzzle :as puzzle]))

(defn scale-epoch-constant
  "Consistently scales a positive epoch constant by `compression-factor` C >= 1 (rounding to nearest >= 1)."
  [val compression-factor]
  (let [c (max 1 (long (or compression-factor 1)))
        v (long (or val 1))]
    (max 1 (long (Math/round (/ (double v) (double c)))))))

(defn scale-lifecycle-config
  "Consistently scales all epoch-denominated constants in `theta` / lifecycle config
   by `:time-compression-factor C` (BIP-024 §3.2.2 item 3)."
  [theta compression-factor]
  (let [c (max 1 (long (or compression-factor 1)))
        base (merge config/ratified-theta-star
                    {:descriptor-ttl-epochs 26280
                     :validator-activation-lead-epochs 6}
                    theta)]
    (-> base
        (assoc :time-compression-factor c)
        (update :bootstrap-sunset-epoch scale-epoch-constant c)
        (update :treasury-trailing-epochs scale-epoch-constant c)
        (update :descriptor-ttl-epochs scale-epoch-constant c)
        (update :validator-activation-lead-epochs #(max 3 (scale-epoch-constant % c)))
        (update :bootstrap-drawdown-lambda
                (fn [lam]
                  (let [l (double (or lam 0.0001))]
                    (cond
                      (<= l 0.0) 0.0
                      (>= l 1.0) 1.0
                      :else (- 1.0 #?(:clj (Math/pow (- 1.0 l) (double c))
                                      :cljs (js/Math.pow (- 1.0 l) (double c)))))))))))

(defn- deterministic-spki-hex
  "Deterministically derives a synthetic valid 88-char SPKI hex identifier from `rng`."
  [rng]
  (let [hex-chars "0123456789abcdef"
        body (apply str (repeatedly 64 #(nth hex-chars (crypto/next-int rng 16))))]
    (str circle/spki-ed25519-prefix body)))

(defn run-circle-mc-scenario
  "Runs a deterministic CRN Circle + Vault + Faucet Monte Carlo scenario (BIP-024 §3.2.2).
   Bit-identical outputs for identical `{:seed :epochs :time-compression-factor ...}`.
   Asserts 7-bucket `INV-C1` conservation on every epoch step."
  [{:keys [seed epochs time-compression-factor genesis-custody-supply faucet-drip-ech theta]
    :or {seed 20261124
         epochs 20
         time-compression-factor 1
         genesis-custody-supply 10000000
         faucet-drip-ech 1000}}]
  (let [master-rng (crypto/make-random (long seed))
        scaled-theta (scale-lifecycle-config theta time-compression-factor)
        net-uri "devnet.bitecho.org"
        gen-cid "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        root-kp (crypto/generate-keypair (crypto/fork-random master-rng "root-pk"))
        root-pk (circle/normalize-spki-pubkey (basalt/bytes->hex (:public root-kp)))
        root-ms {:threshold 1 :pubkeys [root-pk]}
        p-src (vault/canonical-multisig-treasury-puzzle-source 1 [root-pk])
        p-hash (puzzle/puzzle-cid p-src)
        inc-bal (quot (long genesis-custody-supply) 2)
        boot-bal (- (long genesis-custody-supply) inc-bal)
        vst0 (assoc (vault/init-vaults-state {:network-uri net-uri
                                              :network-genesis-cid gen-cid
                                              :genesis-custody-supply (long genesis-custody-supply)
                                              :root-unallocated (long genesis-custody-supply)
                                              :bootstrap-sunset-epoch (:bootstrap-sunset-epoch scaled-theta)
                                              :settlement-take-bps (:settlement-take-bps scaled-theta)
                                              :chartered-vaults #{"vault:root" "vault:root/inc"}})
                    :root-owner-multisig root-ms)
        sign-root (fn [tuple] {root-pk (basalt/bytes->hex (crypto/sign-canonical (:private root-kp) tuple))})
        v1-params {:vault-id "vault:root"
                   :entity-uri (str net-uri "/root")
                   :custody-bucket :bootstrap
                   :puzzle-hash p-hash
                   :balance boot-bal
                   :created-epoch 0
                   :funding-source :root-unallocated}
        v1-sig (sign-root (vault/vault-create-signing-tuple (assoc v1-params :network-uri net-uri :network-genesis-cid gen-cid)))
        v1 (:state (vault/create-vault vst0 (assoc v1-params :root-signatures v1-sig)))
        v2-params {:vault-id "vault:root/inc"
                   :entity-uri (str net-uri "/root/inc")
                   :custody-bucket :ecosystem
                   :puzzle-hash p-hash
                   :balance inc-bal
                   :created-epoch 0
                   :funding-source :root-unallocated}
        v2-sig (sign-root (vault/vault-create-signing-tuple (assoc v2-params :network-uri net-uri :network-genesis-cid gen-cid)))
        v2 (:state (vault/create-vault v1 (assoc v2-params :root-signatures v2-sig)))
        dac-params {:dac-id "faucet-dac"
                    :vault-id "vault:root/inc"
                    :holder-pubkey root-pk
                    :max-per-epoch-bps 500
                    :issued-epoch 0
                    :expires-epoch (+ (long epochs) 100)}
        dac-sig (sign-root (vault/dac-issue-signing-tuple (assoc dac-params :network-uri net-uri :network-genesis-cid gen-cid)))
        v3 (:state (vault/issue-vault-spend-dac v2 (assoc dac-params :root-signatures dac-sig)))
        fst0 (faucet/init-faucet-state {:network-uri net-uri
                                        :network-genesis-cid gen-cid
                                        :drip-amount-ech (long faucet-drip-ech)
                                        :epoch-drip-cap-ech (* 10 (long faucet-drip-ech))})]
    (loop [ep 1
           vst v3
           fst fst0
           drips 0
           all-conserved? true
           nonces []]
      (if (> ep (long epochs))
        {:seed (long seed)
         :epochs (long epochs)
         :scaled-theta scaled-theta
         :total-drips drips
         :all-steps-conserved? all-conserved?
         :sample-nonces nonces
         :final-conservation (vault/verify-7-bucket-conservation vst)
         :final-root-balance (get-in vst [:vaults "vault:root" :balance])
         :final-inc-balance (get-in vst [:vaults "vault:root/inc" :balance])
         :sunset-burned (:sunset-custody-burned vst)}
        (let [ep-rng (crypto/fork-random master-rng (str "faucet-path-" ep))
              ch-res (faucet/issue-faucet-challenge fst {:network-uri net-uri :rng ep-rng} (* ep 10000))
              nonce (get-in ch-res [:challenge :nonce])
              claimant-pk (deterministic-spki-hex ep-rng)
              dac-spend-tuple (vault/dac-spend-signing-tuple {:network-uri net-uri
                                                              :network-genesis-cid gen-cid
                                                              :dac-id "faucet-dac"
                                                              :vault-id "vault:root/inc"
                                                              :receiver claimant-pk
                                                              :amount (long faucet-drip-ech)
                                                              :epoch ep})
              dac-spend-sig (basalt/bytes->hex (crypto/sign-canonical (:private root-kp) dac-spend-tuple))
              dac-res (vault/spend-via-vault-dac vst {:dac-id "faucet-dac"
                                                      :receiver claimant-pk
                                                      :amount (long faucet-drip-ech)
                                                      :epoch ep
                                                      :signature dac-spend-sig})
              vst-after-drip (if (:ok? dac-res) (:state dac-res) vst)
              sunset-res (vault/apply-bootstrap-sunset vst-after-drip ep)
              vst-next (:state sunset-res)
              cons-ok? (:ok? (vault/verify-7-bucket-conservation vst-next))]
          (recur (inc ep)
                 vst-next
                 (:state ch-res)
                 (if (:ok? dac-res) (inc drips) drips)
                 (and all-conserved? cons-ok?)
                 (conj nonces nonce)))))))
