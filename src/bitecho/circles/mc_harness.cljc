(ns bitecho.circles.mc-harness
  "Pure Sans-IO Deterministic Monte Carlo CRN & Time-Compression Harness for BIP-024 (§3.2.2).

   Eliminates all wall-clock and unseeded randomness by injecting `crypto/fork-random`
   and explicit epoch clocks, consistently scaling all epoch constants by
   `:time-compression-factor C` and verifying 7-bucket `INV-C1` conservation on every step."
  (:require [bitecho.circles.vault :as vault]
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
        (update :validator-activation-lead-epochs #(max 1 (scale-epoch-constant % c)))
        (update :bootstrap-drawdown-lambda #(* (double (or % 0.0001)) (double c))))))

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
        root-pk (deterministic-spki-hex (crypto/fork-random master-rng "root-pk"))
        p-src (vault/canonical-multisig-treasury-puzzle-source 1 [root-pk])
        p-hash (puzzle/puzzle-cid p-src)
        inc-bal (quot (long genesis-custody-supply) 2)
        boot-bal (- (long genesis-custody-supply) inc-bal)
        vst0 (vault/init-vaults-state {:network-uri net-uri
                                       :network-genesis-cid gen-cid
                                       :genesis-custody-supply (long genesis-custody-supply)
                                       :bootstrap-sunset-epoch (:bootstrap-sunset-epoch scaled-theta)
                                       :settlement-take-bps (:settlement-take-bps scaled-theta)
                                       :chartered-vaults #{"vault:root" "vault:root/inc"}})
        v1 (:state (vault/create-vault vst0 {:vault-id "vault:root"
                                             :entity-uri (str net-uri "/root")
                                             :custody-bucket :bootstrap
                                             :puzzle-hash p-hash
                                             :balance boot-bal
                                             :created-epoch 0}))
        v2 (:state (vault/create-vault v1 {:vault-id "vault:root/inc"
                                           :entity-uri (str net-uri "/root/inc")
                                           :custody-bucket :ecosystem
                                           :puzzle-hash p-hash
                                           :balance inc-bal
                                           :created-epoch 0}))
        v3 (:state (vault/issue-vault-spend-dac v2 {:dac-id "faucet-dac"
                                                    :vault-id "vault:root/inc"
                                                    :holder-pubkey root-pk
                                                    :max-per-epoch-bps 500
                                                    :issued-epoch 0
                                                    :expires-epoch (+ (long epochs) 100)}))
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
              dac-res (vault/spend-via-vault-dac vst {:dac-id "faucet-dac"
                                                      :receiver claimant-pk
                                                      :amount (long faucet-drip-ech)
                                                      :epoch ep})
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
