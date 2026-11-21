(ns bitecho.config
  "Central configuration for the Bitecho protocol stack.

   All protocol parameters (Basalt, Murmur, Sieve, Contagion) are defined here
   as data maps.  Callers pass a config map into `state-machine/init-state`;
   handlers read values from `(:config state)`.

   Per the Contagion paper (Section 5), sample sizes scale with O(log N):
     - E, R, D  ≈  c · ln(N)   for a security parameter c
     - Ê ≈ 0.7 · E   (echo threshold)
     - R̂ ≈ 0.3 · R   (ready threshold — low to ensure contagion spread)
     - D̂ ≈ 0.8 · D   (delivery threshold — high for safety)
     - G (murmur-k) ≈ O(log N)"
  (:require [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; Protocol Release Version & Sunsets (Milestone D29 / BIP-003)
;; ---------------------------------------------------------------------------

(def version
  "Current protocol and release milestone version."
  "0.23.20")

(def ratified-theta-star
  "Selected Monte Carlo Tokenomics v2.1 Pareto-optimal parameter vector (`BIP-009` / `P-DEPLOY-9`)."
  {:k-bps 5000
   :treasury-trailing-epochs 168
   :settlement-take-bps 50
   :streamlet-share-pct 20
   :min-node-stake 250000
   :max-stake-multiplier 4.0
   :min-signaling-burn 100
   :bootstrap-sunset-epoch 26280
   :bootstrap-drawdown-lambda 0.0001})

(def ratified-theta-star-metrics
  "Recorded Monte Carlo v2.1 Pareto frontier metrics for `ratified-theta-star` (`BIP-009` / `P-DEPLOY-9`)."
  {:pareto-optimal? true
   :candidate-id "theta-0"
   :seed 1795112000
   :gini-median 0.142
   :insolvency-rate 0.0
   :signaling-grief-cost-ratio 1.0
   :supply-conserved? true})

(def infra-cold-root-pubkey
  "Pinned Cold Offline Infra Root Ed25519 public key (HEX) for on-network artifact attestation."
  "302a300506032b6570032100d88b92f094f65be1d32c8c1fb6c85f7913458a99ebdc142009ab2f18fd1bf641")

(def legacy-unbound-offer-hash-sunset
  "Sunset ISO timestamp after which unbound offer hashes (|net:<uri> missing) are strictly rejected."
  "2026-12-31")

;; ---------------------------------------------------------------------------
;; Network URI Registry & Root Subnet Equivalence (Milestone D23)
;; ---------------------------------------------------------------------------

(def network-uris
  "Canonical root network URIs for Devnet, Testnet, and Mainnet."
  {:devnet  "devnet.bitecho.org"
   :testnet "testnet.bitecho.org"
   :mainnet "mainnet.bitecho.org"})

(defn resolve-network-uri
  "Resolves a network keyword (:devnet, :testnet, :mainnet), URI string, or config map
   to its canonical network URI string (or nil if unspecified).
   Returns nil for generic subnet aliases ('global', 'validator-core')."
  [x]
  (cond
    (string? x) (let [s (when-not (str/blank? x) (str/trim x))]
                  (when-not (or (= s "global") (= s "validator-core"))
                    s))
    (keyword? x) (get network-uris x)
    (map? x) (or (resolve-network-uri (:network-uri x))
                 (resolve-network-uri (:network x))
                 (resolve-network-uri (get-in x [:cluster :network-uri]))
                 (resolve-network-uri (get-in x [:cluster :network]))
                 (resolve-network-uri (get-in x [:protocol :network-uri]))
                 (resolve-network-uri (get-in x [:protocol :network])))
    :else nil))

(def root-subnet-ids
  "Set of recognized root subnet identifiers (legacy 'global' / 'validator-core' plus network URIs)."
  #{"devnet.bitecho.org"
    "testnet.bitecho.org"
    "mainnet.bitecho.org"
    "bitecho.org"
    "global"
    "validator-core"})

(defn root-subnet-id?
  "Returns true if sid is a recognized root subnet identifier."
  [sid]
  (contains? root-subnet-ids (str sid)))

(defn equivalent-subnet-id?
  "Returns true if subnet identifiers s1 and s2 refer to the same subnet.
   During N/N+1 rolling upgrades, legacy 'global' is equivalent to the active
   network's root URI (e.g. 'devnet.bitecho.org'), while distinct explicit
   network URIs ('devnet.bitecho.org' vs 'testnet.bitecho.org' vs 'mainnet.bitecho.org')
   are NEVER equivalent."
  ([s1 s2]
   (equivalent-subnet-id? s1 s2 "devnet.bitecho.org"))
  ([s1 s2 active-network-uri]
   (let [a (str (or s1 "global"))
         b (str (or s2 "global"))
         net-uri (str (or (resolve-network-uri active-network-uri) "devnet.bitecho.org"))
         active-roots (cond-> #{"global" net-uri}
                        (contains? #{"devnet.bitecho.org" "bitecho.org"} net-uri)
                        (into ["devnet.bitecho.org" "bitecho.org"]))]
     (or (= a "*")
         (= b "*")
         (= a b)
         (and (contains? active-roots a)
              (contains? active-roots b))))))

;; ---------------------------------------------------------------------------
;; Defaults (suitable for small networks, N ≈ 10–50)
;; ---------------------------------------------------------------------------

(def default-config
  "Default protocol parameters for small / test networks."
  {;; Genesis ledger (hex pubkey -> AccountState)
   :genesis-ledger        {}
   ;; Treasury / Tokenomics parameters
   :epoch-length-ms       3600000
   :tick-interval-ms      3600000
   :treasury-trailing-epochs 168
   :min-node-stake        250000
   :bootstrap-sunset-epoch 26280
   :settlement-take-bps   50
   :economy-enabled?      true
   :burn-floor            100
   :k-bps                 5000
   :streamlet-share-pct   20
   :max-stake-multiplier  4.0
   :bootstrap-drawdown-lambda 0.0001
   :policy-theta          ratified-theta-star
   ;; Murmur — epidemic gossip fanout (G in the paper)
   :murmur-k              5
   ;; Maximum number of seen message IDs kept in the Murmur cache
   :murmur-max-cache-size 1000
   ;; Basalt — maximum peer-view slots
   :basalt-max-view-size  20
   ;; Epochs before a gossip message expires from all caches
   :gossip-ttl-epochs     10
   ;; Trailing epoch window for Contagion anti-entropy summaries (P-CONTAG-4)
   :contagion-summary-window-epochs 16
   ;; Epochs before a frozen log message snapshot is evicted (7 days of 1-hour epochs)
   :frozen-log-retention-epochs 168

   ;; Sieve Echo sample (E, Ê)
   :echo-sample-size      10
   :echo-threshold        7

   ;; Contagion Ready sample (R, R̂)
   :ready-sample-size     10
   :ready-threshold       3

   ;; Contagion Delivery sample (D, D̂)
   :delivery-sample-size  10
   :delivery-threshold    8

   ;; Sieve / Contagion signed control frames
   :require-signed-control-frames true
   ;; Streamlet ancestor sync & propose wire budget (H-2)
   :max-ancestor-sync-depth       16
   :max-propose-wire-bytes        32768
   :max-receipts-per-block        32
   ;; TURN relay configuration (host, port, credentials, force-relay)
   :turn-config                  nil})

;; ---------------------------------------------------------------------------
;; Large-network preset (N ≈ 1000, up to 25 % Byzantine)
;; ---------------------------------------------------------------------------

(def large-network-config
  "Protocol parameters tuned for N ≈ 1000 per the Contagion paper.
   Sample sizes ≈ 3 · ln(1000) ≈ 21.
   Thresholds derived from recommended ratios in Section 5."
  (merge default-config
         {:murmur-k              10
          :basalt-max-view-size   40
          :gossip-ttl-epochs      20
          :echo-sample-size       21
          :echo-threshold         15
          :ready-sample-size      21
          :ready-threshold        7
          :delivery-sample-size   21
          :delivery-threshold     17}))

;; ---------------------------------------------------------------------------
;; Genesis Devnet preset (3-node cluster, N = 3)
;; ---------------------------------------------------------------------------

(def devnet-config
  "Protocol parameters tuned for the 3-node Genesis Devnet cluster (N = 3)."
  (merge default-config
         {:network              :devnet
          :network-uri          "devnet.bitecho.org"
          :epoch-length-ms      10000
          :tick-interval-ms     10000
          :murmur-k             2
          :basalt-max-view-size 10
          :echo-sample-size     2
          :echo-threshold       2
          :ready-sample-size    2
          :ready-threshold      1
          :delivery-sample-size 2
          :delivery-threshold   2}))

;; ---------------------------------------------------------------------------
;; Unified 6-Validator Devnet preset (N = 6, quorum = 4)
;; ---------------------------------------------------------------------------

(def devnet-6-nodes
  "Canonical validator set for the unified 6-node Devnet mesh."
  #{:node1 :node2 :node3 :ns1 :ns2 :ns3})

(defn devnet-6-config
  "Protocol parameters tuned for the unified 6-validator mesh (N = 6, quorum = 4).
   Includes both core validators (:node1..:node3) and co-located edge infra validators (:ns1..:ns3)."
  ([]
   (devnet-6-config {}))
  ([overrides]
   (merge default-config
          {:network              :devnet
           :network-uri          "devnet.bitecho.org"
           :nodes                devnet-6-nodes
           :validator-count      6
           :quorum-threshold     4
           :epoch-length-ms      10000
           :tick-interval-ms     10000
           :murmur-k             5
           :basalt-max-view-size 10
           :echo-sample-size     5
           :echo-threshold       4
           :ready-sample-size    5
           :ready-threshold      2
           :delivery-sample-size 5
           :delivery-threshold   4}
          overrides)))

;; ---------------------------------------------------------------------------
;; Testnet & Mainnet presets (Milestone D23 — BIP-001 Tokenomics v2.2 defaults)
;; ---------------------------------------------------------------------------

(def testnet-config
  "Protocol parameters tuned for Testnet (testnet.bitecho.org) with BIP-001 Tokenomics v2.2 parameters."
  (merge (devnet-6-config)
         {:network                  :testnet
          :network-uri              "testnet.bitecho.org"
          :subnet-id                "testnet.bitecho.org"
          :settlement-take-bps      150
          :treasury-trailing-epochs 336
          :burn-floor               50}))

(def mainnet-config
  "Protocol parameters tuned for Mainnet (mainnet.bitecho.org) with BIP-001 Tokenomics v2.2 parameters
   and strict-network-uri? replay protection enabled."
  (merge default-config
         {:network                  :mainnet
          :network-uri              "mainnet.bitecho.org"
          :subnet-id                "mainnet.bitecho.org"
          :strict-network-uri?      true
          :settlement-take-bps      150
          :treasury-trailing-epochs 336
          :burn-floor               50}))

;; ---------------------------------------------------------------------------
;; Constructor
;; ---------------------------------------------------------------------------

(defn make-config
  "Returns `default-config` with any keys in `overrides` merged on top."
  ([] default-config)
  ([overrides] (merge default-config overrides)))
