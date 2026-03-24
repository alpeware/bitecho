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
     - G (murmur-k) ≈ O(log N)")

;; ---------------------------------------------------------------------------
;; Defaults (suitable for small networks, N ≈ 10–50)
;; ---------------------------------------------------------------------------

(def default-config
  "Default protocol parameters for small / test networks."
  {;; Murmur — epidemic gossip fanout (G in the paper)
   :murmur-k              5
   ;; Maximum number of seen message IDs kept in the Murmur cache
   :murmur-max-cache-size 1000
   ;; Basalt — maximum peer-view slots
   :basalt-max-view-size  20
   ;; Epochs before a gossip message expires from all caches
   :gossip-ttl-epochs     10

   ;; Sieve Echo sample (E, Ê)
   :echo-sample-size      10
   :echo-threshold        7

   ;; Contagion Ready sample (R, R̂)
   :ready-sample-size     10
   :ready-threshold       3

   ;; Contagion Delivery sample (D, D̂)
   :delivery-sample-size  10
   :delivery-threshold    8})

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
;; Constructor
;; ---------------------------------------------------------------------------

(defn make-config
  "Returns `default-config` with any keys in `overrides` merged on top."
  ([] default-config)
  ([overrides] (merge default-config overrides)))
