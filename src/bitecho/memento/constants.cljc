(ns bitecho.memento.constants
  "Normative specification constants and portable binary framing helpers for
   Memento Agent Continuity (Run-2: BIP-A Rolodex, BIP-B Circles, BIP-C Memory Chain).
   Satisfies Axiom's Flag F-1: single source of truth for domain tags, pre-decode ceilings,
   walk-back depth caps, and cold-wake thresholds."
  (:require [bitecho.fressian :as fressian])
  #?(:clj (:import [java.nio ByteBuffer])))

;; =============================================================================
;; Domain Separation Tags
;; =============================================================================

(def ^:const rolodex-domain-tag
  "Ed25519 domain separation tag for BIP-A Rolodex entries."
  "bitecho/rolodex/v1")

(def ^:const memory-aead-info
  "HKDF-SHA-256 info tag for BIP-C AES-256-GCM key derivation."
  "bitecho/memento/aead/v1")

(def ^:const memory-nonce-info
  "HKDF-SHA-256 info prefix for BIP-C 12-byte GCM nonce derivation."
  "bitecho/memento/nonce/v1")

(def ^:const memory-aad-prefix
  "AEAD associated-data prefix for BIP-C memory frames."
  "bitecho/memento/aad/v1")

(def ^:const memory-genesis-prefix
  "RFC 8032 Ed25519 domain prefix for BIP-C genesis memory signature."
  "bitecho/memento/genesis/v1")

;; =============================================================================
;; Pre-Decode Ceilings & Walk-Back Limits
;; =============================================================================

(def ^:const max-blob-bytes
  "Pre-decode byte ceiling per blob (256 KiB)."
  (* 256 1024))

(def ^:const max-snapshot-bytes
  "Pre-decode byte ceiling per Rolodex snapshot (4 MiB)."
  (* 4 1024 1024))

(def ^:const default-walk-back-depth-cap
  "Default maximum link count for streaming memory chain walk-back."
  1024)

(def ^:const max-petnames
  "Hard structural cap on Rolodex petnames so state never grows unbounded."
  10000)

(def ^:const max-subnets
  "Hard structural cap on Rolodex tracked subnets."
  1024)

(def ^:const max-open-sessions
  "Hard structural cap on Rolodex tracked open sessions."
  4096)

(def ^:const min-rotation-grace-epochs
  "Hardcoded design floor (N-min = 4 epochs) for :rotate-log grace window."
  4)

(def default-cap-ceilings
  "Hardcoded safety ceilings for Rolodex tables. Signed network config may only lower these."
  {:max-petnames max-petnames
   :max-subnets max-subnets
   :max-open-sessions max-open-sessions})

(defn effective-cap
  "Deterministically enforces (min ceiling config-cap).
   Signed network config may ONLY lower a cap, never raise it above the hardcoded safety ceiling.
   Returns {:ok? true :cap <eff> :clamped? <bool> :ceiling ceiling :requested config-cap}
   or {:ok? false :code :invalid-cap-config :requested config-cap}."
  [ceiling config-cap]
  (cond
    (nil? config-cap)
    {:ok? true :cap ceiling :clamped? false :ceiling ceiling :requested nil}

    (or (not (integer? config-cap)) (not (pos? config-cap)))
    {:ok? false :code :invalid-cap-config :ceiling ceiling :requested config-cap}

    (> config-cap ceiling)
    {:ok? true :cap ceiling :clamped? true :ceiling ceiling :requested (long config-cap)}

    :else
    {:ok? true :cap (long config-cap) :clamped? false :ceiling ceiling :requested (long config-cap)}))

(defn resolve-effective-caps
  "Resolves effective caps from an optional signed network config :caps map using
   (min constant config) for :max-petnames, :max-subnets, and :max-open-sessions.
   Returns {:ok? true :effective-caps {...} :clamped [...]} or {:ok? false :code :invalid-cap-config ...}."
  [config-caps]
  (let [caps (or config-caps {})
        specs [[:max-petnames max-petnames]
               [:max-subnets max-subnets]
               [:max-open-sessions max-open-sessions]]]
    (loop [remaining specs
           eff {}
           clamped []]
      (if-let [[k ceiling] (first remaining)]
        (let [res (effective-cap ceiling (get caps k))]
          (if-not (:ok? res)
            (assoc res :table k)
            (recur (rest remaining)
                   (assoc eff k (:cap res))
                   (if (:clamped? res)
                     (conj clamped {:table k
                                    :requested (:requested res)
                                    :ceiling ceiling
                                    :effective (:cap res)})
                     clamped))))
        {:ok? true
         :effective-caps eff
         :clamped clamped}))))

(defn compute-grace-window-epochs
  "Computes operational rotation grace window: N = max(N-min, ceil(1.5 * max-sleep-epochs))."
  [max-sleep-epochs]
  (let [sleep (max 0.0 (double (or max-sleep-epochs 0)))
        scaled (long #?(:clj (Math/ceil (* 1.5 sleep))
                        :cljs (js/Math.ceil (* 1.5 sleep))))]
    (max min-rotation-grace-epochs scaled)))

(defn effective-grace-epochs
  "Enforces the hardcoded N-min = 4 epoch floor on a configured grace window."
  [config-n]
  (if (nil? config-n)
    {:grace-epochs min-rotation-grace-epochs
     :floored? false
     :floor min-rotation-grace-epochs
     :requested nil}
    (let [n (long config-n)
          floored? (< n min-rotation-grace-epochs)]
      {:grace-epochs (max min-rotation-grace-epochs n)
       :floored? floored?
       :floor min-rotation-grace-epochs
       :requested n})))

(def valid-node-roles
  "Supported node roles sharing the unified Rolodex mechanism."
  #{:light :infra})

(def valid-cache-incentives
  "Permitted bytes-at-rest cache incentive models."
  #{:free-self-hosted :upfront-fee-ech})

(def ^:const frame-header-bytes
  "Canonical memory frame header size: be64(seq) + raw32(prev-cid) + be32(len) = 44 bytes."
  (+ 8 32 4))

(def zero-cid-hex
  "64-character all-zero hex CID used as :prev-cid for genesis entries."
  (apply str (repeat 64 "0")))

;; =============================================================================
;; Pinned Cold-Wake Benchmark Thresholds
;; =============================================================================

(def cold-wake-thresholds
  "Pinned Run-2 deterministic cold-wake thresholds (10,000 Rolodex entries + 1,024 memory links)."
  {:jvm {:max-p95-ms 2000
         :max-heap-delta-mib 128
         :rolodex-entries 10000
         :memory-links 1024}
   :browser {:max-p95-ms 5000
             :max-heap-delta-mib 64
             :rolodex-entries 10000
             :memory-links 1024}})

;; =============================================================================
;; Portable Binary & CID Helpers
;; =============================================================================

(defn valid-cid64?
  "Returns true iff s is a 64-character lowercase hexadecimal CID string."
  [s]
  (boolean (and (string? s)
                (= 64 (count s))
                (re-matches #"[0-9a-f]{64}" s))))

;; =============================================================================
;; BIP-016 State Discipline Validators (Retention, Ownership, Bytes-at-Rest)
;; =============================================================================

(defn valid-retention-policy?
  "Validates that a pointer retention & rotation policy is bounded and well-formed."
  [policy]
  (boolean
   (and (map? policy)
        (integer? (:max-entries policy))
        (pos? (:max-entries policy))
        (integer? (:max-bytes policy))
        (pos? (:max-bytes policy))
        (integer? (:rotate-every-entries policy))
        (pos? (:rotate-every-entries policy))
        (<= (:rotate-every-entries policy) (:max-entries policy))
        (integer? (:ttl-epochs policy))
        (pos? (:ttl-epochs policy)))))

(defn valid-owner-pubkeys?
  "Validates that state/pointer :owner-pubkeys is a non-empty collection of non-empty strings."
  [owners]
  (boolean
   (and (coll? owners)
        (seq owners)
        (every? #(and (string? %) (boolean (seq %))) owners))))

(defn valid-storage-accounting?
  "Validates explicit bytes-at-rest accounting for every stored blob/snapshot/memory link."
  [acct]
  (boolean
   (and (map? acct)
        (integer? (:bytes-at-rest acct))
        (not (neg? (:bytes-at-rest acct)))
        (contains? valid-cache-incentives (:cache-incentive acct))
        (string? (:payer-pubkey acct))
        (boolean (seq (:payer-pubkey acct)))
        (number? (:fee-ech acct))
        (if (= :upfront-fee-ech (:cache-incentive acct))
          (pos? (:fee-ech acct))
          (zero? (:fee-ech acct))))))

(defn validate-pointer-discipline
  "Validates Simon's binding state discipline on any pointer or state descriptor.
   Returns {:ok? true} or {:ok? false :code <keyword> :detail <map>}."
  [descriptor]
  (cond
    (not (valid-owner-pubkeys? (:owner-pubkeys descriptor)))
    {:ok? false :code :missing-state-owner :detail {:owner-pubkeys (:owner-pubkeys descriptor)}}

    (not (valid-retention-policy? (:retention-policy descriptor)))
    {:ok? false :code :missing-retention-policy :detail {:retention-policy (:retention-policy descriptor)}}

    (and (contains? descriptor :storage-accounting)
         (some? (:storage-accounting descriptor))
         (not (valid-storage-accounting? (:storage-accounting descriptor))))
    {:ok? false :code :invalid-storage-accounting :detail {:storage-accounting (:storage-accounting descriptor)}}

    :else
    {:ok? true}))

(defn be64-bytes
  "Encodes a non-negative 64-bit integer as 8 big-endian bytes."
  [n]
  (let [v (long n)]
    #?(:clj (let [bb (ByteBuffer/allocate 8)]
              (.putLong bb v)
              (.array bb))
       :cljs (let [buf (js/Uint8Array. 8)
                   dv (js/DataView. (.-buffer buf))]
               (.setBigUint64 dv 0 (js/BigInt (str v)))
               buf))))

(defn be32-bytes
  "Encodes a non-negative 32-bit integer as 4 big-endian bytes."
  [n]
  (let [v (int n)]
    #?(:clj (let [bb (ByteBuffer/allocate 4)]
              (.putInt bb v)
              (.array bb))
       :cljs (let [buf (js/Uint8Array. 4)
                   dv (js/DataView. (.-buffer buf))]
               (.setUint32 dv 0 v false)
               buf))))

(defn read-be64
  "Reads an unsigned 64-bit big-endian integer from bytes at offset."
  [bs offset]
  #?(:clj (.getLong (ByteBuffer/wrap ^bytes bs (int offset) 8))
     :cljs (let [dv (js/DataView. (.-buffer bs) (+ (.-byteOffset bs) offset) 8)]
             (js/Number (.getBigUint64 dv 0 false)))))

(defn read-be32
  "Reads an unsigned 32-bit big-endian integer from bytes at offset."
  [bs offset]
  #?(:clj (bit-and (long (.getInt (ByteBuffer/wrap ^bytes bs (int offset) 4))) 0xFFFFFFFF)
     :cljs (let [dv (js/DataView. (.-buffer bs) (+ (.-byteOffset bs) offset) 4)]
             (.getUint32 dv 0 false))))

(defn slice-bytes
  "Returns a sub-slice of bytes from start (inclusive) of length len."
  [bs start len]
  #?(:clj (let [out (byte-array len)]
            (System/arraycopy ^bytes bs (int start) out 0 (int len))
            out)
     :cljs (.slice ^js/Uint8Array bs start (+ start len))))

(defn bytes-contain-subseq?
  "Returns true if byte-array haystack contains non-empty byte-array needle."
  [haystack needle]
  (let [hlen (fressian/count-bytes haystack)
        nlen (fressian/count-bytes needle)]
    (if (or (zero? nlen) (> nlen hlen))
      false
      (let [limit (- hlen nlen)]
        (loop [i 0]
          (if (> i limit)
            false
            (let [matched?
                  (loop [j 0]
                    (if (= j nlen)
                      true
                      (let [hb #?(:clj (aget ^bytes haystack (+ i j))
                                  :cljs (aget haystack (+ i j)))
                            nb #?(:clj (aget ^bytes needle j)
                                  :cljs (aget needle j))]
                        (if (= hb nb)
                          (recur (inc j))
                          false))))]
              (if matched?
                true
                (recur (inc i))))))))))
