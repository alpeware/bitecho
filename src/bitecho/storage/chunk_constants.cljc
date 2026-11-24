(ns bitecho.storage.chunk-constants
  "Pure Sans-IO constants, RFC 8785 JCS canonicalization, manifest v1 validation,
   detached owner envelope verification, quota accounting, refcounted GC eligibility,
   and safe blob HTTP response headers for BIP-017a chunked large-artifact storage
   (Rules 1, 2, 5)."
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

;; =============================================================================
;; 1. BIP-017a Normative Constants
;; =============================================================================

(def manifest-domain-tag
  "Domain separation tag prefixed to RFC 8785 JCS manifest bytes before SHA-256."
  "bitecho/chunk-manifest/v1")

(def min-chunk-bytes
  "Minimum allowed chunk size in bytes (64 KiB)."
  65536)

(def default-chunk-bytes
  "Default chunk size in bytes (1 MiB)."
  1048576)

(def max-chunk-bytes
  "Hard ceiling for individual chunk size in bytes (4 MiB)."
  4194304)

(def max-chunks-per-manifest
  "Hard ceiling on number of chunks in a single manifest."
  8192)

(def default-fetch-concurrency
  "Default concurrent chunk fetch count."
  2)

(def max-fetch-concurrency-940mb
  "Hard concurrency ceiling for 940 MiB RAM-constrained nodes/browsers."
  3)

(def min-grace-epochs
  "Minimum retention grace period in finalized epochs before refcounted GC."
  4)

(def default-infra-chunk-quota-bytes
  "Default infrastructure chunk store quota in bytes (2 GiB)."
  2147483648)

(def default-max-retries-per-chunk
  "Default bounded retry count per chunk before loud failure."
  3)

(def allowed-blob-content-types
  "Strict allowlist of safe Content-Type headers served verbatim on /artifact/v1/blob/<cid>."
  #{"application/octet-stream"
    "application/wasm"
    "application/json"
    "text/plain; charset=utf-8"
    "text/markdown; charset=utf-8"})

;; =============================================================================
;; 2. Pure Cap Ceiling Clamping (Rule 5: Zero Silent Failures)
;; =============================================================================

(defn clamp-cap
  "Pure `(min constant-max requested)` clamp.
   Emits a counted `:diagnose` effect with `:kind :cap-ceiling-clamped` whenever
   `requested` exceeds `constant-max`."
  [cap-name constant-max requested]
  (let [ceil-val (long constant-max)
        req-val (long (or requested ceil-val))
        clamped (min ceil-val req-val)
        clamped? (> req-val ceil-val)]
    {:value clamped
     :clamped? clamped?
     :effects (if clamped?
                [{:type :diagnose
                  :kind :cap-ceiling-clamped
                  :cap cap-name
                  :requested req-val
                  :ceiling ceil-val
                  :reason (str "cap-ceiling-clamped:" (name cap-name) ":" req-val "->" ceil-val)}]
                [])}))

;; =============================================================================
;; 3. RFC 8785 JCS Canonicalization (Pure Portable .cljc — Integers Only)
;; =============================================================================

(defn- json-escape-string
  "Escapes a string per RFC 8785 / RFC 8259 JSON string rules."
  [^String s]
  (let [sb #?(:clj (StringBuilder. "\"") :cljs (js/Array "\""))
        n (count s)]
    (loop [i 0]
      (if (< i n)
        (let [ch (.charAt s i)
              code #?(:clj (int ch) :cljs (.charCodeAt s i))]
          (cond
            (= code 0x22) #?(:clj (.append sb "\\\"") :cljs (.push sb "\\\""))
            (= code 0x5c) #?(:clj (.append sb "\\\\") :cljs (.push sb "\\\\"))
            (= code 0x08) #?(:clj (.append sb "\\b") :cljs (.push sb "\\b"))
            (= code 0x0c) #?(:clj (.append sb "\\f") :cljs (.push sb "\\f"))
            (= code 0x0a) #?(:clj (.append sb "\\n") :cljs (.push sb "\\n"))
            (= code 0x0d) #?(:clj (.append sb "\\r") :cljs (.push sb "\\r"))
            (= code 0x09) #?(:clj (.append sb "\\t") :cljs (.push sb "\\t"))
            (< code 0x20)
            (let [hex #?(:clj (format "\\u%04x" code)
                         :cljs (let [h (.toString code 16)]
                                 (str "\\u" (subs "0000" (count h)) h)))]
              #?(:clj (.append sb hex) :cljs (.push sb hex)))
            :else
            #?(:clj (.append sb ch) :cljs (.push sb ch)))
          (recur (inc i)))
        (do
          #?(:clj (.append sb "\"") :cljs (.push sb "\""))
          #?(:clj (.toString sb) :cljs (.join sb "")))))))

(defn- jcs-key-str
  [k]
  (cond
    (string? k) k
    (keyword? k) (if (namespace k) (str (namespace k) "/" (name k)) (name k))
    :else (throw (ex-info "JCS object key must be string or keyword" {:key k}))))

(defn- integer-number?
  [x]
  #?(:clj (integer? x)
     :cljs (and (number? x) (js/Number.isInteger x) (js/Number.isFinite x))))

(defn jcs-canonicalize
  "Serializes `value` into an RFC 8785 JCS canonical JSON string.
   - Object keys sorted lexicographically (UTF-16 code-unit order).
   - No insignificant whitespace.
   - Integers only (throws fail-closed on non-integer floating-point numbers)."
  [value]
  (cond
    (nil? value) "null"
    (true? value) "true"
    (false? value) "false"
    (string? value) (json-escape-string value)
    (integer-number? value) (str value)
    (number? value)
    (throw (ex-info "RFC 8785 manifest JCS forbids non-integer floating-point numbers"
                    {:value value}))
    (map? value)
    (let [entries (->> value
                       (map (fn [[k v]] [(jcs-key-str k) v]))
                       (sort-by first compare))]
      (str "{"
           (str/join ","
                     (map (fn [[ks v]]
                            (str (json-escape-string ks) ":" (jcs-canonicalize v)))
                          entries))
           "}"))
    (or (vector? value) (sequential? value))
    (str "[" (str/join "," (map jcs-canonicalize value)) "]")
    :else
    (throw (ex-info "Unsupported value type for RFC 8785 JCS canonicalization"
                    {:value value :type (type value)}))))

(defn jcs-canonical-bytes
  "Returns UTF-8 byte array of the RFC 8785 JCS canonical serialization of `value`."
  [value]
  (fressian/utf8->bytes (jcs-canonicalize value)))

(defn manifest-cid
  "Computes `SHA-256(\"bitecho/chunk-manifest/v1\" || jcs-canonical-bytes(manifest))`
   as a 64-character lowercase hex string. Byte-identical across JVM and CLJS."
  [manifest]
  (crypto/sha256-hex (str manifest-domain-tag (jcs-canonicalize manifest))))

;; =============================================================================
;; 4. Manifest v1 Validation & Detached Owner Envelope Verification
;; =============================================================================

(defn- hex64?
  [s]
  (boolean (and (string? s) (re-matches #"^[0-9a-f]{64}$" s))))

(defn- hex-string?
  [s]
  (boolean (and (string? s) (pos? (count s)) (even? (count s)) (re-matches #"^[0-9a-f]+$" s))))

(defn- normalize-manifest-keys
  [m]
  (if-not (map? m)
    nil
    (let [get-f (fn [k-str k-kw]
                  (cond
                    (contains? m k-str) (get m k-str)
                    (contains? m k-kw) (get m k-kw)
                    :else nil))
          raw-ret (or (get-f "retention_policy" :retention-policy)
                      (get m :retention_policy))
          norm-ret (when (map? raw-ret)
                     (let [ge (or (get raw-ret "grace_epochs")
                                  (:grace-epochs raw-ret)
                                  (:grace_epochs raw-ret))]
                       (cond-> {}
                         (some? ge) (assoc "grace_epochs" ge))))
          raw-chunks (get-f "chunks" :chunks)
          norm-chunks (when (sequential? raw-chunks)
                        (mapv (fn [ch]
                                (if (map? ch)
                                  {"index" (or (get ch "index") (:index ch))
                                   "cid" (or (get ch "cid") (:cid ch))
                                   "size" (or (get ch "size") (:size ch))}
                                  ch))
                              raw-chunks))]
      (cond-> {}
        (some? (get-f "version" :version)) (assoc "version" (get-f "version" :version))
        (some? (get-f "artifact_name" :artifact-name)) (assoc "artifact_name" (get-f "artifact_name" :artifact-name))
        (some? (get-f "content_type" :content-type)) (assoc "content_type" (get-f "content_type" :content-type))
        (some? (or (get-f "chunk_size" :chunk-size) (:chunk_size m)))
        (assoc "chunk_size" (or (get-f "chunk_size" :chunk-size) (:chunk_size m)))
        (some? (or (get-f "total_bytes" :total-bytes) (:total_bytes m)))
        (assoc "total_bytes" (or (get-f "total_bytes" :total-bytes) (:total_bytes m)))
        (some? (or (get-f "total_sha256" :total-sha256) (:total_sha256 m)))
        (assoc "total_sha256" (or (get-f "total_sha256" :total-sha256) (:total_sha256 m)))
        (some? (or (get-f "state_owner" :state-owner) (:state_owner m)))
        (assoc "state_owner" (or (get-f "state_owner" :state-owner) (:state_owner m)))
        (some? norm-ret) (assoc "retention_policy" norm-ret)
        (some? norm-chunks) (assoc "chunks" norm-chunks)))))

(defn- fail-manifest
  [kind reason & [extra]]
  {:ok? false
   :error kind
   :reason reason
   :effects [(merge {:type :diagnose :kind kind :reason reason} extra)]})

(defn validate-manifest
  "Purely validates a BIP-017a chunk manifest v1 map.
   Fails closed with counted `:diagnose` effects for:
   - `:missing-state-owner`
   - `:missing-retention-policy`
   - `:storage-accounting-mismatch`
   - `:max-bytes-exceeded`
   - `:invalid-manifest`
   Returns `{:ok? true :manifest norm-m :manifest-cid cid :effects []}` on success."
  ([raw-manifest] (validate-manifest raw-manifest {}))
  ([raw-manifest opts]
   (let [m (normalize-manifest-keys raw-manifest)
         max-bytes (or (:max-bytes opts) (get opts "max_bytes"))]
     (cond
       (not (map? m))
       (fail-manifest :invalid-manifest "manifest-must-be-map")

       (not= 1 (get m "version"))
       (fail-manifest :invalid-manifest "unsupported-manifest-version")

       (not (and (string? (get m "state_owner")) (hex-string? (get m "state_owner"))))
       (fail-manifest :missing-state-owner "manifest-missing-valid-state-owner")

       (not (and (map? (get m "retention_policy"))
                 (integer-number? (get-in m ["retention_policy" "grace_epochs"]))
                 (>= (long (get-in m ["retention_policy" "grace_epochs"])) min-grace-epochs)))
       (fail-manifest :missing-retention-policy
                      (str "manifest-grace-epochs-must-be-at-least-" min-grace-epochs))

       (not (and (integer-number? (get m "chunk_size"))
                 (>= (long (get m "chunk_size")) min-chunk-bytes)
                 (<= (long (get m "chunk_size")) max-chunk-bytes)))
       (fail-manifest :invalid-manifest "chunk-size-out-of-bounds")

       (not (and (integer-number? (get m "total_bytes"))
                 (pos? (long (get m "total_bytes")))))
       (fail-manifest :invalid-manifest "total-bytes-must-be-positive-integer")

       (and (some? max-bytes) (> (long (get m "total_bytes")) (long max-bytes)))
       (fail-manifest :max-bytes-exceeded
                      (str "total-bytes-" (get m "total_bytes") "-exceeds-max-" max-bytes)
                      {:total-bytes (long (get m "total_bytes")) :max-bytes (long max-bytes)})

       (not (hex64? (get m "total_sha256")))
       (fail-manifest :invalid-manifest "invalid-total-sha256")

       (not (and (vector? (get m "chunks"))
                 (pos? (count (get m "chunks")))
                 (<= (count (get m "chunks")) max-chunks-per-manifest)))
       (fail-manifest :invalid-manifest "chunks-count-out-of-bounds")

       :else
       (let [chunks (get m "chunks")
             chunk-size (long (get m "chunk_size"))
             total-bytes (long (get m "total_bytes"))
             bad-chunk (first
                        (keep-indexed
                         (fn [expected-idx ch]
                           (cond
                             (not (map? ch)) {:err :invalid-manifest :reason "chunk-entry-not-map"}
                             (not= expected-idx (get ch "index")) {:err :storage-accounting-mismatch :reason "non-contiguous-chunk-index"}
                             (not (hex64? (get ch "cid"))) {:err :invalid-manifest :reason "invalid-chunk-cid"}
                             (not (and (integer-number? (get ch "size"))
                                       (pos? (long (get ch "size")))
                                       (<= (long (get ch "size")) chunk-size)))
                             {:err :storage-accounting-mismatch :reason "chunk-size-invalid"}
                             :else nil))
                         chunks))
             sum-bytes (if bad-chunk
                         -1
                         (reduce (fn [acc ch] (+ acc (long (get ch "size")))) 0 chunks))]
         (cond
           bad-chunk
           (fail-manifest (:err bad-chunk) (:reason bad-chunk))

           (not= sum-bytes total-bytes)
           (fail-manifest :storage-accounting-mismatch
                          (str "chunk-sum-" sum-bytes "-neq-total-bytes-" total-bytes)
                          {:chunk-sum sum-bytes :total-bytes total-bytes})

           :else
           {:ok? true
            :manifest m
            :manifest-cid (manifest-cid m)
            :effects []}))))))

(defn detached-envelope-signing-payload
  "Canonical UTF-8 signing payload for a detached owner envelope."
  [mcid]
  (str manifest-domain-tag ":" mcid))

(defn sign-detached-owner-envelope
  "Creates a detached `{:manifest-cid :owner-pubkey :sig}` Ed25519 owner envelope."
  [mcid owner-pubkey-hex owner-privkey]
  (let [sig-bytes (crypto/sign owner-privkey (detached-envelope-signing-payload mcid))]
    {:manifest-cid mcid
     :owner-pubkey owner-pubkey-hex
     :sig (fressian/bytes->hex sig-bytes)}))

(defn- normalize-envelope
  [env]
  (when (map? env)
    {:manifest-cid (or (:manifest-cid env) (get env "manifest_cid") (get env "manifest-cid"))
     :owner-pubkey (or (:owner-pubkey env) (get env "owner_pubkey") (get env "owner-pubkey"))
     :sig (or (:sig env) (get env "sig"))}))

(defn verify-detached-owner-envelope
  "Verifies detached `{:manifest-cid :owner-pubkey :sig}` envelope(s) against `manifest`.
   Accepts a single envelope map or a collection of envelope maps.
   Fails closed with counted `:diagnose` effects:
   - `:missing-state-owner` when manifest lacks `state_owner` or envelope lacks `:owner-pubkey`
   - `:owner-signature-ambiguous` when `> 1` verifying owner signatures are present
   - `:owner-signature-invalid` when signature fails verification or signer != `state_owner`."
  [raw-manifest envelope-or-envelopes]
  (let [m (normalize-manifest-keys raw-manifest)
        state-owner (get m "state_owner")]
    (if (not (and (string? state-owner) (hex-string? state-owner)))
      (fail-manifest :missing-state-owner "manifest-missing-state-owner")
      (let [expected-cid (manifest-cid m)
            envelopes (cond
                        (nil? envelope-or-envelopes) []
                        (map? envelope-or-envelopes)
                        (if-let [sigs (or (:signatures envelope-or-envelopes)
                                          (get envelope-or-envelopes "signatures"))]
                          (mapv normalize-envelope sigs)
                          [(normalize-envelope envelope-or-envelopes)])
                        (sequential? envelope-or-envelopes)
                        (mapv normalize-envelope envelope-or-envelopes)
                        :else [])
            payload (detached-envelope-signing-payload expected-cid)]
        (cond
          (empty? envelopes)
          (fail-manifest :owner-signature-invalid "no-detached-owner-envelope")

          (some #(not (and (string? (:owner-pubkey %)) (hex-string? (:owner-pubkey %)))) envelopes)
          (fail-manifest :missing-state-owner "envelope-missing-owner-pubkey")

          :else
          (let [verifying (filterv
                           (fn [{:keys [manifest-cid owner-pubkey sig]}]
                             (and (= manifest-cid expected-cid)
                                  (= owner-pubkey state-owner)
                                  (hex-string? sig)
                                  (crypto/verify owner-pubkey payload sig)))
                           envelopes)]
            (cond
              (> (count verifying) 1)
              (fail-manifest :owner-signature-ambiguous
                             (str "ambiguous-owner-signatures:" (count verifying))
                             {:verifying-count (count verifying)})

              (= (count verifying) 1)
              {:ok? true
               :manifest-cid expected-cid
               :owner-pubkey state-owner
               :effects []}

              :else
              (fail-manifest :owner-signature-invalid "owner-signature-verification-failed"))))))))

;; =============================================================================
;; 5. Quota Accounting & Refcounted GC Eligibility
;; =============================================================================

(defn evaluate-chunk-quota
  "Evaluates chunk store quota counting both `:committed-bytes` and `:staged-unhashed-bytes`
   toward `:bytes-at-rest`. Returns HTTP 507 with `:chunk-store-quota-exceeded` when exceeded."
  [{:keys [committed-bytes staged-unhashed-bytes incoming-bytes max-quota-bytes]
    :or {committed-bytes 0 staged-unhashed-bytes 0 incoming-bytes 0}}]
  (let [clamp-res (clamp-cap :max-chunk-store-bytes
                             default-infra-chunk-quota-bytes
                             (or max-quota-bytes default-infra-chunk-quota-bytes))
        effective-quota (:value clamp-res)
        bytes-at-rest (+ (long committed-bytes) (long staged-unhashed-bytes))
        projected (+ bytes-at-rest (long incoming-bytes))]
    (if (> projected effective-quota)
      {:ok? false
       :http-status 507
       :error :chunk-store-quota-exceeded
       :bytes-at-rest bytes-at-rest
       :projected-bytes projected
       :quota-bytes effective-quota
       :effects (conj (:effects clamp-res)
                      {:type :diagnose
                       :kind :chunk-store-quota-exceeded
                       :bytes-at-rest bytes-at-rest
                       :projected-bytes projected
                       :quota-bytes effective-quota
                       :reason (str "quota-exceeded:" projected ">" effective-quota)})}
      {:ok? true
       :http-status 200
       :bytes-at-rest bytes-at-rest
       :projected-bytes projected
       :quota-bytes effective-quota
       :effects (:effects clamp-res)})))

(defn refcounted-gc-eligible?
  "Determines whether a chunk with `:refcount` unreferenced at `:unreferenced-since-epoch`
   is eligible for garbage collection at `:current-epoch` given `:grace-epochs` (>= 4)."
  [{:keys [refcount unreferenced-since-epoch current-epoch grace-epochs]}]
  (let [rc (long (or refcount 0))
        ge (when (integer-number? grace-epochs) (long grace-epochs))]
    (cond
      (or (nil? ge) (< ge min-grace-epochs))
      {:eligible? false
       :reason :missing-retention-policy
       :grace-remaining min-grace-epochs
       :effects [{:type :diagnose
                  :kind :missing-retention-policy
                  :grace-epochs ge
                  :min-grace-epochs min-grace-epochs
                  :reason (str "grace-epochs-below-minimum:" ge "<" min-grace-epochs)}]}

      (pos? rc)
      {:eligible? false
       :reason :still-referenced
       :grace-remaining ge
       :effects []}

      :else
      (let [elapsed (- (long (or current-epoch 0)) (long (or unreferenced-since-epoch 0)))
            remaining (max 0 (- ge elapsed))]
        (if (>= elapsed ge)
          {:eligible? true
           :reason :grace-elapsed
           :grace-remaining 0
           :effects []}
          {:eligible? false
           :reason :grace-period-active
           :grace-remaining remaining
           :effects []})))))

;; =============================================================================
;; 6. Safe Blob HTTP Response Headers (Scoped Strictly to /artifact/v1/blob/<cid>)
;; =============================================================================

(defn normalize-safe-blob-content-type
  "Enforces the safe Content-Type allowlist for /artifact/v1/blob/<cid>.
   Returns `{:content-type ct :sandbox-csp? bool}`.
   `text/html` is permitted ONLY with `Content-Security-Policy: sandbox` (no allow-same-origin).
   Any non-allowlisted MIME type falls back to `application/octet-stream`."
  [raw-ct]
  (let [norm (str/lower-case (str/trim (str (or raw-ct ""))))]
    (cond
      (contains? allowed-blob-content-types norm)
      {:content-type norm :sandbox-csp? false}

      (or (= norm "text/html") (str/starts-with? norm "text/html;"))
      {:content-type "text/html; charset=utf-8" :sandbox-csp? true}

      (or (= norm "text/plain") (str/starts-with? norm "text/plain;"))
      {:content-type "text/plain; charset=utf-8" :sandbox-csp? false}

      (or (= norm "text/markdown") (str/starts-with? norm "text/markdown;"))
      {:content-type "text/markdown; charset=utf-8" :sandbox-csp? false}

      :else
      {:content-type "application/octet-stream" :sandbox-csp? false})))

(defn safe-blob-response-headers
  "Builds the normative BIP-017a HTTP response headers for `GET/HEAD /artifact/v1/blob/<cid>`.
   NOTE: `Access-Control-Allow-Origin: *` is scoped STRICTLY to `/artifact/v1/blob/<cid>`.
   Includes `Accept-Ranges: bytes` and optional `Content-Range` for `206 Partial Content` (BIP-022 Stage D.1)."
  [{:keys [cid content-type content-length content-range]}]
  (let [{:keys [content-type sandbox-csp?]} (normalize-safe-blob-content-type content-type)]
    (cond-> {"Content-Type" content-type
             "Cache-Control" "public, max-age=31536000, immutable"
             "Access-Control-Allow-Origin" "*"
             "Accept-Ranges" "bytes"
             "X-Content-Type-Options" "nosniff"
             "ETag" (str "\"" cid "\"")
             "X-Bitecho-Blob-Cid" (str cid)}
      (some? content-length) (assoc "Content-Length" (str content-length))
      (and (string? content-range) (not (str/blank? content-range))) (assoc "Content-Range" content-range)
      sandbox-csp? (assoc "Content-Security-Policy" "sandbox"))))
