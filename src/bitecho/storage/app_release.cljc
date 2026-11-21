(ns bitecho.storage.app-release
  "Pure Sans-IO core for BIP-017b Atomic `web/app/release` Pointer Resolution,
   detached 2-of-3 quorum signature verification, CID-pinned genesis anchor
   enforcement (zero TOFU), generalized SHA-384 SRI verification, strict `/app/*`
   CSP + COOP/COEP headers validation, LKG retention pinning, and single-authority
   generation-tagged release lifecycle reducer (Rules 1, 2, 4, 5)."
  (:require [bitecho.core.protocol.acme :as acme]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.storage.chunk-constants :as cc]
            #?(:clj [clojure.data.json :as json])
            [clojure.string :as str]))

;; =============================================================================
;; 1. Domain Tag, Canonicalization, Release CID, & SHA-384 SRI
;; =============================================================================

(def release-domain-tag
  "Domain separation tag prefixed to RFC 8785 JCS release bytes before SHA-256."
  "bitecho/web-app-release/v1")

(defn canonical-release-bytes
  "Returns UTF-8 byte array of the RFC 8785 JCS canonical serialization of `release`."
  [release]
  (cc/jcs-canonical-bytes release))

(defn release-cid
  "Computes `SHA-256(\"bitecho/web-app-release/v1\" || canonical-release-bytes(release))`
   as a 64-character lowercase hex string. Byte-identical across JVM and CLJS."
  [release]
  (crypto/sha256-hex (str release-domain-tag (cc/jcs-canonicalize release))))

(defn compute-sri-sha384
  "Computes W3C Subresource Integrity string `\"sha384-<base64>\"` for `bytes-or-str`."
  [bytes-or-str]
  (str "sha384-" (acme/base64-encode (crypto/sha384 bytes-or-str))))

(defn executable-asset-path?
  "Returns true if `asset-path` or `content-type` identifies an executable JS/WASM asset."
  [asset-path content-type]
  (let [p (str/lower-case (str (or asset-path "")))
        ct (str/lower-case (str (or content-type "")))]
    (boolean
     (or (str/ends-with? p ".js")
         (str/ends-with? p ".mjs")
         (str/ends-with? p ".cjs")
         (str/ends-with? p ".wasm")
         (str/includes? ct "javascript")
         (str/includes? ct "wasm")))))

(defn- html-asset-path?
  [asset-path content-type]
  (let [p (str/lower-case (str (or asset-path "")))
        ct (str/lower-case (str (or content-type "")))]
    (boolean
     (or (str/ends-with? p ".html")
         (str/ends-with? p ".htm")
         (str/includes? ct "text/html")))))

;; =============================================================================
;; 2. Helpers & Fail-Closed Diagnostics
;; =============================================================================

(defn- hex64?
  [s]
  (boolean (and (string? s) (re-matches #"^[0-9a-f]{64}$" s))))

(defn- hex-string?
  [s]
  (boolean (and (string? s) (pos? (count s)) (even? (count s)) (re-matches #"^[0-9a-f]+$" s))))

(defn- integer-number?
  [x]
  #?(:clj (integer? x)
     :cljs (and (number? x) (js/Number.isInteger x) (js/Number.isFinite x))))

(defn- fail-result
  [kind reason & [extra]]
  {:ok? false
   :error kind
   :reason reason
   :effects [(merge {:type :diagnose :kind kind :reason reason} extra)]})

(defn- parse-json-map
  [s]
  (try
    (let [parsed #?(:clj (json/read-str s)
                    :cljs (js->clj (js/JSON.parse s)))]
      (when (map? parsed) parsed))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(defn- get-field
  [m & ks]
  (when (map? m)
    (some (fn [k] (when (contains? m k) (get m k))) ks)))

;; =============================================================================
;; 3. Detached 2-of-3 Quorum Signature Envelopes
;; =============================================================================

(defn release-envelope-signing-payload
  "Canonical domain-separated UTF-8 signing payload for a release quorum envelope."
  [rcid]
  (str release-domain-tag ":" rcid))

(defn sign-release-envelope
  "Creates a detached quorum signature envelope `{:release-cid rcid :sigs [{:owner-pubkey hex :sig hex} ...]}`.
   - 2-arity: `(sign-release-envelope rcid signers)` where `signers` is a seq of `{:owner-pubkey :privkey}`.
   - 3-arity: `(sign-release-envelope rcid owner-pubkey-hex privkey)` for a single signer."
  ([rcid signers]
   (let [payload (release-envelope-signing-payload rcid)
         signer-list (if (map? signers) [signers] (vec signers))]
     {:release-cid rcid
      :sigs (mapv (fn [{:keys [owner-pubkey privkey]}]
                    {:owner-pubkey (str/lower-case (str/trim (str owner-pubkey)))
                     :sig (fressian/bytes->hex (crypto/sign privkey payload))})
                  signer-list)}))
  ([rcid owner-pubkey-hex privkey]
   (sign-release-envelope rcid [{:owner-pubkey owner-pubkey-hex :privkey privkey}])))

(defn- normalize-sig-entry
  [entry]
  (when (map? entry)
    {:owner-pubkey (some-> (get-field entry :owner-pubkey "owner_pubkey" "owner-pubkey")
                           str str/trim str/lower-case)
     :sig (some-> (get-field entry :sig "sig")
                  str str/trim str/lower-case)}))

(defn verify-release-quorum-envelope
  "Verifies a detached `{:release-cid ... :sigs [{:owner-pubkey ... :sig ...}]}` quorum envelope
   against `release` with `threshold` (default 2) distinct signers from `:trusted-signers`.
   Rejects `< threshold`, duplicate signer keys, unknown signers, or tampered bytes fail-closed
   with counted `:diagnose` `:release-sig-invalid`."
  [release envelope {:keys [trusted-signers threshold] :or {threshold 2}}]
  (let [thresh (long (or threshold 2))
        trusted (set (map #(str/lower-case (str/trim (str %))) trusted-signers))]
    (cond
      (not (map? release))
      (fail-result :release-sig-invalid "release-must-be-map")

      (not (map? envelope))
      (fail-result :release-sig-invalid "envelope-must-be-map")

      (or (empty? trusted) (< thresh 1))
      (fail-result :release-sig-invalid "invalid-quorum-policy")

      :else
      (let [expected-cid (release-cid release)
            env-cid (some-> (get-field envelope :release-cid "release_cid" "release-cid")
                            str str/trim str/lower-case)
            raw-sigs (get-field envelope :sigs "sigs" :signatures "signatures")
            sigs (when (sequential? raw-sigs) (mapv normalize-sig-entry raw-sigs))
            payload (release-envelope-signing-payload expected-cid)]
        (cond
          (not= env-cid expected-cid)
          (fail-result :release-sig-invalid "release-cid-mismatch"
                       {:expected expected-cid :actual env-cid})

          (empty? sigs)
          (fail-result :release-sig-invalid "no-quorum-signatures")

          (some #(not (and (map? %) (hex-string? (:owner-pubkey %)) (hex-string? (:sig %)))) sigs)
          (fail-result :release-sig-invalid "malformed-signature-entry")

          (not= (count sigs) (count (distinct (map :owner-pubkey sigs))))
          (fail-result :release-sig-invalid "duplicate-signer-pubkey")

          (some #(not (contains? trusted (:owner-pubkey %))) sigs)
          (fail-result :release-sig-invalid "unknown-signer-pubkey")

          (< (count sigs) thresh)
          (fail-result :release-sig-invalid "quorum-threshold-not-met"
                       {:required thresh :provided (count sigs)})

          :else
          (let [all-valid? (every? (fn [{:keys [owner-pubkey sig]}]
                                     (boolean (crypto/verify owner-pubkey payload sig)))
                                   sigs)]
            (if-not all-valid?
              (fail-result :release-sig-invalid "signature-verification-failed")
              {:ok? true
               :release-cid expected-cid
               :signers (mapv :owner-pubkey sigs)
               :threshold thresh
               :effects []})))))))

;; =============================================================================
;; 4. Strict `/app/*` `headers-config` Validation
;; =============================================================================

(defn default-app-headers-config
  "Returns the canonical BIP-017b strict `/app/*` HTTP security headers map."
  []
  {"Cross-Origin-Opener-Policy" "same-origin"
   "Cross-Origin-Embedder-Policy" "credentialless"
   "Cache-Control" "no-cache"
   "X-Content-Type-Options" "nosniff"
   "Referrer-Policy" "no-referrer"
   "Content-Security-Policy"
   "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' https: wss: blob:; img-src 'self' data: blob:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"})

(defn- parse-csp-directives
  [csp-str]
  (reduce
   (fn [acc part]
     (let [trimmed (str/trim part)]
       (if (str/blank? trimmed)
         acc
         (let [tokens (str/split trimmed #"\s+")
               dir-name (str/lower-case (first tokens))
               dir-vals (set (rest tokens))]
           (assoc acc dir-name dir-vals)))))
   {}
   (str/split (str csp-str) #";")))

(defn validate-headers-config
  "Purely validates a `/app/*` `headers-config` map against BIP-017b security invariants:
   - `Cross-Origin-Opener-Policy: same-origin`
   - `Cross-Origin-Embedder-Policy: credentialless`
   - `Cache-Control` includes `no-cache`
   - `Content-Security-Policy` has `script-src` with `'self'` and `'wasm-unsafe-eval'`,
     `connect-src` with `blob:`, NO `'unsafe-inline'` in `script-src`, and NO `'unsafe-eval'`."
  [raw-config]
  (let [hdr-map (cond
                  (and (map? raw-config) (map? (get-field raw-config :headers "headers")))
                  (get-field raw-config :headers "headers")
                  (map? raw-config) raw-config
                  :else nil)]
    (if-not (map? hdr-map)
      (fail-result :release-headers-invalid "headers-config-must-be-map")
      (let [norm-str-map (into {} (map (fn [[k v]] [(if (keyword? k) (name k) (str k)) (str v)]) hdr-map))
            lower-lookup (into {} (map (fn [[k v]] [(str/lower-case k) (str/trim v)]) norm-str-map))
            coop (get lower-lookup "cross-origin-opener-policy")
            coep (get lower-lookup "cross-origin-embedder-policy")
            cc-hdr (get lower-lookup "cache-control")
            csp (get lower-lookup "content-security-policy")
            cc-tokens (when cc-hdr (set (map #(str/lower-case (str/trim %)) (str/split cc-hdr #","))))
            csp-dirs (when (and (string? csp) (not (str/blank? csp))) (parse-csp-directives csp))
            script-src (get csp-dirs "script-src")
            connect-src (get csp-dirs "connect-src")
            any-unsafe-eval? (some #(contains? % "'unsafe-eval'") (vals csp-dirs))]
        (cond
          (not= "same-origin" coop)
          (fail-result :release-headers-invalid "coop-must-be-same-origin" {:actual coop})

          (not= "credentialless" coep)
          (fail-result :release-headers-invalid "coep-must-be-credentialless" {:actual coep})

          (not (contains? cc-tokens "no-cache"))
          (fail-result :release-headers-invalid "cache-control-must-contain-no-cache" {:actual cc-hdr})

          (nil? csp-dirs)
          (fail-result :release-headers-invalid "missing-content-security-policy")

          (or (nil? script-src)
              (not (contains? script-src "'self'"))
              (not (contains? script-src "'wasm-unsafe-eval'")))
          (fail-result :release-headers-invalid "csp-script-src-must-include-self-and-wasm-unsafe-eval")

          (contains? script-src "'unsafe-inline'")
          (fail-result :release-headers-invalid "csp-script-src-forbids-unsafe-inline")

          any-unsafe-eval?
          (fail-result :release-headers-invalid "csp-forbids-unsafe-eval")

          (or (nil? connect-src) (not (contains? connect-src "blob:")))
          (fail-result :release-headers-invalid "csp-connect-src-must-include-blob")

          :else
          {:ok? true
           :headers norm-str-map
           :effects []})))))

;; =============================================================================
;; 5. HTML `<script>` SRI Cross-Check & Full Release Bundle Validation
;; =============================================================================

(defn- normalize-script-src->asset-key
  [raw-src]
  (let [no-query (first (str/split (str raw-src) #"[?#]" 2))
        trimmed (str/trim no-query)]
    (cond
      (str/starts-with? trimmed "/app/") (subs trimmed 5)
      (str/starts-with? trimmed "./") (subs trimmed 2)
      (str/starts-with? trimmed "/") (subs trimmed 1)
      :else trimmed)))

(defn- extract-html-script-tags
  [html-str]
  (for [[_ attrs] (re-seq #"(?is)<script\b([^>]*)>" (str html-str))]
    (let [src (second (or (re-find #"(?i)\bsrc\s*=\s*\"([^\"]+)\"" attrs)
                          (re-find #"(?i)\bsrc\s*=\s*'([^']+)'" attrs)))
          integrity (second (or (re-find #"(?i)\bintegrity\s*=\s*\"([^\"]+)\"" attrs)
                                (re-find #"(?i)\bintegrity\s*=\s*'([^']+)'" attrs)))]
      {:src src :integrity integrity})))

(defn- normalize-assets-map
  [raw-assets]
  (when (and (map? raw-assets) (pos? (count raw-assets)))
    (into {}
          (map (fn [[k v]]
                 [(if (keyword? k) (name k) (str k))
                  (when (map? v)
                    {:cid (some-> (get-field v :cid "cid") str str/trim str/lower-case)
                     :size (get-field v :size "size")
                     :content-type (or (get-field v :content-type "content_type" "content-type")
                                       "application/octet-stream")
                     :sri (get-field v :sri "sri")})]))
          raw-assets)))

(defn- check-assets-and-sri
  [norm-assets blobs-by-cid declared-bytes-at-rest]
  (let [bad-asset
        (first
         (keep
          (fn [[asset-key meta-map]]
            (cond
              (not (map? meta-map))
              {:err :release-asset-corrupt :reason (str "malformed-asset-meta:" asset-key)}

              (not (hex64? (:cid meta-map)))
              {:err :release-asset-corrupt :reason (str "invalid-asset-cid:" asset-key)}

              (not (and (integer-number? (:size meta-map)) (>= (long (:size meta-map)) 0)))
              {:err :storage-accounting-mismatch :reason (str "invalid-asset-size:" asset-key)}

              :else
              (let [bs (get blobs-by-cid (:cid meta-map))]
                (cond
                  (nil? bs)
                  {:err :release-asset-missing :reason (str "missing-asset-blob:" asset-key) :cid (:cid meta-map)}

                  (not= (long (:size meta-map)) (long (fressian/count-bytes bs)))
                  {:err :release-asset-corrupt :reason (str "asset-size-mismatch:" asset-key) :cid (:cid meta-map)}

                  (not= (:cid meta-map) (crypto/sha256-hex bs))
                  {:err :release-asset-corrupt :reason (str "asset-cid-mismatch:" asset-key) :cid (:cid meta-map)}

                  :else nil))))
          norm-assets))]
    (if bad-asset
      (fail-result (:err bad-asset) (:reason bad-asset) (select-keys bad-asset [:cid]))
      (let [sum-bytes (reduce + 0 (map #(long (:size %)) (vals norm-assets)))]
        (if (not= sum-bytes (long declared-bytes-at-rest))
          (fail-result :storage-accounting-mismatch
                       (str "assets-sum-" sum-bytes "-neq-bytes-at-rest-" declared-bytes-at-rest)
                       {:assets-sum sum-bytes :bytes-at-rest (long declared-bytes-at-rest)})
          ;; Generalized SHA-384 SRI check across ALL executable JS/WASM assets
          (let [sri-by-key
                (reduce-kv
                 (fn [acc asset-key meta-map]
                   (if (executable-asset-path? asset-key (:content-type meta-map))
                     (assoc acc asset-key (compute-sri-sha384 (get blobs-by-cid (:cid meta-map))))
                     acc))
                 {}
                 norm-assets)
                exec-sri-err
                (first
                 (keep
                  (fn [[asset-key actual-sri]]
                    (let [declared-sri (get-in norm-assets [asset-key :sri])]
                      (when (not= declared-sri actual-sri)
                        {:err :release-sri-mismatch
                         :reason (str "executable-sri-mismatch:" asset-key)
                         :asset asset-key})))
                  sri-by-key))]
            (if exec-sri-err
              (fail-result (:err exec-sri-err) (:reason exec-sri-err) {:asset (:asset exec-sri-err)})
              ;; HTML <script> SRI cross-check & .sri file cross-check
              (let [html-sri-err
                    (first
                     (keep
                      (fn [[asset-key meta-map]]
                        (cond
                          (html-asset-path? asset-key (:content-type meta-map))
                          (let [html-str (fressian/bytes->utf8 (get blobs-by-cid (:cid meta-map)))
                                tags (extract-html-script-tags html-str)]
                            (first
                             (keep
                              (fn [{:keys [src integrity]}]
                                (when src
                                  (let [target-key (normalize-script-src->asset-key src)
                                        expected-sri (get sri-by-key target-key)]
                                    (when (and expected-sri (not= integrity expected-sri))
                                      {:err :release-sri-mismatch
                                       :reason (str "html-script-sri-mismatch:" asset-key "->" target-key)
                                       :asset asset-key}))))
                              tags)))

                          (str/ends-with? (str/lower-case asset-key) ".sri")
                          (let [target-key (subs asset-key 0 (- (count asset-key) 4))
                                expected-sri (get sri-by-key target-key)]
                            (when expected-sri
                              (let [sri-lines (set (map str/trim (str/split-lines (fressian/bytes->utf8 (get blobs-by-cid (:cid meta-map))))))]
                                (when-not (contains? sri-lines expected-sri)
                                  {:err :release-sri-mismatch
                                   :reason (str "sri-file-mismatch:" asset-key)
                                   :asset asset-key}))))

                          :else nil))
                      norm-assets))]
                (if html-sri-err
                  (fail-result (:err html-sri-err) (:reason html-sri-err) {:asset (:asset html-sri-err)})
                  {:ok? true
                   :assets norm-assets
                   :bytes-at-rest sum-bytes
                   :sri-by-key sri-by-key
                   :effects []})))))))))

(defn validate-release-bundle
  "Purely validates a complete BIP-017b release descriptor, detached 2-of-3 quorum
   signature envelope, headers-config blob, asset blobs, SHA-384 SRIs, storage
   accounting, and retention/LKG constraints. Fails closed with counted `:diagnose`."
  [release envelope blobs-by-cid opts]
  (let [pinned-genesis (some-> (:genesis-anchor-cid opts) str str/trim str/lower-case)
        rel-genesis (some-> (get-field release :genesis-anchor-cid "genesis_anchor_cid" "genesis-anchor-cid")
                            str str/trim str/lower-case)
        rel-seq (get-field release :seq "seq")
        hdr-cid (some-> (get-field release :headers-config-cid "headers_config_cid" "headers-config-cid")
                        str str/trim str/lower-case)
        bytes-at-rest (get-field release :bytes-at-rest "bytes_at_rest" "bytes-at-rest")
        norm-assets (normalize-assets-map (get-field release :assets "assets"))
        max-bytes (:max-bytes opts)
        lkg-cid (some-> (or (:lkg-release-cid opts)
                            (get-field release :lkg-release-cid "lkg_release_cid" "lkg-release-cid"))
                        str str/trim str/lower-case)
        available-cids (:available-release-cids opts)]
    (cond
      (or (not (hex64? pinned-genesis))
          (not (hex64? rel-genesis))
          (not= pinned-genesis rel-genesis))
      (fail-result :release-genesis-missing "genesis-anchor-cid-missing-or-mismatched")

      (not (and (integer-number? rel-seq) (pos? (long rel-seq))))
      (fail-result :release-seq-non-monotonic "release-seq-must-be-positive-integer")

      (not (hex64? hdr-cid))
      (fail-result :release-headers-invalid "invalid-headers-config-cid")

      (not (and (integer-number? bytes-at-rest) (>= (long bytes-at-rest) 0)))
      (fail-result :storage-accounting-mismatch "invalid-bytes-at-rest")

      (nil? norm-assets)
      (fail-result :release-asset-missing "release-missing-assets-map")

      :else
      (let [sig-res (verify-release-quorum-envelope release envelope opts)]
        (if-not (:ok? sig-res)
          sig-res
          (let [hdr-bytes (get blobs-by-cid hdr-cid)]
            (cond
              (nil? hdr-bytes)
              (fail-result :release-asset-missing "missing-headers-config-blob" {:cid hdr-cid})

              (not= hdr-cid (crypto/sha256-hex hdr-bytes))
              (fail-result :release-asset-corrupt "headers-config-cid-mismatch" {:cid hdr-cid})

              :else
              (let [hdr-map (parse-json-map (fressian/bytes->utf8 hdr-bytes))
                    hdr-res (validate-headers-config hdr-map)]
                (if-not (:ok? hdr-res)
                  hdr-res
                  (let [asset-res (check-assets-and-sri norm-assets blobs-by-cid bytes-at-rest)]
                    (if-not (:ok? asset-res)
                      asset-res
                      (let [active-bytes (:bytes-at-rest asset-res)]
                        (cond
                          (and (some? max-bytes)
                               (< (long max-bytes) (* 2 (long active-bytes))))
                          (fail-result :retention-bound-exceeded
                                       (str "max-bytes-" max-bytes "-lt-2x-active-" active-bytes)
                                       {:max-bytes (long max-bytes) :active-bytes (long active-bytes)})

                          (and (some? available-cids)
                               (hex64? lkg-cid)
                               (not (contains? available-cids lkg-cid)))
                          (fail-result :release-lkg-evicted
                                       (str "lkg-release-evicted:" lkg-cid)
                                       {:lkg-release-cid lkg-cid})

                          :else
                          {:ok? true
                           :release-cid (:release-cid sig-res)
                           :seq (long rel-seq)
                           :genesis-anchor-cid rel-genesis
                           :headers-config-cid hdr-cid
                           :headers (:headers hdr-res)
                           :assets (:assets asset-res)
                           :bytes-at-rest active-bytes
                           :signers (:signers sig-res)
                           :lkg-release-cid lkg-cid
                           :release release
                           :effects []})))))))))))))

;; =============================================================================
;; 6. Single-Authority Generation-Tagged Release Reducer (Rules 4 & 5)
;; =============================================================================

(defn init-release-state
  "Initializes a single-authority generation-tagged BIP-017b release resolver state map."
  ([] (init-release-state {}))
  ([opts]
   (let [lkg (some-> (:lkg-release-cid opts) str str/trim str/lower-case)]
     {:phase :idle
      :generation (long (or (:generation opts) 0))
      :genesis-anchor-cid (some-> (:genesis-anchor-cid opts) str str/trim str/lower-case)
      :trusted-signers (set (map #(str/lower-case (str/trim (str %))) (:trusted-signers opts)))
      :threshold (long (or (:threshold opts) 2))
      :max-bytes (:max-bytes opts)
      :current-seq (long (or (:current-seq opts) 0))
      :active-release nil
      :lkg-release-cid (when (hex64? lkg) lkg)
      :lkg-release nil
      :pinned-release-cids (cond-> #{} (hex64? lkg) (conj lkg))
      :last-error nil
      :diagnostics {:dropped 0 :causes {} :events []}})))

(defn- record-diagnose
  [state diag]
  (let [kind (or (:kind diag) :unknown)]
    (-> state
        (update-in [:diagnostics :dropped] (fnil inc 0))
        (update-in [:diagnostics :causes kind] (fnil inc 0))
        (update-in [:diagnostics :events]
                   (fn [evs] (vec (take-last 64 (conj (vec evs) diag))))))))

(defn transition
  "Pure Sans-IO reducer `(transition state event) -> [new-state effects]`.
   Enforces:
   - Stale generation isolation (`ev-gen < current-gen` -> `:ignored-stale-release`, zero mutation)
   - Strict monotonic `seq` floor (`seq <= current-seq` -> `:release-seq-non-monotonic`, zero mutation)
   - Fail-closed genesis, 2-of-3 quorum, headers-config, asset integrity, SHA-384 SRI,
     storage accounting, retention bound, and atomic LKG pin protection
   - Invariant: `(:dropped (:diagnostics st)) == sum(vals(:causes (:diagnostics st)))`."
  [state event]
  (let [st (merge (init-release-state) state)
        cur-gen (long (:generation st 0))
        ev-gen (:generation event)
        etype (:type event)]
    (cond
      (and (some? ev-gen) (< (long ev-gen) cur-gen))
      (let [diag {:type :diagnose
                  :kind :ignored-stale-release
                  :event-type etype
                  :event-generation (long ev-gen)
                  :current-generation cur-gen
                  :reason "stale-generation-callback"}]
        [(record-diagnose st diag) [diag]])

      (= etype :apply-release)
      (let [release (:release event)
            envelope (:envelope event)
            blobs (or (:blobs event) {})
            rel-seq (get-field release :seq "seq")
            cur-seq (long (:current-seq st 0))
            pinned-genesis (:genesis-anchor-cid st)
            rel-genesis (some-> (get-field release :genesis-anchor-cid "genesis_anchor_cid" "genesis-anchor-cid")
                                str str/trim str/lower-case)]
        (cond
          (or (not (hex64? pinned-genesis))
              (not (hex64? rel-genesis))
              (not= pinned-genesis rel-genesis))
          (let [diag {:type :diagnose
                      :kind :release-genesis-missing
                      :reason "genesis-anchor-cid-missing-or-mismatched"}]
            [(-> st (assoc :last-error :release-genesis-missing) (record-diagnose diag)) [diag]])

          (or (not (integer-number? rel-seq))
              (<= (long rel-seq) cur-seq))
          (let [diag {:type :diagnose
                      :kind :release-seq-non-monotonic
                      :current-seq cur-seq
                      :proposed-seq rel-seq
                      :reason (str "seq-" rel-seq "-lte-current-" cur-seq)}]
            [(-> st (assoc :last-error :release-seq-non-monotonic) (record-diagnose diag)) [diag]])

          :else
          (let [val-res (validate-release-bundle
                         release
                         envelope
                         blobs
                         {:genesis-anchor-cid pinned-genesis
                          :trusted-signers (:trusted-signers st)
                          :threshold (:threshold st)
                          :max-bytes (:max-bytes st)
                          :lkg-release-cid (:lkg-release-cid st)})]
            (if-not (:ok? val-res)
              (let [diag (or (first (:effects val-res))
                             {:type :diagnose :kind (:error val-res) :reason (:reason val-res)})]
                [(-> st
                     (assoc :last-error (:error val-res))
                     (record-diagnose diag))
                 [diag]])
              (let [next-gen (max (inc cur-gen) (long (or ev-gen 0)))
                    rcid (:release-cid val-res)
                    new-seq (:seq val-res)
                    pin-lkg? (or (nil? (:lkg-release-cid st)) (true? (:pin-as-lkg? event)))
                    new-lkg-cid (if pin-lkg? rcid (:lkg-release-cid st))
                    new-lkg-rel (if pin-lkg? val-res (:lkg-release st))
                    pinned (cond-> (set (:pinned-release-cids st))
                             rcid (conj rcid)
                             new-lkg-cid (conj new-lkg-cid))
                    st' (assoc st
                               :phase :active
                               :generation next-gen
                               :current-seq new-seq
                               :active-release val-res
                               :lkg-release-cid new-lkg-cid
                               :lkg-release new-lkg-rel
                               :pinned-release-cids pinned
                               :last-error nil)
                    effs [{:type :persist-release-floor
                           :current-seq new-seq
                           :active-release-cid rcid
                           :lkg-release-cid new-lkg-cid}
                          {:type :emit
                           :event :release-activated
                           :release-cid rcid
                           :seq new-seq
                           :generation next-gen}]]
                [st' effs])))))

      (= etype :pin-lkg)
      (let [cid (some-> (:release-cid event) str str/trim str/lower-case)]
        (if-not (hex64? cid)
          (let [diag {:type :diagnose :kind :release-lkg-evicted :reason "invalid-lkg-cid"}]
            [(-> st (assoc :last-error :release-lkg-evicted) (record-diagnose diag)) [diag]])
          [(-> st
               (assoc :lkg-release-cid cid)
               (update :pinned-release-cids (fnil conj #{}) cid))
           []]))

      (= etype :evict-release)
      (let [cid (some-> (:release-cid event) str str/trim str/lower-case)
            active-cid (get-in st [:active-release :release-cid])
            lkg-cid (:lkg-release-cid st)]
        (if (or (= cid lkg-cid) (= cid active-cid))
          (let [diag {:type :diagnose
                      :kind :release-lkg-evicted
                      :release-cid cid
                      :reason "cannot-evict-pinned-lkg-or-active-release"}]
            [(-> st (assoc :last-error :release-lkg-evicted) (record-diagnose diag)) [diag]])
          [(update st :pinned-release-cids disj cid) []]))

      (= etype :check-retention)
      (let [mb (:max-bytes event)
            active-bytes (long (or (get-in st [:active-release :bytes-at-rest]) 0))]
        (if (and (some? mb) (< (long mb) (* 2 active-bytes)))
          (let [diag {:type :diagnose
                      :kind :retention-bound-exceeded
                      :max-bytes (long mb)
                      :active-bytes active-bytes
                      :reason (str "max-bytes-" mb "-lt-2x-active-" active-bytes)}]
            [(-> st (assoc :last-error :retention-bound-exceeded) (record-diagnose diag)) [diag]])
          [(assoc st :max-bytes mb) []]))

      :else
      (let [diag {:type :diagnose
                  :kind :unknown-release-event
                  :event-type etype
                  :reason "unknown-release-event"}]
        [(record-diagnose st diag) [diag]]))))

;; =============================================================================
;; 7. Atomic `/app/*` Asset Response Resolver
;; =============================================================================

(defn sanitize-app-asset-key
  "Maps `/app`, `/app/`, `/app/<asset>`, or `<asset>` to a safe relative asset key.
   Returns `nil` on path traversal (`..`, null bytes, hidden segments)."
  [raw-path]
  (when (and (string? raw-path) (not (str/includes? raw-path "\u0000")))
    (let [no-query (first (str/split raw-path #"[?#]" 2))
          trimmed (str/trim no-query)
          stripped (cond
                     (or (= trimmed "/app") (= trimmed "/app/") (= trimmed "") (= trimmed "/"))
                     "index.html"

                     (str/starts-with? trimmed "/app/")
                     (subs trimmed 5)

                     (str/starts-with? trimmed "app/")
                     (subs trimmed 4)

                     (str/starts-with? trimmed "/")
                     (subs trimmed 1)

                     :else trimmed)
          segs (remove str/blank? (str/split stripped #"[/\\]"))]
      (when-not (some #(or (= % "..") (and (str/starts-with? % ".") (not= % "."))) segs)
        (if (empty? segs)
          "index.html"
          (str/join "/" segs))))))

(defn resolve-app-asset-response
  "Resolves an HTTP request path under `/app/*` strictly against the active validated
   BIP-017b release in `release-state`, attaching security headers exclusively from the
   resolved `:headers-config` CID."
  [release-state req-path blobs-by-cid]
  (let [active (:active-release release-state)]
    (cond
      (nil? active)
      {:ok? false :status 404 :error :no-active-release :effects []}

      :else
      (if-let [asset-key (sanitize-app-asset-key req-path)]
        (if-let [asset-meta (get-in active [:assets asset-key])]
          (let [cid (:cid asset-meta)
                bs (get blobs-by-cid cid)]
            (cond
              (nil? bs)
              {:ok? false
               :status 503
               :error :release-asset-missing
               :effects [{:type :diagnose
                          :kind :release-asset-missing
                          :asset-key asset-key
                          :cid cid
                          :reason (str "active-release-asset-missing:" asset-key)}]}

              (not= cid (crypto/sha256-hex bs))
              {:ok? false
               :status 503
               :error :release-asset-corrupt
               :effects [{:type :diagnose
                          :kind :release-asset-corrupt
                          :asset-key asset-key
                          :cid cid
                          :reason (str "active-release-asset-corrupt:" asset-key)}]}

              :else
              {:ok? true
               :status 200
               :asset-key asset-key
               :cid cid
               :release-cid (:release-cid active)
               :seq (:seq active)
               :headers (merge (:headers active)
                               {"Content-Type" (:content-type asset-meta)
                                "ETag" (str "\"" cid "\"")
                                "X-Bitecho-Blob-Cid" cid
                                "X-Bitecho-Release-Cid" (:release-cid active)
                                "X-Bitecho-Release-Seq" (str (:seq active))})
               :body bs
               :effects []}))
          {:ok? false :status 404 :error :asset-not-found :effects []})
        {:ok? false :status 403 :error :forbidden :effects []}))))
