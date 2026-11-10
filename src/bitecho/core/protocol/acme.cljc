(ns bitecho.core.protocol.acme
  "Pure Sans-IO `.cljc` RFC 8555 (ACME v2), RFC 7515 (JWS), RFC 7638 (JWK Thumbprint),
   RFC 4648 §5 (Base64URL), PEM DER extractor, and PKCS#10 DER CSR codec.
   Zero I/O or platform-specific imports — runs identically on JVM and ClojureScript."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def ^:private bytes? fressian/bytes?)

(defn- ubyte-at
  [bs ^long idx]
  #?(:clj  (bit-and (long (aget ^bytes bs (int idx))) 0xff)
     :cljs (bit-and (aget bs idx) 0xff)))

(defn vec->bytes
  "Converts a sequence of unsigned/signed byte integers into a native byte array (`byte[]` or `Uint8Array`)."
  [coll]
  #?(:clj  (byte-array (map unchecked-byte coll))
     :cljs (js/Uint8Array. (clj->js (map #(bit-and % 0xff) coll)))))

(defn bytes->uvec
  "Converts a native byte array into a vector of unsigned byte integers (`0..255`)."
  [bs]
  (let [n (fressian/count-bytes bs)]
    (loop [i 0
           acc (transient [])]
      (if (< i n)
        (recur (inc i) (conj! acc (ubyte-at bs i)))
        (persistent! acc)))))

;; =============================================================================
;; 1. Pure RFC 4648 Base64 & Base64URL Codec + PEM DER Extractor
;; =============================================================================

(def ^:private b64-std-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(def ^:private b64-url-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(def ^:private b64-decode-table
  (into {}
        (concat
         (map-indexed (fn [idx ch] [ch idx]) b64-std-alphabet)
         (map-indexed (fn [idx ch] [ch idx]) b64-url-alphabet))))

(defn- encode-b64-with-alphabet
  [data ^String alphabet pad?]
  (let [bs (cond
             (bytes? data) data
             (string? data) (fressian/utf8->bytes data)
             :else (vec->bytes data))
        len (fressian/count-bytes bs)]
    (loop [i 0
           acc (transient [])]
      (if (>= i len)
        (apply str (persistent! acc))
        (let [b0 (ubyte-at bs i)
              rem (- len i)
              b1 (if (> rem 1) (ubyte-at bs (inc i)) 0)
              b2 (if (> rem 2) (ubyte-at bs (+ i 2)) 0)
              triple (bit-or (bit-shift-left b0 16)
                             (bit-shift-left b1 8)
                             b2)
              c0 (nth alphabet (bit-and (bit-shift-right triple 18) 0x3f))
              c1 (nth alphabet (bit-and (bit-shift-right triple 12) 0x3f))
              c2 (nth alphabet (bit-and (bit-shift-right triple 6) 0x3f))
              c3 (nth alphabet (bit-and triple 0x3f))
              acc1 (-> acc (conj! c0) (conj! c1))
              acc2 (cond
                     (> rem 2) (-> acc1 (conj! c2) (conj! c3))
                     (= rem 2) (cond-> (conj! acc1 c2) pad? (conj! \=))
                     :else (cond-> acc1 pad? (conj! "==")))]
          (recur (+ i 3) acc2))))))

(defn base64-encode
  "Encodes a byte array or UTF-8 string to standard RFC 4648 §4 Base64 with `=` padding."
  [data]
  (encode-b64-with-alphabet data b64-std-alphabet true))

(defn base64url-encode
  "Encodes a byte array or UTF-8 string to RFC 4648 §5 Base64URL without padding."
  [data]
  (encode-b64-with-alphabet data b64-url-alphabet false))

(defn base64url-decode
  "Decodes standard Base64 or RFC 4648 §5 Base64URL (ignoring whitespace and `=` padding) into a byte array.
   Throws `ex-info` on invalid Base64 characters or malformed 1-char trailing quantum."
  [s]
  (let [cleaned (str/replace (or s "") #"[\s=]+" "")
        n (count cleaned)]
    (when (= 1 (mod n 4))
      (throw (ex-info "Invalid Base64/Base64URL input length" {:length n})))
    (loop [i 0
           out (transient [])]
      (if (>= i n)
        (vec->bytes (persistent! out))
        (let [rem (- n i)
              v0 (get b64-decode-table (nth cleaned i))
              v1 (get b64-decode-table (nth cleaned (inc i)))
              v2 (when (> rem 2) (get b64-decode-table (nth cleaned (+ i 2))))
              v3 (when (> rem 3) (get b64-decode-table (nth cleaned (+ i 3))))]
          (when (or (nil? v0) (nil? v1)
                    (and (> rem 2) (nil? v2))
                    (and (> rem 3) (nil? v3)))
            (throw (ex-info "Invalid Base64 character" {:offset i})))
          (let [b0 (bit-or (bit-shift-left v0 2) (bit-shift-right v1 4))
                out1 (conj! out b0)
                out2 (if (> rem 2)
                       (conj! out1 (bit-or (bit-shift-left (bit-and v1 0x0f) 4)
                                           (bit-shift-right v2 2)))
                       out1)
                out3 (if (> rem 3)
                       (conj! out2 (bit-or (bit-shift-left (bit-and v2 0x03) 6)
                                           v3))
                       out2)]
            (recur (+ i 4) out3)))))))

(def ^{:doc "Alias for `base64url-decode` accepting both standard Base64 and Base64URL."}
  base64-decode base64url-decode)

(defn base64url-decode-str
  "Decodes an RFC 4648 §5 Base64URL string into a UTF-8 string."
  [s]
  (fressian/bytes->utf8 (base64url-decode s)))

(defn extract-first-pem-block-der
  "Extracts and Base64-decodes the first `-----BEGIN <label>----- ... -----END <label>-----`
   PEM block matching `label` (e.g. `\"CERTIFICATE\"`) into a DER byte array, or `nil` if absent."
  [pem-str label]
  (when (and (string? pem-str) (not (str/blank? pem-str)))
    (let [begin-marker (str "-----BEGIN " label "-----")
          end-marker (str "-----END " label "-----")
          start-idx (str/index-of pem-str begin-marker)]
      (when start-idx
        (let [body-start (+ start-idx (count begin-marker))
              end-idx (str/index-of pem-str end-marker body-start)]
          (when end-idx
            (try
              (base64-decode (subs pem-str body-start end-idx))
              (catch #?(:clj Exception :cljs :default) _ nil))))))))

(defn extract-first-pem-cert-der
  "Extracts the leaf X.509 certificate DER byte array from a PEM chain string."
  [pem-str]
  (extract-first-pem-block-der pem-str "CERTIFICATE"))

(defn cert-der-sha256-hex
  "Computes lowercase 64-character SHA-256 hex fingerprint over leaf certificate DER bytes."
  [cert-der]
  (when (bytes? cert-der)
    (crypto/sha256-hex cert-der)))

;; =============================================================================
;; 2. Deterministic Minimal JSON Serializer (for JWK / JWS / ACME Payloads)
;; =============================================================================

(defn- escape-json-str
  [s]
  (let [st (str s)
        n (count st)]
    (loop [i 0
           acc (transient ["\""])]
      (if (>= i n)
        (apply str (persistent! (conj! acc "\"")))
        (let [ch (nth st i)
              code #?(:clj (int ch) :cljs (.charCodeAt st i))
              piece (case ch
                      \" "\\\""
                      \\ "\\\\"
                      \backspace "\\b"
                      \formfeed "\\f"
                      \newline "\\n"
                      \return "\\r"
                      \tab "\\t"
                      (if (< code 0x20)
                        (let [hex (str/lower-case #?(:clj (Integer/toHexString code) :cljs (.toString code 16)))
                              padded (str (apply str (repeat (- 4 (count hex)) "0")) hex)]
                          (str "\\u" padded))
                        (str ch)))]
          (recur (inc i) (conj! acc piece)))))))

(defn encode-json
  "Pure deterministic JSON serializer supporting maps (lexicographically sorted keys),
   vectors/sequences, strings, keywords, booleans, integers, and nil."
  [x]
  (cond
    (nil? x) "null"
    (boolean? x) (if x "true" "false")
    (number? x) (str x)
    (keyword? x) (escape-json-str (if-let [ns-part (namespace x)]
                                    (str ns-part "/" (name x))
                                    (name x)))
    (string? x) (escape-json-str x)
    (map? x)
    (let [pairs (->> x
                     (map (fn [[k v]]
                            [(if (keyword? k) (name k) (str k)) v]))
                     (sort-by first)
                     (map (fn [[ks v]]
                            (str (escape-json-str ks) ":" (encode-json v)))))]
      (str "{" (str/join "," pairs) "}"))
    (sequential? x)
    (str "[" (str/join "," (map encode-json x)) "]")
    :else
    (escape-json-str (str x))))

;; =============================================================================
;; 3. RFC 7638 JWK & Thumbprint + RFC 8555 Key Authorization & JWS
;; =============================================================================

(defn pad-or-trim-32-bytes
  "Normalizes an unsigned big-endian coordinate byte array to exact 32 bytes
   (stripping a single leading 0x00 sign byte if 33 bytes, or left-padding with zeros if < 32 bytes)."
  [raw-bytes]
  (let [uvec (bytes->uvec raw-bytes)
        n (count uvec)]
    (cond
      (and (= n 33) (zero? (first uvec)))
      (vec->bytes (subvec uvec 1))

      (= n 32)
      (vec->bytes uvec)

      (< n 32)
      (vec->bytes (into (vec (repeat (- 32 n) 0)) uvec))

      :else
      (throw (ex-info "EC P-256 coordinate exceeds 32 bytes" {:count n})))))

(defn coords->jwk
  "Constructs a canonical P-256 EC JWK map from X and Y affine coordinate byte arrays."
  [x-bytes y-bytes]
  {"crv" "P-256"
   "kty" "EC"
   "x" (base64url-encode (pad-or-trim-32-bytes x-bytes))
   "y" (base64url-encode (pad-or-trim-32-bytes y-bytes))})

(defn canonical-jwk-json
  "Returns RFC 7638 lexicographically ordered canonical JSON string for a P-256 JWK map."
  [jwk]
  (str "{\"crv\":\"" (get jwk "crv" "P-256")
       "\",\"kty\":\"" (get jwk "kty" "EC")
       "\",\"x\":\"" (get jwk "x")
       "\",\"y\":\"" (get jwk "y") "\"}"))

(defn jwk->thumbprint
  "Computes RFC 7638 Base64URL-encoded SHA-256 thumbprint for an EC P-256 JWK map."
  [jwk]
  (base64url-encode (crypto/sha256 (fressian/utf8->bytes (canonical-jwk-json jwk)))))

(defn key-authorization-from-thumbprint
  "Returns RFC 8555 HTTP-01 key authorization string `<token>.<thumbprint>`."
  [token thumbprint]
  (str token "." thumbprint))

(defn dns-01-txt-from-key-auth
  "Returns RFC 8555 DNS-01 TXT value (`base64url(sha256(key-authorization))`)."
  [key-auth]
  (base64url-encode (crypto/sha256 (fressian/utf8->bytes key-auth))))

(defn build-jws-signing-input
  "Builds protected header & payload Base64URL strings plus ASCII signing input `<protected>.<payload>`
   for an RFC 8555 ES256 JWS request."
  [{:keys [kid jwk nonce url payload]}]
  (let [header (cond-> {"alg" "ES256"
                        "nonce" (str nonce)
                        "url" (str url)}
                 kid (assoc "kid" (str kid))
                 (not kid) (assoc "jwk" jwk))
        protected-b64 (base64url-encode (encode-json header))
        payload-b64 (if (or (nil? payload) (= payload :post-as-get))
                      ""
                      (base64url-encode (if (string? payload)
                                          payload
                                          (encode-json payload))))
        signing-input (str protected-b64 "." payload-b64)]
    {:protected protected-b64
     :payload payload-b64
     :signing-input signing-input
     :signing-bytes (fressian/utf8->bytes signing-input)}))

(defn assemble-flattened-jws
  "Assembles the final Flattened JWS JSON string from `build-jws-signing-input` output and raw P1363 signature bytes."
  [{:keys [protected payload]} sig-bytes]
  (encode-json {"protected" protected
                "payload" payload
                "signature" (base64url-encode sig-bytes)}))

;; =============================================================================
;; 4. Pure ASN.1 DER & PKCS#10 CSR Builder (RFC 2986)
;; =============================================================================

(defn der-length
  "Encodes ASN.1 DER definite length bytes."
  [^long len]
  (cond
    (< len 128) [len]
    (< len 256) [0x81 len]
    :else [0x82 (bit-and (bit-shift-right len 8) 0xff) (bit-and len 0xff)]))

(defn der-tlv
  "Encodes an ASN.1 DER Tag-Length-Value byte array."
  [^long tag val-bytes]
  (let [v (if (bytes? val-bytes) (bytes->uvec val-bytes) (vec val-bytes))
        hdr (into [(bit-and tag 0xff)] (der-length (count v)))]
    (vec->bytes (into hdr v))))

(defn der-seq
  "Encodes an ASN.1 DER `SEQUENCE` (`0x30`) over a sequence of DER byte arrays."
  [items]
  (der-tlv 0x30 (mapcat bytes->uvec items)))

(defn der-set
  "Encodes an ASN.1 DER `SET` (`0x31`) over a sequence of DER byte arrays."
  [items]
  (der-tlv 0x31 (mapcat bytes->uvec items)))

(defn der-tagged
  "Encodes an ASN.1 DER context-specific / constructed tag over `items`."
  [^long tag items]
  (der-tlv tag (mapcat bytes->uvec items)))

(defn der-dns-name
  "Encodes a `dNSName [2] IA5String` (`0x82`) GeneralName entry for SubjectAlternativeName."
  [domain]
  (der-tlv 0x82 (fressian/utf8->bytes (str domain))))

(defn der-x500-cn
  "Encodes X.500 Distinguished Name `CN=<common-name>` as ASN.1 DER `Name`:
   `SEQUENCE { SET { SEQUENCE { OID(2.5.4.3), UTF8String(cn) } } }`."
  [common-name]
  (let [cn-oid (vec->bytes [0x06 0x03 0x55 0x04 0x03])
        cn-val (der-tlv 0x0c (fressian/utf8->bytes (str common-name)))
        atv (der-seq [cn-oid cn-val])
        rdn (der-set [atv])]
    (der-seq [rdn])))

(defn build-csr-info-der
  "Builds the DER-encoded PKCS#10 `CertificationRequestInfo` structure for `domains`
   (using `(first domains)` as `CN` and all `domains` in `SubjectAlternativeName`)
   and `spki-der-bytes` (`SubjectPublicKeyInfo` DER)."
  [domains spki-der-bytes]
  (when (empty? domains)
    (throw (ex-info "At least one domain required for CSR" {:domains domains})))
  (let [common-name (first domains)
        san-seq (der-seq (mapv der-dns-name domains))
        san-ext-val (der-tlv 0x04 san-seq)
        san-oid (vec->bytes [0x06 0x03 0x55 0x1d 0x11])
        san-ext (der-seq [san-oid san-ext-val])
        exts-seq (der-seq [san-ext])
        ext-req-oid (vec->bytes [0x06 0x09 0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x09 0x0e])
        attr-seq (der-seq [ext-req-oid (der-set [exts-seq])])
        attrs-tagged (der-tagged 0xa0 [attr-seq])
        subject-der (der-x500-cn common-name)
        version-der (vec->bytes [0x02 0x01 0x00])]
    (der-seq [version-der subject-der spki-der-bytes attrs-tagged])))

(defn assemble-csr-der
  "Wraps `csr-info-der` and DER-encoded `SHA256withECDSA` signature bytes into a complete PKCS#10 DER CSR."
  [csr-info-der der-ecdsa-sig-bytes]
  (let [bit-str (der-tlv 0x03 (into [0] (bytes->uvec der-ecdsa-sig-bytes)))
        ;; OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
        sig-alg (vec->bytes [0x30 0x0a 0x06 0x08 0x2a 0x86 0x48 0xce 0x3d 0x04 0x03 0x02])]
    (der-seq [csr-info-der sig-alg bit-str])))

;; =============================================================================
;; 5. Pure ACME Renewal, Subnet Readiness, and Backoff Predicates
;; =============================================================================

(defn needs-renewal?
  "Purely evaluates whether ACME certificate provisioning/renewal should run given `config`,
   `bundle` (`{:self-signed? boolean :expires-at ms}` or `nil`), and `now-ms`."
  [config bundle now-ms]
  (let [acme-cfg (get config :acme {})
        enabled? (get acme-cfg :enabled? true)]
    (boolean
     (and enabled?
          (let [renew-days (long (get acme-cfg :renew-before-days 30))
                renew-window-ms (* renew-days 86400000)]
            (or (nil? bundle)
                (:self-signed? bundle)
                (let [exp (:expires-at bundle)]
                  (or (nil? exp)
                      (< (- (long exp) (long now-ms)) renew-window-ms)))))))))

(defn subnet-ready-for-acme?
  "Purely evaluates whether a Subnet `:leader-election` state has elected this node `:leader`
   and all configured nodes are currently healthy (preventing HTTP-01 validation races during rolling restarts)."
  [le-state]
  (if (nil? le-state)
    true
    (let [all-nodes (:all-nodes le-state)
          healthy-nodes (:healthy-nodes le-state)]
      (and (= :leader (:role le-state))
           (or (empty? all-nodes)
               (= (set all-nodes) (set healthy-nodes)))))))

(defn compute-backoff-ms
  "Computes bounded exponential backoff (`min(24h, base-ms * 2^min(failures, 10))`)."
  [base-backoff-ms consecutive-failures]
  (let [base (long (or base-backoff-ms 60000))
        f (min 10 (max 0 (long (or consecutive-failures 1))))]
    (min 86400000 (* base (bit-shift-left 1 f)))))
