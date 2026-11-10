(ns bitecho.core.protocol.dns
  "Pure Sans-IO `.cljc` Authoritative DNS & Edge Ingress Protocol Module:
   1. RFC 1035 binary DNS packet decoder and encoder (label pointer compression, loop guard,
      `0x20` case preservation, `A`/`AAAA`/`NS`/`CNAME`/`SOA`/`MX`/`TXT`/`CAA`, `TC=1` truncation).
   2. Subnet-backed authoritative DNS zone resolver (resolving live `dns/<TYPE>/<relative>` and
      `acme/challenge/<token>` Subnet Pointers + Blobs, with Gap G8 `2s`/`6s` liveness filtering
      and fail-safe static-IP fallback).
   3. Pure per-subnet (`/24` IPv4, `/64` IPv6) token-bucket rate limiter & monthly egress tracker.
   4. Pure Gap G17 port `:443` stream classifier (`extract-tls-sni`, `ingress-stream?`, `parse-http-connect-request`).
   Zero I/O or platform-specific socket imports — runs identically on JVM and ClojureScript."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.core.data :as data]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def ^:private bytes? fressian/bytes?)

(defn- u8
  [buf ^long idx]
  #?(:clj  (bit-and (long (aget ^bytes buf (int idx))) 0xff)
     :cljs (bit-and (aget buf idx) 0xff)))

(defn- u16
  [buf ^long idx]
  (bit-or (bit-shift-left (u8 buf idx) 8)
          (u8 buf (inc idx))))

(defn- u32
  [buf ^long idx]
  (let [hi (u16 buf idx)
        lo (u16 buf (+ idx 2))]
    (+ (* (long hi) 65536) (long lo))))

(defn- vec->bytes
  [coll]
  #?(:clj  (byte-array (map unchecked-byte coll))
     :cljs (js/Uint8Array. (clj->js (map #(bit-and % 0xff) coll)))))

(defn- slice-bytes
  [buf ^long start ^long len]
  (let [out (transient [])]
    (dotimes [i len]
      (conj! out (u8 buf (+ start i))))
    (vec->bytes (persistent! out))))

(defn- parse-int-radix
  [s radix]
  #?(:clj  (try (Integer/parseInt s (int radix)) (catch Exception _ nil))
     :cljs (let [n (js/parseInt s radix)] (when-not (js/isNaN n) n))))

;; =============================================================================
;; 1. Pure IPv4 / IPv6 Literal Parser & Formatter (RFC 5952)
;; =============================================================================

(defn parse-ipv4
  "Purely parses a dotted-quad IPv4 literal into a 4-element vector of `0..255` ints, or `nil`."
  [s]
  (when (and (string? s) (not (str/blank? s)))
    (let [parts (str/split (str/trim s) #"\." -1)]
      (when (= 4 (count parts))
        (let [octets (mapv (fn [p]
                             (when (re-matches #"\d{1,3}" p)
                               (let [n (parse-int-radix p 10)]
                                 (when (and (integer? n) (<= 0 (long n) 255)) n))))
                           parts)]
          (when (every? integer? octets)
            octets))))))

(defn format-ipv4
  "Formats 4 unsigned byte ints into a dotted-quad IPv4 string."
  [b0 b1 b2 b3]
  (str (bit-and b0 0xff) "."
       (bit-and b1 0xff) "."
       (bit-and b2 0xff) "."
       (bit-and b3 0xff)))

(defn- parse-hextet
  [s]
  (when (and (string? s) (re-matches #"[0-9a-fA-F]{1,4}" s))
    (let [n (parse-int-radix s 16)]
      (when (and (integer? n) (<= 0 (long n) 0xffff)) n))))

(defn parse-ipv6
  "Purely parses an IPv6 literal (including `::` zero-compression) into a 16-element vector of `0..255` ints, or `nil`."
  [s]
  (when (and (string? s) (str/includes? s ":"))
    (let [clean (str/trim s)
          dbl-cnt (count (re-seq #"::" clean))]
      (when (<= dbl-cnt 1)
        (let [hextets
              (if (= dbl-cnt 1)
                (let [[left-s right-s] (str/split clean #"::" 2)
                      left (if (str/blank? left-s) [] (mapv parse-hextet (str/split left-s #":" -1)))
                      right (if (str/blank? right-s) [] (mapv parse-hextet (str/split right-s #":" -1)))
                      missing (- 8 (+ (count left) (count right)))]
                  (when (and (every? integer? left)
                             (every? integer? right)
                             (>= missing 1))
                    (into (into left (repeat missing 0)) right)))
                (let [parts (str/split clean #":" -1)
                      hs (mapv parse-hextet parts)]
                  (when (and (= 8 (count hs)) (every? integer? hs))
                    hs)))]
          (when (= 8 (count hextets))
            (vec (mapcat (fn [h]
                           [(bit-and (bit-shift-right h 8) 0xff)
                            (bit-and h 0xff)])
                         hextets))))))))

(defn format-ipv6
  "Formats 16 unsigned bytes into canonical lowercase RFC 5952 IPv6 string (compressing longest zero hextet run `>= 2`)."
  [bytes16]
  (let [hextets (vec (for [i (range 0 16 2)]
                       (bit-or (bit-shift-left (bit-and (nth bytes16 i) 0xff) 8)
                               (bit-and (nth bytes16 (inc i)) 0xff))))
        ;; Find longest run of consecutive 0s of length >= 2
        best (loop [idx 0
                    cur-start nil
                    cur-len 0
                    best-start nil
                    best-len 0]
               (if (>= idx 8)
                 (if (and (>= cur-len 2) (> cur-len best-len))
                   [cur-start cur-len]
                   [best-start best-len])
                 (if (zero? (nth hextets idx))
                   (recur (inc idx)
                          (or cur-start idx)
                          (inc cur-len)
                          best-start
                          best-len)
                   (let [[bs bl] (if (and (>= cur-len 2) (> cur-len best-len))
                                   [cur-start cur-len]
                                   [best-start best-len])]
                     (recur (inc idx) nil 0 bs bl)))))
        [z-start z-len] best
        hex-str (fn [h]
                  (str/lower-case #?(:clj (Integer/toHexString (int h))
                                     :cljs (.toString h 16))))]
    (if (and z-start (>= z-len 2))
      (let [left (subvec hextets 0 z-start)
            right (subvec hextets (+ z-start z-len))]
        (str (str/join ":" (map hex-str left))
             "::"
             (str/join ":" (map hex-str right))))
      (str/join ":" (map hex-str hextets)))))

;; =============================================================================
;; 2. RFC 1035 DNS Packet Codec (Decode & Encode)
;; =============================================================================

(def ^{:doc "RFC 1035 DNS RR type keyword to unsigned 16-bit code map."} type->int
  {:A 1
   :NS 2
   :CNAME 5
   :SOA 6
   :MX 15
   :TXT 16
   :AAAA 28
   :OPT 41
   :ANY 255
   :CAA 257})

(def ^{:doc "Unsigned 16-bit DNS RR type code to keyword map."} int->type
  (into {} (map (fn [[k v]] [v k]) type->int)))

(def ^{:doc "RFC 1035 DNS class keyword to unsigned 16-bit code map."} class->int
  {:IN 1
   :ANY 255})

(def ^{:doc "Unsigned 16-bit DNS class code to keyword map."} int->class
  (into {} (map (fn [[k v]] [v k]) class->int)))

(def ^{:doc "RFC 1035 DNS RCODE keyword to 4-bit response code map."} rcode->int
  {:noerror 0
   :formerr 1
   :servfail 2
   :nxdomain 3
   :notimp 4
   :refused 5})

(def ^{:doc "4-bit DNS response code to RCODE keyword map."} int->rcode
  (into {} (map (fn [[k v]] [v k]) rcode->int)))

(defn to-type-int
  "Maps keyword or integer DNS record type to RFC 1035 unsigned 16-bit type code."
  [t]
  (if (integer? t) t (get type->int t 0)))

(defn to-class-int
  "Maps keyword or integer DNS class to RFC 1035 unsigned 16-bit class code."
  [c]
  (if (integer? c) c (get class->int c 1)))

(defn to-rcode-int
  "Maps keyword or integer DNS RCODE to RFC 1035 4-bit response code."
  [r]
  (if (integer? r) r (get rcode->int r 0)))

(defn- read-domain-name
  [buf ^long start-offset]
  (let [len (fressian/count-bytes buf)]
    (loop [offset start-offset
           labels []
           next-offset nil
           visited #{}
           hops 0]
      (when (or (< offset 0) (>= offset len) (> hops 16))
        (throw (ex-info "Malformed DNS domain name or pointer loop" {:type :dns/formerr :offset offset})))
      (let [b (u8 buf offset)]
        (cond
          (zero? b)
          [(str/join "." labels) (or next-offset (inc offset))]

          (= (bit-and b 0xc0) 0xc0)
          (do
            (when (>= (inc offset) len)
              (throw (ex-info "Malformed DNS pointer" {:type :dns/formerr :offset offset})))
            (let [ptr (bit-or (bit-shift-left (bit-and b 0x3f) 8)
                              (u8 buf (inc offset)))]
              (when (or (visited ptr) (< ptr 0) (>= ptr len))
                (throw (ex-info "Invalid DNS pointer loop or out of bounds" {:type :dns/formerr :ptr ptr})))
              (recur ptr
                     labels
                     (or next-offset (+ offset 2))
                     (conj visited ptr)
                     (inc hops))))

          :else
          (let [label-len b
                label-end (+ offset 1 label-len)]
            (when (> label-end len)
              (throw (ex-info "DNS label length exceeds packet boundary" {:type :dns/formerr})))
            (let [label-str (fressian/bytes->utf8 (slice-bytes buf (inc offset) label-len))]
              (recur label-end
                     (conj labels label-str)
                     next-offset
                     visited
                     hops))))))))

(defn- decode-rdata
  [buf ^long rdata-start ^long rdlength type-kw]
  (let [rdata-end (+ rdata-start rdlength)]
    (case type-kw
      :A
      (if (= rdlength 4)
        (format-ipv4 (u8 buf rdata-start)
                     (u8 buf (+ rdata-start 1))
                     (u8 buf (+ rdata-start 2))
                     (u8 buf (+ rdata-start 3)))
        (throw (ex-info "Invalid A record length" {:type :dns/formerr})))

      :AAAA
      (if (= rdlength 16)
        (format-ipv6 (mapv #(u8 buf (+ rdata-start %)) (range 16)))
        (throw (ex-info "Invalid AAAA record length" {:type :dns/formerr})))

      :NS
      (first (read-domain-name buf rdata-start))

      :CNAME
      (first (read-domain-name buf rdata-start))

      :SOA
      (let [[mname off1] (read-domain-name buf rdata-start)
            [rname off2] (read-domain-name buf off1)]
        (when (> (+ off2 20) rdata-end)
          (throw (ex-info "SOA record truncated" {:type :dns/formerr})))
        {:mname mname
         :rname rname
         :serial (u32 buf off2)
         :refresh (u32 buf (+ off2 4))
         :retry (u32 buf (+ off2 8))
         :expire (u32 buf (+ off2 12))
         :minimum (u32 buf (+ off2 16))})

      :MX
      (do
        (when (< rdlength 3)
          (throw (ex-info "MX record too short" {:type :dns/formerr})))
        {:preference (u16 buf rdata-start)
         :exchange (first (read-domain-name buf (+ rdata-start 2)))})

      :TXT
      (loop [pos rdata-start
             txt-vec []]
        (if (>= pos rdata-end)
          txt-vec
          (let [c-len (u8 buf pos)
                next-pos (+ pos 1 c-len)]
            (when (> next-pos rdata-end)
              (throw (ex-info "TXT chunk exceeds RDATA bounds" {:type :dns/formerr})))
            (recur next-pos
                   (conj txt-vec (fressian/bytes->utf8 (slice-bytes buf (inc pos) c-len)))))))

      :CAA
      (do
        (when (< rdlength 2)
          (throw (ex-info "CAA record too short" {:type :dns/formerr})))
        (let [flags (u8 buf rdata-start)
              tag-len (u8 buf (inc rdata-start))
              tag-end (+ rdata-start 2 tag-len)]
          (when (> tag-end rdata-end)
            (throw (ex-info "CAA tag exceeds RDATA length" {:type :dns/formerr})))
          {:flags flags
           :tag (fressian/bytes->utf8 (slice-bytes buf (+ rdata-start 2) tag-len))
           :value (fressian/bytes->utf8 (slice-bytes buf tag-end (- rdata-end tag-end)))}))

      (slice-bytes buf rdata-start rdlength))))

(defn decode-packet
  "Decodes an RFC 1035 binary DNS packet (`byte[]` or `Uint8Array`) into a Clojure map.
   Throws `ex-info` with `{:type :dns/formerr}` on malformed input."
  [buf]
  (let [len (if (bytes? buf) (fressian/count-bytes buf) 0)
        id (when (>= len 2) (u16 buf 0))]
    (when (< len 12)
      (throw (ex-info "Packet too short for DNS header (min 12 bytes)"
                      (cond-> {:type :dns/formerr}
                        id (assoc :id id)))))
    (try
      (let [b2 (u8 buf 2)
            qr? (not (zero? (bit-and b2 0x80)))
            opcode (bit-shift-right (bit-and b2 0x78) 3)
            aa? (not (zero? (bit-and b2 0x04)))
            tc? (not (zero? (bit-and b2 0x02)))
            rd? (not (zero? (bit-and b2 0x01)))
            b3 (u8 buf 3)
            ra? (not (zero? (bit-and b3 0x80)))
            z (bit-shift-right (bit-and b3 0x70) 4)
            rcode-val (bit-and b3 0x0f)
            rcode (get int->rcode rcode-val rcode-val)
            qdcount (u16 buf 4)
            ancount (u16 buf 6)
            nscount (u16 buf 8)
            arcount (u16 buf 10)]
        (loop [i 0
               offset 12
               questions []]
          (if (>= i qdcount)
            (let [parse-rrs (fn [cnt start-offset]
                              (loop [j 0
                                     cur-offset start-offset
                                     rrs []]
                                (if (>= j cnt)
                                  [rrs cur-offset]
                                  (let [[nm next-off] (read-domain-name buf cur-offset)]
                                    (when (> (+ next-off 10) len)
                                      (throw (ex-info "RR header truncated" {:type :dns/formerr})))
                                    (let [t-int (u16 buf next-off)
                                          c-int (u16 buf (+ next-off 2))
                                          ttl (u32 buf (+ next-off 4))
                                          rdlen (u16 buf (+ next-off 8))
                                          rd-start (+ next-off 10)
                                          rd-end (+ rd-start rdlen)]
                                      (when (> rd-end len)
                                        (throw (ex-info "RDATA truncated" {:type :dns/formerr})))
                                      (let [t-kw (get int->type t-int t-int)
                                            rdata (decode-rdata buf rd-start rdlen t-kw)]
                                        (recur (inc j)
                                               rd-end
                                               (conj rrs {:name nm
                                                          :type t-kw
                                                          :class (get int->class c-int c-int)
                                                          :ttl ttl
                                                          :rdata rdata}))))))))
                  [answers off-after-ans] (parse-rrs ancount offset)
                  [authority off-after-ns] (parse-rrs nscount off-after-ans)
                  [additional _off-final] (parse-rrs arcount off-after-ns)]
              {:id id
               :qr? qr?
               :opcode opcode
               :aa? aa?
               :tc? tc?
               :rd? rd?
               :ra? ra?
               :z z
               :rcode rcode
               :qdcount qdcount
               :ancount ancount
               :nscount nscount
               :arcount arcount
               :questions questions
               :answers answers
               :authority authority
               :additional additional})
            (let [[qname next-off] (read-domain-name buf offset)]
              (when (> (+ next-off 4) len)
                (throw (ex-info "Question truncated" {:type :dns/formerr})))
              (let [qtype-int (u16 buf next-off)
                    qclass-int (u16 buf (+ next-off 2))]
                (recur (inc i)
                       (+ next-off 4)
                       (conj questions {:qname qname
                                        :qname-lower (str/lower-case qname)
                                        :qtype (get int->type qtype-int qtype-int)
                                        :qclass (get int->class qclass-int qclass-int)})))))))
      (catch #?(:clj clojure.lang.ExceptionInfo :cljs ExceptionInfo) e
        (throw (ex-info (ex-message e) (assoc (ex-data e) :id id) e))))))

(defn- append-u16
  [v ^long x]
  (-> v
      (conj (bit-and (bit-shift-right x 8) 0xff))
      (conj (bit-and x 0xff))))

(defn- append-u32
  [v ^long x]
  (-> v
      (conj (bit-and (bit-shift-right x 24) 0xff))
      (conj (bit-and (bit-shift-right x 16) 0xff))
      (conj (bit-and (bit-shift-right x 8) 0xff))
      (conj (bit-and x 0xff))))

(defn- append-bytes
  [v bs]
  (let [n (fressian/count-bytes bs)]
    (loop [i 0
           acc v]
      (if (< i n)
        (recur (inc i) (conj acc (u8 bs i)))
        acc))))

(defn- encode-domain-name
  [out-vec comp-map name-str ^long base-offset]
  (let [labels (if (or (nil? name-str) (str/blank? name-str) (= name-str "."))
                 []
                 (str/split (str name-str) #"\."))]
    (loop [rem-labels labels
           out out-vec
           cmap comp-map]
      (if (empty? rem-labels)
        [(conj out 0) cmap]
        (let [suffix (str/lower-case (str/join "." rem-labels))
              curr-pos (+ base-offset (count out))]
          (if-let [ptr-off (get cmap suffix)]
            [(-> out
                 (conj (bit-or 0xc0 (bit-and (bit-shift-right ptr-off 8) 0x3f)))
                 (conj (bit-and ptr-off 0xff)))
             cmap]
            (let [lbl (first rem-labels)
                  lbl-bs (fressian/utf8->bytes lbl)
                  lbl-len (fressian/count-bytes lbl-bs)
                  cmap' (if (< curr-pos 16384)
                          (assoc cmap suffix curr-pos)
                          cmap)
                  out' (-> out
                           (conj lbl-len)
                           (append-bytes lbl-bs))]
              (recur (rest rem-labels) out' cmap'))))))))

(defn- encode-rdata
  [comp-map type-kw rdata ^long base-offset]
  (case type-kw
    :A
    [(or (parse-ipv4 (str rdata))
         (throw (ex-info "Invalid IPv4 literal for A record" {:rdata rdata})))
     comp-map]

    :AAAA
    [(or (parse-ipv6 (str rdata))
         (throw (ex-info "Invalid IPv6 literal for AAAA record" {:rdata rdata})))
     comp-map]

    :NS
    (encode-domain-name [] comp-map (str rdata) base-offset)

    :CNAME
    (encode-domain-name [] comp-map (str rdata) base-offset)

    :SOA
    (let [{:keys [mname rname serial refresh retry expire minimum]} rdata
          [v1 cm1] (encode-domain-name [] comp-map (str mname) base-offset)
          [v2 cm2] (encode-domain-name v1 cm1 (str rname) base-offset)
          v3 (-> v2
                 (append-u32 (long (or serial 0)))
                 (append-u32 (long (or refresh 3600)))
                 (append-u32 (long (or retry 600)))
                 (append-u32 (long (or expire 604800)))
                 (append-u32 (long (or minimum 60))))]
      [v3 cm2])

    :MX
    (let [{:keys [preference exchange]} rdata
          v1 (append-u16 [] (long (or preference 0)))
          [v2 cm2] (encode-domain-name [] comp-map (str exchange) (+ base-offset 2))]
      [(into v1 v2) cm2])

    :TXT
    (let [chunks (cond
                   (vector? rdata) rdata
                   (coll? rdata) (vec rdata)
                   :else [(str rdata)])
          out (reduce (fn [acc chunk]
                        (let [bs (fressian/utf8->bytes (str chunk))
                              total (fressian/count-bytes bs)]
                          (loop [off 0
                                 a acc]
                            (if (< off total)
                              (let [sz (min 255 (- total off))
                                    slice (slice-bytes bs off sz)]
                                (recur (+ off sz) (-> a (conj sz) (append-bytes slice))))
                              a))))
                      []
                      chunks)]
      [out comp-map])

    :CAA
    (let [{:keys [flags tag value]} rdata
          tag-bs (fressian/utf8->bytes (str tag))
          val-bs (fressian/utf8->bytes (str value))
          out (-> [(bit-and (long (or flags 0)) 0xff)
                   (bit-and (fressian/count-bytes tag-bs) 0xff)]
                  (append-bytes tag-bs)
                  (append-bytes val-bs))]
      [out comp-map])

    [(if (bytes? rdata) (append-bytes [] rdata) []) comp-map]))

(defn- encode-packet-vec
  [pkt]
  (let [id (long (or (:id pkt) 0))
        b2 (bit-or (if (:qr? pkt) 0x80 0)
                   (bit-shift-left (bit-and (long (or (:opcode pkt) 0)) 0x0f) 3)
                   (if (:aa? pkt) 0x04 0)
                   (if (:tc? pkt) 0x02 0)
                   (if (:rd? pkt) 0x01 0))
        b3 (bit-or (if (:ra? pkt) 0x80 0)
                   (bit-shift-left (bit-and (long (or (:z pkt) 0)) 0x07) 4)
                   (bit-and (long (to-rcode-int (or (:rcode pkt) :noerror))) 0x0f))
        questions (vec (or (:questions pkt) []))
        answers (vec (or (:answers pkt) []))
        authority (vec (or (:authority pkt) []))
        additional (vec (or (:additional pkt) []))
        hdr (-> []
                (append-u16 id)
                (conj b2 b3)
                (append-u16 (count questions))
                (append-u16 (count answers))
                (append-u16 (count authority))
                (append-u16 (count additional)))
        [after-q cmap-q] (reduce (fn [[out cmap] q]
                                   (let [[out1 cm1] (encode-domain-name out cmap (or (:qname q) "") 0)
                                         out2 (-> out1
                                                  (append-u16 (to-type-int (:qtype q)))
                                                  (append-u16 (to-class-int (:qclass q))))]
                                     [out2 cm1]))
                                 [hdr {}]
                                 questions)
        encode-rr-list (fn [[out cmap] rrs]
                         (reduce (fn [[acc cm] rr]
                                   (let [[acc1 cm1] (encode-domain-name acc cm (or (:name rr) "") 0)
                                         t-kw (:type rr)
                                         t-int (to-type-int t-kw)
                                         c-int (to-class-int (:class rr))
                                         ttl (long (or (:ttl rr) 60))
                                         rdata-base (+ (count acc1) 10)
                                         [rdata-vec cm2] (encode-rdata cm1 t-kw (:rdata rr) rdata-base)
                                         acc2 (-> acc1
                                                  (append-u16 t-int)
                                                  (append-u16 c-int)
                                                  (append-u32 ttl)
                                                  (append-u16 (count rdata-vec))
                                                  (into rdata-vec))]
                                     [acc2 cm2]))
                                 [out cmap]
                                 rrs))
        [after-ans cmap-ans] (encode-rr-list [after-q cmap-q] answers)
        [after-ns cmap-ns] (encode-rr-list [after-ans cmap-ans] authority)
        [after-add _] (encode-rr-list [after-ns cmap-ns] additional)]
    after-add))

(defn encode-packet
  "Encodes a DNS packet map into an RFC 1035 wire format byte array (`byte[]` or `Uint8Array`).
   When `:max-bytes` (e.g. `512` for UDP) is exceeded, cleanly sets `:tc? true` (`TC=1`)
   and truncates answer/authority/additional sections."
  ([pkt] (encode-packet pkt nil))
  ([pkt opts]
   (let [max-bytes (long (or (:max-bytes opts) 65535))
         raw-vec (encode-packet-vec pkt)]
     (if (<= (count raw-vec) max-bytes)
       (vec->bytes raw-vec)
       (vec->bytes (encode-packet-vec (assoc pkt
                                             :tc? true
                                             :answers []
                                             :authority []
                                             :additional [])))))))

;; =============================================================================
;; 3. Authoritative Subnet-Backed Zone Resolver (UNIFICATION.md §4 & Gap G8)
;; =============================================================================

(defn- strip-trailing-dot
  [s]
  (let [st (or s "")]
    (if (str/ends-with? st ".")
      (subs st 0 (dec (count st)))
      st)))

(defn- make-soa-record
  [config now-ms]
  (let [domain (:domain config)
        dns-cfg (:dns config)]
    {:name domain
     :type :SOA
     :class :IN
     :ttl (get dns-cfg :ttl-seconds 60)
     :rdata {:mname (str "ns1." domain)
             :rname (get dns-cfg :hostmaster (str "hostmaster." domain))
             :serial (get dns-cfg :serial (quot (long (or now-ms 1700000000000)) 1000))
             :refresh 3600
             :retry 600
             :expire 604800
             :minimum (get dns-cfg :ttl-seconds 60)}}))

(defn- extract-healthy-nodes
  [state]
  (cond
    (:bitecho.subnet/unified? state)
    (get-in state [:leader-election :healthy-nodes])

    (map? (:leader-election state))
    (get-in state [:leader-election :healthy-nodes])

    :else
    (:healthy-nodes state)))

(defn- lookup-subnet-blob-value
  "Purely reads & decodes a Blob payload referenced by `(subnet, path)` in `state`, if hot in RAM."
  [state path now-ms]
  (when (:bitecho.subnet/unified? state)
    (let [sid (:subnet-id state)
          data-st (:data state)]
      (when-let [ptr (data/resolve-pointer data-st sid path now-ms)]
        (let [blob-res (data/get-blob (:blobs data-st) (:pointer/target ptr))]
          (when (:hit? blob-res)
            (let [bs (get-in blob-res [:blob :blob/bytes])
                  mt (get-in blob-res [:blob :blob/media-type] "")]
              (if (= mt "application/fressian")
                (try (fressian/decode-wire bs)
                     (catch #?(:clj Exception :cljs :default) _ nil))
                (fressian/bytes->utf8 bs)))))))))

(defn- collect-subnet-acme-dns-txt
  "Extracts active `acme/challenge/*` DNS-01 TXT values from a unified Subnet instance."
  [state now-ms]
  (if-not (:bitecho.subnet/unified? state)
    (or (:acme-dns-challenges state) {})
    (let [sid (:subnet-id state)
          data-st (:data state)
          txts (keep (fn [[[psub ppath] _ptr]]
                       (when (and (= psub sid) (str/starts-with? ppath "acme/challenge/"))
                         (when-let [v (lookup-subnet-blob-value state ppath now-ms)]
                           (cond
                             (and (map? v) (string? (:dns-txt v))) (:dns-txt v)
                             (string? v) v
                             :else nil))))
                     (:pointers data-st))]
      (if (seq txts)
        {"_acme-challenge" (vec (distinct txts))}
        {}))))

(defn- has-any-subnet-dns-pointer?
  [state relative now-ms]
  (when (:bitecho.subnet/unified? state)
    (let [sid (:subnet-id state)
          data-st (:data state)
          suffix (str "/" relative)]
      (boolean
       (some (fn [[[psub ppath] _]]
               (and (= psub sid)
                    (str/starts-with? ppath "dns/")
                    (str/ends-with? ppath suffix)
                    (some? (data/resolve-pointer data-st sid ppath now-ms))))
             (:pointers data-st))))))

(defn- resolve-subnet-dns-records
  "Looks up dynamic `dns/<QTYPE>/<relative>` Pointer + Blob records in `state`."
  [state qname relative qtype default-ttl now-ms]
  (when (and (:bitecho.subnet/unified? state) (keyword? qtype))
    (let [path (str "dns/" (name qtype) "/" relative)]
      (when-let [val (lookup-subnet-blob-value state path now-ms)]
        (let [ttl (long (or (when (map? val) (:ttl val)) default-ttl 60))
              raw-recs (cond
                         (and (map? val) (contains? val :records)) (:records val)
                         (and (map? val) (contains? val :rdata)) [(:rdata val)]
                         (vector? val) val
                         :else [val])]
          (mapv (fn [r]
                  {:name qname
                   :type qtype
                   :class :IN
                   :ttl ttl
                   :rdata (if (and (= qtype :TXT) (not (vector? r)))
                            [(str r)]
                            r)})
                raw-recs))))))

(defn- resolve-healthy-or-fallback-ips
  [qname config state query-id ip-key rr-type now-ms]
  (let [all-nodes (get-in config [:cluster :nodes] {})
        healthy-ids (set (extract-healthy-nodes state))
        healthy-ips (vec (keep (fn [nid]
                                 (let [ip (get-in all-nodes [nid ip-key])]
                                   (when (and (string? ip) (not (str/blank? ip)))
                                     ip)))
                               healthy-ids))
        ;; Gap G8 Fail-safe fallback: return all configured static node IPs when healthy set is empty!
        ips (if (seq healthy-ips)
              healthy-ips
              (vec (keep (fn [[_ n]]
                           (let [ip (get n ip-key)]
                             (when (and (string? ip) (not (str/blank? ip)))
                               ip)))
                         (sort-by (comp name first) all-nodes))))
        ttl (get-in config [:dns :ttl-seconds] 60)]
    (if (empty? ips)
      {:answers []
       :authority [(make-soa-record config now-ms)]}
      (let [n (count ips)
            shift (mod (long (or query-id 0)) n)
            rotated (vec (concat (drop shift ips) (take shift ips)))]
        {:answers (mapv (fn [ip]
                          {:name qname
                           :type rr-type
                           :class :IN
                           :ttl ttl
                           :rdata ip})
                        rotated)
         :authority []}))))

(def ^:private node-ingress-map
  {"node1.ingress" :ns1
   "node2.ingress" :ns2
   "node3.ingress" :ns3})

(defn- resolve-static-node-query
  [base-response qname qtype node-cfg ttl config now-ms]
  (case qtype
    (:A :ANY)
    (if-let [ip4 (:ip4 node-cfg)]
      (assoc base-response
             :rcode :noerror
             :answers [{:name qname :type :A :class :IN :ttl ttl :rdata ip4}]
             :authority [])
      (assoc base-response
             :rcode :noerror
             :answers []
             :authority [(make-soa-record config now-ms)]))

    :AAAA
    (if-let [ip6 (:ip6 node-cfg)]
      (assoc base-response
             :rcode :noerror
             :answers [{:name qname :type :AAAA :class :IN :ttl ttl :rdata ip6}]
             :authority [])
      (assoc base-response
             :rcode :noerror
             :answers []
             :authority [(make-soa-record config now-ms)]))

    (assoc base-response
           :rcode :noerror
           :answers []
           :authority [(make-soa-record config now-ms)])))

(defn resolve-query
  "Pure authoritative DNS query resolver over `config` and `subnet-or-cluster-state`.
   - Never performs open recursion (`:ra? false`).
   - Returns `:refused` on out-of-zone queries.
   - Resolves dynamic Subnet Pointers (`dns/<TYPE>/<relative>` and `acme/challenge/<token>`).
   - Preserves Gap G8 (`2s`/`6s` healthy-node filtering + `60s` TTL + fail-safe static-IP fallback)."
  ([config state query-pkt]
   (resolve-query config state query-pkt nil))
  ([config state query-pkt now-ms]
   (let [st #?(:clj (if (instance? clojure.lang.IDeref state) @state state)
               :cljs (if (satisfies? IDeref state) @state state))
         questions (or (:questions query-pkt) [])]
     (if (empty? questions)
       {:id (:id query-pkt)
        :qr? true
        :opcode (or (:opcode query-pkt) 0)
        :aa? false
        :tc? false
        :rd? (boolean (:rd? query-pkt))
        :ra? false
        :rcode :formerr
        :questions []
        :answers []
        :authority []
        :additional []}
       (let [q (first questions)
             qname (or (:qname q) "")
             qname-clean (strip-trailing-dot (str/lower-case (or (:qname-lower q) qname)))
             domain (strip-trailing-dot (str/lower-case (or (:domain config) "")))
             qtype (or (:qtype q) :A)
             query-id (:id query-pkt)
             default-ttl (get-in config [:dns :ttl-seconds] 60)]
         (if-not (or (= qname-clean domain)
                     (str/ends-with? qname-clean (str "." domain)))
           {:id query-id
            :qr? true
            :opcode (or (:opcode query-pkt) 0)
            :aa? false
            :tc? false
            :rd? (boolean (:rd? query-pkt))
            :ra? false
            :rcode :refused
            :questions questions
            :answers []
            :authority []
            :additional []}
           (let [relative (if (= qname-clean domain)
                            "@"
                            (subs qname-clean 0 (- (count qname-clean) (inc (count domain)))))
                 base-response {:id query-id
                                :qr? true
                                :opcode (or (:opcode query-pkt) 0)
                                :aa? true
                                :tc? false
                                :rd? (boolean (:rd? query-pkt))
                                :ra? false
                                :questions questions
                                :additional []}
                 dyn-answers (or (resolve-subnet-dns-records st qname relative qtype default-ttl now-ms)
                                 (when (not= qtype :CNAME)
                                   (resolve-subnet-dns-records st qname relative :CNAME default-ttl now-ms)))]
             (cond
               ;; 1. Explicit dynamic Subnet Pointer match takes precedence (e.g. dns/A/nexus.ingress)
               (seq dyn-answers)
               (assoc base-response
                      :rcode :noerror
                      :answers dyn-answers
                      :authority [])

               ;; 2. Static nameserver glue queries (ns1, ns2, ns3)
               (contains? #{"ns1" "ns2" "ns3"} relative)
               (let [node-kw (keyword relative)
                     node-cfg (get-in config [:cluster :nodes node-kw])
                     ns-ttl (get-in config [:dns :ns-ttl-seconds] 3600)]
                 (resolve-static-node-query base-response qname qtype node-cfg ns-ttl config now-ms))

               ;; 2b. Static node ingress aliases (node1.ingress..node3.ingress)
               (contains? node-ingress-map relative)
               (let [node-kw (get node-ingress-map relative)
                     node-cfg (get-in config [:cluster :nodes node-kw])]
                 (resolve-static-node-query base-response qname qtype node-cfg default-ttl config now-ms))

               :else
               (let [subdomains (set (get-in config [:dns :subdomains]))
                     txt-records (get-in config [:dns :txt-records] {})
                     acme-challenges (collect-subnet-acme-dns-txt st now-ms)
                     acme-rel? (or (= relative "_acme-challenge")
                                   (str/starts-with? relative "_acme-challenge."))
                     configured-host? (or (= relative "@")
                                          (contains? subdomains relative)
                                          (contains? subdomains "*")
                                          (contains? txt-records relative)
                                          acme-rel?
                                          (contains? acme-challenges relative)
                                          (has-any-subnet-dns-pointer? st relative now-ms))]
                 (if-not configured-host?
                   (assoc base-response
                          :rcode :nxdomain
                          :answers []
                          :authority [(make-soa-record config now-ms)])
                   (case qtype
                     :A
                     (if (has-any-subnet-dns-pointer? st relative now-ms)
                       (assoc base-response :rcode :noerror :answers [] :authority [(make-soa-record config now-ms)])
                       (let [{:keys [answers authority]} (resolve-healthy-or-fallback-ips qname config st query-id :ip4 :A now-ms)]
                         (assoc base-response :rcode :noerror :answers answers :authority authority)))

                     :AAAA
                     (if (has-any-subnet-dns-pointer? st relative now-ms)
                       (assoc base-response :rcode :noerror :answers [] :authority [(make-soa-record config now-ms)])
                       (let [{:keys [answers authority]} (resolve-healthy-or-fallback-ips qname config st query-id :ip6 :AAAA now-ms)]
                         (assoc base-response :rcode :noerror :answers answers :authority authority)))

                     :NS
                     (if (= relative "@")
                       (let [ns-ttl (get-in config [:dns :ns-ttl-seconds] 3600)]
                         (assoc base-response
                                :rcode :noerror
                                :answers [{:name qname :type :NS :class :IN :ttl ns-ttl :rdata (str "ns1." domain)}
                                          {:name qname :type :NS :class :IN :ttl ns-ttl :rdata (str "ns2." domain)}
                                          {:name qname :type :NS :class :IN :ttl ns-ttl :rdata (str "ns3." domain)}]
                                :authority []))
                       (assoc base-response :rcode :noerror :answers [] :authority [(make-soa-record config now-ms)]))

                     :SOA
                     (assoc base-response
                            :rcode :noerror
                            :answers [(assoc (make-soa-record config now-ms) :name qname)]
                            :authority [])

                     :MX
                     (if (= relative "@")
                       (let [mx-records (get-in config [:dns :mx-records] [])]
                         (assoc base-response
                                :rcode :noerror
                                :answers (mapv (fn [mx] {:name qname :type :MX :class :IN :ttl default-ttl :rdata mx}) mx-records)
                                :authority []))
                       (assoc base-response :rcode :noerror :answers [] :authority [(make-soa-record config now-ms)]))

                     :TXT
                     (let [merged-txt (merge txt-records acme-challenges)
                           txt-val (or (get merged-txt relative)
                                       (when acme-rel? (get acme-challenges "_acme-challenge")))]
                       (if txt-val
                         (let [items (if (coll? txt-val) txt-val [txt-val])]
                           (assoc base-response
                                  :rcode :noerror
                                  :answers (mapv (fn [item]
                                                   {:name qname
                                                    :type :TXT
                                                    :class :IN
                                                    :ttl default-ttl
                                                    :rdata (if (vector? item) item [(str item)])})
                                                 items)
                                  :authority []))
                         (assoc base-response :rcode :noerror :answers [] :authority [(make-soa-record config now-ms)])))

                     :CAA
                     (if (= relative "@")
                       (let [caa-records (get-in config [:dns :caa-records] [])]
                         (assoc base-response
                                :rcode :noerror
                                :answers (mapv (fn [caa] {:name qname :type :CAA :class :IN :ttl default-ttl :rdata caa}) caa-records)
                                :authority []))
                       (assoc base-response :rcode :noerror :answers [] :authority [(make-soa-record config now-ms)]))

                     :ANY
                     (let [{:keys [answers]} (resolve-healthy-or-fallback-ips qname config st query-id :ip4 :A now-ms)]
                       (if (seq answers)
                         (assoc base-response :rcode :noerror :answers answers :authority [])
                         (assoc base-response
                                :rcode :noerror
                                :answers [(assoc (make-soa-record config now-ms) :name qname)]
                                :authority [])))

                     (assoc base-response
                            :rcode :noerror
                            :answers []
                            :authority [(make-soa-record config now-ms)]))))))))))))

;; =============================================================================
;; 4. Pure Token-Bucket Rate Limiter & Monthly Egress Tracker
;; =============================================================================

(defn init-limiter
  "Initializes pure rate-limiter and monthly egress budget state."
  ([] (init-limiter {}))
  ([opts]
   (merge {:capacity (double (get opts :capacity 100.0))
           :refill-per-sec (double (get opts :refill-per-sec 10.0))
           :monthly-egress-limit-bytes (long (get opts :monthly-egress-limit-bytes 900000000))
           :buckets {}
           :egress-by-month {}}
          (dissoc opts :capacity :refill-per-sec :monthly-egress-limit-bytes))))

(defn ip->subnet-key
  "Normalizes IPv4 to `/24` prefix (`1.2.3.0/24`) and IPv6 to `/64` prefix (`2001:db8:85a3:0::/64`),
   stripping brackets and ports."
  [ip-str]
  (when ip-str
    (let [s (str/trim (str ip-str))]
      (if (or (str/ends-with? s "/24")
              (str/ends-with? s "/64"))
        s
        (let [cleaned (-> s
                          (str/replace #"^\[" "")
                          (str/replace #"\](?::\d+)?$" ""))
              cleaned (if (and (str/includes? cleaned ".")
                               (str/includes? cleaned ":")
                               (not (str/includes? cleaned "::")))
                        (first (str/split cleaned #":"))
                        cleaned)]
          (if-let [v4 (parse-ipv4 cleaned)]
            (str (nth v4 0) "." (nth v4 1) "." (nth v4 2) ".0/24")
            (if-let [v6 (parse-ipv6 cleaned)]
              (let [hextets (for [i (range 0 8 2)]
                              (let [h (bit-or (bit-shift-left (nth v6 i) 8)
                                              (nth v6 (inc i)))]
                                (str/lower-case #?(:clj (Integer/toHexString (int h))
                                                   :cljs (.toString h 16)))))]
                (str (str/join ":" hextets) "::/64"))
              cleaned)))))))

(defn prune-stale-buckets
  "Purely evicts token buckets idle for `>= max-idle-ms`."
  [state now-ms max-idle-ms]
  (let [now-l (long now-ms)
        idle-l (long max-idle-ms)
        active (into {}
                     (remove (fn [[_k b]]
                               (>= (- now-l (long (or (:last-refill-ms b) 0))) idle-l)))
                     (:buckets state {}))]
    (assoc state :buckets active)))

(defn check-and-consume
  "Purely evaluates token consumption against `bucket-key`."
  ([state bucket-key tokens now-ms]
   (check-and-consume state bucket-key tokens now-ms nil))
  ([state bucket-key tokens now-ms opts]
   (let [max-b (long (or (:max-buckets state) 4096))
         state (if (> (count (:buckets state)) max-b)
                 (prune-stale-buckets state now-ms 300000)
                 state)
         capacity (double (or (:capacity opts)
                              (get-in state [:buckets bucket-key :capacity])
                              (:capacity state)
                              100.0))
         refill-rate (double (or (:refill-per-sec opts)
                                 (get-in state [:buckets bucket-key :refill-per-sec])
                                 (:refill-per-sec state)
                                 10.0))
         bucket (get-in state [:buckets bucket-key])
         req-toks (double (max 0.0 tokens))
         now-l (long now-ms)
         tokens-before (if bucket
                         (let [last-ms (long (or (:last-refill-ms bucket) now-l))
                               elapsed (max 0 (- now-l last-ms))
                               refill (* elapsed (/ refill-rate 1000.0))]
                           (min capacity (+ (double (:tokens bucket)) refill)))
                         capacity)
         allowed? (>= tokens-before req-toks)]
     (if allowed?
       (let [rem (- tokens-before req-toks)
             ub (assoc (or bucket {}) :tokens rem :last-refill-ms now-l)]
         {:allowed? true
          :state (assoc-in state [:buckets bucket-key] ub)
          :remaining rem
          :retry-after-ms 0})
       (let [missing (- req-toks tokens-before)
             retry-ms (if (<= refill-rate 0.0)
                        999999999
                        (long (Math/ceil (/ (* missing 1000.0) refill-rate))))
             ub (assoc (or bucket {}) :tokens tokens-before :last-refill-ms now-l)]
         {:allowed? false
          :state (assoc-in state [:buckets bucket-key] ub)
          :remaining tokens-before
          :retry-after-ms retry-ms})))))

(defn record-egress
  "Purely tracks monthly egress bytes under `:egress-by-month`."
  [state bytes-count month-key]
  (let [limit (long (get state :monthly-egress-limit-bytes 900000000))
        cur (long (get-in state [:egress-by-month month-key] 0))
        new-total (+ cur (long (max 0 bytes-count)))
        allowed? (<= new-total limit)]
    {:allowed? allowed?
     :state (assoc-in state [:egress-by-month month-key] new-total)
     :remaining-bytes (long (max 0 (- limit new-total)))}))

;; =============================================================================
;; 5. Pure Port `:443` Passthrough Stream Classifier (Gap G17)
;; =============================================================================

(defn extract-tls-sni
  "Purely extracts lowercase TLS ClientHello SNI `host_name` from `buf` (`<= len` bytes), or `nil`."
  [buf ^long len]
  (try
    (when (and (bytes? buf) (>= len 44)
               (= (u8 buf 0) 0x16)
               (= (u8 buf 1) 0x03)
               (= (u8 buf 5) 0x01))
      (let [sid-len (u8 buf 43)
            cs-offset (+ 44 sid-len)]
        (when (<= (+ cs-offset 2) len)
          (let [cs-len (u16 buf cs-offset)
                comp-offset (+ cs-offset 2 cs-len)]
            (when (<= (+ comp-offset 1) len)
              (let [comp-len (u8 buf comp-offset)
                    exts-offset (+ comp-offset 1 comp-len)]
                (when (<= (+ exts-offset 2) len)
                  (let [exts-len (u16 buf exts-offset)
                        exts-end (min len (+ exts-offset 2 exts-len))]
                    (loop [curr (+ exts-offset 2)]
                      (when (<= (+ curr 4) exts-end)
                        (let [ext-type (u16 buf curr)
                              ext-len (u16 buf (+ curr 2))
                              ext-data-start (+ curr 4)
                              ext-data-end (+ ext-data-start ext-len)]
                          (if (zero? ext-type)
                            (when (<= (+ ext-data-start 5) (min len ext-data-end))
                              (when (zero? (u8 buf (+ ext-data-start 2)))
                                (let [name-len (u16 buf (+ ext-data-start 3))
                                      name-start (+ ext-data-start 5)]
                                  (when (<= (+ name-start name-len) (min len ext-data-end))
                                    (str/lower-case (fressian/bytes->utf8 (slice-bytes buf name-start name-len)))))))
                            (recur ext-data-end)))))))))))))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(defn parse-http-connect-request
  "Purely detects and parses an initial `CONNECT <host>:<port> HTTP/1.x` request in `buf` (`<= len` bytes).
   Returns `{:host <lowercase-host> :port <int>}` or `nil`."
  [buf ^long len]
  (when (and (bytes? buf) (>= len 18)
             (= (u8 buf 0) 67) ;; 'C'
             (= (u8 buf 1) 79) ;; 'O'
             (= (u8 buf 2) 78) ;; 'N'
             (= (u8 buf 3) 78) ;; 'N'
             (= (u8 buf 4) 69) ;; 'E'
             (= (u8 buf 5) 67) ;; 'C'
             (= (u8 buf 6) 84) ;; 'T'
             (= (u8 buf 7) 32)) ;; ' '
    (let [s (fressian/bytes->utf8 (slice-bytes buf 0 (min len 512)))
          first-line (first (str/split s #"\r?\n" 2))]
      (when-let [[_ host port-s] (re-matches #"(?i)^CONNECT\s+\[?([a-z0-9._:-]+)\]?:(\d{1,5})\s+HTTP/1\.[01]$" (str/trim (or first-line "")))]
        (let [p (parse-int-radix port-s 10)]
          (when (and (integer? p) (<= 1 (long p) 65535))
            {:host (str/lower-case host) :port p}))))))

(defn ingress-stream?
  "Purely classifies whether initial bytes at port `:443` represent an ingress stream:
   - RFC 4571 DTLS (`0x16 0xFE` after 2-byte frame length)
   - RFC 4571 STUN (`0x00 0x01` + magic cookie `0x2112A442` after 2-byte frame length)
   - TLS ClientHello SNI matching `ingress.<domain>` or `*.ingress.<domain>`."
  [buf ^long len domain]
  (try
    (cond
      (or (not (bytes? buf)) (< len 4))
      false

      (and (>= len 4)
           (= (u8 buf 2) 0x16)
           (= (u8 buf 3) 0xfe))
      true

      (and (>= len 10)
           (= (u8 buf 2) 0x00)
           (= (u8 buf 3) 0x01)
           (= (u8 buf 6) 0x21)
           (= (u8 buf 7) 0x12)
           (= (u8 buf 8) 0xa4)
           (= (u8 buf 9) 0x42))
      true

      (and (>= len 5)
           (= (u8 buf 0) 0x16)
           (= (u8 buf 1) 0x03)
           (<= 0 (u8 buf 2) 4))
      (if-let [sni (extract-tls-sni buf len)]
        (let [clean-dom (when domain (str/lower-case (str/trim (str domain))))]
          (boolean
           (or (= sni "ingress")
               (str/ends-with? sni ".ingress")
               (when (seq clean-dom)
                 (or (= sni (str "ingress." clean-dom))
                     (str/ends-with? sni (str ".ingress." clean-dom)))))))
        false)

      :else
      false)
    (catch #?(:clj Exception :cljs :default) _ false)))
