(ns bitecho.core.data
  "Universal Sans-IO Data Plane for Bitecho Unification (UNIFICATION.md §§3-4):
   1. `Blob`: Immutable content-addressed byte store keyed by lowercase SHA-256 hex CID,
      with pin refcounting, deterministic unpinned LRU eviction, bounded hot RAM (`128 MiB` default),
      and pure counted `:fetch-blob` cache-miss effects (zero impure read-through callbacks).
   2. `Pointer`: Authority-signed mutable reference `(subnet, path) -> target-cid` (or `nil` tombstone),
      verified against policy-versioned `:subnet/path-acl`, typed proof verifiers (`:self`, `:pop`,
      `:quorum`, `:acme-key-auth`, `:cert`, `:zone`, `:dac`, `:home-set`), clock-free
      `:pointer/leader-term` lexicographic fencing, and per-type expiry skew tolerance.
   100% pure `.cljc` portable across Clojure (JVM) and ClojureScript (Node/Browser)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.protocol.acme :as acme]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def ^:private bytes? fressian/bytes?)

(def default-max-hot-bytes
  "Default maximum hot in-memory Blob byte budget (128 MiB for 1 GB e2-micro nodes)."
  (* 128 1024 1024))

(def default-max-unpinned-bytes
  "Default maximum logical byte budget for unpinned Blobs (128 MiB)."
  (* 128 1024 1024))

(def default-pointer-skew-ms
  "Default clock-skew tolerance for Pointer expiration (5 minutes)."
  300000)

(def acme-pointer-skew-ms
  "Tighter clock-skew tolerance for short-lived ACME challenge Pointers (60 seconds)."
  60000)

;; =============================================================================
;; 1. Blob Primitives & Pure Store Reducer
;; =============================================================================

(defn compute-cid
  "Computes lowercase 64-character SHA-256 hex CID for a byte array."
  [bs]
  (str/lower-case (basalt/bytes->hex (crypto/sha256 bs))))

(defn make-blob
  "Constructs a canonical Blob map from raw bytes (or UTF-8 string) and media-type."
  ([content]
   (make-blob content "application/octet-stream"))
  ([content media-type]
   (let [bs (if (string? content) (fressian/utf8->bytes content) content)
         cid (compute-cid bs)]
     {:blob/cid cid
      :blob/media-type (str (or media-type "application/octet-stream"))
      :blob/bytes bs})))

(defn verify-blob
  "Verifies that a Blob map has valid structure and matching SHA-256 content CID."
  [blob]
  (and (map? blob)
       (string? (:blob/cid blob))
       (some? (:blob/bytes blob))
       (= (str/lower-case (:blob/cid blob))
          (compute-cid (:blob/bytes blob)))))

(defn init-blob-store
  "Initializes an empty pure Blob store state map."
  ([] (init-blob-store nil))
  ([opts]
   {:entries {}
    :hot-bytes 0
    :unpinned-bytes 0
    :access-seq 0
    :max-hot-bytes (long (or (:max-hot-bytes opts) default-max-hot-bytes))
    :max-unpinned-bytes (long (or (:max-unpinned-bytes opts) default-max-unpinned-bytes))
    :diagnostics {:cid-mismatch 0
                  :cache-misses 0
                  :dangling-pointers 0
                  :evicted-unpinned 0
                  :evicted-hot 0}}))

(defn has-blob?
  "Returns true if CID is logically tracked in the Blob store (either hot in RAM or cold/pinned)."
  [store cid]
  (contains? (:entries store) (when cid (str/lower-case (str cid)))))

(defn blob-pinned?
  "Returns true if CID currently has a positive pin reference count."
  [store cid]
  (pos? (long (get-in store [:entries (when cid (str/lower-case (str cid))) :pins] 0))))

(defn- evict-unpinned-lru
  "Evicts unpinned entries in deterministic oldest-access-first order until :unpinned-bytes <= :max-unpinned-bytes."
  [store keep-cid]
  (let [max-u (long (:max-unpinned-bytes store default-max-unpinned-bytes))]
    (loop [st store]
      (if (<= (long (:unpinned-bytes st 0)) max-u)
        st
        (let [candidates (->> (:entries st)
                              (keep (fn [[cid entry]]
                                      (when (and (zero? (long (:pins entry 0)))
                                                 (not= cid keep-cid))
                                        [cid entry])))
                              (sort-by (fn [[cid entry]] [(:last-access entry 0) cid])))]
          (if-let [[victim-cid victim] (first candidates)]
            (let [sz (long (:size victim 0))
                  was-hot? (some? (:bytes victim))]
              (recur (-> st
                         (update :entries dissoc victim-cid)
                         (update :unpinned-bytes #(max 0 (- (long (or % 0)) sz)))
                         (cond-> was-hot?
                           (update :hot-bytes #(max 0 (- (long (or % 0)) sz))))
                         (update-in [:diagnostics :evicted-unpinned] (fnil inc 0)))))
            st))))))

(defn- evict-hot-ram-lru
  "Demotes hot `:bytes` to `nil` (cold metadata) in oldest-access-first order until :hot-bytes <= :max-hot-bytes.
   Pinned entries keep their metadata and pin count in `:entries` so subsequent reads emit `:fetch-blob`."
  [store keep-cid]
  (let [max-h (long (:max-hot-bytes store default-max-hot-bytes))]
    (loop [st store]
      (if (<= (long (:hot-bytes st 0)) max-h)
        st
        (let [candidates (->> (:entries st)
                              (keep (fn [[cid entry]]
                                      (when (and (some? (:bytes entry))
                                                 (not= cid keep-cid))
                                        [cid entry])))
                              (sort-by (fn [[cid entry]] [(:last-access entry 0) cid])))]
          (if-let [[victim-cid victim] (first candidates)]
            (let [sz (long (:size victim 0))]
              (recur (-> st
                         (assoc-in [:entries victim-cid :bytes] nil)
                         (update :hot-bytes #(max 0 (- (long (or % 0)) sz)))
                         (update-in [:diagnostics :evicted-hot] (fnil inc 0)))))
            st))))))

(defn put-blob
  "Purely inserts or warms a Blob in store after verifying `sha256(:blob/bytes) == :blob/cid`.
   Idempotent if CID is already hot in store. Fails closed with counted `:diagnose` on hash mismatch.
   Returns `{:ok? boolean :store updated-store :cid cid :effects [...]}`."
  ([store blob]
   (put-blob store blob 0))
  ([store blob _now-ms]
   (let [raw-cid (:blob/cid blob)
         bs (:blob/bytes blob)
         media-type (str (or (:blob/media-type blob) "application/octet-stream"))]
     (if (or (not (string? raw-cid)) (str/blank? raw-cid) (not (bytes? bs)))
       (let [diag {:effect :diagnose :reason :malformed-blob}
             st' (update-in store [:diagnostics :cid-mismatch] (fnil inc 0))]
         {:ok? false :error :malformed-blob :store st' :effects [diag]})
       (let [norm-cid (str/lower-case (str/trim raw-cid))
             actual-cid (compute-cid bs)]
         (if (not= norm-cid actual-cid)
           (let [diag {:effect :diagnose
                       :reason :blob-cid-mismatch
                       :expected norm-cid
                       :actual actual-cid}
                 st' (update-in store [:diagnostics :cid-mismatch] (fnil inc 0))]
             {:ok? false :error :blob-cid-mismatch :store st' :effects [diag]})
           (let [existing (get-in store [:entries norm-cid])
                 sz (fressian/count-bytes bs)
                 next-seq (inc (long (:access-seq store 0)))
                 prev-mt (:media-type existing)
                 resolved-mt (if (and (some? media-type)
                                      (not (str/blank? media-type))
                                      (not= media-type "application/octet-stream"))
                               media-type
                               (if (and (some? prev-mt)
                                        (not (str/blank? prev-mt))
                                        (not= prev-mt "application/octet-stream"))
                                 prev-mt
                                 (or media-type prev-mt "application/octet-stream")))]
             (if (and existing (some? (:bytes existing)))
               ;; Already present and hot -> idempotent touch (upgrading octet-stream media-type per L-D1)
               {:ok? true
                :cid norm-cid
                :store (-> store
                           (assoc :access-seq next-seq)
                           (assoc-in [:entries norm-cid :last-access] next-seq)
                           (assoc-in [:entries norm-cid :media-type] resolved-mt))
                :effects []}
               (let [pins (long (or (:pins existing) 0))
                     was-present? (some? existing)
                     entry {:cid norm-cid
                            :media-type resolved-mt
                            :bytes bs
                            :size sz
                            :pins pins
                            :last-access next-seq}
                     st1 (-> store
                             (assoc :access-seq next-seq)
                             (assoc-in [:entries norm-cid] entry)
                             (update :hot-bytes (fnil + 0) sz)
                             (cond-> (and (not was-present?) (zero? pins))
                               (update :unpinned-bytes (fnil + 0) sz)))
                     st2 (-> st1
                             (evict-unpinned-lru norm-cid)
                             (evict-hot-ram-lru norm-cid))]
                 {:ok? true :cid norm-cid :store st2 :effects []})))))))))

(defn pin-blob
  "Increments the pin reference count for `cid` (creating a cold pinned placeholder if not yet fetched)."
  [store cid]
  (if (or (nil? cid) (str/blank? (str cid)))
    store
    (let [norm-cid (str/lower-case (str/trim (str cid)))
          existing (get-in store [:entries norm-cid])]
      (if existing
        (let [prev-pins (long (:pins existing 0))
              sz (long (:size existing 0))]
          (-> store
              (assoc-in [:entries norm-cid :pins] (inc prev-pins))
              (cond-> (zero? prev-pins)
                (update :unpinned-bytes #(max 0 (- (long (or % 0)) sz))))))
        (assoc-in store [:entries norm-cid]
                  {:cid norm-cid
                   :media-type "application/octet-stream"
                   :bytes nil
                   :size 0
                   :pins 1
                   :last-access (long (:access-seq store 0))})))))

(defn unpin-blob
  "Decrements the pin reference count for `cid`. When pins reach 0, its bytes count toward
   `:unpinned-bytes` and become eligible for LRU eviction."
  [store cid]
  (if (or (nil? cid) (str/blank? (str cid)))
    store
    (let [norm-cid (str/lower-case (str/trim (str cid)))
          existing (get-in store [:entries norm-cid])]
      (if-not existing
        store
        (let [prev-pins (long (:pins existing 0))
              next-pins (max 0 (dec prev-pins))
              sz (long (:size existing 0))
              became-unpinned? (and (pos? prev-pins) (zero? next-pins))]
          (-> store
              (assoc-in [:entries norm-cid :pins] next-pins)
              (cond-> became-unpinned?
                (update :unpinned-bytes (fnil + 0) sz))
              (evict-unpinned-lru nil)))))))

(defn get-blob
  "Purely looks up `cid` in `store`.
   - On hot RAM hit: updates LRU `:last-access` and returns `{:hit? true :blob {...} :store st' :effects []}`.
   - On cold/missing miss: increments `:cache-misses` and emits a pure counted
     `{:effect :fetch-blob :cid cid :subnet ... :pinned? boolean}` effect for the shell to fulfill."
  ([store cid]
   (get-blob store cid nil))
  ([store cid opts]
   (let [norm-cid (when cid (str/lower-case (str/trim (str cid))))
         entry (when norm-cid (get-in store [:entries norm-cid]))]
     (if (and entry (some? (:bytes entry)))
       (let [next-seq (inc (long (:access-seq store 0)))
             st' (-> store
                     (assoc :access-seq next-seq)
                     (assoc-in [:entries norm-cid :last-access] next-seq))]
         {:hit? true
          :blob {:blob/cid norm-cid
                 :blob/media-type (:media-type entry)
                 :blob/bytes (:bytes entry)}
          :store st'
          :effects []})
       (let [pinned? (boolean (and entry (pos? (long (:pins entry 0)))))
             eff (cond-> {:effect :fetch-blob
                          :cid norm-cid
                          :pinned? pinned?}
                   (:subnet opts) (assoc :subnet (:subnet opts)))
             st' (update-in store [:diagnostics :cache-misses] (fnil inc 0))]
         {:hit? false
          :blob nil
          :store st'
          :effects [eff]})))))

;; =============================================================================
;; 2. Pointer Schema, Path-Prefix ACL, Proofs, Fencing & Tombstones
;; =============================================================================

(defn- normalize-hex
  [s]
  (when (and (string? s) (not (str/blank? s)))
    (str/lower-case (str/trim s))))

(defn canonical-pointer-map
  "Produces the canonical Pointer map (without `:pointer/sig`) used for deterministic Fressian signing."
  [pointer]
  (let [auth (normalize-hex (:pointer/authority pointer))
        sub (str (:pointer/subnet pointer))
        path (str (:pointer/path pointer))
        seq-num (long (:pointer/seq pointer 0))
        target (when-let [t (:pointer/target pointer)] (normalize-hex t))
        proof (or (:pointer/proof pointer) {:proof/type :self})]
    (cond-> {:pointer/authority auth
             :pointer/subnet sub
             :pointer/path path
             :pointer/seq seq-num
             :pointer/target target
             :pointer/proof proof}
      (some? (:pointer/leader-term pointer))
      (assoc :pointer/leader-term (long (:pointer/leader-term pointer)))
      (some? (:pointer/expires pointer))
      (assoc :pointer/expires (long (:pointer/expires pointer))))))

(defn canonical-pointer-signing-payload
  "Returns the domain-separated canonical structure signed by `:pointer/authority`."
  [pointer]
  ["bitecho-pointer-v1" (canonical-pointer-map pointer)])

(defn sign-pointer
  "Signs `pointer` with `authority-privkey` over its canonical Fressian payload."
  [authority-privkey pointer]
  (let [canon (canonical-pointer-map pointer)
        payload (canonical-pointer-signing-payload canon)
        sig-bytes (crypto/sign-canonical authority-privkey payload)
        sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))]
    (assoc canon :pointer/sig (str/lower-case sig-hex))))

(defn create-pop-proof
  "Constructs an agent Proof-of-Possession (`:pop`) map for a directory Pointer,
   supporting optional `:prev-privkey` / `:prev-pubkey` key-rotation continuity."
  ([agent-privkey agent-pubkey authority-pubkey subnet path target-cid]
   (create-pop-proof agent-privkey agent-pubkey authority-pubkey subnet path target-cid nil))
  ([agent-privkey agent-pubkey authority-pubkey subnet path target-cid opts]
   (let [norm-agent (normalize-hex agent-pubkey)
         norm-auth (normalize-hex authority-pubkey)
         norm-prev (normalize-hex (:prev-pubkey opts))
         norm-target (normalize-hex target-cid)
         tuple ["bitecho-pointer-pop-v1"
                norm-auth
                (str subnet)
                (str path)
                norm-target
                norm-agent
                (or norm-prev "")]
         pop-sig (basalt/bytes->hex (crypto/sign-canonical agent-privkey tuple))
         rot-sig (when (and (:prev-privkey opts) norm-prev)
                   (basalt/bytes->hex (crypto/sign-canonical (:prev-privkey opts) tuple)))]
     (cond-> {:proof/type :pop
              :agent-pubkey norm-agent
              :pop-sig (str/lower-case pop-sig)}
       (and norm-prev rot-sig)
       (assoc :prev-pubkey norm-prev
              :rotation-sig (str/lower-case rot-sig))))))

(defn create-quorum-proof
  "Constructs a threshold `:quorum` proof signed by a collection of `{:pubkey :privkey}` signers."
  [signer-maps subnet path seq-num target-cid]
  (let [norm-target (normalize-hex target-cid)
        tuple ["bitecho-pointer-quorum-v1" (str subnet) (str path) (long seq-num) (or norm-target "tombstone")]
        sigs (into {}
                   (map (fn [{:keys [pubkey privkey]}]
                          (let [pk (normalize-hex pubkey)
                                s (basalt/bytes->hex (crypto/sign-canonical privkey tuple))]
                            [pk (str/lower-case s)])))
                   signer-maps)]
    {:proof/type :quorum
     :signatures sigs}))

(defn match-path-pattern
  "Matches a Pointer `:pointer/path` against a policy ACL `:pattern`:
   - Exact string match (e.g. `\"bootstrap\"`, `\"subnet/policy\"`)
   - Prefix wildcard `\"prefix/*\"` (e.g. `\"dns/*\"`, `\"acme/challenge/*\"`)
   - Owner-bound pattern `\"homeset/<pubkey>\"` or `\"head/<pubkey>/*\"`, extracting `{:matched? true :owner <pubkey>}`."
  [pattern path]
  (let [pat (str pattern)
        p (str path)]
    (cond
      (= pat p)
      {:matched? true}

      (str/ends-with? pat "/<pubkey>/*")
      (let [prefix (subs pat 0 (- (count pat) (count "<pubkey>/*")))]
        (if (str/starts-with? p prefix)
          (let [rest-p (subs p (count prefix))
                slash-idx (str/index-of rest-p "/")]
            (if (and slash-idx (pos? slash-idx) (< (inc slash-idx) (count rest-p)))
              {:matched? true :owner (normalize-hex (subs rest-p 0 slash-idx))}
              {:matched? false}))
          {:matched? false}))

      (str/ends-with? pat "/<pubkey>")
      (let [prefix (subs pat 0 (- (count pat) (count "<pubkey>")))]
        (if (str/starts-with? p prefix)
          (let [owner (subs p (count prefix))]
            (if (and (seq owner) (nil? (str/index-of owner "/")))
              {:matched? true :owner (normalize-hex owner)}
              {:matched? false}))
          {:matched? false}))

      (str/ends-with? pat "/*")
      (let [prefix (subs pat 0 (dec (count pat)))]
        {:matched? (str/starts-with? p prefix)})

      :else
      {:matched? false})))

(defn- authorize-path-acl
  "Checks whether `:pointer/authority` (and proof) is authorized for `:pointer/path` under `ctx`."
  [pointer ctx]
  (let [path (:pointer/path pointer)
        auth (normalize-hex (:pointer/authority pointer))
        proof (:pointer/proof pointer)
        path-acl (:path-acl ctx)]
    (if (empty? path-acl)
      {:ok? false :error :missing-path-acl}
      (let [matched-entry (some (fn [rule]
                                  (let [m (match-path-pattern (:pattern rule) path)]
                                    (when (:matched? m)
                                      (assoc rule :match m))))
                                path-acl)]
        (if-not matched-entry
          {:ok? false :error :unauthorized-pointer-path}
          (let [principal (:principal matched-entry)
                ptype (:type principal)
                match-info (:match matched-entry)]
            (case ptype
              :pubkey
              (if (= auth (normalize-hex (:pubkey principal)))
                {:ok? true :principal-type :pubkey}
                {:ok? false :error :unauthorized-pointer-authority})

              :self-path-owner
              (let [owner (:owner match-info)
                    admitted (:admitted-members ctx)]
                (if (and owner
                         (= auth owner)
                         (or (nil? admitted) (contains? (set (map normalize-hex admitted)) auth)))
                  {:ok? true :principal-type :self-path-owner}
                  {:ok? false :error :unauthorized-pointer-authority}))

              :leader
              (let [leaders (set (map normalize-hex (or (:leader-pubkeys ctx) (:trust-anchors ctx) #{})))
                    curr-leader (normalize-hex (:current-leader ctx))
                    term (:pointer/leader-term pointer)]
                (cond
                  (not (integer? term))
                  {:ok? false :error :missing-leader-term}

                  (and (:min-leader-term ctx) (< (long term) (long (:min-leader-term ctx))))
                  {:ok? false :error :stale-leader-term}

                  (not (contains? leaders auth))
                  {:ok? false :error :unauthorized-pointer-authority}

                  (and curr-leader (= (long term) (long (or (:min-leader-term ctx) term))) (not= auth curr-leader))
                  {:ok? false :error :not-active-leader}

                  :else
                  {:ok? true :principal-type :leader}))

              :allowlist
              (let [allowed (set (map normalize-hex (or (:signers principal) (:trust-anchors ctx) (:admitted-members ctx) #{})))]
                (if (contains? allowed auth)
                  {:ok? true :principal-type :allowlist}
                  {:ok? false :error :unauthorized-pointer-authority}))

              :quorum
              (let [signers (set (map normalize-hex (or (:signers principal) (:trust-anchors ctx) #{})))
                    threshold (long (or (:threshold principal) 2))]
                (if (and (= :quorum (:proof/type proof))
                         (contains? signers auth))
                  {:ok? true :principal-type :quorum :signers signers :threshold threshold}
                  {:ok? false :error :quorum-proof-required}))

              :governance
              (let [gov (or (:governance principal) (:governance ctx) {})
                    gtype (:governance/type gov)
                    cold-pk (normalize-hex (:cold-pubkey gov))
                    anchors (set (map normalize-hex (or (:signers gov) (:trust-anchors ctx) #{})))
                    threshold (long (or (:threshold gov) 2))]
                (case gtype
                  :cold-key
                  (if (and cold-pk (= auth cold-pk))
                    {:ok? true :principal-type :cold-key}
                    {:ok? false :error :unauthorized-governance-authority})

                  :quorum
                  (if (and (= :quorum (:proof/type proof)) (contains? anchors auth))
                    {:ok? true :principal-type :quorum :signers anchors :threshold threshold}
                    {:ok? false :error :unauthorized-governance-authority})

                  :cold-key-or-quorum
                  (cond
                    (and cold-pk (= auth cold-pk))
                    {:ok? true :principal-type :cold-key}

                    (and (= :quorum (:proof/type proof)) (contains? anchors auth))
                    {:ok? true :principal-type :quorum :signers anchors :threshold threshold}

                    :else
                    {:ok? false :error :unauthorized-governance-authority})

                  {:ok? false :error :invalid-governance-policy}))

              {:ok? false :error :unknown-principal-type})))))))

(defn- verify-pointer-proof
  "Verifies `:pointer/proof` according to `:proof/type` and ACL context."
  [pointer acl-res ctx]
  (let [proof (or (:pointer/proof pointer) {})
        ptype (:proof/type proof)
        target (normalize-hex (:pointer/target pointer))]
    ;; Explicit tombstones (:pointer/target nil) may use :self or :quorum once ACL passes
    (if (and (nil? target) (= ptype :self) (not= :quorum (:principal-type acl-res)))
      {:ok? true}
      (case ptype
        :self
        (if (= :quorum (:principal-type acl-res))
          {:ok? false :error :quorum-proof-required}
          {:ok? true})

        :pop
        (let [agent-pub (normalize-hex (:agent-pubkey proof))
              pop-sig (:pop-sig proof)
              prev-pub (normalize-hex (:prev-pubkey proof))
              rot-sig (:rotation-sig proof)
              tuple ["bitecho-pointer-pop-v1"
                     (normalize-hex (:pointer/authority pointer))
                     (str (:pointer/subnet pointer))
                     (str (:pointer/path pointer))
                     target
                     agent-pub
                     (or prev-pub "")]]
          (cond
            (or (nil? agent-pub) (str/blank? (str pop-sig)) (nil? target))
            {:ok? false :error :malformed-pop-proof}

            (not (crypto/verify-with-fallback agent-pub tuple pop-sig))
            {:ok? false :error :invalid-pop-signature}

            (and prev-pub (not (and (string? rot-sig)
                                    (crypto/verify-with-fallback prev-pub tuple rot-sig))))
            {:ok? false :error :invalid-rotation-signature}

            :else
            {:ok? true}))

        :quorum
        (let [sigs (:signatures proof)
              allowed (set (map normalize-hex (or (:signers acl-res) (:trust-anchors ctx) #{})))
              threshold (long (or (:threshold acl-res) 2))
              tuple ["bitecho-pointer-quorum-v1"
                     (str (:pointer/subnet pointer))
                     (str (:pointer/path pointer))
                     (long (:pointer/seq pointer 0))
                     (or target "tombstone")]
              valid-signers (keep (fn [[pk sig]]
                                    (let [npk (normalize-hex pk)]
                                      (when (and (contains? allowed npk)
                                                 (string? sig)
                                                 (crypto/verify-with-fallback npk tuple sig))
                                        npk)))
                                  sigs)]
          (if (>= (count (distinct valid-signers)) threshold)
            {:ok? true}
            {:ok? false :error :insufficient-quorum-signatures}))

        :acme-key-auth
        (let [tok (:token proof)
              ka (:key-auth proof)
              path (str (:pointer/path pointer))
              expected-tok (when (str/starts-with? path "acme/challenge/")
                             (subs path (count "acme/challenge/")))
              expected-thumb (:acme-thumbprint ctx)
              blob-entry (when (and target (:blobs ctx))
                           (get-in (:blobs ctx) [:entries target]))
              blob-bs (when blob-entry (:bytes blob-entry))
              blob-ka (when (bytes? blob-bs)
                        (if (= "application/fressian" (:media-type blob-entry))
                          (let [d (try (fressian/decode-wire blob-bs)
                                       (catch #?(:clj Exception :cljs :default) _ nil))]
                            (when (map? d) (:key-auth d)))
                          (str/trim (fressian/bytes->utf8 blob-bs))))]
          (if (and (string? tok)
                   (not (str/blank? tok))
                   (or (nil? expected-tok) (= tok expected-tok))
                   (string? ka)
                   (str/starts-with? ka (str tok "."))
                   (> (count ka) (inc (count tok)))
                   (or (nil? expected-thumb) (= ka (str tok "." expected-thumb)))
                   (or (nil? blob-ka) (= ka blob-ka)))
            {:ok? true}
            {:ok? false :error :invalid-acme-proof}))

        :cert
        (let [raw-fp (:fingerprint proof)
              norm-fp (when (string? raw-fp)
                        (-> raw-fp
                            str/trim
                            str/lower-case
                            (str/replace #"^sha-?256:" "")
                            (str/replace ":" "")
                            str/trim))]
          (if-not (and norm-fp (re-matches #"[0-9a-f]{64}" norm-fp))
            {:ok? false :error :invalid-cert-proof}
            (let [blob-entry (when (and target (:blobs ctx))
                               (get-in (:blobs ctx) [:entries target]))
                  blob-bs (or (when blob-entry (or (:bytes blob-entry) (:blob/bytes blob-entry)))
                              (get-in ctx [:blob :blob/bytes])
                              (get-in ctx [:blob :bytes]))]
              (if-not (bytes? blob-bs)
                {:ok? false :error :missing-cert-blob}
                (let [decoded (when (and blob-entry (= "application/fressian" (:media-type blob-entry)))
                                (try (fressian/decode-wire blob-bs)
                                     (catch #?(:clj Exception :cljs :default) _ nil)))
                      cert-der (cond
                                 (and (map? decoded) (bytes? (:cert-der decoded)))
                                 (:cert-der decoded)

                                 (and (map? decoded) (string? (:cert-pem decoded)))
                                 (acme/extract-first-pem-cert-der (:cert-pem decoded))

                                 (map? decoded)
                                 nil

                                 :else
                                 (or (acme/extract-first-pem-cert-der (fressian/bytes->utf8 blob-bs))
                                     blob-bs))
                      actual-fp (when (bytes? cert-der)
                                  (str/lower-case (basalt/bytes->hex (crypto/sha256 cert-der))))]
                  (if (and actual-fp (= norm-fp actual-fp))
                    {:ok? true}
                    {:ok? false :error :cert-fingerprint-mismatch}))))))

        :zone
        (if (and (integer? (:serial proof)) (not (neg? (long (:serial proof)))))
          {:ok? true}
          {:ok? false :error :invalid-zone-proof})

        :dac
        (let [agent-pub (normalize-hex (:agent-pubkey proof))
              caps (:capabilities proof)
              path (str (:pointer/path pointer))
              path-owner (when (str/starts-with? path "dac/")
                           (let [s (subs path 4)]
                             (when (>= (count s) 64) (normalize-hex s))))
              norm-cap (fn [c] (str/lower-case (str/trim (if (keyword? c) (name c) (str c)))))
              proof-caps (when (and (sequential? caps) (seq caps))
                           (set (map norm-cap caps)))
              ctx-allowed (when (seq (:allowed-dac-capabilities ctx))
                            (set (map norm-cap (:allowed-dac-capabilities ctx))))
              blob-entry (when (and target (:blobs ctx))
                           (get-in (:blobs ctx) [:entries target]))
              blob-bs (when blob-entry (:bytes blob-entry))
              decoded (when (and (bytes? blob-bs) (= "application/fressian" (:media-type blob-entry)))
                        (try (fressian/decode-wire blob-bs)
                             (catch #?(:clj Exception :cljs :default) _ nil)))
              blob-scopes (when (and (map? decoded) (seq (:scopes decoded)))
                            (set (map norm-cap (:scopes decoded))))
              blob-agent (when (and (map? decoded) (string? (:agent-pubkey decoded)))
                           (normalize-hex (:agent-pubkey decoded)))]
          (cond
            (or (nil? agent-pub)
                (nil? proof-caps)
                (and path-owner (not= path-owner agent-pub))
                (and blob-agent (not= blob-agent agent-pub)))
            {:ok? false :error :invalid-dac-proof}

            (or (and ctx-allowed (not (every? ctx-allowed proof-caps)))
                (and blob-scopes (not (every? blob-scopes proof-caps))))
            {:ok? false :error :dac-capability-escalation}

            :else
            {:ok? true}))

        :home-set
        (if (and (sequential? (:candidates proof)) (seq (:candidates proof)))
          {:ok? true}
          {:ok? false :error :invalid-home-set-proof})

        :anchor
        (let [child-sid (:child-subnet proof)
              m-root (normalize-hex (:merkle-root proof))
              child-ep (:child-epoch proof)
              path (str (:pointer/path pointer))
              expected-path (str "anchor/" child-sid)]
          (cond
            (or (not (str/starts-with? path "anchor/"))
                (nil? child-sid)
                (not= path expected-path))
            {:ok? false :error :invalid-anchor-path}

            (or (nil? m-root)
                (not (re-matches #"[0-9a-f]{64}" m-root))
                (not (integer? child-ep))
                (neg? (long child-ep)))
            {:ok? false :error :malformed-anchor-proof}

            :else
            (let [blob-entry (when (and target (:blobs ctx))
                               (get-in (:blobs ctx) [:entries target]))
                  blob-bs (or (when blob-entry (or (:bytes blob-entry) (:blob/bytes blob-entry)))
                              (get-in ctx [:blob :blob/bytes])
                              (get-in ctx [:blob :bytes]))]
              (if-not (bytes? blob-bs)
                {:ok? false :error :missing-anchor-blob}
                (let [decoded (try (fressian/decode-wire blob-bs)
                                   (catch #?(:clj Exception :cljs :default) _ nil))]
                  (if-not (and (map? decoded)
                               (= :subnet-state-root (:bitecho/type decoded))
                               (= (str child-sid) (str (:child-subnet decoded)))
                               (= (str (:pointer/subnet pointer)) (str (:parent-subnet decoded)))
                               (= m-root (normalize-hex (:merkle-root decoded)))
                               (= (long child-ep) (long (:child-epoch decoded -1)))
                               (= (long (:pointer/seq pointer)) (long (:anchor-seq decoded -1)))
                               (= (normalize-hex (:prev-anchor-cid proof)) (normalize-hex (:prev-anchor-cid decoded))))
                    {:ok? false :error :anchor-blob-mismatch}
                    {:ok? true}))))))

        {:ok? false :error :unknown-proof-type}))))

(defn pointer-skew-tolerance-ms
  "Returns clock-skew tolerance in ms for a Pointer (`60s` for `acme/challenge/*`, `5m` default)."
  [pointer ctx]
  (let [path (str (:pointer/path pointer))]
    (cond
      (some? (:skew-tolerance-ms ctx)) (long (:skew-tolerance-ms ctx))
      (str/starts-with? path "acme/challenge/") acme-pointer-skew-ms
      :else default-pointer-skew-ms)))

(defn verify-pointer
  "Purely verifies a Pointer's structure, subnet match, path-prefix ACL, Ed25519 authority signature,
   expiry window (with per-type skew tolerance), and typed proof.
   Returns `{:ok? true :pointer canon-ptr}` or `{:ok? false :error <kw>}`."
  ([pointer]
   (verify-pointer pointer nil))
  ([pointer ctx]
   (if-not (and (map? pointer)
                (string? (:pointer/authority pointer))
                (not (str/blank? (:pointer/authority pointer)))
                (string? (:pointer/subnet pointer))
                (not (str/blank? (:pointer/subnet pointer)))
                (string? (:pointer/path pointer))
                (not (str/blank? (:pointer/path pointer)))
                (integer? (:pointer/seq pointer))
                (pos? (long (:pointer/seq pointer)))
                (string? (:pointer/sig pointer))
                (not (str/blank? (:pointer/sig pointer))))
     {:ok? false :error :malformed-pointer}
     (let [expected-subnet (:subnet ctx)
           ptr-subnet (:pointer/subnet pointer)]
       (if (and expected-subnet (not= (str expected-subnet) (str ptr-subnet)))
         {:ok? false :error :pointer-subnet-mismatch}
         (let [expires (:pointer/expires pointer)
               now-ms (:now-ms ctx)
               skew-ms (pointer-skew-tolerance-ms pointer ctx)]
           (if (and (some? expires) (some? now-ms)
                    (>= (long now-ms) (+ (long expires) skew-ms)))
             {:ok? false :error :pointer-expired}
             (let [acl-res (if (or (nil? ctx) (not (contains? ctx :path-acl)))
                             {:ok? true :principal-type :self-path-owner}
                             (authorize-path-acl pointer ctx))]
               (if-not (:ok? acl-res)
                 acl-res
                 (let [canon (canonical-pointer-map pointer)
                       payload (canonical-pointer-signing-payload canon)
                       auth (:pointer/authority canon)
                       sig (:pointer/sig pointer)]
                   (if-not (crypto/verify-with-fallback auth payload sig)
                     {:ok? false :error :invalid-pointer-signature}
                     (let [proof-res (verify-pointer-proof canon acl-res ctx)]
                       (if-not (:ok? proof-res)
                         proof-res
                         {:ok? true :pointer (assoc canon :pointer/sig (normalize-hex sig))})))))))))))))

;; =============================================================================
;; 3. Combined Pure Data State (Blobs + Pointers Table)
;; =============================================================================

(defn init-data-state
  "Initializes a combined pure Data Plane state (`{:blobs ... :pointers {} :diagnostics ...}`)."
  ([] (init-data-state nil))
  ([opts]
   {:blobs (init-blob-store opts)
    :pointers {}
    :diagnostics {:rejected-pointers 0
                  :stale-pointers 0}}))

(defn put-data-blob
  "Inserts a Blob into `(:blobs state)`, returning `{:ok? ... :state ... :effects [...]}`."
  ([state blob]
   (put-data-blob state blob 0))
  ([state blob now-ms]
   (let [res (put-blob (:blobs state) blob now-ms)]
     (assoc res :state (assoc state :blobs (:store res))))))

(defn pointer-order-tuple
  "Returns `[leader-term seq target sig]` for deterministic supersession comparison."
  [pointer]
  [(long (or (:pointer/leader-term pointer) 0))
   (long (or (:pointer/seq pointer) 0))
   (str (or (:pointer/target pointer) ""))
   (str (or (:pointer/sig pointer) ""))])

(defn apply-pointer
  "Verifies and applies a Pointer to `state` keyed by `[subnet path]`:
   - Invalid/unauthorized/expired -> fails closed with counted `:diagnose` effect (Rule 5).
   - Lower or equal `(leader-term, seq)` (or lower zone `:serial` on `:zone` proofs) -> idempotent stale no-op.
   - Strictly newer -> replaces previous entry, unpins old target Blob CID (if any), and pins new target CID
     (or leaves unpinned when `:pointer/target` is `nil` tombstone)."
  [state pointer ctx]
  (let [full-ctx (cond-> (or ctx {})
                   (nil? (:blobs ctx)) (assoc :blobs (:blobs state)))
        v-res (verify-pointer pointer full-ctx)]
    (if-not (:ok? v-res)
      (let [err (:error v-res)
            diag {:effect :diagnose
                  :reason err
                  :subnet (:pointer/subnet pointer)
                  :path (:pointer/path pointer)}
            st' (update-in state [:diagnostics :rejected-pointers] (fnil inc 0))]
        {:ok? false :applied? false :error err :state st' :effects [diag]})
      (let [valid-ptr (:pointer v-res)
            k [(:pointer/subnet valid-ptr) (:pointer/path valid-ptr)]
            existing (get-in state [:pointers k])
            new-ord (pointer-order-tuple valid-ptr)
            old-ord (when existing (pointer-order-tuple existing))
            zone-serial-stale? (and existing
                                    (= :zone (get-in valid-ptr [:pointer/proof :proof/type]))
                                    (= :zone (get-in existing [:pointer/proof :proof/type]))
                                    (<= (long (get-in valid-ptr [:pointer/proof :serial] 0))
                                        (long (get-in existing [:pointer/proof :serial] 0))))]
        (if (or (and old-ord (<= (compare new-ord old-ord) 0))
                zone-serial-stale?)
          {:ok? true
           :applied? false
           :stale? true
           :state (update-in state [:diagnostics :stale-pointers] (fnil inc 0))
           :effects []}
          (let [old-target (:pointer/target existing)
                new-target (:pointer/target valid-ptr)
                blobs1 (if old-target
                         (unpin-blob (:blobs state) old-target)
                         (:blobs state))
                blobs2 (if new-target
                         (pin-blob blobs1 new-target)
                         blobs1)
                st' (-> state
                        (assoc :blobs blobs2)
                        (assoc-in [:pointers k] valid-ptr))]
            {:ok? true :applied? true :pointer valid-ptr :state st' :effects []}))))))

(defn resolve-pointer
  "Resolves the active Pointer at `(subnet, path)`. Returns `nil` if absent, tombstoned (`:pointer/target nil`),
   or expired relative to optional `now-ms` + skew tolerance."
  ([state subnet path]
   (resolve-pointer state subnet path nil))
  ([state subnet path now-ms]
   (let [data-st (or (:data state) state)
         ptr (get-in data-st [:pointers [(str subnet) (str path)]])]
     (when (and ptr (some? (:pointer/target ptr)))
       (let [exp (:pointer/expires ptr)
             skew (pointer-skew-tolerance-ms ptr nil)]
         (if (and (some? exp) (some? now-ms) (>= (long now-ms) (+ (long exp) skew)))
           nil
           ptr))))))

;; =============================================================================
;; 3. Binary Merkle Tree & Inclusion Proofs (Milestone 12 / RFC 6962)
;; =============================================================================

(defn- prefix-bytes
  "Prepends a single byte `b` to byte sequence `bs` portably across JVM and JS."
  [b bs]
  #?(:clj (let [out (byte-array (inc (alength ^bytes bs)))]
            (aset out 0 (byte b))
            (System/arraycopy bs 0 out 1 (alength ^bytes bs))
            out)
     :cljs (let [out (js/Uint8Array. (inc (.-length bs)))]
             (.set out (js/Uint8Array. #js [(byte b)]) 0)
             (.set out (js/Uint8Array. bs) 1)
             out)))

(defn active-subnet-pointers
  "Returns all active (non-tombstoned, non-expired at `now-ms`) Pointers for `subnet-id`
   in `state`, sorted deterministically by `[(str (:pointer/subnet ptr)) (str (:pointer/path ptr)) (str (:pointer/target ptr))]`."
  ([state subnet-id]
   (active-subnet-pointers state subnet-id nil))
  ([state subnet-id now-ms]
   (let [inst (or (:instance state) state)
         data-st (or (:data inst) inst)
         sid (str subnet-id)]
     (->> (:pointers data-st)
          (keep (fn [[[s p] _ptr]]
                  (when (= (str s) sid)
                    (resolve-pointer data-st sid p now-ms))))
          (sort-by (fn [ptr]
                     [(str (:pointer/subnet ptr))
                      (str (:pointer/path ptr))
                      (str (:pointer/target ptr))]))
          vec))))

(defn merkle-leaf-hash
  "Computes RFC 6962 leaf hash (0x00 prefix) for a Pointer:
   `sha256(0x00 || fressian([\"bitecho-merkle-leaf-v1\" (canonical-pointer-map ptr) sig]))`."
  [pointer]
  (let [canon (canonical-pointer-map pointer)
        sig (normalize-hex (:pointer/sig pointer))
        encoded (fressian/encode-canonical ["bitecho-merkle-leaf-v1" canon sig])
        prefixed (prefix-bytes 0 encoded)]
    (compute-cid prefixed)))

(defn merkle-branch-hash
  "Computes RFC 6962 branch hash (0x01 prefix) for two sibling hashes:
   `sha256(0x01 || fressian([\"bitecho-merkle-branch-v1\" left right]))`."
  [left-hash right-hash]
  (let [l (normalize-hex left-hash)
        r (normalize-hex right-hash)
        encoded (fressian/encode-canonical ["bitecho-merkle-branch-v1" l r])
        prefixed (prefix-bytes 1 encoded)]
    (compute-cid prefixed)))

(defn merkle-empty-root
  "Computes deterministic empty-tree root hash for a subnet."
  [subnet-id]
  (compute-cid (fressian/encode-canonical ["bitecho-merkle-empty-v1" (str subnet-id)])))

(defn compute-merkle-root
  "Computes the deterministic binary Merkle root hash over active Pointers for `subnet-id`."
  ([state subnet-id]
   (compute-merkle-root state subnet-id nil))
  ([state subnet-id now-ms]
   (let [leaves (mapv merkle-leaf-hash (active-subnet-pointers state subnet-id now-ms))]
     (if (empty? leaves)
       (merkle-empty-root subnet-id)
       (loop [level leaves]
         (if (= 1 (count level))
           (first level)
           (recur (mapv (fn [pair]
                          (if (= 2 (count pair))
                            (merkle-branch-hash (first pair) (second pair))
                            (first pair)))
                        (partition-all 2 level)))))))))

(defn generate-merkle-proof
  "Generates an RFC 6962 Merkle inclusion proof for the active Pointer at `(subnet-id, path)`."
  ([state subnet-id path]
   (generate-merkle-proof state subnet-id path nil))
  ([state subnet-id path now-ms]
   (let [active (active-subnet-pointers state subnet-id now-ms)
         target-path (str path)
         target-idx (first (keep-indexed (fn [i ptr]
                                           (when (= (str (:pointer/path ptr)) target-path)
                                             i))
                                         active))]
     (when (some? target-idx)
       (let [ptr (nth active target-idx)
             leaves (mapv merkle-leaf-hash active)
             root (compute-merkle-root state subnet-id now-ms)]
         (loop [level leaves
                idx target-idx
                steps []]
           (if (= 1 (count level))
             {:proof/version "bitecho-merkle-proof-v1"
              :subnet-id (str subnet-id)
              :path target-path
              :pointer ptr
              :leaf-hash (merkle-leaf-hash ptr)
              :leaf-index target-idx
              :leaf-count (count active)
              :steps steps
              :root root}
             (let [next-step (if (even? idx)
                               (when (< (inc idx) (count level))
                                 {:position :right :hash (nth level (inc idx))})
                               {:position :left :hash (nth level (dec idx))})
                   next-level (mapv (fn [pair]
                                      (if (= 2 (count pair))
                                        (merkle-branch-hash (first pair) (second pair))
                                        (first pair)))
                                    (partition-all 2 level))
                   next-idx (quot idx 2)
                   new-steps (cond-> steps next-step (conj next-step))]
               (recur next-level next-idx new-steps)))))))))

(defn verify-merkle-proof
  "Purely verifies an RFC 6962 binary Merkle inclusion proof against optional `expected-root`."
  ([proof]
   (verify-merkle-proof proof nil))
  ([proof expected-root]
   (if-not (and (map? proof)
                (= "bitecho-merkle-proof-v1" (:proof/version proof))
                (map? (:pointer proof))
                (string? (:subnet-id proof))
                (string? (:path proof))
                (= (str (:pointer/subnet (:pointer proof))) (:subnet-id proof))
                (= (str (:pointer/path (:pointer proof))) (:path proof))
                (integer? (:leaf-index proof))
                (integer? (:leaf-count proof))
                (<= 0 (:leaf-index proof))
                (< (:leaf-index proof) (:leaf-count proof))
                (string? (:root proof))
                (re-matches #"[0-9a-f]{64}" (normalize-hex (:root proof)))
                (sequential? (:steps proof)))
     {:ok? false :error :malformed-merkle-proof}
     (let [ptr (:pointer proof)
           auth (:pointer/authority ptr)
           sig (:pointer/sig ptr)
           canon (canonical-pointer-map ptr)
           payload (canonical-pointer-signing-payload canon)]
       (if-not (and (string? auth) (string? sig) (crypto/verify-with-fallback auth payload sig))
         {:ok? false :error :invalid-pointer-signature}
         (let [actual-leaf (merkle-leaf-hash ptr)
               proof-leaf (normalize-hex (:leaf-hash proof))]
           (if-not (= actual-leaf proof-leaf)
             {:ok? false :error :leaf-hash-mismatch}
             (let [fold-res
                   (reduce (fn [acc step]
                             (if-not (:ok? acc)
                               (reduced acc)
                               (let [h (normalize-hex (:hash step))
                                     pos (:position step)]
                                 (if-not (and h (re-matches #"[0-9a-f]{64}" h) (contains? #{:left :right} pos))
                                   (reduced {:ok? false :error :invalid-merkle-step})
                                   (let [curr (:hash acc)
                                         nxt (if (= pos :left)
                                               (merkle-branch-hash h curr)
                                               (merkle-branch-hash curr h))]
                                     {:ok? true :hash nxt})))))
                           {:ok? true :hash actual-leaf}
                           (:steps proof))]
               (if-not (:ok? fold-res)
                 fold-res
                 (let [computed-root (:hash fold-res)
                       proof-root (normalize-hex (:root proof))]
                   (cond
                     (not= computed-root proof-root)
                     {:ok? false :error :root-mismatch :computed-root computed-root}

                     (and (some? expected-root)
                          (not= computed-root (normalize-hex expected-root)))
                     {:ok? false :error :expected-root-mismatch :computed-root computed-root}

                     :else
                     {:ok? true :root computed-root :pointer ptr})))))))))))

