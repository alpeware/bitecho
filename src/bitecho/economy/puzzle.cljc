(ns bitecho.economy.puzzle
  "Deterministic ChiaLisp-Style Content-Addressed SCI Puzzle Evaluator for Bitecho.
   Pure Sans-IO smart contract verification for escrow and VOPR simulation.
   Sandboxed evaluation with zero host interop, strict step-bounded fuel,
   size limits, and tokenomic conservation."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]
            [edamame.core :as edamame]
            [sci.core :as sci]))

(def default-max-steps
  "Default step budget limit for pure SCI puzzle evaluation."
  10000)

(def default-max-bytes
  "Default byte limit for puzzle source and solution payloads."
  16384)

(defn- canonicalize-node
  "Recursively converts parsed AST node into a metadata-free, type-tagged canonical representation."
  [x]
  (cond
    (seq? x)
    [:list (mapv canonicalize-node x)]

    (vector? x)
    [:vec (mapv canonicalize-node x)]

    (set? x)
    [:set (vec (sort-by (fn [node] (basalt/bytes->hex (fressian/encode-canonical node)))
                        (mapv canonicalize-node x)))]

    (map? x)
    [:map (vec (sort-by (fn [[k-node _]] (basalt/bytes->hex (fressian/encode-canonical k-node)))
                        (map (fn [[k v]] [(canonicalize-node k) (canonicalize-node v)]) x)))]

    (symbol? x)
    [:sym (some-> (namespace x) str) (name x)]

    (keyword? x)
    [:kw (some-> (namespace x) str) (name x)]

    (integer? x)
    (long x)

    (string? x)
    (str x)

    :else
    x))

(defn canonicalize-puzzle-ast
  "Parses puzzle-source string using edamame, strips comments, whitespace, and line/col metadata,
   and constructs a canonical tagged tree for deterministic content-addressing."
  [puzzle-source]
  (try
    (let [forms (edamame/parse-string-all (str puzzle-source) {:all true})]
      [:puzzle-ast-v1 (mapv canonicalize-node forms)])
    (catch #?(:clj Throwable :cljs :default) _
      nil)))

(defn puzzle-cid
  "Computes canonical lowercase 64-character SHA-256 hex CID for a puzzle source string
   using AST-level canonicalization (comments, whitespace, and metadata stripped)."
  [puzzle-source]
  (if (string? puzzle-source)
    (if-let [ast (canonicalize-puzzle-ast puzzle-source)]
      (data/compute-cid (fressian/encode-canonical ast))
      (data/compute-cid (fressian/utf8->bytes (str/trim puzzle-source))))
    (data/compute-cid puzzle-source)))

(def ^{:doc "Canonical source code of the standard HTLC puzzle."}
  standard-htlc-puzzle-source
  "(fn [env solution]
     (cond
       (= (:mode solution) :payer-authorized)
       [[:release (:amount env) (:receiver env)]]

       (and (= (:mode solution) :preimage)
            (some? (:deliverable-hash env))
            (some? (:preimage solution))
            (= (sha256-hex (:preimage solution)) (:deliverable-hash env)))
       [[:release (:amount env) (:receiver env)]]

       :else []))")

(def ^{:doc "Delayed canonical CID calculation for standard-htlc-puzzle-source."}
  standard-htlc-puzzle-cid
  (delay (puzzle-cid standard-htlc-puzzle-source)))

(defn standard-htlc-cid
  "Returns the canonical CID of the standard HTLC puzzle source."
  []
  @standard-htlc-puzzle-cid)

(def ^:private metered-fn-macro
  (with-meta
    (fn [_&form _&env & decl]
      (let [has-name? (symbol? (first decl))
            fn-name (when has-name? (first decl))
            body (if has-name? (rest decl) decl)
            new-body (if (vector? (first body))
                       (let [params (first body) exprs (rest body)]
                         (list (concat [params] ['(-bitecho-step! 1)] exprs)))
                       (map (fn [arity]
                              (concat [(first arity)] ['(-bitecho-step! 1)] (rest arity)))
                            body))]
        (concat (if fn-name [(symbol "fn*") fn-name] [(symbol "fn*")]) new-body)))
    {:sci/macro true}))

(defn- wrap-alloc
  [step! max-bytes f]
  (fn [& args]
    (let [res (apply f args)
          sz (cond (string? res) (count res) (coll? res) (count res) :else 1)]
      (step! (max 1 sz))
      (when (> sz max-bytes)
        (throw (ex-info "Allocation limit exceeded" {:reason :puzzle-budget-exceeded :size sz})))
      res)))

(defn- wrap-coll
  [step! f]
  (fn [cb & args]
    (let [metered-cb (if (ifn? cb)
                       (fn [& a] (step! 1) (apply cb a))
                       cb)]
      (apply f metered-cb args))))

(defn- build-sandbox-bindings
  [step! solution env-ctx max-bytes]
  (let [eid (or (:intent-id env-ctx) (:escrow-id env-ctx))
        to (or (:timeout-epoch env-ctx) (:expires-epoch env-ctx))
        norm-env (cond-> env-ctx
                   eid (assoc :intent-id eid :escrow-id eid)
                   to (assoc :timeout-epoch to :expires-epoch to))
        wrap-1 (fn [f] (fn [& args] (step! 1) (apply f args)))
        alloc (fn [f] (wrap-alloc step! max-bytes f))
        coll (fn [f] (wrap-coll step! f))
        sha-fn (fn [x]
                 (step! 5)
                 (let [bs (cond
                            (fressian/bytes? x) x
                            (string? x) (fressian/utf8->bytes x)
                            :else (fressian/encode-canonical x))]
                   (str/lower-case (basalt/bytes->hex (crypto/sha256 bs)))))
        sig-fn (fn [pubkey-hex msg-data sig-hex]
                 (step! 20)
                 (try
                   (let [bs (cond
                              (fressian/bytes? msg-data) msg-data
                              (string? msg-data) (fressian/utf8->bytes msg-data)
                              :else (fressian/encode-canonical msg-data))]
                     (boolean (crypto/verify pubkey-hex bs sig-hex)))
                   (catch #?(:clj Throwable :cljs :default) _ false)))
        safe-range (fn [& args]
                     (let [n (case (count args)
                               1 (first args)
                               2 (- (second args) (first args))
                               3 (quot (- (second args) (first args)) (nth args 2))
                               0)]
                       (if (or (> (long n) 256) (< (long n) 0))
                         (throw (ex-info "Range size limit exceeded" {:reason :puzzle-budget-exceeded}))
                         (do
                           (step! (inc (long n)))
                           (apply range args)))))]
    {'solution solution
     'env norm-env
     'escrow norm-env
     'context norm-env
     '-bitecho-step! (fn [n] (step! (long n)))
     'fn metered-fn-macro
     'sha256 sha-fn
     'sha256-hex sha-fn
     'verify-signature sig-fn
     'verify-sig sig-fn
     'bytes= (wrap-1 =)
     '= (wrap-1 =)
     'not= (wrap-1 not=)
     '< (wrap-1 <)
     '<= (wrap-1 <=)
     '> (wrap-1 >)
     '>= (wrap-1 >=)
     '+ (wrap-1 +)
     '- (wrap-1 -)
     '* (wrap-1 *)
     'quot (wrap-1 quot)
     'mod (wrap-1 mod)
     'min (wrap-1 min)
     'max (wrap-1 max)
     'inc (wrap-1 inc)
     'dec (wrap-1 dec)
     'pos? (wrap-1 pos?)
     'zero? (wrap-1 zero?)
     'neg? (wrap-1 neg?)
     'even? (wrap-1 even?)
     'odd? (wrap-1 odd?)
     'true? (wrap-1 true?)
     'false? (wrap-1 false?)
     'nil? (wrap-1 nil?)
     'some? (wrap-1 some?)
     'number? (wrap-1 number?)
     'integer? (wrap-1 integer?)
     'string? (wrap-1 string?)
     'keyword? (wrap-1 keyword?)
     'map? (wrap-1 map?)
     'vector? (wrap-1 vector?)
     'set? (wrap-1 set?)
     'boolean (wrap-1 boolean)
     'not (wrap-1 not)
     'get (wrap-1 get)
     'get-in (wrap-1 get-in)
     'assoc (alloc assoc)
     'dissoc (wrap-1 dissoc)
     'select-keys (wrap-1 select-keys)
     'contains? (wrap-1 contains?)
     'keys (wrap-1 keys)
     'vals (wrap-1 vals)
     'count (wrap-1 count)
     'empty? (wrap-1 empty?)
     'seq (wrap-1 seq)
     'first (wrap-1 first)
     'second (wrap-1 second)
     'last (wrap-1 last)
     'rest (wrap-1 rest)
     'next (wrap-1 next)
     'nth (wrap-1 nth)
     'conj (alloc conj)
     'into (alloc into)
     'vec (alloc vec)
     'set (alloc set)
     'subvec (wrap-1 subvec)
     'str (alloc str)
     'subs (alloc subs)
     'map (coll map)
     'mapv (coll mapv)
     'filter (coll filter)
     'filterv (coll filterv)
     'reduce (coll reduce)
     'every? (coll every?)
     'some (coll some)
     'range safe-range}))

(defn- to-cond-map
  "Coerces vector conditions like [:release amt rec] or [:release rec amt] into condition maps."
  [c]
  (cond
    (map? c) c
    (and (sequential? c) (= :release (first c)))
    (if (number? (second c))
      {:type :release :amount (second c) :receiver (nth c 2 nil)}
      {:type :release :receiver (second c) :amount (nth c 2 nil)})
    (and (sequential? c) (= :refund (first c)))
    (if (number? (second c))
      {:type :refund :amount (second c) :receiver (nth c 2 nil)}
      {:type :refund :receiver (second c) :amount (nth c 2 nil)})
    :else c))

(defn- normalize-conditions
  [res env-ctx]
  (cond
    (true? res)
    {:valid? true
     :conditions [{:type :release :receiver (:receiver env-ctx) :amount (long (or (:amount env-ctx) 0))}]}

    (or (false? res) (nil? res))
    {:valid? false :error :puzzle-returned-false}

    (or (map? res) (vector? res) (seq? res))
    (let [raw-conds (cond (map? res) (or (:conditions res) [res])
                          (or (vector? res) (seq? res)) (vec res)
                          :else [res])
          conditions (mapv to-cond-map raw-conds)
          env-epoch (long (or (:epoch env-ctx) 0))
          env-amount (long (or (:amount env-ctx) 0))]
      (if-not (and (sequential? conditions) (seq conditions) (every? map? conditions))
        {:valid? false :error :invalid-puzzle-conditions}
        (loop [rem conditions
               out-conds []]
          (if (empty? rem)
            (let [final-outs (if (empty? out-conds)
                               [{:type :release :receiver (:receiver env-ctx) :amount env-amount}]
                               out-conds)
                  total-released (reduce + 0 (map (comp long :amount) final-outs))]
              (if (> total-released env-amount)
                {:valid? false :error :puzzle-overspend-violation}
                (let [remainder (- env-amount total-released)
                      final-conditions (cond-> final-outs
                                         (and (pos? remainder) (string? (:payer env-ctx)))
                                         (conj {:type :refund-remainder
                                                :receiver (:payer env-ctx)
                                                :amount remainder}))]
                  {:valid? true :conditions final-conditions})))
            (let [c (first rem)
                  c-type (:type c)]
              (case c-type
                (:assert-epoch-gte :assert-after-epoch)
                (let [min-ep (long (or (:epoch c) (:min-epoch c) 0))]
                  (if (< env-epoch min-ep)
                    {:valid? false :error :epoch-before-min}
                    (recur (rest rem) out-conds)))

                (:assert-epoch-lte :assert-before-epoch)
                (let [max-ep (long (or (:epoch c) (:max-epoch c) #?(:clj Long/MAX_VALUE :cljs js/Number.MAX_SAFE_INTEGER)))]
                  (if (> env-epoch max-ep)
                    {:valid? false :error :epoch-after-max}
                    (recur (rest rem) out-conds)))

                :assert-sig
                (let [pk (:pubkey c)
                      sig (:signature c)
                      raw-msg (or (:message c) (:msg c))
                      bs (cond
                           (fressian/bytes? raw-msg) raw-msg
                           (string? raw-msg) (fressian/utf8->bytes (str raw-msg))
                           :else (fressian/encode-canonical raw-msg))
                      valid-sig? (try
                                   (boolean (and (string? pk) (string? sig) (crypto/verify pk bs sig)))
                                   (catch #?(:clj Throwable :cljs :default) _ false))]
                  (if-not valid-sig?
                    {:valid? false :error :invalid-signature-condition}
                    (recur (rest rem) out-conds)))

                :assert-sha256
                (let [raw-pre (or (:preimage c) (:deliverable c))
                      bs (cond
                           (fressian/bytes? raw-pre) raw-pre
                           (string? raw-pre) (fressian/utf8->bytes (str raw-pre))
                           :else (fressian/encode-canonical raw-pre))
                      computed (str/lower-case (basalt/bytes->hex (crypto/sha256 bs)))
                      expected (str/lower-case (str (or (:hash c) (:deliverable-hash c))))]
                  (if (not= computed expected)
                    {:valid? false :error :hash-mismatch-condition}
                    (recur (rest rem) out-conds)))

                :release
                (let [recv (:receiver c)
                      amt (long (or (:amount c) (:value c) 0))]
                  (if-not (and (string? recv) (not (str/blank? recv)) (pos? amt))
                    {:valid? false :error :invalid-puzzle-conditions}
                    (recur (rest rem) (conj out-conds {:type :release :receiver recv :amount amt}))))

                :refund
                (let [recv (or (:receiver c) (:payer env-ctx))
                      amt (long (or (:amount c) (:value c) 0))]
                  (if-not (and (string? recv)
                               (not (str/blank? recv))
                               (pos? amt)
                               (or (nil? (:payer env-ctx)) (= recv (:payer env-ctx))))
                    {:valid? false :error :invalid-puzzle-conditions}
                    (recur (rest rem) (conj out-conds {:type :refund :receiver recv :amount amt}))))

                ;; Unrecognized condition type
                {:valid? false :error :invalid-puzzle-conditions}))))))

    :else
    {:valid? false :error :puzzle-returned-invalid-type}))

(defn eval-puzzle
  "Evaluates a ChiaLisp-style SCI puzzle source against a solution in an env context.
   Enforces:
   - Size limits for puzzle source and solution
   - Content-address match against (:puzzle-hash env-ctx) when present
   - Step budget limit (max-steps)
   - Zero host interop sandbox (:classes {})
   - Condition validity and conservation (sum <= env amount, remainder auto-refunded)."
  ([puzzle-source solution env-ctx]
   (eval-puzzle puzzle-source solution env-ctx nil))
  ([puzzle-source solution env-ctx opts]
   (let [max-steps (long (or (:max-steps opts) default-max-steps))
         max-bytes (long (or (:max-bytes opts) default-max-bytes))
         src-bytes (when (string? puzzle-source) (fressian/utf8->bytes puzzle-source))
         sol-bytes (try (fressian/encode-canonical (or solution {}))
                        (catch #?(:clj Throwable :cljs :default) _ nil))]
     (cond
       (or (not (string? puzzle-source))
           (nil? src-bytes)
           (> (fressian/count-bytes src-bytes) max-bytes)
           (nil? sol-bytes)
           (> (fressian/count-bytes sol-bytes) max-bytes))
       {:valid? false :error :puzzle-size-exceeded}

       (re-find #"(?:^|[(\s])fn\*(?:[)\s]|$)" puzzle-source)
       {:valid? false :error :puzzle-eval-error :message "fn* is not allowed"}

       (and (:puzzle-hash env-ctx)
            (not= (puzzle-cid puzzle-source) (str/lower-case (:puzzle-hash env-ctx))))
       {:valid? false :error :puzzle-hash-mismatch}

       :else
       (let [steps (volatile! 0)
             step! (fn [^long n]
                     (let [c (vswap! steps + n)]
                       (when (> c max-steps)
                         (throw (ex-info "Puzzle step budget exceeded"
                                         {:reason :puzzle-budget-exceeded :steps c})))))
             bindings (build-sandbox-bindings step! solution env-ctx max-bytes)
             sci-opts {:classes {}
                       :deny ['loop 'recur 'while 'dotimes 'lazy-seq 'iterate 'repeat 'cycle
                              'def 'defn 'defmacro 'eval 'load-string 'resolve 'ns 'var
                              'alter-var-root! 'future 'pcalls 'pmap 'agent 'atom 'ref
                              'volatile! 'vswap! 'vreset! 'rand 'rand-int 'rand-nth 'shuffle
                              'slurp 'spit 'read-line 'pr 'prn 'print 'println]
                       :bindings bindings}]
         (try
           (let [ctx (sci/init sci-opts)
                 raw-res (sci/eval-string* ctx puzzle-source)
                 res (if (fn? raw-res)
                       (raw-res (or env-ctx {}) (or solution {}))
                       raw-res)]
             (normalize-conditions res env-ctx))
           (catch #?(:clj Throwable :cljs :default) e
             (let [d (ex-data e)
                   cause-d (when-let [c #?(:clj (.getCause ^Throwable e) :cljs (.-cause e))]
                             (ex-data c))
                   budget-exceeded? (or (= :puzzle-budget-exceeded (:reason d))
                                        (= :puzzle-budget-exceeded (:reason cause-d)))]
               (if budget-exceeded?
                 {:valid? false :error :puzzle-budget-exceeded}
                 {:valid? false :error :puzzle-eval-error
                  :message #?(:clj (.getMessage ^Throwable e) :cljs (str e))})))))))))
