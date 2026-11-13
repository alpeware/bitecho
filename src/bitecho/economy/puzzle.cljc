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
            [sci.core :as sci]))

(def default-max-steps
  "Default step budget limit for pure SCI puzzle evaluation."
  10000)

(def default-max-bytes
  "Default byte limit for puzzle source and solution payloads."
  16384)

(defn puzzle-cid
  "Computes canonical lowercase 64-character SHA-256 hex CID for a puzzle source string."
  [puzzle-source]
  (let [bs (if (string? puzzle-source)
             (fressian/utf8->bytes puzzle-source)
             puzzle-source)]
    (data/compute-cid bs)))

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
  (let [wrap-1 (fn [f] (fn [& args] (step! 1) (apply f args)))
        alloc (fn [f] (wrap-alloc step! max-bytes f))
        coll (fn [f] (wrap-coll step! f))
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
     'env env-ctx
     '-bitecho-step! (fn [n] (step! (long n)))
     'fn metered-fn-macro
     'sha256 (fn [x]
               (step! 5)
               (let [bs (cond
                          (fressian/bytes? x) x
                          (string? x) (fressian/utf8->bytes x)
                          :else (fressian/encode-canonical x))]
                 (str/lower-case (basalt/bytes->hex (crypto/sha256 bs)))))
     'verify-signature (fn [pubkey-hex msg-data sig-hex]
                         (step! 20)
                         (try
                           (let [bs (cond
                                      (fressian/bytes? msg-data) msg-data
                                      (string? msg-data) (fressian/utf8->bytes msg-data)
                                      :else (fressian/encode-canonical msg-data))]
                             (boolean (crypto/verify pubkey-hex bs sig-hex)))
                           (catch #?(:clj Throwable :cljs :default) _ false)))
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

(defn- normalize-conditions
  [res env-ctx]
  (cond
    (true? res)
    {:valid? true
     :conditions [{:type :release :receiver (:receiver env-ctx) :amount (long (or (:amount env-ctx) 0))}]}

    (or (false? res) (nil? res))
    {:valid? false :error :puzzle-returned-false}

    (or (map? res) (vector? res))
    (let [conditions (if (map? res) (or (:conditions res) [res]) (vec res))]
      (if-not (and (sequential? conditions)
                   (seq conditions)
                   (every? (fn [c]
                             (and (map? c)
                                  (= :release (:type c))
                                  (string? (:receiver c))
                                  (not (str/blank? (:receiver c)))
                                  (integer? (:amount c))
                                  (pos? (long (:amount c)))))
                           conditions))
        {:valid? false :error :invalid-puzzle-conditions}
        (let [total-released (reduce + 0 (map (comp long :amount) conditions))
              env-amount (long (or (:amount env-ctx) 0))]
          (if (> total-released env-amount)
            {:valid? false :error :puzzle-overspend-violation}
            (let [remainder (- env-amount total-released)
                  final-conditions (cond-> conditions
                                     (and (pos? remainder) (string? (:payer env-ctx)))
                                     (conj {:type :refund-remainder
                                            :receiver (:payer env-ctx)
                                            :amount remainder}))]
              {:valid? true :conditions final-conditions})))))

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
                 res (sci/eval-string* ctx puzzle-source)]
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
