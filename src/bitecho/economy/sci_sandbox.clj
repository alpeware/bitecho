(ns bitecho.economy.sci-sandbox
  "Strictly isolated, pure-functional, Turing-incomplete Clojure interpreter utilizing sci."
  (:require [bitecho.basalt.core]
            [bitecho.crypto]
            [clojure.edn :as edn]
            [sci.core :as sci])
  (:import [java.io PushbackReader StringReader]))

(def ^:private max-script-size 4096)

(def ^:private forbidden-symbols
  "A set of symbols that are strictly forbidden to enforce a Turing-incomplete environment.
   This prevents iteration and recursion, thereby sidestepping the Halting Problem."
  #{'loop 'recur 'fn 'defn 'defn- 'def 'while 'for 'trampoline})

(defn- contains-forbidden?
  "Recursively walks the AST and returns true if any forbidden symbol is found."
  [ast]
  (some (fn [node]
          (and (symbol? node)
               (forbidden-symbols node)))
        (tree-seq coll? seq ast)))

(defn- validate-ast!
  "Parses the Clojure code string as EDN, and walks the AST to ensure no
   forbidden symbols (e.g. loop, recur) are present. Throws an exception
   if any forbidden construct is found."
  [code]
  (let [reader (PushbackReader. (StringReader. code))]
    (loop []
      (let [form (edn/read {:eof ::eof} reader)]
        (when-not (= form ::eof)
          (when (contains-forbidden? form)
            (throw (ex-info "Script contains forbidden recursive/looping constructs" {:code code})))
          (recur))))))

(def ^:private safe-context-opts
  "A strictly locked down SCI context options with no I/O, state mutations, or infinite sequence generators."
  {:classes {'java.lang.String java.lang.String
             'java.lang.Math java.lang.Math
             'java.lang.Long java.lang.Long
             'java.lang.Double java.lang.Double}
   ;; Limit available namespaces to a basic clojure.core subset.
   ;; Infinite lazy sequence generators like range, repeat, cycle, iterate are omitted.
   :namespaces {'clojure.core {'+ +
                               '- -
                               '* *
                               '/ /
                               '< <
                               '<= <=
                               '> >
                               '>= >=
                               '= =
                               'not= not=
                               'inc inc
                               'dec dec
                               'max max
                               'min min
                               'rem rem
                               'mod mod
                               'quot quot
                               'even? even?
                               'odd? odd?
                               'zero? zero?
                               'pos? pos?
                               'neg? neg?

                               'map map
                               'reduce reduce
                               'filter filter
                               'remove remove
                               'into into
                               'concat concat
                               'first first
                               'rest rest
                               'next next
                               'cons cons
                               'assoc assoc
                               'dissoc dissoc
                               'get get
                               'get-in get-in
                               'update update
                               'update-in update-in
                               'keys keys
                               'vals vals
                               'merge merge
                               'conj conj
                               'count count
                               'empty? empty?
                               'seq seq
                               'vec vec
                               'set set
                               'hash-map hash-map
                               'list list

                               'str str
                               'keyword keyword
                               'symbol symbol
                               'name name
                               'namespace namespace

                               'not not}
                'bitecho.crypto {'verify bitecho.crypto/verify}
                'bitecho.basalt.core {'hex->bytes bitecho.basalt.core/hex->bytes}}
   :allow []
   :deny ['range 'repeat 'iterate 'cycle 'atom 'reset! 'swap! 'compare-and-set!]})

(defn eval-string
  "Evaluates a string of Clojure code in a strictly isolated, pure-functional,
   Turing-incomplete SCI context. Parses and validates the AST to reject iteration
   and recursion to prevent infinite loops, enforcing deterministic evaluation."
  ([code] (eval-string code {}))
  ([code bindings]
   (when (> (count code) max-script-size)
     (throw (ex-info "Script exceeds maximum allowed size"
                     {:max max-script-size
                      :actual (count code)})))
   (validate-ast! code)
   (sci/eval-string code (assoc safe-context-opts :bindings bindings))))
