(ns bitecho.errors.core
  "Canonical Send-Path Error Taxonomy (BIP-022 Stage A, Row 9; Rules 2 & 5).
   Pure Sans-IO `.cljc` error constructor, classifier, wire serializer, and Rule 5 `:diagnose`
   emitter shared identically across Browser, Node Light, JVM Light, and Full Node shells."
  (:require [clojure.string :as str]))

(def valid-categories
  "Canonical error category set defined by BIP-022 §4.1 A.3."
  #{:auth :transport :session :storage :lifecycle :validation})

(def error-catalog
  "Canonical map of error keyword -> {:category :recoverable? :diagnose-reason}."
  {:session-not-open          {:category :session    :recoverable? true  :diagnose-reason :session-not-open}
   :session-not-found         {:category :session    :recoverable? false :diagnose-reason :session-not-found}
   :session-quarantined       {:category :session    :recoverable? true  :diagnose-reason :session-quarantined}
   :replay-rejected           {:category :session    :recoverable? false :diagnose-reason :replay-rejected}
   :subnet-mismatch           {:category :validation :recoverable? false :diagnose-reason :subnet-mismatch}
   :insufficient-balance      {:category :validation :recoverable? false :diagnose-reason :insufficient-balance}
   :payload-too-large         {:category :validation :recoverable? false :diagnose-reason :payload-too-large}
   :invalid-request           {:category :validation :recoverable? false :diagnose-reason :invalid-request}
   :peer-unreachable          {:category :transport  :recoverable? true  :diagnose-reason :peer-unreachable}
   :transport-disconnected    {:category :transport  :recoverable? true  :diagnose-reason :transport-disconnected}
   :dial-failed               {:category :transport  :recoverable? true  :diagnose-reason :dial-failed}
   :p2p-no-candidates         {:category :transport  :recoverable? true  :diagnose-reason :p2p-no-candidates}
   :send-failed               {:category :transport  :recoverable? true  :diagnose-reason :send-failed}
   :hardware-unlock-required  {:category :auth       :recoverable? true  :diagnose-reason :hardware-unlock-required}
   :keystore-unlock-failed    {:category :auth       :recoverable? true  :diagnose-reason :keystore-unlock-failed}
   :storage-publish-failed    {:category :storage    :recoverable? true  :diagnose-reason :storage-publish-failed}
   :artifact-out-write-failed {:category :storage    :recoverable? true  :diagnose-reason :artifact-out-write-failed}
   :duplicate-instance        {:category :lifecycle  :recoverable? false :diagnose-reason :duplicate-instance}
   :unknown-error             {:category :lifecycle  :recoverable? false :diagnose-reason :unknown-error}})

(def canonical-error-codes
  "Set of all canonical BIP-022 Stage A error keywords."
  (set (keys error-catalog)))

(defn- sanitize-detail-value
  [v]
  (cond
    (or (nil? v) (boolean? v) (number? v) (keyword? v)) v
    (string? v) (let [trimmed (str/trim (first (str/split-lines v)))]
                  (if (> (count trimmed) 240)
                    (subs trimmed 0 240)
                    trimmed))
    (map? v) (reduce-kv (fn [acc k val]
                          (assoc acc
                                 (if (keyword? k) k (str k))
                                 (sanitize-detail-value val)))
                        {}
                        v)
    (sequential? v) (mapv sanitize-detail-value (take 32 v))
    (set? v) (mapv sanitize-detail-value (take 32 v))
    :else (sanitize-detail-value (str v))))

(defn sanitize-detail
  "Normalizes an error detail payload into a clean, serializable map with zero raw exception objects
   or multi-line stack traces."
  [detail]
  (cond
    (nil? detail) {}
    (map? detail) (sanitize-detail-value detail)
    :else {:reason (sanitize-detail-value detail)}))

(defn classify-error
  "Classifies any raw keyword, string, or legacy shell error token into a canonical error keyword
   from `canonical-error-codes`. Never leaks raw Java/JS stack trace text as an error code."
  [raw-err]
  (cond
    (contains? error-catalog raw-err) raw-err

    (keyword? raw-err)
    (classify-error (name raw-err))

    (string? raw-err)
    (let [s (-> raw-err str/trim str/lower-case)]
      (cond
        (contains? error-catalog (keyword s)) (keyword s)
        (or (= s "not-connected")
            (= s "disconnected")
            (str/includes? s "not-connected")
            (str/includes? s "transport-disconnected")) :transport-disconnected
        (or (= s "hardware-unlock-required")
            (str/includes? s "hardware-unlock")) :hardware-unlock-required
        (or (= s "keystore-unlock-failed")
            (str/includes? s "keystore-unlock")) :keystore-unlock-failed
        (or (= s "session-not-open")
            (str/includes? s "session-not-open")) :session-not-open
        (or (= s "session-not-found")
            (str/includes? s "session-not-found")) :session-not-found
        (or (= s "session-quarantined")
            (str/includes? s "quarantin")) :session-quarantined
        (or (= s "replay-detected")
            (= s "replay-rejected")
            (str/includes? s "replay")) :replay-rejected
        (or (= s "subnet-mismatch")
            (str/includes? s "subnet-mismatch")) :subnet-mismatch
        (or (= s "insufficient-balance")
            (= s "insufficient-funds")
            (str/includes? s "insufficient-balance")) :insufficient-balance
        (or (= s "payload-too-large")
            (str/includes? s "too-large")) :payload-too-large
        (or (= s "storage-publish-failed")
            (str/includes? s "storage-publish")) :storage-publish-failed
        (or (= s "artifact-out-write-failed")
            (str/includes? s "artifact-out-write")) :artifact-out-write-failed
        (or (= s "duplicate-instance")
            (str/includes? s "duplicate-instance")) :duplicate-instance
        (or (= s "p2p-no-candidates")
            (str/includes? s "no-candidates")) :p2p-no-candidates
        (or (= s "dial-failed")
            (str/includes? s "connectexception")
            (str/includes? s "econnrefused")) :dial-failed
        (or (= s "mesh-send-failed")
            (= s "peer-unreachable")
            (str/includes? s "unreachable")) :peer-unreachable
        (or (= s "send-failed")
            (str/starts-with? s "send-failed:")) :send-failed
        (or (= s "malformed-request")
            (= s "invalid-request")
            (= s "invalid-json-response")) :invalid-request
        :else :unknown-error))

    :else :unknown-error))

(defn canonical-error
  "Constructs a canonical BIP-022 §4.1 A.3 error map:
   `{:ok false :error <kw> :category <cat> :recoverable? <bool> :detail <map>}`."
  ([code]
   (canonical-error code {}))
  ([code detail]
   (let [canon-code (classify-error code)
         spec (get error-catalog canon-code (get error-catalog :unknown-error))]
     {:ok false
      :error canon-code
      :category (:category spec)
      :recoverable? (:recoverable? spec)
      :detail (sanitize-detail detail)})))

(defn canonical-error->wire
  "Converts a canonical error map into the uniform JSON/wire string-keyed response map."
  ([err-map]
   (canonical-error->wire err-map nil))
  ([err-map extra-fields]
   (let [canon (if (and (map? err-map) (contains? error-catalog (:error err-map)))
                 err-map
                 (canonical-error (or (:error err-map) (get err-map "error") err-map)
                                  (or (:detail err-map) (get err-map "detail") {})))
         wire-detail (reduce-kv (fn [acc k v]
                                  (assoc acc (if (keyword? k) (str/replace (name k) "-" "_") (str k)) v))
                                {}
                                (:detail canon))
         base {"ok" false
               "error" (name (:error canon))
               "category" (name (:category canon))
               "recoverable" (boolean (:recoverable? canon))
               "detail" wire-detail}]
     (if (map? extra-fields)
       (merge extra-fields base)
       base))))

(defn diagnose-effect
  "Builds a counted Rule 5 `:diagnose` effect map from a canonical error map."
  [err-map]
  (let [canon (if (and (map? err-map) (contains? error-catalog (:error err-map)))
                err-map
                (canonical-error err-map {}))]
    {:effect :diagnose
     :type :diagnose
     :reason (:error canon)
     :category (:category canon)
     :recoverable? (:recoverable? canon)
     :detail (:detail canon)}))

(defn record-error-diagnostic
  "Purely increments Rule 5 `:diagnostics` counters on `state` for `err-map`."
  [state err-map]
  (let [canon (if (and (map? err-map) (contains? error-catalog (:error err-map)))
                err-map
                (canonical-error err-map {}))]
    (-> (or state {})
        (update-in [:diagnostics (:error canon)] (fnil inc 0))
        (update-in [:diagnostics :send-path-errors] (fnil inc 0)))))
