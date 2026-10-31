(ns bitecho.shell.discovery
  "Bootstrap peer and WebRTC connection descriptor discovery and parsing.
   Supports both canonical EDN (devnet/bootstrap.edn) and text (devnet/bootstrap.txt) formats."
  (:require [bitecho.shell.identity :as identity]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.net URI]))

(def valid-pubkey-regex
  "Matches either a 64-hex raw public key or an 88-hex SubjectPublicKeyInfo string."
  #"^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{88}$")

(defn- validate-pubkey!
  "Validates a public key hex string, returning its lowercase string or throwing on failure."
  [pubkey-str context-label]
  (let [cleaned (when (string? pubkey-str) (str/trim pubkey-str))]
    (when-not (and cleaned (re-matches valid-pubkey-regex cleaned))
      (throw (ex-info (str "Invalid descriptor: " context-label " public key hex string is invalid")
                      {:error :invalid-descriptor
                       :field context-label
                       :pubkey pubkey-str})))
    (str/lower-case cleaned)))

(defn- normalize-node-entry
  "Validates and normalizes a single validator node entry map."
  [node-id-key node-map]
  (let [node-id (keyword node-id-key)
        ip (when-let [ip-raw (:ip node-map)] (str/trim (str ip-raw)))
        port (when-let [p (:port node-map)] (long p))
        agent-port (when-let [ap (:agent-port node-map)] (long ap))
        agent-tcp-port (when-let [atp (:agent-tcp-port node-map)] (long atp))
        pubkey (validate-pubkey! (:pubkey node-map) (str "node " node-id))
        raw-fp (:fingerprint node-map)
        fp (try
             (identity/normalize-fingerprint raw-fp)
             (catch Exception e
               (throw (ex-info (str "Invalid descriptor: invalid fingerprint for node " node-id ": " (ex-message e))
                               {:error :invalid-descriptor
                                :node-id node-id
                                :fingerprint raw-fp}))))
        ufrag (when-let [u (:ice-ufrag node-map)] (str/trim (str u)))
        pwd (when-let [p (:ice-pwd node-map)] (str/trim (str p)))]
    (when (or (str/blank? ip) (nil? port) (nil? agent-port) (str/blank? ufrag) (str/blank? pwd))
      (throw (ex-info (str "Invalid descriptor: incomplete node entry for " node-id)
                      {:error :invalid-descriptor :node-id node-id :node node-map})))
    (cond-> {:node-id node-id
             :ip ip
             :port port
             :agent-port agent-port
             :pubkey pubkey
             :fingerprint fp
             :ice-ufrag ufrag
             :ice-pwd pwd}
      agent-tcp-port (assoc :agent-tcp-port agent-tcp-port))))

(defn parse-bootstrap-edn
  "Parses a bootstrap.edn string or map, validating all node entries and normalizing fingerprints."
  [edn-or-map]
  (let [data (if (map? edn-or-map)
               edn-or-map
               (try
                 (edn/read-string edn-or-map)
                 (catch Exception e
                   (throw (ex-info (str "Invalid EDN descriptor: " (ex-message e))
                                   {:error :invalid-descriptor :cause e})))))
        network (keyword (:network data :devnet))
        treasury-pk (validate-pubkey! (:treasury-pubkey data) "treasury")
        custody-pk (validate-pubkey! (:custody-pubkey data) "custody")
        nodes-map (or (:nodes data) {})
        _ (when (empty? nodes-map)
            (throw (ex-info "Bootstrap descriptor contains no validator nodes"
                            {:error :invalid-descriptor :data data})))
        normalized-nodes (into {} (for [[k v] nodes-map]
                                    [(keyword k) (normalize-node-entry k v)]))]
    {:network network
     :treasury-pubkey treasury-pk
     :custody-pubkey custody-pk
     :nodes normalized-nodes}))

(defn- parse-single-node-txt-block
  "Extracts a validator node map from a text block starting with 'Node: <id>'."
  [block-str]
  (let [id-match (re-find #"(?i)Node:\s*([a-zA-Z0-9_\-]+)" block-str)
        node-id (when id-match (keyword (second id-match)))
        cluster-match (re-find #"(?i)Cluster Address:\s*([^\s:]+):([0-9]+)" block-str)
        agent-match (re-find #"(?i)Agent Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        agent-tcp-match (re-find #"(?i)Agent TCP Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        pubkey-match (re-find #"(?i)Ed25519 Pubkey:\s*([0-9a-fA-F]+)" block-str)
        fp-match (re-find #"(?i)DTLS Fingerprint:\s*([0-9a-fA-F:]+)" block-str)
        ice-match (re-find #"(?i)ICE Credentials:\s*ufrag=([^\s]+)\s+pwd=([^\s]+)" block-str)]
    (when node-id
      [node-id
       (normalize-node-entry
        node-id
        (cond-> {:ip (when cluster-match (nth cluster-match 1))
                 :port (when cluster-match (Long/parseLong (nth cluster-match 2)))
                 :agent-port (when agent-match (Long/parseLong (nth agent-match 2)))
                 :pubkey (when pubkey-match (second pubkey-match))
                 :fingerprint (when fp-match (second fp-match))
                 :ice-ufrag (when ice-match (nth ice-match 1))
                 :ice-pwd (when ice-match (nth ice-match 2))}
          agent-tcp-match (assoc :agent-tcp-port (Long/parseLong (nth agent-tcp-match 2)))))])))

(defn parse-bootstrap-txt
  "Parses a bootstrap.txt descriptor, extracting network, keys, and validator entries."
  [^String txt-str]
  (when (or (nil? txt-str) (str/blank? txt-str))
    (throw (ex-info "Empty bootstrap.txt descriptor" {:error :invalid-descriptor})))
  (let [net-match (re-find #"(?im)^Network:\s*([a-zA-Z0-9_\-]+)" txt-str)
        treasury-match (re-find #"(?im)^Treasury Public Key:\s*([0-9a-fA-F]+)" txt-str)
        custody-match (re-find #"(?im)^Custody Public Key:\s*([0-9a-fA-F]+)" txt-str)
        network (keyword (str/lower-case (or (second net-match) "devnet")))
        treasury-pk (validate-pubkey! (second treasury-match) "treasury")
        custody-pk (validate-pubkey! (second custody-match) "custody")
        node-blocks (rest (str/split txt-str #"(?im)(?=^Node:\s*)"))
        nodes-entries (keep parse-single-node-txt-block node-blocks)
        nodes-map (into {} nodes-entries)]
    (when (empty? nodes-map)
      (throw (ex-info "No validator node blocks found in bootstrap.txt"
                      {:error :invalid-descriptor :raw-text txt-str})))
    {:network network
     :treasury-pubkey treasury-pk
     :custody-pubkey custody-pk
     :nodes nodes-map}))

(defn parse-bootstrap-descriptor
  "Auto-detects EDN or text format and parses into a validated descriptor map."
  [str-or-map]
  (cond
    (map? str-or-map)
    (parse-bootstrap-edn str-or-map)

    (string? str-or-map)
    (let [trimmed (str/trim str-or-map)]
      (if (or (str/starts-with? trimmed "{")
              (str/starts-with? trimmed ";;"))
        (try
          (parse-bootstrap-edn trimmed)
          (catch Exception _
            (parse-bootstrap-txt trimmed)))
        (parse-bootstrap-txt trimmed)))

    :else
    (throw (ex-info "Unsupported descriptor format: expected EDN map or string"
                    {:error :invalid-descriptor :input str-or-map}))))

(defn load-bootstrap-descriptor!
  "Loads and parses a bootstrap descriptor from a file path or HTTP/HTTPS URL.
   Defaults to 'https://bitecho.org/devnet/bootstrap.txt', falling back to local file when offline."
  ([] (load-bootstrap-descriptor! "https://bitecho.org/devnet/bootstrap.txt"))
  ([^String source-or-url]
   (let [content (if (re-matches #"^https?://.*" (or source-or-url ""))
                   (try
                     (slurp (.toURL (URI/create source-or-url)))
                     (catch Exception e
                       (let [fallback-file (io/file "devnet/bootstrap.txt")]
                         (if (.exists fallback-file)
                           (slurp fallback-file)
                           (throw (ex-info (str "Failed to load remote bootstrap descriptor: " (ex-message e))
                                           {:error :descriptor-load-failed :url source-or-url}
                                           e))))))
                   (let [f (io/file source-or-url)]
                     (if (.exists f)
                       (slurp f)
                       (throw (ex-info (str "Bootstrap descriptor file not found: " source-or-url)
                                       {:error :descriptor-file-not-found :file source-or-url})))))]
     (parse-bootstrap-descriptor content))))
