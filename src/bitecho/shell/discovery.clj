(ns bitecho.shell.discovery
  "Bootstrap peer and WebRTC connection descriptor discovery and parsing.
   Supports both canonical EDN (devnet/bootstrap.edn) and text (devnet/bootstrap.txt) formats."
  (:require [bitecho.light-node.core :as light-node]
            [bitecho.shell.identity :as identity]
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
        ingress-host (when-let [ih (:ingress-host node-map)] (str/trim (str ih)))
        ingress-port (when-let [ip-p (:ingress-port node-map)] (long ip-p))
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
      agent-tcp-port (assoc :agent-tcp-port agent-tcp-port)
      (seq ingress-host) (assoc :ingress-host ingress-host)
      ingress-port (assoc :ingress-port ingress-port))))

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
        dir-pk (when-let [dp (:directory-pubkey data)] (validate-pubkey! dp "directory"))
        dom (when-let [d (:domain data)] (str/trim (str d)))
        auth-pk (when-let [ap (:authority-pubkey data)] (validate-pubkey! ap "authority"))
        issued-ep (when-let [ie (:issued-epoch data)] (long ie))
        expires-ep (when-let [ee (:expires-epoch data)] (long ee))
        sig (when-let [s (:signature data)] (str/trim (str s)))
        nodes-map (or (:nodes data) {})
        _ (when (empty? nodes-map)
            (throw (ex-info "Bootstrap descriptor contains no validator nodes"
                            {:error :invalid-descriptor :data data})))
        parsed-pairs (mapv (fn [[k v]]
                             (try
                               {:ok? true :pair [(keyword k) (normalize-node-entry k v)]}
                               (catch Exception e
                                 {:ok? false :entry (str k " (" (ex-message e) ")")})))
                           nodes-map)
        normalized-nodes (into {} (keep :pair (filter :ok? parsed-pairs)))
        dropped-edn (mapv :entry (remove :ok? parsed-pairs))
        _ (when (empty? normalized-nodes)
            (throw (ex-info "Invalid bootstrap descriptor: no valid validator nodes"
                            {:error :invalid-descriptor :data data :dropped-entries dropped-edn})))]
    (cond-> {:network network
             :treasury-pubkey treasury-pk
             :custody-pubkey custody-pk
             :nodes normalized-nodes}
      (seq dropped-edn) (assoc :dropped-entries dropped-edn)
      dir-pk (assoc :directory-pubkey dir-pk)
      dom (assoc :domain dom)
      auth-pk (assoc :authority-pubkey auth-pk)
      issued-ep (assoc :issued-epoch issued-ep)
      expires-ep (assoc :expires-epoch expires-ep)
      sig (assoc :signature sig)
      (contains? data :economy-enabled?) (assoc :economy-enabled? (boolean (:economy-enabled? data)))
      (some? (:burn-floor data)) (assoc :burn-floor (long (:burn-floor data)))
      (some? (:min-signaling-burn data)) (assoc :min-signaling-burn (long (:min-signaling-burn data))))))

(defn- parse-single-node-txt-block
  "Extracts a validator node map from a text block starting with 'Node: <id>'."
  [block-str]
  (let [id-match (re-find #"(?i)Node:\s*([a-zA-Z0-9_\-]+)" block-str)
        node-id (when id-match (keyword (second id-match)))
        cluster-match (re-find #"(?i)Cluster Address:\s*([^\s:]+):([0-9]+)" block-str)
        agent-match (re-find #"(?i)Agent Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        agent-tcp-match (re-find #"(?i)Agent TCP Ingress:\s*([^\s:]+):([0-9]+)" block-str)
        agent-proxy-match (re-find #"(?i)Agent HTTPS/Proxy Ingress:\s*([^\s:]+):([0-9]+)" block-str)
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
          agent-tcp-match (assoc :agent-tcp-port (Long/parseLong (nth agent-tcp-match 2)))
          agent-proxy-match (assoc :ingress-host (nth agent-proxy-match 1)
                                   :ingress-port (Long/parseLong (nth agent-proxy-match 2)))))])))

(defn parse-bootstrap-txt
  "Parses a bootstrap.txt descriptor, extracting network, keys, and validator entries."
  [^String txt-str]
  (when (or (nil? txt-str) (str/blank? txt-str))
    (throw (ex-info "Empty bootstrap.txt descriptor" {:error :invalid-descriptor})))
  (let [net-match (re-find #"(?im)^Network:\s*([a-zA-Z0-9_\-]+)" txt-str)
        dom-match (re-find #"(?im)^Domain:\s*([^\s]+)" txt-str)
        auth-match (re-find #"(?im)^Authority Pubkey:\s*([0-9a-fA-F]+)" txt-str)
        issued-match (re-find #"(?im)^Issued Epoch:\s*([0-9]+)" txt-str)
        expires-match (re-find #"(?im)^Expires Epoch:\s*([0-9]+)" txt-str)
        sig-match (re-find #"(?im)^Authority Signature:\s*([0-9a-fA-F]+)" txt-str)
        treasury-match (re-find #"(?im)^Treasury Public Key:\s*([0-9a-fA-F]+)" txt-str)
        custody-match (re-find #"(?im)^Custody Public Key:\s*([0-9a-fA-F]+)" txt-str)
        dir-match (re-find #"(?im)^Directory Authority Public Key:\s*([0-9a-fA-F]+)" txt-str)
        econ-match (re-find #"(?im)^Economy Enabled:\s*([^\s]+)" txt-str)
        burn-floor-match (re-find #"(?im)^Burn Floor:\s*([0-9]+)" txt-str)
        min-burn-match (re-find #"(?im)^Min Signaling Burn:\s*([0-9]+)" txt-str)
        network (keyword (str/lower-case (or (second net-match) "devnet")))
        dom (when dom-match (second dom-match))
        auth-pk (when (second auth-match) (validate-pubkey! (second auth-match) "authority"))
        issued-ep (when (second issued-match) (Long/parseLong (second issued-match)))
        expires-ep (when (second expires-match) (Long/parseLong (second expires-match)))
        sig (when sig-match (second sig-match))
        treasury-pk (validate-pubkey! (second treasury-match) "treasury")
        custody-pk (validate-pubkey! (second custody-match) "custody")
        dir-pk (when (second dir-match) (validate-pubkey! (second dir-match) "directory"))
        econ-enabled (when econ-match (Boolean/parseBoolean (str/lower-case (second econ-match))))
        burn-floor (when burn-floor-match (Long/parseLong (second burn-floor-match)))
        min-burn (when min-burn-match (Long/parseLong (second min-burn-match)))
        node-blocks (rest (str/split txt-str #"(?im)(?=^Node:\s*)"))
        parsed-blocks (mapv (fn [b]
                              (try
                                (let [entry (parse-single-node-txt-block b)]
                                  (if entry
                                    {:ok? true :entry entry}
                                    {:ok? false :block (str/trim b)}))
                                (catch Exception e
                                  {:ok? false :block (str (str/trim b) " (" (ex-message e) ")")})))
                            node-blocks)
        nodes-entries (keep :entry (filter :ok? parsed-blocks))
        dropped-txt (mapv :block (remove :ok? parsed-blocks))
        nodes-map (into {} nodes-entries)]
    (when (empty? nodes-map)
      (throw (ex-info "No validator node blocks found in bootstrap.txt"
                      {:error :invalid-descriptor :raw-text txt-str})))
    (cond-> {:network network
             :treasury-pubkey treasury-pk
             :custody-pubkey custody-pk
             :nodes nodes-map}
      (seq dropped-txt) (assoc :dropped-entries dropped-txt)
      dir-pk (assoc :directory-pubkey dir-pk)
      dom (assoc :domain dom)
      auth-pk (assoc :authority-pubkey auth-pk)
      issued-ep (assoc :issued-epoch issued-ep)
      expires-ep (assoc :expires-epoch expires-ep)
      sig (assoc :signature sig)
      (some? econ-enabled) (assoc :economy-enabled? econ-enabled)
      burn-floor (assoc :burn-floor burn-floor)
      min-burn (assoc :min-signaling-burn min-burn))))

(defn format-bootstrap-txt
  "Renders a validated bootstrap descriptor map into canonical bootstrap.txt string format."
  [desc]
  (let [sb (StringBuilder.)]
    (.append sb (str "Network: " (name (or (:network desc) :devnet)) "\n"))
    (when-let [dom (:domain desc)]
      (.append sb (str "Domain: " dom "\n")))
    (when-let [auth-pk (:authority-pubkey desc)]
      (.append sb (str "Authority Pubkey: " auth-pk "\n")))
    (when-let [ie (:issued-epoch desc)]
      (.append sb (str "Issued Epoch: " ie "\n")))
    (when-let [ee (:expires-epoch desc)]
      (.append sb (str "Expires Epoch: " ee "\n")))
    (when-let [sig (:signature desc)]
      (.append sb (str "Authority Signature: " sig "\n")))
    (.append sb (str "Treasury Public Key: " (:treasury-pubkey desc) "\n"))
    (.append sb (str "Custody Public Key: " (:custody-pubkey desc) "\n"))
    (when-let [dp (:directory-pubkey desc)]
      (.append sb (str "Directory Authority Public Key: " dp "\n")))
    (when (contains? desc :economy-enabled?)
      (.append sb (str "Economy Enabled: " (boolean (:economy-enabled? desc)) "\n")))
    (when-let [bf (:burn-floor desc)]
      (.append sb (str "Burn Floor: " bf "\n")))
    (when-let [msb (:min-signaling-burn desc)]
      (.append sb (str "Min Signaling Burn: " msb "\n")))
    (.append sb "\n")
    (doseq [[node-id n] (sort-by #(name (first %)) (:nodes desc))]
      (.append sb (str "Node: " (name node-id) "\n"))
      (.append sb (str "Cluster Address: " (:ip n) ":" (:port n) "\n"))
      (.append sb (str "Agent Ingress: " (:ip n) ":" (:agent-port n) "\n"))
      (when-let [atp (:agent-tcp-port n)]
        (.append sb (str "Agent TCP Ingress: " (:ip n) ":" atp "\n")))
      (when-let [ih (:ingress-host n)]
        (.append sb (str "Agent HTTPS/Proxy Ingress: " ih ":" (or (:ingress-port n) 443) "\n")))
      (.append sb (str "Ed25519 Pubkey: " (:pubkey n) "\n"))
      (.append sb (str "DTLS Fingerprint: " (:fingerprint n) "\n"))
      (.append sb (str "ICE Credentials: ufrag=" (:ice-ufrag n) " pwd=" (:ice-pwd n) "\n\n")))
    (.toString sb)))

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

(def default-devnet-authority-pubkey
  "Pinned Directory Authority public key for bitecho.org devnet."
  "302a300506032b657003210056b505baa32c3b99663d163d6ee00b5018a26e182405f5ec4d5062f12f633ce9")

(defn load-bootstrap-descriptor!
  "Loads and parses a bootstrap descriptor from a file path or HTTP/HTTPS URL.
   Defaults to 'https://bitecho.org/devnet/bootstrap.txt', falling back to local file when offline.
   Accepts optional opts map: {:expected-authority-pubkey <hex> :verify-signature? <bool> :current-epoch <int>}."
  ([] (load-bootstrap-descriptor! "https://bitecho.org/devnet/bootstrap.txt" nil))
  ([source-or-url] (load-bootstrap-descriptor! source-or-url nil))
  ([source-or-url opts]
   (let [remote-url? (and (string? source-or-url) (boolean (re-matches #"^https?://.*" source-or-url)))
         desc (if (map? source-or-url)
                source-or-url
                (let [content (if remote-url?
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
                  (parse-bootstrap-descriptor content)))
         expected-pk (:expected-authority-pubkey opts)
         verify-sig? (:verify-signature? opts)
         current-epoch (:current-epoch opts)
         must-verify? (or (true? verify-sig?)
                          (some? expected-pk)
                          (and (not (false? verify-sig?))
                               (or remote-url? (some? (:signature desc)))))]
     (when must-verify?
       (if (and (true? verify-sig?) (str/blank? (str expected-pk)))
         (throw (ex-info "Missing required expected-authority-pubkey for bootstrap verification"
                         {:type :UntrustedBootstrapDescriptor :error :missing-expected-authority-pubkey :descriptor desc}))
         (let [auth-pk (or expected-pk default-devnet-authority-pubkey)
               v-res (light-node/verify-bootstrap-descriptor auth-pk desc current-epoch)]
           (when-not (:ok? v-res)
             (throw (ex-info (str "Bootstrap descriptor verification failed: " (:error v-res))
                             {:type :UntrustedBootstrapDescriptor :error (:error v-res) :descriptor desc}))))))
     desc)))

(defn load-verified-bootstrap-descriptor!
  "Unconditionally verifies expected-authority-pubkey signature on bootstrap descriptor.
   Fails closed throwing ex-info if descriptor is missing, unsigned, tampered, or expired."
  ([source-or-url expected-authority-pubkey]
   (load-verified-bootstrap-descriptor! source-or-url expected-authority-pubkey nil))
  ([source-or-url expected-authority-pubkey current-epoch]
   (when (str/blank? (str expected-authority-pubkey))
     (throw (ex-info "expected-authority-pubkey must not be blank"
                     {:type :UntrustedBootstrapDescriptor :error :missing-expected-authority-pubkey})))
   (load-bootstrap-descriptor! source-or-url
                               {:expected-authority-pubkey expected-authority-pubkey
                                :verify-signature? true
                                :current-epoch current-epoch})))
