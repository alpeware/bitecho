(ns bitecho.light-node.core
  "Pure Sans-IO protocol state reducer for the Bitecho light node.
   Handles command processing, sealed channel establishment, anti-replay,
   epoch skew tolerance, and Wire/JSONL conversions without side effects."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.economy.bundle :as bundle]
            [bitecho.economy.burn :as burn]
            [bitecho.economy.escrow :as escrow]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.agent-sim :as agent-sim]
            [bitecho.shell.mesh :as mesh]
            [clojure.data.json :as json]
            [clojure.string :as str]
            [taoensso.nippy :as nippy])
  (:import (java.nio.charset StandardCharsets)))

;; -----------------------------------------------------------------------------
;; State Initialization
;; -----------------------------------------------------------------------------

(defn init-light-state
  "Initializes a pure light node state map from an identity public map and options.
   Private keys are never stored in the returned state map."
  [identity-pub-map opts]
  {:pubkey (or (:pubkey-hex identity-pub-map) (:pubkey identity-pub-map))
   :fingerprint (:fingerprint identity-pub-map)
   :ice-creds (:ice-creds identity-pub-map)
   :autonomous? (boolean (:autonomous? opts false))
   :epoch (long (:epoch opts 0))
   :epoch-initialized? (contains? opts :epoch)
   :bootstrap (:bootstrap opts)
   :home-set []
   :petnames {}
   :dac nil
   :dac-spend nil
   :revoked-dacs #{}
   :directory-cache {}
   :sessions {}
   :pending-offers {}
   :inbox []
   :local-accounting {:burned-ech 0}
   :vouchers []
   :account nil
   :intent-seq 0
   :transfer-seq 0
   :last-transfer-hash nil
   :escrows {}
   :rendezvous-policy (merge {:auto-accept? false
                              :min-burn 0
                              :price 10
                              :allowlist #{}
                              :home-node "default-home"}
                             (:rendezvous-policy opts))
   :outbound-rendezvous {}
   :pending-rendezvous {}
   :pending-rendezvous-accepts {}
   :voucher-seqs {}})

;; -----------------------------------------------------------------------------
;; Petnames Address Book & Counterparty Resolution (Pure Helpers)
;; -----------------------------------------------------------------------------

(def ^:private pubkey-pattern #"(?i)^[0-9a-f]{88}$")
(def ^:private petname-pattern #"^[a-zA-Z0-9._-]{1,64}$")

(defn valid-pubkey-hex?
  "Returns true iff s is a string whose trimmed form is an 88-char hex string
   starting with canonical Ed25519 SPKI prefix 302a300506032b6570032100
   and cleanly decodes to 44 bytes via basalt/hex->bytes."
  [s]
  (boolean
   (when (and (string? s) (not (str/blank? s)))
     (let [t (str/trim s)]
       (when (and (re-matches pubkey-pattern t)
                  (str/starts-with? (str/lower-case t) "302a300506032b6570032100"))
         (try
           (let [b (basalt/hex->bytes t)]
             (and (some? b) (= 44 (alength ^bytes b))))
           (catch Exception _ false)))))))

(defn normalize-pubkey-hex
  "Returns lower-case trimmed pubkey hex string when valid-pubkey-hex?, else nil."
  [s]
  (when (valid-pubkey-hex? s)
    (str/lower-case (str/trim s))))

(defn valid-petname?
  "Returns true iff s is a string whose trimmed form (allowing an optional leading @)
   is non-blank, is NOT a valid-pubkey-hex?, and matches ^[a-zA-Z0-9._-]{1,64}$."
  [s]
  (boolean
   (when (and (string? s) (not (str/blank? s)))
     (let [t (str/trim s)
           stripped (if (str/starts-with? t "@") (subs t 1) t)]
       (and (not (str/blank? stripped))
            (not (valid-pubkey-hex? t))
            (not (valid-pubkey-hex? stripped))
            (boolean (re-matches petname-pattern stripped)))))))

(defn normalize-petname
  "Trims s, strips a single leading @ if present, and returns lower-case string
   when valid-petname?, else nil."
  [s]
  (when (valid-petname? s)
    (let [t (str/trim s)
          stripped (if (str/starts-with? t "@") (subs t 1) t)]
      (str/lower-case stripped))))

(defn pubkey->petname
  "Reverse lookup in (:petnames state) returning the canonical petname
   bound to (normalize-pubkey-hex pubkey), or nil."
  [state pubkey]
  (when-let [norm-pub (normalize-pubkey-hex pubkey)]
    (some (fn [[p k]] (when (= k norm-pub) p)) (:petnames state))))

(defn petname->pubkey
  "Forward lookup in (:petnames state) returning the pubkey
   bound to (normalize-petname petname), or nil."
  [state petname]
  (when-let [norm-pname (normalize-petname petname)]
    (get-in state [:petnames norm-pname])))

(defn resolve-counterparty
  "Resolves a counterparty identifier (petname or raw pubkey hex).
   Returns:
     {:ok? false :error \"missing-counterparty\"} when target is blank/nil
     {:ok? true :pubkey bound-pubkey :petname canonical-petname} when target matches a petname
     {:ok? true :pubkey (normalize-pubkey-hex target) :petname (pubkey->petname state target)} when valid pubkey hex
     {:ok? false :error \"unknown-petname\"} otherwise."
  [state target]
  (if (or (nil? target) (and (string? target) (str/blank? target)))
    {:ok? false :error "missing-counterparty"}
    (let [norm-pname (normalize-petname target)]
      (if (and norm-pname (contains? (:petnames state) norm-pname))
        {:ok? true :pubkey (get-in state [:petnames norm-pname]) :petname norm-pname}
        (if (valid-pubkey-hex? target)
          (let [norm-pub (normalize-pubkey-hex target)]
            {:ok? true :pubkey norm-pub :petname (pubkey->petname state norm-pub)})
          {:ok? false :error "unknown-petname"})))))

;; -----------------------------------------------------------------------------
;; Directory Attestation & Proof-of-Possession (PoP) (Axiom Amendment 2)
;; -----------------------------------------------------------------------------

(defn create-directory-pop
  "Creates an agent Proof-of-Possession (PoP) map signed by agent-privkey-bytes.
   Optionally signs with prev-privkey-bytes to prove key rotation continuity."
  [agent-privkey-bytes {:keys [domain nickname pubkey home-set epoch prev-pubkey prev-privkey-bytes]}]
  (when (and (valid-petname? nickname)
             (valid-pubkey-hex? pubkey)
             (or (nil? epoch) (integer? epoch))
             (or (nil? prev-pubkey)
                 (and (valid-pubkey-hex? prev-pubkey)
                      (not= (normalize-pubkey-hex prev-pubkey) (normalize-pubkey-hex pubkey))
                      (some? prev-privkey-bytes))))
    (let [norm-nick (normalize-petname nickname)
          norm-pub (normalize-pubkey-hex pubkey)
          norm-domain (if (or (nil? domain) (str/blank? domain)) "bitecho.org" (str/lower-case (str/trim domain)))
          sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                 (let [n (rendezvous/normalize-home-node hn)]
                                                   (when (and (string? n) (not (str/blank? n))) n)))
                                               home-set))))
          ep (long (or epoch 0))
          norm-prev (when prev-pubkey (normalize-pubkey-hex prev-pubkey))
          canonical-str (str "bitecho-directory-pop-v1|" norm-domain "|" norm-nick "|" norm-pub "|"
                             (str/join "," sorted-hs) "|" ep "|" (or norm-prev ""))
          sig-bytes (crypto/sign agent-privkey-bytes (.getBytes canonical-str "UTF-8"))
          sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))
          rot-sig-bytes (when norm-prev
                          (crypto/sign prev-privkey-bytes (.getBytes canonical-str "UTF-8")))
          rot-sig-hex (when rot-sig-bytes
                        (if (string? rot-sig-bytes) rot-sig-bytes (basalt/bytes->hex rot-sig-bytes)))]
      (cond-> {:domain norm-domain
               :nickname norm-nick
               :pubkey norm-pub
               :home-set sorted-hs
               :epoch ep
               :pop-signature sig-hex}
        norm-prev (assoc :prev-pubkey norm-prev
                         :rotation-signature rot-sig-hex)))))

(defn- normalize-wire-map
  "Normalizes map keys to hyphenated keywords. Handles string or keyword keys.
   Returns nil if m is not a map."
  [m]
  (when (map? m)
    (into {}
          (for [[k v] m]
            (let [k-norm (cond
                           (keyword? k)
                           (if-let [ns (namespace k)]
                             (keyword ns (str/replace (name k) #"_" "-"))
                             (keyword (str/replace (name k) #"_" "-")))
                           (string? k)
                           (let [cleaned (str/replace (str/replace k #"^:+" "") #"_" "-")]
                             (if (str/includes? cleaned "/")
                               (let [[ns n] (str/split cleaned #"/" 2)]
                                 (keyword ns n))
                               (keyword cleaned)))
                           :else (keyword (str/replace (str k) #"_" "-")))]
              [k-norm v])))))

(defn verify-directory-pop
  "Verifies an agent Proof-of-Possession (PoP) map.
   Returns true iff the agent signature verifies under pubkey and (if key rotation)
   the rotation signature verifies under prev-pubkey.
   Strictly fails closed returning false on any malformed, mistyped, or invalid input."
  [pop-map]
  (try
    (let [pop-m (normalize-wire-map pop-map)]
      (boolean
       (when (and (map? pop-m)
                  (string? (:nickname pop-m))
                  (valid-petname? (:nickname pop-m))
                  (string? (:pubkey pop-m))
                  (valid-pubkey-hex? (:pubkey pop-m))
                  (string? (:domain pop-m))
                  (not (str/blank? (:domain pop-m)))
                  (string? (:pop-signature pop-m))
                  (not (str/blank? (:pop-signature pop-m)))
                  (or (nil? (:epoch pop-m)) (integer? (:epoch pop-m)))
                  (or (nil? (:home-set pop-m))
                      (and (coll? (:home-set pop-m))
                           (every? (fn [x] (or (string? x) (keyword? x) (symbol? x))) (:home-set pop-m)))))
         (let [norm-domain (str/lower-case (str/trim (:domain pop-m)))
               norm-nick (normalize-petname (:nickname pop-m))
               norm-pub (normalize-pubkey-hex (:pubkey pop-m))
               hs (or (:home-set pop-m) [])
               sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                      (let [n (rendezvous/normalize-home-node hn)]
                                                        (when (and (string? n) (not (str/blank? n))) n)))
                                                    hs))))
               ep (long (or (:epoch pop-m) 0))
               prev-pk (:prev-pubkey pop-m)
               rot-sig (:rotation-signature pop-m)
               has-rot? (or (some? prev-pk) (some? rot-sig))
               norm-prev (when (and (string? prev-pk) (valid-pubkey-hex? prev-pk))
                           (normalize-pubkey-hex prev-pk))
               canonical-str (str "bitecho-directory-pop-v1|" norm-domain "|" norm-nick "|" norm-pub "|"
                                  (str/join "," sorted-hs) "|" ep "|" (or norm-prev ""))
               pub-bytes (try (basalt/hex->bytes norm-pub) (catch Exception _ nil))
               sig-bytes (try (basalt/hex->bytes (:pop-signature pop-m)) (catch Exception _ nil))
               pop-valid? (boolean (and pub-bytes sig-bytes
                                        (crypto/verify pub-bytes (.getBytes canonical-str "UTF-8") sig-bytes)))]
           (if-not pop-valid?
             false
             (if has-rot?
               (let [rot-keys-valid? (and (string? prev-pk)
                                          (valid-pubkey-hex? prev-pk)
                                          (string? rot-sig)
                                          (not (str/blank? rot-sig))
                                          norm-prev
                                          (not= norm-prev norm-pub))
                     prev-pub-bytes (when rot-keys-valid? (try (basalt/hex->bytes norm-prev) (catch Exception _ nil)))
                     rot-sig-bytes (when rot-keys-valid? (try (basalt/hex->bytes rot-sig) (catch Exception _ nil)))]
                 (boolean (and prev-pub-bytes rot-sig-bytes
                               (crypto/verify prev-pub-bytes (.getBytes canonical-str "UTF-8") rot-sig-bytes))))
               true))))))
    (catch Exception _ false)))

(defn sign-directory-descriptor
  "Signs a directory attestation descriptor under a directory authority key after verifying PoP.
   Agent self-signature proves continuity only; directory signature attests the entry."
  [directory-privkey-bytes directory-pubkey-hex pop-map {:keys [mailbox issued-epoch expires-epoch]}]
  (when (and (string? directory-pubkey-hex)
             (valid-pubkey-hex? directory-pubkey-hex)
             (verify-directory-pop pop-map)
             (integer? issued-epoch)
             (integer? expires-epoch)
             (>= (long expires-epoch) (long issued-epoch)))
    (let [pop-m (normalize-wire-map pop-map)
          domain (str/lower-case (str/trim (or (:domain pop-m) "bitecho.org")))
          norm-nick (normalize-petname (:nickname pop-m))
          norm-pub (normalize-pubkey-hex (:pubkey pop-m))
          sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                 (let [n (rendezvous/normalize-home-node hn)]
                                                   (when (and (string? n) (not (str/blank? n))) n)))
                                               (:home-set pop-m)))))
          norm-prev (when-let [p (:prev-pubkey pop-m)] (normalize-pubkey-hex p))
          pop-sig (:pop-signature pop-m)
          rot-sig (or (:rotation-signature pop-m) "")
          mbox (or mailbox "")
          iss-ep (long issued-epoch)
          exp-ep (long expires-epoch)
          canonical-str (str "bitecho-directory-attestation-v1|" domain "|" norm-nick "|" norm-pub "|"
                             (str/join "," sorted-hs) "|" mbox "|" iss-ep "|" exp-ep "|"
                             (or norm-prev "") "|" pop-sig "|" rot-sig)
          dir-sig-bytes (crypto/sign directory-privkey-bytes (.getBytes canonical-str "UTF-8"))
          dir-sig-hex (if (string? dir-sig-bytes) dir-sig-bytes (basalt/bytes->hex dir-sig-bytes))]
      (cond-> {:bitecho/type :directory-descriptor
               :domain domain
               :nickname norm-nick
               :uri (str domain "/" norm-nick)
               :pubkey norm-pub
               :home-set sorted-hs
               :epoch (long (or (:epoch pop-m) iss-ep))
               :issued-epoch iss-ep
               :expires-epoch exp-ep
               :pop-signature pop-sig
               :directory-pubkey (normalize-pubkey-hex directory-pubkey-hex)
               :directory-signature dir-sig-hex}
        (seq mbox) (assoc :mailbox mbox)
        norm-prev (assoc :prev-pubkey norm-prev)
        (:rotation-signature pop-m) (assoc :rotation-signature (:rotation-signature pop-m))))))

(defn verify-directory-descriptor
  "Verifies a directory descriptor against a trusted directory authority public key and current epoch.
   Strictly fails closed returning {:ok? false :valid? false :error <reason>} on any validation failure."
  [descriptor trusted-directory-pubkey current-epoch]
  (try
    (let [desc (normalize-wire-map descriptor)]
      (cond
        (or (not (map? desc))
            (not (string? (:domain desc))) (str/blank? (:domain desc))
            (not (string? (:nickname desc))) (str/blank? (:nickname desc))
            (not (string? (:pubkey desc))) (str/blank? (:pubkey desc))
            (not (string? (:directory-pubkey desc))) (str/blank? (:directory-pubkey desc))
            (not (string? (:directory-signature desc))) (str/blank? (:directory-signature desc))
            (not (string? (:pop-signature desc))) (str/blank? (:pop-signature desc))
            (not (integer? (:issued-epoch desc)))
            (not (integer? (:expires-epoch desc)))
            (and (some? (:epoch desc)) (not (integer? (:epoch desc))))
            (and (some? current-epoch) (not (integer? current-epoch)))
            (and (some? (:home-set desc))
                 (not (and (coll? (:home-set desc))
                           (every? (fn [x] (or (string? x) (keyword? x) (symbol? x))) (:home-set desc)))))
            (and (some? (:prev-pubkey desc)) (not (string? (:prev-pubkey desc))))
            (and (some? (:rotation-signature desc)) (not (string? (:rotation-signature desc))))
            (and (some? (:mailbox desc)) (not (string? (:mailbox desc)))))
        {:ok? false :valid? false :error "malformed-descriptor"}

        (or (not (string? trusted-directory-pubkey))
            (not (valid-pubkey-hex? trusted-directory-pubkey))
            (not (valid-pubkey-hex? (:directory-pubkey desc)))
            (not= (normalize-pubkey-hex (:directory-pubkey desc))
                  (normalize-pubkey-hex trusted-directory-pubkey)))
        {:ok? false :valid? false :error "untrusted-directory-authority"}

        (or (< (long (:expires-epoch desc)) (long (:issued-epoch desc)))
            (and (integer? current-epoch) (< (long (:expires-epoch desc)) (long current-epoch))))
        {:ok? false :valid? false :error "descriptor-expired"}

        (and (integer? current-epoch) (> (long (:issued-epoch desc)) (+ (long current-epoch) 2)))
        {:ok? false :valid? false :error "descriptor-future-epoch"}

        (not (verify-directory-pop desc))
        {:ok? false :valid? false :error "invalid-pop-signature"}

        :else
        (let [domain (str/lower-case (str/trim (:domain desc)))
              norm-nick (normalize-petname (:nickname desc))
              norm-pub (normalize-pubkey-hex (:pubkey desc))
              hs (or (:home-set desc) [])
              sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                     (let [n (rendezvous/normalize-home-node hn)]
                                                       (when (and (string? n) (not (str/blank? n))) n)))
                                                   hs))))
              mbox (or (:mailbox desc) "")
              iss-ep (long (:issued-epoch desc))
              exp-ep (long (:expires-epoch desc))
              norm-prev (when-let [p (:prev-pubkey desc)] (normalize-pubkey-hex p))
              pop-sig (:pop-signature desc)
              rot-sig (or (:rotation-signature desc) "")
              canonical-str (str "bitecho-directory-attestation-v1|" domain "|" norm-nick "|" norm-pub "|"
                                 (str/join "," sorted-hs) "|" mbox "|" iss-ep "|" exp-ep "|"
                                 (or norm-prev "") "|" pop-sig "|" rot-sig)
              dir-pub-bytes (try (basalt/hex->bytes (normalize-pubkey-hex trusted-directory-pubkey)) (catch Exception _ nil))
              dir-sig-bytes (try (basalt/hex->bytes (:directory-signature desc)) (catch Exception _ nil))]
          (if-not (and dir-pub-bytes dir-sig-bytes
                       (crypto/verify dir-pub-bytes (.getBytes canonical-str "UTF-8") dir-sig-bytes))
            {:ok? false :valid? false :error "invalid-directory-signature"}
            (let [canonical-desc (cond-> {:bitecho/type :directory-descriptor
                                          :domain domain
                                          :nickname norm-nick
                                          :uri (str domain "/" norm-nick)
                                          :pubkey norm-pub
                                          :home-set sorted-hs
                                          :epoch (long (or (:epoch desc) iss-ep))
                                          :issued-epoch iss-ep
                                          :expires-epoch exp-ep
                                          :pop-signature pop-sig
                                          :directory-pubkey (normalize-pubkey-hex trusted-directory-pubkey)
                                          :directory-signature (:directory-signature desc)}
                                   (seq mbox) (assoc :mailbox mbox)
                                   norm-prev (assoc :prev-pubkey norm-prev)
                                   (seq rot-sig) (assoc :rotation-signature rot-sig))]
              {:ok? true :valid? true :descriptor canonical-desc})))))
    (catch Exception _ {:ok? false :valid? false :error "malformed-descriptor"})))

;; -----------------------------------------------------------------------------
;; Delegated Agent Certificates (DACs: Anchor Key -> Hot Agent Key)
;; -----------------------------------------------------------------------------

(defn create-dac
  "Creates a Delegated Agent Certificate (DAC) signed by an anchor cold key."
  [anchor-privkey-bytes {:keys [anchor-pubkey agent-pubkey issued-epoch expires-epoch max-spend-per-epoch scopes]}]
  (when (and (string? anchor-pubkey)
             (valid-pubkey-hex? anchor-pubkey)
             (string? agent-pubkey)
             (valid-pubkey-hex? agent-pubkey)
             (not= (normalize-pubkey-hex anchor-pubkey) (normalize-pubkey-hex agent-pubkey))
             (or (nil? issued-epoch) (integer? issued-epoch))
             (or (nil? expires-epoch) (integer? expires-epoch))
             (or (nil? max-spend-per-epoch) (integer? max-spend-per-epoch))
             (>= (long (or issued-epoch 0)) 0)
             (>= (long (or expires-epoch 0)) (long (or issued-epoch 0)))
             (>= (long (or max-spend-per-epoch 0)) 0)
             (or (nil? scopes)
                 (and (coll? scopes)
                      (every? (fn [x] (and (or (string? x) (keyword? x) (symbol? x))
                                           (not (str/blank? (name x)))))
                              scopes))))
    (let [norm-anchor (normalize-pubkey-hex anchor-pubkey)
          norm-agent (normalize-pubkey-hex agent-pubkey)
          iss-ep (long (or issued-epoch 0))
          exp-ep (long (or expires-epoch 0))
          max-spend (long (or max-spend-per-epoch 0))
          sorted-scopes (vec (sort (distinct (map (fn [s] (str/lower-case (name s)))
                                                  (or scopes ["gossip" "offer" "settle-intent" "transfer"])))))
          canonical-str (str "bitecho-dac-v1|" norm-anchor "|" norm-agent "|" iss-ep "|" exp-ep "|" max-spend "|" (str/join "," sorted-scopes))
          dac-id (basalt/bytes->hex (crypto/sha256 (.getBytes canonical-str "UTF-8")))
          sig-bytes (crypto/sign anchor-privkey-bytes (.getBytes canonical-str "UTF-8"))
          sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))]
      {:bitecho/type :dac
       :dac-id dac-id
       :anchor-pubkey norm-anchor
       :agent-pubkey norm-agent
       :issued-epoch iss-ep
       :expires-epoch exp-ep
       :max-spend-per-epoch max-spend
       :scopes sorted-scopes
       :signature sig-hex})))

(defn create-dac-revocation
  "Creates a DAC revocation map signed by an anchor cold key."
  [anchor-privkey-bytes {:keys [anchor-pubkey agent-pubkey dac-id revoked-epoch]}]
  (when (and (string? anchor-pubkey)
             (valid-pubkey-hex? anchor-pubkey)
             (string? agent-pubkey)
             (valid-pubkey-hex? agent-pubkey)
             (string? dac-id)
             (not (str/blank? dac-id))
             (or (nil? revoked-epoch) (integer? revoked-epoch)))
    (let [norm-anchor (normalize-pubkey-hex anchor-pubkey)
          norm-agent (normalize-pubkey-hex agent-pubkey)
          rev-ep (long (or revoked-epoch 0))
          canonical-str (str "bitecho-dac-revoke-v1|" norm-anchor "|" norm-agent "|" dac-id "|" rev-ep)
          sig-bytes (crypto/sign anchor-privkey-bytes (.getBytes canonical-str "UTF-8"))
          sig-hex (if (string? sig-bytes) sig-bytes (basalt/bytes->hex sig-bytes))]
      {:bitecho/type :dac-revocation
       :dac-id dac-id
       :anchor-pubkey norm-anchor
       :agent-pubkey norm-agent
       :revoked-epoch rev-ep
       :signature sig-hex})))

(defn verify-dac-revocation
  "Verifies a DAC revocation map under its anchor public key.
   Strictly fails closed returning false on any malformed or mistyped input."
  [revocation]
  (try
    (let [rev (normalize-wire-map revocation)]
      (boolean
       (when (and (map? rev)
                  (string? (:anchor-pubkey rev))
                  (valid-pubkey-hex? (:anchor-pubkey rev))
                  (string? (:agent-pubkey rev))
                  (valid-pubkey-hex? (:agent-pubkey rev))
                  (string? (:dac-id rev))
                  (not (str/blank? (:dac-id rev)))
                  (string? (:signature rev))
                  (not (str/blank? (:signature rev)))
                  (or (nil? (:revoked-epoch rev)) (integer? (:revoked-epoch rev))))
         (let [norm-anchor (normalize-pubkey-hex (:anchor-pubkey rev))
               norm-agent (normalize-pubkey-hex (:agent-pubkey rev))
               dac-id (:dac-id rev)
               rev-ep (long (or (:revoked-epoch rev) 0))
               canonical-str (str "bitecho-dac-revoke-v1|" norm-anchor "|" norm-agent "|" dac-id "|" rev-ep)
               pub-bytes (try (basalt/hex->bytes norm-anchor) (catch Exception _ nil))
               sig-bytes (try (basalt/hex->bytes (:signature rev)) (catch Exception _ nil))]
           (and pub-bytes sig-bytes
                (crypto/verify pub-bytes (.getBytes canonical-str "UTF-8") sig-bytes))))))
    (catch Exception _ false)))

(defn verify-dac
  "Verifies a Delegated Agent Certificate (DAC) against expected agent key, epoch, revocations, and scope.
   Strictly fails closed returning {:ok? false :valid? false :error <reason>} on any validation failure."
  [dac {:keys [expected-agent-pubkey current-epoch revoked-dac-ids required-scope]}]
  (try
    (let [d (normalize-wire-map dac)]
      (cond
        (or (not (map? d))
            (not (string? (:anchor-pubkey d))) (str/blank? (:anchor-pubkey d))
            (not (string? (:agent-pubkey d))) (str/blank? (:agent-pubkey d))
            (not (string? (:dac-id d))) (str/blank? (:dac-id d))
            (not (string? (:signature d))) (str/blank? (:signature d))
            (not (integer? (:issued-epoch d)))
            (not (integer? (:expires-epoch d)))
            (not (integer? (:max-spend-per-epoch d)))
            (< (long (:max-spend-per-epoch d)) 0)
            (and (some? current-epoch) (not (integer? current-epoch)))
            (and (some? expected-agent-pubkey) (not (string? expected-agent-pubkey)))
            (not (coll? (:scopes d)))
            (empty? (:scopes d))
            (not (every? (fn [x] (and (or (string? x) (keyword? x) (symbol? x))
                                      (not (str/blank? (name x)))))
                         (:scopes d))))
        {:ok? false :valid? false :error "malformed-dac"}

        (or (not (valid-pubkey-hex? (:anchor-pubkey d)))
            (not (valid-pubkey-hex? (:agent-pubkey d)))
            (= (normalize-pubkey-hex (:anchor-pubkey d)) (normalize-pubkey-hex (:agent-pubkey d))))
        {:ok? false :valid? false :error "invalid-dac-keys"}

        (and expected-agent-pubkey
             (or (not (valid-pubkey-hex? expected-agent-pubkey))
                 (not= (normalize-pubkey-hex expected-agent-pubkey)
                       (normalize-pubkey-hex (:agent-pubkey d)))))
        {:ok? false :valid? false :error "dac-agent-mismatch"}

        (or (< (long (:expires-epoch d)) (long (:issued-epoch d)))
            (and (integer? current-epoch) (< (long (:expires-epoch d)) (long current-epoch))))
        {:ok? false :valid? false :error "dac-expired"}

        (and (integer? current-epoch) (> (long (:issued-epoch d)) (+ (long current-epoch) 2)))
        {:ok? false :valid? false :error "dac-future-epoch"}

        (contains? (set (or revoked-dac-ids [])) (:dac-id d))
        {:ok? false :valid? false :error "dac-revoked"}

        :else
        (let [norm-anchor (normalize-pubkey-hex (:anchor-pubkey d))
              norm-agent (normalize-pubkey-hex (:agent-pubkey d))
              iss-ep (long (:issued-epoch d))
              exp-ep (long (:expires-epoch d))
              max-spend (long (:max-spend-per-epoch d))
              sorted-scopes (vec (sort (distinct (map (fn [s] (str/lower-case (name s))) (:scopes d)))))]
          (if (and required-scope
                   (let [req-set (if (coll? required-scope)
                                   (set (map (fn [s] (str/lower-case (name s))) required-scope))
                                   #{(str/lower-case (name required-scope))})]
                     (not (some req-set sorted-scopes))))
            {:ok? false :valid? false :error "dac-scope-not-permitted"}
            (let [canonical-str (str "bitecho-dac-v1|" norm-anchor "|" norm-agent "|" iss-ep "|" exp-ep "|" max-spend "|" (str/join "," sorted-scopes))
                  expected-id (basalt/bytes->hex (crypto/sha256 (.getBytes canonical-str "UTF-8")))
                  anchor-pub-bytes (try (basalt/hex->bytes norm-anchor) (catch Exception _ nil))
                  sig-bytes (try (basalt/hex->bytes (:signature d)) (catch Exception _ nil))]
              (if-not (and (= (:dac-id d) expected-id)
                           anchor-pub-bytes sig-bytes
                           (crypto/verify anchor-pub-bytes (.getBytes canonical-str "UTF-8") sig-bytes))
                {:ok? false :valid? false :error "invalid-dac-signature"}
                (let [canonical-dac {:bitecho/type :dac
                                     :dac-id (:dac-id d)
                                     :anchor-pubkey norm-anchor
                                     :agent-pubkey norm-agent
                                     :issued-epoch iss-ep
                                     :expires-epoch exp-ep
                                     :max-spend-per-epoch max-spend
                                     :scopes sorted-scopes
                                     :signature (:signature d)}]
                  {:ok? true
                   :valid? true
                   :dac canonical-dac
                   :dac-id (:dac-id d)
                   :anchor-pubkey norm-anchor
                   :agent-pubkey norm-agent
                   :issued-epoch iss-ep
                   :expires-epoch exp-ep
                   :max-spend-per-epoch max-spend
                   :scopes sorted-scopes})))))))
    (catch Exception _ {:ok? false :valid? false :error "malformed-dac"})))

;; -----------------------------------------------------------------------------
;; Milestone 5 (Pillar B): In-Band Authenticated Chain State Snapshot Protocol
;; -----------------------------------------------------------------------------

(defn- parse-long-safe
  "Parses a number or string into a long safely. Returns default-val (default nil) on failure or nil."
  ([v] (parse-long-safe v nil))
  ([v default-val]
   (cond
     (integer? v) (long v)
     (number? v) (long v)
     (string? v) (try (Long/parseLong (str/trim v)) (catch Exception _ default-val))
     :else default-val)))

(defn- canonical-escrow-entry-str
  "Formats a single escrow map into canonical colon-separated representation:
   <escrow-id>:<payer>:<receiver>:<amount>:<deliverable-hash>:<created-epoch>:<expires-epoch>:<status-name>:<settled-epoch-or-empty>:<net-amount-or-empty>:<refund-reason-or-empty>"
  [esc]
  (let [eid (or (:escrow-id esc) (:escrow_id esc) "")
        payer (or (:payer esc) "")
        receiver (or (:receiver esc) (:recipient esc) "")
        amt (long (or (:amount esc) 0))
        dh (or (:deliverable-hash esc) (:deliverable_hash esc) "")
        cr-ep (long (or (:created-epoch esc) (:created_epoch esc) 0))
        exp-ep (long (or (:expires-epoch esc) (:expires_epoch esc) 0))
        st-name (name (or (:status esc) :locked))
        settled-ep (if (some? (or (:settled-epoch esc) (:settled_epoch esc)))
                     (str (or (:settled-epoch esc) (:settled_epoch esc)))
                     "")
        net-amt (if (some? (or (:net-amount esc) (:net_amount esc)))
                  (str (or (:net-amount esc) (:net_amount esc)))
                  "")
        refund-re (if (some? (or (:refund-reason esc) (:refund_reason esc)))
                    (str (or (:refund-reason esc) (:refund_reason esc)))
                    "")]
    (str eid ":" payer ":" receiver ":" amt ":" dh ":" cr-ep ":" exp-ep ":" st-name ":" settled-ep ":" net-amt ":" refund-re)))

(defn canonical-chain-state-snapshot-str
  "Computes deterministic canonical representation of a chain state snapshot:
   bitecho-chain-state-snapshot-v1|<validator-pubkey>|<pubkey>|<finalized-epoch>|<balance>|<spendable>|<seq>|<comma-joined-deps>|<canonical-escrows-str>|<nonce>"
  [snapshot]
  (let [val-pub (or (:validator-pubkey snapshot) (get snapshot "validator_pubkey") "")
        pk (or (:pubkey snapshot) (get snapshot "pubkey") "")
        fin-ep (long (or (:finalized-epoch snapshot) (get snapshot "finalized_epoch") 0))
        bal (long (or (:balance snapshot) (get snapshot "balance") 0))
        spd (long (or (:spendable snapshot) (get snapshot "spendable") 0))
        seq-num (long (or (:seq snapshot) (get snapshot "seq") 0))
        deps (vec (or (:deps snapshot) (get snapshot "deps") []))
        deps-str (str/join "," deps)
        raw-escrows (or (:escrows snapshot) (get snapshot "escrows") [])
        escrows-vec (if (map? raw-escrows) (vals raw-escrows) (vec raw-escrows))
        sorted-escrows (sort-by (fn [e] (str (or (:escrow-id e) (:escrow_id e) ""))) escrows-vec)
        escrows-str (str/join ";" (map canonical-escrow-entry-str sorted-escrows))
        nonce (or (:nonce snapshot) (get snapshot "nonce") "")]
    (str "bitecho-chain-state-snapshot-v1|"
         val-pub "|"
         pk "|"
         fin-ep "|"
         bal "|"
         spd "|"
         seq-num "|"
         deps-str "|"
         escrows-str "|"
         nonce)))

(defn sign-chain-state-snapshot
  "Signs a chain state snapshot map using validator private key bytes.
   Returns snapshot with :bitecho/type :chain-state-snapshot, :type :chain-state-snapshot, and :signature hex."
  [snapshot ^bytes validator-privkey-bytes]
  (let [canonical-str (canonical-chain-state-snapshot-str snapshot)
        sig-bytes (crypto/sign validator-privkey-bytes (.getBytes canonical-str StandardCharsets/UTF_8))]
    (assoc snapshot
           :bitecho/type :chain-state-snapshot
           :type :chain-state-snapshot
           :signature (basalt/bytes->hex sig-bytes))))

(defn verify-chain-state-snapshot
  "Verifies structure, validator signature, nonce, and epoch freshness of a chain state snapshot.
   Returns {:ok? true :snapshot normalized} or {:ok? false :error <reason>}."
  [snapshot opts]
  (cond
    (not (map? snapshot))
    {:ok? false :error "malformed-snapshot"}

    (let [exp-pk (:expected-pubkey opts)
          snap-pk (or (:pubkey snapshot) (get snapshot "pubkey"))]
      (and exp-pk (not= exp-pk snap-pk)))
    {:ok? false :error "pubkey-mismatch"}

    (let [trusted (:trusted-validators opts)
          val-pub (or (:validator-pubkey snapshot) (get snapshot "validator_pubkey"))]
      (or (empty? trusted)
          (not (contains? (set (map normalize-pubkey-hex trusted)) (normalize-pubkey-hex val-pub)))))
    {:ok? false :error "untrusted-validator"}

    (let [exp-nonce (:expected-nonce opts)
          snap-nonce (or (:nonce snapshot) (get snapshot "nonce"))]
      (and exp-nonce (not= (str exp-nonce) (str snap-nonce))))
    {:ok? false :error "nonce-mismatch"}

    (< (long (or (:finalized-epoch snapshot) (get snapshot "finalized_epoch") 0))
       (long (or (:min-finalized-epoch opts) 0)))
    {:ok? false :error "stale-finalized-epoch"}

    (let [sig (or (:signature snapshot) (get snapshot "signature"))]
      (or (nil? sig) (str/blank? (str sig))))
    {:ok? false :error "missing-snapshot-signature"}

    (let [val-pub (or (:validator-pubkey snapshot) (get snapshot "validator_pubkey"))]
      (or (nil? val-pub) (str/blank? (str val-pub))))
    {:ok? false :error "missing-validator-pubkey"}

    :else
    (let [val-pub (or (:validator-pubkey snapshot) (get snapshot "validator_pubkey"))
          sig (or (:signature snapshot) (get snapshot "signature"))
          canonical-str (canonical-chain-state-snapshot-str snapshot)
          val-pub-bytes (try (basalt/hex->bytes val-pub) (catch Exception _ nil))
          sig-bytes (try (basalt/hex->bytes sig) (catch Exception _ nil))
          valid? (and val-pub-bytes sig-bytes
                      (try (crypto/verify val-pub-bytes (.getBytes canonical-str StandardCharsets/UTF_8) sig-bytes)
                           (catch Exception _ false)))]
      (if valid?
        (let [raw-escrows (or (:escrows snapshot) (get snapshot "escrows") [])
              escrows-vec (if (map? raw-escrows) (vals raw-escrows) (vec raw-escrows))
              normalized-escrows (mapv (fn [esc]
                                         (let [eid (or (:escrow-id esc) (:escrow_id esc))
                                               payer (or (:payer esc) "")
                                               receiver (or (:receiver esc) (:recipient esc) "")
                                               amt (long (or (:amount esc) 0))
                                               dh (or (:deliverable-hash esc) (:deliverable_hash esc) "")
                                               cr-ep (long (or (:created-epoch esc) (:created_epoch esc) 0))
                                               exp-ep (long (or (:expires-epoch esc) (:expires_epoch esc) 0))
                                               st-val (let [s (or (:status esc) :locked)]
                                                        (if (keyword? s) s (keyword s)))
                                               set-ep (when-let [se (or (:settled-epoch esc) (:settled_epoch esc))] (long se))
                                               net-a (when-let [na (or (:net-amount esc) (:net_amount esc))] (long na))
                                               ref-r (or (:refund-reason esc) (:refund_reason esc))]
                                           (cond-> {:escrow-id eid
                                                    :payer payer
                                                    :receiver receiver
                                                    :amount amt
                                                    :deliverable-hash dh
                                                    :created-epoch cr-ep
                                                    :expires-epoch exp-ep
                                                    :status st-val}
                                             set-ep (assoc :settled-epoch set-ep)
                                             net-a (assoc :net-amount net-a)
                                             ref-r (assoc :refund-reason ref-r))))
                                       escrows-vec)]
          {:ok? true
           :snapshot {:bitecho/type :chain-state-snapshot
                      :type :chain-state-snapshot
                      :validator-pubkey val-pub
                      :pubkey (or (:pubkey snapshot) (get snapshot "pubkey"))
                      :finalized-epoch (long (or (:finalized-epoch snapshot) (get snapshot "finalized_epoch") 0))
                      :balance (long (or (:balance snapshot) (get snapshot "balance") 0))
                      :spendable (long (or (:spendable snapshot) (get snapshot "spendable") 0))
                      :seq (long (or (:seq snapshot) (get snapshot "seq") 0))
                      :deps (vec (or (:deps snapshot) (get snapshot "deps") []))
                      :escrows normalized-escrows
                      :nonce (or (:nonce snapshot) (get snapshot "nonce") "")
                      :signature sig}})
        {:ok? false :error "invalid-snapshot-signature"}))))

(defn verify-chain-state-quorum
  "Verifies quorum agreement across validator chain state snapshots.
   Requires:
   - All snapshots pass verify-chain-state-snapshot (fails closed on any invalid snapshot)
   - Unique validators count >= quorum-size (default: 2f+1 where n = (count trusted-validators) or (count snapshots))
   - Max finalized-epoch skew <= max-epoch-skew (default 2)
   - Strict agreement on [:balance :spendable :seq :deps :canonical-escrows] across agreeing quorum
   Returns {:ok? true :snapshot best-agreed :quorum-count n :validators [...]} or {:ok? false :error <reason>}."
  [snapshots opts]
  (let [raw-snaps (cond
                    (nil? snapshots) []
                    (map? snapshots) [snapshots]
                    (sequential? snapshots) (vec snapshots)
                    :else [])
        ;; Deduplicate snapshots by validator-pubkey
        unique-snaps (vals (into {}
                                 (keep (fn [s]
                                         (when (map? s)
                                           [(or (:validator-pubkey s) (get s "validator_pubkey")) s]))
                                       raw-snaps)))
        trusted (when (seq (:trusted-validators opts)) (set (:trusted-validators opts)))
        total-n (if (seq trusted) (count trusted) (count unique-snaps))
        quorum-size (long (or (:quorum-size opts)
                              (if (pos? total-n)
                                (long (Math/ceil (/ (* 2.0 total-n) 3.0)))
                                1)))]
    (if (empty? unique-snaps)
      {:ok? false :error "empty-snapshots"}
      (let [verifications (mapv #(verify-chain-state-snapshot % opts) unique-snaps)
            first-err (first (remove :ok? verifications))]
        (if first-err
          {:ok? false :error (:error first-err)}
          (let [valid-snaps (mapv :snapshot verifications)
                n-valid (count valid-snaps)]
            (if (< n-valid quorum-size)
              {:ok? false :error "insufficient-validator-quorum"}
              (let [fin-epochs (mapv :finalized-epoch valid-snaps)
                    min-fin (apply min fin-epochs)
                    max-fin (apply max fin-epochs)
                    max-skew (long (or (:max-epoch-skew opts) 2))]
                (if (> (- max-fin min-fin) max-skew)
                  {:ok? false :error "validator-epoch-skew-exceeded"}
                  (let [state-sig (fn [s]
                                    [(:balance s)
                                     (:spendable s)
                                     (:seq s)
                                     (:deps s)
                                     (str/join ";" (map canonical-escrow-entry-str (sort-by :escrow-id (:escrows s))))])
                        by-epoch (group-by :finalized-epoch valid-snaps)
                        same-epoch-disagreement? (some (fn [[_ snaps]]
                                                         (> (count (distinct (map state-sig snaps))) 1))
                                                       by-epoch)]
                    (if same-epoch-disagreement?
                      {:ok? false :error "validator-state-disagreement"}
                      (let [by-state (group-by state-sig valid-snaps)
                            [_ agreeing-snaps] (apply max-key (fn [[_ snaps]] (count snaps)) by-state)]
                        (if (< (count agreeing-snaps) quorum-size)
                          {:ok? false :error "validator-state-disagreement"}
                          (let [best-snap (apply max-key :finalized-epoch agreeing-snaps)]
                            {:ok? true
                             :snapshot best-snap
                             :quorum-count (count agreeing-snaps)
                             :validators (vec (sort (map :validator-pubkey agreeing-snaps)))}))))))))))))))

(defn apply-verified-chain-state-snapshot
  "Applies a verified chain state snapshot to local light-node state.
   Guards against stale finalized epochs (monotonicity) and clears stale
   status-dependent escrow fields on merge."
  [state snapshot]
  (let [curr-fin-ep (long (or (get-in state [:account :finalized-epoch]) 0))
        fin-epoch (parse-long-safe (or (:finalized-epoch snapshot) (get snapshot "finalized_epoch")) 0)]
    (if (< fin-epoch curr-fin-ep)
      state
      (let [new-account {:balance (long (or (:balance snapshot) 0))
                         :spendable (long (or (:spendable snapshot) 0))
                         :seq (long (or (:seq snapshot) 0))
                         :deps (vec (or (:deps snapshot) []))
                         :finalized-epoch fin-epoch}
            incoming-escrows (or (:escrows snapshot) [])
            existing-escrows (or (:escrows state) {})
            merged-escrows (reduce (fn [acc esc]
                                     (let [eid (:escrow-id esc)
                                           existing (dissoc (get acc eid {})
                                                            :settled-epoch :net-amount :take-burned :refund-reason
                                                            "settled_epoch" "net_amount" "take_burned" "refund_reason")]
                                       (assoc acc eid (merge existing esc))))
                                   existing-escrows
                                   incoming-escrows)]
        (-> state
            (assoc :account new-account
                   :transfer-seq (:seq new-account)
                   :last-transfer-hash (last (:deps new-account))
                   :epoch (max (long (or (:epoch state) 0)) fin-epoch)
                   :epoch-initialized? true
                   :escrows merged-escrows))))))

(defn build-chain-state-query-envelope
  "Builds and wraps an authenticated :query-chain-state agent envelope.
   opts can be a map (e.g. {:nonce ... :epoch ...}) or a string nonce."
  [pubkey-hex ^bytes privkey-bytes opts]
  (let [opts-map (if (map? opts) opts {:nonce (str opts)})
        payload {:type :query-chain-state
                 :pubkey pubkey-hex
                 :epoch (long (or (:epoch opts-map) 0))
                 :nonce (or (:nonce opts-map) (str (System/currentTimeMillis)))}]
    (mesh/wrap-agent-event payload pubkey-hex privkey-bytes)))

(defn- resolve-session-id
  "Resolves a session id from cmd-map or counterparty identifier (petname/pubkey).
   Supports :open (prefers open sessions) or :active (prefers non-closed sessions).
   Fails closed (returns nil) if multiple preferred sessions exist for the counterparty."
  [state cmd-map preference]
  (let [raw-sid (or (get cmd-map "session_id") (get cmd-map "session")
                    (:session_id cmd-map) (:session cmd-map))]
    (if (and raw-sid (contains? (:sessions state) raw-sid))
      raw-sid
      (let [target (or raw-sid (get cmd-map "peer") (get cmd-map "callee")
                       (:peer cmd-map) (:callee cmd-map))
            resolved (when target (resolve-counterparty state target))]
        (when (:ok? resolved)
          (let [matching (filterv (fn [[_ s]] (= (:peer s) (:pubkey resolved))) (:sessions state))
                preferred-pred (case preference
                                 :open (fn [[_ s]] (= "open" (:state s)))
                                 :active (fn [[_ s]] (not= "closed" (:state s)))
                                 (constantly true))
                preferred-matching (filterv preferred-pred matching)]
            (cond
              (= 1 (count preferred-matching))
              (first (first preferred-matching))

              (> (count preferred-matching) 1)
              nil

              (= 1 (count matching))
              (first (first matching))

              :else
              nil)))))))

(defn- resolve-accept-session-id
  "Resolves an accept session id from cmd-map or caller identifier in pending-offers."
  [state cmd-map]
  (let [raw-sid (or (get cmd-map "session_id") (:session_id cmd-map))]
    (if (and raw-sid (or (contains? (:pending-offers state) raw-sid)
                         (contains? (:sessions state) raw-sid)))
      raw-sid
      (let [target (or raw-sid (get cmd-map "caller") (get cmd-map "peer")
                       (:caller cmd-map) (:peer cmd-map))
            resolved (when target (resolve-counterparty state target))]
        (if (and resolved (:ok? resolved))
          (let [matching (filter (fn [[_ offer]] (= (:caller offer) (:pubkey resolved)))
                                 (:pending-offers state))]
            (if (= 1 (count matching))
              (first (first matching))
              raw-sid))
          raw-sid)))))

;; -----------------------------------------------------------------------------
;; Command Handlers (Pure Helpers)
;; -----------------------------------------------------------------------------

(defn- dac-summary [dac]
  (when (map? dac)
    (let [d (into {} (for [[k v] dac]
                       [(if (keyword? k) k (keyword (str/replace (name k) #"_" "-"))) v]))]
      {"dac_id" (:dac-id d)
       "anchor_pubkey" (:anchor-pubkey d)
       "expires_epoch" (:expires-epoch d)})))

(defn- exec-identity [state]
  {:state state
   :response (cond-> {"ok" true
                      "pubkey" (:pubkey state)
                      "fingerprint" (:fingerprint state)
                      "ice_ufrag" (get-in state [:ice-creds :ufrag])
                      "ice_pwd" (get-in state [:ice-creds :pwd])}
               (:dac state) (assoc "dac" (dac-summary (:dac state))))
   :net-envelopes []
   :stdout-events []})

(defn- exec-discover [state]
  (let [bs (:bootstrap state)
        nodes (for [[k v] (or (:nodes bs) {})]
                (cond-> {"node_id" (name k)
                         "ip" (:ip v)
                         "port" (:port v)
                         "agent_port" (:agent-port v)
                         "fingerprint" (:fingerprint v)}
                  (:agent-tcp-port v) (assoc "agent_tcp_port" (:agent-tcp-port v))
                  (:pubkey v) (assoc "pubkey" (:pubkey v))
                  (:ingress-host v) (assoc "ingress_host" (:ingress-host v))
                  (:ingress-port v) (assoc "ingress_port" (:ingress-port v))))]
    {:state state
     :response {"ok" true
                "network" (name (or (:network bs) :devnet))
                "treasury_pubkey" (:treasury-pubkey bs)
                "custody_pubkey" (:custody-pubkey bs)
                "validators" (vec nodes)}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-register-home-set [state cmd-map privkey-bytes]
  (let [p-b (long (or (get cmd-map "price") 0))
        p-b-max (long (or (get cmd-map "price_max") p-b 0))
        explicit-nodes (seq (remove str/blank? (map str (get cmd-map "home_nodes"))))]
    (if explicit-nodes
      (let [known-nodes (set (keys (get-in state [:bootstrap :nodes])))
            requested-nodes (mapv keyword explicit-nodes)]
        (if (or (empty? known-nodes) (not-every? known-nodes requested-nodes))
          {:state state
           :response {"ok" false "error" "unknown-home-node"}
           :net-envelopes []
           :stdout-events []}
          (let [candidate-maps (mapv (fn [cid] {:node-id cid :responsive? true :latency-ms 10 :price p-b}) requested-nodes)
                hs (rendezvous/register-home-set candidate-maps p-b p-b-max)
                my-pub (:pubkey state)
                curr-epoch (:epoch state)
                ice-ufrag (get-in state [:ice-creds :ufrag])
                ice-pwd (get-in state [:ice-creds :pwd])
                env-curr (agent-sim/build-home-set-envelope my-pub privkey-bytes requested-nodes p-b curr-epoch ice-ufrag ice-pwd)
                env-nil (agent-sim/build-home-set-envelope my-pub privkey-bytes requested-nodes p-b nil ice-ufrag ice-pwd)]
            {:state (assoc state :home-set (:home-nodes hs))
             :response {"ok" true
                        "status" (name (:status hs :ok))
                        "price" (:price hs p-b)
                        "home_nodes" (vec (for [n (:home-nodes hs)] (name (or (:node-id n) n))))}
             :net-envelopes [env-curr env-nil]
             :stdout-events []})))
      (let [candidates (vec (keys (get-in state [:bootstrap :nodes])))
            candidate-maps (mapv (fn [cid] {:node-id cid :responsive? true :latency-ms 10 :price p-b}) candidates)
            hs (rendezvous/register-home-set candidate-maps p-b p-b-max)
            my-pub (:pubkey state)
            curr-epoch (:epoch state)
            ice-ufrag (get-in state [:ice-creds :ufrag])
            ice-pwd (get-in state [:ice-creds :pwd])
            env-curr (agent-sim/build-home-set-envelope my-pub privkey-bytes candidates p-b curr-epoch ice-ufrag ice-pwd)
            env-nil (agent-sim/build-home-set-envelope my-pub privkey-bytes candidates p-b nil ice-ufrag ice-pwd)]
        {:state (assoc state :home-set (:home-nodes hs))
         :response {"ok" true
                    "status" (name (:status hs :ok))
                    "price" (:price hs p-b)
                    "home_nodes" (vec (for [n (:home-nodes hs)] (name (or (:node-id n) n))))}
         :net-envelopes [env-curr env-nil]
         :stdout-events []}))))

(defn compute-session-id
  "Computes deterministic session-id from caller, callee, and caller-ephemeral-pub."
  [caller callee caller-ephemeral-pub]
  (let [sid-input (str caller "-" callee "-" caller-ephemeral-pub)]
    (basalt/bytes->hex (crypto/sha256 (.getBytes ^String sid-input "UTF-8")))))

(defn compute-offer-hash
  "Computes deterministic offer-hash binding session-id, caller, callee, ephemeral key, epoch, price, home-node, and optional DAC.
   Recreates the exact 2d21308 base format (session-id-caller-callee-eph-epoch-price-homenode)
   with optional |<dac-id> appended when DAC is present."
  [offer-map]
  (let [caller (str (or (:caller offer-map) (get offer-map "caller") ""))
        callee (str (or (:callee offer-map) (get offer-map "callee") ""))
        eph-pub (str (or (:caller-ephemeral-pub offer-map) (get offer-map "caller_ephemeral_pub") (get offer-map "caller-ephemeral-pub")
                         (:caller-x25519 offer-map) (get offer-map "caller_x25519") (get offer-map "caller-x25519") ""))
        sid (str (or (:session-id offer-map) (get offer-map "session_id") (get offer-map "session-id")
                     (when (and (seq caller) (seq callee) (seq eph-pub))
                       (compute-session-id caller callee eph-pub))
                     ""))
        epoch (parse-long-safe (or (:epoch offer-map) (get offer-map "epoch")) 0)
        price-or-burn (parse-long-safe (or (:price offer-map) (get offer-map "price")
                                           (:burn offer-map) (get offer-map "burn")) 0)
        home-node (or (:home-node offer-map) (get offer-map "home_node") (get offer-map "home-node") "")
        hn-str (cond
                 (string? home-node) home-node
                 (or (keyword? home-node) (symbol? home-node)) (name home-node)
                 :else (str (or home-node "")))
        dac (or (:dac offer-map) (get offer-map "dac"))
        dac-id (or (:dac-id offer-map) (get offer-map "dac_id") (get offer-map "dac-id")
                   (when dac (or (:dac-id dac) (get dac "dac_id") (get dac "dac-id") (:dac_id dac))))
        hash-input (str sid "-" caller "-" callee "-" eph-pub "-" epoch "-" price-or-burn "-" hn-str
                        (when (and (string? dac-id) (not (str/blank? dac-id)))
                          (str "|" dac-id)))]
    (basalt/bytes->hex (crypto/sha256 (.getBytes ^String hash-input "UTF-8")))))

(defn canonical-rendezvous-header-str
  "Computes canonical string for Phase 1 :rendezvous-offer-header caller signature."
  [caller callee offer-hash epoch burn topic home-node dac-id]
  (str "bitecho-rendezvous-header-v1|"
       caller "|" callee "|" offer-hash "|"
       (long epoch) "|" (long burn) "|"
       (or topic "") "|" (or home-node "") "|" (or dac-id "")))

(defn canonical-rendezvous-ack-str
  "Computes canonical string for Phase 1b :rendezvous-ack-voucher callee signature."
  [caller callee offer-hash callee-x25519 epoch ack-sig]
  (str "bitecho-rendezvous-ack-v1|"
       caller "|" callee "|" offer-hash "|"
       callee-x25519 "|" (long epoch) "|" ack-sig))

(defn canonical-rendezvous-reveal-str
  "Computes canonical string for Phase 2 :rendezvous-reveal caller signature."
  [session-id caller callee offer-hash caller-x25519 epoch]
  (str "bitecho-rendezvous-reveal-v1|"
       session-id "|" caller "|" callee "|" offer-hash "|"
       caller-x25519 "|" (long epoch)))

(defn- exec-rendezvous-policy
  "Configures pure rendezvous policy for Callee introducer introduction."
  [state cmd-map]
  (let [curr-pol (or (:rendezvous-policy state)
                     {:auto-accept? false :min-burn 0 :price 10 :allowlist #{} :home-node "default-home"})
        raw-min-burn (or (get cmd-map "min_burn") (get cmd-map "min-burn")
                         (:min_burn cmd-map) (:min-burn cmd-map))
        raw-price (or (get cmd-map "price") (:price cmd-map))
        min-burn-val (when (some? raw-min-burn) (parse-long-safe raw-min-burn :invalid))
        price-val (when (some? raw-price) (parse-long-safe raw-price :invalid))]
    (if (or (and (some? raw-min-burn) (or (= min-burn-val :invalid) (< min-burn-val 0)))
            (and (some? raw-price) (or (= price-val :invalid) (< price-val 0))))
      {:state state
       :response {"ok" false "error" "invalid-policy-numeric"}
       :net-envelopes []
       :stdout-events []}
      (let [allowlist-raw (or (get cmd-map "allowlist") (:allowlist cmd-map))
            allowlist-resolved (when (some? allowlist-raw)
                                 (let [items (cond (sequential? allowlist-raw) allowlist-raw
                                                   (set? allowlist-raw) (vec allowlist-raw)
                                                   (string? allowlist-raw) (str/split allowlist-raw #",")
                                                   :else [])]
                                   (into #{}
                                         (keep (fn [item]
                                                 (let [s (str/trim (str item))]
                                                   (when (seq s)
                                                     (let [res (resolve-counterparty state s)]
                                                       (if (:ok? res)
                                                         (:pubkey res)
                                                         (normalize-pubkey-hex s))))))
                                               items))))
            home-node-val (let [hn (or (get cmd-map "home_node") (get cmd-map "home-node")
                                       (:home_node cmd-map) (:home-node cmd-map))]
                            (when (some? hn)
                              (if (keyword? hn) (name hn) (str hn))))
            auto-accept-val (let [aa (or (get cmd-map "auto_accept") (get cmd-map "auto-accept")
                                         (get cmd-map "auto_accept?") (get cmd-map "auto-accept?")
                                         (:auto_accept cmd-map) (:auto-accept cmd-map)
                                         (:auto_accept? cmd-map) (:auto-accept? cmd-map))]
                              (when (some? aa) (boolean aa)))
            updated-pol (cond-> curr-pol
                          (some? min-burn-val) (assoc :min-burn min-burn-val)
                          (some? price-val) (assoc :price price-val)
                          (some? allowlist-resolved) (assoc :allowlist allowlist-resolved)
                          (some? home-node-val) (assoc :home-node home-node-val)
                          (some? auto-accept-val) (assoc :auto-accept? auto-accept-val))
            new-state (assoc state :rendezvous-policy updated-pol)]
        {:state new-state
         :response {"ok" true
                    "rendezvous_policy" {"min_burn" (:min-burn updated-pol)
                                         "price" (:price updated-pol)
                                         "allowlist" (vec (sort (:allowlist updated-pol #{})))
                                         "home_node" (:home-node updated-pol)
                                         "auto_accept" (:auto-accept? updated-pol)}}
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-rendezvous-offer
  "Phase 1 introduction: Caller initiates two-phase rendezvous offer header,
   withholding ephemeral X25519 key until callee DeliveryAck voucher is returned."
  [state cmd-map privkey-bytes]
  (let [callee-target (or (get cmd-map "callee") (get cmd-map "to")
                          (:callee cmd-map) (:to cmd-map))
        resolved (resolve-counterparty state callee-target)]
    (if-not (:ok? resolved)
      {:state state
       :response {"ok" false "error" (:error resolved)}
       :net-envelopes []
       :stdout-events []}
      (let [raw-burn (or (get cmd-map "burn") (:burn cmd-map))
            parsed-burn (if (some? raw-burn) (parse-long-safe raw-burn :invalid) 500)]
        (if (or (= parsed-burn :invalid) (< parsed-burn 0))
          {:state state
           :response {"ok" false "error" "invalid-burn"}
           :net-envelopes []
           :stdout-events []}
          (let [callee (:pubkey resolved)
                pname (:petname resolved)
                burn-amt parsed-burn
                topic (str (or (get cmd-map "topic") (:topic cmd-map) ""))
                default-home (or (first (keys (get-in state [:bootstrap :nodes]))) :node1)
                home-node (name (or (get cmd-map "home_node") (get cmd-map "home-node")
                                    (:home_node cmd-map) (:home-node cmd-map)
                                    default-home))
                text (or (get cmd-map "text") (:text cmd-map))
                caller (:pubkey state)
                kp-eph (sealed/generate-x25519-keypair)
                caller-x25519-pub (basalt/bytes->hex (:public kp-eph))
                session-id (compute-session-id caller callee caller-x25519-pub)
                epoch (:epoch state)
                active-dac (when-let [d (:dac state)]
                             (when (and (:ok? (verify-dac d {:expected-agent-pubkey caller
                                                             :current-epoch epoch
                                                             :revoked-dac-ids (:revoked-dacs state)}))
                                        (let [sc (set (map name (:scopes d)))]
                                          (or (contains? sc "offer") (contains? sc "rendezvous"))))
                               d))
                dac-id (when active-dac (or (:dac-id active-dac) (get active-dac "dac_id")))
                offer-hash (compute-offer-hash {:session-id session-id
                                                :caller caller
                                                :callee callee
                                                :caller-ephemeral-pub caller-x25519-pub
                                                :epoch epoch
                                                :price burn-amt
                                                :burn burn-amt
                                                :home-node home-node
                                                :dac active-dac})
                header-str (canonical-rendezvous-header-str caller callee offer-hash epoch burn-amt topic home-node dac-id)
                sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes header-str "UTF-8")))
                wire-payload (cond-> {:bitecho/type :rendezvous-offer-header
                                      :type :rendezvous-offer-header
                                      :caller caller
                                      :callee callee
                                      :offer-hash offer-hash
                                      :epoch epoch
                                      :burn burn-amt
                                      :topic topic
                                      :home-node home-node
                                      :signature sig-hex}
                               active-dac (assoc :dac active-dac))
                gossip-env (agent-sim/build-gossip-envelope caller privkey-bytes (nippy/freeze wire-payload) burn-amt)
                outbound-entry {:offer-hash offer-hash
                                :session-id session-id
                                :caller caller
                                :callee callee
                                :caller-x25519-priv (:private kp-eph)
                                :caller-x25519-pub caller-x25519-pub
                                :initial-text text
                                :epoch epoch
                                :burn burn-amt
                                :topic topic
                                :home-node home-node
                                :dac active-dac}
                new-state (-> state
                              (assoc-in [:outbound-rendezvous offer-hash] outbound-entry)
                              (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))]
            {:state new-state
             :response (cond-> {"ok" true
                                "offer_hash" offer-hash
                                "session_id" session-id
                                "caller" caller
                                "callee" callee
                                "burn" burn-amt}
                         pname (assoc "callee_petname" pname "peer_petname" pname))
             :net-envelopes [gossip-env]
             :stdout-events []}))))))

(defn- callee-issue-rendezvous-ack
  "Pure helper for Callee accepting an offer header, signing a DeliveryAck voucher,
   generating ephemeral X25519 key, and creating the :rendezvous-ack-voucher wire envelope."
  [state pending-header privkey-bytes]
  (let [caller (:caller pending-header)
        callee (:callee pending-header)
        offer-hash (:offer-hash pending-header)
        epoch (long (or (:epoch pending-header) (:epoch state) 0))
        home-node (rendezvous/normalize-home-node
                   (or (:home-node pending-header)
                       (get-in state [:rendezvous-policy :home-node])
                       "default-home"))
        p-b (long (or (get-in state [:rendezvous-policy :price]) 10))
        seq-key [home-node epoch]
        curr-seq (long (get-in state [:voucher-seqs seq-key] 0))
        next-seq (inc curr-seq)
        cumulative-debit (* next-seq p-b)
        signed-ack (rendezvous/create-delivery-ack privkey-bytes callee home-node epoch offer-hash next-seq cumulative-debit)
        kp-callee (sealed/generate-x25519-keypair)
        callee-x25519-pub (basalt/bytes->hex (:public kp-callee))
        ack-str (canonical-rendezvous-ack-str caller callee offer-hash callee-x25519-pub epoch (:signature signed-ack))
        sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes ack-str "UTF-8")))
        ack-payload {:bitecho/type :rendezvous-ack-voucher
                     :type :rendezvous-ack-voucher
                     :caller caller
                     :callee callee
                     :offer-hash offer-hash
                     :callee-x25519 callee-x25519-pub
                     :epoch epoch
                     :delivery-ack (into {} signed-ack)
                     :signature sig-hex}
        gossip-env (agent-sim/build-gossip-envelope callee privkey-bytes (nippy/freeze ack-payload) 500)
        accept-entry {:callee-x25519-priv (:private kp-callee)
                      :callee-x25519-pub callee-x25519-pub
                      :caller caller
                      :callee callee
                      :epoch epoch
                      :delivery-ack (into {} signed-ack)
                      :header pending-header}
        new-state (-> state
                      (update :pending-rendezvous dissoc offer-hash)
                      (assoc-in [:pending-rendezvous-accepts offer-hash] accept-entry)
                      (assoc-in [:voucher-seqs seq-key] next-seq))]
    {:state new-state
     :signed-ack signed-ack
     :callee-x25519 callee-x25519-pub
     :next-seq next-seq
     :cumulative-debit cumulative-debit
     :net-envelopes [gossip-env]}))

(defn- exec-rendezvous-accept
  "Explicit Callee accept command for a pending rendezvous offer header."
  [state cmd-map privkey-bytes]
  (let [oh (or (get cmd-map "offer_hash") (get cmd-map "offer-hash")
               (:offer_hash cmd-map) (:offer-hash cmd-map))
        from-target (or (get cmd-map "from") (get cmd-map "caller")
                        (:from cmd-map) (:caller cmd-map))
        pending-header (cond
                         (and oh (contains? (:pending-rendezvous state) oh))
                         (get-in state [:pending-rendezvous oh])

                         from-target
                         (let [res (resolve-counterparty state from-target)]
                           (when (:ok? res)
                             (some (fn [[_ h]] (when (= (normalize-pubkey-hex (:caller h))
                                                        (normalize-pubkey-hex (:pubkey res)))
                                                 h))
                                   (:pending-rendezvous state))))
                         :else nil)]
    (if-not pending-header
      {:state state
       :response {"ok" false "error" "rendezvous-offer-not-found"}
       :net-envelopes []
       :stdout-events []}
      (let [ack-res (callee-issue-rendezvous-ack state pending-header privkey-bytes)
            caller (:caller pending-header)
            caller-pname (pubkey->petname state caller)]
        {:state (:state ack-res)
         :response (cond-> {"ok" true
                            "offer_hash" (:offer-hash pending-header)
                            "caller" caller
                            "callee" (:callee pending-header)
                            "seq" (:next-seq ack-res)
                            "cumulative_debit" (:cumulative-debit ack-res)}
                     caller-pname (assoc "caller_petname" caller-pname "peer_petname" caller-pname))
         :net-envelopes (:net-envelopes ack-res)
         :stdout-events []}))))

(defn- exec-offer [state cmd-map privkey-bytes]
  (let [callee-target (or (get cmd-map "callee") (:callee cmd-map))
        resolved (resolve-counterparty state callee-target)]
    (if-not (:ok? resolved)
      {:state state
       :response {"ok" false "error" (:error resolved)}
       :net-envelopes []
       :stdout-events []}
      (let [raw-price (or (get cmd-map "price") (:price cmd-map))
            raw-burn (or (get cmd-map "burn") (:burn cmd-map))
            parsed-price (if (some? raw-price) (parse-long-safe raw-price :invalid) 0)
            parsed-burn (if (some? raw-burn) (parse-long-safe raw-burn :invalid) 500)]
        (if (or (= parsed-price :invalid) (< parsed-price 0)
                (= parsed-burn :invalid) (< parsed-burn 0))
          {:state state
           :response {"ok" false "error" "invalid-numeric-parameter"}
           :net-envelopes []
           :stdout-events []}
          (let [callee (:pubkey resolved)
                pname (:petname resolved)
                price parsed-price
                default-home (or (first (keys (get-in state [:bootstrap :nodes]))) :node1)
                home-node (name (or (get cmd-map "home_node") (:home_node cmd-map) default-home))
                burn-amt parsed-burn
                kp-eph (sealed/generate-x25519-keypair)
                caller (:pubkey state)
                eph-pub-hex (basalt/bytes->hex (:public kp-eph))
                session-id (compute-session-id caller callee eph-pub-hex)
                epoch (:epoch state)
                active-dac (when-let [d (:dac state)]
                             (when (:ok? (verify-dac d {:expected-agent-pubkey (:pubkey state)
                                                        :current-epoch epoch
                                                        :revoked-dac-ids (:revoked-dacs state)
                                                        :required-scope "offer"}))
                               d))
                offer-hash (compute-offer-hash {:session-id session-id
                                                :caller caller
                                                :callee callee
                                                :caller-ephemeral-pub eph-pub-hex
                                                :epoch epoch
                                                :price price
                                                :home-node home-node
                                                :dac active-dac})
                sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes offer-hash "UTF-8")))
                offer-payload (cond-> {:bitecho/type :channel-offer
                                       :session-id session-id
                                       :caller caller
                                       :callee callee
                                       :caller-ephemeral-pub eph-pub-hex
                                       :epoch epoch
                                       :price price
                                       :home-node home-node
                                       :offer-hash offer-hash
                                       :burn burn-amt
                                       :signature sig-hex}
                                active-dac (assoc :dac active-dac))
                gossip-env (agent-sim/build-gossip-envelope caller privkey-bytes (nippy/freeze offer-payload) burn-amt)
                header-event {:type :receive-offer-header
                              :caller caller
                              :callee callee
                              :home-node home-node
                              :epoch epoch
                              :price price
                              :offer-hash offer-hash
                              :session-id session-id}
                header-env (mesh/wrap-agent-event header-event caller privkey-bytes)
                session-entry {:session-id session-id
                               :peer callee
                               :role :initiator
                               :state "offered"
                               :tx-seq 0
                               :epoch epoch
                               :ephemeral-pub (:public kp-eph)
                               :ephemeral-priv (:private kp-eph)
                               :price price
                               :home-node home-node
                               :offer-hash offer-hash}
                new-state (-> state
                              (assoc-in [:sessions session-id] session-entry)
                              (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))]
            {:state new-state
             :response (cond-> {"ok" true
                                "session_id" session-id
                                "state" "offered"
                                "callee" callee
                                "price" price
                                "burn" burn-amt}
                         pname (assoc "callee_petname" pname "peer_petname" pname))
             :net-envelopes [header-env gossip-env]
             :stdout-events []}))))))

(defn- exec-accept [state cmd-map privkey-bytes]
  (let [session-id (resolve-accept-session-id state cmd-map)]
    (cond
      (contains? (:sessions state) session-id)
      {:state (update state :pending-offers dissoc session-id)
       :response {"ok" false "error" "session-already-exists"}
       :net-envelopes []
       :stdout-events []}

      (not (get-in state [:pending-offers session-id]))
      {:state state :response {"ok" false "error" "offer-not-found"} :net-envelopes [] :stdout-events []}

      :else
      (let [offer (get-in state [:pending-offers session-id])
            caller (:caller offer)
            caller-pname (pubkey->petname state caller)
            kp-resp (sealed/generate-x25519-keypair)
            caller-eph (basalt/hex->bytes (:caller-ephemeral-pub offer))
            shared-sec (sealed/x25519-shared-secret (:private kp-resp) caller-eph)
            keys (sealed/derive-channel-keys shared-sec session-id :responder)
            eph-pub-hex (basalt/bytes->hex (:public kp-resp))
            epoch (long (or (:epoch offer) (:epoch state) 0))
            burn-val (or (:burn offer) 500)
            ack-res (rendezvous/process-offer-header
                     {:caller caller
                      :callee (:pubkey state)
                      :callee-privkey privkey-bytes
                      :offer {:epoch (:epoch offer)
                              :home-node (:home-node offer)
                              :offer-hash (:offer-hash offer)
                              :price (:price offer)}
                      :home-node (:home-node offer)
                      :epoch (:epoch offer)
                      :offer-hash (:offer-hash offer)
                      :price (:price offer)
                      :burn burn-val
                      :seq 1
                      :min-burn 100})
            delivery-ack (into {} (:delivery-ack ack-res))
            sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes (str session-id "-" eph-pub-hex) "UTF-8")))
            accept-payload {:bitecho/type :channel-accept
                            :session-id session-id
                            :caller caller
                            :callee (:pubkey state)
                            :callee-ephemeral-pub eph-pub-hex
                            :epoch epoch
                            :delivery-ack delivery-ack
                            :signature sig-hex}
            gossip-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze accept-payload) 500)
            session-entry {:session-id session-id
                           :peer caller
                           :role :responder
                           :state "open"
                           :tx-seq 0
                           :acked-seq 0
                           :rx-high-seq 0
                           :contiguous-rx-seq 0
                           :replays-deduped 0
                           :outbox-evicted 0
                           :outbox {}
                           :outbox-order []
                           :epoch epoch
                           :tx-key (:tx-key keys)
                           :rx-key (:rx-key keys)
                           :replay-window (sealed/init-replay-window)}
            new-state (-> state
                          (update :pending-offers dissoc session-id)
                          (assoc-in [:sessions session-id] session-entry))
            event (cond-> {"event" "channel-opened" "session_id" session-id "peer" caller}
                    caller-pname (assoc "peer_petname" caller-pname))]
        {:state new-state
         :response (cond-> {"ok" true "session_id" session-id "state" "open" "peer" caller}
                     caller-pname (assoc "peer_petname" caller-pname))
         :net-envelopes [gossip-env]
         :stdout-events [event]}))))

(defn- exec-send [state cmd-map privkey-bytes]
  (let [session-id (resolve-session-id state cmd-map :open)
        session (get-in state [:sessions session-id])]
    (if-not (and session (= "open" (:state session)))
      {:state state :response {"ok" false "error" "session-not-open"} :net-envelopes [] :stdout-events []}
      (let [pname (pubkey->petname state (:peer session))
            text (get cmd-map "text")
            payload-hex (get cmd-map "payload_hex")
            payload-bytes (cond (some? text) (.getBytes ^String text "UTF-8")
                                (some? payload-hex) (basalt/hex->bytes payload-hex)
                                :else (byte-array 0))
            burn-amt (long (or (get cmd-map "burn") 500))
            seq-num (inc (:tx-seq session 0))
            sealed (sealed/seal-message (:tx-key session) seq-num payload-bytes (.getBytes session-id "UTF-8"))
            msg-payload {:bitecho/type :sealed-message
                         :session-id session-id
                         :sender (:pubkey state)
                         :recipient (:peer session)
                         :epoch (long (or (:epoch session) (:epoch state) 0))
                         :seq seq-num
                         :nonce (basalt/bytes->hex (:nonce sealed))
                         :ciphertext (basalt/bytes->hex (:ciphertext sealed))}
            gossip-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze msg-payload) burn-amt)
            max-outbox (long (or (:max-outbox-size state) 64))
            curr-outbox (or (:outbox session) {})
            curr-order (or (:outbox-order session) [])
            next-order (conj curr-order seq-num)
            next-outbox (assoc curr-outbox seq-num {:seq seq-num :msg-payload msg-payload :burn burn-amt :gossip-env gossip-env})
            [final-outbox final-order overflow] (if (> (count next-order) max-outbox)
                                                  (let [overflow (- (count next-order) max-outbox)
                                                        evicted (subvec next-order 0 overflow)
                                                        kept (subvec next-order overflow)]
                                                    [(apply dissoc next-outbox evicted) kept overflow])
                                                  [next-outbox next-order 0])
            new-state (cond-> (-> state
                                  (assoc-in [:sessions session-id :tx-seq] seq-num)
                                  (assoc-in [:sessions session-id :outbox] final-outbox)
                                  (assoc-in [:sessions session-id :outbox-order] final-order)
                                  (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))
                        (pos? overflow)
                        (update-in [:sessions session-id :outbox-evicted] (fnil + 0) overflow))]
        {:state new-state
         :response (cond-> {"ok" true
                            "session_id" session-id
                            "seq" seq-num
                            "bytes_sent" (alength payload-bytes)
                            "burn" burn-amt}
                     pname (assoc "peer_petname" pname))
         :net-envelopes [gossip-env]
         :stdout-events []}))))

(defn- exec-inbox [state]
  (let [enriched-msgs (mapv (fn [m]
                              (let [clean-m (dissoc m :from_petname :from-petname "from_petname" "from-petname")
                                    sender (or (:from clean-m) (get clean-m "from"))
                                    pname (when sender (pubkey->petname state sender))]
                                (cond-> clean-m
                                  pname (assoc :from_petname pname "from_petname" pname))))
                            (:inbox state))
        enriched-offers (mapv (fn [o]
                                (let [clean-o (dissoc o :petname :nickname :caller_petname :caller-petname
                                                      "petname" "nickname" "caller_petname" "caller-petname")
                                      caller (or (:caller clean-o) (get clean-o "caller"))
                                      pname (when caller (pubkey->petname state caller))]
                                  (cond-> clean-o
                                    pname (assoc :caller_petname pname "caller_petname" pname))))
                              (vec (vals (:pending-offers state))))
        enriched-rendezvous (mapv (fn [r]
                                    (let [clean-r (dissoc r :caller_petname :caller-petname "caller_petname" "caller-petname")
                                          caller (or (:caller clean-r) (get clean-r "caller"))
                                          pname (when caller (pubkey->petname state caller))]
                                      (cond-> clean-r
                                        pname (assoc :caller_petname pname "caller_petname" pname))))
                                  (vec (vals (:pending-rendezvous state))))]
    {:state (assoc state :inbox [])
     :response {"ok" true
                "messages" enriched-msgs
                "pending_offers" enriched-offers
                "pending_rendezvous" enriched-rendezvous}
     :net-envelopes []
     :stdout-events []}))

(defn- exec-close [state cmd-map privkey-bytes]
  (let [session-id (resolve-session-id state cmd-map :active)
        session (get-in state [:sessions session-id])]
    (if-not session
      {:state state :response {"ok" false "error" "session-not-found"} :net-envelopes [] :stdout-events []}
      (let [pname (pubkey->petname state (:peer session))
            sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes (str "close-" session-id) "UTF-8")))
            close-payload {:bitecho/type :channel-close
                           :session-id session-id
                           :sender (:pubkey state)
                           :recipient (:peer session)
                           :epoch (long (or (:epoch session) (:epoch state) 0))
                           :signature sig-hex}
            gossip-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze close-payload) 500)
            closed-sess (-> session
                            (assoc :state "closed")
                            (dissoc :tx-key :rx-key :ephemeral-priv))
            new-state (assoc-in state [:sessions session-id] closed-sess)]
        {:state new-state
         :response (cond-> {"ok" true "session_id" session-id "state" "closed"}
                     pname (assoc "peer_petname" pname))
         :net-envelopes [gossip-env]
         :stdout-events []}))))

(defn- exec-sync-account [state cmd-map]
  (let [raw-snapshots (or (get cmd-map "snapshots") (:snapshots cmd-map)
                          (when-let [s (or (get cmd-map "snapshot") (:snapshot cmd-map))]
                            [s]))]
    (if raw-snapshots
      (let [trusted-validators (set (keep :pubkey (vals (get-in state [:bootstrap :nodes]))))
            q-opts {:expected-pubkey (:pubkey state)
                    :trusted-validators trusted-validators
                    :min-finalized-epoch (get-in state [:account :finalized-epoch] 0)}
            q-res (verify-chain-state-quorum raw-snapshots q-opts)]
        (if (:ok? q-res)
          (let [snap (:snapshot q-res)
                st-applied (apply-verified-chain-state-snapshot state snap)
                new-state (assoc-in st-applied [:chain-state-snapshots (:validator-pubkey snap)] snap)]
            {:state new-state
             :response {"ok" true
                        "synced" true
                        "pubkey" (:pubkey state)
                        "balance" (:balance snap)
                        "spendable" (:spendable snap)
                        "seq" (:seq snap)
                        "deps" (vec (:deps snap))
                        "finalized_epoch" (:finalized-epoch snap)
                        "escrows_count" (count (:escrows snap))
                        "quorum_count" (:quorum-count q-res)
                        "validators" (:validators q-res)}
             :net-envelopes []
             :stdout-events []})
          {:state state
           :response {"ok" false "error" (:error q-res)}
           :net-envelopes []
           :stdout-events []}))
      (if (or (contains? cmd-map "balance")
              (contains? cmd-map :balance)
              (contains? cmd-map "seq")
              (contains? cmd-map :seq)
              (contains? cmd-map "spendable")
              (contains? cmd-map :spendable)
              (map? (get cmd-map "account"))
              (map? (get cmd-map :account)))
        (let [acct (or (when (map? (get cmd-map "account")) (get cmd-map "account"))
                       (when (map? (get cmd-map :account)) (get cmd-map :account))
                       cmd-map)
              bal (long (or (get acct "balance")
                            (:balance acct)
                            (get-in state [:account :balance])
                            0))
              spendable (long (or (get cmd-map "spendable")
                                  (:spendable cmd-map)
                                  (get acct "spendable")
                                  (:spendable acct)
                                  bal))
              seq-num (long (or (get acct "seq")
                                (:seq acct)
                                (:transfer-seq state)
                                0))
              deps (vec (map str (or (get acct "deps")
                                     (:deps acct)
                                     (when-let [h (:last-transfer-hash state)] [h])
                                     [])))
              fin-ep (long (or (get cmd-map "finalized_epoch")
                               (:finalized-epoch cmd-map)
                               (get acct "finalized_epoch")
                               (:epoch state)
                               0))
              new-state (assoc state
                               :account {:balance bal
                                         :spendable spendable
                                         :seq seq-num
                                         :deps deps
                                         :finalized-epoch fin-ep}
                               :transfer-seq seq-num
                               :last-transfer-hash (last deps))]
          {:state new-state
           :response {"ok" true
                      "pubkey" (:pubkey state)
                      "balance" bal
                      "spendable" spendable
                      "seq" seq-num
                      "deps" deps
                      "finalized_epoch" fin-ep
                      "synced" true}
           :net-envelopes []
           :stdout-events []})
        (let [acct (:account state)
              bal (long (or (:balance acct) 0))
              spendable (long (or (:spendable acct) bal))
              seq-num (long (or (:seq acct) (:transfer-seq state 0)))
              deps (vec (or (:deps acct) (when-let [h (:last-transfer-hash state)] [h]) []))
              fin-ep (long (or (:finalized-epoch acct) (:epoch state 0)))]
          {:state state
           :response {"ok" true
                      "pubkey" (:pubkey state)
                      "balance" bal
                      "spendable" spendable
                      "seq" seq-num
                      "deps" deps
                      "finalized_epoch" fin-ep
                      "synced" (some? acct)}
           :net-envelopes []
           :stdout-events []})))))

(defn- effective-chain-epoch
  "Returns the best-known on-chain epoch from :epoch and [:account :finalized-epoch]."
  [state]
  (max (long (or (:epoch state) 0))
       (long (or (get-in state [:account :finalized-epoch]) 0))))

(defn- check-dac-spend-authorization
  "Checks whether the current state's DAC permits spending `amount` in `required-scopes`.
   Returns {:ok? true :new-dac-spend ...} on success or when no DAC is attached.
   Returns {:ok? false :error <reason>} if DAC is invalid, expired, revoked, scope not permitted,
   or if (+ current-spent amount) > max-spend-per-epoch.
   Tracks cumulative spend per DAC ID under :dac-spend {dac-id {:epoch current-epoch :spent new-spent}}."
  [state amount required-scopes]
  (if-let [dac (:dac state)]
    (let [curr-epoch (effective-chain-epoch state)
          dac-res (verify-dac dac {:expected-agent-pubkey (:pubkey state)
                                   :current-epoch curr-epoch
                                   :revoked-dac-ids (:revoked-dacs state)
                                   :required-scope required-scopes})]
      (if-not (:ok? dac-res)
        (let [err (:error dac-res)]
          {:ok? false :error (if (= err "dac-scope-not-permitted") "dac-scope-denied" err)})
        (let [dac-id (:dac-id (:dac dac-res))
              max-spend (long (or (:max-spend-per-epoch (:dac dac-res))
                                  (:max-spend-per-epoch dac)
                                  0))
              dac-spend-map (if (map? (:dac-spend state)) (:dac-spend state) {})
              current-record (get dac-spend-map dac-id)
              current-spent (if (and (map? current-record)
                                     (= (:epoch current-record) curr-epoch))
                              (long (or (:spent current-record) 0))
                              0)
              new-spent (+ current-spent (long amount))]
          (if (> new-spent max-spend)
            {:ok? false :error "dac-max-spend-exceeded"}
            {:ok? true
             :new-dac-spend (assoc dac-spend-map dac-id {:epoch curr-epoch :spent new-spent})}))))
    {:ok? true :new-dac-spend (:dac-spend state)}))

(defn- exec-transfer [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient")
                         (:receiver cmd-map) (:recipient cmd-map))
        amount (parse-long-safe (or (get cmd-map "amount") (:amount cmd-map)) 0)]
    (if (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)) (<= amount 0))
      {:state state
       :response {"ok" false "error" "invalid-transfer-params"}
       :net-envelopes []
       :stdout-events []}
      (let [dac-auth (check-dac-spend-authorization state amount "transfer")]
        (if-not (:ok? dac-auth)
          {:state state
           :response {"ok" false "error" (:error dac-auth)}
           :net-envelopes []
           :stdout-events []}
          (let [resolved (resolve-counterparty state raw-receiver)]
            (if-not (:ok? resolved)
              {:state state
               :response {"ok" false "error" (:error resolved)}
               :net-envelopes []
               :stdout-events []}
              (let [receiver (:pubkey resolved)
                    pname (:petname resolved)
                    burn-amt (parse-long-safe (or (get cmd-map "burn") (:burn cmd-map)) 500)
                    acct (:account state)
                    spendable (when acct (parse-long-safe (or (:spendable acct) (:balance acct)) 0))]
                (if (and acct (< spendable (+ amount burn-amt)))
                  {:state state
                   :response {"ok" false "error" "insufficient-balance"}
                   :net-envelopes []
                   :stdout-events []}
                  (let [seq-num (parse-long-safe (or (get cmd-map "seq")
                                                     (:seq cmd-map))
                                                 (inc (long (or (when acct (:seq acct))
                                                                (:transfer-seq state)
                                                                0))))
                        deps (vec (or (get cmd-map "deps")
                                      (:deps cmd-map)
                                      (when (and acct (seq (:deps acct))) (:deps acct))
                                      (when-let [prev (:last-transfer-hash state)] [prev])
                                      []))
                        res (agent-sim/build-transfer-gossip-envelope
                             (:pubkey state)
                             privkey-bytes
                             {:receiver receiver :amount amount :seq seq-num :deps deps}
                             burn-amt)
                        deliver-payload (vec (.getBytes ^String (pr-str {:transfer (into {} (:transfer res))}) "UTF-8"))
                        deliver-env (mesh/wrap-agent-event
                                     {:type :on-deliver
                                      :payload deliver-payload
                                      :message-id (:transfer-hash res)}
                                     (:pubkey state)
                                     privkey-bytes)
                        new-state (cond-> (-> state
                                              (assoc :transfer-seq seq-num
                                                     :last-transfer-hash (:transfer-hash res)
                                                     :dac-spend (:new-dac-spend dac-auth))
                                              (update-in [:local-accounting :burned-ech] (fnil + 0) burn-amt))
                                    acct (-> (assoc-in [:account :seq] seq-num)
                                             (assoc-in [:account :deps] [(:transfer-hash res)])
                                             (update-in [:account :spendable] - (+ amount burn-amt))))]
                    {:state new-state
                     :response (cond-> {"ok" true
                                        "transfer_hash" (:transfer-hash res)
                                        "tx_id" (:transfer-hash res)
                                        "receiver" receiver
                                        "recipient" receiver
                                        "amount" amount
                                        "seq" seq-num}
                                 pname (assoc "receiver_petname" pname "recipient_petname" pname))
                     :net-envelopes [(:envelope res) deliver-env]
                     :stdout-events []}))))))))))

(defn- exec-settle-intent [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient")
                         (:receiver cmd-map) (:recipient cmd-map))
        amount (parse-long-safe (or (get cmd-map "amount") (:amount cmd-map)) 0)]
    (if (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)) (<= amount 0))
      {:state state
       :response {"ok" false "error" "invalid-intent-params"}
       :net-envelopes []
       :stdout-events []}
      (let [dac-auth (check-dac-spend-authorization state amount ["settle" "settle-intent"])]
        (if-not (:ok? dac-auth)
          {:state state
           :response {"ok" false "error" (:error dac-auth)}
           :net-envelopes []
           :stdout-events []}
          (let [resolved (resolve-counterparty state raw-receiver)]
            (if-not (:ok? resolved)
              {:state state
               :response {"ok" false "error" (:error resolved)}
               :net-envelopes []
               :stdout-events []}
              (let [receiver (:pubkey resolved)
                    pname (:petname resolved)
                    acct (:account state)
                    spendable (when acct (parse-long-safe (or (:spendable acct) (:balance acct)) 0))]
                (if (and acct (< spendable amount))
                  {:state state
                   :response {"ok" false "error" "insufficient-balance"}
                   :net-envelopes []
                   :stdout-events []}
                  (let [next-intent-seq (inc (long (:intent-seq state 0)))
                        curr-ep (effective-chain-epoch state)
                        rid (or (get cmd-map "receipt_id")
                                (:receipt_id cmd-map)
                                (str "intent:" (:pubkey state) ":" receiver ":" amount ":" curr-ep ":" next-intent-seq))
                        take-amt (burn/calculate-settlement-take amount burn/default-settlement-take-bps)
                        net-amt (- amount take-amt)
                        intent-env (mesh/wrap-agent-event
                                    {:type :settle-intent
                                     :payer (:pubkey state)
                                     :receiver receiver
                                     :amount amount
                                     :epoch curr-ep
                                     :receipt-id rid}
                                    (:pubkey state)
                                    privkey-bytes)
                        new-state (cond-> (assoc state :intent-seq next-intent-seq
                                                 :dac-spend (:new-dac-spend dac-auth))
                                    acct (update-in [:account :spendable] - amount))]
                    {:state new-state
                     :response (cond-> {"ok" true
                                        "receipt_id" rid
                                        "payer" (:pubkey state)
                                        "receiver" receiver
                                        "amount" amount
                                        "take" take-amt
                                        "net_amount" net-amt}
                                 pname (assoc "receiver_petname" pname))
                     :net-envelopes [intent-env]
                     :stdout-events []}))))))))))

(defn- exec-lock-intent [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient") (get cmd-map "to")
                         (:receiver cmd-map) (:recipient cmd-map) (:to cmd-map))
        raw-amount (or (get cmd-map "amount") (:amount cmd-map))
        amount (when (some? raw-amount) (parse-long-safe raw-amount :invalid))
        raw-dh (or (get cmd-map "deliverable_hash") (get cmd-map "deliverable-hash")
                   (:deliverable_hash cmd-map) (:deliverable-hash cmd-map))
        raw-deliv (or (get cmd-map "deliverable") (:deliverable cmd-map)
                      (get cmd-map "preimage") (:preimage cmd-map))
        deliverable-hash (cond
                           (and (string? raw-dh) (escrow/valid-deliverable-hash? raw-dh)) (escrow/normalize-hex raw-dh)
                           (and (string? raw-deliv) (not (str/blank? raw-deliv))) (basalt/bytes->hex (crypto/sha256 (.getBytes ^String raw-deliv StandardCharsets/UTF_8)))
                           :else nil)
        curr-ep (effective-chain-epoch state)
        raw-expires (or (get cmd-map "expires_epoch") (get cmd-map "expires-epoch")
                        (:expires_epoch cmd-map) (:expires-epoch cmd-map))
        expires-epoch (if (some? raw-expires) (parse-long-safe raw-expires :invalid) (+ curr-ep 10))]
    (cond
      (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)))
      {:state state :response {"ok" false "error" "missing-receiver"} :net-envelopes [] :stdout-events []}

      (or (nil? amount) (= amount :invalid) (<= amount 0))
      {:state state :response {"ok" false "error" "invalid-amount"} :net-envelopes [] :stdout-events []}

      (nil? deliverable-hash)
      {:state state :response {"ok" false "error" (if raw-dh "invalid-deliverable-hash" "missing-deliverable-hash")} :net-envelopes [] :stdout-events []}

      (or (= expires-epoch :invalid) (<= expires-epoch curr-ep))
      {:state state :response {"ok" false "error" "invalid-expires-epoch"} :net-envelopes [] :stdout-events []}

      :else
      (let [resolved (resolve-counterparty state raw-receiver)]
        (if-not (:ok? resolved)
          {:state state :response {"ok" false "error" (:error resolved)} :net-envelopes [] :stdout-events []}
          (let [receiver-pub (:pubkey resolved)
                pname (:petname resolved)]
            (if (= (:pubkey state) receiver-pub)
              {:state state :response {"ok" false "error" "cannot-escrow-self"} :net-envelopes [] :stdout-events []}
              (let [dac-auth (check-dac-spend-authorization state amount ["lock-intent" "settle" "settle-intent"])]
                (if-not (:ok? dac-auth)
                  {:state state :response {"ok" false "error" (:error dac-auth)} :net-envelopes [] :stdout-events []}
                  (let [acct (:account state)
                        spendable (when acct (parse-long-safe (or (:spendable acct) (:balance acct)) 0))]
                    (if (and acct (< spendable amount))
                      {:state state :response {"ok" false "error" "insufficient-balance"} :net-envelopes [] :stdout-events []}
                      (let [raw-eid (or (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                                        (:escrow_id cmd-map) (:escrow-id cmd-map))
                            nonce (str (inc (long (count (:escrows state {})))))
                            escrow-id (or (when (and (string? raw-eid) (not (str/blank? raw-eid))) raw-eid)
                                          (escrow/compute-escrow-id (:pubkey state) receiver-pub amount deliverable-hash curr-ep expires-epoch nonce))
                            intent-payload {:type :lock-intent
                                            :escrow-id escrow-id
                                            :payer (:pubkey state)
                                            :receiver receiver-pub
                                            :amount amount
                                            :deliverable-hash deliverable-hash
                                            :created-epoch curr-ep
                                            :expires-epoch expires-epoch
                                            :epoch curr-ep
                                            :receipt-id (str "lock:" escrow-id)}
                            active-dac (when-let [d (:dac state)]
                                         (when (:ok? (verify-dac d {:expected-agent-pubkey (:pubkey state)
                                                                    :current-epoch curr-ep
                                                                    :revoked-dac-ids (:revoked-dacs state)}))
                                           d))
                            envelope (mesh/wrap-agent-event intent-payload (:pubkey state) privkey-bytes active-dac)
                            local-escrow {:escrow-id escrow-id
                                          :payer (:pubkey state)
                                          :receiver receiver-pub
                                          :amount amount
                                          :deliverable-hash deliverable-hash
                                          :created-epoch curr-ep
                                          :expires-epoch expires-epoch
                                          :status :locked}
                            new-state (cond-> (-> state
                                                  (assoc-in [:escrows escrow-id] local-escrow)
                                                  (assoc :dac-spend (:new-dac-spend dac-auth)))
                                        acct (update-in [:account :spendable] - amount))]
                        {:state new-state
                         :response (cond-> {"ok" true
                                            "escrow_id" escrow-id
                                            "payer" (:pubkey state)
                                            "receiver" receiver-pub
                                            "amount" amount
                                            "deliverable_hash" deliverable-hash
                                            "expires_epoch" expires-epoch
                                            "status" "locked"}
                                     pname (assoc "receiver_petname" pname))
                         :net-envelopes [envelope]
                         :stdout-events []}))))))))))))

(defn- exec-release-intent [state cmd-map privkey-bytes]
  (let [escrow-id (or (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                      (:escrow_id cmd-map) (:escrow-id cmd-map))]
    (if (or (nil? escrow-id) (and (string? escrow-id) (str/blank? escrow-id)))
      {:state state :response {"ok" false "error" "missing-escrow-id"} :net-envelopes [] :stdout-events []}
      (let [preimage (or (get cmd-map "preimage") (:preimage cmd-map)
                         (get cmd-map "deliverable") (:deliverable cmd-map))
            payer-sig (or (get cmd-map "payer_signature") (get cmd-map "payer-signature")
                          (:payer_signature cmd-map) (:payer-signature cmd-map))
            local-escrow (get-in state [:escrows escrow-id])
            d-hash (or (when local-escrow (:deliverable-hash local-escrow))
                       (get cmd-map "deliverable_hash") (get cmd-map "deliverable-hash")
                       (:deliverable_hash cmd-map) (:deliverable-hash cmd-map))
            final-sig (or payer-sig
                          (when (and (= (:pubkey state) (when local-escrow (:payer local-escrow)))
                                     (string? d-hash))
                            (escrow/sign-escrow-release privkey-bytes escrow-id d-hash)))
            release-payload (cond-> {:type :release-intent
                                     :escrow-id escrow-id
                                     :epoch (effective-chain-epoch state)
                                     :receipt-id (str "release:" escrow-id)}
                              preimage (assoc :preimage preimage)
                              final-sig (assoc :payer-signature final-sig))
            envelope (mesh/wrap-agent-event release-payload (:pubkey state) privkey-bytes)
            new-state (if local-escrow
                        (assoc-in state [:escrows escrow-id :status] :release-submitted)
                        state)]
        {:state new-state
         :response {"ok" true "escrow_id" escrow-id "status" "release-submitted"}
         :net-envelopes [envelope]
         :stdout-events []}))))

(defn- exec-refund-intent [state cmd-map privkey-bytes]
  (let [escrow-id (or (get cmd-map "escrow_id") (get cmd-map "escrow-id")
                      (:escrow_id cmd-map) (:escrow-id cmd-map))]
    (if (or (nil? escrow-id) (and (string? escrow-id) (str/blank? escrow-id)))
      {:state state :response {"ok" false "error" "missing-escrow-id"} :net-envelopes [] :stdout-events []}
      (let [refund-payload {:type :refund-intent
                            :escrow-id escrow-id
                            :epoch (effective-chain-epoch state)
                            :receipt-id (str "refund:" escrow-id)}
            envelope (mesh/wrap-agent-event refund-payload (:pubkey state) privkey-bytes)
            local-escrow (get-in state [:escrows escrow-id])
            new-state (if local-escrow
                        (assoc-in state [:escrows escrow-id :status] :refund-submitted)
                        state)]
        {:state new-state
         :response {"ok" true "escrow_id" escrow-id "status" "refund-submitted"}
         :net-envelopes [envelope]
         :stdout-events []}))))

(defn- exec-escrows
  ([state]
   (exec-escrows state {}))
  ([state cmd-map]
   (let [raw-snapshots (or (get cmd-map "snapshots") (:snapshots cmd-map)
                           (when-let [s (or (get cmd-map "snapshot") (:snapshot cmd-map))]
                             [s]))]
     (if raw-snapshots
       (let [sync-res (exec-sync-account state cmd-map)]
         (if (get-in sync-res [:response "ok"])
           (exec-escrows (:state sync-res) (dissoc cmd-map "snapshots" :snapshots "snapshot" :snapshot))
           sync-res))
       (let [enriched (mapv (fn [[eid esc]]
                              (let [payer (:payer esc)
                                    receiver (:receiver esc)
                                    payer-pname (when payer (pubkey->petname state payer))
                                    recv-pname (when receiver (pubkey->petname state receiver))
                                    status-str (name (or (:status esc) :locked))]
                                (cond-> (assoc esc
                                               :escrow_id eid
                                               :escrow-id eid
                                               :status status-str)
                                  (:settled-epoch esc) (assoc :settled_epoch (:settled-epoch esc))
                                  (:net-amount esc) (assoc :net_amount (:net-amount esc))
                                  (:refund-reason esc) (assoc :refund_reason (:refund-reason esc))
                                  payer-pname (assoc :payer_petname payer-pname)
                                  recv-pname (assoc :receiver_petname recv-pname))))
                            (vec (:escrows state {})))]
         {:state state
          :response {"ok" true "escrows" enriched}
          :net-envelopes []
          :stdout-events []})))))

(defn- exec-submit-vouchers [state cmd-map privkey-bytes]
  (let [raw-vouchers (or (get cmd-map "vouchers")
                         (:vouchers cmd-map)
                         (:vouchers state)
                         [])
        compacted (->> raw-vouchers
                       (keep (fn [raw]
                               (let [ack-map (if (instance? bitecho.rendezvous.core.DeliveryAck raw)
                                               (into {} raw)
                                               {:callee (or (get raw "callee") (:callee raw))
                                                :home-node (or (get raw "home_node") (get raw "home-node") (:home-node raw))
                                                :epoch (long (or (get raw "epoch") (:epoch raw) 0))
                                                :offer-hash (or (get raw "offer_hash") (get raw "offer-hash") (:offer-hash raw))
                                                :seq (long (or (get raw "seq") (:seq raw) 0))
                                                :cumulative-debit (long (or (get raw "cumulative_debit") (get raw "cumulative-debit") (:cumulative-debit raw) 0))
                                                :signature (or (get raw "signature") (:signature raw))})
                                     ack (try (rendezvous/map->DeliveryAck ack-map) (catch Exception _ nil))]
                                 (when (and ack (rendezvous/verify-delivery-ack ack))
                                   ack))))
                       bundle/compact-vouchers)]
    (if (empty? compacted)
      {:state state
       :response {"ok" false "error" "no-valid-vouchers"}
       :net-envelopes []
       :stdout-events []}
      (let [voucher-env (mesh/wrap-agent-event
                         {:type :submit-vouchers
                          :vouchers (mapv #(into {} %) compacted)
                          :epoch (effective-chain-epoch state)}
                         (:pubkey state)
                         privkey-bytes)
            new-state (assoc state :vouchers [])]
        {:state new-state
         :response {"ok" true "submitted_count" (count compacted)}
         :net-envelopes [voucher-env]
         :stdout-events []}))))

(defn- exec-petname-set [state cmd-map]
  (let [raw-pname (or (get cmd-map "petname") (get cmd-map "name")
                      (:petname cmd-map) (:name cmd-map))
        raw-pub (or (get cmd-map "pubkey") (:pubkey cmd-map))
        pname (normalize-petname raw-pname)
        pub (normalize-pubkey-hex raw-pub)
        ov (if (contains? cmd-map "overwrite")
             (get cmd-map "overwrite")
             (:overwrite cmd-map))
        overwrite? (boolean (or (true? ov)
                                (and (string? ov) (= "true" (str/lower-case (str/trim ov))))))]
    (cond
      (nil? pname)
      {:state state
       :response {"ok" false "error" "invalid-petname"}
       :net-envelopes []
       :stdout-events []}

      (nil? pub)
      {:state state
       :response {"ok" false "error" "invalid-pubkey"}
       :net-envelopes []
       :stdout-events []}

      :else
      (let [existing-pub (get-in state [:petnames pname])
            existing-pname (pubkey->petname state pub)]
        (cond
          ;; Idempotent: already bound to the same pubkey
          (= existing-pub pub)
          {:state state
           :response {"ok" true "petname" pname "pubkey" pub}
           :net-envelopes []
           :stdout-events []}

          ;; Conflict without overwrite
          (and (not overwrite?) (or (some? existing-pub) (some? existing-pname)))
          {:state state
           :response (cond-> {"ok" false "error" "petname-conflict"}
                       existing-pub (assoc "existing_pubkey" existing-pub)
                       existing-pname (assoc "existing_petname" existing-pname))
           :net-envelopes []
           :stdout-events []}

          ;; Valid set or overwrite: clean old bindings and set new 1:1 binding
          :else
          (let [clean-petnames (cond-> (:petnames state {})
                                 existing-pname (dissoc existing-pname))
                new-petnames (assoc clean-petnames pname pub)
                new-state (assoc state :petnames new-petnames)]
            {:state new-state
             :response {"ok" true "petname" pname "pubkey" pub}
             :net-envelopes []
             :stdout-events []}))))))

(defn- exec-petname-list [state]
  {:state state
   :response {"ok" true
              "petnames" (into (sorted-map) (:petnames state {}))
              "count" (count (:petnames state {}))}
   :net-envelopes []
   :stdout-events []})

(defn- exec-petname-remove [state cmd-map]
  (let [raw-pname (or (get cmd-map "petname") (get cmd-map "name")
                      (:petname cmd-map) (:name cmd-map))
        raw-pub (or (get cmd-map "pubkey") (:pubkey cmd-map))
        pname (or (when raw-pname (normalize-petname raw-pname))
                  (when raw-pub (pubkey->petname state raw-pub)))
        pub (when pname (get-in state [:petnames pname]))]
    (if (and pname pub)
      (let [new-state (update state :petnames dissoc pname)]
        {:state new-state
         :response {"ok" true "removed" true "petname" pname "pubkey" pub}
         :net-envelopes []
         :stdout-events []})
      {:state state
       :response {"ok" false "error" "petname-not-found"}
       :net-envelopes []
       :stdout-events []})))

(defn- exec-petname-resolve [state cmd-map]
  (let [raw-pname (or (get cmd-map "petname") (get cmd-map "name")
                      (:petname cmd-map) (:name cmd-map))
        raw-pub (or (get cmd-map "pubkey") (:pubkey cmd-map))
        raw-tgt (or (get cmd-map "target") (:target cmd-map))
        resolved (cond
                   raw-pname
                   (when-let [pname (normalize-petname raw-pname)]
                     (when-let [pub (get-in state [:petnames pname])]
                       {:petname pname :pubkey pub}))

                   raw-pub
                   (when-let [pub (normalize-pubkey-hex raw-pub)]
                     (when-let [pname (pubkey->petname state pub)]
                       {:petname pname :pubkey pub}))

                   raw-tgt
                   (let [res (resolve-counterparty state raw-tgt)]
                     (when (and (:ok? res) (:petname res))
                       {:petname (:petname res) :pubkey (:pubkey res)}))

                   :else nil)]
    (if resolved
      {:state state
       :response {"ok" true "petname" (:petname resolved) "pubkey" (:pubkey resolved)}
       :net-envelopes []
       :stdout-events []}
      {:state state
       :response {"ok" false "error" "petname-not-found"}
       :net-envelopes []
       :stdout-events []})))

(defn- exec-dac-attach [state cmd-map]
  (let [raw-dac (or (get cmd-map "dac") (:dac cmd-map) cmd-map)
        cur-ep (when (:epoch-initialized? state) (:epoch state))
        res (verify-dac raw-dac {:expected-agent-pubkey (:pubkey state)
                                 :current-epoch cur-ep
                                 :revoked-dac-ids (:revoked-dacs state)})]
    (if-not (:ok? res)
      {:state state
       :response {"ok" false "error" (:error res)}
       :net-envelopes []
       :stdout-events []}
      (let [dac (:dac res)]
        {:state (assoc state :dac dac)
         :response {"ok" true
                    "dac_id" (:dac-id res)
                    "anchor_pubkey" (:anchor-pubkey res)
                    "agent_pubkey" (:agent-pubkey res)
                    "expires_epoch" (long (or (:expires-epoch dac) (get dac "expires_epoch") 0))}
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-dac-revoke [state cmd-map]
  (let [raw-rev (or (get cmd-map "revocation") (:revocation cmd-map) cmd-map)]
    (if-not (verify-dac-revocation raw-rev)
      {:state state
       :response {"ok" false "error" "invalid-dac-revocation"}
       :net-envelopes []
       :stdout-events []}
      (let [rev-map (normalize-wire-map raw-rev)
            dac-id (:dac-id rev-map)
            new-revoked (conj (set (or (:revoked-dacs state) #{})) dac-id)
            attached-dac (:dac state)
            attached-id (or (:dac-id attached-dac) (get attached-dac "dac_id") (get attached-dac "dac-id"))
            cleared-dac? (= attached-id dac-id)
            new-state (cond-> (assoc state :revoked-dacs new-revoked)
                        cleared-dac? (assoc :dac nil))]
        {:state new-state
         :response {"ok" true "revoked" true "dac_id" dac-id}
         :net-envelopes []
         :stdout-events []}))))

(defn- exec-directory-verify [state cmd-map]
  (let [raw-desc (or (get cmd-map "descriptor") (:descriptor cmd-map) cmd-map)
        dir-pub (or (get cmd-map "directory_pubkey") (get cmd-map "directory-pubkey")
                    (:directory_pubkey cmd-map) (:directory-pubkey cmd-map)
                    (get-in state [:bootstrap :custody-pubkey])
                    (get-in state [:bootstrap :treasury-pubkey]))
        cur-ep (when (:epoch-initialized? state) (:epoch state))
        res (verify-directory-descriptor raw-desc dir-pub cur-ep)]
    (if-not (:ok? res)
      {:state state
       :response {"ok" false "error" (:error res)}
       :net-envelopes []
       :stdout-events []}
      (let [desc-map (:descriptor res)
            nick (:nickname desc-map)
            pub (:pubkey desc-map)
            prev-pub (:prev-pubkey desc-map)
            existing (get-in state [:directory-cache nick])
            existing-pub (when existing (or (:pubkey existing) (get existing "pubkey")))
            norm-pub (normalize-pubkey-hex pub)
            norm-existing (when existing-pub (normalize-pubkey-hex existing-pub))
            norm-prev (when prev-pub (normalize-pubkey-hex prev-pub))]
        (if (and norm-existing
                 (not= norm-existing norm-pub)
                 (or (nil? norm-prev)
                     (not= norm-existing norm-prev)))
          {:state state
           :response {"ok" false "error" "broken-key-continuity"}
           :net-envelopes []
           :stdout-events []}
          (let [new-state (assoc-in state [:directory-cache nick] desc-map)]
            {:state new-state
             :response {"ok" true
                        "nickname" nick
                        "uri" (or (:uri desc-map) (str "bitecho.org/" nick))
                        "pubkey" pub
                        "home_set" (or (:home-set desc-map) [])
                        "directory_pubkey" (:directory-pubkey desc-map)
                        "expires_epoch" (:expires-epoch desc-map)}
             :net-envelopes []
             :stdout-events []}))))))

(defn- exec-status [state]
  (let [sessions-summary (vec (for [[_ s] (:sessions state)
                                    :let [pname (pubkey->petname state (:peer s))]]
                                (cond-> (select-keys s [:session-id :peer :role :state :tx-seq :epoch :acked-seq :rx-high-seq :replays-deduped :outbox-evicted])
                                  true (assoc :unacked-count (count (:outbox s)))
                                  pname (assoc :peer-petname pname :peer_petname pname))))]
    {:state state
     :response (cond-> {"ok" true
                        "connected" (boolean (:connected? state false))
                        "connection_error" (:connection-error state)
                        "pubkey" (:pubkey state)
                        "autonomous" (:autonomous? state)
                        "epoch" (:epoch state)
                        "sessions" sessions-summary
                        "pending_offers_count" (count (:pending-offers state))
                        "pending_rendezvous_count" (count (:pending-rendezvous state {}))
                        "rendezvous_policy" (:rendezvous-policy state)
                        "inbox_count" (count (:inbox state))
                        "account" (:account state)
                        "petnames" (into (sorted-map) (:petnames state {}))
                        "petnames_count" (count (:petnames state {}))
                        "dac" (dac-summary (:dac state))
                        "revoked_dacs_count" (count (:revoked-dacs state #{}))
                        "directory_cache_count" (count (:directory-cache state {}))
                        "escrows_count" (count (:escrows state {}))
                        "accounting" {"scope" "local-non-consensus"
                                      "note" "Locally computed devnet totals; never consensus finalized"
                                      "burned_ech" (get-in state [:local-accounting :burned-ech] 0)
                                      "vouchers_count" (count (:vouchers state []))}}
                 (:conn-diagnostics state) (assoc "diagnostics" (:conn-diagnostics state)))
     :net-envelopes []
     :stdout-events []}))

(defn handle-command
  "Dispatches a parsed JSON command map to its corresponding protocol verb reducer.
   Supports both flat command maps and nested {\"cmd\": ..., \"args\": {...}} maps."
  [state cmd-map privkey-bytes]
  (let [effective-map (if (map? (get cmd-map "args"))
                        (merge (get cmd-map "args") (dissoc cmd-map "args"))
                        cmd-map)]
    (case (or (get effective-map "cmd") (:cmd effective-map))
      "identity" (exec-identity state)
      "discover" (exec-discover state)
      "register-home-set" (exec-register-home-set state effective-map privkey-bytes)
      "offer" (exec-offer state effective-map privkey-bytes)
      "accept" (exec-accept state effective-map privkey-bytes)
      "rendezvous-policy" (exec-rendezvous-policy state effective-map)
      "rendezvous-offer" (exec-rendezvous-offer state effective-map privkey-bytes)
      "rendezvous-accept" (exec-rendezvous-accept state effective-map privkey-bytes)
      "send" (exec-send state effective-map privkey-bytes)
      "inbox" (exec-inbox state)
      "close" (exec-close state effective-map privkey-bytes)
      "transfer" (exec-transfer state effective-map privkey-bytes)
      "account" (exec-sync-account state effective-map)
      "sync-account" (exec-sync-account state effective-map)
      "settle-intent" (exec-settle-intent state effective-map privkey-bytes)
      "lock-intent" (exec-lock-intent state effective-map privkey-bytes)
      "release-intent" (exec-release-intent state effective-map privkey-bytes)
      "refund-intent" (exec-refund-intent state effective-map privkey-bytes)
      "escrows" (exec-escrows state effective-map)
      "query-chain-state" (let [env (build-chain-state-query-envelope (:pubkey state) privkey-bytes effective-map)]
                            {:state state
                             :response {"ok" true "query_sent" true}
                             :net-envelopes [env]
                             :stdout-events []})
      "submit-vouchers" (exec-submit-vouchers state effective-map privkey-bytes)
      "petname-set" (exec-petname-set state effective-map)
      "petname-list" (exec-petname-list state)
      "petname-remove" (exec-petname-remove state effective-map)
      "petname-resolve" (exec-petname-resolve state effective-map)
      "dac-attach" (exec-dac-attach state effective-map)
      "dac-revoke" (exec-dac-revoke state effective-map)
      "directory-verify" (exec-directory-verify state effective-map)
      "status" (exec-status state)
      {:state state :response {"ok" false "error" "unknown-command"} :net-envelopes [] :stdout-events []})))

;; -----------------------------------------------------------------------------
;; Inbound Wire Payload Handlers (Pure Helpers)
;; -----------------------------------------------------------------------------

(defn- unwrap-wire-message [raw-payload-or-event]
  (cond
    (bytes? raw-payload-or-event)
    (if-let [thawed (try (nippy/thaw raw-payload-or-event) (catch Exception _ nil))]
      (recur thawed)
      nil)

    (and (map? raw-payload-or-event)
         (contains? raw-payload-or-event :bitecho/type))
    raw-payload-or-event

    (and (map? raw-payload-or-event) (map? (:event raw-payload-or-event)))
    (recur (:event raw-payload-or-event))

    (and (map? raw-payload-or-event) (map? (:message raw-payload-or-event)))
    (let [p (:payload (:message raw-payload-or-event))]
      (if (bytes? p)
        (recur (try (nippy/thaw p) (catch Exception _ nil)))
        (if (map? p) (recur p) nil)))

    (and (map? raw-payload-or-event)
         (contains? raw-payload-or-event :type))
    raw-payload-or-event

    :else nil))

(defn- handle-wire-offer [state msg privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:caller msg)) (valid-pubkey-hex? (:caller msg))
                 (string? (:callee msg)) (valid-pubkey-hex? (:callee msg))
                 (string? (:session-id msg)) (not (str/blank? (:session-id msg)))
                 (string? (:caller-ephemeral-pub msg)) (not (str/blank? (:caller-ephemeral-pub msg)))
                 (string? (:offer-hash msg)) (not (str/blank? (:offer-hash msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (integer? (:epoch msg))
                 (or (nil? (:burn msg)) (integer? (:burn msg)))
                 (or (nil? (:price msg)) (integer? (:price msg)))
                 (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:pubkey state))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [caller-pub (try (basalt/hex->bytes (:caller msg)) (catch Exception _ nil))
            sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
            expected-sid (compute-session-id (:caller msg) (:callee msg) (:caller-ephemeral-pub msg))
            expected-hash-legacy (compute-offer-hash msg)
            expected-hash-sealed (sealed/offer-hash msg)
            wire-dac (or (:dac msg) (get msg "dac"))
            dac-id (or (:dac-id msg) (get msg "dac_id")
                       (when wire-dac (or (:dac-id wire-dac) (get wire-dac "dac_id") (get wire-dac "dac-id"))))
            burn-num (parse-long-safe (or (:price msg) (:burn msg)) 0)
            epoch-num (parse-long-safe (:epoch msg) 0)
            expected-hash-5field (basalt/bytes->hex (crypto/sha256 (.getBytes ^String (str (:caller msg) "-" (:callee msg) "-" (:caller-ephemeral-pub msg) "-" epoch-num "-" burn-num (when (and (string? dac-id) (not (str/blank? dac-id))) (str "|" dac-id))) "UTF-8")))
            valid-hashes? (and (= (:session-id msg) expected-sid)
                               (or (= (:offer-hash msg) expected-hash-legacy)
                                   (= (:offer-hash msg) expected-hash-sealed)
                                   (= (:offer-hash msg) expected-hash-5field)))
            valid-sig? (and valid-hashes?
                            caller-pub sig-bytes
                            (crypto/verify caller-pub (.getBytes ^String (:offer-hash msg) "UTF-8") sig-bytes))
            ref-epoch (:epoch state)
            wire-dac (or (:dac msg) (get msg "dac"))
            dac-check (when wire-dac
                        (verify-dac wire-dac {:expected-agent-pubkey (:caller msg)
                                              :current-epoch ref-epoch
                                              :revoked-dac-ids (:revoked-dacs state)
                                              :required-scope "offer"}))]
        (if (or (not valid-sig?)
                (and wire-dac (not (:ok? dac-check))))
          {:state state :net-envelopes [] :stdout-events []}
          (let [sid (:session-id msg)
                clean-offer (cond-> (select-keys msg [:bitecho/type :session-id :caller :callee :caller-ephemeral-pub :epoch :price :home-node :offer-hash :burn :signature])
                              (and wire-dac (:ok? dac-check)) (assoc :dac (:dac dac-check)))]
            (cond
              (contains? (:sessions state) sid)
              (let [new-state (update-in state [:sessions sid :replays-deduped] (fnil inc 0))]
                {:state new-state :net-envelopes [] :stdout-events []})

              (contains? (:pending-offers state) sid)
              {:state state :net-envelopes [] :stdout-events []}

              (:autonomous? state)
              (let [accept-res (exec-accept (assoc-in state [:pending-offers sid] clean-offer)
                                            {"session_id" sid}
                                            privkey-bytes)]
                {:state (:state accept-res)
                 :net-envelopes (:net-envelopes accept-res)
                 :stdout-events (:stdout-events accept-res)})

              :else
              (let [caller-pname (pubkey->petname state (:caller clean-offer))
                    offer-dac (:dac clean-offer)
                    dac-anchor (when offer-dac (or (:anchor-pubkey offer-dac) (get offer-dac "anchor_pubkey")))
                    dac-id (when offer-dac (or (:dac-id offer-dac) (get offer-dac "dac_id")))
                    event (cond-> {"event" "offer-received"
                                   "session_id" sid
                                   "caller" (:caller clean-offer)
                                   "price" (:price clean-offer)}
                            caller-pname (assoc "caller_petname" caller-pname)
                            dac-anchor (assoc "anchor_pubkey" dac-anchor)
                            dac-id (assoc "dac_id" dac-id))]
                {:state (assoc-in state [:pending-offers sid] clean-offer)
                 :net-envelopes []
                 :stdout-events [event]}))))))
    (catch Exception _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-accept [state msg]
  (try
    (if-not (and (map? msg)
                 (string? (:caller msg)) (= (normalize-pubkey-hex (:caller msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:callee msg)) (valid-pubkey-hex? (:callee msg))
                 (string? (:session-id msg)) (not (str/blank? (:session-id msg)))
                 (string? (:callee-ephemeral-pub msg)) (not (str/blank? (:callee-ephemeral-pub msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (map? (:delivery-ack msg))
                 (or (nil? (:epoch msg)) (integer? (:epoch msg))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [session-id (:session-id msg)
            session (get-in state [:sessions session-id])]
        (cond
          (and session (= "open" (:state session)))
          {:state (update-in state [:sessions session-id :replays-deduped] (fnil inc 0))
           :net-envelopes []
           :stdout-events []}

          (not (and session (= "offered" (:state session))))
          {:state state :net-envelopes [] :stdout-events []}

          :else
          (let [callee-pub (try (basalt/hex->bytes (:callee msg)) (catch Exception _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
                valid-ack? (rendezvous/verify-delivery-ack (:delivery-ack msg) (:callee msg))
                valid-sig? (and callee-pub sig-bytes
                                (crypto/verify callee-pub
                                               (.getBytes (str session-id "-" (:callee-ephemeral-pub msg)) "UTF-8")
                                               sig-bytes))]
            (if-not (and valid-ack? valid-sig?)
              {:state state :net-envelopes [] :stdout-events []}
              (let [callee-eph (try (basalt/hex->bytes (:callee-ephemeral-pub msg)) (catch Exception _ nil))
                    shared-sec (when callee-eph (sealed/x25519-shared-secret (:ephemeral-priv session) callee-eph))]
                (if-not shared-sec
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [keys (sealed/derive-channel-keys shared-sec session-id :initiator)
                        updated-sess (-> session
                                         (assoc :state "open"
                                                :tx-seq 0
                                                :acked-seq 0
                                                :rx-high-seq 0
                                                :contiguous-rx-seq 0
                                                :replays-deduped 0
                                                :outbox-evicted 0
                                                :outbox {}
                                                :outbox-order []
                                                :tx-key (:tx-key keys)
                                                :rx-key (:rx-key keys)
                                                :replay-window (sealed/init-replay-window))
                                         (dissoc :ephemeral-priv))
                        new-state (-> state
                                      (assoc-in [:sessions session-id] updated-sess)
                                      (update :vouchers (fnil conj []) (:delivery-ack msg)))
                        callee-pname (pubkey->petname state (:callee msg))
                        event (cond-> {"event" "channel-opened" "session_id" session-id "peer" (:callee msg)}
                                callee-pname (assoc "peer_petname" callee-pname))]
                    {:state new-state
                     :net-envelopes []
                     :stdout-events [event]}))))))))
    (catch Exception _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- advance-contiguous-rx-seq
  "Advances the contiguous received sequence number starting from contiguous-seq
   as long as contiguous-seq + 1 is present in seen-set or past the window horizon."
  [contiguous-seq seen-set ^long highest-seq]
  (let [window-size 64
        horizon (- highest-seq window-size)]
    (loop [curr (long (or contiguous-seq 0))]
      (let [next-seq (inc curr)]
        (cond
          (contains? seen-set next-seq) (recur next-seq)
          (and (pos? horizon) (<= next-seq horizon)) (recur next-seq)
          :else curr)))))

(defn build-session-ack-envelope
  "Builds and signs a :session-ack envelope wrapping Ed25519 signature."
  ([state session-id peer-pub contiguous-ack-seq msg-seq privkey-bytes]
   (build-session-ack-envelope state session-id peer-pub contiguous-ack-seq msg-seq nil privkey-bytes))
  ([state session-id peer-pub contiguous-ack-seq msg-seq seen-seqs privkey-bytes]
   (when privkey-bytes
     (let [seen-vec (vec (sort (or seen-seqs [])))
           ack-sign-bytes (.getBytes (str "ack-" session-id "-" contiguous-ack-seq "-" msg-seq "-" (str/join "," seen-vec)) "UTF-8")
           sig (crypto/sign privkey-bytes ack-sign-bytes)
           sig-hex (if (string? sig) sig (basalt/bytes->hex sig))
           ack-payload {:bitecho/type :session-ack
                        :session-id session-id
                        :sender (:pubkey state)
                        :recipient peer-pub
                        :epoch (long (or (get-in state [:sessions session-id :epoch]) (:epoch state) 0))
                        :ack-seq contiguous-ack-seq
                        :acked-seq msg-seq
                        :seen-seqs seen-vec
                        :signature sig-hex}]
       (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze ack-payload) 100)))))

(defn- handle-wire-sealed-msg [state msg privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:recipient msg)) (= (normalize-pubkey-hex (:recipient msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:session-id msg))
                 (integer? (:seq msg))
                 (string? (:nonce msg))
                 (string? (:ciphertext msg)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [session-id (:session-id msg)
            session (get-in state [:sessions session-id])]
        (if-not (and session (= "open" (:state session)))
          {:state state :net-envelopes [] :stdout-events []}
          (let [chk (sealed/check-and-advance-replay-window (:replay-window session) (:seq msg))]
            (cond
              (:accepted? chk)
              (let [ct (try (basalt/hex->bytes (:ciphertext msg)) (catch Exception _ nil))
                    decrypted (when ct (sealed/open-message (:rx-key session) (:seq msg) ct (.getBytes session-id "UTF-8")))]
                (if-not decrypted
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [new-rx-high-seq (max (long (:rx-high-seq session 0)) (long (:seq msg)))
                        new-contiguous (advance-contiguous-rx-seq (:contiguous-rx-seq session 0)
                                                                  (:seen (:window chk))
                                                                  (:highest-seq (:window chk) 0))
                        seen-seqs (vec (sort (:seen (:window chk))))
                        ack-env (build-session-ack-envelope state session-id (:sender msg) new-contiguous (:seq msg) seen-seqs privkey-bytes)
                        text (try (String. ^bytes decrypted "UTF-8") (catch Exception _ nil))
                        sender-pname (pubkey->petname state (:sender msg))
                        inbox-item {:session-id session-id
                                    :session_id session-id
                                    :from (:sender msg)
                                    :seq (:seq msg)
                                    :text text
                                    :payload-hex (basalt/bytes->hex decrypted)
                                    :payload_hex (basalt/bytes->hex decrypted)}
                        updated-sess (assoc session
                                            :replay-window (:window chk)
                                            :rx-high-seq new-rx-high-seq
                                            :contiguous-rx-seq new-contiguous)
                        new-state (-> state
                                      (assoc-in [:sessions session-id] updated-sess)
                                      (update :inbox (fnil conj []) inbox-item))
                        event (cond-> {"event" "message-received"
                                       "session_id" session-id
                                       "from" (:sender msg)
                                       "seq" (:seq msg)}
                                text (assoc "text" text)
                                sender-pname (assoc "from_petname" sender-pname))]
                    {:state new-state
                     :net-envelopes (if ack-env [ack-env] [])
                     :stdout-events [event]})))

              (= :replayed-seq (:error chk))
              (let [ct (try (basalt/hex->bytes (:ciphertext msg)) (catch Exception _ nil))
                    decrypted (when ct (sealed/open-message (:rx-key session) (:seq msg) ct (.getBytes session-id "UTF-8")))]
                (if-not decrypted
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [contig (:contiguous-rx-seq session 0)
                        seen-seqs (vec (sort (:seen (:replay-window session))))
                        ack-env (build-session-ack-envelope state session-id (:sender msg) contig (:seq msg) seen-seqs privkey-bytes)
                        new-state (update-in state [:sessions session-id :replays-deduped] (fnil inc 0))]
                    {:state new-state
                     :net-envelopes (if ack-env [ack-env] [])
                     :stdout-events []})))

              :else
              {:state state :net-envelopes [] :stdout-events []})))))
    (catch Exception _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-session-ack [state msg]
  (try
    (if-not (and (map? msg)
                 (string? (:recipient msg)) (= (normalize-pubkey-hex (:recipient msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:session-id msg))
                 (string? (:signature msg))
                 (integer? (:ack-seq msg))
                 (integer? (:acked-seq msg))
                 (coll? (:seen-seqs msg)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [session-id (:session-id msg)
            session (get-in state [:sessions session-id])]
        (if-not (and session
                     (= "open" (:state session))
                     (= (:sender msg) (:peer session)))
          {:state state :net-envelopes [] :stdout-events []}
          (let [peer-pub (try (basalt/hex->bytes (:peer session)) (catch Exception _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
                ack-seq (long (or (:ack-seq msg) 0))
                acked-seq (long (or (:acked-seq msg) 0))
                seen-vec (vec (sort (or (:seen-seqs msg) [])))
                canonical-bytes (.getBytes (str "ack-" session-id "-" ack-seq "-" acked-seq "-" (str/join "," seen-vec)) "UTF-8")
                valid-sig? (and peer-pub sig-bytes
                                (crypto/verify peer-pub canonical-bytes sig-bytes))]
            (if-not valid-sig?
              {:state state :net-envelopes [] :stdout-events []}
              (let [new-acked-seq (max (long (:acked-seq session 0)) ack-seq)
                    curr-outbox (or (:outbox session) {})
                    curr-order (or (:outbox-order session) [])
                    seen-set (set (map long seen-vec))
                    acked? (fn [s] (or (<= (long s) ack-seq) (= (long s) acked-seq) (contains? seen-set (long s))))
                    purged-outbox (reduce-kv (fn [m s item]
                                               (if (acked? s)
                                                 m
                                                 (assoc m s item)))
                                             {}
                                             curr-outbox)
                    purged-order (filterv #(not (acked? %)) curr-order)
                    updated-sess (assoc session
                                        :acked-seq new-acked-seq
                                        :outbox purged-outbox
                                        :outbox-order purged-order)
                    new-state (assoc-in state [:sessions session-id] updated-sess)]
                {:state new-state
                 :net-envelopes []
                 :stdout-events []}))))))
    (catch Exception _
      {:state state :net-envelopes [] :stdout-events []})))

(defn build-unacked-replay-envelopes
  "Extracts unacknowledged session outbox messages and returns signed gossip envelopes
   for failover/reconnect replay, reusing existing signed gossip envelopes to preserve
   message-id deduplication and prevent double-burn."
  ([state privkey-bytes]
   (build-unacked-replay-envelopes state privkey-bytes nil))
  ([state privkey-bytes session-id-filter]
   (if-not privkey-bytes
     []
     (let [sessions (into (sorted-map)
                          (filter (fn [[sid s]]
                                    (and (= "open" (:state s))
                                         (or (nil? session-id-filter)
                                             (= sid session-id-filter))))
                                  (:sessions state)))]
       (vec
        (for [[_ sess] sessions
              seq-num (or (seq (:outbox-order sess)) (sort (keys (or (:outbox sess) {}))))
              :let [item (get-in sess [:outbox seq-num])]
              :when item
              :let [env (:gossip-env item)]]
          (if env
            env
            (let [msg (:msg-payload item)
                  burn (or (:burn item) 500)]
              (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze msg) burn)))))))))

(defn- handle-wire-close [state msg]
  (try
    (if-not (and (map? msg)
                 (string? (:session-id msg)) (not (str/blank? (:session-id msg)))
                 (string? (:sender msg)) (valid-pubkey-hex? (:sender msg))
                 (string? (:signature msg)) (not (str/blank? (:signature msg))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [session-id (:session-id msg)
            session (get-in state [:sessions session-id])]
        (if-not (and session (not= "closed" (:state session)))
          {:state state :net-envelopes [] :stdout-events []}
          (let [sender-pub (try (basalt/hex->bytes (:sender msg)) (catch Exception _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
                valid-sig? (and sender-pub sig-bytes
                                (crypto/verify sender-pub (.getBytes (str "close-" session-id) "UTF-8") sig-bytes))]
            (if-not valid-sig?
              {:state state :net-envelopes [] :stdout-events []}
              (let [closed-sess (-> session
                                    (assoc :state "closed")
                                    (dissoc :tx-key :rx-key :ephemeral-priv))
                    new-state (assoc-in state [:sessions session-id] closed-sess)
                    peer-pname (pubkey->petname state (:sender msg))
                    event (cond-> {"event" "channel-closed" "session_id" session-id "peer" (:sender msg)}
                            peer-pname (assoc "peer_petname" peer-pname))]
                {:state new-state
                 :net-envelopes []
                 :stdout-events [event]}))))))
    (catch Exception _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-rendezvous-header
  "Callee receives Phase 1 :rendezvous-offer-header wire payload.
   Evaluates callee policy (min-burn, allowlist) and either auto-accepts or buffers in :pending-rendezvous."
  [state msg privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:caller msg)) (valid-pubkey-hex? (:caller msg))
                 (string? (:callee msg)) (valid-pubkey-hex? (:callee msg))
                 (string? (:offer-hash msg)) (not (str/blank? (:offer-hash msg)))
                 (string? (:home-node msg)) (not (str/blank? (:home-node msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (integer? (:epoch msg))
                 (integer? (:burn msg))
                 (>= (long (:burn msg)) 0)
                 (or (nil? (:topic msg)) (string? (:topic msg)))
                 (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:pubkey state))))
      {:state state :net-envelopes [] :stdout-events []}
      (let [caller (:caller msg)
            callee (:callee msg)
            offer-hash (:offer-hash msg)
            epoch (long (:epoch msg))
            burn (long (:burn msg))
            topic (str (or (:topic msg) ""))
            home-node (:home-node msg)
            wire-dac (or (:dac msg) (get msg "dac"))
            dac-check (when wire-dac
                        (verify-dac wire-dac {:expected-agent-pubkey caller
                                              :current-epoch (:epoch state)
                                              :revoked-dac-ids (:revoked-dacs state)}))]
        (if (and wire-dac (not (:ok? dac-check)))
          {:state state :net-envelopes [] :stdout-events []}
          (let [dac-id (when (and wire-dac (:ok? dac-check))
                         (or (:dac-id (:dac dac-check)) (get (:dac dac-check) "dac_id")))
                header-str (canonical-rendezvous-header-str caller callee offer-hash epoch burn topic home-node dac-id)
                caller-pub (try (basalt/hex->bytes caller) (catch Exception _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
                valid-sig? (and caller-pub sig-bytes
                                (crypto/verify caller-pub (.getBytes header-str "UTF-8") sig-bytes))]
            (if-not valid-sig?
              {:state state :net-envelopes [] :stdout-events []}
              (let [pol (or (:rendezvous-policy state)
                            {:auto-accept? false :min-burn 0 :price 10 :allowlist #{} :home-node "default-home"})
                    min-burn (long (or (:min-burn pol) 0))
                    allowlist (or (:allowlist pol) #{})
                    rejected-allowlist? (and (seq allowlist) (not (contains? (set allowlist) caller)))
                    rejected-burn? (< burn min-burn)]
                (if (or rejected-allowlist? rejected-burn?)
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [clean-header (cond-> (select-keys msg [:bitecho/type :type :caller :callee :offer-hash :epoch :burn :topic :home-node :signature])
                                       (and wire-dac (:ok? dac-check)) (assoc :dac (:dac dac-check)))
                        caller-pname (pubkey->petname state caller)
                        header-evt (cond-> {"event" "rendezvous-header-received"
                                            "offer_hash" offer-hash
                                            "from" caller
                                            "burn" burn
                                            "topic" topic}
                                     caller-pname (assoc "from_petname" caller-pname))]
                    (if (or (:auto-accept? pol) (:autonomous? state))
                      (let [ack-res (callee-issue-rendezvous-ack state clean-header privkey-bytes)]
                        {:state (:state ack-res)
                         :net-envelopes (:net-envelopes ack-res)
                         :stdout-events [header-evt]})
                      {:state (assoc-in state [:pending-rendezvous offer-hash] clean-header)
                       :net-envelopes []
                       :stdout-events [header-evt]})))))))))
    (catch Exception _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-rendezvous-ack
  "Caller receives Phase 1b :rendezvous-ack-voucher wire payload.
   Verifies callee DeliveryAck voucher, derives session keys, establishes active sealed session,
   and emits Phase 2 :rendezvous-reveal (plus any queued initial message)."
  [state msg privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:caller msg)) (= (normalize-pubkey-hex (:caller msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:callee msg)) (valid-pubkey-hex? (:callee msg))
                 (string? (:offer-hash msg)) (not (str/blank? (:offer-hash msg)))
                 (string? (:callee-x25519 msg)) (not (str/blank? (:callee-x25519 msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (integer? (:epoch msg))
                 (map? (:delivery-ack msg)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [offer-hash (:offer-hash msg)
            outbound (get-in state [:outbound-rendezvous offer-hash])]
        (if-not (and outbound
                     (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:callee outbound))))
          {:state state :net-envelopes [] :stdout-events []}
          (let [ack (:delivery-ack msg)
                ack-valid? (and (map? ack)
                                (= (:offer-hash ack) offer-hash)
                                (= (normalize-pubkey-hex (:callee ack)) (normalize-pubkey-hex (:callee msg)))
                                (rendezvous/verify-delivery-ack ack (:callee msg)))
                ack-sig (str (or (:signature ack) (get ack "signature") ""))
                callee-x25519 (:callee-x25519 msg)
                epoch (long (:epoch msg))
                ack-str (canonical-rendezvous-ack-str (:caller msg) (:callee msg) offer-hash callee-x25519 epoch ack-sig)
                callee-pub (try (basalt/hex->bytes (:callee msg)) (catch Exception _ nil))
                sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
                sig-valid? (and callee-pub sig-bytes
                                (crypto/verify callee-pub (.getBytes ack-str "UTF-8") sig-bytes))]
            (if-not (and ack-valid? sig-valid?)
              {:state state :net-envelopes [] :stdout-events []}
              (let [session-id (:session-id outbound)
                    callee-eph (try (basalt/hex->bytes callee-x25519) (catch Exception _ nil))
                    keys (when callee-eph
                           (sealed/derive-session-keys (:caller-x25519-priv outbound) callee-eph
                                                       (:caller outbound) (:callee outbound)
                                                       offer-hash :initiator))]
                (if-not keys
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [reveal-str (canonical-rendezvous-reveal-str session-id (:pubkey state) (:callee outbound)
                                                                    offer-hash (:caller-x25519-pub outbound) (:epoch state))
                        reveal-sig (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes reveal-str "UTF-8")))
                        reveal-payload {:bitecho/type :rendezvous-reveal
                                        :type :rendezvous-reveal
                                        :session-id session-id
                                        :caller (:pubkey state)
                                        :callee (:callee outbound)
                                        :offer-hash offer-hash
                                        :caller-x25519 (:caller-x25519-pub outbound)
                                        :epoch (:epoch state)
                                        :signature reveal-sig}
                        reveal-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze reveal-payload) 500)
                        initial-text (:initial-text outbound)
                        [session-with-tx net-envs]
                        (if (and initial-text (not (str/blank? initial-text)))
                          (let [text-bytes (.getBytes ^String initial-text "UTF-8")
                                seq-num 1
                                sealed-m (sealed/seal-message (:tx-key keys) seq-num text-bytes (.getBytes session-id "UTF-8"))
                                msg-payload {:bitecho/type :sealed-message
                                             :session-id session-id
                                             :sender (:pubkey state)
                                             :recipient (:callee outbound)
                                             :epoch (long (or (:epoch outbound) (:epoch state) 0))
                                             :seq seq-num
                                             :nonce (basalt/bytes->hex (:nonce sealed-m))
                                             :ciphertext (basalt/bytes->hex (:ciphertext sealed-m))}
                                msg-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze msg-payload) 500)]
                            [{:session-id session-id
                              :peer (:callee outbound)
                              :role :initiator
                              :state "open"
                              :tx-seq seq-num
                              :acked-seq 0
                              :rx-high-seq 0
                              :contiguous-rx-seq 0
                              :replays-deduped 0
                              :outbox-evicted 0
                              :outbox {seq-num {:seq seq-num :msg-payload msg-payload :burn 500 :gossip-env msg-env}}
                              :outbox-order [seq-num]
                              :epoch (long (or (:epoch outbound) (:epoch state) 0))
                              :tx-key (:tx-key keys)
                              :rx-key (:rx-key keys)
                              :replay-window (sealed/init-replay-window)}
                             [reveal-env msg-env]])
                          [{:session-id session-id
                            :peer (:callee outbound)
                            :role :initiator
                            :state "open"
                            :tx-seq 0
                            :acked-seq 0
                            :rx-high-seq 0
                            :contiguous-rx-seq 0
                            :replays-deduped 0
                            :outbox-evicted 0
                            :outbox {}
                            :outbox-order []
                            :epoch (long (or (:epoch outbound) (:epoch state) 0))
                            :tx-key (:tx-key keys)
                            :rx-key (:rx-key keys)
                            :replay-window (sealed/init-replay-window)}
                           [reveal-env]])
                        new-state (-> state
                                      (update :outbound-rendezvous dissoc offer-hash)
                                      (assoc-in [:sessions session-id] session-with-tx)
                                      (update :vouchers (fnil conj []) (into {} ack)))
                        callee-pname (pubkey->petname state (:callee outbound))
                        est-evt (cond-> {"event" "rendezvous-session-established"
                                         "session_id" session-id
                                         "peer" (:callee outbound)
                                         "offer_hash" offer-hash}
                                  callee-pname (assoc "peer_petname" callee-pname))]
                    {:state new-state
                     :net-envelopes net-envs
                     :stdout-events [est-evt]}))))))))
    (catch Exception _
      {:state state :net-envelopes [] :stdout-events []})))

(defn- handle-wire-rendezvous-reveal
  "Callee receives Phase 2 :rendezvous-reveal wire payload.
   Verifies commitment binding of :caller-x25519 against Phase 1 offer-hash,
   verifies caller signature, derives matching keys, and establishes active sealed session."
  [state msg _privkey-bytes]
  (try
    (if-not (and (map? msg)
                 (string? (:session-id msg)) (not (str/blank? (:session-id msg)))
                 (string? (:caller msg)) (valid-pubkey-hex? (:caller msg))
                 (string? (:callee msg)) (= (normalize-pubkey-hex (:callee msg)) (normalize-pubkey-hex (:pubkey state)))
                 (string? (:offer-hash msg)) (not (str/blank? (:offer-hash msg)))
                 (string? (:caller-x25519 msg)) (not (str/blank? (:caller-x25519 msg)))
                 (string? (:signature msg)) (not (str/blank? (:signature msg)))
                 (integer? (:epoch msg)))
      {:state state :net-envelopes [] :stdout-events []}
      (let [offer-hash (:offer-hash msg)
            pending (get-in state [:pending-rendezvous-accepts offer-hash])]
        (if-not (and pending
                     (= (normalize-pubkey-hex (:caller msg)) (normalize-pubkey-hex (:caller pending))))
          {:state state :net-envelopes [] :stdout-events []}
          (let [caller (:caller msg)
                callee (:callee msg)
                caller-x25519 (:caller-x25519 msg)
                sid (:session-id msg)
                header (:header pending)
                expected-sid (compute-session-id caller callee caller-x25519)
                expected-offer-hash (compute-offer-hash {:session-id sid
                                                         :caller caller
                                                         :callee callee
                                                         :caller-ephemeral-pub caller-x25519
                                                         :epoch (:epoch header)
                                                         :price (:burn header)
                                                         :burn (:burn header)
                                                         :home-node (:home-node header)
                                                         :dac (:dac header)})
                commitment-valid? (and (= sid expected-sid)
                                       (= offer-hash expected-offer-hash))]
            (if-not commitment-valid?
              {:state state :net-envelopes [] :stdout-events []}
              (let [reveal-str (canonical-rendezvous-reveal-str sid caller callee offer-hash caller-x25519 (long (:epoch msg)))
                    caller-pub (try (basalt/hex->bytes caller) (catch Exception _ nil))
                    sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
                    sig-valid? (and caller-pub sig-bytes
                                    (crypto/verify caller-pub (.getBytes reveal-str "UTF-8") sig-bytes))]
                (if-not sig-valid?
                  {:state state :net-envelopes [] :stdout-events []}
                  (let [caller-eph (try (basalt/hex->bytes caller-x25519) (catch Exception _ nil))
                        keys (when caller-eph
                               (sealed/derive-session-keys (:callee-x25519-priv pending) caller-eph
                                                           caller callee offer-hash :responder))]
                    (if-not keys
                      {:state state :net-envelopes [] :stdout-events []}
                      (let [session-entry {:session-id sid
                                           :peer caller
                                           :role :responder
                                           :state "open"
                                           :tx-seq 0
                                           :acked-seq 0
                                           :rx-high-seq 0
                                           :contiguous-rx-seq 0
                                           :replays-deduped 0
                                           :outbox-evicted 0
                                           :outbox {}
                                           :outbox-order []
                                           :epoch (long (or (:epoch header) (:epoch state) 0))
                                           :tx-key (:tx-key keys)
                                           :rx-key (:rx-key keys)
                                           :replay-window (sealed/init-replay-window)}
                            new-state (-> state
                                          (update :pending-rendezvous-accepts dissoc offer-hash)
                                          (assoc-in [:sessions sid] session-entry))
                            caller-pname (pubkey->petname state caller)
                            est-evt (cond-> {"event" "rendezvous-session-established"
                                             "session_id" sid
                                             "peer" caller
                                             "offer_hash" offer-hash}
                                      caller-pname (assoc "peer_petname" caller-pname))]
                        {:state new-state
                         :net-envelopes []
                         :stdout-events [est-evt]}))))))))))
    (catch Exception _
      {:state state :net-envelopes [] :stdout-events []})))

(defn handle-wire-chain-state-snapshot
  "Handles incoming validator :chain-state-snapshot over wire.
   Verifies against trusted bootstrap validators and min finalized epoch.
   Buffers snapshot in :chain-state-snapshots, prunes stale snapshots, and applies
   ONLY when verified BFT quorum is reached across trusted validators."
  [state msg]
  (let [trusted (set (keep (comp normalize-pubkey-hex :pubkey) (vals (get-in state [:bootstrap :nodes]))))
        min-fin-ep (long (or (get-in state [:account :finalized-epoch]) 0))
        opts {:expected-pubkey (:pubkey state)
              :trusted-validators trusted
              :min-finalized-epoch min-fin-ep}
        v-res (verify-chain-state-snapshot msg opts)]
    (if-not (:ok? v-res)
      {:state state :net-envelopes [] :stdout-events []}
      (let [snap (:snapshot v-res)
            val-pk (:validator-pubkey snap)
            fin-ep (long (or (:finalized-epoch snap) 0))
            existing-snaps (:chain-state-snapshots state {})
            ;; Prune stale snapshots older than (fin-ep - 2)
            fresh-snaps (into {} (filter (fn [[_ s]]
                                           (>= (long (or (:finalized-epoch s) 0)) (- fin-ep 2)))
                                         existing-snaps))
            buffered-snaps (assoc fresh-snaps val-pk snap)
            buffered-state (assoc state :chain-state-snapshots buffered-snaps)
            q-res (verify-chain-state-quorum (vals buffered-snaps) opts)]
        (if (:ok? q-res)
          (let [agreed-snap (:snapshot q-res)
                st-applied (apply-verified-chain-state-snapshot buffered-state agreed-snap)
                stdout-evt {"event" "chain-state-synced"
                            "pubkey" (:pubkey state)
                            "balance" (:balance agreed-snap)
                            "spendable" (:spendable agreed-snap)
                            "seq" (:seq agreed-snap)
                            "finalized_epoch" (:finalized-epoch agreed-snap)
                            "quorum_count" (:quorum-count q-res)
                            "validator" (:validator-pubkey agreed-snap)}]
            {:state st-applied
             :net-envelopes []
             :stdout-events [stdout-evt]})
          {:state buffered-state
           :net-envelopes []
           :stdout-events []})))))

(defn handle-wire-payload
  "Processes an incoming network event or raw payload. Enforces 2-epoch skew tolerance
   and anti-replay protections before dispatching to message-specific reducers."
  [state raw-payload-or-event privkey-bytes]
  (let [msg (unwrap-wire-message raw-payload-or-event)]
    (if-not (map? msg)
      {:state state :net-envelopes [] :stdout-events []}
      (let [msg-type (or (:bitecho/type msg) (:type msg))
            msg-epoch (when (integer? (:epoch msg)) (long (:epoch msg)))
            sess-epoch (when-let [sid (:session-id msg)]
                         (get-in state [:sessions sid :epoch]))
            ref-epoch (if (or (:epoch-initialized? state)
                              (and (integer? (:epoch state)) (pos? (long (:epoch state)))))
                        (:epoch state)
                        (or sess-epoch msg-epoch))
            skew-exceeded? (and (not= msg-type :chain-state-snapshot)
                                msg-epoch ref-epoch
                                (> (Math/abs (- msg-epoch (long ref-epoch))) 2)
                                (or (nil? sess-epoch)
                                    (> (Math/abs (- msg-epoch (long sess-epoch))) 2)))]
        (if skew-exceeded?
          {:state state :net-envelopes [] :stdout-events []}
          (let [res (case msg-type
                      :channel-offer (handle-wire-offer state msg privkey-bytes)
                      :channel-accept (handle-wire-accept state msg)
                      :sealed-message (handle-wire-sealed-msg state msg privkey-bytes)
                      :session-ack (handle-wire-session-ack state msg)
                      :channel-close (handle-wire-close state msg)
                      :rendezvous-offer-header (handle-wire-rendezvous-header state msg privkey-bytes)
                      :rendezvous-ack-voucher (handle-wire-rendezvous-ack state msg privkey-bytes)
                      :rendezvous-reveal (handle-wire-rendezvous-reveal state msg privkey-bytes)
                      :chain-state-snapshot (handle-wire-chain-state-snapshot state msg)
                      {:state state :net-envelopes [] :stdout-events []})]
            (if (and msg-epoch (not (:epoch-initialized? (:state res))))
              (update res :state assoc :epoch msg-epoch :epoch-initialized? true)
              res)))))))

;; -----------------------------------------------------------------------------
;; JSONL Line Processor
;; -----------------------------------------------------------------------------

(defn process-jsonl-line
  "Parses a single JSONL line, executes the command, and returns the updated state and response."
  [state line-str privkey-bytes]
  (let [trimmed (when (string? line-str) (str/trim line-str))]
    (if (or (nil? trimmed) (str/blank? trimmed))
      {:state state :response {"ok" false "error" "empty-line"} :net-envelopes [] :stdout-events []}
      (try
        (let [cmd-map (json/read-str trimmed)]
          (if (and (map? cmd-map) (contains? cmd-map "cmd"))
            (handle-command state cmd-map privkey-bytes)
            {:state state :response {"ok" false "error" "malformed-request"} :net-envelopes [] :stdout-events []}))
        (catch Exception _
          {:state state :response {"ok" false "error" "malformed-request"} :net-envelopes [] :stdout-events []})))))
