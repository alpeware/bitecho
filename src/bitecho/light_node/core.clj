(ns bitecho.light-node.core
  "Pure Sans-IO protocol state reducer for the Bitecho light node.
   Handles command processing, sealed channel establishment, anti-replay,
   epoch skew tolerance, and Wire/JSONL conversions without side effects."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.economy.bundle :as bundle]
            [bitecho.economy.burn :as burn]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.shell.agent-sim :as agent-sim]
            [bitecho.shell.mesh :as mesh]
            [clojure.data.json :as json]
            [clojure.string :as str]
            [taoensso.nippy :as nippy]))

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
   :last-transfer-hash nil})

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

(defn verify-directory-pop
  "Verifies an agent Proof-of-Possession (PoP) map.
   Returns true iff the agent signature verifies under pubkey and (if key rotation)
   the rotation signature verifies under prev-pubkey."
  [pop-map]
  (boolean
   (when (and (map? pop-map)
              (valid-petname? (:nickname pop-map))
              (valid-pubkey-hex? (:pubkey pop-map))
              (string? (:domain pop-map))
              (not (str/blank? (:domain pop-map)))
              (string? (:pop-signature pop-map))
              (not (str/blank? (:pop-signature pop-map))))
     (let [norm-domain (str/lower-case (str/trim (:domain pop-map)))
           norm-nick (normalize-petname (:nickname pop-map))
           norm-pub (normalize-pubkey-hex (:pubkey pop-map))
           sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                  (let [n (rendezvous/normalize-home-node hn)]
                                                    (when (and (string? n) (not (str/blank? n))) n)))
                                                (:home-set pop-map)))))
           ep (long (or (:epoch pop-map) 0))
           prev-pk (:prev-pubkey pop-map)
           rot-sig (:rotation-signature pop-map)
           has-rot? (or (some? prev-pk) (some? rot-sig))
           norm-prev (when prev-pk (normalize-pubkey-hex prev-pk))
           canonical-str (str "bitecho-directory-pop-v1|" norm-domain "|" norm-nick "|" norm-pub "|"
                              (str/join "," sorted-hs) "|" ep "|" (or norm-prev ""))
           pub-bytes (try (basalt/hex->bytes norm-pub) (catch Exception _ nil))
           sig-bytes (try (basalt/hex->bytes (:pop-signature pop-map)) (catch Exception _ nil))
           pop-valid? (boolean (and pub-bytes sig-bytes
                                    (crypto/verify pub-bytes (.getBytes canonical-str "UTF-8") sig-bytes)))]
       (if-not pop-valid?
         false
         (if has-rot?
           (let [rot-keys-valid? (and (valid-pubkey-hex? prev-pk)
                                      (not= norm-prev norm-pub)
                                      (string? rot-sig)
                                      (not (str/blank? rot-sig)))
                 prev-pub-bytes (when rot-keys-valid? (try (basalt/hex->bytes norm-prev) (catch Exception _ nil)))
                 rot-sig-bytes (when rot-keys-valid? (try (basalt/hex->bytes rot-sig) (catch Exception _ nil)))]
             (boolean (and prev-pub-bytes rot-sig-bytes
                           (crypto/verify prev-pub-bytes (.getBytes canonical-str "UTF-8") rot-sig-bytes))))
           true))))))

(defn sign-directory-descriptor
  "Signs a directory attestation descriptor under a directory authority key after verifying PoP.
   Agent self-signature proves continuity only; directory signature attests the entry."
  [directory-privkey-bytes directory-pubkey-hex pop-map {:keys [mailbox issued-epoch expires-epoch]}]
  (when (and (valid-pubkey-hex? directory-pubkey-hex)
             (verify-directory-pop pop-map)
             (integer? issued-epoch)
             (integer? expires-epoch)
             (>= (long expires-epoch) (long issued-epoch)))
    (let [domain (str/lower-case (str/trim (or (:domain pop-map) "bitecho.org")))
          norm-nick (normalize-petname (:nickname pop-map))
          norm-pub (normalize-pubkey-hex (:pubkey pop-map))
          sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                 (let [n (rendezvous/normalize-home-node hn)]
                                                   (when (and (string? n) (not (str/blank? n))) n)))
                                               (:home-set pop-map)))))
          norm-prev (when-let [p (:prev-pubkey pop-map)] (normalize-pubkey-hex p))
          pop-sig (:pop-signature pop-map)
          rot-sig (or (:rotation-signature pop-map) "")
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
               :epoch (long (or (:epoch pop-map) iss-ep))
               :issued-epoch iss-ep
               :expires-epoch exp-ep
               :pop-signature pop-sig
               :directory-pubkey (normalize-pubkey-hex directory-pubkey-hex)
               :directory-signature dir-sig-hex}
        (seq mbox) (assoc :mailbox mbox)
        norm-prev (assoc :prev-pubkey norm-prev)
        (:rotation-signature pop-map) (assoc :rotation-signature (:rotation-signature pop-map))))))

(defn verify-directory-descriptor
  "Verifies a directory descriptor against a trusted directory authority public key and current epoch.
   Strictly fails closed returning {:ok? false :error <reason>} on any validation failure."
  [descriptor trusted-directory-pubkey current-epoch]
  (let [desc (if (map? descriptor)
               (into {} (for [[k v] descriptor]
                          [(if (keyword? k) k (keyword (str/replace (name k) #"_" "-"))) v]))
               descriptor)]
    (cond
      (or (not (map? desc))
          (str/blank? (str (or (:domain desc) "")))
          (str/blank? (str (or (:nickname desc) "")))
          (str/blank? (str (or (:pubkey desc) "")))
          (str/blank? (str (or (:directory-pubkey desc) "")))
          (str/blank? (str (or (:directory-signature desc) "")))
          (str/blank? (str (or (:pop-signature desc) "")))
          (nil? (:issued-epoch desc))
          (nil? (:expires-epoch desc)))
      {:ok? false :error "malformed-descriptor"}

      (or (not (valid-pubkey-hex? trusted-directory-pubkey))
          (not= (normalize-pubkey-hex (:directory-pubkey desc))
                (normalize-pubkey-hex trusted-directory-pubkey)))
      {:ok? false :error "untrusted-directory-authority"}

      (or (< (long (or (:expires-epoch desc) -1)) (long (or (:issued-epoch desc) 0)))
          (and (some? current-epoch) (< (long (:expires-epoch desc)) (long current-epoch))))
      {:ok? false :error "descriptor-expired"}

      (and (some? current-epoch) (> (long (:issued-epoch desc)) (+ (long current-epoch) 2)))
      {:ok? false :error "descriptor-future-epoch"}

      (not (verify-directory-pop desc))
      {:ok? false :error "invalid-pop-signature"}

      :else
      (let [domain (str/lower-case (str/trim (or (:domain desc) "bitecho.org")))
            norm-nick (normalize-petname (:nickname desc))
            norm-pub (normalize-pubkey-hex (:pubkey desc))
            sorted-hs (vec (sort (distinct (keep (fn [hn]
                                                   (let [n (rendezvous/normalize-home-node hn)]
                                                     (when (and (string? n) (not (str/blank? n))) n)))
                                                 (:home-set desc)))))
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
          {:ok? false :error "invalid-directory-signature"}
          {:ok? true :descriptor descriptor})))))

;; -----------------------------------------------------------------------------
;; Delegated Agent Certificates (DACs: Anchor Key -> Hot Agent Key)
;; -----------------------------------------------------------------------------

(defn create-dac
  "Creates a Delegated Agent Certificate (DAC) signed by an anchor cold key."
  [anchor-privkey-bytes {:keys [anchor-pubkey agent-pubkey issued-epoch expires-epoch max-spend-per-epoch scopes]}]
  (when (and (valid-pubkey-hex? anchor-pubkey)
             (valid-pubkey-hex? agent-pubkey)
             (not= (normalize-pubkey-hex anchor-pubkey) (normalize-pubkey-hex agent-pubkey))
             (>= (long (or issued-epoch 0)) 0)
             (>= (long (or expires-epoch 0)) (long (or issued-epoch 0)))
             (>= (long (or max-spend-per-epoch 0)) 0))
    (let [norm-anchor (normalize-pubkey-hex anchor-pubkey)
          norm-agent (normalize-pubkey-hex agent-pubkey)
          iss-ep (long (or issued-epoch 0))
          exp-ep (long (or expires-epoch 0))
          max-spend (long (or max-spend-per-epoch 0))
          sorted-scopes (vec (sort (distinct (map str/lower-case (map name (or scopes ["gossip" "offer" "settle-intent" "transfer"]))))))
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
  (when (and (valid-pubkey-hex? anchor-pubkey)
             (valid-pubkey-hex? agent-pubkey)
             (string? dac-id)
             (not (str/blank? dac-id)))
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
  "Verifies a DAC revocation map under its anchor public key."
  [revocation]
  (let [rev (if (map? revocation)
              (into {} (for [[k v] revocation]
                         [(if (keyword? k) k (keyword (str/replace (name k) #"_" "-"))) v]))
              revocation)]
    (boolean
     (when (and (map? rev)
                (valid-pubkey-hex? (:anchor-pubkey rev))
                (valid-pubkey-hex? (:agent-pubkey rev))
                (string? (:dac-id rev))
                (not (str/blank? (:dac-id rev)))
                (string? (:signature rev))
                (not (str/blank? (:signature rev))))
       (let [norm-anchor (normalize-pubkey-hex (:anchor-pubkey rev))
             norm-agent (normalize-pubkey-hex (:agent-pubkey rev))
             dac-id (:dac-id rev)
             rev-ep (long (or (:revoked-epoch rev) 0))
             canonical-str (str "bitecho-dac-revoke-v1|" norm-anchor "|" norm-agent "|" dac-id "|" rev-ep)
             pub-bytes (try (basalt/hex->bytes norm-anchor) (catch Exception _ nil))
             sig-bytes (try (basalt/hex->bytes (:signature rev)) (catch Exception _ nil))]
         (and pub-bytes sig-bytes
              (crypto/verify pub-bytes (.getBytes canonical-str "UTF-8") sig-bytes)))))))

(defn verify-dac
  "Verifies a Delegated Agent Certificate (DAC) against expected agent key, epoch, revocations, and scope.
   Strictly fails closed returning {:ok? false :error <reason>} on any validation failure."
  [dac {:keys [expected-agent-pubkey current-epoch revoked-dac-ids required-scope]}]
  (let [d (if (map? dac)
            (into {} (for [[k v] dac]
                       [(if (keyword? k) k (keyword (str/replace (name k) #"_" "-"))) v]))
            dac)]
    (cond
      (not (map? d))
      {:ok? false :error "malformed-dac"}

      (or (not (valid-pubkey-hex? (:anchor-pubkey d)))
          (not (valid-pubkey-hex? (:agent-pubkey d)))
          (= (normalize-pubkey-hex (:anchor-pubkey d)) (normalize-pubkey-hex (:agent-pubkey d))))
      {:ok? false :error "invalid-dac-keys"}

      (and expected-agent-pubkey
           (not= (normalize-pubkey-hex expected-agent-pubkey)
                 (normalize-pubkey-hex (:agent-pubkey d))))
      {:ok? false :error "dac-agent-mismatch"}

      (or (< (long (or (:expires-epoch d) -1)) (long (or (:issued-epoch d) 0)))
          (and (some? current-epoch) (< (long (:expires-epoch d)) (long current-epoch))))
      {:ok? false :error "dac-expired"}

      (and (some? current-epoch) (> (long (:issued-epoch d)) (+ (long current-epoch) 2)))
      {:ok? false :error "dac-future-epoch"}

      (contains? (set (or revoked-dac-ids [])) (:dac-id d))
      {:ok? false :error "dac-revoked"}

      (and required-scope
           (not (contains? (set (map str/lower-case (map name (or (:scopes d) []))))
                           (str/lower-case (name required-scope)))))
      {:ok? false :error "dac-scope-not-permitted"}

      :else
      (let [norm-anchor (normalize-pubkey-hex (:anchor-pubkey d))
            norm-agent (normalize-pubkey-hex (:agent-pubkey d))
            iss-ep (long (or (:issued-epoch d) 0))
            exp-ep (long (or (:expires-epoch d) 0))
            max-spend (long (or (:max-spend-per-epoch d) 0))
            sorted-scopes (vec (sort (distinct (map str/lower-case (map name (or (:scopes d) []))))))
            canonical-str (str "bitecho-dac-v1|" norm-anchor "|" norm-agent "|" iss-ep "|" exp-ep "|" max-spend "|" (str/join "," sorted-scopes))
            expected-id (basalt/bytes->hex (crypto/sha256 (.getBytes canonical-str "UTF-8")))
            anchor-pub-bytes (try (basalt/hex->bytes norm-anchor) (catch Exception _ nil))
            sig-bytes (try (basalt/hex->bytes (str (or (:signature d) ""))) (catch Exception _ nil))]
        (if-not (and (= (:dac-id d) expected-id)
                     anchor-pub-bytes sig-bytes
                     (crypto/verify anchor-pub-bytes (.getBytes canonical-str "UTF-8") sig-bytes))
          {:ok? false :error "invalid-dac-signature"}
          {:ok? true
           :dac dac
           :dac-id (:dac-id d)
           :anchor-pubkey norm-anchor
           :agent-pubkey norm-agent})))))

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
                env-curr (agent-sim/build-home-set-envelope my-pub privkey-bytes requested-nodes p-b curr-epoch)
                env-nil (agent-sim/build-home-set-envelope my-pub privkey-bytes requested-nodes p-b nil)]
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
            env-curr (agent-sim/build-home-set-envelope my-pub privkey-bytes candidates p-b curr-epoch)
            env-nil (agent-sim/build-home-set-envelope my-pub privkey-bytes candidates p-b nil)]
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
  "Computes deterministic offer-hash binding session-id, caller, callee, ephemeral key, epoch, price, and home-node."
  [{:keys [session-id caller callee caller-ephemeral-pub epoch price home-node]}]
  (let [hash-input (str session-id "-" caller "-" callee "-" caller-ephemeral-pub "-" epoch "-" price "-" (name (or home-node "")))]
    (basalt/bytes->hex (crypto/sha256 (.getBytes ^String hash-input "UTF-8")))))

(defn- exec-offer [state cmd-map privkey-bytes]
  (let [callee-target (or (get cmd-map "callee") (:callee cmd-map))
        resolved (resolve-counterparty state callee-target)]
    (if-not (:ok? resolved)
      {:state state
       :response {"ok" false "error" (:error resolved)}
       :net-envelopes []
       :stdout-events []}
      (let [callee (:pubkey resolved)
            pname (:petname resolved)
            price (long (or (get cmd-map "price") (:price cmd-map) 0))
            default-home (or (first (keys (get-in state [:bootstrap :nodes]))) :node1)
            home-node (name (or (get cmd-map "home_node") (:home_node cmd-map) default-home))
            burn-amt (long (or (get cmd-map "burn") (:burn cmd-map) 500))
            kp-eph (sealed/generate-x25519-keypair)
            caller (:pubkey state)
            eph-pub-hex (basalt/bytes->hex (:public kp-eph))
            session-id (compute-session-id caller callee eph-pub-hex)
            epoch (:epoch state)
            offer-hash (compute-offer-hash {:session-id session-id
                                            :caller caller
                                            :callee callee
                                            :caller-ephemeral-pub eph-pub-hex
                                            :epoch epoch
                                            :price price
                                            :home-node home-node})
            sig-hex (basalt/bytes->hex (crypto/sign privkey-bytes (.getBytes offer-hash "UTF-8")))
            active-dac (when-let [d (:dac state)]
                         (when (:ok? (verify-dac d {:expected-agent-pubkey (:pubkey state)
                                                    :current-epoch epoch
                                                    :revoked-dac-ids (:revoked-dacs state)
                                                    :required-scope "offer"}))
                           d))
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
         :stdout-events []}))))

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
            epoch (:epoch state)
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
                         :epoch (:epoch state)
                         :seq seq-num
                         :nonce (basalt/bytes->hex (:nonce sealed))
                         :ciphertext (basalt/bytes->hex (:ciphertext sealed))}
            gossip-env (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze msg-payload) burn-amt)
            max-outbox (long (or (:max-outbox-size state) 64))
            curr-outbox (or (:outbox session) {})
            curr-order (or (:outbox-order session) [])
            next-order (conj curr-order seq-num)
            next-outbox (assoc curr-outbox seq-num {:seq seq-num :msg-payload msg-payload :burn burn-amt})
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
                              (vec (vals (:pending-offers state))))]
    {:state (assoc state :inbox [])
     :response {"ok" true
                "messages" enriched-msgs
                "pending_offers" enriched-offers}
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
                           :epoch (:epoch state)
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
          new-state (cond-> (assoc state
                                   :account {:balance bal
                                             :spendable spendable
                                             :seq seq-num
                                             :deps deps
                                             :finalized-epoch fin-ep}
                                   :transfer-seq seq-num
                                   :last-transfer-hash (last deps))
                      (pos? fin-ep)
                      (assoc :epoch (max (long (:epoch state 0)) fin-ep)
                             :epoch-initialized? true))]
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
       :stdout-events []})))

(defn- exec-transfer [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient")
                         (:receiver cmd-map) (:recipient cmd-map))
        amount (long (or (get cmd-map "amount") (:amount cmd-map) 0))]
    (if (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)) (<= amount 0))
      {:state state
       :response {"ok" false "error" "invalid-transfer-params"}
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
                burn-amt (long (or (get cmd-map "burn") (:burn cmd-map) 500))
                acct (:account state)
                spendable (when acct (long (or (:spendable acct) (:balance acct) 0)))]
            (if (and acct (< spendable (+ amount burn-amt)))
              {:state state
               :response {"ok" false "error" "insufficient-balance"}
               :net-envelopes []
               :stdout-events []}
              (let [seq-num (long (or (get cmd-map "seq")
                                      (:seq cmd-map)
                                      (inc (long (or (when acct (:seq acct))
                                                     (:transfer-seq state)
                                                     0)))))
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
                                                 :last-transfer-hash (:transfer-hash res))
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
                 :stdout-events []}))))))))

(defn- exec-settle-intent [state cmd-map privkey-bytes]
  (let [raw-receiver (or (get cmd-map "receiver") (get cmd-map "recipient")
                         (:receiver cmd-map) (:recipient cmd-map))
        amount (long (or (get cmd-map "amount") (:amount cmd-map) 0))]
    (if (or (nil? raw-receiver) (and (string? raw-receiver) (str/blank? raw-receiver)) (<= amount 0))
      {:state state
       :response {"ok" false "error" "invalid-intent-params"}
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
                spendable (when acct (long (or (:spendable acct) (:balance acct) 0)))]
            (if (and acct (< spendable amount))
              {:state state
               :response {"ok" false "error" "insufficient-balance"}
               :net-envelopes []
               :stdout-events []}
              (let [next-intent-seq (inc (long (:intent-seq state 0)))
                    rid (or (get cmd-map "receipt_id")
                            (:receipt_id cmd-map)
                            (str "intent:" (:pubkey state) ":" receiver ":" amount ":" (:epoch state 0) ":" next-intent-seq))
                    take-amt (burn/calculate-settlement-take amount burn/default-settlement-take-bps)
                    net-amt (- amount take-amt)
                    intent-env (mesh/wrap-agent-event
                                {:type :settle-intent
                                 :payer (:pubkey state)
                                 :receiver receiver
                                 :amount amount
                                 :epoch (:epoch state 0)
                                 :receipt-id rid}
                                (:pubkey state)
                                privkey-bytes)
                    new-state (cond-> (assoc state :intent-seq next-intent-seq)
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
                 :stdout-events []}))))))))

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
                          :epoch (:epoch state 0)}
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
      (let [rev-map (if (map? raw-rev)
                      (into {} (for [[k v] raw-rev]
                                 [(if (keyword? k) k (keyword (str/replace (name k) #"_" "-"))) v]))
                      {})
            dac-id (:dac-id rev-map)
            new-revoked (conj (set (or (:revoked-dacs state) #{})) dac-id)
            attached-dac (:dac state)
            attached-id (or (:dac-id attached-dac) (get attached-dac "dac_id"))
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
                    (get cmd-map "pubkey") (:directory-pubkey cmd-map) (:pubkey cmd-map)
                    (get-in state [:bootstrap :custody-pubkey])
                    (get-in state [:bootstrap :treasury-pubkey]))
        cur-ep (when (:epoch-initialized? state) (:epoch state))
        res (verify-directory-descriptor raw-desc dir-pub cur-ep)]
    (if-not (:ok? res)
      {:state state
       :response {"ok" false "error" (:error res)}
       :net-envelopes []
       :stdout-events []}
      (let [desc (:descriptor res)
            desc-map (if (map? desc)
                       (into {} (for [[k v] desc]
                                  [(if (keyword? k) k (keyword (str/replace (name k) #"_" "-"))) v]))
                       {})
            nick (:nickname desc-map)
            pub (:pubkey desc-map)
            prev-pub (:prev-pubkey desc-map)
            existing (get-in state [:directory-cache nick])]
        (if (and existing
                 (not= (normalize-pubkey-hex (:pubkey existing)) (normalize-pubkey-hex pub))
                 (or (nil? prev-pub)
                     (not= (normalize-pubkey-hex (:pubkey existing)) (normalize-pubkey-hex prev-pub))))
          {:state state
           :response {"ok" false "error" "broken-key-continuity"}
           :net-envelopes []
           :stdout-events []}
          (let [new-state (assoc-in state [:directory-cache nick] desc)]
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
                        "inbox_count" (count (:inbox state))
                        "account" (:account state)
                        "petnames" (into (sorted-map) (:petnames state {}))
                        "petnames_count" (count (:petnames state {}))
                        "dac" (dac-summary (:dac state))
                        "revoked_dacs_count" (count (:revoked-dacs state #{}))
                        "directory_cache_count" (count (:directory-cache state {}))
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
    (case (get effective-map "cmd")
      "identity" (exec-identity state)
      "discover" (exec-discover state)
      "register-home-set" (exec-register-home-set state effective-map privkey-bytes)
      "offer" (exec-offer state effective-map privkey-bytes)
      "accept" (exec-accept state effective-map privkey-bytes)
      "send" (exec-send state effective-map privkey-bytes)
      "inbox" (exec-inbox state)
      "close" (exec-close state effective-map privkey-bytes)
      "transfer" (exec-transfer state effective-map privkey-bytes)
      "account" (exec-sync-account state effective-map)
      "sync-account" (exec-sync-account state effective-map)
      "settle-intent" (exec-settle-intent state effective-map privkey-bytes)
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

    (and (map? raw-payload-or-event) (contains? raw-payload-or-event :bitecho/type))
    raw-payload-or-event

    (and (map? raw-payload-or-event) (map? (:event raw-payload-or-event)))
    (recur (:event raw-payload-or-event))

    (and (map? raw-payload-or-event) (map? (:message raw-payload-or-event)))
    (let [p (:payload (:message raw-payload-or-event))]
      (if (bytes? p)
        (recur (try (nippy/thaw p) (catch Exception _ nil)))
        (if (map? p) (recur p) nil)))

    :else nil))

(defn- handle-wire-offer [state msg privkey-bytes]
  (if-not (= (:callee msg) (:pubkey state))
    {:state state :net-envelopes [] :stdout-events []}
    (let [caller-pub (try (basalt/hex->bytes (:caller msg)) (catch Exception _ nil))
          sig-bytes (try (basalt/hex->bytes (:signature msg)) (catch Exception _ nil))
          expected-sid (compute-session-id (:caller msg) (:callee msg) (:caller-ephemeral-pub msg))
          expected-hash (compute-offer-hash msg)
          valid-hashes? (and (= (:session-id msg) expected-sid)
                             (= (:offer-hash msg) expected-hash))
          valid-sig? (and valid-hashes?
                          caller-pub sig-bytes
                          (crypto/verify caller-pub (.getBytes ^String (:offer-hash msg) "UTF-8") sig-bytes))
          ref-epoch (:epoch state)
          dac-check (when-let [d (:dac msg)]
                      (verify-dac d {:expected-agent-pubkey (:caller msg)
                                     :current-epoch ref-epoch
                                     :revoked-dac-ids (:revoked-dacs state)
                                     :required-scope "offer"}))]
      (if (or (not valid-sig?)
              (and (:dac msg) (not (:ok? dac-check))))
        {:state state :net-envelopes [] :stdout-events []}
        (let [sid (:session-id msg)
              clean-offer (cond-> (select-keys msg [:bitecho/type :session-id :caller :callee :caller-ephemeral-pub :epoch :price :home-node :offer-hash :burn :signature])
                            (and (:dac msg) (:ok? dac-check)) (assoc :dac (:dac msg)))]
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
               :stdout-events [event]})))))))

(defn- handle-wire-accept [state msg]
  (if-not (= (:caller msg) (:pubkey state))
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
            (let [callee-eph (basalt/hex->bytes (:callee-ephemeral-pub msg))
                  shared-sec (sealed/x25519-shared-secret (:ephemeral-priv session) callee-eph)
                  keys (sealed/derive-channel-keys shared-sec session-id :initiator)
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
               :stdout-events [event]})))))))

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
                        :epoch (:epoch state)
                        :ack-seq contiguous-ack-seq
                        :acked-seq msg-seq
                        :seen-seqs seen-vec
                        :signature sig-hex}]
       (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze ack-payload) 100)))))

(defn- handle-wire-sealed-msg [state msg privkey-bytes]
  (if-not (= (:recipient msg) (:pubkey state))
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
            {:state state :net-envelopes [] :stdout-events []}))))))

(defn- handle-wire-session-ack [state msg]
  (if-not (= (:recipient msg) (:pubkey state))
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
               :stdout-events []})))))))

(defn build-unacked-replay-envelopes
  "Extracts unacknowledged session outbox messages, advances their epoch to the current state epoch,
   and wraps them in signed gossip envelopes for failover/reconnect replay."
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
              :let [msg (:msg-payload item)
                    burn (or (:burn item) 500)
                    curr-ep (:epoch state 0)
                    upd-epoch (max (long (or (:epoch msg) 0)) (long curr-ep))
                    upd-msg (assoc msg :epoch upd-epoch)]]
          (agent-sim/build-gossip-envelope (:pubkey state) privkey-bytes (nippy/freeze upd-msg) burn)))))))

(defn- handle-wire-close [state msg]
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

(defn handle-wire-payload
  "Processes an incoming network event or raw payload. Enforces 2-epoch skew tolerance
   and anti-replay protections before dispatching to message-specific reducers."
  [state raw-payload-or-event privkey-bytes]
  (let [msg (unwrap-wire-message raw-payload-or-event)]
    (if-not (map? msg)
      {:state state :net-envelopes [] :stdout-events []}
      (let [msg-epoch (when (integer? (:epoch msg)) (long (:epoch msg)))
            ref-epoch (if (or (:epoch-initialized? state)
                              (and (integer? (:epoch state)) (pos? (long (:epoch state)))))
                        (:epoch state)
                        (or (when-let [sid (:session-id msg)]
                              (get-in state [:sessions sid :epoch]))
                            msg-epoch))
            skew-exceeded? (and msg-epoch ref-epoch
                                (> (Math/abs (- msg-epoch ref-epoch)) 2))]
        (if skew-exceeded?
          {:state state :net-envelopes [] :stdout-events []}
          (let [res (case (:bitecho/type msg)
                      :channel-offer (handle-wire-offer state msg privkey-bytes)
                      :channel-accept (handle-wire-accept state msg)
                      :sealed-message (handle-wire-sealed-msg state msg privkey-bytes)
                      :session-ack (handle-wire-session-ack state msg)
                      :channel-close (handle-wire-close state msg)
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
