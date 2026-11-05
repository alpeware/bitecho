(ns bitecho.fido
  "FIDO Metadata Service (MDS v3) lookup, authenticator security evaluation,
   and unverified MDS JWT parsing.
   Standing Constraint 6: Strength evaluation results are strictly labeled UNVERIFIED
   until x5c attestation chain and FIDO MDS JWT signature verification are implemented."
  (:require [clojure.string :as str]
            #?(:clj [clojure.data.json :as json])))

(def ^:const ^{:doc "Standard unverified security label per Standing Constraint 6."}
  unverified-label "UNVERIFIED")

(def ^:const ^{:doc "Standard unverified warning notice per Standing Constraint 6."}
  unverified-warning "UNVERIFIED (x5c attestation chain and FIDO MDS JWT signature verification pending)")

(def ^:const ^{:doc "Yubico central enrollment status per decentralized architecture decision."}
  yubico-enrollment-policy {:yubico-enrollment :parked
                            :reason "Centralizing step in tension with Bitecho decentralized ethos"})

(def ^:private certified-authenticators
  {"2fc0579f-8113-47ea-b116-bb5a8db9202a"
   {:aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"
    :description "YubiKey 5 Series (NFC / USB, Hardware Secure Element)"
    :vendor "Yubico"
    :authenticator-type :cross-platform-hardware
    :key-protection [:hardware :secure-element]
    :user-verification-details [:pin :touch :presence]
    :attestation-types [:basic-full :packed]
    :certification-level "FIDO2 L1 / L2"}

   "cb69481e-8ff7-4039-93ec-0a2729a1e67d"
   {:aaguid "cb69481e-8ff7-4039-93ec-0a2729a1e67d"
    :description "YubiKey 5 FIPS Series"
    :vendor "Yubico"
    :authenticator-type :cross-platform-hardware
    :key-protection [:hardware :secure-element]
    :user-verification-details [:pin :touch :presence]
    :attestation-types [:basic-full :packed]
    :certification-level "FIDO2 L2 / FIPS 140-2 L3"}

   "ee882879-721c-4916-acfe-341a9c4021e1"
   {:aaguid "ee882879-721c-4916-acfe-341a9c4021e1"
    :description "YubiKey Security Key NFC"
    :vendor "Yubico"
    :authenticator-type :cross-platform-hardware
    :key-protection [:hardware :secure-element]
    :user-verification-details [:touch :presence]}

   "9f727d30-6595-4809-baee-08879813b2c9"
   {:aaguid "9f727d30-6595-4809-baee-08879813b2c9"
    :description "Windows Hello (TPM Hardware-Backed)"
    :vendor "Microsoft"
    :authenticator-type :platform-hardware
    :key-protection [:hardware :tpm]
    :user-verification-details [:pin :biometric]}

   "08987058-cadc-4b81-b6e1-30de50dcbe96"
   {:aaguid "08987058-cadc-4b81-b6e1-30de50dcbe96"
    :description "Windows Hello (Software-Backed)"
    :vendor "Microsoft"
    :authenticator-type :platform-software
    :key-protection [:software]
    :user-verification-details [:pin :biometric]}

   "adce0002-35bc-c60a-648b-0b25f1f05503"
   {:aaguid "adce0002-35bc-c60a-648b-0b25f1f05503"
    :description "Apple Touch ID / Face ID (Secure Enclave)"
    :vendor "Apple"
    :authenticator-type :platform-hardware
    :key-protection [:hardware :secure-element]
    :user-verification-details [:biometric]}

   "00000000-0000-0000-0000-000000000000"
   {:aaguid "00000000-0000-0000-0000-000000000000"
    :description "Self-Attested / Generic FIDO2 Authenticator"
    :vendor "Unknown"
    :authenticator-type :unknown
    :key-protection [:unknown]}})

(defn normalize-aaguid
  "Normalizes an AAGUID (string or byte sequence) into standard lowercase hyphenated UUID format."
  [aaguid]
  (cond
    (string? aaguid)
    (let [clean (-> aaguid (str/replace "-" "") (str/lower-case))]
      (if (= (count clean) 32)
        (str (subs clean 0 8) "-"
             (subs clean 8 12) "-"
             (subs clean 12 16) "-"
             (subs clean 16 20) "-"
             (subs clean 20 32))
        (str/lower-case aaguid)))

    (sequential? aaguid)
    (let [hex (apply str (map (fn [b]
                                (let [s #?(:clj  (Integer/toHexString (bit-and (int b) 0xff))
                                           :cljs (.toString (bit-and (int b) 0xff) 16))]
                                  (if (< (count s) 2) (str "0" s) s)))
                              aaguid))]
      (normalize-aaguid hex))

    #?@(:clj [(bytes? aaguid)
              (normalize-aaguid (mapv #(bit-and (int %) 0xff) ^bytes aaguid))]
        :cljs [(instance? js/Uint8Array aaguid)
               (normalize-aaguid (vec (js/Array.from aaguid)))])

    :else nil))

(defn lookup-aaguid
  "Looks up authenticator metadata by AAGUID in built-in certified metadata statements."
  [aaguid]
  (when-let [norm (normalize-aaguid aaguid)]
    (or (get certified-authenticators norm)
        {:aaguid norm
         :description "Unknown Authenticator"
         :vendor "Unknown"
         :authenticator-type :unknown
         :key-protection [:unknown]})))

(defn evaluate-authenticator-strength
  "Evaluates authenticator security properties based on auth-data and AAGUID metadata.
   Standing Constraint 6: Returns strength rating with verification-status and label
   strictly set to 'UNVERIFIED'."
  [auth-data-or-aaguid]
  (let [aaguid (if (map? auth-data-or-aaguid)
                 (or (:aaguid auth-data-or-aaguid) (:authenticator/aaguid auth-data-or-aaguid))
                 auth-data-or-aaguid)
        meta (lookup-aaguid aaguid)
        flags (when (map? auth-data-or-aaguid)
                {:up? (or (:up? auth-data-or-aaguid) (:authenticator/user-present auth-data-or-aaguid) false)
                 :uv? (or (:uv? auth-data-or-aaguid) (:authenticator/user-verified auth-data-or-aaguid) false)
                 :be? (or (:be? auth-data-or-aaguid) (:authenticator/backup-eligibility auth-data-or-aaguid) false)
                 :bs? (or (:bs? auth-data-or-aaguid) (:authenticator/backup-state auth-data-or-aaguid) false)})
        hardware? (contains? (set (:key-protection meta)) :hardware)
        secure-elem? (contains? (set (:key-protection meta)) :secure-element)
        score (cond
                (and hardware? secure-elem? (or (nil? flags) (:uv? flags))) 95
                (and hardware? (or (nil? flags) (:uv? flags))) 85
                hardware? 75
                :else 50)
        strength (cond
                   (and hardware? secure-elem?) :hardware-secure-element
                   hardware? :hardware-backed
                   :else :basic)]
    {:strength strength
     :score score
     :verification-status unverified-label
     :label unverified-label
     :warning unverified-warning
     :flags flags
     :metadata meta
     :yubico-enrollment :parked}))

(defn- base64url-decode-str [^String s]
  (let [clean (-> s (str/replace "-" "+") (str/replace "_" "/"))
        pad (mod (count clean) 4)
        padded (if (pos? pad)
                 (str clean (apply str (repeat (- 4 pad) "=")))
                 clean)]
    #?(:clj
       (String. (.decode (java.util.Base64/getDecoder) padded) "UTF-8")
       :cljs
       (let [bin (js/atob padded)
             bytes (mapv #(.charCodeAt bin %) (range (count bin)))]
         (.decode (js/TextDecoder. "UTF-8") (js/Uint8Array. (clj->js bytes)))))))

(defn parse-mds-jwt-unverified
  "Parses a FIDO MDS v3 JWT payload blob without signature verification.
   Standing Constraint 6: Marks the result strictly as UNVERIFIED."
  [jwt-str]
  (when (string? jwt-str)
    (let [parts (str/split jwt-str #"\.")]
      (when (>= (count parts) 2)
        (let [header-json (base64url-decode-str (first parts))
              payload-json (base64url-decode-str (second parts))]
          {:header #?(:clj  (clojure.data.json/read-str header-json :key-fn keyword)
                      :cljs (js->clj (.parse js/JSON header-json) :keywordize-keys true))
           :payload #?(:clj  (clojure.data.json/read-str payload-json :key-fn keyword)
                       :cljs (js->clj (.parse js/JSON payload-json) :keywordize-keys true))
           :signature (nth parts 2 nil)
           :verification-status unverified-label
           :label unverified-label
           :warning unverified-warning})))))
