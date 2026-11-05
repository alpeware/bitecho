(ns bitecho.anchor-webauthn-test
  "Comprehensive cross-runtime test suite for Bech32m (BIP-0350), pure CBOR (RFC 8949),
   FIDO MDS v3 authenticator evaluation with UNVERIFIED label (Standing Constraint 6),
   WebAuthn discoverable credential seed recovery, non-extractable WebCrypto specs,
   cold-certifies-hot DAC delegation, and Human Anchor workflows (Milestone 11)."
  (:require [bitecho.anchor.core :as anchor]
            [bitecho.basalt.core :as basalt]
            [bitecho.bech32m :as bech32m]
            [bitecho.cbor :as cbor]
            [bitecho.crypto :as crypto]
            [bitecho.fido :as fido]
            [bitecho.light-node.core :as light-core]
            [bitecho.webauthn :as webauthn]
            [clojure.string :as str]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            #?(:clj [clojure.test.check.clojure-test :refer [defspec]]
               :cljs [clojure.test.check.clojure-test :refer-macros [defspec]])
            [clojure.test.check.generators :as gen]
            #?(:clj [clojure.test.check.properties :refer [for-all]]
               :cljs [clojure.test.check.properties :refer-macros [for-all]])))

;;; ---------------------------------------------------------------------------
;;; Test Fixtures: Real YubiKey Hardware Vectors
;;; ---------------------------------------------------------------------------

(def ^:const ^{:doc "YubiKey COSE P-256 public key + credProtect CBOR fixture."}
  yubikey-cose-credprotect-fixture
  [165 1 2 3 38 32 1 33 88 32 45 134 40 93 24 102 140 35 188 104 200 16 17 164 138 235 86 214 18 32 162 88 177 149 8 231 244 66 159 197 237 206 34 88 32 68 193 29 32 149 149 128 211 180 29 18 79 71 184 178 183 69 252 162 148 154 135 132 23 152 129 152 117 241 32 71 188 161 107 99 114 101 100 80 114 111 116 101 99 116 2])

(def ^:const ^{:doc "YubiKey full packed attestationObject CBOR fixture."}
  yubikey-packed-attestation-fixture
  [163 99 102 109 116 102 112 97 99 107 101 100 103 97 116 116 83 116 109 116 163 99 97 108 103 38 99 115 105 103 88 71 48 69 2 33 0 193 14 85 67 168 181 192 227 1 84 184 175 122 15 247 20 209 195 208 251 144 244 67 31 160 26 242 62 244 188 202 16 2 32 73 148 252 178 13 173 15 203 155 181 128 113 237 238 27 99 188 34 242 157 24 209 116 172 101 86 27 190 124 178 157 129 99 120 53 99 129 89 2 221 48 130 2 217 48 130 1 193 160 3 2 1 2 2 9 0 240 234 187 125 104 4 76 138 48 13 6 9 42 134 72 134 247 13 1 1 11 5 0 48 46 49 44 48 42 6 3 85 4 3 19 35 89 117 98 105 99 111 32 85 50 70 32 82 111 111 116 32 67 65 32 83 101 114 105 97 108 32 52 53 55 50 48 48 54 51 49 48 32 23 13 49 52 48 56 48 49 48 48 48 48 48 48 90 24 15 50 48 53 48 48 57 48 52 48 48 48 48 48 48 90 48 111 49 11 48 9 6 3 85 4 6 19 2 83 69 49 18 48 16 6 3 85 4 10 12 9 89 117 98 105 99 111 32 65 66 49 34 48 32 6 3 85 4 11 12 25 65 117 116 104 101 110 116 105 99 97 116 111 114 32 65 116 116 101 115 116 97 116 105 111 110 49 40 48 38 6 3 85 4 3 12 31 89 117 98 105 99 111 32 85 50 70 32 69 69 32 83 101 114 105 97 108 32 50 49 48 57 52 54 55 51 55 54 48 89 48 19 6 7 42 134 72 206 61 2 1 6 8 42 134 72 206 61 3 1 7 3 66 0 4 230 103 211 59 186 156 69 155 128 158 252 203 106 11 174 44 92 252 75 215 129 213 115 72 61 150 253 233 37 31 100 44 205 230 194 6 85 20 243 51 130 70 172 153 82 128 0 42 210 56 175 188 3 113 182 215 250 195 191 203 158 121 210 48 163 129 129 48 127 48 19 6 10 43 6 1 4 1 130 196 10 13 1 4 5 4 3 5 4 3 48 34 6 9 43 6 1 4 1 130 196 10 2 4 21 49 46 51 46 54 46 49 46 52 46 49 46 52 49 52 56 50 46 49 46 55 48 19 6 11 43 6 1 4 1 130 229 28 2 1 1 4 4 3 2 4 48 48 33 6 11 43 6 1 4 1 130 229 28 1 1 4 4 18 4 16 47 192 87 159 129 19 71 234 177 22 187 90 141 185 32 42 48 12 6 3 85 29 19 1 1 255 4 2 48 0 48 13 6 9 42 134 72 134 247 13 1 1 11 5 0 3 130 1 1 0 182 49 168 40 215 147 56 173 41 0 138 13 127 121 163 160 61 207 46 12 155 31 98 250 207 180 138 158 85 149 119 167 81 108 149 155 100 43 24 240 12 76 119 34 141 25 249 212 66 34 92 18 104 189 35 24 160 140 106 23 115 6 79 2 153 201 155 178 67 138 71 187 103 177 208 219 37 43 148 150 126 18 1 90 154 43 233 228 45 212 84 38 136 144 97 254 31 34 86 254 248 118 221 115 153 50 70 131 113 26 176 109 234 188 111 69 104 106 249 238 225 129 121 108 35 59 62 217 236 61 192 172 189 242 249 13 168 79 25 39 233 115 214 50 0 209 184 244 228 1 57 154 37 52 93 204 4 162 171 178 147 128 35 180 95 91 66 82 65 141 13 82 117 133 99 31 97 196 86 205 185 139 10 20 222 13 110 82 127 103 63 109 50 77 88 97 41 19 39 165 95 196 116 232 230 215 200 113 162 223 103 87 72 172 199 152 215 111 150 122 248 204 185 241 86 254 160 120 18 182 57 26 55 237 221 198 226 100 17 11 153 180 61 64 181 50 45 126 252 148 120 139 11 218 73 34 104 97 117 116 104 68 97 116 97 88 194 73 150 13 229 136 14 140 104 116 52 23 15 100 118 96 91 143 228 174 185 162 134 50 199 153 92 243 186 131 29 151 99 197 0 0 0 1 47 192 87 159 129 19 71 234 177 22 187 90 141 185 32 42 0 48 74 218 175 92 226 89 16 195 72 251 165 44 94 86 162 26 176 12 230 202 124 22 76 214 182 86 58 27 205 154 5 117 142 47 141 221 215 141 234 24 205 10 177 253 182 127 142 179 165 1 2 3 38 32 1 33 88 32 74 218 175 92 226 89 16 195 72 251 165 44 94 33 2 227 102 229 109 172 169 69 105 161 203 227 16 44 190 255 144 157 34 88 32 127 27 196 3 249 191 254 89 47 145 4 230 25 237 99 197 79 211 196 218 218 169 45 236 34 125 251 151 225 64 196 191 161 107 99 114 101 100 80 114 111 116 101 99 116 2])

;;; ---------------------------------------------------------------------------
;;; BIP-0350 Bech32m Tests
;;; ---------------------------------------------------------------------------

(deftest test-bech32m-reference-vectors
  (testing "BIP-0350 and Chia reference vectors encode and decode correctly"
    ;; Chia burn address
    (let [burn-raw (concat (repeat 30 0) [0xde 0xad])
          burn-addr "xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm6ks6e8mvy"]
      (is (= (bech32m/encode-address "xch" burn-raw) burn-addr))
      (let [dec (bech32m/decode-address burn-addr)]
        (is (= "xch" (:hrp dec)))
        (is (= (vec burn-raw) (mapv #(bit-and (int %) 0xff) (:bytes dec))))))

    ;; BIP-0350 test vector 1
    (let [hex-data [0xff 0xbb 0xcd 0xeb 0x38 0xbd 0xab 0x49 0xca 0x30 0x7b 0x9a 0xc5 0xa9 0x28 0x39 0x8a 0x41 0x88 0x20]
          expected "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"]
      (is (= (bech32m/encode-address "abcdef" hex-data) expected))
      (let [dec (bech32m/decode-address expected)]
        (is (= "abcdef" (:hrp dec)))
        (is (= hex-data (mapv #(bit-and (int %) 0xff) (:bytes dec))))))

    ;; BIP-0350 test vector 2
    (let [words [24 23 25 24 22 28 1 16 11 29 8 25 23 29 19 13 16 23 29 22 25 28 1 16 11 3 25 29 27 25 3 3 29 19 11 25 3 3 25 13 24 29 1 25 3 3 25 13]
          expected "split1checkupstagehandshakeupstreamerranterredcaperredlc445v"]
      (is (= (bech32m/encode "split" words) expected))
      (is (= ["split" words] (bech32m/decode expected))))

    ;; BIP-0350 invalid strings: length limits (8..90) and mixed case
    (is (nil? (bech32m/decode "ech1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")))
    (is (nil? (bech32m/decode "ech1q")))
    (is (nil? (bech32m/decode "Abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")))))

(defspec ^{:doc "Property: Bech32m address encoding and decoding roundtrips arbitrary byte sequences within BIP-0350 90-char limit."}
  prop-bech32m-roundtrip 50
  (for-all [hrp (gen/elements ["ech" "bitecho" "test" "agent"])
            data (gen/not-empty (gen/vector (gen/choose 0 255) 1 45))]
           (let [addr (bech32m/encode-address hrp data)
                 dec (bech32m/decode-address addr)]
             (and (some? dec)
                  (= hrp (:hrp dec))
                  (= (vec data) (mapv #(bit-and (int %) 0xff) (:bytes dec)))))))

(defspec ^{:doc "Property: Single character corruption in a Bech32m string is detected and rejected."}
  prop-bech32m-tamper-detection 50
  (for-all [hrp (gen/elements ["ech" "bitecho"])
            data (gen/not-empty (gen/vector (gen/choose 0 255) 4 32))
            mut-char (gen/elements (map str bech32m/charset))
            target-idx-pct (gen/choose 0 99)]
           (let [valid-addr (bech32m/encode-address hrp data)
                 sep (str/last-index-of valid-addr "1")
                 data-part (subs valid-addr (inc sep))
                 idx (int (mod target-idx-pct (count data-part)))
                 corrupted (str (subs valid-addr 0 (+ sep 1 idx))
                                mut-char
                                (subs valid-addr (+ sep 2 idx)))]
             (if (= corrupted valid-addr)
               true
               (nil? (bech32m/decode corrupted))))))

(deftest test-pubkey-bech32m-conversion
  (testing "Ed25519 public keys (32-byte raw and 44-byte SPKI DER) encode to identical ech1... addresses and decode back"
    (let [raw-pub (mapv byte (range 32))
          spki-prefix [48 42 48 5 6 3 43 101 112 3 33 0]
          spki-pub (into (mapv byte spki-prefix) raw-pub)
          spki-hex (str "302a300506032b6570032100"
                        (apply str (map #(let [s #?(:clj (String/format "%02x" (to-array [(bit-and (int %) 0xff)]))
                                                    :cljs (.padStart (.toString (bit-and (int %) 0xff) 16) 2 "0"))]
                                           s)
                                        raw-pub)))
          addr-raw (bech32m/pubkey->bech32m raw-pub "ech")
          addr-spki-bytes (bech32m/pubkey->bech32m spki-pub "ech")
          addr-spki-hex (bech32m/pubkey->bech32m spki-hex "ech")]
      (is (str/starts-with? addr-raw "ech1"))
      (is (= addr-raw addr-spki-bytes))
      (is (= addr-raw addr-spki-hex))
      (let [dec (bech32m/bech32m->pubkey addr-raw)]
        (is (= "ech" (:hrp dec)))
        (is (= spki-hex (:spki-hex dec)))
        (is (= (mapv #(bit-and (int %) 0xff) raw-pub)
               (mapv #(bit-and (int %) 0xff) (:bytes dec))))))))

;;; ---------------------------------------------------------------------------
;;; CBOR (RFC 8949) Tests
;;; ---------------------------------------------------------------------------

(defspec ^{:doc "Property: Pure CBOR codec roundtrips arbitrary nested data structures."}
  prop-cbor-roundtrip 50
  (for-all [n (gen/choose -10000 10000)
            s gen/string-alphanumeric
            b (gen/vector (gen/choose 0 255) 0 32)
            bool gen/boolean]
           (let [val {:count n :name s :bytes b :active? bool :nested [n s bool]}
                 encoded (cbor/encode val)
                 decoded (cbor/decode encoded)]
             (and (map? decoded)
                  (= n (get decoded :count (get decoded "count")))
                  (= s (get decoded :name (get decoded "name")))
                  (= bool (get decoded :active? (get decoded "active?")))))))

(deftest test-yubikey-hardware-captures
  (testing "YubiKey 91-byte COSE key + credProtect concatenated CBOR sequence parses completely"
    (let [seq-res (cbor/decode-sequence yubikey-cose-credprotect-fixture)]
      (is (= 2 (count seq-res)))
      (let [[cose-key ext] seq-res]
        (is (= 2 (get cose-key 1)))     ;; kty: 2 = EC2
        (is (= -7 (get cose-key 3)))    ;; alg: -7 = ES256
        (is (= 1 (get cose-key -1)))    ;; crv: 1 = P-256
        (is (some? (get cose-key -2)))  ;; x-coordinate
        (is (some? (get cose-key -3)))  ;; y-coordinate
        (is (= 2 (get ext "credProtect" (get ext :credProtect)))))))

  (testing "YubiKey 1049-byte packed attestationObject decodes and verifies all fields"
    (let [parsed (webauthn/parse-attestation-object yubikey-packed-attestation-fixture)]
      (is (= "packed" (:fmt parsed)))
      (is (= "2fc0579f-8113-47ea-b116-bb5a8db9202a" (:aaguid parsed)))
      (is (= 48 (count (seq (:credential-id parsed)))))
      (let [flags (get-in parsed [:auth-data :flags])]
        (is (true? (:up? flags)))
        (is (true? (:uv? flags)))
        (is (true? (:at? flags)))
        (is (true? (:ed? flags))))
      (is (= 1 (get-in parsed [:auth-data :sign-count]))))))

;;; ---------------------------------------------------------------------------
;;; FIDO MDS v3 & Standing Constraint 6 UNVERIFIED Label Tests
;;; ---------------------------------------------------------------------------

(deftest test-fido-mds-unverified-evaluations
  (testing "AAGUID lookup and strength evaluation strictly returns UNVERIFIED per Standing Constraint 6"
    (let [meta (fido/lookup-aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a")]
      (is (= "Yubico" (:vendor meta)))
      (is (= :cross-platform-hardware (:authenticator-type meta)))
      (is (contains? (set (:key-protection meta)) :secure-element)))

    (let [eval-result (fido/evaluate-authenticator-strength {:aaguid "2fc0579f-8113-47ea-b116-bb5a8db9202a"
                                                             :up? true :uv? true})]
      ;; Standing Constraint 6 assertions:
      (is (= "UNVERIFIED" (:verification-status eval-result)))
      (is (= "UNVERIFIED" (:label eval-result)))
      (is (str/includes? (:warning eval-result) "UNVERIFIED"))
      (is (= :hardware-secure-element (:strength eval-result)))
      (is (= :parked (:yubico-enrollment eval-result)))))

  (testing "Unverified MDS JWT parsing extracts payload and attaches UNVERIFIED label"
    (let [header "eyJhbGciOiJFUzI1NiJ9"
          payload "eyJub25jZSI6MTIzNDUsImVudHJpZXMiOltdfQ"
          sig "dummy-signature"
          jwt (str header "." payload "." sig)
          parsed (fido/parse-mds-jwt-unverified jwt)]
      (is (= "UNVERIFIED" (:verification-status parsed)))
      (is (= "UNVERIFIED" (:label parsed)))
      (is (= 12345 (get-in parsed [:payload :nonce]))))))

;;; ---------------------------------------------------------------------------
;;; Discoverable Credential Seed Recovery & Cold-Certifies-Hot DAC Tests
;;; ---------------------------------------------------------------------------

(deftest test-discoverable-credential-seed-recovery
  (testing "32-byte seed in user.id or PRF extension is recovered and derives deterministic Ed25519 identity"
    (let [seed (crypto/random-bytes 32)
          reg-opts (webauthn/build-registration-options {:seed-bytes seed :username "alice"})
          assert-opts (webauthn/build-assertion-options {:seed-bytes seed})
          recovered (webauthn/recover-seed-from-assertion {:user-handle seed})
          recovered-prf (webauthn/recover-seed-from-assertion {:extensions {:prf {:results {:first seed}}}})]
      (is (= "required" (get-in reg-opts [:authenticatorSelection :residentKey])))
      (is (empty? (:allowCredentials assert-opts)))
      (is (= "required" (:userVerification assert-opts)))
      (is (some? recovered))
      (is (= :user-handle (:recovery-source recovered)))
      (is (= :prf (:recovery-source recovered-prf)))
      (is (= (:public-hex recovered) (:public-hex recovered-prf)))
      (is (= (:address recovered) (:address recovered-prf)))
      (is (some? (:public-key recovered)))
      (is (some? (:address recovered)))
      (is (str/starts-with? (:address recovered) "ech1"))
      (is (str/includes? (:trust-boundary recovered) "Trust boundary"))
      (is (str/includes? (:origin-scoping recovered) "scoped per WebAuthn RP ID")))))

(deftest test-cold-certifies-hot-dac-and-backup-key
  (testing "Anchor cold key certifies hot key via DAC, and validates through light-node DAC validator"
    (let [cold-kp (crypto/generate-keypair)
          hot-kp (crypto/generate-keypair)
          cold-priv (:private-key cold-kp)
          hot-pub-hex (basalt/bytes->hex (:public-key hot-kp))
          dac (webauthn/cold-certify-hot-key cold-priv hot-pub-hex {:issued-epoch 1 :expires-epoch 50})
          validation (light-core/verify-dac dac {:expected-agent-pubkey hot-pub-hex :current-epoch 10})]
      (is (true? (:ok? validation)))
      (is (true? (:valid? validation)))))

  (testing "Secondary backup key registration and recovery"
    (let [primary-state (anchor/init-anchor-state {:pubkey "302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111"})
          backup-seed (crypto/random-bytes 32)
          with-backup (webauthn/register-backup-key primary-state {:backup-seed backup-seed})
          recovered (webauthn/recover-from-backup-key backup-seed)]
      (is (some? (get-in with-backup [:backup-key :public-hex])))
      (is (= :parked (get-in with-backup [:backup-key :yubico-enrollment])))
      (is (some? (:public-key recovered)))))

  (testing "Non-extractable WebCrypto key specification and warning"
    (let [spec (webauthn/generate-non-extractable-keypair-spec)]
      (is (= :webcrypto-non-extractable (:key-mode spec)))
      (is (false? (:extractable? spec)))
      (is (false? (:backup-available? spec)))
      (is (str/includes? (:warning spec) "Non-extractable WebCrypto key")))))

;;; ---------------------------------------------------------------------------
;;; Human Anchor End-to-End Workflow Tests (Milestone 11A)
;;; ---------------------------------------------------------------------------

(deftest test-human-anchor-workflows
  (testing "Human-in-the-loop offer approval and denial"
    (let [st0 (anchor/init-anchor-state {:pubkey "302a300506032b65700321002222222222222222222222222222222222222222222222222222222222222222"})
          st1 (anchor/set-service-offer st0 :inference {:price 50 :burn-floor 100})
          st2 (anchor/queue-incoming-offer st1 {:offer-id "off-1" :peer-id "peer-bob" :burn 100})
          st3 (anchor/queue-incoming-offer st2 {:offer-id "off-2" :peer-id "peer-carol" :burn 100})]
      (is (= 2 (count (:pending-offers st3))))
      ;; Approve off-1
      (let [[st4 app-effects] (anchor/approve-offer st3 "off-1")]
        (is (= 1 (count (:pending-offers st4))))
        (is (= 1 (:offers-approved st4)))
        (is (= :accept-offer (:effect (first app-effects))))
        ;; Deny off-2
        (let [[st5 deny-effects] (anchor/deny-offer st4 "off-2" "price-too-low")]
          (is (= 0 (count (:pending-offers st5))))
          (is (= 1 (:offers-denied st5)))
          (is (= "price-too-low" (:last-denied-reason st5)))
          (is (= :offer-denied-by-anchor (:reason (first deny-effects))))))))

  (testing "Supervised agent registration, activity tracking, and emergency DAC revocation"
    (let [cold-kp (crypto/generate-keypair)
          hot-kp (crypto/generate-keypair)
          anchor-pub (basalt/bytes->hex (:public-key cold-kp))
          agent-pub (basalt/bytes->hex (:public-key hot-kp))
          st0 (anchor/init-anchor-state {:pubkey anchor-pub}
                                        {:privkey-bytes (:private-key cold-kp)})
          st1 (assoc (anchor/register-supervised-agent st0 {:agent-id "agent-worker-1"
                                                            :hot-pubkey agent-pub
                                                            :max-spend 5000})
                     :privkey-bytes (:private-key cold-kp))
          st2 (anchor/log-agent-activity st1 "agent-worker-1" {:type :offer-accepted :offer-id "off-abc"})
          dashboard (anchor/anchor-dashboard-view st2)]
      (is (= :active (get-in st2 [:supervised-agents "agent-worker-1" :status])))
      (is (= 1 (count (get-in st2 [:supervised-agents "agent-worker-1" :activity-log]))))
      (is (some? (get-in dashboard [:supervised-agents "agent-worker-1" :dac-id])))

      ;; Emergency DAC revocation
      (let [[st3 rev-effects] (anchor/revoke-agent-dac st2 "agent-worker-1" "compromised-key")]
        (is (= :revoked (get-in st3 [:supervised-agents "agent-worker-1" :status])))
        (is (some? (get-in st3 [:supervised-agents "agent-worker-1" :revocation])))
        (is (= 2 (count rev-effects)))
        (is (= :supervised-agent-dac-revoked (:reason (first rev-effects))))
        (is (= :broadcast-dac-revocation (:effect (second rev-effects)))))))

  (testing "Team-call subnet creation and presentation dashboard"
    (let [st0 (anchor/init-anchor-state {:pubkey "302a300506032b65700321003333333333333333333333333333333333333333333333333333333333333333"})
          st1 (anchor/create-team-call-subnet st0 {:topic-name "standup-alpha" :peers ["alice" "bob"]})
          dashboard (anchor/anchor-dashboard-view st1)]
      (is (some? (:team-call-subnet dashboard)))
      (is (= "team-call/standup-alpha" (get-in dashboard [:team-call-subnet :subnet-id])))
      (is (= "UNVERIFIED" (get-in dashboard [:fido-authenticator :label])))
      (is (str/starts-with? (get-in dashboard [:identity :address]) "ech1")))))
