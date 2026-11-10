(ns bitecho.core.protocol-test
  "Cross-runtime (JVM + Node/CLJS) generative `test.check` and unit tests for
   Unification Phase B pure Sans-IO protocol codecs:
   - `bitecho.core.protocol.dns` (RFC 1035 packet codec, Subnet-backed zone resolver, G8 liveness/fallback, token-bucket RRL, & :443 stream classifier)
   - `bitecho.core.protocol.smtp` (RFC 5321 session state machine, open-relay block, size limits, dot-unstuffing, STARTTLS)
   - `bitecho.core.protocol.acme` (RFC 4648 Base64URL, PEM DER extraction, RFC 7638 JWK thumbprint, RFC 8555 key-auth/DNS-01/JWS, PKCS#10 DER CSR, renewal backoff)"
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.core.protocol.acme :as acme]
            [bitecho.core.protocol.dns :as dns]
            [bitecho.core.protocol.smtp :as smtp]
            [bitecho.core.subnet :as subnet]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; 1. Generators for DNS, SMTP, and ACME Pure Codecs
;; =============================================================================

(def ^:private gen-label
  (gen/fmap #(apply str %)
            (gen/vector (gen/elements (vec "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")) 1 10)))

(def ^:private gen-domain
  (gen/fmap #(str/join "." %)
            (gen/vector gen-label 2 4)))

(def ^:private gen-ipv4
  (gen/fmap (fn [[a b c d]] (str a "." b "." c "." d))
            (gen/tuple (gen/choose 1 223) (gen/choose 0 255) (gen/choose 0 255) (gen/choose 1 254))))

(def ^:private gen-bytes
  (gen/fmap (fn [bs]
              #?(:clj (byte-array (map unchecked-byte bs))
                 :cljs (js/Uint8Array. (clj->js bs))))
            (gen/vector (gen/choose 0 255) 0 96)))

;; =============================================================================
;; 2. `bitecho.core.protocol.dns` Generative & Unit Tests
;; =============================================================================

(defspec ^{:doc "Property: RFC 1035 DNS packet encode/decode round-trip preserves 0x20 casing, compression, and record types"}
  prop-dns-packet-codec-roundtrip 50
  (prop/for-all [tx-id (gen/choose 0 65535)
                 qname gen-domain
                 ip4 gen-ipv4
                 ttl (gen/choose 1 86400)
                 txt-val gen-label]
                (let [pkt {:id tx-id
                           :qr? true
                           :opcode 0
                           :aa? true
                           :tc? false
                           :rd? true
                           :ra? false
                           :z 0
                           :rcode :noerror
                           :questions [{:qname qname :qtype :A :qclass :IN}]
                           :answers [{:name qname :type :A :class :IN :ttl ttl :rdata ip4}
                                     {:name qname :type :TXT :class :IN :ttl ttl :rdata [txt-val]}
                                     {:name qname :type :AAAA :class :IN :ttl ttl :rdata "2001:db8::1"}]
                           :authority [{:name qname
                                        :type :SOA
                                        :class :IN
                                        :ttl ttl
                                        :rdata {:mname (str "ns1." qname)
                                                :rname (str "hostmaster." qname)
                                                :serial 2026110901
                                                :refresh 3600
                                                :retry 600
                                                :expire 604800
                                                :minimum 60}}]
                           :additional []}
                      wire (dns/encode-packet pkt)
                      decoded (dns/decode-packet wire)
                      trunc-wire (dns/encode-packet pkt {:max-bytes 40})
                      trunc-dec (dns/decode-packet trunc-wire)]
                  (and (= tx-id (:id decoded))
                       (= qname (get-in decoded [:questions 0 :qname]))
                       (= ip4 (get-in decoded [:answers 0 :rdata]))
                       (= [txt-val] (get-in decoded [:answers 1 :rdata]))
                       (= "2001:db8::1" (get-in decoded [:answers 2 :rdata]))
                       (= 2026110901 (get-in decoded [:authority 0 :rdata :serial]))
                       (:tc? trunc-dec)
                       (empty? (:answers trunc-dec))))))

(deftest test-dns-subnet-zone-resolver-and-g8-liveness-fallback
  (testing "Gap G8 & Subnet DNS Pointers: resolves healthy multi-A IPs, falls back to all configured static IPs when healthy set is empty, and serves dynamic dns/* and acme/challenge/* Pointers"
    (let [leader-kp (crypto/generate-keypair)
          domain-kp (crypto/generate-keypair)
          leader-pub (basalt/bytes->hex (:public leader-kp))
          domain-pub (basalt/bytes->hex (:public domain-kp))
          policy {:subnet/id "bitecho.org/infra"
                  :subnet/parent-id "global"
                  :subnet/gate {:gate/mode :permissioned
                                :gate/admission :allowlist
                                :gate/trust-anchors #{leader-pub domain-pub}}
                  :subnet/path-acl [{:pattern "dns/*" :principal {:type :pubkey :pubkey domain-pub}}
                                    {:pattern "acme/challenge/*" :principal {:type :leader}}]
                  :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                  :subnet/replication {:replication/pointers :leader-election
                                       :replication/blobs :eager-push}}
          inst0 (:instance (subnet/init-subnet-instance policy {:node-id :ns1
                                                                :all-nodes #{:ns1 :ns2 :ns3}
                                                                :now-ms 1000}))
          ;; Bring :ns2 online -> healthy-nodes #{:ns1 :ns2}, :ns1 elected leader at term 1
          inst1 (-> (:state (subnet/reduce-subnet inst0 {:type :leader-heartbeat :from :ns2 :term 0 :now-ms 1100}))
                    (assoc-in [:leader-election :leader-id] leader-pub)
                    (assoc-in [:leader-election :term] 1))
          ;; Publish dynamic delegated ingress record: dns/A/nexus.ingress -> ["203.0.113.77"]
          nexus-blob (data/make-blob (fressian/encode-canonical {:records ["203.0.113.77"] :ttl 45}) "application/fressian")
          inst2 (:state (subnet/reduce-subnet inst1 {:type :put-blob :sender domain-pub :blob nexus-blob :now-ms 1200}))
          nexus-ptr (data/sign-pointer (:private domain-kp)
                                       {:pointer/authority domain-pub
                                        :pointer/subnet "bitecho.org/infra"
                                        :pointer/path "dns/A/nexus.ingress"
                                        :pointer/seq 1
                                        :pointer/target (:blob/cid nexus-blob)
                                        :pointer/proof {:proof/type :zone :serial 1}})
          inst3 (:state (subnet/reduce-subnet inst2 {:type :publish-pointer :sender domain-pub :pointer nexus-ptr :now-ms 1250}))
          ;; Publish ACME challenge Pointer: acme/challenge/tok99 -> DNS-01 TXT value
          acme-blob (data/make-blob (fressian/encode-canonical {:token "tok99"
                                                                :key-auth "tok99.thumb99"
                                                                :dns-txt "dns01-digest-val"})
                                    "application/fressian")
          inst4 (:state (subnet/reduce-subnet inst3 {:type :put-blob :sender leader-pub :blob acme-blob :now-ms 1300}))
          acme-ptr (data/sign-pointer (:private leader-kp)
                                      {:pointer/authority leader-pub
                                       :pointer/subnet "bitecho.org/infra"
                                       :pointer/path "acme/challenge/tok99"
                                       :pointer/leader-term 1
                                       :pointer/seq 1
                                       :pointer/expires 900000
                                       :pointer/target (:blob/cid acme-blob)
                                       :pointer/proof {:proof/type :acme-key-auth
                                                       :token "tok99"
                                                       :key-auth "tok99.thumb99"}})
          inst5 (:state (subnet/reduce-subnet inst4 {:type :publish-pointer :sender leader-pub :pointer acme-ptr :now-ms 1350}))
          cfg {:domain "bitecho.org"
               :dns {:ttl-seconds 60 :subdomains #{"www"}}
               :cluster {:nodes {:ns1 {:ip4 "34.19.71.246"}
                                 :ns2 {:ip4 "34.56.253.255"}
                                 :ns3 {:ip4 "136.108.244.159"}}}}
          ;; 1. Apex A query with :ns1 & :ns2 healthy -> returns only those 2 IPs (excludes dead :ns3)
          apex-resp (dns/resolve-query cfg inst5 {:id 10 :rd? true :questions [{:qname "BiTeChO.oRg" :qtype :A :qclass :IN}]} 2000)
          ;; 2. Empty healthy set -> fail-safe fallback returns all 3 configured static node IPs!
          empty-healthy-inst (assoc-in inst5 [:leader-election :healthy-nodes] #{})
          fallback-resp (dns/resolve-query cfg empty-healthy-inst {:id 11 :rd? true :questions [{:qname "bitecho.org" :qtype :A :qclass :IN}]} 2000)
          ;; 3. Dynamic Pointer record: nexus.ingress.bitecho.org -> 203.0.113.77 (TTL 45)
          nexus-resp (dns/resolve-query cfg inst5 {:id 12 :rd? true :questions [{:qname "nexus.ingress.bitecho.org" :qtype :A :qclass :IN}]} 2000)
          ;; 4. Dynamic ACME DNS-01 TXT record via acme/challenge/* Pointer
          acme-txt-resp (dns/resolve-query cfg inst5 {:id 13 :rd? false :questions [{:qname "_acme-challenge.bitecho.org" :qtype :TXT :qclass :IN}]} 2000)
          ;; 5. Out-of-zone query -> REFUSED + :ra? false
          refused-resp (dns/resolve-query cfg inst5 {:id 14 :rd? true :questions [{:qname "example.com" :qtype :A :qclass :IN}]} 2000)]
      (is (= :noerror (:rcode apex-resp)))
      (is (= "BiTeChO.oRg" (get-in apex-resp [:answers 0 :name])) "0x20 casing preserved")
      (is (= #{"34.19.71.246" "34.56.253.255"} (set (map :rdata (:answers apex-resp)))))
      (is (= #{"34.19.71.246" "34.56.253.255" "136.108.244.159"}
             (set (map :rdata (:answers fallback-resp))))
          "Empty healthy-set must fall back to all configured static IPs")
      (is (= ["203.0.113.77"] (mapv :rdata (:answers nexus-resp))))
      (is (= 45 (get-in nexus-resp [:answers 0 :ttl])))
      (is (= [["dns01-digest-val"]] (mapv :rdata (:answers acme-txt-resp))))
      (is (= :refused (:rcode refused-resp)))
      (is (false? (:ra? refused-resp))))))

(defspec ^{:doc "Property (M3 Step 15B): Delegated *.ingress.<domain> zones return RFC 1035 non-authoritative NS + glue A referrals for all child queries and direct A answers for the glue host"}
  prop-dns-delegated-ingress-referral 50
  (prop/for-all [agent-label gen-label
                 child-label (gen/elements [nil "_acme-challenge" "sub" "ech1test"])
                 qtype (gen/elements [:A :AAAA :TXT :NS :CAA])
                 glue-ip gen-ipv4
                 ttl (gen/choose 30 600)]
                (let [domain "bitecho.org"
                      subzone (str (str/lower-case agent-label) ".ingress")
                      zone-fqdn (str subzone "." domain)
                      ns-host (str "ns1." zone-fqdn)
                      cfg {:domain domain
                           :dns {:ttl-seconds ttl
                                 :delegated-ingress {subzone {:ns ns-host
                                                              :ip4 glue-ip
                                                              :ttl ttl}}}
                           :cluster {:nodes {:ns1 {:ip4 "34.19.71.246"}}}}
                      target-qname (if child-label
                                     (str child-label "." zone-fqdn)
                                     zone-fqdn)
                      ref-resp (dns/resolve-query cfg {} {:id 77 :rd? true :questions [{:qname target-qname :qtype qtype :qclass :IN}]} 2000)
                      glue-resp (dns/resolve-query cfg {} {:id 78 :rd? true :questions [{:qname ns-host :qtype :A :qclass :IN}]} 2000)]
                  (and (= :noerror (:rcode ref-resp))
                       (false? (:aa? ref-resp))
                       (empty? (:answers ref-resp))
                       (= [{:name zone-fqdn :type :NS :class :IN :ttl ttl :rdata ns-host}]
                          (:authority ref-resp))
                       (= [{:name ns-host :type :A :class :IN :ttl ttl :rdata glue-ip}]
                          (:additional ref-resp))
                       (= :noerror (:rcode glue-resp))
                       (= [{:name ns-host :type :A :class :IN :ttl ttl :rdata glue-ip}]
                          (:answers glue-resp))))))

(deftest test-dns-delegated-ingress-subnet-pointers
  (testing "M3 Step 15B: Subnet Pointers dns/NS/nexus.ingress and dns/NS/<bech32m>.ingress emit NS + glue A referrals for zone and _acme-challenge queries"
    (let [domain-kp (crypto/generate-keypair)
          domain-pub (basalt/bytes->hex (:public domain-kp))
          bech-sub "ech1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc9778c.ingress"
          policy {:subnet/id "bitecho.org/infra"
                  :subnet/parent-id "global"
                  :subnet/gate {:gate/mode :permissioned
                                :gate/admission :allowlist
                                :gate/trust-anchors #{domain-pub}}
                  :subnet/path-acl [{:pattern "dns/*" :principal {:type :pubkey :pubkey domain-pub}}]
                  :subnet/economy {:economy/mode :none :economy/burn-floor 0 :economy/settlement-take-bps 0}
                  :subnet/replication {:replication/pointers :leader-election
                                       :replication/blobs :eager-push}}
          inst0 (:instance (subnet/init-subnet-instance policy {:node-id :ns1 :all-nodes #{:ns1} :now-ms 1000}))
          ns-blob (data/make-blob (fressian/encode-canonical {:ns "ns1.nexus.ingress.bitecho.org"
                                                              :ip4 "136.62.15.220"
                                                              :ttl 60})
                                  "application/fressian")
          bech-blob (data/make-blob (fressian/encode-canonical {:ns (str "ns1." bech-sub ".bitecho.org")
                                                                :ip4 "136.62.15.220"
                                                                :ttl 60})
                                    "application/fressian")
          inst1 (:state (subnet/reduce-subnet inst0 {:type :put-blob :sender domain-pub :blob ns-blob :now-ms 1100}))
          inst2 (:state (subnet/reduce-subnet inst1 {:type :put-blob :sender domain-pub :blob bech-blob :now-ms 1110}))
          ptr1 (data/sign-pointer (:private domain-kp)
                                  {:pointer/authority domain-pub
                                   :pointer/subnet "bitecho.org/infra"
                                   :pointer/path "dns/NS/nexus.ingress"
                                   :pointer/seq 1
                                   :pointer/target (:blob/cid ns-blob)
                                   :pointer/proof {:proof/type :zone :serial 1}})
          ptr2 (data/sign-pointer (:private domain-kp)
                                  {:pointer/authority domain-pub
                                   :pointer/subnet "bitecho.org/infra"
                                   :pointer/path (str "dns/NS/" bech-sub)
                                   :pointer/seq 1
                                   :pointer/target (:blob/cid bech-blob)
                                   :pointer/proof {:proof/type :zone :serial 2}})
          inst3 (:state (subnet/reduce-subnet inst2 {:type :publish-pointer :sender domain-pub :pointer ptr1 :now-ms 1150}))
          inst4 (:state (subnet/reduce-subnet inst3 {:type :publish-pointer :sender domain-pub :pointer ptr2 :now-ms 1160}))
          cfg {:domain "bitecho.org"
               :dns {:ttl-seconds 60}
               :cluster {:nodes {:ns1 {:ip4 "34.19.71.246"}}}}
          r-nexus-a (dns/resolve-query cfg inst4 {:id 21 :rd? true :questions [{:qname "nexus.ingress.bitecho.org" :qtype :A :qclass :IN}]} 2000)
          r-nexus-acme (dns/resolve-query cfg inst4 {:id 22 :rd? true :questions [{:qname "_acme-challenge.nexus.ingress.bitecho.org" :qtype :TXT :qclass :IN}]} 2000)
          r-bech-a (dns/resolve-query cfg inst4 {:id 23 :rd? true :questions [{:qname (str bech-sub ".bitecho.org") :qtype :A :qclass :IN}]} 2000)]
      (is (false? (:aa? r-nexus-a)))
      (is (empty? (:answers r-nexus-a)))
      (is (= "ns1.nexus.ingress.bitecho.org" (get-in r-nexus-a [:authority 0 :rdata])))
      (is (= "136.62.15.220" (get-in r-nexus-a [:additional 0 :rdata])))
      (is (false? (:aa? r-nexus-acme)))
      (is (= "ns1.nexus.ingress.bitecho.org" (get-in r-nexus-acme [:authority 0 :rdata])))
      (is (= "136.62.15.220" (get-in r-bech-a [:additional 0 :rdata]))))))

(deftest test-port-443-stream-classifier-and-rate-limiter
  (testing "Gap G17: pure port :443 classifier distinguishes RFC 4571 DTLS, RFC 4571 STUN, HTTP CONNECT, *.ingress SNI, and standard HTTPS"
    (let [dtls-frame #?(:clj (byte-array (map unchecked-byte [0x00 0x20 0x16 0xFE 0xFD 0x00]))
                        :cljs (js/Uint8Array. #js [0x00 0x20 0x16 0xFE 0xFD 0x00]))
          stun-frame #?(:clj (byte-array (map unchecked-byte [0x00 0x14 0x00 0x01 0x00 0x00 0x21 0x12 0xA4 0x42]))
                        :cljs (js/Uint8Array. #js [0x00 0x14 0x00 0x01 0x00 0x00 0x21 0x12 0xA4 0x42]))
          connect-bytes (fressian/utf8->bytes "CONNECT nexus.ingress.bitecho.org:443 HTTP/1.1\r\nHost: nexus.ingress.bitecho.org:443\r\n\r\n")
          rl0 (dns/init-limiter {:capacity 2.0 :refill-per-sec 1.0})
          r1 (dns/check-and-consume rl0 (dns/ip->subnet-key "198.51.100.42") 1.0 1000)
          r2 (dns/check-and-consume (:state r1) (dns/ip->subnet-key "198.51.100.99") 1.0 1000)
          r3 (dns/check-and-consume (:state r2) (dns/ip->subnet-key "198.51.100.7") 1.0 1000)]
      (is (true? (dns/ingress-stream? dtls-frame (fressian/count-bytes dtls-frame) "bitecho.org")))
      (is (true? (dns/ingress-stream? stun-frame (fressian/count-bytes stun-frame) "bitecho.org")))
      (is (= {:host "nexus.ingress.bitecho.org" :port 443}
             (dns/parse-http-connect-request connect-bytes (fressian/count-bytes connect-bytes))))
      (is (= "198.51.100.0/24" (dns/ip->subnet-key "198.51.100.42:54321")))
      (is (= "2001:db8:85a3:0::/64" (dns/ip->subnet-key "[2001:db8:85a3:0:1:2:3:4]:443")))
      (is (:allowed? r1))
      (is (:allowed? r2))
      (is (false? (:allowed? r3)) "Same /24 shares bucket and exhausts capacity 2.0"))))

;; =============================================================================
;; 3. `bitecho.core.protocol.smtp` Generative & Unit Tests
;; =============================================================================

(defspec ^{:doc "Property: SMTP state machine unstuffs leading dots losslessly, enforces max-message-bytes, and prevents open relay"}
  prop-smtp-dot-unstuffing-and-open-relay-prevention 40
  (prop/for-all [body-lines (gen/vector (gen/elements ["Hello Bitecho" ".leading-dot" "..double-dot" "Normal line"]) 1 8)
                 evil-domain gen-domain]
                (let [s0 (:state (smtp/greeting (smtp/init-session {:domain "bitecho.org"
                                                                    :max-message-bytes 4096
                                                                    :allowed-recipients #{"@bitecho.org"}})))
                      s1 (:state (smtp/handle-smtp-line s0 "EHLO mx.client.org"))
                      ;; Out-of-domain relay attempt -> MUST be denied with 550 + counted :diagnose!
                      s2 (:state (smtp/handle-smtp-line s1 "MAIL FROM:<alice@client.org>"))
                      relay-attempt (smtp/handle-smtp-line s2 (str "RCPT TO:<victim@" evil-domain ".invalid>"))
                      ;; Valid in-domain recipient + DATA with RFC 5321 dot-stuffing
                      s3 (:state (smtp/handle-smtp-line s2 "RCPT TO:<simon@bitecho.org>"))
                      s4 (:state (smtp/handle-smtp-line s3 "DATA"))
                      stuffed-lines (mapv #(if (str/starts-with? % ".") (str "." %) %) body-lines)
                      s5 (reduce (fn [st l] (:state (smtp/handle-smtp-line st l))) s4 stuffed-lines)
                      done (smtp/handle-smtp-line s5 ".")
                      deliver-eff (first (filter #(= :deliver-mail (:type %)) (:effects done)))
                      expected-body (str (str/join "\r\n" body-lines) "\r\n")]
                  (and (str/starts-with? (first (:responses relay-attempt)) "550")
                       (some #(= :diagnose (:effect %)) (:effects relay-attempt))
                       (= expected-body (:data-str deliver-eff))
                       (= ["simon@bitecho.org"] (:to deliver-eff))))))

;; =============================================================================
;; 4. `bitecho.core.protocol.acme` Generative & Unit Tests
;; =============================================================================

(defspec ^{:doc "Property: Pure .cljc Base64URL encode/decode round-trips arbitrary byte arrays without padding"}
  prop-acme-base64url-roundtrip 60
  (prop/for-all [bs gen-bytes]
                (let [encoded (acme/base64url-encode bs)
                      decoded (acme/base64url-decode encoded)]
                  (and (not (str/includes? encoded "="))
                       (not (str/includes? encoded "+"))
                       (not (str/includes? encoded "/"))
                       (= (fressian/bytes->hex bs) (fressian/bytes->hex decoded))))))

(deftest test-acme-jwk-thumbprint-csr-and-renewal-predicates
  (testing "RFC 7638 JWK thumbprint, RFC 8555 key-authorization & DNS-01 digest, PKCS#10 DER CSR structure, and renewal/backoff predicates"
    (let [x-bytes (fressian/utf8->bytes "0123456789abcdef0123456789abcdef")
          y-bytes (fressian/utf8->bytes "fedcba9876543210fedcba9876543210")
          jwk (acme/coords->jwk x-bytes y-bytes)
          thumb (acme/jwk->thumbprint jwk)
          key-auth (acme/key-authorization-from-thumbprint "chall-tok-1" thumb)
          dns01 (acme/dns-01-txt-from-key-auth key-auth)
          jws-in (acme/build-jws-signing-input {:nonce "n-123"
                                                :url "https://acme.example/newAccount"
                                                :jwk jwk
                                                :payload {"termsOfServiceAgreed" true}})
          jws-flat (acme/assemble-flattened-jws jws-in (fressian/utf8->bytes "fake-es256-sig"))
          ;; Mock SPKI DER (SEQUENCE) + mock ECDSA DER signature
          mock-spki (acme/der-seq [(fressian/utf8->bytes "spki")])
          csr-info (acme/build-csr-info-der ["bitecho.org" "*.ingress.bitecho.org"] mock-spki)
          csr-der (acme/assemble-csr-der csr-info (fressian/utf8->bytes "ecdsa-sig"))]
      (is (= "P-256" (get jwk "crv")))
      (is (= (str "chall-tok-1." thumb) key-auth))
      (is (= 43 (count dns01)) "SHA-256 Base64URL without padding is 43 chars")
      (is (str/includes? jws-flat "\"protected\""))
      (is (= "30" (subs (fressian/bytes->hex csr-der) 0 2)) "DER CSR outer SEQUENCE tag is 0x30")
      (is (pos? (fressian/count-bytes csr-der)))
      (is (true? (acme/needs-renewal? {:acme {:enabled? true :renew-before-days 30}}
                                      {:self-signed? true :expires-at 9999999999999}
                                      1000)))
      (is (false? (acme/needs-renewal? {:acme {:enabled? true :renew-before-days 30}}
                                       {:self-signed? false :expires-at (+ 1000 (* 60 86400000))}
                                       1000)))
      (is (= 120000 (acme/compute-backoff-ms 60000 1)))
      (is (= 240000 (acme/compute-backoff-ms 60000 2))))))
