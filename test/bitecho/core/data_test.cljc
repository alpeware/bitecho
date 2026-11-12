(ns bitecho.core.data-test
  "Cross-runtime (JVM + Node/CLJS) generative and unit tests for `bitecho.core.data`
   (Blob content-addressed store, pinning/LRU/hot-RAM cache-miss effects, and
   Pointer canonical signing, path-prefix ACLs, typed proofs, leader-term fencing, and tombstones)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(def ^:private gen-bytes
  (gen/fmap (fn [bs]
              #?(:clj (byte-array (map unchecked-byte bs))
                 :cljs (js/Uint8Array. (clj->js bs))))
            (gen/vector (gen/choose 0 255) 1 64)))

(def ^:private gen-media-type
  (gen/elements ["text/html" "application/fressian" "message/rfc822" "application/octet-stream"]))

;; -----------------------------------------------------------------------------
;; 1. Blob Store Generative Properties
;; -----------------------------------------------------------------------------

(defspec ^{:doc "Property: Blob CID integrity, idempotent put-blob, and fail-closed tamper rejection"}
  prop-blob-store-idempotence-and-cid-integrity 50
  (prop/for-all [payload gen-bytes
                 media-type gen-media-type]
                (let [blob (data/make-blob payload media-type)
                      expected-cid (basalt/bytes->hex (crypto/sha256 payload))
                      st0 (data/init-blob-store {:max-unpinned-bytes 65536 :max-hot-bytes 65536})
                      res1 (data/put-blob st0 blob 1000)
                      res2 (data/put-blob (:store res1) blob 1001)
                      bad-blob (assoc blob :blob/cid (apply str (repeat 64 "0")))
                      res-bad (data/put-blob (:store res2) bad-blob 1002)
                      got (data/get-blob (:store res2) expected-cid {:subnet "s1" :now-ms 1003})]
                  (and (= expected-cid (:blob/cid blob))
                       (:ok? res1)
                       (empty? (:effects res1))
                       (:ok? res2)
                       (= (get-in res1 [:store :unpinned-bytes])
                          (get-in res2 [:store :unpinned-bytes]))
                       (false? (:ok? res-bad))
                       (= :blob-cid-mismatch (get-in (first (:effects res-bad)) [:reason]))
                       (= 1 (get-in res-bad [:store :diagnostics :cid-mismatch]))
                       (:hit? got)
                       (= (fressian/bytes->hex payload)
                          (fressian/bytes->hex (get-in got [:blob :blob/bytes])))))))

(defspec ^{:doc "Property: Pinned Blobs survive unpinned LRU eviction; cold-evicted Blobs emit pure counted :fetch-blob effect"}
  prop-blob-pinning-lru-and-hot-eviction-cache-miss 50
  (prop/for-all [b1 gen-bytes
                 b2 gen-bytes
                 b3 gen-bytes]
                (let [blob1 (data/make-blob b1 "application/octet-stream")
                      blob2 (data/make-blob b2 "application/octet-stream")
                      blob3 (data/make-blob b3 "application/octet-stream")
                      distinct-cids? (= 3 (count (distinct [(:blob/cid blob1) (:blob/cid blob2) (:blob/cid blob3)])))]
                  (if-not distinct-cids?
                    true
                    (let [cap-b3 (fressian/count-bytes b3)
                          st0 (data/init-blob-store {:max-unpinned-bytes cap-b3
                                                     :max-hot-bytes cap-b3})
                          s1 (:store (data/put-blob st0 blob1 100))
              ;; Pin blob1 so it can never be logically evicted, even if pushed out of hot RAM
                          s1-pinned (data/pin-blob s1 (:blob/cid blob1))
              ;; Insert blob2 (unpinned) and blob3 (unpinned) -> blob2 should be LRU-evicted, blob1 stays pinned (cold)
                          s2 (:store (data/put-blob s1-pinned blob2 200))
                          s3 (:store (data/put-blob s2 blob3 300))
              ;; Reading pinned-but-cold blob1 emits pure counted :fetch-blob effect
                          read-pinned (data/get-blob s3 (:blob/cid blob1) {:subnet "bitecho.org/infra" :now-ms 400})
                          eff (first (:effects read-pinned))
              ;; Fulfill cache miss via put-blob re-entry -> restores hot bytes while keeping pin count = 1
                          s4 (:store (data/put-blob (:store read-pinned) blob1 500))
                          read-restored (data/get-blob s4 (:blob/cid blob1) {:subnet "bitecho.org/infra" :now-ms 600})]
                      (and (true? (data/blob-pinned? s3 (:blob/cid blob1)))
                           (false? (data/has-blob? s3 (:blob/cid blob2)))
                           (true? (data/has-blob? s3 (:blob/cid blob3)))
                           (false? (:hit? read-pinned))
                           (= :fetch-blob (:effect eff))
                           (= (:blob/cid blob1) (:cid eff))
                           (true? (:pinned? eff))
                           (= 1 (get-in read-pinned [:store :diagnostics :cache-misses]))
                           (:hit? read-restored)
                           (true? (data/blob-pinned? s4 (:blob/cid blob1)))))))))

;; -----------------------------------------------------------------------------
;; 2. Pointer Signing, Path-Prefix ACL, Fencing, and Tombstone Properties
;; -----------------------------------------------------------------------------

(deftest test-pointer-path-acl-and-self-gating
  (testing "G4a & G4b: :self proof is strictly gated by :subnet/path-acl; unauthorized authority is rejected fail-closed"
    (let [domain-kp (crypto/generate-keypair)
          cluster-kp (crypto/generate-keypair)
          alice-kp (crypto/generate-keypair)
          mallory-kp (crypto/generate-keypair)
          domain-pub (basalt/bytes->hex (:public domain-kp))
          cluster-pub (basalt/bytes->hex (:public cluster-kp))
          alice-pub (basalt/bytes->hex (:public alice-kp))
          mallory-pub (basalt/bytes->hex (:public mallory-kp))
          path-acl [{:pattern "bootstrap" :principal {:type :pubkey :pubkey cluster-pub}}
                    {:pattern "dns/*" :principal {:type :pubkey :pubkey domain-pub}}
                    {:pattern "homeset/<pubkey>" :principal {:type :self-path-owner}}
                    {:pattern "head/<pubkey>/*" :principal {:type :self-path-owner}}]
          ctx {:subnet "bitecho.org/infra"
               :path-acl path-acl
               :admitted-members #{domain-pub cluster-pub alice-pub mallory-pub}
               :now-ms 1000000}
          target-cid (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "zone-record")))
          ;; 1. Domain key signs dns/A/ns1 with :self -> valid
          valid-dns (data/sign-pointer (:private domain-kp)
                                       {:pointer/authority domain-pub
                                        :pointer/subnet "bitecho.org/infra"
                                        :pointer/path "dns/A/ns1"
                                        :pointer/seq 1
                                        :pointer/target target-cid
                                        :pointer/proof {:proof/type :self}})
          ;; 2. Mallory attempts :self on dns/A/ns1 -> rejected by path-acl!
          bad-dns (data/sign-pointer (:private mallory-kp)
                                     {:pointer/authority mallory-pub
                                      :pointer/subnet "bitecho.org/infra"
                                      :pointer/path "dns/A/ns1"
                                      :pointer/seq 2
                                      :pointer/target target-cid
                                      :pointer/proof {:proof/type :self}})
          ;; 3. Alice signs her own head/<alice>/chat -> valid; Mallory signing head/<alice>/chat -> rejected!
          valid-head (data/sign-pointer (:private alice-kp)
                                        {:pointer/authority alice-pub
                                         :pointer/subnet "bitecho.org/infra"
                                         :pointer/path (str "head/" alice-pub "/chat")
                                         :pointer/seq 1
                                         :pointer/target target-cid
                                         :pointer/proof {:proof/type :self}})
          spoof-head (data/sign-pointer (:private mallory-kp)
                                        {:pointer/authority mallory-pub
                                         :pointer/subnet "bitecho.org/infra"
                                         :pointer/path (str "head/" alice-pub "/chat")
                                         :pointer/seq 2
                                         :pointer/target target-cid
                                         :pointer/proof {:proof/type :self}})
          ;; 4. Cluster key signs bootstrap -> valid
          valid-boot (data/sign-pointer (:private cluster-kp)
                                        {:pointer/authority cluster-pub
                                         :pointer/subnet "bitecho.org/infra"
                                         :pointer/path "bootstrap"
                                         :pointer/seq 1
                                         :pointer/target target-cid
                                         :pointer/proof {:proof/type :self}})]
      (is (:ok? (data/verify-pointer valid-dns ctx)))
      (let [r-bad (data/verify-pointer bad-dns ctx)]
        (is (false? (:ok? r-bad)))
        (is (= :unauthorized-pointer-authority (:error r-bad))))
      (is (:ok? (data/verify-pointer valid-head ctx)))
      (is (false? (:ok? (data/verify-pointer spoof-head ctx))))
      (is (:ok? (data/verify-pointer valid-boot ctx))))))

(defspec ^{:doc "Property: Leader-term lexicographic fencing blocks stale split-brain leaders and tombstones unpin & allow higher-seq recreation"}
  prop-pointer-leader-term-fencing-and-tombstones 40
  (prop/for-all [b1 gen-bytes
                 b2 gen-bytes
                 seq1 (gen/choose 1 100)
                 stale-high-seq (gen/choose 500 5000)]
                (let [leader1-kp (crypto/generate-keypair)
                      leader2-kp (crypto/generate-keypair)
                      l1-pub (basalt/bytes->hex (:public leader1-kp))
                      l2-pub (basalt/bytes->hex (:public leader2-kp))
                      blob1 (data/make-blob b1 "application/octet-stream")
                      blob2 (data/make-blob b2 "application/octet-stream")
                      path-acl [{:pattern "tls/*" :principal {:type :leader}}]
                      st0 (-> (data/init-data-state {:max-unpinned-bytes 65536 :max-hot-bytes 65536})
                              (data/put-data-blob blob1 100)
                              :state
                              (data/put-data-blob blob2 101)
                              :state)
                      ctx-t2 {:subnet "bitecho.org/infra"
                              :path-acl path-acl
                              :leader-pubkeys #{l1-pub l2-pub}
                              :current-leader l2-pub
                              :min-leader-term 2
                              :now-ms 10000}
          ;; Leader 2 publishes at term 2, seq = seq1 -> pins blob1
                      p-live (data/sign-pointer (:private leader2-kp)
                                                {:pointer/authority l2-pub
                                                 :pointer/subnet "bitecho.org/infra"
                                                 :pointer/path "tls/current-cert"
                                                 :pointer/leader-term 2
                                                 :pointer/seq seq1
                                                 :pointer/target (:blob/cid blob1)
                                                 :pointer/proof {:proof/type :cert
                                                                 :fingerprint (:blob/cid blob1)}})
                      r1 (data/apply-pointer st0 p-live ctx-t2)
          ;; Stale split-brain Leader 1 publishes at term 1, seq = 5000 -> MUST be fenced out!
                      p-stale-leader (data/sign-pointer (:private leader1-kp)
                                                        {:pointer/authority l1-pub
                                                         :pointer/subnet "bitecho.org/infra"
                                                         :pointer/path "tls/current-cert"
                                                         :pointer/leader-term 1
                                                         :pointer/seq stale-high-seq
                                                         :pointer/target (:blob/cid blob2)
                                                         :pointer/proof {:proof/type :cert
                                                                         :fingerprint (:blob/cid blob2)}})
                      r-fenced (data/apply-pointer (:state r1) p-stale-leader (dissoc ctx-t2 :current-leader :min-leader-term))
          ;; Tombstone (:pointer/target nil) at term 2, seq = seq1 + 1 -> unpins blob1!
                      p-tomb (data/sign-pointer (:private leader2-kp)
                                                {:pointer/authority l2-pub
                                                 :pointer/subnet "bitecho.org/infra"
                                                 :pointer/path "tls/current-cert"
                                                 :pointer/leader-term 2
                                                 :pointer/seq (inc seq1)
                                                 :pointer/target nil
                                                 :pointer/proof {:proof/type :self}})
                      r-tomb (data/apply-pointer (:state r-fenced) p-tomb ctx-t2)
          ;; Re-create after tombstone at term 2, seq = seq1 + 2 -> pins blob2!
                      p-recreate (data/sign-pointer (:private leader2-kp)
                                                    {:pointer/authority l2-pub
                                                     :pointer/subnet "bitecho.org/infra"
                                                     :pointer/path "tls/current-cert"
                                                     :pointer/leader-term 2
                                                     :pointer/seq (+ seq1 2)
                                                     :pointer/target (:blob/cid blob2)
                                                     :pointer/proof {:proof/type :cert
                                                                     :fingerprint (:blob/cid blob2)}})
                      r-recreated (data/apply-pointer (:state r-tomb) p-recreate ctx-t2)]
                  (and (:applied? r1)
                       (data/blob-pinned? (get-in r1 [:state :blobs]) (:blob/cid blob1))
                       (false? (:applied? r-fenced))
                       (= (:blob/cid blob1) (:pointer/target (data/resolve-pointer (:state r-fenced) "bitecho.org/infra" "tls/current-cert")))
                       (:applied? r-tomb)
                       (nil? (data/resolve-pointer (:state r-tomb) "bitecho.org/infra" "tls/current-cert"))
                       (or (= (:blob/cid blob1) (:blob/cid blob2))
                           (false? (data/blob-pinned? (get-in r-tomb [:state :blobs]) (:blob/cid blob1))))
                       (:applied? r-recreated)
                       (= (:blob/cid blob2) (:pointer/target (data/resolve-pointer (:state r-recreated) "bitecho.org/infra" "tls/current-cert")))
                       (data/blob-pinned? (get-in r-recreated [:state :blobs]) (:blob/cid blob2))))))

(deftest test-pointer-pop-rotation-quorum-and-acme-expiry-skew
  (testing "G4 & G7: :pop with rotation signature, :quorum 2-of-3 threshold, and ACME 60s vs default 5m expiry skew"
    (let [dir-kp (crypto/generate-keypair)
          old-agent-kp (crypto/generate-keypair)
          new-agent-kp (crypto/generate-keypair)
          v1-kp (crypto/generate-keypair)
          v2-kp (crypto/generate-keypair)
          v3-kp (crypto/generate-keypair)
          leader-kp (crypto/generate-keypair)
          dir-pub (basalt/bytes->hex (:public dir-kp))
          old-pub (basalt/bytes->hex (:public old-agent-kp))
          new-pub (basalt/bytes->hex (:public new-agent-kp))
          v1-pub (basalt/bytes->hex (:public v1-kp))
          v2-pub (basalt/bytes->hex (:public v2-kp))
          v3-pub (basalt/bytes->hex (:public v3-kp))
          leader-pub (basalt/bytes->hex (:public leader-kp))
          desc-cid (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "agent-desc")))
          boot-cid (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "boot-blob")))
          acme-cid (basalt/bytes->hex (crypto/sha256 (fressian/utf8->bytes "tok.thumb")))
          ;; 1. :pop proof with key-rotation continuity
          pop-proof (data/create-pop-proof (:private new-agent-kp) new-pub
                                           dir-pub "global" "dir/axiom" desc-cid
                                           {:prev-privkey (:private old-agent-kp)
                                            :prev-pubkey old-pub})
          p-dir (data/sign-pointer (:private dir-kp)
                                   {:pointer/authority dir-pub
                                    :pointer/subnet "global"
                                    :pointer/path "dir/axiom"
                                    :pointer/seq 1
                                    :pointer/target desc-cid
                                    :pointer/proof pop-proof})
          ;; 2. :quorum 2-of-3 proof on bootstrap
          quorum-proof (data/create-quorum-proof [{:pubkey v1-pub :privkey (:private v1-kp)}
                                                  {:pubkey v2-pub :privkey (:private v2-kp)}]
                                                 "global" "bootstrap" 1 boot-cid)
          p-boot (data/sign-pointer (:private v1-kp)
                                    {:pointer/authority v1-pub
                                     :pointer/subnet "global"
                                     :pointer/path "bootstrap"
                                     :pointer/seq 1
                                     :pointer/target boot-cid
                                     :pointer/proof quorum-proof})
          ;; 3. Expiry skew: ACME challenge expired by 90s is rejected (> 60s skew), while normal pointer expired by 90s is accepted (< 300s skew)
          now-ms 10000000
          expired-90s (- now-ms 90000)
          p-acme (data/sign-pointer (:private leader-kp)
                                    {:pointer/authority leader-pub
                                     :pointer/subnet "bitecho.org/infra"
                                     :pointer/path "acme/challenge/tok1"
                                     :pointer/leader-term 1
                                     :pointer/seq 1
                                     :pointer/expires expired-90s
                                     :pointer/target acme-cid
                                     :pointer/proof {:proof/type :acme-key-auth
                                                     :token "tok1"
                                                     :key-auth "tok1.thumb"}})
          p-dir-skew (data/sign-pointer (:private dir-kp)
                                        {:pointer/authority dir-pub
                                         :pointer/subnet "global"
                                         :pointer/path "dir/axiom"
                                         :pointer/seq 2
                                         :pointer/expires expired-90s
                                         :pointer/target desc-cid
                                         :pointer/proof pop-proof})
          global-ctx {:subnet "global"
                      :path-acl [{:pattern "dir/*" :principal {:type :pubkey :pubkey dir-pub}}
                                 {:pattern "bootstrap" :principal {:type :quorum :threshold 2 :signers #{v1-pub v2-pub v3-pub}}}]
                      :trust-anchors #{v1-pub v2-pub v3-pub}
                      :now-ms now-ms}
          infra-ctx {:subnet "bitecho.org/infra"
                     :path-acl [{:pattern "acme/challenge/*" :principal {:type :leader}}]
                     :leader-pubkeys #{leader-pub}
                     :now-ms now-ms}]
      (is (:ok? (data/verify-pointer p-dir global-ctx)))
      (is (:ok? (data/verify-pointer p-boot global-ctx)))
      (is (false? (:ok? (data/verify-pointer p-acme infra-ctx))) "ACME challenge 90s past expiry exceeds 60s tolerance")
      (is (:ok? (data/verify-pointer p-dir-skew global-ctx)) "Directory pointer 90s past expiry within 5m tolerance"))))

(deftest test-f2-semantic-proof-verifiers
  (testing "F2: :cert, :acme-key-auth, and :dac proof verifiers enforce semantic checks against context and target Blobs"
    (let [leader-kp (crypto/generate-keypair)
          anchor-kp (crypto/generate-keypair)
          agent-kp (crypto/generate-keypair)
          leader-pub (basalt/bytes->hex (:public leader-kp))
          anchor-pub (basalt/bytes->hex (:public anchor-kp))
          agent-pub (basalt/bytes->hex (:public agent-kp))
          ;; 1. Semantic :cert fingerprint verification against PEM leaf certificate DER in target Blob
          fake-cert-der (fressian/utf8->bytes "mock-x509-leaf-der-bytes-for-semantic-fingerprint-test")
          cert-fp (basalt/bytes->hex (crypto/sha256 fake-cert-der))
          wrong-fp (apply str (repeat 64 "a"))
          cert-pem (str "-----BEGIN CERTIFICATE-----\n"
                        "bW9jay14NTA5LWxlYWYtZGVyLWJ5dGVzLWZvci1zZW1hbnRpYy1maW5nZXJwcmludC10ZXN0\n"
                        "-----END CERTIFICATE-----\n")
          cert-blob (data/make-blob (fressian/encode-canonical {:cert-pem cert-pem}) "application/fressian")
          blobs-with-cert (:store (data/put-blob (data/init-blob-store) cert-blob 1000))
          valid-cert-ptr (data/sign-pointer (:private leader-kp)
                                            {:pointer/authority leader-pub
                                             :pointer/subnet "bitecho.org/infra"
                                             :pointer/path "tls/current-cert"
                                             :pointer/leader-term 1
                                             :pointer/seq 1
                                             :pointer/target (:blob/cid cert-blob)
                                             :pointer/proof {:proof/type :cert :fingerprint cert-fp}})
          bad-cert-ptr (data/sign-pointer (:private leader-kp)
                                          {:pointer/authority leader-pub
                                           :pointer/subnet "bitecho.org/infra"
                                           :pointer/path "tls/current-cert"
                                           :pointer/leader-term 1
                                           :pointer/seq 2
                                           :pointer/target (:blob/cid cert-blob)
                                           :pointer/proof {:proof/type :cert :fingerprint wrong-fp}})
          ;; 2. Semantic :acme-key-auth verification against path token, :acme-thumbprint, and target Blob
          acme-blob (data/make-blob (fressian/utf8->bytes "tok42.expected-thumb") "application/octet-stream")
          blobs-all (:store (data/put-blob blobs-with-cert acme-blob 1001))
          valid-acme-ptr (data/sign-pointer (:private leader-kp)
                                            {:pointer/authority leader-pub
                                             :pointer/subnet "bitecho.org/infra"
                                             :pointer/path "acme/challenge/tok42"
                                             :pointer/leader-term 1
                                             :pointer/seq 1
                                             :pointer/target (:blob/cid acme-blob)
                                             :pointer/proof {:proof/type :acme-key-auth
                                                             :token "tok42"
                                                             :key-auth "tok42.expected-thumb"}})
          wrong-thumb-acme-ptr (data/sign-pointer (:private leader-kp)
                                                  {:pointer/authority leader-pub
                                                   :pointer/subnet "bitecho.org/infra"
                                                   :pointer/path "acme/challenge/tok42"
                                                   :pointer/leader-term 1
                                                   :pointer/seq 2
                                                   :pointer/target (:blob/cid acme-blob)
                                                   :pointer/proof {:proof/type :acme-key-auth
                                                                   :token "tok42"
                                                                   :key-auth "tok42.wrong-thumb"}})
          wrong-path-acme-ptr (data/sign-pointer (:private leader-kp)
                                                 {:pointer/authority leader-pub
                                                  :pointer/subnet "bitecho.org/infra"
                                                  :pointer/path "acme/challenge/other-tok"
                                                  :pointer/leader-term 1
                                                  :pointer/seq 3
                                                  :pointer/target (:blob/cid acme-blob)
                                                  :pointer/proof {:proof/type :acme-key-auth
                                                                  :token "tok42"
                                                                  :key-auth "tok42.expected-thumb"}})
          ;; 3. Semantic :dac capability subset & path-agent binding verification
          dac-blob (data/make-blob (fressian/encode-canonical {:agent-pubkey agent-pub
                                                               :scopes ["send" "offer"]})
                                   "application/fressian")
          blobs-with-dac (:store (data/put-blob blobs-all dac-blob 1002))
          valid-dac-ptr (data/sign-pointer (:private anchor-kp)
                                           {:pointer/authority anchor-pub
                                            :pointer/subnet "global"
                                            :pointer/path (str "dac/" agent-pub)
                                            :pointer/seq 1
                                            :pointer/target (:blob/cid dac-blob)
                                            :pointer/proof {:proof/type :dac
                                                            :agent-pubkey agent-pub
                                                            :capabilities ["send"]}})
          escalated-dac-ptr (data/sign-pointer (:private anchor-kp)
                                               {:pointer/authority anchor-pub
                                                :pointer/subnet "global"
                                                :pointer/path (str "dac/" agent-pub)
                                                :pointer/seq 2
                                                :pointer/target (:blob/cid dac-blob)
                                                :pointer/proof {:proof/type :dac
                                                                :agent-pubkey agent-pub
                                                                :capabilities ["send" "admin-root"]}})
          infra-ctx {:subnet "bitecho.org/infra"
                     :path-acl [{:pattern "tls/*" :principal {:type :leader}}
                                {:pattern "acme/challenge/*" :principal {:type :leader}}]
                     :leader-pubkeys #{leader-pub}
                     :acme-thumbprint "expected-thumb"
                     :blobs blobs-with-dac
                     :now-ms 5000}
          dac-ctx {:subnet "global"
                   :path-acl [{:pattern "dac/*" :principal {:type :pubkey :pubkey anchor-pub}}]
                   :allowed-dac-capabilities #{"send" "offer" "relay"}
                   :blobs blobs-with-dac
                   :now-ms 5000}]
      (is (:ok? (data/verify-pointer valid-cert-ptr infra-ctx)))
      (is (= :cert-fingerprint-mismatch (:error (data/verify-pointer bad-cert-ptr infra-ctx))))
      ;; F-Relay-3: verify-pointer :cert fails closed when blob is missing or malformed
      (is (= :missing-cert-blob (:error (data/verify-pointer valid-cert-ptr (assoc infra-ctx :blobs (data/init-blob-store))))))
      (let [malformed-blob (data/make-blob (fressian/encode-canonical {:other "data"}) "application/fressian")
            blobs-with-malformed (:store (data/put-blob (data/init-blob-store) malformed-blob 1000))
            ptr-to-malformed (data/sign-pointer (:private leader-kp)
                                                {:pointer/authority leader-pub
                                                 :pointer/subnet "bitecho.org/infra"
                                                 :pointer/path "tls/current-cert"
                                                 :pointer/leader-term 1
                                                 :pointer/seq 1
                                                 :pointer/epoch 100
                                                 :pointer/target (:blob/cid malformed-blob)
                                                 :pointer/proof {:proof/type :cert :fingerprint cert-fp}})]
        (is (= :cert-fingerprint-mismatch (:error (data/verify-pointer ptr-to-malformed (assoc infra-ctx :blobs blobs-with-malformed))))))
      (is (:ok? (data/verify-pointer valid-acme-ptr infra-ctx)))
      (is (= :invalid-acme-proof (:error (data/verify-pointer wrong-thumb-acme-ptr infra-ctx))))
      (is (= :invalid-acme-proof (:error (data/verify-pointer wrong-path-acme-ptr infra-ctx))))
      (is (:ok? (data/verify-pointer valid-dac-ptr dac-ctx)))
      (is (= :dac-capability-escalation (:error (data/verify-pointer escalated-dac-ptr dac-ctx)))))))
