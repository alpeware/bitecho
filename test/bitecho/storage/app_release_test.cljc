(ns bitecho.storage.app-release-test
  "Strict-TDD generative & model-based tests for BIP-017b atomic `web/app/release`
   pointer resolver, detached 2-of-3 quorum signatures, generalized SHA-384 SRI,
   strict `/app/*` CSP + COOP/COEP headers, LKG retention pin, and monotonic
   rollback dry-run (Rules 1, 2, 4, 5, 6). Runs on both JVM and CLJS Node.js."
  (:require [bitecho.crypto :as crypto]
            [bitecho.fressian :as fressian]
            [bitecho.storage.app-release :as ar]
            [bitecho.storage.chunk-constants :as cc]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

;; =============================================================================
;; Test Fixtures & Helpers
;; =============================================================================

(def ^:private signer-kps
  [(crypto/generate-keypair 101)
   (crypto/generate-keypair 102)
   (crypto/generate-keypair 103)])

(def ^:private unknown-kp
  (crypto/generate-keypair 999))

(defn- kp-hex [kp]
  (fressian/bytes->hex (:public kp)))

(def ^:private trusted-signers-set
  (set (map kp-hex signer-kps)))

(def ^:private genesis-cid
  (crypto/sha256-hex "bitecho/genesis-policy/v1:test-anchor"))

(defn- causes-sum
  [state]
  (reduce + 0 (vals (get-in state [:diagnostics :causes] {}))))

(defn- build-release-fixture
  "Constructs a complete, cryptographically valid BIP-017b release descriptor,
   detached 2-of-3 quorum signature envelope, and CID-indexed blob store."
  [{:keys [seq genesis headers-config raw-assets signers lkg-release-cid]
    :or {seq 1
         genesis genesis-cid
         headers-config (ar/default-app-headers-config)
         signers (take 2 signer-kps)}}]
  (let [hdr-bytes (cc/jcs-canonical-bytes headers-config)
        hdr-cid (crypto/sha256-hex hdr-bytes)
        built-assets
        (reduce-kv
         (fn [acc asset-path {:keys [content content-type]}]
           (let [bs (if (string? content) (fressian/utf8->bytes content) content)
                 cid (crypto/sha256-hex bs)
                 sz (fressian/count-bytes bs)
                 exec? (ar/executable-asset-path? asset-path content-type)
                 sri (when exec? (ar/compute-sri-sha384 bs))
                 meta-map (cond-> {"cid" cid
                                   "size" sz
                                   "content_type" (or content-type "application/octet-stream")}
                            sri (assoc "sri" sri))]
             (-> acc
                 (assoc-in [:assets asset-path] meta-map)
                 (assoc-in [:blobs cid] bs))))
         {:assets {} :blobs {hdr-cid hdr-bytes}}
         raw-assets)
        total-bytes (reduce + 0 (map #(get % "size") (vals (:assets built-assets))))
        release (cond-> {"version" 1
                         "seq" (long seq)
                         "genesis_anchor_cid" genesis
                         "headers_config_cid" hdr-cid
                         "bytes_at_rest" total-bytes
                         "assets" (:assets built-assets)}
                  lkg-release-cid (assoc "lkg_release_cid" lkg-release-cid))
        rcid (ar/release-cid release)
        env (ar/sign-release-envelope
             rcid
             (mapv (fn [kp] {:owner-pubkey (kp-hex kp) :privkey (:private kp)}) signers))]
    {:release release
     :release-cid rcid
     :envelope env
     :blobs (:blobs built-assets)
     :headers-cid hdr-cid
     :headers headers-config
     :bytes-at-rest total-bytes}))

(defn- make-legacy-assets
  "Builds a valid .lkg legacy dashboard asset set (index.html + legacy.js + bitecho-browser.js + .sri)."
  [version-tag]
  (let [browser-js (str "/* bitecho-browser " version-tag " */ globalThis.BitechoBrowser={version:'" version-tag "'};")
        legacy-js (str "/* legacy.js " version-tag " */ (function(){console.log('legacy " version-tag "');})();")
        browser-sri (ar/compute-sri-sha384 browser-js)
        legacy-sri (ar/compute-sri-sha384 legacy-js)
        sri-txt (str browser-sri "\nsha256-placeholder\n")
        index-html (str "<!DOCTYPE html><html><head><title>Legacy " version-tag "</title></head><body>"
                        "<script src=\"/app/bitecho-browser.js?v=" version-tag "\" integrity=\"" browser-sri "\" crossorigin=\"anonymous\"></script>"
                        "<script src=\"/app/legacy.js?v=" version-tag "\" integrity=\"" legacy-sri "\" crossorigin=\"anonymous\"></script>"
                        "</body></html>")]
    {"index.html" {:content index-html :content-type "text/html; charset=utf-8"}
     "legacy.js" {:content legacy-js :content-type "application/javascript; charset=utf-8"}
     "bitecho-browser.js" {:content browser-js :content-type "application/javascript; charset=utf-8"}
     "bitecho-browser.js.sri" {:content sri-txt :content-type "text/plain; charset=utf-8"}}))

(defn- make-hive-assets
  "Builds a valid Hive release asset set (index.html + chat.js + trace-viz.html + trace-viz.js + legacy.html + legacy.js + bitecho-browser.js + .sri + tts.wasm)."
  [version-tag]
  (let [browser-js (str "/* bitecho-browser " version-tag " */ globalThis.BitechoLightNode={apiVersion:'1.1.0'};")
        legacy-js (str "/* legacy.js " version-tag " */ (function(){console.log('legacy');})();")
        chat-js (str "/* chat.js " version-tag " */ (function(){console.log('hive chat " version-tag "');})();")
        trace-js (str "/* trace-viz.js " version-tag " */ (function(){console.log('trace viz');})();")
        wasm-bytes (fressian/utf8->bytes (str "\u0000asm\u0001\u0000\u0000\u0000" version-tag))
        browser-sri (ar/compute-sri-sha384 browser-js)
        legacy-sri (ar/compute-sri-sha384 legacy-js)
        chat-sri (ar/compute-sri-sha384 chat-js)
        trace-sri (ar/compute-sri-sha384 trace-js)
        sri-txt (str browser-sri "\n")
        index-html (str "<!DOCTYPE html><html><head><title>Hive Chat " version-tag "</title></head><body>"
                        "<script src=\"/app/bitecho-browser.js\" integrity=\"" browser-sri "\" crossorigin=\"anonymous\"></script>"
                        "<script src=\"/app/chat.js\" integrity=\"" chat-sri "\" crossorigin=\"anonymous\"></script>"
                        "</body></html>")
        trace-html (str "<!DOCTYPE html><html><head><title>Trace Viz</title></head><body>"
                        "<script src=\"/app/trace-viz.js\" integrity=\"" trace-sri "\" crossorigin=\"anonymous\"></script>"
                        "</body></html>")
        legacy-html (str "<!DOCTYPE html><html><head><title>Legacy</title></head><body>"
                         "<script src=\"/app/bitecho-browser.js\" integrity=\"" browser-sri "\" crossorigin=\"anonymous\"></script>"
                         "<script src=\"/app/legacy.js\" integrity=\"" legacy-sri "\" crossorigin=\"anonymous\"></script>"
                         "</body></html>")]
    {"index.html" {:content index-html :content-type "text/html; charset=utf-8"}
     "chat.js" {:content chat-js :content-type "application/javascript; charset=utf-8"}
     "trace-viz.html" {:content trace-html :content-type "text/html; charset=utf-8"}
     "trace-viz.js" {:content trace-js :content-type "application/javascript; charset=utf-8"}
     "legacy.html" {:content legacy-html :content-type "text/html; charset=utf-8"}
     "legacy.js" {:content legacy-js :content-type "application/javascript; charset=utf-8"}
     "bitecho-browser.js" {:content browser-js :content-type "application/javascript; charset=utf-8"}
     "bitecho-browser.js.sri" {:content sri-txt :content-type "text/plain; charset=utf-8"}
     "tts.wasm" {:content wasm-bytes :content-type "application/wasm"}}))

;; =============================================================================
;; 1. Domain-Separated Release CID & SHA-384 Cross-Runtime Golden Vectors
;; =============================================================================

(deftest test-sha384-and-domain-separated-release-cid
  (testing "Portable SHA-384 matches FIPS 180-4 golden vectors identically on JVM and CLJS"
    (is (= "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
           (crypto/sha384-hex "")))
    (is (= "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
           (crypto/sha384-hex "abc")))
    (is (str/starts-with? (ar/compute-sri-sha384 "abc") "sha384-")))

  (testing "Domain-separated release-cid uses bitecho/web-app-release/v1 || RFC 8785 JCS bytes"
    (is (= "bitecho/web-app-release/v1" ar/release-domain-tag))
    (let [r1 {"version" 1
              "seq" 7
              "genesis_anchor_cid" genesis-cid
              "headers_config_cid" (apply str (repeat 64 "a"))
              "bytes_at_rest" 12
              "assets" {"index.html" {"cid" (apply str (repeat 64 "b"))
                                      "size" 12
                                      "content_type" "text/html; charset=utf-8"}}}
          r2 (array-map
              "assets" {"index.html" (array-map "size" 12
                                                "content_type" "text/html; charset=utf-8"
                                                "cid" (apply str (repeat 64 "b")))}
              "bytes_at_rest" 12
              "headers_config_cid" (apply str (repeat 64 "a"))
              "genesis_anchor_cid" genesis-cid
              "seq" 7
              "version" 1)
          b1 (ar/canonical-release-bytes r1)
          b2 (ar/canonical-release-bytes r2)
          cid1 (ar/release-cid r1)
          cid2 (ar/release-cid r2)]
      (is (= (fressian/bytes->utf8 b1) (fressian/bytes->utf8 b2)))
      (is (= cid1 cid2))
      (is (= 64 (count cid1)))
      (is (re-matches #"^[0-9a-f]{64}$" cid1))
      (is (= cid1 (crypto/sha256-hex (str ar/release-domain-tag (fressian/bytes->utf8 b1)))))
      ;; Different domain tag must yield a different CID than chunk-manifest/v1
      (is (not= cid1 (cc/manifest-cid r1))))))

;; =============================================================================
;; 2. Detached 2-of-3 Quorum Signature Envelope Verification
;; =============================================================================

(deftest test-quorum-signature-envelope-verification
  (let [fix (build-release-fixture {:seq 1 :raw-assets (make-legacy-assets "0.23.19")})
        rel (:release fix)
        rcid (:release-cid fix)
        opts {:trusted-signers trusted-signers-set :threshold 2}]
    (testing "Valid 2-of-3 and 3-of-3 quorum envelopes verify cleanly"
      (let [res2 (ar/verify-release-quorum-envelope rel (:envelope fix) opts)
            env3 (ar/sign-release-envelope
                  rcid
                  (mapv (fn [kp] {:owner-pubkey (kp-hex kp) :privkey (:private kp)}) signer-kps))
            res3 (ar/verify-release-quorum-envelope rel env3 opts)]
        (is (true? (:ok? res2)))
        (is (= 2 (count (:signers res2))))
        (is (empty? (:effects res2)))
        (is (true? (:ok? res3)))
        (is (= 3 (count (:signers res3))))))

    (testing "Below threshold (0 or 1 signature) fails closed with :release-sig-invalid"
      (let [env0 {:release-cid rcid :sigs []}
            env1 (ar/sign-release-envelope rcid (kp-hex (first signer-kps)) (:private (first signer-kps)))
            res0 (ar/verify-release-quorum-envelope rel env0 opts)
            res1 (ar/verify-release-quorum-envelope rel env1 opts)]
        (is (false? (:ok? res0)))
        (is (= :release-sig-invalid (:error res0)))
        (is (= :release-sig-invalid (get-in res0 [:effects 0 :kind])))
        (is (false? (:ok? res1)))
        (is (= :release-sig-invalid (:error res1)))))

    (testing "Duplicate signer keys fail closed with :release-sig-invalid"
      (let [s1 (first signer-kps)
            dup-env (ar/sign-release-envelope
                     rcid
                     [{:owner-pubkey (kp-hex s1) :privkey (:private s1)}
                      {:owner-pubkey (kp-hex s1) :privkey (:private s1)}])
            res (ar/verify-release-quorum-envelope rel dup-env opts)]
        (is (false? (:ok? res)))
        (is (= :release-sig-invalid (:error res)))
        (is (= :release-sig-invalid (get-in res [:effects 0 :kind])))))

    (testing "Unknown signer fails closed with :release-sig-invalid"
      (let [env-unk (ar/sign-release-envelope
                     rcid
                     [{:owner-pubkey (kp-hex (first signer-kps)) :privkey (:private (first signer-kps))}
                      {:owner-pubkey (kp-hex unknown-kp) :privkey (:private unknown-kp)}])
            res (ar/verify-release-quorum-envelope rel env-unk opts)]
        (is (false? (:ok? res)))
        (is (= :release-sig-invalid (:error res)))))

    (testing "Tampered release bytes or tampered signature fails closed with :release-sig-invalid"
      (let [tampered-rel (assoc rel "seq" 999)
            res-tampered (ar/verify-release-quorum-envelope tampered-rel (:envelope fix) opts)
            bad-sig-env (assoc-in (:envelope fix) [:sigs 0 :sig] (apply str (repeat 128 "0")))
            res-bad-sig (ar/verify-release-quorum-envelope rel bad-sig-env opts)]
        (is (false? (:ok? res-tampered)))
        (is (= :release-sig-invalid (:error res-tampered)))
        (is (false? (:ok? res-bad-sig)))
        (is (= :release-sig-invalid (:error res-bad-sig)))))))

;; =============================================================================
;; 3. Strict /app/* Headers Config Validation
;; =============================================================================

(deftest test-strict-headers-config-validation
  (testing "Default /app/* headers config passes strict validation"
    (let [hdrs (ar/default-app-headers-config)
          res (ar/validate-headers-config hdrs)]
      (is (true? (:ok? res)))
      (is (= "same-origin" (get (:headers res) "Cross-Origin-Opener-Policy")))
      (is (= "credentialless" (get (:headers res) "Cross-Origin-Embedder-Policy")))
      (is (= "no-cache" (get (:headers res) "Cache-Control")))))

  (testing "Missing or weakened COOP, COEP, Cache-Control, or CSP directives fail closed"
    (let [base (ar/default-app-headers-config)]
      (doseq [bad-hdrs [(assoc base "Cross-Origin-Opener-Policy" "unsafe-none")
                        (assoc base "Cross-Origin-Embedder-Policy" "unsafe-none")
                        (assoc base "Cache-Control" "public, max-age=3600")
                        (assoc base "Content-Security-Policy"
                               "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; connect-src 'self' blob:")
                        (assoc base "Content-Security-Policy"
                               "default-src 'self'; script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'; connect-src 'self' blob:")
                        (assoc base "Content-Security-Policy"
                               "default-src 'self'; script-src 'self'; connect-src 'self' blob:")
                        (assoc base "Content-Security-Policy"
                               "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' https:")
                        (dissoc base "Content-Security-Policy")]]
        (let [res (ar/validate-headers-config bad-hdrs)]
          (is (false? (:ok? res)) (str "Should reject: " (pr-str bad-hdrs)))
          (is (= :release-headers-invalid (:error res)))
          (is (= :release-headers-invalid (get-in res [:effects 0 :kind]))))))))

;; =============================================================================
;; 4. Genesis Pin, Monotonic Seq, Stale Gen, Assets, SRI, Storage Accounting, LKG
;; =============================================================================

(deftest test-fail-closed-validation-and-reducer-invariants
  (let [fix1 (build-release-fixture {:seq 1 :raw-assets (make-legacy-assets "0.23.19")})
        base-state (ar/init-release-state {:genesis-anchor-cid genesis-cid
                                           :trusted-signers trusted-signers-set
                                           :threshold 2
                                           :max-bytes (* 4 (:bytes-at-rest fix1))})]

    (testing "Missing or mismatched genesis-anchor-cid rejects fail-closed with :release-genesis-missing"
      (let [no-gen-state (ar/init-release-state {:trusted-signers trusted-signers-set :threshold 2})
            [st-no-gen effs-no-gen] (ar/transition no-gen-state {:type :apply-release
                                                                 :generation 1
                                                                 :release (:release fix1)
                                                                 :envelope (:envelope fix1)
                                                                 :blobs (:blobs fix1)})
            wrong-gen-fix (build-release-fixture {:seq 1
                                                  :genesis (crypto/sha256-hex "wrong-genesis")
                                                  :raw-assets (make-legacy-assets "0.23.19")})
            [st-wrong effs-wrong] (ar/transition base-state {:type :apply-release
                                                             :generation 1
                                                             :release (:release wrong-gen-fix)
                                                             :envelope (:envelope wrong-gen-fix)
                                                             :blobs (:blobs wrong-gen-fix)})]
        (is (nil? (:active-release st-no-gen)))
        (is (= :release-genesis-missing (:kind (first effs-no-gen))))
        (is (= 1 (get-in st-no-gen [:diagnostics :causes :release-genesis-missing])))
        (is (nil? (:active-release st-wrong)))
        (is (= :release-genesis-missing (:kind (first effs-wrong))))
        (is (= 1 (get-in st-wrong [:diagnostics :causes :release-genesis-missing])))))

    (testing "Activating seq 1 succeeds and pins LKG; seq <= current-seq and gen < current-gen reject with zero mutation"
      (let [[st1 effs1] (ar/transition base-state {:type :apply-release
                                                   :generation 1
                                                   :release (:release fix1)
                                                   :envelope (:envelope fix1)
                                                   :blobs (:blobs fix1)})]
        (is (= :active (:phase st1)))
        (is (= 1 (:current-seq st1)))
        (is (= 1 (:generation st1)))
        (is (= (:release-cid fix1) (get-in st1 [:active-release :release-cid])))
        (is (= (:release-cid fix1) (:lkg-release-cid st1)))
        (is (some #(= :persist-release-floor (:type %)) effs1))
        (is (= 0 (get-in st1 [:diagnostics :dropped])))

        ;; seq <= current-seq -> :release-seq-non-monotonic, zero mutation
        (let [[st-eq effs-eq] (ar/transition st1 {:type :apply-release
                                                  :generation 1
                                                  :release (:release fix1)
                                                  :envelope (:envelope fix1)
                                                  :blobs (:blobs fix1)})]
          (is (= (:active-release st1) (:active-release st-eq)))
          (is (= 1 (:current-seq st-eq)))
          (is (= :release-seq-non-monotonic (:kind (first effs-eq))))
          (is (= 1 (get-in st-eq [:diagnostics :causes :release-seq-non-monotonic])))
          (is (= (get-in st-eq [:diagnostics :dropped]) (causes-sum st-eq))))

        ;; gen < current-gen -> :ignored-stale-release, zero mutation
        (let [fix2 (build-release-fixture {:seq 2 :raw-assets (make-hive-assets "0.23.20")})
              [st-stale effs-stale] (ar/transition st1 {:type :apply-release
                                                        :generation 0
                                                        :release (:release fix2)
                                                        :envelope (:envelope fix2)
                                                        :blobs (:blobs fix2)})]
          (is (= (:active-release st1) (:active-release st-stale)))
          (is (= 1 (:current-seq st-stale)))
          (is (= :ignored-stale-release (:kind (first effs-stale))))
          (is (= 1 (get-in st-stale [:diagnostics :causes :ignored-stale-release])))
          (is (= (get-in st-stale [:diagnostics :dropped]) (causes-sum st-stale))))

        ;; Missing asset -> :release-asset-missing, previous generation stays active
        (let [fix2 (build-release-fixture {:seq 2 :raw-assets (make-hive-assets "0.23.20")})
              chat-cid (get-in (:release fix2) ["assets" "chat.js" "cid"])
              [st-miss effs-miss] (ar/transition st1 {:type :apply-release
                                                      :generation 1
                                                      :release (:release fix2)
                                                      :envelope (:envelope fix2)
                                                      :blobs (dissoc (:blobs fix2) chat-cid)})]
          (is (= (:active-release st1) (:active-release st-miss)))
          (is (= 1 (:current-seq st-miss)))
          (is (= :release-asset-missing (:kind (first effs-miss)))))

        ;; Corrupt asset -> :release-asset-corrupt, previous generation stays active
        (let [fix2 (build-release-fixture {:seq 2 :raw-assets (make-hive-assets "0.23.20")})
              chat-cid (get-in (:release fix2) ["assets" "chat.js" "cid"])
              [st-corr effs-corr] (ar/transition st1 {:type :apply-release
                                                      :generation 1
                                                      :release (:release fix2)
                                                      :envelope (:envelope fix2)
                                                      :blobs (assoc (:blobs fix2) chat-cid (fressian/utf8->bytes "corrupted!"))})]
          (is (= (:active-release st1) (:active-release st-corr)))
          (is (= 1 (:current-seq st-corr)))
          (is (= :release-asset-corrupt (:kind (first effs-corr)))))

        ;; Generalized SHA-384 SRI tamper (WASM or JS or HTML <script> SRI mismatch) -> :release-sri-mismatch
        (let [fix2 (build-release-fixture {:seq 2 :raw-assets (make-hive-assets "0.23.20")})
              bad-wasm-rel (assoc-in (:release fix2) ["assets" "tts.wasm" "sri"] "sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
              bad-wasm-env (ar/sign-release-envelope
                            (ar/release-cid bad-wasm-rel)
                            (mapv (fn [kp] {:owner-pubkey (kp-hex kp) :privkey (:private kp)}) (take 2 signer-kps)))
              [st-sri effs-sri] (ar/transition st1 {:type :apply-release
                                                    :generation 1
                                                    :release bad-wasm-rel
                                                    :envelope bad-wasm-env
                                                    :blobs (:blobs fix2)})]
          (is (= (:active-release st1) (:active-release st-sri)))
          (is (= :release-sri-mismatch (:kind (first effs-sri)))))

        ;; HTML <script> integrity cross-check tamper -> :release-sri-mismatch
        (let [raw-bad-html (assoc-in (make-hive-assets "0.23.20")
                                     ["index.html" :content]
                                     "<!DOCTYPE html><html><body><script src=\"/app/chat.js\" integrity=\"sha384-tampered\" crossorigin=\"anonymous\"></script></body></html>")
              fix-bad-html (build-release-fixture {:seq 2 :raw-assets raw-bad-html})
              [st-html-sri effs-html-sri] (ar/transition st1 {:type :apply-release
                                                              :generation 1
                                                              :release (:release fix-bad-html)
                                                              :envelope (:envelope fix-bad-html)
                                                              :blobs (:blobs fix-bad-html)})]
          (is (= (:active-release st1) (:active-release st-html-sri)))
          (is (= :release-sri-mismatch (:kind (first effs-html-sri)))))

        ;; Strict :bytes-at-rest != sum(assets[].size) -> :storage-accounting-mismatch
        (let [fix2 (build-release-fixture {:seq 2 :raw-assets (make-hive-assets "0.23.20")})
              bad-acct-rel (assoc (:release fix2) "bytes_at_rest" (inc (:bytes-at-rest fix2)))
              bad-acct-env (ar/sign-release-envelope
                            (ar/release-cid bad-acct-rel)
                            (mapv (fn [kp] {:owner-pubkey (kp-hex kp) :privkey (:private kp)}) (take 2 signer-kps)))
              [st-acct effs-acct] (ar/transition st1 {:type :apply-release
                                                      :generation 1
                                                      :release bad-acct-rel
                                                      :envelope bad-acct-env
                                                      :blobs (:blobs fix2)})]
          (is (= (:active-release st1) (:active-release st-acct)))
          (is (= :storage-accounting-mismatch (:kind (first effs-acct)))))

        ;; Retention bound (:max-bytes < 2 * active-release-bytes) -> :retention-bound-exceeded
        (let [tight-state (assoc st1 :max-bytes (+ (:bytes-at-rest fix1) 10))
              fix2 (build-release-fixture {:seq 2 :raw-assets (make-hive-assets "0.23.20")})
              [st-ret effs-ret] (ar/transition tight-state {:type :apply-release
                                                            :generation 1
                                                            :release (:release fix2)
                                                            :envelope (:envelope fix2)
                                                            :blobs (:blobs fix2)})]
          (is (= (:active-release st1) (:active-release st-ret)))
          (is (= :retention-bound-exceeded (:kind (first effs-ret)))))

        ;; Attempt to evict pinned :lkg-release-cid -> :release-lkg-evicted
        (let [[st-ev effs-ev] (ar/transition st1 {:type :evict-release
                                                  :generation 1
                                                  :release-cid (:lkg-release-cid st1)})]
          (is (= (:lkg-release-cid st1) (:lkg-release-cid st-ev)))
          (is (contains? (:pinned-release-cids st-ev) (:lkg-release-cid st1)))
          (is (= :release-lkg-evicted (:kind (first effs-ev)))))))))

;; =============================================================================
;; 5. Pre-Fleet Lab Monotonic Rollback Dry-Run (seq 1 -> seq 2 -> seq 3)
;; =============================================================================

(deftest test-pre-fleet-lab-monotonic-rollback-dry-run
  (testing "seq 1 (.lkg legacy) -> seq 2 (Hive) -> seq 3 (monotonic rollback to .lkg, never rewinding seq)"
    (let [legacy-headers (assoc (ar/default-app-headers-config)
                                "X-Bitecho-Release-Profile" "legacy-lkg")
          hive-headers (assoc (ar/default-app-headers-config)
                              "X-Bitecho-Release-Profile" "hive-v1")
          lkg-assets (make-legacy-assets "0.23.19")
          hive-assets (make-hive-assets "0.23.20")
          ;; seq 1: .lkg legacy release
          fix-lkg (build-release-fixture {:seq 1
                                          :headers-config legacy-headers
                                          :raw-assets lkg-assets})
          ;; seq 2: Hive release referencing .lkg as lkg-release-cid
          fix-hive (build-release-fixture {:seq 2
                                           :headers-config hive-headers
                                           :raw-assets hive-assets
                                           :lkg-release-cid (:release-cid fix-lkg)})
          ;; seq 3: Pre-signed monotonic rollback back to exact .lkg assets & legacy headers-config (NEVER rewinding seq!)
          fix-rollback (build-release-fixture {:seq 3
                                               :headers-config legacy-headers
                                               :raw-assets lkg-assets
                                               :lkg-release-cid (:release-cid fix-lkg)})
          all-blobs (merge (:blobs fix-lkg) (:blobs fix-hive) (:blobs fix-rollback))
          max-b (* 4 (max (:bytes-at-rest fix-lkg) (:bytes-at-rest fix-hive)))
          st0 (ar/init-release-state {:genesis-anchor-cid genesis-cid
                                      :trusted-signers trusted-signers-set
                                      :threshold 2
                                      :max-bytes max-b})
          ;; Step 1: Activate seq 1 (.lkg)
          [st1 _] (ar/transition st0 {:type :apply-release
                                      :generation 1
                                      :pin-as-lkg? true
                                      :release (:release fix-lkg)
                                      :envelope (:envelope fix-lkg)
                                      :blobs all-blobs})
          ;; Step 2: Upgrade to seq 2 (Hive)
          [st2 _] (ar/transition st1 {:type :apply-release
                                      :generation 2
                                      :release (:release fix-hive)
                                      :envelope (:envelope fix-hive)
                                      :blobs all-blobs})
          ;; Attempting to rewind seq back to 1 MUST fail closed with :release-seq-non-monotonic
          [st-rewind effs-rewind] (ar/transition st2 {:type :apply-release
                                                      :generation 2
                                                      :release (:release fix-lkg)
                                                      :envelope (:envelope fix-lkg)
                                                      :blobs all-blobs})
          ;; Step 3: Monotonic rollback at seq 3 back to exact .lkg content & headers
          [st3 _] (ar/transition st2 {:type :apply-release
                                      :generation 3
                                      :release (:release fix-rollback)
                                      :envelope (:envelope fix-rollback)
                                      :blobs all-blobs})]

      ;; Assert Step 1 (.lkg)
      (is (= 1 (:current-seq st1)))
      (is (= (:release-cid fix-lkg) (:lkg-release-cid st1)))

      ;; Assert Step 2 (Hive serving all Hive routes + strict headers)
      (is (= 2 (:current-seq st2)))
      (let [resp-hive-idx (ar/resolve-app-asset-response st2 "/app/" all-blobs)
            resp-chat (ar/resolve-app-asset-response st2 "/app/chat.js" all-blobs)
            resp-trace (ar/resolve-app-asset-response st2 "/app/trace-viz.html" all-blobs)]
        (is (true? (:ok? resp-hive-idx)))
        (is (= "hive-v1" (get-in resp-hive-idx [:headers "X-Bitecho-Release-Profile"])))
        (is (= "same-origin" (get-in resp-hive-idx [:headers "Cross-Origin-Opener-Policy"])))
        (is (= "credentialless" (get-in resp-hive-idx [:headers "Cross-Origin-Embedder-Policy"])))
        (is (true? (:ok? resp-chat)))
        (is (true? (:ok? resp-trace))))

      ;; Assert rewind to seq 1 rejected
      (is (= 2 (:current-seq st-rewind)))
      (is (= :release-seq-non-monotonic (:kind (first effs-rewind))))

      ;; Assert Step 3 (Monotonic rollback at seq 3 restores exact .lkg bytes, .sri, index.html, and legacy headers-config)
      (is (= 3 (:current-seq st3)))
      (let [orig-idx (ar/resolve-app-asset-response st1 "/app/index.html" all-blobs)
            orig-sri (ar/resolve-app-asset-response st1 "/app/bitecho-browser.js.sri" all-blobs)
            orig-legacy (ar/resolve-app-asset-response st1 "/app/legacy.js" all-blobs)
            rb-idx (ar/resolve-app-asset-response st3 "/app/" all-blobs)
            rb-sri (ar/resolve-app-asset-response st3 "/app/bitecho-browser.js.sri" all-blobs)
            rb-legacy (ar/resolve-app-asset-response st3 "/app/legacy.js" all-blobs)]
        (is (true? (:ok? rb-idx)))
        (is (true? (:ok? rb-sri)))
        (is (true? (:ok? rb-legacy)))
        (is (= (fressian/bytes->utf8 (:body orig-idx))
               (fressian/bytes->utf8 (:body rb-idx))))
        (is (= (fressian/bytes->utf8 (:body orig-sri))
               (fressian/bytes->utf8 (:body rb-sri))))
        (is (= (fressian/bytes->utf8 (:body orig-legacy))
               (fressian/bytes->utf8 (:body rb-legacy))))
        (is (= "legacy-lkg" (get-in rb-idx [:headers "X-Bitecho-Release-Profile"])))
        (is (= (get-in orig-idx [:headers "Content-Security-Policy"])
               (get-in rb-idx [:headers "Content-Security-Policy"])))
        (is (= "3" (get-in rb-idx [:headers "X-Bitecho-Release-Seq"])))))))

;; =============================================================================
;; 6. Generative & Model-Based Command-Sequence Tests (Rule 1 & Rule 5)
;; =============================================================================

(defspec ^{:doc "Property: Model-based command sequences preserve monotonic seq, LKG pin, generation isolation, and :dropped == sum(causes)."}
  prop-model-based-release-lifecycle-invariants 40
  (prop/for-all [ops (gen/vector
                      (gen/elements [:apply-valid
                                     :apply-non-monotonic
                                     :apply-stale-gen
                                     :apply-bad-sig
                                     :apply-missing-asset
                                     :apply-corrupt-asset
                                     :apply-sri-tamper
                                     :apply-accounting-mismatch
                                     :apply-bad-headers
                                     :evict-lkg])
                      1 20)]
                (let [init-st (ar/init-release-state {:genesis-anchor-cid genesis-cid
                                                      :trusted-signers trusted-signers-set
                                                      :threshold 2
                                                      :max-bytes 1048576})]
                  (loop [st init-st
                         remaining ops
                         step 1]
                    (if (empty? remaining)
                      (= (get-in st [:diagnostics :dropped]) (causes-sum st))
                      (let [op (first remaining)
                            cur-seq (:current-seq st)
                            cur-gen (:generation st)
                            fix (build-release-fixture {:seq (inc cur-seq)
                                                        :raw-assets (make-legacy-assets (str "v" step))})
                            ev (case op
                                 :apply-valid
                                 {:type :apply-release
                                  :generation cur-gen
                                  :release (:release fix)
                                  :envelope (:envelope fix)
                                  :blobs (:blobs fix)}

                                 :apply-non-monotonic
                                 (let [f-old (build-release-fixture {:seq (max 1 cur-seq)
                                                                     :raw-assets (make-legacy-assets (str "old" step))})]
                                   {:type :apply-release
                                    :generation cur-gen
                                    :release (:release f-old)
                                    :envelope (:envelope f-old)
                                    :blobs (:blobs f-old)})

                                 :apply-stale-gen
                                 {:type :apply-release
                                  :generation (dec cur-gen)
                                  :release (:release fix)
                                  :envelope (:envelope fix)
                                  :blobs (:blobs fix)}

                                 :apply-bad-sig
                                 {:type :apply-release
                                  :generation cur-gen
                                  :release (:release fix)
                                  :envelope {:release-cid (:release-cid fix) :sigs []}
                                  :blobs (:blobs fix)}

                                 :apply-missing-asset
                                 {:type :apply-release
                                  :generation cur-gen
                                  :release (:release fix)
                                  :envelope (:envelope fix)
                                  :blobs {}}

                                 :apply-corrupt-asset
                                 (let [cid (get-in (:release fix) ["assets" "legacy.js" "cid"])]
                                   {:type :apply-release
                                    :generation cur-gen
                                    :release (:release fix)
                                    :envelope (:envelope fix)
                                    :blobs (assoc (:blobs fix) cid (fressian/utf8->bytes "corrupt"))})

                                 :apply-sri-tamper
                                 (let [bad-rel (assoc-in (:release fix) ["assets" "legacy.js" "sri"] "sha384-bad")
                                       bad-env (ar/sign-release-envelope
                                                (ar/release-cid bad-rel)
                                                (mapv (fn [kp] {:owner-pubkey (kp-hex kp) :privkey (:private kp)}) (take 2 signer-kps)))]
                                   {:type :apply-release
                                    :generation cur-gen
                                    :release bad-rel
                                    :envelope bad-env
                                    :blobs (:blobs fix)})

                                 :apply-accounting-mismatch
                                 (let [bad-rel (assoc (:release fix) "bytes_at_rest" (+ 99 (:bytes-at-rest fix)))
                                       bad-env (ar/sign-release-envelope
                                                (ar/release-cid bad-rel)
                                                (mapv (fn [kp] {:owner-pubkey (kp-hex kp) :privkey (:private kp)}) (take 2 signer-kps)))]
                                   {:type :apply-release
                                    :generation cur-gen
                                    :release bad-rel
                                    :envelope bad-env
                                    :blobs (:blobs fix)})

                                 :apply-bad-headers
                                 (let [bad-fix (build-release-fixture
                                                {:seq (inc cur-seq)
                                                 :headers-config {"Cache-Control" "public"}
                                                 :raw-assets (make-legacy-assets (str "bh" step))})]
                                   {:type :apply-release
                                    :generation cur-gen
                                    :release (:release bad-fix)
                                    :envelope (:envelope bad-fix)
                                    :blobs (:blobs bad-fix)})

                                 :evict-lkg
                                 {:type :evict-release
                                  :generation cur-gen
                                  :release-cid (or (:lkg-release-cid st) genesis-cid)})
                            [st' _effs] (ar/transition st ev)
                            invariants-ok?
                            (and (>= (:current-seq st') cur-seq)
                                 (>= (:generation st') cur-gen)
                                 (= (get-in st' [:diagnostics :dropped]) (causes-sum st'))
                                 (or (nil? (:lkg-release-cid st))
                                     (= (:lkg-release-cid st) (:lkg-release-cid st'))))]
                        (if invariants-ok?
                          (recur st' (rest remaining) (inc step))
                          false)))))))
