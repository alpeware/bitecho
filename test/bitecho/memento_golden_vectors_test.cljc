(ns bitecho.memento-golden-vectors-test
  "Cross-runtime (JVM + CLJS Node.js) byte-for-byte golden vector and portable core tests
   for BIP-016 Memento Agent Continuity & Unified Rolodex (Edge 3, Rule 1, Rule 6)."
  (:require [bitecho.browser-cli :as browser-cli]
            [bitecho.crypto :as crypto]
            [bitecho.crypto.sealed :as sealed]
            [bitecho.fressian :as fressian]
            [bitecho.light-node.cli :as cli]
            [bitecho.memento.constants :as mc]
            [bitecho.memento.memory-chain :as memory-chain]
            [bitecho.memento.rolodex :as rolodex]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])))

;; =============================================================================
;; Pinned BIP-016 Cross-Runtime Golden Vectors (JVM == Node.js node:crypto)
;; =============================================================================

(def ^:private golden-seed-hex
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

(def ^:private golden-pub32-hex
  "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")

(def ^:private golden-aead-key-hex
  "4c808659a14e546726eefb8066152a3e4bfcaf44c49785a96756447fb64e40ed")

(def ^:private golden-nonce-seq1-hex
  "314f27a504fa5f1833b36f9c")

(def ^:private golden-aad-seq1-hex
  "6269746563686f2f6d656d656e746f2f6161642f763100000000000000010000000000000000000000000000000000000000000000000000000000000000")

(def ^:private golden-plaintext-str
  "bitecho/memento/golden-vector/v1")

(def ^:private golden-ciphertext-hex
  "49b9877c2fbff3d5fee27bc4f7aab39a044f522e39440477f6e9e27a94e8aa920112c84ff2ce6d3e63a5e3519c6dcbbc")

(def ^:private golden-frame-cid-hex
  "878fcff80563206b3bfb98268ea48ebd60c310df8f76386ab571edb4f1b713cf")

(def ^:private golden-genesis-sig-hex
  "7992fc58ec934210adb4352734684538cade704e819fc7d37cd2f80da3c558834c443049c22ec0e7d301063fe575e3f1d9ad2982802ca7997e204fb376e53106")

(deftest test-cross-runtime-memento-golden-vectors
  (testing "HKDF-SHA-256, AES-256-GCM, canonical frame CID, and RFC 8032 genesis signature match byte-for-byte on JVM and Node.js"
    (let [seed32 (fressian/hex->bytes golden-seed-hex)
          kp (crypto/generate-keypair seed32)
          pub-der (:public kp)
          priv-der (:private kp)
          pub32 (mc/slice-bytes pub-der 12 32)
          aead-key (sealed/hkdf-sha256 seed32 nil (memory-chain/aead-key-info) 32)
          nonce1 (sealed/hkdf-sha256 seed32 nil (memory-chain/nonce-info 1) 12)
          aad1 (memory-chain/aad-bytes 1 mc/zero-cid-hex)
          pt (fressian/utf8->bytes golden-plaintext-str)
          ct (sealed/aes-gcm-seal aead-key nonce1 pt aad1)
          opened (sealed/aes-gcm-open aead-key nonce1 ct aad1)
          frame (memory-chain/encode-frame 1 mc/zero-cid-hex ct)
          decoded (memory-chain/decode-frame frame)
          cid (memory-chain/frame-cid frame)
          gen-msg (memory-chain/genesis-message-bytes pub32)
          gen-sig (crypto/sign priv-der gen-msg)]
      (is (= golden-pub32-hex (fressian/bytes->hex pub32)))
      (is (= golden-aead-key-hex (fressian/bytes->hex aead-key)))
      (is (= golden-nonce-seq1-hex (fressian/bytes->hex nonce1)))
      (is (= golden-aad-seq1-hex (fressian/bytes->hex aad1)))
      (is (= golden-ciphertext-hex (fressian/bytes->hex ct)))
      (is (= golden-plaintext-str (fressian/bytes->utf8 opened)))
      (is (= golden-frame-cid-hex cid))
      (is (true? (:ok? decoded)))
      (is (= 1 (:seq decoded)))
      (is (= mc/zero-cid-hex (:prev-cid decoded)))
      (is (= golden-genesis-sig-hex (fressian/bytes->hex gen-sig)))
      (is (true? (crypto/verify pub-der gen-msg gen-sig))))))

(deftest test-portable-monotonic-epoch-seq-and-lkg-checksum
  (testing "Monotonic (epoch, seq) replay protection and checksum-verified .lkg rollback work identically on JVM and CLJS"
    (let [s0 (rolodex/init-rolodex)
          e1 {:seq 1 :epoch 2 :prev-cid mc/zero-cid-hex :op :upsert
              :petname "simon" :pubkey golden-pub32-hex :allowed-actions #{:gossip}
              :signature "aa"}
          cid1 (rolodex/entry-cid e1)
          [s1 effs1] (rolodex/transition s0 {:type :apply-remote-entry
                                             :entry e1 :cid cid1 :declared-bytes 200 :sig-valid? true})
          ;; Lower epoch (epoch 1 < current 2) must halt with :epoch-replay-or-stale
          e-stale-epoch {:seq 2 :epoch 1 :prev-cid cid1 :op :upsert
                         :petname "axiom" :pubkey golden-pub32-hex :allowed-actions #{:gossip}
                         :signature "bb"}
          [s-stale effs-stale] (rolodex/transition s1 {:type :apply-remote-entry
                                                       :entry e-stale-epoch
                                                       :cid (rolodex/entry-cid e-stale-epoch)
                                                       :declared-bytes 200
                                                       :sig-valid? true})
          ;; Valid snapshot checksum passes; tampered snapshot halts with :lkg-checksum-mismatch
          good-snap (rolodex/make-snapshot s1)
          tampered-snap (assoc-in good-snap [:state "simon" :pubkey] "deadbeef")
          [s-snap-ok effs-snap-ok] (rolodex/transition s1 {:type :load-snapshot
                                                           :snapshot good-snap
                                                           :declared-bytes 512})
          [s-snap-bad effs-snap-bad] (rolodex/transition s1 {:type :load-snapshot
                                                             :snapshot tampered-snap
                                                             :declared-bytes 512})]
      (is (empty? effs1))
      (is (= 2 (:rotation-epoch s1)))
      (is (= :halted (:phase s-stale)))
      (is (some #(= :epoch-replay-or-stale (:code %)) effs-stale))
      (is (true? (rolodex/verify-snapshot-checksum good-snap)))
      (is (false? (rolodex/verify-snapshot-checksum tampered-snap)))
      (is (empty? effs-snap-ok))
      (is (= :idle (:phase s-snap-ok)))
      (is (= :halted (:phase s-snap-bad)))
      (is (some #(= :lkg-checksum-mismatch (:code %)) effs-snap-bad)))))

(deftest test-bip016-cli-verb-and-flag-parity
  (testing "BIP-016 rolodex-* and memento-* verbs and flags are registered in both light-node and browser CLI"
    (let [expected-verbs ["rolodex-status" "rolodex-put" "rolodex-rotate" "rolodex-restore"
                          "memento-head" "memento-put" "memento-walk"]
          expected-flags ["--node-role" "--retention-max-entries" "--retention-max-bytes"
                          "--rotate-every" "--grace-epochs" "--lkg-cid"
                          "--walk-depth-cap" "--owner-pubkey" "--cache-incentive"]
          flags-set (set cli/known-command-flags)]
      (doseq [v expected-verbs]
        (is (contains? cli/all-recognized-cli-verbs-set v))
        (is (contains? browser-cli/browser-cli-verb-inventory v))
        (is (= :supported (get-in browser-cli/browser-cli-verb-inventory [v :support])))
        (let [desugared (cli/desugar-cli-cmd-map {"cmd" v})]
          (is (= v (get desugared "cmd")))
          (is (contains? cli/canonical-cli-verbs-set (get desugared "canonical_cmd")))))
      (doseq [f expected-flags]
        (is (contains? flags-set f))))))
