(ns bitecho.d37-bip011-gentoo-host-and-unified-rollout-test
  "Milestone D37 (`BIP-011: Gentoo Host-Layer Migration, On-Network Binhost,
   Unified Pointer-Driven Rolling Upgrades, and Merkle Root-Hash Attestation` / `v0.23.15`).
   Strict TDD generative `clojure.test.check` invariants (`Rule 1`, `Rule 2`, `Rule 4`, `Rule 5`, `Rule 6`)
   plus all 7 deterministic proof scenarios (`S-D37-1` through `S-D37-7`)."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.config :as config]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.fressian :as fressian]
            [bitecho.governance.core :as gov]
            [bitecho.host.core :as host]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]))

(defn- kp->pk-hex [kp]
  (let [pub (or (:public kp) (:public-key kp))]
    (str/lower-case (if (string? pub) pub (basalt/bytes->hex pub)))))

(defn- utf8-bytes [s]
  (fressian/utf8->bytes (str s)))

(defn- sample-manifest
  [arch os-pkgs runtimes apps]
  (host/build-system-merkle-manifest
   {:arch arch
    :stage3-cid (deploy/sha256-hex (str "stage3-" arch "-20261115"))
    :profile-cid (deploy/sha256-hex (str "default/linux/" arch "/23.0/no-multilib/hardened"))
    :os-packages os-pkgs
    :runtimes runtimes
    :app-artifacts apps}))

(def ^:private gen-arch
  (gen/elements ["amd64" "arm64"]))

(def ^:private gen-safe-token
  (gen/fmap #(str "pkg-" (Math/abs (long %))) gen/small-integer))

(def ^:private gen-os-package
  (gen/let [atom-name (gen/elements ["sys-kernel/gentoo-kernel-bin"
                                     "sys-apps/openrc"
                                     "net-misc/openssh"
                                     "sys-fs/btrfs-progs"
                                     "sys-apps/kexec-tools"
                                     "app-arch/zstd"])
            ver (gen/fmap #(str "1." (Math/abs (long %)) ".0") gen/small-integer)
            salt gen-safe-token]
    {:atom atom-name
     :version ver
     :cid (deploy/sha256-hex (str atom-name "-" ver "-" salt))}))

(def ^:private gen-runtime-entry
  (gen/let [rt-name (gen/elements ["openjdk" "nodejs"])
            ver (gen/elements ["25.0.5" "25.0.6" "22.23.5" "22.24.0"])
            salt gen-safe-token]
    {:name rt-name
     :version ver
     :cid (deploy/sha256-hex (str rt-name "-" ver "-" salt))}))

(def ^:private gen-app-entry
  (gen/let [art (gen/elements ["bitecho-full-node.cjs" "bitecho.jar"])
            ver (gen/elements ["0.23.14" "0.23.15"])
            salt gen-safe-token]
    {:artifact art
     :version ver
     :cid (deploy/sha256-hex (str art "-" ver "-" salt))}))

;; =============================================================================
;; 1. Generative Invariants (Rule 1: Strict TDD)
;; =============================================================================

(defspec ^{:doc "BIP-011 Prop 1 (P-HOST-1, P-HOST-5): 3-subtree Merkle root is deterministic across input orderings, reproducible across independent builds, and per-layer Merkle proofs verify against the root."}
  prop-system-merkle-root-deterministic-and-layer-proofs-verify 30
  (prop/for-all [arch gen-arch
                 os-pkgs (gen/not-empty (gen/vector gen-os-package 1 6))
                 runtimes (gen/not-empty (gen/vector gen-runtime-entry 1 3))
                 apps (gen/not-empty (gen/vector gen-app-entry 1 2))]
                (let [m1 (sample-manifest arch os-pkgs runtimes apps)
                      m2 (sample-manifest arch (reverse os-pkgs) (reverse runtimes) (reverse apps))
                      recomputed (host/compute-system-merkle-root m1)
                      os-proof (host/generate-layer-proof m1 :os-subtree)
                      rt-proof (host/generate-layer-proof m1 :runtime-subtree)
                      app-proof (host/generate-layer-proof m1 :app-subtree)
                      repro (host/verify-reproducible-builds m1 m2)
                      profile (host/gentoo-profile-spec arch)]
                  (and (= (:system-merkle-root m1) (:system-merkle-root m2))
                       (= (:subtree-roots m1) (:subtree-roots m2))
                       (= (:system-merkle-root m1) (:system-merkle-root recomputed))
                       (true? (:reproducible? repro))
                       (true? (:valid? (host/verify-layer-proof os-proof (:system-merkle-root m1))))
                       (true? (:valid? (host/verify-layer-proof rt-proof (:system-merkle-root m1))))
                       (true? (:valid? (host/verify-layer-proof app-proof (:system-merkle-root m1))))
                       (false? (:valid? (host/verify-layer-proof os-proof (deploy/sha256-hex "wrong-root"))))
                       (true? (:ok? (host/validate-profile-spec profile)))))))

(defspec ^{:doc "BIP-011 Prop 2 (P-HOST-5): A single-package change in any layer flips only that exact subtree root and localizes cleanly to the divergent subtree."}
  prop-single-package-change-localizes-to-exact-subtree 30
  (prop/for-all [arch gen-arch
                 os-pkgs (gen/not-empty (gen/vector gen-os-package 1 5))
                 runtimes (gen/not-empty (gen/vector gen-runtime-entry 1 3))
                 apps (gen/not-empty (gen/vector gen-app-entry 1 2))
                 target-layer (gen/elements [:os-subtree :runtime-subtree :app-subtree])
                 bump-salt (gen/fmap #(str "bumped-" (Math/abs (long %))) gen/small-integer)]
                (let [m-base (sample-manifest arch os-pkgs runtimes apps)
                      m-mut (case target-layer
                              :os-subtree
                              (sample-manifest
                               arch
                               (conj (vec os-pkgs)
                                     {:atom "net-misc/openssh-patch"
                                      :version "9.9_p2"
                                      :cid (deploy/sha256-hex (str "os-bump-" bump-salt))})
                               runtimes
                               apps)

                              :runtime-subtree
                              (sample-manifest
                               arch
                               os-pkgs
                               (conj (vec runtimes)
                                     {:name "openjdk-patch"
                                      :version "25.0.7"
                                      :cid (deploy/sha256-hex (str "rt-bump-" bump-salt))})
                               apps)

                              :app-subtree
                              (sample-manifest
                               arch
                               os-pkgs
                               runtimes
                               (conj (vec apps)
                                     {:artifact "bitecho-patch.cjs"
                                      :version "0.23.16"
                                      :cid (deploy/sha256-hex (str "app-bump-" bump-salt))})))
                      diff (host/localize-merkle-divergence m-base m-mut)
                      unchanged-layers (remove #{target-layer} [:os-subtree :runtime-subtree :app-subtree])]
                  (and (false? (:match? diff))
                       (= [target-layer] (:divergent-subtrees diff))
                       (every? #(= (get-in m-base [:subtree-roots %])
                                   (get-in m-mut [:subtree-roots %]))
                               unchanged-layers)
                       (not= (get-in m-base [:subtree-roots target-layer])
                             (get-in m-mut [:subtree-roots target-layer]))))))

(defspec ^{:doc "BIP-011 Prop 3 (P-HOST-2): On-network binhost .gpkg.tar verification fails closed with counted :diagnose on tampered bytes, unsigned metadata, or untrusted signers."}
  prop-binpkg-signature-verification-fail-closed-on-tamper-or-unsigned 25
  (prop/for-all [arch gen-arch
                 pkg-body (gen/not-empty gen/string-alphanumeric)
                 tamper-mode (gen/elements [:valid :tampered-bytes :unsigned :untrusted-signer])]
                (let [auth-kp (crypto/generate-keypair "d37-binhost-auth")
                      rogue-kp (crypto/generate-keypair "d37-binhost-rogue")
                      auth-pk (kp->pk-hex auth-kp)
                      rogue-pk (kp->pk-hex rogue-kp)
                      raw-bytes (utf8-bytes pkg-body)
                      cid (deploy/sha256-hex raw-bytes)
                      base-meta {:arch arch
                                 :atom "net-misc/openssh"
                                 :version "9.9_p1"
                                 :filename "openssh-9.9_p1.gpkg.tar"
                                 :sha256-cid cid
                                 :signer-pubkey auth-pk}
                      signed-meta (host/sign-binpkg-artifact (:private auth-kp) base-meta)
                      st {:trusted-deploy-authorities #{auth-pk} :diagnostics {}}
                      [test-meta test-bytes]
                      (case tamper-mode
                        :valid [signed-meta raw-bytes]
                        :tampered-bytes [signed-meta (utf8-bytes (str pkg-body "-corrupted"))]
                        :unsigned [(dissoc signed-meta :signature) raw-bytes]
                        :untrusted-signer [(host/sign-binpkg-artifact
                                            (:private rogue-kp)
                                            (assoc base-meta :signer-pubkey rogue-pk))
                                           raw-bytes])
                      res (host/verify-binpkg-artifact st test-meta test-bytes)]
                  (if (= tamper-mode :valid)
                    (and (true? (:ok? res))
                         (= (str "host/gentoo/binpkgs/" arch "/openssh-9.9_p1.gpkg.tar")
                            (host/binhost-package-path arch (:filename test-meta))))
                    (and (false? (:ok? res))
                         (some #(= :binpkg-verification-failed (:reason %)) (:effects res))
                         (= 1 (get-in res [:state :diagnostics :binpkg-verification-failed])))))))

(defspec ^{:doc "BIP-011 Prop 4 (P-HOST-4, P-HOST-6): Unified dynamic rolling upgrade state machine executes host-then-node, ignores stale-generation callbacks with counted :diagnose, and atomically rolls back both host (@rootfs) and node bundle while never rolling back @bitecho-state."}
  prop-unified-rollout-state-machine-atomic-rollback-and-stale-gen-guard 25
  (prop/for-all [cmds (gen/vector
                       (gen/elements [:stale-callback
                                      :valid-advance-and-succeed
                                      :advance-fail-at-host
                                      :advance-fail-at-node
                                      :advance-tampered-code])
                       1 6)]
                (let [auth-kp (crypto/generate-keypair "d37-unified-auth")
                      auth-pk (kp->pk-hex auth-kp)
                      auth-sk (:private auth-kp)
                      lkg-code-bytes (utf8-bytes "full-node-v0.23.14")
                      lkg-code-cid (deploy/sha256-hex lkg-code-bytes)
                      lkg-manifest (sample-manifest
                                    "amd64"
                                    [{:atom "sys-apps/openrc" :version "0.55" :cid (deploy/sha256-hex "openrc-0.55")}]
                                    [{:name "nodejs" :version "22.23.5" :cid (deploy/sha256-hex "node-22.23.5")}]
                                    [{:artifact "bitecho-full-node.cjs" :version "0.23.14" :cid lkg-code-cid}])
                      lkg-host-target {:arch "amd64"
                                       :profile-cid (:profile-cid lkg-manifest)
                                       :packages-manifest-cid (deploy/sha256-hex "pkg-manifest-v1")
                                       :kernel-version "6.1.0-56"
                                       :jdk-version "25.0.5"
                                       :node-version "22.23.5"
                                       :reboot-required? false
                                       :system-merkle-root (:system-merkle-root lkg-manifest)}
                      lkg-ptr (deploy/sign-config-pointer
                               auth-sk
                               {:network "devnet"
                                :seq 1
                                :activate-at-epoch 10
                                :code-target-cid lkg-code-cid
                                :host-target lkg-host-target
                                :system-merkle-root (:system-merkle-root lkg-manifest)
                                :author-pubkey auth-pk})
                      st0 (host/init-unified-watcher-state
                           {:node-id :ns3
                            :stage :canary
                            :arch "amd64"
                            :current-pointer lkg-ptr
                            :current-host-target lkg-host-target
                            :current-code-cid lkg-code-cid
                            :current-merkle-root (:system-merkle-root lkg-manifest)
                            :rootfs-snapshot "rootfs-snap-0"
                            :state-subvolume "@bitecho-state"
                            :trusted-deploy-authorities #{auth-pk}})]
                  (loop [rem cmds
                         st st0
                         next-seq 2
                         ok-so-far? true]
                    (if (or (empty? rem) (not ok-so-far?))
                      ok-so-far?
                      (let [cmd (first rem)
                            cur-gen (:generation st)
                            lkg-before (:last-known-good st)
                            pkg-bytes (utf8-bytes (str "openssh-pkg-seq-" next-seq))
                            pkg-cid (deploy/sha256-hex pkg-bytes)
                            pkg-meta (host/sign-binpkg-artifact
                                      auth-sk
                                      {:arch "amd64"
                                       :atom "net-misc/openssh"
                                       :version (str "9.9_p" next-seq)
                                       :filename (str "openssh-9.9_p" next-seq ".gpkg.tar")
                                       :sha256-cid pkg-cid
                                       :signer-pubkey auth-pk})
                            new-code-bytes (utf8-bytes (str "full-node-seq-" next-seq))
                            new-code-cid (deploy/sha256-hex new-code-bytes)
                            new-manifest (sample-manifest
                                          "amd64"
                                          [{:atom "net-misc/openssh" :version (str "9.9_p" next-seq) :cid pkg-cid}]
                                          [{:name "nodejs" :version "22.23.5" :cid (deploy/sha256-hex "node-22.23.5")}]
                                          [{:artifact "bitecho-full-node.cjs" :version "0.23.15" :cid new-code-cid}])
                            new-host-target {:arch "amd64"
                                             :profile-cid (:profile-cid new-manifest)
                                             :packages-manifest-cid (deploy/sha256-hex (str "pkg-manifest-" next-seq))
                                             :kernel-version "6.1.0-56"
                                             :jdk-version "25.0.5"
                                             :node-version "22.23.5"
                                             :reboot-required? false
                                             :system-merkle-root (:system-merkle-root new-manifest)}
                            new-ptr (deploy/sign-config-pointer
                                     auth-sk
                                     {:network "devnet"
                                      :seq next-seq
                                      :activate-at-epoch (+ 10 next-seq)
                                      :code-target-cid new-code-cid
                                      :host-target new-host-target
                                      :system-merkle-root (:system-merkle-root new-manifest)
                                      :author-pubkey auth-pk})]
                        (case cmd
                          :stale-callback
                          (let [[st' effs] (host/reduce-unified-rollout-tick
                                            st
                                            {:type :host-layer-applied
                                             :generation (dec cur-gen)
                                             :ok? true})]
                            (recur (rest rem)
                                   st'
                                   next-seq
                                   (and (= (inc (:dropped st)) (:dropped st'))
                                        (some #(= :stale-generation-callback (:reason %)) effs)
                                        (= (:state-subvolume st) "@bitecho-state"))))

                          :advance-tampered-code
                          (let [[st' effs] (host/reduce-unified-rollout-tick
                                            st
                                            {:type :pointer-advance
                                             :epoch (+ 10 next-seq)
                                             :pointer new-ptr
                                             :binpkg-artifacts [{:meta pkg-meta :bytes pkg-bytes}]
                                             :code-artifact-bytes (utf8-bytes "tampered-node-bytes")
                                             :expected-manifest new-manifest})]
                            (recur (rest rem)
                                   st'
                                   (inc next-seq)
                                   (and (= (:current-code-cid st') (:code-cid lkg-before))
                                        (= (:current-host-target st') (:host-target lkg-before))
                                        (some #(= :diagnose (:effect %)) effs))))

                          :advance-fail-at-host
                          (let [[st1 _] (host/reduce-unified-rollout-tick
                                         st
                                         {:type :pointer-advance
                                          :epoch (+ 10 next-seq)
                                          :pointer new-ptr
                                          :binpkg-artifacts [{:meta pkg-meta :bytes pkg-bytes}]
                                          :code-artifact-bytes new-code-bytes
                                          :expected-manifest new-manifest})
                                [st2 effs2] (host/reduce-unified-rollout-tick
                                             st1
                                             {:type :host-layer-applied
                                              :epoch (+ 10 next-seq)
                                              :ok? false
                                              :error :emerge-exit-1})]
                            (recur (rest rem)
                                   st2
                                   (inc next-seq)
                                   (and (= :rolled-back (:phase st2))
                                        (= (:current-code-cid st2) (:code-cid lkg-before))
                                        (= (:current-host-target st2) (:host-target lkg-before))
                                        (= (:state-subvolume st2) "@bitecho-state")
                                        (some #(= :restore-rootfs-snapshot (:effect %)) effs2)
                                        (some #(= :unified-rollout-combined-rollback (:reason %)) effs2))))

                          :advance-fail-at-node
                          (let [[st1 _] (host/reduce-unified-rollout-tick
                                         st
                                         {:type :pointer-advance
                                          :epoch (+ 10 next-seq)
                                          :pointer new-ptr
                                          :binpkg-artifacts [{:meta pkg-meta :bytes pkg-bytes}]
                                          :code-artifact-bytes new-code-bytes
                                          :expected-manifest new-manifest})
                                [st2 _] (host/reduce-unified-rollout-tick
                                         st1
                                         {:type :host-layer-applied
                                          :epoch (+ 10 next-seq)
                                          :ok? true
                                          :actual-merkle-root (:system-merkle-root new-manifest)})
                                [st3 effs3] (host/reduce-unified-rollout-tick
                                             st2
                                             {:type :node-layer-applied
                                              :epoch (+ 10 next-seq)
                                              :ok? false
                                              :error :node-rejoin-timeout})]
                            (recur (rest rem)
                                   st3
                                   (inc next-seq)
                                   (and (= :rolled-back (:phase st3))
                                        (= (:current-code-cid st3) (:code-cid lkg-before))
                                        (= (:current-host-target st3) (:host-target lkg-before))
                                        (= (:state-subvolume st3) "@bitecho-state")
                                        (some #(= :restore-rootfs-snapshot (:effect %)) effs3)
                                        (some #(= :restore-lkg-node-bundle (:effect %)) effs3)
                                        (some #(= :unified-rollout-combined-rollback (:reason %)) effs3))))

                          :valid-advance-and-succeed
                          (let [[st1 effs1] (host/reduce-unified-rollout-tick
                                             st
                                             {:type :pointer-advance
                                              :epoch (+ 10 next-seq)
                                              :pointer new-ptr
                                              :binpkg-artifacts [{:meta pkg-meta :bytes pkg-bytes}]
                                              :code-artifact-bytes new-code-bytes
                                              :expected-manifest new-manifest})
                                [st2 effs2] (host/reduce-unified-rollout-tick
                                             st1
                                             {:type :host-layer-applied
                                              :epoch (+ 10 next-seq)
                                              :ok? true
                                              :actual-merkle-root (:system-merkle-root new-manifest)})
                                [st3 effs3] (host/reduce-unified-rollout-tick
                                             st2
                                             {:type :node-layer-applied
                                              :epoch (+ 10 next-seq)
                                              :ok? true
                                              :attested-pointer-seq next-seq
                                              :attested-merkle-root (:system-merkle-root new-manifest)})]
                            (recur (rest rem)
                                   st3
                                   (inc next-seq)
                                   (and (some #(= :take-rootfs-snapshot (:effect %)) effs1)
                                        (some #(= :apply-host-binpkgs (:effect %)) effs1)
                                        (some #(= :swap-full-node-bundle (:effect %)) effs2)
                                        (= :watching (:phase st3))
                                        (= new-code-cid (:current-code-cid st3))
                                        (= (:system-merkle-root new-manifest) (:current-merkle-root st3))
                                        (some #(= :audit-record (:effect %)) effs3)))))))))))

;; =============================================================================
;; 2. Deterministic Proof Scenarios S-D37-1 through S-D37-7
;; =============================================================================

(deftest s-d37-1-reproducible-image-test
  (testing "S-D37-1: Two independent builds of P-HOST-1 from pinned inputs produce identical OS & runtime subtree hashes"
    (let [profile-amd64 (host/gentoo-profile-spec "amd64")
          profile-arm64 (host/gentoo-profile-spec "arm64")
          os-pkgs [{:atom "sys-kernel/gentoo-kernel-bin" :version "6.1.0-56" :cid (deploy/sha256-hex "kernel-6.1.0-56")}
                   {:atom "sys-apps/openrc" :version "0.55.1" :cid (deploy/sha256-hex "openrc-0.55.1")}
                   {:atom "net-misc/openssh" :version "9.9_p1" :cid (deploy/sha256-hex "openssh-9.9_p1")}
                   {:atom "sys-fs/btrfs-progs" :version "6.11" :cid (deploy/sha256-hex "btrfs-6.11")}]
          runtimes [{:name "openjdk" :version "25.0.5.1+2-LTS" :cid (deploy/sha256-hex "temurin-25.0.5")}
                    {:name "nodejs" :version "22.23.5" :cid (deploy/sha256-hex "node-22.23.5")}]
          apps [{:artifact "bitecho-full-node.cjs" :version "0.23.15" :cid (deploy/sha256-hex "full-node-0.23.15")}]
          build-1 (sample-manifest "amd64" os-pkgs runtimes apps)
          build-2 (sample-manifest "amd64" (reverse os-pkgs) (reverse runtimes) apps)
          repro (host/verify-reproducible-builds build-1 build-2)
          non-repro-build (sample-manifest "amd64"
                                           (conj os-pkgs {:atom "app-misc/nondet" :version "1.0" :cid (deploy/sha256-hex "ts-999")})
                                           runtimes
                                           apps)
          non-repro-res (host/verify-reproducible-builds build-1 non-repro-build)]
      (is (true? (:ok? (host/validate-profile-spec profile-amd64))))
      (is (true? (:ok? (host/validate-profile-spec profile-arm64))))
      (is (= "default/linux/amd64/23.0/no-multilib/hardened" (:profile profile-amd64)))
      (is (= "default/linux/arm64/23.0/no-multilib/hardened" (:profile profile-arm64)))
      (is (= :openrc (:init profile-amd64)))
      (is (= :supervise-daemon (:supervisor profile-amd64)))
      (is (= "@bitecho-state" (get-in profile-amd64 [:subvolumes :state])))
      (is (true? (:reproducible? repro)))
      (is (= (get-in build-1 [:subtree-roots :os-subtree])
             (get-in build-2 [:subtree-roots :os-subtree])))
      (is (= (get-in build-1 [:subtree-roots :runtime-subtree])
             (get-in build-2 [:subtree-roots :runtime-subtree])))
      (is (= (:system-merkle-root build-1) (:system-merkle-root build-2)))
      (is (false? (:reproducible? non-repro-res)))
      (is (= [:os-subtree] (:divergent-subtrees non-repro-res)))
      (is (some #(= :non-reproducible-image-build (:reason %)) (:effects non-repro-res))))))

(deftest s-d37-2-pointer-driven-host-update-test
  (testing "S-D37-2: :host-target pointer move applies signed binpkg update on canary at epoch gate, refuses tampered/unsigned, emits P-DEPLOY-5 audit records"
    (let [auth-kp (crypto/generate-keypair "s-d37-2-auth")
          auth-pk (kp->pk-hex auth-kp)
          auth-sk (:private auth-kp)
          pkg-bytes (utf8-bytes "openssh-9.9_p2-gpkg-tar-content")
          pkg-cid (deploy/sha256-hex pkg-bytes)
          signed-pkg (host/sign-binpkg-artifact
                      auth-sk
                      {:arch "amd64"
                       :atom "net-misc/openssh"
                       :version "9.9_p2"
                       :filename "openssh-9.9_p2.gpkg.tar"
                       :sha256-cid pkg-cid
                       :signer-pubkey auth-pk})
          unsigned-pkg (dissoc signed-pkg :signature)
          host-target {:arch "amd64"
                       :profile-cid (deploy/sha256-hex "hardened-amd64")
                       :packages-manifest-cid (deploy/sha256-hex "manifest-openssh-9.9p2")
                       :kernel-version "6.1.0-56"
                       :jdk-version "25.0.5"
                       :node-version "22.23.5"
                       :reboot-required? false}
          cfg-ptr (deploy/sign-config-pointer
                   auth-sk
                   {:network "devnet"
                    :seq 2
                    :activate-at-epoch 20
                    :code-target-cid (deploy/sha256-hex "full-node-0.23.15")
                    :host-target host-target
                    :author-pubkey auth-pk})
          node-st {:epoch 19
                   :node-id :ns3
                   :trusted-deploy-authorities #{auth-pk}
                   :config (config/devnet-6-config)
                   :audit-trail []
                   :diagnostics {}}
          ;; Refuses tampered bytes & unsigned package
          tampered-res (host/verify-host-target node-st host-target [{:meta signed-pkg :bytes (utf8-bytes "tampered")}])
          unsigned-res (host/verify-host-target node-st host-target [{:meta unsigned-pkg :bytes pkg-bytes}])
          ;; Valid package succeeds
          valid-res (host/verify-host-target node-st host-target [{:meta signed-pkg :bytes pkg-bytes}])
          ;; Stage & activate config pointer at epoch 20
          staged (deploy/stage-config-pointer node-st cfg-ptr)
          activated (deploy/apply-epoch-boundary-configs (:state staged) 20)
          audit-check (deploy/reconstruct-cluster-history-from-audit-trail (get-in activated [:state :audit-trail]) 20)]
      (is (false? (:ok? tampered-res)))
      (is (some #(= :binpkg-verification-failed (:reason %)) (:effects tampered-res)))
      (is (false? (:ok? unsigned-res)))
      (is (some #(= :binpkg-verification-failed (:reason %)) (:effects unsigned-res)))
      (is (true? (:ok? valid-res)))
      (is (true? (:ok? staged)))
      (is (true? (:activated? activated)))
      (is (= host-target (get-in activated [:state :config :host-target])))
      (is (true? (:chain-valid? audit-check)))
      (is (true? (:signatures-valid? audit-check))))))

(deftest s-d37-3-host-rollback-preserves-state-subvolume-test
  (testing "S-D37-3: Failed host update gate restores pre-update @rootfs snapshot while @bitecho-state and node identity remain untouched"
    (let [node-pk (kp->pk-hex (crypto/generate-keypair "s-d37-3-ns3"))
          h0 (host/init-host-state
              {:node-id :ns3
               :arch "amd64"
               :os-id "gentoo"
               :pubkey node-pk
               :balance 500000
               :epoch 34329
               :ips {:internal "10.128.0.5" :external "34.59.10.2"}
               :bootstrap-descriptors ["ns1.bitecho.org:443" "ns2.bitecho.org:443"]
               :home-sets #{:home-a :home-b}
               :rootfs-snapshot "rootfs-snap-pre-update"
               :state-subvolume "@bitecho-state"})
          [h1 effs1] (host/reduce-host-update h0 {:type :take-rootfs-snapshot
                                                  :snapshot-id "rootfs-snap-ep-34329"
                                                  :epoch 34329})
          [h2 _] (host/reduce-host-update h1 {:type :apply-host-update
                                              :epoch 34330
                                              :target-packages-cid (deploy/sha256-hex "bad-pkg-set")})
          [h3 effs3] (host/reduce-host-update h2 {:type :gate-failed
                                                  :epoch 34331
                                                  :reason :post-update-health-check-failed})]
      (is (some #(= :create-btrfs-snapshot (:effect %)) effs1))
      (is (= :rolled-back (:phase h3)))
      (is (= "rootfs-snap-ep-34329" (:active-rootfs-snapshot h3)))
      ;; @bitecho-state and node identity are NEVER rolled back
      (is (= "@bitecho-state" (:state-subvolume h3)))
      (is (= node-pk (:pubkey h3)))
      (is (= 500000 (:balance h3)))
      (is (= 34329 (:state-epoch h3)))
      (is (= #{:home-a :home-b} (:home-sets h3)))
      (is (some #(and (= :restore-rootfs-snapshot (:effect %))
                      (= "rootfs-snap-ep-34329" (:snapshot-id %))
                      (false? (:rollback-state-subvolume? %)))
                effs3))
      (is (some #(= :host-update-rolled-back (:reason %)) effs3)))))

(deftest s-d37-4-transition-continuity-and-pivot-abort-rollback-test
  (testing "S-D37-4: P-HOST-3 live migration preserves pubkey, balance, epoch, IPs, bootstrap descriptors, and home sets; pivot abort rolls back cleanly to Debian"
    (let [node-pk (kp->pk-hex (crypto/generate-keypair "s-d37-4-ns3"))
          debian-state (host/init-host-state
                        {:node-id :ns3
                         :arch "amd64"
                         :os-id "debian-12"
                         :pubkey node-pk
                         :balance 1250000
                         :epoch 34329
                         :ips {:internal "10.128.0.5" :external "34.59.10.2"}
                         :bootstrap-descriptors ["ns1.bitecho.org:443" "ns2.bitecho.org:443" "ns3.bitecho.org:443"]
                         :home-sets #{:subnet-alpha :subnet-beta}
                         :rootfs-snapshot "debian-pre-migration-snap"
                         :state-subvolume "@bitecho-state"})
          ;; Path A: Deliberate abort at pivot step rolls back to Debian
          [aborted abort-effs] (host/reduce-host-update
                                debian-state
                                {:type :stage3-pivot-abort
                                 :epoch 34329
                                 :pre-migration-snapshot "debian-pre-migration-snap"
                                 :reason :deliberate-pivot-abort})
          ;; Path B: Successful Stage3 live migration to Gentoo
          [migrated mig-effs] (host/reduce-host-update
                               aborted
                               {:type :stage3-live-migrate
                                :epoch 34330
                                :target-os "gentoo-2.18-hardened-openrc"
                                :stage3-cid (deploy/sha256-hex "stage3-amd64-hardened-openrc")
                                :peak-ram-mib 464
                                :peak-disk-mib 4206
                                :reboot-downtime-s 21})]
      ;; Abort verification
      (is (= "debian-12" (:os-id aborted)))
      (is (= :rolled-back (:phase aborted)))
      (is (= node-pk (:pubkey aborted)))
      (is (= 1250000 (:balance aborted)))
      (is (some #(= :stage3-pivot-aborted-rollback (:reason %)) abort-effs))
      ;; Successful migration continuity verification
      (is (= "gentoo-2.18-hardened-openrc" (:os-id migrated)))
      (is (= :steady (:phase migrated)))
      (is (= node-pk (:pubkey migrated)))
      (is (= 1250000 (:balance migrated)))
      (is (= 34329 (:state-epoch migrated)))
      (is (= {:internal "10.128.0.5" :external "34.59.10.2"} (:ips migrated)))
      (is (= ["ns1.bitecho.org:443" "ns2.bitecho.org:443" "ns3.bitecho.org:443"]
             (:bootstrap-descriptors migrated)))
      (is (= #{:subnet-alpha :subnet-beta} (:home-sets migrated)))
      (is (= "@bitecho-state" (:state-subvolume migrated)))
      (is (some #(= :audit-record (:effect %)) mig-effs)))))

(deftest s-d37-5-root-hash-attestation-and-divergence-localization-test
  (testing "S-D37-5: External verifier recomputes Merkle root from published manifest alone, verifies per-layer proof, localizes single-package divergence to :os-subtree"
    (let [os-pkgs [{:atom "sys-apps/openrc" :version "0.55.1" :cid (deploy/sha256-hex "openrc-0.55.1")}
                   {:atom "net-misc/openssh" :version "9.9_p1" :cid (deploy/sha256-hex "openssh-9.9_p1")}]
          runtimes [{:name "openjdk" :version "25.0.5" :cid (deploy/sha256-hex "jdk-25.0.5")}
                    {:name "nodejs" :version "22.23.5" :cid (deploy/sha256-hex "node-22.23.5")}]
          apps [{:artifact "bitecho-full-node.cjs" :version "0.23.15" :cid (deploy/sha256-hex "full-node-0.23.15")}]
          expected-manifest (sample-manifest "amd64" os-pkgs runtimes apps)
          claimed-root (:system-merkle-root expected-manifest)
          ;; External verifier receives only the manifest (stripped of precomputed roots) and recomputes
          external-view (dissoc expected-manifest :system-merkle-root :subtree-roots)
          recomputed (host/compute-system-merkle-root external-view)
          os-proof (host/generate-layer-proof expected-manifest :os-subtree)
          rt-proof (host/generate-layer-proof expected-manifest :runtime-subtree)
          app-proof (host/generate-layer-proof expected-manifest :app-subtree)
          ;; Single OS package change flips ONLY :os-subtree and the root
          drifted-manifest (sample-manifest
                            "amd64"
                            [(first os-pkgs)
                             {:atom "net-misc/openssh" :version "9.9_p2" :cid (deploy/sha256-hex "openssh-9.9_p2")}]
                            runtimes
                            apps)
          div (host/localize-merkle-divergence expected-manifest drifted-manifest)]
      (is (= claimed-root (:system-merkle-root recomputed)))
      (is (true? (:valid? (host/verify-layer-proof os-proof claimed-root))))
      (is (true? (:valid? (host/verify-layer-proof rt-proof claimed-root))))
      (is (true? (:valid? (host/verify-layer-proof app-proof claimed-root))))
      (is (false? (:match? div)))
      (is (= [:os-subtree] (:divergent-subtrees div)))
      (is (= (get-in expected-manifest [:subtree-roots :runtime-subtree])
             (get-in drifted-manifest [:subtree-roots :runtime-subtree])))
      (is (= (get-in expected-manifest [:subtree-roots :app-subtree])
             (get-in drifted-manifest [:subtree-roots :app-subtree]))))))

(deftest s-d37-6-kexec-kernel-update-and-fallback-gate-test
  (testing "S-D37-6: Kernel bump with :reboot-required? true completes via kexec inside downtime budget; failure falls back to cold reboot and two consecutive failures trip stage gate"
    (let [h0 (host/init-host-state
              {:node-id :ns3
               :arch "amd64"
               :os-id "gentoo"
               :kernel-version "6.1.0-56"
               :kexec-budget-ms 10000})
          ;; 1. Successful kexec kernel bump inside downtime budget (4200ms <= 10000ms)
          [h-ok effs-ok] (host/reduce-kexec-update
                          h0
                          {:epoch 40
                           :kernel-version "6.6.62-gentoo"
                           :reboot-required? true
                           :kexec-ok? true
                           :downtime-ms 4200})
          ;; 2. First kexec failure falls back to cold reboot (gate NOT tripped yet)
          [h-fail1 effs-fail1] (host/reduce-kexec-update
                                h-ok
                                {:epoch 41
                                 :kernel-version "6.6.63-gentoo"
                                 :reboot-required? true
                                 :kexec-ok? false
                                 :downtime-ms 45000})
          ;; 3. Second consecutive kexec failure trips the stage gate
          [h-fail2 effs-fail2] (host/reduce-kexec-update
                                h-fail1
                                {:epoch 42
                                 :kernel-version "6.6.64-gentoo"
                                 :reboot-required? true
                                 :kexec-ok? false
                                 :downtime-ms 46000})]
      (is (= "6.6.62-gentoo" (:kernel-version h-ok)))
      (is (= 0 (:kexec-consecutive-failures h-ok)))
      (is (some #(= :kexec-reboot (:effect %)) effs-ok))
      (is (= 1 (:kexec-consecutive-failures h-fail1)))
      (is (not (true? (:stage-gate-tripped? h-fail1))))
      (is (some #(= :cold-reboot (:effect %)) effs-fail1))
      (is (some #(= :kexec-fallback-cold-reboot (:reason %)) effs-fail1))
      (is (= 2 (:kexec-consecutive-failures h-fail2)))
      (is (true? (:stage-gate-tripped? h-fail2)))
      (is (= :gate-tripped (:phase h-fail2)))
      (is (some #(= :kexec-consecutive-failures-gate-tripped (:reason %)) effs-fail2)))))

(deftest s-d37-7-unified-pointer-move-and-combined-rollback-test
  (testing "S-D37-7: Single config-pointer advance rolls binpkg + full-node release with no manual step; second-layer failure or tampered artifact trips combined mechanical rollback"
    (let [auth-kp (crypto/generate-keypair "s-d37-7-auth")
          auth-pk (kp->pk-hex auth-kp)
          auth-sk (:private auth-kp)
          v14-bytes (utf8-bytes "bitecho-full-node-0.23.14")
          v14-cid (deploy/sha256-hex v14-bytes)
          v14-manifest (sample-manifest
                        "amd64"
                        [{:atom "net-misc/openssh" :version "9.9_p1" :cid (deploy/sha256-hex "openssh-9.9p1")}]
                        [{:name "nodejs" :version "22.23.5" :cid (deploy/sha256-hex "node-22.23.5")}]
                        [{:artifact "bitecho-full-node.cjs" :version "0.23.14" :cid v14-cid}])
          v14-host {:arch "amd64"
                    :profile-cid (:profile-cid v14-manifest)
                    :packages-manifest-cid (deploy/sha256-hex "pkgs-v14")
                    :kernel-version "6.1.0-56"
                    :jdk-version "25.0.5"
                    :node-version "22.23.5"
                    :reboot-required? false
                    :system-merkle-root (:system-merkle-root v14-manifest)}
          v14-ptr (deploy/sign-config-pointer
                   auth-sk
                   {:network "devnet"
                    :seq 1
                    :activate-at-epoch 50
                    :code-target-cid v14-cid
                    :host-target v14-host
                    :system-merkle-root (:system-merkle-root v14-manifest)
                    :author-pubkey auth-pk})
          ;; Prepare v15 unified advance (binpkg + full-node release)
          pkg-v15-bytes (utf8-bytes "openssh-9.9_p2.gpkg.tar")
          pkg-v15-cid (deploy/sha256-hex pkg-v15-bytes)
          pkg-v15-meta (host/sign-binpkg-artifact
                        auth-sk
                        {:arch "amd64"
                         :atom "net-misc/openssh"
                         :version "9.9_p2"
                         :filename "openssh-9.9_p2.gpkg.tar"
                         :sha256-cid pkg-v15-cid
                         :signer-pubkey auth-pk})
          v15-bytes (utf8-bytes "bitecho-full-node-0.23.15")
          v15-cid (deploy/sha256-hex v15-bytes)
          v15-manifest (sample-manifest
                        "amd64"
                        [{:atom "net-misc/openssh" :version "9.9_p2" :cid pkg-v15-cid}]
                        [{:name "nodejs" :version "22.23.5" :cid (deploy/sha256-hex "node-22.23.5")}]
                        [{:artifact "bitecho-full-node.cjs" :version "0.23.15" :cid v15-cid}])
          v15-host {:arch "amd64"
                    :profile-cid (:profile-cid v15-manifest)
                    :packages-manifest-cid (deploy/sha256-hex "pkgs-v15")
                    :kernel-version "6.1.0-56"
                    :jdk-version "25.0.5"
                    :node-version "22.23.5"
                    :reboot-required? false
                    :system-merkle-root (:system-merkle-root v15-manifest)}
          v15-ptr (deploy/sign-config-pointer
                   auth-sk
                   {:network "devnet"
                    :seq 2
                    :activate-at-epoch 58
                    :code-target-cid v15-cid
                    :host-target v15-host
                    :system-merkle-root (:system-merkle-root v15-manifest)
                    :author-pubkey auth-pk})
          w0 (host/init-unified-watcher-state
              {:node-id :ns3
               :stage :canary
               :arch "amd64"
               :current-pointer v14-ptr
               :current-host-target v14-host
               :current-code-cid v14-cid
               :current-merkle-root (:system-merkle-root v14-manifest)
               :rootfs-snapshot "rootfs-snap-v14"
               :state-subvolume "@bitecho-state"
               :trusted-deploy-authorities #{auth-pk}})
          ;; A. Happy path: host-then-node succeeds atomically
          [w1 effs1] (host/reduce-unified-rollout-tick
                      w0
                      {:type :pointer-advance
                       :epoch 58
                       :pointer v15-ptr
                       :binpkg-artifacts [{:meta pkg-v15-meta :bytes pkg-v15-bytes}]
                       :code-artifact-bytes v15-bytes
                       :expected-manifest v15-manifest})
          [w2 effs2] (host/reduce-unified-rollout-tick
                      w1
                      {:type :host-layer-applied
                       :epoch 58
                       :ok? true
                       :actual-merkle-root (:system-merkle-root v15-manifest)})
          [w3 effs3] (host/reduce-unified-rollout-tick
                      w2
                      {:type :node-layer-applied
                       :epoch 58
                       :ok? true
                       :attested-pointer-seq 2
                       :attested-merkle-root (:system-merkle-root v15-manifest)})
          ;; B. Second-layer failure after first layer applied -> combined mechanical rollback!
          [w-rb-final effs-rb] (host/reduce-unified-rollout-tick
                                w2
                                {:type :node-layer-applied
                                 :epoch 58
                                 :ok? false
                                 :error :full-node-self-test-failed})
          ;; C. Tampered binpkg rejected before anything is applied
          [w-tamp effs-tamp] (host/reduce-unified-rollout-tick
                              w0
                              {:type :pointer-advance
                               :epoch 58
                               :pointer v15-ptr
                               :binpkg-artifacts [{:meta pkg-v15-meta :bytes (utf8-bytes "corrupted-binpkg")}]
                               :code-artifact-bytes v15-bytes
                               :expected-manifest v15-manifest})]
      ;; Happy path assertions
      (is (= :applying-host (:phase w1)))
      (is (some #(= :take-rootfs-snapshot (:effect %)) effs1))
      (is (some #(= :apply-host-binpkgs (:effect %)) effs1))
      (is (= :applying-node (:phase w2)))
      (is (some #(= :swap-full-node-bundle (:effect %)) effs2))
      (is (some #(= :exit-75-respawn (:effect %)) effs2))
      (is (= :watching (:phase w3)))
      (is (= v15-cid (:current-code-cid w3)))
      (is (= (:system-merkle-root v15-manifest) (:current-merkle-root w3)))
      (is (= 2 (get-in w3 [:current-pointer :seq])))
      (is (some #(= :audit-record (:effect %)) effs3))
      (is (true? (:chain-valid? (deploy/reconstruct-cluster-history-from-audit-trail (:audit-trail w3) 58))))
      ;; Combined rollback assertions (host + node consistent on v14, @bitecho-state untouched)
      (is (= :rolled-back (:phase w-rb-final)))
      (is (= v14-cid (:current-code-cid w-rb-final)))
      (is (= v14-host (:current-host-target w-rb-final)))
      (is (= (:system-merkle-root v14-manifest) (:current-merkle-root w-rb-final)))
      (is (= "@bitecho-state" (:state-subvolume w-rb-final)))
      (is (some #(= :restore-rootfs-snapshot (:effect %)) effs-rb))
      (is (some #(= :restore-lkg-node-bundle (:effect %)) effs-rb))
      (is (some #(= :unified-rollout-combined-rollback (:reason %)) effs-rb))
      (is (true? (:chain-valid? (deploy/reconstruct-cluster-history-from-audit-trail (:audit-trail w-rb-final) 58))))
      ;; Tampered artifact rejection assertions
      (is (= :watching (:phase w-tamp)))
      (is (= v14-cid (:current-code-cid w-tamp)))
      (is (some #(= :unified-pointer-verification-failed (:reason %)) effs-tamp)))))

(deftest s-d37-8-ops-scripts-runbook-and-bip011-receipt-test
  (testing "Rule 6: Co-committed ops scripts, OpenRC init scripts, provider-agnostic runbook, version bump, and BIP-011 8-gate receipt"
    (is (= "0.23.15" config/version))
    (doseq [path ["scripts/gentoo-stage3-live-migrate.sh"
                  "docs/runbooks/gentoo-stage3-live-migration.md"
                  "scripts/gentoo-openrc/bitecho-infra.initd"
                  "scripts/gentoo-openrc/bitecho-validator.initd"
                  "scripts/run-infra-node.sh"
                  "scripts/run-validator-node.sh"
                  "docs/bips/bip-011-v02315.edn"]]
      (is (.exists (io/file path)) (str "Required co-committed deliverable missing: " path)))
    (let [migrate-sh (slurp "scripts/gentoo-stage3-live-migrate.sh")
          infra-initd (slurp "scripts/gentoo-openrc/bitecho-infra.initd")
          val-initd (slurp "scripts/gentoo-openrc/bitecho-validator.initd")
          run-infra (slurp "scripts/run-infra-node.sh")
          run-val (slurp "scripts/run-validator-node.sh")
          bip011-spec (edn/read-string (slurp "docs/bips/bip-011-v02315.edn"))
          gate-check (gov/verify-bip-admission-gates bip011-spec)]
      (is (str/includes? migrate-sh "--dry-run"))
      (is (str/includes? migrate-sh "RENAME_EXCHANGE"))
      (is (str/includes? infra-initd "supervise-daemon"))
      (is (str/includes? val-initd "supervise-daemon"))
      (is (str/includes? run-infra "active.edn"))
      (is (str/includes? run-val "active.edn"))
      (is (true? (:ok? gate-check)) (str "BIP-011 missing gates: " (:missing-gates gate-check)))
      (is (empty? (:missing-gates gate-check))))))
