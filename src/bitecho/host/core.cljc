(ns bitecho.host.core
  "Milestone D37 (`BIP-011: Gentoo Host-Layer Migration, On-Network Binhost,
   Unified Pointer-Driven Rolling Upgrades, and Merkle Root-Hash Attestation` / `v0.23.15`).
   100% Pure Sans-IO `.cljc` Engine (Rule 2, Rule 4, Rule 5):
   - `P-HOST-1`: Minimal hardened Gentoo profile family (`default/linux/<arch>/23.0/no-multilib/hardened`,
     OpenRC + `supervise-daemon`, `zram`, isolated `@bitecho-state` Btrfs subvolume)
   - `P-HOST-2`: On-network binhost (`host/gentoo/binpkgs/<arch>/`) `.gpkg.tar` Ed25519 signature
     verification and `:host-target` schema validation
   - `P-HOST-4`: Host rollback reducer (`@rootfs` snapshot restore with `@bitecho-state` immutability)
     and `kexec` kernel update transition reducer
   - `P-HOST-5`: 3-subtree Merkle root-hash attestation (`:os-subtree`, `:runtime-subtree`, `:app-subtree`),
     per-layer Merkle proofs, single-package divergence localization, and reproducibility verification
   - `P-HOST-6`: Unified dynamic rolling upgrade pure reducer (single config-pointer advance rolling
     both `:host-target` binpackages and full-node code host-then-node, with atomic combined mechanical
     rollback on failure in either layer and counted `:diagnose` effects)."
  (:refer-clojure :exclude [bytes?])
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.core.data :as data]
            [bitecho.crypto :as crypto]
            [bitecho.deploy.core :as deploy]
            [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(def ^:private bytes? fressian/bytes?)

(defn- normalize-hex
  [s]
  (when (and (string? s) (not (str/blank? s)))
    (str/lower-case (str/trim s))))

(defn- valid-sha256-hex?
  [s]
  (let [n (normalize-hex s)]
    (boolean (and n (= 64 (count n)) (re-matches #"^[0-9a-f]{64}$" n)))))

;; =============================================================================
;; 1. P-HOST-1: Minimal Hardened Gentoo Profile Family
;; =============================================================================

(def supported-architectures
  "Architectures supported by the BIP-011 Gentoo profile family (`P-HOST-1`)."
  #{"amd64" "arm64"})

(def disallowed-production-packages
  "Compiler toolchain packages excluded from minimal production Gentoo images (`P-HOST-1`)."
  #{"sys-devel/gcc" "sys-devel/clang" "sys-devel/binutils"})

(defn binhost-channel-path
  "Returns the on-network binhost channel prefix for `arch` (`P-HOST-2`)."
  [arch]
  (let [a (str/lower-case (str/trim (str (or arch "amd64"))))]
    (str "host/gentoo/binpkgs/" a "/")))

(defn binhost-package-path
  "Returns the full on-network binhost artifact path for `arch` and `pkg-filename` (`P-HOST-2`)."
  [arch pkg-filename]
  (str (binhost-channel-path arch) (str/replace (str (or pkg-filename "")) #"^/+" "")))

(defn gentoo-profile-spec
  "Returns the canonical P-HOST-1 minimal hardened Gentoo profile specification for `arch`."
  ([arch]
   (gentoo-profile-spec arch nil))
  ([arch opts]
   (let [a (str/lower-case (str/trim (str (or arch "amd64"))))]
     (merge
      {:arch a
       :profile (str "default/linux/" a "/23.0/no-multilib/hardened")
       :init :openrc
       :supervisor :supervise-daemon
       :zram {:enabled? true
              :algo "zstd"
              :percent 100
              :priority 100}
       :subvolumes {:rootfs "@rootfs"
                    :state "@bitecho-state"
                    :state-isolated? true}
       :use-flags ["-X" "-wayland" "-gtk" "-qt5" "-qt6" "-alsa" "-pulseaudio"
                   "-bluetooth" "-cups" "-nls" "-doc" "-examples"
                   "hardened" "pie" "ssp" "zstd"]
       :exclude-packages disallowed-production-packages
       :core-packages ["sys-kernel/gentoo-kernel-bin"
                       "dev-java/openjdk-bin:25"
                       "net-libs/nodejs:22"
                       "sys-apps/openrc"
                       "net-misc/openssh"
                       "sys-fs/btrfs-progs"
                       "sys-apps/kexec-tools"]
       :binhost-channel (binhost-channel-path a)}
      opts))))

(defn validate-profile-spec
  "Validates a P-HOST-1 Gentoo profile specification."
  [profile-spec]
  (let [arch (:arch profile-spec)
        profile (str (:profile profile-spec))
        core-pkgs (set (:core-packages profile-spec))
        has-compiler? (boolean (some disallowed-production-packages core-pkgs))
        errors
        (cond-> []
          (not (contains? supported-architectures arch))
          (conj :unsupported-architecture)

          (not (str/ends-with? profile "/23.0/no-multilib/hardened"))
          (conj :non-hardened-profile)

          (not= :openrc (:init profile-spec))
          (conj :init-must-be-openrc)

          (not= :supervise-daemon (:supervisor profile-spec))
          (conj :supervisor-must-be-supervise-daemon)

          (not (true? (get-in profile-spec [:zram :enabled?])))
          (conj :zram-must-be-enabled)

          (not (and (= "@rootfs" (get-in profile-spec [:subvolumes :rootfs]))
                    (= "@bitecho-state" (get-in profile-spec [:subvolumes :state]))
                    (true? (get-in profile-spec [:subvolumes :state-isolated?]))))
          (conj :state-subvolume-not-isolated)

          has-compiler?
          (conj :compiler-toolchain-in-production-image))]
    {:ok? (empty? errors)
     :errors errors}))

;; =============================================================================
;; 2. P-HOST-2: On-Network Binhost & :host-target Validation
;; =============================================================================

(defn canonical-binpkg-signing-payload
  "Canonical domain-separated signing payload for a `.gpkg.tar` binhost package (`P-HOST-2`)."
  [{:keys [arch atom version filename sha256-cid signer-pubkey]}]
  ["bitecho-gentoo-binpkg-v1"
   (str/lower-case (str/trim (str (or arch "amd64"))))
   (str (or atom ""))
   (str (or version ""))
   (str (or filename ""))
   (or (normalize-hex sha256-cid) "")
   (or (normalize-hex signer-pubkey) "")])

(defn sign-binpkg-artifact
  "Signs a binpkg metadata map with `authority-privkey` (`P-HOST-2`)."
  [authority-privkey pkg-meta]
  (let [payload (canonical-binpkg-signing-payload pkg-meta)
        sig (crypto/sign-canonical authority-privkey payload)
        sig-hex (str/lower-case (if (string? sig) sig (basalt/bytes->hex sig)))]
    (assoc pkg-meta
           :sha256-cid (normalize-hex (:sha256-cid pkg-meta))
           :signer-pubkey (normalize-hex (:signer-pubkey pkg-meta))
           :signature sig-hex)))

(defn verify-binpkg-artifact
  "Fail-closed `.gpkg.tar` package verifier (`P-HOST-2`, `Rule 5`):
   Verifies SHA-256 content digest, trusted authority membership, and Ed25519 signature.
   Emits a counted `:diagnose` (`:reason :binpkg-verification-failed`) on any failure."
  [state pkg-meta pkg-bytes]
  (let [expected-cid (normalize-hex (:sha256-cid pkg-meta))
        actual-cid (when (and pkg-bytes (bytes? pkg-bytes))
                     (deploy/sha256-hex pkg-bytes))
        hash-ok? (and (some? expected-cid)
                      (some? actual-cid)
                      (= expected-cid actual-cid))
        signer (normalize-hex (:signer-pubkey pkg-meta))
        sig (normalize-hex (:signature pkg-meta))
        trusted (set (map normalize-hex (or (:trusted-deploy-authorities state)
                                            (get-in state [:config :trusted-deploy-authorities])
                                            [])))
        auth-ok? (and (some? signer)
                      (or (empty? trusted) (contains? trusted signer)))
        sig-ok? (boolean
                 (when (and (some? signer) (some? sig))
                   (try
                     (crypto/verify-with-fallback
                      (basalt/hex->bytes signer)
                      (canonical-binpkg-signing-payload pkg-meta)
                      (basalt/hex->bytes sig))
                     (catch #?(:clj Exception :cljs :default) _ false))))]
    (if (and hash-ok? auth-ok? sig-ok?)
      {:ok? true
       :cid actual-cid
       :path (binhost-package-path (:arch pkg-meta) (:filename pkg-meta))
       :state state
       :effects []}
      (let [cause (cond
                    (not hash-ok?) :binpkg-hash-mismatch
                    (not (some? sig)) :binpkg-unsigned
                    (not auth-ok?) :binpkg-untrusted-signer
                    (not sig-ok?) :binpkg-invalid-signature
                    :else :binpkg-verification-failed)
            diag {:effect :diagnose
                  :type :diagnose
                  :reason :binpkg-verification-failed
                  :cause cause
                  :atom (:atom pkg-meta)
                  :filename (:filename pkg-meta)
                  :expected-cid expected-cid
                  :actual-cid actual-cid}
            st' (update-in (or state {:diagnostics {}})
                           [:diagnostics :binpkg-verification-failed]
                           (fnil inc 0))]
        {:ok? false
         :error :binpkg-verification-failed
         :cause cause
         :state st'
         :effects [diag]}))))

(defn validate-host-target
  "Validates the `:host-target` schema in `config/<network>/active.edn` (`P-HOST-2`)."
  [host-target]
  (if-not (map? host-target)
    {:ok? false :errors [:host-target-not-a-map]}
    (let [arch (str/lower-case (str/trim (str (or (:arch host-target) "amd64"))))
          errors
          (cond-> []
            (not (contains? supported-architectures arch))
            (conj :unsupported-arch)

            (not (valid-sha256-hex? (:profile-cid host-target)))
            (conj :invalid-profile-cid)

            (not (valid-sha256-hex? (:packages-manifest-cid host-target)))
            (conj :invalid-packages-manifest-cid)

            (str/blank? (str (:kernel-version host-target)))
            (conj :missing-kernel-version)

            (str/blank? (str (:jdk-version host-target)))
            (conj :missing-jdk-version)

            (str/blank? (str (:node-version host-target)))
            (conj :missing-node-version)

            (not (boolean? (:reboot-required? host-target)))
            (conj :reboot-required-must-be-boolean)

            (and (contains? host-target :system-merkle-root)
                 (some? (:system-merkle-root host-target))
                 (not (valid-sha256-hex? (:system-merkle-root host-target))))
            (conj :invalid-system-merkle-root))]
      {:ok? (empty? errors)
       :errors errors})))

(defn verify-host-target
  "Verifies `:host-target` schema and every binpkg artifact `{:meta ... :bytes ...}` (`P-HOST-2`, `Rule 5`)."
  ([state host-target]
   (verify-host-target state host-target nil))
  ([state host-target binpkg-artifacts]
   (let [schema-res (validate-host-target host-target)]
     (if-not (:ok? schema-res)
       (let [diag {:effect :diagnose
                   :type :diagnose
                   :reason :invalid-host-target-schema
                   :errors (:errors schema-res)}
             st' (update-in (or state {:diagnostics {}})
                            [:diagnostics :invalid-host-target-schema]
                            (fnil inc 0))]
         {:ok? false
          :error :invalid-host-target-schema
          :errors (:errors schema-res)
          :state st'
          :effects [diag]})
       (loop [rem (vec (or binpkg-artifacts []))
              st (or state {:diagnostics {}})
              effs []]
         (if (empty? rem)
           {:ok? true
            :host-target host-target
            :state st
            :effects effs}
           (let [{pkg-meta :meta pkg-bytes :bytes} (first rem)
                 v (verify-binpkg-artifact st pkg-meta pkg-bytes)]
             (if-not (:ok? v)
               {:ok? false
                :error (:error v)
                :cause (:cause v)
                :state (:state v)
                :effects (into effs (:effects v))}
               (recur (subvec rem 1)
                      (:state v)
                      (into effs (:effects v)))))))))))

;; =============================================================================
;; 3. P-HOST-5: 3-Subtree Merkle Root-Hash Attestation
;; =============================================================================

(def merkle-layer-order
  "Canonical 3-subtree layering for system root-hash attestation (`P-HOST-5`)."
  [:os-subtree :runtime-subtree :app-subtree])

(defn- normalize-os-entry
  [e]
  {:kind :os
   :atom (str (or (:atom e) ""))
   :version (str (or (:version e) ""))
   :cid (or (normalize-hex (:cid e)) "")})

(defn- normalize-runtime-entry
  [e]
  {:kind :runtime
   :name (str (or (:name e) ""))
   :version (str (or (:version e) ""))
   :cid (or (normalize-hex (:cid e)) "")})

(defn- normalize-app-entry
  [e]
  {:kind :app
   :artifact (str (or (:artifact e) ""))
   :version (str (or (:version e) ""))
   :cid (or (normalize-hex (:cid e)) "")})

(defn- compute-layer-subtree-root
  "Computes the RFC 6962 Merkle root over a layer's deterministically sorted entries."
  [layer-kw entries]
  (if (empty? entries)
    (deploy/sha256-hex ["bitecho-system-merkle-empty-layer-v1" (name layer-kw)])
    (data/compute-rfc6962-merkle-root
     (mapv (fn [entry] ["bitecho-system-merkle-entry-v1" (name layer-kw) entry])
           entries))))

(defn- combine-three-subtrees
  "Combines the 3 layer subtree roots into one canonical binary Merkle root:
   `left = branch(os, runtime)`, `root = branch(left, app)`."
  [os-root runtime-root app-root]
  (let [left (data/merkle-branch-hash os-root runtime-root)]
    (data/merkle-branch-hash left app-root)))

(defn validate-attestation-manifest
  "Fail-closed P-HOST-5 / F-SADV1-1 attestation manifest validator:
   Requires `(map? manifest)`, `(map? (:layers manifest))`, and non-empty sequential
   `:os-subtree`, `:runtime-subtree`, and `:app-subtree`.
   Returns `{:ok? true :manifest manifest}` or `{:ok? false :error \"invalid-manifest-missing-layers\" :missing-layers [...]}`."
  [manifest]
  (if-not (and (map? manifest) (map? (:layers manifest)))
    {:ok? false
     :error "invalid-manifest-missing-layers"
     :missing-layers [:layers]}
    (let [layers (:layers manifest)
          missing (filterv (fn [k]
                             (let [v (get layers k)]
                               (not (and (sequential? v) (seq v)))))
                           merkle-layer-order)]
      (if (seq missing)
        {:ok? false
         :error "invalid-manifest-missing-layers"
         :missing-layers missing}
        {:ok? true
         :manifest manifest}))))

(defn compute-system-merkle-root
  "Pure external-verifier recomputation (`P-HOST-5`): given a manifest containing `:layers`
   (`:os-subtree`, `:runtime-subtree`, `:app-subtree`), recomputes `:subtree-roots` and
   `:system-merkle-root` from the manifest alone."
  [manifest]
  (let [layers (:layers manifest)
        os-entries (vec (sort-by (juxt :atom :version :cid)
                                 (map normalize-os-entry (or (:os-subtree layers) []))))
        rt-entries (vec (sort-by (juxt :name :version :cid)
                                 (map normalize-runtime-entry (or (:runtime-subtree layers) []))))
        app-entries (vec (sort-by (juxt :artifact :version :cid)
                                  (map normalize-app-entry (or (:app-subtree layers) []))))
        os-root (compute-layer-subtree-root :os-subtree os-entries)
        rt-root (compute-layer-subtree-root :runtime-subtree rt-entries)
        app-root (compute-layer-subtree-root :app-subtree app-entries)
        sys-root (combine-three-subtrees os-root rt-root app-root)]
    {:subtree-roots {:os-subtree os-root
                     :runtime-subtree rt-root
                     :app-subtree app-root}
     :system-merkle-root sys-root}))

(defn build-system-merkle-manifest
  "Constructs a canonical 3-subtree Merkle attestation manifest (`P-HOST-5`)."
  [{:keys [arch stage3-cid profile-cid os-packages runtimes app-artifacts]}]
  (let [a (str/lower-case (str/trim (str (or arch "amd64"))))
        s3 (or (normalize-hex stage3-cid) (deploy/sha256-hex (str "stage3-" a)))
        prof (or (normalize-hex profile-cid) (deploy/sha256-hex (str "profile-" a)))
        os-entries (vec (sort-by (juxt :atom :version :cid)
                                 (into [{:kind :os :atom "gentoo/stage3-seed" :version a :cid s3}
                                        {:kind :os :atom "gentoo/profile" :version a :cid prof}]
                                       (map normalize-os-entry (or os-packages [])))))
        rt-entries (vec (sort-by (juxt :name :version :cid)
                                 (map normalize-runtime-entry (or runtimes []))))
        app-entries (vec (sort-by (juxt :artifact :version :cid)
                                  (map normalize-app-entry (or app-artifacts []))))
        base {:schema "bitecho-system-merkle-v1"
              :arch a
              :stage3-cid s3
              :profile-cid prof
              :layers {:os-subtree os-entries
                       :runtime-subtree rt-entries
                       :app-subtree app-entries}}
        computed (compute-system-merkle-root base)]
    (merge base computed)))

(defn generate-layer-proof
  "Generates a compact per-layer Merkle proof for `layer-kw` (`:os-subtree`, `:runtime-subtree`,
   or `:app-subtree`) allowing an external verifier to verify ONE layer without the full manifest (`P-HOST-5`)."
  [manifest layer-kw]
  (let [roots (or (:subtree-roots manifest)
                  (:subtree-roots (compute-system-merkle-root manifest)))
        os-root (:os-subtree roots)
        rt-root (:runtime-subtree roots)
        app-root (:app-subtree roots)
        sys-root (combine-three-subtrees os-root rt-root app-root)]
    (case layer-kw
      :os-subtree
      {:layer :os-subtree
       :layer-root os-root
       :siblings [{:side :right :hash rt-root}
                  {:side :right :hash app-root}]
       :system-merkle-root sys-root}

      :runtime-subtree
      {:layer :runtime-subtree
       :layer-root rt-root
       :siblings [{:side :left :hash os-root}
                  {:side :right :hash app-root}]
       :system-merkle-root sys-root}

      :app-subtree
      {:layer :app-subtree
       :layer-root app-root
       :siblings [{:side :left :hash (data/merkle-branch-hash os-root rt-root)}]
       :system-merkle-root sys-root}

      nil)))

(defn verify-layer-proof
  "Verifies a per-layer Merkle inclusion proof against `expected-root` (`P-HOST-5`)."
  [proof expected-root]
  (if-not (and (map? proof) (valid-sha256-hex? (:layer-root proof)) (valid-sha256-hex? expected-root))
    {:valid? false :error :malformed-layer-proof}
    (let [computed (reduce (fn [acc {:keys [side hash]}]
                             (if (= side :left)
                               (data/merkle-branch-hash hash acc)
                               (data/merkle-branch-hash acc hash)))
                           (normalize-hex (:layer-root proof))
                           (or (:siblings proof) []))
          norm-exp (normalize-hex expected-root)]
      {:valid? (= computed norm-exp)
       :layer (:layer proof)
       :computed-root computed
       :expected-root norm-exp})))

(defn localize-merkle-divergence
  "Compares `expected-manifest` and `actual-manifest` and localizes any root mismatch to the
   exact divergent subtree(s) (`:os-subtree`, `:runtime-subtree`, `:app-subtree`) (`P-HOST-5`)."
  [expected-manifest actual-manifest]
  (let [exp-comp (compute-system-merkle-root expected-manifest)
        act-comp (compute-system-merkle-root actual-manifest)
        exp-roots (:subtree-roots exp-comp)
        act-roots (:subtree-roots act-comp)
        divergent (filterv (fn [layer-kw]
                             (not= (get exp-roots layer-kw)
                                   (get act-roots layer-kw)))
                           merkle-layer-order)
        match? (and (= (:system-merkle-root exp-comp) (:system-merkle-root act-comp))
                    (empty? divergent))]
    {:match? match?
     :expected-root (:system-merkle-root exp-comp)
     :actual-root (:system-merkle-root act-comp)
     :divergent-subtrees divergent}))

(defn verify-reproducible-builds
  "Verifies two independent P-HOST-1 builds from pinned inputs produce identical subtree hashes (`P-HOST-1`, `P-HOST-5`).
   Emits a counted `:diagnose` (`:reason :non-reproducible-image-build`) if any subtree diverges."
  [build-a-manifest build-b-manifest]
  (let [div (localize-merkle-divergence build-a-manifest build-b-manifest)]
    (if (:match? div)
      {:reproducible? true
       :system-merkle-root (:expected-root div)
       :divergent-subtrees []
       :effects []}
      {:reproducible? false
       :expected-root (:expected-root div)
       :actual-root (:actual-root div)
       :divergent-subtrees (:divergent-subtrees div)
       :effects [{:effect :diagnose
                  :type :diagnose
                  :reason :non-reproducible-image-build
                  :divergent-subtrees (:divergent-subtrees div)}]})))

;; =============================================================================
;; 4. P-HOST-3 & P-HOST-4: Host Rollback & kexec Transition Reducers
;; =============================================================================

(defn init-host-state
  "Initializes single-authority generation-tagged host lifecycle state (`Rule 4`)."
  [{:keys [node-id arch os-id kernel-version pubkey balance epoch ips
           bootstrap-descriptors home-sets rootfs-snapshot state-subvolume kexec-budget-ms]}]
  {:node-id (keyword (or node-id :ns3))
   :arch (str/lower-case (str (or arch "amd64")))
   :os-id (str (or os-id "gentoo"))
   :kernel-version (str (or kernel-version "6.1.0-56"))
   :pubkey pubkey
   :balance (long (or balance 0))
   :state-epoch (long (or epoch 0))
   :ips (or ips {})
   :bootstrap-descriptors (vec (or bootstrap-descriptors []))
   :home-sets (set (or home-sets #{}))
   :phase :steady
   :generation 1
   :active-rootfs-snapshot (or rootfs-snapshot "rootfs-baseline")
   :pre-update-rootfs-snapshot (or rootfs-snapshot "rootfs-baseline")
   :state-subvolume (or state-subvolume "@bitecho-state")
   :kexec-budget-ms (long (or kexec-budget-ms 10000))
   :kexec-consecutive-failures 0
   :stage-gate-tripped? false
   :dropped 0
   :last-error nil
   :diagnostics {}
   :audit-trail []})

(defn reduce-host-update
  "Pure host update & rollback reducer (`P-HOST-3`, `P-HOST-4`, `Rule 4`, `Rule 5`):
   `(reduce-host-update host-state event) -> [new-host-state effects]`.
   Restoring `@rootfs` NEVER rolls back `@bitecho-state` or node identity."
  [host-state event]
  (let [cur-gen (long (:generation host-state 1))
        ev-gen (:generation event)
        ep (long (or (:epoch event) (:state-epoch host-state) 0))]
    (if (and (some? ev-gen) (< (long ev-gen) cur-gen))
      (let [diag {:effect :diagnose
                  :type :diagnose
                  :reason :stale-generation-callback
                  :event-generation (long ev-gen)
                  :current-generation cur-gen}
            st' (-> host-state
                    (update :dropped (fnil inc 0))
                    (update-in [:diagnostics :stale-generation-callback] (fnil inc 0)))]
        [st' [diag]])
      (case (:type event)
        :take-rootfs-snapshot
        (let [snap-id (str (or (:snapshot-id event) (str "rootfs-snap-ep-" ep)))
              st' (assoc host-state
                         :pre-update-rootfs-snapshot snap-id
                         :active-rootfs-snapshot snap-id)]
          [st' [{:effect :create-btrfs-snapshot
                 :subvolume "@rootfs"
                 :snapshot-id snap-id
                 :state-subvolume (:state-subvolume host-state)}]])

        :apply-host-update
        (let [st' (assoc host-state
                         :phase :updating
                         :pending-packages-cid (:target-packages-cid event))]
          [st' [{:effect :apply-binpkgs
                 :packages-cid (:target-packages-cid event)}]])

        (:gate-failed :host-update-failed)
        (let [snap-id (:pre-update-rootfs-snapshot host-state)
              reason (or (:reason event) :host-update-failed)
              audit-res (deploy/append-audit-record
                         host-state
                         {:epoch ep
                          :event-type :host-rolled-back
                          :payload {:node-id (:node-id host-state)
                                    :restored-snapshot snap-id
                                    :state-subvolume-untouched? true
                                    :reason reason}})
              diag {:effect :diagnose
                    :type :diagnose
                    :reason :host-update-rolled-back
                    :cause reason
                    :restored-snapshot snap-id}
              st' (-> (:state audit-res)
                      (assoc :phase :rolled-back
                             :active-rootfs-snapshot snap-id
                             :last-error reason)
                      (dissoc :pending-packages-cid)
                      (update :generation inc)
                      (update-in [:diagnostics :host-update-rolled-back] (fnil inc 0)))]
          [st' [{:effect :restore-rootfs-snapshot
                 :snapshot-id snap-id
                 :rollback-state-subvolume? false}
                diag
                {:effect :audit-record :record (:record audit-res)}]])

        :stage3-pivot-abort
        (let [snap-id (or (:pre-migration-snapshot event)
                          (:pre-update-rootfs-snapshot host-state))
              reason (or (:reason event) :stage3-pivot-abort)
              audit-res (deploy/append-audit-record
                         host-state
                         {:epoch ep
                          :event-type :stage3-pivot-aborted
                          :payload {:node-id (:node-id host-state)
                                    :restored-snapshot snap-id
                                    :os-id (:os-id host-state)
                                    :state-subvolume-untouched? true
                                    :reason reason}})
              diag {:effect :diagnose
                    :type :diagnose
                    :reason :stage3-pivot-aborted-rollback
                    :cause reason
                    :restored-snapshot snap-id}
              st' (-> (:state audit-res)
                      (assoc :phase :rolled-back
                             :active-rootfs-snapshot snap-id
                             :last-error reason)
                      (update :generation inc)
                      (update-in [:diagnostics :stage3-pivot-aborted-rollback] (fnil inc 0)))]
          [st' [{:effect :restore-pre-migration-snapshot
                 :snapshot-id snap-id
                 :rollback-state-subvolume? false}
                diag
                {:effect :audit-record :record (:record audit-res)}]])

        :stage3-live-migrate
        (let [target-os (str (or (:target-os event) "gentoo-2.18-hardened-openrc"))
              audit-res (deploy/append-audit-record
                         host-state
                         {:epoch ep
                          :event-type :stage3-live-migrated
                          :payload {:node-id (:node-id host-state)
                                    :from-os (:os-id host-state)
                                    :to-os target-os
                                    :stage3-cid (:stage3-cid event)
                                    :peak-ram-mib (:peak-ram-mib event)
                                    :peak-disk-mib (:peak-disk-mib event)
                                    :reboot-downtime-s (:reboot-downtime-s event)
                                    :pubkey (:pubkey host-state)
                                    :state-epoch (:state-epoch host-state)}})
              st' (-> (:state audit-res)
                      (assoc :os-id target-os
                             :phase :steady
                             :last-error nil)
                      (update :generation inc))]
          [st' [{:effect :audit-record :record (:record audit-res)}]])

        [host-state []]))))

(defn reduce-kexec-update
  "Pure `kexec` kernel update transition reducer (`P-HOST-4`, `Rule 5`):
   `(reduce-kexec-update host-state event) -> [new-host-state effects]`.
   - When `:reboot-required? true` and `:kexec-ok? true` within `:kexec-budget-ms`, completes via `:kexec-reboot`.
   - On failure or budget overrun, falls back to `:cold-reboot`, emits counted `:diagnose`,
     and trips the stage gate on 2 consecutive failures."
  [host-state {:keys [epoch kernel-version reboot-required? kexec-ok? downtime-ms]}]
  (let [ep (long (or epoch (:state-epoch host-state) 0))
        budget (long (:kexec-budget-ms host-state 10000))
        dt (long (or downtime-ms 0))]
    (if-not reboot-required?
      [(assoc host-state :kernel-version (or kernel-version (:kernel-version host-state)))
       []]
      (if (and (true? kexec-ok?) (<= dt budget))
        (let [audit-res (deploy/append-audit-record
                         host-state
                         {:epoch ep
                          :event-type :host-kexec-completed
                          :payload {:node-id (:node-id host-state)
                                    :kernel-version kernel-version
                                    :downtime-ms dt
                                    :budget-ms budget}})
              st' (assoc (:state audit-res)
                         :kernel-version kernel-version
                         :kexec-consecutive-failures 0
                         :stage-gate-tripped? false
                         :phase :steady
                         :last-error nil)]
          [st' [{:effect :kexec-reboot
                 :kernel-version kernel-version
                 :downtime-ms dt}
                {:effect :audit-record :record (:record audit-res)}]])
        (let [fails (inc (long (:kexec-consecutive-failures host-state 0)))
              tripped? (>= fails 2)
              fallback-diag {:effect :diagnose
                             :type :diagnose
                             :reason :kexec-fallback-cold-reboot
                             :kernel-version kernel-version
                             :downtime-ms dt
                             :budget-ms budget
                             :consecutive-failures fails}
              gate-diag (when tripped?
                          {:effect :diagnose
                           :type :diagnose
                           :reason :kexec-consecutive-failures-gate-tripped
                           :consecutive-failures fails})
              audit-res (deploy/append-audit-record
                         host-state
                         {:epoch ep
                          :event-type (if tripped? :kexec-gate-tripped :kexec-fallback-cold-reboot)
                          :payload {:node-id (:node-id host-state)
                                    :kernel-version kernel-version
                                    :downtime-ms dt
                                    :consecutive-failures fails
                                    :stage-gate-tripped? tripped?}})
              st' (-> (:state audit-res)
                      (assoc :kexec-consecutive-failures fails
                             :stage-gate-tripped? tripped?
                             :phase (if tripped? :gate-tripped :steady)
                             :last-error (if tripped?
                                           :kexec-consecutive-failures-gate-tripped
                                           :kexec-fallback-cold-reboot))
                      (update-in [:diagnostics :kexec-fallback-cold-reboot] (fnil inc 0))
                      (cond-> tripped?
                        (update-in [:diagnostics :kexec-consecutive-failures-gate-tripped] (fnil inc 0))))]
          [st' (cond-> [{:effect :cold-reboot :kernel-version kernel-version}
                        fallback-diag]
                 gate-diag (conj gate-diag)
                 true (conj {:effect :audit-record :record (:record audit-res)}))])))))

;; =============================================================================
;; 5. P-HOST-6: Unified Dynamic Rolling Upgrade Pure Reducer
;; =============================================================================

(defn init-unified-watcher-state
  "Initializes the single-authority generation-tagged unified pointer watcher state (`P-HOST-6`, `Rule 4`)."
  [{:keys [node-id stage arch current-pointer current-host-target current-code-cid
           current-merkle-root rootfs-snapshot state-subvolume trusted-deploy-authorities
           ratified-bip-cids]}]
  (let [lkg {:pointer current-pointer
             :host-target current-host-target
             :code-cid (normalize-hex current-code-cid)
             :merkle-root (normalize-hex current-merkle-root)
             :rootfs-snapshot (or rootfs-snapshot "rootfs-lkg")}]
    {:node-id (keyword (or node-id :ns3))
     :stage (keyword (or stage :canary))
     :arch (str/lower-case (str (or arch "amd64")))
     :phase :watching
     :generation 1
     :active-config-seq (long (or (:seq current-pointer) 0))
     :current-pointer current-pointer
     :current-host-target current-host-target
     :current-code-cid (normalize-hex current-code-cid)
     :current-merkle-root (normalize-hex current-merkle-root)
     :rootfs-snapshot (or rootfs-snapshot "rootfs-lkg")
     :state-subvolume (or state-subvolume "@bitecho-state")
     :last-known-good lkg
     :pending-rollout nil
     :trusted-deploy-authorities (set (map normalize-hex (or trusted-deploy-authorities #{})))
     :ratified-bip-cids (set (map normalize-hex (or ratified-bip-cids #{})))
     :dropped 0
     :last-error nil
     :diagnostics {}
     :audit-trail []}))

(defn verify-unified-pointer-advance
  "Fail-closed verifier for a unified P-HOST-6 pointer advance carrying BOTH `:host-target`
   and full-node `:code-target-cid`. Verifies pointer signature/seq, `:host-target` + binpkg
   signatures/hashes, full-node bundle SHA-256, and optional `:system-merkle-root` manifest match."
  [watcher-state pointer-map {:keys [binpkg-artifacts code-artifact-bytes expected-manifest]}]
  (let [ptr-check (deploy/verify-config-pointer watcher-state pointer-map)]
    (if-not (:ok? ptr-check)
      {:ok? false :cause (:error ptr-check)}
      (let [ptr (:pointer ptr-check)
            host-target (:host-target pointer-map)
            host-check (verify-host-target watcher-state host-target binpkg-artifacts)]
        (if-not (:ok? host-check)
          {:ok? false :cause (or (:cause host-check) (:error host-check))}
          (let [expected-code-cid (normalize-hex (:code-target-cid ptr))
                actual-code-cid (when (and code-artifact-bytes (bytes? code-artifact-bytes))
                                  (deploy/sha256-hex code-artifact-bytes))
                code-ok? (and (some? expected-code-cid)
                              (some? actual-code-cid)
                              (= expected-code-cid actual-code-cid))
                expected-root (normalize-hex (or (:system-merkle-root pointer-map)
                                                 (:system-merkle-root host-target)))
                manifest-ok? (if (and expected-manifest expected-root)
                               (= expected-root (:system-merkle-root (compute-system-merkle-root expected-manifest)))
                               true)]
            (cond
              (not code-ok?)
              {:ok? false :cause :code-artifact-hash-mismatch}

              (not manifest-ok?)
              {:ok? false :cause :system-merkle-root-mismatch}

              :else
              {:ok? true
               :pointer ptr
               :host-target host-target
               :code-cid expected-code-cid
               :merkle-root expected-root})))))))

(defn- execute-combined-rollback
  [watcher-state ep cause restore-node-bundle?]
  (let [lkg (:last-known-good watcher-state)
        snap-id (:rootfs-snapshot lkg)
        audit-res (deploy/append-audit-record
                   watcher-state
                   {:epoch ep
                    :event-type :unified-rollout-rolled-back
                    :payload {:node-id (:node-id watcher-state)
                              :stage (:stage watcher-state)
                              :cause cause
                              :reverted-pointer-seq (:seq (:pointer lkg))
                              :last-known-good-code-cid (:code-cid lkg)
                              :last-known-good-merkle-root (:merkle-root lkg)
                              :restored-rootfs-snapshot snap-id
                              :state-subvolume-untouched? true}})
        diag {:effect :diagnose
              :type :diagnose
              :reason :unified-rollout-combined-rollback
              :cause cause
              :node-id (:node-id watcher-state)
              :stage (:stage watcher-state)
              :restored-rootfs-snapshot snap-id}
        st' (-> (:state audit-res)
                (assoc :phase :rolled-back
                       :current-pointer (:pointer lkg)
                       :current-host-target (:host-target lkg)
                       :current-code-cid (:code-cid lkg)
                       :current-merkle-root (:merkle-root lkg)
                       :active-config-seq (long (or (:seq (:pointer lkg)) 0))
                       :rootfs-snapshot snap-id
                       :pending-rollout nil
                       :last-error cause)
                (update :generation inc)
                (update-in [:diagnostics :unified-rollout-combined-rollback] (fnil inc 0)))
        effs (cond-> [{:effect :revert-config-pointer :pointer (:pointer lkg)}
                      {:effect :restore-rootfs-snapshot
                       :snapshot-id snap-id
                       :rollback-state-subvolume? false}]
               restore-node-bundle?
               (conj {:effect :restore-lkg-node-bundle :code-cid (:code-cid lkg)})
               true
               (conj diag {:effect :audit-record :record (:record audit-res)}))]
    [st' effs]))

(defn reduce-unified-rollout-tick
  "Pure unified dynamic rolling upgrade reducer (`P-HOST-6`, `Rule 4`, `Rule 5`):
   `(reduce-unified-rollout-tick watcher-state event) -> [new-state effects]`.
   Executes a single config-pointer advance in strict **host-then-node** order; any verification
   failure refuses the advance, and any execution failure in EITHER layer triggers an atomic
   combined mechanical rollback leaving host + node consistent on `:last-known-good` while
   never rolling back `@bitecho-state`."
  [watcher-state event]
  (let [cur-gen (long (:generation watcher-state 1))
        ev-gen (:generation event)
        ep (long (or (:epoch event) 0))]
    (if (and (some? ev-gen) (< (long ev-gen) cur-gen))
      (let [diag {:effect :diagnose
                  :type :diagnose
                  :reason :stale-generation-callback
                  :event-generation (long ev-gen)
                  :current-generation cur-gen}
            st' (-> watcher-state
                    (update :dropped (fnil inc 0))
                    (update-in [:diagnostics :stale-generation-callback] (fnil inc 0)))]
        [st' [diag]])
      (case (:type event)
        :pointer-advance
        (let [v (verify-unified-pointer-advance
                 watcher-state
                 (:pointer event)
                 {:binpkg-artifacts (:binpkg-artifacts event)
                  :code-artifact-bytes (:code-artifact-bytes event)
                  :expected-manifest (:expected-manifest event)})]
          (if-not (:ok? v)
            (let [diag {:effect :diagnose
                        :type :diagnose
                        :reason :unified-pointer-verification-failed
                        :cause (:cause v)
                        :node-id (:node-id watcher-state)}
                  audit-res (deploy/append-audit-record
                             watcher-state
                             {:epoch ep
                              :event-type :unified-pointer-rejected
                              :payload {:node-id (:node-id watcher-state)
                                        :cause (:cause v)}})
                  st' (-> (:state audit-res)
                          (assoc :last-error (:cause v))
                          (update-in [:diagnostics :unified-pointer-verification-failed] (fnil inc 0)))]
              [st' [diag {:effect :audit-record :record (:record audit-res)}]])
            (let [snap-id (str "rootfs-pre-seq-" (:seq (:pointer v)))
                  lkg (assoc (:last-known-good watcher-state) :rootfs-snapshot snap-id)
                  pending {:pointer (:pointer v)
                           :host-target (:host-target v)
                           :code-cid (:code-cid v)
                           :merkle-root (:merkle-root v)
                           :pre-update-snapshot snap-id}
                  st' (assoc watcher-state
                             :phase :applying-host
                             :last-known-good lkg
                             :pending-rollout pending)]
              [st' [{:effect :take-rootfs-snapshot
                     :subvolume "@rootfs"
                     :snapshot-id snap-id
                     :state-subvolume (:state-subvolume watcher-state)}
                    {:effect :apply-host-binpkgs
                     :host-target (:host-target v)
                     :binhost-channel (binhost-channel-path (:arch watcher-state))}]])))

        :host-layer-applied
        (let [pending (:pending-rollout watcher-state)
              expected-root (:merkle-root pending)
              actual-root (normalize-hex (:actual-merkle-root event))
              root-ok? (or (nil? expected-root) (nil? actual-root) (= expected-root actual-root))]
          (if (and (true? (:ok? event)) root-ok? (some? pending))
            (let [reboot? (true? (get-in pending [:host-target :reboot-required?]))
                  st' (assoc watcher-state
                             :phase :applying-node
                             :current-host-target (:host-target pending))]
              [st' [{:effect :swap-full-node-bundle
                     :code-cid (:code-cid pending)}
                    (if reboot?
                      {:effect :kexec-reboot
                       :kernel-version (get-in pending [:host-target :kernel-version])}
                      {:effect :exit-75-respawn
                       :node-id (:node-id watcher-state)})]])
            (execute-combined-rollback
             watcher-state
             ep
             (or (:error event) (when-not root-ok? :post-host-merkle-root-mismatch) :host-layer-apply-failed)
             false)))

        :node-layer-applied
        (let [pending (:pending-rollout watcher-state)
              expected-seq (long (or (get-in pending [:pointer :seq]) -1))
              att-seq (long (or (:attested-pointer-seq event) expected-seq))
              expected-root (:merkle-root pending)
              att-root (normalize-hex (or (:attested-merkle-root event) expected-root))
              attest-ok? (and (= expected-seq att-seq)
                              (or (nil? expected-root) (= expected-root att-root)))]
          (if (and (true? (:ok? event)) attest-ok? (some? pending))
            (let [new-lkg {:pointer (:pointer pending)
                           :host-target (:host-target pending)
                           :code-cid (:code-cid pending)
                           :merkle-root (:merkle-root pending)
                           :rootfs-snapshot (str "rootfs-seq-" expected-seq)}
                  audit-res (deploy/append-audit-record
                             watcher-state
                             {:epoch ep
                              :event-type :unified-rollout-applied
                              :payload {:node-id (:node-id watcher-state)
                                        :stage (:stage watcher-state)
                                        :pointer-seq expected-seq
                                        :code-cid (:code-cid pending)
                                        :packages-manifest-cid (get-in pending [:host-target :packages-manifest-cid])
                                        :system-merkle-root (:merkle-root pending)}})
                  st' (assoc (:state audit-res)
                             :phase :watching
                             :active-config-seq expected-seq
                             :current-pointer (:pointer pending)
                             :current-host-target (:host-target pending)
                             :current-code-cid (:code-cid pending)
                             :current-merkle-root (:merkle-root pending)
                             :rootfs-snapshot (:rootfs-snapshot new-lkg)
                             :last-known-good new-lkg
                             :pending-rollout nil
                             :last-error nil)]
              [st' [{:effect :audit-record :record (:record audit-res)}]])
            (execute-combined-rollback
             watcher-state
             ep
             (or (:error event) (when-not attest-ok? :post-node-attestation-mismatch) :node-layer-apply-failed)
             true)))

        [watcher-state []]))))
