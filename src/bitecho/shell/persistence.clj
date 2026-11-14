(ns bitecho.shell.persistence
  "Provides pure functions and I/O wrappers for snapshotting the Root State Map.
   Ensures unserializable objects like core.async channels or PersistentQueues are safely handled."
  (:require [bitecho.basalt.core :as basalt]
            [bitecho.economy.account :as account]
            [bitecho.fressian :as fressian]
            [bitecho.rendezvous.core :as rendezvous]
            [bitecho.streamlet.core :as streamlet]
            [clojure.java.io :as io]
            [clojure.walk :as walk])
  (:import [java.nio.file Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]))

(def default-snapshot-filename
  "The default filename used for saving and loading the state snapshot."
  "snapshot.bin")

(defonce ^:private snapshot-save-lock (Object.))

(defn strip-unserializable-state
  "Transforms the pure state map into a serializable format.
   Strips raw java.util.Random instances, clojure.core.async channels,
   private key material, and converts the :murmur-cache :queue into a standard vector."
  [state]
  (let [queue-handled (if (get-in state [:murmur-cache :queue])
                        (update-in state [:murmur-cache :queue] vec)
                        state)
        secrets-stripped (-> queue-handled
                             (dissoc :keypair :keys :node-private-key :treasury-privkey :custody-privkey)
                             (cond-> (map? (:config queue-handled))
                               (update :config dissoc :keypair :keys :node-private-key :treasury-privkey :custody-privkey)))]
    (walk/postwalk
     (fn [x]
       (cond
         (instance? java.util.Random x) nil
         ;; Handle core.async channels safely without class errors by checking class name
         (and (class x) (= "clojure.core.async.impl.channels.ManyToManyChannel" (.getName (class x)))) nil
         :else x))
     secrets-stripped)))

(def ^:private set-typed-state-keys
  [:notarized-blocks
   :finalized-blocks
   :executed-finalized-blocks
   :minted-epochs
   :contagion-known-ids
   :known-receipt-ids
   :executed-receipt-ids
   :settled-escrow-ids
   :voted-epochs
   :equivocated-voters
   :global-echo-sample
   :global-ready-sample
   :global-delivery-sample
   :echo-subscribers
   :ready-subscribers
   :delivery-subscribers
   :sieve-delivered-set
   :local-ready-set
   :delivered-set
   :settled-transcript-pairs
   :settled-voucher-tuples])

(defn- restore-basalt-view
  [bv]
  (cond
    (set? bv)
    (into #{}
          (map (fn [item]
                 (if (and (map? item) (not (record? item)) (or (contains? item :ip) (contains? item :id)) (contains? item :pubkey))
                   (basalt/map->Peer item)
                   item))
               bv))

    (sequential? bv)
    (mapv (fn [slot]
            (cond
              (and (map? slot) (map? (:peer slot)))
              (update slot :peer #(if (record? %) % (basalt/map->Peer %)))

              (and (map? slot) (not (record? slot)) (or (contains? slot :ip) (contains? slot :id)) (contains? slot :pubkey))
              (basalt/map->Peer slot)

              :else slot))
          bv)

    :else bv))

(defn restore-unserializable-state
  "Reconstitutes a Fressian-serialized state map back into its fully functional form.
   Restores domain defrecords (AccountState, Block, Vote, DeliveryAck, Peer),
   set-typed state fields, and converts the :murmur-cache :queue vector back into a PersistentQueue."
  [state]
  (when (map? state)
    (let [s (reduce (fn [acc k]
                      (if (contains? acc k)
                        (update acc k #(when (some? %) (set %)))
                        acc))
                    state
                    set-typed-state-keys)]
      (cond-> s
        (get-in s [:murmur-cache :queue])
        (update-in [:murmur-cache :queue] #(into clojure.lang.PersistentQueue/EMPTY %))

        (get-in s [:murmur-cache :set])
        (update-in [:murmur-cache :set] set)

        (get-in s [:murmur-cache :seen])
        (update-in [:murmur-cache :seen] set)

        (map? (:ledger s))
        (update :ledger
                #(into {}
                       (map (fn [[k v]]
                              [k (if (map? v)
                                   (account/map->AccountState
                                    (cond-> v
                                      (contains? v :deps) (update :deps vec)))
                                   v)])
                            %)))

        (map? (:blocks s))
        (update :blocks
                #(into {}
                       (map (fn [[k v]]
                              [k (if (map? v)
                                   (streamlet/map->Block
                                    (cond-> v
                                      (contains? v :txs) (update :txs vec)))
                                   v)])
                            %)))

        (map? (:block-votes s))
        (update :block-votes
                #(into {}
                       (map (fn [[k v]]
                              [k (set v)])
                            %)))

        (map? (:block-vote-proofs s))
        (update :block-vote-proofs
                #(into {}
                       (map (fn [[bhash voter-map]]
                              [bhash (if (map? voter-map)
                                       (into {}
                                             (map (fn [[voter v]]
                                                    [voter (if (map? v)
                                                             (streamlet/map->Vote v)
                                                             v)])
                                                  voter-map))
                                       voter-map)])
                            %)))

        (contains? s :pending-vouchers)
        (update :pending-vouchers
                #(when (some? %)
                   (mapv (fn [v]
                           (if (map? v)
                             (rendezvous/map->DeliveryAck v)
                             v))
                         %)))

        (contains? s :basalt-view)
        (update :basalt-view restore-basalt-view)))))

(defn save-state-to-disk
  "Serializes the provided state map using Canonical Fressian and atomically writes it
   to the specified filepath using a temporary file rename to prevent corruption.
   Sets 0600 (rw-------) POSIX file permissions.
   Returns true if successful, or throws an exception on failure."
  [filepath state]
  (locking snapshot-save-lock
    (let [safe-state (strip-unserializable-state state)
          encoded-bytes ^bytes (fressian/encode safe-state)
          file (io/file filepath)
          parent (or (.getParentFile file) (io/file "."))
          _ (.mkdirs parent)
          temp-file (java.io.File/createTempFile "snapshot-" ".tmp" parent)]
      (try
        (Files/write (.toPath temp-file)
                     encoded-bytes
                     (into-array java.nio.file.OpenOption []))
        (try
          (Files/setPosixFilePermissions (.toPath temp-file) (PosixFilePermissions/fromString "rw-------"))
          (catch UnsupportedOperationException _ nil))
        ;; Atomic rename using java.nio.file.Files/move
        (try
          (Files/move (.toPath temp-file)
                      (.toPath file)
                      (into-array java.nio.file.CopyOption
                                  [StandardCopyOption/REPLACE_EXISTING
                                   StandardCopyOption/ATOMIC_MOVE]))
          (catch Exception _
            (Files/move (.toPath temp-file)
                        (.toPath file)
                        (into-array java.nio.file.CopyOption
                                    [StandardCopyOption/REPLACE_EXISTING]))))
        true
        (finally
          (when (.exists temp-file)
            (try (.delete temp-file) (catch Exception _ nil))))))))

(defn load-state-from-disk
  "Reads a Fressian-serialized state map from the specified filepath and restores domain records and collection types.
   Rejects legacy Nippy ('NPY') payloads fail-closed (returns nil).
   Returns the reconstituted state map, or nil if the file does not exist or fails decoding."
  [filepath]
  (let [file (io/file filepath)]
    (when (.exists file)
      (let [raw-bytes (Files/readAllBytes (.toPath file))]
        (when (and (pos? (alength raw-bytes))
                   (not (fressian/nippy-payload? raw-bytes)))
          (when-let [raw-state (try (fressian/decode raw-bytes) (catch Exception _ nil))]
            (restore-unserializable-state raw-state)))))))
