(ns bitecho.shell.persistence
  "Provides pure functions and I/O wrappers for snapshotting the Root State Map.
   Ensures unserializable objects like core.async channels or PersistentQueues are safely handled."
  (:require [bitecho.core.mesh :as core-mesh]
            [bitecho.fressian :as fressian]
            [bitecho.snapshot.core :as snap]
            [clojure.java.io :as io])
  (:import [java.io File]
           [java.nio.file Files StandardCopyOption]
           [java.nio.file.attribute PosixFilePermissions]))

(def default-snapshot-filename
  "The default filename used for saving and loading the state snapshot."
  "snapshot.bin")

(defonce ^:private snapshot-save-lock (Object.))

(defonce ^:private last-saved-snapshots (atom {}))

(defn persistence-stats
  "Returns snapshot persistence metrics `{:saved-count <n> :skipped-clean <m>}` for `filepath` (`P-SOAK-5` / `B7`)."
  [filepath]
  (let [entry (get @last-saved-snapshots (str filepath))]
    {:saved-count (long (or (:saved-count entry) 0))
     :skipped-clean (long (or (:skipped-clean entry) 0))}))

(defn strip-unserializable-state
  "Transforms the pure state map into a serializable format.
   Strips raw java.util.Random instances, clojure.core.async channels,
   private key material, and converts the :murmur-cache :queue into a standard vector."
  [state]
  (core-mesh/strip-unserializable-state state))

(defn restore-unserializable-state
  "Reconstitutes a Fressian-serialized state map back into its fully functional form.
   Restores domain defrecords (AccountState, Block, Vote, DeliveryAck, Peer),
   set-typed state fields, and converts the :murmur-cache :queue vector back into a PersistentQueue."
  [state]
  (core-mesh/restore-unserializable-state state))

(defn save-state-to-disk
  "Serializes the provided state map using non-canonical fast Fressian (`P-SOAK-5` / `B7`)
   and atomically writes it to the specified filepath using a temporary file rename to prevent corruption.
   Skips redundant disk writes when the stripped state is identical to the last saved snapshot for `filepath`.
   Sets 0600 (rw-------) POSIX file permissions.
   Returns true if successful, or throws an exception on failure."
  [filepath state]
  (locking snapshot-save-lock
    (let [path-key (str filepath)
          file (io/file filepath)
          safe-state (strip-unserializable-state state)
          prev-state (get-in @last-saved-snapshots [path-key :state])]
      (if (and (.exists file)
               (pos? (.length file))
               (some? prev-state)
               (= safe-state prev-state))
        (do
          (swap! last-saved-snapshots update-in [path-key :skipped-clean] (fnil inc 0))
          true)
        (let [encoded-bytes ^bytes (fressian/write-standard-fressian (fressian/normalize-for-wire safe-state))
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
            (swap! last-saved-snapshots
                   (fn [m]
                     (-> m
                         (assoc-in [path-key :state] safe-state)
                         (update-in [path-key :saved-count] (fnil inc 0)))))
            true
            (finally
              (when (.exists temp-file)
                (try (.delete temp-file) (catch Exception _ nil))))))))))

(defn load-state-from-disk
  "Reads a Fressian-serialized state map (standard or canonical) from the specified filepath and restores domain records and collection types.
   Rejects legacy Nippy ('NPY') payloads fail-closed (returns nil).
   Returns the reconstituted state map, or nil if the file does not exist or fails decoding."
  [filepath]
  (let [file (io/file filepath)]
    (when (.exists file)
      (let [raw-bytes (Files/readAllBytes (.toPath file))]
        (when (and (pos? (alength raw-bytes))
                   (not (fressian/nippy-payload? raw-bytes)))
          (when-let [raw-state (or (try (fressian/decode raw-bytes) (catch Exception _ nil))
                                   (try (fressian/decode-wire raw-bytes) (catch Exception _ nil)))]
            (restore-unserializable-state raw-state)))))))

(defn prune-epoch-snapshots!
  "Prunes old immutable epoch snapshots in `state-dir` for `node-id` according to
   `bitecho.snapshot.core/plan-snapshot-retention` (`keep-epochs` default 360, `min-keep >= 2`).
   Never deletes foreign snapshots, `.tmp` files, or legacy `snapshot-<node>.edn`."
  ([state-dir node-id current-epoch]
   (prune-epoch-snapshots! state-dir node-id current-epoch nil))
  ([state-dir node-id current-epoch opts]
   (let [dir (io/file state-dir)]
     (if-not (.isDirectory dir)
       {:ok? true :kept 0 :deleted 0 :errors []}
       (let [filenames (mapv #(.getName ^File %) (or (.listFiles dir) []))
             {:keys [keep delete]} (snap/plan-snapshot-retention node-id filenames current-epoch opts)
             errors (atom [])
             deleted (atom 0)]
         (doseq [fname delete]
           (try
             (let [f (io/file dir fname)]
               (when (.exists f)
                 (if (.delete f)
                   (swap! deleted inc)
                   (swap! errors conj {:file fname :error :delete-returned-false}))))
             (catch Exception e
               (swap! errors conj {:file fname :error (.getMessage e)}))))
         {:ok? (empty? @errors)
          :kept (count keep)
          :deleted @deleted
          :errors @errors})))))

(defn save-epoch-snapshot!
  "Saves `state` to an immutable epoch-addressed snapshot file
   `snapshot-<sanitized>-epoch-<012d>.fressian` inside `state-dir` via atomic temp-file move,
   and prunes expired epoch snapshots ONLY after the write succeeds (BIP-014 / P-ASYNC-3)."
  ([state-dir node-id state]
   (save-epoch-snapshot! state-dir node-id state nil))
  ([state-dir node-id state opts]
   (let [ep (long (or (:epoch opts)
                      (:last-executed-finalized-epoch state)
                      (:epoch state)
                      0))
         fname (snap/snapshot-filename node-id ep)
         dir (io/file state-dir)
         _ (.mkdirs dir)
         dest (io/file dir fname)]
     (try
       (save-state-to-disk (.getAbsolutePath dest) state)
       (let [prune-res (prune-epoch-snapshots! state-dir node-id ep opts)]
         {:ok? true
          :epoch ep
          :filename fname
          :path (.getAbsolutePath dest)
          :prune prune-res})
       (catch Exception e
         {:ok? false
          :epoch ep
          :filename fname
          :error (.getMessage e)})))))

(defn load-latest-epoch-snapshot
  "Selects and loads the highest-epoch immutable snapshot for `node-id` in `state-dir`
   via `bitecho.snapshot.core/select-latest-snapshot`, falling back seamlessly to
   `legacy-filename` (e.g. `snapshot-<node>.edn`) when present and no epoch snapshots exist."
  ([state-dir node-id]
   (load-latest-epoch-snapshot state-dir node-id (str "snapshot-" (snap/sanitize-node-id node-id) ".edn")))
  ([state-dir node-id legacy-filename]
   (let [dir (io/file state-dir)]
     (when (.isDirectory dir)
       (let [filenames (mapv #(.getName ^File %) (or (.listFiles dir) []))]
         (when-let [selected (snap/select-latest-snapshot node-id filenames legacy-filename)]
           (load-state-from-disk (.getAbsolutePath (io/file dir selected)))))))))
