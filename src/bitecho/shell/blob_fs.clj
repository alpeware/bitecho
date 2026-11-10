(ns bitecho.shell.blob-fs
  "Disk-backed Content-Addressed Storage (`CAS`) shell for `bitecho.core.data` Blobs (Gap G6):
   - Persists immutable Blobs atomically under `<store-dir>/blobs/<2-char-prefix>/<cid>`
     (with sidecar `<cid>.meta.edn` for `:blob/media-type`), keeping the `<cid>` file itself
     strictly raw content bytes so `bitecho.shell.http` can stream zero-heap `FileChannel` byte slices
     directly from disk on `1 GB e2-micro` nodes.
   - Verifies `compute-cid(bytes) == cid` on both `write-blob!` and `read-blob!`, failing closed
     with counted `:diagnose` effects on any hash mismatch or corruption (Rule 5)."
  (:require [bitecho.core.data :as data]
            [bitecho.fressian :as fressian]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io File]
           [java.nio.file CopyOption Files OpenOption StandardCopyOption]))

(defn- valid-cid?
  [cid]
  (and (string? cid)
       (boolean (re-matches #"[0-9a-f]{64}" (str/lower-case (str/trim cid))))))

(defn- normalize-cid
  [cid]
  (when cid
    (str/lower-case (str/trim (str cid)))))

(defn- atomic-move!
  [^File tmp ^File dest]
  (try
    (Files/move (.toPath tmp) (.toPath dest)
                (into-array CopyOption [StandardCopyOption/ATOMIC_MOVE
                                        StandardCopyOption/REPLACE_EXISTING]))
    (catch Exception _
      (Files/move (.toPath tmp) (.toPath dest)
                  (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING])))))

(defn blob-file
  "Returns the `^java.io.File` path `<store-dir>/blobs/<2-char>/<cid>` for `cid` (or `nil` if `cid` is malformed)."
  ^File [store-dir cid]
  (let [ncid (normalize-cid cid)]
    (when (valid-cid? ncid)
      (io/file store-dir "blobs" (subs ncid 0 2) ncid))))

(defn- meta-file
  ^File [store-dir cid]
  (let [ncid (normalize-cid cid)]
    (when (valid-cid? ncid)
      (io/file store-dir "blobs" (subs ncid 0 2) (str ncid ".meta.edn")))))

(defn has-disk-blob?
  "Returns true if `<store-dir>/blobs/<2-char>/<cid>` exists on disk."
  [store-dir cid]
  (if-let [^File f (blob-file store-dir cid)]
    (.exists f)
    false))

(defn write-blob!
  "Verifies `sha256(:blob/bytes) == :blob/cid` and atomically persists raw bytes + media-type metadata to disk.
   Idempotent if already present on disk. Returns `{:ok? boolean :file File :cid cid :effects [...]}`."
  [store-dir blob]
  (let [ncid (normalize-cid (:blob/cid blob))
        bs (:blob/bytes blob)
        media-type (str (or (:blob/media-type blob) "application/octet-stream"))]
    (if-not (and (valid-cid? ncid) (fressian/bytes? bs))
      {:ok? false
       :error :malformed-blob
       :effects [{:effect :diagnose :reason :blob-fs-malformed-write :cid ncid}]}
      (let [actual (data/compute-cid bs)]
        (if (not= ncid actual)
          {:ok? false
           :error :blob-cid-mismatch
           :effects [{:effect :diagnose :reason :blob-cid-mismatch :expected ncid :actual actual}]}
          (let [^File dest (blob-file store-dir ncid)
                ^File mdest (meta-file store-dir ncid)
                parent (.getParentFile dest)]
            (.mkdirs parent)
            (when-not (.exists dest)
              (let [tmp (File/createTempFile "blob-" ".tmp" parent)]
                (try
                  (Files/write (.toPath tmp) ^bytes bs (into-array OpenOption []))
                  (atomic-move! tmp dest)
                  (finally
                    (when (.exists tmp) (.delete tmp))))))
            (let [existing-meta (when (.exists mdest)
                                  (try (edn/read-string (slurp mdest)) (catch Exception _ nil)))
                  existing-mt (:media-type existing-meta)
                  should-write-meta? (or (not (.exists mdest))
                                         (and (= existing-mt "application/octet-stream")
                                              (not= media-type "application/octet-stream")))]
              (when should-write-meta?
                (let [mtmp (File/createTempFile "meta-" ".tmp" parent)]
                  (try
                    (spit mtmp (pr-str {:media-type media-type :size (alength ^bytes bs)}))
                    (atomic-move! mtmp mdest)
                    (finally
                      (when (.exists mtmp) (.delete mtmp)))))))
            {:ok? true :cid ncid :file dest :effects []}))))))

(defn read-blob-meta
  "Reads sidecar metadata (`{:media-type ... :size ...}`) for `cid` without loading content bytes into heap."
  [store-dir cid]
  (let [^File f (blob-file store-dir cid)
        ^File mf (meta-file store-dir cid)]
    (when (and f (.exists f))
      (let [meta-map (when (and mf (.exists mf))
                       (try (edn/read-string (slurp mf)) (catch Exception _ nil)))]
        {:cid (normalize-cid cid)
         :file f
         :size (.length f)
         :media-type (or (:media-type meta-map) "application/octet-stream")}))))

(defn read-blob!
  "Reads `<store-dir>/blobs/<2-char>/<cid>` from disk and verifies its SHA-256 CID before returning.
   Fails closed with counted `:diagnose` effect if missing, unreadable, or tampered on disk."
  [store-dir cid]
  (let [ncid (normalize-cid cid)
        ^File f (blob-file store-dir ncid)]
    (if-not (and f (.exists f))
      {:ok? false
       :error :blob-not-found
       :effects [{:effect :diagnose :reason :blob-fs-miss :cid ncid}]}
      (try
        (let [bs (Files/readAllBytes (.toPath f))
              actual (data/compute-cid bs)]
          (if (not= ncid actual)
            {:ok? false
             :error :blob-cid-mismatch
             :effects [{:effect :diagnose :reason :blob-fs-corrupt :expected ncid :actual actual}]}
            (let [m (read-blob-meta store-dir ncid)]
              {:ok? true
               :blob {:blob/cid ncid
                      :blob/media-type (or (:media-type m) "application/octet-stream")
                      :blob/bytes bs}
               :file f
               :effects []})))
        (catch Exception e
          {:ok? false
           :error :blob-io-error
           :effects [{:effect :diagnose :reason :blob-fs-io-error :cid ncid :message (.getMessage e)}]})))))

(defn delete-blob!
  "Deletes `<cid>` and `<cid>.meta.edn` from disk if present."
  [store-dir cid]
  (let [^File f (blob-file store-dir cid)
        ^File mf (meta-file store-dir cid)
        existed? (boolean (and f (.exists f)))]
    (when f (try (.delete f) (catch Exception _ nil)))
    (when mf (try (.delete mf) (catch Exception _ nil)))
    {:deleted? existed? :cid (normalize-cid cid)}))

(defn gc-unpinned-blobs!
  "Deletes any Blob on disk under `<store-dir>/blobs/` whose CID is not in `keep-cids`."
  [store-dir keep-cids]
  (let [keep-set (set (keep normalize-cid keep-cids))
        blobs-root (io/file store-dir "blobs")]
    (if-not (.exists blobs-root)
      {:deleted-count 0 :deleted []}
      (let [deleted (atom [])]
        (doseq [^File shard (or (.listFiles blobs-root) [])
                :when (.isDirectory shard)
                ^File f (or (.listFiles shard) [])
                :let [nm (.getName f)]
                :when (and (.isFile f) (valid-cid? nm) (not (contains? keep-set nm)))]
          (delete-blob! store-dir nm)
          (swap! deleted conj nm))
        {:deleted-count (count @deleted)
         :deleted @deleted}))))
