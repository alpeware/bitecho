(ns bitecho.shell.persistence
  "Provides pure functions and I/O wrappers for snapshotting the Root State Map.
   Ensures unserializable objects like core.async channels or PersistentQueues are safely handled."
  (:require [clojure.java.io :as io]
            [clojure.walk :as walk]
            [taoensso.nippy :as nippy]))

(def default-snapshot-filename
  "The default filename used for saving and loading the state snapshot."
  "snapshot.bin")

(defn strip-unserializable-state
  "Transforms the pure state map into a serializable format.
   Strips raw java.util.Random instances, clojure.core.async channels,
   and converts the :murmur-cache :queue (a clojure.lang.PersistentQueue) into a standard vector."
  [state]
  (let [queue-handled (if (get-in state [:murmur-cache :queue])
                        (update-in state [:murmur-cache :queue] vec)
                        state)]
    (walk/postwalk
     (fn [x]
       (cond
         (instance? java.util.Random x) nil
         ;; Handle core.async channels safely without class errors by checking class name
         (and (class x) (= "clojure.core.async.impl.channels.ManyToManyChannel" (.getName (class x)))) nil
         :else x))
     queue-handled)))

(defn restore-unserializable-state
  "Reconstitutes a strictly EDN-serialized state map back into its fully functional form.
   Converts the :murmur-cache :queue vector back into a clojure.lang.PersistentQueue."
  [state]
  (let [queue-restored (if (get-in state [:murmur-cache :queue])
                         (update-in state [:murmur-cache :queue] #(into clojure.lang.PersistentQueue/EMPTY %))
                         state)]
    ;; Restore missing keys that may have been stripped out, if they ever get added back
    queue-restored))

(defn save-state-to-disk
  "Serializes the provided state map and atomically writes it to the specified filepath
   using a temporary file rename to prevent corruption.
   Returns true if successful, or throws an exception on failure."
  [filepath state]
  (let [safe-state (strip-unserializable-state state)
        temp-filepath (str filepath ".tmp")
        file (io/file filepath)
        temp-file (io/file temp-filepath)]
    (nippy/freeze-to-file temp-filepath safe-state)
    ;; Atomic rename using java.nio.file.Files/move
    (java.nio.file.Files/move (.toPath temp-file)
                              (.toPath file)
                              (into-array java.nio.file.CopyOption
                                          [java.nio.file.StandardCopyOption/REPLACE_EXISTING
                                           java.nio.file.StandardCopyOption/ATOMIC_MOVE]))
    true))

(defn load-state-from-disk
  "Reads a serialized state map from the specified filepath and restores unserializable types.
   Returns the reconstituted state map, or nil if the file does not exist."
  [filepath]
  (when (.exists (io/file filepath))
    (let [raw-state (nippy/thaw-from-file filepath)]
      (restore-unserializable-state raw-state))))
