(ns bitecho.shell.updater
  "JVM P-UPD-1 Self-Update Boundary Shell (D40.2).
   Shared across JVM light nodes (`bitecho.shell.light-node`) and JVM full/infra nodes
   (`bitecho.main`), delegating all pointer verification, monotonic version checks,
   SHA-256 == CID checks, pin-version opt-out, stale-generation guards, and LKG rollback
   decisions to pure `.cljc` `bitecho.deploy.core/reduce-light-update-tick`."
  (:require [bitecho.config :as config]
            [bitecho.deploy.core :as deploy]
            [clojure.edn :as edn]
            [clojure.string :as str])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files Path StandardCopyOption]
           [java.time Duration]
           [java.util.concurrent Executors ScheduledExecutorService TimeUnit]))

(defn- current-jar-path
  "Returns the Path of the currently executing uberjar, or nil when running from source."
  []
  (try
    (let [loc (-> (class (fn [])) .getProtectionDomain .getCodeSource .getLocation)
          p (when loc (Path/of (.toURI loc)))]
      (when (and p (str/ends-with? (str p) ".jar") (Files/isRegularFile p (into-array java.nio.file.LinkOption [])))
        p))
    (catch Exception _ nil)))

(defn- file-sha256-hex
  [^Path p]
  (when (and p (Files/isRegularFile p (into-array java.nio.file.LinkOption [])))
    (try
      (deploy/sha256-hex (Files/readAllBytes p))
      (catch Exception _ nil))))

(defn- fetch-bytes!
  [^HttpClient client ^String url-str timeout-ms]
  (try
    (let [req (-> (HttpRequest/newBuilder (URI/create url-str))
                  (.timeout (Duration/ofMillis (long (or timeout-ms 15000))))
                  (.GET)
                  (.build))
          resp (.send client req (HttpResponse$BodyHandlers/ofByteArray))
          status (.statusCode resp)]
      {:ok? (and (>= status 200) (< status 300))
       :status status
       :bytes (.body resp)})
    (catch Exception e
      {:ok? false :status 500 :error (.getMessage e)})))

(defn- verify-staged-jar!
  "Pre-swap health gate: spawns `java -jar <staged-jar> light-node --help` with a 15s timeout."
  [^Path staged-jar]
  (try
    (let [java-bin (str (System/getProperty "java.home") "/bin/java")
          pb (ProcessBuilder. ^java.util.List [java-bin "-jar" (str staged-jar) "light-node" "--help"])
          _ (.redirectErrorStream pb true)
          proc (.start pb)
          finished? (.waitFor proc 15 TimeUnit/SECONDS)]
      (if finished?
        (zero? (.exitValue proc))
        (do
          (.destroyForcibly proc)
          false)))
    (catch Exception _ false)))

(defn start-jvm-auto-updater!
  "Starts a background daemon `ScheduledExecutorService` polling `pointer-url` via
   `deploy/reduce-light-update-tick` (`:artifact-role :jvm-jar`).
   Returns a zero-arg stop function, or nil when `pointer-url` is blank."
  [{:keys [node-id pointer-url poll-interval-ms current-version pinned-version
           trusted-deploy-authorities last-applied-seq on-event stop-node-fn!
           mesh-connected-fn mesh-chunk-fetch-fn]}]
  (when (and (string? pointer-url) (not (str/blank? pointer-url)))
    (let [jar-path (current-jar-path)
          cur-cid (file-sha256-hex jar-path)
          poll-ms (max 5000 (long (or poll-interval-ms 60000)))
          client (-> (HttpClient/newBuilder)
                     (.connectTimeout (Duration/ofSeconds 10))
                     (.build))
          eff-trusted (if (some? trusted-deploy-authorities)
                        (set trusted-deploy-authorities)
                        config/default-trusted-deploy-authorities)
          updater-atom (atom (deploy/init-light-updater-state
                              (cond-> {:node-id (or node-id "jvm-node")
                                       :artifact-role :jvm-jar
                                       :current-version (or current-version "0.23.22")
                                       :current-cid cur-cid
                                       :trusted-deploy-authorities eff-trusted
                                       :pinned-version pinned-version
                                       :poll-interval-ms poll-ms}
                                (some? last-applied-seq) (assoc :last-applied-seq (long last-applied-seq)))))
          staged-bytes-atom (atom nil)
          staged-path-atom (atom nil)
          emit! (fn [m] (when on-event (try (on-event m) (catch Exception _ nil))))
          dispatch!
          (fn dispatch! [ev]
            (let [effs-box (atom [])]
              (swap! updater-atom
                     (fn [st]
                       (let [[st' effs] (deploy/reduce-light-update-tick st ev)]
                         (reset! effs-box effs)
                         st')))
              (doseq [eff @effs-box]
                (case (:effect eff)
                  :fetch-pointer
                  (let [gen (:generation eff)
                        res (fetch-bytes! client pointer-url 15000)]
                    (if (:ok? res)
                      (let [txt (String. ^bytes (:bytes res) StandardCharsets/UTF_8)
                            ptr (try (edn/read-string txt) (catch Exception _ nil))]
                        (if (map? ptr)
                          (dispatch! {:type :pointer-seen
                                      :pointer ptr
                                      :mesh-connected? (boolean (and mesh-connected-fn (mesh-connected-fn)))
                                      :generation gen})
                          (emit! {"event" "auto-update-diagnose" "reason" "malformed-pointer-edn"})))
                      (emit! {"event" "auto-update-diagnose" "reason" "fetch-pointer-failed" "error" (:error res)})))

                  :fetch-bundle-mesh-chunks
                  (let [gen (:generation eff)
                        cid (:cid eff)]
                    (if (fn? mesh-chunk-fetch-fn)
                      (let [mres (try
                                   (mesh-chunk-fetch-fn cid eff)
                                   (catch Exception e
                                     {:ok? false :reason (.getMessage e)}))]
                        (if (and (:ok? mres) (bytes? (:bytes mres)))
                          (do
                            (reset! staged-bytes-atom (:bytes mres))
                            (dispatch! {:type :blob-fetched :cid cid :bytes (:bytes mres) :generation gen}))
                          (dispatch! {:type :mesh-fetch-failed
                                      :cid cid
                                      :reason (or (:reason mres) (:error mres) :mesh-chunk-fetch-failed)
                                      :generation gen})))
                      (dispatch! {:type :mesh-fetch-failed
                                  :cid cid
                                  :reason :mesh-chunk-unavailable-jvm
                                  :generation gen})))

                  :fetch-bundle-blob
                  (let [gen (:generation eff)
                        cid (:cid eff)
                        blob-url (deploy/build-blob-fetch-url pointer-url cid)
                        res (fetch-bytes! client blob-url 30000)]
                    (if (:ok? res)
                      (do
                        (reset! staged-bytes-atom (:bytes res))
                        (dispatch! {:type :blob-fetched :cid cid :bytes (:bytes res) :generation gen}))
                      (do
                        (emit! {"event" "auto-update-diagnose" "reason" "fetch-bundle-blob-failed" "cid" cid "error" (:error res)})
                        (dispatch! {:type :blob-fetch-failed :cid cid :reason (:error res) :generation gen}))))

                  :stage-light-bundle
                  (when (and jar-path @staged-bytes-atom)
                    (try
                      (let [dir (.getParent ^Path jar-path)
                            cid8 (subs (str (:cid eff)) 0 (min 8 (count (str (:cid eff)))))
                            tmp-p (.resolve dir (str ".bitecho-update-" cid8 ".jar.tmp"))]
                        (Files/write tmp-p ^bytes @staged-bytes-atom (into-array java.nio.file.OpenOption []))
                        (reset! staged-path-atom tmp-p))
                      (catch Exception e
                        (emit! {"event" "auto-update-diagnose" "reason" "stage-write-failed" "detail" (.getMessage e)}))))

                  :atomic-swap-and-restart-light-node
                  (let [gen (:generation eff)
                        cid (:cid eff)
                        ^Path tmp-p @staged-path-atom]
                    (when (and jar-path tmp-p)
                      (if-not (verify-staged-jar! tmp-p)
                        (dispatch! {:type :health-check-result :healthy? false :generation gen})
                        (try
                          (let [lkg-p (Path/of (str jar-path ".lkg") (into-array String []))]
                            (Files/copy ^Path jar-path lkg-p (into-array java.nio.file.CopyOption [StandardCopyOption/REPLACE_EXISTING]))
                            (Files/move tmp-p ^Path jar-path (into-array java.nio.file.CopyOption [StandardCopyOption/ATOMIC_MOVE StandardCopyOption/REPLACE_EXISTING]))
                            (emit! {"event" "auto-update-applied" "cid" cid "restarting" true})
                            (when stop-node-fn! (try (stop-node-fn!) (catch Exception _ nil)))
                            (System/exit 0))
                          (catch Exception e
                            (emit! {"event" "auto-update-diagnose" "reason" "atomic-swap-failed" "detail" (.getMessage e)})
                            (dispatch! {:type :health-check-result :healthy? false :generation gen}))))))

                  :restore-lkg-light-bundle
                  (do
                    (when-let [^Path tmp-p @staged-path-atom]
                      (try (Files/deleteIfExists tmp-p) (catch Exception _ nil)))
                    (emit! {"event" "auto-update-rolled-back" "lkg_version" (:lkg-version eff) "lkg_cid" (:lkg-cid eff)}))

                  :diagnose
                  (emit! {"event" "auto-update-diagnose" "reason" (name (or (:reason eff) :unknown))})

                  :obs-record
                  (emit! {"event" "auto-update-obs" "transition" (name (or (get-in eff [:record :data :transition]) :unknown))})

                  nil))))
          ^ScheduledExecutorService exec
          (Executors/newSingleThreadScheduledExecutor
           (reify java.util.concurrent.ThreadFactory
             (newThread [_ r]
               (doto (Thread. r "bitecho-jvm-auto-updater")
                 (.setDaemon true)))))]
      (.scheduleAtFixedRate exec
                            ^Runnable (fn [] (try (dispatch! {:type :poll-tick}) (catch Exception _ nil)))
                            15000
                            poll-ms
                            TimeUnit/MILLISECONDS)
      (fn []
        (.shutdownNow exec)))))
