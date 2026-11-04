(ns bitecho.cljs-runner
  "Compiles and runs ClojureScript test runner on Node.js."
  (:require [cljs.build.api :as cljs])
  (:gen-class))

(defn -main
  "Builds ClojureScript tests and executes Node test runner."
  [& _args]
  (println "\n=== Compiling ClojureScript tests for Node.js ===")
  (try
    (cljs/build (cljs/inputs "src" "test")
                {:main 'bitecho.cljs-test-runner
                 :output-to "target/cljs-test/test.js"
                 :target :nodejs
                 :output-dir "target/cljs-test/out"
                 :optimizations :none})
    (println "=== Running Node.js test runner ===")
    (let [node-bin (or (System/getenv "NODE_BIN")
                       (let [local-node (java.io.File. (System/getProperty "user.home") ".local/bin/node")]
                         (if (.canExecute local-node)
                           (.getAbsolutePath local-node)
                           "node")))
          proc (-> (ProcessBuilder. [node-bin "target/cljs-test/test.js"])
                   (.inheritIO)
                   (.start))
          exit-code (.waitFor proc)]
      (System/exit exit-code))
    (catch Throwable t
      (.printStackTrace t)
      (System/exit 1))))
