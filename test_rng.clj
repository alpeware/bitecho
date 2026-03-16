(doseq [i (range 100000)]
  (let [rng (java.util.Random. i)
        val (.nextDouble rng)]
    (when (< val 0.05)
      (println i val)
      (System/exit 0))))
