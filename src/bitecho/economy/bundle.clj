(ns bitecho.economy.bundle
  "Pure functions for a Full Node to buffer and bundle micro-transfers.")

(defn add-to-buffer
  "Adds a transfer to the bundling buffer.
   If the buffer was empty, sets the bundle-start-time to current-time.
   Returns the updated state map."
  [state transfer current-time]
  (let [buffer (:buffer state [])]
    (if (empty? buffer)
      (assoc state
             :buffer [transfer]
             :bundle-start-time current-time)
      (assoc state
             :buffer (conj buffer transfer)))))

(defn try-bundle
  "Checks if the buffer has reached the max-size or if max-time has elapsed
   since the bundle-start-time.
   If conditions are met and buffer is not empty, returns a map with:
     :bundle -> the array of transfers
     :state -> updated state with empty buffer and nil start time
   Otherwise, returns:
     :bundle -> nil
     :state -> original state"
  [state current-time max-size max-time]
  (let [buffer (:buffer state [])
        start-time (:bundle-start-time state)]
    (if (and (not (empty? buffer))
             (or (>= (count buffer) max-size)
                 (and start-time (>= (- current-time start-time) max-time))))
      {:bundle buffer
       :state (assoc state :buffer [] :bundle-start-time nil)}
      {:bundle nil
       :state state})))