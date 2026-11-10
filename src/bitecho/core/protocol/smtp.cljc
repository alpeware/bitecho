(ns bitecho.core.protocol.smtp
  "Pure Sans-IO `.cljc` RFC 5321 inbound SMTP session state machine.
   Enforces strict open-relay prevention, message size caps (`128 KB` default),
   RFC 5321 §4.5.2 leading-dot unstuffing, `STARTTLS` state resets, command-sequence rules,
   and counted `:diagnose` effects on every rejected command/relay/oversize event (Rule 5)."
  (:require [bitecho.fressian :as fressian]
            [clojure.string :as str]))

(defn- parse-long-safe
  [s]
  (when (and (string? s) (re-matches #"\d+" s))
    #?(:clj  (try (Long/parseLong s) (catch Exception _ nil))
       :cljs (let [n (js/parseInt s 10)] (when-not (js/isNaN n) n)))))

(defn init-session
  "Initializes a pure SMTP session state map.
   Options:
     `:domain` (default `\"localhost\"`)
     `:max-message-bytes` (default `131072` = `128 KB`)
     `:allowed-recipients` (set/coll of lowercase email addresses or wildcard `\"@domain\"`)
     `:tls-active?` (boolean, default `false`)"
  ([] (init-session {}))
  ([opts]
   (let [domain (or (:domain opts) "localhost")
         max-bytes (long (or (:max-message-bytes opts) 131072))
         recipients (set (keep (fn [r]
                                 (when r
                                   (-> (if (keyword? r) (name r) (str r))
                                       (str/trim)
                                       (str/lower-case))))
                               (or (:allowed-recipients opts) [])))
         tls? (boolean (:tls-active? opts))]
     {:state :connected
      :domain domain
      :max-message-bytes max-bytes
      :allowed-recipients recipients
      :tls-active? tls?
      :helo nil
      :mail-from nil
      :rcpt-to []
      :data-lines []
      :data-bytes 0
      :over-size? false
      :diagnostics {:relay-denied 0
                    :oversize-rejected 0
                    :protocol-errors 0}})))

(defn greeting
  "Generates the initial `220` ESMTP service-ready greeting."
  [session-state]
  {:state (assoc session-state :state :greeted)
   :responses [(str "220 " (:domain session-state) " ESMTP bitecho ready")]
   :effects []})

(defn recipient-allowed?
  "Checks if recipient address is allowed by configuration to prevent open relay.
   Only accepts exact addresses in `allowed-recipients` or addresses at `@<domain>`
   when `\"@<domain>\"` is explicitly configured in `allowed-recipients`."
  [allowed-recipients domain addr]
  (let [addr-lower (str/lower-case (or addr ""))
        domain-lower (str/lower-case (or domain ""))
        domain-suffix (str "@" domain-lower)]
    (or (contains? allowed-recipients addr-lower)
        (and (str/ends-with? addr-lower domain-suffix)
             (contains? allowed-recipients domain-suffix)))))

(defn- parse-mail-from-line
  [raw-line]
  (let [line (str/replace-first raw-line #"(?i)^MAIL\s*FROM:\s*" "")
        size-match (re-find #"(?i)\bSIZE=(\d+)" line)
        size (when size-match (parse-long-safe (second size-match)))
        path-match (re-find #"<([^>]*)>" line)]
    (if path-match
      {:from (second path-match) :size size}
      (let [clean (str/trim (str/replace line #"(?i)\bSIZE=\d+" ""))]
        {:from (if (str/blank? clean) "" clean)
         :size size}))))

(defn- parse-rcpt-to-line
  [raw-line]
  (let [line (str/replace-first raw-line #"(?i)^RCPT\s*TO:\s*" "")
        path-match (re-find #"<([^>]*)>" line)]
    (if path-match
      (second path-match)
      (str/trim line))))

(defn handle-smtp-line
  "Pure function processing a single SMTP line (without trailing CRLF).
   Returns `{:state updated-state :responses [strings...] :effects [effects...]}`."
  [state raw-line]
  (let [line (or raw-line "")]
    (if (= (:state state) :reading-data)
      ;; -----------------------------------------------------------------------
      ;; DATA mode: collecting message body until "."
      ;; -----------------------------------------------------------------------
      (if (= line ".")
        (if (or (:over-size? state) (> (long (:data-bytes state)) (long (:max-message-bytes state))))
          (let [st' (-> state
                        (assoc :state :greeted :mail-from nil :rcpt-to [] :data-lines [] :data-bytes 0 :over-size? false)
                        (update-in [:diagnostics :oversize-rejected] (fnil inc 0)))]
            {:state st'
             :responses ["552 5.3.4 Message size exceeds fixed maximum"]
             :effects [{:effect :diagnose :reason :smtp-message-oversize :bytes (:data-bytes state)}]})
          (let [data-str (str (str/join "\r\n" (:data-lines state)) "\r\n")]
            {:state (assoc state :state :greeted :mail-from nil :rcpt-to [] :data-lines [] :data-bytes 0 :over-size? false)
             :responses ["250 2.0.0 OK: queued"]
             :effects [{:type :deliver-mail
                        :from (:mail-from state)
                        :to (:rcpt-to state)
                        :helo (:helo state)
                        :data-str data-str
                        :size-bytes (:data-bytes state)}]}))

        ;; Data line: leading-dot unstuffing (RFC 5321 §4.5.2) and size check
        (let [unstuffed (if (str/starts-with? line "..") (subs line 1) line)
              line-bytes (+ (fressian/count-bytes (fressian/utf8->bytes line)) 2)
              new-bytes (+ (long (:data-bytes state)) line-bytes)
              max-bytes (long (:max-message-bytes state))]
          (cond
            (> new-bytes (* 2 max-bytes))
            (let [st' (-> state
                          (assoc :state :greeted :mail-from nil :rcpt-to [] :data-lines [] :data-bytes 0 :over-size? false)
                          (update-in [:diagnostics :oversize-rejected] (fnil inc 0)))]
              {:state st'
               :responses ["552 5.3.4 Message size exceeds fixed maximum"]
               :effects [{:type :close}
                         {:effect :diagnose :reason :smtp-message-hard-cap-abort :bytes new-bytes}]})

            (> new-bytes max-bytes)
            {:state (assoc state
                           :data-lines []
                           :data-bytes new-bytes
                           :over-size? true)
             :responses []
             :effects []}

            :else
            {:state (assoc state
                           :data-lines (conj (:data-lines state) unstuffed)
                           :data-bytes new-bytes)
             :responses []
             :effects []})))

      ;; -----------------------------------------------------------------------
      ;; Command mode
      ;; -----------------------------------------------------------------------
      (let [trimmed (str/trim line)
            upper (str/upper-case trimmed)
            compact-upper (str/replace upper #"\s+" "")]
        (cond
          (str/blank? trimmed)
          {:state (update-in state [:diagnostics :protocol-errors] (fnil inc 0))
           :responses ["500 5.5.1 Empty command"]
           :effects [{:effect :diagnose :reason :smtp-empty-command}]}

          (or (= upper "EHLO") (str/starts-with? upper "EHLO "))
          (let [helo-arg (str/trim (subs trimmed (min (count trimmed) 4)))
                clean-helo (if (str/blank? helo-arg) "client" helo-arg)
                responses (concat
                           [(str "250-" (:domain state))]
                           (when-not (:tls-active? state)
                             ["250-STARTTLS"])
                           [(str "250-SIZE " (:max-message-bytes state))
                            "250 8BITMIME"])]
            {:state (assoc state
                           :helo clean-helo
                           :mail-from nil
                           :rcpt-to []
                           :data-lines []
                           :data-bytes 0
                           :state :greeted)
             :responses (vec responses)
             :effects []})

          (or (= upper "HELO") (str/starts-with? upper "HELO "))
          (let [helo-arg (str/trim (subs trimmed (min (count trimmed) 4)))
                clean-helo (if (str/blank? helo-arg) "client" helo-arg)]
            {:state (assoc state
                           :helo clean-helo
                           :mail-from nil
                           :rcpt-to []
                           :data-lines []
                           :data-bytes 0
                           :state :greeted)
             :responses [(str "250 " (:domain state))]
             :effects []})

          (= upper "STARTTLS")
          (if (:tls-active? state)
            {:state (update-in state [:diagnostics :protocol-errors] (fnil inc 0))
             :responses ["503 5.5.1 TLS already active"]
             :effects [{:effect :diagnose :reason :smtp-tls-already-active}]}
            {:state (assoc state
                           :helo nil
                           :mail-from nil
                           :rcpt-to []
                           :data-lines []
                           :data-bytes 0
                           :tls-active? true
                           :state :greeted)
             :responses ["220 2.0.0 Ready to start TLS"]
             :effects [{:type :starttls}]})

          (str/starts-with? compact-upper "MAILFROM:")
          (if-not (:helo state)
            {:state (update-in state [:diagnostics :protocol-errors] (fnil inc 0))
             :responses ["503 5.5.1 Send HELO/EHLO first"]
             :effects [{:effect :diagnose :reason :smtp-missing-helo}]}
            (let [{:keys [from size]} (parse-mail-from-line trimmed)]
              (if (and size (> (long size) (long (:max-message-bytes state))))
                {:state (update-in state [:diagnostics :oversize-rejected] (fnil inc 0))
                 :responses ["552 5.3.4 Message size exceeds fixed maximum"]
                 :effects [{:effect :diagnose :reason :smtp-declared-size-exceeded :size size}]}
                {:state (assoc state
                               :mail-from from
                               :rcpt-to []
                               :data-lines []
                               :data-bytes 0
                               :state :mail)
                 :responses ["250 2.1.0 OK"]
                 :effects []})))

          (str/starts-with? compact-upper "RCPTTO:")
          (if-not (or (= (:state state) :mail) (= (:state state) :rcpt))
            {:state (update-in state [:diagnostics :protocol-errors] (fnil inc 0))
             :responses ["503 5.5.1 Need MAIL command"]
             :effects [{:effect :diagnose :reason :smtp-missing-mail}]}
            (let [addr (parse-rcpt-to-line trimmed)
                  addr-lower (str/lower-case addr)]
              (cond
                (not (recipient-allowed? (:allowed-recipients state) (:domain state) addr-lower))
                {:state (update-in state [:diagnostics :relay-denied] (fnil inc 0))
                 :responses ["550 5.7.1 Relay access denied"]
                 :effects [{:effect :diagnose :reason :smtp-relay-denied :recipient addr-lower}]}

                (>= (count (:rcpt-to state)) 16)
                {:state (update-in state [:diagnostics :protocol-errors] (fnil inc 0))
                 :responses ["452 4.5.3 Too many recipients"]
                 :effects [{:effect :diagnose :reason :smtp-too-many-recipients}]}

                :else
                {:state (assoc state
                               :rcpt-to (conj (:rcpt-to state) addr-lower)
                               :state :rcpt)
                 :responses ["250 2.1.5 OK"]
                 :effects []})))

          (= upper "DATA")
          (if (empty? (:rcpt-to state))
            {:state (update-in state [:diagnostics :protocol-errors] (fnil inc 0))
             :responses ["503 5.5.1 Need RCPT command"]
             :effects [{:effect :diagnose :reason :smtp-missing-rcpt}]}
            {:state (assoc state
                           :state :reading-data
                           :data-lines []
                           :data-bytes 0)
             :responses ["354 Start mail input; end with <CRLF>.<CRLF>"]
             :effects []})

          (= upper "RSET")
          {:state (assoc state
                         :mail-from nil
                         :rcpt-to []
                         :data-lines []
                         :data-bytes 0
                         :state :greeted)
           :responses ["250 2.0.0 OK"]
           :effects []}

          (or (= upper "NOOP") (str/starts-with? upper "NOOP "))
          {:state state :responses ["250 2.0.0 OK"] :effects []}

          (or (= upper "VRFY") (str/starts-with? upper "VRFY "))
          {:state state :responses ["252 2.5.2 Cannot VRFY user"] :effects []}

          (= upper "QUIT")
          {:state (assoc state :state :quit)
           :responses ["221 2.0.0 Bye"]
           :effects [{:type :close}]}

          :else
          {:state (update-in state [:diagnostics :protocol-errors] (fnil inc 0))
           :responses ["500 5.5.1 Command unrecognized"]
           :effects [{:effect :diagnose :reason :smtp-unrecognized-command}]})))))
