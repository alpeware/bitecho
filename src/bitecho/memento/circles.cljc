(ns bitecho.memento.circles
  "BIP-B: Circles & Advisory Twin Capability Boundary.
   Pure Sans-IO .cljc namespace.
   - :human-anchor is a circle-policy convention inherited by subcircles, NEVER a protocol gate.
   - Advisory twins (:advisory-twin? true or :role :twin) can NEVER reach real bip-consent
     or signing handles, emitting counted :diagnose :advisory-twin-real-consent-blocked."
  (:require [bitecho.memento.constants :as mc]))

(def real-consent-or-signing-actions
  "Actions strictly reserved for real non-twin principals."
  #{:bip-consent :sign-real :sign-bip-receipt :access-signing-handle})

(def advisory-actions
  "Actions permitted for advisory twins (always tagged :advisory-only true)."
  #{:advisory-vote :draft-proposal :simulate-consent :review-comment})

(defn make-circle
  "Creates a pure Circle descriptor backed by Rolodex petnames.
   :human-anchor is an optional circle-policy convention (nil is valid at protocol level)."
  [{:keys [subnet-id members values-cid governance-pointer human-anchor parent-circle-id policy
           owner-pubkeys retention-policy storage-accounting]}]
  (cond-> {:subnet-id subnet-id
           :members (set (or members #{}))
           :values-cid values-cid
           :governance-pointer governance-pointer
           :human-anchor human-anchor
           :parent-circle-id parent-circle-id
           :policy (merge {:inherit-human-anchor? true} policy)}
    (some? owner-pubkeys) (assoc :owner-pubkeys (vec owner-pubkeys))
    (some? retention-policy) (assoc :retention-policy retention-policy)
    (some? storage-accounting) (assoc :storage-accounting storage-accounting)))

(defn create-subcircle
  "Creates a subcircle inheriting :human-anchor from parent-circle by circle-policy convention
   unless explicitly overridden."
  [parent-circle {:keys [subnet-id members values-cid governance-pointer human-anchor policy
                         owner-pubkeys retention-policy storage-accounting]}]
  (let [inherit? (get-in parent-circle [:policy :inherit-human-anchor?] true)
        resolved-anchor (if (some? human-anchor)
                          human-anchor
                          (when inherit? (:human-anchor parent-circle)))]
    (make-circle {:subnet-id subnet-id
                  :members members
                  :values-cid values-cid
                  :governance-pointer governance-pointer
                  :human-anchor resolved-anchor
                  :parent-circle-id (:subnet-id parent-circle)
                  :policy (merge (:policy parent-circle) policy)
                  :owner-pubkeys (or owner-pubkeys (:owner-pubkeys parent-circle))
                  :retention-policy (or retention-policy (:retention-policy parent-circle))
                  :storage-accounting storage-accounting})))

(defn valid-circle?
  "Protocol-level validity check for a Circle descriptor.
   Notice: :human-anchor is NOT required (remains a circle-policy convention, never a protocol gate)."
  [circle]
  (boolean (and (map? circle)
                (string? (:subnet-id circle))
                (seq (:subnet-id circle))
                (set? (:members circle))
                (mc/valid-cid64? (:values-cid circle))
                (string? (:governance-pointer circle))
                (seq (:governance-pointer circle)))))

(defn validate-circle-discipline
  "Validates BIP-016 state discipline (:owner-pubkeys, :retention-policy, :storage-accounting)
   on a Circle descriptor, emitting a counted :diagnose on violation."
  [circle]
  (let [res (mc/validate-pointer-discipline circle)]
    (if (:ok? res)
      {:ok? true}
      {:ok? false
       :diagnose (merge {:type :diagnose :code (:code res) :subnet-id (:subnet-id circle) :count 1}
                        (:detail res))})))

(defn resolve-circle-members
  "Resolves circle :members petnames against a Rolodex :state map.
   Returns petname -> {:petname :verified? :pubkey :allowed-actions :advisory-twin?}."
  [circle rolodex-state]
  (into {}
        (for [petname (:members circle)]
          (if-let [entry (get rolodex-state petname)]
            [petname {:petname petname
                      :verified? (boolean (and (string? (:pubkey entry)) (seq (:pubkey entry))))
                      :pubkey (:pubkey entry)
                      :allowed-actions (set (or (:allowed-actions entry) #{}))
                      :advisory-twin? (boolean (:advisory-twin? entry))}]
            [petname {:petname petname
                      :verified? false
                      :pubkey nil
                      :allowed-actions #{}
                      :advisory-twin? false}]))))

(defn advisory-twin?
  "Returns true if actor-descriptor, rolodex entry, or request marks an advisory twin."
  [actor-descriptor rolodex-entry action-request]
  (boolean (or (true? (:advisory-twin? actor-descriptor))
               (= :twin (:role actor-descriptor))
               (true? (:advisory-twin? rolodex-entry))
               (true? (:simulation? action-request)))))

(defn authorize-action
  "Pure capability boundary check for Circle actions.
   Guarantees an advisory twin can NEVER reach real bip-consent or signing handles
   even via inherited :human-anchor, :allowed-actions, or validly signed entries."
  [circle rolodex-state actor-descriptor action-request]
  (let [petname (:petname actor-descriptor)
        action (:action action-request)
        rolodex-entry (get rolodex-state petname)
        twin? (advisory-twin? actor-descriptor rolodex-entry action-request)
        member? (contains? (:members circle) petname)
        real-gated? (contains? real-consent-or-signing-actions action)]
    (cond
      ;; HARD INVARIANT: Advisory twins can NEVER reach real consent or signing handles!
      (and twin? real-gated?)
      {:allowed? false
       :advisory-only true
       :reason :advisory-twin-real-consent-blocked
       :effects [{:type :diagnose
                  :code :advisory-twin-real-consent-blocked
                  :subnet-id (:subnet-id circle)
                  :actor petname
                  :action action
                  :count 1}]}

      (not member?)
      {:allowed? false
       :reason :not-a-circle-member
       :effects [{:type :diagnose
                  :code :not-a-circle-member
                  :subnet-id (:subnet-id circle)
                  :actor petname
                  :action action
                  :count 1}]}

      (nil? rolodex-entry)
      {:allowed? false
       :reason :missing-rolodex-entry
       :effects [{:type :diagnose
                  :code :missing-rolodex-entry
                  :subnet-id (:subnet-id circle)
                  :actor petname
                  :action action
                  :count 1}]}

      (and twin? (contains? advisory-actions action))
      {:allowed? true
       :advisory-only true
       :reason :advisory-action-permitted
       :effects []}

      (contains? (set (:allowed-actions rolodex-entry)) action)
      {:allowed? true
       :advisory-only twin?
       :reason :authorized
       :effects []}

      :else
      {:allowed? false
       :reason :action-not-allowed
       :effects [{:type :diagnose
                  :code :action-not-allowed
                  :subnet-id (:subnet-id circle)
                  :actor petname
                  :action action
                  :count 1}]})))
