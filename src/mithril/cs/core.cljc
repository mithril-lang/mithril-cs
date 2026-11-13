(ns mithril.cs.core
  "Portable, pure authorization and run state. No I/O or model credentials.")

(def capabilities
  {:source-review :implemented
   :autonomous-pentesting :controlled-fixture-only
   :pr-reviews :adapter-required
   :auto-fix :controlled-fixture-only
   :continuous-coverage :planned
   :infrastructure :planned})

(defn positive-int? [n]
  (and (integer? n) (pos? n) (<= n 9007199254740991)))

(defn identifier? [v]
  (and (string? v) (boolean (re-matches #"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}" v))))

(defn validate-grant [grant now]
  (cond
    (not (every? identifier? ((juxt :id :tenant :project :target) grant))) :invalid-identity
    (not (contains? #{:source-review :fixture-pentest} (:operation grant))) :unsupported-operation
    (not (and (positive-int? now) (positive-int? (:expires-at grant)))) :invalid-clock
    (<= (:expires-at grant) now) :expired
    (not= true (:authorized? grant)) :not-authorized
    (not (and (positive-int? (:max-steps grant))
              (<= (:max-steps grant) 100))) :invalid-budget
    :else nil))

(defn start-run [grant run-id now]
  (if-let [reason (or (validate-grant grant now)
                      (when-not (identifier? run-id) :invalid-run-id))]
    {:status :denied :reason reason}
    {:schema-version 1 :id run-id :grant grant :status :ready
     :started-at now :last-at now :steps 0 :evidence [] :findings []}))

(defn cancel [run]
  (if (contains? #{:ready :running} (:status run))
    (assoc run :status :cancelled)
    run))

(defn gate [run context now]
  (cond
    (not (contains? #{:ready :running} (:status run))) :terminal-run
    (or (not (positive-int? now)) (< now (:last-at run))) :invalid-clock
    (:revoked? context) :revoked
    (not= (select-keys (:grant run) [:id :tenant :project :target :operation :source-revision :source-sha256])
          (select-keys context [:id :tenant :project :target :operation :source-revision :source-sha256])) :scope-mismatch
    (validate-grant context now) (validate-grant context now)
    (validate-grant (:grant run) now) (validate-grant (:grant run) now)
    (>= (:steps run) (min (get-in run [:grant :max-steps]) (:max-steps context))) :budget-exhausted
    :else nil))

(defn admit-step [run context now]
  (if-let [reason (gate run context now)]
    (if (= :terminal-run reason)
      run
      (assoc run :status :denied :reason reason :last-at now))
    (-> run (assoc :status :running :last-at now) (update :steps inc))))

(defn valid-evidence? [run evidence]
  (and (identifier? (:id evidence))
       (= (:id run) (:run-id evidence))
       (= (get-in run [:grant :target]) (:target evidence))
       (string? (:source-sha256 evidence))
       (boolean (re-matches #"[0-9a-f]{64}" (:source-sha256 evidence)))
       (contains? #{:candidate :observation :unknown} (:kind evidence))
       (identifier? (:rule evidence))
       (positive-int? (:line evidence))))

(defn record-evidence [run evidence]
  (cond
    (not= :running (:status run)) (throw (ex-info "Run is not active" {:code :inactive}))
    (not (valid-evidence? run evidence)) (throw (ex-info "Invalid evidence binding" {:code :invalid-evidence}))
    (some #(= (:id evidence) (:id %)) (:evidence run))
    (throw (ex-info "Duplicate evidence id" {:code :duplicate-evidence}))
    :else
    (cond-> (update run :evidence conj evidence)
      (= :candidate (:kind evidence))
      (update :findings conj {:id (:id evidence) :rule (:rule evidence)
                             :status :needs-review :evidence-id (:id evidence)}))))

(defn finish [run coverage]
  (if (= :running (:status run))
    (assoc run :status (if (= :complete (:status coverage)) :completed :incomplete)
           :coverage coverage)
    run))
