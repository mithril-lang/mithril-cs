(ns mithril.cs.autofix
  "Evidence-bound proposals; application is restricted to the bundled fixture."
  (:require [mithril.cs.fixture :as fixture] [mithril.cs.digest :as digest]
            [mithril.cs.pentest :as pentest] [mithril.cs.core :as core]))

(defn propose [sandbox validation proposal-id]
  (when-not (and (core/identifier? (:id validation)) (core/identifier? (:run-id validation))
                (= :controlled-fixture (:environment validation))
                (= :reproduced (:status validation)) (= "MCS-IDOR-001" (:rule validation))
                (= (:target sandbox) (:target validation))
                (= (:revision sandbox) (:source-revision validation))
                (= (:source-sha256 sandbox) (:source-sha256 validation))
                (= fixture/vulnerable-source (:source sandbox))
                (core/identifier? proposal-id))
    (throw (ex-info "No matching reproduced evidence" {:code :proposal-evidence})))
  {:id proposal-id :status :proposed :environment :controlled-fixture
   :target (:target sandbox) :base-revision (:revision sandbox)
   :before-sha256 (:source-sha256 sandbox) :after-sha256 (digest/sha256 fixture/repaired-source)
   :evidence-id (:id validation) :rule "MCS-IDOR-001"
   :before fixture/vulnerable-source :after fixture/repaired-source})

(defn apply-reviewed
  "No files, GitHub, merge or deployment. Review binds the entire typed proposal."
  [sandbox proposal review]
  (when-not (and (= :approved (:decision review)) (string? (:reviewer review))
                (seq (:reviewer review)) (= proposal (:proposal review))
                (= :proposed (:status proposal))
                (= :controlled-fixture (:environment proposal))
                (= (:target sandbox) (:target proposal))
                (= (:revision sandbox) (:base-revision proposal))
                (= (:source-sha256 sandbox) (:before-sha256 proposal)
                   (digest/sha256 (:source sandbox)))
                (= fixture/vulnerable-source (:before proposal) (:source sandbox))
                (= fixture/repaired-source (:after proposal))
                (= (digest/sha256 (:after proposal)) (:after-sha256 proposal)))
    (throw (ex-info "Review or source binding rejected" {:code :patch-admission})))
  (fixture/sandbox (:target sandbox) (:revision sandbox) (:after proposal)))

(defn retest [patched proposal grant run-id controls]
  (when-not (and (= (:target patched) (:target proposal))
                (= (:revision patched) (:base-revision proposal))
                (= (:source-sha256 patched) (:after-sha256 proposal))
                (= :controlled-fixture (:environment proposal)))
    (throw (ex-info "Patched source does not match" {:code :retest-binding})))
  (let [result (pentest/assess patched grant run-id controls)]
    {:proposal-id (:id proposal) :result result
     :status (if (and (= :completed (get-in result [:run :status]))
                      (= :not-reproduced (get-in result [:validation :status])))
               :verified-in-fixture :unknown)}))
