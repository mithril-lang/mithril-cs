(ns mithril.cs.core-test
  (:require [mithril.cs.core :as cs]
            [mithril.cs.rules :as rules]
            #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])))

(def grant {:id "g1" :tenant "t1" :project "p1" :target "source1"
            :operation :source-review :authorized? true :expires-at 1000 :max-steps 1})
(defn ready [] (cs/start-run grant "run1" 100))
(defn active [] (cs/admit-step (ready) grant 101))
(def evidence {:id "e1" :run-id "run1" :target "source1"
               :source-sha256 (apply str (repeat 64 "a"))
               :kind :candidate :rule "MCS001" :line 1})

(deftest grant-validation
  (is (= :ready (:status (ready))))
  (doseq [[field value reason]
          [[:authorized? false :not-authorized] [:expires-at 100 :expired]
           [:tenant nil :invalid-identity] [:max-steps 0 :invalid-budget]
           [:max-steps 101 :invalid-budget] [:max-steps 1.5 :invalid-budget]
           [:operation :pentest :unsupported-operation]]]
    (is (= reason (:reason (cs/start-run (assoc grant field value) "r" 100)))))
  (is (= :invalid-clock (:reason (cs/start-run grant "r" -1)))))

(deftest scope-and-lifecycle
  (is (= :running (:status (active))))
  (doseq [field [:id :tenant :project :target]]
    (is (= :scope-mismatch (:reason (cs/admit-step (ready) (assoc grant field "other") 101)))))
  (is (= :revoked (:reason (cs/admit-step (ready) (assoc grant :revoked? true) 101))))
  (is (= :expired (:reason (cs/admit-step (ready) grant 1000))))
  (is (= :invalid-clock (:reason (cs/admit-step (ready) grant 99))))
  (is (= :budget-exhausted (:reason (cs/admit-step (active) grant 102))))
  (is (= :cancelled (:status (cs/admit-step (cs/cancel (ready)) grant 102))))
  (is (= :completed (:status (cs/finish (active) {:status :complete}))))
  (is (= :incomplete (:status (cs/finish (active) {:status :empty})))))

(deftest evidence-is-bound-and-advisory
  (let [run (cs/record-evidence (active) evidence)]
    (is (= :needs-review (get-in run [:findings 0 :status])))
    (is (= 1 (count (:evidence run))))
    (is (thrown? #?(:clj Exception :cljs js/Error) (cs/record-evidence run evidence))))
  (doseq [bad [(assoc evidence :target "elsewhere")
               (assoc evidence :run-id "another")
               (assoc evidence :kind :confirmed)
               (assoc evidence :source-sha256 "abc")
               (assoc evidence :line 0)]]
    (is (thrown? #?(:clj Exception :cljs js/Error) (cs/record-evidence (active) bad))))
  (is (thrown? #?(:clj Exception :cljs js/Error) (cs/record-evidence (ready) evidence))))

(deftest lexical-review
  (is (empty? (rules/review-text "const value = 42;")) )
  (is (= ["MCS001" "MCS003" "MCS004" "MCS002"]
         (mapv :rule (rules/review-text "eval(input)\nx.innerHTML = input\nverify=False\nsubprocess.run(x, shell=True)"))))
  (is (= 2 (:line (first (rules/review-text "safe\neval(x)"))))))
