(ns mithril.web-scanner.risk-test
  (:require [clojure.test :refer [deftest is testing]]
            [mithril.web-scanner.core :as core]
            [mithril.web-scanner.risk :as risk]
            [mithril.web-scanner.report :as report]))

(deftest cvss-band-test
  (testing "all bands"
    (is (= :none (risk/cvss-band nil)))
    (is (= :none (risk/cvss-band 0)))
    (is (= :low (risk/cvss-band 0.1)))
    (is (= :low (risk/cvss-band 3.9)))
    (is (= :medium (risk/cvss-band 4.0)))
    (is (= :medium (risk/cvss-band 6.9)))
    (is (= :high (risk/cvss-band 7.0)))
    (is (= :high (risk/cvss-band 8.9)))
    (is (= :critical (risk/cvss-band 9.0)))
    (is (= :critical (risk/cvss-band 10.0)))))

(deftest risk-rank-test
  (testing "p0 by cvss"
    (is (= :p0 (risk/risk-rank {:cvss 9.0}))))
  (testing "p0 by kev"
    (is (= :p0 (risk/risk-rank {:kev true}))))
  (testing "p0 by cvss and epss"
    (is (= :p0 (risk/risk-rank {:cvss 7.5 :epss 0.5}))))
  (testing "p1 by cvss"
    (is (= :p1 (risk/risk-rank {:cvss 4.0}))))
  (testing "p1 by severity high"
    (is (= :p1 (risk/risk-rank {:severity :high}))))
  (testing "p1 by epss"
    (is (= :p1 (risk/risk-rank {:epss 0.1}))))
  (testing "p2 otherwise"
    (is (= :p2 (risk/risk-rank {:cvss 2.0 :severity :low}))))
  (testing "p2 with empty finding"
    (is (= :p2 (risk/risk-rank {})))))

(deftest annotate-test
  (testing "annotate adds band and rank"
    (let [f (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89" :cvss 9.8})
          g (risk/annotate f)]
      (is (= :critical (:cvss-band g)))
      (is (= :p0 (:risk-rank g)))))
  (testing "annotate-all preserves order"
    (let [fs [(core/finding {:rule-id "10038" :title "T" :evidence "E" :url "https://h/"})
              (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cvss 9.8})]
          gs (risk/annotate-all fs)]
      (is (= 2 (count gs)))
      (is (= :p2 (:risk-rank (first gs))))
      (is (= :p0 (:risk-rank (second gs)))))))

(deftest report-risk-json-test
  (testing "finding json includes risk_rank and cvss_band"
    (let [f (risk/annotate (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89" :cvss 9.8}))
          doc (report/report-edn {:target "https://h/" :findings [f] :started-at "t"})
          j (report/report-json doc)]
      (is (re-find #"risk_rank" j) (str j))
      (is (re-find #"cvss_band" j) (str j)))))
