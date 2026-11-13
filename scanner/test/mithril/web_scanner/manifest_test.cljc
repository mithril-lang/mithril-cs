(ns mithril.web-scanner.manifest-test
  (:require [clojure.test :refer [deftest is testing]]
            [mithril.web-scanner.core :as core]
            [mithril.web-scanner.risk :as risk]
            [mithril.web-scanner.report :as report]
            [mithril.web-scanner.manifest :as manifest]))

(def ^:private cat {:version 1 :last-updated "2026-11-14"})

(deftest summarize-test
  (testing "counts"
    (let [fs [(core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89" :cve-ids ["CVE-2024-0001"]})
              (risk/annotate (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89" :cve-ids ["CVE-2024-0001" "CVE-2024-0002"] :cvss 9.8}))]
          s (manifest/summarize fs)]
      (is (= {"CWE-89" 2} (:cwe-counts s)))
      (is (= ["CVE-2024-0001" "CVE-2024-0002"] (:cve-ids s)))
      (is (= {:p0 1} (:risk-counts s))))))

(deftest bind-and-verify-test
  (testing "bound report verifies ok"
    (let [f (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89"})
          doc (manifest/bind-catalog (report/report-edn {:target "https://h/" :findings [f] :started-at "t"}) cat)
          v (manifest/verify doc)]
      (is (true? (:ok? v)))
      (is (= 0 (:missing-cwe-count v)))
      (is (= 1 (:catalog-version v)))))
  (testing "missing cwe fails"
    (let [f (core/finding {:rule-id "10038" :title "T" :evidence "E" :url "https://h/"})
          doc (manifest/bind-catalog (report/report-edn {:target "https://h/" :findings [f] :started-at "t"}) cat)
          v (manifest/verify doc)]
      (is (false? (:ok? v)))
      (is (= 1 (:missing-cwe-count v)))))
  (testing "nil catalog version fails"
    (let [doc (manifest/bind-catalog (report/report-edn {:target "https://h/" :findings [] :started-at "t"}) {:last-updated "2026-11-14"})
          v (manifest/verify doc)]
      (is (false? (:ok? v)))
      (is (nil? (:catalog-version v)))))
  (testing "unbound doc fails"
    (let [doc (report/report-edn {:target "https://h/" :findings [] :started-at "t"})
          v (manifest/verify doc)]
      (is (false? (:ok? v))))))

(deftest report-catalog-json-test
  (testing "bound catalog emitted, unbound is null"
    (let [f (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89"})
          bound (manifest/bind-catalog (report/report-edn {:target "https://h/" :findings [f] :started-at "t"}) cat)
          unbound (report/report-edn {:target "https://h/" :findings [f] :started-at "t"})]
      (is (re-find #"catalog" (report/report-json bound)) (report/report-json bound))
      (is (re-find #"\"catalog\":null" (report/report-json unbound)) (report/report-json unbound)))))
