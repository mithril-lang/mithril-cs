(ns mithril.web-scanner.catalog-test
  (:require [clojure.test :refer [deftest is testing]]
            [mithril.web-scanner.core :as core]
            [mithril.web-scanner.catalog :as catalog]))

(def ^:private cat {:entries {"CWE-89" {:cve-ids ["CVE-2024-0001" "CVE-2024-0002"] :cvss 9.8 :kev true :epss 0.42}
                               "CWE-693" {:cve-ids []}}})

(deftest catalog-for-test
  (testing "hit and miss"
    (is (= {:cve-ids ["CVE-2024-0001" "CVE-2024-0002"] :cvss 9.8 :kev true :epss 0.42} (catalog/catalog-for cat "CWE-89")))
    (is (nil? (catalog/catalog-for cat "CWE-999")))))

(deftest enrich-finding-test
  (testing "fills cve-ids and cvss"
    (let [f (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89"})
          g (catalog/enrich-finding f cat)]
      (is (= ["CVE-2024-0001" "CVE-2024-0002"] (:cve-ids g)))
      (is (= 9.8 (:cvss g)))
      (is (true? (:kev g)))
      (is (= 0.42 (:epss g)))))
  (testing "existing ids win"
    (let [f (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89" :cve-ids ["CVE-OTHER"] :cvss 1.0})
          g (catalog/enrich-finding f cat)]
      (is (= ["CVE-OTHER"] (:cve-ids g)))
      (is (= 1.0 (:cvss g)))
      (is (true? (:kev g)))
      (is (= 0.42 (:epss g))))
  (testing "existing kev/epss win"
    (let [f (assoc (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89"}) :kev false :epss 0.01)
          g (catalog/enrich-finding f cat)]
      (is (false? (:kev g)))
      (is (= 0.01 (:epss g))))))
  (testing "no cwe untouched"
    (let [f (core/finding {:rule-id "10038" :title "T" :evidence "E" :url "https://h/"})]
      (is (= f (catalog/enrich-finding f cat)))))
  (testing "unknown cwe untouched"
    (let [f (core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-999"})]
      (is (= f (catalog/enrich-finding f cat)))))
  (testing "empty catalog ids keep finding unchanged"
    (let [f (core/finding {:rule-id "10038" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-693"})
          g (catalog/enrich-finding f cat)]
      (is (not (contains? g :cve-ids))))))

(deftest enrich-findings-test
  (testing "nil catalog no-op"
    (let [fs [(core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89"})]]
      (is (= fs (catalog/enrich-findings fs nil)))))
  (testing "vector enriched"
    (let [fs [(core/finding {:rule-id "40018" :title "T" :evidence "E" :url "https://h/" :cwe "CWE-89"})]
          gs (catalog/enrich-findings fs cat)]
      (is (= 1 (count gs)))
      (is (= 9.8 (:cvss (first gs)))))))
