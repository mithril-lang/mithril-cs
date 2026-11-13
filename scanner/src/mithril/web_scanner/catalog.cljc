(ns mithril.web-scanner.catalog
  "CWE -> CVE catalog enrichment.

  Pure. The catalog is an EDN map loaded from
  resources/zap_proxy/catalog/cwe-cve.edn, produced by scripts/nvd-ingest.py
  from NVD API 2.0 + CWE dictionary.

  Shape:
    {:version 1 :source \"nvd\" :last-updated \"2026-11-14\"
     :entries {\"CWE-89\" {:cve-ids [\"CVE-2024-0001\"] :cvss 9.8}}}
  "
  (:require [mithril.web-scanner.core :as core]))

(defn catalog-for
  "Catalog entry for a CWE string, or nil."
  [catalog cwe]
  (get-in catalog [:entries cwe]))

(defn enrich-finding
  "Merge catalog CVE/CVSS/KEV/EPSS into a finding. Existing values win;
  missing CWE or catalog entry leaves the finding untouched."
  [finding catalog]
  (let [cwe (:cwe finding)
        entry (when cwe (catalog-for catalog cwe))]
    (if (nil? entry)
      finding
      (cond-> finding
        (and (seq (:cve-ids entry)) (not (seq (:cve-ids finding))))
        (assoc :cve-ids (:cve-ids entry))
        (and (:cvss entry) (nil? (:cvss finding)))
        (assoc :cvss (:cvss entry))
        (and (:kev entry) (nil? (:kev finding)))
        (assoc :kev (:kev entry))
        (and (:epss entry) (nil? (:epss finding)))
        (assoc :epss (:epss entry))))))

(defn enrich-findings
  "Enrich every finding; nil catalog is a no-op."
  [findings catalog]
  (if (nil? catalog)
    findings
    (vec (map #(enrich-finding % catalog) findings))))
