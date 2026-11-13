(ns mithril.web-scanner.manifest
  "Signed-manifest support: bind the NVD catalog version into a report and
  verify the binding. Pure.

  bind-catalog takes a report EDN doc (from mithril.web-scanner.report/report-edn)
  and a catalog map (from mithril.web-scanner.catalog data: :version/:last-updated) and
  returns a new doc with :report/catalog bound.

  verify returns {:ok? bool, :missing-cwe-count n, :catalog-version v}:
  ok requires a bound catalog version and every finding carrying :cwe.
  Findings are :report/findings (EDN doc) — call verify on the EDN doc,
  not on the JSON string."
  (:require [mithril.web-scanner.core :as core]))

(defn summarize
  "Counts of CWE ids, unique CVE ids, and risk ranks across findings."
  [findings]
  (let [cwe-counts (into {} (for [[c fs] (group-by :cwe findings)
                                   :when c] [c (count fs)]))
        cve-ids (vec (sort (distinct (mapcat :cve-ids findings))))
        risk-counts (into {} (for [[r fs] (group-by :risk-rank findings)
                                    :when r] [r (count fs)]))]
    {:cwe-counts cwe-counts :cve-ids cve-ids :risk-counts risk-counts}))

(defn bind-catalog
  "Bind {:version :last-updated} from catalog into the report doc."
  [doc catalog]
  (assoc doc :report/catalog {:version (:version catalog)
                              :last-updated (:last-updated catalog)}))

(defn verify
  "Verify a bound report doc. :ok? is true only with a catalog version
  and no missing CWE. Nil catalog binds as missing."
  [doc]
  (let [findings (:report/findings doc)
        missing (count (filter #(nil? (:cwe %)) findings))
        version (get-in doc [:report/catalog :version])]
    {:ok? (boolean (and version (zero? missing)))
     :missing-cwe-count missing
     :catalog-version version}))
