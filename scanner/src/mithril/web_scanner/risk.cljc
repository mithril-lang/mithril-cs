(ns mithril.web-scanner.risk
  "Risk scoring: CVSS band + KEV/EPSS aware priority (P0/P1/P2).

  Pure. Inputs are finding maps (see mithril.web-scanner.core/finding) with
  optional :cvss (number 0..10), :kev (boolean), :epss (number 0..1) and
  :severity (:low/:medium/:high). Outputs add :cvss-band and :risk-rank.

  Bands follow NVD CVSS: 9-10 critical, 7-8.9 high, 4-6.9 medium,
  0.1-3.9 low, 0/nil none.
  Ranks: P0 = cvss>=9 or kev or (cvss>=7 and epss>=0.5);
         P1 = cvss>=4 or severity :high or epss>=0.1;
         P2 = otherwise.")

(defn cvss-band
  "NVD CVSS qualitative band for a numeric score (or nil)."
  [score]
  (cond
    (nil? score) :none
    (>= score 9.0) :critical
    (>= score 7.0) :high
    (>= score 4.0) :medium
    (> score 0) :low
    :else :none))

(defn risk-rank
  "Priority rank for a finding map."
  [finding]
  (let [cvss (:cvss finding)
        epss (:epss finding)
        kev (:kev finding)]
    (cond
      (and cvss (>= cvss 9.0)) :p0
      (true? kev) :p0
      (and cvss (>= cvss 7.0) epss (>= epss 0.5)) :p0
      (and cvss (>= cvss 4.0)) :p1
      (= :high (:severity finding)) :p1
      (and epss (>= epss 0.1)) :p1
      :else :p2)))

(defn annotate
  "Add :cvss-band and :risk-rank to one finding."
  [finding]
  (assoc finding :cvss-band (cvss-band (:cvss finding)) :risk-rank (risk-rank finding)))

(defn annotate-all
  "Annotate every finding, preserving order."
  [findings]
  (vec (map annotate findings)))
