(ns mithril.web-scanner.text
  "Small scanner-local string adapter over Clojure; no external runtime."
  (:require [clojure.string :as s]))
(def lower-case s/lower-case)
(def join s/join)
(def blank? s/blank?)
(def trim s/trim)
(def starts-with? s/starts-with?)
(def index-of s/index-of)
(def replace s/replace)
(defn split
  ([text pattern] (split text pattern 0))
  ([text pattern limit]
   (s/split (str text)
            (if (string? pattern) (re-pattern (java.util.regex.Pattern/quote pattern)) pattern)
            limit)))
