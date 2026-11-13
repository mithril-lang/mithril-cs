(ns mithril.cs.rules
  (:require [clojure.string :as str]))

;; Deliberately lexical, advisory rules. Never call a match exploit confirmation.
(def rules
  [{:id "MCS001" :pattern #"\beval\s*\(" :message "Dynamic evaluation requires review."}
   {:id "MCS002" :pattern #"\bsubprocess\..*shell\s*=\s*true" :message "Shell subprocess requires input-flow review."}
   {:id "MCS003" :pattern #"\.innerhtml\s*=" :message "HTML sink requires trusted-input or sanitization review."}
   {:id "MCS004" :pattern #"verify\s*=\s*false" :message "TLS verification may be disabled."}])

(defn review-text [text]
  (vec (for [[index line] (map-indexed vector (str/split-lines text))
             {:keys [id pattern message]} rules
             :when (re-find pattern (str/lower-case line))]
         {:rule id :line (inc index) :message message :kind :candidate})))
