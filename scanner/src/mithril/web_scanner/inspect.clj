(ns mithril.web-scanner.inspect
  "Pure response inspection for owner-authorized bounded validation; no transport."
  (:require [cheshire.core :as json] [clojure.edn :as edn]
            [mithril.web-scanner.passive :as passive]
            [mithril.web-scanner.spider :as spider]))
(defn -main [& _]
  (let [{:keys [url response]} (edn/read-string (slurp *in*))]
    (when-not (and (string? url) (map? response) (string? (:body response))
                   (<= (count (:body response)) 1048576)) (throw (ex-info "inspection bounds" {})))
    (println (json/generate-string
      {:findings (passive/passive-scan {:url url} response)
       :discovered (spider/extract-candidates url (:body response))}))))
