(ns mithril.cs.edge-test
  (:require #?(:clj [clojure.test :refer [deftest is]] :cljs [cljs.test :refer-macros [deftest is]])
            [mithril.cs.edge :as edge]))
(deftest positive-and-hardened
  (let [input {:url "https://example.test/" :status 200 :body-complete true :headers {"content-type" "text/html; charset=utf-8"}}
        hardened (assoc input :headers (into {"content-type" "text/html"} (map (juxt :header :suggested) edge/rules)))]
    (is (= 5 (count (:findings (edge/assess input)))))
    (is (empty? (:findings (edge/assess hardened))))
    (is (= "partial" (get-in (edge/assess hardened) [:coverage :status])))))
(deftest error-and-context
  (doseq [status [301 401 403 500 0]]
    (is (empty? (:findings (edge/assess {:url "https://example.test/" :status status :headers {"content-type" "text/html"}})))))
  (let [result (edge/assess {:url "https://example.test/icon.ico" :status 200 :headers {"content-type" "image/vnd.microsoft.icon"}})]
    (is (= #{"MCS-H001" "MCS-H002"} (set (map :rule-id (:findings result)))))
    (is (false? (get-in result [:coverage :body-complete])))))
(deftest framing-alternative
  (is (not-any? #(= "MCS-H005" (:rule-id %))
                 (:findings (edge/assess {:url "https://example.test/" :status 200
                  :headers {"content-type" "text/html" "content-security-policy" "frame-ancestors 'none'"}})))))
(deftest explicit-terminal-states
  (is (edge/allowed-transition? "running" "cancelled"))
  (is (edge/allowed-transition? "running" "partial"))
  (doseq [pair [["cancelled" "partial"] ["failed" "running"] ["rejected" "approved"] ["running" "complete"]]]
    (is (not (apply edge/allowed-transition? pair))))))
