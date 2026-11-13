(ns mithril.web-scanner.plugin-entry
  "Fixed standalone Python HTTP transport; no target or runtime supplied code."
  (:require [clojure.edn :as edn] [clojure.string :as strings] [clojure.java.shell :as shell]
            [mithril.web-scanner.spider :as spider] [mithril.web-scanner.passive :as passive]
            [mithril.web-scanner.active :as active] [mithril.web-scanner.authorization :as auth]
            [mithril.web-scanner.report :as report]))
(defn -main [& _]
  (let [{:keys [target active? max-pages approval-id] :as request}
        (auth/validate-production-request! (edn/read-string (slurp *in*)))
        max-pages (or max-pages 50) mode (if active? "active" "passive")
        scope (auth/authorization-scope approval-id target mode max-pages)
        fetch (fn [{:keys [method url]}]
                (when-not (= "GET" method) (throw (ex-info "GET only" {})))
                (auth/require-url! scope url)
                (auth/require-url! (auth/authorization-scope approval-id url mode max-pages) url)
                (let [{:keys [exit out]} (shell/sh "python3" (auth/trusted-repo-file "plugin/http_fetch.py")
                                                  url approval-id mode (str max-pages))]
                  (when-not (zero? exit) (throw (ex-info "transport authorization failed" {})))
                  (edn/read-string out)))
        crawl (spider/spider {:seed-url target :fetch-fn fetch :max-pages max-pages :approval-id approval-id :mode mode})
        pages (:pages crawl)
        findings (vec (concat (mapcat #(passive/passive-scan {:url (:url %)} %) pages)
                              (when active? (mapcat #(active/active-scan {:url (:url %) :send-fn fetch
                                                       :approval-id approval-id :max-pages max-pages}) pages))))
        doc (report/report-edn {:target target :findings findings :crawl crawl :mode mode :max-pages max-pages})]
    (println (if (= "json" (System/getenv "ZAP_PROXY_OUTPUT_FORMAT"))
               (let [rendered (report/report-json doc)]
                 (str (subs rendered 0 (dec (count rendered)))
                      ",\"http_status_counts\":{"
                      (strings/join "," (for [[status n] (frequencies (map :status pages))]
                                          (str "\"" status "\":" n))) "}}"))
               (pr-str doc)))))
