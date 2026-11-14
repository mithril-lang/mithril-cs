(ns mithril.cs.edge
  "Portable bounded passive-response review. No network, storage or clock."
  (:require [clojure.string :as str]
            [mithril.cs.rules :as source-rules]))
(def limits {:max-pages 1 :response-bytes 1048576 :request-timeout-ms 15000
             :run-deadline-ms 25000 :concurrency 1 :method "GET"})
(def rules
  [{:id "MCS-H001" :header "strict-transport-security" :title "Review HTTPS transport policy" :scope :https :suggested "max-age=31536000"}
   {:id "MCS-H002" :header "x-content-type-options" :title "Review MIME sniffing protection" :scope :all :suggested "nosniff"}
   {:id "MCS-H003" :header "content-security-policy" :title "Review document content policy" :scope :document :suggested "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"}
   {:id "MCS-H004" :header "referrer-policy" :title "Review referrer policy" :scope :document :suggested "strict-origin-when-cross-origin"}
   {:id "MCS-H005" :header "x-frame-options" :title "Review framing protection" :scope :frame :suggested "SAMEORIGIN"}])
(defn allowed-transition? [from to]
  (contains? (get {"queued" #{"running" "cancelled" "unknown"}
                   "running" #{"partial" "failed" "cancelled" "unknown"}
                   "proposed" #{"approved" "rejected"}
                   "approved" #{"exported" "rejected"}
                   "exported" #{"exported"}}
                 from #{}) to))
(defn assess [{:keys [url status headers body-complete]}]
  (let [ctype (str/lower-case (str (get headers "content-type" "")))
        document? (boolean (re-find #"^(text/html|application/xhtml\+xml)(;|$)" ctype))
        svg? (str/starts-with? ctype "image/svg+xml")
        csp (str/lower-case (str (get headers "content-security-policy" "")))
        success? (and (number? status) (<= 200 status 299))
        findings
        (if-not success? []
          (vec (for [{:keys [id header title scope suggested]} rules
                     :when (and (str/blank? (get headers header))
                                (case scope
                                  :https (str/starts-with? url "https://")
                                  :document (or document? svg?)
                                  :frame (and (or document? svg?) (not (re-find #"frame-ancestors\s+" csp)))
                                  true))]
                 {:rule-id id :header header :title title :severity "low"
                  :status "needs-review" :kind "configuration-review"
                  :evidence (str header " absent on received response")
                  :suggested-value suggested})))]
    {:engine "mithril-edge-passive-v1" :findings findings
     :coverage {:status "partial" :method "single-url-passive-response"
                :received-status status :body-complete (boolean body-complete)
                :browser false :authenticated-target false :active-probes false
                :exploit-validation "not-performed"}
     :limitations ["One explicitly selected URL; no crawl, authentication or active probes."
                   "Header observations require context and compatibility review."
                   "A response without candidates does not establish application security."]}))
#?(:cljs
   (aset js/globalThis "MITHRIL_EDGE"
     #js {:assess (fn [value]
                    (let [v (js->clj value)
                          input {:url (get v "url") :status (get v "status")
                                 :headers (get v "headers") :body-complete (get v "body-complete")}]
                      (clj->js (assess input))))
          :reviewText (fn [text] (clj->js (source-rules/review-text text)))
          :transition (fn [from to] (allowed-transition? from to))
          :limits (clj->js limits)}))
